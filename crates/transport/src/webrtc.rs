//! WebRTC peer (str0m answerer), driven by a tokio UDP socket + timers.
//!
//! The agent is always the ANSWERER: it receives an SDP offer
//! from the viewer, attaches an outgoing H.264 video track to the recvonly
//! transceiver, and accepts the `input` DataChannel (viewer -> agent).
//!
//! The peer runs its own tokio task. The orchestrator talks to it through
//! channels:
//!   * `media_tx`   — push encoded H.264 frames to send to the viewer
//!   * `signals`    — the viewer's trickled ICE candidates and re-offers (ICE restart), whole and
//!     in order, in a queue of their own ([`crate::peer_signal`])
//!   * `control_tx` — bitrate / heartbeat / cursor / playout / clipboard: bounded, and for most of
//!     them a full queue refuses the message by design (the next one supersedes it)
//!   * `closer`     — end the peer; a separate signal so a full `control_tx` cannot lose it
//!     ([`PeerCloser`])
//!   * `events`     — Connected / link lost / Disconnected (with why) / input datachannel bytes /
//!     PLI / local candidates found after the answer, to trickle / the answer to a re-offer
//!
//! ## Surviving a network change
//!
//! ICE losing the path does not end the peer. It starts a grace window ([`ICE_GRACE`]) in which
//! the viewer can restart ICE with a new offer for the same session ([`PeerSignal::Renegotiate`]);
//! str0m applies that to the live `Rtc`, so capture, encoder, DTLS and the data channels all carry
//! on. Only a window that runs out ends the peer, as [`PeerEnd::IceTimeout`].
//!
//! ## Sending where the viewer is
//!
//! str0m sends DTLS and media on the highest-priority pair the viewer ever nominated, whether or
//! not that pair answers us, and keeps it while the viewer keeps checking it (`crate::paths`, module
//! docs). The run loop watches the pair str0m sends on against the viewer's own
//! choice — where its DTLS and RTCP come from, which pairs it nominated, which answer our checks —
//! and when str0m's pair is dead and the viewer is demonstrably elsewhere, withdraws the dead remote
//! candidate from str0m (`DirectApi::invalidate_candidate`), which then sends on the viewer's
//! nominated pair ([`PeerLoop::follow_viewer`], `crate::paths::judge_send_path`).

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU32, AtomicU64, AtomicU8, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use afklink_protocol::{IceCandidate, PeerStage, CHANNEL_CURSOR, CHANNEL_INPUT};
use anyhow::{Context, Result};
use str0m::bwe::{Bitrate, BweKind};
use str0m::change::SdpOffer;
use str0m::channel::ChannelId;
use str0m::format::Codec;
use str0m::media::{MediaKind, MediaTime, Mid};
use str0m::net::{Protocol, Receive};
use str0m::rtp::Extension;
use str0m::{Candidate, CandidateKind, Event, IceConnectionState, Input, Output, Rtc};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, watch};

use crate::cursor_lane::{CursorLane, Kind as LaneKind, STALL_AFTER};
use crate::host_peer::{
    ChannelDelivery, ChannelRole, DataVerdict, HostPeerOptions, HostSocket, OpenedChannel,
    PeerHooks,
};
use crate::paths::{
    judge_send_path, Dir, DtlsRole, DtlsSeen, DtlsWatch, Follow, Hold, Kind, Leave, Noted,
    PathBook, Stall, Verdict, DTLS_STALL_WARN_AFTER, FOLLOW_EVERY,
};
use crate::peer_signal::{signal_queue, PeerSignal, SignalReceiver, SignalSender};
use crate::playout::{
    self, PlayoutDelay, PlayoutPolicy, RtxTrace, LOSS_MEMORY, LOSS_REPORTS_TO_HOLD,
    PLAYOUT_DELAY_MAX_LOSSY_MS, PLAYOUT_DELAY_MAX_MS, RELEASE_MAX_FLOOR_MS, RELEASE_MAX_MARGIN_MS,
    RELEASE_MIN_FLOOR_MS, RELEASE_RAMP_MS_PER_S,
};
use crate::shaper::LinkShaper;
use crate::socket::PeerSocket;
use crate::stun;

/// One encoded H.264 frame (Annex-B) to send to the viewer.
#[derive(Debug, Clone)]
pub struct MediaSample {
    pub data: Vec<u8>,
    pub is_keyframe: bool,
    /// Presentation timestamp in milliseconds, monotonic from session start.
    pub timestamp_ms: u64,
    /// The quantiser the encoder coded this frame at, when it can say. For the log only: the
    /// `keyframe handed to str0m` line carries it, so the keyframe the viewer actually starts from
    /// is on record with its quality — the encode loop's own keyframe line is rate-limited, and can
    /// spend its slot on an opening keyframe that never leaves (encoded before the connection) and
    /// hold back the one that does.
    pub qp: Option<u32>,
}

/// Orchestrator -> peer: everything but the viewer's own signaling, which has a queue of its own
/// ([`PeerSignal`], [`Peer::signals`]) because none of it may be dropped.
///
/// This queue is bounded (16) and shared by several senders, and most of what goes on it is
/// refused by design when it is full: the heartbeat and the cursor reports (the next one supersedes
/// them), the viewer's playout report (the next is a second away), the ceiling and the background
/// hold's page state (the control task offers them again on its next tick). The clipboard's messages
/// wait for room instead (`send().await` from its own task). A re-anchor refused is logged and the
/// controller lets its hold go (`afklink_core::quality`).
#[derive(Debug)]
pub enum PeerControl {
    /// Raise or lower the ceiling congestion control probes towards, in kbps.
    ///
    /// The orchestrator owns this number because only it knows what the agent would send if
    /// bandwidth allowed: that depends on the quality ladder, the real size of the screen, and
    /// the viewer's setting, none of which this crate can see. See
    /// `afklink_core::quality::desired_bitrate_kbps`.
    ///
    /// Emphatically *not* the current estimate. See the `EgressBitrateEstimate` handler.
    ///
    /// Set on arrival, except one that would end str0m's quiet while no video flows (a background
    /// hold's end, drain mode's): that one goes with the next video frame, carried by the re-anchor
    /// armed for it if there is one. See [`ceiling_waits_for_video`].
    SetDesiredBitrate(u32),
    /// Restart the bandwidth estimator from a given bitrate, in kbps.
    ///
    /// ## Why an estimate ever needs restarting
    ///
    /// The pacer drains at `estimate * PACING_FACTOR` — `str0m-0.23.1/src/pacer/control.rs:49`,
    /// where `min_pacing_rate = estimate * PACING_FACTOR` and the factor is 1.1. There is no
    /// application-side lever on that rate. So when the orchestrator's budget exceeds the estimate
    /// — which is exactly what happens on the first motion after a pause, because str0m's estimate
    /// is bounded by acked traffic and our silence talked it down — the extra bytes do not go out
    /// faster. They queue inside str0m, its delay controller reads its own queue as overuse and
    /// decreases to `0.85 x acked` (`bwe/delay/rate_control.rs:248-270`), and acked during an idle
    /// stretch is tens of kbps. Measured: an estimate of **59 kbps** two
    /// seconds after motion resumed on a link that had been carrying ten megabits.
    ///
    /// `Rtc::bwe().reset(init)` is str0m's own answer, and its documentation describes this exact
    /// use — "warm up the video stream for a while then calling reset with a provided
    /// init_bitrate" (`bwe/api.rs:43-56`). It rebuilds the estimator whole, so what follows is a
    /// fresh measurement starting from the supplied number rather than a number we have asserted:
    /// if the link narrowed while we were idle, overuse is detected from the new init within a
    /// second and the estimate falls from there, under load.
    ///
    /// Emphatically not a ceiling — that is [`Self::SetDesiredBitrate`], which is a policy about
    /// probing. This is a one-shot starting point, and only `afklink_core::quality` knows when the
    /// situation calls for one: see `QualityController::take_bwe_reanchor`.
    ///
    /// Applied through [`reanchor_bwe`], not a bare `reset`: a bare reset opens with probes at 3x
    /// and 6x the new estimate, which on a narrow link is a queue and a loss burst per re-anchor.
    ResetBwe(u32),
    /// [`Self::ResetBwe`] whose opening probes may reach `probe_cap_kbps` rather than stop at
    /// `kbps` — never past twice the ceiling ([`Self::SetDesiredBitrate`]). For the restart that
    /// exists to *find* room: a media path that became more direct, whose opening is str0m's whole
    /// 3x and 6x up to the ladder's ceiling (`afklink_core::quality::ReanchorTrigger::PathChange`).
    /// Applied through [`reanchor_bwe_probing`].
    ResetBweProbing { kbps: u32, probe_cap_kbps: u32 },
    /// [`Self::ResetBwe`], applied right before the next video frame is handed to str0m — or at once
    /// when one was handed over within [`REANCHOR_FLOWING_WITHIN`], the frame having come first.
    ///
    /// For a restart decided before the video it has to measure exists: the end of a background
    /// hold (`afklink_core::quality::ReanchorTrigger::at_next_frame`). A restarted estimator has no
    /// acknowledged rate until its first 500 ms window closes and then takes that window's rate
    /// straight (`str0m-0.23.1/src/bwe/acked_bitrate_estimator.rs`, `INITIAL_BITRATE_WINDOW` in
    /// `bwe/mod.rs`), so a restart into the hold's padding measures padding again; and one after the
    /// resumed keyframe races the old estimator, which reads the keyframe's own queue as overuse and
    /// cuts to 0.85 times the padding rate it acknowledged (`bwe/delay/rate_control.rs`,
    /// `decrease`). Armed until that frame comes, however long the capture takes to start; a later
    /// one replaces it.
    ResetBweAtNextFrame(u32),
    /// Send the agent's pipeline heartbeat (one JSON text message) to the viewer.
    ///
    /// On the `cursor` channel, whose contract — unordered, never retransmitted — is exactly a
    /// heartbeat's: the next one supersedes it, a late one is worthless and a retransmitted one only
    /// adds delay. Dropped, with a trace line, while that channel is not open (before the viewer
    /// has connected, or if it closed); the next heartbeat is a second away. Held here, the newest
    /// only, while the viewer's SCTP acknowledges nothing and the viewer is known to be out of
    /// reach — ICE lost the path, or its page is hidden ([`PeerControl::ViewerHidden`]) — and
    /// written the moment it acknowledges or shows it is back (`crate::cursor_lane`). See
    /// `afklink_protocol::heartbeat`.
    SendHeartbeat(String),
    /// Send a cursor report (`cp`, one JSON text message) to the viewer, on the `cursor` channel
    /// like the heartbeat and for the same reason: the next report supersedes it. Up to about
    /// thirty a second while the pointer moves; dropped at trace while the channel is not open,
    /// held like the heartbeat. See `afklink_protocol::cursor`.
    SendCursor(String),
    /// The viewer's page is hidden (its `vis hidden`, from the grace on) or visible again, as the
    /// session's background hold has it (`afklink_core::bg_hold`). Sent by the control task when
    /// that changes. With ICE's lost path, the only thing that lets the `cursor` channel hold
    /// anything: acknowledgements that stop on a visible page are a congested path's, and go on
    /// being written straight through (`crate::cursor_lane`, "Why the gate").
    ViewerHidden(bool),
    /// Messages for the viewer on the reliable `input` channel, in order: clipboard sync's
    /// `cb_state` and `cb_ack` (`afklink_core::clipboard`). Queued here and written while the
    /// channel's SCTP buffer holds less than [`RELIABLE_HIGH_WATER`], the rest as SACKs free room —
    /// so a long text never fills str0m's buffer, which the heartbeat and the cursor reports share.
    /// Dropped, with a debug line, while the channel is not open. Never logged but by count and
    /// size: a clipboard can hold a password.
    SendReliable(Vec<String>),
    /// One message like [`PeerControl::SendReliable`], refused rather than queued when it would
    /// take the queue past its byte limit; `queued` says which. For a host that must know whether
    /// a status message is on its way (`crate::host_peer`).
    SendReliableReceipt {
        text: String,
        queued: tokio::sync::oneshot::Sender<bool>,
    },
    /// Like [`PeerControl::SendReliable`], in the same queue and the same order, but taken back by
    /// [`PeerControl::RevokeQueued`] while still queued: the `cb_pc` chunks of the PC's clipboard
    /// text, which must stop going the moment the owner turns «Только игра» on.
    SendRevocable(Vec<String>),
    /// Drop, unsent, every message of [`PeerControl::SendRevocable`] still queued for `input`; what
    /// str0m has already taken goes on, so a text may reach the viewer cut short (its joiner
    /// abandons an unfinished text at the next one). The messages of [`PeerControl::SendReliable`]
    /// stay, in order. Said at debug with what was dropped.
    RevokeQueued,
    /// What the viewer said about its own jitter buffer, engine and freezes in its once-a-second
    /// `vv` report. The engine decides how a playout hold is released — fast for Chromium, carefully
    /// for anyone else — and a careful release follows the buffer down and never below it; for a
    /// Chromium viewer, freezes that recur without loss raise a cushion sized from the buffer (see
    /// `crate::playout`).
    ViewerPlayout(ViewerPlayout),
}

/// The part of the viewer's `vv` report the playout policy reads. See [`PeerControl::ViewerPlayout`].
///
/// Numbers from a peer: the policy ignores a target that is not a finite number within the
/// contract's bound, and takes freeze counters that go backwards as a new base.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ViewerPlayout {
    /// The viewer's browser engine, once the orchestrator knows it (the viewer's own word, or its
    /// Telegram platform for a viewer that predates the field).
    pub engine: Option<afklink_protocol::ViewerEngine>,
    /// `jitterBufferTargetDelay` per emitted frame over the viewer's last interval, ms
    /// (`jbuf_target_ms`); absent when no frame was emitted or the browser does not expose it.
    pub jbuf_target_ms: Option<f64>,
    /// The browser's own freeze count and total frozen time this session, cumulative
    /// (`freeze_count`, `freeze_ms`); absent when the browser does not expose them.
    pub freezes: Option<u64>,
    pub freeze_ms: Option<u64>,
}

/// Ends a peer, whatever its control queue holds.
///
/// Closing is not a [`PeerControl`] message because that queue is bounded and shared with the
/// heartbeat and the control task's bitrate messages, so a `try_send` of the close into a full
/// queue would be refused. A session that ended with its peer's queue full would leave the peer
/// running — a socket and a task streaming to nobody — until ICE gave up on its own. This is a
/// separate signal that cannot fill up, and the run loop checks it on every turn.
///
/// Dropping the closer closes the peer too: a peer that nobody can close any more has nobody to
/// serve.
#[derive(Debug)]
pub struct PeerCloser(watch::Sender<bool>);

/// The run loop's end of a [`PeerCloser`].
#[derive(Debug)]
pub struct CloseSignal(watch::Receiver<bool>);

/// Why a [`CloseSignal`] fired, for the log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloseCause {
    /// [`PeerCloser::close`].
    Asked,
    /// The [`PeerCloser`] was dropped without being asked.
    Dropped,
}

impl CloseCause {
    fn as_str(self) -> &'static str {
        match self {
            CloseCause::Asked => "asked",
            CloseCause::Dropped => "closer_dropped",
        }
    }
}

impl PeerCloser {
    /// A closer and the signal it drives. [`spawn_peer`] makes one for every peer; public so a
    /// test can stand in for a peer and see whether it was closed.
    pub fn new() -> (PeerCloser, CloseSignal) {
        let (tx, rx) = watch::channel(false);
        (PeerCloser(tx), CloseSignal(rx))
    }

    /// Ask the peer to close. `true` when a running peer was there to hear it; `false` when its
    /// run loop had already ended, which is what was wanted anyway.
    pub fn close(&self) -> bool {
        self.0.send(true).is_ok()
    }
}

impl CloseSignal {
    /// A close already asked for, or a closer already gone. Checked at the top of every turn of
    /// the run loop, so a turn that never reaches its `select!` still hears it.
    fn pending(&self) -> Option<CloseCause> {
        if *self.0.borrow() {
            return Some(CloseCause::Asked);
        }
        // `Err` is the closer dropped: nobody can ever ask again.
        self.0.has_changed().is_err().then_some(CloseCause::Dropped)
    }

    /// Resolves once a close is asked for, or once the closer is dropped.
    async fn fired(&mut self) -> CloseCause {
        match self.0.wait_for(|asked| *asked).await {
            Ok(_) => CloseCause::Asked,
            Err(_) => CloseCause::Dropped,
        }
    }

    /// Whether [`PeerCloser::close`] has been called. For tests standing in for a peer.
    pub fn is_asked(&self) -> bool {
        *self.0.borrow()
    }
}

/// Peer -> orchestrator.
#[derive(Debug)]
pub enum PeerEvent {
    Connected,
    /// The peer is gone for good, and why: its run loop has ended and nothing else will arrive.
    /// Always the last event a peer sends.
    ///
    /// Not sent when ICE reports `Disconnected`: that would end the session about twenty seconds
    /// into a network change, before the viewer's ICE restart (which Chrome only sends once it
    /// declares the path `failed`) could arrive. A lost path is [`Self::LinkLost`] and a grace
    /// window; see [`ICE_GRACE`].
    Disconnected {
        reason: PeerEnd,
    },
    /// ICE lost the path. The peer stays up for [`ICE_GRACE`], waiting for the viewer to restart
    /// ICE ([`PeerSignal::Renegotiate`]) or for the path to come back by itself.
    ///
    /// Anything held has to be released now: a button-up cannot cross a dead path, and the window
    /// is long enough for a held button to become a drag across someone's desktop.
    LinkLost,
    /// Raw bytes received on either input data channel (an input event's JSON string).
    InputData(Vec<u8>),
    /// The reliable input channel closed while the peer is still up.
    ///
    /// Anything held has to be released by the agent now: the channel a release would
    /// have arrived on is the one that just went away.
    InputChannelClosed,
    /// The encoder should emit an IDR, and who asked: the viewer (its PLI or FIR), or this peer
    /// for a reason of its own. See [`KeyframeAsk`].
    KeyframeRequest(KeyframeAsk),
    /// What the link looks like it can carry right now, in kbps.
    ///
    /// str0m's congestion controller, fed by the viewer's transport-wide feedback. Until this
    /// existed the agent had no idea whether anything it sent arrived on time, and pushed a
    /// fixed bitrate into whatever pipe it was given — so a weak link meant growing queues and
    /// input latency climbing, which is the one thing this product cannot afford.
    BitrateEstimate {
        kbps: u32,
    },
    /// What the *receiver* reports, once a second, from RTCP receiver reports.
    ///
    /// Everything else this agent measures it measures about itself. These four numbers come from
    /// the far end, and without them three separate diagnoses have been argued from half the
    /// evidence:
    ///
    ///   `rtt_ms`  the path. Every latency sum written down in this project so far has used a
    ///             *guessed* 70 ms for it and measured only the local send queue.
    ///   `loss`    a relay dropping 3% and a link that is merely narrow look identical from a
    ///             bandwidth estimate alone.
    ///   `plis`    how often the viewer lost the picture and asked for a keyframe. Each one costs
    ///             an IDR, the largest thing this pipeline emits, so a storm is its own cause.
    ///   `nacks`   retransmissions, which spend link the estimate then reports as used.
    LinkStats {
        rtt_ms: Option<u32>,
        loss: Option<f32>,
        plis: u64,
        nacks: u64,
        firs: u64,
    },
    /// A local candidate found after the answer went out, for the orchestrator to trickle to the
    /// viewer as an `ice` message.
    ///
    /// Only one thing produces it: a server-reflexive address that was not in the answer — a STUN
    /// reply that missed the answer's budget (see `crate::stun`), or a mapping discovered again
    /// after an ICE restart that differs from the one already offered. Without that address a
    /// viewer whose only route is its TURN relay cannot reach this PC at all — the relay forwards
    /// only to peers the viewer has created a permission for, and host candidates on a private
    /// network give it nothing to permit. Already added to the `Rtc` when this is emitted; shaped as
    /// `RTCIceCandidateInit` (`sdpMid` of the answer's first m-line, `sdpMLineIndex` 0, the ufrag
    /// of the credentials current when it was found), which the viewer passes to
    /// `addIceCandidate`, buffering it if the answer has not been applied yet. After a restart it
    /// always follows that restart's [`Self::Answer`] on this channel, so it cannot overtake it.
    LocalCandidate(IceCandidate),
    /// The answer to a [`PeerSignal::Renegotiate`] offer, for the orchestrator to send to the
    /// viewer as an `sdp` answer.
    ///
    /// On this channel rather than a reply to the signal so that it is ordered with
    /// [`Self::LocalCandidate`]: a candidate stamped with a restart's new ufrag must not reach the
    /// viewer before the answer that introduces that ufrag.
    ///
    /// Not always at once: when the viewer has offered only relays and none of our candidates is
    /// public, the answer is held until the srflx discovery has a mapping — then the answer goes
    /// out, followed at once by the candidate — or gives up, or
    /// [`stun::RELAY_ONLY_ANSWER_BUDGET`] runs out. See [`PeerLoop::renegotiate`].
    Answer(String),
}

/// Who asked for the keyframe a [`PeerEvent::KeyframeRequest`] carries.
///
/// The orchestrator needs the difference. The viewer repeats its request while it waits — Chrome
/// every 200 ms until a keyframe arrives — and on a long round trip the repeat leaves before the
/// keyframe the first one asked for can have reached it: measured at a 290 ms round trip, that
/// cost two to three keyframes per lost picture. A keyframe
/// already on its way answers such a repeat, so the agent holds the viewer's requests against the
/// last keyframe sent (`afklink_core::keyframe_window`). This peer's own requests are never held:
/// each says frames this side sent are gone, which no keyframe sent before them can repair.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyframeAsk {
    /// The viewer's RTCP PLI or FIR: str0m's `Event::KeyframeRequest`, one per poll that saw any
    /// (it coalesces the PLIs and FIRs that arrive between two polls and nothing more,
    /// `streams/send.rs` `pending_request_keyframe`).
    Viewer,
    /// The viewer's reference chain is broken by encoded frames it never got: frames before the
    /// connection, the breaker's discards, a write str0m refused. See [`RefChain`].
    ChainBroken,
    /// ICE brought a lost path back: whatever was sent into the outage is gone.
    PathRestored,
    /// The send pair moved off a remote the viewer does not answer on: what went there is gone.
    PairMoved,
}

impl KeyframeAsk {
    /// The name the logs use.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Viewer => "viewer",
            Self::ChainBroken => "chain_broken",
            Self::PathRestored => "path_restored",
            Self::PairMoved => "pair_moved",
        }
    }

    /// Whether the viewer asked — the only requests a keyframe already on its way can answer.
    #[must_use]
    pub fn from_viewer(self) -> bool {
        matches!(self, Self::Viewer)
    }
}

/// Why a peer's run loop ended. Carried by [`PeerEvent::Disconnected`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerEnd {
    /// The orchestrator closed it: [`PeerCloser::close`], or it dropped the closer.
    Closed,
    /// The viewer said goodbye and str0m closed the connection after it (`Event::Closed`): the
    /// viewer's DTLS `close_notify`, or its SCTP association closed — an ABORT with «User-Initiated
    /// Abort», which `RTCPeerConnection.close()` sends (the Mini App's «Отключиться», its screen
    /// closing), or a SHUTDOWN. The viewer's own doing: a path that dies sends nothing and ends as
    /// [`Self::IceTimeout`]. Rarely also an SCTP packet from the viewer that sctp-proto could not
    /// take, which closes the association too (`handle_inbound got err`, logged at `error`).
    ViewerClosed,
    /// str0m closed the connection by itself with no goodbye from the viewer before it.
    RtcClosed,
    /// ICE lost the path and nothing brought it back within [`ICE_GRACE`]: no ICE restart from
    /// the viewer, or one that did not find a path in its own window.
    IceTimeout,
    /// A re-offer ([`PeerSignal::Renegotiate`]) could not be applied.
    RestartFailed,
    /// The run loop failed on an error from str0m.
    Error,
}

impl PeerEnd {
    /// The `session_end` reason the orchestrator reports for this ending.
    ///
    /// Specific on purpose: a single `peer_closed` for a network change, a dead viewer and a
    /// failed restart alike would leave the session history unable to tell them apart. The strings are
    /// `afklink_protocol::end_reason`'s, held to `SESSION_END_REASONS` there.
    ///
    /// [`Self::ViewerClosed`] is `peer_closed` on the wire too: the contract has no reason of its
    /// own for it (`viewer_closed` is the viewer's, sent in its own `session_end`), and the agent
    /// tells it apart where it matters — the connection journal — with [`Self::by_viewer`].
    pub fn reason(self) -> &'static str {
        use afklink_protocol::end_reason;
        match self {
            PeerEnd::Closed | PeerEnd::ViewerClosed | PeerEnd::RtcClosed => end_reason::PEER_CLOSED,
            PeerEnd::IceTimeout => end_reason::ICE_TIMEOUT,
            PeerEnd::RestartFailed => end_reason::ICE_RESTART_FAILED,
            PeerEnd::Error => end_reason::PEER_ERROR,
        }
    }

    /// The viewer ended the connection itself ([`Self::ViewerClosed`]), as opposed to the network,
    /// the agent or str0m on its own.
    pub fn by_viewer(self) -> bool {
        matches!(self, PeerEnd::ViewerClosed)
    }
}

/// How long a session outlives its ICE path, waiting for the viewer to restart ICE or give up.
///
/// ## What has to fit inside it
///
/// str0m reports ICE `Disconnected` only once every candidate pair has failed, and a pair stays
/// viable both for 15 s after the viewer's last binding request (`RECENT_BINDING_REQUEST`,
/// `is-0.11.0/src/pair.rs:12,445-471`) and until nine of our own checks in a row have gone
/// unanswered plus one last 3 s wait — 250 ms doubling to a 3 s cap, about 19 s from the first
/// unanswered check (`is-0.11.0/src/stun.rs:12,37-48,64-71`). So the agent hears of a dead path
/// no earlier than 15 s after the last packet, and in practice 19-25 s after.
///
/// Chrome declares the same path `failed` about 15 s after its last STUN response (libwebrtc's
/// `CONNECTION_WRITE_TIMEOUT`), and that is when `webrtc.ts` sends its restart offer. So in the
/// ordinary network change the restart reaches us *before* our own `Disconnected` and resets ICE
/// before the window ever starts. The window is for when it is later: the viewer's signaling socket
/// reconnecting across the same network change (the Mini App re-sends an unanswered offer once it
/// is back), or a second restart after the first one's checks failed.
///
/// ## Why twenty seconds
///
/// The viewer's own give-up is the bound that matters. `useViewerSession.ts` ends a stalled
/// session `STALL_TIMEOUT_MS + RECOVERY_TIMEOUT_MS` = 5 + 30 = 35 s after the last sign of life,
/// and says so with a `session_end` — which ends this peer at once, whatever the window says.
/// Measured from our earliest possible `Disconnected` (15 s), that is 20 s. So twenty is the
/// shortest window that never ends a session the viewer is still trying to rescue — with a few
/// seconds to spare in the usual case, which covers loss in one direction only (the viewer still
/// hearing us, so its 35 s start later than our silence did) and the signaling hops. Longer would
/// only keep streaming to nobody when the viewer vanished without a word — and then the server's
/// own 20 s viewer-socket grace (`VIEWER_GRACE_MS` in `server/src/signaling/sessions.ts`) ends the
/// session anyway. A viewer that has no picture yet gives up on its own 30 s connect deadline,
/// which is well inside this.
///
/// ## And it also bounds a restart
///
/// An applied restart starts a fresh window of the same length, which ends when its path connects.
/// Without it a restart that never finds a path could hang forever: str0m holds `Checking` while
/// an ICE restart has no remote candidates, treating an empty list as "still possible"
/// (`is-0.11.0/src/agent.rs:2024-2029`), so no `Disconnected` would ever come. The viewer sends its
/// restart about 16 s after its last packet and gives up 35 s after it, so its restart has about
/// 19 s to work — inside this.
pub const ICE_GRACE: Duration = Duration::from_secs(20);

/// The run loop's view of the ICE path, for the grace window. Sans-IO: the loop supplies the
/// clock, which is what lets the rules below be tested without a network.
///
/// The rules:
///   * ICE `Disconnected` opens a window of [`ICE_GRACE`] — unless one is already open, which it
///     does not extend: the path has been gone since the first report.
///   * An applied ICE restart replaces whatever window was open with a fresh one: the viewer has
///     just shown it is alive and trying, and the restart deserves a full window of its own.
///   * ICE `Connected` or `Completed` after a loss or a restart closes the window: the path is
///     back, and the encoder owes the viewer a keyframe on it.
///   * A window that runs out ends the peer as [`PeerEnd::IceTimeout`].
#[derive(Debug, Default)]
struct LinkWatch {
    /// When the current outage began: the path lost, or a restart applied, whichever came first.
    outage_since: Option<Instant>,
    /// When the restart currently in progress was applied, if one is.
    restart_at: Option<Instant>,
    /// When the peer is given up on unless the path comes back.
    deadline: Option<Instant>,
}

/// What an ICE state change meant to the [`LinkWatch`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LinkNote {
    /// Nothing that touches the window.
    Unchanged,
    /// The path was lost and a window opened.
    Lost,
    /// Lost again while a window was already open. The deadline stands; this much of it is left.
    StillLost { left: Duration },
    /// The path is back, after an outage of this long.
    Restored { outage: Duration, restarted: bool },
}

impl LinkWatch {
    fn on_state(&mut self, state: IceConnectionState, now: Instant, grace: Duration) -> LinkNote {
        match state {
            IceConnectionState::Disconnected => match self.deadline {
                Some(deadline) => LinkNote::StillLost {
                    left: deadline.saturating_duration_since(now),
                },
                None => {
                    self.deadline = Some(now + grace);
                    self.outage_since.get_or_insert(now);
                    LinkNote::Lost
                }
            },
            IceConnectionState::Connected | IceConnectionState::Completed => {
                match self.outage_since.take() {
                    Some(since) => {
                        self.deadline = None;
                        LinkNote::Restored {
                            outage: now.saturating_duration_since(since),
                            restarted: self.restart_at.take().is_some(),
                        }
                    }
                    None => LinkNote::Unchanged,
                }
            }
            IceConnectionState::New | IceConnectionState::Checking => LinkNote::Unchanged,
        }
    }

    /// An ICE restart was applied. Returns how much was left of the window it replaced, if one was
    /// open.
    fn on_restart(&mut self, now: Instant, grace: Duration) -> Option<Duration> {
        let replaced = self
            .deadline
            .map(|deadline| deadline.saturating_duration_since(now));
        self.outage_since.get_or_insert(now);
        self.restart_at = Some(now);
        self.deadline = Some(now + grace);
        replaced
    }

    fn expired(&self, now: Instant) -> bool {
        self.deadline.is_some_and(|deadline| now >= deadline)
    }

    fn deadline(&self) -> Option<Instant> {
        self.deadline
    }

    /// How long the current outage has lasted, for the log.
    fn outage(&self, now: Instant) -> Option<Duration> {
        self.outage_since
            .map(|since| now.saturating_duration_since(since))
    }

    fn restarting(&self) -> bool {
        self.restart_at.is_some()
    }
}

pub use crate::host_peer::IceTiming;

/// A host's [`PeerHooks`], in [`Tuning`].
struct HostHooks(Box<dyn PeerHooks>);

impl std::fmt::Debug for HostHooks {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("HostHooks")
    }
}

/// What [`spawn_peer`] otherwise decides from the machine and the constants, so a test can decide
/// it instead. Production always uses [`Tuning::default`].
#[derive(Debug)]
pub(crate) struct Tuning {
    /// See [`ICE_GRACE`].
    pub ice_grace: Duration,
    /// Host candidate addresses, the first of them also the base the srflx line names. `None`
    /// asks the routing table ([`local_ipv4s`], [`primary_local_ipv4`]).
    pub host_ips: Option<Vec<Ipv4Addr>>,
    /// `None` keeps str0m's own schedule.
    pub ice_timing: Option<IceTiming>,
    /// The bench link shaper, when the CLI was started with a link flag. `None` in production:
    /// the socket is used directly. See `crate::shaper`.
    pub shaper: Option<Arc<LinkShaper>>,
    /// Take str0m off a send pair the viewer does not answer on ([`PeerLoop::follow_viewer`]).
    /// Always on in production; off only for the test that shows what str0m does without it.
    pub follow_viewer: bool,
    /// [`stun::RELAY_ONLY_ANSWER_BUDGET`], unless a test shortened it.
    pub relay_only_answer_budget: Duration,
    /// How the viewer's mDNS names are looked up. [`MdnsResolver::Network`] in production.
    pub mdns: MdnsResolver,
    /// A host-driven peer's hooks ([`spawn_host_peer`]); `None` for the agent's own peers.
    hooks: Option<HostHooks>,
}

impl Default for Tuning {
    fn default() -> Self {
        Self {
            ice_grace: ICE_GRACE,
            host_ips: None,
            ice_timing: None,
            shaper: None,
            follow_viewer: true,
            relay_only_answer_budget: stun::RELAY_ONLY_ANSWER_BUDGET,
            mdns: MdnsResolver::Network,
            hooks: None,
        }
    }
}

/// A peer on the socket a host supplies, with the host's [`PeerHooks`]: see `crate::host_peer`.
///
/// The offer is accepted and the answer (after [`PeerHooks::answer`]) is ready on return, like
/// [`spawn_peer`]'s. No STUN server is asked, and the peer offers exactly one candidate: the host
/// socket's address ([`HostSocket::address`]) as a relayed candidate whose base is
/// `options.host_ip`. The run loop's task is returned rather than detached, so the host can wait for
/// the peer's teardown — the socket's close included.
///
/// An error here comes before the run loop starts: neither [`PeerHooks::ended`] nor
/// [`HostSocket::close`] is called, and the socket and hooks are dropped with the error.
pub async fn spawn_host_peer(
    offer_sdp: &str,
    socket: Box<dyn HostSocket>,
    hooks: Box<dyn PeerHooks>,
    options: HostPeerOptions,
) -> Result<(Peer, tokio::task::JoinHandle<()>)> {
    let tuning = Tuning {
        host_ips: Some(vec![options.host_ip]),
        ice_grace: options.ice_grace,
        ice_timing: options.ice_timing,
        hooks: Some(HostHooks(hooks)),
        ..Tuning::default()
    };
    tracing::debug!(
        port = options.bound_port,
        grace_ms = options.ice_grace.as_millis() as u64,
        "host-driven peer: the host's socket and hooks"
    );
    spawn_peer_task(
        PeerSocket::Host(socket),
        options.bound_port,
        offer_sdp,
        Vec::new(),
        tuning,
    )
    .await
}

/// How an mDNS name the viewer signalled becomes an address. See [`PeerLoop::resolve_mdns`].
#[derive(Debug, Clone)]
pub(crate) enum MdnsResolver {
    /// Asked on the network ([`crate::mdns::resolve`]), from each local address in turn.
    Network,
    /// The names a test knows, each lookup answered after `delay`, and how many lookups were made:
    /// a name not in the table fails, as a lookup nobody answers does after its timeout.
    #[cfg(test)]
    Table {
        names: Vec<(String, Ipv4Addr)>,
        delay: Duration,
        asked: Arc<AtomicU32>,
    },
}

/// An mDNS name the viewer signalled, by its lowercased name: shared by the run loop, which asks,
/// and the lookups it spawns, which answer. See [`PeerLoop::resolve_mdns`].
type MdnsBook = Arc<std::sync::Mutex<std::collections::HashMap<String, MdnsName>>>;

#[derive(Debug)]
enum MdnsName {
    /// A lookup is running: the candidates the name stands in, each fed in once it resolves.
    Resolving(Vec<IceCandidate>),
    /// Looked up: a later candidate naming it is fed in with this address at once.
    Resolved(Ipv4Addr),
}

/// The book, through a poisoned lock: a lookup that panicked leaves nothing half-written in it.
fn mdns_book(
    book: &MdnsBook,
) -> std::sync::MutexGuard<'_, std::collections::HashMap<String, MdnsName>> {
    book.lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// `cand` with the mDNS name in its address replaced by `addr`, as str0m can read it. `None` when
/// it names none.
fn with_mdns_address(cand: &IceCandidate, addr: Ipv4Addr) -> Option<IceCandidate> {
    let name = mdns_host_name(&cand.candidate)?;
    Some(IceCandidate {
        candidate: cand.candidate.replacen(&name, &addr.to_string(), 1),
        ..cand.clone()
    })
}

/// Whether two signals of an mDNS host are the same candidate: the same generation, transport
/// and port (the name being the same already).
fn same_mdns_candidate(a: &IceCandidate, b: &IceCandidate) -> bool {
    let fields = |c: &IceCandidate| {
        let mut f = c.candidate.split_whitespace();
        (
            f.nth(2).map(str::to_ascii_lowercase),
            f.nth(2).map(str::to_string),
        )
    };
    a.username_fragment == b.username_fragment && fields(a) == fields(b)
}

/// The run loop's side of [`judge_send_path`]: when it last looked, what it decided, and what it
/// took str0m off. See [`PeerLoop::follow_viewer`].
#[derive(Debug)]
struct FollowState {
    /// [`Tuning::follow_viewer`].
    enabled: bool,
    /// When to look next; `None` until str0m first sends DTLS or media.
    next_at: Option<Instant>,
    /// The last reason to stay, to log a change of reason and not every look.
    hold: Option<Hold>,
    /// The remotes withdrawn from str0m in this ICE generation. Never withdrawn twice, never moved
    /// back to: str0m has discarded them until a restart brings new candidates.
    left: Vec<SocketAddr>,
    /// When the last move was made and where str0m was sending then, until its next DTLS or media
    /// datagram shows where it went.
    moving: Option<(Instant, SocketAddr)>,
}

impl FollowState {
    fn new(enabled: bool) -> Self {
        Self {
            enabled,
            next_at: None,
            // What every healthy session holds on, from the start: not logged until it changes.
            hold: Some(Hold::SendPathAnswers),
            left: Vec::new(),
            moving: None,
        }
    }
}

/// Handle to a running peer.
pub struct Peer {
    /// SDP answer to relay back to the viewer.
    pub answer_sdp: String,
    pub media_tx: mpsc::Sender<MediaSample>,
    /// The viewer's trickled candidates and re-offers, for the orchestrator to hand over as they
    /// come, never waiting and never losing one below [`crate::SIGNAL_QUEUE_CAP`]. See
    /// [`crate::peer_signal`].
    pub signals: SignalSender,
    /// Everything else the orchestrator and its tasks tell the peer. See [`PeerControl`].
    pub control_tx: mpsc::Sender<PeerControl>,
    /// Ends the peer, reliably; see [`PeerCloser`]. Dropping it ends the peer too.
    pub closer: PeerCloser,
    pub events: mpsc::Receiver<PeerEvent>,
    /// How long the oldest packet still waiting to go out has been waiting, in milliseconds.
    ///
    /// The one number that says whether this session is late, and the only one that says it
    /// *before* the viewer notices. An atomic rather than an event because the thread that has to
    /// act on it is the capture thread, the useful reaction is "do not produce the next frame",
    /// and a value that has been through a channel and a task wake-up is describing a queue that
    /// has already grown since.
    pub outstanding_bytes: Arc<AtomicU32>,
    /// Bytes the producer has committed to [`Self::media_tx`] and this peer has not yet written
    /// into str0m. The producer adds before sending; the peer loop subtracts once the frame is in
    /// the send queue. Whoever fills the channel must hold this, or the channel's depth is a
    /// latency nobody can see.
    pub queued_media_bytes: Arc<AtomicU32>,
    /// How long the oldest packet still waiting has been waiting, in milliseconds.
    ///
    /// **The latency signal, measured.** `first_unsent()` is the instant str0m enqueued the oldest
    /// packet it has not yet released, so its age is the queueing delay itself — no bandwidth
    /// estimate, no division by a rate anyone has to guess, no arithmetic that can be wrong.
    ///
    /// Inferring the delay instead goes wrong in ways that cost quality. Bytes divided by the
    /// *budget* mis-read whenever the budget is wrong. Bytes divided by the *estimate* mis-read
    /// whenever the screen is idle, because the estimate is bounded by what has been acknowledged:
    /// measured on a static desktop, 17 524 bytes read as a 922 ms queue against an estimate of
    /// 139 kbps, and 40 817 bytes read as 1010 ms against 294 — while the same bytes actually
    /// drained in 367 ms, which is 890 kbps.
    ///
    /// A snapshot older than [`QUEUE_SAMPLE_FRESH_MS`] is treated as *no queue* rather than as bad
    /// news. `queue_info()` is recomputed when the pacer releases a packet, so a stale sample means
    /// nothing has been sent recently, which means there is nothing waiting.
    pub queue_age_ms: Arc<AtomicU32>,
    /// How fast bytes are actually leaving, in kbps — a decaying peak of measured egress.
    ///
    /// ## Why not the bandwidth estimate
    ///
    /// Because the estimate measures *us* when we are idle, not the link. str0m's delay-based
    /// controller is bounded by roughly `acked x 1.5`, so a still desktop that sends 12 kbps gets
    /// an estimate near nothing — and dividing a queue by that turns a perfectly ordinary burst
    /// into an emergency.
    ///
    /// Measured, on a static screen: `in_flight` of 17524 bytes read as a 922 ms queue, because the
    /// estimate had collapsed to 139 kbps for want of traffic. Seventeen kilobytes. At the rate the
    /// same link demonstrably carried later in that session it is under 140 ms. The link was fine,
    /// and the ladder gave up a rung for it.
    ///
    /// Egress is a *measurement*: these bytes left, in this second. A decaying peak of it is a
    /// lower bound on what the link carries, it cannot be talked down by our own idleness, and when
    /// the queue is backed up it is exactly the drain rate by definition.
    pub drain_kbps: Arc<AtomicU32>,
    /// What actually left the socket in the last second, in kbps, unsmoothed.
    ///
    /// For the `egress` log line. **Not** for the conservation check — see
    /// [`Self::egress_bytes_total`] for that, and why.
    ///
    /// Deliberately not the decaying peak in [`Self::drain_kbps`]: a peak has memory, and memory is
    /// exactly wrong for "is the queue growing right now".
    pub egress_kbps: Arc<AtomicU32>,
    /// Every byte this peer has put on the socket. Monotonic, never reset.
    ///
    /// ## Why a counter and not a rate
    ///
    /// This is the other half of a conservation check: if the encoder produced more than left the
    /// socket, the backlog grew, by arithmetic, from two independent measurements with no bandwidth
    /// estimate between them.
    ///
    /// The once-a-second rate above would make the check wrong in the one direction that matters.
    /// It is republished once a second by [`EgressMeter::report_if_due`]; the controller builds
    /// its feedback every 200 ms from a *fresh* production figure. So on four ticks in five the
    /// numerator would be current and the denominator up to a second old — and during a climb,
    /// when production rises to follow a budget that just went up, that is a systematic
    /// overestimate of the ratio.
    ///
    /// Measured, on a healthy 1080p30 stretch with the queue at zero: production went 2696 → 3691
    /// kbps as the budget rose 3186 → 3717, while a rate-based denominator still read the previous
    /// window's 2809. The ratio came out at 1.31 and the ladder shed a rung, though per *second*
    /// production over egress across that stretch was 0.89 to 1.02. Each climb manufactured the
    /// evidence for its own undoing: eleven rung changes in three and a half minutes on a link
    /// carrying 4 Mbps.
    ///
    /// A monotonic counter has no window of its own, so the reader's window is the only one there
    /// is and both halves necessarily share it.
    pub egress_bytes_total: Arc<AtomicU64>,
    /// Encoded frames this peer did not send, over the session: the ones the circuit breaker
    /// discarded, and the delta frames held back after it (or after any other lost frame) until a
    /// keyframe repaired the viewer's reference chain. See [`RefChain`].
    ///
    /// The one number that explains "it said 30 fps and the picture froze". `encode_fps` counts
    /// what the *encoder* produced; the breaker discards after that, in the transport, so a
    /// perfectly healthy-looking frame rate can sit above a third of a second of nothing.
    ///
    /// Measured: two breaker episodes discarding 10 and 11 consecutive frames, which at 30 fps is
    /// 333 and 366 ms of frozen picture, on a line reading `encode_fps=31`.
    pub discarded_frames: Arc<AtomicU32>,
    /// NACKs the viewer has sent this session, counted the moment str0m decrypts each one (its
    /// raw-packet mirror, [`PeerLoop::note_raw_packet`]), one per RTCP NACK packet. Monotonic.
    ///
    /// For the encode thread's keyframe window (`afklink_core::keyframe_window`), which judges a
    /// viewer's keyframe request against the keyframe already on its way, and lets the window go
    /// when the path lost packets since that keyframe went out. str0m's own NACK counter reaches it
    /// only once a stats interval, up to a second late: on the bench 5 of the 16
    /// requests held on 3g and 10 of the 22 on loss-0p5 waited for a keyframe that never arrived,
    /// held because the request came before the next stats interval said what the NACKs already had.
    ///
    /// Incremented before the events of the same poll are handed on (str0m emits a poll's raw
    /// packets before its keyframe requests), with `Release`, so a reader that loads it with
    /// `Acquire` after taking a request that came after a NACK sees that NACK.
    pub nacks_received: Arc<AtomicU64>,
    /// How many times the media path changed under the session: the 5-tuple RTP leaves on moved
    /// (ICE selected another candidate pair — a restart's new pair, or the viewer switching
    /// networks), or ICE brought a lost path back. Monotonic.
    ///
    /// For the quality controller, whose round-trip baseline is the least round trip it has seen
    /// on *a* path: after a change that minimum describes a path the packets have left, and a
    /// longer new path then reads as a standing queue for up to thirty seconds — measured going
    /// from WiFi to LTE, the brake held a 524 kbps ceiling for 30 s against a baseline
    /// learned on WiFi. See `afklink_core::quality::QualityController::note_path_change`.
    ///
    /// Incremented with `Release` after [`Self::path_kind`] is stored, so a reader that loads this
    /// with `Acquire` and sees a change also sees the kind of the pair it changed to.
    pub path_changes: Arc<AtomicU32>,
    /// How direct the candidate pair the media takes is: [`PATH_KIND_RELAY`],
    /// [`PATH_KIND_REFLEXIVE`] or [`PATH_KIND_HOST`] by the viewer's candidate, or
    /// [`PATH_KIND_UNKNOWN`] before the first media datagram. Set on the first one and on every
    /// change of pair, before [`Self::path_changes`] moves. For the quality controller, which
    /// re-probes a path that became more direct: str0m's opening probes measured the pair the
    /// session started on (`afklink_core::quality::ReanchorTrigger::PathChange`).
    pub path_kind: Arc<AtomicU8>,
    /// How far the peer got and over which pair ([`PeerPath`]), for the session's
    /// `session_end.detail`: current within a second while the peer runs, exact once it ended.
    pub path: Arc<PeerPathCell>,
    /// Bytes the socket took, and of those to a relay candidate (`crate::socket_bytes`): the
    /// session summary's `bytes_socket` and `bytes_relay`.
    pub socket_bytes: Arc<crate::SocketBytes>,
}

/// [`Peer::path_kind`] before the media has taken any pair.
pub const PATH_KIND_UNKNOWN: u8 = 0;
/// [`Peer::path_kind`]: the viewer's candidate is a TURN relay.
pub const PATH_KIND_RELAY: u8 = 1;
/// [`Peer::path_kind`]: the viewer's candidate is server- or peer-reflexive, or an address it never
/// signalled (a peer-reflexive one ICE learned from a check).
pub const PATH_KIND_REFLEXIVE: u8 = 2;
/// [`Peer::path_kind`]: the viewer's candidate is a host address.
pub const PATH_KIND_HOST: u8 = 3;

/// The [`Peer::path_kind`] value for the viewer's candidate at `destination`.
fn path_kind_of(book: &[RemoteCandidate], destination: SocketAddr) -> u8 {
    match book.iter().find(|c| c.addr == destination) {
        Some(c) if c.kind == CandidateKind::Relayed => PATH_KIND_RELAY,
        Some(c) if c.kind == CandidateKind::Host => PATH_KIND_HOST,
        Some(_) | None => PATH_KIND_REFLEXIVE,
    }
}

/// How far a peer got and over which pair: its half of `session_end.detail`.
/// Kinds and verdicts only, never an address — what `crate::paths` already works out for the log.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PeerPath {
    /// How far it got: no check yet, ICE checking, ICE up and DTLS not, DTLS up.
    pub stage: PeerStage,
    /// Which side of a stalled DTLS handshake was not heard (`Verdict::as_str`); only at
    /// [`PeerStage::Dtls`], and only once the counters were read.
    pub verdict: Option<&'static str>,
    /// Milliseconds from ICE connected to DTLS up; absent until DTLS came.
    pub dtls_after_ice_ms: Option<u64>,
    /// The selected pair's local candidate type: `host` (str0m sends from a host base; a srflx
    /// pair with the same base is pruned as redundant), absent before a pair is known.
    pub pair_local_kind: Option<&'static str>,
    /// The viewer's candidate type on the selected pair: `host`, `srflx`, `prflx` (one it never
    /// signalled, learned from a check) or `relay`.
    pub pair_remote_kind: Option<&'static str>,
    /// For a relay: how the viewer reaches it (`udp`, `tcp`, `tls`), when its priority says.
    pub relay_transport: Option<&'static str>,
}

impl PeerPath {
    /// As `session_end.detail` carries it, without `ended_detail` (the orchestrator's to add).
    pub fn detail(&self) -> afklink_protocol::SessionEndDetail {
        afklink_protocol::SessionEndDetail {
            ended_detail: None,
            stage: Some(self.stage.as_str().to_string()),
            verdict: self.verdict.map(str::to_string),
            dtls_after_ice_ms: self.dtls_after_ice_ms,
            pair_local_kind: self.pair_local_kind.map(str::to_string),
            pair_remote_kind: self.pair_remote_kind.map(str::to_string),
            relay_transport: self.relay_transport.map(str::to_string),
        }
    }
}

/// A peer's [`PeerPath`], kept current by its run loop — at ICE's first connect, DTLS up, every
/// change of pair, once a second while it runs, and last of all as it ends — and read by whoever
/// ends the session: the peer's own end, or the orchestrator's (the kill switch, a capture lost).
#[derive(Debug, Default)]
pub struct PeerPathCell(std::sync::Mutex<PeerPath>);

impl PeerPathCell {
    /// The path as last published.
    pub fn get(&self) -> PeerPath {
        // A panic while holding it cannot leave a half-written `Copy` value: take it through.
        *self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Publish `path`; whether it changed.
    pub fn set(&self, path: PeerPath) -> bool {
        let mut slot = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let changed = *slot != path;
        *slot = path;
        changed
    }
}

/// The contract's word for a str0m candidate type (`CANDIDATE_KINDS`).
fn candidate_kind_word(kind: CandidateKind) -> &'static str {
    match kind {
        CandidateKind::Host => "host",
        CandidateKind::ServerReflexive => "srflx",
        CandidateKind::PeerReflexive => "prflx",
        CandidateKind::Relayed => "relay",
    }
}

/// The viewer's candidate at `remote`, as `session_end.detail` names it: its type, and for a relay
/// how the viewer reaches it — `udp`, `tcp` or `tls`, nothing when its priority does not say. An
/// address the viewer never signalled is a peer-reflexive one ICE learned from a check.
fn remote_path_kinds(
    book: &[RemoteCandidate],
    remote: SocketAddr,
) -> (&'static str, Option<&'static str>) {
    match book.iter().find(|c| c.addr == remote) {
        Some(c) if c.kind == CandidateKind::Relayed => {
            let transport = relay_transport(c.prio);
            (
                "relay",
                afklink_protocol::metrics::RELAY_TRANSPORTS
                    .contains(&transport)
                    .then_some(transport),
            )
        }
        Some(c) => (candidate_kind_word(c.kind), None),
        None => ("prflx", None),
    }
}

/// What the breaker decided about one frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Shed {
    /// Send it.
    Send,
    /// Discard it. The queue is past its limit.
    Discard,
    /// The queue has drained: this frame may go, and the episode discarded this many. Every one of
    /// them was an encoded frame the viewer's decoder will never see, so from here the
    /// [`RefChain`] holds delta frames until a keyframe — however few were discarded.
    Resumed { discarded: u32 },
}

/// Bounds the send queue by discarding, because nothing else in the path will.
///
/// A hysteretic breaker, deliberately not a controller. Its two thresholds are an order of
/// magnitude apart and both sit far above the normal operating point, so it contributes no dynamics
/// where the system actually lives — which is the property every previous attempt at bounding this
/// queue lacked, and why each of them found a new way to collapse the frame rate.
#[derive(Debug, Default)]
struct Breaker {
    shedding: bool,
    discarded: u32,
}

impl Breaker {
    fn admit(&mut self, queue_ms: u32) -> Shed {
        if self.shedding {
            if queue_ms > QUEUE_RESUME_MS {
                self.discarded = self.discarded.saturating_add(1);
                return Shed::Discard;
            }
            self.shedding = false;
            let discarded = std::mem::take(&mut self.discarded);
            // Always a resync, however few were discarded. Skipping the keyframe for one or two
            // frames would assume the viewer's decoder notices the missing reference and asks for
            // a keyframe itself. Chrome does; a decoder that does not (WebKit) is left predicting
            // from a picture it never got, and nothing obliges any viewer to report that. In the
            // simulator, `wifi-0924-4m` writes 1115 frames against a broken reference without this
            // gate, and none with it.
            //
            // The cost of a resync — an IDR on a link that has just congested, and the loop of
            // IDR -> queue -> breaker it could close — is avoided upstream: the encode loop
            // withholds frames *before* encoding while the queue is past this breaker's limit
            // (`afklink_core::agent`, the queue guard's hard hold), so on the recorded shapes the
            // breaker rarely discards at all, and when it does, one keyframe repairs it.
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

/// Where the send queue stops being a queue and becomes a fault, in milliseconds.
///
/// One second is the product's own hard limit — past it a person cannot drive a computer at all —
/// so this is not a tuning parameter but the requirement, restated as a number. The normal
/// operating point measured on a healthy session is 20 to 100 ms, so the breaker sits an order of
/// magnitude above where the system lives and cannot interfere with it.
///
/// It is not an alternative to keeping production under the drain rate. It is what catches the
/// case where that has already failed, which on a real session meant 280 seconds of backlog.
///
/// Public because the encode loop's queue guard mirrors this breaker *before* encoding: a frame
/// withheld there costs nothing, where a frame discarded here costs the viewer's reference chain
/// and therefore a keyframe.
pub const QUEUE_HARD_LIMIT_MS: u32 = 1_000;

/// Where discarding stops. Far below the trip point, because a breaker that resets at its own
/// threshold chatters, and every frame it discards costs a keyframe to recover from. Public for the
/// same reason as [`QUEUE_HARD_LIMIT_MS`].
pub const QUEUE_RESUME_MS: u32 = 150;

/// How many packets one turn of the loop may release before it must poll its other inputs again.
///
/// str0m hands out one RTP packet per `handle_input`, so draining a backlog means calling it many
/// times, and going through a timer between calls costs 15.6 ms on Windows — a ceiling of about
/// 900 kbps that no amount of bandwidth can lift.
///
/// Thirty-two, because a bound is what keeps this a fast path rather than a starvation bug: at the
/// 1150-byte MTU that is 37 kB, roughly one keyframe, released before the socket and the control
/// channel get another look. The predecessor of this loop spun a whole core when an overdue
/// timeout produced nothing, so the burst also stops the moment a call yields no packet.
const BURST_PER_TURN: u32 = 32;

/// How long delta frames may be held for a keyframe before it is asked for again.
///
/// The encoder answers a request on the next frame it encodes (`afklink_encode`, `pending_keyframe`
/// survives until then), and between the request and that frame there are at most the two frames
/// of the media channel and one being encoded — about 50 ms at 60 fps, 100 at 30. Held deltas half
/// a second after asking mean the request itself was lost (the event queue refused it) or its
/// keyframe was discarded in its turn, and waiting longer is only a longer freeze.
const KEYFRAME_RETRY: Duration = Duration::from_millis(500);

/// Which loss broke the viewer's reference chain, for the log. See [`RefChain`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChainBreak {
    /// The breaker discarded frames past the send queue's hard limit.
    Breaker,
    /// Frames the encoder made before ICE and DTLS were up, which were never sent. The first of
    /// them is the encoder's opening IDR, so everything after it references a picture the viewer
    /// never got.
    BeforeConnect,
    /// The negotiation left no way to send H.264: no video m-line, no writer or no payload type.
    NoVideo,
    /// str0m's writer refused the frame.
    WriteError,
}

impl ChainBreak {
    fn as_str(self) -> &'static str {
        match self {
            ChainBreak::Breaker => "breaker",
            ChainBreak::BeforeConnect => "before_connect",
            ChainBreak::NoVideo => "no_video",
            ChainBreak::WriteError => "write_error",
        }
    }
}

/// A broken chain: since when, why, and what has been done about it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Broken {
    why: ChainBreak,
    since: Instant,
    /// Encoded frames lost to the drop itself (the breaker's discards, the unsent ones).
    lost: u32,
    /// Delta frames the gate withheld afterwards because they reference a lost frame.
    held: u32,
    /// When a keyframe was last asked for, and how many times.
    asked_at: Option<Instant>,
    asks: u32,
}

/// What [`RefChain::admit`] decided about one frame about to be written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Gate {
    /// Write it: the chain is whole, or this is a keyframe, which makes it whole again.
    Write,
    /// Withhold it: a delta frame whose reference the viewer never got. `ask` when a keyframe
    /// request goes out with it — the first held frame, then every [`KEYFRAME_RETRY`].
    Hold { ask: bool },
}

/// Whether the viewer's decoder holds every reference the next frame needs.
///
/// ## The rule
///
/// **An encoded frame that does not reach str0m breaks the H.264 reference chain for every decoder
/// that does not report it, and the next frame the viewer gets must be a keyframe.** Every such drop
/// in this file calls [`Self::lost`]: the breaker's discards, frames encoded before the connection
/// was up, frames the negotiation gave no way to send, and frames str0m's writer refused. From then
/// until a keyframe is written, delta frames are held rather than sent — each one references a
/// picture the decoder does not have — and a keyframe is asked for.
///
/// Held rather than sent because sending them buys nothing on any viewer: a decoder that conceals
/// shows artefacts for the frames before the keyframe arrives, and one that does not — WebKit on
/// the iPhone — shows nothing it would not have shown anyway, and on that viewer the broken frames
/// are exactly what freezes the picture without a PLI. What it costs is the frames
/// between the request and the keyframe, about one to three.
///
/// Losses the network causes are not here: those leave a hole in the RTP sequence, the viewer's
/// NACKs repair most of them, and a decoder that still misses a frame knows it and asks.
#[derive(Debug, Default)]
struct RefChain {
    broken: Option<Broken>,
}

impl RefChain {
    /// An encoded frame did not reach str0m. `true` when this is what broke a whole chain.
    fn lost(&mut self, why: ChainBreak, now: Instant) -> bool {
        match self.broken.as_mut() {
            Some(b) => {
                b.lost = b.lost.saturating_add(1);
                false
            }
            None => {
                self.broken = Some(Broken {
                    why,
                    since: now,
                    lost: 1,
                    held: 0,
                    asked_at: None,
                    asks: 0,
                });
                true
            }
        }
    }

    fn broken(&self) -> Option<Broken> {
        self.broken
    }

    /// A keyframe was asked for outside [`Self::admit`] — on `Connected`, before any frame of the
    /// connection has been offered. Retries count from here.
    fn asked(&mut self, now: Instant) {
        if let Some(b) = self.broken.as_mut() {
            b.asked_at = Some(now);
            b.asks = b.asks.saturating_add(1);
        }
    }

    /// The gate, for a frame about to be written.
    fn admit(&mut self, keyframe: bool, now: Instant) -> Gate {
        let Some(b) = self.broken.as_mut() else {
            return Gate::Write;
        };
        if keyframe {
            // Whole again only once it is actually written; see `written`.
            return Gate::Write;
        }
        b.held = b.held.saturating_add(1);
        let ask = b
            .asked_at
            .is_none_or(|at| now.saturating_duration_since(at) >= KEYFRAME_RETRY);
        if ask {
            b.asked_at = Some(now);
            b.asks = b.asks.saturating_add(1);
        }
        Gate::Hold { ask }
    }

    /// A frame reached str0m. A keyframe repairs the chain; returns the episode it ended, if any.
    fn written(&mut self, keyframe: bool) -> Option<Broken> {
        if keyframe {
            self.broken.take()
        } else {
            None
        }
    }
}

// The gap between the two is the whole of the anti-chatter argument, so it is checked where it
// cannot rot: a breaker that resets near its own trip point oscillates, and every frame it discards
// costs a keyframe — which would make it a keyframe generator, the single most expensive thing this
// pipeline can do.
const _: () = assert!(
    QUEUE_RESUME_MS * 4 < QUEUE_HARD_LIMIT_MS,
    "the breaker's thresholds must stay far apart"
);

/// How recent a `queue_info()` snapshot must be to be believed, in milliseconds.
///
/// str0m recomputes it when the pacer releases a packet, so its freshness is a function of the
/// send rate. Older than this and it describes a moment that has passed — and the right reading of
/// "nothing has been sent lately" is *nothing is waiting*, not *something is very late*. Getting
/// that backwards once already throttled sessions that had nothing wrong with them: a static
/// desktop sending 134 kbps reported a 672 ms queue that could not physically exist.
const QUEUE_SAMPLE_FRESH_MS: u64 = 200;

/// The slowest link the queue arithmetic will assume, in kbps.
///
/// Guards the division, and guards it *symmetrically*: without a floor an empty queue gives `0/0`
/// and a single byte gives an infinity, and those two read as opposite instructions in the first
/// second of every session.
const MIN_DRAIN_KBPS: u32 = 120;

/// Where the bandwidth estimate starts, in kbps.
///
/// Below the rung a session opens on, on purpose. str0m ramps up from here, and starting above
/// what the link can carry makes the opening seconds of every session a probe at full rate whose
/// recovery costs a keyframe. Starting under it costs a few seconds of lower quality instead,
/// which is the cheaper mistake.
const INITIAL_BITRATE_KBPS: u64 = 600;

/// The ceiling congestion control probes towards, until the orchestrator says otherwise.
///
/// A bootstrap value, not a policy: the real figure comes from the quality ladder priced against
/// the actual screen, and arrives as [`PeerControl::SetDesiredBitrate`] as soon as the session
/// task has one — which is within a frame or two of the peer existing.
///
/// Only a starting point because an estimate cannot rise above what it is allowed to probe for:
/// a fixed ceiling here would make a link that streams 1080p without trouble report "about
/// 1.2 Mbps", a number that looks like a measurement of the network but is a measurement of the
/// constant, and the quality ladder would adapt to it.
///
/// Not the current estimate either. See the note in the `EgressBitrateEstimate` handler for why
/// feeding that back is a ratchet.
const DEFAULT_DESIRED_BITRATE_KBPS: u64 = 2_500;

// ## Why the sender has an opinion about the receiver's buffer
//
// Every latency budget in this tree stops at the socket. The browser's jitter buffer is the term
// after it, and `afklink_core::quality::QUEUE_GUARD_MS` prices it at "30–100 ms of the browser's
// jitter buffer and decode". `playout-delay`
// (`http://www.webrtc.org/experiments/rtp-hdrext/playout-delay`) is the only lever the sender has
// on it: a per-frame RTP header carrying a min/max pair in units of 10 ms. The policy — which pair,
// when, and what Chrome does with each — is `crate::playout`; this file negotiates the extension
// and writes the pair on every frame.
//
// What the viewer's buffer was doing before the policy had a `min`: three 1080p60 sessions across
// a relayed path, RTT 137-141 ms, each second bucketed by whether it carried a NACK. The viewer's
// own `jitterBufferDelay / jitterBufferEmittedCount` (`jbuf_ms`): in session 3 the 48 seconds with
// no NACK had mean `jbuf_ms` 11.6, the 64 with one had 51.8 at 0.14% mean loss, and all 40 seconds
// with `jbuf_ms` over 40 ms were NACK seconds. The share of NACK seconds predicted the complaint:
// 23% -> reported smooth; 57% -> "freezes every 1-2 s, fps jumping 50-74". `encode_fps` was 58-62
// throughout: the receiver was waiting for retransmissions, not the sender being late.

/// Extension header id offered for `playout-delay`.
///
/// Five, matching the numbering Chrome itself uses for this URI (str0m records Chrome's offer in
/// `rtp/ext.rs:342`). The number is only an opening bid — as the answerer we re-map to whatever
/// ids the viewer's offer used (`change/sdp.rs:1195`) — but picking Chrome's own keeps the common
/// case a no-op. It is free in `ExtensionMap::standard()`, which maps 1, 2, 3, 4, 10, 11 and 13.
const EXT_ID_PLAYOUT_DELAY: u8 = 5;

/// Extension header id offered for `video-content-type`. Six, for the same reason as
/// [`EXT_ID_PLAYOUT_DELAY`] (`rtp/ext.rs:343`).
const EXT_ID_VIDEO_CONTENT_TYPE: u8 = 6;

/// The shortest a turn of the run loop may take when the last one produced no packet.
///
/// The loop is allowed to spin as fast as str0m can hand out packets — that is what makes the
/// pacer's one-packet-per-turn contract work, and removing the old floor unconditionally is what
/// finally let egress keep up with the encoder. But a turn that produces nothing has nothing to
/// hurry for, and repeating it immediately turns the loop into a busy-wait.
///
/// One millisecond, because at 1150 bytes an MTU that still permits about 8.8 Mbps of egress from
/// the idle path alone, and any turn that actually matters is on the fast path anyway.
const IDLE_TURN: Duration = Duration::from_millis(1);

/// [`PeerControl::SendReliable`] writes to `input` only while that channel's SCTP buffer holds less
/// than this. str0m buffers 128 KiB across all channels and refuses writes past it, the heartbeat's
/// and the cursor's included: a 64 KiB clipboard text written at once would take half of it. Four
/// chunks in flight still fill a fast link; on a slow one the heartbeat keeps its room.
const RELIABLE_HIGH_WATER: usize = 16 * 1024;

/// What may wait in [`PeerLoop::reliable_out`] at most: several clipboard texts. More than that is a
/// viewer that stopped reading, and what comes then is dropped and said.
const RELIABLE_QUEUE_MAX: usize = 512 * 1024;

/// One message waiting in [`PeerLoop::reliable_out`] for `input`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct QueuedReliable {
    text: String,
    /// It came with [`PeerControl::SendRevocable`]: [`PeerControl::RevokeQueued`] takes it back.
    revocable: bool,
}

/// Take every revocable message out of `queue`, keeping the others in their order: how many were
/// dropped, and their bytes. See [`PeerControl::RevokeQueued`].
fn revoke_queued(queue: &mut std::collections::VecDeque<QueuedReliable>) -> (usize, usize) {
    let (mut dropped, mut bytes) = (0usize, 0usize);
    queue.retain(|m| {
        if m.revocable {
            dropped += 1;
            bytes += m.text.len();
        }
        !m.revocable
    });
    (dropped, bytes)
}

/// What [`reanchor_bwe`] did, for the log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reanchor {
    /// The rate str0m's opening probe clusters were held to, in kbps.
    pub probe_cap_kbps: u64,
    /// The two opening probes a bare `reset` would have fired instead, in kbps: 3x and 6x the new
    /// estimate, each capped at twice the ceiling.
    pub bare_reset_probes_kbps: (u64, u64),
}

/// str0m's opening probes after a reset: 3x and 6x the estimate
/// (`str0m-0.23.1/src/bwe/probe/control.rs:278-291`, `first/second_exponential_probe_scale`).
const STR0M_INITIAL_PROBE_SCALES: (u64, u64) = (3, 6);

/// A [`PeerControl::ResetBweAtNextFrame`] that finds a video frame handed to str0m this recently
/// is applied at once: the video it is for is already flowing — the capture's first frame beat the
/// control task's tick. Two frame intervals of the slowest rung (8 fps); after a background hold
/// the last frame is the hold's length ago.
pub const REANCHOR_FLOWING_WITHIN: Duration = Duration::from_millis(250);

/// str0m's probing minimum, in kbps: a probe cluster under it is not queued at all, and every
/// cluster is held to twice the desired bitrate first (`queue_probe`,
/// `str0m-0.24.1/src/bwe/probe/control.rs:529-537`). So a desired bitrate whose double is under it
/// stops all of str0m's probing — what the background hold and the quality controller's quiet tell
/// it (`afklink_core::bg_hold::BG_HOLD_DESIRED_KBPS`, 1 kbps). See [`ceiling_waits_for_video`].
pub const STR0M_PROBE_MIN_KBPS: u32 = 5;

/// Whether a desired bitrate of `kbps` lets str0m probe nothing at all. See
/// [`STR0M_PROBE_MIN_KBPS`].
#[must_use]
pub fn probes_nothing(kbps: u32) -> bool {
    kbps.saturating_mul(2) < STR0M_PROBE_MIN_KBPS
}

/// Whether a [`PeerControl::SetDesiredBitrate`] of `kbps` waits for the next video frame instead of
/// going to str0m on arrival: when str0m's own copy (`str0m_kbps`) probes nothing
/// ([`probes_nothing`]), `kbps` would let it probe, and no video frame has been handed to str0m
/// within [`REANCHOR_FLOWING_WITHIN`] (`since_frame`, `None` for never). It then goes with that
/// frame: carried by a re-anchor armed for it ([`PeerControl::ResetBweAtNextFrame`] —
/// [`reanchor_bwe`] ends by restoring the ceiling), or set right before it. A ceiling that keeps
/// str0m quiet, or one that arrives while the video flows, goes at once as always.
///
/// ## Why: str0m 0.24 answers a ceiling that rises in its application-limited region with a probe
///
/// The quiet values are told while nothing of ours flows — a background hold, drain mode — and
/// str0m 0.24 counts any 500 ms without a media packet as application-limited
/// (`bwe/alr_detector/detector.rs:76-84`, `bwe/mod.rs:301-305`; 0.23 only updated its detector
/// when a packet went out). In that region a desired bitrate that rises is answered on str0m's next
/// timeout: an allocation probe at 1x and 2x desired (`maybe_increase_alr`, `control.rs:331-372`)
/// or, five seconds after the last probe, a periodic one at 2x desired (`maybe_periodic_alr`,
/// `:374-396`) — on the estimator from before the silence, into a path that carries nothing of ours
/// yet, a moment before the resumed keyframe and the restart that discards that estimator and its
/// probe's result. In the simulator's ten-minute hold over a playing video (4 Mbps, 40 ms) the hold's
/// ceiling went back at 615.100 s and str0m sent a 3394 kbps cluster at 615.103 s, 252 ms before
/// the restart at 615.352 s. That probe is the reason for this guard, and the simulator is where it
/// is confirmed: held, the ceiling reaches str0m together with the restart, which opens its probing
/// at the restart value (`reanchor_bwe`), or with the first frame of video, which ends the silence
/// that put str0m in that region.
///
/// ## What the bench showed, and what it did not
///
/// The bench (`hide-30`, a Chromium viewer; 12 returns without this guard, 9 with it)
/// does not tell the two apart. An estimate under 0.62 times the restart value in the ten seconds
/// after the return came in 1 of 12 returns on master, 3 of 9 with this guard and 3 of 6 on 0.24
/// without it (Fisher p 0.27: noise), and the deepest of them all was master's (5513 -> 480 kbps).
/// Nor does the window this guard closes explain those dips: master went 3-156 ms from the ceiling
/// to the restart in 6 of its 12 returns and none of those dipped. Where the guard did hold the
/// ceiling (4 of 6 returns in the last round; in the others the resumed keyframe reached str0m
/// before the hold's end and both went at once) it went with the restart 47-118 ms after the hold
/// ended, str0m's desired at 1 kbps until then, so nothing was probed in between. The estimate 1, 3,
/// 5 and 10 s after the return, the time to the first frame and the freezes were master's (medians
/// within 10%, p >= 0.25).
#[must_use]
pub fn ceiling_waits_for_video(str0m_kbps: u32, kbps: u32, since_frame: Option<Duration>) -> bool {
    probes_nothing(str0m_kbps)
        && !probes_nothing(kbps)
        && !since_frame.is_some_and(|d| d <= REANCHOR_FLOWING_WITHIN)
}

/// Restart str0m's bandwidth estimator at `init`, without the probe bursts a bare reset fires.
///
/// ## What a bare reset does to a narrow link
///
/// `Rtc::bwe().reset(init)` rebuilds the whole estimator (`bwe/mod.rs:404-406`), probe controller
/// included, and a probe controller that has never probed opens with two clusters at 3x and 6x the
/// estimate, capped only at twice the desired bitrate (`bwe/probe/control.rs:278-291,529-532`). A
/// re-anchor at 3.6 Mbps under a 10 Mbps ceiling therefore sends 10.9 and 20 Mbps probes — into a
/// link that has just been measured at 3.6. In the simulator's 4 Mbps WiFi scenario each re-anchor
/// queued 350-400 ms at the bottleneck, dropped packets, added ~200 ms of RTT and ~4% loss, and the
/// loss then made the controller read the next collapses as not clean.
///
/// ## What this does instead
///
/// Holds the probes to `init` itself, using the one cap str0m applies to every cluster: twice the
/// desired bitrate, read when the cluster is queued (`queue_probe`, `control.rs:529-532`). So:
/// desired lowered to `init / 2`, reset, one timeout — the new probe controller queues its opening
/// clusters in that call (`SendSideBandwidthEstimator::handle_timeout` enables probing, hands over
/// the estimate and the desired rate, and runs `maybe_initial`), and a queued cluster keeps the rate
/// it was queued at — then the real ceiling back. Restoring it also reprices the pacer at the new
/// estimate at once (`Session::set_bwe_desired_bitrate` -> `configure_pacer`); a bare reset left the
/// pacer on the collapsed estimate until the next feedback report.
///
/// A probe at `init` does not bet beyond what the controller asserted, and it still tests the
/// assertion: str0m applies a probe result as the new estimate whatever it is
/// (`bwe/delay/rate_control.rs:177-185`), so a link that narrowed since is measured within a round
/// trip, and one that is wider carries on through str0m's ordinary exponential probing (2x the
/// estimate, once the probe comes back above 70% of its rate). No str0m patch: the cap is its own
/// public lever, applied for the length of one call.
///
/// Sans-IO: the caller drains `poll_output` afterwards, as after any mutation. Shared with the
/// simulator, which calls it on its virtual clock.
pub fn reanchor_bwe(
    rtc: &mut Rtc,
    init: Bitrate,
    desired: Bitrate,
    now: Instant,
) -> Result<Reanchor, str0m::RtcError> {
    reanchor_bwe_probing(rtc, init, desired, init, now)
}

/// [`reanchor_bwe`] with the opening probes held to `probe_cap` instead of `init` — never under
/// `init`, never over twice `desired`, the one cap str0m itself applies. With `probe_cap` at twice
/// the ceiling this is str0m's own opening (3x and 6x of `init`), for a media path nothing has
/// measured yet. See [`PeerControl::ResetBweProbing`].
pub fn reanchor_bwe_probing(
    rtc: &mut Rtc,
    init: Bitrate,
    desired: Bitrate,
    probe_cap: Bitrate,
    now: Instant,
) -> Result<Reanchor, str0m::RtcError> {
    let init_bps = init.as_u64();
    let desired_bps = desired.as_u64();
    // Never above what the real ceiling allows anyway, and never under the restart value: a probe
    // under it would measure less than the estimate is being restarted at.
    let cap_bps = probe_cap
        .as_u64()
        .max(init_bps)
        .min(desired_bps.saturating_mul(2));
    let bare = |scale: u64| {
        init_bps
            .saturating_mul(scale)
            .min(desired_bps.saturating_mul(2))
            / 1000
    };
    let outcome = Reanchor {
        probe_cap_kbps: cap_bps / 1000,
        bare_reset_probes_kbps: (
            bare(STR0M_INITIAL_PROBE_SCALES.0),
            bare(STR0M_INITIAL_PROBE_SCALES.1),
        ),
    };
    tracing::debug!(
        init_kbps = init_bps / 1000,
        desired_kbps = desired_bps / 1000,
        held_desired_kbps = cap_bps / 2 / 1000,
        probe_cap_kbps = outcome.probe_cap_kbps,
        asked_probe_cap_kbps = probe_cap.as_u64() / 1000,
        "bwe re-anchor: ceiling held at half the probe cap for one timeout, so the opening probes \
         are queued no higher than it (the estimate itself, unless a re-probe asked for more)"
    );
    rtc.bwe().set_desired_bitrate(Bitrate::bps(cap_bps / 2));
    rtc.bwe().reset(init);
    let queued = rtc.handle_input(Input::Timeout(now));
    // Put the ceiling back whatever the timeout did: a peer left with half its ceiling would probe
    // towards the wrong target for the rest of the session.
    rtc.bwe().set_desired_bitrate(desired);
    queued?;
    Ok(outcome)
}

/// Create a peer: bind a socket, accept the viewer's offer, produce the answer,
/// and spawn the run loop. The `answer_sdp` is ready immediately on return.
///
/// `stun_servers` ("host:port", from the session's ICE URLs via [`crate::stun_servers`]) are asked
/// for a server-reflexive candidate, so the agent is reachable across NAT. That
/// candidate matters most when P2P is impossible: a viewer that can only use its TURN relay needs
/// our public address to create the relay permission at all. The answer waits up to
/// [`stun::ANSWER_BUDGET`] for it — [`stun::RELAY_ONLY_ANSWER_BUDGET`] when the offer itself shows
/// a relay-only viewer — and a mapping that arrives later is trickled as
/// [`PeerEvent::LocalCandidate`].
pub async fn spawn_peer(offer_sdp: &str, stun_servers: Vec<String>) -> Result<Peer> {
    spawn_peer_with(offer_sdp, stun_servers, None).await
}

/// [`spawn_peer`], with the peer's socket behind the bench link shaper when `shaper` is given.
///
/// `None` is exactly [`spawn_peer`]. With a shaper, every datagram this peer sends or receives —
/// str0m's and the srflx STUN transaction's — goes through the profile in force; see
/// `crate::shaper`.
pub async fn spawn_peer_with(
    offer_sdp: &str,
    stun_servers: Vec<String>,
    shaper: Option<Arc<LinkShaper>>,
) -> Result<Peer> {
    let socket = UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))
        .await
        .context("bind udp socket")?;
    let tuning = Tuning {
        shaper,
        ..Tuning::default()
    };
    spawn_peer_on(socket, offer_sdp, stun_servers, tuning).await
}

/// [`spawn_peer`] on a socket the caller has bound, with what it would otherwise decide itself in
/// `tuning`. Split out so tests can bind loopback, name their own host candidates and shorten the
/// clocks.
async fn spawn_peer_on(
    socket: UdpSocket,
    offer_sdp: &str,
    stun_servers: Vec<String>,
    tuning: Tuning,
) -> Result<Peer> {
    let bound_port = socket.local_addr()?.port();
    let socket = PeerSocket::new(socket, tuning.shaper.clone())
        .context("wrap the socket in the link shaper")?;
    let (peer, task) = spawn_peer_task(socket, bound_port, offer_sdp, stun_servers, tuning).await?;
    // Detached: the peer ends through its closer, and its run loop logs its own end.
    drop(task);
    Ok(peer)
}

/// The peer, and its run loop's task.
async fn spawn_peer_task(
    mut socket: PeerSocket,
    bound_port: u16,
    offer_sdp: &str,
    stun_servers: Vec<String>,
    tuning: Tuning,
) -> Result<(Peer, tokio::task::JoinHandle<()>)> {
    // First, so the STUN transaction before the answer runs on the finer tick too. Held by the run
    // loop for the peer's life; an early return below drops it, withdrawing the request.
    let timer_resolution = crate::timer::acquire("webrtc peer");
    let shaped = tuning.shaper.is_some();
    // From here on every datagram, the STUN transaction below included, goes through this.
    let mut hooks = tuning.hooks.map(|hooks| hooks.0);
    let host_addr = socket.host_address();
    if shaped {
        tracing::debug!(
            port = bound_port,
            "peer socket is behind the bench link shaper"
        );
    }
    // The machine's addresses, unless the caller named them: the routing table's favourite is the
    // base the srflx line names, and every usable address is offered as a host candidate.
    let (host_ip, local_ips) = match tuning.host_ips.as_deref() {
        Some([first, ..]) => {
            tracing::debug!(host_ips = ?tuning.host_ips, "host candidates named by the caller");
            (*first, tuning.host_ips.clone().unwrap_or_default())
        }
        _ => (
            primary_local_ipv4().unwrap_or_else(|| {
                // No route to anywhere: the srflx line then names loopback as its base. Harmless
                // (the base is informational), but it says this machine had no network at all.
                tracing::debug!("no routable local IPv4; the srflx base falls back to loopback");
                Ipv4Addr::LOCALHOST
            }),
            local_ipv4s(),
        ),
    };
    let base_addr = SocketAddr::new(IpAddr::V4(host_ip), bound_port);
    let local_addr = host_addr.unwrap_or(base_addr);
    tracing::debug!(
        port = bound_port,
        base = %host_ip,
        local_ips = ?local_ips,
        stun_servers = ?stun_servers,
        offer = %sdp_summary(offer_sdp),
        "peer socket bound; the viewer's offer"
    );

    // str0m's raw-packet mirror clones every packet sent and hands every RTCP packet received to
    // this loop. Two things read it:
    //
    //   * the NACK count the encode thread's keyframe window judges requests by
    //     ([`Peer::nacks_received`]) — a decision, not a log line, so the mirror is on at every
    //     level;
    //   * the retransmission trace (`crate::playout::RtxTrace`), which only feeds a debug line and so
    //     is kept exactly when that line would be written.
    //
    // The price is small. Measured against str0m 0.23.1 in a release build, with a sender set up
    // like this one at 60 frames a second and 10 Mbit/s (about 1150 packets a second, zero-latency
    // link): 150–230 ns per packet sent (the clone and its box, two frees, one more turn of
    // `drain`), about 0.2 ms of CPU a second — 0.02% of one core, a few per cent of what str0m
    // itself spends sending, and nothing next to the encoder. At debug — every development build,
    // and every release during the beta test — it was on all along.
    let trace_rtx = tracing::enabled!(tracing::Level::DEBUG);
    tracing::debug!(
        trace_rtx,
        "str0m's raw-packet mirror on for this peer: the NACK count for the keyframe window always, \
         the retransmission trace only at debug (trace_rtx)"
    );

    // Build the Rtc as an answerer that only speaks H.264. Use the pure-Rust
    // crypto backend so no C toolchain (aws-lc-rs / nasm / cmake) is required.
    let mut config = Rtc::builder()
        .set_crypto_provider(Arc::new(str0m::crypto::from_feature_flags()))
        .clear_codecs()
        .enable_h264(true)
        // Congestion control. Off by default in str0m (`bwe_config: None`), which meant the
        // agent sent at a fixed rate no matter what was getting through — the classic way to
        // turn a merely slow link into an unusable one, because the queue that builds is in
        // front of the input packets too.
        //
        // This sets where the estimate *starts*; the ceiling it climbs towards is set separately
        // below, and confusing the two is what broke the first version.
        .enable_bwe(Some(Bitrate::kbps(INITIAL_BITRATE_KBPS)))
        // What the *receiver* says, once a second. Off by default in str0m, and its absence is why
        // every diagnosis so far has been half-blind.
        //
        // `MediaEgressStats` carries four things this agent has never had and cannot derive:
        //
        //   rtt    the path, from RTCP receiver reports. Every "latency" figure in this project so
        //          far has been the local send queue — one term of a sum whose other terms were
        //          guessed at 70 ms and never measured.
        //   loss   whether the link is dropping. A relay that loses 3% and a link that is merely
        //          narrow look identical from a bandwidth estimate.
        //   plis   how often the viewer has lost the picture and asked for a keyframe. Each PLI
        //          costs an IDR, and an IDR is the single largest thing this pipeline emits, so a
        //          PLI storm is both a symptom and its own cause.
        //   nacks  retransmission requests, which spend bandwidth the estimate then reports as used.
        //
        // One second, matching the pipeline line, so the two can be read side by side.
        .set_stats_interval(Some(Duration::from_secs(1)))
        // The sender's only lever on the browser's jitter buffer, and it has to be negotiated
        // before a single header goes out. `ExtensionMap::standard()` — what str0m starts from —
        // maps only ids 1, 2, 3, 4, 10, 11, 13, none of which is either of these (`rtp/ext.rs:370`),
        // so `Writer::playout_delay` was writing values into an extension that was never on the
        // wire. Enabling them here is what makes [`PLAYOUT_DELAY_MAX_MS`] mean anything.
        //
        // `video-content-type` is negotiated alongside it because it is the same lever's other
        // half — Chrome applies a different jitter and decode policy to screenshare content — but
        // see [`Inner::log_negotiated_jitter_extensions`]: str0m 0.23.1's frame-level `Writer`
        // exposes no setter for the value, so we currently negotiate it without writing it.
        .set_extension(EXT_ID_PLAYOUT_DELAY, Extension::PlayoutDelay)
        .set_extension(EXT_ID_VIDEO_CONTENT_TYPE, Extension::VideoContentType)
        .enable_raw_packets(true);
    if let Some(t) = tuning.ice_timing {
        tracing::debug!(?t, "ICE check schedule overridden by the caller");
        config.set_initial_stun_rto(t.initial_rto);
        config.set_max_stun_rto(t.max_rto);
        config.set_max_stun_retransmits(t.retransmits);
    }
    let mut rtc = config.build(Instant::now());

    // The ceiling to aim for. A property of what this agent can produce, not of what the network
    // is currently doing — updating it from the estimate is what made the first version ratchet
    // downward and never recover. The orchestrator replaces this bootstrap value with the ladder's
    // own figure once it knows the screen; see `PeerControl::SetDesiredBitrate`.
    rtc.bwe()
        .set_desired_bitrate(Bitrate::kbps(DEFAULT_DESIRED_BITRATE_KBPS));

    // Host candidates: every usable local address, not one guessed "primary".
    //
    // Picking one by asking the routing table (connect a UDP socket to 8.8.8.8 and read back the
    // local address) fails with a VPN up: the table picks the tunnel's address, exactly the one
    // the phone in the next room cannot reach. Measured: a machine offering 192.168.0.24 on Wi-Fi
    // and 172.18.0.1 on a tunnel got the tunnel, so a session that had resolved the phone's LAN
    // address over mDNS still went through the relay.
    //
    // Offering all of them is not a workaround, it is what ICE is for: candidates are proposals,
    // and connectivity checks are how a pair is chosen. Guessing which single proposal will work
    // is the one thing the protocol explicitly does not ask of us.
    let mut offered = 0;
    // Whether any host candidate is an address a TURN relay forwards to. Behind a NAT none is, and
    // then a viewer that offers only relays can reach this PC only through a srflx candidate.
    let mut public_host = false;
    if let Some(address) = host_addr {
        // A host's socket is a relay the host allocated: its address is the one candidate.
        let candidate =
            Candidate::relayed(address, base_addr, "udp").context("host relay candidate")?;
        anyhow::ensure!(
            rtc.add_local_candidate(candidate).is_some(),
            "host relay candidate refused"
        );
        tracing::debug!("offering the host socket's relayed address as the only candidate");
        offered = 1;
        public_host = true;
    } else {
        for &ip in &local_ips {
            let addr = SocketAddr::new(IpAddr::V4(ip), bound_port);
            match Candidate::host(addr, "udp") {
                Ok(c) => {
                    let public = is_public_v4(ip);
                    tracing::info!(%addr, public, "offering host candidate");
                    rtc.add_local_candidate(c);
                    offered += 1;
                    public_host |= public;
                }
                Err(e) => tracing::debug!(%addr, "skipping host candidate: {e}"),
            }
        }
    }
    if offered == 0 {
        // Nothing routable to offer. The session can still work through the relay, so this is a
        // note rather than a failure — but it means no direct path is possible at all.
        tracing::warn!("no local host candidates; relay only");
    }

    // Our own addresses, for recognising a STUN mapping that is not a NAT's: every host candidate
    // plus the routing table's favourite, which is what the srflx line names as its base.
    let mut own_ips = local_ips;
    if !own_ips.contains(&host_ip) {
        own_ips.push(host_ip);
    }

    // Server-reflexive candidate via STUN Binding transactions on this socket, BEFORE accept_offer
    // so that in the ordinary case it is carried in the answer SDP and nothing has to be trickled.
    // Nothing else reads the socket yet: the run loop has not started. What the answer cannot wait
    // for continues on the run loop — see `crate::stun` for the schedule and the incident behind
    // it, and `PeerLoop::drive_srflx`.
    let mut late_srflx = None;
    // The mapping the `Rtc` has as a candidate, if any: a later discovery that finds the same one
    // (after an ICE restart) has nothing to trickle.
    let mut srflx_addr = None;
    // What the viewer's offer itself carries. Usually nothing: the Mini App trickles, and its
    // candidates reach this peer only after the answer (the orchestrator hands them over once the
    // peer exists), so the offer is the only word on a relay-only viewer the first answer can have.
    // Its mDNS hosts are looked up once the run loop exists, below.
    let offered_by_viewer = sdp_candidates(offer_sdp);
    offered_by_viewer.log("offer");
    let mut remote_candidates = Vec::new();
    for c in &offered_by_viewer.parsed {
        remember_candidate(&mut remote_candidates, c.clone());
    }
    let viewer_mix = CandidateMix::of(&remote_candidates);
    let viewer_addrs: Vec<SocketAddr> = remote_candidates.iter().map(|c| c.addr).collect();
    // When this offer's answer began waiting the relay-only budget for a srflx candidate, if it
    // did: the same offer sent again shares that one budget. See `PeerLoop::answer_hold`.
    let mut hold_clock = None;
    if host_addr.is_some() {
        tracing::debug!("the answer offers only the host socket's relayed address");
    } else if stun_servers.is_empty() {
        tracing::warn!(
            "no STUN server in the session's ICE config: no srflx candidate, so a viewer that can \
             reach this PC only through its relay will not connect"
        );
    } else {
        let need = srflx_need(viewer_mix, false, public_host);
        let budget = if need == SrflxNeed::Required {
            tuning.relay_only_answer_budget
        } else {
            stun::ANSWER_BUDGET
        };
        tracing::debug!(
            need = need.as_str(),
            viewer_relays = viewer_mix.relay,
            viewer_other = viewer_mix.other,
            public_host,
            budget_ms = budget.as_millis() as u64,
            "STUN: how long the answer waits for a srflx candidate (longer only for a viewer that \
             offered nothing but relays, which cannot reach a private host candidate)"
        );
        let started = Instant::now();
        if need == SrflxNeed::Required {
            hold_clock = Some(HoldClock {
                ufrag: sdp_ice_ufrag(offer_sdp),
                since: started,
            });
        }
        let mut probe = stun::Probe::new(stun_servers.clone(), started);
        let mut lookups = stun::spawn_lookups(&probe);
        let found = stun::run_until(&mut socket, &mut probe, &mut lookups, started + budget).await;
        let now = Instant::now();
        let attempts = probe.attempts();
        let elapsed_ms = probe.elapsed_ms(now);
        match found {
            Some(found) if is_own_address(found.addr, &own_ips) => tracing::info!(
                mapped = %found.addr,
                via = %found.server,
                attempts,
                elapsed_ms,
                "STUN: the mapped address is this machine's own, so there is no NAT to cross and \
                 the host candidates already cover it; no srflx candidate needed"
            ),
            Some(found) => match srflx_candidate(found.addr, host_ip, bound_port) {
                Ok(c) => {
                    tracing::info!(
                        attempts,
                        elapsed_ms,
                        "srflx candidate {} (via {})",
                        found.addr,
                        found.server
                    );
                    if rtc.add_local_candidate(c).is_some() {
                        srflx_addr = Some(found.addr);
                    } else {
                        tracing::warn!(mapped = %found.addr, "str0m refused the srflx candidate as redundant");
                    }
                }
                Err(e) => tracing::warn!("srflx candidate for {} not usable: {e:#}", found.addr),
            },
            None if probe.is_finished(now) => tracing::warn!(
                attempts,
                elapsed_ms,
                cause = probe.cause(),
                servers = %probe.describe(),
                "STUN: no srflx candidate and nothing left to try; the answer carries host \
                 candidates only, and a viewer that can reach this PC only through its relay \
                 will not connect"
            ),
            None => {
                tracing::warn!(
                    attempts,
                    elapsed_ms,
                    budget_ms = budget.as_millis() as u64,
                    cause = probe.cause(),
                    servers = %probe.describe(),
                    "STUN: no srflx candidate within the answer's budget; answering with host \
                     candidates only, retrying in the background, and trickling one if it arrives"
                );
                late_srflx = Some(LateSrflx {
                    probe,
                    lookups,
                    sdp_mid: None,
                    after: SRFLX_AFTER_ANSWER,
                    restarts: 0,
                });
            }
        }
    }

    let offer = SdpOffer::from_sdp_string(offer_sdp).context("parse SDP offer")?;
    let answer = rtc.sdp_api().accept_offer(offer).context("accept offer")?;
    let answer_sdp = answer.to_sdp_string();
    let answer_sdp = match hooks.as_mut() {
        Some(hooks) => hooks.answer(answer_sdp, local_addr)?,
        None => answer_sdp,
    };
    // The path book tells this generation's checks from a replaced one's by our ufrag in them.
    let mut paths = PathBook::default();
    paths.new_generation(Some(rtc.direct_api().local_ice_credentials().ufrag));
    // str0m answers a browser's `a=setup:actpass` with `passive` (`change/sdp.rs:763-781`): this
    // side is the DTLS server, which waits for the viewer's ClientHello and answers it with the
    // flight that carries its certificate.
    let dtls_role = DtlsRole::from_answer(&answer_sdp);
    tracing::debug!(
        bytes = answer_sdp.len(),
        answer = %sdp_summary(&answer_sdp),
        dtls_role = dtls_role.as_str(),
        "offer accepted; the answer"
    );
    if let Some(late) = late_srflx.as_mut() {
        late.sdp_mid = first_mid(&answer_sdp);
    }

    let outstanding_bytes = Arc::new(AtomicU32::new(0));
    let queued_media_bytes = Arc::new(AtomicU32::new(0));
    let drain_kbps = Arc::new(AtomicU32::new(0));
    let queue_age_ms = Arc::new(AtomicU32::new(0));
    let egress_kbps = Arc::new(AtomicU32::new(0));
    let egress_bytes_total = Arc::new(AtomicU64::new(0));
    let discarded_frames = Arc::new(AtomicU32::new(0));
    let nacks_received = Arc::new(AtomicU64::new(0));
    let path_changes = Arc::new(AtomicU32::new(0));
    let path_kind = Arc::new(AtomicU8::new(PATH_KIND_UNKNOWN));
    let path = Arc::new(PeerPathCell::default());
    let socket_bytes = Arc::new(crate::SocketBytes::default());
    // Two frames, not eight.
    //
    // This channel is pure latency: a frame sitting in it is committed, unsent, and invisible to
    // the viewer. Eight frames is 267 ms at a healthy 1.5 kB and **3.3 seconds** at the 44 kB
    // frames the last failing session actually produced — on a product whose hard limit is one
    // second end to end. The depth bought nothing, because the peer loop drains far faster than the
    // encoder fills: it turns every 7.6 ms against a frame every 33.
    //
    // Two rather than one so an ordinary scheduling hiccup does not park the encode thread on every
    // single frame. Parking it is now harmless in any case — the capturer paces unconditionally and
    // the frame channel keeps only the newest, so a stalled encoder costs stale frames, which are
    // counted, rather than back-pressure into a controller nobody owns.
    let (media_tx, media_rx) = mpsc::channel::<MediaSample>(2);
    // The viewer's candidates and re-offers, kept apart from the control queue below because none
    // of them may be refused the way a stale heartbeat may (a full control queue can drop ten
    // relays at once). See `crate::peer_signal`.
    let (signals, signal_rx) = signal_queue();
    let (control_tx, control_rx) = mpsc::channel::<PeerControl>(16);
    let (closer, close_signal) = PeerCloser::new();
    let (event_tx, event_rx) = mpsc::channel::<PeerEvent>(64);

    let mut peer_loop = PeerLoop {
        hooks,
        rtc,
        socket,
        local_addr,
        video_mid: None,
        input_channel: None,
        cursor_channel: None,
        cursor_lane: CursorLane::new(Instant::now()),
        reliable_out: std::collections::VecDeque::new(),
        reliable_out_bytes: 0,
        connected: false,
        viewer_goodbye: false,
        start: Instant::now(),
        events: event_tx,
        outstanding_bytes: outstanding_bytes.clone(),
        queued_media_bytes: queued_media_bytes.clone(),
        measured_drain: drain_kbps.clone(),
        queue_age: queue_age_ms.clone(),
        last_egress: egress_kbps.clone(),
        egress_total: egress_bytes_total.clone(),
        discarded: discarded_frames.clone(),
        nacks_received: nacks_received.clone(),
        path_changes: path_changes.clone(),
        path_kind: path_kind.clone(),
        path: path.clone(),
        socket_bytes: socket_bytes.clone(),
        relay_dest: std::collections::HashMap::new(),
        path_published_at: Instant::now(),
        media_route: None,
        remote_candidates,
        viewer_mix,
        viewer_addrs,
        viewer_mix_before: CandidateMix::default(),
        remote_ufrag: sdp_ice_ufrag(offer_sdp),
        public_host,
        held_answer: None,
        hold_clock,
        relay_only_answer_budget: tuning.relay_only_answer_budget,
        mdns: MdnsBook::default(),
        mdns_resolver: tuning.mdns,
        _timer_resolution: timer_resolution,
        desired_kbps: u32::try_from(DEFAULT_DESIRED_BITRATE_KBPS).unwrap_or(u32::MAX),
        str0m_desired_kbps: u32::try_from(DEFAULT_DESIRED_BITRATE_KBPS).unwrap_or(u32::MAX),
        armed_reanchor: None,
        last_frame_written: None,
        breaker: Breaker::default(),
        chain: RefChain::default(),
        keyframe_request_refused: false,
        estimate_kbps: u32::try_from(INITIAL_BITRATE_KBPS).unwrap_or(MIN_DRAIN_KBPS),
        bwe_can_probe: None,
        signals: signals.clone(),
        playout: PlayoutPolicy::default(),
        last_delay: PlayoutDelay::CLEAN,
        last_nacks: 0,
        rtx_trace: trace_rtx.then(RtxTrace::default),
        rtx_ssrc: None,
        playout_report_at: Instant::now(),
        egress: EgressMeter::new(),
        srflx: late_srflx,
        stun_servers,
        host_ip,
        bound_port,
        own_ips,
        srflx_addr,
        link: LinkWatch::default(),
        ice_grace: tuning.ice_grace,
        unsent_before_connect: 0,
        unsent_no_video: 0,
        kf_request_logged_at: None,
        kf_requests_held: 0,
        paths,
        dtls: DtlsWatch::default(),
        dtls_role,
        nominated: None,
        send_to: None,
        follow: FollowState::new(tuning.follow_viewer),
    };
    // The offer's mDNS hosts, which str0m kept as unused attributes: looked up like trickled ones,
    // their results coming back through the signal queue once the loop runs.
    for (cand, name) in offered_by_viewer.mdns {
        peer_loop.resolve_mdns(cand, name, "offer");
    }

    let peer = Peer {
        answer_sdp,
        media_tx,
        signals,
        control_tx,
        closer,
        events: event_rx,
        outstanding_bytes,
        queued_media_bytes,
        drain_kbps,
        queue_age_ms,
        egress_kbps,
        egress_bytes_total,
        discarded_frames,
        nacks_received,
        path_changes,
        path_kind,
        path,
        socket_bytes,
    };
    let task = tokio::spawn(peer_loop.run(media_rx, signal_rx, control_rx, close_signal));
    Ok((peer, task))
}

/// How often a running peer refreshes its published [`PeerPath`] besides its transitions: what an
/// end the orchestrator makes (the kill switch, a capture lost) reads, so at most this stale.
const PATH_PUBLISH_EVERY: Duration = Duration::from_secs(1);

struct PeerLoop {
    /// A host-driven peer's hooks (`crate::host_peer`); `None` for the agent's own peers.
    hooks: Option<Box<dyn PeerHooks>>,
    rtc: Rtc,
    /// The socket itself, or behind the bench link shaper. See `crate::socket`.
    socket: PeerSocket,
    local_addr: SocketAddr,
    video_mid: Option<Mid>,
    input_channel: Option<ChannelId>,
    cursor_channel: Option<ChannelId>,
    /// What goes on `cursor` while the viewer's SCTP acknowledges nothing and the viewer is known to
    /// be out of reach: held, newest only, and one kick when it is back. See `crate::cursor_lane`,
    /// [`Self::step_cursor_lane`] and [`Self::gate_cursor_lane`].
    cursor_lane: CursorLane,
    /// Messages for the viewer on `input` not written yet ([`PeerControl::SendReliable`],
    /// [`PeerControl::SendRevocable`]), and their bytes. Written at the top of every turn while the
    /// channel's buffer has room and the `cursor` lane is not stalled.
    reliable_out: std::collections::VecDeque<QueuedReliable>,
    reliable_out_bytes: usize,
    connected: bool,
    /// The viewer's DTLS or SCTP said goodbye (str0m's `Event::Closed`): the connection str0m
    /// closes after it ends the peer as [`PeerEnd::ViewerClosed`], not [`PeerEnd::RtcClosed`].
    viewer_goodbye: bool,
    start: Instant,
    events: mpsc::Sender<PeerEvent>,
    /// Published to the capture thread; see [`Peer::outstanding_bytes`].
    outstanding_bytes: Arc<AtomicU32>,
    /// Bytes sitting in the channel between the encode thread and this loop.
    ///
    /// Part of the latency signal, and for the life of this field it contributed nothing. It used
    /// to be a plain `u32` set immediately before the synchronous `write_media` and cleared
    /// immediately after — both inside one `select!` arm, with no `.await` between them — while the
    /// only reader, [`Self::sample_send_queue`], runs at the top of the *next* iteration. **It was
    /// provably zero every time it was read.** The comment above it claimed "a frame is never
    /// invisible"; the channel's whole depth was invisible.
    ///
    /// It is now a counter shared with the producer: the encode thread adds a frame's bytes before
    /// `blocking_send`, and this loop subtracts them once the frame is inside str0m's send queue,
    /// where `queue_info()` takes over the accounting. A frame is therefore counted exactly once,
    /// in one place or the other, for the whole time it is committed and unsent.
    queued_media_bytes: Arc<AtomicU32>,
    /// Measured egress, as a decaying peak, in kbps. See [`Peer::drain_kbps`] for why this rather
    /// than the bandwidth estimate.
    measured_drain: Arc<AtomicU32>,
    /// Measured egress of the window just ended, unsmoothed. See [`Peer::egress_kbps`].
    last_egress: Arc<AtomicU32>,
    /// See [`Peer::egress_bytes_total`]. Monotonic; the reader picks the window.
    egress_total: Arc<AtomicU64>,
    /// Encoded frames not sent: the breaker's discards and the deltas [`RefChain`] held. See
    /// [`Peer::discarded_frames`].
    discarded: Arc<AtomicU32>,
    /// See [`Peer::nacks_received`]. Counted in [`Self::note_raw_packet`].
    nacks_received: Arc<AtomicU64>,
    /// See [`Peer::path_changes`].
    path_changes: Arc<AtomicU32>,
    /// See [`Peer::path_kind`]. Stored by [`Self::note_selected_pair`].
    path_kind: Arc<AtomicU8>,
    /// See [`Peer::path`]. Published by [`Self::publish_path`].
    path: Arc<PeerPathCell>,
    /// See [`Peer::socket_bytes`]. Counted in [`Self::drain`], after each send the socket took.
    socket_bytes: Arc<crate::SocketBytes>,
    /// Whether each destination [`Self::socket_bytes`] counted for is a relay candidate, so a
    /// datagram is one lookup rather than a look through the viewer's candidates. Emptied whenever
    /// those change, and at a re-offer (a restart moves the media).
    relay_dest: std::collections::HashMap<SocketAddr, bool>,
    /// When [`Self::path`] was last refreshed on the clock ([`PATH_PUBLISH_EVERY`]).
    path_published_at: Instant,
    /// The local and remote address the last RTP/RTCP datagram left on, to notice ICE moving the
    /// media to another candidate pair. `None` until the first one. See [`Self::note_transmit`].
    media_route: Option<(SocketAddr, SocketAddr)>,
    /// Every candidate the viewer offered — in the offer, a restart's offer, or trickled — by
    /// address, to name the pair the media takes. See [`Self::note_selected_pair`].
    remote_candidates: Vec<RemoteCandidate>,
    /// The kinds of candidate the viewer has offered in the current ICE generation, and in the
    /// last earlier one that had any: whether it is relay-only. See [`srflx_need`].
    viewer_mix: CandidateMix,
    /// The addresses counted in [`Self::viewer_mix`]: a candidate signalled again — the Mini App's
    /// resume re-sends its offer with the candidates in it, then trickles them again — is counted
    /// once. See [`Self::note_viewer_candidate`].
    viewer_addrs: Vec<SocketAddr>,
    viewer_mix_before: CandidateMix,
    /// The viewer's ICE ufrag of the current generation, from its last applied offer: a trickled
    /// candidate stamped with another belongs to a generation already replaced.
    remote_ufrag: Option<String>,
    /// Whether one of our host candidates is a public address, which a TURN relay forwards to.
    public_host: bool,
    /// A re-offer's answer waiting for the srflx discovery. See [`Self::renegotiate`].
    held_answer: Option<HeldAnswer>,
    /// When an answer for the viewer's ICE generation first waited for the srflx discovery. See
    /// [`HoldClock`].
    hold_clock: Option<HoldClock>,
    /// [`stun::RELAY_ONLY_ANSWER_BUDGET`], unless a test shortened it.
    relay_only_answer_budget: Duration,
    /// Every mDNS name the viewer signalled that was looked up or is being looked up, so one name
    /// is asked once. See [`Self::resolve_mdns`].
    mdns: MdnsBook,
    /// [`Tuning::mdns`].
    mdns_resolver: MdnsResolver,
    /// Published age of the oldest unsent packet. See [`Peer::queue_age_ms`].
    queue_age: Arc<AtomicU32>,
    /// This peer's request for a 1 ms timer resolution, withdrawn when the loop ends. Without it a
    /// timer wake on Windows lands on the 15.6 ms system tick, and str0m's probe clusters — one
    /// burst per wake — measure a fraction of what they test. See `crate::timer`.
    _timer_resolution: crate::timer::HighResolution,
    /// The ceiling the orchestrator last set with [`PeerControl::SetDesiredBitrate`], in kbps.
    /// Kept because a re-anchor lowers str0m's copy for one call and has to put this back; see
    /// [`reanchor_bwe`].
    desired_kbps: u32,
    /// The ceiling str0m has, in kbps (outside a re-anchor's one call): `desired_kbps`, unless that
    /// is waiting for the next video frame ([`ceiling_waits_for_video`]).
    str0m_desired_kbps: u32,
    /// A [`PeerControl::ResetBweAtNextFrame`] waiting for its frame: the value, and when it came.
    armed_reanchor: Option<(u32, Instant)>,
    /// When a video frame was last handed to str0m. See [`REANCHOR_FLOWING_WITHIN`].
    last_frame_written: Option<Instant>,
    /// A loopback into this peer's own signal queue, so work that cannot happen on the run loop —
    /// an mDNS lookup with a timeout — can hand its result back through the one path that already
    /// exists for candidates. Also where the queue's counts are read for the log
    /// ([`SignalSender::counts`]), and what keeps the queue open while the loop runs.
    signals: SignalSender,
    /// Bounds the send queue by discarding. See [`Breaker`].
    breaker: Breaker,
    /// Whether the viewer's decoder holds every reference the next frame needs. See [`RefChain`].
    chain: RefChain,
    /// Whether the last keyframe request this peer made of the encoder was refused by the event
    /// queue, so a run of refusals is one warning rather than one per held frame.
    keyframe_request_refused: bool,
    /// The last bandwidth estimate, in kbps. The divisor that turns queued bytes into
    /// milliseconds, and the only rate this loop knows.
    estimate_kbps: u32,
    /// What str0m's last TWCC estimate said about probing (`BweKind::Twcc::can_probe`, str0m 0.24),
    /// `None` before the first. Kept to log the changes: while it is `false` str0m holds the
    /// estimate where it was and sends no updates, so the controller would be reading a frozen
    /// number.
    bwe_can_probe: Option<bool>,
    /// Which `playout-delay` pair goes on each frame, from the receiver's reports. The round trip
    /// and the loss it is sized from are kept there, not here: the frame that needs them is written
    /// by this loop, not by the orchestrator. See `crate::playout`.
    playout: PlayoutPolicy,
    /// The pair written on the last frame, for the once-a-second `playout` line.
    last_delay: PlayoutDelay,
    /// The NACK count of the previous receiver report.
    ///
    /// str0m's counter is cumulative for the session, so "the link is losing packets right now" is
    /// an *increase* here, not a non-zero value — comparing against zero would latch the lossy pair
    /// on for the rest of the session after one bad second.
    last_nacks: u64,
    /// Every NACK and the retransmission that answered it, when debug logging was on as the peer
    /// started (it reads str0m's raw-packet mirror, which is on at every level for
    /// [`Self::nacks_received`]). See `crate::playout::RtxTrace`.
    rtx_trace: Option<RtxTrace>,
    /// The RTX SSRC str0m allocated for the video stream: a sent packet on it is a retransmission
    /// or padding. Set when the video m-line is added.
    rtx_ssrc: Option<str0m::rtp::Ssrc>,
    /// When the `playout` line was last written.
    playout_report_at: Instant,
    /// What actually left the socket, and how often the engine got a turn.
    ///
    /// Separate from the encoder's own byte count on purpose: the gap between the two *is* the
    /// send queue, and for the life of this project nothing measured it. The pipeline log reported
    /// what the encoder produced and called it the bitrate, so a session that produced 2800 kbps
    /// and delivered 1634 looked healthy from the inside while the viewer watched a ten-second-old
    /// desktop.
    egress: EgressMeter,
    /// A STUN transaction running on the loop: the one the answer could not wait for, or the one an
    /// ICE restart started — an ICE restart continues one still running rather than replacing it.
    /// `None` in the ordinary case, where the answer already carries the srflx candidate. See
    /// [`Self::drive_srflx`] and [`Self::start_srflx`].
    srflx: Option<LateSrflx>,
    /// The session's STUN servers ("host:port"), kept so an ICE restart can ask them again.
    stun_servers: Vec<String>,
    /// The base and port a srflx candidate line names, exactly as the answer's own did.
    host_ip: Ipv4Addr,
    bound_port: u16,
    /// This machine's addresses: a mapping onto one of them is not a NAT's and needs no candidate.
    own_ips: Vec<Ipv4Addr>,
    /// The mapping the `Rtc` has as a local candidate, if any. str0m keeps local candidates across
    /// an ICE restart, so the restart's answer already carries it, and a discovery that finds it
    /// again has nothing to trickle.
    srflx_addr: Option<SocketAddr>,
    /// The ICE path and its grace window. See [`LinkWatch`] and [`ICE_GRACE`].
    link: LinkWatch,
    /// [`ICE_GRACE`], unless a test shortened it.
    ice_grace: Duration,
    /// Frames the encoder sent before the connection was up, and so never written. Expected — the
    /// encode thread starts with the answer — and said once, on `Connected`, as a count.
    unsent_before_connect: u64,
    /// Frames not written although the connection was up: no video m-line, no writer, or no H.264
    /// payload type. A black picture with every other number healthy, so the first one is a
    /// warning and the rest are counted.
    unsent_no_video: u64,
    /// When a viewer keyframe request was last logged, and how many were held back since. See
    /// [`Self::note_keyframe_request`].
    kf_request_logged_at: Option<Instant>,
    kf_requests_held: u32,
    /// Every datagram str0m sent and every one handed to it, by remote address, way and kind
    /// (STUN, DTLS with the handshake messages in it, RTP/RTCP, other). Only counted per datagram;
    /// read by the few aggregated lines that need it. See `crate::paths`.
    paths: PathBook,
    /// ICE connected, DTLS not yet: the stall warning's clock. See `crate::paths::DtlsWatch`.
    dtls: DtlsWatch,
    /// This side of the DTLS handshake, from the answer's `a=setup`.
    dtls_role: DtlsRole,
    /// The (local base, remote) pair str0m nominated for sending, from its once-a-second
    /// `PeerStats`; `None` until a report names one. See [`Self::note_peer_stats`].
    nominated: Option<(SocketAddr, SocketAddr)>,
    /// Where str0m's last DTLS or RTP/RTCP datagram went: its send pair, exactly and at once
    /// (every one of them goes to `send_addr`, `str0m-0.23.1/src/lib.rs:1804-1818`). `None`
    /// before the first. See [`Self::note_send_path`].
    send_to: Option<SocketAddr>,
    /// Taking str0m off a send pair the viewer does not answer on. See [`Self::follow_viewer`].
    follow: FollowState,
}

/// Where a srflx discovery on the run loop came from, for the log.
const SRFLX_AFTER_ANSWER: &str = "answer";
const SRFLX_AFTER_RESTART: &str = "ice_restart";

/// A server-reflexive discovery running on the run loop.
///
/// Carried by the run loop because the mapping has to be the one *this* socket has, so the
/// requests go out on it and the replies arrive in its receive path, where they are picked out
/// before str0m sees them.
struct LateSrflx {
    probe: stun::Probe,
    lookups: mpsc::UnboundedReceiver<stun::Resolved>,
    /// The first m-line of the answer that preceded it, which is what the trickled candidate names
    /// as its `sdpMid`.
    sdp_mid: Option<String>,
    /// [`SRFLX_AFTER_ANSWER`] or [`SRFLX_AFTER_RESTART`]: what its result is for now.
    after: &'static str,
    /// ICE restarts it was continued through. See [`PeerLoop::start_srflx`].
    restarts: u32,
}

/// The kinds of candidate the viewer offered in one ICE generation: relays, and anything else.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct CandidateMix {
    relay: u32,
    other: u32,
}

impl CandidateMix {
    /// Each address once: an SDP may list a candidate under every m-line it bundles.
    fn of(candidates: &[RemoteCandidate]) -> Self {
        let mut mix = Self::default();
        for (i, c) in candidates.iter().enumerate() {
            if !candidates[..i].iter().any(|k| k.addr == c.addr) {
                mix.note(c.kind);
            }
        }
        mix
    }

    fn note(&mut self, kind: CandidateKind) {
        if kind == CandidateKind::Relayed {
            self.relay += 1;
        } else {
            self.other += 1;
        }
    }

    fn is_empty(self) -> bool {
        self.relay == 0 && self.other == 0
    }
}

/// Whether an answer needs a srflx candidate to work at all, and if not, why not. Decides how
/// long an answer waits for one: see [`stun::RELAY_ONLY_ANSWER_BUDGET`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SrflxNeed {
    /// The viewer offered only relays, and none of our candidates is one a relay forwards to.
    Required,
    /// A srflx candidate is offered already (str0m keeps local candidates across a restart).
    Offered,
    /// One of our host candidates is public.
    PublicHost,
    /// The viewer offered something besides relays: a path can form without our public address
    /// (our checks to its srflx open the NAT, or it is on our network).
    ViewerNotRelayOnly,
    /// The viewer has offered no candidate yet — it trickles them — so nothing says it is
    /// relay-only.
    ViewerUnknown,
}

impl SrflxNeed {
    fn as_str(self) -> &'static str {
        match self {
            SrflxNeed::Required => "required",
            SrflxNeed::Offered => "srflx_offered",
            SrflxNeed::PublicHost => "public_host",
            SrflxNeed::ViewerNotRelayOnly => "viewer_not_relay_only",
            SrflxNeed::ViewerUnknown => "viewer_unknown",
        }
    }
}

/// See [`SrflxNeed`]. `mix` is the viewer's candidates as far as they are known.
fn srflx_need(mix: CandidateMix, srflx_offered: bool, public_host: bool) -> SrflxNeed {
    if srflx_offered {
        SrflxNeed::Offered
    } else if public_host {
        SrflxNeed::PublicHost
    } else if mix.is_empty() {
        SrflxNeed::ViewerUnknown
    } else if mix.other > 0 {
        SrflxNeed::ViewerNotRelayOnly
    } else {
        SrflxNeed::Required
    }
}

/// Whether a TURN relay forwards to this address: not private, loopback, link-local, shared
/// (100.64/10, carrier-grade NAT), reserved, documentation or multicast. Cloudflare's refuses a
/// permission for any of those, and they are what a host candidate behind a NAT has.
fn is_public_v4(ip: Ipv4Addr) -> bool {
    let [a, b, ..] = ip.octets();
    !(ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_unspecified()
        || ip.is_broadcast()
        || ip.is_documentation()
        || ip.is_multicast()
        || a == 0
        || (a == 100 && (64..128).contains(&b))
        || (a == 198 && (b == 18 || b == 19))
        || a >= 240)
}

/// The `a=ice-ufrag` of an SDP (the first one: the Mini App bundles, so every m-line has the same).
fn sdp_ice_ufrag(sdp: &str) -> Option<String> {
    sdp.lines()
        .find_map(|l| l.trim_end().strip_prefix("a=ice-ufrag:"))
        .map(str::to_string)
}

/// A re-offer's answer held back until the srflx discovery has a mapping. See
/// [`PeerLoop::renegotiate`].
struct HeldAnswer {
    sdp: String,
    /// Our ufrag in it, for the log.
    ufrag: String,
    /// [`HOLD_RESTART`] or [`HOLD_RESENT`]: what the offer it answers was, for the log.
    offer: &'static str,
    /// When the first offer this hold answers arrived: a newer offer that supersedes a held answer
    /// inherits its clock, so one restart never waits more than the budget in all.
    since: Instant,
    /// When it goes out whatever has happened.
    deadline: Instant,
}

/// What a held answer answers, as its log lines name it: an ICE restart's offer (new credentials),
/// or an offer with unchanged credentials — in practice the Mini App re-sending, after its
/// signalling socket came back, an offer whose answer it never got.
const HOLD_RESTART: &str = "restart";
const HOLD_RESENT: &str = "re-sent offer";

/// When an answer for one ICE generation of the viewer's first waited for the srflx discovery: the
/// first answer's wait with the relay-only budget, or a re-offer's hold. Every later answer to an
/// offer of the same generation — the same offer sent again — shares that one budget, as a restart
/// shares it with the offers that supersede its held answer: the viewer has been waiting since.
#[derive(Debug, Clone)]
struct HoldClock {
    /// The viewer's ufrag of that generation.
    ufrag: Option<String>,
    since: Instant,
}

/// How often the run loop looks for a DNS answer while a STUN server name is still resolving.
///
/// The loop has no wake-up for that channel of its own; before ICE connects it turns far more often
/// than this anyway (media frames arrive at 30-60 a second), so this only bounds the worst case.
const SRFLX_DNS_POLL: Duration = Duration::from_millis(50);

/// The srflx candidate for a STUN mapping.
///
/// The same line the answer has always carried — foundation, priority and all — whether it goes
/// out in the answer or is trickled afterwards, so the late path is not a second, untested shape.
fn srflx_candidate(mapped: SocketAddr, host_ip: Ipv4Addr, bound_port: u16) -> Result<Candidate> {
    let line = format!(
        "candidate:2 1 udp 1694498815 {} {} typ srflx raddr {} rport {}",
        mapped.ip(),
        mapped.port(),
        host_ip,
        bound_port,
    );
    Candidate::from_sdp_string(&line).with_context(|| format!("bad srflx candidate line {line:?}"))
}

/// Whether a datagram's first byte says RTP or RTCP (SRTP/SRTCP on the wire): RFC 7983's
/// demultiplexing range, 128 to 191. STUN is 0-3 and DTLS 20-63.
fn is_rtp_or_rtcp(first: u8) -> bool {
    (128..=191).contains(&first)
}

/// What one outgoing datagram said about the media path. See [`media_route_note`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RouteNote {
    /// Not RTP or RTCP: a STUN check, DTLS, SCTP — says nothing about the selected pair.
    NotMedia,
    /// The session's first media datagram.
    First,
    /// Media on the route it was already taking.
    Same,
    /// Media on a new (local, remote) pair; `from` is the one it left.
    Changed { from: (SocketAddr, SocketAddr) },
}

/// Track the (local, remote) pair media leaves on. Pure, for the tests; see
/// `PeerLoop::note_transmit` for why the first byte decides what counts.
fn media_route_note(
    route: &mut Option<(SocketAddr, SocketAddr)>,
    source: SocketAddr,
    destination: SocketAddr,
    first: Option<u8>,
) -> RouteNote {
    if !first.is_some_and(is_rtp_or_rtcp) {
        return RouteNote::NotMedia;
    }
    match route.replace((source, destination)) {
        None => RouteNote::First,
        Some(from) if from != (source, destination) => RouteNote::Changed { from },
        Some(_) => RouteNote::Same,
    }
}

/// A candidate the viewer offered, kept so the pair the media takes can be named: its kind, its
/// transport, and — for a relay — how the viewer reaches its TURN server. See
/// [`PeerLoop::note_selected_pair`]. And the candidate itself, parsed from the same line str0m
/// parsed, so it can be withdrawn from str0m again: `invalidate_candidate` finds a remote by its
/// address, base, related address and kind (`is-0.11.0/src/agent.rs:956-966`), all of which the
/// line decides. See [`PeerLoop::leave_send_path`].
#[derive(Debug, Clone, PartialEq, Eq)]
struct RemoteCandidate {
    addr: SocketAddr,
    kind: CandidateKind,
    proto: Protocol,
    prio: u32,
    candidate: Candidate,
}

impl RemoteCandidate {
    fn of(c: &Candidate) -> Self {
        Self {
            addr: c.addr(),
            kind: c.kind(),
            proto: c.proto(),
            prio: c.prio(),
            candidate: c.clone(),
        }
    }
}

/// Keep `c` in `book`, replacing an earlier one at the same address: a restart's offer or a later
/// trickle describes the same address anew.
fn remember_candidate(book: &mut Vec<RemoteCandidate>, c: RemoteCandidate) {
    match book.iter_mut().find(|k| k.addr == c.addr) {
        Some(k) => *k = c,
        None => book.push(c),
    }
}

/// What an SDP's own `a=candidate:` lines hold. See [`sdp_candidates`].
#[derive(Debug, Default)]
struct SdpCandidates {
    /// The lines a candidate parses from: str0m adds these itself when it applies the SDP.
    parsed: Vec<RemoteCandidate>,
    /// The mDNS hosts (`<uuid>.local`), which str0m keeps as an unused attribute: each as the
    /// trickled candidate it would have been — its m-line's mid and index, and its generation's
    /// ufrag, stamped on the line too (unless it carries one) so str0m refuses it once that
    /// generation is replaced, as it does a browser's trickled line — with the name to look up.
    mdns: Vec<(IceCandidate, String)>,
    /// Every other line, with why it was not read: said, never used.
    rejected: Vec<String>,
}

impl SdpCandidates {
    /// One debug line per SDP that has candidates: what was read, what goes to the mDNS lookup,
    /// and what nothing can read.
    fn log(&self, source: &'static str) {
        let lines = self.parsed.len() + self.mdns.len() + self.rejected.len();
        if lines == 0 {
            return;
        }
        let names: Vec<&str> = self.mdns.iter().map(|(_, name)| name.as_str()).collect();
        tracing::debug!(
            source,
            lines,
            parsed = self.parsed.len(),
            mdns = self.mdns.len(),
            mdns_names = ?names,
            rejected = self.rejected.len(),
            rejected_lines = ?self.rejected,
            "the viewer's SDP carries candidates: parsed ones str0m adds itself, mDNS hosts go to \
             the lookup (str0m cannot read a name), rejected ones are not used"
        );
    }
}

/// The candidates an SDP carries on its own `a=candidate:` lines, sorted into what str0m reads, the
/// mDNS hosts it cannot, and the rest.
///
/// An mDNS host is usually trickled, and resolved on that path. Not always: the Mini App's resume
/// re-sends its offer with the candidates it trickled into a dead socket in it (`webrtc.ts`,
/// `pendingLocalDescription`), and those trickles never arrived. So the offer's own mDNS lines are
/// looked up too ([`PeerLoop::resolve_mdns`]), each name once.
fn sdp_candidates(sdp: &str) -> SdpCandidates {
    // A section's ufrag and mid can come after its candidates (Chrome writes `a=candidate` before
    // `a=ice-ufrag` and `a=mid`), so the sections are read whole first. The first is the session
    // part, before any `m=`, whose ufrag a section without its own inherits.
    struct Section<'a> {
        index: Option<u16>,
        mid: Option<&'a str>,
        ufrag: Option<&'a str>,
        candidates: Vec<&'a str>,
    }
    let mut sections = vec![Section {
        index: None,
        mid: None,
        ufrag: None,
        candidates: Vec::new(),
    }];
    for line in sdp.lines().map(str::trim_end) {
        if line.starts_with("m=") {
            let index = u16::try_from(sections.len() - 1).ok();
            sections.push(Section {
                index,
                mid: None,
                ufrag: None,
                candidates: Vec::new(),
            });
            continue;
        }
        let Some(attr) = line.strip_prefix("a=") else {
            continue;
        };
        let Some(section) = sections.last_mut() else {
            continue;
        };
        if let Some(mid) = attr.strip_prefix("mid:") {
            section.mid = Some(mid);
        } else if let Some(ufrag) = attr.strip_prefix("ice-ufrag:") {
            section.ufrag = Some(ufrag);
        } else if attr.starts_with("candidate:") {
            section.candidates.push(attr);
        }
    }
    let session_ufrag = sections.first().and_then(|s| s.ufrag);
    let mut out = SdpCandidates::default();
    for section in &sections {
        let ufrag = section.ufrag.or(session_ufrag);
        for &line in &section.candidates {
            match Candidate::from_sdp_string(line) {
                Ok(c) => out.parsed.push(RemoteCandidate::of(&c)),
                Err(e) => match mdns_host_name(line) {
                    Some(name) => {
                        let stamped = line.split_whitespace().skip(8).any(|w| w == "ufrag");
                        let candidate = match ufrag {
                            Some(u) if !stamped => format!("{line} ufrag {u}"),
                            _ => line.to_string(),
                        };
                        let cand = IceCandidate {
                            candidate,
                            sdp_mid: section.mid.map(str::to_string),
                            sdp_mline_index: section.index,
                            username_fragment: ufrag.map(str::to_string),
                        };
                        out.mdns.push((cand, name));
                    }
                    None => out.rejected.push(e.to_string()),
                },
            }
        }
    }
    out
}

/// How a relay candidate reaches its TURN server, read from its ICE priority, or `unknown`.
///
/// The candidate line itself says only how the *relay* talks to us (always UDP from a TURN
/// server). The leg between the viewer and the relay is in the priority: libwebrtc — Chrome, and
/// the WebKit of Telegram on iOS and macOS — sets a relay candidate's type preference, the top
/// byte, from that leg's transport (`ICE_TYPE_PREFERENCE_RELAY_UDP` 2, `_TCP` 1, `_TLS` 0,
/// `p2p/base/port.h`). An iPhone viewer has been seen offering relays at 16785663 and 16786431
/// (TCP) and 8959 and 8191 (TLS) and nothing over UDP — a relay over TCP/TLS, whose round trip ran
/// 180-450 ms idle. Other stacks may encode it differently; hence `unknown` for any
/// other value.
fn relay_transport(prio: u32) -> &'static str {
    match prio >> 24 {
        2 => "udp",
        1 => "tcp",
        0 => "tls",
        _ => "unknown",
    }
}

/// The remote end of the pair media leaves on, in words for the log: its kind, its transport, the
/// relay's transport to the viewer (`-` when not a relay), and its priority. A destination the
/// viewer never signalled is a peer-reflexive candidate ICE learned from a connectivity check.
fn describe_remote(
    book: &[RemoteCandidate],
    destination: SocketAddr,
) -> (String, String, &'static str, Option<u32>) {
    match book.iter().find(|c| c.addr == destination) {
        Some(c) => (
            c.kind.to_string(),
            format!("{:?}", c.proto).to_ascii_lowercase(),
            if c.kind == CandidateKind::Relayed {
                relay_transport(c.prio)
            } else {
                "-"
            },
            Some(c.prio),
        ),
        None => (
            "prflx (not signalled)".to_string(),
            "udp".to_string(),
            "-",
            None,
        ),
    }
}

/// What the viewer said an address is, in a word for the path lines: `host`, `srflx`, `prflx`,
/// `relay/<udp|tcp|tls|unknown>` (the leg between the viewer and its TURN server, see
/// [`relay_transport`]), or `unsignalled` — an address the viewer never offered: a peer-reflexive
/// candidate ICE learned from a check, or anything else that wrote to the socket.
fn short_kind(book: &[RemoteCandidate], addr: SocketAddr) -> String {
    match book.iter().find(|c| c.addr == addr) {
        Some(c) if c.kind == CandidateKind::Relayed => {
            format!("relay/{}", relay_transport(c.prio))
        }
        Some(c) => c.kind.to_string(),
        None => "unsignalled".to_string(),
    }
}

/// Whether a STUN mapping is one of this machine's own addresses: no NAT in between.
fn is_own_address(mapped: SocketAddr, own_ips: &[Ipv4Addr]) -> bool {
    matches!(mapped.ip(), IpAddr::V4(v4) if own_ips.contains(&v4))
}

/// The `a=mid` of an SDP's first m-line.
fn first_mid(sdp: &str) -> Option<String> {
    sdp.lines()
        .find_map(|l| l.trim_end().strip_prefix("a=mid:"))
        .map(str::to_string)
}

/// What an SDP negotiates, on one line, for the log: each m-line with its mid, direction, codecs
/// (H.264 with its profile and packetization mode) and header extensions, then the candidates by
/// type, the ICE ufrag and the DTLS `a=setup` (the first m-line's: `actpass` in an offer, and in
/// our answer `passive` — this side is the DTLS server).
///
/// Built for the two questions a failed session asks of its SDP — "was H.264 at a profile the
/// browser decodes on the table" and "did the extension this end relies on survive" — without the
/// kilobytes of the SDP itself. Never the `ice-pwd` or the DTLS fingerprint: neither answers either
/// question, and the password is a credential for the length of the session.
fn sdp_summary(sdp: &str) -> String {
    use std::collections::BTreeMap;
    use std::fmt::Write as _;

    struct Section {
        media: String,
        mid: String,
        dir: &'static str,
        // pt -> encoding name/clock rate, in the order the m-line lists them.
        codecs: Vec<(String, String)>,
        fmtp: BTreeMap<String, String>,
        ext: Vec<String>,
    }
    let mut sections: Vec<Section> = Vec::new();
    let mut candidates: BTreeMap<String, u32> = BTreeMap::new();
    let mut ufrag = "-".to_string();
    let mut setup: Option<&str> = None;
    for line in sdp.lines().map(str::trim_end) {
        if let Some(s) = line.strip_prefix("a=setup:") {
            setup.get_or_insert(s);
        }
        if let Some(m) = line.strip_prefix("m=") {
            sections.push(Section {
                media: m.split_whitespace().next().unwrap_or("?").to_string(),
                mid: "-".to_string(),
                dir: "-",
                codecs: Vec::new(),
                fmtp: BTreeMap::new(),
                ext: Vec::new(),
            });
            continue;
        }
        if let Some(u) = line.strip_prefix("a=ice-ufrag:") {
            ufrag = u.to_string();
        }
        if let Some(c) = line.strip_prefix("a=candidate:") {
            let kind = c
                .split_whitespace()
                .skip_while(|w| *w != "typ")
                .nth(1)
                .unwrap_or("?");
            *candidates.entry(kind.to_string()).or_default() += 1;
            continue;
        }
        let Some(s) = sections.last_mut() else {
            continue;
        };
        if let Some(mid) = line.strip_prefix("a=mid:") {
            s.mid = mid.to_string();
        } else if let Some((pt, codec)) = line
            .strip_prefix("a=rtpmap:")
            .and_then(|r| r.split_once(' '))
        {
            s.codecs.push((pt.to_string(), codec.to_string()));
        } else if let Some((pt, params)) =
            line.strip_prefix("a=fmtp:").and_then(|r| r.split_once(' '))
        {
            s.fmtp.insert(pt.to_string(), params.to_string());
        } else if let Some(ext) = line.strip_prefix("a=extmap:") {
            let (id, uri) = ext.split_once(' ').unwrap_or((ext, ""));
            let uri = uri.split_whitespace().next().unwrap_or("");
            let short = uri.rsplit(['/', ':']).next().unwrap_or(uri);
            s.ext.push(format!("{id}:{short}"));
        } else if let Some(dir) = line.strip_prefix("a=").and_then(|a| {
            ["sendrecv", "sendonly", "recvonly", "inactive"]
                .into_iter()
                .find(|d| *d == a)
        }) {
            s.dir = dir;
        }
    }
    let mut out = String::new();
    for s in &sections {
        let mut codecs: Vec<String> = Vec::new();
        // H.264 in full (its fmtp decides whether the browser can decode it); everything else
        // counted by name, so a Chrome offer's twenty payload types stay one short list.
        let mut others: BTreeMap<&str, u32> = BTreeMap::new();
        for (pt, codec) in &s.codecs {
            let name = codec.split('/').next().unwrap_or(codec);
            if name.eq_ignore_ascii_case("H264") {
                let fmtp = s.fmtp.get(pt).map_or("", String::as_str);
                let param = |key: &str| {
                    fmtp.split(';')
                        .find_map(|p| p.trim().strip_prefix(key))
                        .unwrap_or("-")
                        .to_string()
                };
                codecs.push(format!(
                    "{pt}:H264(profile={},mode={})",
                    param("profile-level-id="),
                    param("packetization-mode=")
                ));
            } else {
                *others.entry(name).or_default() += 1;
            }
        }
        for (name, n) in others {
            codecs.push(if n > 1 {
                format!("{name}x{n}")
            } else {
                name.to_string()
            });
        }
        let _ = write!(
            out,
            "m={} mid={} dir={} codecs=[{}] ext=[{}]; ",
            s.media,
            s.mid,
            s.dir,
            codecs.join(","),
            s.ext.join(",")
        );
    }
    let cands: Vec<String> = candidates.iter().map(|(k, n)| format!("{k}={n}")).collect();
    let _ = write!(
        out,
        "candidates=[{}] ufrag={ufrag} setup={}",
        cands.join(","),
        setup.unwrap_or("-")
    );
    out
}

/// A one-second window of what the peer loop actually did.
struct EgressMeter {
    window_start: Instant,
    /// Trips round the run loop. str0m releases at most one RTP packet per trip, so this is the
    /// hard ceiling on the packet rate and the first thing to check when egress is short.
    turns: u64,
    bytes: u64,
    packets: u64,
    /// Which `select!` arm woke each turn.
    ///
    /// Free, and it settles a question that two separate analyses of the same log could not: a turn
    /// rate that tracks the packet rate one-for-one is *either* the pacer doing its job — one packet
    /// per `handle_input`, at an interval the estimate sets — *or* a loop whose wake-up is quantised
    /// by the platform timer. The arithmetic fits both, and the difference decides whether egress is
    /// bounded by the link or by this process.
    ///
    /// `timer` dominating with a full queue is the pacer; `timer` dominating with an *empty* queue
    /// is this loop spinning. One number instead of an argument.
    woke_timer: u64,
    woke_socket: u64,
    woke_media: u64,
    /// How late the timer arm fired, over the wakes where the loop actually slept (a wait above
    /// zero): how many, the sum and the worst lateness in microseconds, and how many were 4 ms or
    /// more late — the signature of the 15.6 ms system tick. What `crate::timer` is for, measured
    /// on the session itself rather than assumed from the policy: on the default tick a 2 ms sleep
    /// comes back ~14 ms late, with a 1 ms period about a millisecond late.
    timer_sleeps: u64,
    timer_late_us_sum: u64,
    timer_late_us_max: u64,
    timer_late_4ms: u64,
    /// Datagrams the socket refused in this window, and the last reason. Per packet they are trace;
    /// a window with any is one debug line, because a socket refusing packets is loss on our own
    /// side that no receiver report will ever explain.
    send_errors: u64,
    last_send_error: Option<String>,
    /// Frames str0m's writer refused in this window, and the last reason. Same treatment.
    write_errors: u64,
    last_write_error: Option<String>,
}

impl EgressMeter {
    const WINDOW: Duration = Duration::from_secs(1);

    fn new() -> Self {
        Self {
            window_start: Instant::now(),
            turns: 0,
            bytes: 0,
            packets: 0,
            woke_timer: 0,
            woke_socket: 0,
            woke_media: 0,
            timer_sleeps: 0,
            timer_late_us_sum: 0,
            timer_late_us_max: 0,
            timer_late_4ms: 0,
            send_errors: 0,
            last_send_error: None,
            write_errors: 0,
            last_write_error: None,
        }
    }

    /// One wake of the timer arm after a sleep of `asked`, `late` after its deadline. A zero-length
    /// sleep is not a sleep and says nothing about the tick, so it is not counted.
    fn note_timer_wake(&mut self, asked: Duration, late: Duration) {
        if asked.is_zero() {
            return;
        }
        let late_us = u64::try_from(late.as_micros()).unwrap_or(u64::MAX);
        self.timer_sleeps += 1;
        self.timer_late_us_sum = self.timer_late_us_sum.saturating_add(late_us);
        self.timer_late_us_max = self.timer_late_us_max.max(late_us);
        if late_us >= 4_000 {
            self.timer_late_4ms += 1;
        }
    }

    /// `mean/max ms n=<sleeps> >=4ms=<count>`, or `-` when the loop never slept on the timer.
    fn timer_late_summary(&self) -> String {
        if self.timer_sleeps == 0 {
            return "-".to_string();
        }
        format!(
            "{:.1}/{:.1}ms n={} >=4ms={}",
            self.timer_late_us_sum as f64 / self.timer_sleeps as f64 / 1000.0,
            self.timer_late_us_max as f64 / 1000.0,
            self.timer_sleeps,
            self.timer_late_4ms
        )
    }

    /// Update the decaying peak of measured egress, and return it in kbps.
    ///
    /// A peak rather than the current rate, because the current rate is production-limited whenever
    /// the queue is empty — an idle desktop sends 12 kbps and that says nothing about the link. The
    /// peak remembers what the link has demonstrably carried.
    ///
    /// Decayed rather than held, or a single burst on a link that has since degraded would license
    /// a queue for the rest of the session. Ten percent a second is a half-life of about seven
    /// seconds: slow enough to survive a quiet stretch, fast enough to follow a link that has
    /// genuinely fallen.
    fn note_drain(&mut self, kbps: u32, drain: &AtomicU32) {
        let decayed = drain.load(Ordering::Relaxed) * 9 / 10;
        drain.store(decayed.max(kbps), Ordering::Relaxed);
    }

    /// Publish what left the socket in the window just ended, unsmoothed.
    ///
    /// Distinct from the decaying peak, and both are needed. The peak answers "what can this link
    /// carry", which wants memory. This answers "what left in the last second", which must not have
    /// any, because it is one half of a conservation check: production above egress means the
    /// backlog is growing, by arithmetic, with two independent measurements and no estimate between
    /// them.
    fn note_egress(&mut self, kbps: u32, egress: &AtomicU32) {
        egress.store(kbps, Ordering::Relaxed);
    }

    fn report_if_due(&mut self, drain: &AtomicU32, egress: &AtomicU32) {
        let elapsed = self.window_start.elapsed();
        if elapsed < Self::WINDOW {
            return;
        }
        let secs = elapsed.as_secs_f64();
        let egress_kbps = (self.bytes as f64 * 8.0 / secs / 1000.0) as u32;
        self.note_drain(egress_kbps, drain);
        self.note_egress(egress_kbps, egress);
        tracing::info!(
            turns_per_s = format!("{:.0}", self.turns as f64 / secs),
            packets_per_s = format!("{:.0}", self.packets as f64 / secs),
            egress_kbps = format!("{:.0}", self.bytes as f64 * 8.0 / secs / 1000.0),
            woke = %format!(
                "t{} s{} m{}",
                self.woke_timer, self.woke_socket, self.woke_media
            ),
            timer_late = %self.timer_late_summary(),
            "egress"
        );
        if self.send_errors > 0 {
            tracing::debug!(
                count = self.send_errors,
                last = self.last_send_error.as_deref().unwrap_or("-"),
                "udp send failed in the last second"
            );
        }
        if self.write_errors > 0 {
            tracing::debug!(
                count = self.write_errors,
                last = self.last_write_error.as_deref().unwrap_or("-"),
                "media write refused by str0m in the last second"
            );
        }
        *self = Self::new();
    }
}

impl PeerLoop {
    /// Serve the peer until it ends, then say why: [`PeerEvent::Disconnected`] is always the last
    /// event, whatever ended the loop — including an error from str0m, so the orchestrator never
    /// has to infer an ending from a closed channel.
    async fn run(
        mut self,
        media_rx: mpsc::Receiver<MediaSample>,
        mut signal_rx: SignalReceiver,
        control_rx: mpsc::Receiver<PeerControl>,
        close: CloseSignal,
    ) {
        // The signal queue's receiver outlives `serve`, so the end line below can still count what
        // was left in it (dropping the receiver empties the queue).
        let served = self
            .serve(media_rx, &mut signal_rx, control_rx, close)
            .await;
        if let Some(hooks) = self.hooks.as_mut() {
            hooks.ended();
            self.socket.close_host().await;
        }
        let (end, failure) = match served {
            Ok(end) => (end, None),
            Err(e) => {
                let failure = format!("{e:#}");
                // With what DTLS had done by then. str0m's `DTLS error: timeout: handshake` is
                // dimpl giving up once its flight has gone unanswered through four resends (1, 2,
                // 4 and 8 s apart, ±0.25 s each, then a last 16 s wait: ~31 s after the flight
                // began; a resend in answer to the peer's repeated flight — at most one per wait,
                // since 0.7.5 — uses up one of the four and starts the next wait;
                // `dimpl-0.7.5/src/dtls12/engine.rs:395-451, 596-610`, `config.rs:84-101`), and on
                // its own it said nothing about which side was not being heard.
                tracing::warn!(
                    dtls_connected = self.connected,
                    dtls_role = self.dtls_role.as_str(),
                    pair = self.pair_label(),
                    dtls_out = self.paths.dtls_summary(Dir::Out, self.start),
                    dtls_in = self.paths.dtls_summary(Dir::In, self.start),
                    "webrtc peer loop failed: {failure}"
                );
                (PeerEnd::Error, Some(failure))
            }
        };
        if let Some(held) = self.held_answer.take() {
            tracing::debug!(
                ?end,
                ufrag = %held.ufrag,
                held_ms = held.since.elapsed().as_millis() as u64,
                "a held {} answer was never sent: the peer ended first",
                held.offer
            );
        }
        self.log_paths_at_end(end, failure.as_deref());
        // Before the end goes out: the session's `session_end.detail` is read from this.
        let path = self.current_path(Instant::now());
        self.path.set(path);
        // The viewer's signals over the peer's life: `signals_dropped` is candidates or re-offers
        // refused at the queue's cap (each said at warn by the orchestrator), `signals_left` what
        // was still queued, untaken, when the loop ended.
        let signals = self.signals.counts();
        tracing::info!(
            ?end,
            reason = end.reason(),
            stage = path.stage.as_str(),
            verdict = path.verdict.unwrap_or("-"),
            dtls_after_ice_ms = ?path.dtls_after_ice_ms,
            pair_local_kind = path.pair_local_kind.unwrap_or("-"),
            pair_remote_kind = path.pair_remote_kind.unwrap_or("-"),
            relay_transport = path.relay_transport.unwrap_or("-"),
            remote_candidates = self.remote_candidates.len(),
            signals_queued = signals.queued,
            signals_taken = signals.taken,
            signals_dropped = signals.dropped,
            signals_max_depth = signals.max_depth,
            signals_left = self.signals.depth(),
            "webrtc peer loop ended"
        );
        // Closed before the end goes out, so a signal the orchestrator hands over from here is
        // refused as for an ended peer rather than queued for nobody.
        drop(signal_rx);
        if self
            .events
            .send(PeerEvent::Disconnected { reason: end })
            .await
            .is_err()
        {
            tracing::debug!(
                ?end,
                "nobody is listening for this peer's end: the session is gone"
            );
        }
    }

    async fn serve(
        &mut self,
        mut media_rx: mpsc::Receiver<MediaSample>,
        signal_rx: &mut SignalReceiver,
        mut control_rx: mpsc::Receiver<PeerControl>,
        mut close: CloseSignal,
    ) -> Result<PeerEnd> {
        let mut buf = vec![0u8; 2048];

        loop {
            // First, every turn: the burst path below `continue`s without reaching the `select!`,
            // and a close must not wait for a quiet moment to be heard.
            if let Some(cause) = close.pending() {
                return Ok(self.close_now(cause.as_str()).await);
            }
            // A stalled `cursor` lane is looked at every turn: the first acknowledgement releases
            // what it holds, and a kick armed by the viewer's coming back goes out at once.
            if self.cursor_lane.stalled() {
                self.step_cursor_lane(None);
            }
            // What waits for room on `input` goes in before the drain below sends it.
            if !self.reliable_out.is_empty() {
                self.write_reliable();
            }
            // Drain the engine after any mutation (str0m single-mutation invariant).
            let sent_before = self.egress.packets;
            let timeout = self.drain().await?;
            if !self.rtc.is_alive() {
                let end = if self.viewer_goodbye {
                    PeerEnd::ViewerClosed
                } else {
                    PeerEnd::RtcClosed
                };
                tracing::info!(
                    ?end,
                    viewer_goodbye = self.viewer_goodbye,
                    "str0m closed the connection {}",
                    if self.viewer_goodbye {
                        "after the viewer's goodbye: the viewer ended it"
                    } else {
                        "by itself, with no goodbye from the viewer"
                    }
                );
                return Ok(end);
            }
            let produced_work = self.egress.packets > sent_before;
            self.egress.turns += 1;
            self.sample_send_queue();
            self.egress
                .report_if_due(&self.measured_drain, &self.last_egress);
            self.report_playout_if_due();
            if self.srflx.is_some() {
                self.drive_srflx().await;
            }
            // After `drive_srflx`, so a discovery that just gave up lets its held answer go now.
            if self.held_answer.is_some() {
                self.drive_held_answer(Instant::now()).await;
            }

            let now = Instant::now();
            self.watch_dtls(now);
            self.publish_path_if_due(now);
            // str0m sending to a pair the viewer does not answer on, while the viewer is elsewhere:
            // take it off that pair. A move mutates the `Rtc`, so the next turn drains it first.
            if self.follow_viewer(now).await? {
                continue;
            }
            // The grace window ran out: the path has been gone for `ice_grace` and neither a
            // restart nor the path itself came back. The viewer, if it is still there, gave up on
            // its own deadline before this — see `ICE_GRACE` — so there is nobody left to wait for.
            if self.link.expired(now) {
                tracing::warn!(
                    grace_s = self.ice_grace.as_secs_f32(),
                    outage_ms = self.link.outage(now).map(|d| d.as_millis() as u64),
                    restarting = self.link.restarting(),
                    "ICE path lost for the whole grace window and nothing brought it back \
                     (restarting=true: a restart was applied and found no path); ending the peer"
                );
                self.rtc.disconnect();
                return Ok(PeerEnd::IceTimeout);
            }
            let wait = timeout.saturating_duration_since(now);

            // str0m has a packet ready *now*. Hand it the clock directly and do not go near a
            // timer, because on Windows a timer costs 15.6 ms.
            //
            // ## The ceiling this removes
            //
            // The pacer releases exactly one RTP packet per `handle_input`, and clears its own gate
            // only when time is handed to it again — having asked for that to happen immediately.
            // So an overdue timeout is str0m saying "call me back now". Answering it through
            // `tokio::time::sleep(0)` inside `select!` is a round trip through the runtime's timer,
            // whose resolution on Windows is the system default.
            //
            // Measured that way, with the `egress` counters:
            //
            //     turns/s p50 99   packets/s p50 78   egress p50 263 kbps
            //     woke: timer 62%  socket 23%  media 15%      bytes/packet 379
            //
            // 62% of 99 turns is 61 timer wakes a second — **16.4 ms apart**, against Windows's
            // 15.6 ms default. One packet per turn at 99 turns a second is a hard ceiling of about
            // 900 kbps at str0m's 1150-byte MTU, and 300 kbps at the 379-byte mean these sessions
            // actually produced.
            //
            // Such a ceiling looks like anything but itself: the bandwidth estimate cannot exceed
            // what we can physically emit, so it plateaus below a megabit and reads as the
            // network's limit; the send queue never drains because the drain is capped; and the
            // quality ladder descends, on evidence that is arithmetically correct and causally
            // backwards.
            //
            // Bounded, because a peer that always has something ready must not starve the socket
            // or the control channel — and because an unbounded loop spins a core at 142% when an
            // overdue timeout produces nothing at all.
            let mut immediate = 0;
            while wait.is_zero() && produced_work && immediate < BURST_PER_TURN {
                immediate += 1;
                self.rtc.handle_input(Input::Timeout(Instant::now()))?;
                let before = self.egress.packets;
                let next = self.drain().await?;
                self.egress.turns += 1;
                if !self.rtc.is_alive() || self.egress.packets == before {
                    break;
                }
                if next > Instant::now() {
                    break;
                }
            }
            if immediate > 0 {
                self.sample_send_queue();
                continue;
            }
            // A turn that produced nothing may not be repeated immediately.
            //
            // The zero floor below is right while str0m is handing out packets, and catastrophic
            // when it is not: an overdue timeout that yields no output simply comes back overdue,
            // and the loop then spins a core at full speed for as long as the peer exists.
            //
            // Measured: with two sessions closed and nothing in the log for minutes, the agent was
            // burning 142% of a core across 37 threads — two abandoned peer loops, each spinning.
            // On a product that sits in the tray on somebody's own computer that is worse than any
            // of the video problems this loop was opened to fix, and it is invisible: no log line,
            // no traffic, just a warm laptop.
            //
            // So the fast path is conditional on there having been something to be fast about.
            let wait = if produced_work {
                wait
            } else {
                wait.max(IDLE_TURN)
            };
            // A STUN transaction still running keeps its own clock: its next retransmission, or its
            // deadline. Woken by the timer arm below, served by `drive_srflx` on the next turn.
            let wait = match self.srflx_wait(now) {
                Some(srflx) => wait.min(srflx),
                None => wait,
            };
            // And a held restart answer its deadline, released by `drive_held_answer` on the next
            // turn — which ends the hold, so a zero wait here does not stay zero.
            let wait = match &self.held_answer {
                Some(held) => wait.min(held.deadline.saturating_duration_since(now)),
                None => wait,
            };
            // And so does the grace window: the loop must wake when it runs out even if nothing
            // else happens, which on a dead path is exactly what nothing else does. Checked at the
            // top of the next turn.
            let wait = match self.link.deadline() {
                Some(deadline) => wait.min(deadline.saturating_duration_since(now)),
                None => wait,
            };
            // And the DTLS stall watch: a stalled handshake is exactly a link on which nothing
            // else happens, and its warning must still come on time. Never a zero wait that stays
            // zero: `watch_dtls` at the top of the turn moves the deadline on once it is reached.
            let wait = match self.dtls.next_due() {
                Some(due) => wait.min(due.saturating_duration_since(now)),
                None => wait,
            };
            // And the look at str0m's send pair, which is about time passing without an answer —
            // again what happens on a link where nothing else does.
            let wait = match self.follow_due() {
                Some(due) => wait.min(due.saturating_duration_since(now)),
                None => wait,
            };

            // No floor on this wait.
            //
            // str0m's pacer releases **exactly one RTP packet per `handle_input`**. It gates
            // itself — `needs_timeout_before_next_poll` in `pacer/leaky.rs` — and clears the gate
            // only when time is handed to it again, having asked for that to happen immediately
            // (`request_immediate_timeout`, "at the next microsecond"). So `poll_output` returning
            // a timeout already in the past is not a hint: it is str0m saying "I have a packet
            // ready, call me back now".
            //
            // A floor such as `.max(Duration::from_millis(1))` turns that into "call me back in a
            // millisecond", which caps egress at 1000 packets/s — about 8.8 Mbps at str0m's
            // 1150-byte MTU on a machine with a 1 ms timer, and far less on Windows, whose default
            // timer resolution is 15.6 ms and which nothing in this process raises.
            //
            // Measured with such a floor: the viewer recorded 1634 kbps arriving while the encoder
            // was producing 2800. The difference went into `SendQueue` — a bare `VecDeque` with no
            // capacity, no eviction and no age check — and came out ten seconds later: the picture
            // was ten seconds behind, and modelling the per-second output against its estimate puts
            // the peak backlog at 10.0 Mbit, or 6.9 seconds of video.
            //
            // A zero wait is still polled through `select!` rather than looped directly, so a
            // backlog cannot starve the socket, the media channel or the control channel — tokio
            // picks fairly among ready branches. When str0m has nothing pending the timeout is a
            // real one and this sleeps properly.
            tokio::select! {
                _ = tokio::time::sleep(wait) => {
                    self.egress.woke_timer += 1;
                    let woke = Instant::now();
                    self.egress
                        .note_timer_wake(wait, woke.saturating_duration_since(now + wait));
                    self.rtc.handle_input(Input::Timeout(woke))?;
                }
                res = self.socket.recv_from(&mut buf) => {
                    self.egress.woke_socket += 1;
                    match res {
                        Ok((n, source)) => {
                            // A reply to the STUN transaction that outlived the answer is picked
                            // out before str0m, which would take it for one of its own checks and
                            // drop it. One `Option` test per datagram otherwise.
                            let stun_reply = self.srflx.is_some()
                                && self.take_srflx_reply(source, &buf[..n]).await;
                            if stun_reply {
                                continue;
                            }
                            if self.hooks.as_mut().is_some_and(|hooks| !hooks.admit_datagram(source)) {
                                tracing::trace!(%source, "datagram refused by the host's hooks");
                                continue;
                            }
                            let received = Instant::now();
                            let datagram = &buf[..n];
                            // Counted before str0m sees it, so a datagram it cannot parse is
                            // counted too. See `crate::paths`.
                            let noted =
                                self.paths.note(Dir::In, None, source, datagram, received);
                            if noted.kind == Kind::Dtls {
                                self.note_dtls_datagram(Dir::In, source, n, noted, received);
                            }
                            match str0m::net::DatagramRecv::try_from(datagram) {
                                Ok(contents) => {
                                    let recv = Receive {
                                        proto: Protocol::Udp,
                                        source,
                                        destination: self.local_addr,
                                        contents,
                                    };
                                    self.rtc.handle_input(Input::Receive(received, recv))?;
                                }
                                Err(e) => {
                                    // Per datagram, so trace; the count is on the path lines.
                                    self.paths.unparsed(source);
                                    tracing::trace!(%source, bytes = n, "skip datagram: {e:?}");
                                }
                            }
                        }
                        Err(e) => tracing::warn!("udp recv: {e}"),
                    }
                }
                Some(sample) = media_rx.recv() => {
                    self.egress.woke_media += 1;
                    // Released only once the frame is inside str0m's queue, where `queue_info()`
                    // takes over counting it. The producer added these bytes before it sent, so
                    // between the two the frame is counted exactly once and never falls out of the
                    // latency signal — which is what the predecessor did on every single frame.
                    let len = u32::try_from(sample.data.len()).unwrap_or(u32::MAX);
                    self.write_media(sample);
                    self.queued_media_bytes.fetch_sub(len, Ordering::Relaxed);
                }
                cause = close.fired() => {
                    return Ok(self.close_now(cause.as_str()).await);
                }
                // The viewer's candidates and re-offers, one a turn, in the order it sent them.
                signal = signal_rx.recv() => {
                    match signal {
                        Some(PeerSignal::AddRemoteIce(v)) => {
                            let local = self.local_addr;
                            if let Some(Err(reason)) = self
                                .hooks
                                .as_mut()
                                .map(|hooks| hooks.admit_candidate(&v.candidate, local))
                            {
                                return Ok(self.close_now(reason).await);
                            }
                            // Per candidate, so trace; the peer's own `remote candidate` line
                            // follows at info once it is parsed.
                            tracing::trace!(
                                left = self.signals.depth(),
                                "viewer signal taken: a candidate"
                            );
                            self.add_remote_ice(v);
                        }
                        Some(PeerSignal::Renegotiate(sdp)) => {
                            if let Some(Err(reason)) =
                                self.hooks.as_mut().map(|hooks| hooks.admit_renegotiation())
                            {
                                return Ok(self.close_now(reason).await);
                            }
                            tracing::trace!(
                                left = self.signals.depth(),
                                bytes = sdp.len(),
                                "viewer signal taken: an offer"
                            );
                            if let Err(end) = self.renegotiate(&sdp).await {
                                self.rtc.disconnect();
                                return Ok(end);
                            }
                        }
                        // Unreachable while this loop holds its own sender (`signals`, for the mDNS
                        // results); handled as a close because a closed queue would mean nobody can
                        // reach this peer again.
                        None => return Ok(self.close_now("signal_queue_closed").await),
                    }
                }
                ctrl = control_rx.recv() => {
                    match ctrl {
                        Some(PeerControl::SetDesiredBitrate(kbps)) => {
                            self.set_desired(kbps, Instant::now());
                        }
                        Some(PeerControl::ResetBwe(kbps)) => {
                            self.apply_reanchor(kbps, None, "on-arrival", None, Instant::now())?;
                        }
                        Some(PeerControl::ResetBweProbing {
                            kbps,
                            probe_cap_kbps,
                        }) => {
                            self.apply_reanchor(
                                kbps,
                                Some(probe_cap_kbps),
                                "on-arrival",
                                None,
                                Instant::now(),
                            )?;
                        }
                        Some(PeerControl::ResetBweAtNextFrame(kbps)) => {
                            self.arm_reanchor(kbps, Instant::now())?;
                        }
                        Some(PeerControl::SendHeartbeat(text)) => self.send_heartbeat(text),
                        Some(PeerControl::SendCursor(text)) => self.send_cursor_report(text),
                        Some(PeerControl::ViewerHidden(hidden)) => {
                            self.gate_cursor_lane(None, Some(hidden), "viewer_vis");
                        }
                        Some(PeerControl::SendReliable(messages)) => {
                            self.queue_reliable(messages, false);
                        }
                        Some(PeerControl::SendReliableReceipt { text, queued }) => {
                            let accepted = self.reliable_out_bytes + text.len() <= RELIABLE_QUEUE_MAX
                                && self.queue_reliable(vec![text], false);
                            if queued.send(accepted).is_err() {
                                tracing::trace!(accepted, "reliable message receipt: its waiter is gone");
                            }
                        }
                        Some(PeerControl::SendRevocable(messages)) => {
                            self.queue_reliable(messages, true);
                        }
                        Some(PeerControl::RevokeQueued) => self.revoke_reliable(),
                        Some(PeerControl::ViewerPlayout(v)) => {
                            let now = Instant::now();
                            // The buffer first: a report whose freezes engage the cushion sizes it
                            // with its own jitter-buffer target among the rest.
                            self.playout.note_viewer(now, v.engine, v.jbuf_target_ms);
                            self.playout.note_freezes(now, v.freezes, v.freeze_ms);
                        }
                        // Every sender gone: the session's tasks have all stopped, which only its
                        // end does — and that closes the peer through its closer anyway. Handled
                        // as a close because a closed queue means nobody can reach this peer
                        // again.
                        None => return Ok(self.close_now("control_channel_closed").await),
                    }
                }
            }
        }
    }

    /// End the peer on the orchestrator's word: tell the viewer, flush it, and report
    /// [`PeerEnd::Closed`].
    async fn close_now(&mut self, why: &'static str) -> PeerEnd {
        tracing::debug!(why, "peer closing on the orchestrator's word");
        self.rtc.disconnect();
        // One more drain to flush the DTLS close, then stop. An error here costs only the viewer
        // hearing the close a little later, from ICE.
        if let Err(e) = self.drain().await {
            tracing::debug!("drain after close failed: {e}");
        }
        PeerEnd::Closed
    }

    /// Apply a new offer from the viewer to this live session, and send back the answer.
    ///
    /// In practice an ICE restart: `webrtc.ts` sends one when its connection fails. str0m supports
    /// it on an existing `Rtc`: `accept_offer` sees the remote ICE credentials change and restarts
    /// its ICE agent (`str0m-0.23.1/src/change/sdp.rs:725-752`, `is-0.11.0/src/agent.rs:986-1016`)
    /// — new local credentials, every pair and remote candidate flushed, local candidates kept —
    /// while DTLS, SCTP and the media streams carry on untouched (`init_dtls` and `try_init_sctp`
    /// return early once initialised, `lib.rs:1482-1485,1510-1512`; the ICE role is only chosen on
    /// the first offer, `sdp.rs:95-99`). Until a new pair is nominated str0m keeps sending on the
    /// old one, so a path that still half works keeps carrying the picture meanwhile.
    ///
    /// An offer with unchanged credentials is answered without a restart: that is the Mini App
    /// re-sending an offer whose answer it never received, and answering it again is harmless.
    ///
    /// The answer is held back while the srflx discovery runs when the viewer offers only relays
    /// and none of our candidates is public ([`Self::answer_hold`]): sent with host candidates
    /// only, such an answer fails within half a second on the viewer, which after two restarts
    /// gives up (`ice_failed`). It goes out when a mapping arrives — with the candidate
    /// right behind it — or the discovery ends, or the viewer turns out not to be relay-only, or
    /// [`stun::RELAY_ONLY_ANSWER_BUDGET`] runs out ([`Self::drive_held_answer`]). A newer offer
    /// drops a held answer: the viewer wants only the answer to its latest.
    ///
    /// A restart's answer, and a re-sent offer's: the resume re-sends an offer
    /// whose answer never arrived, perhaps with the relays it trickled into the dead socket in it,
    /// and that re-sent offer may be the first word that the viewer is relay-only — the first
    /// answer would wait only the ordinary [`stun::ANSWER_BUDGET`], with nothing to say otherwise.
    /// Its answer is the first the viewer applies, so it is the same answer a restart's is: useless
    /// to that viewer without our srflx, and a srflx trickled seconds after it rides a socket that
    /// has just died once. Held, the candidate goes out right behind the answer, and an answer to
    /// the offer sent yet again carries it (str0m has it as a local candidate by then). One budget
    /// per offer, however often it is sent ([`HoldClock`]): a re-send of an offer whose answer has
    /// already waited — the first answer, or an earlier re-send — is not held again.
    ///
    /// `Err` means the offer could not be applied and the peer must end: the viewer is waiting for
    /// an answer that cannot come, and str0m may have been left half-restarted.
    async fn renegotiate(&mut self, offer_sdp: &str) -> Result<(), PeerEnd> {
        let offered_candidates = offer_sdp
            .lines()
            .filter(|l| l.starts_with("a=candidate:"))
            .count();
        let offer = match SdpOffer::from_sdp_string(offer_sdp) {
            Ok(offer) => offer,
            Err(e) => {
                tracing::warn!(
                    bytes = offer_sdp.len(),
                    "re-offer rejected: not a parsable SDP offer ({e}); ending the peer, since the \
                     viewer is waiting for an answer that cannot come"
                );
                return Err(PeerEnd::RestartFailed);
            }
        };
        let before = self.rtc.direct_api().local_ice_credentials();
        let answer = match self.rtc.sdp_api().accept_offer(offer) {
            Ok(answer) => answer,
            Err(e) => {
                tracing::warn!(
                    offered_candidates,
                    "re-offer rejected by str0m ({e}); ending the peer, since the viewer is \
                     waiting for an answer that cannot come"
                );
                return Err(PeerEnd::RestartFailed);
            }
        };
        let answer_sdp = answer.to_sdp_string();
        tracing::debug!(
            offer = %sdp_summary(offer_sdp),
            answer = %sdp_summary(&answer_sdp),
            "re-offer accepted"
        );
        let offered = sdp_candidates(offer_sdp);
        offered.log("re-offer");
        let sdp_mid = first_mid(&answer_sdp);
        let after = self.rtc.direct_api().local_ice_credentials();
        let restarted = after != before;
        // The viewer's candidates by generation: a restart starts a new one, and the last one that
        // had any candidates is kept, since the restart's own usually arrive after its offer.
        if restarted {
            if !self.viewer_mix.is_empty() {
                self.viewer_mix_before = self.viewer_mix;
            }
            self.viewer_mix = CandidateMix::default();
            self.viewer_addrs.clear();
            self.remote_ufrag = sdp_ice_ufrag(offer_sdp);
        }
        let parsed = offered.parsed.len();
        let mut again = 0;
        for c in offered.parsed {
            if !self.note_viewer_candidate(c.addr, c.kind) {
                again += 1;
            }
            remember_candidate(&mut self.remote_candidates, c);
        }
        if parsed > 0 {
            tracing::debug!(
                parsed,
                again,
                restarted,
                viewer_relays = self.viewer_mix.relay,
                viewer_other = self.viewer_mix.other,
                "the re-offer's candidates in this ICE generation's mix, once per address (again: \
                 signalled before in this generation — trickled, or in the offer sent before — and \
                 not counted twice)"
            );
        }
        // The candidates may have changed, and a restart moves the media: looked up afresh.
        self.relay_dest.clear();
        if restarted {
            let now = Instant::now();
            let outage_ms = self.link.outage(now).map(|d| d.as_millis() as u64);
            let replaced = self.link.on_restart(now, self.ice_grace);
            // str0m flushed every pair and remote candidate: what the path book knew about this
            // generation's pairs, and every remote withdrawn from it, is history.
            self.paths.new_generation(Some(after.ufrag.clone()));
            let withdrawn = std::mem::take(&mut self.follow.left);
            let hold_was = self.follow.hold.replace(Hold::SendPathAnswers);
            let moving = self.follow.moving.take();
            tracing::debug!(
                withdrawn = withdrawn.len(),
                hold_was = hold_was.map_or("-", Hold::as_str),
                was_moving = moving.is_some(),
                "send-pair watch: evidence starts over for the restart's ICE generation (str0m \
                 flushed its remote candidates, so nothing withdrawn stays withdrawn)"
            );
            // `dtls_connected=false` is a viewer rescuing a handshake that stalled on its first
            // path. DTLS is not restarted with ICE: str0m keeps it, and sends what it has next —
            // a resend on dimpl's clock, or the answer to the viewer's next ClientHello — to the
            // pair ICE nominates from here. dimpl's clocks do not restart either: a flight gives up
            // ~31 s after it began (after the answer, if no ClientHello ever came) and the whole
            // handshake 40 s after the answer, which bounds how late such a rescue can come.
            tracing::info!(
                old_ufrag = %before.ufrag,
                new_ufrag = %after.ufrag,
                offered_candidates,
                outage_ms,
                replaced_window_left_ms = replaced.map(|d| d.as_millis() as u64),
                grace_s = self.ice_grace.as_secs_f32(),
                dtls_connected = self.connected,
                dtls_stalled_ms = self
                    .dtls
                    .stalled_for(now)
                    .map(|d| d.as_millis() as u64),
                dtls_out = self.paths.dtls_summary(Dir::Out, self.start),
                dtls_in = self.paths.dtls_summary(Dir::In, self.start),
                "ICE restart applied: new credentials, pairs flushed, media and data channels \
                 carry on; the restart has grace_s to find a path"
            );
        } else {
            tracing::info!(
                ufrag = %after.ufrag,
                offered_candidates,
                "re-offer with unchanged ICE credentials answered without an ICE restart (an \
                 offer re-sent because its answer was lost, or a change that is not ICE)"
            );
        }
        // The offer's mDNS hosts, once its generation is settled: a name already looked up is fed
        // in at once — and counted, before the hold below is decided — and a new one is looked up.
        for (cand, name) in offered.mdns {
            self.resolve_mdns(cand, name, "re-offer");
        }
        let now = Instant::now();
        // An answer still held belongs to an offer the viewer has replaced with this one (or sent
        // again, unchanged): only the newest is wanted, and two in a row would leave the viewer
        // applying the stale one, or refusing the second.
        let superseded = self.held_answer.take();
        if let Some(old) = &superseded {
            tracing::debug!(
                held_ms = now.saturating_duration_since(old.since).as_millis() as u64,
                old_ufrag = %old.ufrag,
                restarted,
                "a newer offer came while the answer to a {} was held: that answer is dropped, and \
                 this offer's answer inherits its hold's clock",
                old.offer
            );
        }
        // Nothing here can trickle: a mapping is only adopted when its reply is read, on a later
        // turn, and the answer — sent below or released by the hold — always goes first.
        if restarted {
            self.start_srflx(sdp_mid, SRFLX_AFTER_RESTART);
        }
        let offer = if restarted { HOLD_RESTART } else { HOLD_RESENT };
        // The budget already spent on this answer: a superseded hold's, or the one an earlier
        // answer to this same offer — this generation's — spent ([`HoldClock`]). A restart is a new
        // generation, with a budget of its own.
        let clock = match &superseded {
            Some(old) => Some((old.since, "superseded")),
            None => self
                .hold_clock
                .as_ref()
                .filter(|c| c.ufrag == self.remote_ufrag)
                .map(|c| (c.since, "same_offer")),
        };
        match self.answer_hold(now, clock, offer) {
            Some((since, deadline)) => {
                tracing::info!(
                    ufrag = %after.ufrag,
                    offer,
                    wait_ms = deadline.saturating_duration_since(now).as_millis() as u64,
                    held_before_ms = now.saturating_duration_since(since).as_millis() as u64,
                    "{offer} answer held: the viewer offers only relays and none of our candidates \
                     is public, so this answer works only with a srflx candidate; it goes out when \
                     the discovery has a mapping (followed at once by the candidate), gives up, or \
                     wait_ms runs out"
                );
                self.hold_clock = Some(HoldClock {
                    ufrag: self.remote_ufrag.clone(),
                    since,
                });
                self.held_answer = Some(HeldAnswer {
                    sdp: answer_sdp,
                    ufrag: after.ufrag,
                    offer,
                    since,
                    deadline,
                });
            }
            None => {
                if self
                    .events
                    .send(PeerEvent::Answer(answer_sdp))
                    .await
                    .is_err()
                {
                    tracing::debug!(
                        "the orchestrator is gone; the re-offer's answer has nowhere to go"
                    );
                }
            }
        }
        Ok(())
    }

    /// The viewer's candidates as far as they say whether it is relay-only: the current
    /// generation's, or — while it has none, as right after a restart, whose own candidates
    /// usually come after its offer — the last earlier one that had any.
    fn viewer_mix_now(&self) -> (CandidateMix, &'static str) {
        if self.viewer_mix.is_empty() {
            (self.viewer_mix_before, "previous")
        } else {
            (self.viewer_mix, "current")
        }
    }

    /// Whether a re-offer's answer waits for the srflx discovery, and until when:
    /// `(since, deadline)`. `offer` is [`HOLD_RESTART`] or [`HOLD_RESENT`], for the log.
    ///
    /// Only when it cannot work without one ([`SrflxNeed::Required`]: a relay-only viewer answered
    /// with private host candidates fails in half a second, twice, and gives up) and a
    /// discovery is running to wait for — after a restart the one [`Self::start_srflx`] continued
    /// or began, after an offer sent again the one the first answer could not wait for. `clock` is
    /// when the budget this answer shares began, and whose it is: a held answer this one replaces
    /// (`superseded`), or an earlier answer to the same offer (`same_offer`, [`HoldClock`]). Every
    /// outcome said at debug, once per re-offer.
    fn answer_hold(
        &self,
        now: Instant,
        clock: Option<(Instant, &'static str)>,
        offer: &'static str,
    ) -> Option<(Instant, Instant)> {
        let (mix, generation) = self.viewer_mix_now();
        let need = srflx_need(mix, self.srflx_addr.is_some(), self.public_host);
        let running = self.srflx.as_ref();
        let Some(late) = running.filter(|_| need == SrflxNeed::Required) else {
            tracing::debug!(
                offer,
                viewer_relays = mix.relay,
                viewer_other = mix.other,
                generation,
                need = need.as_str(),
                discovery_running = running.is_some(),
                discovery_after = running.map_or("-", |late| late.after),
                "{offer} answer goes out at once: it does not need a srflx candidate, or no \
                 discovery is running to wait for"
            );
            return None;
        };
        let (since, clock) = clock.unwrap_or((now, "new"));
        let deadline = since + self.relay_only_answer_budget;
        if deadline <= now {
            tracing::debug!(
                offer,
                clock,
                held_before_ms = now.saturating_duration_since(since).as_millis() as u64,
                budget_ms = self.relay_only_answer_budget.as_millis() as u64,
                discovery_attempts = late.probe.attempts(),
                discovery_elapsed_ms = late.probe.elapsed_ms(now),
                "{offer} answer goes out at once: the answers to this offer before it used up the \
                 hold's budget (clock=superseded: a held answer it replaces; clock=same_offer: an \
                 earlier answer to the same offer, sent again)"
            );
            return None;
        }
        tracing::debug!(
            offer,
            clock,
            viewer_relays = mix.relay,
            viewer_other = mix.other,
            generation,
            discovery_after = late.after,
            discovery_attempts = late.probe.attempts(),
            discovery_elapsed_ms = late.probe.elapsed_ms(now),
            held_before_ms = now.saturating_duration_since(since).as_millis() as u64,
            budget_ms = self.relay_only_answer_budget.as_millis() as u64,
            "{offer} answer to be held for the srflx discovery"
        );
        Some((since, deadline))
    }

    /// Release a held answer if its discovery has ended, its time is up, or the viewer has offered
    /// something besides relays since it was held — a trickle, or one of its mDNS hosts resolved —
    /// and so does not need our srflx any more. At the top of every turn while one is held; a mapping
    /// releases it itself, before its candidate is trickled (see [`Self::adopt_late_srflx`]).
    async fn drive_held_answer(&mut self, now: Instant) {
        let Some(deadline) = self.held_answer.as_ref().map(|held| held.deadline) else {
            return;
        };
        if self.srflx.is_none() {
            // The line before this one says how it ended: gave up, or a path came back.
            self.release_held_answer("discovery_ended").await;
        } else if now >= deadline {
            self.release_held_answer("budget").await;
        } else {
            let (mix, generation) = self.viewer_mix_now();
            let need = srflx_need(mix, self.srflx_addr.is_some(), self.public_host);
            if need != SrflxNeed::Required {
                tracing::debug!(
                    viewer_relays = mix.relay,
                    viewer_other = mix.other,
                    generation,
                    need = need.as_str(),
                    "the viewer offered a candidate besides relays while its answer was held: the \
                     answer can work without our srflx now"
                );
                self.release_held_answer("viewer_not_relay_only").await;
            }
        }
    }

    /// Send a held answer now, saying why and after how long.
    async fn release_held_answer(&mut self, why: &'static str) {
        let Some(held) = self.held_answer.take() else {
            return;
        };
        let now = Instant::now();
        tracing::info!(
            why,
            ufrag = %held.ufrag,
            offer = held.offer,
            held_ms = now.saturating_duration_since(held.since).as_millis() as u64,
            srflx = ?self.srflx_addr,
            discovery_running = self.srflx.is_some(),
            "{} answer released (why=mapping_arrived: the candidate follows it at once; \
             why=budget: the discovery goes on and trickles a mapping if one comes; \
             why=viewer_not_relay_only: the viewer offered more than relays meanwhile)",
            held.offer
        );
        if self.events.send(PeerEvent::Answer(held.sdp)).await.is_err() {
            tracing::debug!("the orchestrator is gone; the held answer has nowhere to go");
        }
    }

    /// Discover the server-reflexive mapping on this socket for the ICE generation a restart just
    /// began: continue the discovery still running, or start a fresh one.
    ///
    /// After an ICE restart, because a restart is the viewer saying it needs a path, and the one
    /// candidate a relay-only viewer cannot do without is this one. The mapping the answer carried
    /// may be stale by now (the PC's own network may have moved too, and a NAT binding towards the
    /// STUN server that nothing has refreshed can expire), or there may never have been one: the
    /// transaction at the start of the session can have given up. It costs a few 20-byte datagrams.
    ///
    /// A discovery still running is continued, never replaced (`crate::stun`, «An ICE restart
    /// continues it»): this peer has one socket for its whole life, so the mapping it is asking for
    /// is the one the restart needs, and its requests still in flight are the ones most likely to be
    /// answered next. Replacing it loses sessions on a slow path: each restart discards sixteen
    /// requests owed a reply and begins again from nothing. It is renewed
    /// ([`stun::Probe::renew`]: every server asked again at once, earlier ids still valid) and its
    /// result goes to the new generation — str0m stamps a candidate added now with the restart's
    /// ufrag. A different socket is a different peer, with a discovery of its own.
    ///
    /// The same transaction the answer could not wait for, run the same way — [`Self::drive_srflx`],
    /// [`Self::take_srflx_reply`], [`Self::adopt_late_srflx`] — so a new mapping is trickled exactly
    /// as a late one is, and an unchanged one is not trickled at all.
    fn start_srflx(&mut self, sdp_mid: Option<String>, after: &'static str) {
        if self.stun_servers.is_empty() {
            tracing::debug!(
                after,
                "no STUN server in the session's ICE config: no srflx discovery after this"
            );
            return;
        }
        let now = Instant::now();
        if let Some(late) = self.srflx.as_mut() {
            if !late.probe.is_finished(now) {
                let attempts = late.probe.attempts();
                let renewed = late.probe.renew(now);
                late.sdp_mid = sdp_mid;
                let was_after = std::mem::replace(&mut late.after, after);
                late.restarts += 1;
                tracing::debug!(
                    after,
                    was_after,
                    restarts = late.restarts,
                    attempts,
                    elapsed_ms = late.probe.elapsed_ms(now),
                    renewed_servers = renewed,
                    left_ms = late.probe.left_ms(now),
                    current = ?self.srflx_addr,
                    "STUN: a srflx discovery is still running on this socket; continued into the \
                     restart's ICE generation (replies to its requests so far still count) and \
                     every server it has asked is asked again at once"
                );
                return;
            }
            // Out of time or out of servers, and not yet collected by `drive_srflx` this turn:
            // nothing left in it to continue.
            tracing::debug!(
                after,
                was_after = late.after,
                attempts = late.probe.attempts(),
                elapsed_ms = late.probe.elapsed_ms(now),
                cause = late.probe.cause(),
                "STUN: the srflx discovery had just finished without a mapping; a fresh one starts"
            );
            self.srflx = None;
        }
        let probe = stun::Probe::new(self.stun_servers.clone(), now);
        let lookups = stun::spawn_lookups(&probe);
        tracing::info!(
            after,
            servers = self.stun_servers.len(),
            current = ?self.srflx_addr,
            "STUN: discovering the srflx mapping again on the same socket; a different one will be \
             trickled"
        );
        self.srflx = Some(LateSrflx {
            probe,
            lookups,
            sdp_mid,
            after,
            restarts: 0,
        });
    }

    /// What an ICE state change means for the session: the grace window, held input, a keyframe.
    async fn on_ice_state(&mut self, state: IceConnectionState) {
        let now = Instant::now();
        // The first time ICE has a path: DTLS goes next, and the stall watch's clock starts.
        if matches!(
            state,
            IceConnectionState::Connected | IceConnectionState::Completed
        ) && self.dtls.ice_connected(now)
        {
            // The viewer's signals so far (`crate::peer_signal`): `signals_dropped` above zero is
            // candidates lost at the queue's cap, each said at warn by the orchestrator.
            let signals = self.signals.counts();
            tracing::info!(
                elapsed_ms = self.start.elapsed().as_millis() as u64,
                ?state,
                dtls_role = self.dtls_role.as_str(),
                dtls_connected = self.connected,
                pair = self.pair_label(),
                stun_from = self.paths.sources_of(Kind::Stun),
                remote_candidates = self.remote_candidates.len(),
                signals_queued = signals.queued,
                signals_taken = signals.taken,
                signals_dropped = signals.dropped,
                signals_max_depth = signals.max_depth,
                dtls_in = self.paths.dtls_summary(Dir::In, self.start),
                "ICE connected for the first time; the DTLS handshake is next (str0m names the \
                 pair it nominated in its stats within a second)"
            );
            self.publish_path(now, "ice_connected");
        }
        match self.link.on_state(state, now, self.ice_grace) {
            LinkNote::Lost => {
                tracing::warn!(
                    grace_s = self.ice_grace.as_secs_f32(),
                    dtls_connected = self.connected,
                    "ICE lost the path: the session stays up for grace_s for the viewer to restart \
                     ICE; media keeps going to the last path meanwhile; releasing held input"
                );
                // The viewer is out of reach: the `cursor` lane may hold from here.
                self.gate_cursor_lane(Some(true), None, "ice_lost");
                if let Some(hooks) = self.hooks.as_mut() {
                    hooks.link_lost();
                }
                if self.events.send(PeerEvent::LinkLost).await.is_err() {
                    tracing::debug!("the orchestrator is gone; link loss not reported");
                }
            }
            LinkNote::StillLost { left } => tracing::debug!(
                left_ms = left.as_millis() as u64,
                "ICE reported the path lost again; the grace window already running is not \
                 extended"
            ),
            LinkNote::Restored { outage, restarted } => {
                tracing::info!(
                    outage_ms = outage.as_millis() as u64,
                    restarted,
                    ?state,
                    "ICE path restored; asking the encoder for a keyframe so the picture resyncs on \
                     it"
                );
                // As on the first connection: a path exists, so a srflx candidate has nothing left
                // to enable.
                if let Some(late) = self.srflx.take() {
                    tracing::info!(
                        after = late.after,
                        attempts = late.probe.attempts(),
                        elapsed_ms = late.probe.elapsed_ms(now),
                        "path restored before a srflx mapping arrived; STUN retries stopped"
                    );
                }
                // Whatever path came back — the same pair, or a restart's new one (which
                // `note_transmit` also sees when its addresses differ) — the round trip measured
                // before the outage is not evidence about it.
                self.note_path_change(if restarted {
                    "ice_restart_restored"
                } else {
                    "ice_restored"
                });
                // The data channels ride the same path: if the `cursor` lane stalled through the
                // outage, kick it now rather than wait for sctp-proto's backed-off timer — armed
                // first, so a stall the hidden page keeps open kicks; one the path alone held ends
                // with the gate and writes what it held.
                self.note_viewer_back("path_restored");
                self.gate_cursor_lane(Some(false), None, "ice_restored");
                if self
                    .events
                    .send(PeerEvent::KeyframeRequest(KeyframeAsk::PathRestored))
                    .await
                    .is_err()
                {
                    tracing::debug!("the orchestrator is gone; keyframe after restore not asked");
                }
            }
            LinkNote::Unchanged => tracing::debug!(
                ?state,
                window_left_ms = self
                    .link
                    .deadline()
                    .map(|d| d.saturating_duration_since(now).as_millis() as u64),
                "ICE state"
            ),
        }
    }

    /// Write one heartbeat on the `cursor` channel, or hold it while the viewer acknowledges
    /// nothing. See [`PeerControl::SendHeartbeat`] and [`Self::step_cursor_lane`].
    fn send_heartbeat(&mut self, text: String) {
        self.step_cursor_lane(Some((LaneKind::Heartbeat, text)));
    }

    /// Offer a heartbeat or a cursor report to the `cursor` channel — or, with `None`, only look at
    /// the channel — through [`CursorLane`]: written now, or held while the viewer's SCTP
    /// acknowledges nothing; and whatever the look releases or kicks, written now. See
    /// `crate::cursor_lane`.
    ///
    /// Each message's outcome is logged at trace: the heartbeat comes once a second for the life of
    /// the session and the cursor reports up to thirty a second, and the orchestrator logs both
    /// itself. A heartbeat str0m refuses is logged at debug, because that says something about SCTP
    /// rather than about timing. A stall's start and end and each kick are one debug line each.
    fn step_cursor_lane(&mut self, offered: Option<(LaneKind, String)>) {
        let Some(id) = self.cursor_channel else {
            if let Some((kind, _)) = offered {
                tracing::trace!(
                    kind = kind.as_str(),
                    "dropped: the cursor channel is not open"
                );
            }
            return;
        };
        let Some(mut channel) = self.rtc.channel(id) else {
            if let Some((kind, _)) = offered {
                tracing::trace!(
                    kind = kind.as_str(),
                    "dropped: the cursor channel is not writable yet"
                );
            }
            return;
        };
        let now = Instant::now();
        let unacked = channel.buffered_amount();
        let step = self.cursor_lane.step(unacked, offered, now);
        let gate = self.cursor_lane.gate();
        if let Some(u) = step.unheld_started {
            tracing::debug!(
                unacked = u.unacked,
                silent_ms = u.silent.as_millis() as u64,
                stall_after_ms = STALL_AFTER.as_millis() as u64,
                path_lost = gate.path_lost,
                page_hidden = gate.page_hidden,
                "cursor channel: the viewer's SCTP has freed none of the unacked bytes for \
                 silent_ms, but the viewer is not known to be out of reach (ICE has its path, the \
                 page is visible) — a slow path, not a sleeping viewer: nothing is held, heartbeats \
                 and cursor reports are written straight through"
            );
        }
        if let Some(u) = step.unheld_ended {
            tracing::debug!(
                silent_ms = u.silent.as_millis() as u64,
                unacked = u.unacked,
                into_stall = u.into_stall,
                path_lost = gate.path_lost,
                page_hidden = gate.page_hidden,
                "cursor channel: the acknowledgement silence written straight through is over{}",
                if u.into_stall {
                    " — the viewer is out of reach now, and the lane stalls"
                } else {
                    ": the viewer's SCTP acknowledges again"
                }
            );
        }
        if let Some(s) = step.started {
            tracing::debug!(
                why = s.why,
                unacked = s.unacked,
                silent_ms = s.silent.as_millis() as u64,
                stall_after_ms = STALL_AFTER.as_millis() as u64,
                stalls = s.stalls,
                reliable_waiting = self.reliable_out.len(),
                "cursor channel stalled: the viewer's SCTP has freed none of the unacked bytes for \
                 silent_ms and the viewer is out of reach (why). Heartbeats and cursor reports are \
                 held here, the newest of each, and reliable messages wait in our queue, so the \
                 association's window keeps room for one message the moment the viewer is back \
                 (sctp-proto otherwise sends nothing new until its backed-off retransmission timer \
                 fires, up to 60 s on)"
            );
        }
        if let Some(e) = step.ended {
            tracing::debug!(
                how = e.how,
                stalled_ms = e.stalled.as_millis() as u64,
                unacked_at_start = e.unacked_at_start,
                unacked = e.unacked,
                held_heartbeat = e.held_heartbeat,
                held_cursor = e.held_cursor,
                superseded_heartbeats = e.superseded_heartbeats,
                superseded_cursor = e.superseded_cursor,
                kicks = e.kicks,
                reliable_waiting = self.reliable_out.len(),
                "cursor channel stall over: {}; the newest held heartbeat and cursor report are \
                 written now, and the reliable messages that waited follow",
                if e.how == "viewer_reachable" {
                    "the viewer is no longer known to be out of reach, though its SCTP has not \
                     acknowledged yet — written straight through from here"
                } else {
                    "the viewer's SCTP acknowledges again"
                }
            );
        }
        if let Some(k) = step.kicked {
            tracing::debug!(
                why = k.why,
                kind = k.kind.as_str(),
                bytes = k.bytes,
                unacked = k.unacked,
                stalled_ms = k.stalled.as_millis() as u64,
                kicks = k.kicks,
                next_gap_ms = k.next_gap.as_millis() as u64,
                "cursor channel kicked: the viewer is back while the lane is stalled — one held \
                 message is written at once, to fit the window sctp-proto left and draw the SACK \
                 that makes it forward past what the viewer missed"
            );
        }
        if step.held {
            tracing::trace!(
                superseded = step.superseded,
                unacked,
                "held: the cursor channel is stalled"
            );
        }
        for (kind, text) in step.write {
            match channel.write(false, text.as_bytes()) {
                Ok(true) => {
                    self.cursor_lane.wrote(text.len());
                    tracing::trace!(kind = kind.as_str(), bytes = text.len(), "sent");
                }
                Ok(false) if kind == LaneKind::Heartbeat => tracing::debug!(
                    bytes = text.len(),
                    "heartbeat dropped: the SCTP send buffer is full"
                ),
                Ok(false) => tracing::trace!(
                    bytes = text.len(),
                    "cursor report dropped: the SCTP send buffer is full"
                ),
                Err(e) if kind == LaneKind::Heartbeat => {
                    tracing::debug!("heartbeat write failed: {e}")
                }
                Err(e) => tracing::trace!("cursor report write failed: {e}"),
            }
        }
    }

    /// What says the viewer is out of reach changed: ICE's path (`path_lost`) or the page's
    /// visibility (`page_hidden`); `None` leaves that one as it is. One debug line per change, with
    /// what the lane is doing, and a look at the channel at once so a stall starts or ends now
    /// rather than at the next message. See `crate::cursor_lane::Gate`.
    fn gate_cursor_lane(
        &mut self,
        path_lost: Option<bool>,
        page_hidden: Option<bool>,
        from: &'static str,
    ) {
        let before = self.cursor_lane.gate();
        let mut changed = false;
        if let Some(lost) = path_lost {
            changed |= self.cursor_lane.set_path_lost(lost);
        }
        if let Some(hidden) = page_hidden {
            changed |= self.cursor_lane.set_page_hidden(hidden);
        }
        let after = self.cursor_lane.gate();
        if !changed {
            tracing::trace!(
                from,
                gate = after.why(),
                "cursor channel gate: told again what it already had"
            );
            return;
        }
        tracing::debug!(
            from,
            was = before.why(),
            now = after.why(),
            open = after.open(),
            stalled = self.cursor_lane.stalled(),
            channel_open = self.cursor_channel.is_some(),
            "cursor channel gate changed: {}",
            if after.open() {
                "the viewer is out of reach, so the lane may hold once its SCTP stops acknowledging"
            } else {
                "the viewer is not known to be out of reach, so nothing is held: a stall ends and \
                 writes what it held"
            }
        );
        self.step_cursor_lane(None);
    }

    /// The viewer shows it is back (`why`): its data arrived, or ICE restored the path. A stalled
    /// `cursor` lane kicks at the top of the next turn. See `crate::cursor_lane`.
    fn note_viewer_back(&mut self, why: &'static str) {
        if self.cursor_lane.viewer_back(why) {
            tracing::debug!(
                why,
                stalled_ms = self
                    .cursor_lane
                    .stalled_for(Instant::now())
                    .map(|d| d.as_millis() as u64),
                "cursor channel stalled and the viewer is back: a kick goes at the next turn"
            );
        }
    }

    /// The `cursor` channel opened or closed: its lane starts over, and what it held is gone.
    fn reset_cursor_lane(&mut self, why: &'static str) {
        if let Some((stalled, heartbeat, cursor)) = self.cursor_lane.reset(Instant::now()) {
            tracing::debug!(
                why,
                stalled_ms = stalled.as_millis() as u64,
                held_heartbeat = heartbeat,
                held_cursor = cursor,
                "cursor channel stall dropped with the channel: what it held is not sent"
            );
        }
    }

    /// Queue messages for `input` ([`PeerControl::SendReliable`], or [`PeerControl::SendRevocable`]
    /// when `revocable`) and write what fits now. Refused whole, with a debug line, while the
    /// channel is not open — no viewer is there to read them — or when the queue already holds
    /// [`RELIABLE_QUEUE_MAX`] (a viewer that stopped reading).
    fn queue_reliable(&mut self, messages: Vec<String>, revocable: bool) -> bool {
        let bytes: usize = messages.iter().map(String::len).sum();
        if self.input_channel.is_none() {
            tracing::debug!(
                messages = messages.len(),
                bytes,
                revocable,
                "reliable messages for the viewer dropped: the input channel is not open"
            );
            return false;
        }
        if self.reliable_out_bytes + bytes > RELIABLE_QUEUE_MAX {
            tracing::warn!(
                messages = messages.len(),
                bytes,
                revocable,
                queued = self.reliable_out.len(),
                queued_bytes = self.reliable_out_bytes,
                max_bytes = RELIABLE_QUEUE_MAX,
                "reliable messages for the viewer dropped: what is queued for the input channel \
                 is not draining (the viewer is not reading)"
            );
            return false;
        }
        tracing::debug!(
            messages = messages.len(),
            bytes,
            revocable,
            queued_before = self.reliable_out.len(),
            "reliable messages for the viewer queued on the input channel"
        );
        self.reliable_out_bytes += bytes;
        self.reliable_out.extend(
            messages
                .into_iter()
                .map(|text| QueuedReliable { text, revocable }),
        );
        self.write_reliable();
        self.input_channel.is_some()
    }

    /// Take back, unsent, the revocable messages still queued for `input`
    /// ([`PeerControl::RevokeQueued`]).
    fn revoke_reliable(&mut self) {
        let (dropped, dropped_bytes) = revoke_queued(&mut self.reliable_out);
        self.reliable_out_bytes = self.reliable_out_bytes.saturating_sub(dropped_bytes);
        if dropped == 0 {
            tracing::debug!(
                left = self.reliable_out.len(),
                "revocable reliable messages: none queued to take back (all already written)"
            );
            return;
        }
        tracing::debug!(
            dropped,
            dropped_bytes,
            left = self.reliable_out.len(),
            left_bytes = self.reliable_out_bytes,
            "revocable reliable messages taken back unsent; what str0m already took goes on"
        );
    }

    /// Write queued `input` messages while that channel's SCTP buffer holds less than
    /// [`RELIABLE_HIGH_WATER`]; the rest waits for a later turn. A message str0m refuses for room
    /// stays first in line; one it refuses with an error is dropped and said.
    ///
    /// Nothing is written while the `cursor` lane is stalled: the viewer acknowledges nothing, and
    /// a reliable chunk in flight would be retransmitted on sctp-proto's backed-off timer and stand
    /// in the way of the FORWARD-TSN the lane's kick is for. They wait here, in order; the stall's
    /// start and end lines say how many (`crate::cursor_lane`).
    fn write_reliable(&mut self) {
        if self.cursor_lane.stalled() {
            return;
        }
        let Some(id) = self.input_channel else {
            let dropped = self.reliable_out.len();
            self.reliable_out.clear();
            self.reliable_out_bytes = 0;
            tracing::debug!(
                dropped,
                "queued reliable messages dropped: the input channel closed"
            );
            return;
        };
        let Some(mut channel) = self.rtc.channel(id) else {
            tracing::trace!("reliable messages wait: the input channel is not writable yet");
            return;
        };
        let mut written = 0usize;
        let mut written_bytes = 0usize;
        let mut lane_failed = false;
        while let Some(QueuedReliable { text, .. }) = self.reliable_out.front() {
            if channel.buffered_amount() >= RELIABLE_HIGH_WATER {
                break;
            }
            let len = text.len();
            match channel.write(false, text.as_bytes()) {
                Ok(true) => {
                    written += 1;
                    written_bytes += len;
                }
                Ok(false) => break,
                Err(e) => {
                    tracing::debug!(
                        bytes = len,
                        "a reliable message for the viewer not written, dropped: {e}"
                    );
                    // A host's reliable lane does not skip a message: it closes.
                    if self.hooks.is_some() {
                        lane_failed = true;
                        break;
                    }
                }
            }
            self.reliable_out.pop_front();
            self.reliable_out_bytes = self.reliable_out_bytes.saturating_sub(len);
        }
        if let Some(hooks) = self.hooks.as_mut().filter(|_| lane_failed) {
            hooks.reliable_lane_failed();
            tracing::debug!(
                dropped = self.reliable_out.len(),
                "the host's input channel closed after a failed write"
            );
            self.input_channel = None;
            self.reliable_out.clear();
            self.reliable_out_bytes = 0;
            self.rtc.direct_api().close_data_channel(id);
        }
        if written > 0 {
            tracing::trace!(
                written,
                written_bytes,
                left = self.reliable_out.len(),
                left_bytes = self.reliable_out_bytes,
                "reliable messages written on the input channel"
            );
        }
    }

    /// Write one cursor report on the `cursor` channel, or hold it while the viewer acknowledges
    /// nothing. See [`PeerControl::SendCursor`] and [`Self::step_cursor_lane`].
    ///
    /// Up to thirty a second, so every outcome is trace — including a full SCTP buffer, which for
    /// a sample the next one replaces costs nothing (the orchestrator's cursor reporter counts what
    /// it sends in its own debug line).
    fn send_cursor_report(&mut self, text: String) {
        if let Some(hooks) = self.hooks.as_mut() {
            if let Some((id, mut channel)) = self
                .cursor_channel
                .and_then(|id| self.rtc.channel(id).map(|channel| (id, channel)))
            {
                if hooks.cursor_report(text.len(), channel.buffered_amount()) {
                    match channel.write(false, text.as_bytes()) {
                        Ok(true) => return,
                        Ok(false) => {}
                        Err(error) => {
                            tracing::debug!(%error, "cursor report write failed; the host's cursor channel closes");
                            hooks.cursor_lane_failed();
                            self.cursor_channel = None;
                            self.rtc.direct_api().close_data_channel(id);
                        }
                    }
                }
            }
            tracing::trace!("cursor report dropped: the host's cursor channel did not take it");
            return;
        }
        self.step_cursor_lane(Some((LaneKind::Cursor, text)));
    }

    /// Look up an mDNS host candidate and feed it back once it has an address.
    ///
    /// Off the run loop, because a multicast query with a timeout has no business inside a loop
    /// whose job is to release one RTP packet per turn. The resolved candidate returns through the
    /// signal queue as an ordinary [`PeerSignal::AddRemoteIce`], waiting for room rather than being
    /// refused ([`SignalSender::send_waiting`]), so there stays exactly one path into str0m and the
    /// rewritten string is parsed by the same code that parses every other candidate.
    ///
    /// Failure is quiet by design (one info line): a guest network with AP isolation, a phone on
    /// mobile data, a responder that never answers — all of them mean there was no direct path to
    /// find, and ICE carries on with the relay candidates it already has. This can only add a route.
    ///
    /// `source` is where the candidate came from: `trickle`, or the `offer` / `re-offer` whose own
    /// lines carried it ([`sdp_candidates`]). Each name is asked once ([`Self::mdns`]): the Mini
    /// App's resume signals the same host up to three times — trickled, in the re-sent offer, and
    /// trickled again. A name already resolved is fed in at once with its address (str0m ignores a
    /// candidate it already has in a pair; after a restart it is the new generation's); one being
    /// resolved gets this candidate added to those it feeds in, unless it is already among them. A
    /// failed name is forgotten, so its next signal asks again: a lost multicast answer is not a
    /// verdict.
    fn resolve_mdns(&mut self, cand: IceCandidate, name: String, source: &'static str) {
        if self.hooks.as_mut().is_some_and(|hooks| !hooks.admit_mdns()) {
            tracing::trace!(source, "mDNS candidate dropped by the host's hooks");
            return;
        }
        let key = name.to_ascii_lowercase();
        enum Seen {
            New,
            Resolved(Ipv4Addr),
            Resolving { waiting: usize, duplicate: bool },
        }
        let seen = {
            let mut book = mdns_book(&self.mdns);
            match book.get_mut(&key) {
                Some(MdnsName::Resolved(addr)) => Seen::Resolved(*addr),
                Some(MdnsName::Resolving(waiting)) => {
                    let duplicate = waiting.iter().any(|w| same_mdns_candidate(w, &cand));
                    if !duplicate {
                        waiting.push(cand.clone());
                    }
                    Seen::Resolving {
                        waiting: waiting.len(),
                        duplicate,
                    }
                }
                None => {
                    book.insert(key.clone(), MdnsName::Resolving(vec![cand.clone()]));
                    Seen::New
                }
            }
        };
        match seen {
            Seen::Resolved(addr) => {
                tracing::debug!(
                    %name,
                    %addr,
                    source,
                    ufrag = ?cand.username_fragment,
                    "mdns name already resolved: the candidate goes in with that address, no lookup"
                );
                match with_mdns_address(&cand, addr) {
                    Some(resolved) => self.add_remote_ice(resolved),
                    None => tracing::debug!(
                        candidate = %cand.candidate,
                        "the candidate names no mdns host after all; not used"
                    ),
                }
                return;
            }
            Seen::Resolving { waiting, duplicate } => {
                tracing::debug!(
                    %name,
                    source,
                    ufrag = ?cand.username_fragment,
                    waiting,
                    duplicate,
                    "mdns name already being resolved: no second lookup (duplicate=true: this very \
                     candidate already waits for it; false: it goes in with the others when the \
                     name resolves)"
                );
                return;
            }
            Seen::New => {}
        }
        let signals = self.signals.clone();
        let book = self.mdns.clone();
        let resolver = self.mdns_resolver.clone();
        // Every local address, not the one the routing table prefers. The name being looked up is
        // registered on the network the phone is on, and on a machine with a VPN up the preferred
        // address is the tunnel's — from which the query reaches nothing. Asking on each in turn
        // costs a timeout per dead interface and finds the answer on the live one.
        let interfaces = match resolver {
            MdnsResolver::Network => local_ipv4s(),
            #[cfg(test)]
            MdnsResolver::Table { .. } => Vec::new(),
        };
        tracing::debug!(
            %name,
            source,
            ufrag = ?cand.username_fragment,
            interfaces = ?interfaces,
            "resolving mdns candidate"
        );
        tokio::spawn(async move {
            let tried = interfaces.len();
            let resolved = match resolver {
                MdnsResolver::Network => {
                    let mut resolved = Err(anyhow::anyhow!("no local interface to ask from"));
                    for from in interfaces {
                        resolved = crate::mdns::resolve(&name, from).await;
                        match &resolved {
                            Ok(_) => break,
                            // Each dead interface costs a timeout; which ones failed, and how, is
                            // what tells an isolated guest network from a query that went out the
                            // VPN.
                            Err(e) => tracing::debug!(
                                %name,
                                %from,
                                "mdns lookup from this interface failed: {e:#}"
                            ),
                        }
                    }
                    resolved
                }
                #[cfg(test)]
                MdnsResolver::Table {
                    names,
                    delay,
                    asked,
                } => {
                    asked.fetch_add(1, Ordering::SeqCst);
                    tokio::time::sleep(delay).await;
                    names
                        .iter()
                        .find(|(n, _)| n.eq_ignore_ascii_case(&name))
                        .map(|(_, addr)| *addr)
                        .ok_or_else(|| anyhow::anyhow!("not in the test's table"))
                }
            };
            // Recorded before anything is fed in, so a candidate naming it from here on goes in at
            // once; and what waited for it, taken in the same look.
            let waiting = {
                let mut book = mdns_book(&book);
                let was = match &resolved {
                    Ok(addr) => book.insert(key, MdnsName::Resolved(*addr)),
                    Err(_) => book.remove(&key),
                };
                match was {
                    Some(MdnsName::Resolving(waiting)) => waiting,
                    _ => Vec::new(),
                }
            };
            match resolved {
                Ok(addr) => {
                    tracing::info!(
                        %name,
                        %addr,
                        candidates = waiting.len(),
                        "resolved mdns candidate; a direct path is possible"
                    );
                    for cand in waiting {
                        let Some(resolved) = with_mdns_address(&cand, addr) else {
                            tracing::debug!(
                                candidate = %cand.candidate,
                                "the candidate names no mdns host after all; not used"
                            );
                            continue;
                        };
                        match signals
                            .send_waiting(PeerSignal::AddRemoteIce(resolved))
                            .await
                        {
                            // Per candidate, so trace: the info line above has their count, and
                            // each says `remote candidate` once the peer has parsed it.
                            Ok(depth) => tracing::trace!(
                                %name,
                                depth,
                                "resolved mdns candidate queued for the peer"
                            ),
                            Err(_) => {
                                tracing::debug!(
                                    %name,
                                    "the peer ended before its mdns candidate resolved"
                                );
                                break;
                            }
                        }
                    }
                }
                Err(e) => tracing::info!(
                    %name,
                    tried,
                    candidates = waiting.len(),
                    "mdns lookup failed, relay only: {e:#}"
                ),
            }
        });
    }

    /// Keep the STUN transaction running on the loop going: DNS answers in, due retransmissions
    /// out, and a warning when it runs out of time.
    ///
    /// Called at the top of every turn while one is running, which before ICE connects is dozens
    /// of times a second; [`Self::srflx_wait`] makes sure the loop also wakes for it when nothing
    /// else would. Stops for good on a mapping (see [`Self::take_srflx_reply`]), on `Connected`
    /// or a restored path, or when the transaction's 19.75 s are up.
    async fn drive_srflx(&mut self) {
        let Some(late) = self.srflx.as_mut() else {
            return;
        };
        let now = Instant::now();
        while let Ok((idx, res)) = late.lookups.try_recv() {
            late.probe.resolved(idx, res);
        }
        while let Some(t) = late.probe.poll_transmit(now) {
            if let Err(e) = self.socket.send_stun_to(&t.bytes, t.to).await {
                late.probe.send_failed(t.idx, e.to_string());
            }
        }
        if late.probe.is_finished(now) {
            match self.srflx_addr {
                // A rediscovery after a restart that found nothing: the mapping already offered
                // is all there is, which is not a new failure.
                Some(current) => tracing::info!(
                    after = late.after,
                    restarts = late.restarts,
                    attempts = late.probe.attempts(),
                    elapsed_ms = late.probe.elapsed_ms(now),
                    cause = late.probe.cause(),
                    servers = %late.probe.describe(),
                    %current,
                    "STUN: no fresh srflx mapping; the one already offered stays in use"
                ),
                None => tracing::warn!(
                    after = late.after,
                    restarts = late.restarts,
                    attempts = late.probe.attempts(),
                    elapsed_ms = late.probe.elapsed_ms(now),
                    cause = late.probe.cause(),
                    servers = %late.probe.describe(),
                    "STUN: gave up on a srflx candidate; a viewer that can reach this PC only \
                     through its relay cannot connect in this session"
                ),
            }
            self.srflx = None;
        }
    }

    /// How long the loop may sleep before the running STUN transaction needs it, if one is.
    fn srflx_wait(&self, now: Instant) -> Option<Duration> {
        let late = self.srflx.as_ref()?;
        let mut wake = late.probe.next_wake();
        if late.probe.has_unresolved() {
            wake = wake.min(now + SRFLX_DNS_POLL);
        }
        // Never zero: anything already due was served at the top of this turn, and a zero wait
        // that stays zero is the busy loop `IDLE_TURN` exists to prevent.
        Some(wake.saturating_duration_since(now).max(IDLE_TURN))
    }

    /// Whether a datagram was a reply to the running STUN transaction. A mapping is adopted on the
    /// spot, which ends the transaction.
    async fn take_srflx_reply(&mut self, source: SocketAddr, datagram: &[u8]) -> bool {
        let Some(late) = self.srflx.as_mut() else {
            return false;
        };
        let (mapped, server) = match late.probe.handle_input(source, datagram) {
            stun::Input::NotOurs => return false,
            stun::Input::Consumed => return true,
            stun::Input::Mapped { addr, server } => (addr, server),
        };
        if let Some(late) = self.srflx.take() {
            self.adopt_late_srflx(late, mapped, server).await;
        }
        true
    }

    /// Add a mapping that arrived after the answer to the `Rtc`, and hand it to the orchestrator
    /// to trickle to the viewer.
    ///
    /// The viewer's side of this already existed: it passes an agent's `ice` message to
    /// `addIceCandidate`, and buffers it if the answer has not been applied yet.
    async fn adopt_late_srflx(&mut self, late: LateSrflx, mapped: SocketAddr, server: usize) {
        let now = Instant::now();
        let via = late.probe.server_name(server).to_string();
        let attempts = late.probe.attempts();
        let elapsed_ms = late.probe.elapsed_ms(now);
        // A restart answer held for this discovery goes first, whatever the mapping turns out to
        // be: the candidate below names the restart's ufrag and must not overtake the answer that
        // introduces it.
        self.release_held_answer("mapping_arrived").await;
        if is_own_address(mapped, &self.own_ips) {
            tracing::info!(
                %mapped,
                %via,
                attempts,
                elapsed_ms,
                after = late.after,
                restarts = late.restarts,
                "STUN: the late mapped address is this machine's own; no srflx candidate needed"
            );
            return;
        }
        // Already a local candidate, so already in the answer this discovery followed: str0m keeps
        // local candidates across an ICE restart. Re-adding it would make str0m replace it and
        // discard its pairs mid-check; trickling it would tell the viewer nothing new.
        if self.srflx_addr == Some(mapped) {
            tracing::info!(
                %mapped,
                %via,
                attempts,
                elapsed_ms,
                after = late.after,
                "STUN: the srflx mapping is unchanged and already offered; nothing to trickle"
            );
            return;
        }
        let candidate = match srflx_candidate(mapped, self.host_ip, self.bound_port) {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!("late srflx candidate not usable: {e:#}");
                return;
            }
        };
        // What str0m accepted, not what we built: it adopts the candidate by stamping our ufrag on
        // it, and that is the form the viewer should see.
        let Some(added) = self.rtc.add_local_candidate(candidate) else {
            tracing::warn!(%mapped, "str0m refused the late srflx candidate as redundant");
            return;
        };
        let ice = IceCandidate {
            candidate: added.to_sdp_string(),
            sdp_mid: late.sdp_mid.clone(),
            sdp_mline_index: Some(0),
            username_fragment: added.ufrag().map(str::to_string),
        };
        tracing::info!(
            attempts,
            elapsed_ms,
            after = late.after,
            restarts = late.restarts,
            replaces = ?self.srflx_addr,
            "late srflx candidate {mapped} (via {via}); trickling it to the viewer"
        );
        self.srflx_addr = Some(mapped);
        if self
            .events
            .send(PeerEvent::LocalCandidate(ice))
            .await
            .is_err()
        {
            tracing::debug!(%mapped, "the orchestrator is gone; late srflx candidate not trickled");
        }
    }

    /// Record whether this negotiation left str0m able to probe at all. Once per session.
    ///
    /// ## Why a log line decides a design question
    ///
    /// str0m's bandwidth estimate can only rise to `acknowledged * 1.5 + 10 kbps`
    /// (`bwe/delay/rate_control.rs:21,191,242` — goog-cc's own increase rule). To learn that a
    /// quiet link could carry more than it is currently carrying, something has to *send* more,
    /// and on a still screen the encoder has nothing to send. That something is a probe cluster:
    /// padding packets emitted purely to demonstrate capacity.
    ///
    /// Whether this session can emit one at all, as of str0m 0.24.1 (#1046), is decided by what
    /// the m-line negotiated, not by RTX alone (`Session::probe_media` / `probe_pt`,
    /// `str0m-0.24.1/src/session.rs:416-441`): a sending video m-line whose remote extmap has the
    /// transport sequence number and whose H.264 PT has `transport-cc` feedback. With that, probe
    /// clusters go out — as RTX padding on the video stream once it has sent media and has an RTX
    /// PT, otherwise on a non-media SSRC 0 stream bound only while a cluster runs
    /// (`Streams::set_probe_media` / `send_queue_states`, `streams/mod.rs:616-658`), the way
    /// libwebrtc probes before media. str0m reports the same condition itself with every estimate
    /// (`BweKind::Twcc`'s `can_probe`, logged where the estimate is handled).
    ///
    /// RTX still decides the rest (`streams/send.rs:502`):
    ///
    /// ```ignore
    /// fn padding_enabled(&self) -> bool {
    ///     (self.ssrc.is_probe() || self.rtx.is_some()) && self.pt_for_padding.is_some()
    /// }
    /// ```
    ///
    /// Without an RTX payload type for the H.264 PT str0m sends no padding outside a cluster and
    /// retransmits nothing — a lost packet is a broken frame until the next keyframe. (str0m 0.23.1
    /// went further and discarded the clusters too, `pacer/leaky.rs:420-423` there.) Both halves of
    /// RTX are observable from outside: `resend()` on the negotiated `PayloadParams` is the RTX
    /// payload type, and `StreamTx::rtx()` is the RTX SSRC str0m allocated for it.
    ///
    /// `fb_transport_cc` is on the same line because it decides something else that has been
    /// asserted in this tree and never checked: transport-wide congestion control feedback is what
    /// makes the estimate send-side at all, and libwebrtc's pacing multiplier drops from 2.5 to 1.1
    /// on the first feedback packet.
    fn log_probe_capability(&mut self, mid: Mid) {
        let params: Vec<_> = match self.rtc.writer(mid) {
            Some(w) => w.payload_params().copied().collect(),
            None => {
                tracing::debug!(%mid, "no writer for the video m-line: payload types not listed");
                return;
            }
        };
        for p in &params {
            tracing::info!(
                pt = *p.pt(),
                codec = ?p.spec().codec,
                rtx_pt = p.resend().map_or_else(|| "-".to_string(), |r| r.to_string()),
                transport_cc = p.fb_transport_cc(),
                nack = p.fb_nack(),
                pli = p.fb_pli(),
                "negotiated payload type"
            );
        }
        // `pt_for_padding` is `first_pt_with_rtx`, so this is that half of `padding_enabled`.
        let any_rtx_pt = params
            .iter()
            .any(|p| p.spec().codec == Codec::H264 && p.resend().is_some());
        let rtx_ssrc = self
            .rtc
            .direct_api()
            .stream_tx_by_mid(mid, None)
            .and_then(|s| s.rtx());
        let rtx = any_rtx_pt && rtx_ssrc.is_some();
        // str0m 0.24.1's own test for probing (`Session::probe_pt`): the transport sequence
        // number in the viewer's extmap and `transport-cc` feedback on the PT.
        let twcc_ext_id = self
            .rtc
            .media(mid)
            .and_then(|m| m.remote_extmap().id_of(Extension::TransportSequenceNumber));
        let h264_transport_cc = params
            .iter()
            .any(|p| p.spec().codec == Codec::H264 && p.fb_transport_cc());
        let can_probe = twcc_ext_id.is_some() && h264_transport_cc;
        // The warnings below are not about a malfunction — each is a statement about what the
        // estimate or a lost packet can mean for the rest of this session, and every later reading
        // has to be interpreted against this line.
        match (can_probe, rtx) {
            (true, true) => tracing::info!(
                rtx_ssrc = ?rtx_ssrc,
                twcc_ext_id = ?twcc_ext_id,
                "probing available: transport-wide feedback negotiated and RTX padding on the \
                 video stream, so the estimate can exceed acked traffic"
            ),
            (true, false) => tracing::warn!(
                h264_rtx_pt = any_rtx_pt,
                rtx_ssrc = ?rtx_ssrc,
                twcc_ext_id = ?twcc_ext_id,
                "no RTX on the video m-line: str0m still probes (its clusters go on a non-media \
                 SSRC 0 stream) but pads nothing else and retransmits nothing, so a lost packet \
                 breaks the picture until the next keyframe"
            ),
            (false, _) => tracing::warn!(
                h264_rtx_pt = any_rtx_pt,
                rtx_ssrc = ?rtx_ssrc,
                twcc_ext_id = ?twcc_ext_id,
                h264_transport_cc,
                "probing unavailable: no transport-wide feedback on the video m-line, so str0m \
                 queues no probe and the estimate is bounded by acked traffic (acked * 1.5 + 10 \
                 kbps) and cannot discover idle capacity"
            ),
        }
    }

    /// Record which of the two jitter-buffer extensions the viewer actually accepted. Once per
    /// session, next to [`Self::log_probe_capability`] and for the same reason.
    ///
    /// ## Why this is a log line and not an assumption
    ///
    /// An RTP header extension is written only if both ends agreed an id for it. str0m enforces
    /// that at the media level: `update_media` (`change/sdp.rs:1337-1357`) keeps an entry only
    /// when the id appears in the remote's extmap *and* resolves to the same `Extension` in our
    /// session map, and packetisation writes from exactly that map (`session.rs:1006`). So a
    /// `playout_delay(..)` call on a session where the viewer omitted the URI is silently a no-op
    /// — the values go into `ExtensionValues` and are dropped on the way to the wire.
    ///
    /// That failure is invisible from the agent's side and looks, in the numbers, exactly like
    /// "the setting did not help". Printing the negotiated ids makes the difference between "the
    /// lever is connected and this is what it bought" and "the lever was never connected" a
    /// question a session log answers.
    ///
    /// `video_content_type` is listed even though nothing writes it: str0m 0.23.1's `Writer`
    /// (`media/writer.rs:69-120`) exposes `playout_delay`, `video_orientation`, `audio_level`,
    /// `abs_capture_time` and a user-extension escape hatch, but no setter for
    /// `ExtensionValues::video_content_type`, and the escape hatch cannot be used for a URI str0m
    /// knows natively (a `UnknownUri` never compares equal to the built-in variant the remote SDP
    /// parses into, `rtp/ext.rs:1269`, so the entry would be dropped by the check above). The
    /// extension is therefore negotiated and ready; writing the screenshare byte needs either a
    /// str0m `Writer` method or the RTP-level API, which this crate does not use.
    fn log_negotiated_jitter_extensions(&self, mid: Mid) {
        let Some(media) = self.rtc.media(mid) else {
            tracing::debug!(%mid, "no media for the video m-line: extensions not listed");
            return;
        };
        let exts = media.remote_extmap();
        let playout_delay = exts.id_of(Extension::PlayoutDelay);
        let video_content_type = exts.id_of(Extension::VideoContentType);
        if playout_delay.is_some() {
            tracing::info!(
                playout_delay_ext_id = playout_delay,
                video_content_type_ext_id = video_content_type,
                clean_min_ms = PlayoutDelay::CLEAN.min_ms,
                clean_max_ms = PLAYOUT_DELAY_MAX_MS,
                lossy_max_ms = PLAYOUT_DELAY_MAX_LOSSY_MS,
                lossy_reports_to_hold = LOSS_REPORTS_TO_HOLD,
                window_s = LOSS_MEMORY.as_secs(),
                release_ramp_ms_per_s = RELEASE_RAMP_MS_PER_S,
                release_min_floor_ms = RELEASE_MIN_FLOOR_MS,
                release_margin_ms = RELEASE_MAX_MARGIN_MS,
                release_max_floor_ms = RELEASE_MAX_FLOOR_MS,
                "playout-delay negotiated: the viewer renders frames as soon as they are decodable \
                 while the link is clean, and is asked to hold them for one retransmission's round \
                 trip (at most lossy_max_ms) once lossy_reports_to_hold receiver reports in window_s \
                 have shown loss; a hold is released fast to the clean pair for a Chromium viewer, \
                 and for any other at release_ramp_ms_per_s down to release_min_floor_ms, where it \
                 parks for the rest of the session by design, the max following the viewer's \
                 jitter-buffer target + release_margin_ms, never below release_max_floor_ms"
            );
        } else {
            // Not a malfunction — it is a statement about what every later `jbuf_ms` reading in
            // this session can mean. Without the header the browser sizes its buffer alone.
            tracing::warn!(
                video_content_type_ext_id = video_content_type,
                "playout-delay not negotiated: the viewer ignored the extension, so its jitter \
                 buffer is unbounded from here and jbuf_ms reflects Chrome's own policy"
            );
        }
    }

    /// How long the oldest packet still waiting has been waiting, in milliseconds. See
    /// [`Peer::queue_age_ms`].
    ///
    /// Measured, not inferred. Read fresh from str0m on every call because this is the number the
    /// circuit breaker acts on, and one stale read is a discarded frame.
    fn queue_age_ms(&mut self) -> u32 {
        let Some(mid) = self.video_mid else {
            return 0;
        };
        let now = Instant::now();
        let age = self
            .rtc
            .direct_api()
            .stream_tx_by_mid(mid, None)
            .and_then(|s| s.queue_info())
            .filter(|q| {
                // A snapshot str0m has not refreshed recently describes a moment that has passed.
                // It is recomputed when the pacer releases a packet, so a stale one means nothing
                // has gone out lately — which means nothing is waiting, not that something is late.
                now.saturating_duration_since(q.created_at()).as_millis()
                    <= u128::from(QUEUE_SAMPLE_FRESH_MS)
            })
            .and_then(|q| q.first_unsent())
            .map_or(0, |t| now.saturating_duration_since(t).as_millis());
        u32::try_from(age).unwrap_or(u32::MAX)
    }

    /// Publish how far behind the send queue is, for the capture thread to act on.
    ///
    /// ## Why this is the signal and the bandwidth estimate is not
    ///
    /// str0m's send queue is an unbounded `VecDeque` with no eviction and no age check, and its
    /// pacer's only defence is to raise the drain rate once the average wait passes two seconds —
    /// which relocates the delay into the bottleneck rather than removing it. Bounding it is
    /// explicitly the application's job: `queue_info()` exists because someone hit exactly this
    /// (str0m issue #1001, a cloud-gaming sender whose "backlog grows without bound"), and the
    /// maintainer's answer was to expose the queue and leave the drop policy to the caller.
    ///
    /// `first_unsent()` is better than a byte count because it needs no division by a rate we
    /// would have to guess: it is the delay, measured. A bandwidth estimate says what the link
    /// might carry; this says what is already late.
    fn sample_send_queue(&mut self) {
        let Some(mid) = self.video_mid else {
            return;
        };
        // Bytes, not milliseconds, and the change is not cosmetic.
        //
        // Publishing a delay here (`first_unsent().elapsed()`) goes wrong two ways.
        //
        // Ignoring `created_at`, a snapshot taken during a brief burst keeps reporting that burst
        // until something refreshes it — and nothing refreshes it precisely when there is no
        // traffic. A static desktop sending 134 kbps, on which a queue of that depth is not
        // possible, reported a p90 of 672 ms and had its capture rate throttled for it.
        //
        // Guarding that with a freshness window creates the opposite failure, because the
        // snapshot is recomputed when the pacer releases a packet: its refresh interval is
        // inversely proportional to the bitrate. At 1150-byte packets, 375 kbps is a tick every
        // 25 ms and 60 kbps is one every 160 — so below roughly 120 kbps the reading would be
        // discarded as stale every time, the gauge would read a permanent zero, and the whole
        // latency subsystem would switch itself off on exactly the links it exists to protect.
        //
        // A byte count has neither problem. It needs no division by a rate anyone has to estimate,
        // so there is no freshness race against the bitrate, and it is already the unit the
        // capturer's credit is denominated in.
        let bytes = self
            .rtc
            .direct_api()
            .stream_tx_by_mid(mid, None)
            .and_then(|s| s.queue_info().map(|q| q.byte_size()))
            .map_or(0, |n| u32::try_from(n).unwrap_or(u32::MAX));
        // Plus what is waiting in the channel between the encoder and this loop. Those frames are
        // just as committed and just as invisible to the viewer; leaving them out would make the
        // latency signal under-report by the channel's whole depth.
        let queued_here = self.queued_media_bytes.load(Ordering::Relaxed);
        self.outstanding_bytes
            .store(bytes.saturating_add(queued_here), Ordering::Relaxed);
        // And the measured age, which is what actually decides anything. Bytes are for the log.
        let age = self.queue_age_ms();
        self.queue_age.store(age, Ordering::Relaxed);
    }

    /// Drain `poll_output` until the next `Timeout`, sending datagrams and
    /// dispatching events along the way.
    async fn drain(&mut self) -> Result<Instant> {
        // One clock read for everything this drain sends: the datagrams leave microseconds apart,
        // and the path counters need no finer time than that.
        let mut sent_at: Option<Instant> = None;
        loop {
            match self.rtc.poll_output()? {
                Output::Timeout(t) => return Ok(t),
                Output::Transmit(t) => {
                    self.egress.bytes += t.contents.len() as u64;
                    self.egress.packets += 1;
                    // The same bytes, counted a second time and never reset. The meter above is
                    // windowed and republished once a second, which is the wrong shape for a
                    // conservation check read every 200 ms. See `Peer::egress_bytes_total`.
                    self.egress_total
                        .fetch_add(t.contents.len() as u64, Ordering::Relaxed);
                    self.note_transmit(t.source, t.destination, t.contents.first().copied());
                    let at = *sent_at.get_or_insert_with(Instant::now);
                    let noted =
                        self.paths
                            .note(Dir::Out, Some(t.source), t.destination, &t.contents, at);
                    // Everything str0m sends but its STUN checks and replies goes to its send pair.
                    if noted.kind != Kind::Stun {
                        self.note_send_path(t.destination, at);
                    }
                    if noted.kind == Kind::Dtls {
                        self.note_dtls_datagram(
                            Dir::Out,
                            t.destination,
                            t.contents.len(),
                            noted,
                            at,
                        );
                    }
                    match self.socket.send_to(&t.contents, t.destination).await {
                        // The summary's `bytes_socket`/`bytes_relay`: what the socket took.
                        Ok(_) => {
                            let relay = self.is_relay_destination(t.destination);
                            self.socket_bytes.note(t.contents.len(), relay);
                        }
                        Err(e) => {
                            tracing::trace!("udp send: {e}");
                            // Counted for the once-a-second summary in `EgressMeter::report_if_due`.
                            self.egress.send_errors += 1;
                            self.egress.last_send_error =
                                Some(format!("{e} (to {})", t.destination));
                        }
                    }
                }
                Output::Event(e) => self.handle_event(e).await,
            }
        }
    }

    async fn handle_event(&mut self, e: Event) {
        match e {
            Event::Connected => {
                self.connected = true;
                let dtls_after_ice = self.dtls.dtls_up(Instant::now());
                // The message is read by the video bench's log parser: fields may be added, the
                // text may not change.
                tracing::info!(
                    elapsed_ms = self.start.elapsed().as_millis() as u64,
                    frames_before = self.unsent_before_connect,
                    dtls_role = self.dtls_role.as_str(),
                    dtls_after_ice_ms = dtls_after_ice.map(|d| d.as_millis() as u64),
                    pair = self.pair_label(),
                    send_to = %self.send_to.map_or_else(
                        || "-".to_string(),
                        |a| format!("{a} ({})", short_kind(&self.remote_candidates, a))
                    ),
                    send_pairs_left = self.follow.left.len(),
                    dtls_out = self.paths.dtls_summary(Dir::Out, self.start),
                    dtls_in = self.paths.dtls_summary(Dir::In, self.start),
                    "webrtc connected: ICE and DTLS are up; media flows from here"
                );
                self.publish_path(Instant::now(), "dtls_up");
                // A path exists, so a late srflx candidate has nothing left to enable.
                if let Some(late) = self.srflx.take() {
                    tracing::info!(
                        attempts = late.probe.attempts(),
                        elapsed_ms = late.probe.elapsed_ms(Instant::now()),
                        "connected before a srflx candidate arrived; STUN retries stopped"
                    );
                }
                if self.events.send(PeerEvent::Connected).await.is_err() {
                    tracing::debug!("the orchestrator is gone; connection not reported");
                }
                // The encoder started with the answer, so its opening IDR — and every frame since —
                // was made before there was anywhere to send it. The frames arriving from here
                // reference that IDR; ask for a keyframe now rather than on the first of them, so
                // the viewer's first picture is not a round trip of undecodable deltas away.
                if let Some(b) = self.chain.broken() {
                    let now = Instant::now();
                    self.chain.asked(now);
                    let asked = self.chain.broken().unwrap_or(b);
                    self.request_keyframe(asked, now);
                }
            }
            // Not the end of the session any more: a lost path opens the grace window. See
            // `on_ice_state` and `ICE_GRACE`.
            Event::IceConnectionStateChange(state) => self.on_ice_state(state).await,
            Event::MediaAdded(m) => {
                if m.kind == MediaKind::Video {
                    tracing::info!("video m-line added: mid={}", m.mid);
                    self.video_mid = Some(m.mid);
                    self.log_probe_capability(m.mid);
                    self.log_negotiated_jitter_extensions(m.mid);
                    self.rtx_ssrc = self
                        .rtc
                        .direct_api()
                        .stream_tx_by_mid(m.mid, None)
                        .and_then(|s| s.rtx());
                    if self.rtx_trace.is_some() && self.rtx_ssrc.is_none() {
                        // Without an RTX SSRC str0m cannot retransmit at all, so the trace would
                        // only ever count NACKs; say so once rather than report "unanswered".
                        tracing::debug!(
                            mid = %m.mid,
                            "retransmission trace: no RTX SSRC on the video stream; retransmissions \
                             cannot be matched to NACKs"
                        );
                    }
                } else {
                    tracing::debug!(mid = %m.mid, kind = ?m.kind, "non-video m-line: not used");
                }
            }
            Event::ChannelOpen(id, label) => {
                if let Some(hooks) = self.hooks.as_mut() {
                    use str0m::channel::Reliability;
                    let config = self.rtc.channel(id).and_then(|channel| {
                        channel.config().map(|cfg| (cfg.ordered, cfg.reliability))
                    });
                    let delivery = match config {
                        Some((true, Reliability::Reliable)) => ChannelDelivery::ReliableOrdered,
                        Some((false, Reliability::MaxRetransmits { retransmits: 0 })) => {
                            ChannelDelivery::UnorderedLatest
                        }
                        _ => ChannelDelivery::Other,
                    };
                    let role = hooks.channel_opened(OpenedChannel {
                        label: &label,
                        delivery,
                        input_taken: self.input_channel.is_some(),
                        cursor_taken: self.cursor_channel.is_some(),
                    });
                    tracing::debug!(%label, ?delivery, ?role, "data channel open; the host's role for it");
                    match role {
                        ChannelRole::Input => self.input_channel = Some(id),
                        ChannelRole::Cursor => self.cursor_channel = Some(id),
                        ChannelRole::Refuse => self.rtc.disconnect(),
                    }
                    return;
                }
                tracing::info!("data channel open: {label}");
                // Both input channels are accepted and both feed the same parser. The
                // label decides nothing about how a message is handled — a peer that
                // puts a button-up on the cursor channel is buggy or hostile, and
                // either way the event still has to be applied rather than dropped,
                // because dropping it is what leaves a button held.
                match label.as_str() {
                    CHANNEL_INPUT => self.input_channel = Some(id),
                    CHANNEL_CURSOR => {
                        self.cursor_channel = Some(id);
                        self.reset_cursor_lane("cursor channel opened");
                    }
                    other => tracing::debug!("ignoring unknown data channel: {other}"),
                }
            }
            Event::ChannelClose(id) => {
                if let Some(hooks) = self.hooks.as_mut() {
                    let role = if Some(id) == self.input_channel {
                        self.input_channel = None;
                        ChannelRole::Input
                    } else if Some(id) == self.cursor_channel {
                        self.cursor_channel = None;
                        ChannelRole::Cursor
                    } else {
                        tracing::debug!(?id, "unknown data channel closed");
                        return;
                    };
                    tracing::debug!(?role, "the host's data channel closed");
                    hooks.channel_closed(role);
                    return;
                }
                if Some(id) == self.input_channel {
                    // The reliable channel is how a release would have arrived. With it
                    // gone, the viewer has no way left to release whatever is held,
                    // so the agent has to do it.
                    self.input_channel = None;
                    tracing::info!("input channel closed");
                    if self
                        .events
                        .send(PeerEvent::InputChannelClosed)
                        .await
                        .is_err()
                    {
                        tracing::debug!(
                            "the orchestrator is gone; input channel close not reported"
                        );
                    }
                } else if Some(id) == self.cursor_channel {
                    // The heartbeat rides this channel; from here the viewer hears nothing about
                    // the pipeline, which it would otherwise read as the agent having died.
                    self.cursor_channel = None;
                    tracing::info!("cursor channel closed; heartbeats stop");
                    self.reset_cursor_lane("cursor channel closed");
                } else {
                    tracing::debug!(?id, "unknown data channel closed");
                }
            }
            Event::ChannelData(cd) => {
                if let Some(hooks) = self.hooks.as_mut() {
                    let received = Instant::now();
                    let role = if Some(cd.id) == self.input_channel {
                        ChannelRole::Input
                    } else if Some(cd.id) == self.cursor_channel {
                        ChannelRole::Cursor
                    } else {
                        tracing::trace!(id = ?cd.id, bytes = cd.data.len(), "data on an unknown channel ignored");
                        return;
                    };
                    if hooks.data(role, cd.data, cd.binary, received) == DataVerdict::Disconnect {
                        tracing::debug!(
                            ?role,
                            "the host's hooks ended the peer on a data-channel message"
                        );
                        self.rtc.disconnect();
                    }
                    return;
                }
                if Some(cd.id) == self.input_channel || Some(cd.id) == self.cursor_channel {
                    // The viewer's SCTP is talking: if ours is stalled towards it, kick it.
                    self.note_viewer_back("viewer_data");
                    if self
                        .events
                        .send(PeerEvent::InputData(cd.data))
                        .await
                        .is_err()
                    {
                        tracing::trace!("input dropped: the orchestrator is gone");
                    }
                } else {
                    tracing::trace!(id = ?cd.id, bytes = cd.data.len(), "data on an unknown channel ignored");
                }
            }
            Event::KeyframeRequest(r) => {
                self.note_keyframe_request(r.kind);
                // The viewer's decoder lost the picture: a stall for the playout cushion, unless
                // it follows loss (`crate::playout`).
                self.playout.note_keyframe_request(Instant::now());
                if self
                    .events
                    .send(PeerEvent::KeyframeRequest(KeyframeAsk::Viewer))
                    .await
                    .is_err()
                {
                    tracing::trace!("keyframe request dropped: the orchestrator is gone");
                }
            }
            Event::EgressBitrateEstimate(kind) => {
                // Deliberately does NOT feed the estimate back via `set_desired_bitrate`.
                //
                // That is what the first version did, on the reasoning that telling str0m what
                // we intend to send stops it probing beyond what the pipeline produces. It is a
                // ratchet. `set_desired_bitrate` is the ceiling BWE probes *towards*, so setting
                // it to the current estimate says "you have reached my target, stop probing" —
                // and probing is the only way an estimate ever rises. Every drop became
                // permanent.
                //
                // Observed on a healthy link: zero packet loss, 129 ms round trip, and an
                // estimate that fell to 52 kbps over two minutes and stayed there. The ceiling
                // is now set once, at construction.
                //
                // str0m 0.24 says with each TWCC estimate whether its estimator can probe
                // (`can_probe`: SRTP keys and a sending m-line with TWCC feedback and the transport
                // sequence extension). The first event comes when that becomes true — after DTLS,
                // carrying the configured start, `INITIAL_BITRATE_KBPS`, as 0.23 did at once. If it
                // ever turns false, str0m repeats the last estimate once and then sends nothing
                // until probing is back: the number below stops moving. That is logged; the value
                // is still the last estimate there is, so it is passed on as before.
                let (estimate, can_probe) = match kind {
                    BweKind::Twcc {
                        estimate,
                        can_probe,
                    } => (estimate, Some(can_probe)),
                    BweKind::Remb { estimate, .. } => (estimate, None),
                    // `BweKind` is #[non_exhaustive]: a str0m upgrade may add an estimator, and
                    // silently ignoring it would leave adaptation dead with no sign of why.
                    other => {
                        tracing::debug!("unhandled bandwidth estimate kind: {other:?}");
                        return;
                    }
                };
                let kbps = (estimate.as_u64() / 1000) as u32;
                if let Some(can_probe) = can_probe {
                    let was = self.bwe_can_probe.replace(can_probe);
                    match (was, can_probe) {
                        (Some(true), true) | (Some(false), false) => {}
                        (None | Some(false), true) => tracing::debug!(
                            kbps,
                            was = ?was,
                            "bandwidth estimator can probe: str0m's TWCC estimate is live from here"
                        ),
                        (_, false) => tracing::warn!(
                            kbps,
                            was = ?was,
                            "bandwidth estimator cannot probe (no SRTP keys, or no sending m-line \
                             with TWCC feedback): str0m holds its estimate here and sends no \
                             updates until it can again"
                        ),
                    }
                }
                self.estimate_kbps = kbps;
                // Trace: one per feedback report, and the pipeline line carries it once a second.
                tracing::trace!(kbps, ?can_probe, "bandwidth estimate");
                if self
                    .events
                    .send(PeerEvent::BitrateEstimate { kbps })
                    .await
                    .is_err()
                {
                    tracing::trace!("estimate dropped: the orchestrator is gone");
                }
            }
            // What the receiver says about what it actually got. The other half of every latency
            // sum this project has ever written down, and the only place a PLI storm is visible.
            Event::MediaEgressStats(s) => {
                // Two of these four numbers are not only telemetry: they size the viewer's
                // jitter buffer from here, once a second, through `crate::playout`.
                //
                // Either sign of a lossy link counts. `loss` is the receiver report's fraction
                // lost, which rounds to zero for a single packet in a second at this bitrate;
                // `nacks` counts the retransmission requests themselves and so catches exactly that
                // case. The NACK counter is cumulative, so what matters is the increase since the
                // last report.
                let new_nacks = s.nacks.saturating_sub(self.last_nacks);
                // Trace: once a second, and every number here is on the pipeline line.
                tracing::trace!(
                    rtt_ms = ?s.rtt.map(|d| d.as_millis() as u64),
                    loss = ?s.loss,
                    plis = s.plis,
                    nacks = s.nacks,
                    new_nacks,
                    firs = s.firs,
                    "egress stats"
                );
                self.last_nacks = s.nacks;
                self.playout
                    .note_report(Instant::now(), s.rtt, s.loss, new_nacks);
                if self
                    .events
                    .send(PeerEvent::LinkStats {
                        rtt_ms: s.rtt.map(|d| d.as_millis() as u32),
                        loss: s.loss,
                        plis: s.plis,
                        nacks: s.nacks,
                        firs: s.firs,
                    })
                    .await
                    .is_err()
                {
                    tracing::trace!("egress stats dropped: the orchestrator is gone");
                }
            }
            // The viewer's DTLS or SCTP said goodbye. str0m winds down after this, and the run loop
            // ends on `!is_alive()` with `ViewerClosed`; this line is the viewer's half of that
            // story. str0m's event says nothing of which of the two it was (its own debug line
            // `Association lost, reason: …` does, and sctp-proto's `error` line for a packet it
            // could not take).
            Event::Closed => {
                self.viewer_goodbye = true;
                tracing::info!(
                    "the viewer closed DTLS/SCTP; the peer is shutting down (the viewer's own end)"
                )
            }
            Event::MediaChanged(m) => {
                tracing::debug!(mid = %m.mid, direction = ?m.direction, "media direction changed");
            }
            Event::StreamPaused(p) => tracing::debug!(
                mid = %p.mid,
                paused = p.paused,
                "incoming stream pause state changed"
            ),
            // str0m's debug mirror of every RTCP packet received and every RTP packet sent, on
            // only while the retransmission trace is (`trace_rtx` in `spawn_peer_on`).
            Event::RawPacket(p) => self.note_raw_packet(&p),
            // Once a second: the one place str0m names the pair it nominated.
            Event::PeerStats(s) => self.note_peer_stats(&s),
            // Per-packet and per-second statistics this agent does not use. Trace, because their
            // Debug form can be large.
            other => tracing::trace!("unhandled str0m event: {other:?}"),
        }
    }

    /// One datagram about to leave: if it is media, has the path it takes changed?
    ///
    /// Per packet, so it does one byte comparison for anything that is not RTP or RTCP and one
    /// address comparison for anything that is. str0m does not report the selected candidate pair
    /// (its `NominatedSend` stays inside `Rtc`), but it sends every RTP and RTCP packet to that
    /// pair and nothing else, so the 5-tuple the media leaves on *is* the selected pair. STUN
    /// checks go to every candidate and are not media, which is why the first byte decides
    /// (RFC 7983: 128-191 is RTP/RTCP, 0-3 STUN, 20-63 DTLS).
    fn note_transmit(&mut self, source: SocketAddr, destination: SocketAddr, first: Option<u8>) {
        match media_route_note(&mut self.media_route, source, destination, first) {
            RouteNote::NotMedia | RouteNote::Same => {}
            RouteNote::First => {
                tracing::debug!(
                    %source,
                    %destination,
                    "media path: the first RTP/RTCP datagram of the session"
                );
                self.note_selected_pair(source, destination, "first");
            }
            RouteNote::Changed { from } => {
                tracing::info!(
                    from_local = %from.0,
                    from_remote = %from.1,
                    to_local = %source,
                    to_remote = %destination,
                    "media path changed: ICE moved the media to another candidate pair"
                );
                self.note_selected_pair(source, destination, "changed");
                self.note_path_change("selected_pair");
            }
        }
    }

    /// Name the candidate pair the media now takes, once per selection (the first media datagram,
    /// and every change after it): what kind each end is, and for a relay how the viewer reaches
    /// it — UDP, TCP or TLS — which the round trip, its jitter and what probing can measure all
    /// depend on. The local end is the socket address str0m sends from, which for a srflx pair is
    /// its host base; the srflx mapping, when there is one, is printed beside it.
    fn note_selected_pair(&self, source: SocketAddr, destination: SocketAddr, why: &'static str) {
        let (remote_kind, remote_proto, relay_transport, remote_prio) =
            describe_remote(&self.remote_candidates, destination);
        // Before `note_path_change` moves the count: the controller reads the kind when it sees
        // the count move. See [`Peer::path_kind`].
        let kind = path_kind_of(&self.remote_candidates, destination);
        let was = self.path_kind.swap(kind, Ordering::Relaxed);
        tracing::debug!(
            why,
            from = was,
            to = kind,
            "path kind published for the quality controller (0 unknown, 1 relay, 2 reflexive, 3 host)"
        );
        tracing::info!(
            why,
            local = %source,
            local_kind = self.local_kind(source),
            local_srflx = %self.srflx_addr.map_or_else(|| "-".to_string(), |a| a.to_string()),
            remote = %destination,
            remote_kind = %remote_kind,
            remote_proto = %remote_proto,
            relay_transport,
            remote_prio = ?remote_prio,
            candidates_known = self.remote_candidates.len(),
            "ICE candidate pair in use"
        );
        self.publish_path(Instant::now(), "media_pair");
    }

    /// What a local address str0m names as a datagram's source is: one of this machine's own
    /// (a host candidate, or the base of the srflx one), or `unknown`.
    fn local_kind(&self, local: SocketAddr) -> &'static str {
        match local.ip() {
            IpAddr::V4(v4) if self.own_ips.contains(&v4) => "host",
            _ => "unknown",
        }
    }

    /// The pair str0m nominated, for a log line: `local -> remote (kind)`, or `-` before its stats
    /// have named one.
    fn pair_label(&self) -> String {
        match self.nominated {
            Some((local, remote)) => format!(
                "{local} -> {remote} ({})",
                short_kind(&self.remote_candidates, remote)
            ),
            None => "-".to_string(),
        }
    }

    /// Every path this peer has used, each way, by kind. See `crate::paths::PathBook::describe`.
    fn paths_label(&self) -> String {
        self.paths.describe(
            self.start,
            |addr| short_kind(&self.remote_candidates, addr),
            self.send_path(),
        )
    }

    /// Where str0m sends DTLS and media: where its last such datagram went, or before there was
    /// one, the pair its stats named.
    fn send_path(&self) -> Option<SocketAddr> {
        self.send_to.or(self.nominated.map(|(_, remote)| remote))
    }

    /// One of str0m's DTLS or media datagrams left for `dest`. Per datagram: one comparison, and
    /// the rest only when its send pair changed or a move is waiting to be seen.
    fn note_send_path(&mut self, dest: SocketAddr, now: Instant) {
        let changed = self.send_to != Some(dest);
        if !changed && self.follow.moving.is_none() {
            return;
        }
        let from = self.send_to.replace(dest);
        let moving = self.follow.moving.take();
        let after_move_ms =
            moving.map(|(at, _)| now.saturating_duration_since(at).as_millis() as u64);
        if self.follow.left.contains(&dest) {
            // The move found nothing to go to: str0m had no other nominated pair, and keeps its
            // old `send_addr` until the viewer nominates one.
            tracing::warn!(
                to = %dest,
                to_kind = %short_kind(&self.remote_candidates, dest),
                after_move_ms,
                dtls_connected = self.connected,
                "str0m still sends to a remote withdrawn from it: it had no other nominated pair \
                 to move to, and keeps the old one until the viewer nominates another"
            );
            return;
        }
        match from {
            // The first datagram of the session: `DTLS first datagram out` says where it went.
            None => {}
            Some(from) => tracing::debug!(
                %from,
                from_kind = %short_kind(&self.remote_candidates, from),
                to = %dest,
                to_kind = %short_kind(&self.remote_candidates, dest),
                after_move_ms,
                dtls_connected = self.connected,
                "str0m's send pair changed: DTLS and media go to this remote from here"
            ),
        }
    }

    /// When [`Self::follow_viewer`] next wants to look, if it does.
    fn follow_due(&self) -> Option<Instant> {
        if !self.follow.enabled || self.send_to.is_none() {
            return None;
        }
        self.follow.next_at
    }

    /// What this ICE generation says about one path, in words for the move and hold lines:
    /// `203.0.113.158:56111 srflx: checks unanswered 3 over 1508 ms, replies 0 (last never),
    /// nominated 3x, last stun in 248 ms ago, dtls in 0, rtp in 0` — our checks there since its
    /// last answer and how long the oldest has waited, its answers to them, its nominations, and
    /// (over the session) when it last sent STUN and how much DTLS and RTP/RTCP came from it.
    fn evidence_label(&self, addr: SocketAddr, now: Instant) -> String {
        let kind = short_kind(&self.remote_candidates, addr);
        let Some(p) = self.paths.path(addr) else {
            return format!("{addr} {kind}: not counted");
        };
        let ev = p.evidence();
        let ago = |t: Option<Instant>| {
            t.map_or_else(
                || "never".to_string(),
                |t| format!("{} ms ago", now.saturating_duration_since(t).as_millis()),
            )
        };
        format!(
            "{addr} {kind}: checks unanswered {} over {} ms, replies {} (last {}), nominated {}x, \
             last stun in {}, dtls in {}, rtp in {}",
            ev.unanswered,
            ev.unanswered_for(now).map_or(0, |d| d.as_millis()),
            ev.replies,
            ago(ev.last_reply),
            ev.nominations,
            ago(p.tally(Dir::In, Kind::Stun).last),
            p.tally(Dir::In, Kind::Dtls).packets,
            p.tally(Dir::In, Kind::Rtp).packets,
        )
    }

    /// Look at the pair str0m sends on, every [`FOLLOW_EVERY`] once it sends anything, and take
    /// it off that pair when the viewer does not answer there and is demonstrably elsewhere —
    /// see `crate::paths::judge_send_path` for the rule and the module docs of `crate::paths`
    /// for why str0m needs it. `Ok(true)` when it moved: the `Rtc` changed and wants draining.
    ///
    /// A reason to stay is logged when it changes, not each look; the default one — the pair
    /// answers — only when it comes back after another.
    async fn follow_viewer(&mut self, now: Instant) -> Result<bool> {
        if !self.follow.enabled {
            return Ok(false);
        }
        let Some(send) = self.send_to else {
            return Ok(false);
        };
        if self.follow.next_at.is_some_and(|at| now < at) {
            return Ok(false);
        }
        self.follow.next_at = Some(now + FOLLOW_EVERY);
        match judge_send_path(&self.paths, send, self.connected, &self.follow.left, now) {
            Follow::Hold(hold) => {
                if self.follow.hold != Some(hold) {
                    let viewer_on = self.paths.last_data().map(|(addr, at)| {
                        format!(
                            "{addr} {} ({} ms ago)",
                            short_kind(&self.remote_candidates, addr),
                            now.saturating_duration_since(at).as_millis()
                        )
                    });
                    let send_label = self.evidence_label(send, now);
                    tracing::debug!(
                        hold = hold.as_str(),
                        why = hold.hint(),
                        was = self.follow.hold.map_or("-", Hold::as_str),
                        send = send_label.as_str(),
                        viewer_on = viewer_on.as_deref().unwrap_or("-"),
                        dtls_connected = self.connected,
                        "send-pair watch: str0m's send pair stands"
                    );
                    self.follow.hold = Some(hold);
                }
                Ok(false)
            }
            Follow::Leave(leave) => {
                self.leave_send_path(leave, send, now).await?;
                Ok(true)
            }
        }
    }

    /// Whether `destination` is one of the viewer's relay candidates, for [`Self::socket_bytes`]:
    /// the answer per destination is kept ([`Self::relay_dest`]), so a datagram costs one lookup
    /// rather than a look through the viewer's candidates.
    fn is_relay_destination(&mut self, destination: SocketAddr) -> bool {
        if let Some(&relay) = self.relay_dest.get(&destination) {
            return relay;
        }
        let relay = path_kind_of(&self.remote_candidates, destination) == PATH_KIND_RELAY;
        self.relay_dest.insert(destination, relay);
        tracing::trace!(
            relay,
            known = self.relay_dest.len(),
            "socket bytes: a destination not seen since the candidates last changed; counted as \
             relay or not from here"
        );
        relay
    }

    /// The remote candidate str0m holds at `addr`: the one the viewer signalled there, parsed
    /// from the same line; failing that, the peer-reflexive one str0m made itself from a check
    /// (`is-0.11.0/src/agent.rs:1526-1538`: address and base both the source, no related
    /// address) — which also matches a signalled candidate str0m saw a check from first.
    fn remote_candidates_at(&self, addr: SocketAddr) -> Vec<Candidate> {
        let mut found: Vec<Candidate> = self
            .remote_candidates
            .iter()
            .filter(|c| c.addr == addr)
            .map(|c| c.candidate.clone())
            .collect();
        let line = format!(
            "candidate:0 1 udp 1 {} {} typ prflx",
            addr.ip(),
            addr.port()
        );
        match Candidate::from_sdp_string(&line) {
            Ok(c) => found.push(c),
            Err(e) => tracing::debug!(%addr, "no peer-reflexive candidate for {addr}: {e}"),
        }
        found
    }

    /// Take str0m off the pairs `leave` names: withdraw each dead remote candidate
    /// (`DirectApi::invalidate_candidate`, which discards every pair on it,
    /// `is-0.11.0/src/agent.rs:941-977`), then let its ICE agent run, which — its nominated pair
    /// gone — nominates the best pair the viewer nominated that is left and sends there
    /// (`agent.rs:1899-1944`). Checks the viewer still sends from a withdrawn address are ignored
    /// from here on (`agent.rs:1507-1517`); a restart's new candidates bring it back.
    async fn leave_send_path(
        &mut self,
        leave: Leave,
        send: SocketAddr,
        now: Instant,
    ) -> Result<()> {
        let phase = if self.connected {
            "connected"
        } else {
            "handshake"
        };
        // Numbers first, while the path book still describes the state that decided it.
        let dead_label = self.evidence_label(send, now);
        let to_label = self.evidence_label(leave.to, now);
        let also: Vec<String> = leave
            .dead
            .iter()
            .filter(|a| **a != send)
            .map(|a| self.evidence_label(*a, now))
            .collect();
        let viewer_data_ago_ms = self
            .paths
            .last_data()
            .map(|(_, at)| now.saturating_duration_since(at).as_millis() as u64);
        let mut withdrawn = 0;
        let mut not_found: Vec<SocketAddr> = Vec::new();
        for &addr in &leave.dead {
            let mut done = false;
            for c in self.remote_candidates_at(addr) {
                if self.rtc.direct_api().invalidate_candidate(&c) {
                    done = true;
                    break;
                }
            }
            if done {
                withdrawn += 1;
            } else {
                not_found.push(addr);
            }
            // Either way, never again this generation: a remote str0m does not know cannot be
            // withdrawn by trying twice.
            self.follow.left.push(addr);
        }
        // str0m re-picks its send pair when its ICE agent next runs.
        self.rtc.handle_input(Input::Timeout(Instant::now()))?;
        self.follow.moving = Some((now, send));
        self.follow.hold = None;
        let also_dead = if also.is_empty() {
            "-".to_string()
        } else {
            also.join(" | ")
        };
        tracing::info!(
            phase,
            dead = dead_label.as_str(),
            also_dead = also_dead.as_str(),
            to = to_label.as_str(),
            viewer_data_ago_ms,
            withdrawn,
            not_found = not_found.len(),
            dtls_connected = self.connected,
            since_ice_connected_ms = self
                .dtls
                .ice_connected_at()
                .map(|t| now.saturating_duration_since(t).as_millis() as u64),
            "ICE send pair left: str0m was sending to a pair our checks go unanswered on, while \
             the viewer talks, nominates and answers on another; the dead remote is withdrawn \
             from str0m, which sends on a pair the viewer nominated from here"
        );
        if !not_found.is_empty() {
            let list: Vec<String> = not_found.iter().map(ToString::to_string).collect();
            tracing::warn!(
                not_found = list.join(",").as_str(),
                "send-pair watch: str0m holds no remote candidate at these addresses as signalled \
                 or peer-reflexive; they could not be withdrawn, and str0m may keep sending there"
            );
        }
        // Mid-session, the frames sent to the dead pair are lost: the picture resyncs on a
        // keyframe, as after any restored path.
        if self.connected
            && self
                .events
                .send(PeerEvent::KeyframeRequest(KeyframeAsk::PairMoved))
                .await
                .is_err()
        {
            tracing::debug!("the orchestrator is gone; keyframe after the move not asked");
        }
        Ok(())
    }

    /// str0m's once-a-second peer statistics, which carry the one thing it reports about its
    /// candidate pair: the pair it nominated for sending (`send_addr`,
    /// `str0m-0.23.1/src/lib.rs:1598-1614,2047-2057`) — where every DTLS, RTP and RTCP datagram
    /// goes (`lib.rs:1804-1818`). Before this the log had to infer it from the first media
    /// datagram, and a session whose DTLS never finished sent none.
    ///
    /// Logged when a report first names a pair and whenever it names another; the rest of the
    /// report, once a second, is trace.
    fn note_peer_stats(&mut self, s: &str0m::stats::PeerStats) {
        let reported = s.selected_candidate_pair.as_ref();
        tracing::trace!(
            peer_bytes_tx = s.peer_bytes_tx,
            peer_bytes_rx = s.peer_bytes_rx,
            pair = ?reported.map(|p| (p.local.addr, p.remote.addr)),
            "peer stats"
        );
        let Some(p) = reported else {
            return;
        };
        let pair = (p.local.addr, p.remote.addr);
        let why = match self.nominated {
            None => "first",
            Some(known) if known != pair => "changed",
            Some(_) => return,
        };
        let previous = self.nominated.replace(pair);
        let now = Instant::now();
        let (remote_kind, remote_proto, relay_transport, remote_prio) =
            describe_remote(&self.remote_candidates, pair.1);
        tracing::info!(
            why,
            local = %pair.0,
            local_kind = self.local_kind(pair.0),
            local_srflx = %self.srflx_addr.map_or_else(|| "-".to_string(), |a| a.to_string()),
            remote = %pair.1,
            remote_kind = %remote_kind,
            remote_proto = %remote_proto,
            relay_transport,
            remote_prio = ?remote_prio,
            protocol = %format!("{:?}", p.protocol).to_ascii_lowercase(),
            rtt_ms = ?p.current_round_trip_time.map(|d| d.as_millis() as u64),
            stun_responses = p.responses_received,
            previous = %previous.map_or_else(|| "-".to_string(), |(l, r)| format!("{l} -> {r}")),
            dtls_connected = self.connected,
            since_ice_connected_ms = self
                .dtls
                .ice_connected_at()
                .map(|t| now.saturating_duration_since(t).as_millis() as u64),
            "ICE nominated pair (from str0m's stats): DTLS, RTP and RTCP go to this remote"
        );
        self.publish_path(now, "nominated_pair");
    }

    /// A DTLS datagram in or out. The first of the session each way, and the first to or from each
    /// further address, at debug — a handful a session; every other one only counts in
    /// [`Self::paths`].
    fn note_dtls_datagram(
        &self,
        dir: Dir,
        addr: SocketAddr,
        bytes: usize,
        noted: Noted,
        now: Instant,
    ) {
        if !noted.first_on_path {
            return;
        }
        let content = noted
            .dtls
            .map_or_else(|| "-".to_string(), |p| DtlsSeen::from(p).to_string());
        let remote_kind = short_kind(&self.remote_candidates, addr);
        let since_ice_ms = self
            .dtls
            .ice_connected_at()
            .map(|t| now.saturating_duration_since(t).as_millis() as u64);
        // Whether this is the remote str0m nominated; `None` before its stats have named one.
        let nominated = self.nominated.map(|(_, remote)| remote == addr);
        let dtls_role = self.dtls_role.as_str();
        match (dir, noted.first_anywhere) {
            (Dir::Out, true) => tracing::debug!(
                to = %addr,
                remote_kind,
                bytes,
                content,
                dtls_role,
                since_ice_ms,
                nominated = ?nominated,
                "DTLS first datagram out"
            ),
            (Dir::In, true) => tracing::debug!(
                from = %addr,
                remote_kind,
                bytes,
                content,
                dtls_role,
                since_ice_ms,
                nominated = ?nominated,
                "DTLS first datagram in"
            ),
            (dir, false) => tracing::debug!(
                dir = dir.as_str(),
                %addr,
                remote_kind,
                bytes,
                content,
                since_ice_ms,
                nominated = ?nominated,
                "DTLS on another path: the first datagram this way to or from this address"
            ),
        }
    }

    /// The stall warning: ICE up and DTLS not, [`DTLS_STALL_WARN_AFTER`] after ICE first connected;
    /// then the same at debug every `crate::paths::DTLS_STALL_REPORT_EVERY` until DTLS comes up or
    /// the peer ends. `verdict` is which side is not being heard, read from the counters (see
    /// `crate::paths::Verdict`); `paths` is every address each way.
    fn watch_dtls(&mut self, now: Instant) {
        let (waited, first) = match self.dtls.poll(now) {
            Stall::Quiet => return,
            Stall::Warn { waited } => (waited, true),
            Stall::Report { waited } => (waited, false),
        };
        let verdict = Verdict::of(self.dtls_role, &self.paths, self.send_path(), now);
        let waited_ms = waited.as_millis() as u64;
        let dtls_role = self.dtls_role.as_str();
        let pair = self.pair_label();
        let dtls_out = self.paths.dtls_summary(Dir::Out, self.start);
        let dtls_in = self.paths.dtls_summary(Dir::In, self.start);
        let paths = self.paths_label();
        if first {
            tracing::warn!(
                waited_ms,
                dtls_role,
                verdict = verdict.as_str(),
                hint = verdict.hint(),
                pair,
                dtls_out,
                dtls_in,
                paths,
                "DTLS handshake stalled: ICE is connected and DTLS is not up"
            );
        } else {
            tracing::debug!(
                waited_ms,
                dtls_role,
                verdict = verdict.as_str(),
                pair,
                dtls_out,
                dtls_in,
                paths,
                "DTLS handshake still stalled"
            );
        }
    }

    /// How far this peer got and over which pair, as the counters say now: the stage, the DTLS
    /// verdict while ICE is up and DTLS is not, how long DTLS took after ICE, and the kinds of the
    /// pair str0m sends on. See [`PeerPath`].
    fn current_path(&self, now: Instant) -> PeerPath {
        let stage = if self.connected {
            PeerStage::Connected
        } else if self.dtls.ice_connected_at().is_some() {
            PeerStage::Dtls
        } else if self.paths.total(Dir::Out, Kind::Stun).packets > 0
            || self.paths.total(Dir::In, Kind::Stun).packets > 0
        {
            // Our checks went out, or the viewer's came in: a pair was being checked.
            PeerStage::Ice
        } else {
            PeerStage::New
        };
        let verdict = (stage == PeerStage::Dtls)
            .then(|| Verdict::of(self.dtls_role, &self.paths, self.send_path(), now).as_str());
        // The pair str0m sends on, else the one the media last left on.
        let remote = self
            .send_path()
            .or(self.media_route.map(|(_, remote)| remote));
        let (pair_remote_kind, relay_transport) = match remote {
            Some(remote) => {
                let (kind, transport) = remote_path_kinds(&self.remote_candidates, remote);
                (Some(kind), transport)
            }
            None => (None, None),
        };
        PeerPath {
            stage,
            verdict,
            dtls_after_ice_ms: self
                .dtls
                .dtls_after_ice()
                .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX)),
            // str0m sends from its one host base (`local_addr`): a srflx candidate on the same base
            // forms only pairs it prunes as redundant (`is-0.11.0/src/agent.rs:851-897`), so the
            // pair's local end is the host candidate whenever there is a pair at all.
            pair_local_kind: remote.map(|_| "host"),
            pair_remote_kind,
            relay_transport,
        }
    }

    /// Publish [`Self::current_path`] for whoever ends the session (`why`: what moved it, for the
    /// log). A change is logged at debug, kinds only — the addresses are on the lines that log pairs.
    fn publish_path(&self, now: Instant, why: &'static str) {
        let path = self.current_path(now);
        if self.path.set(path) {
            tracing::debug!(
                why,
                stage = path.stage.as_str(),
                verdict = path.verdict.unwrap_or("-"),
                dtls_after_ice_ms = ?path.dtls_after_ice_ms,
                pair_local_kind = path.pair_local_kind.unwrap_or("-"),
                pair_remote_kind = path.pair_remote_kind.unwrap_or("-"),
                relay_transport = path.relay_transport.unwrap_or("-"),
                "peer path published (session_end.detail)"
            );
        }
    }

    /// [`Self::publish_path`] on its clock, every [`PATH_PUBLISH_EVERY`]: what keeps an end the
    /// orchestrator makes at most that stale. Every turn checks the clock; the work is once a second.
    fn publish_path_if_due(&mut self, now: Instant) {
        if now.saturating_duration_since(self.path_published_at) < PATH_PUBLISH_EVERY {
            return;
        }
        self.path_published_at = now;
        self.publish_path(now, "clock");
    }

    /// The peer's last word on its paths, just before `webrtc peer loop ended`.
    ///
    /// A peer that never connected gets the whole story: at warn when ICE had been up long enough
    /// for any handshake to finish ([`DTLS_STALL_WARN_AFTER`]) — a handshake that failed — and at
    /// info otherwise (ICE never found a pair, or the viewer left seconds after it did). A connected
    /// one gets its paths at debug.
    fn log_paths_at_end(&self, end: PeerEnd, failure: Option<&str>) {
        let now = Instant::now();
        let lived_ms = now.saturating_duration_since(self.start).as_millis() as u64;
        let paths = self.paths_label();
        if self.connected {
            tracing::debug!(lived_ms, paths, "peer paths over the session");
            return;
        }
        let ice_up = self.dtls.stalled_for(now);
        let (stage, verdict, hint) = match ice_up {
            Some(_) => {
                let v = Verdict::of(self.dtls_role, &self.paths, self.send_path(), now);
                ("dtls_never_completed", v.as_str(), v.hint())
            }
            None => (
                "ice_never_connected",
                "-",
                "ICE found no working pair; the STUN counts in paths say which of the viewer's \
                 candidates answered",
            ),
        };
        let ice_up_ms = ice_up.map(|d| d.as_millis() as u64);
        let dtls_role = self.dtls_role.as_str();
        let pair = self.pair_label();
        let dtls_out = self.paths.dtls_summary(Dir::Out, self.start);
        let dtls_in = self.paths.dtls_summary(Dir::In, self.start);
        let stun_from = self.paths.sources_of(Kind::Stun);
        if ice_up.is_some_and(|d| d >= DTLS_STALL_WARN_AFTER) {
            tracing::warn!(
                ?end,
                reason = end.reason(),
                failure,
                stage,
                lived_ms,
                ice_up_ms,
                dtls_role,
                verdict,
                hint,
                pair,
                dtls_out,
                dtls_in,
                stun_from,
                paths,
                "peer ended before the connection came up"
            );
        } else {
            tracing::info!(
                ?end,
                reason = end.reason(),
                failure,
                stage,
                lived_ms,
                ice_up_ms,
                dtls_role,
                verdict,
                hint,
                pair,
                dtls_out,
                dtls_in,
                stun_from,
                paths,
                "peer ended before the connection came up"
            );
        }
    }

    /// The media path changed under the session: tell the controller through
    /// [`Peer::path_changes`], and forget the round trip the playout hold is sized from, which
    /// described the old path.
    fn note_path_change(&mut self, why: &'static str) {
        // Release: the path kind stored before it is visible to whoever sees this count move.
        let n = self.path_changes.fetch_add(1, Ordering::Release) + 1;
        tracing::debug!(
            why,
            path_changes = n,
            rtt_envelope_ms = ?self.playout.rtt_envelope_ms(),
            "media path change published: the controller resets its round-trip baseline, and the \
             playout hold forgets the old path's round trip"
        );
        self.playout.forget_rtt(why);
    }

    /// Ask the encoder for a keyframe on this peer's own account: the reference chain is broken.
    ///
    /// `try_send`, because this runs inside `write_media`, which cannot wait. A refusal is retried
    /// by [`RefChain::admit`] after [`KEYFRAME_RETRY`], and the viewer's own PLI, where it has one,
    /// is the other way back.
    fn request_keyframe(&mut self, b: Broken, now: Instant) {
        match self
            .events
            .try_send(PeerEvent::KeyframeRequest(KeyframeAsk::ChainBroken))
        {
            Ok(()) => {
                self.keyframe_request_refused = false;
                tracing::debug!(
                    why = b.why.as_str(),
                    lost = b.lost,
                    held = b.held,
                    broken_ms = now.saturating_duration_since(b.since).as_millis() as u64,
                    asks = b.asks,
                    "{}",
                    if b.asks > 1 {
                        "still no keyframe after asking: asking the encoder again"
                    } else {
                        "keyframe requested: the viewer's reference chain is broken, so delta \
                         frames are held until one arrives"
                    }
                );
            }
            Err(e) => {
                if !self.keyframe_request_refused {
                    self.keyframe_request_refused = true;
                    tracing::warn!(
                        error = %e,
                        why = b.why.as_str(),
                        held = b.held,
                        "keyframe request refused by the event queue; retried in {} ms while delta \
                         frames are held",
                        KEYFRAME_RETRY.as_millis()
                    );
                }
            }
        }
    }

    /// Log a keyframe request from the viewer: the first at once, then at most one line a second
    /// with how many arrived in between. A PLI storm is a few a second for as long as the picture
    /// is broken, so it has to be visible without being the whole log. Each is handed on as
    /// [`KeyframeAsk::Viewer`]; whether it costs an IDR is the encode thread's decision
    /// (`afklink_core::keyframe_window`), logged there.
    fn note_keyframe_request(&mut self, kind: str0m::media::KeyframeRequestKind) {
        let now = Instant::now();
        let due = self
            .kf_request_logged_at
            .is_none_or(|t| now.saturating_duration_since(t) >= Duration::from_secs(1));
        if due {
            tracing::debug!(
                ?kind,
                since_last_line = self.kf_requests_held,
                "viewer asked for a keyframe"
            );
            self.kf_request_logged_at = Some(now);
            self.kf_requests_held = 0;
        } else {
            self.kf_requests_held = self.kf_requests_held.saturating_add(1);
        }
    }

    /// One packet of str0m's raw-packet mirror: the NACK count, and the retransmission trace.
    ///
    /// Every incoming NACK moves [`Peer::nacks_received`], for the encode thread's keyframe window,
    /// whatever the log level. With the trace on, it also opens an entry per sequence number, and an
    /// outgoing packet on the RTX SSRC closes one, by the original sequence number its payload starts
    /// with. Everything else — media packets, receiver reports, TWCC feedback — passes through
    /// untouched: this runs once per packet sent, so it does nothing it does not have to.
    fn note_raw_packet(&mut self, p: &str0m::rtp::RawPacket) {
        use str0m::rtp::rtcp::Rtcp;
        use str0m::rtp::RawPacket;
        if matches!(p, RawPacket::RtcpRx(Rtcp::Nack(_))) {
            // Release: published before this poll's keyframe requests are handed on (str0m emits
            // a poll's raw packets first), which reach the encode thread through the event task.
            // Per packet: no line here; the encode thread logs what it does with the count, and the
            // `playout` line and the stats interval count NACKs once a second.
            self.nacks_received.fetch_add(1, Ordering::Release);
        }
        let Some(trace) = self.rtx_trace.as_mut() else {
            return;
        };
        match p {
            RawPacket::RtcpRx(Rtcp::Nack(nack)) => {
                let now = Instant::now();
                let seqs = (&nack.reports)
                    .into_iter()
                    .flat_map(|e| playout::nack_seqs(e.pid, e.blp));
                trace.on_nack(now, seqs);
            }
            RawPacket::RtpTx(header, packet) if Some(header.ssrc) == self.rtx_ssrc => {
                match playout::rtx_original_seq(packet, header.header_len) {
                    Some(orig) => trace.on_rtx(Instant::now(), orig, header.timestamp),
                    // Blank padding for a probe: no original sequence number, nothing to match.
                    None => tracing::trace!(
                        bytes = packet.len(),
                        "retransmission trace: blank padding on the RTX SSRC"
                    ),
                }
            }
            _ => {}
        }
    }

    /// The `playout` line, once a second while media flows: the pair on the wire, why, and what
    /// the retransmission trace saw.
    ///
    /// Debug, because it is the evidence behind a decision rather than an event; one line a second
    /// is the pipeline line's own cadence. Quiet windows (no frame written, no NACK) write nothing.
    /// Without the trace (debug off when the peer started) the numbers it would carry do not exist,
    /// and neither does the line.
    fn report_playout_if_due(&mut self) {
        let now = Instant::now();
        if now.saturating_duration_since(self.playout_report_at) < EgressMeter::WINDOW {
            return;
        }
        self.playout_report_at = now;
        let Some(trace) = self.rtx_trace.as_mut() else {
            return;
        };
        let w = trace.take_window(now);
        if w.is_quiet() {
            return;
        }
        let list = |v: &[u32]| v.iter().map(u32::to_string).collect::<Vec<_>>().join(",");
        let viewer = self.playout.viewer_target(now);
        tracing::debug!(
            lossy = self.playout.holding(),
            phase = self.playout.phase().as_str(),
            target_min_ms = self.playout.target_ms(),
            min_ms = self.last_delay.min_ms,
            max_ms = self.last_delay.max_ms,
            viewer_target_ms = ?viewer.map(|(t, _)| t),
            viewer_report_age_ms = ?viewer.map(|(_, age)| age.as_millis()),
            engine = self.playout.engine().map_or("-", afklink_protocol::ViewerEngine::as_str),
            rtt_envelope_ms = self.playout.rtt_envelope_ms(),
            cushion_ms = self.playout.cushion_ms(),
            outage = self.playout.outage(),
            stalls = self.playout.cushion_stalls(now),
            frames = w.frames,
            nacked = w.nacked,
            renacked = w.renacked,
            rtx = w.rtx,
            rtx_ms = %w.rtx_after_summary(),
            unanswered = w.unanswered,
            spurious = w.spurious,
            rtp_anchor_ms = w.rtp_anchor_ms,
            keyframes_rtp = %list(&w.keyframes_rtp),
            rtx_rtp = %list(&w.rtx_rtp),
            "playout"
        );
    }

    /// Hand one encoded frame to str0m — unless the queue has already run away.
    ///
    /// ## The circuit breaker, and why nothing else works
    ///
    /// str0m's `SendQueue` is an unbounded `VecDeque` with no eviction, its pacer drains at only
    /// 1.1x the estimate, and its own force-drain does not arm until the *average* wait approaches
    /// two seconds. Nothing downstream bounds this queue, so if production exceeds drain for any
    /// sustained period the excess integrates without limit.
    ///
    /// Measured, on a 6 ms LAN with no packet loss at all: 1.7 megabytes in flight, then 1.9, then
    /// 2.1, growing about a second of video per second, reaching **280 seconds of backlog**. The
    /// estimate read 1200 kbps and the encoder produced 2400. The user's report was "the picture is
    /// ten seconds behind" and, in the next session, "it never recovered".
    ///
    /// A rate controller cannot fix this. Pushback on the bitrate is proportional and bottoms at
    /// half, so production stays above `0.45 x estimate`; against an integrator, any steady excess
    /// wins eventually. The encoder also overshoots its own target — measured `spend_ratio` 1.05 —
    /// so "aim below the estimate" is not sufficient either. **Something has to discard.**
    ///
    /// So: past [`QUEUE_HARD_LIMIT_MS`] this stops writing, and resumes only once the queue is back
    /// under [`QUEUE_RESUME_MS`]. The frames it threw away have broken the receiver's prediction
    /// chain, so from there [`RefChain`] holds delta frames and asks for a keyframe.
    ///
    /// It is deliberately a breaker and not a controller: it has no gain, it sits an order of
    /// magnitude above the normal operating point (20-100 ms), and it cannot oscillate there. Every
    /// previous attempt to bound this queue put a *controller* at the operating point, and each one
    /// found a new way to make the frame rate collapse.
    ///
    /// ## Every other way an encoded frame can fail to go out
    ///
    /// Each one is a frame the viewer's decoder never sees, and each goes through the same
    /// [`Self::lose_frame`]: frames encoded before the connection was up, frames the negotiation
    /// gave no way to send, and frames str0m's writer refused. Nothing upstream drops an encoded
    /// frame: the media channel is a `blocking_send` (the encode thread waits; see
    /// `afklink_core::agent::MediaSink`), and every frame the encode loop decides not to send it
    /// decides not to *encode*, which leaves the chain whole.
    fn write_media(&mut self, sample: MediaSample) {
        let now = Instant::now();
        if !self.connected {
            // Expected while ICE and DTLS come up: the encoder starts with the answer. Counted,
            // and the count is on the `webrtc connected` line.
            self.unsent_before_connect += 1;
            if self.unsent_before_connect == 1 {
                tracing::debug!("frames are arriving before the connection is up; not sent");
            }
            self.lose_frame(ChainBreak::BeforeConnect, now);
            return;
        }
        let Some(mid) = self.video_mid else {
            Self::note_unsent_no_video(&mut self.unsent_no_video, "no video m-line was negotiated");
            self.lose_frame(ChainBreak::NoVideo, now);
            return;
        };
        // Whether this negotiation can send the frame at all, asked before the breaker and the
        // gate: a peer that can never write must not be asking the encoder for keyframes it
        // cannot send either.
        let Some(params) = self.h264_params(mid) else {
            self.lose_frame(ChainBreak::NoVideo, now);
            return;
        };

        let queued = self.queue_age_ms();
        match self.breaker.admit(queued) {
            Shed::Send => {}
            Shed::Discard => {
                self.discarded.fetch_add(1, Ordering::Relaxed);
                if self.breaker.discarded == 1 {
                    tracing::warn!(
                        queue_ms = queued,
                        in_flight = self.outstanding_bytes.load(Ordering::Relaxed),
                        estimate_kbps = self.estimate_kbps,
                        "send queue past its hard limit: discarding until it drains"
                    );
                }
                self.lose_frame(ChainBreak::Breaker, now);
                return;
            }
            Shed::Resumed { discarded } => {
                tracing::info!(
                    queue_ms = queued,
                    discarded,
                    keyframe = sample.is_keyframe,
                    "send queue drained; resuming — the discarded frames broke the viewer's \
                     reference chain, so delta frames are held until a keyframe"
                );
            }
        }

        match self.chain.admit(sample.is_keyframe, now) {
            Gate::Write => {}
            Gate::Hold { ask } => {
                // Counted with the discards: an encoded frame the viewer does not get.
                self.discarded.fetch_add(1, Ordering::Relaxed);
                if let Some(b) = self.chain.broken() {
                    if ask {
                        self.request_keyframe(b, now);
                    } else {
                        tracing::trace!(
                            why = b.why.as_str(),
                            held = b.held,
                            "delta frame held: it references a frame the viewer never got"
                        );
                    }
                }
                return;
            }
        }

        // A restart armed for this moment (`PeerControl::ResetBweAtNextFrame`): right before the
        // frame, so the restarted estimator's first window measures it. Before the writer, which
        // borrows `self.rtc` for the rest of the function.
        if let Some((kbps, armed)) = self.armed_reanchor.take() {
            if let Err(e) = self.apply_reanchor(kbps, None, "before-frame", Some(armed), now) {
                tracing::error!(
                    kbps,
                    error = %e,
                    "bwe re-anchor before the frame failed: str0m refused the timeout after the \
                     reset; the frame is written all the same"
                );
            }
        }
        // A ceiling that waited for the video ([`ceiling_waits_for_video`]) and had no re-anchor to
        // ride: it goes now, with the frame that ends the silence.
        self.release_waiting_desired("before-frame");
        // Before the writer, because it borrows `self.rtc` for the rest of the function.
        let delay = self.playout.delay(Instant::now());
        self.last_delay = delay;
        // RTP timestamp as str0m will write it: the 90 kHz media time, truncated to 32 bits
        // (`packet/payload.rs:93`, no offset added).
        let rtp = (sample.timestamp_ms.wrapping_mul(90) & 0xffff_ffff) as u32;
        if let Some(trace) = self.rtx_trace.as_mut() {
            match playout::unix_ms_now() {
                Some(now_ms) => {
                    let anchor = now_ms
                        .saturating_sub(i64::try_from(sample.timestamp_ms).unwrap_or(i64::MAX));
                    trace.on_frame(rtp, sample.is_keyframe, anchor);
                }
                None => tracing::trace!("system clock before 1970: frame not anchored"),
            }
        }
        if sample.is_keyframe {
            // Rare by design (each one is the largest thing this pipeline sends), so a line each —
            // with its quantiser, which the encode loop's own keyframe line may have held back.
            tracing::debug!(
                rtp_ts = rtp,
                bytes = sample.data.len(),
                qp = %sample.qp.map_or_else(|| "-".to_string(), |q| q.to_string()),
                min_ms = delay.min_ms,
                max_ms = delay.max_ms,
                "keyframe handed to str0m"
            );
        }

        let Some(writer) = self.rtc.writer(mid) else {
            // `h264_params` found one a moment ago, on this same `Rtc`; kept as an exit rather than
            // an `expect`, and counted like any other frame that cannot go out.
            Self::note_unsent_no_video(
                &mut self.unsent_no_video,
                "str0m has no writer for the video m-line",
            );
            self.lose_frame(ChainBreak::NoVideo, now);
            return;
        };
        let pt = params.pt();
        let freq = params.spec().clock_rate;
        // 90 kHz clock: ms * 90 = ticks.
        let media_time = MediaTime::new(sample.timestamp_ms.saturating_mul(90), freq);
        let wallclock = self.start + Duration::from_millis(sample.timestamp_ms);
        // On every frame, not once: the extension is per-packet header state, str0m builds a fresh
        // `Writer` (and therefore a fresh, default `ExtensionValues`) for each `rtc.writer(mid)`,
        // and libwebrtc only honours the most recent pair it has seen. Expressed in milliseconds
        // and rebased by str0m to the wire's hundredths-of-a-second unit (`rtp/ext.rs:686-687`),
        // which is exact: `crate::playout` only hands out whole 10 ms ticks.
        //
        // Per-frame is also what makes the pair adaptive at no cost: it is recomputed from the
        // latest receiver report every time, so the change after a loss reaches the viewer on the
        // next frame — about 17 ms at 60 fps — and the return to the clean pair does too.
        let writer = writer.playout_delay(
            MediaTime::from_millis(delay.min_ms),
            MediaTime::from_millis(delay.max_ms),
        );
        let keyframe = sample.is_keyframe;
        match writer.write(pt, wallclock, media_time, sample.data) {
            Ok(()) => {
                self.last_frame_written = Some(now);
                if let Some(b) = self.chain.written(keyframe) {
                    tracing::debug!(
                        why = b.why.as_str(),
                        lost = b.lost,
                        held = b.held,
                        broken_ms = now.saturating_duration_since(b.since).as_millis() as u64,
                        asks = b.asks,
                        "keyframe written: the viewer's reference chain is whole again"
                    );
                }
            }
            Err(e) => {
                // Per frame, so trace here and a once-a-second count in
                // `EgressMeter::report_if_due`.
                tracing::trace!("media write failed: {e}");
                self.egress.write_errors += 1;
                self.egress.last_write_error = Some(e.to_string());
                self.lose_frame(ChainBreak::WriteError, now);
            }
        }
    }

    /// Restart str0m's estimator at `kbps` through [`reanchor_bwe_probing`], with its line: the
    /// opening probes held to `kbps`, or to `probe_cap` when given ([`PeerControl::ResetBweProbing`]).
    /// `applied` says when: `on-arrival` ([`PeerControl::ResetBwe`]), `at-once` or `before-frame`
    /// ([`PeerControl::ResetBweAtNextFrame`], with when it was `armed`).
    fn apply_reanchor(
        &mut self,
        kbps: u32,
        probe_cap: Option<u32>,
        applied: &'static str,
        armed: Option<Instant>,
        now: Instant,
    ) -> Result<(), str0m::RtcError> {
        let desired = self.desired_kbps;
        let waited = self.str0m_desired_kbps != desired;
        let r = reanchor_bwe_probing(
            &mut self.rtc,
            Bitrate::kbps(u64::from(kbps)),
            Bitrate::kbps(u64::from(desired)),
            Bitrate::kbps(u64::from(probe_cap.unwrap_or(kbps))),
            now,
        );
        // `reanchor_bwe_probing` puts the ceiling back whatever its timeout did.
        self.str0m_desired_kbps = desired;
        let r = r?;
        if waited {
            tracing::debug!(
                desired_kbps = desired,
                applied,
                "bwe ceiling that waited for the video handed to str0m with the re-anchor"
            );
        }
        tracing::info!(
            kbps,
            asked_probe_cap_kbps = %probe_cap.map_or_else(|| "-".to_string(), |c| c.to_string()),
            applied,
            armed_ms = %armed.map_or_else(
                || "-".to_string(),
                |a| now.saturating_duration_since(a).as_millis().to_string()
            ),
            estimate_was_kbps = self.estimate_kbps,
            probe_cap_kbps = r.probe_cap_kbps,
            desired_kbps = desired,
            bare_reset_probes_kbps = %format!(
                "{}/{}",
                r.bare_reset_probes_kbps.0, r.bare_reset_probes_kbps.1
            ),
            "bwe re-anchored: str0m's estimator is restarted at kbps — on arrival, at once, or right \
             before the frame it was armed for (applied) — and its opening probes are held to \
             probe_cap_kbps instead of the bursts a bare reset fires (bare_reset_probes_kbps)"
        );
        Ok(())
    }

    /// [`PeerControl::SetDesiredBitrate`]: the ceiling is this peer's from now (a re-anchor restores
    /// it), and str0m's at once — unless it would end str0m's quiet while no video flows, when it
    /// waits for the next frame ([`ceiling_waits_for_video`]).
    fn set_desired(&mut self, kbps: u32, now: Instant) {
        let since_frame = self
            .last_frame_written
            .map(|t| now.saturating_duration_since(t));
        let was = self.str0m_desired_kbps;
        self.desired_kbps = kbps;
        if ceiling_waits_for_video(was, kbps, since_frame) {
            tracing::debug!(
                kbps,
                str0m_kbps = was,
                since_frame_ms =
                    %since_frame.map_or_else(|| "never".to_string(), |d| d.as_millis().to_string()),
                flowing_within_ms = REANCHOR_FLOWING_WITHIN.as_millis() as u64,
                armed_reanchor = self.armed_reanchor.is_some(),
                "bwe ceiling set, held for the video: str0m probes nothing now and no frame is \
                 flowing, and in its application-limited region a rising ceiling is a probe at \
                 once; it goes with the next frame (with the re-anchor armed for it, if any)"
            );
            return;
        }
        tracing::debug!(kbps, str0m_was_kbps = was, "bwe ceiling set");
        self.str0m_desired_kbps = kbps;
        self.rtc
            .bwe()
            .set_desired_bitrate(Bitrate::kbps(u64::from(kbps)));
    }

    /// A ceiling still waiting for the video goes to str0m now. Said once, with what released it.
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

    /// [`PeerControl::ResetBweAtNextFrame`]: applied at once if a frame went out within
    /// [`REANCHOR_FLOWING_WITHIN`], armed for the next one otherwise.
    fn arm_reanchor(&mut self, kbps: u32, now: Instant) -> Result<(), str0m::RtcError> {
        let since_frame = self
            .last_frame_written
            .map(|t| now.saturating_duration_since(t));
        let since_frame_ms =
            since_frame.map_or_else(|| "never".to_string(), |d| d.as_millis().to_string());
        if since_frame.is_some_and(|d| d <= REANCHOR_FLOWING_WITHIN) {
            tracing::debug!(
                kbps,
                since_frame_ms,
                flowing_within_ms = REANCHOR_FLOWING_WITHIN.as_millis() as u64,
                "bwe re-anchor for the next frame applied at once: a frame went out just before it \
                 arrived, so the video it is for is already flowing"
            );
            return self.apply_reanchor(kbps, None, "at-once", Some(now), now);
        }
        if let Some((was, at)) = self.armed_reanchor.replace((kbps, now)) {
            tracing::debug!(
                kbps,
                replaced_kbps = was,
                armed_ms = now.saturating_duration_since(at).as_millis() as u64,
                "bwe re-anchor re-armed: a newer one replaces the one still waiting for its frame"
            );
        }
        tracing::debug!(
            kbps,
            since_frame_ms,
            estimate_kbps = self.estimate_kbps,
            "bwe re-anchor armed: applied right before the next video frame is handed to str0m, so \
             the restarted estimator measures that video and not the padding before it"
        );
        Ok(())
    }

    /// An encoded frame did not reach str0m. See [`RefChain`]: from here delta frames are held and
    /// a keyframe is asked for, as soon as a frame can be written at all.
    fn lose_frame(&mut self, why: ChainBreak, now: Instant) {
        if self.chain.lost(why, now) {
            tracing::debug!(
                why = why.as_str(),
                "the viewer's reference chain is broken: an encoded frame did not reach str0m, so \
                 delta frames are held from the next writable frame until a keyframe"
            );
        } else {
            // Per frame while the loss lasts; the episode is logged once, when it starts and when
            // the keyframe ends it.
            tracing::trace!(why = why.as_str(), "another encoded frame not sent");
        }
    }

    /// The negotiated H.264 payload type and clock rate for the video m-line, if this negotiation
    /// has one; logs (throttled) and returns `None` otherwise.
    fn h264_params(&mut self, mid: Mid) -> Option<str0m::format::PayloadParams> {
        let Some(writer) = self.rtc.writer(mid) else {
            Self::note_unsent_no_video(
                &mut self.unsent_no_video,
                "str0m has no writer for the video m-line",
            );
            return None;
        };
        let params = writer
            .payload_params()
            .find(|p| p.spec().codec == Codec::H264)
            .copied();
        if params.is_none() {
            Self::note_unsent_no_video(
                &mut self.unsent_no_video,
                "no H.264 payload type was negotiated",
            );
        }
        params
    }

    /// A frame that could not be written although the connection is up. See
    /// [`Self::unsent_no_video`]: the first says why at warn, and every hundredth after it says how
    /// many, so a session stuck like this cannot look like a still screen.
    ///
    /// Takes the counter rather than `&mut self` because two of its callers still hold a borrow of
    /// `self.rtc` (the writer) when they give up.
    fn note_unsent_no_video(unsent: &mut u64, why: &'static str) {
        *unsent += 1;
        if *unsent == 1 || unsent.is_multiple_of(100) {
            tracing::warn!(
                why,
                frames = *unsent,
                "encoded frames are not being sent: the negotiation left no way to send H.264"
            );
        }
    }

    /// Count a candidate of the viewer's towards the current ICE generation's mix, once per
    /// address: whether the viewer is relay-only is a question about its candidates, not about how
    /// often one was signalled (the Mini App's resume re-sends an offer with its candidates in it
    /// and then trickles them again). `false` when the address was counted already.
    fn note_viewer_candidate(&mut self, addr: SocketAddr, kind: CandidateKind) -> bool {
        if self.viewer_addrs.contains(&addr) {
            return false;
        }
        self.viewer_addrs.push(addr);
        self.viewer_mix.note(kind);
        true
    }

    fn add_remote_ice(&mut self, cand: IceCandidate) {
        // Typed rather than digging a field out of a JSON blob: the shape is part of
        // the contract, so a malformed one is rejected at the edge by serde instead
        // of silently turning into a `None` here.
        if cand.candidate.is_empty() {
            tracing::debug!(ufrag = ?cand.username_fragment, "viewer: end of candidates");
            return; // end-of-candidates marker
        }
        match Candidate::from_sdp_string(&cand.candidate) {
            Ok(c) => {
                tracing::info!(
                    kind = ?c.kind(),
                    addr = %c.addr(),
                    proto = ?c.proto(),
                    prio = c.prio(),
                    ufrag = ?cand.username_fragment,
                    "remote candidate"
                );
                // Counted towards this generation's mix unless it names another generation's
                // ufrag: a late trickle from before a restart says nothing about the viewer now
                // (and str0m rejects it).
                let ufrag = cand.username_fragment.as_deref().or(c.ufrag());
                match (ufrag, self.remote_ufrag.as_deref()) {
                    (Some(theirs), Some(current)) if theirs != current => tracing::debug!(
                        ufrag = theirs,
                        current,
                        "remote candidate of a replaced ICE generation: not counted as the \
                         viewer's current kind of candidate"
                    ),
                    _ => {
                        if !self.note_viewer_candidate(c.addr(), c.kind()) {
                            tracing::debug!(
                                addr = %c.addr(),
                                viewer_relays = self.viewer_mix.relay,
                                viewer_other = self.viewer_mix.other,
                                "remote candidate signalled before in this ICE generation (in an \
                                 offer, or trickled): counted once in the viewer's mix"
                            );
                        }
                    }
                }
                remember_candidate(&mut self.remote_candidates, RemoteCandidate::of(&c));
                self.relay_dest.clear();
                self.rtc.add_remote_candidate(c);
            }
            // The most likely reason a candidate fails to parse is not a bug — it is mDNS, and
            // mDNS is why this product had never once made a peer-to-peer connection. See
            // `crate::mdns`. Resolving happens off this loop and comes back through the same
            // channel as an ordinary candidate, which keeps the one path into str0m single.
            Err(e) => match mdns_host_name(&cand.candidate) {
                Some(name) => self.resolve_mdns(cand, name, "trickle"),
                None => tracing::info!(
                    candidate = %cand.candidate,
                    "remote candidate rejected: {e}"
                ),
            },
        }
    }
}

/// The `<uuid>.local` name in a host candidate, if that is what this is.
///
/// The connection address is the fifth space-separated field of an SDP candidate attribute
/// (RFC 5245 §15.1): `candidate:<foundation> <component> <transport> <priority> <address> ...`.
/// Parsed positionally rather than by searching the string for ".local", so a name appearing in
/// some other field — a ufrag, a future extension — cannot be mistaken for an address.
fn mdns_host_name(candidate: &str) -> Option<String> {
    let addr = candidate.split_whitespace().nth(4)?;
    // Lowercase because DNS names are case-insensitive and the rewrite below matches literally.
    addr.to_ascii_lowercase()
        .strip_suffix(".local")
        .map(|_| addr.to_string())
}

/// Discover the primary outbound IPv4 by asking the OS routing table which
/// local address it would use to reach a public host (no packets are sent).
fn primary_local_ipv4() -> Option<Ipv4Addr> {
    let sock = std::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).ok()?;
    sock.connect((Ipv4Addr::new(8, 8, 8, 8), 80)).ok()?;
    match sock.local_addr().ok()?.ip() {
        IpAddr::V4(v4) if !v4.is_loopback() => Some(v4),
        _ => None,
    }
}

/// Every local IPv4 worth offering as a host candidate, most-likely-useful first.
///
/// Enumerated by asking the routing table which address it would use to reach a handful of
/// well-separated destinations, and keeping the distinct answers. That is deliberately not the same
/// as reading the interface list: an address the routing table would never choose is one no peer
/// can reach either, and offering it only spends ICE checks.
///
/// Link-local `169.254.x` is filtered out. Windows keeps those on adapters that have no DHCP lease
/// — this machine has three — and they are reachable from nothing.
fn local_ipv4s() -> Vec<Ipv4Addr> {
    // Public DNS resolvers on different networks, plus a private-range address so a route for the
    // LAN itself is consulted rather than only the default route. The packets are never sent:
    // `connect` on a UDP socket only fixes the peer and picks a source address.
    const PROBES: &[Ipv4Addr] = &[
        Ipv4Addr::new(8, 8, 8, 8),
        Ipv4Addr::new(1, 1, 1, 1),
        Ipv4Addr::new(192, 168, 0, 1),
        Ipv4Addr::new(192, 168, 1, 1),
        Ipv4Addr::new(10, 0, 0, 1),
    ];

    let mut found: Vec<Ipv4Addr> = Vec::new();
    for probe in PROBES {
        // Trace: a probe with no route is the ordinary answer for most of these destinations, and
        // the callers log what was found.
        let sock = match std::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)) {
            Ok(sock) => sock,
            Err(e) => {
                tracing::trace!(%probe, "local address probe: bind failed: {e}");
                continue;
            }
        };
        if let Err(e) = sock.connect((*probe, 80)) {
            tracing::trace!(%probe, "local address probe: no route: {e}");
            continue;
        }
        if let Ok(SocketAddr::V4(local)) = sock.local_addr() {
            let ip = *local.ip();
            if !ip.is_loopback()
                && !ip.is_link_local()
                && !ip.is_unspecified()
                && !found.contains(&ip)
            {
                found.push(ip);
            }
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use afklink_protocol::{AgentToServer, PeerStage, CHANNEL_INPUT};
    use str0m::change::{SdpAnswer, SdpPendingOffer};
    use str0m::media::{Direction, MediaKind};
    use str0m::net::{DatagramRecv, Protocol, Receive};
    use str0m::{Candidate, CandidateKind, IceConnectionState, Input, Output, Rtc};
    use tokio::net::UdpSocket;
    use tokio::sync::mpsc;

    use crate::host_peer::{
        ChannelDelivery, ChannelRole, DataVerdict, HostPeerOptions, HostSocket, OpenedChannel,
        PeerHooks,
    };
    use std::sync::atomic::{AtomicU32, Ordering};

    use super::{
        candidate_kind_word, describe_remote, first_mid, is_own_address, is_public_v4,
        is_rtp_or_rtcp, mdns_host_name, media_route_note, path_kind_of, reanchor_bwe,
        reanchor_bwe_probing, relay_transport, remember_candidate, remote_path_kinds,
        same_mdns_candidate, sdp_candidates, sdp_ice_ufrag, sdp_summary, short_kind,
        spawn_host_peer, spawn_peer_on, srflx_candidate, srflx_need, with_mdns_address, Breaker,
        CandidateMix, ChainBreak, EgressMeter, Gate, IceTiming, KeyframeAsk, LinkNote, LinkWatch,
        MdnsResolver, MediaSample, PeerControl, PeerEnd, PeerEvent, PeerPath, PeerSignal, Reanchor,
        RefChain, RemoteCandidate, RouteNote, Shed, SrflxNeed, Tuning, ICE_GRACE, KEYFRAME_RETRY,
        PATH_KIND_HOST, PATH_KIND_REFLEXIVE, PATH_KIND_RELAY, QUEUE_HARD_LIMIT_MS, QUEUE_RESUME_MS,
    };

    /// `RevokeQueued` takes back the PC's clipboard text still queued, and nothing else: the
    /// `cb_state` and `cb_ack` around it keep their order.
    #[test]
    fn revoking_takes_back_only_the_revocable_messages_in_order() {
        use super::{revoke_queued, QueuedReliable};
        let q = |text: &str, revocable| QueuedReliable {
            text: text.to_string(),
            revocable,
        };
        let mut queue: std::collections::VecDeque<QueuedReliable> = [
            q("ack-1", false),
            q("pc-0", true),
            q("pc-1", true),
            q("state", false),
            q("pc-2", true),
            q("ack-2", false),
        ]
        .into_iter()
        .collect();
        assert_eq!(revoke_queued(&mut queue), (3, 12));
        let left: Vec<&str> = queue.iter().map(|m| m.text.as_str()).collect();
        assert_eq!(left, ["ack-1", "state", "ack-2"]);
        assert_eq!(revoke_queued(&mut queue), (0, 0));
    }

    /// A ceiling that would end str0m's quiet waits for the video only while none flows; one that
    /// keeps it quiet, one that arrives while the video flows, and one raised from an ordinary
    /// ceiling go at once. The background hold's resume: 1 kbps to the 1697 from before it, the last
    /// frame ten minutes ago.
    #[test]
    fn a_ceiling_that_ends_the_quiet_waits_for_the_video() {
        use super::{ceiling_waits_for_video, probes_nothing, REANCHOR_FLOWING_WITHIN};
        assert!(probes_nothing(1) && probes_nothing(2) && !probes_nothing(3));
        let held_ten_minutes = Some(Duration::from_secs(600));
        assert!(ceiling_waits_for_video(1, 1_697, held_ten_minutes));
        assert!(ceiling_waits_for_video(1, 1_697, None), "never a frame");
        assert!(
            !ceiling_waits_for_video(1, 1_697, Some(REANCHOR_FLOWING_WITHIN)),
            "the video flows"
        );
        assert!(
            !ceiling_waits_for_video(1, 1, held_ten_minutes),
            "still quiet"
        );
        assert!(
            !ceiling_waits_for_video(2_500, 1_697, held_ten_minutes),
            "str0m was not quiet"
        );
    }

    #[test]
    fn a_reanchor_holds_the_opening_probes_to_the_new_estimate() {
        // The numbers of the simulator's 4 Mbps scenario: a re-anchor at 3625 kbps under a
        // 10306 kbps ceiling. A bare reset would open with 10875 and 20612 kbps probes (3x, and 6x
        // capped at twice the ceiling); held, both go out at the estimate.
        let mut rtc = Rtc::builder()
            .set_crypto_provider(Arc::new(str0m::crypto::from_feature_flags()))
            .enable_bwe(Some(str0m::bwe::Bitrate::kbps(600)))
            .build(Instant::now());
        let r = reanchor_bwe(
            &mut rtc,
            str0m::bwe::Bitrate::kbps(3625),
            str0m::bwe::Bitrate::kbps(10_306),
            Instant::now(),
        )
        .expect("a timeout on an idle Rtc cannot fail");
        assert_eq!(
            r,
            Reanchor {
                probe_cap_kbps: 3625,
                bare_reset_probes_kbps: (10_875, 20_612),
            }
        );
        // A ceiling below half the estimate is the tighter cap, as it always was.
        let r = reanchor_bwe(
            &mut rtc,
            str0m::bwe::Bitrate::kbps(4000),
            str0m::bwe::Bitrate::kbps(1500),
            Instant::now(),
        )
        .expect("a timeout on an idle Rtc cannot fail");
        assert_eq!(r.probe_cap_kbps, 3000);
        assert_eq!(r.bare_reset_probes_kbps, (3000, 3000));
    }

    /// A re-probe lets the opening probes past the restart value, and still never past twice the
    /// ceiling: a path change's whole opening (measured: 1337 kbps on the LAN under the 11726
    /// ceiling), a cap inside twice the ceiling as asked, one past it held there.
    #[test]
    fn a_reprobe_lets_the_opening_probes_reach_its_cap_within_twice_the_ceiling() {
        let mut rtc = Rtc::builder()
            .set_crypto_provider(Arc::new(str0m::crypto::from_feature_flags()))
            .enable_bwe(Some(str0m::bwe::Bitrate::kbps(600)))
            .build(Instant::now());
        let kbps = str0m::bwe::Bitrate::kbps;
        let r = reanchor_bwe_probing(
            &mut rtc,
            kbps(1337),
            kbps(11_726),
            kbps(23_452),
            Instant::now(),
        )
        .expect("a timeout on an idle Rtc cannot fail");
        assert_eq!(
            r.probe_cap_kbps, 23_452,
            "the whole opening: 3x and 6x of 1337 fit"
        );
        // A cap inside twice the ceiling: taken as asked.
        let r = reanchor_bwe_probing(&mut rtc, kbps(851), kbps(1702), kbps(3404), Instant::now())
            .expect("a timeout on an idle Rtc cannot fail");
        assert_eq!(r.probe_cap_kbps, 3404);
        // Asked for more than twice the ceiling: held there.
        let r = reanchor_bwe_probing(&mut rtc, kbps(851), kbps(1180), kbps(3404), Instant::now())
            .expect("a timeout on an idle Rtc cannot fail");
        assert_eq!(r.probe_cap_kbps, 2360);
        // Asked for less than the restart value: the restart value, as `reanchor_bwe`.
        let r = reanchor_bwe_probing(
            &mut rtc,
            kbps(2000),
            kbps(10_306),
            kbps(500),
            Instant::now(),
        )
        .expect("a timeout on an idle Rtc cannot fail");
        assert_eq!(r.probe_cap_kbps, 2000);
    }

    #[test]
    fn the_path_kind_ranks_the_viewers_candidate() {
        let candidate = |line: &str| {
            let c = Candidate::from_sdp_string(line).expect("candidate");
            RemoteCandidate::of(&c)
        };
        let book = vec![
            candidate("candidate:1 1 udp 2113937151 192.168.0.74 64609 typ host"),
            candidate(
                "candidate:2 1 udp 1677729535 203.0.113.21 64609 typ srflx raddr 0.0.0.0 rport 0",
            ),
            candidate(
                "candidate:3 1 udp 50341119 198.51.100.147 14574 typ relay raddr 0.0.0.0 rport 0",
            ),
        ];
        let at = |s: &str| s.parse::<SocketAddr>().expect("address");
        assert_eq!(
            path_kind_of(&book, at("192.168.0.74:64609")),
            PATH_KIND_HOST
        );
        assert_eq!(
            path_kind_of(&book, at("203.0.113.21:64609")),
            PATH_KIND_REFLEXIVE
        );
        assert_eq!(
            path_kind_of(&book, at("198.51.100.147:14574")),
            PATH_KIND_RELAY
        );
        assert_eq!(
            path_kind_of(&book, at("10.0.0.9:5000")),
            PATH_KIND_REFLEXIVE,
            "an address the viewer never signalled is a peer-reflexive one ICE learned"
        );
    }

    #[test]
    fn timer_lateness_counts_only_real_sleeps() {
        let mut m = EgressMeter::new();
        assert_eq!(m.timer_late_summary(), "-");
        // A zero-length sleep is the burst path's poll, not a sleep: it says nothing about the tick.
        m.note_timer_wake(Duration::ZERO, Duration::from_millis(9));
        assert_eq!(m.timer_late_summary(), "-");
        // What the default Windows tick does to a 2 ms sleep, and what a 1 ms period does.
        m.note_timer_wake(Duration::from_millis(2), Duration::from_micros(13_600));
        m.note_timer_wake(Duration::from_millis(2), Duration::from_micros(1_000));
        assert_eq!(m.timer_late_summary(), "7.3/13.6ms n=2 >=4ms=1");
    }

    #[test]
    fn the_breaker_bounds_a_queue_that_would_otherwise_integrate() {
        // The failure this exists for, from a measured session on a 6 ms LAN with zero packet
        // loss: the estimate read 1200 kbps, the encoder produced 2400, and the difference went
        // into str0m's unbounded `SendQueue` — 1.7 MB, then 1.9, then 2.1, growing about a second
        // of video per second, reaching 280 seconds of backlog. The user's report was that the
        // picture was ten seconds behind and then never recovered.
        //
        // No rate controller can catch that. Pushback is proportional and bottoms at half, so
        // production stays above `0.45 x estimate`, and against an integrator any steady excess
        // wins eventually. Something has to discard.
        let mut b = Breaker::default();
        assert_eq!(b.admit(0), Shed::Send, "an empty queue sends");
        assert_eq!(
            b.admit(QUEUE_HARD_LIMIT_MS),
            Shed::Send,
            "and so does the limit itself"
        );

        assert_eq!(
            b.admit(QUEUE_HARD_LIMIT_MS + 1),
            Shed::Discard,
            "past it, it does not"
        );
        // Still discarding while the queue is anywhere above the resume level — including at
        // values that are *below* the trip point, which is the whole point of the hysteresis.
        for q in [5_000, 900, QUEUE_RESUME_MS + 1] {
            assert_eq!(
                b.admit(q),
                Shed::Discard,
                "{q} ms must keep the breaker open"
            );
        }
        match b.admit(QUEUE_RESUME_MS) {
            Shed::Resumed { discarded } => {
                assert_eq!(discarded, 4, "it counts what it threw away")
            }
            other => panic!("draining must resume, got {other:?}"),
        }
        assert_eq!(
            b.admit(0),
            Shed::Send,
            "and then it is out of the way again"
        );
    }

    /// Telegram iOS (WebKit): the queue crosses the limit at 1031 ms, two frames are discarded, and
    /// the breaker resumes at 0 ms. A resume "without a keyframe" leaves the iPhone frozen with no
    /// PLI until the periodic IDR fifteen seconds later. Two discarded frames must cost a keyframe
    /// exactly as four do, and the delta frames in between must not reach the viewer.
    #[test]
    fn two_discarded_frames_hold_the_deltas_until_a_keyframe() {
        let t0 = Instant::now();
        let at = |ms: u64| t0 + Duration::from_millis(ms);
        let mut b = Breaker::default();
        let mut chain = RefChain::default();

        // 19:51:45.779 queue 1031 -> discard; .892 still past the resume level -> discard.
        assert_eq!(b.admit(1_031), Shed::Discard);
        assert!(
            chain.lost(ChainBreak::Breaker, at(0)),
            "the first loss breaks it"
        );
        assert_eq!(b.admit(1_017), Shed::Discard);
        assert!(
            !chain.lost(ChainBreak::Breaker, at(113)),
            "the second only counts"
        );
        // .979 queue 0 -> resume, however few were discarded.
        assert_eq!(b.admit(0), Shed::Resumed { discarded: 2 });

        // The resuming frame is a delta: held, and a keyframe asked for with it.
        assert_eq!(chain.admit(false, at(200)), Gate::Hold { ask: true });
        // The next ones before the retry interval are held without asking again.
        assert_eq!(chain.admit(false, at(217)), Gate::Hold { ask: false });
        assert_eq!(chain.admit(false, at(233)), Gate::Hold { ask: false });
        // The keyframe goes, and once written the chain is whole.
        assert_eq!(chain.admit(true, at(250)), Gate::Write);
        let ended = chain.written(true).expect("the keyframe ends the episode");
        assert_eq!(
            (ended.why, ended.lost, ended.held, ended.asks),
            (ChainBreak::Breaker, 2, 3, 1)
        );
        assert_eq!(
            chain.admit(false, at(267)),
            Gate::Write,
            "deltas flow again"
        );
        assert_eq!(chain.written(false), None);
    }

    #[test]
    fn a_keyframe_that_never_comes_is_asked_for_again() {
        let t0 = Instant::now();
        let mut chain = RefChain::default();
        chain.lost(ChainBreak::BeforeConnect, t0);
        // Asked on `Connected`, before any frame of the connection was offered.
        chain.asked(t0);
        assert_eq!(
            chain.admit(false, t0 + Duration::from_millis(30)),
            Gate::Hold { ask: false },
            "the request on Connected covers the first deltas"
        );
        assert_eq!(
            chain.admit(false, t0 + KEYFRAME_RETRY),
            Gate::Hold { ask: true },
            "half a second of held deltas means the request was lost: ask again"
        );
        assert_eq!(chain.broken().map(|b| b.asks), Some(2));
    }

    #[test]
    fn a_keyframe_str0m_refused_does_not_repair_the_chain() {
        let t0 = Instant::now();
        let mut chain = RefChain::default();
        assert_eq!(
            chain.admit(true, t0),
            Gate::Write,
            "a whole chain gates nothing"
        );
        assert_eq!(
            chain.written(true),
            None,
            "and a keyframe on it ends no episode"
        );

        // A delta the writer refused breaks it.
        assert!(chain.lost(ChainBreak::WriteError, t0));
        // The keyframe passes the gate, but its write fails too: still broken.
        assert_eq!(chain.admit(true, t0), Gate::Write);
        assert!(!chain.lost(ChainBreak::WriteError, t0));
        assert!(chain.broken().is_some());
        assert_eq!(chain.admit(false, t0), Gate::Hold { ask: true });
        // The next keyframe is written: whole again.
        assert_eq!(chain.admit(true, t0), Gate::Write);
        let ended = chain.written(true).expect("repaired");
        assert_eq!(
            (ended.why, ended.lost, ended.held),
            (ChainBreak::WriteError, 2, 1)
        );
        assert!(chain.broken().is_none());
    }

    #[test]
    fn only_rtp_and_rtcp_say_which_pair_the_media_takes() {
        // RFC 7983: RTP v2 and RTCP start 0x80-0xBF; STUN 0x00-0x03; DTLS 0x14-0x3F.
        for b in [0x80, 0x90, 0xBF] {
            assert!(is_rtp_or_rtcp(b), "{b:#x}");
        }
        for b in [0x00, 0x01, 0x03, 0x14, 0x16, 0x3F, 0x7F, 0xC0] {
            assert!(!is_rtp_or_rtcp(b), "{b:#x}");
        }

        let local: SocketAddr = "192.168.1.10:50000".parse().expect("addr");
        let relay_wifi: SocketAddr = "198.51.100.123:63339".parse().expect("addr");
        let relay_lte: SocketAddr = "198.51.100.238:12979".parse().expect("addr");
        let mut route = None;
        assert_eq!(
            media_route_note(&mut route, local, relay_wifi, Some(0x01)),
            RouteNote::NotMedia,
            "a STUN check before any media says nothing"
        );
        assert_eq!(
            media_route_note(&mut route, local, relay_wifi, Some(0x80)),
            RouteNote::First
        );
        assert_eq!(
            media_route_note(&mut route, local, relay_lte, Some(0x00)),
            RouteNote::NotMedia,
            "a check on another pair is not the media moving"
        );
        assert_eq!(
            media_route_note(&mut route, local, relay_wifi, Some(0x90)),
            RouteNote::Same
        );
        assert_eq!(
            media_route_note(&mut route, local, relay_lte, Some(0x80)),
            RouteNote::Changed {
                from: (local, relay_wifi)
            },
            "the viewer's new relay: the path changed"
        );
        assert_eq!(
            media_route_note(&mut route, local, relay_lte, Some(0x80)),
            RouteNote::Same
        );
    }

    /// The pair line names the viewer's candidate and, for a relay, the leg to its TURN server —
    /// from the priorities an iPhone has been seen offering: TCP and TLS relays and no UDP one.
    #[test]
    fn the_selected_pair_is_named_with_the_relays_transport() {
        assert_eq!(relay_transport(16_785_663), "tcp");
        assert_eq!(relay_transport(16_786_431), "tcp");
        assert_eq!(relay_transport(8_959), "tls");
        assert_eq!(relay_transport(8_191), "tls");
        assert_eq!(
            relay_transport(41_885_439),
            "udp",
            "Chrome's relay over UDP"
        );
        assert_eq!(relay_transport(2_122_260_223), "unknown", "a host priority");

        let offer = "v=0\r\n\
                     a=candidate:1 1 udp 2122260223 192.168.0.5 50000 typ host\r\n\
                     a=candidate:3 1 udp 16785663 198.51.100.100 56073 typ relay raddr 0.0.0.0 rport 0\r\n\
                     a=candidate:4 1 udp 8959 198.51.100.238 35829 typ relay raddr 0.0.0.0 rport 0\r\n";
        let mut book = sdp_candidates(offer).parsed;
        assert_eq!(book.len(), 3, "{book:?}");
        let tcp_relay: SocketAddr = "198.51.100.100:56073".parse().expect("addr");
        let tls_relay: SocketAddr = "198.51.100.238:35829".parse().expect("addr");
        let host: SocketAddr = "192.168.0.5:50000".parse().expect("addr");
        let unknown: SocketAddr = "198.51.100.7:40000".parse().expect("addr");
        let (kind, proto, relay, prio) = describe_remote(&book, tcp_relay);
        assert_eq!(
            (kind.as_str(), proto.as_str(), relay),
            ("relay", "udp", "tcp")
        );
        assert_eq!(prio, Some(16_785_663));
        assert_eq!(describe_remote(&book, tls_relay).2, "tls");
        let (kind, _, relay, _) = describe_remote(&book, host);
        assert_eq!((kind.as_str(), relay), ("host", "-"));
        let (kind, _, relay, prio) = describe_remote(&book, unknown);
        assert_eq!(
            (kind.as_str(), relay, prio),
            ("prflx (not signalled)", "-", None)
        );
        // And in a word, for the path lines.
        assert_eq!(short_kind(&book, tcp_relay), "relay/tcp");
        assert_eq!(short_kind(&book, tls_relay), "relay/tls");
        assert_eq!(short_kind(&book, host), "host");
        assert_eq!(short_kind(&book, unknown), "unsignalled");

        // A restart's offer re-describes an address rather than adding a second entry for it.
        let again = sdp_candidates(
            "a=candidate:9 1 udp 41885439 198.51.100.100 56073 typ relay raddr 0.0.0.0 rport 0\r\n",
        );
        for c in again.parsed {
            remember_candidate(&mut book, c);
        }
        assert_eq!(book.len(), 3);
        assert_eq!(describe_remote(&book, tcp_relay).2, "udp");
    }

    #[test]
    fn the_breaker_cannot_chatter_at_the_operating_point() {
        // A breaker that resets at its own threshold oscillates, and every frame it discards costs
        // a keyframe to recover from — so a chattering one would emit a keyframe storm, which is
        // the single most expensive thing this pipeline can do.
        //
        // The gap is what prevents it. Normal operation measured 20-100 ms, so the trip point sits
        // an order of magnitude above where the system actually lives.
        let mut b = Breaker::default();
        // A queue sitting exactly at a healthy operating point, forever, must never trip it.
        for _ in 0..1_000 {
            assert_eq!(b.admit(100), Shed::Send);
        }
    }

    #[test]
    fn spots_the_mdns_name_a_browser_actually_sends() {
        // Verbatim from a session log. This is the only host candidate an iOS browser offers, and
        // failing to recognise it is why every session in this product's history used the relay.
        let c = "candidate:2573368309 1 udp 2113937151 \
                 2d1bab66-20b5-4b47-bbd8-3ace2d76f6b4.local 52726 typ host \
                 generation 0 ufrag rsXV network-cost 999";
        assert_eq!(
            mdns_host_name(c).as_deref(),
            Some("2d1bab66-20b5-4b47-bbd8-3ace2d76f6b4.local")
        );
    }

    #[test]
    fn leaves_ordinary_candidates_alone() {
        // These parse on their own and must never be sent on a multicast round trip.
        for c in [
            "candidate:1 1 udp 2113937151 192.168.1.42 52726 typ host generation 0",
            "candidate:2 1 udp 1694498815 203.0.113.21 52726 typ srflx raddr 0.0.0.0 rport 0",
            "candidate:3 1 udp 41885439 198.51.100.133 52589 typ relay raddr 0.0.0.0 rport 0",
        ] {
            assert_eq!(mdns_host_name(c), None, "{c}");
        }
    }

    #[test]
    fn reads_the_address_field_and_not_the_whole_string() {
        // ".local" appearing anywhere else — a ufrag, some future extension — is not an address,
        // and treating it as one would send a lookup for a name nothing has registered.
        let c = "candidate:1 1 udp 2113937151 192.168.1.42 52726 typ host ufrag my.local";
        assert_eq!(mdns_host_name(c), None);
    }

    #[test]
    fn a_malformed_candidate_is_not_a_panic() {
        for c in ["", "candidate:1", "candidate:1 1 udp 2113937151"] {
            assert_eq!(mdns_host_name(c), None, "{c:?}");
        }
    }

    /// An offer's own candidate lines, as Chrome lays them out — before its section's `a=ice-ufrag`
    /// and `a=mid` — sorted into what str0m reads, the mDNS hosts to look up (each as the trickle
    /// it would have been, stamped with its generation's ufrag), and the rest, kept with why.
    #[test]
    fn an_sdps_candidate_lines_are_parsed_looked_up_or_rejected_and_none_is_dropped() {
        let sdp = "v=0\r\no=- 1 2 IN IP4 0.0.0.0\r\ns=-\r\n\
                   m=video 9 UDP/TLS/RTP/SAVPF 96\r\nc=IN IP4 0.0.0.0\r\n\
                   a=candidate:1 1 udp 2122260223 5F3C1D2E-8a4b-4c6d-9e0f-1a2b3c4d5e6f.local 54400 typ host generation 0 network-id 1\r\n\
                   a=candidate:2 1 udp 1686052607 203.0.113.21 54400 typ srflx raddr 0.0.0.0 rport 0 generation 0\r\n\
                   a=candidate:3 1 udp 41885439 198.51.100.133 52589 typ relay raddr 0.0.0.0 rport 0\r\n\
                   a=candidate:4 1 udp 2122260223 not-an-address 54401 typ host\r\n\
                   a=ice-ufrag:kTDt\r\na=ice-pwd:x\r\na=mid:0\r\n\
                   m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n\
                   a=candidate:5 1 udp 2122260223 aaaa.local 54402 typ host ufrag kTDt\r\n\
                   a=ice-ufrag:kTDt\r\na=mid:1\r\n";
        let found = sdp_candidates(sdp);
        let parsed: Vec<_> = found.parsed.iter().map(|c| (c.kind, c.addr)).collect();
        assert_eq!(
            parsed,
            [
                (
                    CandidateKind::ServerReflexive,
                    "203.0.113.21:54400".parse().expect("addr")
                ),
                (
                    CandidateKind::Relayed,
                    "198.51.100.133:52589".parse().expect("addr")
                ),
            ]
        );
        assert_eq!(found.mdns.len(), 2, "{:?}", found.mdns);
        let (first, name) = &found.mdns[0];
        assert_eq!(name, "5F3C1D2E-8a4b-4c6d-9e0f-1a2b3c4d5e6f.local");
        assert_eq!(
            first.candidate,
            "candidate:1 1 udp 2122260223 5F3C1D2E-8a4b-4c6d-9e0f-1a2b3c4d5e6f.local 54400 typ host \
             generation 0 network-id 1 ufrag kTDt",
            "the line, stamped with the ufrag its section names after it"
        );
        assert_eq!(first.sdp_mid.as_deref(), Some("0"));
        assert_eq!(first.sdp_mline_index, Some(0));
        assert_eq!(first.username_fragment.as_deref(), Some("kTDt"));
        let (second, name) = &found.mdns[1];
        assert_eq!(name, "aaaa.local");
        assert!(
            second.candidate.ends_with("typ host ufrag kTDt"),
            "a line with a ufrag of its own is left as it is: {}",
            second.candidate
        );
        assert_eq!(second.sdp_mid.as_deref(), Some("1"));
        assert_eq!(second.sdp_mline_index, Some(1));
        assert_eq!(found.rejected.len(), 1, "{:?}", found.rejected);
        assert!(
            found.rejected[0].contains("not-an-address"),
            "{:?}",
            found.rejected
        );

        // Once resolved, the stamped line is one str0m reads, for that generation only.
        let addr = Ipv4Addr::new(192, 168, 0, 31);
        let resolved = with_mdns_address(first, addr).expect("names an mDNS host");
        let c = Candidate::from_sdp_string(&resolved.candidate).expect("parses");
        assert_eq!(c.addr(), "192.168.0.31:54400".parse().expect("addr"));
        assert_eq!(c.ufrag(), Some("kTDt"));
        // The same host trickled — Chrome puts the ufrag earlier on the line — is the same
        // candidate to the lookup; another port or generation is not.
        let trickle = afklink_protocol::IceCandidate {
            candidate: "candidate:1 1 udp 2122260223 5F3C1D2E-8a4b-4c6d-9e0f-1a2b3c4d5e6f.local \
                        54400 typ host generation 0 ufrag kTDt network-id 1"
                .into(),
            sdp_mid: Some("0".into()),
            sdp_mline_index: Some(0),
            username_fragment: Some("kTDt".into()),
        };
        assert!(same_mdns_candidate(first, &trickle));
        let elsewhere = afklink_protocol::IceCandidate {
            candidate: trickle.candidate.replace("54400", "54409"),
            ..trickle.clone()
        };
        assert!(!same_mdns_candidate(first, &elsewhere));
        let restarted = afklink_protocol::IceCandidate {
            username_fragment: Some("Zq9x".into()),
            ..trickle
        };
        assert!(!same_mdns_candidate(first, &restarted));
        // Nothing to say about an SDP without candidates.
        assert!(sdp_candidates("v=0\r\nm=video 9 UDP/TLS/RTP/SAVPF 96\r\n")
            .parsed
            .is_empty());
    }

    /// An offer shaped like the viewer's: one recvonly video transceiver and a data channel.
    fn viewer_like_offer() -> String {
        let mut rtc = Rtc::builder()
            .set_crypto_provider(Arc::new(str0m::crypto::from_feature_flags()))
            .clear_codecs()
            .enable_h264(true)
            .build(Instant::now());
        let mut api = rtc.sdp_api();
        api.add_media(MediaKind::Video, Direction::RecvOnly, None, None, None);
        api.add_channel(CHANNEL_INPUT.to_string());
        let (offer, _pending) = api.apply().expect("an offer");
        offer.to_sdp_string()
    }

    /// The SDP line in the log answers "which codec, which extensions, which candidates" and never
    /// carries the ICE password or the DTLS fingerprint.
    #[test]
    fn the_sdp_summary_names_what_was_negotiated_and_no_credential() {
        let sdp = "v=0\r\no=- 1 2 IN IP4 0.0.0.0\r\ns=-\r\na=ice-ufrag:AbCd\r\n\
                   a=ice-pwd:supersecretpassword123\r\n\
                   a=fingerprint:sha-256 AA:BB:CC\r\n\
                   m=video 9 UDP/TLS/RTP/SAVPF 96 97 98\r\na=mid:0\r\na=setup:actpass\r\n\
                   a=recvonly\r\n\
                   a=extmap:5 http://www.webrtc.org/experiments/rtp-hdrext/playout-delay\r\n\
                   a=rtpmap:96 VP8/90000\r\na=rtpmap:97 H264/90000\r\n\
                   a=fmtp:97 level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42e01f\r\n\
                   a=rtpmap:98 rtx/90000\r\n\
                   a=candidate:1 1 udp 2122260223 192.168.0.5 50000 typ host\r\n\
                   a=candidate:2 1 udp 1686052607 203.0.113.9 50001 typ srflx raddr 0.0.0.0 rport 0\r\n\
                   m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\na=mid:1\r\n";
        let s = sdp_summary(sdp);
        assert!(
            s.contains(
                "m=video mid=0 dir=recvonly codecs=[97:H264(profile=42e01f,mode=1),VP8,rtx]"
            ),
            "{s}"
        );
        assert!(s.contains("ext=[5:playout-delay]"), "{s}");
        assert!(s.contains("m=application mid=1"), "{s}");
        assert!(
            s.ends_with("candidates=[host=1,srflx=1] ufrag=AbCd setup=actpass"),
            "{s}"
        );
        assert!(!s.contains("supersecretpassword123"), "{s}");
        assert!(!s.contains("AA:BB:CC"), "{s}");
        // And a real offer from str0m parses into something that names H.264.
        assert!(sdp_summary(&viewer_like_offer()).contains("H264("));
    }

    #[test]
    fn the_first_mid_is_the_first_m_lines() {
        let sdp = "v=0\r\no=- 1 2 IN IP4 0.0.0.0\r\ns=-\r\na=group:BUNDLE 0 1\r\n\
                   m=video 9 UDP/TLS/RTP/SAVPF 96\r\na=mid:0\r\n\
                   m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\na=mid:1\r\n";
        assert_eq!(first_mid(sdp).as_deref(), Some("0"));
        assert_eq!(first_mid("v=0\r\n"), None);
    }

    #[test]
    fn a_srflx_candidate_is_the_line_the_answer_always_carried() {
        let mapped: SocketAddr = "203.0.113.7:40000".parse().expect("addr");
        let c = srflx_candidate(mapped, Ipv4Addr::new(192, 168, 0, 24), 52888).expect("parses");
        assert_eq!(c.kind(), str0m::CandidateKind::ServerReflexive);
        assert_eq!(c.addr(), mapped);
        assert!(is_own_address(
            "192.168.0.24:1".parse().expect("addr"),
            &[Ipv4Addr::new(192, 168, 0, 24)]
        ));
        assert!(!is_own_address(mapped, &[Ipv4Addr::new(192, 168, 0, 24)]));
    }

    #[tokio::test]
    async fn a_srflx_that_misses_the_answer_is_trickled_when_it_arrives() {
        // The path to the STUN server loses the first three requests —
        // the whole of the answer's budget — and answers the fourth, at 1750 ms. The answer goes
        // out with host candidates only; the mapping follows as a trickled candidate.
        let mapped: SocketAddr = "203.0.113.7:40000".parse().expect("addr");
        let (server, seen) = crate::stun::test_server::spawn(3, mapped).await;
        let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind");

        let t0 = Instant::now();
        let mut peer = spawn_peer_on(
            socket,
            &viewer_like_offer(),
            vec![server.to_string()],
            Tuning::default(),
        )
        .await
        .expect("a peer");
        let answered = t0.elapsed();
        assert!(
            answered >= crate::stun::ANSWER_BUDGET
                && answered < crate::stun::ANSWER_BUDGET + Duration::from_millis(500),
            "the answer waited {answered:?}"
        );
        assert!(
            !peer.answer_sdp.contains("typ srflx"),
            "{}",
            peer.answer_sdp
        );

        let ice = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                match peer.events.recv().await {
                    Some(PeerEvent::LocalCandidate(c)) => return c,
                    Some(_) => {}
                    None => panic!("the peer ended without trickling a candidate"),
                }
            }
        })
        .await
        .expect("a trickled candidate within the transaction's lifetime");
        assert_eq!(seen.load(std::sync::atomic::Ordering::SeqCst), 4);
        assert!(
            ice.candidate.starts_with("candidate:")
                && ice.candidate.contains(" 203.0.113.7 40000 typ srflx"),
            "{}",
            ice.candidate
        );
        assert!(ice.sdp_mid.is_some());
        assert_eq!(ice.sdp_mid, first_mid(&peer.answer_sdp));
        assert_eq!(ice.sdp_mline_index, Some(0));

        // What the viewer receives, after the server relays it unchanged: `RTCIceCandidateInit`
        // field names, which `addRemoteIce` in the Mini App reads.
        let wire = serde_json::to_value(AgentToServer::Ice {
            session_id: "3fa85f64-5717-4562-b3fc-2c963f66afa6".into(),
            candidate: ice.clone(),
        })
        .expect("serialises");
        assert_eq!(wire["type"], "ice");
        assert_eq!(wire["candidate"]["candidate"], ice.candidate.as_str());
        assert_eq!(wire["candidate"]["sdpMid"].as_str(), ice.sdp_mid.as_deref());
        assert_eq!(wire["candidate"]["sdpMLineIndex"], 0);

        peer.closer.close();
    }

    #[tokio::test]
    async fn a_prompt_srflx_goes_in_the_answer_and_nothing_is_trickled() {
        let mapped: SocketAddr = "203.0.113.8:40001".parse().expect("addr");
        let (server, seen) = crate::stun::test_server::spawn(0, mapped).await;
        let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
        let mut peer = spawn_peer_on(
            socket,
            &viewer_like_offer(),
            vec![server.to_string()],
            Tuning::default(),
        )
        .await
        .expect("a peer");
        assert!(
            peer.answer_sdp.contains("203.0.113.8 40001 typ srflx"),
            "{}",
            peer.answer_sdp
        );
        assert_eq!(seen.load(std::sync::atomic::Ordering::SeqCst), 1);
        // No background transaction, so nothing arrives.
        let next = tokio::time::timeout(Duration::from_millis(600), peer.events.recv()).await;
        assert!(
            !matches!(next, Ok(Some(PeerEvent::LocalCandidate(_)))),
            "{next:?}"
        );
        peer.closer.close();
    }

    #[test]
    fn only_a_relay_only_viewer_and_nothing_public_of_ours_make_a_srflx_required() {
        // A viewer that offers eight relays and nothing else.
        let offer = "a=ice-ufrag:kTDt\r\n\
                     a=candidate:1 1 udp 16786175 198.51.100.133 26747 typ relay raddr 0.0.0.0 rport 0\r\n\
                     a=candidate:2 1 udp 8191 198.51.100.12 65387 typ relay raddr 0.0.0.0 rport 0\r\n";
        let relays = CandidateMix::of(&sdp_candidates(offer).parsed);
        assert_eq!(relays, CandidateMix { relay: 2, other: 0 });
        // Listed twice (an SDP may repeat its candidates under every bundled m-line): the same two.
        let twice = format!("{offer}m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n{offer}");
        assert_eq!(sdp_candidates(&twice).parsed.len(), 4);
        assert_eq!(CandidateMix::of(&sdp_candidates(&twice).parsed), relays);
        assert_eq!(sdp_ice_ufrag(offer).as_deref(), Some("kTDt"));
        assert_eq!(srflx_need(relays, false, false), SrflxNeed::Required);
        // Anything that lets a path form without our public address.
        assert_eq!(srflx_need(relays, true, false), SrflxNeed::Offered);
        assert_eq!(srflx_need(relays, false, true), SrflxNeed::PublicHost);
        let mut mixed = relays;
        mixed.note(str0m::CandidateKind::ServerReflexive);
        assert_eq!(
            srflx_need(mixed, false, false),
            SrflxNeed::ViewerNotRelayOnly
        );
        // A trickling viewer whose candidates have not come yet is not taken for relay-only.
        assert_eq!(
            srflx_need(CandidateMix::default(), false, false),
            SrflxNeed::ViewerUnknown
        );
    }

    #[test]
    fn a_host_address_behind_a_nat_is_not_one_a_relay_forwards_to() {
        // This PC's two (Wi-Fi, `xray_tun`), and the rest a relay refuses.
        for ip in [
            "192.168.0.24",
            "172.18.0.1",
            "10.0.0.5",
            "100.64.0.1",
            "100.127.255.254",
            "127.0.0.1",
            "169.254.1.1",
            "0.0.0.0",
            "198.18.0.1",
            "203.0.113.7",
            "224.0.0.1",
            "255.255.255.255",
        ] {
            assert!(!is_public_v4(ip.parse().expect("ip")), "{ip}");
        }
        // Globally routable addresses (public DNS resolvers: a documentation range would be refused
        // above), and the edge of shared space.
        for ip in ["8.8.8.8", "9.9.9.9", "100.128.0.1", "1.1.1.1"] {
            assert!(is_public_v4(ip.parse().expect("ip")), "{ip}");
        }
    }

    /* ── The grace window, as rules ──────────────────────────────────────────── */

    const S: fn(u64) -> Duration = Duration::from_secs;

    #[test]
    fn a_lost_path_opens_a_window_that_a_second_report_does_not_extend() {
        let t0 = Instant::now();
        let grace = S(20);
        let mut w = LinkWatch::default();
        // The first connection is not a restore: nothing was lost.
        assert_eq!(
            w.on_state(IceConnectionState::Checking, t0, grace),
            LinkNote::Unchanged
        );
        assert_eq!(
            w.on_state(IceConnectionState::Connected, t0, grace),
            LinkNote::Unchanged
        );
        assert_eq!(
            w.on_state(IceConnectionState::Completed, t0, grace),
            LinkNote::Unchanged
        );
        assert!(!w.expired(t0 + S(3600)), "a healthy link has no deadline");

        let lost = t0 + S(60);
        assert_eq!(
            w.on_state(IceConnectionState::Disconnected, lost, grace),
            LinkNote::Lost
        );
        assert_eq!(w.deadline(), Some(lost + grace));
        // A trickled candidate briefly gives str0m something to check, and that fails too. The
        // path has been gone since the first report, and the window says so.
        assert_eq!(
            w.on_state(IceConnectionState::Checking, lost + S(5), grace),
            LinkNote::Unchanged
        );
        assert_eq!(
            w.on_state(IceConnectionState::Disconnected, lost + S(8), grace),
            LinkNote::StillLost { left: S(12) }
        );
        assert!(!w.expired(lost + grace - Duration::from_millis(1)));
        assert!(w.expired(lost + grace));
    }

    #[test]
    fn a_restart_replaces_the_window_and_the_restored_path_closes_it() {
        let t0 = Instant::now();
        let grace = S(20);
        let mut w = LinkWatch::default();
        w.on_state(IceConnectionState::Connected, t0, grace);
        w.on_state(IceConnectionState::Disconnected, t0 + S(1), grace);

        // The viewer's restart lands ten seconds into the window: the rest of that window goes,
        // and the restart gets a whole one of its own.
        assert_eq!(w.on_restart(t0 + S(11), grace), Some(S(10)));
        assert!(
            !w.expired(t0 + S(1) + grace),
            "the loss's window no longer applies"
        );
        assert_eq!(w.deadline(), Some(t0 + S(11) + grace));
        // The restart's own checks failing does not buy it more time.
        assert_eq!(
            w.on_state(IceConnectionState::Disconnected, t0 + S(15), grace),
            LinkNote::StillLost { left: S(16) }
        );
        assert_eq!(
            w.on_state(IceConnectionState::Connected, t0 + S(16), grace),
            LinkNote::Restored {
                outage: S(15),
                restarted: true
            }
        );
        assert_eq!(w.deadline(), None);
        assert!(!w.expired(t0 + S(3600)));

        // A later loss is a new outage, and recovering from it without a restart says so.
        assert_eq!(
            w.on_state(IceConnectionState::Disconnected, t0 + S(100), grace),
            LinkNote::Lost
        );
        assert_eq!(
            w.on_state(IceConnectionState::Completed, t0 + S(103), grace),
            LinkNote::Restored {
                outage: S(3),
                restarted: false
            }
        );
    }

    #[test]
    fn a_restart_that_never_connects_runs_out_too() {
        // The viewer restarted before we noticed anything (Chrome declares failure before str0m
        // does), and the restart's candidates never arrive: str0m then sits in `Checking` for good,
        // so only this window ends it.
        let t0 = Instant::now();
        let grace = S(20);
        let mut w = LinkWatch::default();
        w.on_state(IceConnectionState::Connected, t0, grace);
        assert_eq!(w.on_restart(t0 + S(5), grace), None);
        assert_eq!(
            w.on_state(IceConnectionState::Checking, t0 + S(5), grace),
            LinkNote::Unchanged
        );
        assert!(!w.expired(t0 + S(5) + grace - Duration::from_millis(1)));
        assert!(w.expired(t0 + S(5) + grace));
    }

    #[test]
    fn every_ending_has_its_own_reason() {
        // The strings reach the server's session history, which must tell a network change, a
        // dead viewer and a failed restart apart. They are listed in
        // `SESSION_END_REASONS` (packages/protocol/src/errors.ts).
        assert_eq!(PeerEnd::IceTimeout.reason(), "ice_timeout");
        assert_eq!(PeerEnd::RestartFailed.reason(), "ice_restart_failed");
        assert_eq!(PeerEnd::Closed.reason(), "peer_closed");
        assert_eq!(PeerEnd::RtcClosed.reason(), "peer_closed");
        // The viewer's goodbye is `peer_closed` on the wire too; the journal tells it apart.
        assert_eq!(PeerEnd::ViewerClosed.reason(), "peer_closed");
        assert_eq!(PeerEnd::Error.reason(), "peer_error");
        assert!(PeerEnd::ViewerClosed.by_viewer());
        for end in [
            PeerEnd::Closed,
            PeerEnd::RtcClosed,
            PeerEnd::IceTimeout,
            PeerEnd::RestartFailed,
            PeerEnd::Error,
        ] {
            assert!(!end.by_viewer(), "{end:?}");
        }
    }

    /* ── The same, against a real str0m viewer ───────────────────────────────── */

    /// A viewer played by a second str0m `Rtc` on its own loopback socket, driven by the test.
    /// The agent's peer loop runs for real on the other side of the loopback.
    struct TestViewer {
        rtc: Rtc,
        socket: UdpSocket,
        addr: SocketAddr,
        buf: Vec<u8>,
        /// Datagrams larger than this, on their way to the viewer, are lost: a path that carries a
        /// STUN check and not a DTLS flight, as some VPNs seem to. `None` loses nothing.
        drop_in_over: Option<usize>,
        /// A second path that carries the viewer's checks to the agent and nothing back. See
        /// [`TestViewer::haunt`].
        ghost: Option<Ghost>,
        /// The viewer's `input` channel, to talk on ([`TestViewer::say`]).
        input: str0m::channel::ChannelId,
        /// The viewer's `cursor` channel, when it offered one ([`TestViewer::say_cursor`]).
        cursor: Option<str0m::channel::ChannelId>,
        /// Every text message the agent's data channels delivered to the viewer, when.
        heard: Vec<(Instant, String)>,
        /// Video frames str0m handed the viewer whole (`Event::MediaData`).
        frames: u32,
    }

    /// A one-way path: an iPhone's srflx address behind its VPN, which delivers the phone's checks
    /// to the agent and nothing of the agent's to the phone.
    ///
    /// A socket of its own that sends the agent a copy of every check the viewer sends — each with
    /// the USE-CANDIDATE the viewer puts on it, which is what libwebrtc does on a pair that
    /// outranks its selected one — and swallows whatever the agent sends back, counting it.
    struct Ghost {
        socket: UdpSocket,
        addr: SocketAddr,
        /// Whether the viewer's checks are copied over the ghost path right now.
        copying: bool,
        /// What the agent sent to the ghost address, by the first byte: STUN, DTLS, RTP/RTCP.
        got_stun: u32,
        got_dtls: u32,
        got_rtp: u32,
    }

    impl Ghost {
        /// Swallow everything the agent sent here so far, counting it.
        fn drain(&mut self) {
            let mut buf = [0u8; 2048];
            while let Ok((n, _)) = self.socket.try_recv_from(&mut buf) {
                match crate::paths::Kind::of(&buf[..n]) {
                    crate::paths::Kind::Stun => self.got_stun += 1,
                    crate::paths::Kind::Dtls => self.got_dtls += 1,
                    crate::paths::Kind::Rtp => self.got_rtp += 1,
                    crate::paths::Kind::Other => {}
                }
            }
        }
    }

    impl TestViewer {
        /// A viewer shaped like the Mini App (recvonly video, the input channel) with one host
        /// candidate, and the offer it opens with.
        ///
        /// `lite` makes it an ICE-lite agent, which never sends checks of its own. That is not what
        /// Chrome does; it is what lets a test make the agent notice a dead path in about a second
        /// rather than twenty: str0m keeps a pair alive for 15 s after the remote's last check,
        /// whatever its own timing (`RECENT_BINDING_REQUEST`), and a lite remote sends none.
        async fn new(lite: bool) -> (Self, String, SdpPendingOffer) {
            Self::with_channels(lite, false).await
        }

        /// [`TestViewer::new`] with the Mini App's `cursor` channel too: unordered, never
        /// retransmitted (`webrtc.ts`, `DATA_CHANNELS`), the one the heartbeat and the cursor
        /// reports ride.
        async fn with_cursor(lite: bool) -> (Self, String, SdpPendingOffer) {
            Self::with_channels(lite, true).await
        }

        async fn with_channels(lite: bool, cursor: bool) -> (Self, String, SdpPendingOffer) {
            let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind viewer");
            Self::on_socket(socket, lite, cursor)
        }

        fn on_socket(
            socket: UdpSocket,
            lite: bool,
            cursor: bool,
        ) -> (Self, String, SdpPendingOffer) {
            let addr = socket.local_addr().expect("viewer addr");
            let mut rtc = Rtc::builder()
                .set_crypto_provider(Arc::new(str0m::crypto::from_feature_flags()))
                .clear_codecs()
                .enable_h264(true)
                .set_ice_lite(lite)
                .build(Instant::now());
            rtc.add_local_candidate(Candidate::host(addr, "udp").expect("host candidate"));
            let mut api = rtc.sdp_api();
            api.add_media(MediaKind::Video, Direction::RecvOnly, None, None, None);
            let input = api.add_channel(CHANNEL_INPUT.to_string());
            let cursor = cursor.then(|| {
                api.add_channel_with_config(str0m::channel::ChannelConfig {
                    label: afklink_protocol::CHANNEL_CURSOR.to_string(),
                    ordered: false,
                    reliability: str0m::channel::Reliability::MaxRetransmits { retransmits: 0 },
                    ..Default::default()
                })
            });
            let (offer, pending) = api.apply().expect("an offer");
            let viewer = Self {
                rtc,
                socket,
                addr,
                buf: vec![0; 2048],
                drop_in_over: None,
                ghost: None,
                input,
                cursor,
                heard: Vec::new(),
                frames: 0,
            };
            (viewer, offer.to_sdp_string(), pending)
        }

        /// Write `text` on the viewer's `input` channel, as the Mini App sends `vis` or a move.
        fn say(&mut self, text: &str) {
            let mut channel = self
                .rtc
                .channel(self.input)
                .expect("the input channel is open");
            assert!(
                channel.write(false, text.as_bytes()).expect("written"),
                "str0m took it"
            );
        }

        /// Write `text` on the viewer's `cursor` channel.
        fn say_cursor(&mut self, text: &str) {
            let mut channel = self
                .rtc
                .channel(self.cursor.expect("cursor channel offered"))
                .expect("cursor channel open");
            assert!(channel.write(false, text.as_bytes()).expect("written"));
        }

        /// Throw away, unread, every datagram the agent sent while the viewer was not reading: a
        /// phone whose network slept with it lost them.
        fn forget_inbox(&mut self) -> usize {
            let mut forgotten = 0;
            while self.socket.try_recv_from(&mut self.buf).is_ok() {
                forgotten += 1;
            }
            forgotten
        }

        /// Give the viewer a ghost path ([`Ghost`]) and return `offer` as the agent should see
        /// it: the viewer's own address signalled as a relay it reaches over TCP (priority
        /// 16785663, as an iPhone offers), and the ghost's as its srflx candidate (1677729535,
        /// as the iPhone's srflx had), which outranks the relay by far.
        async fn haunt(&mut self, offer: &str) -> String {
            let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind ghost");
            let addr = socket.local_addr().expect("ghost addr");
            self.ghost = Some(Ghost {
                socket,
                addr,
                copying: true,
                got_stun: 0,
                got_dtls: 0,
                got_rtp: 0,
            });
            let host = offer
                .lines()
                .find(|l| l.starts_with("a=candidate:"))
                .expect("the viewer's host candidate")
                .trim_end()
                .to_string();
            let lines = format!(
                "a=candidate:3 1 udp 16785663 {} {} typ relay raddr 0.0.0.0 rport 0\r\n\
                 a=candidate:2 1 udp 1677729535 {} {} typ srflx raddr 0.0.0.0 rport 0",
                self.addr.ip(),
                self.addr.port(),
                addr.ip(),
                addr.port()
            );
            offer.replace(&host, &lines)
        }

        fn ghost(&self) -> &Ghost {
            self.ghost.as_ref().expect("a haunted viewer")
        }

        fn ghost_mut(&mut self) -> &mut Ghost {
            self.ghost.as_mut().expect("a haunted viewer")
        }

        fn accept(&mut self, pending: SdpPendingOffer, answer_sdp: &str) {
            let answer = SdpAnswer::from_sdp_string(answer_sdp).expect("the answer parses");
            self.rtc
                .sdp_api()
                .accept_answer(pending, answer)
                .expect("the viewer takes the answer");
        }

        /// What `createOffer({ iceRestart: true })` produces: new credentials, same session.
        fn restart_offer(&mut self) -> (String, SdpPendingOffer) {
            let mut api = self.rtc.sdp_api();
            api.ice_restart(true);
            let (offer, pending) = api.apply().expect("a restart offer");
            (offer.to_sdp_string(), pending)
        }

        /// Serve the viewer's side of the network for `dur`.
        async fn pump(&mut self, dur: Duration) {
            let until = Instant::now() + dur;
            loop {
                if let Some(ghost) = self.ghost.as_mut() {
                    ghost.drain();
                }
                let timeout = loop {
                    match self.rtc.poll_output().expect("viewer output") {
                        Output::Timeout(t) => break t,
                        Output::Transmit(t) => {
                            // A check (a Binding request) goes over the ghost path too, first, so
                            // the agent hears the copy before the original.
                            if let Some(ghost) = &self.ghost {
                                if ghost.copying && t.contents.starts_with(&[0x00, 0x01]) {
                                    let _ = ghost.socket.send_to(&t.contents, t.destination).await;
                                }
                            }
                            // Candidates on TEST-NET addresses are unreachable by design.
                            let _ = self.socket.send_to(&t.contents, t.destination).await;
                        }
                        Output::Event(str0m::Event::ChannelData(cd)) => self
                            .heard
                            .push((Instant::now(), String::from_utf8_lossy(&cd.data).into())),
                        Output::Event(str0m::Event::MediaData(_)) => self.frames += 1,
                        Output::Event(_) => {}
                    }
                };
                let now = Instant::now();
                if now >= until {
                    return;
                }
                let wait = timeout.min(until).saturating_duration_since(now);
                tokio::select! {
                    _ = tokio::time::sleep(wait) => {
                        self.rtc
                            .handle_input(Input::Timeout(Instant::now()))
                            .expect("viewer timeout");
                    }
                    res = self.socket.recv_from(&mut self.buf) => {
                        // Windows reports an ICMP port-unreachable as an error on the next receive.
                        let Ok((n, source)) = res else { continue };
                        if self.drop_in_over.is_some_and(|max| n > max) {
                            continue;
                        }
                        let Ok(contents) = DatagramRecv::try_from(&self.buf[..n]) else {
                            continue;
                        };
                        let recv = Receive {
                            proto: Protocol::Udp,
                            source,
                            destination: self.addr,
                            contents,
                        };
                        let _ = self.rtc.handle_input(Input::Receive(Instant::now(), recv));
                    }
                }
            }
        }
    }

    /// A [`HostSocket`] over a plain loopback socket, recording that it was closed.
    struct LoopbackHostSocket {
        socket: UdpSocket,
        closed: Arc<std::sync::atomic::AtomicBool>,
    }

    impl HostSocket for LoopbackHostSocket {
        fn send_to<'a>(
            &'a self,
            buf: &'a [u8],
            to: SocketAddr,
        ) -> crate::host_peer::HostFuture<'a, std::io::Result<usize>> {
            Box::pin(self.socket.send_to(buf, to))
        }

        fn recv_from<'a>(
            &'a self,
            buf: &'a mut [u8],
        ) -> crate::host_peer::HostFuture<'a, std::io::Result<(usize, SocketAddr)>> {
            Box::pin(self.socket.recv_from(buf))
        }

        fn address(&self) -> SocketAddr {
            self.socket.local_addr().expect("loopback address")
        }

        fn close(&mut self) -> crate::host_peer::HostFuture<'_, ()> {
            self.closed.store(true, Ordering::SeqCst);
            Box::pin(async {})
        }
    }

    /// Hooks that accept the Mini App's two channels and record what reaches them; a message
    /// `bye` disconnects.
    #[derive(Default)]
    struct RecordingHooks {
        seen: Arc<std::sync::Mutex<Vec<String>>>,
    }

    impl RecordingHooks {
        fn note(&self, what: String) {
            self.seen.lock().expect("test log").push(what);
        }
    }

    impl PeerHooks for RecordingHooks {
        fn admit_datagram(&mut self, _: SocketAddr) -> bool {
            true
        }
        fn admit_candidate(&mut self, _: &str, _: SocketAddr) -> Result<(), &'static str> {
            Err("test_candidate_refused")
        }
        fn admit_renegotiation(&mut self) -> Result<(), &'static str> {
            Err("test_renegotiation_refused")
        }
        fn admit_mdns(&mut self) -> bool {
            false
        }
        fn answer(&mut self, answer: String, _: SocketAddr) -> anyhow::Result<String> {
            self.note("answer".into());
            Ok(answer)
        }
        fn link_lost(&mut self) {
            self.note("link_lost".into());
        }
        fn ended(&mut self) {
            self.note("ended".into());
        }
        fn channel_opened(&mut self, channel: OpenedChannel<'_>) -> ChannelRole {
            self.note(format!("open {} {:?}", channel.label, channel.delivery));
            match (channel.label, channel.delivery) {
                (CHANNEL_INPUT, ChannelDelivery::ReliableOrdered) => ChannelRole::Input,
                (afklink_protocol::CHANNEL_CURSOR, ChannelDelivery::UnorderedLatest) => {
                    ChannelRole::Cursor
                }
                _ => ChannelRole::Refuse,
            }
        }
        fn channel_closed(&mut self, role: ChannelRole) {
            self.note(format!("closed {role:?}"));
        }
        fn data(&mut self, role: ChannelRole, data: Vec<u8>, _: bool, _: Instant) -> DataVerdict {
            let text = String::from_utf8_lossy(&data).into_owned();
            self.note(format!("data {role:?} {text}"));
            if text == "bye" {
                DataVerdict::Disconnect
            } else {
                DataVerdict::Continue
            }
        }
        fn reliable_lane_failed(&mut self) {
            self.note("reliable_lane_failed".into());
        }
        fn cursor_report(&mut self, _: usize, _: usize) -> bool {
            true
        }
        fn cursor_lane_failed(&mut self) {
            self.note("cursor_lane_failed".into());
        }
    }

    #[tokio::test]
    async fn a_host_peer_gives_its_channels_to_the_hooks_and_closes_its_socket() {
        let (mut viewer, offer, pending) = TestViewer::with_channels(false, true).await;
        let socket = UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind host socket");
        let bound_port = socket.local_addr().expect("host address").port();
        let closed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let hooks = RecordingHooks::default();
        let seen = hooks.seen.clone();
        let (mut peer, task) = spawn_host_peer(
            &offer,
            Box::new(LoopbackHostSocket {
                socket,
                closed: closed.clone(),
            }),
            Box::new(hooks),
            HostPeerOptions {
                host_ip: Ipv4Addr::LOCALHOST,
                bound_port,
                ice_grace: Duration::ZERO,
                ice_timing: None,
            },
        )
        .await
        .expect("host peer");
        assert!(
            peer.answer_sdp.contains("typ relay"),
            "the host socket is the one relayed candidate: {}",
            peer.answer_sdp
        );
        viewer.accept(pending, &peer.answer_sdp);
        viewer.pump(Duration::from_millis(800)).await;

        let (queued, receipt) = tokio::sync::oneshot::channel();
        peer.control_tx
            .send(PeerControl::SendReliableReceipt {
                text: "status".into(),
                queued,
            })
            .await
            .expect("control queue");
        peer.control_tx
            .send(PeerControl::SendCursor("cursor report".into()))
            .await
            .expect("control queue");
        viewer.say("hello");
        viewer.say_cursor("moved");
        viewer.pump(Duration::from_millis(200)).await;
        assert!(
            receipt.await.expect("receipt"),
            "the status message was queued"
        );
        assert!(viewer.heard.iter().any(|(_, text)| text == "status"));
        assert!(viewer.heard.iter().any(|(_, text)| text == "cursor report"));
        while let Ok(event) = peer.events.try_recv() {
            assert!(
                !matches!(event, PeerEvent::InputData(_)),
                "a host peer's data is the hooks', not the orchestrator's"
            );
        }

        viewer.say("bye");
        viewer.pump(Duration::from_millis(300)).await;
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .expect("the run loop ends after the hooks disconnect")
            .expect("run loop joined");
        assert!(closed.load(Ordering::SeqCst), "the host socket was closed");
        let seen = seen.lock().expect("test log").clone();
        for expected in [
            "answer",
            "open input ReliableOrdered",
            "open cursor UnorderedLatest",
            "data Input hello",
            "data Cursor moved",
            "data Input bye",
            "ended",
        ] {
            assert!(
                seen.iter().any(|s| s == expected),
                "{expected} missing: {seen:?}"
            );
        }
    }

    /// Loopback host candidates, so ICE between the two ends is deterministic on any machine.
    fn loopback(ice_grace: Duration, fast_checks: bool) -> Tuning {
        Tuning {
            ice_grace,
            host_ips: Some(vec![Ipv4Addr::LOCALHOST]),
            // Four unanswered checks 100..300 ms apart, then 300 ms: a dead path is noticed in
            // about 1.3 s instead of 20.
            ice_timing: fast_checks.then_some(IceTiming {
                initial_rto: Duration::from_millis(100),
                max_rto: Duration::from_millis(300),
                retransmits: 4,
            }),
            shaper: None,
            follow_viewer: true,
            relay_only_answer_budget: crate::stun::RELAY_ONLY_ANSWER_BUDGET,
            // No multicast from a test: a name nobody gave it fails at once.
            mdns: mdns_table(&[], Duration::ZERO).0,
            hooks: None,
        }
    }

    /// A resolver that knows `names`, each lookup answered after `delay`, and how many lookups it
    /// was asked for.
    fn mdns_table(names: &[(&str, Ipv4Addr)], delay: Duration) -> (MdnsResolver, Arc<AtomicU32>) {
        let asked = Arc::new(AtomicU32::new(0));
        let resolver = MdnsResolver::Table {
            names: names.iter().map(|(n, a)| (n.to_string(), *a)).collect(),
            delay,
            asked: asked.clone(),
        };
        (resolver, asked)
    }

    fn ice_ufrag(sdp: &str) -> String {
        sdp.lines()
            .find_map(|l| l.trim_end().strip_prefix("a=ice-ufrag:"))
            .map(str::to_string)
            .expect("an a=ice-ufrag line")
    }

    fn answer_in(events: &[PeerEvent]) -> String {
        events
            .iter()
            .find_map(|e| match e {
                PeerEvent::Answer(sdp) => Some(sdp.clone()),
                _ => None,
            })
            .expect("an answer")
    }

    fn ended(events: &[PeerEvent]) -> bool {
        events
            .iter()
            .any(|e| matches!(e, PeerEvent::Disconnected { .. }))
    }

    /// Serve the viewer until the agent sends an event `stop` accepts. Every event seen, in order,
    /// the accepted one last. A peer that ends first is a failure unless `stop` accepts that.
    async fn pump_until(
        viewer: &mut TestViewer,
        events: &mut mpsc::Receiver<PeerEvent>,
        limit: Duration,
        stop: impl Fn(&PeerEvent) -> bool,
    ) -> Vec<PeerEvent> {
        let until = Instant::now() + limit;
        let mut seen = Vec::new();
        while Instant::now() < until {
            viewer.pump(Duration::from_millis(20)).await;
            while let Ok(e) = events.try_recv() {
                let done = stop(&e);
                let end = matches!(e, PeerEvent::Disconnected { .. });
                seen.push(e);
                if done {
                    return seen;
                }
                assert!(!end, "the peer ended: {seen:?}");
            }
        }
        panic!("nothing matching within {limit:?}; saw {seen:?}");
    }

    /// Serve the viewer for `dur`, collecting whatever the agent says meanwhile.
    async fn pump_for(
        viewer: &mut TestViewer,
        events: &mut mpsc::Receiver<PeerEvent>,
        dur: Duration,
    ) -> Vec<PeerEvent> {
        let until = Instant::now() + dur;
        let mut seen = Vec::new();
        while Instant::now() < until {
            viewer.pump(Duration::from_millis(20)).await;
            while let Ok(e) = events.try_recv() {
                seen.push(e);
            }
        }
        seen
    }

    /// Wait for an event with the viewer silent: it neither answers nor sends.
    async fn silent_until(
        events: &mut mpsc::Receiver<PeerEvent>,
        limit: Duration,
        stop: impl Fn(&PeerEvent) -> bool,
    ) -> Vec<PeerEvent> {
        let mut seen = Vec::new();
        let found = tokio::time::timeout(limit, async {
            while let Some(e) = events.recv().await {
                let done = stop(&e);
                seen.push(e);
                if done {
                    return true;
                }
            }
            false
        })
        .await;
        assert!(
            matches!(found, Ok(true)),
            "nothing matching within {limit:?}; saw {seen:?}"
        );
        seen
    }

    /// A viewer connected to a live peer, both ends up.
    async fn connected(
        lite: bool,
        stun: Vec<String>,
        tuning: Tuning,
    ) -> (TestViewer, super::Peer, String) {
        let (mut viewer, offer, pending) = TestViewer::new(lite).await;
        let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind agent");
        let mut peer = spawn_peer_on(socket, &offer, stun, tuning)
            .await
            .expect("a peer");
        viewer.accept(pending, &peer.answer_sdp);
        pump_until(&mut viewer, &mut peer.events, S(10), |e| {
            matches!(e, PeerEvent::Connected)
        })
        .await;
        viewer.pump(Duration::from_millis(200)).await;
        assert!(viewer.rtc.is_connected(), "the viewer's side is up too");
        (viewer, peer, offer)
    }

    /// Hand the peer one of the viewer's signals as the orchestrator does — never waiting — and
    /// insist it was queued.
    fn signal(peer: &super::Peer, signal: PeerSignal) {
        let kind = signal.kind();
        let sent = peer.signals.send(signal);
        assert!(
            matches!(sent, crate::peer_signal::SignalSent::Queued { .. }),
            "the peer's signal queue refused a {kind}: {sent:?}"
        );
    }

    #[tokio::test]
    async fn an_ice_restart_reconnects_the_live_peer_and_rediscovers_srflx() {
        // The mapping changes between the session's discovery and the restart's: the NAT moved,
        // or its binding expired while nothing refreshed it.
        let first: SocketAddr = "203.0.113.7:40000".parse().expect("addr");
        let moved: SocketAddr = "203.0.113.9:40002".parse().expect("addr");
        let (stun, asked) = crate::stun::test_server::spawn_mappings(0, vec![first, moved]).await;
        let asked = move || asked.load(std::sync::atomic::Ordering::SeqCst);
        let (mut viewer, mut peer, offer) =
            connected(false, vec![stun.to_string()], loopback(ICE_GRACE, false)).await;
        assert!(peer.answer_sdp.contains("203.0.113.7 40000 typ srflx"));
        assert_eq!(asked(), 1);
        let first_ufrag = ice_ufrag(&peer.answer_sdp);

        // 1. The same offer again — what the Mini App sends when its signaling socket lost the
        // answer. Answered, and nothing else happens: same credentials, no restart, no discovery.
        signal(&peer, PeerSignal::Renegotiate(offer));
        let seen = pump_until(&mut viewer, &mut peer.events, S(5), |e| {
            matches!(e, PeerEvent::Answer(_))
        })
        .await;
        assert_eq!(ice_ufrag(&answer_in(&seen)), first_ufrag, "not a restart");
        let seen = pump_for(&mut viewer, &mut peer.events, Duration::from_millis(400)).await;
        assert!(
            !seen.iter().any(|e| matches!(
                e,
                PeerEvent::Answer(_)
                    | PeerEvent::LocalCandidate(_)
                    | PeerEvent::KeyframeRequest(_)
                    | PeerEvent::LinkLost
                    | PeerEvent::Disconnected { .. }
            )),
            "nothing follows a plain re-answer: {seen:?}"
        );
        assert!(
            viewer.rtc.is_connected(),
            "and the path it did not touch is still up"
        );
        assert_eq!(asked(), 1, "no rediscovery without a restart");

        // 2. A restart. The answer is held back from the viewer until the rediscovery has landed,
        // so the restored path cannot stop it first — which on a real network it usually would not
        // have the chance to, a STUN round trip being shorter than the answer's trip to the phone.
        let (restart, pending) = viewer.restart_offer();
        signal(&peer, PeerSignal::Renegotiate(restart));
        let seen = pump_until(&mut viewer, &mut peer.events, S(5), |e| {
            matches!(e, PeerEvent::LocalCandidate(_))
        })
        .await;
        let answer = answer_in(&seen);
        let answer_at = seen
            .iter()
            .position(|e| matches!(e, PeerEvent::Answer(_)))
            .expect("an answer");
        assert!(
            answer_at < seen.len() - 1,
            "the answer goes out before the candidate carrying its new ufrag: {seen:?}"
        );
        let new_ufrag = ice_ufrag(&answer);
        assert_ne!(new_ufrag, first_ufrag, "the agent restarted ICE");
        assert!(
            answer.contains("203.0.113.7 40000 typ srflx"),
            "str0m keeps local candidates across the restart, so the answer still offers the \
             first mapping: {answer}"
        );
        let Some(PeerEvent::LocalCandidate(trickled)) = seen.last() else {
            panic!("{seen:?}");
        };
        assert!(
            trickled.candidate.contains(" 203.0.113.9 40002 typ srflx"),
            "{}",
            trickled.candidate
        );
        assert_eq!(
            trickled.username_fragment.as_deref(),
            Some(new_ufrag.as_str()),
            "stamped with the restart's credentials"
        );
        assert_eq!(trickled.sdp_mid, first_mid(&answer));
        assert_eq!(asked(), 2, "one fresh transaction, answered at once");
        assert!(
            !seen
                .iter()
                .any(|e| matches!(e, PeerEvent::KeyframeRequest(_))),
            "no path yet, so no keyframe yet: {seen:?}"
        );

        viewer.accept(pending, &answer);
        let seen = pump_until(&mut viewer, &mut peer.events, S(10), |e| {
            matches!(e, PeerEvent::KeyframeRequest(_))
        })
        .await;
        assert!(!ended(&seen), "{seen:?}");
        viewer.pump(Duration::from_millis(200)).await;
        assert!(
            viewer.rtc.is_connected(),
            "the viewer is back on the new path"
        );

        // 3. Another restart, and this time the NAT has kept the mapping: nothing to trickle.
        let (restart, pending) = viewer.restart_offer();
        signal(&peer, PeerSignal::Renegotiate(restart));
        let seen = pump_until(&mut viewer, &mut peer.events, S(5), |e| {
            matches!(e, PeerEvent::Answer(_))
        })
        .await;
        let answer = answer_in(&seen);
        let mut seen = seen;
        let asked_by = Instant::now() + S(3);
        while asked() < 3 && Instant::now() < asked_by {
            seen.extend(pump_for(&mut viewer, &mut peer.events, Duration::from_millis(20)).await);
        }
        assert_eq!(asked(), 3, "the restart asked again");
        seen.extend(pump_for(&mut viewer, &mut peer.events, Duration::from_millis(400)).await);
        assert!(
            !seen
                .iter()
                .any(|e| matches!(e, PeerEvent::LocalCandidate(_))),
            "an unchanged mapping is already offered, so nothing is trickled: {seen:?}"
        );
        viewer.accept(pending, &answer);
        let seen = pump_until(&mut viewer, &mut peer.events, S(10), |e| {
            matches!(e, PeerEvent::KeyframeRequest(_))
        })
        .await;
        assert!(!ended(&seen), "{seen:?}");

        peer.closer.close();
    }

    /// `offer` with the viewer's host candidate signalled as a relay it reaches over TCP (priority
    /// 16785663, as the iPhone offered): what a viewer with `iceTransportPolicy: "relay"` offers.
    fn as_relay_only(offer: &str, viewer: SocketAddr) -> String {
        let host = offer
            .lines()
            .find(|l| l.starts_with("a=candidate:"))
            .expect("the viewer's host candidate")
            .trim_end()
            .to_string();
        let relay = format!(
            "a=candidate:3 1 udp 16785663 {} {} typ relay raddr 0.0.0.0 rport 0",
            viewer.ip(),
            viewer.port()
        );
        offer.replace(&host, &relay)
    }

    /// `sdp` without its candidates: what the Mini App sends, trickling them afterwards.
    fn without_candidates(sdp: &str) -> String {
        sdp.split_inclusive("\r\n")
            .filter(|l| !l.starts_with("a=candidate:"))
            .collect()
    }

    /// A candidate of the viewer's, trickled: `typ` is `host` or `relay`, `ufrag` the generation's.
    fn viewer_ice(addr: SocketAddr, typ: &str, ufrag: &str) -> afklink_protocol::IceCandidate {
        let candidate = if typ == "relay" {
            format!(
                "candidate:3 1 udp 16785663 {} {} typ relay raddr 0.0.0.0 rport 0",
                addr.ip(),
                addr.port()
            )
        } else {
            format!(
                "candidate:1 1 udp 2122260223 {} {} typ {typ}",
                addr.ip(),
                addr.port()
            )
        };
        afklink_protocol::IceCandidate {
            candidate,
            sdp_mid: Some("0".into()),
            sdp_mline_index: Some(0),
            username_fragment: Some(ufrag.to_string()),
        }
    }

    #[tokio::test]
    async fn a_relay_only_offer_waits_longer_and_its_answer_carries_the_srflx() {
        // An offer that shows a relay-only viewer: an answer with private host candidates only is
        // useless to it, so the answer waits past the ordinary 1.5 s. The path to the STUN server
        // loses the first three requests, as in
        // `a_srflx_that_misses_the_answer_is_trickled_when_it_arrives`; here the fourth's reply, at
        // 1750 ms, is in the answer.
        let mapped: SocketAddr = "203.0.113.7:40000".parse().expect("addr");
        let (server, seen) = crate::stun::test_server::spawn(3, mapped).await;
        let (viewer, offer, _pending) = TestViewer::new(false).await;
        let offer = as_relay_only(&offer, viewer.addr);
        let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
        let t0 = Instant::now();
        let peer = spawn_peer_on(
            socket,
            &offer,
            vec![server.to_string()],
            loopback(ICE_GRACE, false),
        )
        .await
        .expect("a peer");
        let answered = t0.elapsed();
        assert!(
            answered >= Duration::from_millis(1_740)
                && answered < crate::stun::RELAY_ONLY_ANSWER_BUDGET,
            "the answer waited {answered:?}"
        );
        assert!(
            peer.answer_sdp.contains("203.0.113.7 40000 typ srflx"),
            "{}",
            peer.answer_sdp
        );
        assert_eq!(seen.load(std::sync::atomic::Ordering::SeqCst), 4);
        peer.closer.close();
    }

    #[tokio::test]
    async fn an_ice_restart_continues_the_running_discovery_and_holds_a_relay_only_answer() {
        // STUN replies take 2.4 s (a VPN starved of CPU), so the first answer — 1.5 s: the offer
        // has no candidates, the Mini App trickles them — goes out with host candidates only. The
        // viewer trickles relays only, fails, and restarts ICE. The restart keeps the discovery
        // running: the reply to the session's very first
        // request, the only one this server ever answers, becomes the srflx candidate. The
        // restart's answer waits for it, and the candidate follows right behind the answer.
        let log = CapturedLog::default();
        let _log = log.install();
        let mapped: SocketAddr = "203.0.113.7:40000".parse().expect("addr");
        let (server, asked) =
            crate::stun::test_server::spawn_slow(1, Duration::from_millis(2_400), mapped).await;
        let (mut viewer, offer, pending) = TestViewer::new(false).await;
        let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
        let t0 = Instant::now();
        let mut peer = spawn_peer_on(
            socket,
            &without_candidates(&offer),
            vec![server.to_string()],
            loopback(ICE_GRACE, false),
        )
        .await
        .expect("a peer");
        let answered = t0.elapsed();
        assert!(
            answered >= crate::stun::ANSWER_BUDGET && answered < Duration::from_millis(2_100),
            "a viewer not known to be relay-only waits the ordinary budget: {answered:?}"
        );
        assert!(!peer.answer_sdp.contains("typ srflx"));
        let first_ufrag = ice_ufrag(&peer.answer_sdp);
        viewer.accept(pending, &peer.answer_sdp);

        // The viewer's trickle: relays only. Then its restart, trickling again.
        signal(
            &peer,
            PeerSignal::AddRemoteIce(viewer_ice(viewer.addr, "relay", &ice_ufrag(&offer))),
        );
        let (restart, _pending) = viewer.restart_offer();
        signal(&peer, PeerSignal::Renegotiate(without_candidates(&restart)));

        let seen = silent_until(&mut peer.events, S(5), |e| {
            matches!(e, PeerEvent::Answer(_))
        })
        .await;
        let held_until = t0.elapsed();
        assert!(
            held_until >= Duration::from_millis(2_350),
            "the restart's answer waited for the mapping: {held_until:?}"
        );
        assert!(
            held_until < answered + crate::stun::RELAY_ONLY_ANSWER_BUDGET,
            "and was released by it, not by the budget: {held_until:?}"
        );
        let answer = answer_in(&seen);
        let new_ufrag = ice_ufrag(&answer);
        assert_ne!(new_ufrag, first_ufrag, "the agent restarted ICE");
        assert!(
            !seen
                .iter()
                .any(|e| matches!(e, PeerEvent::LocalCandidate(_))),
            "{seen:?}"
        );

        let seen = silent_until(&mut peer.events, S(1), |e| {
            matches!(e, PeerEvent::LocalCandidate(_))
        })
        .await;
        let Some(PeerEvent::LocalCandidate(trickled)) = seen.last() else {
            panic!("{seen:?}");
        };
        assert!(
            trickled.candidate.contains(" 203.0.113.7 40000 typ srflx"),
            "{}",
            trickled.candidate
        );
        assert_eq!(
            trickled.username_fragment.as_deref(),
            Some(new_ufrag.as_str()),
            "stamped for the restart's generation"
        );
        assert_eq!(trickled.sdp_mid, first_mid(&answer));
        assert!(asked.load(std::sync::atomic::Ordering::SeqCst) >= 4);

        let text = log.text();
        for line in [
            "continued into the restart's ICE generation",
            // The restart asked the server again at once, in a round of its own…
            "attempt=1 of=7 round=2",
            "restart answer held",
            // …and the reply that came was to the first round's request.
            "reply_round=1 rounds=2",
            "why=\"mapping_arrived\"",
        ] {
            assert!(text.contains(line), "{line:?} missing from:\n{text}");
        }
        assert!(
            !text.contains("replaced by a fresh one"),
            "the discovery was not thrown away"
        );
        peer.closer.close();
    }

    #[tokio::test]
    async fn a_restart_answer_waits_only_for_a_relay_only_viewer_and_only_the_budget() {
        // STUN is dead. A viewer that trickled a host candidate gets its restart answer at once;
        // after its next restart it trickles only relays (what the Mini App's fallback to TURN over
        // TCP/TLS does), and that restart's answer waits for the discovery until the budget runs
        // out — 600 ms here — and then goes out without it, the discovery going on.
        let log = CapturedLog::default();
        let _log = log.install();
        let mapped: SocketAddr = "203.0.113.7:40000".parse().expect("addr");
        let (server, _asked) = crate::stun::test_server::spawn(u32::MAX, mapped).await;
        let budget = Duration::from_millis(600);
        let tuning = Tuning {
            relay_only_answer_budget: budget,
            ..loopback(ICE_GRACE, false)
        };
        let (mut viewer, offer, pending) = TestViewer::new(false).await;
        let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
        let mut peer = spawn_peer_on(
            socket,
            &without_candidates(&offer),
            vec![server.to_string()],
            tuning,
        )
        .await
        .expect("a peer");
        assert!(!peer.answer_sdp.contains("typ srflx"));
        viewer.accept(pending, &peer.answer_sdp);

        // 1. A host candidate: not relay-only, so the restart's answer goes out at once.
        signal(
            &peer,
            PeerSignal::AddRemoteIce(viewer_ice(viewer.addr, "host", &ice_ufrag(&offer))),
        );
        let (restart, pending) = viewer.restart_offer();
        let restart_ufrag = ice_ufrag(&restart);
        let sent = Instant::now();
        signal(&peer, PeerSignal::Renegotiate(without_candidates(&restart)));
        let seen = silent_until(&mut peer.events, S(2), |e| {
            matches!(e, PeerEvent::Answer(_))
        })
        .await;
        assert!(
            sent.elapsed() < Duration::from_millis(300),
            "{:?}",
            sent.elapsed()
        );
        viewer.accept(pending, &answer_in(&seen));

        // 2. Relays only in that generation: the next restart's answer waits out the budget.
        signal(
            &peer,
            PeerSignal::AddRemoteIce(viewer_ice(viewer.addr, "relay", &restart_ufrag)),
        );
        let (restart, _pending) = viewer.restart_offer();
        let sent = Instant::now();
        signal(&peer, PeerSignal::Renegotiate(without_candidates(&restart)));
        let seen = silent_until(&mut peer.events, S(3), |e| {
            matches!(e, PeerEvent::Answer(_))
        })
        .await;
        let held = sent.elapsed();
        assert!(
            held >= budget - Duration::from_millis(10)
                && held < budget + Duration::from_millis(400),
            "{held:?}"
        );
        assert!(
            !seen.iter().any(|e| matches!(
                e,
                PeerEvent::LocalCandidate(_) | PeerEvent::Disconnected { .. }
            )),
            "{seen:?}"
        );

        let text = log.text();
        for line in [
            "need=\"viewer_not_relay_only\"",
            "restart answer held",
            "why=\"budget\"",
            "restarts=2",
        ] {
            assert!(text.contains(line), "{line:?} missing from:\n{text}");
        }
        assert!(
            !text.contains("gave up on a srflx candidate"),
            "the discovery goes on after the hold"
        );
        peer.closer.close();
    }

    /* ── An offer re-sent before its answer was applied ─────────────────────── */

    // The answer to the viewer's offer can fail to reach it: its signaling socket dies right after
    // it sends the offer. The Mini App then resumes rather than replacing the session: once its
    // socket is back it sends the very offer it sent before (its
    // `pendingLocalDescription`, by then perhaps with `a=candidate` lines for what it has trickled)
    // and applies the answer that comes — never having applied the first. The agent takes a second
    // offer for a live session as a re-offer (`start_session` hands it to the peer as
    // `PeerSignal::Renegotiate`). `an_ice_restart_reconnects_the_live_peer_and_rediscovers_srflx`
    // covers that on a connected peer; these cover it before anything connected.
    //
    // Why the answer to the same offer can stand in for the lost one, in str0m 0.23.1:
    //   * `accept_offer` on a live `Rtc` restarts ICE only when the offer's credentials differ from
    //     the remote ones it has (`src/change/sdp.rs:730-752`), and `set_remote_credentials` leaves
    //     equal ones alone (`is-0.11.0/src/agent.rs:527-532`). DTLS and SCTP are set up once
    //     (`lib.rs:1482-1485,1510-1512`), the ICE role is only chosen on the first offer
    //     (`sdp.rs:95-99`), and the video stream already made is kept (`sdp.rs:1017-1022`).
    //   * The answer is written from the agent's state now: with no pending change of its own, its
    //     current local credentials and every local candidate not discarded (`sdp.rs:129-130,
    //     1608-1631`, `is-0.11.0/src/agent.rs:497-502`) — the host and srflx the first answer had,
    //     and any candidate added since.
    //   * The offer's candidates go to `add_remote_candidate` again (`sdp.rs:756-758`), which
    //     ignores one equivalent to a remote still in a pair (`is-0.11.0/src/agent.rs:754-766`);
    //     once the agent's checks gave up and their pairs were pruned (`agent.rs:1227-1240`), str0m
    //     lists it a second time — the first entry has no pair left — and pairs it afresh, which
    //     takes ICE from `Disconnected` back to `Checking`. The agent's own book replaces by
    //     address (`remember_candidate`), so it holds the candidate once either way.
    //   * A candidate line str0m cannot read — an mDNS host — is kept as an unused attribute, not
    //     an error (`sdp/parser.rs:758,781-791`). `sdp_candidates` picks it out and the agent looks
    //     the name up as it does a trickled one (`resolve_mdns`): its trickle may be what the dead
    //     socket lost.
    // str0m playing the viewer queues the agent's checks until it has an answer
    // (`is-0.11.0/src/agent.rs:1397-1426`), so the agent checks in vain meanwhile and, with fast
    // checks, gives up, which opens the grace window. (A browser may answer them before it has an
    // answer; that only keeps the agent's pairs alive, the first case below.)

    /// Where the agent's own checks are when the re-sent offer comes.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum AgentChecks {
        /// Still running: the viewer is back within seconds.
        Running,
        /// Given up, every pair pruned: ICE `Disconnected`, `LinkLost`, the grace window open.
        GaveUp,
    }

    /// The value of `sdp`'s first line that starts with `key`.
    fn sdp_line<'a>(sdp: &'a str, key: &str) -> &'a str {
        sdp.lines()
            .find_map(|l| l.trim_end().strip_prefix(key))
            .unwrap_or_else(|| panic!("no {key} line in:\n{sdp}"))
    }

    /// The `a=candidate:` lines of `sdp`, in order.
    fn candidate_lines(sdp: &str) -> Vec<&str> {
        sdp.lines()
            .map(str::trim_end)
            .filter(|l| l.starts_with("a=candidate:"))
            .collect()
    }

    /// `second` speaks for the ICE agent and the DTLS endpoint `first` did: the credentials the
    /// agent checks and answers checks with, the certificate the viewer's DTLS will verify, and the
    /// DTLS role.
    fn assert_same_identity(first: &str, second: &str) {
        for key in ["a=ice-ufrag:", "a=ice-pwd:", "a=fingerprint:", "a=setup:"] {
            assert_eq!(
                sdp_line(first, key),
                sdp_line(second, key),
                "{key} differs\nfirst:\n{first}\nsecond:\n{second}"
            );
        }
    }

    /// The viewer's own candidate in `offer`, trickled as the Mini App sends it.
    fn trickled(offer: &str) -> afklink_protocol::IceCandidate {
        let candidate = candidate_lines(offer)
            .first()
            .and_then(|l| l.strip_prefix("a="))
            .expect("the viewer's host candidate")
            .to_string();
        afklink_protocol::IceCandidate {
            candidate,
            sdp_mid: first_mid(offer),
            sdp_mline_index: Some(0),
            username_fragment: Some(ice_ufrag(offer)),
        }
    }

    /// What the orchestrator acts on for the signaling or the session — an answer, a candidate to
    /// trickle, a lost path, the end — as opposed to the estimates and stats str0m reports anyway
    /// (its opening `BitrateEstimate` comes before anything connects).
    fn of_note(e: &PeerEvent) -> bool {
        matches!(
            e,
            PeerEvent::Answer(_)
                | PeerEvent::LocalCandidate(_)
                | PeerEvent::LinkLost
                | PeerEvent::Disconnected { .. }
        )
    }

    /// The events of `seen` that are [`of_note`].
    fn noted(seen: &[PeerEvent]) -> Vec<&PeerEvent> {
        seen.iter().filter(|e| of_note(e)).collect()
    }

    /// Data both ways and media between a connected viewer and the peer: a message on the viewer's
    /// `input` channel reaches the agent, and one from the agent's reliable queue and a keyframe
    /// reach the viewer. Every event the peer sent meanwhile; none of them its end.
    async fn flows_both_ways(viewer: &mut TestViewer, peer: &mut super::Peer) -> Vec<PeerEvent> {
        let mut seen = Vec::new();
        let open_by = Instant::now() + S(5);
        while viewer.rtc.channel(viewer.input).is_none() {
            assert!(
                Instant::now() < open_by,
                "the viewer's input channel never opened; the peer said {seen:?}"
            );
            seen.extend(pump_for(viewer, &mut peer.events, Duration::from_millis(20)).await);
        }
        let said = r#"{"t":"vis","hidden":false}"#;
        viewer.say(said);
        seen.extend(
            pump_until(
                viewer,
                &mut peer.events,
                S(5),
                |e| matches!(e, PeerEvent::InputData(d) if d.as_slice() == said.as_bytes()),
            )
            .await,
        );
        let told = r#"{"t":"test","n":1}"#;
        peer.control_tx
            .send(PeerControl::SendReliable(vec![told.to_string()]))
            .await
            .expect("control");
        let data = vec![0, 0, 0, 1, 0x65, 0x88, 0x84];
        peer.queued_media_bytes
            .fetch_add(u32::try_from(data.len()).expect("small"), Ordering::Relaxed);
        peer.media_tx
            .send(MediaSample {
                data,
                is_keyframe: true,
                timestamp_ms: 0,
                qp: None,
            })
            .await
            .expect("media");
        let by = Instant::now() + S(5);
        while viewer.frames == 0 || !viewer.heard.iter().any(|(_, text)| text == told) {
            assert!(
                Instant::now() < by,
                "frames {}, heard {:?}; the peer said {seen:?}",
                viewer.frames,
                viewer.heard
            );
            seen.extend(pump_for(viewer, &mut peer.events, Duration::from_millis(20)).await);
        }
        assert!(!ended(&seen), "{seen:?}");
        seen
    }

    /// The viewer's answer is lost; it sends the same offer again once the agent's checks are
    /// `checks` — with its candidates in it when `with_candidates`, and an mDNS host the agent cannot
    /// read — and applies the answer to that. See the comment above [`AgentChecks`].
    async fn resend_before_the_answer(checks: AgentChecks, with_candidates: bool) {
        let log = CapturedLog::default();
        let _log = log.install();
        let mapped: SocketAddr = "203.0.113.7:40000".parse().expect("addr");
        let (stun, asked) = crate::stun::test_server::spawn(0, mapped).await;
        let asked = move || asked.load(Ordering::SeqCst);
        let gave_up = checks == AgentChecks::GaveUp;
        // Where the checks are to give up, they are fast (about a second), and the grace window
        // short enough to outlive below.
        let grace = if gave_up { S(3) } else { ICE_GRACE };
        let (mut viewer, offer, pending) = TestViewer::new(false).await;
        // The Mini App's offer: no candidates, trickled after it.
        let first_offer = without_candidates(&offer);
        let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind agent");
        let mut peer = spawn_peer_on(
            socket,
            &first_offer,
            vec![stun.to_string()],
            loopback(grace, gave_up),
        )
        .await
        .expect("a peer");
        let first = peer.answer_sdp.clone();
        assert!(first.contains(" typ host"), "{first}");
        assert!(first.contains("203.0.113.7 40000 typ srflx"), "{first}");
        signal(&peer, PeerSignal::AddRemoteIce(trickled(&offer)));

        // The answer is lost on its way. The viewer serves its network, with nothing to apply.
        let seen = match checks {
            AgentChecks::Running => {
                pump_for(&mut viewer, &mut peer.events, Duration::from_millis(500)).await
            }
            AgentChecks::GaveUp => {
                pump_until(&mut viewer, &mut peer.events, S(5), |e| {
                    matches!(e, PeerEvent::LinkLost)
                })
                .await
            }
        };
        let noted_before = noted(&seen);
        assert!(
            match checks {
                AgentChecks::Running => noted_before.is_empty(),
                AgentChecks::GaveUp => matches!(noted_before[..], [PeerEvent::LinkLost]),
            },
            "nothing, or the path lost where the checks gave up: {seen:?}"
        );
        let lost_at = Instant::now();

        // Its socket is back: the same offer again.
        let resent = if with_candidates {
            // What `pendingLocalDescription` holds by now: the candidate it trickled, and an mDNS
            // host of the kind WebKit gathers.
            let host = candidate_lines(&offer)
                .first()
                .expect("the viewer's host candidate")
                .to_string();
            let mdns = "a=candidate:2 1 udp 2122194687 \
                        5f3c1d2e-8a4b-4c6d-9e0f-1a2b3c4d5e6f.local 54400 typ host generation 0";
            offer.replace(&host, &format!("{host}\r\n{mdns}"))
        } else {
            first_offer.clone()
        };
        assert_eq!(
            ice_ufrag(&resent),
            ice_ufrag(&first_offer),
            "the same offer"
        );
        signal(&peer, PeerSignal::Renegotiate(resent.clone()));
        let seen = pump_until(&mut viewer, &mut peer.events, S(3), |e| {
            matches!(e, PeerEvent::Answer(_))
        })
        .await;
        assert_eq!(
            noted(&seen).len(),
            1,
            "the answer, and nothing before it: {seen:?}"
        );
        let second = answer_in(&seen);
        assert_same_identity(&first, &second);
        assert_eq!(
            candidate_lines(&second),
            candidate_lines(&first),
            "the same local candidates, the srflx among them"
        );
        assert_eq!(asked(), 1, "not a restart, so no discovery");

        // The viewer applies it — the first answer it has — and both ends come up.
        viewer.accept(pending, &second);
        let seen = pump_until(&mut viewer, &mut peer.events, S(10), |e| {
            matches!(e, PeerEvent::Connected)
        })
        .await;
        assert!(noted(&seen).is_empty(), "{seen:?}");
        viewer.pump(Duration::from_millis(200)).await;
        assert!(viewer.rtc.is_connected(), "the viewer's side is up too");
        let seen = flows_both_ways(&mut viewer, &mut peer).await;
        assert!(noted(&seen).is_empty(), "{seen:?}");
        // The grace window the given-up checks opened was closed by the connection: outlived here.
        let quiet = if gave_up {
            (lost_at + grace + Duration::from_millis(500)).saturating_duration_since(Instant::now())
        } else {
            Duration::from_millis(500)
        };
        let seen = pump_for(&mut viewer, &mut peer.events, quiet).await;
        assert!(noted(&seen).is_empty(), "{seen:?}");
        assert!(viewer.rtc.is_connected(), "and stays up");

        let text = log.text();
        let reoffer = line_with(
            &text,
            "re-offer with unchanged ICE credentials answered without an ICE restart",
        );
        let offered = format!("offered_candidates={}", candidate_lines(&resent).len());
        assert!(
            reoffer.contains(&offered),
            "{offered} missing from: {reoffer}"
        );
        for absent in ["ICE restart applied", "re-offer rejected", "answer held"] {
            assert!(!text.contains(absent), "{absent:?} in:\n{text}");
        }
        // Not held: the viewer is not relay-only, and the srflx is in the answer anyway.
        assert!(
            line_with(&text, "re-sent offer answer goes out at once")
                .contains("need=\"srflx_offered\""),
            "{text}"
        );
        if with_candidates {
            // The trickled candidate, in the offer too: counted once in the viewer's mix.
            assert_fields(
                line_with(
                    &text,
                    "the re-offer's candidates in this ICE generation's mix",
                ),
                &["parsed=1".into(), "again=1".into(), "viewer_other=1".into()],
            );
            // The mDNS host goes to the lookup, which (this test's resolver knowing no name)
            // fails: nothing is dropped unsaid.
            assert_fields(
                line_with(&text, "the viewer's SDP carries candidates"),
                &[
                    "source=\"re-offer\"".into(),
                    "parsed=1".into(),
                    "mdns=1".into(),
                    "rejected=0".into(),
                ],
            );
            assert!(
                line_with(&text, "resolving mdns candidate").contains("source=\"re-offer\""),
                "{text}"
            );
            assert!(text.contains("mdns lookup failed"), "{text}");
        } else {
            assert!(!text.contains("resolving mdns candidate"), "{text}");
        }
        // The agent's book: the viewer's one candidate, once, however often it was signalled.
        let up = line_with(&text, "ICE connected for the first time");
        assert!(up.contains("remote_candidates=1"), "{up}");
        peer.closer.close();
    }

    #[tokio::test]
    async fn an_offer_re_sent_while_the_agent_still_checks_is_answered_alike_and_connects() {
        resend_before_the_answer(AgentChecks::Running, false).await;
    }

    #[tokio::test]
    async fn an_offer_re_sent_after_the_agents_checks_gave_up_is_answered_alike_and_connects() {
        resend_before_the_answer(AgentChecks::GaveUp, false).await;
    }

    #[tokio::test]
    async fn a_re_sent_offer_carrying_the_trickled_candidate_adds_it_once_and_connects() {
        resend_before_the_answer(AgentChecks::Running, true).await;
    }

    #[tokio::test]
    async fn a_re_sent_offer_carrying_the_trickled_candidate_after_the_checks_gave_up_connects() {
        resend_before_the_answer(AgentChecks::GaveUp, true).await;
    }

    /// The same resume for a viewer that offers only relays, whose first answer is held for the
    /// srflx discovery. The re-sent offer cannot reach the peer during that hold: `spawn_peer_on`
    /// hands out the peer's signal queue only with the answer, and the agent reads the server's
    /// next message only once `start_session` has it (`handle_server_msg` awaits
    /// `spawn_peer_with`). So it comes as the held answer goes out — here with the hold's budget
    /// spent and the discovery still running, the closest the two can be.
    ///
    /// Every answer to that one offer agrees — same credentials, same certificate, the candidates
    /// the agent had when it wrote it: the re-answer goes out at once (the first answer already
    /// waited the whole hold budget for this offer, which it shares — `HoldClock`); the mapping,
    /// when it comes, is trickled once under the same ufrag; and the answer
    /// to the offer sent once more after that — the trickle lost to a dead socket too — carries it.
    #[tokio::test]
    async fn every_answer_to_a_relay_only_viewers_re_sent_offer_agrees_and_the_srflx_comes_once() {
        let log = CapturedLog::default();
        let _log = log.install();
        let mapped: SocketAddr = "203.0.113.7:40000".parse().expect("addr");
        // The server answers the session's first request only, 1.2 s late: past the hold's budget,
        // half a second here.
        let (server, _asked) =
            crate::stun::test_server::spawn_slow(1, Duration::from_millis(1_200), mapped).await;
        let budget = Duration::from_millis(500);
        let tuning = Tuning {
            relay_only_answer_budget: budget,
            ..loopback(ICE_GRACE, false)
        };
        let (mut viewer, offer, pending) = TestViewer::new(false).await;
        let offer = as_relay_only(&offer, viewer.addr);
        let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind agent");
        let t0 = Instant::now();
        let mut peer = spawn_peer_on(socket, &offer, vec![server.to_string()], tuning)
            .await
            .expect("a peer");
        let held = t0.elapsed();
        assert!(
            held >= budget - Duration::from_millis(10)
                && held < budget + Duration::from_millis(400),
            "the first answer was held for the discovery: {held:?}"
        );
        let first = peer.answer_sdp.clone();
        assert!(!first.contains("typ srflx"), "{first}");
        let ufrag = ice_ufrag(&first);

        // 1. The re-sent offer, read as the held answer goes out (and is lost).
        let sent = Instant::now();
        signal(&peer, PeerSignal::Renegotiate(offer.clone()));
        let seen = silent_until(&mut peer.events, S(2), |e| {
            matches!(e, PeerEvent::Answer(_))
        })
        .await;
        assert!(
            sent.elapsed() < Duration::from_millis(300),
            "answered at once: {:?}",
            sent.elapsed()
        );
        assert_eq!(noted(&seen).len(), 1, "{seen:?}");
        let second = answer_in(&seen);
        assert_same_identity(&first, &second);
        assert_eq!(
            candidate_lines(&second),
            candidate_lines(&first),
            "what the agent has: no srflx yet"
        );

        // 2. The mapping arrives: trickled once, for the same ICE generation.
        let seen = silent_until(&mut peer.events, S(3), |e| {
            matches!(e, PeerEvent::LocalCandidate(_))
        })
        .await;
        assert_eq!(
            noted(&seen).len(),
            1,
            "the candidate, and no answer: {seen:?}"
        );
        let Some(PeerEvent::LocalCandidate(late)) = seen.last() else {
            panic!("{seen:?}");
        };
        assert!(
            late.candidate.contains(" 203.0.113.7 40000 typ srflx"),
            "{}",
            late.candidate
        );
        assert_eq!(late.username_fragment.as_deref(), Some(ufrag.as_str()));
        assert_eq!(late.sdp_mid, first_mid(&first));

        // 3. Lost as well. The offer comes once more, and its answer carries the mapping.
        signal(&peer, PeerSignal::Renegotiate(offer.clone()));
        let seen = silent_until(&mut peer.events, S(2), |e| {
            matches!(e, PeerEvent::Answer(_))
        })
        .await;
        assert_eq!(noted(&seen).len(), 1, "{seen:?}");
        let third = answer_in(&seen);
        assert_same_identity(&first, &third);
        let (before, after) = (candidate_lines(&second), candidate_lines(&third));
        assert!(
            before.iter().all(|l| after.contains(l)),
            "every candidate kept: {before:?} -> {after:?}"
        );
        let added: Vec<_> = after.iter().filter(|l| !before.contains(l)).collect();
        assert!(
            !added.is_empty()
                && added
                    .iter()
                    .all(|l| l.contains(" 203.0.113.7 40000 typ srflx")),
            "the srflx is the one new line: {added:?}"
        );

        // 4. The viewer applies that answer and both ends come up; nothing is trickled again.
        viewer.accept(pending, &third);
        let seen = pump_until(&mut viewer, &mut peer.events, S(10), |e| {
            matches!(e, PeerEvent::Connected)
        })
        .await;
        assert!(noted(&seen).is_empty(), "{seen:?}");
        viewer.pump(Duration::from_millis(200)).await;
        assert!(viewer.rtc.is_connected(), "the viewer's side is up too");

        let text = log.text();
        assert_eq!(
            text.matches("re-offer with unchanged ICE credentials answered without an ICE restart")
                .count(),
            2,
            "{text}"
        );
        assert_eq!(
            text.matches("trickling it to the viewer").count(),
            1,
            "{text}"
        );
        for absent in ["ICE restart applied", "answer held", "re-offer rejected"] {
            assert!(!text.contains(absent), "{absent:?} in:\n{text}");
        }
        // The first re-answer is not held although the viewer is relay-only and the discovery
        // runs: the first answer already waited the whole budget for this offer.
        assert_fields(
            line_with(&text, "used up the hold's budget"),
            &[
                "offer=\"re-sent offer\"".into(),
                "clock=\"same_offer\"".into(),
            ],
        );
        peer.closer.close();
    }

    /// `offer` with the viewer's host candidate signalled under the mDNS name `name`, as Chrome and
    /// WebKit gather it, on `port`: what the name stands for only the lookup says.
    fn with_mdns_host(offer: &str, name: &str, port: u16) -> String {
        let host = candidate_lines(offer)
            .first()
            .expect("the viewer's host candidate")
            .to_string();
        let mdns = format!(
            "a=candidate:1 1 udp 2122260223 {name} {port} typ host generation 0 network-id 1"
        );
        offer.replace(&host, &mdns)
    }

    /// The same mDNS host trickled, as the Mini App sends it (Chrome's line: the ufrag before the
    /// network id).
    fn mdns_trickle(name: &str, port: u16, ufrag: &str) -> afklink_protocol::IceCandidate {
        afklink_protocol::IceCandidate {
            candidate: format!(
                "candidate:1 1 udp 2122260223 {name} {port} typ host generation 0 ufrag {ufrag} \
                 network-id 1"
            ),
            sdp_mid: Some("0".into()),
            sdp_mline_index: Some(0),
            username_fragment: Some(ufrag.to_string()),
        }
    }

    const MDNS_NAME: &str = "5f3c1d2e-8a4b-4c6d-9e0f-1a2b3c4d5e6f.local";

    /// An mDNS host only in the offer, never trickled, is looked up and used. The viewer is
    /// ICE-lite, so it sends no check of its own: the agent reaches it only at the address the
    /// lookup gave, or not at all.
    #[tokio::test]
    async fn an_mdns_host_only_in_the_offer_is_looked_up_and_connects() {
        let log = CapturedLog::default();
        let _log = log.install();
        let (mut viewer, offer, pending) = TestViewer::new(true).await;
        let (mdns, asked) = mdns_table(&[(MDNS_NAME, Ipv4Addr::LOCALHOST)], Duration::ZERO);
        let tuning = Tuning {
            mdns,
            ..loopback(ICE_GRACE, false)
        };
        let offer = with_mdns_host(&offer, MDNS_NAME, viewer.addr.port());
        let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind agent");
        let mut peer = spawn_peer_on(socket, &offer, vec![], tuning)
            .await
            .expect("a peer");
        viewer.accept(pending, &peer.answer_sdp);
        let seen = pump_until(&mut viewer, &mut peer.events, S(10), |e| {
            matches!(e, PeerEvent::Connected)
        })
        .await;
        assert!(noted(&seen).is_empty(), "{seen:?}");
        assert_eq!(asked.load(Ordering::SeqCst), 1, "one lookup");

        let text = log.text();
        assert_fields(
            line_with(&text, "the viewer's SDP carries candidates"),
            &[
                "source=\"offer\"".into(),
                "parsed=0".into(),
                "mdns=1".into(),
                "rejected=0".into(),
            ],
        );
        assert!(
            line_with(&text, "resolving mdns candidate").contains("source=\"offer\""),
            "{text}"
        );
        assert!(
            line_with(&text, "resolved mdns candidate").contains("candidates=1"),
            "{text}"
        );
        let remote = format!("addr=127.0.0.1:{}", viewer.addr.port());
        assert!(
            line_with(&text, "remote candidate kind=").contains(&remote),
            "{text}"
        );
        let up = line_with(&text, "ICE connected for the first time");
        assert!(up.contains("remote_candidates=1"), "{up}");
        peer.closer.close();
    }

    /// The resume signals one mDNS host up to three times, none of which reached the agent before
    /// (the first offer had no candidates, its trickle died with the socket): in the re-sent
    /// offer, trickled again right behind it while the lookup runs, and — here — once more after
    /// the connection. One lookup; the candidate goes in once from it and is counted once; the
    /// ICE-lite viewer is reached through it.
    #[tokio::test]
    async fn an_mdns_host_in_a_re_sent_offer_is_looked_up_once_however_often_it_comes() {
        let log = CapturedLog::default();
        let _log = log.install();
        let (mut viewer, offer, pending) = TestViewer::new(true).await;
        let (mdns, asked) = mdns_table(
            &[(MDNS_NAME, Ipv4Addr::LOCALHOST)],
            Duration::from_millis(300),
        );
        let tuning = Tuning {
            mdns,
            ..loopback(ICE_GRACE, false)
        };
        let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind agent");
        let mut peer = spawn_peer_on(socket, &without_candidates(&offer), vec![], tuning)
            .await
            .expect("a peer");
        // The answer is lost; the viewer serves its network with nothing to apply.
        let seen = pump_for(&mut viewer, &mut peer.events, Duration::from_millis(300)).await;
        assert!(noted(&seen).is_empty(), "{seen:?}");

        // Its socket is back: the offer again, with the host it gathered, and its candidates again.
        let (port, ufrag) = (viewer.addr.port(), ice_ufrag(&offer));
        for s in [
            PeerSignal::Renegotiate(with_mdns_host(&offer, MDNS_NAME, port)),
            PeerSignal::AddRemoteIce(mdns_trickle(MDNS_NAME, port, &ufrag)),
        ] {
            signal(&peer, s);
        }
        let seen = pump_until(&mut viewer, &mut peer.events, S(3), |e| {
            matches!(e, PeerEvent::Answer(_))
        })
        .await;
        assert_eq!(noted(&seen).len(), 1, "{seen:?}");
        viewer.accept(pending, &answer_in(&seen));
        let seen = pump_until(&mut viewer, &mut peer.events, S(10), |e| {
            matches!(e, PeerEvent::Connected)
        })
        .await;
        assert!(noted(&seen).is_empty(), "{seen:?}");

        // Once more, connected: the address is known by now.
        signal(
            &peer,
            PeerSignal::AddRemoteIce(mdns_trickle(MDNS_NAME, port, &ufrag)),
        );
        let seen = pump_for(&mut viewer, &mut peer.events, Duration::from_millis(300)).await;
        assert!(noted(&seen).is_empty(), "{seen:?}");
        assert!(viewer.rtc.is_connected(), "and stays up");
        assert_eq!(asked.load(Ordering::SeqCst), 1, "one lookup");

        let text = log.text();
        assert_eq!(
            text.matches("resolving mdns candidate").count(),
            1,
            "{text}"
        );
        assert!(
            line_with(&text, "resolving mdns candidate").contains("source=\"re-offer\""),
            "{text}"
        );
        assert_fields(
            line_with(&text, "mdns name already being resolved"),
            &[
                "source=\"trickle\"".into(),
                "waiting=1".into(),
                "duplicate=true".into(),
            ],
        );
        assert!(
            line_with(&text, "resolved mdns candidate").contains("candidates=1"),
            "{text}"
        );
        assert!(
            line_with(&text, "mdns name already resolved").contains("source=\"trickle\""),
            "{text}"
        );
        assert_eq!(
            text.matches("remote candidate kind=").count(),
            2,
            "fed in by the lookup, and by the last signal: {text}"
        );
        assert_fields(
            line_with(
                &text,
                "remote candidate signalled before in this ICE generation",
            ),
            &["viewer_relays=0".into(), "viewer_other=1".into()],
        );
        let up = line_with(&text, "ICE connected for the first time");
        assert!(up.contains("remote_candidates=1"), "{up}");
        peer.closer.close();
    }

    /// The resume of a relay-only viewer whose first offer said nothing (the Mini App trickles):
    /// the first answer waited the ordinary 1.5 s for a STUN reply that takes 2.4 s, went out
    /// without the srflx — and was lost. The re-sent offer carries the relays the viewer trickled
    /// into the dead socket, the first word that it is relay-only. Its answer is the first the
    /// viewer applies, useless to it without our srflx: held like a restart's until the running
    /// discovery has the mapping, which follows it at once under the same ufrag.
    #[tokio::test]
    async fn a_re_sent_offer_that_first_shows_a_relay_only_viewer_is_held_for_the_srflx() {
        let log = CapturedLog::default();
        let _log = log.install();
        let mapped: SocketAddr = "203.0.113.7:40000".parse().expect("addr");
        let (server, _asked) =
            crate::stun::test_server::spawn_slow(1, Duration::from_millis(2_400), mapped).await;
        let (mut viewer, offer, pending) = TestViewer::new(false).await;
        let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind agent");
        let t0 = Instant::now();
        let mut peer = spawn_peer_on(
            socket,
            &without_candidates(&offer),
            vec![server.to_string()],
            loopback(ICE_GRACE, false),
        )
        .await
        .expect("a peer");
        let answered = t0.elapsed();
        assert!(
            answered >= crate::stun::ANSWER_BUDGET && answered < Duration::from_millis(2_100),
            "nothing said the viewer was relay-only: the ordinary budget, {answered:?}"
        );
        let first = peer.answer_sdp.clone();
        assert!(!first.contains("typ srflx"), "{first}");

        // 1. The re-sent offer, relays only.
        let resent = as_relay_only(&offer, viewer.addr);
        assert_eq!(ice_ufrag(&resent), ice_ufrag(&offer), "the same offer");
        let sent = Instant::now();
        signal(&peer, PeerSignal::Renegotiate(resent));
        let seen = silent_until(&mut peer.events, S(5), |e| {
            matches!(e, PeerEvent::Answer(_))
        })
        .await;
        let held_until = t0.elapsed();
        assert!(
            held_until >= Duration::from_millis(2_350),
            "held for the mapping: {held_until:?}"
        );
        assert!(
            sent.elapsed() < crate::stun::RELAY_ONLY_ANSWER_BUDGET,
            "and released by it, not by the budget: {:?}",
            sent.elapsed()
        );
        assert_eq!(noted(&seen).len(), 1, "{seen:?}");
        let second = answer_in(&seen);
        assert_same_identity(&first, &second);

        // 2. The srflx right behind it, for the same generation.
        let seen = silent_until(&mut peer.events, S(1), |e| {
            matches!(e, PeerEvent::LocalCandidate(_))
        })
        .await;
        assert_eq!(noted(&seen).len(), 1, "{seen:?}");
        let Some(PeerEvent::LocalCandidate(late)) = seen.last() else {
            panic!("{seen:?}");
        };
        assert!(
            late.candidate.contains(" 203.0.113.7 40000 typ srflx"),
            "{}",
            late.candidate
        );
        assert_eq!(
            late.username_fragment.as_deref(),
            Some(ice_ufrag(&first).as_str())
        );

        // 3. The viewer applies that answer, the first it has, and both ends come up.
        viewer.accept(pending, &second);
        let seen = pump_until(&mut viewer, &mut peer.events, S(10), |e| {
            matches!(e, PeerEvent::Connected)
        })
        .await;
        assert!(noted(&seen).is_empty(), "{seen:?}");

        let text = log.text();
        assert_fields(
            line_with(
                &text,
                "re-sent offer answer to be held for the srflx discovery",
            ),
            &[
                "clock=\"new\"".into(),
                "viewer_relays=1".into(),
                "viewer_other=0".into(),
                "discovery_after=\"answer\"".into(),
            ],
        );
        assert!(text.contains("re-sent offer answer held"), "{text}");
        assert_fields(
            line_with(&text, "re-sent offer answer released"),
            &["why=\"mapping_arrived\"".into()],
        );
        assert!(!text.contains("ICE restart applied"), "{text}");
        peer.closer.close();
    }

    /// The same with STUN dead: the re-sent offer's answer waits out the budget and goes out
    /// without the srflx, the discovery going on. Sent yet again, the offer is answered at once:
    /// one budget per offer, however often it comes.
    #[tokio::test]
    async fn a_re_sent_offer_is_held_once_and_only_for_the_budget() {
        let log = CapturedLog::default();
        let _log = log.install();
        let mapped: SocketAddr = "203.0.113.7:40000".parse().expect("addr");
        let (server, _asked) = crate::stun::test_server::spawn(u32::MAX, mapped).await;
        let budget = Duration::from_millis(600);
        let tuning = Tuning {
            relay_only_answer_budget: budget,
            ..loopback(ICE_GRACE, false)
        };
        let (viewer, offer, _pending) = TestViewer::new(false).await;
        let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind agent");
        let mut peer = spawn_peer_on(
            socket,
            &without_candidates(&offer),
            vec![server.to_string()],
            tuning,
        )
        .await
        .expect("a peer");
        let resent = as_relay_only(&offer, viewer.addr);

        // 1. Held, for the budget.
        let sent = Instant::now();
        signal(&peer, PeerSignal::Renegotiate(resent.clone()));
        let seen = silent_until(&mut peer.events, S(3), |e| {
            matches!(e, PeerEvent::Answer(_))
        })
        .await;
        let held = sent.elapsed();
        assert!(
            held >= budget - Duration::from_millis(10)
                && held < budget + Duration::from_millis(400),
            "{held:?}"
        );
        assert_eq!(noted(&seen).len(), 1, "{seen:?}");

        // 2. Lost as well, and sent again: answered at once.
        let sent = Instant::now();
        signal(&peer, PeerSignal::Renegotiate(resent));
        let seen = silent_until(&mut peer.events, S(2), |e| {
            matches!(e, PeerEvent::Answer(_))
        })
        .await;
        assert!(
            sent.elapsed() < Duration::from_millis(300),
            "{:?}",
            sent.elapsed()
        );
        assert_eq!(noted(&seen).len(), 1, "{seen:?}");

        let text = log.text();
        assert_eq!(
            text.matches("re-sent offer answer held").count(),
            1,
            "{text}"
        );
        assert!(
            line_with(&text, "re-sent offer answer released").contains("why=\"budget\""),
            "{text}"
        );
        assert_fields(
            line_with(&text, "used up the hold's budget"),
            &[
                "offer=\"re-sent offer\"".into(),
                "clock=\"same_offer\"".into(),
            ],
        );
        assert!(
            !text.contains("gave up on a srflx candidate"),
            "the discovery goes on after the hold"
        );
        peer.closer.close();
    }

    /// A held answer goes out as soon as the viewer shows it is not relay-only after all: here an
    /// mDNS host in the re-sent offer, next to its relay, resolves while the answer waits — the
    /// viewer is on this PC's network, and the answer works without our srflx.
    #[tokio::test]
    async fn a_held_answer_goes_out_once_an_mdns_host_of_the_offer_resolves() {
        let log = CapturedLog::default();
        let _log = log.install();
        let mapped: SocketAddr = "203.0.113.7:40000".parse().expect("addr");
        let (server, _asked) = crate::stun::test_server::spawn(u32::MAX, mapped).await;
        let (mdns, asked) = mdns_table(
            &[(MDNS_NAME, Ipv4Addr::LOCALHOST)],
            Duration::from_millis(300),
        );
        let tuning = Tuning {
            mdns,
            ..loopback(ICE_GRACE, false)
        };
        let (viewer, offer, _pending) = TestViewer::new(false).await;
        let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind agent");
        let mut peer = spawn_peer_on(
            socket,
            &without_candidates(&offer),
            vec![server.to_string()],
            tuning,
        )
        .await
        .expect("a peer");
        // The relay, and the host it gathered under an mDNS name (on a port of its own, so it is a
        // second address).
        let relay_only = as_relay_only(&offer, viewer.addr);
        let relay = candidate_lines(&relay_only)
            .first()
            .expect("the relay")
            .to_string();
        let mdns = format!(
            "a=candidate:1 1 udp 2122260223 {MDNS_NAME} {} typ host generation 0",
            viewer.addr.port() + 1
        );
        let resent = relay_only.replace(&relay, &format!("{mdns}\r\n{relay}"));
        let sent = Instant::now();
        signal(&peer, PeerSignal::Renegotiate(resent));
        let seen = silent_until(&mut peer.events, S(3), |e| {
            matches!(e, PeerEvent::Answer(_))
        })
        .await;
        let held = sent.elapsed();
        assert!(
            held >= Duration::from_millis(290) && held < Duration::from_millis(1_500),
            "held until the lookup, not for the budget: {held:?}"
        );
        assert_eq!(noted(&seen).len(), 1, "{seen:?}");
        assert_eq!(asked.load(Ordering::SeqCst), 1);

        let text = log.text();
        assert!(text.contains("re-sent offer answer held"), "{text}");
        assert!(
            text.contains(
                "the viewer offered a candidate besides relays while its answer was held"
            ),
            "{text}"
        );
        assert!(
            line_with(&text, "re-sent offer answer released")
                .contains("why=\"viewer_not_relay_only\""),
            "{text}"
        );
        peer.closer.close();
    }

    /// The viewer closing its connection — what `RTCPeerConnection.close()` does on «Отключиться» —
    /// ends the peer as the viewer's own end, not as str0m closing by itself: the journal records
    /// it as an ordinary end, not as «Связь потеряна».
    #[tokio::test]
    async fn the_viewer_closing_its_connection_ends_the_peer_as_its_own_end() {
        let (mut viewer, mut peer, _) = connected(false, vec![], loopback(ICE_GRACE, false)).await;

        viewer.rtc.close().expect("the viewer closes");
        let seen = pump_until(&mut viewer, &mut peer.events, S(5), |e| {
            matches!(e, PeerEvent::Disconnected { .. })
        })
        .await;
        match seen.last() {
            Some(PeerEvent::Disconnected { reason }) => {
                assert_eq!(*reason, PeerEnd::ViewerClosed, "{seen:?}");
                assert!(reason.by_viewer());
                assert_eq!(
                    reason.reason(),
                    "peer_closed",
                    "the wire reason is unchanged"
                );
            }
            other => panic!("the peer must end: {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_lost_path_nobody_restarts_ends_the_peer_when_the_window_runs_out() {
        let grace = Duration::from_millis(800);
        let (_viewer, mut peer, _) = connected(true, vec![], loopback(grace, true)).await;

        // The viewer goes silent — the phone left the network — and never comes back.
        let seen = silent_until(&mut peer.events, S(10), |e| {
            matches!(e, PeerEvent::LinkLost | PeerEvent::Disconnected { .. })
        })
        .await;
        assert!(
            matches!(seen.last(), Some(PeerEvent::LinkLost)),
            "a lost path is not the end of the peer any more: {seen:?}"
        );
        let lost_at = Instant::now();

        let seen = silent_until(&mut peer.events, grace + S(5), |e| {
            matches!(e, PeerEvent::Disconnected { .. })
        })
        .await;
        let waited = lost_at.elapsed();
        assert!(
            matches!(
                seen.last(),
                Some(PeerEvent::Disconnected {
                    reason: PeerEnd::IceTimeout
                })
            ),
            "{seen:?}"
        );
        // Not before the window ran out (less the time the loss report took to reach us), and
        // promptly once it had.
        assert!(
            waited + Duration::from_millis(100) >= grace,
            "ended {waited:?} after the loss, inside a {grace:?} window"
        );
        assert!(waited < grace + S(2), "ended only after {waited:?}");
    }

    #[tokio::test]
    async fn a_restart_inside_the_window_keeps_the_session() {
        let grace = Duration::from_millis(1_500);
        let (mut viewer, mut peer, _) = connected(true, vec![], loopback(grace, true)).await;

        let seen = silent_until(&mut peer.events, S(10), |e| {
            matches!(e, PeerEvent::LinkLost | PeerEvent::Disconnected { .. })
        })
        .await;
        assert!(matches!(seen.last(), Some(PeerEvent::LinkLost)), "{seen:?}");

        // The viewer is back, on what might be a different network, and restarts ICE.
        let (restart, pending) = viewer.restart_offer();
        signal(&peer, PeerSignal::Renegotiate(restart));
        let seen = pump_until(&mut viewer, &mut peer.events, S(3), |e| {
            matches!(e, PeerEvent::Answer(_))
        })
        .await;
        viewer.accept(pending, &answer_in(&seen));
        let seen = pump_until(&mut viewer, &mut peer.events, S(5), |e| {
            matches!(e, PeerEvent::KeyframeRequest(_))
        })
        .await;
        assert!(!ended(&seen), "{seen:?}");

        // Well past where the loss's window, and the restart's, would have run out: still up.
        let seen = pump_for(
            &mut viewer,
            &mut peer.events,
            grace + Duration::from_millis(700),
        )
        .await;
        assert!(
            !ended(&seen),
            "the restored path closed the window: {seen:?}"
        );
        assert!(viewer.rtc.is_connected());

        peer.closer.close();
        let seen = silent_until(&mut peer.events, S(5), |e| {
            matches!(e, PeerEvent::Disconnected { .. })
        })
        .await;
        assert!(
            matches!(
                seen.last(),
                Some(PeerEvent::Disconnected {
                    reason: PeerEnd::Closed
                })
            ),
            "{seen:?}"
        );
    }

    #[tokio::test]
    async fn a_blackout_on_the_link_shaper_loses_the_path_and_a_restart_brings_it_back() {
        use crate::shaper::{EgressProfile, IngressProfile, LinkProfile, LinkShaper};

        // What the bench does to force an ICE disconnect and restart: the whole session, handshake
        // included, runs through the shaper; then the link goes black.
        let delayed = LinkProfile {
            egress: EgressProfile {
                delay_ms: 20,
                ..EgressProfile::default()
            },
            ingress: IngressProfile {
                delay_ms: 20,
                ..IngressProfile::default()
            },
            ..LinkProfile::default()
        };
        let shaper = LinkShaper::new(delayed.clone());
        let grace = S(5);
        let tuning = Tuning {
            shaper: Some(shaper.clone()),
            ..loopback(grace, true)
        };
        let (mut viewer, mut peer, _) = connected(true, vec![], tuning).await;

        assert!(shaper.set_profile(
            LinkProfile {
                blackout: true,
                ..delayed.clone()
            },
            "test"
        ));
        let seen = pump_until(&mut viewer, &mut peer.events, S(10), |e| {
            matches!(e, PeerEvent::LinkLost)
        })
        .await;
        assert!(!ended(&seen), "{seen:?}");

        // The link comes back and the viewer restarts ICE, as the Mini App does.
        assert!(shaper.set_profile(delayed, "test"));
        let (restart, pending) = viewer.restart_offer();
        signal(&peer, PeerSignal::Renegotiate(restart));
        let seen = pump_until(&mut viewer, &mut peer.events, S(3), |e| {
            matches!(e, PeerEvent::Answer(_))
        })
        .await;
        viewer.accept(pending, &answer_in(&seen));
        let seen = pump_until(&mut viewer, &mut peer.events, S(5), |e| {
            matches!(e, PeerEvent::KeyframeRequest(_))
        })
        .await;
        assert!(!ended(&seen), "{seen:?}");
        peer.closer.close();
    }

    #[tokio::test]
    async fn a_re_offer_that_cannot_be_applied_ends_the_peer_with_that_reason() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
        let mut peer = spawn_peer_on(
            socket,
            &viewer_like_offer(),
            vec![],
            loopback(ICE_GRACE, false),
        )
        .await
        .expect("a peer");
        signal(
            &peer,
            PeerSignal::Renegotiate("v=0\r\nnot an offer\r\n".into()),
        );
        let seen = silent_until(&mut peer.events, S(5), |e| {
            matches!(e, PeerEvent::Disconnected { .. })
        })
        .await;
        assert!(
            matches!(
                seen.last(),
                Some(PeerEvent::Disconnected {
                    reason: PeerEnd::RestartFailed
                })
            ),
            "the viewer is waiting for an answer that cannot come: {seen:?}"
        );
    }

    /// The encoder starts with the answer, so its opening IDR is made before there is anywhere to
    /// send it. Every frame after that references a picture the viewer never got: the peer asks for
    /// a keyframe the moment it connects, instead of sending deltas and waiting for the viewer to
    /// notice — which the iPhone does not.
    #[tokio::test]
    async fn frames_encoded_before_the_connection_cost_a_keyframe_on_connected() {
        let (mut viewer, offer, pending) = TestViewer::new(false).await;
        let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind agent");
        let mut peer = spawn_peer_on(socket, &offer, vec![], loopback(ICE_GRACE, false))
            .await
            .expect("a peer");
        for (ts, key) in [(0u64, true), (33, false)] {
            let data = vec![0, 0, 0, 1, if key { 0x65 } else { 0x41 }, 0x88, 0x84];
            // As the encode thread does: committed before it is sent. See `queued_media_bytes`.
            peer.queued_media_bytes
                .fetch_add(u32::try_from(data.len()).expect("small"), Ordering::Relaxed);
            peer.media_tx
                .send(MediaSample {
                    data,
                    is_keyframe: key,
                    timestamp_ms: ts,
                    qp: None,
                })
                .await
                .expect("media");
        }
        viewer.accept(pending, &peer.answer_sdp);
        let seen = pump_until(&mut viewer, &mut peer.events, S(10), |e| {
            matches!(e, PeerEvent::KeyframeRequest(_))
        })
        .await;
        // This peer's own request, which the orchestrator honours whatever keyframe went before
        // (`KeyframeAsk::from_viewer` is false): the opening IDR never reached the viewer.
        assert!(
            matches!(
                seen.last(),
                Some(PeerEvent::KeyframeRequest(KeyframeAsk::ChainBroken))
            ),
            "{seen:?}"
        );
        let connected_at = seen
            .iter()
            .position(|e| matches!(e, PeerEvent::Connected))
            .expect("connected first");
        assert_eq!(
            connected_at,
            seen.len() - 2,
            "the request follows Connected at once: {seen:?}"
        );
        peer.closer.close();
    }

    /// What this thread logs, as the app's file shows it: `fmt::layer()` without colour and with
    /// targets, behind the `debug` level's filter (`LogLevel::Debug` in `afklink_core::logging`).
    /// Installed for the test's thread only; the loopback tests run on a current-thread runtime,
    /// so the peer's run loop logs on this thread too.
    #[derive(Clone, Default)]
    struct CapturedLog(Arc<std::sync::Mutex<Vec<u8>>>);

    impl CapturedLog {
        fn install(&self) -> tracing::subscriber::DefaultGuard {
            use tracing_subscriber::layer::SubscriberExt;
            let out = self.clone();
            let subscriber = tracing_subscriber::registry()
                .with(tracing_subscriber::EnvFilter::new("warn,afklink=debug"))
                .with(
                    tracing_subscriber::fmt::layer()
                        .with_ansi(false)
                        .with_target(true)
                        .with_writer(move || out.clone()),
                );
            tracing::subscriber::set_default(subscriber)
        }

        fn text(&self) -> String {
            String::from_utf8_lossy(&self.0.lock().expect("captured log")).into_owned()
        }
    }

    impl std::io::Write for CapturedLog {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().expect("captured log").extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// The `ICE candidate pair in use` line must appear between `media path: the first RTP/RTCP
    /// datagram` and `session connected`. This drives the real run loop to its first media datagram
    /// and reads the line as the file shows it: both kinds, the relay's transport and both
    /// addresses.
    ///
    /// The viewer's one candidate is signalled as a relay it reaches over TCP (priority 16785663,
    /// as an iPhone offers). ICE pairs addresses, not what a candidate calls
    /// itself, so the pair still forms on loopback.
    #[tokio::test]
    async fn the_first_media_datagram_puts_the_candidate_pair_in_the_log() {
        let log = CapturedLog::default();
        let _log = log.install();
        let (mut viewer, offer, pending) = TestViewer::new(false).await;
        let host = offer
            .lines()
            .find(|l| l.starts_with("a=candidate:"))
            .expect("the viewer's host candidate")
            .to_string();
        let relay = format!(
            "a=candidate:3 1 udp 16785663 {} {} typ relay raddr 0.0.0.0 rport 0",
            viewer.addr.ip(),
            viewer.addr.port()
        );
        let offer = offer.replace(&host, &relay);
        let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind agent");
        let agent = socket.local_addr().expect("agent addr");
        let mut peer = spawn_peer_on(socket, &offer, vec![], loopback(ICE_GRACE, false))
            .await
            .expect("a peer");
        viewer.accept(pending, &peer.answer_sdp);
        pump_until(&mut viewer, &mut peer.events, S(10), |e| {
            matches!(e, PeerEvent::Connected)
        })
        .await;

        // A keyframe, so there is media to send.
        let data = vec![0, 0, 0, 1, 0x65, 0x88, 0x84];
        peer.queued_media_bytes
            .fetch_add(u32::try_from(data.len()).expect("small"), Ordering::Relaxed);
        peer.media_tx
            .send(MediaSample {
                data,
                is_keyframe: true,
                timestamp_ms: 0,
                qp: None,
            })
            .await
            .expect("media");
        let until = Instant::now() + S(5);
        while !log.text().contains("ICE candidate pair in use") && Instant::now() < until {
            viewer.pump(Duration::from_millis(20)).await;
        }
        viewer.pump(Duration::from_millis(100)).await;
        peer.closer.close();

        let text = log.text();
        let line = text
            .lines()
            .find(|l| l.contains("ICE candidate pair in use"))
            .unwrap_or_else(|| panic!("no pair line in the log:\n{text}"));
        assert!(
            line.contains(" INFO afklink_transport::webrtc: ICE candidate pair in use "),
            "{line}"
        );
        for field in [
            "why=\"first\"".to_string(),
            format!("local={agent} "),
            "local_kind=\"host\"".to_string(),
            "local_srflx=-".to_string(),
            format!("remote={} ", viewer.addr),
            "remote_kind=relay".to_string(),
            "remote_proto=udp".to_string(),
            "relay_transport=\"tcp\"".to_string(),
            "remote_prio=Some(16785663)".to_string(),
            "candidates_known=1".to_string(),
        ] {
            assert!(line.contains(&field), "{field} is missing from: {line}");
        }
        let first = text
            .find("media path: the first RTP/RTCP datagram of the session")
            .unwrap_or_else(|| panic!("no first-datagram line in the log:\n{text}"));
        let pair = text.find("ICE candidate pair in use").expect("found above");
        assert!(
            first < pair,
            "the pair line follows its datagram's:\n{text}"
        );
        assert_eq!(
            text.matches("ICE candidate pair in use").count(),
            1,
            "once per selection, not per datagram:\n{text}"
        );
    }

    /// The peer publishes how far it got for the session's `session_end.detail`: a connected peer
    /// is `connected`, with how long DTLS took after ICE and the pair's kinds — here a relay the
    /// viewer reaches over TCP — and the same stands once it ended. Kinds only: nothing in it is an
    /// address.
    #[tokio::test]
    async fn a_connected_peer_publishes_its_stage_and_pair_kinds() {
        let (mut viewer, offer, pending) = TestViewer::new(false).await;
        let host = offer
            .lines()
            .find(|l| l.starts_with("a=candidate:"))
            .expect("the viewer's host candidate")
            .to_string();
        let relay = format!(
            "a=candidate:3 1 udp 16785663 {} {} typ relay raddr 0.0.0.0 rport 0",
            viewer.addr.ip(),
            viewer.addr.port()
        );
        let offer = offer.replace(&host, &relay);
        let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind agent");
        let mut peer = spawn_peer_on(socket, &offer, vec![], loopback(ICE_GRACE, false))
            .await
            .expect("a peer");
        assert_eq!(peer.path.get(), PeerPath::default(), "nothing yet: new");
        viewer.accept(pending, &peer.answer_sdp);
        pump_until(&mut viewer, &mut peer.events, S(10), |e| {
            matches!(e, PeerEvent::Connected)
        })
        .await;
        let until = Instant::now() + S(5);
        while peer.path.get().pair_remote_kind.is_none() && Instant::now() < until {
            viewer.pump(Duration::from_millis(20)).await;
        }
        let path = peer.path.get();
        assert_eq!(path.stage, PeerStage::Connected, "{path:?}");
        assert_eq!(path.verdict, None, "a verdict only for a stalled handshake");
        assert!(path.dtls_after_ice_ms.is_some(), "{path:?}");
        assert_eq!(path.pair_local_kind, Some("host"));
        assert_eq!(path.pair_remote_kind, Some("relay"));
        assert_eq!(path.relay_transport, Some("tcp"));

        assert!(peer.closer.close());
        silent_until(&mut peer.events, S(5), |e| {
            matches!(e, PeerEvent::Disconnected { .. })
        })
        .await;
        let ended = peer.path.get();
        assert_eq!(ended.stage, PeerStage::Connected, "how far it got stands");
        assert_eq!(ended.pair_remote_kind, Some("relay"));
        let detail = ended.detail();
        assert_eq!(detail.ended_detail, None, "the orchestrator's to add");
        assert_eq!(detail.stage.as_deref(), Some("connected"));
        assert_eq!(detail.relay_transport.as_deref(), Some("tcp"));
        let (kept, dropped) = detail.clone().keep_valid();
        assert!(dropped.is_empty(), "{dropped:?}");
        assert_eq!(kept, detail);
        let wire = serde_json::to_string(&detail).expect("serialises");
        assert!(!wire.contains("127.0.0.1"), "no address: {wire}");
    }

    /// A peer that ends before any pair was checked says `new`, with nothing else: no verdict, no
    /// pair.
    #[tokio::test]
    async fn a_peer_that_never_checked_a_pair_ends_as_new() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
        let mut peer = spawn_peer_on(
            socket,
            &viewer_like_offer(),
            vec![],
            loopback(ICE_GRACE, false),
        )
        .await
        .expect("a peer");
        assert!(peer.closer.close());
        silent_until(&mut peer.events, S(5), |e| {
            matches!(e, PeerEvent::Disconnected { .. })
        })
        .await;
        let path = peer.path.get();
        assert_eq!(path, PeerPath::default());
        assert_eq!(
            serde_json::to_value(path.detail()).expect("serialises"),
            serde_json::json!({ "stage": "new" })
        );
    }

    /// The relay's transport is said only when its priority says it: `unknown` is not a word the
    /// contract has, and the server would drop it anyway.
    #[test]
    fn remote_kinds_are_the_contracts_words() {
        let at = |port: u16| SocketAddr::from(([10, 0, 0, 1], port));
        let line = |typ: &str, prio: u32, port: u16| {
            let raddr = if typ == "host" {
                String::new()
            } else {
                " raddr 0.0.0.0 rport 0".to_string()
            };
            let c = Candidate::from_sdp_string(&format!(
                "candidate:1 1 udp {prio} 10.0.0.1 {port} typ {typ}{raddr}"
            ))
            .expect("a candidate");
            RemoteCandidate::of(&c)
        };
        let book = vec![
            line("host", 2_122_260_223, 1),
            line("srflx", 1_686_052_607, 2),
            line("relay", 41_885_439, 3),
            line("relay", 8_959, 4),
            line("relay", 0x0300_0000, 5),
        ];
        assert_eq!(remote_path_kinds(&book, at(1)), ("host", None));
        assert_eq!(remote_path_kinds(&book, at(2)), ("srflx", None));
        assert_eq!(remote_path_kinds(&book, at(3)), ("relay", Some("udp")));
        assert_eq!(remote_path_kinds(&book, at(4)), ("relay", Some("tls")));
        assert_eq!(
            remote_path_kinds(&book, at(5)),
            ("relay", None),
            "a priority that does not say"
        );
        assert_eq!(
            remote_path_kinds(&book, at(9)),
            ("prflx", None),
            "never signalled: learned from a check"
        );
        for kind in [
            CandidateKind::Host,
            CandidateKind::ServerReflexive,
            CandidateKind::PeerReflexive,
            CandidateKind::Relayed,
        ] {
            assert!(afklink_protocol::metrics::CANDIDATE_KINDS.contains(&candidate_kind_word(kind)));
        }
    }

    /// The first line of the captured log that contains `needle`.
    fn line_with<'a>(text: &'a str, needle: &str) -> &'a str {
        text.lines()
            .find(|l| l.contains(needle))
            .unwrap_or_else(|| panic!("no {needle:?} in the log:\n{text}"))
    }

    fn assert_fields(line: &str, fields: &[String]) {
        for field in fields {
            assert!(
                line.contains(field.as_str()),
                "{field} is missing from: {line}"
            );
        }
    }

    /// A handshake that works says how it went: this side's role, the first DTLS datagram each way
    /// (the viewer's ClientHello in, our flight out), the pair str0m nominated, and how long DTLS
    /// took after ICE — and the peer's paths once it ends. No stall line.
    #[tokio::test]
    async fn a_healthy_handshake_names_its_role_pair_and_datagrams() {
        let log = CapturedLog::default();
        let _log = log.install();
        let (mut viewer, offer, pending) = TestViewer::new(false).await;
        let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind agent");
        let agent = socket.local_addr().expect("agent addr");
        let mut peer = spawn_peer_on(socket, &offer, vec![], loopback(ICE_GRACE, false))
            .await
            .expect("a peer");
        viewer.accept(pending, &peer.answer_sdp);
        pump_until(&mut viewer, &mut peer.events, S(10), |e| {
            matches!(e, PeerEvent::Connected)
        })
        .await;
        // str0m names its pair in its once-a-second stats.
        let until = Instant::now() + S(3);
        while !log.text().contains("ICE nominated pair") && Instant::now() < until {
            viewer.pump(Duration::from_millis(20)).await;
        }
        peer.closer.close();
        silent_until(&mut peer.events, S(5), |e| {
            matches!(e, PeerEvent::Disconnected { .. })
        })
        .await;

        let text = log.text();
        let v = viewer.addr;
        assert_fields(
            line_with(&text, "offer accepted; the answer"),
            &["setup=passive".into(), "dtls_role=\"server\"".into()],
        );
        assert_fields(
            line_with(&text, "ICE connected for the first time"),
            &[
                " INFO afklink_transport::webrtc:".into(),
                "dtls_role=\"server\"".into(),
                "dtls_connected=false".into(),
            ],
        );
        assert_fields(
            line_with(&text, "DTLS first datagram in"),
            &[format!("from={v} "), "content=\"CH\"".into()],
        );
        assert_fields(
            line_with(&text, "DTLS first datagram out"),
            &[
                format!("to={v} "),
                "remote_kind=\"host\"".into(),
                "content=\"SH Cert SKE CR SHD\"".into(),
            ],
        );
        let connected = line_with(&text, "webrtc connected: ICE and DTLS are up");
        assert_fields(
            connected,
            &[
                "dtls_role=\"server\"".into(),
                "dtls_after_ice_ms=".into(),
                // Our flight out; the viewer's ClientHello and second flight in. (Counted, so a
                // resend on a slow machine would read `SHx2`/`CHx2`.)
                "Cert SKE CR SHD}".into(),
                "Cert CV CKE CCS Enc}".into(),
            ],
        );
        assert_fields(
            line_with(&text, "ICE nominated pair (from str0m's stats)"),
            &[
                " INFO afklink_transport::webrtc:".into(),
                "why=\"first\"".into(),
                format!("local={agent} "),
                format!("remote={v} "),
                "remote_kind=host".into(),
                "protocol=udp".into(),
            ],
        );
        assert_fields(
            line_with(&text, "peer paths over the session"),
            &[format!("{v} host*: out stun ")],
        );
        assert!(!text.contains("DTLS handshake stalled"), "{text}");
        assert!(!text.contains("before the connection came up"), "{text}");
        // A pair that answers is never left, and its watch says nothing.
        assert!(!text.contains("ICE send pair left"), "{text}");
        assert!(!text.contains("send-pair watch"), "{text}");
    }

    /// ICE can connect within a second while DTLS never does, and the log has to say why. Here the
    /// path loses every datagram over 400 bytes on its way to the viewer:
    /// STUN and the viewer's ClientHello get through, our server flight does not. The log has to say
    /// exactly that — at warn, three seconds after ICE: the viewer resending its ClientHello, our
    /// flight and its size, the pair — and again when the peer ends.
    #[tokio::test]
    async fn a_dtls_flight_lost_on_the_way_to_the_viewer_is_named_in_the_log() {
        let log = CapturedLog::default();
        let _log = log.install();
        let (mut viewer, offer, pending) = TestViewer::new(false).await;
        viewer.drop_in_over = Some(400);
        let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind agent");
        let agent = socket.local_addr().expect("agent addr");
        let mut peer = spawn_peer_on(socket, &offer, vec![], loopback(ICE_GRACE, false))
            .await
            .expect("a peer");
        viewer.accept(pending, &peer.answer_sdp);
        let mut seen = Vec::new();
        let until = Instant::now() + S(10);
        while !log.text().contains("DTLS handshake stalled") && Instant::now() < until {
            seen.extend(pump_for(&mut viewer, &mut peer.events, Duration::from_millis(50)).await);
        }
        assert!(
            !seen.iter().any(|e| matches!(e, PeerEvent::Connected)),
            "{seen:?}"
        );
        assert!(!viewer.rtc.is_connected());
        peer.closer.close();
        silent_until(&mut peer.events, S(5), |e| {
            matches!(e, PeerEvent::Disconnected { .. })
        })
        .await;

        let text = log.text();
        let v = viewer.addr;
        let stalled = line_with(&text, "DTLS handshake stalled");
        let expected = [
            " WARN afklink_transport::webrtc: DTLS handshake stalled".to_string(),
            "dtls_role=\"server\"".into(),
            "verdict=\"viewer_resends_hello\"".into(),
            format!("pair=\"{agent} -> {v} (host)\""),
            "dtls_in=\"".into(),
            "{CHx".into(),
            "Cert SKE CR SHD}".into(),
            format!("paths=\"{v} host*: out stun "),
        ];
        assert_fields(stalled, &expected);
        let waited: u64 = stalled
            .split("waited_ms=")
            .nth(1)
            .and_then(|s| s.split(' ').next())
            .and_then(|s| s.parse().ok())
            .unwrap_or_else(|| panic!("no waited_ms in: {stalled}"));
        assert!(
            (3_000..4_000).contains(&waited),
            "warned {waited} ms after ICE"
        );
        // Our flight is the datagram the path lost: over 400 bytes, each time it went.
        let out = stalled.split("dtls_out=\"").nth(1).expect("dtls_out");
        let max: usize = out
            .split("B<=")
            .nth(1)
            .and_then(|s| s.split(' ').next())
            .and_then(|s| s.parse().ok())
            .unwrap_or_else(|| panic!("no max in: {out}"));
        assert!(max > 400, "{stalled}");

        let ended = line_with(&text, "peer ended before the connection came up");
        assert_fields(
            ended,
            &[
                " WARN afklink_transport::webrtc:".into(),
                "stage=\"dtls_never_completed\"".into(),
                "reason=\"peer_closed\"".into(),
                "verdict=\"viewer_resends_hello\"".into(),
            ],
        );
        let end_at = text.find("peer ended before the connection came up");
        let loop_end_at = text.find("webrtc peer loop ended");
        assert!(end_at < loop_end_at, "the summary comes first:\n{text}");
    }

    /// The fallback the Mini App takes when DTLS stalls: an ICE restart, in production onto a relay
    /// over TCP/TLS. The agent applies it to a peer that has never connected, and the handshake that
    /// stalled finishes after it — str0m keeps DTLS across a restart and sends its next datagram to
    /// whatever pair ICE nominates.
    ///
    /// On loopback the new pair has the old pair's addresses, so what this shows is the state
    /// machine: a restart before DTLS is up costs the handshake nothing. That the datagrams follow
    /// the new nomination is str0m's `send_addr` (`lib.rs:1598-1614`), shown on a live connection by
    /// `an_ice_restart_reconnects_the_live_peer_and_rediscovers_srflx`.
    #[tokio::test]
    async fn an_ice_restart_before_dtls_lets_the_stalled_handshake_finish() {
        let log = CapturedLog::default();
        let _log = log.install();
        let (mut viewer, offer, pending) = TestViewer::new(false).await;
        viewer.drop_in_over = Some(400);
        let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind agent");
        let mut peer = spawn_peer_on(socket, &offer, vec![], loopback(ICE_GRACE, false))
            .await
            .expect("a peer");
        viewer.accept(pending, &peer.answer_sdp);
        let seen = pump_for(&mut viewer, &mut peer.events, S(2)).await;
        assert!(
            !seen.iter().any(|e| matches!(e, PeerEvent::Connected)),
            "the path loses our flight: {seen:?}"
        );

        // The viewer restarts ICE onto a path that carries large datagrams.
        viewer.drop_in_over = None;
        let (restart, pending) = viewer.restart_offer();
        signal(&peer, PeerSignal::Renegotiate(restart));
        let seen = pump_until(&mut viewer, &mut peer.events, S(3), |e| {
            matches!(e, PeerEvent::Answer(_))
        })
        .await;
        viewer.accept(pending, &answer_in(&seen));
        let seen = pump_until(&mut viewer, &mut peer.events, S(15), |e| {
            matches!(e, PeerEvent::Connected)
        })
        .await;
        assert!(!ended(&seen), "{seen:?}");
        viewer.pump(Duration::from_millis(200)).await;
        assert!(viewer.rtc.is_connected(), "the viewer's side is up too");
        peer.closer.close();

        let text = log.text();
        assert_fields(
            line_with(&text, "ICE restart applied"),
            &["dtls_connected=false".into(), "dtls_stalled_ms=".into()],
        );
        assert!(
            text.find("ICE restart applied") < text.find("webrtc connected: ICE and DTLS are up"),
            "{text}"
        );
    }

    /// The segment of a `paths` field about `addr`: `<addr> <kind>[*]: out ...; in ...`.
    fn path_segment(line: &str, addr: SocketAddr) -> &str {
        let paths = line
            .split("paths=\"")
            .nth(1)
            .unwrap_or_else(|| panic!("no paths in: {line}"));
        paths
            .split(" | ")
            .find(|s| s.starts_with(&format!("{addr} ")))
            .unwrap_or_else(|| panic!("no {addr} in: {paths}"))
    }

    /// The one-way [`Ghost`] path on loopback, with str0m left to itself (the send-pair watch off): what
    /// str0m 0.23.1 does when the viewer nominates a higher-priority pair that carries its checks
    /// to us and nothing back, and talks DTLS on another.
    ///
    /// The ghost path copies each of the viewer's checks — USE-CANDIDATE included — from an
    /// address signalled as the viewer's srflx; the viewer's own socket is signalled as a relay
    /// over TCP. str0m nominates the ghost's pair on the first USE-CANDIDATE, with not one of its
    /// own checks there ever answered (`stun_responses=0`), sends its whole DTLS flight there
    /// while the ClientHello keeps coming from the relay, and stays: the ghost's next check renews
    /// the pair (`RECENT_BINDING_REQUEST`), and the relay pair, nominated too, ranks lower. The
    /// handshake never finishes, and the stall warning names it: `nominated_path_silent`.
    #[tokio::test]
    async fn str0m_alone_sends_its_flight_to_a_nominated_pair_that_never_answered() {
        let log = CapturedLog::default();
        let _log = log.install();
        let (mut viewer, offer, pending) = TestViewer::new(false).await;
        let offer = viewer.haunt(&offer).await;
        let ghost = viewer.ghost().addr;
        let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind agent");
        let tuning = Tuning {
            follow_viewer: false,
            ..loopback(ICE_GRACE, false)
        };
        let mut peer = spawn_peer_on(socket, &offer, vec![], tuning)
            .await
            .expect("a peer");
        viewer.accept(pending, &peer.answer_sdp);
        let mut seen = Vec::new();
        let until = Instant::now() + S(10);
        while !log.text().contains("DTLS handshake stalled") && Instant::now() < until {
            seen.extend(pump_for(&mut viewer, &mut peer.events, Duration::from_millis(50)).await);
        }
        assert!(
            !seen.iter().any(|e| matches!(e, PeerEvent::Connected)),
            "{seen:?}"
        );
        assert!(!viewer.rtc.is_connected());
        let g = viewer.ghost();
        assert!(g.got_dtls > 0, "our flight went to the ghost address");
        assert_eq!(g.got_rtp, 0);
        peer.closer.close();
        silent_until(&mut peer.events, S(5), |e| {
            matches!(e, PeerEvent::Disconnected { .. })
        })
        .await;

        let text = log.text();
        let v = viewer.addr;
        assert_fields(
            line_with(&text, "ICE nominated pair (from str0m's stats)"),
            &[
                format!("remote={ghost} "),
                "remote_kind=srflx".into(),
                "stun_responses=0".into(),
            ],
        );
        assert_fields(
            line_with(&text, "DTLS first datagram in"),
            &[format!("from={v} "), "remote_kind=\"relay/tcp\"".into()],
        );
        assert_fields(
            line_with(&text, "DTLS first datagram out"),
            &[format!("to={ghost} "), "remote_kind=\"srflx\"".into()],
        );
        let stalled = line_with(&text, "DTLS handshake stalled");
        assert_fields(
            stalled,
            &[
                "verdict=\"nominated_path_silent\"".into(),
                format!("{ghost} srflx*: out stun "),
            ],
        );
        // The ghost's pair each way: our checks out and none answered; its checks in, nominating.
        let segment = path_segment(stalled, ghost);
        let (out, inn) = segment.split_once("; in ").expect("both ways");
        assert!(
            out.contains("[checks ") && out.contains("dtls "),
            "{segment}"
        );
        assert!(
            inn.contains(", nominating ") && inn.contains(", replies 0]"),
            "{segment}"
        );
        assert!(!inn.contains("dtls"), "no DTLS from the ghost: {segment}");
        assert!(
            !text.contains("ICE send pair left"),
            "the watch was off:\n{text}"
        );
    }

    /// The same session with the send-pair watch on, as in production: once the agent's checks on
    /// the ghost's pair have gone unanswered for a second and a half while the viewer's ClientHello
    /// comes from its relay — a pair it nominated and answers on — the ghost's candidate is
    /// withdrawn from str0m, str0m sends on the relay, and the handshake finishes. Once: the pair
    /// left is never gone back to, and the media that follows goes to the relay too.
    #[tokio::test]
    async fn the_agent_leaves_a_nominated_pair_that_never_answers_for_the_one_the_viewer_uses() {
        let log = CapturedLog::default();
        let _log = log.install();
        let (mut viewer, offer, pending) = TestViewer::new(false).await;
        let offer = viewer.haunt(&offer).await;
        let ghost = viewer.ghost().addr;
        let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind agent");
        let mut peer = spawn_peer_on(socket, &offer, vec![], loopback(ICE_GRACE, false))
            .await
            .expect("a peer");
        viewer.accept(pending, &peer.answer_sdp);
        let seen = pump_until(&mut viewer, &mut peer.events, S(10), |e| {
            matches!(e, PeerEvent::Connected)
        })
        .await;
        assert!(!ended(&seen), "{seen:?}");
        viewer.pump(Duration::from_millis(200)).await;
        assert!(viewer.rtc.is_connected(), "the viewer's side is up too");
        let dtls_to_ghost = viewer.ghost().got_dtls;

        // Media: it goes to the relay, and nothing more goes to the ghost but STUN replies.
        let data = vec![0, 0, 0, 1, 0x65, 0x88, 0x84];
        peer.queued_media_bytes
            .fetch_add(u32::try_from(data.len()).expect("small"), Ordering::Relaxed);
        peer.media_tx
            .send(MediaSample {
                data,
                is_keyframe: true,
                timestamp_ms: 0,
                qp: None,
            })
            .await
            .expect("media");
        let until = Instant::now() + S(5);
        while !log.text().contains("ICE candidate pair in use") && Instant::now() < until {
            viewer.pump(Duration::from_millis(20)).await;
        }
        // And well past the watch's thresholds: nothing moves again.
        pump_for(&mut viewer, &mut peer.events, S(4)).await;
        let g = viewer.ghost();
        assert_eq!(g.got_rtp, 0, "no media to the ghost");
        assert_eq!(
            g.got_dtls, dtls_to_ghost,
            "no DTLS to the ghost after the move"
        );
        peer.closer.close();
        silent_until(&mut peer.events, S(5), |e| {
            matches!(e, PeerEvent::Disconnected { .. })
        })
        .await;

        let text = log.text();
        let v = viewer.addr;
        let left = line_with(&text, "ICE send pair left");
        assert_fields(
            left,
            &[
                " INFO afklink_transport::webrtc: ICE send pair left".into(),
                "phase=\"handshake\"".into(),
                format!("dead=\"{ghost} srflx: checks unanswered "),
                ", replies 0 (last never)".into(),
                format!("to=\"{v} relay/tcp: checks unanswered "),
                "also_dead=\"-\"".into(),
                "withdrawn=1".into(),
                "not_found=0".into(),
                "dtls_connected=false".into(),
            ],
        );
        assert_eq!(
            text.matches("ICE send pair left").count(),
            1,
            "one move:\n{text}"
        );
        assert_fields(
            line_with(&text, "str0m's send pair changed"),
            &[
                format!("from={ghost} "),
                format!("to={v} "),
                "to_kind=relay/tcp".into(),
                "after_move_ms=".into(),
            ],
        );
        assert!(
            text.find("ICE send pair left") < text.find("webrtc connected: ICE and DTLS are up"),
            "{text}"
        );
        assert_fields(
            line_with(&text, "webrtc connected: ICE and DTLS are up"),
            &[
                format!("send_to={v} (relay/tcp)"),
                "send_pairs_left=1".into(),
            ],
        );
        assert_fields(
            line_with(&text, "ICE candidate pair in use"),
            &[format!("remote={v} "), "relay_transport=\"tcp\"".into()],
        );
        assert!(
            !text.contains("str0m still sends to a remote withdrawn"),
            "{text}"
        );
        assert!(!text.contains("could not be withdrawn"), "{text}");
    }

    /// Mid-session, the same trap: the viewer's checks start reaching us over the one-way path
    /// as well, each nominating it. str0m moves the media there at once — the pair outranks the
    /// relay — and on its own would keep it there as long as those checks keep coming. The watch
    /// takes it off after its connected-phase threshold, asks for a keyframe, and that is the one
    /// move: the relay carries the media again and nothing goes back to the ghost.
    #[tokio::test]
    async fn a_connected_session_is_taken_off_a_one_way_pair_str0m_moved_it_to() {
        let log = CapturedLog::default();
        let _log = log.install();
        let (mut viewer, offer, pending) = TestViewer::new(false).await;
        let offer = viewer.haunt(&offer).await;
        viewer.ghost_mut().copying = false;
        let ghost = viewer.ghost().addr;
        let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind agent");
        let mut peer = spawn_peer_on(socket, &offer, vec![], loopback(ICE_GRACE, false))
            .await
            .expect("a peer");
        viewer.accept(pending, &peer.answer_sdp);
        pump_until(&mut viewer, &mut peer.events, S(10), |e| {
            matches!(e, PeerEvent::Connected)
        })
        .await;
        pump_for(&mut viewer, &mut peer.events, Duration::from_millis(500)).await;
        assert_eq!(viewer.ghost().got_rtp, 0, "connected on the relay");

        viewer.ghost_mut().copying = true;
        let mut seen = Vec::new();
        let until = Instant::now() + S(15);
        while !log.text().contains("ICE send pair left") && Instant::now() < until {
            seen.extend(pump_for(&mut viewer, &mut peer.events, Duration::from_millis(50)).await);
        }
        let rtp_to_ghost = viewer.ghost().got_rtp;
        assert!(
            rtp_to_ghost > 0,
            "str0m moved the media to the one-way pair the viewer nominated"
        );
        seen.extend(pump_for(&mut viewer, &mut peer.events, S(4)).await);
        assert!(!ended(&seen), "{seen:?}");
        assert!(
            seen.iter()
                .any(|e| matches!(e, PeerEvent::KeyframeRequest(KeyframeAsk::PairMoved))),
            "the frames lost on the dead pair are made good with a keyframe: {seen:?}"
        );
        // A few in flight when the move was made at most; then nothing.
        let after = viewer.ghost().got_rtp;
        assert!(after - rtp_to_ghost < 10, "{rtp_to_ghost} -> {after}");
        pump_for(&mut viewer, &mut peer.events, S(1)).await;
        assert_eq!(
            viewer.ghost().got_rtp,
            after,
            "no media to the ghost after the move"
        );
        assert!(viewer.rtc.is_connected());
        peer.closer.close();

        let text = log.text();
        let v = viewer.addr;
        assert_fields(
            line_with(&text, "ICE send pair left"),
            &[
                "phase=\"connected\"".into(),
                format!("dead=\"{ghost} srflx: checks unanswered "),
                format!("to=\"{v} relay/tcp: "),
                "withdrawn=1".into(),
                "dtls_connected=true".into(),
            ],
        );
        assert_eq!(
            text.matches("ICE send pair left").count(),
            1,
            "one move:\n{text}"
        );
        // Moved there by str0m, and back by the watch.
        assert_eq!(
            text.matches("media path changed: ICE moved the media to another candidate pair")
                .count(),
            2,
            "{text}"
        );
        assert_fields(
            line_with(&text, "str0m's send pair changed"),
            &[format!("from={v} "), format!("to={ghost} ")],
        );
    }

    /// A close is heard however full the control queue is: as a message in that queue it would be
    /// refused when the queue is full, and the peer would run until ICE gave up on its own.
    #[tokio::test]
    async fn a_close_is_heard_through_a_full_control_queue() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
        let mut peer = spawn_peer_on(
            socket,
            &viewer_like_offer(),
            vec![],
            loopback(ICE_GRACE, false),
        )
        .await
        .expect("a peer");
        // The test runtime is single-threaded and nothing has yielded since the spawn, so the run
        // loop has not taken anything yet: this fills the queue for real.
        let mut queued = 0;
        while peer
            .control_tx
            .try_send(PeerControl::SetDesiredBitrate(1_000))
            .is_ok()
        {
            queued += 1;
        }
        assert_eq!(queued, 16, "the queue is full");
        assert!(peer.closer.close(), "the peer is running to hear it");
        let seen = silent_until(&mut peer.events, S(5), |e| {
            matches!(e, PeerEvent::Disconnected { .. })
        })
        .await;
        assert!(
            matches!(
                seen.last(),
                Some(PeerEvent::Disconnected {
                    reason: PeerEnd::Closed
                })
            ),
            "{seen:?}"
        );
        assert!(!peer.closer.close(), "and afterwards nobody is listening");
    }

    /// On loopback: the answer waits out its STUN budget while the viewer trickles, and the
    /// orchestrator hands every candidate over in one burst the moment the session exists: 40 here,
    /// past the 16 of the control queue, which would drop the last ones (seen: every TCP and TLS
    /// relay). The peer has taken none when the burst ends; it takes all
    /// of them, in the order sent, and says at ICE connected and at its end that none was dropped.
    #[tokio::test]
    async fn a_burst_of_candidates_before_the_peer_takes_any_reaches_it_whole_and_in_order() {
        const BURST: u16 = 40;
        let log = CapturedLog::default();
        let _log = log.install();
        let (mut viewer, offer, pending) = TestViewer::new(false).await;
        let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind agent");
        // As the Mini App offers: no candidates, trickled after it.
        let mut peer = spawn_peer_on(
            socket,
            &without_candidates(&offer),
            vec![],
            loopback(ICE_GRACE, false),
        )
        .await
        .expect("a peer");
        // The test runtime is single-threaded and nothing has yielded since the spawn, so the run
        // loop has not had a turn: the whole burst is queued before it takes any. First 39 relays
        // the viewer reaches over TCP (TEST-NET, unreachable by design), then its own host
        // candidate — last, where the relays the control queue dropped were.
        let ufrag = ice_ufrag(&offer);
        let mut sent = Vec::new();
        for n in 1..BURST {
            let addr = SocketAddr::from((
                [203, 0, 113, u8::try_from(n % 4 + 1).expect("small")],
                40_000 + n,
            ));
            sent.push(addr);
            signal(
                &peer,
                PeerSignal::AddRemoteIce(viewer_ice(addr, "relay", &ufrag)),
            );
        }
        sent.push(viewer.addr);
        signal(
            &peer,
            PeerSignal::AddRemoteIce(viewer_ice(viewer.addr, "host", &ufrag)),
        );
        let counts = peer.signals.counts();
        assert_eq!(
            (
                counts.queued,
                counts.taken,
                counts.dropped,
                counts.max_depth
            ),
            (40, 0, 0, 40),
            "all of them queued at once, none taken yet: {counts:?}"
        );

        viewer.accept(pending, &peer.answer_sdp);
        pump_until(&mut viewer, &mut peer.events, S(10), |e| {
            matches!(e, PeerEvent::Connected)
        })
        .await;
        let by = Instant::now() + S(5);
        while peer.signals.counts().taken < u32::from(BURST) {
            assert!(Instant::now() < by, "{:?}", peer.signals.counts());
            viewer.pump(Duration::from_millis(20)).await;
        }
        assert!(peer.closer.close());
        silent_until(&mut peer.events, S(5), |e| {
            matches!(e, PeerEvent::Disconnected { .. })
        })
        .await;

        let text = log.text();
        let taken: Vec<SocketAddr> = text
            .lines()
            .filter(|l| l.contains("remote candidate kind="))
            .map(|l| {
                let at = l.find(" addr=").expect("an addr field") + " addr=".len();
                l[at..]
                    .split_whitespace()
                    .next()
                    .and_then(|a| a.parse().ok())
                    .unwrap_or_else(|| panic!("an address in: {l}"))
            })
            .collect();
        assert_eq!(
            taken, sent,
            "every candidate reached str0m, in the order sent"
        );
        // How many were taken by then depends on how the run loop's turns fell; none was dropped.
        assert_fields(
            line_with(&text, "ICE connected for the first time"),
            &[
                "signals_queued=40".into(),
                "signals_dropped=0".into(),
                "signals_max_depth=40".into(),
            ],
        );
        // What the end line says, read where it reads it from. The line itself is not looked for:
        // a peer of a test running alongside that ends first can register its callsite while this
        // test's log is the only one installed, and tracing then caches it as unwanted on every
        // thread (`tracing-core`, `Rebuilder::JustOne` asks only the registering thread's default).
        let counts = peer.signals.counts();
        assert_eq!(
            (
                counts.queued,
                counts.taken,
                counts.dropped,
                counts.max_depth
            ),
            (40, 40, 0, 40),
            "{counts:?}"
        );
        assert_eq!(peer.signals.depth(), 0, "nothing left untaken");
    }

    /// Dropping the closer ends the peer: a peer nobody can close any more has nobody to serve.
    #[tokio::test]
    async fn a_peer_whose_closer_is_dropped_ends() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
        let peer = spawn_peer_on(
            socket,
            &viewer_like_offer(),
            vec![],
            loopback(ICE_GRACE, false),
        )
        .await
        .expect("a peer");
        let super::Peer {
            closer, mut events, ..
        } = peer;
        drop(closer);
        let seen = silent_until(&mut events, S(5), |e| {
            matches!(e, PeerEvent::Disconnected { .. })
        })
        .await;
        assert!(
            matches!(
                seen.last(),
                Some(PeerEvent::Disconnected {
                    reason: PeerEnd::Closed
                })
            ),
            "{seen:?}"
        );
    }

    /// The `seq` of a test message on the `cursor` channel.
    fn seq_of(text: &str) -> Option<u32> {
        let rest = &text[text.find(r#""seq":"#)? + 6..];
        let end = rest
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(rest.len());
        rest[..end].parse().ok()
    }

    /// A heartbeat and a cursor report at their real sizes: about 300 and 90 bytes of JSON.
    fn sized_heartbeat(seq: u32) -> String {
        format!(r#"{{"t":"hb","seq":{seq},"pad":"{}"}}"#, "h".repeat(270))
    }

    fn sized_cursor_report(seq: u32) -> String {
        format!(r#"{{"t":"cp","seq":{seq},"pad":"{}"}}"#, "c".repeat(60))
    }

    /// What tells the agent a sleeping viewer is out of reach, in [`sleep_and_wake`].
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum OutOfReach {
        /// The page said `vis hidden` as it went (the control task's `ViewerHidden(true)`), and on
        /// waking says `vis hidden: false` at once (then `ViewerHidden(false)`). ICE is left alone.
        PageHidden,
        /// Nothing is said; ICE notices the dead path (fast checks, an ICE-lite viewer), and on
        /// waking the viewer restarts ICE, as an iPhone does, and says nothing.
        PathLost,
    }

    /// One tick of the agent's writing: a cursor report every tick, a heartbeat every other.
    async fn write_tick(peer: &mut super::Peer, seq: &mut u32, tick: &mut u32) {
        peer.control_tx
            .send(PeerControl::SendCursor(sized_cursor_report(*seq)))
            .await
            .expect("control");
        *seq += 1;
        if tick.is_multiple_of(2) {
            peer.control_tx
                .send(PeerControl::SendHeartbeat(sized_heartbeat(*seq)))
                .await
                .expect("control");
            *seq += 1;
        }
        *tick += 1;
    }

    /// An iPhone viewer asleep, on loopback: the viewer sleeps 8 s while the agent writes a
    /// heartbeat a second and a cursor report twice a second at their real sizes, then wakes having
    /// lost everything sent meanwhile. How long after waking the first message the agent wrote after
    /// it took to arrive, and the `cursor channel` lines the agent logged.
    ///
    /// Without the lane it is the retransmission timer's next expiry: 1, 3 and 7 s into the sleep,
    /// and next at 15 — seven seconds after waking (measured: 7.2 s).
    async fn sleep_and_wake(how: OutOfReach) -> (Duration, Vec<String>) {
        const SLEEP: Duration = Duration::from_secs(8);
        const TICK: Duration = Duration::from_millis(500);
        let log = CapturedLog::default();
        let _log = log.install();
        let lite = how == OutOfReach::PathLost;
        let (mut viewer, offer, pending) = TestViewer::with_cursor(lite).await;
        let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind agent");
        let mut peer = spawn_peer_on(socket, &offer, vec![], loopback(ICE_GRACE, lite))
            .await
            .expect("a peer");
        viewer.accept(pending, &peer.answer_sdp);
        pump_until(&mut viewer, &mut peer.events, S(10), |e| {
            matches!(e, PeerEvent::Connected)
        })
        .await;

        // Awake: the channel carries.
        let mut seq = 0u32;
        let carried_by = Instant::now() + S(5);
        while viewer.heard.is_empty() {
            assert!(
                Instant::now() < carried_by,
                "the cursor channel never carried"
            );
            peer.control_tx
                .send(PeerControl::SendHeartbeat(sized_heartbeat(seq)))
                .await
                .expect("control");
            seq += 1;
            pump_for(&mut viewer, &mut peer.events, Duration::from_millis(200)).await;
        }

        // Asleep: the viewer neither reads nor answers. A page that says `vis hidden` says it as
        // it goes. (Said instead 2.4 s in — when the background hold's "asleep" would have it —
        // 1326 bytes are unacknowledged by then, the kick does not fit, and the
        // wait after waking is the timer's again: 7.2 s, measured.)
        if how == OutOfReach::PageHidden {
            peer.control_tx
                .send(PeerControl::ViewerHidden(true))
                .await
                .expect("control");
        }
        let mut tick = 0u32;
        let mut lost = false;
        let asleep_until = Instant::now() + SLEEP;
        while Instant::now() < asleep_until {
            write_tick(&mut peer, &mut seq, &mut tick).await;
            tokio::time::sleep(TICK).await;
            while let Ok(e) = peer.events.try_recv() {
                lost |= matches!(e, PeerEvent::LinkLost);
                assert!(
                    !matches!(e, PeerEvent::Disconnected { .. }),
                    "the peer ended while the viewer slept: {e:?}"
                );
            }
        }
        assert_eq!(
            lost,
            how == OutOfReach::PathLost,
            "ICE lost the path only where meant to"
        );

        // Awake again, having lost what came meanwhile.
        let forgotten = viewer.forget_inbox();
        assert!(
            forgotten > 0,
            "the agent sent something while the viewer slept"
        );
        let woke = Instant::now();
        let first_after_waking = seq;
        match how {
            OutOfReach::PageHidden => {
                // As in the agent: the `vis` arrives on the data channel first, and the control
                // task tells the peer the page is visible on its next tick, after the hold has it.
                viewer.say(r#"{"t":"vis","hidden":false}"#);
                pump_until(&mut viewer, &mut peer.events, S(3), |e| {
                    matches!(e, PeerEvent::InputData(_))
                })
                .await;
                peer.control_tx
                    .send(PeerControl::ViewerHidden(false))
                    .await
                    .expect("control");
            }
            OutOfReach::PathLost => {
                let (restart, pending) = viewer.restart_offer();
                signal(&peer, PeerSignal::Renegotiate(restart));
                let seen = pump_until(&mut viewer, &mut peer.events, S(3), |e| {
                    matches!(e, PeerEvent::Answer(_))
                })
                .await;
                viewer.accept(pending, &answer_in(&seen));
            }
        }
        let mut next_tick = woke;
        let heard_at = loop {
            if Instant::now() >= next_tick {
                write_tick(&mut peer, &mut seq, &mut tick).await;
                next_tick += TICK;
            }
            pump_for(&mut viewer, &mut peer.events, Duration::from_millis(50)).await;
            let heard = viewer
                .heard
                .iter()
                .find(|(_, text)| seq_of(text).is_some_and(|s| s >= first_after_waking));
            if let Some((at, _)) = heard {
                break *at;
            }
            assert!(
                woke.elapsed() < S(12),
                "nothing written after waking reached the viewer within 12 s"
            );
        };
        let waited = heard_at.saturating_duration_since(woke);
        // A little more, so the stall's end is in the log.
        pump_for(&mut viewer, &mut peer.events, Duration::from_millis(300)).await;
        peer.closer.close();
        let lines: Vec<String> = log
            .text()
            .lines()
            .filter(|l| l.contains("cursor channel"))
            .map(str::to_string)
            .collect();
        eprintln!("{how:?}: waited {waited:?} after waking; the lane said:");
        for line in &lines {
            eprintln!("{line}");
        }
        (waited, lines)
    }

    fn said(lines: &[String], what: &str) -> bool {
        lines.iter().any(|l| l.contains(what))
    }

    /// The page said `vis hidden` and slept; it wakes and says `vis` at once. The stall began on
    /// the hidden page's silence, the `vis` kicked it, and the first message written after waking
    /// arrives in tens of milliseconds, not at the retransmission timer's next expiry.
    #[tokio::test]
    async fn a_hidden_page_that_slept_hears_the_cursor_channel_again_as_soon_as_it_talks() {
        let (waited, lines) = sleep_and_wake(OutOfReach::PageHidden).await;
        assert!(
            waited < Duration::from_millis(500),
            "the first message written after waking took {waited:?} to arrive"
        );
        for what in [
            "cursor channel gate changed",
            "cursor channel stalled:",
            "why=\"page_hidden\"",
            "cursor channel kicked:",
            "cursor channel stall over:",
        ] {
            assert!(said(&lines, what), "no {what:?} line: {lines:#?}");
        }
    }

    /// Nothing said `vis`; ICE lost the path while the viewer slept, and the viewer restarted ICE
    /// on waking. The stall began when ICE lost the path, the restored path ended it, and the first
    /// message written after waking arrives as soon as the restart is through.
    #[tokio::test]
    async fn a_viewer_that_slept_through_a_lost_path_hears_the_cursor_channel_once_it_is_back() {
        let (waited, lines) = sleep_and_wake(OutOfReach::PathLost).await;
        assert!(
            waited < S(2),
            "the first message written after waking took {waited:?} to arrive, restart included"
        );
        for what in [
            "cursor channel stalled:",
            "why=\"path_lost\"",
            "how=\"viewer_reachable\"",
        ] {
            assert!(said(&lines, what), "no {what:?} line: {lines:#?}");
        }
    }

    /// The summary's `bytes_socket` counts what the socket took — the handshake and the media — and
    /// `bytes_relay` only what went to a relay candidate: none on a host-to-host loopback.
    #[tokio::test]
    async fn the_socket_bytes_count_what_the_socket_took() {
        let (mut viewer, mut peer, _offer) =
            connected(false, vec![], loopback(ICE_GRACE, false)).await;
        let after_connect = peer.socket_bytes.total();
        assert!(after_connect > 0, "the handshake went through the socket");
        pump_for(&mut viewer, &mut peer.events, Duration::from_millis(300)).await;
        assert!(
            peer.socket_bytes.total() >= after_connect,
            "never goes back"
        );
        assert_eq!(
            peer.socket_bytes.relay(),
            0,
            "no relay candidate on a loopback"
        );
        assert!(
            peer.socket_bytes.total() <= peer.egress_bytes_total.load(Ordering::Relaxed),
            "what the socket took is at most what str0m handed the loop"
        );
    }
}
