//! The viewer: str0m as a recvonly H.264 peer standing in for Chrome in the Mini App.
//!
//! It produces what the agent's congestion control and controller consume — transport-wide
//! feedback, receiver reports, NACKs and PLIs — and it records when each frame became complete,
//! which is all the delivery-timing metrics need. It does not decode (see `crate::metrics` for where
//! a decoder and a picture-quality metric would plug in).
//!
//! ## Which str0m
//!
//! The viewer's str0m is chosen per run ([`ViewerStr0m`]), apart from the agent's: 0.23.1 or 0.24.1
//! (`[viewer] str0m = "0.23.1"` in a scenario, or `AFKLINK_SIM_VIEWER_STR0M` for every scenario a
//! process runs that does not name one). The real viewers are Chrome and WebKit, and neither str0m
//! is either of them; the switch exists so that a change of the agent's str0m can be measured with
//! the viewer held still — what moves then is the sender's doing, and the sender is what Chrome and
//! WebKit meet. The two receivers are one code path (`str0m_receiver!`) that differs only in the
//! crate it names and 0.24's frame-release deadline, which is turned off so the release is 0.23's.
//!
//! ## Where str0m's receiver is not Chrome's, in ways the sender's BWE can feel
//!
//! | behaviour | str0m receiver (0.23.1 lines unless 0.24.1 is named) | Chrome (libwebrtc) | here |
//! |---|---|---|---|
//! | A frame behind a hole | 0.23.1: held until 30 complete frames queue after it (`reordering_size_video`), then released non-contiguous. 0.24.1 adds a per-frame deadline, default 2 s (`RtcConfig::set_reordering_timeout_video`): an incomplete frame at the front is dropped at its deadline and nothing behind it is released before that (`packet/buffer_rx.rs:281-370,561-580`) | assembles each complete frame as it comes; asks for a keyframe after 200 ms without a decodable one | **0.23.1's count-only release on both** (0.24.1 with `set_reordering_timeout_video(None)`): at 60 fps the 2 s deadline holds decodable frames ~4x longer than the count did, at 1-7 fps it holds them shorter; neither is Chrome |
//! | Receive state across a pause | 0.23.1: a stream that has received nothing for 1.5 s (`pause_threshold`) drops its depacketizer's partial frames (`session.rs:827-837`). 0.24.1 keeps them (#1057) and leaves an incomplete frame to the frame-release deadline or the depacketizing queue's bound (`packet/buffer_rx.rs`) | keeps the stream; the jitter buffer and NACK module run on | as the chosen version does; matters only where the media stops for longer than that — the background hold, a guard that withholds frames |
//! | Receiver report loss | `fraction_lost` wraps to ~98 % when RTX repairs land in a later report interval (`streams/register.rs:224-242`, both versions; fixed upstream after 0.24.1, #1065) | clamps a negative interval loss to 0 | not worked around: a lossy scenario can show a lone ~98 % report (`3g-0919` at 54.1 s), which the brake reads as real |
//! | TWCC feedback cadence | every 50 ms while there is unreported traffic (`session.rs:47`, `:1120-1127`) | adaptive, `clamp(feedback_size / (5% of receive rate), 50 ms, 250 ms)` — 50 ms at the rates that matter, up to 250 ms on a thin link (`RemoteEstimatorProxy` / transport feedback generator) | not configurable (a private constant); matches Chrome above roughly 100 kbps, reports up to 5x more often below |
//! | Receiver report interval | fixed `rtcp_report_interval_video`, default 1 s (`config.rs:764-766`) | ~1 s for video, randomised to [0.5, 1.5] x | [`ViewerConfig::rr_interval`], default 1 s, no randomisation |
//! | NACK timing | every missing packet in a 100-packet window, re-sent every 33 ms (`NACK_MIN_INTERVAL`, `session.rs:44`) up to 5 times (`register_nack.rs:9`), no RTT spacing | first NACK on the gap, retries spaced by the RTT, up to 10, give-up and keyframe request past limits (`NackRequester`) | on/off only ([`ViewerConfig::nack`]); str0m has no NACK timing knob. On a 136 ms path str0m NACKs a packet ~4 times before the first retransmission can arrive, and the sender resends each time, so retransmission bytes are overstated on lossy links |
//! | Keyframe requests | never on its own; the application asks | the frame buffer asks when a delta frame's reference is missing, and again every 200 ms (`max_wait_for_keyframe`) until a keyframe arrives | [`ViewerConfig::pli_on_gap`], [`ViewerConfig::pli_repeat`]: a PLI when str0m marks a frame non-contiguous, repeated until a keyframe; frames in between are not displayed |
//! | Jitter buffer / playout delay | none | adaptive, honouring the playout-delay header | not modelled: "displayed" means complete and decodable |
//! | Data channels | — | the input channel, heartbeats | not modelled |
//!
//! The receiver also offers the two extensions the agent asks for (playout-delay id 5,
//! video-content-type id 6), because Chrome's offer carries them, so the answer negotiates the same
//! header bytes the real session puts on every packet. Offer and answer cross as SDP text, as they
//! do over the agent's signalling (`webrtc.rs`, `SdpOffer::from_sdp_string`).

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use anyhow::Result;

use crate::clock::VirtualClock;
use crate::link::Datagram;

/// Which str0m runs the viewer. See the module documentation, "Which str0m".
///
/// ## Why 0.23.1 by default
///
/// It is the viewer every scenario and threshold in `tests/` was written and checked against, and
/// the closer Chrome where the two differ in a way the tests feel. Measured with the
/// agent on str0m 0.23.1 and only the viewer changed, one run each:
///
/// - `3g-0919`: a hole at 92 s that the NACKs did not fill held every frame behind it for 24 s on
///   0.24.1 — the keyframes the PLIs asked for included (59 encoded against 14) — and the latency
///   p95/max went from 1069/1781 to 16159/17200 ms. 0.23.1 let the next keyframe through 0.9 s
///   after its hole, as Chrome's frame buffer would.
/// - the page that sleeps behind UDP (`tests/hold.rs`): 0.24.1, which keeps its receive state
///   across the 30 s pause (#1057), handed over a delta frame marked non-contiguous 1.1 s after the
///   resume; its PLI's second keyframe dipped the budget to 1515 kbps from 1697, past the test's
///   10 %. 0.23.1, which drops that state at the pause, did not, and the budget held at 1697.
///
/// Both are the receiver's doing: the same agent passes both tests with 0.23.1. A change of the
/// viewer's str0m is a change of the simulated Chrome, to be made on its own and measured as such,
/// not along with the agent's.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ViewerStr0m {
    /// str0m 0.23.1 (`str0m_023` in `Cargo.toml`).
    #[default]
    V0_23,
    /// str0m 0.24.1, the agent's own, with 0.23's count-only frame release.
    V0_24,
}

impl ViewerStr0m {
    /// The variable that picks the viewer's str0m for every scenario that does not name one: `0.23`,
    /// `0.23.1`, `0.24` or `0.24.1`.
    pub const ENV: &'static str = "AFKLINK_SIM_VIEWER_STR0M";

    /// `0.23`, `0.23.1`, `0.24` or `0.24.1`.
    pub fn parse(s: &str) -> Result<Self> {
        match s.trim() {
            "0.23" | "0.23.1" => Ok(Self::V0_23),
            "0.24" | "0.24.1" => Ok(Self::V0_24),
            other => {
                anyhow::bail!("the viewer's str0m must be \"0.23.1\" or \"0.24.1\", not {other:?}")
            }
        }
    }

    /// The scenario's choice if it made one, else [`Self::ENV`], else the default.
    pub fn resolve(scenario: Option<&str>) -> Result<Self> {
        if let Some(s) = scenario {
            return Self::parse(s);
        }
        match std::env::var(Self::ENV) {
            Ok(v) => Self::parse(&v).map_err(|e| anyhow::anyhow!("{}: {e}", Self::ENV)),
            Err(std::env::VarError::NotPresent) => Ok(Self::default()),
            Err(e) => anyhow::bail!("{}: {e}", Self::ENV),
        }
    }

    /// The crate version, as the log and the summary print it.
    #[must_use]
    pub fn version(self) -> &'static str {
        match self {
            Self::V0_23 => "0.23.1",
            Self::V0_24 => "0.24.1",
        }
    }
}

impl std::fmt::Display for ViewerStr0m {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.version())
    }
}

/// How the simulated viewer behaves where str0m and Chrome differ. See the module documentation.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ViewerConfig {
    pub rr_interval: Duration,
    pub nack: bool,
    pub pli_on_gap: bool,
    pub pli_repeat: Duration,
    pub str0m: ViewerStr0m,
}

impl Default for ViewerConfig {
    fn default() -> Self {
        Self {
            rr_interval: Duration::from_secs(1),
            nack: true,
            pli_on_gap: true,
            pli_repeat: Duration::from_millis(200),
            str0m: ViewerStr0m::default(),
        }
    }
}

/// One frame the viewer's str0m emitted.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ViewerFrame {
    /// When the frame became complete (virtual time).
    pub at: Duration,
    /// The RTP timestamp: the agent's encode-start milliseconds times 90.
    pub rtp: u32,
    pub bytes: usize,
    pub keyframe: bool,
    pub contiguous: bool,
    /// Complete and decodable: not waiting for a keyframe after a hole.
    pub displayed: bool,
}

/// What one `poll_output` of the viewer's str0m gave, in terms neither version owns.
#[derive(Debug)]
enum Polled {
    Timeout(Instant),
    Transmit(Datagram),
    Connected,
    /// The offer's video m-line is known by its mid.
    VideoAdded(String),
    Frame {
        rtp: u32,
        bytes: usize,
        keyframe: bool,
        contiguous: bool,
    },
    IceState(String),
    /// An event the viewer does not act on.
    Other,
}

/// What the viewer asks of its str0m, whichever version runs it. One implementation per version,
/// both from `str0m_receiver!`.
trait Receiver {
    /// One recvonly video transceiver, as the Mini App's (`webrtc.rs:2792-2803` builds the same
    /// shape for its tests, minus the data channel); the offer as SDP text.
    fn create_offer(&mut self) -> Result<String>;
    fn accept_answer(&mut self, answer: &str) -> Result<()>;
    /// A datagram from the agent. One str0m cannot parse is logged and skipped.
    fn handle_receive(&mut self, at: Instant, source: SocketAddr, contents: &[u8]) -> Result<()>;
    fn handle_timeout(&mut self, at: Instant) -> Result<()>;
    fn poll(&mut self) -> Result<Polled>;
    /// Whether the video m-line's mid is known.
    fn has_video(&self) -> bool;
    /// A PLI on the video stream, or why none went out.
    fn request_pli(&mut self) -> Result<()>;
    /// Whether the receive stream was there to have its NACKs suppressed.
    fn suppress_nack(&mut self) -> bool;
}

/// One str0m version's [`Receiver`], configured as the viewer always was: H.264 only, the agent's
/// two header extensions, the scenario's report interval, and 0.23.1's count-only frame release.
/// `$configure` (a function, by its path from inside the generated module) is applied to the
/// builder before it is built — what one version needs that the other does not have.
macro_rules! str0m_receiver {
    ($module:ident, $str0m:ident, $configure:path) => {
        mod $module {
            use std::net::SocketAddr;
            use std::sync::Arc;
            use std::time::{Duration, Instant};

            use anyhow::{Context, Result};
            use $str0m::change::{SdpAnswer, SdpOffer, SdpPendingOffer};
            use $str0m::media::{Direction, KeyframeRequestKind, MediaKind, Mid};
            use $str0m::net::{DatagramRecv, Protocol, Receive};
            use $str0m::rtp::Extension;
            use $str0m::{Candidate, Event, Input, Output, Rtc, RtcConfig};

            use super::{Polled, Receiver};
            use crate::link::Datagram;
            use crate::transport::{EXT_ID_PLAYOUT_DELAY, EXT_ID_VIDEO_CONTENT_TYPE};

            pub(super) struct Peer {
                rtc: Rtc,
                local: SocketAddr,
                mid: Option<Mid>,
                pending: Option<SdpPendingOffer>,
            }

            impl Peer {
                pub(super) fn new(
                    start: Instant,
                    local: SocketAddr,
                    rr_interval: Duration,
                ) -> Result<Self> {
                    let configure: fn(RtcConfig) -> RtcConfig = $configure;
                    let config = Rtc::builder()
                        .set_crypto_provider(Arc::new($str0m::crypto::from_feature_flags()))
                        .clear_codecs()
                        .enable_h264(true)
                        .set_extension(EXT_ID_PLAYOUT_DELAY, Extension::PlayoutDelay)
                        .set_extension(EXT_ID_VIDEO_CONTENT_TYPE, Extension::VideoContentType)
                        .set_rtcp_report_interval_video(rr_interval);
                    let mut rtc = configure(config).build(start);
                    let cand = Candidate::host(local, "udp").context("viewer host candidate")?;
                    rtc.add_local_candidate(cand);
                    Ok(Self {
                        rtc,
                        local,
                        mid: None,
                        pending: None,
                    })
                }
            }

            impl Receiver for Peer {
                fn create_offer(&mut self) -> Result<String> {
                    let mut api = self.rtc.sdp_api();
                    // The offerer learns its mid here: str0m raises `MediaAdded` only for media
                    // the remote side added.
                    let mid = api.add_media(MediaKind::Video, Direction::RecvOnly, None, None, None);
                    let (offer, pending): (SdpOffer, SdpPendingOffer) =
                        api.apply().context("viewer: nothing to offer")?;
                    self.mid = Some(mid);
                    self.pending = Some(pending);
                    tracing::debug!(%mid, "viewer: video transceiver offered");
                    Ok(offer.to_sdp_string())
                }

                fn accept_answer(&mut self, answer: &str) -> Result<()> {
                    let pending = self
                        .pending
                        .take()
                        .context("viewer: an answer without an offer")?;
                    let answer =
                        SdpAnswer::from_sdp_string(answer).context("viewer: parse the answer")?;
                    self.rtc
                        .sdp_api()
                        .accept_answer(pending, answer)
                        .context("viewer: accept answer")
                }

                fn handle_receive(
                    &mut self,
                    at: Instant,
                    source: SocketAddr,
                    contents: &[u8],
                ) -> Result<()> {
                    match DatagramRecv::try_from(contents) {
                        Ok(contents) => {
                            let recv = Receive {
                                proto: Protocol::Udp,
                                source,
                                destination: self.local,
                                contents,
                            };
                            self.rtc
                                .handle_input(Input::Receive(at, recv))
                                .context("viewer: handle receive")
                        }
                        Err(e) => {
                            tracing::debug!("viewer: undecodable datagram skipped: {e:?}");
                            Ok(())
                        }
                    }
                }

                fn handle_timeout(&mut self, at: Instant) -> Result<()> {
                    self.rtc
                        .handle_input(Input::Timeout(at))
                        .context("viewer: handle timeout")
                }

                fn poll(&mut self) -> Result<Polled> {
                    Ok(match self.rtc.poll_output().context("viewer: poll_output")? {
                        Output::Timeout(t) => Polled::Timeout(t),
                        Output::Transmit(t) => Polled::Transmit(Datagram {
                            source: t.source,
                            destination: t.destination,
                            contents: t.contents.to_vec(),
                        }),
                        Output::Event(Event::Connected) => Polled::Connected,
                        Output::Event(Event::MediaAdded(m)) if m.kind == MediaKind::Video => {
                            self.mid = Some(m.mid);
                            Polled::VideoAdded(m.mid.to_string())
                        }
                        Output::Event(Event::MediaData(md)) => Polled::Frame {
                            rtp: (md.time.numer() & 0xffff_ffff) as u32,
                            bytes: md.data.len(),
                            keyframe: md.is_keyframe(),
                            contiguous: md.contiguous,
                        },
                        Output::Event(Event::IceConnectionStateChange(state)) => {
                            Polled::IceState(format!("{state:?}"))
                        }
                        Output::Event(_) => Polled::Other,
                    })
                }

                fn has_video(&self) -> bool {
                    self.mid.is_some()
                }

                fn request_pli(&mut self) -> Result<()> {
                    let mid = self.mid.context("no video mid")?;
                    let mut writer = self
                        .rtc
                        .writer(mid)
                        .context("str0m has no writer for the mid")?;
                    writer
                        .request_keyframe(None, KeyframeRequestKind::Pli)
                        .map_err(|e| anyhow::anyhow!("{e}"))
                }

                fn suppress_nack(&mut self) -> bool {
                    let Some(mid) = self.mid else {
                        return false;
                    };
                    let mut api = self.rtc.direct_api();
                    match api.stream_rx_by_mid(mid, None) {
                        Some(s) => {
                            s.suppress_nack(true);
                            true
                        }
                        None => false,
                    }
                }
            }
        }
    };
}

/// What str0m 0.24.1's receiver is built with beyond what both share: count-only frame release, as
/// 0.23.1 does it. 0.24's 2 s per-frame deadline is a new viewer model, not the agent's doing
/// (module table, "A frame behind a hole").
fn configure_024(c: str0m::RtcConfig) -> str0m::RtcConfig {
    c.set_reordering_timeout_video(None)
}

/// str0m 0.23.1's receiver needs nothing beyond what both share.
fn configure_023(c: str0m_023::RtcConfig) -> str0m_023::RtcConfig {
    c
}

str0m_receiver!(receiver_024, str0m, super::configure_024);
str0m_receiver!(receiver_023, str0m_023, super::configure_023);

/// The viewer peer.
pub struct Viewer {
    peer: Box<dyn Receiver>,
    pub local: SocketAddr,
    cfg: ViewerConfig,
    connected: bool,
    nack_applied: bool,
    suppress_pending: bool,
    pli_pending: Option<&'static str>,
    /// A hole was seen and no keyframe has arrived since. Starts true: nothing is decodable before
    /// the first keyframe.
    waiting_keyframe: bool,
    last_pli: Option<Duration>,
    pub plis_sent: u64,
    /// When each PLI was sent, for the summary's recoveries (`crate::metrics::recoveries`).
    pub pli_times: Vec<Duration>,
    pub frames: Vec<ViewerFrame>,
    pub next_wake: Option<Duration>,
}

impl std::fmt::Debug for Viewer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Viewer")
            .field("local", &self.local)
            .field("str0m", &self.cfg.str0m)
            .field("connected", &self.connected)
            .field("frames", &self.frames.len())
            .field("waiting_keyframe", &self.waiting_keyframe)
            .finish()
    }
}

impl Viewer {
    pub fn new(clock: &VirtualClock, local: SocketAddr, cfg: ViewerConfig) -> Result<Self> {
        let peer: Box<dyn Receiver> = match cfg.str0m {
            ViewerStr0m::V0_23 => Box::new(receiver_023::Peer::new(
                clock.instant(),
                local,
                cfg.rr_interval,
            )?),
            ViewerStr0m::V0_24 => Box::new(receiver_024::Peer::new(
                clock.instant(),
                local,
                cfg.rr_interval,
            )?),
        };
        tracing::debug!(
            %local,
            str0m = %cfg.str0m,
            rr_interval_ms = cfg.rr_interval.as_millis() as u64,
            nack = cfg.nack,
            pli_on_gap = cfg.pli_on_gap,
            pli_repeat_ms = cfg.pli_repeat.as_millis() as u64,
            frame_release = "count-only (no reordering timeout)",
            "viewer peer built"
        );
        Ok(Self {
            peer,
            local,
            cfg,
            connected: false,
            nack_applied: false,
            suppress_pending: false,
            pli_pending: None,
            waiting_keyframe: true,
            last_pli: None,
            plis_sent: 0,
            pli_times: Vec::new(),
            frames: Vec::new(),
            next_wake: Some(clock.now()),
        })
    }

    /// The viewer's offer, as SDP text: one recvonly video transceiver.
    pub fn create_offer(&mut self) -> Result<String> {
        self.peer.create_offer()
    }

    /// The agent's answer, as SDP text.
    pub fn accept_answer(&mut self, answer: &str) -> Result<()> {
        self.peer.accept_answer(answer)
    }

    pub fn receive(
        &mut self,
        clock: &VirtualClock,
        d: &Datagram,
        out: &mut Vec<Datagram>,
    ) -> Result<()> {
        self.peer
            .handle_receive(clock.instant(), d.source, &d.contents)?;
        self.settle(clock, out)
    }

    pub fn timer(&mut self, clock: &VirtualClock, out: &mut Vec<Datagram>) -> Result<()> {
        self.peer.handle_timeout(clock.instant())?;
        self.settle(clock, out)
    }

    /// When the next keyframe re-request is due, while waiting for one.
    #[must_use]
    pub fn pli_due(&self) -> Option<Duration> {
        if !(self.cfg.pli_on_gap && self.waiting_keyframe && self.peer.has_video()) {
            return None;
        }
        // Before any request has been made, the first one waits for the first frame to tell us
        // whether a hole exists; see `on_frame`.
        self.last_pli.map(|t| t + self.cfg.pli_repeat)
    }

    /// Re-request a keyframe if one is still owed.
    pub fn pli_timer(&mut self, clock: &VirtualClock, out: &mut Vec<Datagram>) -> Result<()> {
        if self.pli_due().is_some_and(|t| t <= clock.now()) {
            self.request_keyframe(clock, "still waiting for a keyframe");
        }
        self.settle(clock, out)
    }

    fn request_keyframe(&mut self, clock: &VirtualClock, why: &'static str) {
        match self.peer.request_pli() {
            Ok(()) => {
                self.plis_sent += 1;
                self.pli_times.push(clock.now());
                self.last_pli = Some(clock.now());
                tracing::debug!(at_s = clock.now().as_secs_f64(), why, "viewer: PLI");
            }
            Err(e) => tracing::debug!(why, "viewer: PLI not sent: {e:#}"),
        }
    }

    /// Drain after any input, act on what the frames said (outside the poll loop, so str0m sees
    /// one mutation at a time), then schedule the next wake.
    fn settle(&mut self, clock: &VirtualClock, out: &mut Vec<Datagram>) -> Result<()> {
        let now = clock.now();
        let before = out.len();
        let mut timeout = self.drain(clock, out)?;
        if self.suppress_pending && !self.nack_applied {
            self.suppress_pending = false;
            if self.peer.suppress_nack() {
                self.nack_applied = true;
                tracing::debug!("viewer: NACKs suppressed");
            } else {
                tracing::debug!("viewer: NACKs not suppressed yet: no receive stream for the mid");
            }
            timeout = self.drain(clock, out)?;
        }
        if let Some(why) = self.pli_pending.take() {
            self.request_keyframe(clock, why);
            timeout = self.drain(clock, out)?;
        }
        let produced = out.len() > before;
        let t = clock.offset_of(timeout);
        self.next_wake =
            if timeout.saturating_duration_since(clock.instant()) > Duration::from_secs(3600) {
                None
            } else if t > now {
                Some(t)
            } else if produced {
                Some(now + Duration::from_micros(1))
            } else {
                Some(now + Duration::from_millis(1))
            };
        Ok(())
    }

    fn drain(&mut self, clock: &VirtualClock, out: &mut Vec<Datagram>) -> Result<Instant> {
        loop {
            match self.peer.poll()? {
                Polled::Timeout(t) => return Ok(t),
                Polled::Transmit(d) => out.push(d),
                Polled::Connected => {
                    self.connected = true;
                    tracing::info!(
                        at_s = clock.now().as_secs_f64(),
                        str0m = %self.cfg.str0m,
                        "viewer: connected"
                    );
                }
                Polled::VideoAdded(mid) => {
                    tracing::debug!(%mid, "viewer: video m-line added");
                }
                Polled::Frame {
                    rtp,
                    bytes,
                    keyframe,
                    contiguous,
                } => {
                    if !self.nack_applied && !self.cfg.nack {
                        self.suppress_pending = true;
                    }
                    self.on_frame(clock, rtp, bytes, keyframe, contiguous);
                }
                Polled::IceState(state) => {
                    tracing::debug!(%state, at_s = clock.now().as_secs_f64(), "viewer: ICE state");
                }
                Polled::Other => {}
            }
        }
    }

    /// Chrome's frame buffer, reduced to what decides display: a non-contiguous delta frame cannot
    /// be decoded, so ask for a keyframe and show nothing until one arrives.
    fn on_frame(
        &mut self,
        clock: &VirtualClock,
        rtp: u32,
        bytes: usize,
        keyframe: bool,
        contiguous: bool,
    ) {
        let now = clock.now();
        if keyframe {
            if self.waiting_keyframe {
                tracing::debug!(
                    at_s = now.as_secs_f64(),
                    "viewer: keyframe, decodable again"
                );
            }
            self.waiting_keyframe = false;
        } else if !contiguous || self.waiting_keyframe {
            if !self.waiting_keyframe {
                tracing::debug!(
                    at_s = now.as_secs_f64(),
                    "viewer: a hole in the stream the NACKs did not fill; the picture freezes"
                );
            }
            self.waiting_keyframe = true;
            if self.cfg.pli_on_gap && self.last_pli.is_none_or(|t| now >= t + self.cfg.pli_repeat) {
                self.pli_pending = Some("delta frame without its reference");
            }
        }
        let displayed = !self.waiting_keyframe;
        self.frames.push(ViewerFrame {
            at: now,
            rtp,
            bytes,
            keyframe,
            contiguous,
            displayed,
        });
        tracing::trace!(
            at_s = now.as_secs_f64(),
            rtp,
            bytes,
            keyframe,
            contiguous,
            displayed,
            "viewer: frame"
        );
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::ViewerStr0m;

    #[test]
    fn the_viewers_str0m_is_named_by_version() {
        assert_eq!(ViewerStr0m::parse("0.23.1").unwrap(), ViewerStr0m::V0_23);
        assert_eq!(ViewerStr0m::parse("0.23").unwrap(), ViewerStr0m::V0_23);
        assert_eq!(ViewerStr0m::parse(" 0.24.1 ").unwrap(), ViewerStr0m::V0_24);
        assert_eq!(ViewerStr0m::parse("0.24").unwrap(), ViewerStr0m::V0_24);
        assert!(ViewerStr0m::parse("0.25").is_err());
        assert_eq!(
            ViewerStr0m::resolve(Some("0.24.1")).unwrap(),
            ViewerStr0m::V0_24,
            "a scenario's choice wins over the environment"
        );
        assert_eq!(ViewerStr0m::V0_23.to_string(), "0.23.1");
    }
}
