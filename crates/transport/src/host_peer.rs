//! A peer driven by its host: the host supplies the datagram socket and decides, through
//! [`PeerHooks`], which datagrams, candidates and data channels the peer accepts and what becomes of
//! the viewer's data-channel messages.
//!
//! The ordinary agent never uses this: [`crate::webrtc::spawn_peer`] binds its own UDP socket,
//! gathers its own candidates and hands every data-channel message to the orchestrator as
//! [`crate::webrtc::PeerEvent::InputData`]. A host with a different trust model — a relay it
//! allocated itself, an allow-list of candidates, its own input admission — starts the peer with
//! [`crate::webrtc::spawn_host_peer`] instead and keeps the media path (encoder feed, congestion
//! control, playout) exactly as the agent's.
//!
//! The hooks run on the peer's run loop: they must not block, wait on another task or hold a lock
//! across anything that can. Each is called at most once per event.

use std::future::Future;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::time::{Duration, Instant};

/// A boxed future a [`HostSocket`] returns.
pub type HostFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// The datagram socket a host-driven peer sends and receives on, in place of the UDP socket the
/// peer would bind itself (a TURN allocation the host owns, for example).
///
/// The peer never runs server-reflexive discovery here: [`crate::webrtc::spawn_host_peer`] asks no
/// STUN server, and a binding transaction on a host's socket is refused before it is sent.
///
/// If [`crate::webrtc::spawn_host_peer`] fails during setup (an offer str0m refuses,
/// [`PeerHooks::answer`] returning an error), neither [`Self::close`] nor [`PeerHooks::ended`] is
/// called: the socket and the hooks are dropped with the error, and releasing what the socket holds
/// is then up to its `Drop`.
pub trait HostSocket: Send + Sync {
    /// Send one datagram to `to`.
    fn send_to<'a>(&'a self, buf: &'a [u8], to: SocketAddr) -> HostFuture<'a, io::Result<usize>>;

    /// Receive one datagram. Must be cancel-safe: the run loop drops this future whenever another
    /// branch of its select wins, and nothing may be lost then.
    fn recv_from<'a>(
        &'a self,
        buf: &'a mut [u8],
    ) -> HostFuture<'a, io::Result<(usize, SocketAddr)>>;

    /// The address the viewer reaches this socket at (a relay's allocated address, say). The peer
    /// offers it as its one candidate, a relayed one whose base is [`HostPeerOptions::host_ip`],
    /// and uses it as its local address towards str0m.
    fn address(&self) -> SocketAddr;

    /// Release the socket. Called once, after the run loop has ended and [`PeerHooks::ended`];
    /// never when [`crate::webrtc::spawn_host_peer`] failed during setup (see the trait).
    fn close(&mut self) -> HostFuture<'_, ()>;
}

/// The role a host gives a data channel the viewer opened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelRole {
    /// The reliable `input` channel: the viewer's ordered messages, and the agent's reliable ones.
    Input,
    /// The `cursor` channel: superseded samples and the agent's cursor reports.
    Cursor,
    /// Not accepted: the peer disconnects.
    Refuse,
}

/// How a data channel the viewer opened delivers, as its SCTP configuration says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelDelivery {
    /// Ordered and reliable.
    ReliableOrdered,
    /// Unordered and never retransmitted.
    UnorderedLatest,
    /// Anything else, or a channel whose configuration could not be read.
    Other,
}

/// A data channel the viewer opened, as a host judges it.
#[derive(Debug, Clone, Copy)]
pub struct OpenedChannel<'a> {
    pub label: &'a str,
    pub delivery: ChannelDelivery,
    /// Whether a channel already holds the [`ChannelRole::Input`] or [`ChannelRole::Cursor`] role.
    pub input_taken: bool,
    pub cursor_taken: bool,
}

/// What the peer does after a host took a data-channel message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataVerdict {
    /// Go on.
    Continue,
    /// Disconnect the peer.
    Disconnect,
}

/// A host's decisions on a peer started with [`crate::webrtc::spawn_host_peer`].
///
/// With hooks, the peer never sends [`crate::webrtc::PeerEvent::InputData`],
/// [`crate::webrtc::PeerEvent::InputChannelClosed`] or resolves mDNS names on its own: the data
/// channels are the host's. Every method runs on the peer's run loop and must return promptly.
pub trait PeerHooks: Send {
    /// A datagram from `source`, before str0m sees it. `false` drops it.
    fn admit_datagram(&mut self, source: SocketAddr) -> bool;

    /// A candidate the viewer trickled, before str0m takes it; `local` is the peer's own address.
    /// `Err(reason)` ends the peer with that reason.
    fn admit_candidate(&mut self, candidate: &str, local: SocketAddr) -> Result<(), &'static str>;

    /// The viewer sent a new offer. `Err(reason)` ends the peer with that reason.
    fn admit_renegotiation(&mut self) -> Result<(), &'static str>;

    /// An mDNS host candidate the viewer signalled. `false` drops it without a lookup.
    fn admit_mdns(&mut self) -> bool;

    /// The SDP answer before it leaves; `local` is the peer's own address. An error ends the
    /// peer before it starts.
    fn answer(&mut self, answer: String, local: SocketAddr) -> anyhow::Result<String>;

    /// ICE reported the path lost.
    fn link_lost(&mut self);

    /// The run loop has ended; the socket closes next. Not called when
    /// [`crate::webrtc::spawn_host_peer`] failed during setup: the hooks are then dropped unused.
    fn ended(&mut self);

    /// The viewer opened a data channel. [`ChannelRole::Refuse`] disconnects the peer.
    fn channel_opened(&mut self, channel: OpenedChannel<'_>) -> ChannelRole;

    /// The channel holding `role` closed (never [`ChannelRole::Refuse`]).
    fn channel_closed(&mut self, role: ChannelRole);

    /// A message on the channel holding `role`, received at `received`.
    fn data(
        &mut self,
        role: ChannelRole,
        data: Vec<u8>,
        binary: bool,
        received: Instant,
    ) -> DataVerdict;

    /// A reliable message could not be written: the peer has closed the input channel and
    /// dropped what was still queued for it.
    fn reliable_lane_failed(&mut self);

    /// Whether a cursor report of `len` bytes may be written now, with `buffered` bytes already in
    /// the cursor channel's SCTP buffer. Reports a host refuses, or that do not fit, are dropped:
    /// with hooks there is no held cursor lane.
    fn cursor_report(&mut self, len: usize, buffered: usize) -> bool;

    /// Writing a cursor report failed: the peer has closed the cursor channel.
    fn cursor_lane_failed(&mut self);
}

/// str0m's schedule for ICE connectivity checks, when the caller needs its own.
#[derive(Debug, Clone, Copy)]
pub struct IceTiming {
    pub initial_rto: Duration,
    pub max_rto: Duration,
    pub retransmits: usize,
}

/// What a host-driven peer would otherwise decide from the machine.
#[derive(Debug, Clone)]
pub struct HostPeerOptions {
    /// The base of the relayed candidate the peer offers ([`HostSocket::address`]), as the answer
    /// names it. Not offered as a candidate itself.
    pub host_ip: Ipv4Addr,
    /// The port the host's socket is bound to locally.
    pub bound_port: u16,
    /// How long the session waits for ICE to come back after it reports the path lost.
    pub ice_grace: Duration,
    /// `None` keeps str0m's own schedule.
    pub ice_timing: Option<IceTiming>,
}
