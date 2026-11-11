//! Transport layer for the AFKLink agent: WebSocket signaling
//! and the WebRTC answerer peer.
//!
//! Message types are no longer defined here. They live in `afklink-protocol`,
//! which is generated from and tested against the shared contract in
//! `packages/protocol`; this crate only re-exports them so call sites keep one
//! import path.

mod cursor_lane;
pub mod host_peer;
pub mod mdns;
mod paths;
pub mod peer_signal;
mod playout;
pub mod shaper;
pub mod signaling;
mod socket;
pub mod socket_bytes;
mod stun;
pub mod timer;
pub mod webrtc;

pub use afklink_protocol::{
    AgentSessionStats, AgentToServer, BindingInfo, GoodbyeReason, IceCandidate, SdpType,
    ServerToAgent, TurnCreds, MIN_SUPPORTED_PROTOCOL, PROTOCOL_VERSION,
};
pub use peer_signal::{
    signal_queue, PeerSignal, SignalCounts, SignalReceiver, SignalSender, SignalSent,
    SIGNAL_QUEUE_CAP,
};
pub use shaper::{LinkProfile, LinkShaper};
pub use signaling::{
    connect, connect_with, ConnectFailed, ConnectFailure, ConnectStage, EndCause, GoodbyeHandle,
    GoodbyeResult, GoodbyeTicket, HandshakeRefused, HandshakeSilent, HelloInfo, LinkEnd,
    LinkHealth, Signaling, SignalingConfig, Signer,
};
pub use socket_bytes::SocketBytes;
pub use stun::stun_servers;
pub use webrtc::{
    spawn_peer, spawn_peer_with, CloseCause, CloseSignal, KeyframeAsk, MediaSample, Peer,
    PeerCloser, PeerControl, PeerEnd, PeerEvent, PeerPath, PeerPathCell, ViewerPlayout, ICE_GRACE,
    QUEUE_HARD_LIMIT_MS, QUEUE_RESUME_MS,
};
