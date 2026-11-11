//! One direction of the network path: a bottleneck with a capacity schedule, a drop-tail queue in
//! front of it, random loss, propagation delay and jitter.
//!
//! The model lives in `afklink-netem` (see [`afklink_netem::link`] for the whole description), so
//! the simulator and the agent's real-time bench link shaper (`afklink_transport::shaper`) shape
//! traffic with the same code. The simulator drives it on its virtual clock and runs the ICE/DTLS
//! handshake in the link's ideal mode, for the reason given there.

pub use afklink_netem::link::*;
