//! A model of one direction of a network path, and the seeded generator it draws from.
//!
//! Pure: a [`link::Link`] is a function of the datagrams handed to it, the clock readings they are
//! handed with and its seed. It keeps no timer and reads no clock of its own — the caller says what
//! time it is — so the same model runs on two very different clocks:
//!
//! * **virtual time** in `afklink-sim`, where a minute of session is simulated in a fraction of that;
//! * **real time** in the agent's bench link shaper (`afklink_transport::shaper`), where the clock
//!   is `Instant::now()` minus the moment the shaper started and the datagrams are real ones on the
//!   peer's UDP socket.
//!
//! Extracted from `afklink-sim` so the bench and the simulator shape traffic with one model rather
//! than two that could drift apart: a profile that says "700 kbps, 80 ms queue, 1% loss" means the
//! same thing in a simulated session and on the wire.

pub mod link;
pub mod rng;

pub use link::{
    describe_capacity, parse_mahimahi, Capacity, Datagram, Link, LinkConfig, LinkStats, LinkWindow,
    Loss, LossAt, QueueLimit,
};
pub use rng::SimRng;
