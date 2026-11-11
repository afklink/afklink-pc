//! The simulator's own random numbers: seeded, versioned, and nothing else's.
//!
//! The generator itself ([`SimRng`], xoshiro256** seeded through SplitMix64) lives in
//! `afklink-netem` with the link model that draws from it; see there for why it is not `rand`. What
//! stays here is the simulator's own knowledge: which named streams a scenario seed splits into.
//!
//! str0m's own randomness (SSRCs, sequence starts, ICE credentials) is a separate matter, handled
//! by seeding fastrand's thread-local generator; see `crate::sim`.

pub use afklink_netem::rng::SimRng;

/// Distinct streams derived from one scenario seed, so the uplink's losses do not shift when the
/// downlink draws one more number.
pub mod stream {
    pub const LINK_UP: u64 = 0x5550_4c49_4e4b_0001;
    pub const LINK_DOWN: u64 = 0x444f_574e_4c4b_0002;
    pub const CONTENT: u64 = 0x434f_4e54_454e_0003;
    pub const STR0M: u64 = 0x5354_5230_4d00_0004;
}

#[cfg(test)]
mod tests {
    use super::{stream, SimRng};

    #[test]
    fn derived_streams_are_independent_of_each_other() {
        let mut up = SimRng::derive(7, stream::LINK_UP);
        let mut down = SimRng::derive(7, stream::LINK_DOWN);
        assert_ne!(up.next_u64(), down.next_u64());
    }
}
