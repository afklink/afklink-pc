//! The model's own random numbers: seeded, versioned by this file, and nothing else's.
//!
//! Not `rand`, on purpose. A simulator's output has to be a function of its scenario and its seed,
//! and a dependency's generator can change its stream in a minor release. xoshiro256** seeded
//! through SplitMix64 is twenty lines, has no state beyond four words, and will produce the same
//! sequence for the same seed for as long as this file does.
//!
//! Moved here from `afklink-sim` together with the link model; the simulator's named streams
//! (`afklink_sim::rng::stream`) stay in the simulator, which is the only thing that knows them.

/// xoshiro256** (Blackman & Vigna), seeded from a single `u64` through SplitMix64.
#[derive(Debug, Clone)]
pub struct SimRng {
    s: [u64; 4],
}

impl SimRng {
    #[must_use]
    pub fn new(seed: u64) -> Self {
        let mut sm = seed;
        let mut next = || {
            sm = sm.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = sm;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        };
        Self {
            s: [next(), next(), next(), next()],
        }
    }

    /// A generator for one named purpose, derived from a seed and a stream constant.
    #[must_use]
    pub fn derive(seed: u64, stream: u64) -> Self {
        Self::new(seed ^ stream.rotate_left(17).wrapping_mul(0x9E37_79B9_7F4A_7C15))
    }

    pub fn next_u64(&mut self) -> u64 {
        let result = self.s[1].wrapping_mul(5).rotate_left(7).wrapping_mul(9);
        let t = self.s[1] << 17;
        self.s[2] ^= self.s[0];
        self.s[3] ^= self.s[1];
        self.s[1] ^= self.s[2];
        self.s[0] ^= self.s[3];
        self.s[2] ^= t;
        self.s[3] = self.s[3].rotate_left(45);
        result
    }

    /// Uniform in `[0, 1)`, 53 bits.
    pub fn next_f64(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 * (1.0 / (1u64 << 53) as f64)
    }

    /// `true` with probability `p`. Draws a number only when `p` is strictly between 0 and 1, so a
    /// lossless link consumes nothing from its stream.
    pub fn chance(&mut self, p: f64) -> bool {
        if p <= 0.0 {
            false
        } else if p >= 1.0 {
            true
        } else {
            self.next_f64() < p
        }
    }

    /// Uniform in `0..n`; `0` when `n` is `0`.
    pub fn below(&mut self, n: u64) -> u64 {
        if n == 0 {
            0
        } else {
            self.next_u64() % n
        }
    }
}

#[cfg(test)]
mod tests {
    use super::SimRng;

    #[test]
    fn a_seed_is_a_sequence() {
        let mut a = SimRng::new(42);
        let mut b = SimRng::new(42);
        let xs: Vec<u64> = (0..64).map(|_| a.next_u64()).collect();
        let ys: Vec<u64> = (0..64).map(|_| b.next_u64()).collect();
        assert_eq!(xs, ys);
        let mut c = SimRng::new(43);
        assert_ne!(xs[0], c.next_u64());
    }

    #[test]
    fn derived_streams_differ() {
        let mut up = SimRng::derive(7, 1);
        let mut down = SimRng::derive(7, 2);
        assert_ne!(up.next_u64(), down.next_u64());
    }

    #[test]
    fn unit_interval_and_chance_behave() {
        let mut r = SimRng::new(1);
        let mut hits = 0u32;
        for _ in 0..100_000 {
            let x = r.next_f64();
            assert!((0.0..1.0).contains(&x));
            if r.chance(0.1) {
                hits += 1;
            }
        }
        assert!((9_000..11_000).contains(&hits), "{hits}");
        assert!(!r.chance(0.0));
        assert!(r.chance(1.0));
    }
}
