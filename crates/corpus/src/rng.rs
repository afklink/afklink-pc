//! A small seeded generator, so a scenario is a pure function of its parameters.
//!
//! SplitMix64 rather than a crate: the sequence for a seed must never change under a dependency
//! bump, or a corpus regenerated next month would silently differ from the one a result was
//! measured on. Floats derived from it go through `ln`/`cos`/`sqrt` in [`Rng::normal`]; those are
//! deterministic on one platform and build, which is the promise made here (positions are rounded
//! to whole pixels afterwards, so a last-bit libm difference elsewhere would rarely show at all).

/// Seeded pseudo-random source (SplitMix64).
#[derive(Debug, Clone)]
pub struct Rng {
    state: u64,
}

impl Rng {
    #[must_use]
    pub fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    /// A child generator for an independent stream (timing jitter vs. gesture choice), so adding a
    /// draw to one does not shift every value of the other.
    #[must_use]
    pub fn fork(&mut self, salt: u64) -> Self {
        Self::new(self.next_u64() ^ salt.wrapping_mul(0x9E37_79B9_7F4A_7C15))
    }

    pub fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Uniform in `[0, 1)`, 53 bits.
    pub fn unit(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64
    }

    /// Uniform in `[lo, hi)`.
    pub fn range(&mut self, lo: f64, hi: f64) -> f64 {
        lo + (hi - lo) * self.unit()
    }

    /// Uniform integer in `[lo, hi]`.
    pub fn int(&mut self, lo: u64, hi: u64) -> u64 {
        if hi <= lo {
            return lo;
        }
        lo + self.next_u64() % (hi - lo + 1)
    }

    /// True with probability `p`.
    pub fn chance(&mut self, p: f64) -> bool {
        self.unit() < p
    }

    /// Standard normal (Box-Muller).
    pub fn normal(&mut self) -> f64 {
        let u1 = self.unit().max(1e-12);
        let u2 = self.unit();
        (-2.0 * u1.ln()).sqrt() * (std::f64::consts::TAU * u2).cos()
    }

    /// Log-normal with the given median and log-space sigma, for human intervals (key presses,
    /// pauses) that are skewed long.
    pub fn lognormal(&mut self, median: f64, sigma: f64) -> f64 {
        median * (sigma * self.normal()).exp()
    }
}

#[cfg(test)]
mod tests {
    use super::Rng;

    #[test]
    fn same_seed_same_sequence_and_forks_are_independent() {
        let mut a = Rng::new(42);
        let mut b = Rng::new(42);
        for _ in 0..1000 {
            assert_eq!(a.next_u64(), b.next_u64());
        }
        let mut c = Rng::new(43);
        assert_ne!(Rng::new(42).next_u64(), c.next_u64());

        let mut base = Rng::new(7);
        let mut f1 = base.fork(1);
        let mut base2 = Rng::new(7);
        let mut f2 = base2.fork(2);
        assert_ne!(
            f1.next_u64(),
            f2.next_u64(),
            "different salts give different streams"
        );
    }

    #[test]
    fn ranges_stay_in_bounds() {
        let mut r = Rng::new(1);
        for _ in 0..10_000 {
            let u = r.unit();
            assert!((0.0..1.0).contains(&u));
            let x = r.range(-3.0, 5.0);
            assert!((-3.0..5.0).contains(&x));
            let i = r.int(10, 12);
            assert!((10..=12).contains(&i));
        }
        assert_eq!(r.int(5, 5), 5);
    }
}
