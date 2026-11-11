//! Virtual time.
//!
//! str0m is sans-IO: every `handle_input` carries the `Instant` it happens at and `poll_output`
//! answers with the `Instant` it next wants to be woken. Nothing in its media path reads the wall
//! clock, so an `Instant` that is a fixed epoch plus a simulated offset is indistinguishable, to
//! str0m, from a real one — which is what lets a minute of session run in a fraction of a second.
//!
//! ## Where str0m does touch the real clock, and what that means here
//!
//! Audited in `str0m-0.23.1/src` (non-test code), plus `dimpl` (DTLS; 0.7.3, and again for 0.7.5)
//! and `is-0.11.0` (ICE):
//!
//! * `util/time_tricks.rs:5-9` `not_happening()` is `Instant::now() + 100 years`, computed once. A
//!   "never" sentinel; a simulation of minutes cannot reach it.
//! * `util/time_tricks.rs:16-43` `BEGINNING_OF_TIME` pairs `Instant::now()` with `SystemTime::now()`
//!   once per process, and `already_happened()` is its `Instant` half (up to an hour before the
//!   first call). Used as a "long ago" sentinel for last-sent/last-report fields; the epoch below
//!   is taken after it is fixed, so every virtual instant is later than it, as str0m requires
//!   (`to_unix_duration` warns on earlier ones).
//! * The `SystemTime` half maps instants to NTP for sender reports (`streams/send.rs:1028`), the
//!   RTT arithmetic on receiver reports (`streams/send_stats.rs:88`, `streams/receive.rs:316`) and
//!   abs-send-time (`rtp/ext.rs:635`). Only *differences* of these matter, and they are exact —
//!   except for quantisation: RTCP carries the middle 32 bits of NTP (1/65536 s), so where the
//!   process's wall-clock phase happens to fall moves a computed RTT by up to ~30 µs. Within one
//!   process every run shares [`sim_epoch`] and the mapping, so runs are bit-identical; across
//!   processes an RTT can differ by that much, which changes `rtt_ms` only when the true value sits
//!   within ~30 µs of a whole millisecond. This is the one source of cross-process
//!   non-determinism left, and it cannot be removed without patching str0m.
//! * `lib.rs:2193-2197` reads `SystemTime` only under the `_internal_dont_use_log_stats` feature,
//!   which is off.
//! * `dimpl` keeps its own `BEGINNING_OF_TIME` (`time_tricks.rs:11-38`) for the DTLS 1.2 random's
//!   timestamp; it affects bytes, not timing. Its other `Instant::now()` calls (0.7.5:
//!   `dtls12/client.rs:1420`, `dtls13/client.rs:1624`, the engines' tests) are in test code.
//! * Randomness: str0m and `is` draw ids from fastrand's thread-local (seeded by `crate::sim`);
//!   DTLS keys, randoms and certificates come from the OS generator and cannot be seeded through
//!   str0m's API. They change handshake *bytes* (an ECDSA signature is 70-72 bytes), which is why
//!   the links run ideal — fixed delay, no capacity, no loss — until the sender reports
//!   `Connected`, and the link statistics and the sender's egress counters start over there: from
//!   then on every packet size, and so everything the controller reads, is a function of the seed.

use std::cell::Cell;
use std::fmt;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

/// The process-wide instant that virtual time zero maps to.
///
/// Shared by every simulation in the process so that str0m's instant-to-NTP mapping, which is also
/// process-wide, is the same for all of them — two runs of one scenario in one process are then
/// identical to the bit (see the module note for across processes).
pub fn sim_epoch() -> Instant {
    static EPOCH: OnceLock<Instant> = OnceLock::new();
    *EPOCH.get_or_init(|| {
        // Building any `Rtc` fixes str0m's `BEGINNING_OF_TIME` (`lib.rs:2020`, "first ever time
        // must be now"). Do it before choosing the epoch so the epoch is after it — for each str0m
        // in the process, the agent's and the viewer's other version (`crate::viewer`), which keep
        // one each (`util/time_tricks.rs:16` in both).
        let probe = str0m::Rtc::builder()
            .set_crypto_provider(std::sync::Arc::new(str0m::crypto::from_feature_flags()))
            .build(Instant::now());
        drop(probe);
        let probe = str0m_023::Rtc::builder()
            .set_crypto_provider(std::sync::Arc::new(str0m_023::crypto::from_feature_flags()))
            .build(Instant::now());
        drop(probe);
        let epoch = Instant::now();
        tracing::debug!("simulation epoch fixed after str0m's time base");
        epoch
    })
}

/// Virtual time for one simulation: a monotonic offset from [`sim_epoch`].
#[derive(Debug, Clone)]
pub struct VirtualClock {
    epoch: Instant,
    now: Duration,
}

impl Default for VirtualClock {
    fn default() -> Self {
        Self::new()
    }
}

impl VirtualClock {
    /// A clock at virtual zero. From here until [`clear_log_time`], log lines emitted on this
    /// thread carry virtual time.
    #[must_use]
    pub fn new() -> Self {
        LOG_NOW.with(|c| c.set(Some(Duration::ZERO)));
        Self {
            epoch: sim_epoch(),
            now: Duration::ZERO,
        }
    }

    /// Virtual time since the start of the simulation.
    #[must_use]
    pub fn now(&self) -> Duration {
        self.now
    }

    /// The current virtual time as the `Instant` str0m is handed.
    #[must_use]
    pub fn instant(&self) -> Instant {
        self.epoch + self.now
    }

    /// Any virtual time as an `Instant`.
    #[must_use]
    pub fn at(&self, t: Duration) -> Instant {
        self.epoch + t
    }

    /// An `Instant` str0m produced, as virtual time. Sentinels before the epoch
    /// (`already_happened()`) read as zero; `not_happening()` reads as a very large offset.
    #[must_use]
    pub fn offset_of(&self, i: Instant) -> Duration {
        i.saturating_duration_since(self.epoch)
    }

    /// Move time forward. Time never goes backwards: an event scheduled in the past (a str0m
    /// timeout that is already due) is served now.
    pub fn advance_to(&mut self, t: Duration) {
        if t > self.now {
            self.now = t;
        }
        LOG_NOW.with(|c| c.set(Some(self.now)));
    }
}

thread_local! {
    /// The virtual time of the simulation running on this thread, for log timestamps.
    static LOG_NOW: Cell<Option<Duration>> = const { Cell::new(None) };
}

/// Forget this thread's virtual time (a simulation has finished), so later log lines carry the wall
/// clock again.
pub fn clear_log_time() {
    LOG_NOW.with(|c| c.set(None));
}

/// A `tracing` timer that stamps events with the virtual time of the simulation on the emitting
/// thread, so a controller decision logged at debug can be read against the per-second lines.
#[derive(Debug, Clone, Copy, Default)]
pub struct VirtualTimer;

impl tracing_subscriber::fmt::time::FormatTime for VirtualTimer {
    fn format_time(&self, w: &mut tracing_subscriber::fmt::format::Writer<'_>) -> fmt::Result {
        match LOG_NOW.with(Cell::get) {
            Some(t) => write!(w, "sim+{:>10.6}s", t.as_secs_f64()),
            None => write!(w, "{:>15}", "-"),
        }
    }
}

/// `2000-01-01THH:MM:SS.ffffffZ` for a virtual time, the shape of the agent's own log timestamps,
/// so `ladder_replay` (which slices `HH:MM:SS` out of columns 11..19) reads simulated sessions.
///
/// The date is fixed and meaningless; the time of day is the virtual time since the simulation
/// began, wrapping after 24 hours.
#[must_use]
pub fn log_timestamp(t: Duration) -> String {
    let us = t.as_micros();
    let secs = us / 1_000_000;
    let frac = us % 1_000_000;
    let h = (secs / 3600) % 24;
    let m = (secs / 60) % 60;
    let s = secs % 60;
    format!("2000-01-01T{h:02}:{m:02}:{s:02}.{frac:06}Z")
}

#[cfg(test)]
mod tests {
    use super::{log_timestamp, sim_epoch, VirtualClock};
    use std::time::Duration;

    #[test]
    fn the_clock_only_moves_forward() {
        let mut c = VirtualClock::new();
        assert_eq!(c.now(), Duration::ZERO);
        assert_eq!(c.instant(), sim_epoch());
        c.advance_to(Duration::from_millis(250));
        assert_eq!(c.now(), Duration::from_millis(250));
        // A timeout that was due in the past is served now, not by rewinding.
        c.advance_to(Duration::from_millis(100));
        assert_eq!(c.now(), Duration::from_millis(250));
        assert_eq!(c.instant(), sim_epoch() + Duration::from_millis(250));
        assert_eq!(c.offset_of(c.instant()), Duration::from_millis(250));
    }

    #[test]
    fn the_epoch_is_shared_and_the_offset_of_a_sentinel_is_safe() {
        let a = VirtualClock::new();
        let b = VirtualClock::new();
        assert_eq!(a.instant(), b.instant());
        // An instant before the epoch (str0m's `already_happened()`) reads as zero, not a panic.
        let before = sim_epoch()
            .checked_sub(Duration::from_secs(1))
            .unwrap_or(sim_epoch());
        assert_eq!(a.offset_of(before), Duration::ZERO);
    }

    #[test]
    fn log_timestamps_carry_the_virtual_time_where_ladder_replay_reads_it() {
        let ts = log_timestamp(Duration::from_micros(3_723_004_005));
        assert_eq!(ts, "2000-01-01T01:02:03.004005Z");
        assert_eq!(&ts[11..19], "01:02:03");
    }
}
