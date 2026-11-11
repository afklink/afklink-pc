//! How the viewer's input messages arrive, for the session's 10-second `input` line: the most that
//! came within any 50 ms (`burst_50ms`) and the longest gap between two in a row while input was
//! active (`gap_max_ms`). Times only — never what a message was.
//!
//! A network that holds the data channel back and then lets it go shows as a gap followed by a
//! burst: keys pressed apart on the phone arriving together on the PC, which a game reads as a chord
//! (or a key held for the length of the gap). A gap of [`INPUT_SILENCE_RELEASE_MS`] or more is the
//! viewer not sending input at all — the person stopped — and is not counted: past that much silence
//! the agent releases what is held anyway.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use afklink_protocol::INPUT_SILENCE_RELEASE_MS;

/// The burst's window.
const BURST_WINDOW: Duration = Duration::from_millis(50);

/// A gap this long or longer is a pause, not a gap while input is active.
const PAUSE: Duration = Duration::from_millis(INPUT_SILENCE_RELEASE_MS);

/// The arrivals of one window of the `input` line.
#[derive(Debug, Default)]
pub(crate) struct InputRhythm {
    /// Arrivals of the last [`BURST_WINDOW`], oldest first.
    recent: VecDeque<Instant>,
    last: Option<Instant>,
    burst: u32,
    gap_max: Duration,
}

impl InputRhythm {
    /// A message arrived at `now` (as the session's event task took it, before it is injected).
    pub(crate) fn note(&mut self, now: Instant) {
        if let Some(last) = self.last {
            let gap = now.saturating_duration_since(last);
            if gap < PAUSE {
                self.gap_max = self.gap_max.max(gap);
            }
        }
        self.last = Some(now);
        while self
            .recent
            .front()
            .is_some_and(|&t| now.saturating_duration_since(t) >= BURST_WINDOW)
        {
            self.recent.pop_front();
        }
        self.recent.push_back(now);
        self.burst = self.burst.max(self.recent.len() as u32);
    }

    /// The window's `burst_50ms` and `gap_max_ms`, and a fresh window — which still knows the last
    /// arrival, so the first gap of the next one is measured from it.
    pub(crate) fn take(&mut self) -> (u32, u64) {
        let out = (self.burst, self.gap_max.as_millis() as u64);
        self.burst = 0;
        self.gap_max = Duration::ZERO;
        self.recent.clear();
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rhythm(at_ms: &[u64]) -> (u32, u64) {
        let t0 = Instant::now();
        let mut r = InputRhythm::default();
        for &ms in at_ms {
            r.note(t0 + Duration::from_millis(ms));
        }
        r.take()
    }

    #[test]
    fn a_steady_stream_is_neither_bursty_nor_gappy() {
        // Sixty a second: a moving finger.
        let at: Vec<u64> = (0..120).map(|i| i * 16).collect();
        assert_eq!(rhythm(&at), (4, 16));
    }

    /// Held back by the network, then let go: a 600 ms gap and twelve messages within 50 ms.
    #[test]
    fn a_stall_shows_as_a_gap_then_a_burst() {
        let mut at: Vec<u64> = (0..10).map(|i| i * 16).collect();
        at.extend((0..12).map(|i| 744 + i * 2));
        assert_eq!(rhythm(&at), (12, 600));
    }

    #[test]
    fn a_pause_of_the_silence_timeout_or_more_is_not_a_gap() {
        assert_eq!(rhythm(&[0, 100, 2_100, 2_200, 9_000]), (1, 100));
        assert_eq!(rhythm(&[0, 1_999]), (1, 1_999));
        assert_eq!(rhythm(&[]), (0, 0));
    }

    #[test]
    fn a_new_window_starts_afresh_but_measures_its_first_gap_from_the_last_arrival() {
        let t0 = Instant::now();
        let mut r = InputRhythm::default();
        for ms in [0, 1, 2, 3] {
            r.note(t0 + Duration::from_millis(ms));
        }
        assert_eq!(r.take(), (4, 1));
        r.note(t0 + Duration::from_millis(303));
        assert_eq!(r.take(), (1, 300));
        assert_eq!(r.take(), (0, 0));
    }
}
