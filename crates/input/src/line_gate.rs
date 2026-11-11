//! A per-event `debug` line a viewer's flood must not turn into one line per message (KB-6): a
//! blocked key, a combo, a press dropped, a code no key has. The first [`LineGate::BURST`] of a
//! [`LineGate::WINDOW`] are said as before; the rest go to `trace`, and when the next window opens
//! with some unsaid, one line says how many. The per-second aggregates count every event either way.

use std::time::{Duration, Instant};

#[derive(Debug, Default)]
pub(crate) struct LineGate {
    /// When the current window opened; `None` before the first line.
    window: Option<Instant>,
    said: u32,
    unsaid: u32,
}

impl LineGate {
    /// Lines a window may say: a person blocks or misses a few keys, not dozens, in ten seconds.
    pub(crate) const BURST: u32 = 8;
    pub(crate) const WINDOW: Duration = Duration::from_secs(10);

    pub(crate) const fn new() -> Self {
        Self {
            window: None,
            said: 0,
            unsaid: 0,
        }
    }

    /// Whether the line for this event may go at `debug` now (`what`: the kind of line, for the
    /// count of those that did not). False: the caller says it at `trace`, if at all.
    pub(crate) fn admit(&mut self, now: Instant, what: &'static str) -> bool {
        if self
            .window
            .is_none_or(|opened| now.saturating_duration_since(opened) >= Self::WINDOW)
        {
            if self.unsaid > 0 {
                tracing::debug!(
                    what,
                    unsaid = self.unsaid,
                    burst = Self::BURST,
                    window_s = Self::WINDOW.as_secs(),
                    "a flood of per-event lines: these went to trace in the last window (the \
                     aggregate lines count them)"
                );
            }
            self.window = Some(now);
            self.said = 0;
            self.unsaid = 0;
        }
        if self.said < Self::BURST {
            self.said += 1;
            true
        } else {
            self.unsaid += 1;
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_window_says_its_burst_and_counts_the_rest() {
        let mut gate = LineGate::new();
        let t0 = Instant::now();
        let said = (0..1_000).filter(|_| gate.admit(t0, "test")).count();
        assert_eq!(said, LineGate::BURST as usize);
        assert_eq!(gate.unsaid, 1_000 - LineGate::BURST);
        assert!(
            gate.admit(t0 + LineGate::WINDOW, "test"),
            "a new window says again"
        );
        assert_eq!(gate.unsaid, 0);
    }
}
