//! `--no-input`: an injector that injects nothing.
//!
//! The bench device must never touch the owner's real mouse or keyboard, and its viewer is a script
//! that sends input anyway (the product sends pointer moves, clicks and keys as a matter of course).
//! Every event is taken, counted and dropped: discrete events (buttons, keys, combos, text,
//! release-all) are logged at debug as they come, the high-rate ones (pointer moves, relative moves,
//! the wheel) at trace, and every [`EVERY`] a debug line counts what arrived. Nothing is ever held,
//! so `release_all` has nothing to release.
//!
//! It also says it moves no pointer ([`InputInjector::moves_pointer`]), which turns off the
//! pipeline's "pointer moved, no frame followed" stall evidence: with nothing injected, a move is no
//! evidence of anything, and a still stretch of the corpus must not restart the capture.

use std::sync::Mutex;
use std::time::{Duration, Instant};

use afklink_core::traits::InputInjector;
use afklink_core::InputMessage;

/// How often the count is logged while input arrives.
pub const EVERY: Duration = Duration::from_secs(5);

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Counts {
    pub moves: u64,
    pub rel: u64,
    pub wheel: u64,
    pub buttons: u64,
    pub keys: u64,
    pub combos: u64,
    pub text: u64,
    pub release_all: u64,
    pub other: u64,
}

impl Counts {
    pub fn total(&self) -> u64 {
        self.moves
            + self.rel
            + self.wheel
            + self.buttons
            + self.keys
            + self.combos
            + self.text
            + self.release_all
            + self.other
    }
}

#[derive(Debug, Default)]
struct Tally {
    window_start: Option<Instant>,
    window: Counts,
    total: Counts,
}

/// See the module documentation.
#[derive(Debug, Default)]
pub struct NoopInjector {
    tally: Mutex<Tally>,
}

impl NoopInjector {
    #[must_use]
    pub fn new() -> Self {
        tracing::info!(
            "--no-input: remote input is counted and dropped; the real mouse and keyboard are \
             never touched"
        );
        Self::default()
    }

    /// Everything taken so far.
    #[cfg(test)]
    #[must_use]
    pub fn totals(&self) -> Counts {
        afklink_core::lock(&self.tally).total
    }

    fn flush_if_due(t: &mut Tally, now: Instant) {
        let Some(start) = t.window_start else {
            return;
        };
        if now.saturating_duration_since(start) < EVERY {
            return;
        }
        let w = std::mem::take(&mut t.window);
        t.window_start = None;
        if w.total() > 0 {
            // not-a-key-name: a count of key events
            tracing::debug!(
                window_s = now.saturating_duration_since(start).as_secs(),
                events = w.total(),
                moves = w.moves,
                rel = w.rel,
                wheel = w.wheel,
                buttons = w.buttons,
                keys = w.keys,
                combos = w.combos,
                text = w.text,
                release_all = w.release_all,
                other = w.other,
                total = t.total.total(),
                "--no-input: input that would have been injected"
            );
        }
    }
}

/// A message the orchestrator should have kept from the injector, by its wire tag.
fn non_input_kind(m: &InputMessage) -> &'static str {
    match m {
        InputMessage::Quality { .. } => "q",
        InputMessage::ViewerLatency { .. } => "vl",
        InputMessage::ViewerVideo(_) => "vv",
        InputMessage::KeyframeRequest { .. } => "kf",
        InputMessage::Visibility { .. } => "vis",
        InputMessage::ClipboardSync { .. } => "cb_sync",
        InputMessage::ClipboardSet(_) => "cb_set",
        _ => "input",
    }
}

fn bump(t: &mut Tally, f: impl Fn(&mut Counts)) {
    f(&mut t.window);
    f(&mut t.total);
}

impl InputInjector for NoopInjector {
    fn inject(&self, event: &InputMessage) -> anyhow::Result<()> {
        let now = Instant::now();
        let mut t = afklink_core::lock(&self.tally);
        t.window_start.get_or_insert(now);
        match event {
            InputMessage::Move { x, y } => {
                bump(&mut t, |c| c.moves += 1);
                tracing::trace!(x, y, "--no-input: pointer move not injected");
            }
            InputMessage::Rel { dx, dy, .. } => {
                bump(&mut t, |c| c.rel += 1);
                tracing::trace!(dx, dy, "--no-input: relative move not injected");
            }
            InputMessage::Wheel { dx, dy, mode, game } => {
                bump(&mut t, |c| c.wheel += 1);
                tracing::trace!(dx, dy, ?mode, ?game, "--no-input: wheel not injected");
            }
            InputMessage::Down { b } | InputMessage::Up { b } => {
                bump(&mut t, |c| c.buttons += 1);
                let down = matches!(event, InputMessage::Down { .. });
                tracing::debug!(button = *b, down, "--no-input: mouse button not injected");
            }
            InputMessage::Key { d, code, src, .. } => {
                bump(&mut t, |c| c.keys += 1);
                // The physical key only for one of the viewer's own keys (`k.src`): a key from its
                // keyboard is never named — it may be a password being typed. Enough either way to
                // see that a scripted keystroke arrived.
                let ours = src.is_some_and(afklink_protocol::KeySource::is_ours);
                tracing::debug!(
                    target: afklink_input::KEY_NAMES_TARGET,
                    code = if ours { code.as_str() } else { "-" },
                    src = src.map_or("untagged", afklink_protocol::KeySource::as_str),
                    down = *d == 1,
                    "--no-input: key not injected"
                );
            }
            InputMessage::Combo { name } => {
                bump(&mut t, |c| c.combos += 1);
                tracing::debug!(
                    target: afklink_input::KEY_NAMES_TARGET,
                    combo = %name,
                    "--no-input: combo not injected"
                );
            }
            InputMessage::Text { text, game } => {
                bump(&mut t, |c| c.text += 1);
                // The length only: committed text is what a person types, passwords included.
                tracing::debug!(
                    chars = text.chars().count(),
                    ?game,
                    "--no-input: text not injected"
                );
            }
            InputMessage::ReleaseAll => {
                bump(&mut t, |c| c.release_all += 1);
                tracing::debug!("--no-input: release-all (nothing is ever held)");
            }
            // Not input: the orchestrator handles these before the injector. Counted if one ever
            // gets here, so a change in that routing shows.
            other => {
                bump(&mut t, |c| c.other += 1);
                // Its kind, not its contents: a clipboard chunk can hold a password.
                tracing::debug!(
                    kind = non_input_kind(other),
                    "--no-input: a non-input message reached the injector"
                );
            }
        }
        Self::flush_if_due(&mut t, now);
        Ok(())
    }

    fn release_all(&self) {
        // Called on every two seconds of input silence as well as on session end and the kill
        // switch, which also makes it the moment a trailing window gets its line.
        tracing::trace!("--no-input: release_all: nothing is held");
        let mut t = afklink_core::lock(&self.tally);
        Self::flush_if_due(&mut t, Instant::now());
    }

    fn moves_pointer(&self) -> bool {
        false
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;

    #[test]
    fn everything_is_taken_counted_and_dropped() {
        let inj = NoopInjector::new();
        let events = [
            InputMessage::Move { x: 0.5, y: 0.5 },
            InputMessage::Move { x: 0.6, y: 0.5 },
            InputMessage::Rel {
                dx: 0.01,
                dy: 0.0,
                s: None,
                x: None,
                y: None,
            },
            InputMessage::Wheel {
                dx: 0.0,
                dy: 3.0,
                mode: None,
                game: None,
            },
            InputMessage::Down { b: 0 },
            InputMessage::Up { b: 0 },
            InputMessage::Key {
                d: 1,
                code: "KeyA".into(),
                key: Some("a".into()),
                mods: None,
                src: None,
            },
            InputMessage::Combo {
                name: "ctrl+c".into(),
            },
            InputMessage::Text {
                text: "secret".into(),
                game: None,
            },
            InputMessage::ReleaseAll,
        ];
        for e in &events {
            inj.inject(e).unwrap();
        }
        inj.release_all();
        let c = inj.totals();
        assert_eq!(
            c,
            Counts {
                moves: 2,
                rel: 1,
                wheel: 1,
                buttons: 2,
                keys: 1,
                combos: 1,
                text: 1,
                release_all: 1,
                other: 0,
            }
        );
        assert_eq!(c.total(), events.len() as u64);
        assert!(!inj.moves_pointer(), "stall evidence must be off");
    }

    #[test]
    fn the_window_is_counted_and_restarted() {
        let mut t = Tally::default();
        let t0 = Instant::now();
        t.window_start = Some(t0);
        bump(&mut t, |c| c.moves += 3);
        NoopInjector::flush_if_due(&mut t, t0 + Duration::from_secs(1));
        assert_eq!(t.window.moves, 3, "not due yet");
        NoopInjector::flush_if_due(&mut t, t0 + EVERY);
        assert_eq!(t.window, Counts::default(), "flushed");
        assert!(t.window_start.is_none());
        assert_eq!(t.total.moves, 3, "totals are kept");
    }
}
