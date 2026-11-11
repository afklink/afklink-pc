//! Whether the viewer's presses reach the window in front: «Управление не доходит».
//!
//! Without the driver every click, key and text goes by `SendInput`, and into a window that runs as
//! administrator while the agent does not, Windows' UIPI takes it, answers success and drops it.
//! The decision per press is the one text and the wheel already take
//! ([`Reach`](crate::game_guard::Reach)): the foreground window's elevation, looked at afresh, with
//! the driver not open. This watch counts what that decision says for every fresh press — a mouse
//! button going down, a key going down that the `SendInput` path does not already hold, a text — and
//! calls the input blocked once [`BLOCKED_PRESSES`] in a row were dropped within [`BLOCKED_WITHIN`]:
//! a window left open as administrator (Task Manager) that nobody presses into, or one stray click on
//! it, is not «the controls do not reach the game». Blocked lasts while presses keep being dropped and
//! [`BLOCKED_HOLD`] after the last one. A press that got through ends a run of dropped ones (in a
//! row); one whose window's elevation could not be read neither counts nor ends it.
//!
//! Moves and the wheel are not counted: the cursor is not lost the way a press is, and one wheel
//! gesture is dozens of messages (its route is the HID router's decision).
//!
//! The counts since the process started — dropped, delivered, how often blocked began — are never
//! reset: the orchestrator reads them at a session's start and end to say what happened in between
//! (`afklink_core::input_reach`).
//!
//! ## Logs
//!
//! `debug`: the moment presses are found blocked (how many, within how long, into which exe), the
//! moment that ends (how long it lasted, how many were dropped in it), and one `input reach` line a
//! second while presses are being dropped, or their window's elevation cannot be read, or the input
//! is blocked — counts by kind. `trace`: each press, and the second's line when every press got
//! through. Nothing per press at `debug`.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use afklink_core::traits::{DriverPresence, InputReach};
use afklink_protocol::InputMessage;

use crate::game_guard::Reach;

/// How many presses in a row must be dropped…
pub(crate) const BLOCKED_PRESSES: usize = 3;
/// …within how long, for the input to count as blocked.
pub(crate) const BLOCKED_WITHIN: Duration = Duration::from_secs(2);
/// Blocked lasts this long after the last dropped press.
pub(crate) const BLOCKED_HOLD: Duration = Duration::from_secs(10);

/// The aggregate line: one per this long while anything happens.
const STATS_EVERY: Duration = Duration::from_secs(1);

/// What kind of press the viewer made.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Press {
    /// A mouse button going down.
    Button,
    /// A key going down.
    Key,
    /// A text (the phone's keyboard, an IME's committed text).
    Text,
}

impl Press {
    /// The fresh press `event` is, if it is one. `held_button` and `held_key` say whether the
    /// `SendInput` path already holds that button or key: a repeat of a held one is not a new press.
    /// A key this agent has no virtual-key code for is not sent at all, so it is no press either.
    pub(crate) fn of(
        event: &InputMessage,
        held_button: impl FnOnce(u8) -> bool,
        held_key: impl FnOnce(&str) -> bool,
    ) -> Option<Self> {
        match event {
            InputMessage::Down { b } if !held_button(*b) => Some(Self::Button),
            InputMessage::Key { d: 1, code, .. }
                if crate::code_to_vk(code).is_some() && !held_key(code) =>
            {
                Some(Self::Key)
            }
            InputMessage::Text { text, .. } if !text.is_empty() => Some(Self::Text),
            _ => None,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Button => "button",
            Self::Key => "key",
            Self::Text => "text",
        }
    }

    fn index(self) -> usize {
        match self {
            Self::Button => 0,
            Self::Key => 1,
            Self::Text => 2,
        }
    }
}

/// Where a press went.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Landing {
    /// Windows dropped it: the window in front runs elevated, the agent does not, the driver is
    /// not open.
    Dropped,
    /// It reached the window: through the driver, or by `SendInput` to a window it reaches.
    Reached,
    /// The window's elevation (or the agent's) could not be read.
    Unknown,
}

impl Landing {
    /// From the decision text and the wheel take ([`Reach::of`]).
    pub(crate) fn of(reach: Reach) -> Self {
        match reach {
            Reach::ElevatedNoDriver => Self::Dropped,
            Reach::Driver | Reach::BothElevated | Reach::Ordinary => Self::Reached,
            Reach::Unknown => Self::Unknown,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Dropped => "dropped",
            Self::Reached => "reached",
            Self::Unknown => "unknown",
        }
    }
}

/// The per-second aggregate.
#[derive(Debug, Default)]
struct Second {
    since: Option<Instant>,
    /// By [`Press::index`].
    dropped: [u32; 3],
    reached: u32,
    unknown: u32,
}

/// Blocked, since when, and how many presses were dropped in it.
#[derive(Debug)]
struct Episode {
    since: Instant,
    dropped: u32,
}

/// The watch: one per process-wide backend, told of every fresh press of every session.
#[derive(Debug, Default)]
pub(crate) struct ReachWatch {
    /// The current run of dropped presses: when each was, at most [`BLOCKED_PRESSES`].
    run: VecDeque<Instant>,
    episode: Option<Episode>,
    last_dropped: Option<Instant>,
    /// The exe of the window the last dropped press was meant for, for the lines.
    exe: Option<String>,
    lost: u64,
    delivered: u64,
    episodes: u64,
    second: Second,
}

impl ReachWatch {
    /// One fresh press, where it went, and the exe of the window in front (when known).
    pub(crate) fn note(&mut self, press: Press, landing: Landing, exe: Option<&str>, now: Instant) {
        self.expire(now);
        self.flush_if_due(now);
        self.second.since.get_or_insert(now);
        tracing::trace!(
            press = press.name(),
            landing = landing.name(),
            foreground = exe.unwrap_or("-"),
            "input reach: a press"
        );
        match landing {
            Landing::Dropped => self.dropped(press, exe, now),
            Landing::Reached => {
                self.delivered += 1;
                self.second.reached += 1;
                if !self.run.is_empty() {
                    tracing::trace!(
                        dropped_in_a_row = self.run.len(),
                        "input reach: a press got through; the run of dropped ones ends"
                    );
                    self.run.clear();
                }
            }
            Landing::Unknown => self.second.unknown += 1,
        }
    }

    fn dropped(&mut self, press: Press, exe: Option<&str>, now: Instant) {
        self.lost += 1;
        self.second.dropped[press.index()] += 1;
        if let Some(exe) = exe {
            if self.exe.as_deref() != Some(exe) {
                self.exe = Some(exe.to_owned());
            }
        }
        self.last_dropped = Some(now);
        if let Some(episode) = self.episode.as_mut() {
            episode.dropped += 1;
            return;
        }
        self.run.push_back(now);
        while self.run.len() > BLOCKED_PRESSES {
            self.run.pop_front();
        }
        let Some(&first) = self.run.front() else {
            return;
        };
        let within = now.saturating_duration_since(first);
        if self.run.len() < BLOCKED_PRESSES || within > BLOCKED_WITHIN {
            return;
        }
        self.run.clear();
        self.episodes += 1;
        self.episode = Some(Episode {
            since: now,
            dropped: BLOCKED_PRESSES as u32,
        });
        tracing::debug!(
            presses = BLOCKED_PRESSES,
            within_ms = within.as_millis() as u64,
            threshold_ms = BLOCKED_WITHIN.as_millis() as u64,
            last = press.name(),
            foreground = self.exe.as_deref().unwrap_or("-"),
            hold_s = BLOCKED_HOLD.as_secs(),
            "input reach: blocked — presses in a row did not reach the window in front (it runs \
             as administrator, the agent does not, and the driver is not open: Windows' UIPI \
             drops them)"
        );
    }

    /// Blocked ends [`BLOCKED_HOLD`] after the last dropped press.
    fn expire(&mut self, now: Instant) {
        let (Some(episode), Some(last)) = (self.episode.as_ref(), self.last_dropped) else {
            return;
        };
        let quiet = now.saturating_duration_since(last);
        if quiet < BLOCKED_HOLD {
            return;
        }
        tracing::debug!(
            lasted_ms = now.saturating_duration_since(episode.since).as_millis() as u64,
            dropped = episode.dropped,
            quiet_ms = quiet.as_millis() as u64,
            foreground = self.exe.as_deref().unwrap_or("-"),
            "input reach: no longer blocked — no press dropped for {} s",
            BLOCKED_HOLD.as_secs()
        );
        self.episode = None;
    }

    /// The word for the heartbeat and the orchestrator, with the driver as the backend sees it.
    pub(crate) fn snapshot(&mut self, driver: DriverPresence, now: Instant) -> InputReach {
        self.expire(now);
        self.flush_if_due(now);
        InputReach {
            driver,
            blocked: self.episode.is_some(),
            lost: self.lost,
            delivered: self.delivered,
            episodes: self.episodes,
        }
    }

    /// The first session begins or the last ends: the run and the episode were the last batch's
    /// (the counts stay — they are the process's).
    pub(crate) fn reset(&mut self, why: &'static str, now: Instant) {
        self.flush(now, why);
        if let Some(episode) = self.episode.take() {
            tracing::debug!(
                why,
                dropped = episode.dropped,
                "input reach: no longer blocked — the sessions it was in are over"
            );
        }
        self.run.clear();
        self.last_dropped = None;
        self.exe = None;
        tracing::trace!(
            why,
            lost = self.lost,
            delivered = self.delivered,
            episodes = self.episodes,
            "input reach: watch reset"
        );
    }

    fn flush_if_due(&mut self, now: Instant) {
        if self
            .second
            .since
            .is_some_and(|t| now.saturating_duration_since(t) >= STATS_EVERY)
        {
            self.flush(now, "second");
        }
    }

    fn flush(&mut self, now: Instant, why: &'static str) {
        let s = std::mem::take(&mut self.second);
        let Some(since) = s.since else {
            return;
        };
        let window_ms = now.saturating_duration_since(since).as_millis() as u64;
        let [buttons, keys, text] = s.dropped;
        let blocked = self.episode.is_some();
        if buttons + keys + text > 0 || s.unknown > 0 || blocked {
            tracing::debug!(
                why,
                window_ms,
                dropped_buttons = buttons,
                dropped_keys = keys,
                dropped_text = text,
                reached = s.reached,
                unknown = s.unknown,
                blocked,
                foreground = self.exe.as_deref().unwrap_or("-"),
                "input reach"
            );
        } else {
            tracing::trace!(why, window_ms, reached = s.reached, "input reach");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const L2: Option<&str> = Some("ScrydeGame.bin");

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    fn blocked(watch: &mut ReachWatch, now: Instant) -> bool {
        watch.snapshot(DriverPresence::Missing, now).blocked
    }

    /// Three presses in a row dropped within two seconds: blocked, from the third on.
    #[test]
    fn three_dropped_within_two_seconds_are_blocked() {
        let t0 = Instant::now();
        let mut w = ReachWatch::default();
        w.note(Press::Key, Landing::Dropped, L2, t0);
        w.note(Press::Button, Landing::Dropped, L2, t0 + ms(600));
        assert!(!blocked(&mut w, t0 + ms(700)), "two are not enough");
        w.note(Press::Text, Landing::Dropped, L2, t0 + ms(1_900));
        let reach = w.snapshot(DriverPresence::Missing, t0 + ms(1_950));
        assert!(reach.blocked);
        assert_eq!((reach.lost, reach.delivered, reach.episodes), (3, 0, 1));
        assert_eq!(reach.driver, DriverPresence::Missing);
    }

    /// An administrator's window in front that nobody presses into is never blocked, however long.
    #[test]
    fn an_elevated_window_nobody_presses_into_is_not_blocked() {
        let t0 = Instant::now();
        let mut w = ReachWatch::default();
        for s in 0..60 {
            assert!(!blocked(&mut w, t0 + Duration::from_secs(s)));
        }
        let reach = w.snapshot(DriverPresence::Missing, t0 + Duration::from_secs(60));
        assert_eq!((reach.lost, reach.episodes), (0, 0));
    }

    /// Spread wider than two seconds, three are not blocked; the window slides, so the next one
    /// close enough to the two before it is.
    #[test]
    fn the_window_slides_over_the_run() {
        let t0 = Instant::now();
        let mut w = ReachWatch::default();
        w.note(Press::Key, Landing::Dropped, L2, t0);
        w.note(Press::Key, Landing::Dropped, L2, t0 + ms(1_500));
        w.note(Press::Key, Landing::Dropped, L2, t0 + ms(2_500));
        assert!(!blocked(&mut w, t0 + ms(2_600)), "2.5 s for three");
        w.note(Press::Key, Landing::Dropped, L2, t0 + ms(3_000));
        assert!(
            blocked(&mut w, t0 + ms(3_100)),
            "the last three within 1.5 s"
        );
    }

    /// A press that got through ends the run (in a row); one whose window could not be read neither
    /// counts nor ends it.
    #[test]
    fn a_press_that_got_through_ends_the_run_and_an_unknown_one_does_not() {
        let t0 = Instant::now();
        let mut w = ReachWatch::default();
        w.note(Press::Button, Landing::Dropped, L2, t0);
        w.note(Press::Button, Landing::Dropped, L2, t0 + ms(100));
        w.note(
            Press::Button,
            Landing::Reached,
            Some("explorer.exe"),
            t0 + ms(200),
        );
        w.note(Press::Button, Landing::Dropped, L2, t0 + ms(300));
        assert!(!blocked(&mut w, t0 + ms(400)), "two, one through, one");

        let mut w = ReachWatch::default();
        w.note(Press::Key, Landing::Dropped, L2, t0);
        w.note(Press::Key, Landing::Unknown, None, t0 + ms(100));
        w.note(Press::Key, Landing::Dropped, L2, t0 + ms(200));
        assert!(!blocked(&mut w, t0 + ms(250)));
        w.note(Press::Key, Landing::Dropped, L2, t0 + ms(300));
        let reach = w.snapshot(DriverPresence::Missing, t0 + ms(350));
        assert!(reach.blocked, "the unknown one did not break the run");
        assert_eq!((reach.lost, reach.delivered), (3, 0));
    }

    /// Blocked lasts while presses keep being dropped and ten seconds after the last one — a press
    /// that gets through meanwhile does not end it sooner.
    #[test]
    fn blocked_is_held_ten_seconds_after_the_last_dropped_press() {
        let t0 = Instant::now();
        let mut w = ReachWatch::default();
        for i in 0..3 {
            w.note(Press::Key, Landing::Dropped, L2, t0 + ms(100 * i));
        }
        assert!(blocked(&mut w, t0 + ms(300)));
        w.note(Press::Key, Landing::Dropped, L2, t0 + ms(5_000));
        w.note(
            Press::Key,
            Landing::Reached,
            Some("explorer.exe"),
            t0 + ms(6_000),
        );
        assert!(
            blocked(&mut w, t0 + ms(14_999)),
            "10 s after the last dropped"
        );
        assert!(!blocked(&mut w, t0 + ms(15_000)));
        let reach = w.snapshot(DriverPresence::Missing, t0 + ms(15_000));
        assert_eq!((reach.lost, reach.delivered, reach.episodes), (4, 1, 1));

        // A new episode needs three in a row again.
        w.note(Press::Key, Landing::Dropped, L2, t0 + ms(20_000));
        assert!(!blocked(&mut w, t0 + ms(20_001)));
        w.note(Press::Key, Landing::Dropped, L2, t0 + ms(20_100));
        w.note(Press::Key, Landing::Dropped, L2, t0 + ms(20_200));
        let reach = w.snapshot(DriverPresence::Missing, t0 + ms(20_300));
        assert!(reach.blocked);
        assert_eq!(reach.episodes, 2);
    }

    /// The sessions end: blocked ends with them, the counts stay (the orchestrator diffs them).
    #[test]
    fn a_reset_ends_blocked_and_keeps_the_counts() {
        let t0 = Instant::now();
        let mut w = ReachWatch::default();
        for i in 0..3 {
            w.note(Press::Key, Landing::Dropped, L2, t0 + ms(100 * i));
        }
        w.note(Press::Key, Landing::Reached, None, t0 + ms(400));
        assert!(blocked(&mut w, t0 + ms(500)));
        w.reset("last session ended", t0 + ms(600));
        let reach = w.snapshot(DriverPresence::Open, t0 + ms(700));
        assert!(!reach.blocked);
        assert_eq!((reach.lost, reach.delivered, reach.episodes), (3, 1, 1));
        assert_eq!(reach.driver, DriverPresence::Open);
    }

    /// Fresh presses only: a button or key already held is a repeat, a release is no press, a key
    /// with no virtual-key code is never sent, and moves and the wheel are not counted.
    #[test]
    fn only_fresh_presses_count() {
        let no = |_: u8| false;
        let none = |_: &str| false;
        let key = |d: u8, code: &str| InputMessage::Key {
            d,
            code: code.into(),
            key: None,
            mods: None,
            src: None,
        };
        assert_eq!(
            Press::of(&InputMessage::Down { b: 0 }, no, none),
            Some(Press::Button)
        );
        assert_eq!(
            Press::of(&InputMessage::Down { b: 0 }, |_| true, none),
            None
        );
        assert_eq!(Press::of(&InputMessage::Up { b: 0 }, no, none), None);
        assert_eq!(Press::of(&key(1, "KeyW"), no, none), Some(Press::Key));
        assert_eq!(Press::of(&key(1, "KeyW"), no, |_| true), None, "a repeat");
        assert_eq!(Press::of(&key(0, "KeyW"), no, none), None);
        assert_eq!(Press::of(&key(1, "NoSuchKey"), no, none), None);
        let text = |t: &str| InputMessage::Text {
            text: t.into(),
            game: None,
        };
        assert_eq!(Press::of(&text("gg"), no, none), Some(Press::Text));
        assert_eq!(Press::of(&text(""), no, none), None);
        assert_eq!(
            Press::of(&InputMessage::Move { x: 0.5, y: 0.5 }, no, none),
            None
        );
        assert_eq!(Press::of(&InputMessage::ReleaseAll, no, none), None);
        assert_eq!(
            Press::of(
                &InputMessage::Combo {
                    name: "ctrl_alt_del".into()
                },
                no,
                none
            ),
            None
        );
    }

    /// The text's and the wheel's decision, read for a press.
    #[test]
    fn the_landing_is_the_reach_decision() {
        assert_eq!(Landing::of(Reach::ElevatedNoDriver), Landing::Dropped);
        assert_eq!(Landing::of(Reach::Ordinary), Landing::Reached);
        assert_eq!(Landing::of(Reach::BothElevated), Landing::Reached);
        assert_eq!(Landing::of(Reach::Driver), Landing::Reached);
        assert_eq!(Landing::of(Reach::Unknown), Landing::Unknown);
    }
}
