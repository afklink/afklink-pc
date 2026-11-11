//! The button watch (game-only mode): did the game take each press and release of a mouse button the
//! driver wrote? A release it plainly missed goes once more.
//!
//! ## Why
//!
//! Lineage 2 hides the cursor while the right button is held — its camera turn — and shows it again
//! 10–50 ms after the button comes up. About one transition in thirty, either way, it does not take:
//! the router's ledger is balanced, the release went out in its HID report, and yet the cursor stays
//! hidden (37 s in one report) while every move turns the camera — the game still holds the button.
//! How it loses one is not known; the probe lines below are there to tell.
//!
//! ## What is watched
//!
//! Every button change the router writes for a viewer's `d` or `u` (or a re-send) is watched while
//! the cursor can be read: every [`POLL`] until the cursor reacts or [`PROBE_AT`] has passed, and once
//! more at [`CHECK_AT`] when that decides something. `ra`, the game losing the front, a desktop HID
//! may not drive and a failed write release everything by a neutral report and end every watch.
//!
//! * **A normal pair**: the cursor showed before the press, was hidden after it, and showed again
//!   within [`CHECK_AT`] after the release. Counted per button for the session.
//! * **A missed release**: such a pair with the cursor still hidden [`CHECK_AT`] after the release.
//!   The press goes again at once and its release [`super::typing::TAP_MIN_HOLD`] later, through the
//!   queue a short tap's release waits in — only when the button made [`NORMAL_PAIRS_MIN`] normal
//!   pairs, the release is not a re-send itself, none went in the last [`RETRY_EVERY`], the button
//!   was not given up on, and (`HidRuntime::may_resend`) game-only mode is on, the game has the
//!   front, nothing is held on either path or queued, and HID may drive a working device. Still
//!   hidden after the re-send: a `warn`, and the button is left alone until pressed again.
//! * **A missed press**: still held [`CHECK_AT`] after the press and the cursor never hid — only
//!   logged; nothing is re-sent.
//!
//! «Держать ПКМ» — the right button held on purpose — is a press with no release: nothing to re-send.
//!
//! ## Logs
//!
//! `debug` per transition (they are rare): how the cursor took it at [`PROBE_AT`], the buttons as
//! Windows' async key state has them and as ours, and for the right button the game thread's mouse
//! capture, the window under the cursor and the foreground window (handle, class, and an exe unless
//! it is the game's process, which is never opened); every missed release and press; each re-send
//! and whether it helped; the session's account when the device closes. `trace`: every look.

use std::time::{Duration, Instant};

use super::Host;
use crate::cursor_sync::hid_button_names;

#[cfg(test)]
mod tests;

/// How often the cursor is looked at after a button change, until it reacts or [`PROBE_AT`] passed.
pub(crate) const POLL: Duration = Duration::from_millis(5);
/// When the transition's probe line is said: the game normally reacts within 10–50 ms.
pub(crate) const PROBE_AT: Duration = Duration::from_millis(50);
/// A cursor still hidden this long after a release that should have shown it is a release the game
/// missed (and still showing this long after a press that should have hidden it, a press it missed).
pub(crate) const CHECK_AT: Duration = Duration::from_millis(250);
/// Re-sends are at least this far apart.
pub(crate) const RETRY_EVERY: Duration = Duration::from_millis(300);
/// Normal pairs of a button, this session, before a release of it is ever re-sent: the game is known
/// to hide the cursor for that button.
pub(crate) const NORMAL_PAIRS_MIN: u32 = 3;
/// A re-send asked for and not begun by then (its queue was dropped) is forgotten.
const RETRY_STALE: Duration = Duration::from_secs(1);

/// The HID mouse button bits, in the watch's order: left, right, middle.
const BITS: [u8; 3] = [1, 2, 4];
/// The right button: its probe line says who has the mouse.
const RIGHT: u8 = 2;

/// What Windows says of the mouse around a button change ([`Host::button_probe`]).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct ButtonProbe {
    /// The buttons Windows' async key state has down (`GetAsyncKeyState`), as HID bits: the physical
    /// buttons — the driver's and the PC's own mouse alike. It reads 0 where Windows does not let this
    /// process read it.
    pub(crate) windows: u8,
    /// With detail (the right button): the game's thread's mouse capture (`GetGUIThreadInfo`), the
    /// window under the cursor and the foreground window, described — or why they are unreadable.
    pub(crate) capture: Option<String>,
    pub(crate) under: Option<String>,
    pub(crate) foreground: Option<String>,
}

/// A release the game seems to have missed, with the numbers that decided it: the router re-sends it
/// ([`ButtonWatch::resend`]) or says why not ([`ButtonWatch::not_resent`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Missed {
    /// The HID button bit.
    pub(crate) bit: u8,
    /// How long the button was held before the release.
    held: Duration,
    /// How long after the release the cursor was still hidden.
    hidden_for: Duration,
    normal_pairs: u32,
}

/// What the watch saw and did, for the device's open period (the session's account).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct WatchTally {
    pub(crate) presses: u32,
    pub(crate) releases: u32,
    pub(crate) normal_pairs: u32,
    pub(crate) missed_releases: u32,
    pub(crate) resent: u32,
    pub(crate) helped: u32,
    pub(crate) failed: u32,
    pub(crate) not_resent: u32,
    pub(crate) missed_presses: u32,
}

/// One transition being looked at.
#[derive(Clone, Copy, Debug)]
struct Watch {
    at: Instant,
    /// The cursor right after the report was written — before the game could react — `None` when
    /// it could not be read.
    before: Option<bool>,
    /// How long after the transition the cursor was first seen changed the way the transition should
    /// change it: hidden after a press, shown after a release.
    reacted: Option<Duration>,
    /// When to look next.
    next: Instant,
    probe_said: bool,
    /// The watch's own re-send.
    resent: bool,
}

impl Watch {
    fn new(at: Instant, before: Option<bool>, resent: bool, reacts_from: bool) -> Self {
        Self {
            at,
            before,
            reacted: None,
            // Only a cursor that can change the expected way is looked at closely.
            next: if before == Some(reacts_from) {
                at + POLL
            } else {
                at + PROBE_AT
            },
            probe_said: false,
            resent,
        }
    }

    /// The next look before the probe line: every [`POLL`] while a reaction can still come.
    fn next_before_probe(&self, now: Instant, reacts_from: bool) -> Instant {
        if self.before == Some(reacts_from) && self.reacted.is_none() {
            (now + POLL).min(self.at + PROBE_AT)
        } else {
            self.at + PROBE_AT
        }
    }
}

/// The press of the pair now held.
#[derive(Clone, Copy, Debug)]
struct Pressed {
    at: Instant,
    /// The cursor showed right before it.
    shown_before: bool,
    /// And was seen hidden after it.
    hidden: bool,
    /// Moves made while it was held: exact (the cursor showed) and the camera's (hidden).
    exact_moves: u32,
    camera_moves: u32,
}

/// The release of a pair, being looked at.
#[derive(Clone, Copy, Debug)]
struct Release {
    watch: Watch,
    /// Its press found the cursor showing and hid it.
    began: bool,
    held: Duration,
}

#[derive(Clone, Copy, Debug, Default)]
struct Button {
    normal_pairs: u32,
    pressed: Option<Pressed>,
    press: Option<Watch>,
    release: Option<Release>,
    /// A re-sent release did not help: nothing is re-sent for this button until the viewer presses it
    /// again.
    gave_up: bool,
}

/// The router's button watch (see the module docs). Pure: the cursor and Windows' word come through
/// the router's [`Host`], time as an argument.
#[derive(Debug, Default)]
pub(crate) struct ButtonWatch {
    buttons: [Button; 3],
    /// A re-send asked for and not finished: its button, and when it was asked for.
    retry: Option<(u8, Instant)>,
    last_retry: Option<Instant>,
    tally: WatchTally,
    /// Bumped whenever something new is watched, so the glue knows to wake its worker.
    changes: u64,
}

fn ms(d: Duration) -> String {
    format!("{:.1}", d.as_secs_f64() * 1000.0)
}

fn seen(visible: Option<bool>) -> &'static str {
    match visible {
        Some(true) => "visible",
        Some(false) => "hidden",
        None => "unreadable",
    }
}

fn way(down: bool) -> &'static str {
    if down {
        "press"
    } else {
        "release"
    }
}

/// What a probe line needs besides the watch.
struct ProbeCx<'a> {
    now: Instant,
    visible: Option<bool>,
    game: usize,
    ours: u8,
    host: &'a mut dyn Host,
}

/// The transition's probe line: how the cursor took it, and what Windows says of the mouse.
fn say_probe(
    bit: u8,
    down: bool,
    w: &Watch,
    held: Option<Duration>,
    normal_pairs: u32,
    cx: &mut ProbeCx<'_>,
) {
    let probe = cx.host.button_probe(cx.game, bit == RIGHT);
    let age = cx.now.saturating_duration_since(w.at);
    let cursor = match w.reacted {
        Some(after) => format!(
            "{} after {} ms",
            if down { "hidden" } else { "shown" },
            ms(after)
        ),
        None => format!("no change by {} ms: {}", ms(age), seen(cx.visible)),
    };
    tracing::debug!(
        button = %hid_button_names(bit),
        way = way(down),
        resent = w.resent,
        cursor_before = seen(w.before),
        cursor = %cursor,
        held_ms = %held.map_or_else(|| "-".to_owned(), ms),
        windows_buttons = %hid_button_names(probe.windows),
        ours = %hid_button_names(cx.ours),
        capture = probe.capture.as_deref().unwrap_or("-"),
        under = probe.under.as_deref().unwrap_or("-"),
        foreground = probe.foreground.as_deref().unwrap_or("-"),
        normal_pairs,
        "button watch: how the game took it"
    );
}

impl ButtonWatch {
    fn slot(&mut self, bit: u8) -> Option<&mut Button> {
        let i = BITS.iter().position(|&b| b == bit)?;
        self.buttons.get_mut(i)
    }

    pub(crate) fn changes(&self) -> u64 {
        self.changes
    }

    /// When the router must call [`Self::poll`] next; `None` while nothing is watched.
    pub(crate) fn due(&self) -> Option<Instant> {
        self.buttons
            .iter()
            .flat_map(|b| [b.press, b.release.map(|r| r.watch)])
            .flatten()
            .map(|w| w.next)
            .min()
    }

    /// A button the router writes (`bit`, HID) went down or up in game-only mode; `before`: whether the
    /// cursor showed right after the report was written (`None`: unreadable).
    pub(crate) fn transition(&mut self, bit: u8, down: bool, before: Option<bool>, now: Instant) {
        let resent = matches!(self.retry, Some((b, _)) if b == bit);
        if resent && !down {
            self.retry = None;
        }
        if down {
            self.tally.presses += 1;
        } else {
            self.tally.releases += 1;
        }
        self.changes += 1;
        let Some(b) = self.slot(bit) else {
            return;
        };
        if down {
            if let Some(old) = b.release.take() {
                tracing::trace!(
                    button = %hid_button_names(bit),
                    released_ms = %ms(now.saturating_duration_since(old.watch.at)),
                    "button watch: pressed again before its release was decided; the new pair \
                     takes over"
                );
            }
            if let Some(old) = b.press.filter(|w| !w.probe_said) {
                tracing::trace!(
                    button = %hid_button_names(bit),
                    pressed_ms = %ms(now.saturating_duration_since(old.at)),
                    "button watch: pressed again before the last press's probe; the new press \
                     takes over"
                );
            }
            if b.gave_up && !resent {
                b.gave_up = false;
                tracing::debug!(
                    button = %hid_button_names(bit),
                    "button watch: the viewer pressed the button again: its releases are watched \
                     again"
                );
            }
            b.pressed = Some(Pressed {
                at: now,
                shown_before: before == Some(true),
                hidden: false,
                exact_moves: 0,
                camera_moves: 0,
            });
            b.press = Some(Watch::new(now, before, resent, true));
        } else {
            let (began, held) = match b.pressed.take() {
                // The press hid a showing cursor: seen while held, or hidden right at the release.
                Some(p) => (
                    p.shown_before && (p.hidden || before == Some(false)),
                    now.saturating_duration_since(p.at),
                ),
                // Pressed before the watch could see it (game-only mode came on while held).
                None => (false, Duration::ZERO),
            };
            b.release = Some(Release {
                watch: Watch::new(now, before, resent, false),
                began,
                held,
            });
        }
        tracing::trace!(
            button = %hid_button_names(bit),
            way = way(down),
            cursor = seen(before),
            resent,
            "button watch: a button change to watch"
        );
    }

    /// A move was planned (`exact`: the cursor showed; else the camera's): counted for a press held now.
    pub(crate) fn moved(&mut self, exact: bool) {
        for p in self.buttons.iter_mut().filter_map(|b| b.pressed.as_mut()) {
            if exact {
                p.exact_moves = p.exact_moves.saturating_add(1);
            } else {
                p.camera_moves = p.camera_moves.saturating_add(1);
            }
        }
    }

    /// Look at the cursor for every watch that is due (`game`: game-only mode's window, `None` with
    /// the mode off; `ours`: the buttons the router holds). A release the game seems to have missed,
    /// when the watch's own conditions allow a re-send, is handed back for the router to decide.
    pub(crate) fn poll(
        &mut self,
        now: Instant,
        game: Option<usize>,
        ours: u8,
        host: &mut dyn Host,
    ) -> Option<Missed> {
        if self.due().is_none_or(|due| due > now) {
            return None;
        }
        let Some(game) = game else {
            self.reset("game-only mode is off");
            return None;
        };
        if self
            .retry
            .is_some_and(|(_, at)| now.saturating_duration_since(at) >= RETRY_STALE)
        {
            tracing::debug!("button watch: a re-send asked for never went (its queue was dropped)");
            self.retry = None;
        }
        let visible = match host.cursor_look() {
            Ok(look) => Some(look.showing),
            Err(error) => {
                tracing::trace!(%error, "button watch: the cursor is unreadable");
                None
            }
        };
        tracing::trace!(visible = seen(visible), "button watch: a look");
        let mut cx = ProbeCx {
            now,
            visible,
            game,
            ours,
            host,
        };
        let mut ask = None;
        for (i, &bit) in BITS.iter().enumerate() {
            self.poll_press(i, bit, &mut cx);
            if let Some(missed) = self.poll_release(i, bit, &mut cx, ask.is_some()) {
                ask = Some(missed);
            }
        }
        ask
    }

    fn poll_press(&mut self, i: usize, bit: u8, cx: &mut ProbeCx<'_>) {
        let Some(b) = self.buttons.get_mut(i) else {
            return;
        };
        let Some(mut w) = b.press.take() else {
            return;
        };
        if w.next > cx.now {
            b.press = Some(w);
            return;
        }
        let age = cx.now.saturating_duration_since(w.at);
        // Still the pair's press (not released since).
        let held = b.pressed.filter(|p| p.at == w.at);
        if cx.visible == Some(false) {
            if let Some(p) = b.pressed.as_mut().filter(|p| p.at == w.at) {
                p.hidden = true;
            }
            if w.before == Some(true) && w.reacted.is_none() {
                w.reacted = Some(age);
            }
        }
        if !w.probe_said && age >= PROBE_AT {
            w.probe_said = true;
            say_probe(bit, true, &w, None, b.normal_pairs, cx);
        }
        let may_be_missed = held.is_some()
            && !w.resent
            && w.before == Some(true)
            && w.reacted.is_none()
            && b.normal_pairs >= NORMAL_PAIRS_MIN;
        if !w.probe_said {
            w.next = w.next_before_probe(cx.now, true);
            b.press = Some(w);
        } else if may_be_missed && age < CHECK_AT {
            w.next = w.at + CHECK_AT;
            b.press = Some(w);
        } else if may_be_missed && cx.visible == Some(true) {
            let (exact_moves, camera_moves) =
                held.map_or((0, 0), |p| (p.exact_moves, p.camera_moves));
            self.tally.missed_presses += 1;
            tracing::debug!(
                button = %hid_button_names(bit),
                held_ms = %ms(age),
                exact_moves,
                camera_moves,
                normal_pairs = b.normal_pairs,
                missed_presses = self.tally.missed_presses,
                "button watch: the game seems to have missed a press: the cursor still shows {} ms \
                 after it, while the button is held (nothing is re-sent for a press)",
                CHECK_AT.as_millis()
            );
        } else {
            tracing::trace!(
                button = %hid_button_names(bit),
                hidden_ms = %w.reacted.map_or_else(|| "-".to_owned(), ms),
                cursor_before = seen(w.before),
                cursor = seen(cx.visible),
                held = held.is_some(),
                "button watch: a press's watch ends"
            );
        }
    }

    fn poll_release(
        &mut self,
        i: usize,
        bit: u8,
        cx: &mut ProbeCx<'_>,
        asked: bool,
    ) -> Option<Missed> {
        let b = self.buttons.get_mut(i)?;
        let mut r = b.release.take()?;
        if r.watch.next > cx.now {
            b.release = Some(r);
            return None;
        }
        let age = cx.now.saturating_duration_since(r.watch.at);
        if cx.visible == Some(true) && r.watch.before == Some(false) && r.watch.reacted.is_none() {
            r.watch.reacted = Some(age);
            if r.watch.resent {
                self.tally.helped += 1;
                tracing::debug!(
                    button = %hid_button_names(bit),
                    shown_ms = %ms(age),
                    resent = self.tally.resent,
                    helped = self.tally.helped,
                    "button watch: the re-sent release worked: the game shows the cursor again"
                );
            } else if r.began {
                b.normal_pairs += 1;
                self.tally.normal_pairs += 1;
            }
        }
        if !r.watch.probe_said && age >= PROBE_AT {
            r.watch.probe_said = true;
            say_probe(bit, false, &r.watch, Some(r.held), b.normal_pairs, cx);
        }
        if !r.watch.probe_said {
            r.watch.next = r.watch.next_before_probe(cx.now, false);
            b.release = Some(r);
            return None;
        }
        // Shown, or nothing to wait for (the cursor showed right at the release, or cannot be read).
        if r.watch.reacted.is_some() || r.watch.before != Some(false) || cx.visible.is_none() {
            tracing::trace!(
                button = %hid_button_names(bit),
                shown_ms = %r.watch.reacted.map_or_else(|| "-".to_owned(), ms),
                cursor_at_release = seen(r.watch.before),
                cursor = seen(cx.visible),
                "button watch: a release's watch ends"
            );
            return None;
        }
        if age < CHECK_AT {
            r.watch.next = r.watch.at + CHECK_AT;
            b.release = Some(r);
            return None;
        }
        // Still hidden CHECK_AT after the release.
        if r.watch.resent {
            b.gave_up = true;
            self.tally.failed += 1;
            tracing::warn!(
                button = %hid_button_names(bit),
                hidden_ms = %ms(age),
                normal_pairs = b.normal_pairs,
                resent = self.tally.resent,
                helped = self.tally.helped,
                failed = self.tally.failed,
                "button watch: the game did not take the re-sent release either: the cursor is \
                 still hidden; this button is left alone until the viewer presses it again"
            );
            return None;
        }
        if !r.began {
            tracing::debug!(
                button = %hid_button_names(bit),
                hidden_ms = %ms(age),
                held_ms = %ms(r.held),
                "button watch: the cursor is still hidden after a release, but its press did not \
                 hide a showing cursor: not taken for a missed release"
            );
            return None;
        }
        self.tally.missed_releases += 1;
        let missed = Missed {
            bit,
            held: r.held,
            hidden_for: age,
            normal_pairs: b.normal_pairs,
        };
        let why = if b.gave_up {
            Some(
                "a re-sent release of this button did not help; it is left alone until the viewer \
                 presses it again",
            )
        } else if b.normal_pairs < NORMAL_PAIRS_MIN {
            Some("too few normal pairs of this button this session to tell")
        } else if asked
            || self
                .last_retry
                .is_some_and(|t| cx.now.saturating_duration_since(t) < RETRY_EVERY)
        {
            Some("another re-send less than 300 ms ago")
        } else {
            None
        };
        match why {
            Some(why) => {
                self.not_resent(missed, why);
                None
            }
            None => Some(missed),
        }
    }

    /// The router re-sends a missed release: the button's press now, its release after the minimum
    /// hold, both through the queue. The watch marks them its own when they come.
    pub(crate) fn resend(&mut self, missed: Missed, now: Instant) {
        self.retry = Some((missed.bit, now));
        self.last_retry = Some(now);
        self.tally.resent += 1;
        self.changes += 1;
        tracing::debug!(
            button = %hid_button_names(missed.bit),
            held_ms = %ms(missed.held),
            hidden_ms = %ms(missed.hidden_for),
            normal_pairs = missed.normal_pairs,
            missed_releases = self.tally.missed_releases,
            resent = self.tally.resent,
            "button watch: the game seems to have missed a release (the cursor stays hidden): the \
             button is pressed and released once more"
        );
    }

    /// A missed release is not re-sent, and why.
    pub(crate) fn not_resent(&mut self, missed: Missed, why: &'static str) {
        self.tally.not_resent += 1;
        tracing::debug!(
            button = %hid_button_names(missed.bit),
            held_ms = %ms(missed.held),
            hidden_ms = %ms(missed.hidden_for),
            normal_pairs = missed.normal_pairs,
            missed_releases = self.tally.missed_releases,
            not_resent = self.tally.not_resent,
            "button watch: the game seems to have missed a release (the cursor stays hidden); not \
             re-sent: {why}"
        );
    }

    /// Everything was let up by a neutral report (`ra`, the game lost the front, a blocked desktop, a
    /// failed write), or game-only mode went off: every watch ends, a re-send asked for is forgotten.
    /// The counts stay.
    pub(crate) fn reset(&mut self, why: &'static str) {
        let watching = self.retry.is_some()
            || self
                .buttons
                .iter()
                .any(|b| b.press.is_some() || b.release.is_some() || b.pressed.is_some());
        if !watching {
            return;
        }
        for b in &mut self.buttons {
            b.press = None;
            b.release = None;
            b.pressed = None;
        }
        self.retry = None;
        self.changes += 1;
        tracing::debug!(why, "button watch: every watch ends");
    }

    /// The device closes: the session's account, when anything was watched.
    pub(crate) fn account(&mut self, why: &'static str) {
        let t = std::mem::take(&mut self.tally);
        if t == WatchTally::default() {
            return;
        }
        let [left, right, middle] = self.buttons.map(|b| b.normal_pairs);
        tracing::debug!(
            why,
            presses = t.presses,
            releases = t.releases,
            normal_pairs = t.normal_pairs,
            normal_pairs_left = left,
            normal_pairs_right = right,
            normal_pairs_middle = middle,
            missed_releases = t.missed_releases,
            resent = t.resent,
            helped = t.helped,
            failed = t.failed,
            not_resent = t.not_resent,
            missed_presses = t.missed_presses,
            "button watch: the session's account"
        );
    }

    #[cfg(test)]
    pub(crate) fn tally(&self) -> WatchTally {
        self.tally
    }

    #[cfg(test)]
    pub(crate) fn normal_pairs(&self, bit: u8) -> u32 {
        BITS.iter()
            .position(|&b| b == bit)
            .and_then(|i| self.buttons.get(i))
            .map_or(0, |b| b.normal_pairs)
    }
}
