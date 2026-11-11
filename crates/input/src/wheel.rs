//! What the viewer's wheel delta means in notches, for both injection paths.
//!
//! The number the viewer sends is meaningless without its unit (`mode`, `WheelEvent.deltaMode`): a
//! Chrome notch is ~100 pixels, Firefox reports 3 lines, and a two-finger phone scroll reports
//! single digits. Both paths first turn it into notches ([`notches`]); then
//!
//! * `SendInput` takes the wheel in 1/120 of a notch (`WHEEL_DELTA`), so it scrolls smoothly;
//! * the FakerInput HID mouse has no Resolution Multiplier (its descriptor, `Device.c`: Wheel and
//!   AC Pan are one signed byte each, −127..127, whole notches only — one unit is one `WHEEL_DELTA`
//!   of 120 to Windows), so the HID path keeps the fraction ([`WheelCarry`]) until a whole notch is
//!   made. It carries the viewer's game-mode wheel (`game: true`), and every other wheel only where
//!   `SendInput` cannot go: in
//!   game-only mode, and to a foreground window that runs elevated while the agent does not (UIPI).
//!   See `fakerinput`.

use std::time::Duration;

use afklink_protocol::WheelMode;

/// Pixels a browser reports for one notch, near enough across engines. The `SendInput` path.
pub(crate) const PIXELS_PER_NOTCH: f64 = 100.0;

/// Pixels of the viewer's scroll that make one whole HID wheel notch — the FakerInput path.
///
/// **The knob to tune after the owner's live check** on the desktop. The same as
/// [`PIXELS_PER_NOTCH`] to start with, so a browser's notch (~100 px) and the Mini App's pinch (one
/// `w` of 100 px per notch) stay one notch each. Smaller makes a slow two-finger scroll turn a notch
/// sooner (less sticky), but then one browser notch or one pinch step turns more than one; larger
/// makes every notch cost more finger travel.
pub(crate) const HID_PIXELS_PER_NOTCH: f64 = PIXELS_PER_NOTCH;

/// Windows' own default: three lines per notch (`SPI_GETWHEELSCROLLLINES`).
pub(crate) const LINES_PER_NOTCH: f64 = 3.0;

/// A page scroll is one viewport; treat it as a long notch run rather than guess.
pub(crate) const NOTCHES_PER_PAGE: f64 = 5.0;

/// A wheel not marked `game` that goes as whole HID notches (game-only mode, an elevated window)
/// forgets its unfinished notch after this long without a message, so a remainder left by one
/// gesture does not turn the wheel at the start of a later one — in another place, maybe another
/// window.
///
/// Why 300 ms: while a gesture lasts the viewer sends a wheel message every animation frame it has
/// one (the Mini App coalesces per frame: 16 ms at 60 Hz, 33 ms when the phone is busy), a trackpad's
/// momentum keeps sending until it stops, and a slow finger's whole-pixel rounding still sends every
/// few frames — gaps well under 100 ms. 300 ms is about eighteen frames: past any gap inside a
/// gesture, yet shorter than lifting the fingers and starting a deliberate new stroke. The game wheel
/// does not use it: its pinch sends whole notches, and its carry stays as it was.
pub(crate) const STEPPED_CARRY_PAUSE: Duration = Duration::from_millis(300);

/// The most notches one wheel message may turn on the HID path, per axis: four full reports.
///
/// No real gesture comes near it (a fast fling is tens of notches, ten pages are fifty); it only
/// bounds how many reports — each waited on for up to 250 ms — one malformed message can queue.
pub(crate) const MAX_HID_NOTCHES_PER_MESSAGE: f64 = 4.0 * 127.0;

/// The viewer's wheel delta in (fractional) notches; `pixels_per_notch` reads a pixel delta.
pub(crate) fn notches(delta: f64, mode: WheelMode, pixels_per_notch: f64) -> f64 {
    match mode {
        WheelMode::Pixel => delta / pixels_per_notch,
        WheelMode::Line => delta / LINES_PER_NOTCH,
        WheelMode::Page => delta * NOTCHES_PER_PAGE,
    }
}

/// How close to a whole notch counts as whole: ten scrolls of 10 px are 0.1 × 10, which is
/// 0.9999999999999999 in floating point, and must still turn the wheel once.
const WHOLE_EPSILON: f64 = 1e-9;

/// The part of the HID wheel that did not make a whole notch yet, in HID signs: `wheel` > 0 is away
/// from the user (scroll up), `pan` > 0 is right.
///
/// A slow two-finger scroll is many messages of a few pixels, each a small fraction of a notch.
/// Sending each one rounded would turn the wheel at random or never; keeping the fraction makes the
/// notches over a stroke add up to the distance scrolled. A change of direction drops what the old
/// direction had not finished, as a physical wheel would: scrolling back up after 90 px down turns
/// the wheel up after 100 px, not 190. Cleared by `release_all` (the stroke is over), and by the
/// router when the wheel's route changes and, for a wheel not marked `game`, after
/// [`STEPPED_CARRY_PAUSE`].
#[derive(Debug, Default, Clone, Copy, PartialEq)]
pub(crate) struct WheelCarry {
    pub(crate) wheel: f64,
    pub(crate) pan: f64,
}

impl WheelCarry {
    /// Whole notches to send for one message — `(wheel, pan)`, HID signs — keeping the fractions.
    /// The inputs must be finite (the caller checks).
    pub(crate) fn step(&mut self, wheel: f64, pan: f64) -> (i32, i32) {
        (axis(&mut self.wheel, wheel), axis(&mut self.pan, pan))
    }

    /// Would [`Self::step`] with these notches drop an unfinished notch of the other direction, on
    /// either axis? Asked before the step, for the router's count of dropped remainders.
    pub(crate) fn reverses(&self, wheel: f64, pan: f64) -> bool {
        let reverses = |carry: f64, notches: f64| {
            carry != 0.0 && notches != 0.0 && (carry > 0.0) != (notches > 0.0)
        };
        reverses(self.wheel, wheel) || reverses(self.pan, pan)
    }
}

/// One axis of [`WheelCarry::step`].
fn axis(carry: &mut f64, notches: f64) -> i32 {
    if notches == 0.0 {
        return 0;
    }
    if *carry != 0.0 && (*carry > 0.0) != (notches > 0.0) {
        // A change of direction: the old direction's unfinished notch is not owed to the new one.
        *carry = 0.0;
    }
    let total = *carry + notches;
    let whole = if total >= 0.0 {
        (total + WHOLE_EPSILON).trunc()
    } else {
        (total - WHOLE_EPSILON).trunc()
    };
    let rest = total - whole;
    *carry = if rest.abs() < WHOLE_EPSILON {
        0.0
    } else {
        rest
    };
    // At most MAX_HID_NOTCHES_PER_MESSAGE plus a fraction: well inside i32.
    whole as i32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn units_become_notches() {
        assert!((notches(100.0, WheelMode::Pixel, 100.0) - 1.0).abs() < 1e-12);
        assert!((notches(-50.0, WheelMode::Pixel, 100.0) + 0.5).abs() < 1e-12);
        assert!((notches(3.0, WheelMode::Line, 100.0) - 1.0).abs() < 1e-12);
        assert!((notches(1.0, WheelMode::Page, 100.0) - 5.0).abs() < 1e-12);
        // The pixel knob only changes pixels.
        assert!((notches(100.0, WheelMode::Pixel, 50.0) - 2.0).abs() < 1e-12);
        assert!((notches(3.0, WheelMode::Line, 50.0) - 1.0).abs() < 1e-12);
    }

    #[test]
    fn the_carry_keeps_fractions_and_forgets_a_reversed_one() {
        let mut carry = WheelCarry::default();
        let mut sum = 0;
        for _ in 0..10 {
            sum += carry.step(0.1, 0.0).0;
        }
        assert_eq!(sum, 1, "ten tenths are one notch despite floating point");
        assert_eq!(carry, WheelCarry::default());
        assert_eq!(carry.step(0.9, 0.0), (0, 0));
        assert_eq!(
            carry.step(-1.0, 0.0),
            (-1, 0),
            "back the other way: one notch, not 1.9"
        );
        assert_eq!(carry, WheelCarry::default());
        assert_eq!(carry.step(0.0, -2.5), (0, -2));
        assert!((carry.pan + 0.5).abs() < 1e-12);
    }

    #[test]
    fn a_reversal_is_seen_before_the_step_on_either_axis() {
        let mut carry = WheelCarry::default();
        assert!(
            !carry.reverses(-1.0, 1.0),
            "nothing carried, nothing dropped"
        );
        carry.step(0.4, -0.3);
        assert!(!carry.reverses(0.2, -0.2), "the same way on both axes");
        assert!(!carry.reverses(0.0, 0.0), "no motion drops nothing");
        assert!(carry.reverses(-0.1, 0.0), "the wheel back");
        assert!(carry.reverses(0.0, 0.1), "the pan back");
        carry.step(-0.1, 0.0);
        assert!(
            (carry.wheel + 0.1).abs() < 1e-12,
            "the step dropped the 0.4 as `reverses` said"
        );
    }
}
