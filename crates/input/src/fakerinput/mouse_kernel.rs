//! Confirmed mouse buttons, relative report splitting and wheel carry shared by the HID paths.

use afklink_protocol::WheelMode;
use anyhow::{ensure, Result};

use crate::wheel::{notches, WheelCarry, MAX_HID_NOTCHES_PER_MESSAGE};

use super::button_bit;

#[derive(Default)]
pub(super) struct MouseKernel {
    buttons: u8,
    wheel: WheelCarry,
    wheel_clamp_said: bool,
}

pub(super) struct WheelStep {
    pub(super) wheel: i32,
    pub(super) pan: i32,
    pub(super) reversed: bool,
}

impl MouseKernel {
    pub(super) fn buttons(&self) -> u8 {
        self.buttons
    }

    pub(super) fn holds(&self, button: u8) -> bool {
        button_bit(button).is_some_and(|bit| self.buttons & bit != 0)
    }

    pub(super) fn button_mask(&self, button: u8, down: bool) -> Option<u8> {
        let bit = button_bit(button)?;
        Some(if down {
            self.buttons | bit
        } else {
            self.buttons & !bit
        })
    }

    #[cfg(windows)]
    pub(super) fn release_mask(&self, buttons: impl IntoIterator<Item = u8>) -> Option<u8> {
        buttons.into_iter().try_fold(self.buttons, |held, button| {
            Some(held & !button_bit(button)?)
        })
    }

    /// A write that fails may have reached the device. Keep the last confirmed state;
    /// the caller retains its dirty flag and requires a completed neutral report.
    pub(super) fn write_buttons(
        &mut self,
        next: u8,
        send: impl FnOnce(u8) -> Result<()>,
    ) -> Result<()> {
        send(next)?;
        self.confirm_buttons(next);
        Ok(())
    }

    fn confirm_buttons(&mut self, next: u8) {
        self.buttons = next;
    }

    #[cfg(windows)]
    pub(super) fn neutral_confirmed(&mut self) {
        self.confirm_buttons(0);
    }

    pub(super) fn wheel_step(
        &mut self,
        dx: f64,
        dy: f64,
        mode: WheelMode,
        pixels_per_notch: f64,
    ) -> Result<WheelStep> {
        ensure!(dx.is_finite() && dy.is_finite(), "non-finite wheel delta");
        let limit = MAX_HID_NOTCHES_PER_MESSAGE;
        let wheel_in = -notches(dy, mode, pixels_per_notch);
        let pan_in = notches(dx, mode, pixels_per_notch);
        if wheel_in.abs() > limit || pan_in.abs() > limit {
            if self.wheel_clamp_said {
                tracing::trace!(wheel_in, pan_in, limit, "HID wheel: message clamped");
            } else {
                self.wheel_clamp_said = true;
                tracing::debug!(
                    wheel_in,
                    pan_in,
                    limit,
                    "HID wheel: a message asked for more notches than any gesture makes; clamped (further ones at trace)"
                );
            }
        }
        let before = self.wheel;
        let (wheel_in_clamped, pan_in_clamped) =
            (wheel_in.clamp(-limit, limit), pan_in.clamp(-limit, limit));
        let reversed = before.reverses(wheel_in_clamped, pan_in_clamped);
        let (wheel, pan) = self.wheel.step(wheel_in_clamped, pan_in_clamped);
        tracing::trace!(
            wheel_in,
            pan_in,
            carried_wheel = before.wheel,
            carried_pan = before.pan,
            reversed,
            wheel,
            pan,
            left_wheel = self.wheel.wheel,
            left_pan = self.wheel.pan,
            "HID wheel: notches accumulated"
        );
        Ok(WheelStep {
            wheel,
            pan,
            reversed,
        })
    }

    pub(super) fn drop_wheel_carry(&mut self, why: &'static str) -> bool {
        if self.wheel == WheelCarry::default() {
            return false;
        }
        tracing::trace!(
            why,
            wheel = self.wheel.wheel,
            pan = self.wheel.pan,
            "HID wheel: unfinished notch dropped"
        );
        self.wheel = WheelCarry::default();
        true
    }

    #[cfg(test)]
    pub(super) fn wheel_carry(&self) -> WheelCarry {
        self.wheel
    }
}

/// Relative movement and wheel use the same splitting rule. The caller chooses a
/// per-report limit and, for direct HID access, authorizes each piece before it reaches HID.
pub(super) fn split_axes(mut x: i32, mut y: i32, limit: i32) -> impl Iterator<Item = (i32, i32)> {
    std::iter::from_fn(move || {
        if x == 0 && y == 0 {
            return None;
        }
        let piece = (x.clamp(-limit, limit), y.clamp(-limit, limit));
        x -= piece.0;
        y -= piece.1;
        Some(piece)
    })
}
