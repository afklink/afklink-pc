//! A simulated Windows cursor for the tests, on a virtual clock: what Windows does with the reports the
//! planner asks for. Relative counts move the cursor by `S × speed factor` physical px each (EPP off,
//! as measured: 1.5 px per count at 150 %) or along a nonlinear curve of the report's size (EPP on),
//! with Windows' sub-pixel remainder kept and the cursor clamped to the screen; an absolute HID report
//! lands where Windows maps FakerInput's `0..32767` (`floor(X · width / 32768)`, the probe's data). Each input
//! shows in [`CursorWorld::look`] only after [`SimCursor::delay`], like `GetCursorPos` ~2 ms after a
//! report. Nothing here touches Windows.
#![allow(clippy::unwrap_used)]

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use super::{magnitude, speed_factor, CursorLook, CursorWorld, ForegroundInfo, PointerSettings, V};

#[derive(Clone, Copy, Debug)]
enum Input {
    Counts(i32, i32),
    Pixel(i32, i32),
}

pub(crate) struct SimCursor {
    pub(crate) width: i32,
    pub(crate) height: i32,
    pub(crate) dpi: u32,
    pub(crate) epp: bool,
    pub(crate) speed: u32,
    /// Windows' own position, with its sub-pixel remainder.
    pos: V,
    pub(crate) showing: bool,
    pub(crate) suppressed: bool,
    /// `GetCursorInfo` fails (another desktop has the input).
    pub(crate) unreadable: bool,
    /// How long an input takes to show.
    pub(crate) delay: Duration,
    pub(crate) now: Instant,
    queue: VecDeque<(Instant, Input)>,
    /// Every relative report applied: its counts and the px it moved (for the tests' own checks).
    pub(crate) applied: Vec<((i32, i32), V)>,
    /// A gain the planner cannot know about (Windows doing something else than the model says).
    pub(crate) extra_gain: f64,
    /// Inputs are dropped without a trace (UIPI: `SendInput` over an elevated window).
    pub(crate) deaf: bool,
    pub(crate) foreground: usize,
    pub(crate) foreground_elevated: bool,
    pub(crate) settings_reads: u32,
}

/// EPP's gain factor for a report of this size (counts, Windows' magnitude): slow moves slower than
/// linear, fast ones up to 2.6 times — the shape of Windows' default curve, not its numbers.
pub(crate) fn epp_curve(size: f64) -> f64 {
    if size <= 2.0 {
        0.5
    } else if size <= 10.0 {
        0.5 + (size - 2.0) * 0.15
    } else if size <= 40.0 {
        1.7 + (size - 10.0) * 0.03
    } else {
        2.6
    }
}

impl SimCursor {
    /// A 3600×2400 screen at `dpi`, EPP off, speed 10, the cursor showing at (1000, 1000), inputs
    /// showing 2 ms later.
    pub(crate) fn new(dpi: u32, now: Instant) -> Self {
        Self {
            width: 3600,
            height: 2400,
            dpi,
            epp: false,
            speed: 10,
            pos: (1000.0, 1000.0),
            showing: true,
            suppressed: false,
            unreadable: false,
            delay: Duration::from_millis(2),
            now,
            queue: VecDeque::new(),
            applied: Vec::new(),
            extra_gain: 1.0,
            deaf: false,
            foreground: 0x10,
            foreground_elevated: false,
            settings_reads: 0,
        }
    }

    fn scale(&self) -> f64 {
        f64::from(self.dpi) / 96.0
    }

    /// Px per count Windows gives one report of these counts.
    pub(crate) fn gain(&self, counts: (i32, i32)) -> f64 {
        let linear = self.scale() * speed_factor(self.speed) * self.extra_gain;
        if self.epp {
            linear * epp_curve(magnitude((f64::from(counts.0), f64::from(counts.1))))
        } else {
            linear
        }
    }

    pub(crate) fn send_counts(&mut self, cx: i32, cy: i32) {
        if self.deaf {
            return;
        }
        self.queue
            .push_back((self.now + self.delay, Input::Counts(cx, cy)));
    }

    /// FakerInput's absolute report as Windows maps it (measured: `floor(X · width / 32768)`).
    pub(crate) fn send_absolute_wire(&mut self, x: u16, y: u16) {
        if self.deaf {
            return;
        }
        let px = (i64::from(x) * i64::from(self.width) / 32768) as i32;
        let py = (i64::from(y) * i64::from(self.height) / 32768) as i32;
        self.queue
            .push_back((self.now + self.delay, Input::Pixel(px, py)));
    }

    /// Move the clock and apply what has come due.
    pub(crate) fn advance(&mut self, by: Duration) {
        self.now += by;
        self.settle();
    }

    fn settle(&mut self) {
        while let Some(&(at, input)) = self.queue.front() {
            if at > self.now {
                break;
            }
            self.queue.pop_front();
            match input {
                Input::Counts(cx, cy) => {
                    let g = self.gain((cx, cy));
                    let before = self.position();
                    self.pos = (
                        self.pos.0 + f64::from(cx) * g,
                        self.pos.1 + f64::from(cy) * g,
                    );
                    self.clamp();
                    let after = self.position();
                    self.applied.push((
                        (cx, cy),
                        (f64::from(after.0 - before.0), f64::from(after.1 - before.1)),
                    ));
                }
                Input::Pixel(px, py) => {
                    self.pos = (f64::from(px), f64::from(py));
                    self.clamp();
                }
            }
        }
    }

    fn clamp(&mut self) {
        self.pos = (
            self.pos.0.clamp(0.0, f64::from(self.width - 1)),
            self.pos.1.clamp(0.0, f64::from(self.height - 1)),
        );
    }

    /// Someone else puts the cursor here (the PC's own mouse, a game's warp): at once.
    pub(crate) fn warp(&mut self, x: i32, y: i32) {
        self.pos = (f64::from(x), f64::from(y));
        self.clamp();
    }

    /// Where `GetCursorPos` says the cursor is.
    pub(crate) fn position(&self) -> (i32, i32) {
        (
            (self.pos.0 + 1e-9).floor() as i32,
            (self.pos.1 + 1e-9).floor() as i32,
        )
    }

    /// Everything sent has shown.
    pub(crate) fn drain(&mut self) {
        self.advance(self.delay + Duration::from_millis(1));
    }
}

impl CursorWorld for SimCursor {
    fn look(&mut self) -> Result<CursorLook, String> {
        self.settle();
        if self.unreadable {
            return Err("simulated: another desktop has the input".to_owned());
        }
        let (x, y) = self.position();
        Ok(CursorLook {
            x,
            y,
            showing: self.showing,
            suppressed: self.suppressed,
        })
    }

    fn screen(&mut self) -> (i32, i32) {
        (self.width, self.height)
    }

    fn settings(&mut self) -> Result<PointerSettings, String> {
        self.settings_reads += 1;
        Ok(PointerSettings {
            dpi: self.dpi,
            epp: self.epp,
            speed: self.speed,
            thresholds: if self.epp { (6, 10) } else { (0, 0) },
            awareness: "per-monitor aware",
        })
    }

    fn foreground(&mut self) -> usize {
        self.foreground
    }

    fn describe_foreground(&mut self, _window: usize) -> ForegroundInfo {
        ForegroundInfo {
            pid: 4242,
            exe: Ok("ScrydeGame.bin".to_owned()),
            elevated: Ok(self.foreground_elevated),
            agent_elevated: Ok(false),
        }
    }
}
