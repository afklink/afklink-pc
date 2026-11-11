//! Agent-side cursor sync: what one relative move (`r`) does to the PC's cursor.
//!
//! The viewer's `r` says how far the hand moved (a fraction of the captured screen) and, from a
//! viewer that points at the picture, where its pointer is (`x`, `y`). Which one the PC's cursor
//! follows depends on the cursor, so the planner decides per event from a fresh `GetCursorInfo`
//! (microseconds; the viewer's `cp` reports are a round trip late):
//!
//! * **camera** — the cursor is hidden, off the captured screen, or unreadable: a game is turning
//!   its camera. Counts are the fraction times the physical screen, the remainder carried
//!   ([`crate::RelCarry`]), so camera sensitivity is unchanged.
//! * **point** — a target, a visible cursor and no button held by us: one absolute move onto the
//!   target's pixel (FakerInput's absolute report on HID, `SendInput`'s absolute event otherwise).
//! * **exact** — any other visible cursor (a drag, a finger mode without a target): relative counts
//!   that move it by exactly the intended physical distance, so a game reading the mouse sees motion,
//!   never a jump. The viewer's `m` always goes as one absolute move; the planner only books it
//!   ([`CursorSync::absolute`]) so the next look does not take it for someone else's motion.
//!
//! **Exact mode.** Windows moves a visible cursor by more than a pixel per count (1.5 px at 150 %
//! scale, "Enhance pointer precision" (EPP) off, on both paths). The planner keeps an aim, turns
//! wanted pixels into counts through a gain model, and closes the loop on `GetCursorPos` (a report
//! shows ~2 ms after it is written, well inside the ~16 ms between moves): it corrects half the
//! remaining error per move, at most `max(3 px, half the hand's motion)`, nothing within 1 px;
//! sends not yet visible count as done (40 ms at most); the aim re-anchors on entering exact mode
//! and on motion our sends cannot explain. With EPP off the gain is `dpi / 96 ×` the pointer-speed
//! factor, replaced by the measured gain if 30+ samples disagree by over 12 %; with EPP on it is
//! learned per report-size bin rather than rebuilt from Windows' undocumented curve.
//!
//! **Game-only mode.** Targets map into the game's client area ([`CursorSync::set_space`],
//! [`map_point`]) and the aim is clamped to it, so the cursor cannot leave the window (`ClipCursor`
//! would be reset on every foreground change and would confine the owner's own mouse too). The
//! camera's counts are untouched.
//!
//! **Moves the cursor shows.** Each cursor poll answers the lowest numbered move not yet visible
//! ([`CursorSync::unshown`]; matched read-only by [`CursorSync::resolve`] against the poll's own look
//! taken under the planner's lock), so the viewer's marker never steps back. A send counts as shown
//! once the cursor moved at all, the game hid it, or [`REFLECT_TIMEOUT`] passed; a queued move
//! ([`CursorSync::queued`]) once released or after [`QUEUED_MAX`].
//!
//! Pure: Win32 reads sit behind [`CursorWorld`], time is an argument. Logs: settings, mode changes
//! and re-anchors at `debug` (rate-limited), a `cursor sync` line a second, each move at `trace`.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

#[cfg(test)]
pub(crate) mod sim;
#[cfg(windows)]
pub(crate) mod system;
#[cfg(test)]
mod tests;

/* --------------------------------------------------------------------------------------------- */
/* What the planner reads                                                                         */
/* --------------------------------------------------------------------------------------------- */

/// One look at the OS cursor (`GetCursorInfo`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CursorLook {
    /// Position on the virtual screen, whose origin is the primary (captured) monitor's top-left
    /// corner.
    pub(crate) x: i32,
    pub(crate) y: i32,
    /// `CURSOR_SHOWING`, with a shape to show (a null `hCursor` counts as hidden).
    pub(crate) showing: bool,
    /// `CURSOR_SUPPRESSED`: touch or pen input, the system draws no cursor.
    pub(crate) suppressed: bool,
}

/// Windows' pointer settings and the display's scale: what one relative count does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PointerSettings {
    /// The primary monitor's effective DPI as the injecting thread sees it (96 = 100 %).
    pub(crate) dpi: u32,
    /// "Enhance pointer precision": `SPI_GETMOUSE`'s third value is not 0.
    pub(crate) epp: bool,
    /// The pointer-speed slider, `SPI_GETMOUSESPEED`: 1..=20, 10 the middle.
    pub(crate) speed: u32,
    /// `SPI_GETMOUSE`'s two thresholds, for the log.
    pub(crate) thresholds: (i32, i32),
    /// The injecting thread's DPI awareness, for the log.
    pub(crate) awareness: &'static str,
}

impl PointerSettings {
    /// What the planner assumes before it could read anything: 100 %, no acceleration, speed 10.
    const FALLBACK: Self = Self {
        dpi: 96,
        epp: false,
        speed: 10,
        thresholds: (0, 0),
        awareness: "unknown",
    };

    /// The display scale: physical pixels per 96-dpi pixel.
    pub(crate) fn scale(&self) -> f64 {
        f64::from(self.dpi) / 96.0
    }

    /// A DPI of 0 or a slider outside 1..=20 is not what Windows means; the log says so.
    fn sanitized(self) -> Self {
        Self {
            dpi: if self.dpi == 0 { 96 } else { self.dpi },
            speed: self.speed.clamp(1, 20),
            ..self
        }
    }
}

/// The foreground window's process, for the log.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ForegroundInfo {
    pub(crate) pid: u32,
    /// The exe's file name, or why it is unknown.
    pub(crate) exe: Result<String, String>,
    /// Whether it runs elevated, or why that could not be read.
    pub(crate) elevated: Result<bool, String>,
    /// Whether this agent does.
    pub(crate) agent_elevated: Result<bool, String>,
}

/// What the planner reads of the PC — behind a trait, so the tests drive a simulated Windows.
pub(crate) trait CursorWorld {
    /// The cursor now.
    fn look(&mut self) -> Result<CursorLook, String>;
    /// The captured (primary) screen, in the same pixels as [`CursorLook`].
    fn screen(&mut self) -> (i32, i32);
    fn settings(&mut self) -> Result<PointerSettings, String>;
    /// The foreground window's handle; 0 for none.
    fn foreground(&mut self) -> usize;
    fn describe_foreground(&mut self, window: usize) -> ForegroundInfo;
}

/* --------------------------------------------------------------------------------------------- */
/* What the planner answers                                                                       */
/* --------------------------------------------------------------------------------------------- */

/// Which path injects a move. The planner decides the same for both; the path only says how an
/// absolute move goes out.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RelPath {
    Hid,
    SendInput,
}

impl RelPath {
    fn name(self) -> &'static str {
        match self {
            Self::Hid => "hid",
            Self::SendInput => "sendinput",
        }
    }
}

/// One `r`, as the planner needs it.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) struct RelEvent {
    pub(crate) dx: f64,
    pub(crate) dy: f64,
    /// The viewer's pointer on the captured screen, `[0..1]`; both or neither.
    pub(crate) x: Option<f64>,
    pub(crate) y: Option<f64>,
    /// The viewer's number for the move (`r.s`), when it numbers them: the cursor report's `ack`
    /// names it once the cursor shows it ([`CursorSync::unshown`]).
    pub(crate) s: Option<u32>,
}

/// What decided a move.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Mode {
    Camera,
    Point,
    Exact,
}

impl Mode {
    fn name(self) -> &'static str {
        match self {
            Self::Camera => "camera",
            Self::Point => "point",
            Self::Exact => "exact",
        }
    }
}

/// What the path sends for one `r`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Plan {
    /// Relative counts exactly as before: the path's own carry, the fraction times the physical
    /// screen.
    Camera,
    /// Put the cursor on this pixel of the `width`×`height` captured screen.
    Absolute {
        px: i32,
        py: i32,
        width: i32,
        height: i32,
    },
    /// Move by these counts.
    Relative { cx: i32, cy: i32 },
    /// Nothing to send for this move (it rounds to no count yet, or the cursor is already there).
    Nothing,
}

/* --------------------------------------------------------------------------------------------- */
/* Tuning                                                                                         */
/* --------------------------------------------------------------------------------------------- */

/// The pointer settings are read again at most this often, on the next move (a few microseconds).
const SETTINGS_EVERY: Duration = Duration::from_secs(1);
/// The `cursor sync` line: one per this long while moves come.
const STATS_EVERY: Duration = Duration::from_secs(1);
/// The foreground window is looked at no more often than this.
const FOREGROUND_EVERY: Duration = Duration::from_millis(200);
/// A send whose effect has not shown by then is taken as done (or lost). Measured: a HID report shows in
/// `GetCursorPos` 1.6–1.8 ms after it is written, `SendInput` in 0.3 ms. The cursor report's `ack`
/// holds to it too ([`CursorSync::unshown`]): a move Windows changed or ate (the screen's edge, a game
/// that warped or hid the cursor, UIPI) is acknowledged this long after its send at the latest.
const REFLECT_TIMEOUT: Duration = Duration::from_millis(40);
/// A numbered move waiting in the HID router's queue (behind a click, a key, a tap's minimum hold, a
/// button waiting for an absolute move) is taken as gone after this, for the cursor report's `ack`:
/// a queue the router dropped is released through the planner ([`CursorSync::release`]), and this
/// bounds one it did not hear of. Those waits are 30 ms or less; game text can hold moves longer,
/// and then the `ack` stops waiting for them.
const QUEUED_MAX: Duration = Duration::from_millis(250);
/// Queued numbered moves remembered at most; the oldest goes first (the router's queue is smaller).
const QUEUED_KEPT: usize = 256;
/// The share of the remaining error one move corrects. Below 1 so a gain the model has wrong (EPP
/// before its bins are learned) cannot make the correction overshoot and ring: the error shrinks by
/// `1 − 0.5·γ` per move, monotonically for a gain up to twice the model's and convergent up to four.
const DAMPING: f64 = 0.5;
/// A move's correction is at most this, or [`CORRECTION_SHARE`] of the hand's own motion if that is
/// more: a correction rides on the hand and never looks like a jump.
const CORRECTION_MIN_PX: f64 = 3.0;
const CORRECTION_SHARE: f64 = 0.5;
/// An error this small is left alone: one count is 1.5 px at 150 %, and Windows keeps the sub-pixel
/// remainder itself.
const DEADBAND_PX: f64 = 1.0;
/// A difference between what our sends should have moved and what the cursor did is never someone
/// else's motion below this.
const EXTERNAL_MIN_PX: f64 = 4.0;
/// Sends expected to move at least this much that moved nothing at all: they did not reach the cursor
/// (UIPI: an unelevated `SendInput` over an elevated window is accepted and dropped).
const NO_EFFECT_MIN_PX: f64 = 3.0;
/// Mode changes said at `debug` per [`STATS_EVERY`]; the rest go to `trace`, counted.
const MODE_LINES_PER_WINDOW: u32 = 8;

/// The pointer-speed slider's multiplier with EPP off, for `SPI_GETMOUSESPEED` 1..=20 (Microsoft's
/// pointer-ballistics table: 1/32, 1/16, 1/8, then eighths to 1 at 10, then quarters to 3.5).
const SPEED_FACTOR: [f64; 20] = [
    0.031_25, 0.0625, 0.125, 0.25, 0.375, 0.5, 0.625, 0.75, 0.875, 1.0, 1.25, 1.5, 1.75, 2.0, 2.25,
    2.5, 2.75, 3.0, 3.25, 3.5,
];

pub(crate) fn speed_factor(speed: u32) -> f64 {
    let index = usize::try_from(speed.clamp(1, 20) - 1).unwrap_or(9);
    SPEED_FACTOR.get(index).copied().unwrap_or(1.0)
}

/// HID mouse button bits (1 left, 2 right, 4 middle) in words, for the log: `left+right`, `-` for
/// none.
pub(crate) fn hid_button_names(bits: u8) -> String {
    let names: Vec<&str> = [(1, "left"), (2, "right"), (4, "middle")]
        .into_iter()
        .filter(|&(bit, _)| bits & bit != 0)
        .map(|(_, name)| name)
        .collect();
    if names.is_empty() {
        "-".to_owned()
    } else {
        names.join("+")
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Vector helpers                                                                                 */
/* --------------------------------------------------------------------------------------------- */

type V = (f64, f64);

fn add(a: V, b: V) -> V {
    (a.0 + b.0, a.1 + b.1)
}

fn sub(a: V, b: V) -> V {
    (a.0 - b.0, a.1 - b.1)
}

fn mul(a: V, k: f64) -> V {
    (a.0 * k, a.1 * k)
}

fn dot(a: V, b: V) -> f64 {
    a.0 * b.0 + a.1 * b.1
}

fn len(a: V) -> f64 {
    a.0.hypot(a.1)
}

/// `a`, shortened to at most `max`.
fn clamp_len(a: V, max: f64) -> V {
    let l = len(a);
    if l > max && l > 0.0 {
        mul(a, max / l)
    } else {
        a
    }
}

fn pixel(p: (i32, i32)) -> V {
    (f64::from(p.0), f64::from(p.1))
}

fn is_zero(a: V) -> bool {
    a.0 == 0.0 && a.1 == 0.0
}

/// Windows' size of a report: the larger axis plus half the smaller.
pub(crate) fn magnitude(a: V) -> f64 {
    let (x, y) = (a.0.abs(), a.1.abs());
    x.max(y) + x.min(y) / 2.0
}

/// A fraction of the screen as whole counts, never past what an `i32` holds.
fn whole(v: f64) -> i32 {
    v.round().clamp(-1.0e6, 1.0e6) as i32
}

/// The pixel a point on the captured screen falls in (`t` in fractions of it, like `m`).
pub(crate) fn target_pixel(t: V, width: i32, height: i32) -> (i32, i32) {
    if width <= 0 || height <= 0 {
        return (0, 0);
    }
    let px = (t.0 * f64::from(width))
        .floor()
        .clamp(0.0, f64::from(width - 1)) as i32;
    let py = (t.1 * f64::from(height))
        .floor()
        .clamp(0.0, f64::from(height - 1)) as i32;
    (px, py)
}

/// Where the viewer's picture is on the screen, when it is not the whole primary monitor: the game's
/// client area in game-only mode. Physical pixels of the virtual screen (the primary monitor's
/// top-left corner is its origin), like [`CursorLook`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Space {
    pub(crate) left: i32,
    pub(crate) top: i32,
    pub(crate) width: i32,
    pub(crate) height: i32,
}

impl Space {
    /// From a rectangle's edges, right and bottom exclusive. `None` for an empty one.
    pub(crate) fn from_edges(left: i32, top: i32, right: i32, bottom: i32) -> Option<Self> {
        let width = i32::try_from(i64::from(right) - i64::from(left)).ok()?;
        let height = i32::try_from(i64::from(bottom) - i64::from(top)).ok()?;
        (width > 0 && height > 0).then_some(Self {
            left,
            top,
            width,
            height,
        })
    }

    fn describe(space: Option<Self>) -> String {
        match space {
            None => "the primary monitor".to_owned(),
            Some(s) => format!(
                "the game's client area {}x{} at {},{}",
                s.width, s.height, s.left, s.top
            ),
        }
    }
}

/// The pixels a target may be put on, inclusive: the space, cut to the `width`×`height` screen (the
/// absolute paths reach the primary monitor only), or the whole screen without a space — and the
/// whole screen when the space lies entirely off it. Never empty for a screen that is not.
pub(crate) fn target_bounds(space: Option<Space>, width: i32, height: i32) -> (i32, i32, i32, i32) {
    let screen = (0, 0, (width - 1).max(0), (height - 1).max(0));
    let Some(s) = space else {
        return screen;
    };
    let x0 = s.left.max(0);
    let y0 = s.top.max(0);
    let x1 = s.left.saturating_add(s.width - 1).min(screen.2);
    let y1 = s.top.saturating_add(s.height - 1).min(screen.3);
    if x0 > x1 || y0 > y1 {
        screen
    } else {
        (x0, y0, x1, y1)
    }
}

/// The screen pixel a point of the viewer's picture falls in (`t` in fractions of it, like `m`):
/// [`target_pixel`] on the whole screen without a space; in game-only mode, `left + floor(x ·
/// width)` of the game's client area, clamped to it and to the screen ([`target_bounds`]).
pub(crate) fn map_point(t: V, space: Option<Space>, width: i32, height: i32) -> (i32, i32) {
    let Some(s) = space else {
        return target_pixel(t, width, height);
    };
    let (x0, y0, x1, y1) = target_bounds(Some(s), width, height);
    let axis = |f: f64, origin: i32, size: i32, lo: i32, hi: i32| -> i32 {
        let f = if f.is_finite() {
            f.clamp(0.0, 1.0)
        } else {
            0.0
        };
        let offset = (f * f64::from(size)).floor() as i64;
        (i64::from(origin) + offset).clamp(i64::from(lo), i64::from(hi)) as i32
    };
    (
        axis(t.0, s.left, s.width, x0, x1),
        axis(t.1, s.top, s.height, y0, y1),
    )
}

/* --------------------------------------------------------------------------------------------- */
/* The gain                                                                                       */
/* --------------------------------------------------------------------------------------------- */

/// Report-size bins (counts, Windows' magnitude): upper bounds, the last bin open. Finer where
/// Windows' curve bends (a few counts per report is a slow hand), coarser where it flattens.
const BINS: usize = 13;
const BIN_UPPER: [f64; BINS - 1] = [
    1.5, 2.5, 3.5, 5.5, 8.5, 12.5, 18.5, 26.5, 38.5, 56.5, 80.5, 128.5,
];
/// A bin forgets old samples by this per new one (about five samples' memory): EPP's curve is fixed,
/// the samples are quantised to whole pixels.
const BIN_DECAY: f64 = 0.8;
/// Every sample, for the log and the check of the linear model (about thirty samples' memory).
const POOLED_DECAY: f64 = 0.97;
/// A bin's gain is trusted for telling someone else's motion from ours after this many samples.
const KNOWN_SAMPLES: u32 = 4;
/// With EPP off, the measured gain replaces the model after this many samples, when it is off by
/// more than [`MEASURED_OFF_BY`], and gives way again within [`MEASURED_BACK_WITHIN`].
const MEASURED_MIN_SAMPLES: u32 = 30;
const MEASURED_OFF_BY: f64 = 0.12;
const MEASURED_BACK_WITHIN: f64 = 0.05;
/// A sample outside this (px per count) is not a gain.
const GAIN_MIN: f64 = 0.02;
const GAIN_MAX: f64 = 40.0;

fn bin_of(magnitude: f64) -> usize {
    BIN_UPPER
        .iter()
        .position(|&upper| magnitude < upper)
        .unwrap_or(BINS - 1)
}

/// Decayed sums of what sends did: pixels along the send per count, and the reports' mean size.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
struct Tally {
    along_px: f64,
    counts: f64,
    size: f64,
    weight: f64,
    n: u32,
}

impl Tally {
    fn add(&mut self, along_px: f64, counts: f64, size: f64, decay: f64) {
        self.along_px = self.along_px * decay + along_px;
        self.counts = self.counts * decay + counts;
        self.size = self.size * decay + size;
        self.weight = self.weight * decay + 1.0;
        self.n = self.n.saturating_add(1);
    }

    fn gain(&self) -> Option<f64> {
        (self.n > 0 && self.counts > 0.0).then(|| self.along_px / self.counts)
    }

    /// The mean report size (counts) the gain was learned at.
    fn centre(&self) -> Option<f64> {
        (self.n > 0 && self.weight > 0.0).then(|| self.size / self.weight)
    }
}

/// Where the gain in use comes from, for the log.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum GainSource {
    /// EPP off: `S × speed factor`.
    Model,
    /// EPP off, but Windows measurably does something else.
    Measured,
    /// EPP on: learned for this report size.
    Learned,
    /// EPP on, nothing learned for this size yet: the linear gain.
    Seed,
}

impl GainSource {
    fn name(self) -> &'static str {
        match self {
            Self::Model => "model",
            Self::Measured => "measured",
            Self::Learned => "learned",
            Self::Seed => "seed",
        }
    }
}

#[derive(Clone, Debug)]
struct GainModel {
    /// `S × speed factor`: physical px per count with EPP off, and EPP's seed.
    base: f64,
    epp: bool,
    bins: [Tally; BINS],
    pooled: Tally,
    /// With EPP off: what Windows measurably does, when that is not the model.
    measured: Option<f64>,
}

impl GainModel {
    fn new(settings: &PointerSettings) -> Self {
        Self {
            base: settings.scale() * speed_factor(settings.speed),
            epp: settings.epp,
            bins: [Tally::default(); BINS],
            pooled: Tally::default(),
            measured: None,
        }
    }

    /// Px per count for a report of `size` counts. With EPP on: between the sizes learned so far,
    /// interpolated; beyond them, along the slope of the two outermost (Windows' gain grows with
    /// the size, and holding it flat past the fastest move learned so far overshot the first move
    /// of a faster hand by half its length), at most doubled or halved; before anything is
    /// learned, the linear gain (the seed).
    fn at(&self, size: f64) -> (f64, GainSource) {
        if !self.epp {
            return match self.measured {
                Some(g) => (g, GainSource::Measured),
                None => (self.base, GainSource::Model),
            };
        }
        // Bins are in size order, and each one's centre lies inside it.
        let points: Vec<V> = self
            .bins
            .iter()
            .filter_map(|t| Some((t.centre()?, t.gain()?)))
            .collect();
        let (Some(&first), Some(&last)) = (points.first(), points.last()) else {
            return (self.base, GainSource::Seed);
        };
        let slope = |a: V, b: V| (b.0 - a.0 >= 1.0 && b.1 > a.1).then(|| (b.1 - a.1) / (b.0 - a.0));
        let g = if points.len() == 1 {
            // One size learned: no slope yet. Windows' default curve grows roughly with the square
            // root of the size over the sizes a hand makes; a guess, which the feedback corrects and
            // the next sample replaces.
            (first.1 * (size.max(0.5) / first.0).sqrt()).clamp(first.1 / 2.0, 2.0 * first.1)
        } else if size >= last.0 {
            let rising = points
                .len()
                .checked_sub(2)
                .and_then(|i| points.get(i))
                .and_then(|&before| slope(before, last));
            rising.map_or(last.1, |s| (last.1 + s * (size - last.0)).min(2.0 * last.1))
        } else if size <= first.0 {
            let rising = points.get(1).and_then(|&next| slope(first, next));
            rising.map_or(first.1, |s| {
                (first.1 - s * (first.0 - size)).max(first.1 / 2.0)
            })
        } else {
            points
                .windows(2)
                .find(|w| w[0].0 <= size && size < w[1].0)
                .map_or(last.1, |w| {
                    let (a, b) = (w[0], w[1]);
                    a.1 + (b.1 - a.1) * (size - a.0) / (b.0 - a.0)
                })
        };
        (g.max(GAIN_MIN), GainSource::Learned)
    }

    /// Is the gain for a report of these counts known well enough to call a large difference
    /// someone else's motion?
    fn known(&self, counts: (i32, i32)) -> bool {
        !self.epp
            || self
                .bins
                .get(bin_of(magnitude(pixel(counts))))
                .is_some_and(|t| t.n >= KNOWN_SAMPLES)
    }

    /// The gain for moving `want` px in one report: with EPP on, the report size `m` (counts) whose
    /// gain carries it that far, `at(m) · m = size of want` — found by bisection, since the size
    /// decides the gain. (Windows' curve makes that product grow with `m`; bisection finds a
    /// solution even where a learned curve does not.)
    fn gain_for(&self, want: V) -> f64 {
        let size = magnitude(want);
        if !self.epp || size < 1e-9 {
            return self.at(size).0;
        }
        let lowest = self
            .bins
            .iter()
            .filter_map(Tally::gain)
            .fold(self.base, f64::min)
            .max(GAIN_MIN);
        let (mut lo, mut hi) = (0.0, size / lowest + 1.0);
        for _ in 0..48 {
            let m = (lo + hi) / 2.0;
            if self.at(m).0 * m < size {
                lo = m;
            } else {
                hi = m;
            }
        }
        self.at(hi).0.max(GAIN_MIN)
    }

    /// The counts that move the cursor by `want` px, and the gain they were computed with.
    fn counts_for(&self, want: V) -> ((i32, i32), f64) {
        let g = self.gain_for(want);
        ((whole(want.0 / g), whole(want.1 / g)), g)
    }

    /// One send's effect: its counts and what the cursor did. Returns the sample's gain when it is
    /// one.
    fn learn(&mut self, counts: (i32, i32), moved: V) -> Option<f64> {
        let c = pixel(counts);
        let cl = len(c);
        if cl < 1.0 {
            return None;
        }
        let along = dot(moved, c) / cl;
        let g = along / cl;
        if !(GAIN_MIN..=GAIN_MAX).contains(&g) {
            return None;
        }
        let size = magnitude(c);
        if let Some(bin) = self.bins.get_mut(bin_of(size)) {
            bin.add(along, cl, size, BIN_DECAY);
        }
        self.pooled.add(along, cl, size, POOLED_DECAY);
        self.check_model();
        Some(g)
    }

    /// With EPP off: does Windows do what the model says? The model was measured on one PC.
    fn check_model(&mut self) {
        if self.epp || self.pooled.n < MEASURED_MIN_SAMPLES {
            return;
        }
        let Some(g) = self.pooled.gain() else {
            return;
        };
        let off = (g / self.base - 1.0).abs();
        match self.measured {
            None if off > MEASURED_OFF_BY => {
                self.measured = Some(g);
                tracing::warn!(
                    measured = %format!("{g:.3}"),
                    model = %format!("{:.3}", self.base),
                    samples = self.pooled.n,
                    "cursor sync: Windows moves the cursor by another amount per count than the \
                     model (display scale × pointer speed) says; exact moves use what it measures"
                );
            }
            Some(_) if off < MEASURED_BACK_WITHIN => {
                self.measured = None;
                tracing::debug!(
                    measured = %format!("{g:.3}"),
                    model = %format!("{:.3}", self.base),
                    "cursor sync: the measured gain agrees with the model again; using the model"
                );
            }
            Some(m) if (g / m - 1.0).abs() > MEASURED_BACK_WITHIN => self.measured = Some(g),
            _ => {}
        }
    }

    /// The gain at the most used report size (or at 10 counts before any), for the log.
    fn typical(&self) -> (f64, GainSource) {
        let size = self
            .bins
            .iter()
            .filter(|t| t.n > 0)
            .max_by_key(|t| t.n)
            .and_then(Tally::centre)
            .unwrap_or(10.0);
        self.at(size)
    }

    /// The learned sizes, `size:gain/samples`, for the log.
    fn bins_text(&self) -> String {
        if !self.epp {
            return "-".to_owned();
        }
        let learned: Vec<String> = self
            .bins
            .iter()
            .filter_map(|t| {
                let (c, g) = (t.centre()?, t.gain()?);
                Some(format!("{c:.1}:{g:.2}/{}", t.n))
            })
            .collect();
        if learned.is_empty() {
            "-".to_owned()
        } else {
            learned.join(",")
        }
    }
}

/* --------------------------------------------------------------------------------------------- */
/* The planner                                                                                    */
/* --------------------------------------------------------------------------------------------- */

/// A send whose effect may not have shown yet.
#[derive(Clone, Copy, Debug)]
struct Sent {
    at: Instant,
    /// The displacement it should make, px.
    d: V,
    /// A relative send's counts (what the gain learns from); `None` for an absolute one.
    counts: Option<(i32, i32)>,
    /// The viewer's number of the move that made it (`r.s`); `None` for an `m` or an unnumbered `r`.
    s: Option<u32>,
}

/// What one look at the cursor says about the sends before it.
#[derive(Clone, Copy, Debug)]
struct Seen {
    r: (i32, i32),
    /// What the sends resolved now should have moved the cursor, and what it did move since the
    /// last look.
    expected: V,
    moved: V,
    resolved: usize,
    /// The one send resolved, when exactly one was (a clean sample for the gain).
    single: Option<Sent>,
    /// Sends taken as done only because they are old, with no movement at all.
    timed_out: usize,
    /// Still expected to show.
    inflight: V,
    /// There was a previous look to compare with.
    tracked: bool,
    /// This look or the last one is on the screen's border, where Windows clamps.
    at_edge: bool,
}

/// Why the cursor did not do what our sends should have made it do.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Unexplained {
    /// Someone else moved it: the PC's own mouse, an application's warp.
    External(&'static str),
    /// Our sends moved nothing: they did not reach it.
    NoEffect,
}

/// The per-second aggregate.
#[derive(Clone, Debug, Default)]
struct Stats {
    since: Option<Instant>,
    camera: u32,
    point: u32,
    exact: u32,
    hid: u32,
    sendinput: u32,
    /// Absolute moves sent, and point moves that found the cursor already there.
    absolute: u32,
    already_there: u32,
    /// Relative sends in exact mode, and their counts (|x| + |y|).
    relative: u32,
    counts: u64,
    /// How far the cursor was from where the last move meant it to be, when the next move looked.
    resid_sum: f64,
    resid_n: u32,
    resid_max: f64,
    reanchors: u32,
    external: u32,
    no_effect: u32,
    failed: u32,
    /// Moves that found a send still in flight; sends taken as done by age alone.
    inflight: u32,
    timed_out: u32,
    transitions: u32,
    quiet_transitions: u32,
    /// Clean samples of what a count did, this window.
    gain: Tally,
    /// `m` — the viewer's absolute position — by the path that carried it.
    m_hid: u32,
    m_sendinput: u32,
    /// Button transitions that waited for an absolute report (an `m`, a point move) to show before
    /// going out (the FakerInput router's ordering wait), the longest such wait, and the waits that
    /// gave up.
    order_waits: u32,
    order_wait_max: Duration,
    order_timeouts: u32,
    /// The wheel, by the way each message went (see [`WheelTally`]).
    wheel: WheelTally,
    /// Cursor polls that found a numbered move the cursor did not show yet ([`CursorSync::unshown`]:
    /// the report's `ack` stayed below it).
    unshown_polls: u32,
    /// Numbered moves the HID router queued behind other input, and those taken as gone because
    /// they waited longer than [`QUEUED_MAX`].
    queued_moves: u32,
    queued_expired: u32,
}

impl Stats {
    fn moves(&self) -> u32 {
        self.camera + self.point + self.exact
    }

    /// Anything to say this window.
    fn active(&self) -> bool {
        self.moves() > 0
            || self.failed > 0
            || self.m_hid > 0
            || self.m_sendinput > 0
            || self.order_waits > 0
            || self.wheel != WheelTally::default()
    }

    fn resid(&mut self, px: f64) {
        self.resid_sum += px;
        self.resid_n += 1;
        self.resid_max = self.resid_max.max(px);
    }
}

/// Wheel messages for the aggregate line, by the way each went, told by whoever sent them: the
/// `SendInput` path counts its own, the FakerInput router its HID ones and the unfinished notches it
/// dropped.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct WheelTally {
    /// Messages sent by `SendInput` (smooth: 1/120 of a notch).
    pub(crate) sendinput: u32,
    /// Messages of the viewer's game mode (`game: true`) sent as whole HID notches.
    pub(crate) hid_game: u32,
    /// Messages not marked `game` sent as whole HID notches: game-only mode, or a foreground window
    /// that runs elevated while the agent does not.
    pub(crate) hid_stepped: u32,
    /// Whole notches written to HID (Wheel and AC Pan together).
    pub(crate) notches: u32,
    /// Unfinished notches dropped: a change of direction or of the wheel's route, a pause.
    pub(crate) resets: u32,
}

impl WheelTally {
    pub(crate) fn add(&mut self, other: Self) {
        self.sendinput = self.sendinput.saturating_add(other.sendinput);
        self.hid_game = self.hid_game.saturating_add(other.hid_game);
        self.hid_stepped = self.hid_stepped.saturating_add(other.hid_stepped);
        self.notches = self.notches.saturating_add(other.notches);
        self.resets = self.resets.saturating_add(other.resets);
    }
}

#[derive(Clone, Debug, Default)]
struct ForegroundWatch {
    checked_at: Option<Instant>,
    window: Option<usize>,
    pid: Option<u32>,
    /// The window's process runs elevated and this agent does not, and its exe: what Unicode
    /// `SendInput` cannot reach (UIPI). `None` when either could not be read, or for no window.
    elevation: Option<Elevation>,
}

/// Whether the foreground window runs elevated, and whether this agent does — what decides if
/// `SendInput`'s Unicode text reaches it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Elevation {
    pub(crate) foreground: bool,
    pub(crate) agent: bool,
    /// The foreground window's exe, for the log.
    pub(crate) exe: String,
}

impl Elevation {
    /// `SendInput` cannot reach the window: it runs elevated and the agent does not (UIPI takes the
    /// events, answers success and drops them).
    pub(crate) fn blocks_sendinput(&self) -> bool {
        self.foreground && !self.agent
    }
}

/// The planner: one per process-wide injector, shared by its HID and `SendInput` paths.
#[derive(Debug)]
pub(crate) struct CursorSync {
    settings: Option<PointerSettings>,
    settings_at: Option<Instant>,
    settings_failing: bool,
    /// Why the next first read of the settings happens, for its log line.
    settings_reason: &'static str,
    gain: GainModel,
    mode: Option<Mode>,
    /// Exact mode's intended position (px); `None`: re-anchored on the next exact move.
    aim: Option<V>,
    /// The target pixel the aim was on the last exact move, when there was one.
    aim_target: Option<V>,
    /// What rounding to whole counts left unsent (px): the cursor is short of the aim by exactly
    /// this, which the next move sends along — quantisation is not an error to damp.
    carry: V,
    /// Point mode's last target pixel, for its residual.
    point_target: Option<(i32, i32)>,
    pending: VecDeque<Sent>,
    /// Numbered moves waiting in the HID router's queue, and since when ([`Self::queued`]): not on
    /// the cursor until the router sends them, which plans them here.
    queued: VecDeque<(u32, Instant)>,
    /// The cursor as the last move saw it, before its send.
    last_seen: Option<(i32, i32)>,
    foreground: ForegroundWatch,
    stats: Stats,
    lone_coordinate_said: bool,
    /// Game-only mode: the game's client area, which targets are mapped into and the aim is kept
    /// in. `None`: the whole primary monitor (see the module's «Game-only mode: the space»).
    space: Option<Space>,
    /// The space's line: when it was last said at `debug`, and the changes since at `trace`.
    space_said_at: Option<Instant>,
    space_quiet: u32,
    /// The mouse buttons the HID router holds (HID bits) and its last button change — which, which
    /// way, when — for the visibility line ([`Self::note_visibility`]).
    hid_buttons: u8,
    last_hid_button: Option<(u8, bool, Instant)>,
    /// Whether the cursor showed at the last cursor poll; `None` before the first of a session.
    visible: Option<bool>,
}

impl Default for CursorSync {
    fn default() -> Self {
        Self::new()
    }
}

impl CursorSync {
    #[cfg(windows)]
    pub(crate) fn mode(&self) -> Option<Mode> {
        self.mode
    }

    pub(crate) fn new() -> Self {
        Self {
            settings: None,
            settings_at: None,
            settings_failing: false,
            settings_reason: "first move",
            gain: GainModel::new(&PointerSettings::FALLBACK),
            mode: None,
            aim: None,
            aim_target: None,
            carry: (0.0, 0.0),
            point_target: None,
            pending: VecDeque::new(),
            queued: VecDeque::new(),
            last_seen: None,
            foreground: ForegroundWatch::default(),
            stats: Stats::default(),
            lone_coordinate_said: false,
            space: None,
            space_said_at: None,
            space_quiet: 0,
            hid_buttons: 0,
            last_hid_button: None,
            visible: None,
        }
    }

    /// A session starts: nothing carried over, the settings read (and said) now. The space is the
    /// primary monitor until an event says otherwise (game-only mode sets it on every event).
    pub(crate) fn begin_session(&mut self, world: &mut dyn CursorWorld, now: Instant) {
        self.forget();
        self.queued.clear();
        self.mode = None;
        self.settings = None;
        self.settings_at = None;
        self.settings_reason = "session start";
        self.foreground = ForegroundWatch::default();
        self.space = None;
        self.space_said_at = None;
        self.space_quiet = 0;
        self.hid_buttons = 0;
        self.last_hid_button = None;
        self.visible = None;
        tracing::debug!(
            space = %Space::describe(None),
            "cursor sync: coordinate space at session start (game-only mode sets the game's client \
             area with the first event)"
        );
        self.refresh_settings(world, now);
        self.note_foreground(world, now);
    }

    /// The last session ended: its last aggregate line, and nothing kept.
    pub(crate) fn end_session(&mut self, now: Instant) {
        self.flush(now, "session end");
        self.forget();
        self.queued.clear();
        self.mode = None;
        self.settings_reason = "first move";
        self.settings = None;
        self.settings_at = None;
        self.space = None;
        self.hid_buttons = 0;
        self.last_hid_button = None;
        self.visible = None;
    }

    /// The HID router's mouse buttons: `held` (HID bits) now, after `change` — a button (its HID bit)
    /// going down or up, and when — or after a neutral report that let everything up (`None`).
    pub(crate) fn hid_buttons(&mut self, held: u8, change: Option<(u8, bool, Instant)>) {
        self.hid_buttons = held;
        if change.is_some() {
            self.last_hid_button = change;
        }
    }

    /// The mouse buttons the HID router last said it holds (HID bits).
    #[cfg_attr(not(windows), allow(dead_code))]
    pub(crate) fn hid_buttons_held(&self) -> u8 {
        self.hid_buttons
    }

    /// The cursor poll's look (about thirty a second while a session runs): a change of the cursor's
    /// visibility is said at `debug` with the mouse buttons held then on either path (`sendinput`: the
    /// `SendInput` ledger's, as HID bits) and the HID router's last button change — a game hides the
    /// cursor while its camera button is held, so a cursor hidden with nothing held is a button the
    /// game still thinks down. The first look of a session says nothing.
    pub(crate) fn note_visibility(&mut self, visible: bool, sendinput: u8, now: Instant) {
        let before = self.visible.replace(visible);
        if before.is_none_or(|was| was == visible) {
            return;
        }
        let (last, last_ms) = match self.last_hid_button {
            Some((bit, down, at)) => (
                format!(
                    "{} {}",
                    hid_button_names(bit),
                    if down { "down" } else { "up" }
                ),
                now.saturating_duration_since(at).as_millis().to_string(),
            ),
            None => ("-".to_owned(), "-".to_owned()),
        };
        tracing::debug!(
            visible,
            buttons_held = %hid_button_names(self.hid_buttons | sendinput),
            hid = %hid_button_names(self.hid_buttons),
            sendinput = %hid_button_names(sendinput),
            last_hid_button = %last,
            last_hid_button_ms = %last_ms,
            "cursor visibility changed (the input's view: what was held then)"
        );
    }

    /// Where the viewer's picture is: the whole primary monitor (`None`), or in game-only mode the
    /// game's client area. Set before every event; a change is said (at most one `debug` line a
    /// second, the rest at `trace`, counted) and starts exact mode afresh — an aim kept in the old
    /// area means nothing in the new one.
    pub(crate) fn set_space(&mut self, space: Option<Space>, now: Instant) {
        if self.space == space {
            return;
        }
        let from = std::mem::replace(&mut self.space, space);
        self.aim = None;
        self.aim_target = None;
        self.carry = (0.0, 0.0);
        if self
            .space_said_at
            .is_some_and(|t| now.saturating_duration_since(t) < STATS_EVERY)
        {
            self.space_quiet = self.space_quiet.saturating_add(1);
            tracing::trace!(
                to = %Space::describe(space),
                "cursor sync: coordinate space changed"
            );
            return;
        }
        tracing::debug!(
            from = %Space::describe(from),
            to = %Space::describe(space),
            changes_since_last_line = self.space_quiet,
            "cursor sync: coordinate space (targets are mapped into it and the cursor is kept in it; \
             the camera's counts are not touched)"
        );
        self.space_said_at = Some(now);
        self.space_quiet = 0;
    }

    /// Targets are mapped into the game's client area (game-only mode).
    pub(crate) fn confined(&self) -> bool {
        self.space.is_some()
    }

    /// Where a mouse button pressed now would land: while a move of ours is still on its way (sent
    /// under [`REFLECT_TIMEOUT`] ago), where it is taking the cursor — exact mode's aim, or the last
    /// absolute move's pixel (a tap is `m`, `d`, `u` back to back, and the `d` must be judged where
    /// the `m` puts it, not where the cursor still is) — else where the cursor is. `None` when the
    /// cursor cannot be read.
    pub(crate) fn press_target(
        &mut self,
        world: &mut dyn CursorWorld,
        now: Instant,
    ) -> Option<(i32, i32)> {
        let moving = self
            .pending
            .iter()
            .any(|s| now.saturating_duration_since(s.at) < REFLECT_TIMEOUT);
        if moving {
            if let Some(aim) = self.aim {
                return Some((aim.0.round() as i32, aim.1.round() as i32));
            }
            if let Some(p) = self.point_target {
                return Some(p);
            }
        }
        world.look().ok().map(|look| (look.x, look.y))
    }

    /// The foreground window's elevation, looked at afresh (not from the 200 ms cache: a text is
    /// routed on it), described only when the window changed. `None` when it cannot be read.
    pub(crate) fn foreground_elevation(
        &mut self,
        world: &mut dyn CursorWorld,
        now: Instant,
    ) -> Option<Elevation> {
        self.foreground.checked_at = None;
        self.note_foreground(world, now);
        self.foreground.elevation.clone()
    }

    /// Everything held was released (`ra`, silence, a mode switch on the viewer): the stroke ended.
    /// The next exact move re-anchors on the real cursor. The HID router drops its queue with every
    /// release, so the numbered moves waiting in it will never show: they are no longer waited for.
    pub(crate) fn release(&mut self, now: Instant) {
        if !self.queued.is_empty() {
            tracing::trace!(
                dropped = self.queued.len(),
                "cursor sync: numbered moves waiting in the router's queue are dropped with it"
            );
            self.queued.clear();
        }
        self.flush(now, "release");
        self.forget();
        self.mode = None;
    }

    /// The HID router queued a numbered move behind other input (a click, a key, a tap's minimum
    /// hold): it is not on the cursor until the router sends it, which plans it here. Until then
    /// [`Self::unshown`] holds the cursor report's `ack` below it.
    pub(crate) fn queued(&mut self, s: u32, now: Instant) {
        if self.queued.len() >= QUEUED_KEPT {
            self.queued.pop_front();
        }
        self.queued.push_back((s, now));
        self.stats.queued_moves = self.stats.queued_moves.saturating_add(1);
        tracing::trace!(
            s,
            waiting = self.queued.len(),
            "cursor sync: a numbered move waits in the router's queue"
        );
    }

    /// The lowest move number (`r.s`) the cursor at `at` does not show yet, for the cursor report's
    /// `ack`; `None` when every numbered move shows. `at` is a look the caller took under the same
    /// lock as every plan, so no move is planned between the look and this.
    ///
    /// A move does not show while its send is in flight — matched against the cursor's movement as
    /// [`Self::resolve`] matches (Windows applies reports in order), each send taken as shown
    /// [`REFLECT_TIMEOUT`] after it was made at the latest — or while it waits in the HID router's
    /// queue ([`Self::queued`], at most [`QUEUED_MAX`]). Nothing is taken off the books here: the
    /// next move's own look does that, and learns from it. Counted for the per-second line; each
    /// poll that found one at `trace`.
    pub(crate) fn unshown(&mut self, at: (i32, i32), now: Instant) -> Option<u32> {
        let before = self.queued.len();
        self.queued
            .retain(|&(_, since)| now.saturating_duration_since(since) < QUEUED_MAX);
        let expired = before - self.queued.len();
        if expired > 0 {
            self.stats.queued_expired = self
                .stats
                .queued_expired
                .saturating_add(u32::try_from(expired).unwrap_or(u32::MAX));
            tracing::trace!(
                expired,
                after_ms = QUEUED_MAX.as_millis(),
                "cursor sync: numbered moves waited in the router's queue too long; no longer \
                 waited for"
            );
        }
        let queued = self.queued.iter().map(|&(s, _)| s).min();
        let shown = match self.last_seen {
            Some(last) => self.matched(at, last, now).0,
            // Nothing tracked: nothing is in flight either (a send is only made after a look).
            None => self.pending.len(),
        };
        let in_flight = self
            .pending
            .iter()
            .skip(shown)
            .filter_map(|sent| sent.s)
            .min();
        let unshown = match (in_flight, queued) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
        if unshown.is_some() {
            self.stats.unshown_polls = self.stats.unshown_polls.saturating_add(1);
            tracing::trace!(
                cursor_x = at.0,
                cursor_y = at.1,
                last_seen = ?self.last_seen,
                sends = self.pending.len(),
                shown,
                in_flight = ?in_flight,
                queued = ?queued,
                "cursor sync: a numbered move does not show yet; the report's ack stays below it"
            );
        }
        unshown
    }

    /// The send this planner asked for failed: nothing of it is expected any more.
    pub(crate) fn failed(&mut self, why: &'static str) {
        self.stats.failed += 1;
        if self.stats.failed == 1 {
            tracing::debug!(
                why,
                "cursor sync: re-anchor on the next move: the send failed"
            );
        } else {
            tracing::trace!(why, "cursor sync: another send failed");
        }
        self.forget();
    }

    /// Any input: say the foreground window when it changed (at most one look per 200 ms).
    pub(crate) fn note_input(&mut self, world: &mut dyn CursorWorld, now: Instant) {
        self.note_foreground(world, now);
    }

    /// The aggregate line, if its second is over. Called on every move and from the ~30 Hz cursor
    /// poll, so the last second of a stroke is said without waiting for the next one.
    pub(crate) fn flush_if_due(&mut self, now: Instant) {
        if self
            .stats
            .since
            .is_some_and(|t| now.saturating_duration_since(t) >= STATS_EVERY)
        {
            self.flush(now, "second");
        }
    }

    /// Nothing in flight, no aim: the next move starts afresh.
    fn forget(&mut self) {
        self.pending.clear();
        self.last_seen = None;
        self.aim = None;
        self.aim_target = None;
        self.carry = (0.0, 0.0);
        self.point_target = None;
    }

    /// One `r`: what to send. `held`: a mouse button this agent injected is down (either path).
    pub(crate) fn plan(
        &mut self,
        event: RelEvent,
        held: bool,
        path: RelPath,
        world: &mut dyn CursorWorld,
        now: Instant,
    ) -> Plan {
        self.flush_if_due(now);
        self.refresh_settings(world, now);
        self.note_foreground(world, now);
        self.stats.since.get_or_insert(now);
        match path {
            RelPath::Hid => self.stats.hid += 1,
            RelPath::SendInput => self.stats.sendinput += 1,
        }
        // A move the router had queued goes now: from here it is in flight, or done.
        if let Some(s) = event.s {
            if let Some(i) = self.queued.iter().position(|&(q, _)| q == s) {
                self.queued.remove(i);
            }
        }

        if !event.dx.is_finite() || !event.dy.is_finite() {
            // The path's own checks say so (and move nothing), as before.
            tracing::trace!(
                dx = event.dx,
                dy = event.dy,
                "cursor sync: not a number; camera path"
            );
            self.stats.camera += 1;
            self.forget();
            return Plan::Camera;
        }
        let target = self.target_of(&event);
        let (width, height) = world.screen();
        let look = world.look();
        let (mode, why) = decide(&look, width, height, target.is_some(), held);
        self.note_mode(mode, why, &look, held, target.is_some(), path, now);

        match (mode, look) {
            (Mode::Point, Ok(look)) => {
                let t = target.unwrap_or((0.5, 0.5));
                self.point(t, event.s, look, (width, height), path, now)
            }
            (Mode::Exact, Ok(look)) => {
                self.exact(&event, target, look, (width, height), held, path, now)
            }
            _ => {
                self.stats.camera += 1;
                self.forget();
                tracing::trace!(
                    path = path.name(),
                    dx = event.dx,
                    dy = event.dy,
                    why,
                    "cursor sync: camera move"
                );
                Plan::Camera
            }
        }
    }

    /// The target, when the message carries a usable one: both coordinates, numbers, clamped to the
    /// screen. One without the other is not a target (the contract refuses such a message; this is
    /// the last line).
    fn target_of(&mut self, event: &RelEvent) -> Option<V> {
        match (event.x, event.y) {
            (Some(x), Some(y)) if x.is_finite() && y.is_finite() => {
                Some((x.clamp(0.0, 1.0), y.clamp(0.0, 1.0)))
            }
            (None, None) => None,
            (x, y) => {
                if !self.lone_coordinate_said {
                    self.lone_coordinate_said = true;
                    tracing::debug!(
                        has_x = x.is_some(),
                        has_y = y.is_some(),
                        "cursor sync: a move carries half a target (or not a number); moved as \
                         if it had none (said once)"
                    );
                }
                None
            }
        }
    }

    /// One `m`, the viewer's "the cursor is here" at `t` (fractions of the captured screen, like a
    /// target): the pixel it falls in and the screen it is on — what FakerInput's absolute report
    /// is aimed at (its centre), exactly as for a point move. `None` when the screen size is unknown
    /// (nothing can be aimed then).
    ///
    /// The move itself is not the planner's to decide: `m` always goes as one absolute move, on
    /// whichever path the router chose (`path`, for the count). What the planner does is keep its
    /// books as a point move does: it looks at the cursor before the move, puts the move in flight
    /// (so the next look does not take it for someone else's motion and re-anchor with a line in the
    /// log), and forgets exact mode's aim, so the next exact move re-anchors on the real cursor
    /// instead of pulling it back toward where the aim was.
    pub(crate) fn absolute(
        &mut self,
        t: V,
        path: RelPath,
        world: &mut dyn CursorWorld,
        now: Instant,
    ) -> Option<(i32, i32, i32, i32)> {
        self.absolute_numbered(t, None, path, world, now)
    }

    /// A verified re-anchor can also carry a relative move's number when a direct host's
    /// cursor starts off the primary monitor. Its sample must still wait for reflection.
    pub(crate) fn absolute_numbered(
        &mut self,
        t: V,
        seq: Option<u32>,
        path: RelPath,
        world: &mut dyn CursorWorld,
        now: Instant,
    ) -> Option<(i32, i32, i32, i32)> {
        self.flush_if_due(now);
        self.stats.since.get_or_insert(now);
        match path {
            RelPath::Hid => self.stats.m_hid += 1,
            RelPath::SendInput => self.stats.m_sendinput += 1,
        }
        let (width, height) = world.screen();
        if width <= 0 || height <= 0 {
            // Nothing to aim at, and nothing known about where the cursor goes: start afresh.
            self.forget();
            tracing::trace!(
                path = path.name(),
                width,
                height,
                "cursor sync: absolute position (m): the screen size is unknown"
            );
            return None;
        }
        let t = (t.0.clamp(0.0, 1.0), t.1.clamp(0.0, 1.0));
        // Into the game's client area in game-only mode.
        let (px, py) = map_point(t, self.space, width, height);
        // Leaving exact mode, as a point move does: its next move re-anchors.
        self.aim = None;
        self.aim_target = None;
        self.carry = (0.0, 0.0);
        match world.look() {
            Ok(look) => {
                let seen = self.resolve((look.x, look.y), (width, height), now);
                if seen.tracked && is_zero(seen.inflight) {
                    // Where the last absolute move (an `m`, a point move) meant the cursor to be.
                    if let Some(p) = self.point_target {
                        self.stats.resid(len(sub(pixel(seen.r), pixel(p))));
                    }
                }
                let d = sub(pixel((px, py)), add(pixel(seen.r), seen.inflight));
                if len(d) >= 0.5 {
                    self.pending.push_back(Sent {
                        at: now,
                        d,
                        counts: None,
                        s: seq,
                    });
                }
                tracing::trace!(
                    path = path.name(),
                    px,
                    py,
                    cursor_x = seen.r.0,
                    cursor_y = seen.r.1,
                    "cursor sync: absolute position (m)"
                );
            }
            Err(error) => {
                // Nothing to compare with: the next move starts afresh.
                self.pending.clear();
                self.last_seen = None;
                tracing::trace!(
                    path = path.name(),
                    px,
                    py,
                    %error,
                    "cursor sync: absolute position (m); the cursor is unreadable"
                );
            }
        }
        self.point_target = Some((px, py));
        Some((px, py, width, height))
    }

    /// A mouse button transition waited `waited` for an absolute report (an `m`, a point move) to
    /// show before it went out (the FakerInput router's ordering wait), or gave up after it
    /// (`timed_out`): counted into the aggregate line.
    pub(crate) fn order_waited(&mut self, waited: Duration, timed_out: bool, now: Instant) {
        self.flush_if_due(now);
        self.stats.since.get_or_insert(now);
        self.stats.order_waits += 1;
        self.stats.order_wait_max = self.stats.order_wait_max.max(waited);
        if timed_out {
            self.stats.order_timeouts += 1;
        }
    }

    /// Wheel messages and the HID wheel's dropped remainders, counted into the aggregate line (the
    /// planner does not route the wheel; its line is the input's per-second one).
    pub(crate) fn count_wheel(&mut self, tally: WheelTally, now: Instant) {
        if tally == WheelTally::default() {
            return;
        }
        self.flush_if_due(now);
        self.stats.since.get_or_insert(now);
        self.stats.wheel.add(tally);
    }

    fn point(
        &mut self,
        t: V,
        s: Option<u32>,
        look: CursorLook,
        (width, height): (i32, i32),
        path: RelPath,
        now: Instant,
    ) -> Plan {
        self.stats.point += 1;
        let seen = self.resolve((look.x, look.y), (width, height), now);
        if !is_zero(seen.inflight) {
            self.stats.inflight += 1;
        }
        if seen.tracked && is_zero(seen.inflight) {
            if let Some(p) = self.point_target {
                self.stats.resid(len(sub(pixel(seen.r), pixel(p))));
            }
        }
        // Leaving exact mode: its next move re-anchors.
        self.aim = None;
        self.aim_target = None;
        self.carry = (0.0, 0.0);
        let (px, py) = map_point(t, self.space, width, height);
        self.point_target = Some((px, py));
        let expect = add(pixel(seen.r), seen.inflight);
        let d = sub(pixel((px, py)), expect);
        if len(d) < 0.5 {
            self.stats.already_there += 1;
            tracing::trace!(
                path = path.name(),
                px,
                py,
                "cursor sync: point move: already there"
            );
            return Plan::Nothing;
        }
        self.stats.absolute += 1;
        self.pending.push_back(Sent {
            at: now,
            d,
            counts: None,
            s,
        });
        tracing::trace!(
            path = path.name(),
            px,
            py,
            cursor_x = seen.r.0,
            cursor_y = seen.r.1,
            s = ?s,
            "cursor sync: point move"
        );
        Plan::Absolute {
            px,
            py,
            width,
            height,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn exact(
        &mut self,
        event: &RelEvent,
        target: Option<V>,
        look: CursorLook,
        (width, height): (i32, i32),
        held: bool,
        path: RelPath,
        now: Instant,
    ) -> Plan {
        self.stats.exact += 1;
        // The aim stays in the viewer's picture: the screen, or in game-only mode the game's client
        // area (cut to the screen) — the cursor cannot be moved out of the game's window. The hand's
        // delta is a fraction of that picture too.
        let space = self.space;
        let (x0, y0, x1, y1) = target_bounds(space, width, height);
        let (x0, y0, x1, y1) = (f64::from(x0), f64::from(y0), f64::from(x1), f64::from(y1));
        let clamp = |p: V| (p.0.clamp(x0, x1), p.1.clamp(y0, y1));
        let (wf, hf) = space.map_or((f64::from(width), f64::from(height)), |s| {
            (f64::from(s.width), f64::from(s.height))
        });
        let was_tracking = self.last_seen.is_some();
        let seen = self.resolve((look.x, look.y), (width, height), now);
        if !is_zero(seen.inflight) {
            self.stats.inflight += 1;
        }
        self.stats.timed_out += u32::try_from(seen.timed_out).unwrap_or(u32::MAX);

        // What the sends just resolved did: someone else's motion, nothing at all, or a sample.
        // (With sends still in flight and a still cursor, both sides are zero: nothing to judge.)
        let mut inflight = seen.inflight;
        if seen.tracked {
            let known = seen
                .single
                .and_then(|s| s.counts)
                .map_or(!self.gain.epp, |c| self.gain.known(c));
            match (seen.at_edge, unexplained(&seen, known)) {
                (false, Some(Unexplained::External(why))) => {
                    self.stats.external += 1;
                    self.reanchor(why, &seen, path);
                    inflight = (0.0, 0.0);
                }
                (false, Some(Unexplained::NoEffect)) => {
                    self.stats.no_effect += 1;
                    self.reanchor(
                        "our moves did not move the cursor (UIPI? see the foreground window's \
                         elevation)",
                        &seen,
                        path,
                    );
                    inflight = (0.0, 0.0);
                }
                (false, None) => {
                    if let Some(Sent {
                        counts: Some(c), ..
                    }) = seen.single
                    {
                        if let Some(g) = self.gain.learn(c, seen.moved) {
                            let cl = len(pixel(c));
                            self.stats.gain.add(g * cl, cl, magnitude(pixel(c)), 1.0);
                        }
                    }
                }
                (true, _) => {}
            }
        }

        let x_now = add(pixel(seen.r), inflight);
        let entering = self.aim.is_none() || !was_tracking;
        let base = match self.aim {
            Some(a) if !entering => {
                self.stats.resid(len(sub(a, x_now)));
                a
            }
            _ => {
                self.aim_target = None;
                self.carry = (0.0, 0.0);
                clamp(x_now)
            }
        };
        let hand = (
            event.dx.clamp(-1.0, 1.0) * wf,
            event.dy.clamp(-1.0, 1.0) * hf,
        );
        let target_px = target.map(|t| pixel(map_point(t, space, width, height)));
        let (goal, feed) = match (target_px, self.aim_target) {
            // The pointer's own motion since the last move is the hand's.
            (Some(t), Some(previous)) => (t, sub(t, previous)),
            // The first move toward a target: the hand leads, the rest is correction.
            (Some(t), None) => (t, sub(clamp(add(base, hand)), base)),
            (None, _) => {
                let goal = clamp(add(base, hand));
                (goal, sub(goal, base))
            }
        };
        // Where the cursor falls short of the goal after the hand's own motion; the part rounding
        // left unsent is known exactly and goes along whole, the rest is error, corrected damped
        // and bounded.
        let gap = sub(goal, add(x_now, feed));
        let error = sub(gap, self.carry);
        let correction = if len(error) <= DEADBAND_PX {
            (0.0, 0.0)
        } else {
            clamp_len(
                mul(error, DAMPING),
                CORRECTION_MIN_PX.max(CORRECTION_SHARE * len(feed)),
            )
        };
        let want = add(add(feed, correction), self.carry);
        let ((cx, cy), g) = self.gain.counts_for(want);
        self.carry = sub(want, mul(pixel((cx, cy)), g));
        self.aim = Some(goal);
        self.aim_target = target_px;
        tracing::trace!(
            path = path.name(),
            held,
            target = target.is_some(),
            s = ?event.s,
            cursor_x = seen.r.0,
            cursor_y = seen.r.1,
            inflight = %format!("{:.1},{:.1}", inflight.0, inflight.1),
            aim = %format!("{:.1},{:.1}", goal.0, goal.1),
            feed = %format!("{:.1},{:.1}", feed.0, feed.1),
            correction = %format!("{:.1},{:.1}", correction.0, correction.1),
            cx,
            cy,
            gain = %format!("{g:.3}"),
            "cursor sync: exact move"
        );
        if (cx, cy) == (0, 0) {
            return Plan::Nothing;
        }
        self.stats.relative += 1;
        self.stats.counts += u64::from(cx.unsigned_abs()) + u64::from(cy.unsigned_abs());
        self.pending.push_back(Sent {
            at: now,
            d: mul(pixel((cx, cy)), g),
            counts: Some((cx, cy)),
            s: event.s,
        });
        Plan::Relative { cx, cy }
    }

    /// The aim moves to the real cursor: our model of it does not hold any more. At `debug` up to
    /// [`MODE_LINES_PER_WINDOW`] a second (someone moving the PC's own mouse through a drag would
    /// re-anchor every move), the rest at `trace`, counted in the aggregate.
    fn reanchor(&mut self, why: &'static str, seen: &Seen, path: RelPath) {
        self.stats.reanchors += 1;
        let aim = self
            .aim
            .map_or_else(|| "-".to_owned(), |a| format!("{:.1},{:.1}", a.0, a.1));
        if self.stats.reanchors <= MODE_LINES_PER_WINDOW {
            tracing::debug!(
                why,
                path = path.name(),
                cursor_x = seen.r.0,
                cursor_y = seen.r.1,
                sends = seen.resolved,
                expected = %format!("{:.1},{:.1}", seen.expected.0, seen.expected.1),
                moved = %format!("{:.1},{:.1}", seen.moved.0, seen.moved.1),
                aim = %aim,
                "cursor sync: re-anchored on the real cursor"
            );
        } else {
            tracing::trace!(why, aim = %aim, "cursor sync: re-anchored on the real cursor");
        }
        self.aim = None;
        self.aim_target = None;
        // What we thought was still on its way is as unreliable as the rest: a send that shows
        // later is one more small surprise, not a wrong anchor.
        self.pending.clear();
    }

    /// Match the cursor's movement since the last look to the sends made after it. Windows applies
    /// reports in order, so if the cursor moved at all, at least the first send has shown; of the
    /// possible prefixes, the one whose expected sum is nearest what it moved. Sends older than
    /// [`REFLECT_TIMEOUT`] are done in any case.
    fn resolve(&mut self, r: (i32, i32), (width, height): (i32, i32), now: Instant) -> Seen {
        let on_edge = |p: (i32, i32)| p.0 <= 0 || p.1 <= 0 || p.0 >= width - 1 || p.1 >= height - 1;
        let Some(last) = self.last_seen.replace(r) else {
            self.pending.clear();
            return Seen {
                r,
                expected: (0.0, 0.0),
                moved: (0.0, 0.0),
                resolved: 0,
                single: None,
                timed_out: 0,
                inflight: (0.0, 0.0),
                tracked: false,
                at_edge: on_edge(r),
            };
        };
        let moved = sub(pixel(r), pixel(last));
        let still = r == last;
        let (j, forced) = self.matched(r, last, now);
        let single = if j == 1 {
            self.pending.front().copied()
        } else {
            None
        };
        let expected = self
            .pending
            .drain(..j.min(self.pending.len()))
            .fold((0.0, 0.0), |sum, s| add(sum, s.d));
        let inflight = self.pending.iter().fold((0.0, 0.0), |sum, s| add(sum, s.d));
        Seen {
            r,
            expected,
            moved,
            resolved: j,
            single,
            timed_out: if still { forced } else { 0 },
            inflight,
            tracked: true,
            at_edge: on_edge(r) || on_edge(last),
        }
    }

    /// How many of the sends in flight, oldest first, the cursor at `r` shows, having been at `last`
    /// before any of them could show — and how many at their front are older than
    /// [`REFLECT_TIMEOUT`], and so taken as shown whatever the cursor did. Windows applies reports in
    /// order, so if the cursor moved at all, at least the first send has shown; of the possible
    /// prefixes, the one whose expected sum is nearest what it moved. Reads only: [`Self::resolve`]
    /// takes them off the books, [`Self::unshown`] asks without.
    fn matched(&self, r: (i32, i32), last: (i32, i32), now: Instant) -> (usize, usize) {
        let moved = sub(pixel(r), pixel(last));
        let forced = self
            .pending
            .iter()
            .take_while(|s| now.saturating_duration_since(s.at) >= REFLECT_TIMEOUT)
            .count();
        let still = r == last;
        let j = if self.pending.is_empty() {
            0
        } else if still {
            forced
        } else {
            let from = forced.max(1);
            let mut best = (from, f64::INFINITY);
            let mut sum = (0.0, 0.0);
            for (i, s) in self.pending.iter().enumerate() {
                sum = add(sum, s.d);
                let k = i + 1;
                if k < from {
                    continue;
                }
                let off = len(sub(moved, sum));
                if off <= best.1 {
                    best = (k, off);
                }
            }
            best.0
        };
        (j, forced)
    }

    #[allow(clippy::too_many_arguments)]
    fn note_mode(
        &mut self,
        mode: Mode,
        why: &'static str,
        look: &Result<CursorLook, String>,
        held: bool,
        target: bool,
        path: RelPath,
        now: Instant,
    ) {
        let from = self.mode.replace(mode);
        if from == Some(mode) {
            return;
        }
        self.stats.transitions += 1;
        let settings = self.settings.unwrap_or(PointerSettings::FALLBACK);
        let (gain, source) = self.gain.typical();
        let (cursor, visible, suppressed) = match look {
            Ok(l) => (format!("{},{}", l.x, l.y), l.showing, l.suppressed),
            Err(error) => (format!("unreadable: {error}"), false, false),
        };
        let from = from.map_or("none", Mode::name);
        if self.stats.transitions > MODE_LINES_PER_WINDOW {
            self.stats.quiet_transitions += 1;
            tracing::trace!(from, to = mode.name(), why, "cursor sync: mode");
            return;
        }
        tracing::debug!(
            from,
            to = mode.name(),
            why,
            path = path.name(),
            cursor = %cursor,
            visible,
            suppressed,
            buttons_held = held,
            target,
            scale = %format!("{:.2}", settings.scale()),
            dpi = settings.dpi,
            epp = settings.epp,
            speed = settings.speed,
            gain = %format!("{gain:.3}"),
            gain_source = source.name(),
            since_ms = self
                .stats
                .since
                .map_or(0, |t| now.saturating_duration_since(t).as_millis()),
            "cursor sync: mode"
        );
    }

    fn refresh_settings(&mut self, world: &mut dyn CursorWorld, now: Instant) {
        if self
            .settings_at
            .is_some_and(|t| now.saturating_duration_since(t) < SETTINGS_EVERY)
        {
            return;
        }
        self.settings_at = Some(now);
        let read = match world.settings() {
            Ok(read) => {
                if self.settings_failing {
                    self.settings_failing = false;
                    tracing::debug!("cursor sync: pointer settings readable again");
                }
                read
            }
            Err(error) => {
                if !self.settings_failing {
                    self.settings_failing = true;
                    tracing::debug!(
                        %error,
                        "cursor sync: pointer settings unreadable; keeping the last ones (before \
                         any: 96 dpi, no acceleration, speed 10)"
                    );
                }
                if self.settings.is_some() {
                    return;
                }
                PointerSettings::FALLBACK
            }
        };
        let sane = read.sanitized();
        if sane != read {
            tracing::debug!(
                dpi = read.dpi,
                speed = read.speed,
                "cursor sync: pointer settings out of range; read as {} dpi, speed {}",
                sane.dpi,
                sane.speed
            );
        }
        if self.settings == Some(sane) {
            return;
        }
        let first = self.settings.is_none();
        self.settings = Some(sane);
        self.gain = GainModel::new(&sane);
        let reason = if first {
            self.settings_reason
        } else {
            // What was learned or anchored under the old settings does not hold any more.
            self.forget();
            self.stats.reanchors += 1;
            "changed"
        };
        tracing::debug!(
            reason,
            dpi = sane.dpi,
            scale = %format!("{:.2}", sane.scale()),
            epp = sane.epp,
            speed = sane.speed,
            speed_factor = speed_factor(sane.speed),
            thresholds = %format!("{},{}", sane.thresholds.0, sane.thresholds.1),
            awareness = sane.awareness,
            gain_model = if sane.epp {
                "learned per report size (Windows' acceleration), seeded with the linear gain"
            } else {
                "linear: scale × speed factor"
            },
            px_per_count = %format!("{:.3}", self.gain.base),
            "cursor sync: pointer settings"
        );
    }

    fn note_foreground(&mut self, world: &mut dyn CursorWorld, now: Instant) {
        if self
            .foreground
            .checked_at
            .is_some_and(|t| now.saturating_duration_since(t) < FOREGROUND_EVERY)
        {
            return;
        }
        self.foreground.checked_at = Some(now);
        let window = world.foreground();
        if self.foreground.window == Some(window) {
            return;
        }
        self.foreground.window = Some(window);
        if window == 0 {
            tracing::debug!("foreground window: none");
            self.foreground.pid = None;
            self.foreground.elevation = None;
            return;
        }
        let info = world.describe_foreground(window);
        let same_process = self.foreground.pid == Some(info.pid);
        self.foreground.pid = Some(info.pid);
        let exe = match &info.exe {
            Ok(exe) => exe.clone(),
            Err(error) => format!("unknown ({error})"),
        };
        self.foreground.elevation = match (&info.elevated, &info.agent_elevated) {
            (Ok(foreground), Ok(agent)) => Some(Elevation {
                foreground: *foreground,
                agent: *agent,
                exe: exe.clone(),
            }),
            _ => None,
        };
        let agent_elevated = match &info.agent_elevated {
            Ok(e) => e.to_string(),
            Err(error) => format!("unknown ({error})"),
        };
        match &info.elevated {
            Ok(elevated) => tracing::debug!(
                window = %format!("{window:#x}"),
                pid = info.pid,
                exe = %exe,
                elevated,
                agent_elevated = %agent_elevated,
                same_process,
                "foreground window changed"
            ),
            Err(error) => tracing::debug!(
                window = %format!("{window:#x}"),
                pid = info.pid,
                exe = %exe,
                elevation_error = %error,
                agent_elevated = %agent_elevated,
                same_process,
                "foreground window changed; whether it runs elevated is unreadable"
            ),
        }
    }

    fn flush(&mut self, now: Instant, why: &'static str) {
        let Some(since) = self.stats.since else {
            return;
        };
        let s = std::mem::take(&mut self.stats);
        if !s.active() {
            return;
        }
        let settings = self.settings.unwrap_or(PointerSettings::FALLBACK);
        let (gain, source) = self.gain.typical();
        let resid_mean = if s.resid_n > 0 {
            s.resid_sum / f64::from(s.resid_n)
        } else {
            0.0
        };
        tracing::debug!(
            why,
            window_ms = now.saturating_duration_since(since).as_millis(),
            camera = s.camera,
            point = s.point,
            exact = s.exact,
            hid = s.hid,
            sendinput = s.sendinput,
            absolute = s.absolute,
            already_there = s.already_there,
            relative = s.relative,
            counts = s.counts,
            resid_mean_px = %format!("{resid_mean:.2}"),
            resid_max_px = %format!("{:.1}", s.resid_max),
            resid_n = s.resid_n,
            reanchors = s.reanchors,
            external = s.external,
            no_effect = s.no_effect,
            failed = s.failed,
            inflight = s.inflight,
            timed_out = s.timed_out,
            transitions = s.transitions,
            quiet_transitions = s.quiet_transitions,
            m_hid = s.m_hid,
            m_sendinput = s.m_sendinput,
            order_waits = s.order_waits,
            order_wait_max_ms = %format!("{:.1}", s.order_wait_max.as_secs_f64() * 1000.0),
            order_timeouts = s.order_timeouts,
            wheel_sendinput = s.wheel.sendinput,
            wheel_hid_game = s.wheel.hid_game,
            wheel_hid_stepped = s.wheel.hid_stepped,
            wheel_hid_notches = s.wheel.notches,
            wheel_carry_resets = s.wheel.resets,
            unshown_polls = s.unshown_polls,
            queued_moves = s.queued_moves,
            queued_expired = s.queued_expired,
            gain = %format!("{gain:.3}"),
            gain_source = source.name(),
            gain_obs = %s.gain.gain().map_or_else(|| "-".to_owned(), |g| format!("{g:.3}")),
            gain_bins = %self.gain.bins_text(),
            epp = settings.epp,
            scale = %format!("{:.2}", settings.scale()),
            "cursor sync"
        );
    }

    /// The gain in use and where it comes from, and the learned bins — for the mouse probe's record.
    #[cfg(all(test, windows))]
    pub(crate) fn gain_summary(&self) -> String {
        let (g, source) = self.gain.typical();
        format!(
            "{g:.3} ({}), bins {}, measured {:?}",
            source.name(),
            self.gain.bins_text(),
            self.gain.measured
        )
    }
}

/// Camera, point or exact, and the reason in words.
fn decide(
    look: &Result<CursorLook, String>,
    width: i32,
    height: i32,
    target: bool,
    held: bool,
) -> (Mode, &'static str) {
    let Ok(c) = look else {
        return (Mode::Camera, "the cursor is unreadable (another desktop?)");
    };
    if width <= 0 || height <= 0 {
        return (Mode::Camera, "the screen size is unknown");
    }
    if !c.showing {
        return (Mode::Camera, "the cursor is hidden");
    }
    if c.suppressed {
        return (Mode::Camera, "the cursor is suppressed (touch or pen)");
    }
    if !(0..width).contains(&c.x) || !(0..height).contains(&c.y) {
        return (Mode::Camera, "the cursor is off the captured screen");
    }
    match (target, held) {
        (true, false) => (Mode::Point, "a target, and no button held"),
        (true, true) => (
            Mode::Exact,
            "a button held: relative moves toward the target",
        ),
        (false, _) => (Mode::Exact, "no target: the hand's own distance, exactly"),
    }
}

/// Did the cursor do what the sends just resolved should have made it do?
fn unexplained(seen: &Seen, known: bool) -> Option<Unexplained> {
    let error = sub(seen.moved, seen.expected);
    if len(error) <= EXTERNAL_MIN_PX {
        return None;
    }
    let s = seen.expected;
    let sl = len(s);
    if sl < 1.0 {
        return Some(Unexplained::External(
            "the cursor moved while nothing of ours was due",
        ));
    }
    if len(seen.moved) < 1.0 && sl >= NO_EFFECT_MIN_PX {
        return Some(Unexplained::NoEffect);
    }
    let lambda = dot(seen.moved, s) / (sl * sl);
    let across = len(sub(seen.moved, mul(s, lambda)));
    let (low, high) = if known { (0.5, 2.0) } else { (0.2, 5.0) };
    if across > EXTERNAL_MIN_PX + 0.25 * sl {
        Some(Unexplained::External("the cursor moved across our move"))
    } else if !(low..=high).contains(&lambda) {
        Some(Unexplained::External(
            "the cursor moved far more or less than our move",
        ))
    } else {
        None
    }
}
