//! Native FakerInput API v1 reports, as documented by Ryochan7/FakerInput's
//! fakerinputcommon.h and Ryochan7/FakerInputDll's fakerinputclient.cpp.
//! No DLL, installer, keyboard hook or reads of the owner's keyboard are involved.
//!
//! [`SessionInputBackend`] (built by `create_input_injector`) opens the FakerInput device only while
//! a session is live, so nothing is held open or sent between sessions. While it is open,
//! [`FakerInputInjector`] routes each event to HID or to `SendInput`.
//! ## Which path an event takes
//!
//! One invariant: **the path that pressed a key or button is the path that releases it.** A press
//! held by an HID report stays down until a neutral HID report clears it, so a press on one path
//! and a release on the other strands state. Therefore:
//!
//! * a new press and any move (`r`, `m`) follow the current target — HID when the Default desktop
//!   of the active console session has the input, SendInput otherwise (the UAC secure desktop, the
//!   lock screen, or a desktop we cannot confirm). HID is deliberately *not* gated by the foreground
//!   window's privilege: the owner controls their own PC, so HID reaches an administrator window
//!   exactly as a physical keyboard would;
//! * a repeat press goes to the path already holding the key, and releases (`u`, key-up, `ra`,
//!   `release_all`) follow whoever holds it, whatever the target is now;
//! * the game-mode wheel (`w` with `game: true`) follows the target in whole HID notches, because
//!   games reading the mouse directly ignore SendInput wheels. Every other wheel stays on smooth
//!   SendInput (the HID descriptor has no Resolution Multiplier, so HID scrolls in steps), except in
//!   game-only mode or to an elevated window (UIPI drops SendInput there), where stepped beats none
//!   ([`super::game_guard::Reach`]);
//! * game text (`text` with `game: true`) is typed as key presses on the PC's layout by a worker
//!   ([`typing`]), and later input waits behind it; other text uses SendInput unless the game guard
//!   routes it here.
//!
//! A move's report comes from the cursor-sync planner (`crate::cursor_sync`). An absolute position
//! (`m`) goes as FakerInput's absolute report (report 4); since that and the buttons' report 3 are
//! two collections with no promised order, a button change right after an absolute move waits (in
//! the queue, never on the caller's thread) until `GetCursorPos` shows the move, at most
//! [`ORDER_WAIT_MAX`]. A key or button released sooner than [`typing::TAP_MIN_HOLD`] after its press
//! is released that long after it, so a polling game sees a tap. HID keys auto-repeat in Windows'
//! own HID keyboard driver and end any emulated SendInput repeat (`super::repeat`). In game-only
//! mode [`button_watch`] re-sends a release the game plainly missed.
//!
//! [`HidRuntime`] routes and keeps the held state, generic over [`Driver`] and [`Host`] with time
//! passed in, so tests drive it with fakes on a virtual clock.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
#[cfg(windows)]
use std::sync::{Arc, Condvar};
use std::time::{Duration, Instant};

use afklink_core::sync::lock;
use afklink_core::traits::InputInjector;
#[cfg(windows)]
use afklink_core::traits::{
    CursorSample, CursorShape, DriverPresence, GameFocus, GameScope, InputReach, InputScope,
    WindowOwner, WindowTarget,
};
use afklink_protocol::{InputMessage, WheelMode};
use anyhow::{bail, ensure, Result};

#[cfg(windows)]
use super::cursor_sync::Space;
use super::cursor_sync::{CursorLook, Elevation, Plan, RelEvent, RelPath, WheelTally};
use super::game_guard::Reach;
#[cfg(windows)]
use super::game_guard::{system::SystemGuard, GameGuard, GuardHost};
#[cfg(windows)]
use super::reach::{Landing, Press as FreshPress, ReachWatch};
use super::wheel::{HID_PIXELS_PER_NOTCH, PIXELS_PER_NOTCH, STEPPED_CARRY_PAUSE};
use super::{RelCarry, SendInputInjector};
use button_watch::{ButtonProbe, ButtonWatch};
use mouse_kernel::{split_axes, MouseKernel};
use typing::{Gate, Keyboard, PressHold, TextPath, Typist, MAX_QUEUED_CHARS, MAX_QUEUED_JOBS};

// Did the game take each button change the driver wrote (game-only mode)? A release it plainly
// missed goes once more.
mod button_watch;
// Direct HID access for a host that runs its own input policy (`direct.rs`).
#[cfg(windows)]
mod direct;
#[cfg(windows)]
pub use direct::{
    DirectHid, HidCursor, HidCursorLook, HidCursorPlan, HidInputPaused, HidKey, HidLanguageSwitch,
    HidLayoutProgress, HidMouse, HidTextStroke,
};
#[cfg(windows)]
pub use typing::PressHold as HidPressHold;
#[cfg(test)]
mod fake;
#[cfg(windows)]
mod layouts;
// Hand-run diagnostics (ignored tests): how the foreground application reacts to each way of moving
// the cursor, and the absolute position's clicks and drags through the router in Notepad; they need
// this module's device, router and report internals.
#[cfg(all(test, windows))]
mod click_probe;
mod mouse_kernel;
#[cfg(all(test, windows))]
mod mouse_probe;
#[cfg(windows)]
pub(crate) mod platform;
pub(crate) mod typing;

type Report = [u8; 65];

/// Only output reports; deliberately no input-reading operation in this interface.
trait Driver: Send {
    fn write(&mut self, report: &Report) -> Result<()>;
}

fn wrap(payload: &[u8]) -> Report {
    let mut report = [0; 65];
    report[0] = 0x40;
    report[1] = payload.len() as u8;
    report[2..2 + payload.len()].copy_from_slice(payload);
    report
}

fn keyboard(modifiers: u8, keys: &BTreeSet<u8>) -> Report {
    let mut payload = [0; 9];
    payload[0] = 1;
    payload[1] = modifiers;
    for (slot, key) in payload[3..].iter_mut().zip(keys) {
        *slot = *key;
    }
    wrap(&payload)
}

/// The relative mouse report: `[3, buttons, x_lo, x_hi, y_lo, y_hi, wheel, pan]`. X and Y are
/// signed 16-bit; Wheel and AC Pan one signed byte each, −127..127 in FakerInput's descriptor
/// (`Device.c`), with no Resolution Multiplier — whole notches. HID signs: Wheel > 0 scrolls up
/// (away from the user), AC Pan > 0 scrolls right.
fn mouse(buttons: u8, x: i16, y: i16, wheel: i8, pan: i8) -> Report {
    let mut payload = [3, buttons, 0, 0, 0, 0, 0, 0];
    payload[2..4].copy_from_slice(&x.to_le_bytes());
    payload[4..6].copy_from_slice(&y.to_le_bytes());
    payload[6] = wheel.to_le_bytes()[0];
    payload[7] = pan.to_le_bytes()[0];
    wrap(&payload)
}

/// FakerInput's absolute mouse report (`FakerInputAbsMouseReport`: id 4, buttons, X and Y as
/// little-endian u16 over `LOGICAL 0..32767`, wheel — upstream `Device.c`, `fakerinputcommon.h`). A
/// separate collection: to Windows a second mouse with its own buttons, so its buttons and wheel are
/// always 0 here — the buttons stay on the relative report, and the cursor-sync planner moves
/// absolutely only while none is held.
fn absolute_mouse(x: u16, y: u16) -> Report {
    let [xl, xh] = x.to_le_bytes();
    let [yl, yh] = y.to_le_bytes();
    wrap(&[4, 0, xl, xh, yl, yh, 0])
}

/// What FakerInput's absolute report carries to put the cursor on pixel `(px, py)` of the primary
/// `width`×`height` monitor.
///
/// Windows maps the report onto the monitor as `floor(X · width / 32768)`. A probe at 3600×2400
/// (sent with the mapping `round(px / width · 32767)`): X 19915 → 2187, 13708 → 1506,
/// 12342 → 1355, 18550 → 2037; Y 11305 → 828, 13353 → 978, 18732 → 1371, 20780 → 1521 — every one
/// fits that formula, while `/ 32767` (floored or rounded) and a detour through `0..65535` each miss
/// at least one. So this aims at the pixel's centre, `(px + 0.5) · 32768 / width`, rounded: the
/// rounding moves the point by at most `width / 65536` px, which keeps it inside `px` for any width
/// under 32768. The old mapping aimed at the pixel's left edge and landed one short about half the
/// time (2188 → 2187).
pub(crate) fn absolute_wire(px: i32, py: i32, width: i32, height: i32) -> (u16, u16) {
    let axis = |p: i32, size: i32| -> u16 {
        let size = size.max(1);
        let centre = f64::from(p.clamp(0, size - 1)) + 0.5;
        (centre * 32768.0 / f64::from(size))
            .round()
            .clamp(0.0, 32767.0) as u16
    };
    (axis(px, width), axis(py, height))
}

/// FakerInput's HID identity, as `HidD_GetAttributes` reports it on each of its collections — what
/// the official client (fakerinputclient.cpp) matches on. The interface *path* does not carry it:
/// the device is root-enumerated (`ROOT\SYSTEM\NNNN`, hardware id `root\FakerInput`), so its
/// collections' paths read `\\?\hid#system&colNN#…`, with no `vid_fe0f&pid_00ff` in them.
const VENDOR_ID: u16 = 0xfe0f;
const PRODUCT_ID: u16 = 0x00ff;
/// The usage page of the two vendor collections the API goes through.
const VENDOR_USAGE_PAGE: u16 = 0xff00;
/// Both vendor collections' output report: the report id and 64 bytes — a [`Report`].
const VENDOR_OUTPUT_LEN: u16 = 65;
const _: () = assert!(VENDOR_OUTPUT_LEN as usize == std::mem::size_of::<Report>());

/// What one HID interface is to us, from its attributes and top-level caps ([`classify`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Collection {
    /// Another device (a real keyboard, a headset, a security key): nothing more is read from it.
    Foreign,
    /// One of FakerInput's own keyboard, mouse or consumer-control collections (or any other of its
    /// collections that is not the API's): Windows owns these; they are never opened for writing.
    Other,
    /// Vendor usage 1: the control collection every input report is written to.
    Control,
    /// Vendor usage 2: the API collection, whose feature report 0x42 carries the API version.
    Api,
    /// A vendor collection whose output report is not [`VENDOR_OUTPUT_LEN`] bytes: a driver build
    /// this client does not speak to.
    Incompatible,
}

impl Collection {
    /// For the log.
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Foreign => "foreign",
            Self::Other => "other",
            Self::Control => "control",
            Self::Api => "api",
            Self::Incompatible => "incompatible",
        }
    }
}

/// Whether HID attributes are FakerInput's.
pub(crate) fn is_fakerinput(vendor_id: u16, product_id: u16) -> bool {
    vendor_id == VENDOR_ID && product_id == PRODUCT_ID
}

/// Which collection an HID interface is, from its VID/PID, its top-level usage page and usage, and
/// its output report length — the official client's rule, never the interface path. Pure, so it is
/// tested without a device.
pub(crate) fn classify(
    vendor_id: u16,
    product_id: u16,
    usage_page: u16,
    usage: u16,
    output_len: u16,
) -> Collection {
    if !is_fakerinput(vendor_id, product_id) {
        return Collection::Foreign;
    }
    match (usage_page, usage) {
        (VENDOR_USAGE_PAGE, 1 | 2) if output_len != VENDOR_OUTPUT_LEN => Collection::Incompatible,
        (VENDOR_USAGE_PAGE, 1) => Collection::Control,
        (VENDOR_USAGE_PAGE, 2) => Collection::Api,
        _ => Collection::Other,
    }
}

/// How long a `warn` about a given failure is suppressed after one is emitted.
const WARN_EVERY: Duration = Duration::from_secs(10);

/// A rate limiter for a repeating `warn`: emit the first at once, then at most one every
/// [`WARN_EVERY`], each carrying how many were suppressed in between. Mirrors the `SendInput`
/// `refused` limiter so a stuck condition (a wrong target, a failing write) cannot write sixty
/// lines a second.
struct WarnThrottle {
    last: Mutex<Option<Instant>>,
    suppressed: AtomicU64,
}

impl WarnThrottle {
    const fn new() -> Self {
        Self {
            last: Mutex::new(None),
            suppressed: AtomicU64::new(0),
        }
    }

    /// `Some(n)` when it is time to warn again — `n` is how many were suppressed since the last one
    /// — or `None` while still inside the quiet window.
    fn should_warn(&self) -> Option<u64> {
        let now = Instant::now();
        let mut last = lock(&self.last);
        let suppressed = self.suppressed.fetch_add(1, Ordering::Relaxed);
        if last.is_none_or(|t| now.saturating_duration_since(t) >= WARN_EVERY) {
            *last = Some(now);
            self.suppressed.store(0, Ordering::Relaxed);
            Some(suppressed)
        } else {
            None
        }
    }
}

/// Failed HID writes: throttled so a briefly failing device does not flood the log.
static WRITE_WARN: WarnThrottle = WarnThrottle::new();

#[derive(Default)]
struct Held {
    keys: BTreeSet<u8>,
    modifiers: u8,
    media: u8,
    // An unsuccessful write can still have reached the device. Only a successful neutral
    // report clears uncertainty; never forget a failed key-up or replay relative motion.
    dirty_keyboard: bool,
    dirty_media: bool,
    dirty_mouse: bool,
}

struct State<D> {
    driver: D,
    held: Held,
    mouse: MouseKernel,
    rel: RelCarry,
    failed: bool,
}

/// What one HID wheel message did, for the per-second line.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct WheelOut {
    /// Whole notches written (Wheel and AC Pan together).
    notches: u32,
    /// It went the other way than the unfinished notch before it, which was dropped.
    reversed: bool,
}

/// Every keyboard report passes these, a key's or a typed one's: six non-modifier keys at most (the
/// descriptor's rollover), and no sequence Windows keeps for itself — the complete candidate state is
/// checked, so pressing a modifier last does not slip past.
fn check_keyboard(modifiers: u8, keys: &BTreeSet<u8>) -> Result<()> {
    ensure!(
        keys.len() <= 6,
        "FakerInput keyboard supports six simultaneous non-modifier keys"
    );
    ensure!(
        !((keys.contains(&0x4c) || keys.contains(&0x63))
            && modifiers & 0x11 != 0
            && modifiers & 0x44 != 0),
        "Ctrl+Alt+Delete is not supported by remote input"
    );
    ensure!(
        !(keys.contains(&0x0f) && modifiers & 0x88 != 0),
        "locking Windows is not supported by remote HID input"
    );
    Ok(())
}

/// The protocol button id (0 = left, 1 = middle, 2 = right) as its HID button bit, or `None` for an
/// unsupported id. Kept in one place so the ledger check and the report use the same mapping.
fn button_bit(button: u8) -> Option<u8> {
    match button {
        0 => Some(1),
        1 => Some(4),
        2 => Some(2),
        _ => None,
    }
}

/// An HID button bit as the protocol's button id: [`button_bit`] backwards.
fn bit_button(bit: u8) -> Option<u8> {
    match bit {
        1 => Some(0),
        4 => Some(1),
        2 => Some(2),
        _ => None,
    }
}

impl<D: Driver> State<D> {
    fn new(driver: D) -> Self {
        Self {
            driver,
            held: Held::default(),
            mouse: MouseKernel::default(),
            rel: RelCarry::default(),
            failed: false,
        }
    }

    fn write(&mut self, report: &Report) -> Result<()> {
        Self::write_driver(&mut self.driver, &mut self.failed, report)
    }

    fn write_driver(driver: &mut D, failed: &mut bool, report: &Report) -> Result<()> {
        if let Err(error) = driver.write(report) {
            *failed = true;
            if let Some(suppressed) = WRITE_WARN.should_warn() {
                tracing::warn!(%error, report_id = report[2], suppressed, "FakerInput report failed; neutral cleanup required before more input");
            }
            return Err(error);
        }
        Ok(())
    }

    /// Is this key/button currently held on the HID path? Routes a release to the same path that
    /// pressed it.
    fn holds_key(&self, key: Key) -> bool {
        match key {
            Key::Usage(usage) => self.held.keys.contains(&usage),
            Key::Modifier(bit) => self.held.modifiers & bit != 0,
            Key::Media(bit) => self.held.media & bit != 0,
        }
    }

    fn holds_button(&self, button: u8) -> bool {
        self.mouse.holds(button)
    }

    /// Would pressing `usage` exceed the HID keyboard's six-key rollover? A repeat of a key already
    /// held never overflows; the caller sends an overflowing key through SendInput instead of losing
    /// it.
    fn usage_overflows(&self, usage: u8) -> bool {
        !self.held.keys.contains(&usage) && self.held.keys.len() >= 6
    }

    fn release(&mut self) -> Result<()> {
        if self.held.dirty_keyboard || self.held.dirty_media || self.held.dirty_mouse {
            // not-a-key-name: a count of held keys
            tracing::debug!(
                keys = self.held.keys.len(),
                modifiers = self.held.modifiers,
                buttons = self.mouse.buttons(),
                media = self.held.media,
                "releasing held FakerInput state"
            );
        }
        self.rel = RelCarry::default();
        // The unfinished notch belongs to the gesture that just ended; the wheel holds nothing, so
        // there is no report to send for it (the drop is said at trace, not counted: no route
        // dropped it).
        self.drop_wheel_carry("release");
        let mut last_error = None;
        if self.held.dirty_keyboard {
            match self.write(&keyboard(0, &BTreeSet::new())) {
                Ok(()) => {
                    self.held.keys.clear();
                    self.held.modifiers = 0;
                    self.held.dirty_keyboard = false;
                }
                Err(error) => last_error = Some(error),
            }
        }
        if self.held.dirty_media {
            match self.write(&wrap(&[2, 0, 0, 0])) {
                Ok(()) => {
                    self.held.media = 0;
                    self.held.dirty_media = false;
                }
                Err(error) => last_error = Some(error),
            }
        }
        if self.held.dirty_mouse {
            if let Err(error) = self.set_mouse_buttons(0) {
                last_error = Some(error);
            }
        }
        if let Some(error) = last_error {
            return Err(error);
        }
        if self.failed {
            tracing::debug!("FakerInput neutral cleanup recovered; accepting new input");
        }
        self.failed = false;
        Ok(())
    }

    fn key(&mut self, key: Key, down: bool) -> Result<()> {
        match key {
            Key::Media(bit) => {
                if down {
                    self.held.media |= bit;
                } else {
                    self.held.media &= !bit;
                }
                self.held.dirty_media = true;
                self.write(&wrap(&[2, self.held.media, 0, 0]))?;
                self.held.dirty_media = self.held.media != 0;
            }
            _ => {
                let mut keys = self.held.keys.clone();
                let mut modifiers = self.held.modifiers;
                match key {
                    Key::Usage(usage) => {
                        if down {
                            keys.insert(usage);
                        } else {
                            keys.remove(&usage);
                        }
                    }
                    Key::Modifier(bit) => {
                        if down {
                            modifiers |= bit;
                        } else {
                            modifiers &= !bit;
                        }
                    }
                    Key::Media(_) => unreachable!(),
                }
                check_keyboard(modifiers, &keys)?;
                self.held.dirty_keyboard = true;
                self.write(&keyboard(modifiers, &keys))?;
                self.held.keys = keys;
                self.held.modifiers = modifiers;
                self.held.dirty_keyboard = !self.held.keys.is_empty() || modifiers != 0;
            }
        }
        Ok(())
    }

    /// A keyboard report for typing game text ([`typing`]): what the device holds until the next
    /// report — the panel's held keys and modifiers plus a typed key or typing modifiers — while the
    /// ledger (`held.keys`, `held.modifiers`) stays the panel's, which the typing restores at the
    /// end. The same checks as [`Self::key`], and the same uncertainty rule: until the report is
    /// known to have gone out, the keyboard counts as holding something.
    fn typing_report(&mut self, modifiers: u8, keys: &BTreeSet<u8>) -> Result<()> {
        check_keyboard(modifiers, keys)?;
        self.held.dirty_keyboard = true;
        self.write(&keyboard(modifiers, keys))?;
        self.held.dirty_keyboard = !keys.is_empty() || modifiers != 0;
        Ok(())
    }

    fn button(&mut self, button: u8, down: bool) -> Result<()> {
        let Some(buttons) = self.mouse.button_mask(button, down) else {
            bail!("unsupported mouse button {button}");
        };
        let changed = buttons != self.mouse.buttons();
        self.set_mouse_buttons(buttons)?;
        super::note_button(button, down, changed, "fakerinput");
        Ok(())
    }

    fn set_mouse_buttons(&mut self, buttons: u8) -> Result<()> {
        self.held.dirty_mouse = true;
        self.mouse.write_buttons(buttons, |buttons| {
            Self::write_driver(
                &mut self.driver,
                &mut self.failed,
                &mouse(buttons, 0, 0, 0, 0),
            )
        })?;
        self.held.dirty_mouse = buttons != 0;
        Ok(())
    }

    fn movement(&mut self, x: i32, y: i32) -> Result<()> {
        for (dx, dy) in split_axes(x, y, 32767) {
            // A failed move never gets replayed: the driver may already have delivered it.
            self.write(&mouse(self.mouse.buttons(), dx as i16, dy as i16, 0, 0))?;
        }
        Ok(())
    }

    /// One game-wheel message as whole HID notches, pixels read at [`HID_PIXELS_PER_NOTCH`] (see
    /// [`Self::wheel_scaled`]).
    fn wheel(&mut self, dx: f64, dy: f64, mode: WheelMode) -> Result<WheelOut> {
        self.wheel_scaled(dx, dy, mode, HID_PIXELS_PER_NOTCH)
    }

    /// One wheel message as whole HID notches: the unit read as on the SendInput path ([`super::wheel::notches`],
    /// pixels at `pixels_per_notch` — the game wheel's knob, or SendInput's own scale for a wheel not
    /// marked `game`), the fraction carried to the next message, a big turn split into reports of at
    /// most ±127. Signs as on the SendInput path: the viewer's `dy` > 0 scrolls down, which is HID
    /// Wheel < 0; `dx` > 0 scrolls right, HID AC Pan > 0.
    fn wheel_scaled(
        &mut self,
        dx: f64,
        dy: f64,
        mode: WheelMode,
        pixels_per_notch: f64,
    ) -> Result<WheelOut> {
        let step = self.mouse.wheel_step(dx, dy, mode, pixels_per_notch)?;
        self.wheel_reports(step.wheel, step.pan)?;
        Ok(WheelOut {
            notches: step
                .wheel
                .unsigned_abs()
                .saturating_add(step.pan.unsigned_abs()),
            reversed: step.reversed,
        })
    }

    /// Whole notches as reports of at most ±127 each (the descriptor's range).
    fn wheel_reports(&mut self, wheel: i32, pan: i32) -> Result<()> {
        for (w, p) in split_axes(wheel, pan, 127) {
            tracing::trace!(wheel = w, pan = p, "HID wheel report");
            // Held buttons ride along — a zero there would release them. A failed report is not
            // replayed: the driver may already have delivered it.
            self.write(&mouse(self.mouse.buttons(), 0, 0, w as i8, p as i8))?;
        }
        Ok(())
    }

    /// Forget the HID wheel's unfinished notch (a release, a change of the wheel's route, a pause of
    /// the stepped wheel). Whether there was one to forget.
    fn drop_wheel_carry(&mut self, why: &'static str) -> bool {
        self.mouse.drop_wheel_carry(why)
    }

    fn relative(&mut self, dx: f64, dy: f64, width: i32, height: i32) -> Result<()> {
        ensure!(
            dx.is_finite() && dy.is_finite(),
            "non-finite relative mouse delta"
        );
        ensure!(width > 0 && height > 0, "primary screen size unavailable");
        let (x, y) = self.rel.step(dx, dy, width, height);
        self.movement(x, y)
    }

    /// Put the cursor on a pixel with the absolute report (the cursor-sync planner's point mode).
    /// It holds nothing, so there is nothing to release; a failed write marks the device for neutral
    /// cleanup like any other.
    fn absolute(&mut self, px: i32, py: i32, width: i32, height: i32) -> Result<()> {
        ensure!(width > 0 && height > 0, "primary screen size unavailable");
        let (x, y) = absolute_wire(px, py, width, height);
        tracing::trace!(px, py, x, y, "HID absolute report");
        self.write(&absolute_mouse(x, y))
    }

    /// The viewer's `m` on HID: the same absolute report as [`Self::absolute`]. It holds nothing
    /// either, but a failed one leaves the mouse dirty, so the recovery before the next input writes
    /// the relative report's neutral report — which moves nothing and, with no button held, changes
    /// nothing — and a device that takes neither is found unusable (the rest of the session on
    /// SendInput) instead of failing every `m` of the tablet mode, whose only way of moving the
    /// cursor it is. The failed position is not replayed: the next `m` replaces it.
    fn position(&mut self, px: i32, py: i32, width: i32, height: i32) -> Result<()> {
        ensure!(width > 0 && height > 0, "primary screen size unavailable");
        self.held.dirty_mouse = true;
        self.absolute(px, py, width, height)?;
        self.held.dirty_mouse = self.mouse.buttons() != 0;
        Ok(())
    }
}

/// A physical DOM code maps straight to USB HID usage, independent of the Windows layout.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Key {
    Usage(u8),
    Modifier(u8),
    Media(u8),
}

/// Caps Lock, whose press typing has to know about (see `typing::Memory::caps_pressed`).
const CAPS_LOCK: Key = Key::Usage(0x39);

/// Whether either path has a key for `code`: the driver's ([`key`]) or `SendInput`'s
/// ([`super::code_to_vk`]). A code neither maps goes nowhere: [`SessionInputBackend`] stops its
/// message before the guard.
#[cfg_attr(not(windows), allow(dead_code))]
fn maps_key(code: &str) -> bool {
    key(code).is_some() || super::code_to_vk(code).is_some()
}

fn key(code: &str) -> Option<Key> {
    if let Some(letter) = code.strip_prefix("Key").filter(|s| s.len() == 1) {
        let c = letter.as_bytes()[0];
        if c.is_ascii_uppercase() {
            return Some(Key::Usage(c - b'A' + 4));
        }
    }
    if let Some(digit) = code.strip_prefix("Digit").filter(|s| s.len() == 1) {
        let c = digit.as_bytes()[0];
        if c.is_ascii_digit() {
            return Some(Key::Usage(if c == b'0' { 0x27 } else { c - b'1' + 0x1e }));
        }
    }
    if let Some(n) = code.strip_prefix('F').and_then(|s| s.parse::<u8>().ok()) {
        if (1..=12).contains(&n) {
            return Some(Key::Usage(0x3a + n - 1));
        }
        // F13..24 are outside upstream's keyboard descriptor Usage Maximum (0x65).
    }
    if let Some(digit) = code.strip_prefix("Numpad").filter(|s| s.len() == 1) {
        let c = digit.as_bytes()[0];
        if c.is_ascii_digit() {
            return Some(Key::Usage(if c == b'0' { 0x62 } else { c - b'1' + 0x59 }));
        }
    }
    let usage = match code {
        "ControlLeft" => return Some(Key::Modifier(1)),
        "ShiftLeft" => return Some(Key::Modifier(2)),
        "AltLeft" => return Some(Key::Modifier(4)),
        "MetaLeft" | "OSLeft" => return Some(Key::Modifier(8)),
        "ControlRight" => return Some(Key::Modifier(16)),
        "ShiftRight" => return Some(Key::Modifier(32)),
        "AltRight" => return Some(Key::Modifier(64)),
        "MetaRight" | "OSRight" => return Some(Key::Modifier(128)),
        "MediaTrackNext" => return Some(Key::Media(1)),
        "MediaTrackPrevious" => return Some(Key::Media(2)),
        "MediaStop" => return Some(Key::Media(4)),
        "MediaPlayPause" => return Some(Key::Media(8)),
        "AudioVolumeMute" => return Some(Key::Media(16)),
        "AudioVolumeDown" => return Some(Key::Media(32)),
        "AudioVolumeUp" => return Some(Key::Media(64)),
        "Enter" => 0x28,
        "Escape" => 0x29,
        "Backspace" => 0x2a,
        "Tab" => 0x2b,
        "Space" => 0x2c,
        "Minus" => 0x2d,
        "Equal" => 0x2e,
        "BracketLeft" => 0x2f,
        "BracketRight" => 0x30,
        "Backslash" => 0x31,
        "Semicolon" => 0x33,
        "Quote" => 0x34,
        "Backquote" => 0x35,
        "Comma" => 0x36,
        "Period" => 0x37,
        "Slash" => 0x38,
        "CapsLock" => 0x39,
        "PrintScreen" => 0x46,
        "ScrollLock" => 0x47,
        "Pause" => 0x48,
        "Insert" => 0x49,
        "Home" => 0x4a,
        "PageUp" => 0x4b,
        "Delete" => 0x4c,
        "End" => 0x4d,
        "PageDown" => 0x4e,
        "ArrowRight" => 0x4f,
        "ArrowLeft" => 0x50,
        "ArrowDown" => 0x51,
        "ArrowUp" => 0x52,
        "NumLock" => 0x53,
        "NumpadDivide" => 0x54,
        "NumpadMultiply" => 0x55,
        "NumpadSubtract" => 0x56,
        "NumpadAdd" => 0x57,
        "NumpadEnter" => 0x58,
        "NumpadDecimal" => 0x63,
        "IntlBackslash" => 0x64,
        "ContextMenu" => 0x65,
        _ => return None,
    };
    Some(Key::Usage(usage))
}

/// How long a target decision is reused before it is re-evaluated.
///
/// Short on purpose: a held HID key auto-repeats into whatever has the input after 250–500 ms, so a
/// switch to a surface we must not drive (the secure desktop, the lock screen) has to be noticed
/// well inside that. Between re-evaluations the cached decision spares a few system calls on every
/// mouse move.
const TARGET_CACHE_TTL: Duration = Duration::from_millis(100);

/// Which path a wheel message or an `m` took.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Via {
    Hid,
    SendInput,
}

impl Via {
    fn name(self) -> &'static str {
        match self {
            Self::Hid => "hid",
            Self::SendInput => "sendinput",
        }
    }
}

/// What one message's path and reason are to the one before, as [`PathLog::note`] saw it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Change {
    Same,
    /// The same path for another reason (the game wheel, then a wheel for an elevated window).
    Reason,
    Path,
}

/// At most one path line at `debug` per this long, per kind of input.
const PATH_LOG_EVERY: Duration = Duration::from_secs(2);

/// Says which path one kind of input takes and why — the wheel (`"wheel"`), the absolute position
/// (`"position (m)"`): on the first one after the device opens, then on every change of path or
/// reason — the viewer entering or leaving game mode, game-only mode, an elevated window taking
/// the front, the target changing, the device breaking. At `debug` as `<what> path` (with the
/// foreground window's exe when that is the reason), but at most one line per [`PATH_LOG_EVERY`]; a
/// change inside that window goes to `trace` and is counted into the next `debug` line, so a viewer
/// alternating game and desktop wheels, or a target flickering, cannot flood the log.
#[derive(Debug)]
struct PathLog {
    what: &'static str,
    last: Option<(Via, &'static str)>,
    logged_at: Option<Instant>,
    quiet: u32,
}

impl PathLog {
    const fn new(what: &'static str) -> Self {
        Self {
            what,
            last: None,
            logged_at: None,
            quiet: 0,
        }
    }

    /// Record the path of one message, and what changed.
    fn note(&mut self, path: Via, reason: &'static str, now: Instant) -> Change {
        self.note_about(path, reason, None, now)
    }

    /// [`Self::note`], naming the foreground window's exe in the line when it is the reason (the
    /// wheel for an elevated window). A change of that window alone is not a change here: the
    /// planner says every change of the foreground window, with its exe and elevation.
    fn note_about(
        &mut self,
        path: Via,
        reason: &'static str,
        foreground: Option<&str>,
        now: Instant,
    ) -> Change {
        if self.last == Some((path, reason)) {
            return Change::Same;
        }
        let change = if self.last.map(|(p, _)| p) == Some(path) {
            Change::Reason
        } else {
            Change::Path
        };
        self.last = Some((path, reason));
        if self
            .logged_at
            .is_some_and(|t| now.saturating_duration_since(t) < PATH_LOG_EVERY)
        {
            self.quiet = self.quiet.saturating_add(1);
            tracing::trace!(
                path = path.name(),
                reason,
                foreground = foreground.unwrap_or("-"),
                "{} path changed",
                self.what
            );
            return change;
        }
        match foreground {
            Some(exe) => tracing::debug!(
                path = path.name(),
                reason,
                foreground = exe,
                changes_since_last_line = self.quiet,
                "{} path",
                self.what
            ),
            None => tracing::debug!(
                path = path.name(),
                reason,
                changes_since_last_line = self.quiet,
                "{} path",
                self.what
            ),
        }
        self.logged_at = Some(now);
        self.quiet = 0;
        change
    }
}

/// The game wheel on HID.
const GAME_WHEEL_HID: &str = "game-mode wheel: whole HID notches, fractions carried";

// Why a wheel the viewer did not mark `game` goes the way it goes (option C). Smooth SendInput
// wherever it reaches — as before; whole HID notches where it cannot.
const WHEEL_ORDINARY: &str = "wheel not marked game, an ordinary window: smooth SendInput";
const WHEEL_BOTH_ELEVATED: &str = "wheel not marked game, the foreground window runs elevated and \
                                   so does the agent: smooth SendInput reaches it";
const WHEEL_UNKNOWN: &str = "wheel not marked game, the foreground window's elevation cannot be \
                             read: smooth SendInput";
const WHEEL_ELEVATED: &str = "wheel not marked game, the foreground window runs elevated and the \
                              agent does not: SendInput cannot reach it (UIPI), so whole HID \
                              notches, fractions carried";
const WHEEL_GAME_ONLY: &str = "wheel not marked game, game-only mode: to the game in whole HID \
                               notches, fractions carried";
const WHEEL_STEPPED_BLOCKED: &str = "wheel not marked game, meant for HID (game-only mode or an \
                                     elevated window), but the HID target is blocked: SendInput";
const WHEEL_STEPPED_UNKNOWN: &str = "wheel not marked game, meant for HID (game-only mode or an \
                                     elevated window), but the HID target is unknown: SendInput";
const WHEEL_BROKEN: &str = "wheel not marked game, the device is unusable: smooth SendInput";
const WHEEL_ELEVATED_NO_DRIVER: &str = "wheel not marked game, the foreground window runs \
                                        elevated and the agent does not, but the driver is not \
                                        open: SendInput, which Windows drops there (UIPI)";

/// Where a wheel the viewer did not mark `game` goes.
#[derive(Clone, Debug, PartialEq, Eq)]
enum WheelRoute {
    /// Smooth SendInput, as before (the reason).
    Smooth(&'static str),
    /// Whole HID notches where the target allows (the reason, and the elevated foreground's exe).
    Stepped(&'static str, Option<String>),
}

/// Why an `m` goes through HID.
const POSITION_HID: &str =
    "target allowed: FakerInput's absolute report (report 4) onto the pixel's centre";

/// How long a mouse button going down or up right after an absolute move (an `m`, or a point move of
/// `r`) waits, at most, for its report to show in `GetCursorPos` before it goes out anyway. The
/// report and the buttons' report are two collections — to Windows two mice, read separately — so
/// a button written right after the report could reach Windows first and click where the cursor was
/// (a tap of the tablet mode is `m`, `d`, `u` back to back; the desktop viewer's press is `m`, `d`;
/// the desktop game mode's click is a point move, then `d`). the probe saw a report show 1.6–1.8 ms after
/// its write; this is several of those, and half a frame of the viewer's.
const ORDER_WAIT_MAX: Duration = Duration::from_millis(8);
/// How often the waiting button looks again (the worker's wait rounds it up to the timer's 1 ms
/// while a session raises the resolution).
const ORDER_POLL: Duration = Duration::from_micros(500);
/// A cursor this close to the move's pixel counts as there: a reader that is not per-monitor DPI
/// aware sees scaled coordinates, rounded.
const ORDER_NEAR_PX: i32 = 1;

/// An absolute report (an `m`, a point move) written and not yet seen to have moved the cursor.
#[derive(Clone, Copy, Debug)]
struct Unseen {
    px: i32,
    py: i32,
    at: Instant,
}

/// Where HID input may go on this desktop.
///
/// The owner controls their own PC, so a physical HID device behaves like a real keyboard and is
/// deliberately *not* gated by the foreground window's privilege: it reaches an administrator window
/// exactly as a physical keyboard would. What it must never drive is a surface Windows keeps for
/// itself — the UAC secure desktop and the lock screen (a non-Default desktop) — or another session.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Target {
    /// The Default desktop of the active console session: HID may drive it, administrator windows
    /// included.
    Allowed,
    /// A surface a physical device must not drive — the secure desktop, the lock screen (a
    /// non-Default desktop), or another session. The router releases held input once on entry (a
    /// held HID key must not stay down across the switch) and routes new input via SendInput.
    Blocked,
    /// The desktop could not be identified — only an internal query failure, which is essentially
    /// never seen. The router routes new input via SendInput but does not disturb held HID, since
    /// this is a transient blip rather than a known-bad surface.
    Unknown,
}

/// A [`Target`] with a short, static reason for the transition log.
pub(crate) struct TargetEval {
    pub(crate) target: Target,
    pub(crate) reason: &'static str,
}

/// The SendInput path as the router uses it. The agent's is [`SendInputInjector`], shared with the
/// selector so both backends keep one held-key ledger; tests record into a fake.
pub(crate) trait SendInputPath {
    fn inject(&self, event: &InputMessage) -> Result<()>;
    fn release_all(&self);
    fn holds_key(&self, code: &str) -> bool;
    fn holds_button(&self, b: u8) -> bool;
    /// A key went down through the driver: SendInput's emulated repeat stops, as it would for a
    /// physical keyboard's new key — unless it is a modifier that was already down.
    fn other_key_pressed(&self, modifier: bool, was_held: bool);
    /// The modifiers this path holds down, as HID modifier bits.
    fn held_modifiers(&self) -> u8;
    /// One `r` on the HID path: what the cursor-sync planner — one for both paths, kept with the
    /// SendInput ledger — says to send. `hid_held`: a mouse button is held on HID (the planner adds
    /// this path's own).
    fn plan_rel(&self, event: RelEvent, hid_held: bool, now: Instant) -> Plan;
    /// The HID send a plan asked for failed: the planner expects nothing of it.
    fn rel_failed(&self, why: &'static str);
    /// A numbered move (`r.s`) waits in the queue behind other input: the planner holds the cursor
    /// report's `ack` below it until it is sent (and planned).
    fn rel_queued(&self, s: u32, now: Instant);
    /// Any input event: the planner looks at the foreground window (at most every 200 ms) and says
    /// when it changed — its exe, and whether it runs elevated.
    fn note_input(&self, now: Instant);
    /// One `m` on the HID path: the pixel `(x, y)` falls in and the screen it is on — the planner's,
    /// as for a point move, which keeps its books for it — or `None` when the screen size is
    /// unknown.
    fn plan_abs(&self, x: f64, y: f64, now: Instant) -> Option<(i32, i32, i32, i32)>;
    /// A button transition waited `waited` for an absolute move (an `m`, a point move) to show (or
    /// gave up): the planner's per-second line counts it.
    fn order_waited(&self, waited: Duration, timed_out: bool, now: Instant);
    /// The foreground window's elevation, looked at afresh (`CursorSync::foreground_elevation`): a
    /// wheel not marked `game` is routed on it. `None` when it cannot be read.
    fn foreground_elevation(&self, now: Instant) -> Option<Elevation>;
    /// The router's HID wheel messages and the unfinished notches it dropped: the planner's
    /// per-second line counts them (this path counts its own wheels itself).
    fn wheel_tally(&self, tally: WheelTally, now: Instant);
    /// The mouse buttons the router holds on HID changed: `held` (HID bits) after `change` — a
    /// button's bit going down or up, and when — or after a neutral report (`None`). The planner's
    /// line for a change of the cursor's visibility says them.
    fn hid_buttons(&self, held: u8, change: Option<(u8, bool, Instant)>);
}

impl SendInputPath for SendInputInjector {
    fn inject(&self, event: &InputMessage) -> Result<()> {
        InputInjector::inject(self, event)
    }

    fn release_all(&self) {
        InputInjector::release_all(self)
    }

    fn holds_key(&self, code: &str) -> bool {
        SendInputInjector::holds_key(self, code)
    }

    fn holds_button(&self, b: u8) -> bool {
        SendInputInjector::holds_button(self, b)
    }

    fn other_key_pressed(&self, modifier: bool, was_held: bool) {
        SendInputInjector::other_key_pressed(self, modifier, was_held)
    }

    fn held_modifiers(&self) -> u8 {
        self.held_modifier_bits()
    }

    fn plan_rel(&self, event: RelEvent, hid_held: bool, now: Instant) -> Plan {
        SendInputInjector::plan_rel(self, event, hid_held, RelPath::Hid, now)
    }

    fn rel_failed(&self, why: &'static str) {
        SendInputInjector::rel_failed(self, why)
    }

    fn rel_queued(&self, s: u32, now: Instant) {
        SendInputInjector::rel_queued(self, s, now)
    }

    fn note_input(&self, now: Instant) {
        SendInputInjector::note_input(self, now)
    }

    fn plan_abs(&self, x: f64, y: f64, now: Instant) -> Option<(i32, i32, i32, i32)> {
        SendInputInjector::plan_abs(self, x, y, RelPath::Hid, now)
    }

    fn order_waited(&self, waited: Duration, timed_out: bool, now: Instant) {
        SendInputInjector::order_waited(self, waited, timed_out, now)
    }

    fn foreground_elevation(&self, now: Instant) -> Option<Elevation> {
        SendInputInjector::foreground_elevation(self, now)
    }

    fn wheel_tally(&self, tally: WheelTally, now: Instant) {
        self.count_wheel(tally, now)
    }

    fn hid_buttons(&self, held: u8, change: Option<(u8, bool, Instant)>) {
        SendInputInjector::hid_buttons(self, held, change)
    }
}

/// Everything around the device the router touches. The agent's is `System` (the real desktop,
/// `SendInput` and keyboard layouts); tests use a fake world.
pub(crate) trait Host: Send {
    /// Where HID input may go right now.
    fn evaluate_target(&mut self) -> TargetEval;
    /// The primary screen in pixels: relative motion is scaled to it.
    fn screen_size(&mut self) -> (i32, i32);
    /// Where the cursor is (`GetCursorPos`: the virtual screen, whose origin is the primary
    /// monitor's top-left corner), or why it cannot be read (another desktop has the input). The
    /// ordering wait after an absolute move asks.
    fn cursor_pos(&mut self) -> Result<(i32, i32), String>;
    /// The foreground window (`GetForegroundWindow`; 0 for none). In game-only mode the worker asks
    /// before everything it sends unattended.
    fn foreground(&mut self) -> usize;
    fn sendinput(&self) -> &dyn SendInputPath;
    fn keyboard(&mut self) -> &mut dyn Keyboard;
    /// Wait, on the calling thread. Only a queue sent at once without its worker does (once, for a
    /// modifier change to settle); tests move their virtual clock instead.
    fn pause(&mut self, duration: Duration);
    /// The cursor now (`GetCursorInfo`): whether a game hid it. The button watch looks after every
    /// mouse button change in game-only mode.
    fn cursor_look(&mut self) -> Result<CursorLook, String>;
    /// What Windows says of the mouse around a button change, for the button watch's line: the three
    /// buttons' async key state, and with `detail` who has the mouse — the game's (`game`, its window)
    /// thread's capture, the window under the cursor, the foreground window.
    fn button_probe(&mut self, game: usize, detail: bool) -> ButtonProbe;
}

/// A key or a mouse button held on HID, for its minimum hold.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Press {
    Key(Key),
    Button(u8),
}

/// One open FakerInput device plus the routing state for one session batch.
///
/// Serialized HID writes and held state (`state`), the short-lived foreground decision
/// (`target_cache`/`last_target`), a `broken` latch that sends the rest of the session through
/// SendInput once the device stops accepting writes, and the game text being typed with the input
/// waiting behind it (`typist`). Time comes in as an argument, so tests run it on a virtual clock.
struct HidRuntime<D, H> {
    state: State<D>,
    host: H,
    /// The last foreground decision and when it was taken (valid for [`TARGET_CACHE_TTL`]).
    target_cache: Option<(Target, Instant)>,
    /// The last decision actually acted on, for one-shot transition logging and cleanup.
    last_target: Option<Target>,
    /// The device failed mid-session and could not be recovered; route through SendInput.
    broken: bool,
    /// Which way the wheel went last, for its transition log.
    wheel_path: PathLog,
    /// When the last wheel not marked `game` went as HID notches: after a pause
    /// ([`STEPPED_CARRY_PAUSE`]) its unfinished notch is forgotten.
    stepped_wheel_at: Option<Instant>,
    /// Which way `m` went last, for its transition log.
    position_path: PathLog,
    /// The last absolute report (an `m`, a point move), until the cursor is seen there: a button
    /// going down or up right after it waits for it (see `wait_for_position`).
    unseen: Option<Unseen>,
    /// When the button waiting for it first waited (for the per-second line's longest wait).
    order_wait_since: Option<Instant>,
    /// The cursor was unreadable for that check once already (said at `debug` once).
    order_blind_said: bool,
    /// Game text being typed, and the input queued behind it.
    typist: Typist,
    /// When each key (`k`) and mouse button (`d`) still held on HID went down: a release sooner
    /// than [`typing::TAP_MIN_HOLD`] after it waits (see `release_held`).
    pressed_at: BTreeMap<Press, PressHold>,
    /// Releases deferred so far, for their trace line.
    tap_deferrals: u64,
    /// Off only while the queue is sent at once (`flush_unpaced`): nothing may wait then.
    defer_taps: bool,
    /// A worker thread works the queue (the agent's glue; the tests step by hand).
    #[cfg_attr(not(windows), allow(dead_code))]
    worker_running: bool,
    /// Where the worker may send what is queued — game text, and the input waiting behind it. In
    /// game-only mode only while the game's window is the foreground window; otherwise the queue is
    /// dropped and everything held released, as for a desktop HID may not drive. Set with every
    /// event ([`FakerInputInjector::inject_confined`]).
    queue_gate: QueueGate,
    /// Game-only mode: did the game take each mouse button change ([`button_watch`])? Polled by the
    /// worker, which runs while it watches anything.
    watch: ButtonWatch,
    /// The per-press lines any viewer can repeat (a seventh key, a key outside the descriptor,
    /// each sent through SendInput): a flood of presses is not a line each (KB-6).
    lines: crate::line_gate::LineGate,
}

/// Where the typing worker may send what is queued.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum QueueGate {
    /// Game-only mode is off: wherever the desktop allows, as before.
    #[default]
    Desktop,
    /// Game-only mode: only while this window — the game's — has the front.
    Game(usize),
    /// Game-only mode, and the game's window is not shown: nowhere.
    Closed,
}

impl std::fmt::Display for QueueGate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Desktop => write!(f, "the desktop"),
            Self::Game(window) => {
                write!(f, "the game's window {window:#x}, while it has the front")
            }
            Self::Closed => write!(f, "nowhere (the game's window is not shown)"),
        }
    }
}

/// FakerInput rejections/failures, throttled like [`WRITE_WARN`].
static REJECT_WARN: WarnThrottle = WarnThrottle::new();

fn note_rejected(error: &anyhow::Error) {
    if let Some(suppressed) = REJECT_WARN.should_warn() {
        tracing::warn!(%error, suppressed, "FakerInput rejected or failed input");
    }
}

impl<D: Driver, H: Host> HidRuntime<D, H> {
    fn new(state: State<D>, host: H) -> Self {
        Self {
            state,
            host,
            target_cache: None,
            last_target: None,
            broken: false,
            wheel_path: PathLog::new("wheel"),
            stepped_wheel_at: None,
            position_path: PathLog::new("position (m)"),
            unseen: None,
            order_wait_since: None,
            order_blind_said: false,
            typist: Typist::default(),
            pressed_at: BTreeMap::new(),
            tap_deferrals: 0,
            defer_taps: true,
            worker_running: false,
            queue_gate: QueueGate::Desktop,
            watch: ButtonWatch::default(),
            lines: crate::line_gate::LineGate::new(),
        }
    }

    /// Where the worker may send what is queued (game-only mode). Said when it changes.
    fn confine_to(&mut self, gate: QueueGate) {
        if self.queue_gate == gate {
            return;
        }
        tracing::debug!(
            from = %self.queue_gate,
            to = %gate,
            "queued input (game text and what waits behind it) goes to"
        );
        self.queue_gate = gate;
    }

    /// Outside game-only mode, always; in it, whether the game's window is the foreground window
    /// now — looked at afresh.
    fn game_in_front(&mut self) -> bool {
        match self.queue_gate {
            QueueGate::Desktop => true,
            QueueGate::Game(game) => self.host.foreground() == game,
            QueueGate::Closed => false,
        }
    }

    /// Log the wheel's path on a change. Any change of its route — the path, or the reason (the game
    /// wheel, game-only mode, an elevated window, back to smooth) — drops the unfinished HID notch:
    /// it was made for the old route, maybe for another window. Whether one was dropped.
    fn note_wheel_path(
        &mut self,
        path: Via,
        reason: &'static str,
        foreground: Option<&str>,
        now: Instant,
    ) -> bool {
        match self.wheel_path.note_about(path, reason, foreground, now) {
            Change::Same => false,
            Change::Reason | Change::Path => {
                self.state.drop_wheel_carry("the wheel's route changed")
            }
        }
    }

    /// Log `m`'s path on a change. Leaving HID forgets the absolute move a button would wait for: the
    /// buttons that follow go by SendInput, or on a desktop HID may not drive.
    fn note_position_path(&mut self, path: Via, reason: &'static str, now: Instant) {
        if self.position_path.note(path, reason, now) == Change::Path && path == Via::SendInput {
            self.unseen = None;
        }
    }

    /// The foreground target for a press/move, cached for [`TARGET_CACHE_TTL`]. Logs only on a
    /// change of state, and releases held HID (and SendInput) input once when it becomes blocked —
    /// dropping queued typing with it.
    fn target(&mut self, now: Instant) -> Target {
        if let Some((target, at)) = self.target_cache {
            if now.saturating_duration_since(at) < TARGET_CACHE_TTL {
                return target;
            }
        }
        let eval = self.host.evaluate_target();
        if self.last_target != Some(eval.target) {
            match eval.target {
                Target::Allowed => {
                    tracing::debug!(reason = eval.reason, "HID target allowed")
                }
                Target::Blocked => tracing::warn!(
                    reason = eval.reason,
                    "HID target blocked: releasing held input; new presses/moves go through SendInput"
                ),
                Target::Unknown => tracing::debug!(
                    reason = eval.reason,
                    "HID target unknown: new presses/moves go through SendInput"
                ),
            }
            if eval.target == Target::Blocked {
                // A physical HID key still held when the input switches to a surface we must not
                // drive (the secure desktop, the lock screen) must not stay down across it. Release
                // everything held, once, on the transition into this state — and never type into it.
                self.typist.drop_all("HID target blocked");
                self.pressed_at.clear();
                self.forget_order_wait();
                self.watch.reset("HID target blocked");
                let buttons = self.state.mouse.buttons();
                if let Err(error) = self.state.release() {
                    tracing::error!(%error, "HID blocked-target cleanup failed");
                }
                self.tell_buttons(buttons);
                self.host.sendinput().release_all();
            }
            self.last_target = Some(eval.target);
        }
        self.target_cache = Some((eval.target, now));
        eval.target
    }

    /// [`Self::target`] looked at afresh, not from the cache: what the worker asks before anything
    /// it sends unattended.
    fn target_now(&mut self, now: Instant) -> Target {
        self.target_cache = None;
        self.target(now)
    }

    /// Before the worker sends something queued (an event, a held wheel): the desktop, afresh. If
    /// HID may not drive it — a UAC prompt or the lock screen took the input, another session, or a
    /// desktop it cannot confirm — nothing queued goes: everything is dropped and everything held
    /// released (the transition into a blocked desktop has done so already). The device being
    /// unusable is not the desktop's business: then everything goes by SendInput, which Windows
    /// gates on its own.
    fn unattended_allowed(&mut self, now: Instant) -> bool {
        // Game-only mode: nothing queued goes into another window, by either path.
        if !self.game_in_front() {
            if self.typist.has_work() || !self.typist.held_wheels.is_empty() {
                self.drop_and_release("game-only mode: the game's window lost the front");
            }
            return false;
        }
        if self.broken {
            return true;
        }
        let target = self.target_now(now);
        if target == Target::Allowed {
            return true;
        }
        if self.typist.has_work() || !self.typist.held_wheels.is_empty() {
            self.drop_and_release(if target == Target::Blocked {
                "HID target blocked before queued input"
            } else {
                "HID target unknown before queued input"
            });
        }
        false
    }

    /// A wheel message. The game wheel (`game`) follows the target like a move: whole HID notches
    /// where HID may go, SendInput elsewhere. Every other wheel asks where it is going first
    /// ([`Self::wheel_route`]): smooth SendInput wherever that reaches — without a look at the
    /// target, so desktop scrolling stays smooth with the device open — and, in game-only mode and
    /// to a foreground window SendInput cannot reach, whole HID notches by the target like the game
    /// wheel. What went where is counted for the planner's
    /// per-second line.
    fn wheel(
        &mut self,
        event: &InputMessage,
        (dx, dy, mode): (f64, f64, Option<u8>),
        game: bool,
        now: Instant,
    ) -> Result<()> {
        let mode = WheelMode::from_wire(mode);
        let mut tally = WheelTally::default();
        let result = if game {
            self.game_wheel(event, (dx, dy, mode), &mut tally, now)
        } else {
            self.unmarked_wheel(event, (dx, dy, mode), &mut tally, now)
        };
        if tally != WheelTally::default() {
            self.host.sendinput().wheel_tally(tally, now);
        }
        result
    }

    /// The viewer's game-mode wheel (`game: true`): as it always was.
    fn game_wheel(
        &mut self,
        event: &InputMessage,
        (dx, dy, mode): (f64, f64, WheelMode),
        tally: &mut WheelTally,
        now: Instant,
    ) -> Result<()> {
        let (path, reason) = match self.target(now) {
            Target::Allowed => (Via::Hid, GAME_WHEEL_HID),
            Target::Blocked => (Via::SendInput, "game-mode wheel, HID target blocked"),
            Target::Unknown => (Via::SendInput, "game-mode wheel, HID target unknown"),
        };
        tally.resets += u32::from(self.note_wheel_path(path, reason, None, now));
        match path {
            Via::Hid => self.hid_wheel((dx, dy, mode), false, tally),
            Via::SendInput => self.host.sendinput().inject(event),
        }
    }

    /// A wheel the viewer did not mark `game` (the desktop's; any wheel in game-only mode), on the
    /// route [`Self::wheel_route`] gives it. On HID: SendInput's own scale ([`PIXELS_PER_NOTCH`], one
    /// notch a `WHEEL_DELTA` of 120), the fraction carried to the next message — but not across a
    /// pause ([`STEPPED_CARRY_PAUSE`]), a change of route or of direction.
    fn unmarked_wheel(
        &mut self,
        event: &InputMessage,
        (dx, dy, mode): (f64, f64, WheelMode),
        tally: &mut WheelTally,
        now: Instant,
    ) -> Result<()> {
        let (path, reason, foreground) = match self.wheel_route(now) {
            WheelRoute::Smooth(reason) => (Via::SendInput, reason, None),
            WheelRoute::Stepped(reason, foreground) => match self.target(now) {
                Target::Allowed => (Via::Hid, reason, foreground),
                // A surface Windows keeps for itself, or one we cannot confirm: never HID.
                Target::Blocked => (Via::SendInput, WHEEL_STEPPED_BLOCKED, None),
                Target::Unknown => (Via::SendInput, WHEEL_STEPPED_UNKNOWN, None),
            },
        };
        tally.resets += u32::from(self.note_wheel_path(path, reason, foreground.as_deref(), now));
        // Per message, so trace: a scrolling finger is sixty of these a second.
        tracing::trace!(
            path = path.name(),
            reason,
            dx,
            dy,
            ?mode,
            "wheel not marked game"
        );
        if path == Via::SendInput {
            return self.host.sendinput().inject(event);
        }
        let paused = self
            .stepped_wheel_at
            .is_some_and(|at| now.saturating_duration_since(at) >= STEPPED_CARRY_PAUSE);
        if paused && self.state.drop_wheel_carry("a pause in the stepped wheel") {
            tally.resets += 1;
        }
        self.stepped_wheel_at = Some(now);
        self.hid_wheel((dx, dy, mode), true, tally)
    }

    /// Where a wheel the viewer did not mark `game` goes, decided when it is sent (it may have waited
    /// behind queued input, and then it goes where the foreground is by then). In game-only mode: to
    /// the game in whole HID notches — the game guard let it through only while the game has the
    /// front, and nothing queued goes unless it does. Otherwise the text's decision ([`Reach`]) on
    /// the foreground window's elevation, looked at afresh, with the driver open (a broken device
    /// sent everything to SendInput before this).
    fn wheel_route(&mut self, now: Instant) -> WheelRoute {
        if self.queue_gate != QueueGate::Desktop {
            return WheelRoute::Stepped(WHEEL_GAME_ONLY, None);
        }
        let elevation = self.host.sendinput().foreground_elevation(now);
        match Reach::of(elevation.as_ref(), true) {
            Reach::Driver => WheelRoute::Stepped(WHEEL_ELEVATED, elevation.map(|e| e.exe)),
            Reach::BothElevated => WheelRoute::Smooth(WHEEL_BOTH_ELEVATED),
            Reach::Ordinary => WheelRoute::Smooth(WHEEL_ORDINARY),
            Reach::Unknown => WheelRoute::Smooth(WHEEL_UNKNOWN),
            // Not with the driver open; the reason says it all the same.
            Reach::ElevatedNoDriver => WheelRoute::Smooth(WHEEL_ELEVATED_NO_DRIVER),
        }
    }

    /// One wheel message as whole HID notches, counted: the game wheel's pixels at its own knob
    /// ([`HID_PIXELS_PER_NOTCH`]), a wheel not marked `game` (`stepped`) at SendInput's scale
    /// ([`PIXELS_PER_NOTCH`]). A failed report is not counted: the failure is said at `warn`, and
    /// the recovery follows.
    fn hid_wheel(
        &mut self,
        (dx, dy, mode): (f64, f64, WheelMode),
        stepped: bool,
        tally: &mut WheelTally,
    ) -> Result<()> {
        let out = if stepped {
            self.state.wheel_scaled(dx, dy, mode, PIXELS_PER_NOTCH)?
        } else {
            self.state.wheel(dx, dy, mode)?
        };
        if stepped {
            tally.hid_stepped += 1;
        } else {
            tally.hid_game += 1;
        }
        tally.notches = tally.notches.saturating_add(out.notches);
        tally.resets += u32::from(out.reversed);
        Ok(())
    }

    /// A prior HID write failed. Try neutral cleanup before touching the device again; if the
    /// cleanup also fails the device is gone, and the rest of the session runs on SendInput. The
    /// event whose write failed is not replayed — it may have reached the driver. With game text
    /// queued the failure also stops the typing: everything queued is dropped and everything held
    /// released, on both paths (see [`typing`]).
    fn recover(&mut self) {
        if self.broken || !self.state.failed {
            return;
        }
        if self.typist.has_work() {
            self.drop_and_release("a driver write failed while game text was queued");
            return;
        }
        // The neutral report lets everything up: no button change of before it is watched any more.
        self.watch.reset("a driver write failed");
        let buttons = self.state.mouse.buttons();
        if let Err(error) = self.state.release() {
            self.broken = true;
            tracing::warn!(%error, "FakerInput device unusable (write and neutral cleanup both failed); using SendInput for the rest of the session");
            self.host.sendinput().release_all();
            // Nothing goes by HID any more: no button waits for an absolute move.
            self.forget_order_wait();
        }
        self.tell_buttons(buttons);
    }

    /// Stop typing: drop everything queued (counted) and release everything held on both paths —
    /// the queue is never dropped without that release, so a key-up waiting in it cannot strand its
    /// key. A neutral cleanup that fails too marks the device unusable, as `recover` does.
    fn drop_and_release(&mut self, reason: &'static str) {
        self.typist.drop_all(reason);
        self.pressed_at.clear();
        self.forget_order_wait();
        self.watch.reset(reason);
        let buttons = self.state.mouse.buttons();
        if !self.broken {
            if let Err(error) = self.state.release() {
                self.broken = true;
                tracing::warn!(%error, "FakerInput device unusable (write and neutral cleanup both failed); using SendInput for the rest of the session");
            }
        }
        self.tell_buttons(buttons);
        self.host.sendinput().release_all();
    }

    /// After a neutral report: the planner hears of the buttons it let up (`before`: what was held).
    fn tell_buttons(&self, before: u8) {
        let after = self.state.mouse.buttons();
        if after != before {
            self.host.sendinput().hid_buttons(after, None);
        }
    }

    /// A mouse button through the driver (`b`, the protocol's id), written; when that changed it, the
    /// planner hears of it, and in game-only mode the button watch, with the cursor as it is right
    /// after the report (before the game can react) — when the cursor can be read.
    fn hid_button(&mut self, b: u8, down: bool, now: Instant) -> Result<()> {
        let before = self.state.mouse.buttons();
        self.state.button(b, down)?;
        let changed = before ^ self.state.mouse.buttons();
        if changed == 0 {
            return Ok(());
        }
        self.host
            .sendinput()
            .hid_buttons(self.state.mouse.buttons(), Some((changed, down, now)));
        if matches!(self.queue_gate, QueueGate::Game(_)) {
            match self.host.cursor_look() {
                Ok(look) => self
                    .watch
                    .transition(changed, down, Some(look.showing), now),
                Err(error) => tracing::trace!(
                    %error,
                    "button watch: the cursor is unreadable at a button change; not watched"
                ),
            }
        }
        Ok(())
    }

    /// The button watch's due looks (worked by [`Self::step`]): a release the game seems to have
    /// missed is sent once more — the press now, the release behind it after the minimum hold, both
    /// queued so whatever comes meanwhile waits behind them — when [`Self::may_resend`] allows.
    fn watch_step(&mut self, now: Instant) {
        if self.watch.due().is_none_or(|due| due > now) {
            return;
        }
        let game = match self.queue_gate {
            QueueGate::Game(game) => Some(game),
            QueueGate::Desktop | QueueGate::Closed => None,
        };
        let ours = self.state.mouse.buttons();
        let Some(missed) = self.watch.poll(now, game, ours, &mut self.host) else {
            return;
        };
        let Some(b) = bit_button(missed.bit) else {
            return;
        };
        match self.may_resend(game, now) {
            Ok(()) => {
                self.watch.resend(missed, now);
                self.typist.push_event(InputMessage::Down { b }, now);
                self.typist.push_event(InputMessage::Up { b }, now);
            }
            Err(why) => self.watch.not_resent(missed, why),
        }
    }

    /// The router's part of a re-send's conditions (the watch's own are its): game-only mode with the
    /// game's window in front, a working device on a desktop HID may drive, nothing waiting in the
    /// queue, and nothing held on either path — no button, key or modifier.
    fn may_resend(&mut self, game: Option<usize>, now: Instant) -> Result<(), &'static str> {
        let Some(game) = game else {
            return Err("game-only mode is off");
        };
        if self.broken {
            return Err("the device is unusable");
        }
        if self.host.foreground() != game {
            return Err("the game's window does not have the front");
        }
        if self.typist.has_work() || !self.typist.held_wheels.is_empty() {
            return Err("input waits in the queue");
        }
        let held = &self.state.held;
        if self.state.mouse.buttons() != 0
            || !held.keys.is_empty()
            || held.modifiers != 0
            || held.media != 0
        {
            return Err("something is held through the driver");
        }
        let sendinput = self.host.sendinput();
        if sendinput.held_modifiers() != 0 || (0..=2).any(|b| sendinput.holds_button(b)) {
            return Err("something is held through SendInput");
        }
        if self.target_now(now) != Target::Allowed {
            return Err("HID may not drive the desktop now");
        }
        Ok(())
    }

    /// A viewer event, in order. Game text is queued for the worker ([`Self::step`]); while anything
    /// is queued, the keys, buttons, combos and text that must not overtake it wait behind it.
    /// Positional input (`r`, `m`, `w`) goes at once only while nothing but text waits: once a
    /// click, a key or a combo waits, a move after it waits too — a click lands where the pointer
    /// was, and a queued button release is not outrun by a drag. A game wheel that comes while the
    /// typing holds a modifier down (a capital's Shift) waits for it to go up. Everything else is
    /// routed now.
    fn admit(&mut self, event: &InputMessage, now: Instant) -> Result<()> {
        let busy = self.typist.has_work();
        match event {
            InputMessage::Text {
                text,
                game: Some(true),
            } => {
                if !busy {
                    self.recover();
                    let unicode = if self.broken {
                        Some("the device is unusable")
                    } else {
                        match self.target(now) {
                            Target::Allowed => None,
                            Target::Blocked => Some("HID target blocked"),
                            Target::Unknown => Some("HID target unknown"),
                        }
                    };
                    if let Some(reason) = unicode {
                        // Today's path, exactly: the whole text by Unicode, now.
                        self.typist.memory.path.note(TextPath::Unicode(reason));
                        return self.host.sendinput().inject(event);
                    }
                }
                self.queue_text(text, now);
                Ok(())
            }
            // Behind a queued click, key or combo, positional input waits its turn.
            InputMessage::Move { .. } | InputMessage::Rel { .. } | InputMessage::Wheel { .. }
                if busy && !self.typist.only_text() =>
            {
                self.queue_event(event, now)
            }
            // Only text waits: the camera keeps turning while a line is typed.
            InputMessage::Move { .. } | InputMessage::Rel { .. } => self.execute(event, now),
            // A wheel under the typing's Shift would be a Shift+wheel (modifier state is one for
            // every input path): it waits for the modifiers to go up — the typing lets them up at
            // the next character for it — and so does every wheel after it, in order.
            InputMessage::Wheel { .. }
                if self.typist.head_holds_modifiers() || !self.typist.held_wheels.is_empty() =>
            {
                self.typist.hold_wheel(event.clone());
                Ok(())
            }
            InputMessage::Wheel { .. } => self.execute(event, now),
            InputMessage::Key { .. }
            | InputMessage::Down { .. }
            | InputMessage::Up { .. }
            | InputMessage::Combo { .. }
            | InputMessage::Text { .. }
                if busy =>
            {
                self.queue_event(event, now)
            }
            _ => self.execute(event, now),
        }
    }

    fn queue_text(&mut self, text: &str, now: Instant) {
        let normalized = typing::normalize(text);
        if normalized.chars.is_empty() {
            tracing::trace!(
                newlines_dropped = normalized.newlines,
                "game text: nothing left to type after normalisation"
            );
            return;
        }
        if self.typist.queue.len() >= MAX_QUEUED_JOBS {
            self.flush_unpaced(now, "the typing queue is full");
        }
        let queued = self.typist.queued_chars();
        if queued + normalized.chars.len() > MAX_QUEUED_CHARS {
            tracing::debug!(
                chars = normalized.chars.len(),
                queued,
                limit = MAX_QUEUED_CHARS,
                "game text over the typing queue's limit: it goes by Unicode, in its turn"
            );
            self.typist.push_event(
                InputMessage::Text {
                    text: normalized.chars.into_iter().collect(),
                    game: None,
                },
                now,
            );
            return;
        }
        self.typist.push_text(normalized, now);
    }

    fn queue_event(&mut self, event: &InputMessage, now: Instant) -> Result<()> {
        if self.typist.queue.len() >= MAX_QUEUED_JOBS {
            self.flush_unpaced(now, "the typing queue is full");
            return self.execute(event, now);
        }
        self.typist.push_event(event.clone(), now);
        // A numbered move behind a click or a key is not on the cursor yet: the cursor report's
        // `ack` must not claim it until it goes (the planner hears of it then).
        if let InputMessage::Rel { s: Some(s), .. } = event {
            self.host.sendinput().rel_queued(*s, now);
        }
        Ok(())
    }

    /// Route one event now: the rules in the module docs. The barrier is `admit`'s; this is also
    /// what a queued event goes through when its turn comes.
    fn execute(&mut self, event: &InputMessage, now: Instant) -> Result<()> {
        self.host.sendinput().note_input(now);
        self.recover();
        if self.broken {
            // The device failed earlier this session; everything goes through SendInput now.
            match event {
                InputMessage::Wheel { game, .. } => {
                    let reason = if *game == Some(true) {
                        "game-mode wheel, but the device is unusable"
                    } else {
                        WHEEL_BROKEN
                    };
                    if self.note_wheel_path(Via::SendInput, reason, None, now) {
                        let dropped = WheelTally {
                            resets: 1,
                            ..WheelTally::default()
                        };
                        self.host.sendinput().wheel_tally(dropped, now);
                    }
                }
                InputMessage::Move { .. } => {
                    self.note_position_path(Via::SendInput, "the device is unusable", now);
                }
                _ => {}
            }
            return self.host.sendinput().inject(event);
        }

        // Always SendInput: IME text (game text the driver types never gets here: `admit` queues
        // it; nor does text the game guard sent to the driver). The wheel: see `wheel`.
        match event {
            InputMessage::Text { .. } => return self.host.sendinput().inject(event),
            InputMessage::Wheel { dx, dy, mode, game } => {
                return self.wheel(event, (*dx, *dy, *mode), *game == Some(true), now);
            }
            InputMessage::Combo { .. } => {
                bail!("system key combinations are not supported by FakerInput")
            }
            _ => {}
        }

        // Releases follow whoever holds the key/button, never the current target: a press and its
        // release must not split across backends.
        match event {
            InputMessage::Up { b } => {
                return if self.state.holds_button(*b) {
                    self.release_held(Press::Button(*b), event, now)
                } else {
                    // Held by SendInput, or by no one (a stray up): SendInput's up is idempotent.
                    self.host.sendinput().inject(event)
                };
            }
            InputMessage::Key { d: 0, code, .. } => {
                return match key(code) {
                    Some(k) if self.state.holds_key(k) => {
                        self.release_held(Press::Key(k), event, now)
                    }
                    Some(_) => self.host.sendinput().inject(event),
                    None if super::code_to_vk(code).is_some() => {
                        self.host.sendinput().inject(event)
                    }
                    None => bail!("key has no supported physical mapping"),
                };
            }
            _ => {}
        }

        // Presses (down / key-down) and moves. A repeat of something already held goes to the path
        // that holds it: routing a repeat by target instead would press a SendInput-held key a
        // second time on HID, and its release (routed above by who holds it) would then free only one
        // copy and strand the other. A genuinely new press, or a move, follows the current target.
        match event {
            InputMessage::Down { b } => {
                if self.state.holds_button(*b) {
                    return self.state.button(*b, true);
                }
                if self.host.sendinput().holds_button(*b) {
                    return self.host.sendinput().inject(event);
                }
                match self.target(now) {
                    Target::Allowed => {
                        if self.wait_for_position(event, now) {
                            // Queued: it goes once the absolute move before it shows.
                            return Ok(());
                        }
                        self.hid_button(*b, true, now)?;
                        // A new press: its release waits out the minimum hold.
                        self.pressed_at
                            .insert(Press::Button(*b), PressHold::new(now));
                        Ok(())
                    }
                    _ => self.host.sendinput().inject(event),
                }
            }
            InputMessage::Key { code, .. } => {
                // d == 1 here (key-up returned above).
                let mapped = key(code);
                if let Some(k) = mapped {
                    if self.state.holds_key(k) {
                        // A press on HID ends SendInput's emulated repeat, as a physical keyboard's
                        // new key would; a re-press of a modifier already down does not.
                        self.host
                            .sendinput()
                            .other_key_pressed(matches!(k, Key::Modifier(_)), true);
                        return self.state.key(k, true);
                    }
                }
                if self.host.sendinput().holds_key(code) {
                    return self.host.sendinput().inject(event);
                }
                match self.target(now) {
                    Target::Allowed => match mapped {
                        Some(Key::Usage(usage)) if self.state.usage_overflows(usage) => {
                            // The seventh simultaneous non-modifier key: the HID descriptor holds
                            // six. Send it through SendInput rather than drop it; its release follows
                            // the same path (routed above by who holds it), so nothing strands.
                            if self.lines.admit(now, "seventh key") {
                                tracing::debug!("seventh simultaneous key routed via SendInput");
                            } else {
                                tracing::trace!("seventh simultaneous key routed via SendInput");
                            }
                            self.host.sendinput().inject(event)
                        }
                        Some(k) => {
                            self.host
                                .sendinput()
                                .other_key_pressed(matches!(k, Key::Modifier(_)), false);
                            self.state.key(k, true)?;
                            // A new press: its release waits out the minimum hold.
                            self.pressed_at.insert(Press::Key(k), PressHold::new(now));
                            if k == CAPS_LOCK {
                                // Typing reads Caps Lock as the focused window sees it, which may
                                // not have read this press yet.
                                self.typist.memory.caps_pressed(now);
                            }
                            Ok(())
                        }
                        None if super::code_to_vk(code).is_some() => {
                            if self.lines.admit(now, "key outside the descriptor") {
                                tracing::debug!(
                                    "key outside FakerInput descriptor; using SendInput"
                                );
                            } else {
                                tracing::trace!(
                                    "key outside FakerInput descriptor; using SendInput"
                                );
                            }
                            self.host.sendinput().inject(event)
                        }
                        None => bail!("key has no supported physical mapping"),
                    },
                    // Blocked (the secure desktop, the lock screen, another session) or unknown (a
                    // rare internal query failure): never drive HID at a surface Windows keeps for
                    // itself or one we cannot confirm. SendInput, which Windows gates on its own.
                    _ => self.host.sendinput().inject(event),
                }
            }
            InputMessage::Rel { dx, dy, x, y, s } => match self.target(now) {
                Target::Allowed => self.relative(
                    RelEvent {
                        dx: *dx,
                        dy: *dy,
                        x: *x,
                        y: *y,
                        s: *s,
                    },
                    now,
                ),
                // The SendInput path asks the same planner itself.
                _ => self.host.sendinput().inject(event),
            },
            // The absolute position follows the target like any move: report 4 where HID may go,
            // today's SendInput event elsewhere (which tells the same planner itself).
            InputMessage::Move { x, y } => match self.target(now) {
                Target::Allowed => self.position(*x, *y, now),
                target => {
                    let reason = if target == Target::Blocked {
                        "HID target blocked"
                    } else {
                        "HID target unknown"
                    };
                    self.note_position_path(Via::SendInput, reason, now);
                    self.host.sendinput().inject(event)
                }
            },
            // ReleaseAll is handled in `inject`; non-input variants reach here as no-ops.
            _ => Ok(()),
        }
    }

    /// An `m` on HID: FakerInput's absolute report onto the pixel the planner gives — the point
    /// move's pixel and mapping (`cursor_sync::target_pixel`, [`absolute_wire`]) — with a button
    /// held as well (a drag). The report is remembered until the cursor is seen there, so a button
    /// right after it cannot overtake it (see [`Self::wait_for_position`]).
    fn position(&mut self, x: f64, y: f64, now: Instant) -> Result<()> {
        ensure!(
            x.is_finite() && y.is_finite(),
            "non-finite absolute position"
        );
        let Some((px, py, width, height)) = self.host.sendinput().plan_abs(x, y, now) else {
            bail!("primary screen size unavailable");
        };
        self.note_position_path(Via::Hid, POSITION_HID, now);
        let result = self.state.position(px, py, width, height);
        self.absolute_written(&result, (px, py), now, "the HID absolute report (m) failed");
        result
    }

    /// An absolute report (an `m`, or a point move of `r`) was written, or its write failed. Written,
    /// it is remembered until the cursor is seen on its pixel, so a button right after it waits for
    /// it ([`Self::wait_for_position`]); failed, there is nothing to wait for, and the planner
    /// expects nothing of it either.
    fn absolute_written(
        &mut self,
        result: &Result<()>,
        (px, py): (i32, i32),
        now: Instant,
        failed: &'static str,
    ) {
        if result.is_ok() {
            self.unseen = Some(Unseen { px, py, at: now });
        } else {
            self.unseen = None;
            self.host.sendinput().rel_failed(failed);
        }
    }

    /// Whether a mouse button going down or up on HID (the relative report's collection) must wait
    /// for the absolute move written just before it — an `m`, or a point move of `r`; if so, it is
    /// put at the head of the queue for a moment (`true`) and the worker brings it back here then.
    /// The move's report 4 is another collection — to Windows another mouse, read on its own — so a
    /// button written right behind it may reach Windows first and click where the cursor was. It
    /// waits until `GetCursorPos` shows the move (within [`ORDER_NEAR_PX`]), at most
    /// [`ORDER_WAIT_MAX`] after the move was written; whatever comes after it waits behind it in
    /// order, moves too. Never on the caller's thread: the queue's worker waits. A button long after
    /// the move, or one when the cursor is already there, goes at once; so does one when the cursor
    /// cannot be read, or while the queue is being sent at once.
    fn wait_for_position(&mut self, event: &InputMessage, now: Instant) -> bool {
        let Some(unseen) = self.unseen else {
            return false;
        };
        let age = now.saturating_duration_since(unseen.at);
        let cursor = match self.host.cursor_pos() {
            Ok(cursor) => cursor,
            Err(error) => {
                if self.order_blind_said {
                    tracing::trace!(
                        %error,
                        "button after an absolute move: the cursor is unreadable; not waiting"
                    );
                } else {
                    self.order_blind_said = true;
                    tracing::debug!(
                        %error,
                        "button after an absolute move: the cursor is unreadable, so the button \
                         goes without waiting for the move to show (said once; further ones at \
                         trace)"
                    );
                }
                self.finish_order_wait(now, false);
                return false;
            }
        };
        let there = (cursor.0 - unseen.px).abs() <= ORDER_NEAR_PX
            && (cursor.1 - unseen.py).abs() <= ORDER_NEAR_PX;
        if there {
            tracing::trace!(
                age_us = age.as_micros(),
                waited = self.order_wait_since.is_some(),
                "button after an absolute move: the cursor is there; it goes"
            );
            self.finish_order_wait(now, false);
            return false;
        }
        if age >= ORDER_WAIT_MAX {
            match self.order_wait_since {
                Some(since) => tracing::debug!(
                    waited_ms = %format!("{:.1}", now.saturating_duration_since(since).as_secs_f64() * 1000.0),
                    move_age_ms = %format!("{:.1}", age.as_secs_f64() * 1000.0),
                    px = unseen.px,
                    py = unseen.py,
                    cursor_x = cursor.0,
                    cursor_y = cursor.1,
                    "button after an absolute move: the cursor did not show the move in time; \
                     the button goes anyway (a clipped cursor, the PC's own mouse, another \
                     desktop?)"
                ),
                // It came long after the move: that one has shown, or never will (the PC's own
                // mouse moved the cursor since). Not a wait.
                None => tracing::trace!(
                    move_age_ms = %format!("{:.1}", age.as_secs_f64() * 1000.0),
                    "button long after an absolute move, the cursor elsewhere; it goes"
                ),
            }
            let timed_out = self.order_wait_since.is_some();
            self.finish_order_wait(now, timed_out);
            return false;
        }
        if !self.defer_taps {
            // The queue is being sent at once (`flush_unpaced`): nothing may wait.
            tracing::trace!(
                "button after an absolute move: the queue is sent at once; not waiting"
            );
            self.finish_order_wait(now, false);
            return false;
        }
        let first = self.order_wait_since.is_none();
        let since = *self.order_wait_since.get_or_insert(now);
        let at = (now + ORDER_POLL).min(unseen.at + ORDER_WAIT_MAX);
        tracing::trace!(
            first,
            move_age_us = age.as_micros(),
            waited_us = now.saturating_duration_since(since).as_micros(),
            px = unseen.px,
            py = unseen.py,
            cursor_x = cursor.0,
            cursor_y = cursor.1,
            "button after an absolute move waits for it to show"
        );
        self.typist.wait_front(event.clone(), at, now);
        true
    }

    /// The button stops waiting for the absolute move (it showed, the time is up, or the cursor
    /// could not be read): forget the move, and count the wait if there was one.
    fn finish_order_wait(&mut self, now: Instant, timed_out: bool) {
        self.unseen = None;
        if let Some(since) = self.order_wait_since.take() {
            self.host.sendinput().order_waited(
                now.saturating_duration_since(since),
                timed_out,
                now,
            );
        }
    }

    /// The absolute move and a button waiting for it are forgotten with what was queued (`ra`, a
    /// blocked desktop, a failure): the button was dropped with the queue.
    fn forget_order_wait(&mut self) {
        self.unseen = None;
        if self.order_wait_since.take().is_some() {
            tracing::trace!("a button waiting for an absolute move was dropped with the queue");
        }
    }

    /// A move on HID, as the cursor-sync planner decides it (`crate::cursor_sync`): the camera's
    /// relative counts exactly as before, an absolute report onto the target, or exact relative
    /// counts.
    fn relative(&mut self, event: RelEvent, now: Instant) -> Result<()> {
        let hid_held = self.state.mouse.buttons() != 0;
        let plan = self.host.sendinput().plan_rel(event, hid_held, now);
        // For a press the button watch looks at: the moves made while it is held, by kind.
        match plan {
            Plan::Camera => self.watch.moved(false),
            Plan::Relative { .. } => self.watch.moved(true),
            Plan::Absolute { .. } | Plan::Nothing => {}
        }
        match plan {
            Plan::Camera => {
                let (width, height) = self.host.screen_size();
                self.state.relative(event.dx, event.dy, width, height)
            }
            Plan::Absolute {
                px,
                py,
                width,
                height,
            } => {
                // A click right after it waits for it, as after an `m` (the desktop game mode's
                // press is a point move, then `d`).
                let result = self.state.absolute(px, py, width, height);
                self.absolute_written(&result, (px, py), now, "the HID absolute report failed");
                result
            }
            Plan::Relative { cx, cy } => {
                let result = self.state.movement(cx, cy);
                if result.is_err() {
                    self.host
                        .sendinput()
                        .rel_failed("the HID relative report failed");
                }
                result
            }
            Plan::Nothing => Ok(()),
        }
    }

    /// Release a key or button held on HID — but not sooner than [`typing::TAP_MIN_HOLD`] after its press:
    /// a phone's tap sends the down and the up back to back, and a game that polls once a frame
    /// would never see it. Such a release waits at the head of the queue, so everything after it —
    /// the next key, a click, and a move too — waits behind it. A button's release right after an
    /// absolute move (an `m`, a point move) also waits for it to show ([`Self::wait_for_position`]).
    fn release_held(&mut self, press: Press, event: &InputMessage, now: Instant) -> Result<()> {
        if let Some(&pressed) = self.pressed_at.get(&press) {
            let at = pressed.release_at();
            if at > now && self.defer_taps {
                self.tap_deferrals += 1;
                tracing::trace!(
                    button = matches!(press, Press::Button(_)),
                    held_ms = pressed.elapsed(now).as_millis(),
                    wait_ms = at.saturating_duration_since(now).as_millis(),
                    deferred = self.tap_deferrals,
                    "HID release deferred: a tap shorter than the minimum hold"
                );
                self.typist
                    .defer_front(event.clone(), at, now, pressed.elapsed(now));
                return Ok(());
            }
        }
        // A drag's end right after its last `m`: the button comes up where the `m` put the cursor.
        if matches!(press, Press::Button(_)) && self.wait_for_position(event, now) {
            return Ok(());
        }
        self.pressed_at.remove(&press);
        match press {
            Press::Key(k) => self.state.key(k, false),
            Press::Button(b) => self.hid_button(b, false, now),
        }
    }

    /// Work the queue: everything due by `now`, after the button watch's due looks (which may queue
    /// a re-send). Returns when the next step is due — the queue's or the watch's — or `None` when the
    /// queue is empty and nothing is watched. Nothing is sent without a fresh look at the desktop
    /// first.
    fn step(&mut self, now: Instant) -> Option<Instant> {
        self.watch_step(now);
        let queue = self.step_queue(now);
        match (queue, self.watch.due()) {
            (Some(queue), Some(watch)) => Some(queue.min(watch)),
            (queue, watch) => queue.or(watch),
        }
    }

    /// [`Self::step`]'s queue: everything due by `now`; when its next step is due, or `None` when it
    /// is empty.
    fn step_queue(&mut self, now: Instant) -> Option<Instant> {
        loop {
            match self.typist.next(now) {
                typing::Next::Empty => {
                    // Wheels are held only while text is queued; one left over goes now.
                    self.release_held_wheels(now);
                    self.typist.idle();
                    return None;
                }
                typing::Next::Wait(at) => return Some(at),
                typing::Next::Event => {
                    if !self.unattended_allowed(now) {
                        continue;
                    }
                    if let Some(typing::Job::Event { event, arrived, .. }) = self.typist.pop() {
                        // A release deferred on its turn keeps this arrival, for the gap after it.
                        self.typist.replaying = Some(arrived);
                        let result = self.execute(&event, now);
                        self.typist.replaying = None;
                        self.typist.note_replayed(arrived, now);
                        if let Err(error) = result {
                            note_rejected(&error);
                        }
                    }
                }
                typing::Next::Text => {
                    if let Some(at) = self.step_text(now) {
                        return Some(at);
                    }
                }
            }
        }
    }

    /// Send the wheels that waited for the typing's modifiers, in order.
    fn release_held_wheels(&mut self, now: Instant) {
        if self.typist.held_wheels.is_empty() || !self.unattended_allowed(now) {
            return;
        }
        let wheels = std::mem::take(&mut self.typist.held_wheels);
        tracing::trace!(
            wheels = wheels.len(),
            "held wheels sent: the typing's modifiers are up"
        );
        for wheel in wheels {
            if let Err(error) = self.execute(&wheel, now) {
                note_rejected(&error);
            }
        }
    }

    /// One step of the text at the head of the queue: when to come back, or `None` to look at the
    /// queue again.
    fn step_text(&mut self, now: Instant) -> Option<Instant> {
        // A write that failed since the last step (a move between two typed keys) stops typing.
        self.recover();
        // Game-only mode: not a character into another window — the chat line is dropped, and
        // what the typing holds released.
        if !self.game_in_front() {
            if self.typist.has_work() {
                self.drop_and_release(
                    "game-only mode: the game's window lost the front while text was typed",
                );
            }
            return None;
        }
        let Some(typing::Job::Text(job)) = self.typist.queue.front() else {
            return None;
        };
        let started = job.started();
        let gate = if self.broken {
            Gate::Unusable
        } else {
            // Afresh, not from the cache: the worker types unattended.
            match self.target_now(now) {
                Target::Allowed => Gate::Hid,
                // Not begun: the whole message by Unicode, which Windows gates on its own.
                Target::Unknown if !started => Gate::Unknown,
                target => {
                    // Blocked (the transition dropped and released already, unless the queue grew
                    // since), or unknown mid-message: nothing more is typed.
                    if self.typist.has_work() {
                        self.drop_and_release(if target == Target::Blocked {
                            "HID target blocked"
                        } else {
                            "HID target unknown while typing"
                        });
                    }
                    return None;
                }
            }
        };
        let yield_modifiers = !self.typist.held_wheels.is_empty();
        let Self {
            state,
            host,
            typist,
            ..
        } = self;
        let Some(typing::Job::Text(job)) = typist.queue.front_mut() else {
            return None;
        };
        let mut cx = typing::Cx {
            state,
            host,
            memory: &mut typist.memory,
            gate,
            yield_modifiers,
        };
        match job.advance(now, &mut cx) {
            typing::Advance::Wait(at) => {
                if self.typist.queue.front().is_some_and(|job| match job {
                    typing::Job::Text(job) => job.clean(),
                    typing::Job::Event { .. } => true,
                }) {
                    self.release_held_wheels(now);
                }
                Some(at)
            }
            typing::Advance::Done => {
                if let Some(typing::Job::Text(job)) = self.typist.pop() {
                    self.typist.finished(&job);
                }
                self.release_held_wheels(now);
                None
            }
            typing::Advance::Stopped(stop) => {
                if stop == typing::Stop::Target {
                    // Say the change (and release, for a blocked desktop) as any look would.
                    self.target_now(now);
                }
                if self.typist.has_work() {
                    self.drop_and_release(stop.reason());
                }
                None
            }
        }
    }

    /// Everything queued, at once and in order: text by Unicode (after restoring what typing holds),
    /// the rest routed as usual, releases not deferred. For when the worker cannot run (its thread
    /// did not start) or the queue is full.
    fn flush_unpaced(&mut self, now: Instant, why: &'static str) {
        tracing::warn!(
            why,
            queued = self.typist.queue.len(),
            "game text: everything queued is sent at once, text by Unicode"
        );
        self.defer_taps = false;
        // Held wheels go right after the head (the text whose modifiers they waited for lets them
        // up first), before whatever was queued after them.
        let mut wheels = Some(std::mem::take(&mut self.typist.held_wheels));
        while let Some(job) = self.typist.pop() {
            match job {
                typing::Job::Text(mut job) => {
                    let gate = if self.broken {
                        Gate::Unusable
                    } else {
                        Gate::Hid
                    };
                    let Self {
                        state,
                        host,
                        typist,
                        ..
                    } = self;
                    job.flush(&mut typing::Cx {
                        state,
                        host,
                        memory: &mut typist.memory,
                        gate,
                        yield_modifiers: false,
                    });
                    self.typist.finished(&job);
                }
                typing::Job::Event { event, .. } => {
                    if let Err(error) = self.execute(&event, now) {
                        note_rejected(&error);
                    }
                }
            }
            self.send_wheels(wheels.take(), now);
        }
        self.send_wheels(wheels.take(), now);
        self.defer_taps = true;
        self.typist.idle();
    }

    fn send_wheels(
        &mut self,
        wheels: Option<std::collections::VecDeque<InputMessage>>,
        now: Instant,
    ) {
        for wheel in wheels.into_iter().flatten() {
            if let Err(error) = self.execute(&wheel, now) {
                note_rejected(&error);
            }
        }
    }

    /// `ra`, `release_all`, the session's end: drop what is queued (counted) and release everything
    /// held on both paths.
    fn release_all(&mut self) {
        self.typist.drop_all("release_all");
        self.pressed_at.clear();
        self.forget_order_wait();
        // Not a release the button watch judges (a neutral report, maybe the session's end): its
        // watches end, and nothing is re-sent after it.
        self.watch.reset("release_all");
        let buttons = self.state.mouse.buttons();
        if !self.broken {
            tracing::trace!("FakerInput release requested");
            // A queued HID read can transiently be unavailable. Bounded retries, no sleeps,
            // and preserve pending state if all fail so a later cleanup call can retry it.
            for attempt in 1..=3 {
                match self.state.release() {
                    Ok(()) => break,
                    Err(error) => {
                        tracing::warn!(%error, attempt, "FakerInput release_all failed; retaining pending releases")
                    }
                }
            }
        }
        self.tell_buttons(buttons);
        self.host.sendinput().release_all();
    }
}

/// The agent's host: this PC's desktop, its SendInput path and its keyboard layouts.
#[cfg(windows)]
struct System {
    sendinput: SendInputInjector,
    keyboard: layouts::WinKeyboard,
}

#[cfg(windows)]
impl Host for System {
    fn evaluate_target(&mut self) -> TargetEval {
        platform::evaluate_target()
    }

    fn screen_size(&mut self) -> (i32, i32) {
        platform::screen_size()
    }

    fn cursor_pos(&mut self) -> Result<(i32, i32), String> {
        platform::cursor_pos()
    }

    fn foreground(&mut self) -> usize {
        // SAFETY: plain call.
        unsafe { windows::Win32::UI::WindowsAndMessaging::GetForegroundWindow() }.0 as usize
    }

    fn sendinput(&self) -> &dyn SendInputPath {
        &self.sendinput
    }

    fn keyboard(&mut self) -> &mut dyn Keyboard {
        &mut self.keyboard
    }

    fn pause(&mut self, duration: Duration) {
        std::thread::sleep(duration);
    }

    fn cursor_look(&mut self) -> Result<CursorLook, String> {
        use super::cursor_sync::CursorWorld;
        super::cursor_sync::system::SystemCursor.look()
    }

    fn button_probe(&mut self, game: usize, detail: bool) -> ButtonProbe {
        platform::button_probe(game, detail)
    }
}

#[cfg(windows)]
type Runtime = HidRuntime<platform::Device, System>;

/// What the injector and its typing worker share.
#[cfg(windows)]
struct Shared {
    rt: Mutex<Runtime>,
    /// Wakes the worker when the queue changes.
    wake: Condvar,
}

/// An open FakerInput device with HID⇄SendInput routing (see the module docs).
///
/// Held as `Some` inside [`SessionInputBackend`] while a session batch keeps the device open, and
/// also used standalone by the manual acceptance test and the click probe. Unrepresentable keys and
/// committed IME text take the shared SendInput fallback, and so does the desktop wheel wherever
/// SendInput reaches (not in game-only mode, nor to an elevated window). Game text is
/// typed by a worker thread that lives only while something is queued; the same worker sends a
/// button that waits for the absolute move before it to show, and in game-only mode looks at the
/// cursor after each button change for the button watch (it lives while that watches anything).
#[cfg(windows)]
pub struct FakerInputInjector {
    shared: Arc<Shared>,
    /// For the cursor, which is read thirty times a second and must not wait behind a report.
    fallback: SendInputInjector,
    /// The last typing worker started, joined when the injector goes so no thread outlives it.
    worker: Mutex<Option<std::thread::JoinHandle<()>>>,
}

#[cfg(windows)]
impl FakerInputInjector {
    /// Open the device with a private SendInput fallback. Used by the manual acceptance test.
    pub fn connect() -> Result<Option<Self>> {
        Self::connect_with(SendInputInjector::new())
    }

    /// Open the device, sharing `fallback` with the selector so the HID path and the SendInput path
    /// keep one held-key ledger between them.
    fn connect_with(fallback: SendInputInjector) -> Result<Option<Self>> {
        Ok(platform::Device::open()?.map(|device| {
            let host = System {
                sendinput: fallback.clone(),
                keyboard: layouts::WinKeyboard,
            };
            Self {
                shared: Arc::new(Shared {
                    rt: Mutex::new(HidRuntime::new(State::new(device), host)),
                    wake: Condvar::new(),
                }),
                fallback,
                worker: Mutex::new(None),
            }
        }))
    }

    /// What the worker follows: the queue's changes and the button watch's.
    fn changes(rt: &Runtime) -> (u64, u64) {
        (rt.typist.changes, rt.watch.changes())
    }

    /// After the runtime took an event: a changed queue or a new button watch wakes the worker, and
    /// work — something queued, or watched — with no worker starts one.
    fn after(&self, rt: &mut Runtime, before: (u64, u64)) {
        if Self::changes(rt) == before {
            return;
        }
        if (rt.typist.has_work() || rt.watch.due().is_some()) && !rt.worker_running {
            self.start_worker(rt);
        }
        self.shared.wake.notify_all();
    }

    fn start_worker(&self, rt: &mut Runtime) {
        let shared = Arc::clone(&self.shared);
        // Spawned under the runtime's lock: the thread's first act is to take it, so it starts only
        // after this event is fully recorded.
        match std::thread::Builder::new()
            .name("afklink-typing".into())
            .spawn(move || type_queued(&shared))
        {
            Ok(handle) => {
                rt.worker_running = true;
                tracing::trace!("typing worker started");
                let previous = lock(&self.worker).replace(handle);
                if let Some(previous) = previous {
                    // It cleared the flag as its last act under the runtime's lock, which it has
                    // let go since (we hold it): it is only finishing, and needs no lock of ours.
                    if previous.join().is_err() {
                        tracing::warn!("the previous typing worker had panicked");
                    }
                }
            }
            Err(error) => {
                tracing::warn!(%error, "game text: the typing thread did not start");
                if rt.typist.has_work() {
                    rt.flush_unpaced(Instant::now(), "the typing thread did not start");
                }
                // Nobody would look for the button watch: it ends.
                rt.watch.reset("the typing thread did not start");
            }
        }
    }
}

/// The typing worker: works the queue and the button watch's looks, sleeping until its next step is
/// due, and exits when the queue is empty and nothing is watched. Its sleep releases the lock, so
/// input keeps flowing between steps — a camera turn is never held up by more than one report.
#[cfg(windows)]
fn type_queued(shared: &Shared) {
    let _exit = WorkerExit(shared);
    let mut rt = lock(&shared.rt);
    loop {
        let Some(due) = rt.step(Instant::now()) else {
            rt.worker_running = false;
            tracing::trace!("typing worker exits: nothing queued");
            return;
        };
        let now = Instant::now();
        if due > now {
            // Woken early by any change (a new event, a release): the next step looks again.
            rt = match shared.wake.wait_timeout(rt, due - now) {
                Ok((guard, _)) => guard,
                Err(poisoned) => poisoned.into_inner().0,
            };
        }
    }
}

/// If the worker panics, nothing typed may stay down and nothing may wait forever behind it.
#[cfg(windows)]
struct WorkerExit<'a>(&'a Shared);

#[cfg(windows)]
impl Drop for WorkerExit<'_> {
    fn drop(&mut self) {
        if std::thread::panicking() {
            let mut rt = lock(&self.0.rt);
            rt.worker_running = false;
            tracing::error!(
                "the typing worker panicked: what it had queued is dropped and held input released"
            );
            rt.release_all();
        }
    }
}

#[cfg(windows)]
impl FakerInputInjector {
    /// One event, with where the typing worker may send what it queues ([`QueueGate`]): in
    /// game-only mode, game text and the input queued behind it go only while the game's window
    /// has the front.
    pub(crate) fn inject_confined(&self, event: &InputMessage, gate: QueueGate) -> Result<()> {
        if matches!(event, InputMessage::ReleaseAll) {
            self.release_all();
            return Ok(());
        }
        let mut rt = lock(&self.shared.rt);
        rt.confine_to(gate);
        let changes = Self::changes(&rt);
        let result = rt.admit(event, Instant::now());
        if let Err(error) = &result {
            note_rejected(error);
        }
        self.after(&mut rt, changes);
        result
    }
}

#[cfg(windows)]
impl InputInjector for FakerInputInjector {
    fn inject(&self, event: &InputMessage) -> Result<()> {
        if matches!(event, InputMessage::ReleaseAll) {
            self.release_all();
            return Ok(());
        }
        let mut rt = lock(&self.shared.rt);
        let changes = Self::changes(&rt);
        let result = rt.admit(event, Instant::now());
        if let Err(error) = &result {
            note_rejected(error);
        }
        self.after(&mut rt, changes);
        result
    }

    fn release_all(&self) {
        let mut rt = lock(&self.shared.rt);
        rt.release_all();
        drop(rt);
        // A worker, if one runs, finds the queue empty and exits.
        self.shared.wake.notify_all();
    }

    fn cursor(&self) -> Option<CursorSample> {
        self.fallback.cursor()
    }

    fn cursor_shape(&self, sample: &CursorSample) -> Option<CursorShape> {
        InputInjector::cursor_shape(&self.fallback, sample)
    }
}

#[cfg(windows)]
impl Drop for FakerInputInjector {
    fn drop(&mut self) {
        self.release_all();
        // The worker exits as soon as it sees the empty queue; wait for it, so no thread — and no
        // reference to the device — outlives the injector.
        let handle = lock(&self.worker).take();
        if let Some(handle) = handle {
            if handle.join().is_err() {
                tracing::warn!("the typing worker had panicked");
            }
        }
        // The device's open period was the session (or the batch of sessions): its button watch's
        // account.
        lock(&self.shared.rt).watch.account("the device closes");
    }
}

/// The process-wide injector: it opens the FakerInput device only while a session is live and
/// chooses the backend per session (see the module docs and `create_input_injector`). It also keeps
/// the reach watch (`crate::reach`): every fresh press either path takes, and whether it got to the
/// window in front — through the driver always; by `SendInput`, unless that window runs elevated and
/// the agent does not.
#[cfg(windows)]
pub struct SessionInputBackend {
    /// Shared with the open device's [`FakerInputInjector`] so both keep one SendInput ledger, and
    /// used directly when no device is open.
    fallback: SendInputInjector,
    hid: Mutex<HidSlot>,
    /// Game-only mode's policy (`crate::game_guard`), asked for every event before either path
    /// sees it. Locked after `hid`, never before.
    guard: Mutex<GameGuard>,
    /// Whether the viewer's presses reach the window in front (`crate::reach`): told of every fresh
    /// press either path takes, read by [`InputInjector::input_reach`]. Locked after `hid` (and
    /// never with `guard`), never before.
    reach: Mutex<ReachWatch>,
    /// The line for a key message whose code neither path maps ([`Self::inject_scoped`]): a flood of
    /// them is not a line each. Locked alone, before any other lock.
    unmapped: Mutex<crate::line_gate::LineGate>,
}

/// The driver can be installed here: the desktop app's embedded installer is the x64 build
/// (`fakerinput_setup` in the app). Elsewhere a missing driver is nothing to ask for, and the
/// heartbeat says nothing about it.
#[cfg(windows)]
const DRIVER_INSTALLABLE: bool = cfg!(target_arch = "x86_64");

/// The open device and how many sessions are keeping it open.
#[cfg(windows)]
#[derive(Default)]
struct HidSlot {
    sessions: usize,
    backend: Option<FakerInputInjector>,
    /// A game-mode wheel was already said to go through SendInput for want of the device; cleared
    /// whenever the device opens or closes, so each stretch without it says so once.
    game_wheel_noted: bool,
    /// The same for game text, which then goes by Unicode.
    game_text_noted: bool,
    /// The same for the absolute position (`m`), which then goes by SendInput.
    position_noted: bool,
    /// Why the last wheel not marked `game` went by SendInput without the device, as said; a new
    /// reason (an elevated window took the front, game-only mode) is said again.
    wheel_noted: Option<&'static str>,
}

#[cfg(windows)]
impl HidSlot {
    /// The device opened or closed: the next game wheel, game text, `m` and wheel without it say so
    /// again.
    fn forget_notes(&mut self) {
        self.game_wheel_noted = false;
        self.game_text_noted = false;
        self.position_noted = false;
        self.wheel_noted = None;
    }
}

/// Whether a window has `WS_EX_NOACTIVATE`: a click on it does not bring it forward, and what it
/// types goes to the window that has the front (the on-screen keyboard). False for a window that
/// cannot be read (gone: `GetWindowLongPtrW` answers 0).
#[cfg(windows)]
fn never_activates(window: usize) -> bool {
    use windows::Win32::UI::WindowsAndMessaging::{
        GetWindowLongPtrW, GWL_EXSTYLE, WS_EX_NOACTIVATE,
    };
    // SAFETY: any window handle may be asked about; a stale one answers 0.
    let style = unsafe {
        GetWindowLongPtrW(
            windows::Win32::Foundation::HWND(window as *mut std::ffi::c_void),
            GWL_EXSTYLE,
        )
    };
    (style as u32) & WS_EX_NOACTIVATE.0 != 0
}

/// Windows' Mouse Keys is on (`SPI_GETMOUSEKEYS`): the numeric keypad moves and clicks the pointer.
/// `None` when it cannot be read, said at `debug`.
#[cfg(windows)]
fn mouse_keys_on() -> Option<bool> {
    use windows::Win32::UI::WindowsAndMessaging::{
        SystemParametersInfoW, SPI_GETMOUSEKEYS, SYSTEM_PARAMETERS_INFO_UPDATE_FLAGS,
    };
    /// `MOUSEKEYS` (winuser.h), laid out here: the `windows` crate keeps it behind its whole
    /// accessibility feature.
    #[repr(C)]
    #[derive(Default)]
    struct MouseKeys {
        cb_size: u32,
        dw_flags: u32,
        i_max_speed: u32,
        i_time_to_max_speed: u32,
        i_ctrl_speed: u32,
        dw_reserved1: u32,
        dw_reserved2: u32,
    }
    /// `MKF_MOUSEKEYSON`.
    const ON: u32 = 0x1;
    let mut keys = MouseKeys {
        cb_size: std::mem::size_of::<MouseKeys>() as u32,
        ..MouseKeys::default()
    };
    // SAFETY: a MOUSEKEYS-sized, -laid-out buffer with its size set, as SPI_GETMOUSEKEYS asks.
    let read = unsafe {
        SystemParametersInfoW(
            SPI_GETMOUSEKEYS,
            keys.cb_size,
            Some(std::ptr::addr_of_mut!(keys).cast()),
            SYSTEM_PARAMETERS_INFO_UPDATE_FLAGS(0),
        )
    };
    match read {
        Ok(()) => Some(keys.dw_flags & ON != 0),
        Err(e) => {
            tracing::debug!("Mouse Keys not read: {e}");
            None
        }
    }
}

/// Why a wheel not marked `game` goes by SendInput without the device.
#[cfg(windows)]
const WHEEL_NO_DRIVER: &str = "wheel not marked game, the driver is not open: smooth SendInput";
#[cfg(windows)]
const WHEEL_GAME_ONLY_NO_DRIVER: &str = "wheel not marked game, game-only mode, but the driver is \
                                         not open: smooth SendInput (a game reading the mouse \
                                         directly may not see it)";

#[cfg(windows)]
impl SessionInputBackend {
    pub fn new() -> Self {
        Self {
            fallback: SendInputInjector::new(),
            hid: Mutex::new(HidSlot::default()),
            guard: Mutex::new(GameGuard::default()),
            reach: Mutex::new(ReachWatch::default()),
            unmapped: Mutex::new(crate::line_gate::LineGate::new()),
        }
    }

    /// Release everything held on both paths (the slot's lock held by the caller).
    fn release_both(&self, slot: &HidSlot) {
        if let Some(backend) = slot.backend.as_ref() {
            backend.release_all();
        }
        InputInjector::release_all(&self.fallback);
    }

    /// Re-probe the driver and, if it is now present and sessions are live, open it and switch those
    /// sessions to HID at once — no restart. `patient` retries briefly (~3 s), for a caller that has
    /// not waited for PnP itself; the desktop app waits for the device after an install on its own
    /// (up to 10 s, `fakerinput_setup`) and then asks for a single look, as it does for «Проверить».
    /// A no-op when there is no live session (the next session's `begin_session` probes anyway) or
    /// the device is already open.
    pub fn refresh_driver(&self, patient: bool) {
        {
            let slot = lock(&self.hid);
            if slot.sessions == 0 {
                tracing::debug!(
                    "driver refresh: no live session; the driver opens on the next session"
                );
                return;
            }
            if slot.backend.is_some() {
                tracing::debug!("driver refresh: device already open");
                return;
            }
        }
        let attempts = if patient { 10 } else { 1 };
        for attempt in 1..=attempts {
            match FakerInputInjector::connect_with(self.fallback.clone()) {
                Ok(Some(backend)) => {
                    let mut slot = lock(&self.hid);
                    if slot.sessions == 0 {
                        tracing::info!(
                            "driver refresh: the last session ended during the probe; not opening"
                        );
                        return;
                    }
                    if slot.backend.is_some() {
                        tracing::debug!("driver refresh: another path already opened the device");
                        return;
                    }
                    // Release everything held on SendInput before the switch, so a key pressed via
                    // SendInput is not later released through HID (see the module invariant).
                    InputInjector::release_all(&self.fallback);
                    slot.backend = Some(backend);
                    slot.forget_notes();
                    tracing::info!(
                        attempt,
                        sessions = slot.sessions,
                        "driver refresh: device opened; live sessions switched to HID"
                    );
                    return;
                }
                Ok(None) => tracing::debug!(attempt, "driver refresh: driver not present yet"),
                Err(error) => tracing::debug!(attempt, %error, "driver refresh: probe failed"),
            }
            if attempt < attempts {
                std::thread::sleep(Duration::from_millis(300));
            }
        }
        if patient {
            tracing::warn!(
                attempts,
                "driver refresh: the driver did not appear in time; staying on SendInput"
            );
        } else {
            tracing::debug!("driver refresh: driver not present; staying on SendInput");
        }
    }

    /// A wheel not marked `game` with no device open goes by SendInput whatever happens; say why when
    /// that changes — above all when the foreground window runs elevated and the agent does not, the
    /// text's decision ([`Reach`]) without the driver: Windows drops the wheel there (UIPI).
    fn note_wheel_without_driver(&self, slot: &mut HidSlot, scope: &InputScope, now: Instant) {
        let (reason, foreground) = match scope {
            InputScope::Game(_) => (WHEEL_GAME_ONLY_NO_DRIVER, None),
            InputScope::Desktop => {
                let elevation = self.fallback.foreground_elevation(now);
                match Reach::of(elevation.as_ref(), false) {
                    Reach::ElevatedNoDriver => (WHEEL_ELEVATED_NO_DRIVER, elevation.map(|e| e.exe)),
                    _ => (WHEEL_NO_DRIVER, None),
                }
            }
        };
        if slot.wheel_noted == Some(reason) {
            tracing::trace!(reason, "wheel not marked game, without the driver");
            return;
        }
        slot.wheel_noted = Some(reason);
        tracing::debug!(
            path = "sendinput",
            reason,
            foreground = foreground.as_deref().unwrap_or("-"),
            "wheel path"
        );
    }

    /// Close the device for any live session (before the owner removes the driver, or on demand),
    /// after releasing everything held on both paths. Those sessions continue on SendInput; the
    /// session count is untouched, so the next `end_session` still balances. Our open handle would
    /// otherwise make Windows ask for a reboot to remove the driver.
    pub fn release_device_for_maintenance(&self) {
        let mut slot = lock(&self.hid);
        slot.forget_notes();
        match slot.backend.take() {
            Some(backend) => {
                // Release held on both paths before the handle closes (dropping `backend` closes it).
                backend.release_all();
                drop(backend);
                tracing::info!(
                    sessions = slot.sessions,
                    "driver maintenance: device closed; live sessions continue on SendInput"
                );
            }
            None => tracing::debug!("driver maintenance: the device was not open"),
        }
    }
}

#[cfg(windows)]
impl InputInjector for SessionInputBackend {
    fn inject(&self, event: &InputMessage) -> Result<()> {
        self.inject_scoped(event, &InputScope::Desktop)
    }

    /// The game guard first (`crate::game_guard`): it may release everything held (the game lost
    /// the front), drop the event, or rewrite text to the driver's typing. Then the planner is told
    /// where the viewer's picture is — the game's client area in game-only mode — and the event
    /// takes the path it always took.
    fn inject_scoped(&self, event: &InputMessage, scope: &InputScope) -> Result<()> {
        if matches!(event, InputMessage::ReleaseAll) {
            self.release_all();
            return Ok(());
        }
        let now = Instant::now();
        // A key no path has (KB-6): nothing to press or release on the PC, so it goes no further —
        // not to the guard and its key log, whose books would otherwise take every distinct code a
        // viewer sends. Before any lock but the line's own.
        if let InputMessage::Key { d, code, src, .. } = event {
            if !maps_key(code) {
                if lock(&self.unmapped).admit(now, "unmapped key") {
                    tracing::debug!(
                        target: crate::KEY_NAMES_TARGET,
                        code = crate::key_log::loggable(code, *src),
                        src = crate::key_log::source_name(*src),
                        down = *d == 1,
                        "unmapped key code: neither the driver nor SendInput has it; not injected"
                    );
                } else {
                    tracing::trace!("unmapped key code: not injected");
                }
                return Ok(());
            }
        }
        let mut slot = lock(&self.hid);
        let admission = {
            let mut host = SystemGuard {
                fallback: &self.fallback,
                driver_open: slot.backend.is_some(),
                now,
            };
            lock(&self.guard).admit(event, scope, &mut host, now)
        };
        if admission.release {
            self.release_both(&slot);
        }
        let Some(event) = admission.event else {
            return Ok(());
        };
        let event = &event;
        // A fresh press, for the reach watch: judged before this event changes the `SendInput`
        // path's ledger, so a repeat of a key it holds is not a new press.
        let press = FreshPress::of(
            event,
            |b| self.fallback.holds_button(b),
            |code| self.fallback.holds_key(code),
        );
        // Where `m` and `r.x/y` point, and where the cursor is kept: the game's client area, or the
        // primary monitor. A window not shown takes only releases, which need no space.
        match scope {
            InputScope::Desktop => self.fallback.set_space(None, now),
            InputScope::Game(game) => {
                if let Some(window) = game.window {
                    let c = window.client;
                    self.fallback
                        .set_space(Space::from_edges(c.left, c.top, c.right, c.bottom), now);
                }
            }
        }
        let gate = match scope {
            InputScope::Desktop => QueueGate::Desktop,
            InputScope::Game(game) => game
                .window
                .map_or(QueueGate::Closed, |window| QueueGate::Game(window.hwnd)),
        };
        match slot.backend.as_ref() {
            Some(backend) => {
                let result = backend.inject_confined(event, gate);
                // Through the driver, a press reaches an administrator's window as a physical one
                // would (where the router sends it by `SendInput` instead — the secure desktop, IME
                // text — the window in front is not what blocks it).
                if let (Some(press), Ok(())) = (press, &result) {
                    lock(&self.reach).note(press, Landing::Reached, None, now);
                }
                result
            }
            None => {
                if matches!(
                    event,
                    InputMessage::Wheel {
                        game: Some(true),
                        ..
                    }
                ) && !slot.game_wheel_noted
                {
                    slot.game_wheel_noted = true;
                    tracing::debug!(
                        "game-mode wheel via SendInput: the HID driver is not open (games reading \
                         the mouse directly may not see it)"
                    );
                }
                if matches!(
                    event,
                    InputMessage::Text {
                        game: Some(true),
                        ..
                    }
                ) && !slot.game_text_noted
                {
                    slot.game_text_noted = true;
                    tracing::debug!(
                        "game text by Unicode: the HID driver is not open (games reading the \
                         keyboard directly may not see it)"
                    );
                }
                if matches!(event, InputMessage::Move { .. }) && !slot.position_noted {
                    slot.position_noted = true;
                    tracing::debug!(
                        "position (m) path: sendinput, the HID driver is not open (an \
                         administrator window does not see it)"
                    );
                }
                if let InputMessage::Wheel { game, .. } = event {
                    if *game != Some(true) {
                        self.note_wheel_without_driver(&mut slot, scope, now);
                    }
                }
                drop(slot);
                if let Some(press) = press {
                    // The text's and the wheel's decision ([`Reach`]), for a click and a key as well:
                    // into a window that runs elevated while the agent does not, `SendInput` is
                    // dropped. Looked at before the press goes, like the text's route.
                    let elevation = self.fallback.foreground_elevation(now);
                    let landing = Landing::of(Reach::of(elevation.as_ref(), false));
                    lock(&self.reach).note(
                        press,
                        landing,
                        elevation.as_ref().map(|e| e.exe.as_str()),
                        now,
                    );
                }
                InputInjector::inject(&self.fallback, event)
            }
        }
    }

    fn release_all(&self) {
        let slot = lock(&self.hid);
        if let Some(backend) = slot.backend.as_ref() {
            backend.release_all();
        }
        // Nothing is down through us any more: a combination is judged afresh.
        lock(&self.guard).released();
        drop(slot);
        InputInjector::release_all(&self.fallback);
    }

    /// This injector confines input to the game's window rather than dropping it, so the scope does
    /// not decide: a press can hold something whenever either path has a key for its code — the
    /// driver's ([`key`]) or `SendInput`'s ([`super::code_to_vk`]). A code neither maps goes
    /// nowhere (the driver path refuses its key-up, `SendInput` notes it unmapped). Buttons: always.
    fn press_may_hold(&self, event: &InputMessage, _scope: &InputScope) -> bool {
        match event {
            InputMessage::Key { d: 1, code, .. } => maps_key(code),
            _ => true,
        }
    }

    fn cursor(&self) -> Option<CursorSample> {
        // Polled ~30 times a second while a session runs: the key log's line for a second goes out
        // on time even after the last key of a burst. The guard's lock alone, taken and let go
        // before the planner's.
        lock(&self.guard).flush_keys_if_due(Instant::now());
        self.fallback.cursor()
    }

    fn cursor_shape(&self, sample: &CursorSample) -> Option<CursorShape> {
        InputInjector::cursor_shape(&self.fallback, sample)
    }

    /// The session's focus watch: the guard looks at the foreground window (never asking the game
    /// back to the front from here), and everything held is released the moment the game lost it.
    fn game_focus(&self, game: &GameScope) -> GameFocus {
        let now = Instant::now();
        let slot = lock(&self.hid);
        let (focus, release) = {
            let mut host = SystemGuard {
                fallback: &self.fallback,
                driver_open: slot.backend.is_some(),
                now,
            };
            lock(&self.guard).watch(game, &mut host, now)
        };
        if release {
            self.release_both(&slot);
        }
        focus
    }

    /// The process owning the foreground window, or the top-level window under the pixel a press
    /// sent now would land on (the planner's target, as game-only mode's press check reads it) and
    /// whether that top-level window never takes the front (`WS_EX_NOACTIVATE`): for the guard on
    /// AFKLink's own windows (`afklink_core`'s `own_windows`). Window-manager reads only — no
    /// lock but the planner's for the press target, nothing opened.
    fn window_owner(&self, target: WindowTarget) -> Option<WindowOwner> {
        let mut host = SystemGuard {
            fallback: &self.fallback,
            // Not read for this.
            driver_open: false,
            now: Instant::now(),
        };
        let (pid, no_activate) = match target {
            WindowTarget::Foreground => match host.foreground() {
                0 => (0, false),
                window => (host.window_pid(window), false),
            },
            WindowTarget::UnderPress => {
                let (x, y) = host.press_target()?;
                match host.window_at(x, y) {
                    // The top-level window's process: WebView2 draws our windows' content in a
                    // child window of its own process, and that child is ours.
                    Ok(at) if at.root_pid != 0 => (at.root_pid, never_activates(at.root)),
                    Ok(at) => (at.pid, never_activates(at.hwnd)),
                    Err(why) => {
                        tracing::trace!(x, y, "window owner: nothing read under the press: {why}");
                        (0, false)
                    }
                }
            }
        };
        (pid != 0).then_some(WindowOwner { pid, no_activate })
    }

    /// Mouse Keys (`SPI_GETMOUSEKEYS`, `MKF_MOUSEKEYSON`): one `SystemParametersInfoW`.
    fn mouse_keys_on(&self) -> Option<bool> {
        mouse_keys_on()
    }

    /// The driver as the live sessions have it — open, or missing where it could be installed —
    /// and the reach watch's word (`crate::reach`).
    fn input_reach(&self) -> InputReach {
        let now = Instant::now();
        // The slot's lock is let go before the watch's is taken.
        let open = lock(&self.hid).backend.is_some();
        let driver = if open {
            DriverPresence::Open
        } else if DRIVER_INSTALLABLE {
            DriverPresence::Missing
        } else {
            DriverPresence::Unknown
        };
        lock(&self.reach).snapshot(driver, now)
    }

    fn begin_session(&self) {
        let mut slot = lock(&self.hid);
        slot.sessions += 1;
        if slot.sessions > 1 {
            let backend = if slot.backend.is_some() {
                "fakerinput"
            } else {
                "sendinput"
            };
            tracing::info!(
                backend,
                sessions = slot.sessions,
                "input backend for new session: joining the active backend"
            );
            return;
        }
        // First concurrent session: the cursor-sync planner starts afresh and says the pointer
        // settings it works with; then probe (read-only, sends no report) and open the device.
        self.fallback.cursor_sync_begin();
        lock(&self.guard).reset("first session", Instant::now());
        lock(&self.reach).reset("first session", Instant::now());
        slot.forget_notes();
        match FakerInputInjector::connect_with(self.fallback.clone()) {
            Ok(Some(backend)) => {
                slot.backend = Some(backend);
                tracing::info!(
                    backend = "fakerinput",
                    "input backend for session: compatible HID driver found and opened"
                );
            }
            Ok(None) => tracing::info!(
                backend = "sendinput",
                reason = "driver_not_installed",
                "input backend for session: FakerInput is not installed"
            ),
            Err(error) => {
                tracing::warn!(%error, "FakerInput probe failed");
                tracing::info!(
                    backend = "sendinput",
                    reason = "probe_error",
                    "input backend for session: FakerInput probe failed, using SendInput"
                );
            }
        }
    }

    fn end_session(&self) {
        let mut slot = lock(&self.hid);
        if slot.sessions == 0 {
            // The count is driven by `InputSession`, which brackets begin/end one-to-one; a zero
            // here would be a bug in that bracketing, not a normal path.
            tracing::warn!("end_session with no active input session; ignoring");
            return;
        }
        slot.sessions -= 1;
        if slot.sessions > 0 {
            tracing::debug!(
                sessions = slot.sessions,
                "input session ended; device stays open for the remaining sessions"
            );
            return;
        }
        // The session's final release already stopped it; this is the guarantee that no repeat
        // (and no repeat thread) outlives the last session, whatever that release did.
        self.fallback.stop_key_repeat("last session ended");
        self.fallback.cursor_sync_end();
        lock(&self.guard).reset("last session ended", Instant::now());
        lock(&self.reach).reset("last session ended", Instant::now());
        slot.forget_notes();
        match slot.backend.take() {
            Some(backend) => {
                // Final neutral release before the handle closes; dropping the backend closes it.
                backend.release_all();
                drop(backend);
                tracing::info!(
                    backend = "fakerinput",
                    "input device closed: the last session ended"
                );
            }
            None => tracing::debug!(backend = "sendinput", "last input session ended"),
        }
    }
}

#[cfg(test)]
mod tests;
