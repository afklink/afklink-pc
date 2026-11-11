//! Remote input injection via WinAPI `SendInput`.
//!
//! Mouse coordinates arrive normalized `[0..1]`; we map them to absolute
//! virtual coordinates `0..=65535` on the primary monitor
//! (`MOUSEEVENTF_ABSOLUTE`). Keyboard `KeyboardEvent.code` strings are mapped
//! to Windows Virtual-Key codes via [`code_to_vk`], and pressed by their hardware scan code
//! ([`key_stroke`]) so games reading DirectInput / raw input see them.
//!
//! ## Held state
//!
//! Every press this injector performs is recorded and not forgotten until the matching
//! release is performed. That ledger is the whole reason this type has state: a button
//! down is not an event, it is a *change of state on someone's desktop*, and if the
//! viewer disappears between the down and the up, nothing else in the system knows the
//! left button is still held. [`SendInputInjector::release_all`] unwinds it.
//!
//! ## Held keys repeat
//!
//! Windows does not auto-repeat a key injected through `SendInput` (a physical or HID keyboard's
//! repeat comes from its driver, which injected keys never pass through), so this injector repeats
//! the last key it holds down itself, at Windows' keyboard delay and rate — see `src/repeat.rs`.
//!
//! ## Relative moves
//!
//! What an `r` does to the cursor — the camera's counts as before, an absolute move onto the viewer's
//! pointer, or a move by exactly the intended distance — is decided per event by the cursor-sync
//! planner (`src/cursor_sync.rs`), one per injector family, which the FakerInput path asks too. An
//! `m` is not the planner's to decide (it is always one absolute move), but it is told of every one,
//! on either path, so an `r` after it does not take it for someone else's motion.

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use afklink_core::sync::lock;
use afklink_core::traits::{CursorSample, CursorShape, InputInjector};
use afklink_protocol::InputMessage;
use anyhow::Result;

mod keymap;
pub use keymap::{code_to_vk, key_stroke, vk_to_scan, KeyStroke};

// Pure (its Win32 reads sit behind a trait); off Windows only the tests use it.
#[cfg_attr(not(any(windows, test)), allow(dead_code))]
mod cursor_sync;
use cursor_sync::{CursorSync, Elevation, Plan, RelEvent, RelPath, Space, WheelTally};

// The cursor's picture and the window under it, for the cursor report's line per new shape; its
// pixel arithmetic is pure and tested everywhere, its reads are Windows'.
#[cfg(any(windows, test))]
mod cursor_shape;

// Game-only mode's input policy: pure (its Win32 reads sit behind a trait); off Windows only the
// tests use it.
#[cfg_attr(not(any(windows, test)), allow(dead_code))]
mod game_guard;

// Which keys reached the PC, for the log — ours by name, every other key counted (`k.src`): pure;
// the game guard keeps it. Off Windows only the tests use it.
#[cfg_attr(not(any(windows, test)), allow(dead_code))]
mod key_log;

// A per-event debug line a viewer's flood must not repeat per message (KB-6): pure; off Windows
// only the tests use it.
#[cfg_attr(not(any(windows, test)), allow(dead_code))]
mod line_gate;

/// The target of every log line that names a key — a key code, a combination, the language
/// hotkey, the lists of the viewer's keys (`key_log`). Whatever the module that writes it: a reader
/// of the log can tell these lines apart by it, and the desktop app's automatic report leaves them
/// out (the privacy policy: «нажатых клавиш там нет»). Under `afklink`, so the log level's filter
/// treats it like the rest of the crate. `key_log`'s tests hold every such line in the workspace to
/// it.
pub const KEY_NAMES_TARGET: &str = "afklink_input::key_names";

// Whether the viewer's presses reach the window in front («Управление не доходит»): pure; off Windows
// only the tests use it.
#[cfg_attr(not(any(windows, test)), allow(dead_code))]
mod reach;

mod repeat;
// Units shared by both wheel paths; off Windows only the tests use them.
#[cfg_attr(not(any(windows, test)), allow(dead_code))]
mod wheel;

#[cfg(any(windows, test))]
mod fakerinput;
#[cfg(windows)]
pub use fakerinput::FakerInputInjector;
#[cfg(windows)]
pub use fakerinput::{
    DirectHid, HidCursor, HidCursorLook, HidCursorPlan, HidInputPaused, HidKey, HidLanguageSwitch,
    HidLayoutProgress, HidMouse, HidPressHold, HidTextStroke,
};

/// A handle to the process-wide input backend that the desktop app keeps in Tauri managed state so
/// it can react to the owner installing or removing the driver *without a restart* (the CLI does not
/// need this and uses [`create_input_injector`]).
///
/// [`Self::injector`] is what goes into `Backends`; the other two switch a live session's backend:
/// after an install the app re-probes and opens the device ([`Self::refresh_driver`]), and before a
/// removal it closes it ([`Self::release_device_for_maintenance`]) so the open handle does not block
/// the driver's removal. Cloning is cheap (it shares the one backend).
#[derive(Clone)]
pub struct InputBackendHandle {
    injector: Arc<dyn InputInjector>,
    #[cfg(windows)]
    backend: Arc<fakerinput::SessionInputBackend>,
}

impl InputBackendHandle {
    /// The injector to hand to `Backends`.
    pub fn injector(&self) -> Arc<dyn InputInjector> {
        self.injector.clone()
    }

    /// Re-probe the driver and, if it is now present and sessions are live, open it and switch those
    /// sessions to HID at once. `patient` waits briefly for PnP to enumerate a just-installed device.
    /// A no-op off Windows.
    pub fn refresh_driver(&self, patient: bool) {
        #[cfg(windows)]
        self.backend.refresh_driver(patient);
        #[cfg(not(windows))]
        {
            let _ = patient;
            tracing::debug!("refresh_driver: no HID driver backend on this platform");
        }
    }

    /// Close the device for any live session (before the owner removes the driver); those sessions
    /// continue on SendInput. A no-op off Windows.
    pub fn release_device_for_maintenance(&self) {
        #[cfg(windows)]
        self.backend.release_device_for_maintenance();
        #[cfg(not(windows))]
        tracing::debug!("release_device_for_maintenance: no HID driver backend on this platform");
    }
}

/// Build the process-wide input backend and a handle to it. It selects a backend *per session*, not
/// once for the process: the returned value opens no device and sends nothing until a session begins.
///
/// On Windows it is a session-aware selector (see [`fakerinput::SessionInputBackend`]): on the first
/// session's `begin_session` it probes for the FakerInput driver (a read-only probe that sends no
/// report) and, if present, opens it; on the last session's `end_session` it closes it. So installing
/// or removing the driver takes effect without a restart — immediately for a live session through the
/// handle, otherwise on the next session — and between sessions no device handle is held open. Off
/// Windows there is only `SendInput`.
pub fn create_input_backend() -> InputBackendHandle {
    #[cfg(windows)]
    {
        tracing::debug!(
            "input backend selector created; the driver is probed and chosen per session"
        );
        let backend = Arc::new(fakerinput::SessionInputBackend::new());
        InputBackendHandle {
            injector: backend.clone(),
            backend,
        }
    }
    #[cfg(not(windows))]
    {
        tracing::debug!("SendInput selected: FakerInput requires Windows");
        InputBackendHandle {
            injector: Arc::new(SendInputInjector::new()),
        }
    }
}

/// The injector alone, for callers that do not manage the driver at runtime (the CLI).
pub fn create_input_injector() -> Arc<dyn InputInjector> {
    create_input_backend().injector()
}

/// Whether `SendInput` cannot reach this window: its process runs elevated and this agent does not,
/// so Windows' UIPI drops the input and says it went — what only the driver gets through. Read the
/// way the foreground window's elevation is for every text, wheel and press (`cursor_sync`): the
/// window's process opened for `PROCESS_QUERY_LIMITED_INFORMATION` and its token for `TOKEN_QUERY`,
/// nothing more — no input, no message, no memory read (the owner's game runs a kernel anti-cheat).
/// The desktop app's «Окно игры» asks it for each window it lists while the driver is missing.
/// `Err` says what could not be read; off Windows, `Ok(false)`.
pub fn window_blocks_sendinput(hwnd: usize) -> Result<bool, String> {
    #[cfg(windows)]
    {
        use cursor_sync::CursorWorld;
        let info = cursor_sync::system::SystemCursor.describe_foreground(hwnd);
        let elevated = info.elevated?;
        let agent = info.agent_elevated?;
        Ok(elevated && !agent)
    }
    #[cfg(not(windows))]
    {
        let _ = hwnd;
        Ok(false)
    }
}

/// Read-only discovery for the installation UI; no virtual key/button/motion is sent.
pub fn fakerinput_available() -> Result<bool> {
    #[cfg(windows)]
    {
        fakerinput::platform::Device::open().map(|device| device.is_some())
    }
    #[cfg(not(windows))]
    {
        Ok(false)
    }
}

/// What the injector has pressed and not yet released.
#[derive(Debug, Default)]
struct Held {
    /// Mouse buttons, by protocol id (0 = left, 1 = middle, 2 = right).
    buttons: BTreeSet<u8>,
    /// Keys, as the `(vk, extended)` pair actually sent to `SendInput` — the same shape
    /// the release has to use, so a remapped keyboard cannot strand a key.
    keys: BTreeSet<(u16, bool)>,
}

impl Held {
    fn is_empty(&self) -> bool {
        self.buttons.is_empty() && self.keys.is_empty()
    }
}

/// The part of relative moves (`r`) that did not make a whole pixel yet.
///
/// The viewer sends fractions of the screen; `SendInput` moves whole pixels. Rounding every
/// message on its own threw away up to half a pixel each time — and a slow, careful finger stroke
/// is sixty tiny messages a second, most of which rounded to nothing, so the cursor lagged the
/// finger or did not move at all. Carrying the remainder makes the pixels injected over a stroke
/// add up to the fractions sent.
#[derive(Debug, Default, Clone, Copy, PartialEq)]
struct RelCarry {
    x: f64,
    y: f64,
}

impl RelCarry {
    /// Whole pixels to move for one `r` message on a `w`×`h` screen, keeping what rounding left
    /// over for the next one.
    ///
    /// Each fraction is clamped to one screen, as the wire promises. A fraction that is not a
    /// number moves nothing and leaves the carry untouched — it must not poison every move after
    /// it.
    fn step(&mut self, dx_frac: f64, dy_frac: f64, w: i32, h: i32) -> (i32, i32) {
        if !dx_frac.is_finite() || !dy_frac.is_finite() {
            return (0, 0);
        }
        let fx = dx_frac.clamp(-1.0, 1.0) * f64::from(w) + self.x;
        let fy = dy_frac.clamp(-1.0, 1.0) * f64::from(h) + self.y;
        let (px, py) = (fx.round(), fy.round());
        self.x = fx - px;
        self.y = fy - py;
        (px as i32, py as i32)
    }
}

/// `SendInput`-backed injector (path B: user session, no elevation).
///
/// Cheap to clone: clones share one ledger, which is what makes a release from the
/// session task undo presses performed on any other.
#[derive(Clone)]
pub struct SendInputInjector {
    held: Arc<Mutex<Held>>,
    /// Sub-pixel remainder of relative moves; shared like the ledger.
    rel: Arc<Mutex<RelCarry>>,
    /// Emulated auto-repeat of the last key held down through `SendInput`; shared like the ledger,
    /// so a release through any clone stops it.
    repeat: Arc<repeat::Engine>,
    /// The cursor-sync planner (`cursor_sync`): what each `r` does to the cursor. Shared like the
    /// ledger — and with the FakerInput path, which plans its moves through this same one, so the
    /// aim, the moves in flight and the learned gain survive a switch between the paths.
    sync: Arc<Mutex<CursorSync>>,
}

impl Default for SendInputInjector {
    fn default() -> Self {
        let held = Arc::new(Mutex::new(Held::default()));
        #[cfg(windows)]
        let timing: fn() -> repeat::RepeatTiming = repeat::system_timing;
        #[cfg(not(windows))]
        let timing: fn() -> repeat::RepeatTiming = repeat::RepeatTiming::windows_default;
        let sink = Arc::new(LedgerSink { held: held.clone() });
        Self {
            held,
            rel: Arc::default(),
            repeat: Arc::new(repeat::Engine::new(sink, timing)),
            sync: Arc::default(),
        }
    }
}

/// Where the repeat worker presses a key again: through this injector's ledger, so a repeat goes out
/// only for a key still held, and under the ledger lock that every release takes before sending its
/// key-up — a repeat can precede the release, never follow it (see `repeat`).
struct LedgerSink {
    held: Arc<Mutex<Held>>,
}

impl repeat::Sink for LedgerSink {
    fn repeat(&self, key: repeat::Vk) -> bool {
        let held = lock(&self.held);
        if !held.keys.contains(&key) {
            return false;
        }
        // Pressed with the ledger still locked: that is the ordering guarantee.
        #[cfg(windows)]
        imp::key(key.0, key.1, true);
        drop(held);
        true
    }
}

impl SendInputInjector {
    pub fn new() -> Self {
        Self::default()
    }

    /// A key went down through the HID driver. Like a physical keyboard's new key, it ends this
    /// injector's emulated repeat (Windows repeats the HID key itself) — unless it is a modifier that
    /// was already down.
    #[cfg_attr(not(windows), allow(dead_code))]
    pub(crate) fn other_key_pressed(&self, modifier: bool, was_held: bool) {
        self.repeat.other_path_press(modifier, was_held);
    }

    /// Stop the emulated key repeat, if one runs (its worker thread exits).
    #[cfg_attr(not(windows), allow(dead_code))]
    pub(crate) fn stop_key_repeat(&self, reason: &'static str) {
        self.repeat.stop(reason);
    }

    /// True while anything is pressed — lets callers skip a pointless release.
    pub fn has_held(&self) -> bool {
        !lock(&self.held).is_empty()
    }

    /// Whether this injector currently holds the given protocol button down. The FakerInput backend
    /// asks so a repeat press routes to the path that pressed, and a release follows the holder.
    pub fn holds_button(&self, b: u8) -> bool {
        lock(&self.held).buttons.contains(&b)
    }

    /// Whether this injector currently holds the key for `code` down — matched on the same
    /// `(vk, extended)` the press recorded, so a remapped keyboard cannot fool it.
    pub fn holds_key(&self, code: &str) -> bool {
        code_to_vk(code).is_some_and(|vk| lock(&self.held).keys.contains(&vk))
    }

    /// One `r`: what the cursor-sync planner says to send. A button counts as held when `hid_held`
    /// (the FakerInput path holds one) or this injector's own ledger holds one.
    #[cfg_attr(not(any(windows, test)), allow(dead_code))]
    pub(crate) fn plan_rel(
        &self,
        event: RelEvent,
        hid_held: bool,
        path: RelPath,
        now: Instant,
    ) -> Plan {
        #[cfg(windows)]
        {
            let held = hid_held || !lock(&self.held).buttons.is_empty();
            lock(&self.sync).plan(
                event,
                held,
                path,
                &mut cursor_sync::system::SystemCursor,
                now,
            )
        }
        #[cfg(not(windows))]
        {
            // No cursor to look at: the camera's counts, as before.
            let _ = (event, hid_held, path, now);
            Plan::Camera
        }
    }

    /// One `m` at `(x, y)` (fractions of the primary screen): the pixel it falls in and the screen it
    /// is on, with the planner's books kept for it (`CursorSync::absolute`). `path` says which path
    /// carries the move. `None` when the screen size is unknown, and off Windows (no cursor there).
    #[cfg_attr(not(any(windows, test)), allow(dead_code))]
    pub(crate) fn plan_abs(
        &self,
        x: f64,
        y: f64,
        path: RelPath,
        now: Instant,
    ) -> Option<(i32, i32, i32, i32)> {
        #[cfg(windows)]
        {
            lock(&self.sync).absolute((x, y), path, &mut cursor_sync::system::SystemCursor, now)
        }
        #[cfg(not(windows))]
        {
            let _ = (x, y, path, now);
            None
        }
    }

    /// A button transition waited for an absolute report (an `m`, a point move) to show (the FakerInput router's
    /// ordering wait): into the planner's aggregate line.
    #[cfg_attr(not(any(windows, test)), allow(dead_code))]
    pub(crate) fn order_waited(&self, waited: std::time::Duration, timed_out: bool, now: Instant) {
        lock(&self.sync).order_waited(waited, timed_out, now);
    }

    /// Wheel messages and the HID wheel's dropped remainders, into the planner's aggregate line (the
    /// FakerInput router tells its own; this path's are counted in `inject`).
    #[cfg_attr(not(any(windows, test)), allow(dead_code))]
    pub(crate) fn count_wheel(&self, tally: WheelTally, now: Instant) {
        lock(&self.sync).count_wheel(tally, now);
    }

    /// The send a plan asked for failed.
    #[cfg_attr(not(any(windows, test)), allow(dead_code))]
    pub(crate) fn rel_failed(&self, why: &'static str) {
        lock(&self.sync).failed(why);
    }

    /// The HID router queued numbered move `s` behind other input: the planner holds the cursor
    /// report's `ack` below it until it is sent (`CursorSync::queued`).
    #[cfg_attr(not(any(windows, test)), allow(dead_code))]
    pub(crate) fn rel_queued(&self, s: u32, now: Instant) {
        lock(&self.sync).queued(s, now);
    }

    /// The HID router's mouse buttons changed (`CursorSync::hid_buttons`): for the cursor's
    /// visibility line, which says what was held when a game hid or showed the cursor.
    #[cfg_attr(not(any(windows, test)), allow(dead_code))]
    pub(crate) fn hid_buttons(&self, held: u8, change: Option<(u8, bool, Instant)>) {
        lock(&self.sync).hid_buttons(held, change);
    }

    /// Any input event: the planner says when the foreground window changed.
    #[cfg_attr(not(any(windows, test)), allow(dead_code))]
    pub(crate) fn note_input(&self, now: Instant) {
        #[cfg(windows)]
        lock(&self.sync).note_input(&mut cursor_sync::system::SystemCursor, now);
        #[cfg(not(windows))]
        let _ = now;
    }

    /// Where the viewer's picture is: the primary monitor (`None`), or in game-only mode the game's
    /// client area — the planner maps targets into it and keeps the cursor in it.
    #[cfg_attr(not(windows), allow(dead_code))]
    pub(crate) fn set_space(&self, space: Option<Space>, now: Instant) {
        lock(&self.sync).set_space(space, now);
    }

    /// Where a mouse button pressed now would land (`CursorSync::press_target`). `None` when the
    /// cursor cannot be read, and off Windows.
    #[cfg_attr(not(windows), allow(dead_code))]
    pub(crate) fn press_target(&self, now: Instant) -> Option<(i32, i32)> {
        #[cfg(windows)]
        {
            lock(&self.sync).press_target(&mut cursor_sync::system::SystemCursor, now)
        }
        #[cfg(not(windows))]
        {
            let _ = now;
            None
        }
    }

    /// The foreground window's elevation, looked at afresh (`CursorSync::foreground_elevation`).
    #[cfg_attr(not(windows), allow(dead_code))]
    pub(crate) fn foreground_elevation(&self, now: Instant) -> Option<Elevation> {
        #[cfg(windows)]
        {
            lock(&self.sync).foreground_elevation(&mut cursor_sync::system::SystemCursor, now)
        }
        #[cfg(not(windows))]
        {
            let _ = now;
            None
        }
    }

    /// The first session begins: the planner starts afresh and says the pointer settings.
    #[cfg_attr(not(windows), allow(dead_code))]
    pub(crate) fn cursor_sync_begin(&self) {
        #[cfg(windows)]
        lock(&self.sync).begin_session(&mut cursor_sync::system::SystemCursor, Instant::now());
    }

    /// The last session ended: the planner's last aggregate line, and nothing kept.
    #[cfg_attr(not(windows), allow(dead_code))]
    pub(crate) fn cursor_sync_end(&self) {
        lock(&self.sync).end_session(Instant::now());
    }

    /// One `r` on the SendInput path, as the planner decides it.
    #[cfg(windows)]
    fn relative(&self, event: RelEvent, now: Instant) {
        match self.plan_rel(event, false, RelPath::SendInput, now) {
            // Exactly the code every `r` took before the planner.
            Plan::Camera => imp::mouse_move_rel(event.dx, event.dy, &self.rel),
            Plan::Absolute {
                px,
                py,
                width,
                height,
            } => {
                if !imp::send_one(imp::absolute_pixel_input(px, py, width, height)) {
                    self.rel_failed("SendInput refused the absolute move");
                }
            }
            Plan::Relative { cx, cy } => {
                if !imp::send_one(imp::relative_counts_input(cx, cy)) {
                    self.rel_failed("SendInput refused the relative move");
                }
            }
            Plan::Nothing => {}
        }
    }

    /// One `m` on the SendInput path: the planner keeps its books (the move in flight, exact mode's
    /// aim forgotten, the count per path) before the event goes out. Outside game-only mode the
    /// event itself is exactly today's (`imp::absolute_input`, the pixel's left edge); in it, the
    /// fractions are of the game's client area, so the event goes to the planner's pixel — mapped
    /// into that area — aimed at its centre (`imp::absolute_pixel_input`).
    #[cfg(windows)]
    fn position(&self, event: &InputMessage, x: f64, y: f64, now: Instant) {
        if !(x.is_finite() && y.is_finite()) {
            // JSON cannot carry one. Mapped as it always was outside game-only mode; nowhere in it.
            tracing::trace!(
                x,
                y,
                "absolute position (m): not a number; the planner is not told"
            );
            if !lock(&self.sync).confined() {
                imp::execute(event, &self.rel);
            }
            return;
        }
        let planned = self.plan_abs(x, y, RelPath::SendInput, now);
        let confined = lock(&self.sync).confined();
        match planned {
            Some((px, py, width, height)) if confined => {
                if !imp::send_one(imp::absolute_pixel_input(px, py, width, height)) {
                    self.rel_failed("SendInput refused the absolute position");
                }
            }
            Some(_) => imp::execute(event, &self.rel),
            None => {
                tracing::trace!("absolute position (m): the screen size is unknown to the planner");
                if !confined {
                    imp::execute(event, &self.rel);
                }
            }
        }
    }

    /// The modifiers this injector holds down, as HID keyboard modifier bits (left Ctrl, Shift, Alt,
    /// Win = 1, 2, 4, 8; the right ones 16, 32, 64, 128). Typing game text through the driver asks,
    /// because a modifier held here changes what a key typed there makes.
    #[cfg_attr(not(windows), allow(dead_code))]
    pub(crate) fn held_modifier_bits(&self) -> u8 {
        lock(&self.held)
            .keys
            .iter()
            .map(|&(vk, _)| match vk {
                0xA2 => 0x01, // ControlLeft
                0xA0 => 0x02, // ShiftLeft
                0xA4 => 0x04, // AltLeft
                0x5B => 0x08, // MetaLeft
                0xA3 => 0x10, // ControlRight
                0xA1 => 0x20, // ShiftRight
                0xA5 => 0x40, // AltRight
                0x5C => 0x80, // MetaRight
                _ => 0,
            })
            .fold(0, |bits, bit| bits | bit)
    }

    /// The mouse buttons held on either path, as HID button bits: this injector's ledger, and what
    /// the HID router last told the planner it holds (`CursorSync::hid_buttons`). For the game
    /// guard's transition line. The ledger's lock is let go before the planner's is taken, as in
    /// [`InputInjector::cursor`].
    #[cfg_attr(not(windows), allow(dead_code))]
    pub(crate) fn held_button_bits(&self) -> u8 {
        let sendinput = hid_bits(&lock(&self.held).buttons);
        sendinput | lock(&self.sync).hid_buttons_held()
    }
}

impl InputInjector for SendInputInjector {
    fn inject(&self, event: &InputMessage) -> Result<()> {
        if matches!(event, InputMessage::ReleaseAll) {
            // Logged by `release_all` when it actually releases something.
            self.release_all();
            return Ok(());
        }

        // Record before injecting: if `SendInput` partially succeeds we would rather
        // hold a key we did not press (harmless, the release is idempotent) than lose
        // one we did (a key stuck down on the owner's desktop).
        // A mouse button transition comes out of the block for its debug line, written once
        // the ledger is unlocked; a key transition for the auto-repeat, told once the key went out.
        let (button, key) = {
            let mut held = lock(&self.held);
            match event {
                InputMessage::Down { b } => (Some((*b, true, held.buttons.insert(*b))), None),
                InputMessage::Up { b } => (Some((*b, false, held.buttons.remove(b))), None),
                InputMessage::Key { d, code, .. } => {
                    let key = code_to_vk(code).map(|vk| {
                        let down = *d == 1;
                        // For a press: was it already down (a repeat of a held key)?
                        let was_held = if down {
                            !held.keys.insert(vk)
                        } else {
                            held.keys.remove(&vk)
                        };
                        (vk, down, was_held)
                    });
                    (None, key)
                }
                // `Rel` moves nothing held; `Text` presses and releases each unit
                // immediately, so neither can strand state. They are listed here so a
                // future variant has to decide explicitly which side it is on.
                InputMessage::Rel { .. } | InputMessage::Text { .. } => (None, None),
                _ => (None, None),
            }
        };
        if let Some((b, down, changed)) = button {
            note_button(b, down, changed, "viewer");
        }

        #[cfg(windows)]
        {
            let now = Instant::now();
            self.note_input(now);
            match event {
                InputMessage::Rel { dx, dy, x, y, s } => self.relative(
                    RelEvent {
                        dx: *dx,
                        dy: *dy,
                        x: *x,
                        y: *y,
                        s: *s,
                    },
                    now,
                ),
                InputMessage::Move { x, y } => self.position(event, *x, *y, now),
                InputMessage::Wheel { .. } => {
                    // Every wheel that reaches SendInput, whoever routed it: the per-second line.
                    self.count_wheel(
                        WheelTally {
                            sendinput: 1,
                            ..WheelTally::default()
                        },
                        now,
                    );
                    imp::execute(event, &self.rel);
                }
                _ => imp::execute(event, &self.rel),
            }
            // After the key itself went out. A key-up's ledger entry is already gone, so the worker
            // cannot press it again whatever the order here; stopping just ends its timer.
            if let Some((vk, down, was_held)) = key {
                if down {
                    self.repeat.press(vk, repeat::auto_repeats(vk.0), was_held);
                } else {
                    self.repeat.release(vk);
                }
            }
        }
        #[cfg(not(windows))]
        {
            // SendInput is Windows-only, and so is repeating what it did not press.
            let _ = (event, &self.rel, key);
        }
        Ok(())
    }

    /// The default rule for the scope (this injector cannot confine input: in game scope it drops
    /// every press), and a key whose code has no Windows mapping holds nothing: it is never pressed
    /// (`note_unmapped`).
    fn press_may_hold(
        &self,
        event: &InputMessage,
        scope: &afklink_core::traits::InputScope,
    ) -> bool {
        if matches!(scope, afklink_core::traits::InputScope::Game(_)) {
            return false;
        }
        match event {
            InputMessage::Key { d: 1, code, .. } => code_to_vk(code).is_some(),
            _ => true,
        }
    }

    fn release_all(&self) {
        // The repeat first, so its worker is not left pressing a key this release is about to
        // take out of the ledger (it would find the key gone and stop anyway).
        self.repeat.stop("release_all");

        // The sub-pixel remainder belongs to the stroke that just ended (mode switch, hidden
        // viewer, silence): the next stroke starts from a whole pixel. Under half a pixel either
        // way, so there is nothing worth logging.
        *lock(&self.rel) = RelCarry::default();
        // So do the planner's aim and moves in flight; its aggregate line goes out now.
        lock(&self.sync).release(Instant::now());

        // Take the ledger rather than iterating it: a concurrent inject must not see a
        // half-unwound state, and if the release itself fails we still want the entries
        // gone — a stale "held" that is no longer held would suppress the next real
        // press's release.
        let mut held = lock(&self.held);
        if held.is_empty() {
            return;
        }
        let taken = std::mem::take(&mut *held);
        drop(held);

        // not-a-key-name: a count of held keys
        tracing::debug!(
            buttons = taken.buttons.len(),
            keys = taken.keys.len(),
            "releasing held input"
        );
        for b in &taken.buttons {
            note_button(*b, false, true, "release_all");
        }

        #[cfg(windows)]
        {
            // Keys first: releasing a modifier before the button means the click that
            // was in flight cannot land as Ctrl+click on whatever is under the cursor.
            for (vk, extended) in &taken.keys {
                imp::key(*vk, *extended, false);
            }
            for b in &taken.buttons {
                imp::mouse_button(*b, false);
            }
        }
        #[cfg(not(windows))]
        {
            let _ = &taken;
        }
    }

    /// The OS cursor against the primary monitor — the one WGC captures and the one `m` and `r`
    /// are scaled to — for the viewer's cursor marker, with the lowest numbered move it does not
    /// show yet (`CursorSync::unshown`).
    fn cursor(&self) -> Option<CursorSample> {
        let now = Instant::now();
        // The buttons this path holds, for the visibility line: read before the planner's lock is
        // taken, never under it (a plan takes this ledger's lock and lets it go before the planner's).
        let sendinput = hid_bits(&lock(&self.held).buttons);
        // The look and the question are one reading under the planner's lock, which every plan
        // holds for its own look: no move is planned between them, so a move in flight is never
        // matched against a look taken before it was planned. The lock is held for a few Win32
        // reads at most (never across a HID write), so the wait is microseconds.
        let mut sync = lock(&self.sync);
        // Polled ~30 times a second while a session runs: the planner's per-second line goes out
        // on time even after the last move of a stroke.
        sync.flush_if_due(now);
        #[cfg(windows)]
        {
            let mut sample = imp::cursor_sample()?;
            sample.unshown = sync.unshown((sample.x, sample.y), now);
            sync.note_visibility(sample.visible, sendinput, now);
            Some(sample)
        }
        #[cfg(not(windows))]
        {
            let _ = sendinput;
            drop(sync);
            None
        }
    }

    /// The cursor's picture and the window under it (`cursor_shape`), once per new shape.
    fn cursor_shape(&self, sample: &CursorSample) -> Option<CursorShape> {
        #[cfg(windows)]
        {
            Some(cursor_shape::describe(sample))
        }
        #[cfg(not(windows))]
        {
            let _ = sample;
            None
        }
    }
}

/// One debug line per mouse button press or release.
///
/// Button transitions are discrete — a tap is one press and one release — and moves (`m`, `r`)
/// never come here, so this is not the per-frame path. No position: which button, who asked
/// (`viewer` for the viewer's `d`/`u`, `release_all` for a release the agent makes on its own or
/// on the viewer's `ra`), and whether it changed the ledger. A press of a button already down, or
/// a release of one that was not, is the viewer and the desktop disagreeing — which is what a stuck
/// button looks like from here.
fn note_button(b: u8, down: bool, changed: bool, source: &'static str) {
    let button = button_name(b);
    if down {
        tracing::debug!(button, source, changed, "mouse button down");
    } else {
        tracing::debug!(button, source, changed, "mouse button up");
    }
}

/// The protocol's button ids (0 = left, 1 = middle, 2 = right) as HID button bits (1 left, 2 right,
/// 4 middle), the planner's and the button watch's words for them.
fn hid_bits(buttons: &BTreeSet<u8>) -> u8 {
    buttons.iter().fold(0, |bits, b| {
        bits | match b {
            0 => 1,
            1 => 4,
            2 => 2,
            _ => 0,
        }
    })
}

/// The protocol's button id (0 = left, 1 = middle, 2 = right) in words, for the log.
fn button_name(b: u8) -> &'static str {
    match b {
        0 => "left",
        1 => "middle",
        2 => "right",
        _ => "other",
    }
}

#[cfg(windows)]
mod imp {
    use afklink_protocol::{InputMessage, WheelMode};
    use windows::Win32::UI::Input::KeyboardAndMouse::{
        SendInput, INPUT, INPUT_0, INPUT_KEYBOARD, INPUT_MOUSE, KEYBDINPUT, KEYBD_EVENT_FLAGS,
        KEYEVENTF_KEYUP, MOUSEEVENTF_ABSOLUTE, MOUSEEVENTF_HWHEEL, MOUSEEVENTF_LEFTDOWN,
        MOUSEEVENTF_LEFTUP, MOUSEEVENTF_MIDDLEDOWN, MOUSEEVENTF_MIDDLEUP, MOUSEEVENTF_MOVE,
        MOUSEEVENTF_RIGHTDOWN, MOUSEEVENTF_RIGHTUP, MOUSEEVENTF_WHEEL, MOUSEINPUT,
        MOUSE_EVENT_FLAGS, VIRTUAL_KEY,
    };

    use super::keymap::{code_to_vk, key_stroke, KeyStroke};
    use super::RelCarry;
    use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU64, Ordering};
    use std::sync::Mutex;
    use std::time::{Duration, Instant};

    /// Absolute-coordinate normalization range for `MOUSEEVENTF_ABSOLUTE`.
    const ABS_MAX: f64 = 65535.0;

    /// `rel` is the injector's sub-pixel remainder for relative moves.
    pub fn execute(event: &InputMessage, rel: &Mutex<RelCarry>) {
        match event {
            InputMessage::Move { x, y } => mouse_move(*x, *y),
            // The injector plans every `r` (`cursor_sync`) before it gets here; this is its camera
            // path, the one every `r` took before the planner.
            InputMessage::Rel { dx, dy, .. } => mouse_move_rel(*dx, *dy, rel),
            InputMessage::Down { b } => mouse_button(*b, true),
            InputMessage::Up { b } => mouse_button(*b, false),
            // `game` does not matter here: every wheel that reaches SendInput scrolls smoothly.
            InputMessage::Wheel { dx, dy, mode, .. } => {
                mouse_wheel(*dx, *dy, WheelMode::from_wire(*mode))
            }
            InputMessage::Key { d, code, src, .. } => match code_to_vk(code) {
                Some((vk, extended)) => key(vk, extended, *d == 1),
                None => note_unmapped(code, *src),
            },
            // `game` does not matter here: text that reaches SendInput is typed as Unicode. Game
            // text the driver can type never gets here (`fakerinput::typing`).
            InputMessage::Text { text, .. } => send_text(text),
            InputMessage::Combo { name } => handle_combo(name),
            // Handled by the injector before it reaches the platform layer, which has
            // no ledger of its own to unwind.
            InputMessage::ReleaseAll => {}
            // Not input at all: the session task intercepts these and adjusts the quality ladder,
            // records a measurement, or forces a keyframe. Reaching here would mean that
            // interception was removed, and injecting nothing is the right answer either way —
            // this layer moves a mouse, it does not pick bitrates or keep statistics.
            InputMessage::Quality { .. }
            | InputMessage::ViewerLatency { .. }
            | InputMessage::ViewerVideo(_)
            | InputMessage::KeyframeRequest { .. }
            | InputMessage::Visibility { .. }
            | InputMessage::ClipboardSync { .. }
            | InputMessage::ClipboardSet(_) => {}
        }
    }

    /// # Safety
    ///
    /// `inputs` must be a valid, live slice of `INPUT`, and `cbsize` must be the size
    /// of a single `INPUT`. `SendInput` copies the data synchronously, so the slice
    /// does not need to outlive the call.
    unsafe fn send(inputs: &[INPUT]) -> bool {
        // Explicit block rather than relying on the enclosing `unsafe fn`: it marks
        // exactly which call carries the obligation above, and it is what edition 2024
        // requires.
        let sent = unsafe { SendInput(inputs, std::mem::size_of::<INPUT>() as i32) };
        if sent as usize != inputs.len() {
            // Read at once, before anything else can overwrite it. Access denied here is UIPI:
            // an elevated window has focus and a non-elevated agent may not type into it.
            let os_error = std::io::Error::last_os_error();
            refused(sent, inputs.len(), &os_error);
            return false;
        }
        true
    }

    /// One mouse event through `SendInput`: whether Windows took it. (Over an elevated window UIPI
    /// takes it and drops it, answering yes — measured; the planner notices a move that moved nothing.)
    pub(crate) fn send_one(input: INPUT) -> bool {
        // SAFETY: one live, fully initialised INPUT; `send` passes its size.
        unsafe { send(&[input]) }
    }

    /// When `SendInput` refused events, and how many refusals since the last warning.
    ///
    /// A refusal is per event, and the usual cause — an elevated window in the foreground — refuses
    /// every event for as long as it has focus: sixty warnings a second of a moving mouse. So the
    /// first is a warning at once, and after it at most one every [`REFUSED_WARN_EVERY`], saying
    /// how many were refused in between.
    static REFUSED_WARNED_AT: Mutex<Option<Instant>> = Mutex::new(None);
    static REFUSED_SINCE: AtomicU64 = AtomicU64::new(0);
    const REFUSED_WARN_EVERY: Duration = Duration::from_secs(10);

    fn refused(sent: u32, wanted: usize, os_error: &std::io::Error) {
        let now = Instant::now();
        let mut at = afklink_core::sync::lock(&REFUSED_WARNED_AT);
        let held = REFUSED_SINCE.fetch_add(1, Ordering::Relaxed);
        if at.is_none_or(|t| now.saturating_duration_since(t) >= REFUSED_WARN_EVERY) {
            *at = Some(now);
            REFUSED_SINCE.store(0, Ordering::Relaxed);
            tracing::warn!(
                refused_since_last_warning = held,
                "SendInput injected {sent}/{wanted} events: {os_error}"
            );
        }
    }

    /// The OS cursor for the viewer's marker: position relative to the primary monitor (the one
    /// WGC captures; its top-left corner is the virtual screen's origin), the monitor's size in the
    /// same pixels, whether the cursor is drawn at all, and its shape (`HCURSOR`). The moves it
    /// does not show yet are the planner's to fill in.
    ///
    /// `GetCursorInfo` rather than `GetCursorPos` because it also says whether the cursor shows —
    /// a game hides it, and touch input suppresses it — and one call answers both. It fails while
    /// another desktop has the input (the secure desktop of a UAC prompt or the lock screen); that
    /// is said once per streak at debug, and the report simply pauses.
    pub fn cursor_sample() -> Option<super::CursorSample> {
        use windows::Win32::UI::WindowsAndMessaging::{
            GetCursorInfo, GetSystemMetrics, CURSORINFO, CURSOR_SHOWING, SM_CXSCREEN, SM_CYSCREEN,
        };
        static FAILING: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

        let mut info = CURSORINFO {
            cbSize: std::mem::size_of::<CURSORINFO>() as u32,
            ..Default::default()
        };
        // SAFETY: `info` is a live CURSORINFO we own, with `cbSize` set as the API requires.
        if let Err(e) = unsafe { GetCursorInfo(&mut info) } {
            if !FAILING.swap(true, Ordering::Relaxed) {
                tracing::debug!("cursor position unavailable (another desktop has input?): {e}");
            }
            return None;
        }
        if FAILING.swap(false, Ordering::Relaxed) {
            tracing::debug!("cursor position available again");
        }
        // SAFETY: plain metric queries; no pointers involved.
        let width = unsafe { GetSystemMetrics(SM_CXSCREEN) };
        let height = unsafe { GetSystemMetrics(SM_CYSCREEN) };
        Some(super::CursorSample {
            x: info.ptScreenPos.x,
            y: info.ptScreenPos.y,
            width,
            height,
            visible: info.flags.0 & CURSOR_SHOWING.0 != 0,
            shape: info.hCursor.0 as usize,
            unshown: None,
        })
    }

    /// A key code with no Windows mapping: once per distinct code in a row, since a held key
    /// repeats its keydown thirty times a second. Debug, because it is the viewer asking for a key
    /// this build cannot press — a gap in the keymap, not a fault. The code is named only for one of
    /// the viewer's own keys (`k.src`): one from its keyboard may be part of a password.
    ///
    /// A flood of distinct codes (or two alternating) is not a line each (KB-6): past the line
    /// gate's burst they go to `trace`, and the next window says how many did.
    fn note_unmapped(code: &str, src: Option<afklink_protocol::KeySource>) {
        static LAST: Mutex<(String, crate::line_gate::LineGate)> =
            Mutex::new((String::new(), crate::line_gate::LineGate::new()));
        let mut last = afklink_core::sync::lock(&LAST);
        if last.0 != code {
            if last.1.admit(Instant::now(), "unmapped key") {
                tracing::debug!(
                    target: crate::KEY_NAMES_TARGET,
                    code = crate::key_log::loggable(code, src),
                    src = crate::key_log::source_name(src),
                    "unmapped key code: not injected"
                );
            } else {
                tracing::trace!("unmapped key code: not injected");
            }
            code.clone_into(&mut last.0);
        }
    }

    fn mouse_move(x: f64, y: f64) {
        unsafe { send(&[absolute_input(x, y)]) };
    }

    /// The `SendInput` event of an absolute move (`m`): `x`, `y` are fractions of the primary
    /// monitor, clamped to it and scaled to `MOUSEEVENTF_ABSOLUTE`'s `0..=65535` — without
    /// `MOUSEEVENTF_VIRTUALDESK`, so Windows maps them onto the primary monitor.
    ///
    /// Built apart from the call so the mouse probe (`fakerinput::mouse_probe`, an ignored test)
    /// injects exactly this event and still sees what `SendInput` answered.
    pub(crate) fn absolute_input(x: f64, y: f64) -> INPUT {
        let dx = (x.clamp(0.0, 1.0) * ABS_MAX).round() as i32;
        let dy = (y.clamp(0.0, 1.0) * ABS_MAX).round() as i32;
        INPUT {
            r#type: INPUT_MOUSE,
            Anonymous: INPUT_0 {
                mi: MOUSEINPUT {
                    dx,
                    dy,
                    mouseData: 0,
                    dwFlags: MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE,
                    time: 0,
                    dwExtraInfo: 0,
                },
            },
        }
    }

    /// The cursor-sync planner's point move on this path: the pixel's centre as a fraction of the
    /// screen, through the same event `m` uses. `MOUSEEVENTF_ABSOLUTE` maps `0..65535` onto the
    /// monitor as `floor(dx · width / 65536)` (measured: 27415 → 1505 on 3600 px), so the centre lands on
    /// the pixel where its left edge — `m`'s mapping — lands one short about half the time.
    pub(crate) fn absolute_pixel_input(px: i32, py: i32, width: i32, height: i32) -> INPUT {
        let (w, h) = (f64::from(width.max(1)), f64::from(height.max(1)));
        absolute_input(
            (f64::from(px.clamp(0, width.max(1) - 1)) + 0.5) / w,
            (f64::from(py.clamp(0, height.max(1) - 1)) + 0.5) / h,
        )
    }

    /// The cursor-sync planner's exact move on this path: these counts, as they are. Windows scales
    /// and accelerates them exactly as it does a HID report's, which the planner has taken out.
    pub(crate) fn relative_counts_input(cx: i32, cy: i32) -> INPUT {
        INPUT {
            r#type: INPUT_MOUSE,
            Anonymous: INPUT_0 {
                mi: MOUSEINPUT {
                    dx: cx,
                    dy: cy,
                    mouseData: 0,
                    dwFlags: MOUSEEVENTF_MOVE,
                    time: 0,
                    dwExtraInfo: 0,
                },
            },
        }
    }

    /// The camera's relative move: the fraction times the screen, the remainder carried.
    pub(crate) fn mouse_move_rel(dx_frac: f64, dy_frac: f64, rel: &Mutex<RelCarry>) {
        if let Some(input) = relative_input(dx_frac, dy_frac, rel) {
            unsafe { send(&[input]) };
        }
    }

    /// Relative move for trackpad / MMO-look deltas: the `SendInput` event for one `r`
    /// message, or `None` when it moves nothing (yet).
    ///
    /// Deliberately *without* `MOUSEEVENTF_ABSOLUTE`: an absolute warp is what makes
    /// game cameras hit the screen edge, and raw-input games ignore warps entirely.
    /// Fractions are scaled by the primary monitor size, matching what `mouse_move`
    /// targets, so one full-screen swipe is one screen of travel at any resolution.
    /// What does not make a whole pixel is carried to the next message ([`RelCarry`]).
    ///
    /// Built apart from the call, like [`absolute_input`], for the mouse probe.
    pub(crate) fn relative_input(
        dx_frac: f64,
        dy_frac: f64,
        rel: &Mutex<RelCarry>,
    ) -> Option<INPUT> {
        use windows::Win32::UI::WindowsAndMessaging::{GetSystemMetrics, SM_CXSCREEN, SM_CYSCREEN};
        let w = unsafe { GetSystemMetrics(SM_CXSCREEN) };
        let h = unsafe { GetSystemMetrics(SM_CYSCREEN) };
        if w <= 0 || h <= 0 {
            tracing::debug!(
                w,
                h,
                "relative move dropped: the screen size is unavailable"
            );
            return None;
        }
        if !dx_frac.is_finite() || !dy_frac.is_finite() {
            // JSON cannot carry one, so this is a bug upstream; moving on it would poison the carry.
            tracing::debug!(dx_frac, dy_frac, "relative move dropped: not a number");
            return None;
        }
        let (dx, dy) = afklink_core::sync::lock(rel).step(dx_frac, dy_frac, w, h);
        // Per message, so trace: a moving finger is sixty of these a second.
        tracing::trace!(dx_frac, dy_frac, dx, dy, "relative move");
        if dx == 0 && dy == 0 {
            // Under a pixel so far: the carry holds it until the next message.
            return None;
        }
        Some(INPUT {
            r#type: INPUT_MOUSE,
            Anonymous: INPUT_0 {
                mi: MOUSEINPUT {
                    dx,
                    dy,
                    mouseData: 0,
                    dwFlags: MOUSEEVENTF_MOVE,
                    time: 0,
                    dwExtraInfo: 0,
                },
            },
        })
    }

    /// Committed IME text as Unicode keystrokes.
    ///
    /// `KEYEVENTF_UNICODE` carries the UTF-16 unit in `wScan` and needs no layout
    /// mapping — which is exactly why it works for mobile keyboards that report no
    /// `code`. Surrogate pairs go as two units, in order; each unit is pressed and
    /// released immediately, so text never lands in the held ledger.
    fn send_text(text: &str) {
        let units: Vec<u16> = text.encode_utf16().collect();
        if units.is_empty() {
            return;
        }
        let inputs: Vec<INPUT> = units
            .iter()
            .flat_map(|&u| [key_unicode(u, true), key_unicode(u, false)])
            .collect();
        unsafe { send(&inputs) };
    }

    fn key_unicode(scan: u16, down: bool) -> INPUT {
        use windows::Win32::UI::Input::KeyboardAndMouse::KEYEVENTF_UNICODE;
        let mut flags = KEYEVENTF_UNICODE;
        if !down {
            flags |= KEYEVENTF_KEYUP;
        }
        INPUT {
            r#type: INPUT_KEYBOARD,
            Anonymous: INPUT_0 {
                ki: KEYBDINPUT {
                    wVk: VIRTUAL_KEY(0),
                    wScan: scan,
                    dwFlags: flags,
                    time: 0,
                    dwExtraInfo: 0,
                },
            },
        }
    }

    pub fn mouse_button(b: u8, down: bool) {
        let flags = match (b, down) {
            (0, true) => MOUSEEVENTF_LEFTDOWN,
            (0, false) => MOUSEEVENTF_LEFTUP,
            (1, true) => MOUSEEVENTF_MIDDLEDOWN,
            (1, false) => MOUSEEVENTF_MIDDLEUP,
            (2, true) => MOUSEEVENTF_RIGHTDOWN,
            (2, false) => MOUSEEVENTF_RIGHTUP,
            _ => {
                tracing::debug!(button = b, down, "unknown mouse button: not injected");
                return;
            }
        };
        emit_mouse(flags, 0);
    }

    /// One Windows wheel notch. `WHEEL_DELTA` from `winuser.h`.
    const WHEEL_DELTA: f64 = 120.0;

    fn mouse_wheel(dx: f64, dy: f64, mode: WheelMode) {
        // The viewer's delta is meaningless without its unit: a Chrome notch is ~100
        // pixels, Firefox reports 3 lines, and a two-finger phone scroll reports single
        // digits. Convert to notches first (`crate::wheel`, shared with the HID path), then to
        // Windows' 120-per-notch units, so all three feel the same on the desktop.
        let to_windows = |d: f64| {
            (crate::wheel::notches(d, mode, crate::wheel::PIXELS_PER_NOTCH) * WHEEL_DELTA).round()
                as i32
        };

        // WheelEvent sign: down > 0. Windows wheel: positive = forward/up, so
        // vertical wheelData = -deltaY.
        // A small pixel nudge can round to zero; forward one unit rather than
        // swallow the gesture, or slow trackpad scrolling does nothing at all.
        let v = (dy != 0.0).then(|| match to_windows(-dy) {
            0 => sign(-dy),
            v => v,
        });
        let h = (dx != 0.0).then(|| match to_windows(dx) {
            0 => sign(dx),
            h => h,
        });
        // Per message, so trace: a scrolling finger is sixty of these a second.
        tracing::trace!(dx, dy, ?mode, wheel_data = ?v, hwheel_data = ?h, "SendInput wheel");
        if let Some(v) = v {
            emit_mouse(MOUSEEVENTF_WHEEL, v as u32);
        }
        if let Some(h) = h {
            emit_mouse(MOUSEEVENTF_HWHEEL, h as u32);
        }
    }

    fn sign(v: f64) -> i32 {
        if v < 0.0 {
            -1
        } else {
            1
        }
    }

    fn emit_mouse(flags: MOUSE_EVENT_FLAGS, mouse_data: u32) {
        let input = INPUT {
            r#type: INPUT_MOUSE,
            Anonymous: INPUT_0 {
                mi: MOUSEINPUT {
                    dx: 0,
                    dy: 0,
                    mouseData: mouse_data,
                    dwFlags: flags,
                    time: 0,
                    dwExtraInfo: 0,
                },
            },
        };
        unsafe { send(&[input]) };
    }

    /// Press or release a key by its hardware scan code where it has one ([`key_stroke`]): games
    /// reading DirectInput or raw input see the scan code, and a Virtual-Key sent with `wScan = 0`
    /// never reached them. The ledger and `release_all` go through here too, so a release always
    /// names the key exactly as its press did.
    pub fn key(vk: u16, extended: bool, down: bool) {
        let stroke = key_stroke(vk, extended, down);
        note_stroke(&stroke);
        let input = INPUT {
            r#type: INPUT_KEYBOARD,
            Anonymous: INPUT_0 {
                ki: KEYBDINPUT {
                    wVk: VIRTUAL_KEY(stroke.vk),
                    wScan: stroke.scan,
                    dwFlags: KEYBD_EVENT_FLAGS(stroke.flags),
                    time: 0,
                    dwExtraInfo: 0,
                },
            },
        };
        unsafe { send(&[input]) };
    }

    /// How keys are pressed, said once per process; and a key that has to go by Virtual-Key alone
    /// (no single-byte scan code: Pause, media keys — games may not see it), once per such key in a
    /// row, since a held key repeats. Never which key was pressed — not even which of those: the
    /// press may come from the viewer's own keyboard, whose keys are never named.
    fn note_stroke(stroke: &KeyStroke) {
        static SAID_SCAN: AtomicBool = AtomicBool::new(false);
        static LAST_VK_ONLY: AtomicU16 = AtomicU16::new(0);
        if stroke.by_scan_code() {
            if !SAID_SCAN.swap(true, Ordering::Relaxed) {
                tracing::debug!(
                    "keys are pressed by their hardware scan code (KEYEVENTF_SCANCODE): games \
                     reading DirectInput or raw input see them"
                );
            }
        } else if LAST_VK_ONLY.swap(stroke.vk, Ordering::Relaxed) != stroke.vk {
            tracing::debug!(
                kind = "pause_or_media",
                "key has no single-byte scan code (Pause or a media key): pressed by Virtual-Key \
                 only, games reading the keyboard directly may not see it"
            );
        }
    }

    fn handle_combo(name: &str) {
        match name {
            // Ctrl+Alt+Del is a Secure Attention Sequence: it can only be
            // synthesized by a SYSTEM process (SendSAS). In path B (user
            // session) this is a no-op.
            "ctrl_alt_del" => tracing::warn!(
                target: crate::KEY_NAMES_TARGET,
                "ctrl_alt_del requested but requires SYSTEM privileges (path A)"
            ),
            other => tracing::debug!(target: crate::KEY_NAMES_TARGET, "unhandled combo: {other}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Why most of these are `#[ignore]`d: `inject` and `release_all` reach the real `SendInput`
    // on Windows, so a plain `cargo test` would click the left and right buttons wherever the
    // developer's cursor is, hold Ctrl, move the pointer and type «привет» into whichever window
    // has focus. Run them on purpose, with nothing important focused:
    // `cargo test -p afklink-input -- --ignored`. Only tests that never reach `SendInput` stay
    // in the default run.

    /// The ledger is the contract; the `SendInput` calls under it are Windows-only, so
    /// these assert the bookkeeping, which is where the stuck-key bug actually lives.
    #[test]
    #[ignore = "drives the real cursor and keyboard; run manually with --ignored"]
    fn a_press_without_a_release_stays_held() {
        let inj = SendInputInjector::new();
        inj.inject(&InputMessage::Down { b: 0 }).unwrap();
        assert!(inj.has_held());
        inj.inject(&InputMessage::Up { b: 0 }).unwrap();
        assert!(!inj.has_held(), "the matching up must clear the ledger");
    }

    #[test]
    #[ignore = "drives the real cursor and keyboard; run manually with --ignored"]
    fn release_all_unwinds_buttons_and_keys() {
        let inj = SendInputInjector::new();
        inj.inject(&InputMessage::Down { b: 0 }).unwrap();
        inj.inject(&InputMessage::Key {
            d: 1,
            code: "ControlLeft".into(),
            key: None,
            mods: None,
            src: None,
        })
        .unwrap();
        assert!(inj.has_held());
        inj.release_all();
        assert!(!inj.has_held());
        inj.release_all(); // idempotent
        assert!(!inj.has_held());
    }

    #[test]
    #[ignore = "drives the real cursor and keyboard; run manually with --ignored"]
    fn the_release_all_message_is_handled_like_the_call() {
        let inj = SendInputInjector::new();
        inj.inject(&InputMessage::Down { b: 2 }).unwrap();
        inj.inject(&InputMessage::ReleaseAll).unwrap();
        assert!(!inj.has_held());
    }

    #[test]
    #[ignore = "drives the real cursor and keyboard; run manually with --ignored"]
    fn clones_share_one_ledger() {
        // The session task releases through its own handle; it has to undo presses the
        // event task performed.
        let a = SendInputInjector::new();
        let b = a.clone();
        a.inject(&InputMessage::Down { b: 0 }).unwrap();
        assert!(b.has_held());
        b.release_all();
        assert!(!a.has_held());
    }

    #[test]
    #[ignore = "drives the real cursor and keyboard; run manually with --ignored"]
    fn relative_moves_and_text_leave_nothing_held() {
        // Neither carries a transition, so neither may pollute the ledger that
        // release_all unwinds.
        let inj = SendInputInjector::new();
        inj.inject(&InputMessage::Rel {
            dx: 0.02,
            dy: -0.01,
            s: None,
            x: None,
            y: None,
        })
        .unwrap();
        inj.inject(&InputMessage::Text {
            text: "привет".into(),
            game: None,
        })
        .unwrap();
        assert!(!inj.has_held());
        inj.release_all(); // must stay a no-op, not a crash
        assert!(!inj.has_held());
    }

    // `RelCarry` is plain arithmetic: these never reach `SendInput`, so they run by default.

    #[test]
    fn slow_relative_moves_add_up_instead_of_rounding_away() {
        // A careful stroke: a hundred messages of 0.384 px each on a 1920-wide screen. Rounded one
        // by one every message is 0 px and the cursor never moves; carried, they make 38 px.
        let mut carry = RelCarry::default();
        let mut total = 0;
        for _ in 0..100 {
            let (dx, dy) = carry.step(0.0002, 0.0, 1920, 1080);
            assert_eq!(dy, 0);
            total += dx;
        }
        assert_eq!(total, 38, "0.0002 × 1920 × 100 = 38.4 px");
        assert!(carry.x.abs() <= 0.5, "what is left is under half a pixel");
    }

    #[test]
    fn the_carry_works_in_both_directions_and_on_both_axes() {
        let mut carry = RelCarry::default();
        let (mut sx, mut sy) = (0, 0);
        for _ in 0..10 {
            let (dx, dy) = carry.step(-0.0003, 0.0004, 1920, 1080);
            sx += dx;
            sy += dy;
        }
        // -0.0003 × 1920 × 10 = -5.76 px; 0.0004 × 1080 × 10 = 4.32 px.
        assert_eq!(sx, -6);
        assert_eq!(sy, 4);
    }

    #[test]
    fn a_relative_step_is_clamped_to_one_screen() {
        let mut carry = RelCarry::default();
        assert_eq!(carry.step(3.0, -3.0, 1920, 1080), (1920, -1080));
        assert_eq!(
            carry,
            RelCarry::default(),
            "whole pixels leave no remainder"
        );
    }

    #[test]
    fn a_non_number_moves_nothing_and_keeps_the_carry() {
        let mut carry = RelCarry::default();
        carry.step(0.0001, 0.0, 1920, 1080); // 0.192 px carried
        let before = carry;
        assert_eq!(carry.step(f64::NAN, 0.0, 1920, 1080), (0, 0));
        assert_eq!(carry.step(0.0, f64::INFINITY, 1920, 1080), (0, 0));
        assert_eq!(carry, before);
    }

    #[test]
    fn an_unmapped_key_is_not_recorded_as_held() {
        // Nothing was sent, so nothing can be stuck — recording it would make
        // release_all emit a key-up for a key that was never pressed. Safe to run by default:
        // an unmapped code stops at `code_to_vk` and never reaches `SendInput`, and the ledger
        // stays empty so `release_all` has nothing to send either.
        let inj = SendInputInjector::new();
        inj.inject(&InputMessage::Key {
            d: 1,
            code: "NoSuchKey".into(),
            key: None,
            mods: None,
            src: None,
        })
        .unwrap();
        assert!(!inj.has_held());
    }

    #[test]
    fn held_modifiers_read_as_hid_bits() {
        // The ledger alone, never `SendInput`: what typing game text asks before it types.
        let inj = SendInputInjector::new();
        assert_eq!(inj.held_modifier_bits(), 0);
        for code in ["ShiftLeft", "AltRight", "KeyA", "MetaLeft"] {
            lock(&inj.held).keys.insert(code_to_vk(code).unwrap());
        }
        assert_eq!(inj.held_modifier_bits(), 0x02 | 0x40 | 0x08);
        for code in [
            "ControlLeft",
            "ControlRight",
            "ShiftRight",
            "AltLeft",
            "MetaRight",
        ] {
            lock(&inj.held).keys.insert(code_to_vk(code).unwrap());
        }
        assert_eq!(inj.held_modifier_bits(), 0xFF);
    }

    /// The planner's point move on the SendInput path lands on the pixel: `MOUSEEVENTF_ABSOLUTE`'s
    /// `0..65535` maps onto the monitor as `floor(dx · width / 65536)` (measured: 27415 → 1505 on 3600
    /// px, where `m`'s edge mapping aimed at 1506). Builds the events only; nothing is sent.
    #[cfg(windows)]
    #[test]
    fn a_point_move_through_sendinput_lands_on_every_pixel() {
        for size in [3600, 2400, 1920, 1080, 2560, 3840, 5120, 1366] {
            for p in 0..size {
                let input = imp::absolute_pixel_input(p, p.min(size - 1), size, size);
                // SAFETY: `absolute_pixel_input` builds a mouse event; this reads its own fields.
                let (dx, dy) = unsafe { (input.Anonymous.mi.dx, input.Anonymous.mi.dy) };
                assert_eq!(
                    i64::from(dx) * i64::from(size) / 65536,
                    i64::from(p),
                    "{p} of {size}"
                );
                assert_eq!(dx, dy);
            }
        }
        // SAFETY: as above.
        let dx = unsafe {
            imp::absolute_pixel_input(1506, 0, 3600, 2400)
                .Anonymous
                .mi
                .dx
        };
        assert_eq!(i64::from(dx) * 3600 / 65536, 1506, "E1's 1505 is 1506 now");
    }

    /// The planner's exact move goes as its counts, a plain relative move.
    #[cfg(windows)]
    #[test]
    fn an_exact_move_through_sendinput_is_its_counts() {
        use windows::Win32::UI::Input::KeyboardAndMouse::MOUSEEVENTF_MOVE;
        let input = imp::relative_counts_input(-7, 12);
        // SAFETY: `relative_counts_input` builds a mouse event; this reads its own fields.
        let mi = unsafe { input.Anonymous.mi };
        assert_eq!((mi.dx, mi.dy), (-7, 12));
        assert_eq!(mi.dwFlags, MOUSEEVENTF_MOVE);
    }

    #[test]
    fn button_log_names_follow_the_protocol_ids() {
        assert_eq!(super::button_name(0), "left");
        assert_eq!(super::button_name(1), "middle");
        assert_eq!(super::button_name(2), "right");
        assert_eq!(super::button_name(7), "other");
    }

    /// `SendInput` cannot confine input, so in game scope its default drops every press — none can
    /// hold — and on the desktop a key holds only when it has a Windows mapping. Pure: nothing is
    /// injected.
    #[test]
    fn sendinput_says_a_press_can_hold_only_on_the_desktop_and_only_for_a_mapped_key() {
        use afklink_core::traits::{GameScope, InputScope};
        let inj = SendInputInjector::new();
        let key = |code: &str| InputMessage::Key {
            d: 1,
            code: code.into(),
            key: None,
            mods: None,
            src: None,
        };
        let game = InputScope::Game(GameScope {
            state: afklink_protocol::GameWindowState::Shown,
            window: None,
        });
        assert!(inj.press_may_hold(&key("KeyA"), &InputScope::Desktop));
        assert!(inj.press_may_hold(&InputMessage::Down { b: 0 }, &InputScope::Desktop));
        for code in ["", "Bogus"] {
            assert!(
                !inj.press_may_hold(&key(code), &InputScope::Desktop),
                "{code:?}"
            );
        }
        assert!(!inj.press_may_hold(&key("KeyA"), &game));
        assert!(!inj.press_may_hold(&InputMessage::Down { b: 0 }, &game));
    }
}
