//! Key auto-repeat for keys held through `SendInput`.
//!
//! ## Why the agent repeats keys itself
//!
//! A keyboard does not repeat keys; its host does. The USB HID class leaves «Repeat Rate and Delay
//! Before First Repeat» to the host (HID 1.11, Appendix C), and on Windows the HID keyboard mapper
//! driver (`kbdhid.sys`) runs that timer, with the delay and rate set in Control Panel. So a key held
//! through the FakerInput virtual keyboard repeats by itself, exactly like a physical one, and
//! nothing here touches it. A key pressed through `SendInput` never passes through a keyboard
//! driver: Windows records it as down and that is all — it does not repeat. The Mini App holds a key
//! while the finger is on its button (`k d=1` … `k d=0`) and sends no repeats of its own, so on the
//! `SendInput` path holding Backspace deleted one character.
//!
//! ## What repeats, and what stops it — a physical keyboard's rules
//!
//! * Only the last key pressed repeats; modifiers and lock keys never do ([`auto_repeats`]).
//! * The first repeat comes after the keyboard delay, then one every repeat interval — Windows' own
//!   settings (`SPI_GETKEYBOARDDELAY`, `SPI_GETKEYBOARDSPEED`), read at each press, so a change in
//!   Control Panel applies at once ([`RepeatTiming::from_settings`]).
//! * Releasing that key, pressing any other key (on either path), `release_all` and the end of the
//!   session stop it. Releasing some other key does not, nor does a second press of a modifier that
//!   is already down.
//! * A physical keyboard at the viewer repeats in the browser, which sends `k d=1` again for the
//!   same key. Each such repeat is injected as it comes and pushes the emulated one a whole delay
//!   away, so while the viewer repeats, its stream is the only one — never two interleaved.
//!   Emulation takes over only if the viewer goes quiet for a delay with the key still down.
//!
//! ## The thread, and why a repeat cannot strand a key
//!
//! One worker thread per injector, alive only while a key repeats: it sleeps on a condition
//! variable until the next repeat is due and exits as soon as nothing repeats, so the end of a
//! session — which releases everything — leaves no thread behind. The input path only updates the
//! state machine ([`Repeater`]) and wakes the worker; it never waits for a repeat.
//!
//! The worker presses a key again only through [`Sink::repeat`], which does it under the injector's
//! held-key ledger lock and only while the key is in the ledger; every release takes the key out of
//! the ledger (under that lock) before its key-up is sent. So a repeat goes out before the key-up or
//! not at all — never a key-down after the release, which would leave the key down on the owner's
//! desktop. Lock order: the repeat state, then the ledger; nothing takes them the other way round.

use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use afklink_core::sync::lock;

/// A key as the held-key ledger names it: `(virtual_key, extended)` from `code_to_vk`.
pub(crate) type Vk = (u16, bool);

/// Whether a key auto-repeats when held: everything but the modifiers and the lock keys. A real
/// keyboard does send repeats of Shift, but nothing reads them; a repeated Caps Lock would at best
/// do nothing and at worst toggle.
pub(crate) fn auto_repeats(vk: u16) -> bool {
    // Shift, Ctrl and Alt (generic, then left/right), the two Windows keys; Caps, Num, Scroll Lock.
    !matches!(
        vk,
        0x10..=0x12 | 0xA0..=0xA5 | 0x5B | 0x5C | 0x14 | 0x90 | 0x91
    )
}

/// Windows' default keyboard delay setting (500 ms), used where it cannot be read.
const DEFAULT_DELAY_SETTING: u32 = 1;
/// Windows' default keyboard speed setting (30 a second), used where it cannot be read.
const DEFAULT_SPEED_SETTING: u32 = 31;

/// The keyboard delay before the first repeat and the interval between repeats.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RepeatTiming {
    pub(crate) delay: Duration,
    pub(crate) interval: Duration,
}

impl RepeatTiming {
    /// From Windows' keyboard settings, as `SystemParametersInfo` documents them:
    /// `SPI_GETKEYBOARDDELAY` is 0 (about 250 ms) through 3 (about 1 s), so `(setting + 1) × 250
    /// ms`; `SPI_GETKEYBOARDSPEED` is 0 (about 2.5 repeats a second) through 31 (about 30), taken
    /// as linear between the two. Out-of-range values are clamped.
    pub(crate) fn from_settings(delay: u32, speed: u32) -> Self {
        let delay = Duration::from_millis(250 * (u64::from(delay.min(3)) + 1));
        let per_second = 2.5 + f64::from(speed.min(31)) * (30.0 - 2.5) / 31.0;
        Self {
            delay,
            interval: Duration::from_secs_f64(1.0 / per_second),
        }
    }

    /// Windows' defaults: delay 1 (500 ms), speed 31 (30 a second, ~33 ms). Off Windows, where
    /// there are no settings to read (nor anything to repeat).
    #[cfg(any(not(windows), test))]
    pub(crate) fn windows_default() -> Self {
        Self::from_settings(DEFAULT_DELAY_SETTING, DEFAULT_SPEED_SETTING)
    }

    fn delay_ms(&self) -> u64 {
        millis(self.delay)
    }

    fn interval_ms(&self) -> f64 {
        self.interval.as_secs_f64() * 1000.0
    }
}

fn millis(d: Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
}

/// The auto-repeat state machine: which key repeats and when next. Pure — time comes in as
/// arguments — so the timer logic is tested without threads or `SendInput`.
///
/// Logs never name the key: it may be part of a password.
#[derive(Debug, Default)]
pub(crate) struct Repeater {
    active: Option<Active>,
}

#[derive(Debug)]
struct Active {
    key: Vk,
    timing: RepeatTiming,
    /// When the next emulated repeat is due.
    next: Instant,
    /// When the key was pressed, for the stop line's `held_ms`.
    pressed: Instant,
    /// Emulated repeats sent.
    repeats: u32,
    /// The viewer's own repeats of this key.
    viewer_repeats: u32,
}

impl Repeater {
    /// A key-down went out through `SendInput`. `repeats` says whether this key auto-repeats at all
    /// ([`auto_repeats`]); `was_held` whether it was already down before this press. `timing` is
    /// asked only when a new repeat is armed.
    pub(crate) fn press(
        &mut self,
        key: Vk,
        repeats: bool,
        was_held: bool,
        now: Instant,
        timing: impl FnOnce() -> RepeatTiming,
    ) {
        if let Some(active) = self.active.as_mut() {
            if active.key == key {
                // The viewer's own repeat (a physical keyboard at the viewer): it was injected as it
                // came; the emulation steps a whole delay back so the two never interleave.
                active.next = now + active.timing.delay;
                active.viewer_repeats = active.viewer_repeats.saturating_add(1);
                if active.viewer_repeats == 1 {
                    tracing::debug!(
                        emulated_so_far = active.repeats,
                        "the viewer repeats the held key itself: emulated repeat yields while it does"
                    );
                } else {
                    tracing::trace!(
                        viewer_repeats = active.viewer_repeats,
                        "viewer's key repeat: emulated repeat postponed by the delay"
                    );
                }
                return;
            }
        }
        if !repeats {
            if was_held {
                // A modifier already down, pressed again: nothing new was pressed.
                tracing::trace!("a held modifier pressed again: auto-repeat state unchanged");
            } else {
                self.stop("modifier or lock key pressed", now);
            }
            return;
        }
        // Another key: it takes the repeat over, after its own delay.
        self.stop("another key pressed", now);
        let timing = timing();
        tracing::trace!(
            delay_ms = timing.delay_ms(),
            interval_ms = timing.interval_ms(),
            "key auto-repeat armed"
        );
        self.active = Some(Active {
            key,
            timing,
            next: now + timing.delay,
            pressed: now,
            repeats: 0,
            viewer_repeats: 0,
        });
    }

    /// A key-down went out through the HID driver. Windows repeats that key itself, and like a
    /// physical keyboard's new key it ends the repeat here — unless it is a modifier that was
    /// already down.
    pub(crate) fn other_path_press(&mut self, modifier: bool, was_held: bool, now: Instant) {
        if self.active.is_none() {
            return;
        }
        if modifier && was_held {
            tracing::trace!("a held HID modifier pressed again: auto-repeat state unchanged");
            return;
        }
        self.stop("a key pressed through the driver", now);
    }

    /// A key-up went out. Only the repeating key's own release stops the repeat.
    pub(crate) fn release(&mut self, key: Vk, now: Instant) {
        if self.active.as_ref().is_some_and(|a| a.key == key) {
            self.stop("key released", now);
        }
    }

    /// Stop repeating, if anything repeats. A repeat that fired is reported at `debug` (its start
    /// was); one stopped before its first repeat — an ordinary key tap — only at `trace`.
    pub(crate) fn stop(&mut self, reason: &'static str, now: Instant) {
        let Some(active) = self.active.take() else {
            return;
        };
        let held_ms = millis(now.saturating_duration_since(active.pressed));
        if active.repeats > 0 {
            tracing::debug!(
                reason,
                repeats = active.repeats,
                viewer_repeats = active.viewer_repeats,
                held_ms,
                "key auto-repeat stopped"
            );
        } else {
            tracing::trace!(
                reason,
                viewer_repeats = active.viewer_repeats,
                held_ms,
                "key auto-repeat disarmed before its first repeat"
            );
        }
    }

    /// When the next repeat is due, or `None` when nothing repeats.
    pub(crate) fn due(&self) -> Option<Instant> {
        self.active.as_ref().map(|a| a.next)
    }

    /// The key to press again if a repeat is due at `now`, scheduling the next one. A late wake-up
    /// sends one repeat, not a burst of the missed ones: the next is an interval after `now`.
    pub(crate) fn fire(&mut self, now: Instant) -> Option<Vk> {
        let active = self.active.as_mut()?;
        if now < active.next {
            return None;
        }
        let late = now.saturating_duration_since(active.next);
        active.repeats = active.repeats.saturating_add(1);
        if active.repeats == 1 {
            tracing::debug!(
                delay_ms = active.timing.delay_ms(),
                interval_ms = active.timing.interval_ms(),
                viewer_repeats = active.viewer_repeats,
                "key auto-repeat started (SendInput path: Windows does not repeat injected keys)"
            );
        }
        tracing::trace!(
            n = active.repeats,
            late_us = u64::try_from(late.as_micros()).unwrap_or(u64::MAX),
            "emulated key repeat"
        );
        active.next += active.timing.interval;
        if active.next <= now {
            active.next = now + active.timing.interval;
        }
        Some(active.key)
    }
}

/// Where the worker presses a key again.
pub(crate) trait Sink: Send + Sync {
    /// Press `key` again if it is still held, and say whether it was. It must check and press under
    /// the same lock every release takes to remove the key from the ledger (see the module docs).
    fn repeat(&self, key: Vk) -> bool;
}

/// The [`Repeater`] with its worker thread. One per `SendInputInjector` (clones share it).
pub(crate) struct Engine {
    state: Mutex<EngineState>,
    wake: Condvar,
    sink: Arc<dyn Sink>,
    /// Reads the keyboard delay and rate; Windows' settings in the agent, fixed ones in tests.
    timing: fn() -> RepeatTiming,
}

#[derive(Default)]
struct EngineState {
    machine: Repeater,
    /// A worker thread is running (it clears this itself as it exits).
    worker: bool,
}

impl Engine {
    pub(crate) fn new(sink: Arc<dyn Sink>, timing: fn() -> RepeatTiming) -> Self {
        Self {
            state: Mutex::new(EngineState::default()),
            wake: Condvar::new(),
            sink,
            timing,
        }
    }

    /// A key-down went out through `SendInput` (see [`Repeater::press`]). Starts the worker when a
    /// repeat is armed and none runs.
    pub(crate) fn press(self: &Arc<Self>, key: Vk, repeats: bool, was_held: bool) {
        let mut state = lock(&self.state);
        state
            .machine
            .press(key, repeats, was_held, Instant::now(), self.timing);
        self.ensure_worker(&mut state);
        drop(state);
        self.wake.notify_all();
    }

    /// A key-down went out through the HID driver (see [`Repeater::other_path_press`]).
    pub(crate) fn other_path_press(&self, modifier: bool, was_held: bool) {
        lock(&self.state)
            .machine
            .other_path_press(modifier, was_held, Instant::now());
        self.wake.notify_all();
    }

    /// A key-up went out through `SendInput` (see [`Repeater::release`]).
    pub(crate) fn release(&self, key: Vk) {
        lock(&self.state).machine.release(key, Instant::now());
        self.wake.notify_all();
    }

    /// Stop any repeat; the worker wakes and exits.
    pub(crate) fn stop(&self, reason: &'static str) {
        lock(&self.state).machine.stop(reason, Instant::now());
        self.wake.notify_all();
    }

    #[cfg(test)]
    pub(crate) fn worker_running(&self) -> bool {
        lock(&self.state).worker
    }

    fn ensure_worker(self: &Arc<Self>, state: &mut EngineState) {
        if state.worker || state.machine.due().is_none() {
            return;
        }
        let engine = Arc::clone(self);
        // Spawned under the state lock: the thread's first act is to take it, so it starts only
        // after this press is fully recorded.
        match std::thread::Builder::new()
            .name("afklink-key-repeat".into())
            .spawn(move || engine.run())
        {
            Ok(_) => {
                state.worker = true;
                tracing::trace!("key repeat worker started");
            }
            Err(error) => {
                tracing::warn!(
                    %error,
                    "key auto-repeat unavailable: its thread did not start; the key stays held without repeating"
                );
                state
                    .machine
                    .stop("worker thread did not start", Instant::now());
            }
        }
    }

    /// The worker: sleep until the next repeat is due, press, repeat; exit when nothing repeats.
    fn run(self: Arc<Self>) {
        let mut state = lock(&self.state);
        loop {
            let Some(due) = state.machine.due() else {
                state.worker = false;
                tracing::trace!("key repeat worker exits: nothing repeats");
                return;
            };
            let now = Instant::now();
            if now < due {
                // Woken early by any change (a stop, a viewer repeat, another key): look again.
                state = match self.wake.wait_timeout(state, due - now) {
                    Ok((guard, _)) => guard,
                    Err(poisoned) => poisoned.into_inner().0,
                };
                continue;
            }
            if let Some(key) = state.machine.fire(now) {
                // Under the repeat lock, so a stop cannot slip between the decision and the press.
                if !self.sink.repeat(key) {
                    state.machine.stop("key no longer held", now);
                }
            }
        }
    }
}

/// Windows' keyboard delay and repeat rate, read now (a change in Control Panel applies to the next
/// press). A setting that cannot be read falls back to Windows' default: `warn` the first time in
/// the process, `trace` after.
#[cfg(windows)]
pub(crate) fn system_timing() -> RepeatTiming {
    use std::sync::atomic::{AtomicBool, Ordering};
    use windows::Win32::UI::WindowsAndMessaging::{
        SystemParametersInfoW, SPI_GETKEYBOARDDELAY, SPI_GETKEYBOARDSPEED,
        SYSTEM_PARAMETERS_INFO_UPDATE_FLAGS,
    };
    static WARNED: AtomicBool = AtomicBool::new(false);
    let failed = |setting: &'static str, error: windows::core::Error| {
        if WARNED.swap(true, Ordering::Relaxed) {
            tracing::trace!(setting, %error, "keyboard repeat setting unreadable; Windows' default used");
        } else {
            tracing::warn!(setting, %error, "keyboard repeat setting unreadable; Windows' default used");
        }
    };

    // `pvParam` is an `int` for the delay and a `DWORD` for the speed, as the API documents them.
    const DEFAULT_DELAY: i32 = DEFAULT_DELAY_SETTING as i32;
    let mut delay: i32 = DEFAULT_DELAY;
    let mut speed: u32 = DEFAULT_SPEED_SETTING;
    // SAFETY: `pvParam` points at a live integer of the documented type; nothing else is written.
    if let Err(error) = unsafe {
        SystemParametersInfoW(
            SPI_GETKEYBOARDDELAY,
            0,
            Some((&mut delay as *mut i32).cast()),
            SYSTEM_PARAMETERS_INFO_UPDATE_FLAGS(0),
        )
    } {
        failed("delay", error);
        delay = DEFAULT_DELAY;
    }
    // SAFETY: as above.
    if let Err(error) = unsafe {
        SystemParametersInfoW(
            SPI_GETKEYBOARDSPEED,
            0,
            Some((&mut speed as *mut u32).cast()),
            SYSTEM_PARAMETERS_INFO_UPDATE_FLAGS(0),
        )
    } {
        failed("speed", error);
        speed = DEFAULT_SPEED_SETTING;
    }
    let timing =
        RepeatTiming::from_settings(u32::try_from(delay).unwrap_or(DEFAULT_DELAY_SETTING), speed);
    tracing::trace!(
        delay_setting = delay,
        speed_setting = speed,
        delay_ms = timing.delay_ms(),
        interval_ms = timing.interval_ms(),
        "keyboard repeat settings"
    );
    timing
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

    const A: Vk = (0x41, false);
    const B: Vk = (0x42, false);
    const SHIFT: Vk = (0xA0, false);

    fn timing() -> RepeatTiming {
        RepeatTiming {
            delay: Duration::from_millis(500),
            interval: Duration::from_millis(40),
        }
    }

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    /// Every repeat `fire` gives between `from` and `to` (inclusive), checked each millisecond.
    fn fired(r: &mut Repeater, t0: Instant, from: u64, to: u64) -> Vec<(u64, Vk)> {
        (from..=to)
            .filter_map(|t| r.fire(t0 + ms(t)).map(|k| (t, k)))
            .collect()
    }

    #[test]
    fn settings_map_to_windows_documented_timings() {
        let fastest = RepeatTiming::from_settings(0, 31);
        assert_eq!(fastest.delay, ms(250));
        assert!((fastest.interval.as_secs_f64() - 1.0 / 30.0).abs() < 1e-6);
        let slowest = RepeatTiming::from_settings(3, 0);
        assert_eq!(slowest.delay, ms(1000));
        assert!((slowest.interval.as_secs_f64() - 0.4).abs() < 1e-6);
        assert_eq!(RepeatTiming::windows_default().delay, ms(500));
        assert_eq!(
            RepeatTiming::from_settings(99, 999),
            RepeatTiming::from_settings(3, 31),
            "out of range is clamped"
        );
    }

    #[test]
    fn modifiers_and_locks_never_repeat() {
        for code in [
            "ShiftLeft",
            "ShiftRight",
            "ControlLeft",
            "ControlRight",
            "AltLeft",
            "AltRight",
            "MetaLeft",
            "MetaRight",
            "CapsLock",
            "NumLock",
            "ScrollLock",
        ] {
            let (vk, _) = crate::code_to_vk(code).unwrap();
            assert!(!auto_repeats(vk), "{code}");
        }
        for code in [
            "KeyA",
            "Backspace",
            "Delete",
            "ArrowLeft",
            "Space",
            "Enter",
            "Digit1",
            "F5",
        ] {
            let (vk, _) = crate::code_to_vk(code).unwrap();
            assert!(auto_repeats(vk), "{code}");
        }
    }

    #[test]
    fn a_held_key_repeats_after_the_delay_at_the_interval() {
        let t0 = Instant::now();
        let mut r = Repeater::default();
        r.press(A, true, false, t0, timing);
        assert!(
            fired(&mut r, t0, 0, 499).is_empty(),
            "nothing before the delay"
        );
        let got = fired(&mut r, t0, 500, 620);
        assert_eq!(got, vec![(500, A), (540, A), (580, A), (620, A)]);
        r.release(A, t0 + ms(630));
        assert_eq!(r.due(), None);
        assert!(fired(&mut r, t0, 630, 2000).is_empty());
    }

    #[test]
    fn a_late_wake_up_sends_one_repeat_not_a_burst() {
        let t0 = Instant::now();
        let mut r = Repeater::default();
        r.press(A, true, false, t0, timing);
        assert_eq!(r.fire(t0 + ms(900)), Some(A));
        assert_eq!(r.fire(t0 + ms(900)), None);
        assert_eq!(r.due(), Some(t0 + ms(940)));
    }

    #[test]
    fn the_viewers_own_repeats_hold_the_emulation_off() {
        // A physical keyboard at the viewer: its browser repeats every 33 ms after 300 ms.
        let t0 = Instant::now();
        let mut r = Repeater::default();
        r.press(A, true, false, t0, timing);
        let mut t = 300;
        while t <= 3000 {
            assert!(
                fired(&mut r, t0, t - 32, t - 1).is_empty(),
                "no emulated repeat at {t}"
            );
            r.press(A, true, true, t0 + ms(t), timing);
            t += 33;
        }
        let last = t - 33;
        // The viewer stops repeating with the key still down: emulation resumes a delay later.
        assert!(fired(&mut r, t0, last, last + 499).is_empty());
        assert_eq!(r.fire(t0 + ms(last + 500)), Some(A));
    }

    #[test]
    fn a_first_viewer_repeat_arriving_early_postpones_the_first_emulated_one() {
        let t0 = Instant::now();
        let mut r = Repeater::default();
        r.press(A, true, false, t0, timing);
        r.press(A, true, true, t0 + ms(450), timing);
        assert!(fired(&mut r, t0, 450, 949).is_empty());
        assert_eq!(r.fire(t0 + ms(950)), Some(A));
    }

    #[test]
    fn another_key_takes_the_repeat_over_after_its_own_delay() {
        let t0 = Instant::now();
        let mut r = Repeater::default();
        r.press(A, true, false, t0, timing);
        assert_eq!(r.fire(t0 + ms(500)), Some(A));
        r.press(B, true, false, t0 + ms(510), timing);
        assert!(fired(&mut r, t0, 510, 1009).is_empty(), "B waits its delay");
        assert_eq!(r.fire(t0 + ms(1010)), Some(B));
        // Releasing the key that stopped repeating changes nothing.
        r.release(A, t0 + ms(1020));
        assert_eq!(r.fire(t0 + ms(1050)), Some(B));
        r.release(B, t0 + ms(1060));
        assert_eq!(r.due(), None);
    }

    #[test]
    fn a_modifier_stops_the_repeat_and_never_repeats_itself() {
        let t0 = Instant::now();
        let mut r = Repeater::default();
        // Shift alone arms nothing.
        r.press(SHIFT, false, false, t0, timing);
        assert_eq!(r.due(), None);
        // Shift held, then A: A repeats (a shifted A)…
        r.press(A, true, false, t0 + ms(10), timing);
        // …and Shift pressed again while held (a re-sent modifier) does not stop it.
        r.press(SHIFT, false, true, t0 + ms(20), timing);
        assert_eq!(r.fire(t0 + ms(510)), Some(A));
        // Releasing Shift does not stop it either (the A continues, unshifted).
        r.release(SHIFT, t0 + ms(520));
        assert_eq!(r.fire(t0 + ms(550)), Some(A));
        // A fresh modifier press does.
        r.press((0xA2, false), false, false, t0 + ms(560), timing);
        assert_eq!(r.due(), None);
    }

    #[test]
    fn a_press_on_the_hid_path_stops_the_repeat_unless_it_is_a_held_modifier() {
        let t0 = Instant::now();
        let mut r = Repeater::default();
        r.press(A, true, false, t0, timing);
        r.other_path_press(true, true, t0 + ms(10));
        assert!(r.due().is_some(), "a held HID modifier pressed again");
        r.other_path_press(true, false, t0 + ms(20));
        assert_eq!(r.due(), None, "a new HID modifier");
        r.press(A, true, false, t0 + ms(30), timing);
        r.other_path_press(false, false, t0 + ms(40));
        assert_eq!(r.due(), None, "a new HID key");
    }

    #[test]
    fn stop_is_idempotent() {
        let t0 = Instant::now();
        let mut r = Repeater::default();
        r.stop("release_all", t0);
        r.press(A, true, false, t0, timing);
        r.stop("release_all", t0 + ms(1));
        r.stop("release_all", t0 + ms(2));
        assert_eq!(r.due(), None);
        assert_eq!(r.fire(t0 + ms(5000)), None);
    }

    // The worker, with a recording sink instead of `SendInput` and short real timings.

    struct Recorder {
        held: AtomicBool,
        repeats: AtomicU32,
    }

    impl Sink for Recorder {
        fn repeat(&self, _: Vk) -> bool {
            if !self.held.load(Ordering::SeqCst) {
                return false;
            }
            self.repeats.fetch_add(1, Ordering::SeqCst);
            true
        }
    }

    fn fast() -> RepeatTiming {
        RepeatTiming {
            delay: ms(20),
            interval: ms(5),
        }
    }

    fn engine() -> (Arc<Engine>, Arc<Recorder>) {
        let sink = Arc::new(Recorder {
            held: AtomicBool::new(true),
            repeats: AtomicU32::new(0),
        });
        (Arc::new(Engine::new(sink.clone(), fast)), sink)
    }

    /// Wait (up to 5 s) for `cond`.
    fn eventually(cond: impl Fn() -> bool) -> bool {
        let until = Instant::now() + Duration::from_secs(5);
        while Instant::now() < until {
            if cond() {
                return true;
            }
            std::thread::sleep(ms(2));
        }
        cond()
    }

    #[test]
    fn the_worker_repeats_until_released_then_exits() {
        let (engine, sink) = engine();
        engine.press(A, true, false);
        assert!(engine.worker_running());
        assert!(eventually(|| sink.repeats.load(Ordering::SeqCst) >= 3));
        engine.release(A);
        assert!(
            eventually(|| !engine.worker_running()),
            "no thread outlives the repeat"
        );
        let after = sink.repeats.load(Ordering::SeqCst);
        std::thread::sleep(ms(60));
        assert_eq!(sink.repeats.load(Ordering::SeqCst), after);
        // A later hold starts a fresh worker.
        engine.press(B, true, false);
        assert!(eventually(|| sink.repeats.load(Ordering::SeqCst) > after));
        engine.stop("release_all");
        assert!(eventually(|| !engine.worker_running()));
    }

    #[test]
    fn the_worker_stops_by_itself_when_the_key_is_no_longer_held() {
        let (engine, sink) = engine();
        sink.held.store(false, Ordering::SeqCst);
        engine.press(A, true, false);
        assert!(eventually(|| !engine.worker_running()));
        assert_eq!(sink.repeats.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn a_modifier_starts_no_worker() {
        let (engine, _) = engine();
        engine.press(SHIFT, false, false);
        assert!(!engine.worker_running());
    }
}
