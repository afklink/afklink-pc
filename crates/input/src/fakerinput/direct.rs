//! Direct HID access for a host that runs its own input policy on one input worker: checked
//! keyboard, mouse and text reports through the installed FakerInput device, each written through
//! the fenced writer (`platform::FencedDevice`) and refused once the host's authority is gone.

use std::collections::BTreeSet;
use std::sync::atomic::{AtomicBool, AtomicU64};
use std::sync::Arc;
use std::time::{Duration, Instant};

use afklink_protocol::WheelMode;
use anyhow::{ensure, Result};
use windows::Win32::Foundation::{HWND, LPARAM, WPARAM};
use windows::Win32::UI::Input::KeyboardAndMouse::GetKeyboardLayout;
use windows::Win32::UI::WindowsAndMessaging::{
    GetWindowThreadProcessId, PostMessageW, WM_INPUTLANGCHANGEREQUEST,
};

use super::mouse_kernel::{split_axes, MouseKernel};
use super::typing::{self, Hkl, Keyboard, LanguageHotkey, Stroke};
use super::{absolute_mouse, absolute_wire, key, keyboard, layouts, mouse, platform, Key, Target};
use crate::cursor_sync::{
    system::SystemCursor, target_pixel, CursorLook, CursorSync, CursorWorld, ForegroundInfo, Mode,
    Plan, PointerSettings, RelEvent, RelPath, Space,
};
use crate::wheel::{HID_PIXELS_PER_NOTCH, PIXELS_PER_NOTCH, STEPPED_CARRY_PAUSE};
use crate::RelCarry;
use platform::NeutralReport;

pub const HID_TEXT_LIMIT: usize = 64;
const CLEANUP_RETRY: Duration = Duration::from_millis(10);
const MAX_HID_MOTION_COMPONENT: i32 = 256;
const MAX_HID_WHEEL_COMPONENT: i32 = 16;

/// The ordinary cursor planner without either ordinary injector. The private worker
/// owns admission and writes each resulting report through its own checked device.
#[derive(Default)]
pub struct HidCursor {
    sync: CursorSync,
    carry: RelCarry,
}

pub enum HidCursorPlan {
    Absolute(i32, i32),
    Relative(i32, i32),
    PointAtRest(i32, i32),
    Nothing,
    Camera(i32, i32),
}

/// Both snapshots are in physical pixels, taken by the host's input worker.
pub struct HidCursorLook {
    pub position: (i32, i32),
    pub visible: bool,
    pub screen: (i32, i32),
    pub client: [i32; 4],
}

impl HidCursorLook {
    pub fn on_primary(&self) -> bool {
        on_primary(self.position, self.screen)
    }
}

fn on_primary((x, y): (i32, i32), (width, height): (i32, i32)) -> bool {
    (0..width).contains(&x) && (0..height).contains(&y)
}

impl CursorWorld for HidCursorLook {
    fn look(&mut self) -> Result<CursorLook, String> {
        Ok(CursorLook {
            x: self.position.0,
            y: self.position.1,
            showing: self.visible,
            suppressed: false,
        })
    }

    fn screen(&mut self) -> (i32, i32) {
        self.screen
    }

    fn settings(&mut self) -> Result<PointerSettings, String> {
        SystemCursor.settings()
    }

    fn foreground(&mut self) -> usize {
        SystemCursor.foreground()
    }

    fn describe_foreground(&mut self, window: usize) -> ForegroundInfo {
        SystemCursor.describe_foreground(window)
    }
}

impl HidCursor {
    pub fn screen() -> (i32, i32) {
        platform::screen_size()
    }

    pub fn target(
        [left, top, right, bottom]: [i32; 4],
        screen: (i32, i32),
        target: (f64, f64),
    ) -> Option<(i32, i32)> {
        let space = Space::from_edges(left, top, right, bottom)?;
        let (x, y) = target_pixel(target, space.width, space.height);
        let point = (left.checked_add(x)?, top.checked_add(y)?);
        // The ordinary planner clips its space to the primary monitor. A direct click must
        // keep the actual captured pixel, even if the window spans two monitors.
        on_primary(point, screen).then_some(point)
    }

    pub fn absolute(
        &mut self,
        target: (f64, f64),
        mut look: HidCursorLook,
        now: Instant,
    ) -> Option<(i32, i32)> {
        let intended = Self::target(look.client, look.screen, target)?;
        let [left, top, right, bottom] = look.client;
        let space = Space::from_edges(left, top, right, bottom)?;
        self.sync.set_space(Some(space), now);
        self.sync
            .absolute(target, RelPath::Hid, &mut look, now)
            .and_then(|(x, y, _, _)| ((x, y) == intended).then_some(intended))
    }

    pub fn relative(
        &mut self,
        delta: (f64, f64),
        target: Option<(f64, f64)>,
        seq: Option<u32>,
        held: bool,
        mut look: HidCursorLook,
        now: Instant,
    ) -> Option<HidCursorPlan> {
        let intended = match (look.visible, target) {
            (true, Some(target)) => Some(Self::target(look.client, look.screen, target)?),
            _ => None,
        };
        let [left, top, right, bottom] = look.client;
        let space = Space::from_edges(left, top, right, bottom)?;
        self.sync.set_space(Some(space), now);
        if look.visible && !look.on_primary() {
            let intended = intended?;
            let (x, y, _, _) =
                self.sync
                    .absolute_numbered(target?, seq, RelPath::Hid, &mut look, now)?;
            tracing::trace!(target: afklink_core::EMBED_LOG_TARGET, "re-anchoring a visible off-primary cursor");
            return ((x, y) == intended).then_some(HidCursorPlan::Absolute(x, y));
        }
        let event = RelEvent {
            dx: delta.0,
            dy: delta.1,
            x: target.map(|(x, _)| x),
            y: target.map(|(_, y)| y),
            s: seq,
        };
        let plan = self.sync.plan(event, held, RelPath::Hid, &mut look, now);
        Some(match plan {
            Plan::Absolute { px, py, .. } if intended == Some((px, py)) => {
                HidCursorPlan::Absolute(px, py)
            }
            Plan::Absolute { .. } => return None,
            Plan::Relative { cx, cy } => HidCursorPlan::Relative(cx, cy),
            Plan::Nothing if self.sync.mode() == Some(Mode::Point) => {
                let (x, y) = intended?;
                HidCursorPlan::PointAtRest(x, y)
            }
            Plan::Nothing => HidCursorPlan::Nothing,
            Plan::Camera => {
                let (width, height) = look.screen;
                // The host's mailbox can coalesce multiple ordinary, one-screen deltas.
                let pieces = delta.0.abs().max(delta.1.abs()).ceil().max(1.0) as u32;
                let (mut x, mut y) = (0i32, 0i32);
                for piece in 0..pieces {
                    let within_piece =
                        |v: f64| (v.abs() - f64::from(piece)).clamp(0.0, 1.0) * v.signum();
                    let (dx, dy) = self.carry.step(
                        within_piece(delta.0),
                        within_piece(delta.1),
                        width,
                        height,
                    );
                    x = x.saturating_add(dx);
                    y = y.saturating_add(dy);
                }
                HidCursorPlan::Camera(x, y)
            }
        })
    }

    pub fn unshown(&mut self, point: (i32, i32), visible: bool, now: Instant) -> Option<u32> {
        self.sync.flush_if_due(now);
        self.sync.note_visibility(visible, 0, now);
        self.sync.unshown(point, now)
    }

    pub fn failed(&mut self) {
        self.sync.failed("direct placement or movement refused");
        self.carry = RelCarry::default();
    }

    pub fn released(&mut self, now: Instant) {
        self.sync.release(now);
        self.carry = RelCarry::default();
    }
}

/// Ordinary HID mouse state with direct-access report chunks. The caller authorizes every
/// positive report and supplies the checked writer. No input or focus fallback is available.
#[derive(Default)]
pub struct HidMouse {
    kernel: MouseKernel,
    last_wheel: Option<(bool, Instant)>,
}

impl HidMouse {
    pub fn buttons(&self) -> u8 {
        self.kernel.buttons()
    }

    pub fn holds(&self, button: u8) -> bool {
        self.kernel.holds(button)
    }

    pub fn press(&mut self, button: u8, send: impl FnOnce(u8) -> Result<()>) -> Result<()> {
        let next = self
            .kernel
            .button_mask(button, true)
            .ok_or_else(|| anyhow::anyhow!("unsupported mouse button"))?;
        self.kernel.write_buttons(next, send)
    }

    pub fn release(
        &mut self,
        buttons: impl IntoIterator<Item = u8>,
        send: impl FnOnce(u8) -> Result<()>,
    ) -> Result<()> {
        let next = self.remaining_buttons(buttons)?;
        if next != self.kernel.buttons() {
            self.kernel.write_buttons(next, send)?;
        }
        Ok(())
    }

    pub fn remaining_buttons(&self, releases: impl IntoIterator<Item = u8>) -> Result<u8> {
        self.kernel
            .release_mask(releases)
            .ok_or_else(|| anyhow::anyhow!("unsupported mouse release"))
    }

    pub fn neutral(&mut self, send: impl FnOnce(u8) -> Result<()>) -> Result<()> {
        self.kernel.write_buttons(0, send)
    }

    pub fn neutral_confirmed(&mut self) {
        self.kernel.neutral_confirmed();
    }

    pub fn reset_wheel(&mut self, why: &'static str) {
        self.kernel.drop_wheel_carry(why);
        self.last_wheel = None;
    }

    pub fn motion_reports(x: i32, y: i32) -> impl Iterator<Item = (i16, i16)> {
        split_axes(x, y, MAX_HID_MOTION_COMPONENT).map(|(x, y)| (x as i16, y as i16))
    }

    pub fn wheel_reports(wheel: i32, pan: i32) -> impl Iterator<Item = (i8, i8)> {
        split_axes(wheel, pan, MAX_HID_WHEEL_COMPONENT).map(|(w, p)| (w as i8, p as i8))
    }

    /// Deltas are finite and mode-checked by the private input wire parser.
    pub fn wheel_step(
        &mut self,
        dx: f64,
        dy: f64,
        mode: u8,
        game: bool,
        now: Instant,
    ) -> Result<(i32, i32)> {
        if self.last_wheel.is_some_and(|(previous_game, at)| {
            game != previous_game
                || (!game && now.saturating_duration_since(at) >= STEPPED_CARRY_PAUSE)
        }) {
            self.kernel
                .drop_wheel_carry("direct wheel route or gesture changed");
        }
        self.last_wheel = Some((game, now));
        let mode = WheelMode::from_wire(Some(mode));
        let scale = if game {
            HID_PIXELS_PER_NOTCH
        } else {
            PIXELS_PER_NOTCH
        };
        let step = self.kernel.wheel_step(dx, dy, mode, scale)?;
        Ok((step.wheel, step.pan))
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct HidKey(Key);

impl HidKey {
    pub fn from_code(code: &str) -> Option<Self> {
        let key = key(code)?;
        match key {
            // Lock/toggle, print, pause, context-menu, system and consumer controls.
            Key::Usage(0x39 | 0x46..=0x48 | 0x53 | 0x65)
            | Key::Modifier(8 | 128)
            | Key::Media(_) => None,
            _ => Some(Self(key)),
        }
    }

    pub fn modifiers(keys: &BTreeSet<Self>) -> u8 {
        keys.iter().fold(0, |mask, key| match key.0 {
            Key::Modifier(bit) => mask | bit,
            _ => mask,
        })
    }

    pub fn rollover_ok(keys: &BTreeSet<Self>) -> bool {
        keys.iter()
            .filter(|key| matches!(key.0, Key::Usage(_)))
            .count()
            <= 6
    }

    /// Test the complete prospective chord, including sampled local state. The deny predicates
    /// are monotonic so pressing a modifier last, or releasing an unrelated key, cannot evade them.
    pub fn chord_allowed(
        keys: &BTreeSet<Self>,
        observed_modifiers: u8,
        observed_keys: &BTreeSet<Self>,
    ) -> bool {
        let mods = Self::modifiers(keys) | observed_modifiers;
        let ctrl = mods & 0x11 != 0;
        let shift = mods & 0x22 != 0;
        let alt = mods & 0x44 != 0;
        let has = |usage| {
            let key = Self(Key::Usage(usage));
            keys.contains(&key) || observed_keys.contains(&key)
        };
        !(mods & 0x88 != 0
            || (alt && (ctrl || shift || [0x29, 0x2b, 0x2c, 0x3d, 0x3f].into_iter().any(has)))
            || (ctrl && [0x06, 0x19, 0x1b, 0x29, 0x49].into_iter().any(has))
            || (shift && [0x43, 0x49, 0x4c].into_iter().any(has)))
    }
}

#[derive(Clone, Copy)]
pub struct HidTextStroke {
    layout: Hkl,
    stroke: Stroke,
}

impl HidTextStroke {
    pub fn uses_shift(self) -> bool {
        self.stroke.shift
    }

    pub fn layout_is(self, focus: usize) -> bool {
        layout(focus) == Some(self.layout)
    }

    /// The caller must revalidate this exact keyboard recipient immediately before posting.
    pub fn request_layout(self, focus: usize) -> Result<(), i32> {
        // SAFETY: focus was verified by the host's input worker, and this is an installed layout handle
        // with scalar message arguments. Posting neither waits nor changes the foreground window.
        unsafe {
            PostMessageW(
                Some(HWND(focus as *mut _)),
                WM_INPUTLANGCHANGEREQUEST,
                WPARAM(layouts::charset_flag(self.layout)),
                LPARAM(self.layout.0 as isize),
            )
        }
        .map_err(|error| error.code().0)
    }

    pub fn language_switch(self, focus: usize) -> Option<HidLanguageSwitch> {
        let current = layout(focus)?;
        let hotkey = match layouts::language_hotkey_setting() {
            Ok(hotkey) => hotkey,
            Err(error) => {
                // not-a-key-name: Win32 registry status code.
                tracing::debug!(target: afklink_core::EMBED_LOG_TARGET, code = error.0, "language hotkey setting unreadable");
                return None;
            }
        };
        let installed = layouts::WinKeyboard.installed_layouts();
        HidLanguageSwitch::new(current, self.layout, hotkey, &installed)
    }
}

/// Only the configured product layout chord is representable here. The viewer cannot construct
/// one or provide HID reports. The caller still verifies the exact game recipient per report.
#[derive(Clone, Copy)]
pub struct HidLanguageSwitch {
    hotkey: LanguageHotkey,
    target: Hkl,
    before: Hkl,
    remaining: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HidLayoutProgress {
    Ready,
    Waiting,
    Retry,
    Refused,
}

impl HidLanguageSwitch {
    fn new(current: Hkl, target: Hkl, hotkey: LanguageHotkey, installed: &[Hkl]) -> Option<Self> {
        if current.lang() == target.lang()
            || !installed.contains(&target)
            || typing::hotkey_reports(hotkey).is_empty()
        {
            return None;
        }
        Some(Self {
            hotkey,
            target,
            before: current,
            remaining: installed.len().min(8),
        })
    }

    pub fn report(self, index: usize) -> Option<(u8, Duration)> {
        typing::hotkey_reports(self.hotkey).get(index).copied()
    }

    pub fn observe(&mut self, focus: usize) -> HidLayoutProgress {
        self.observe_layout(layout(focus))
    }

    fn observe_layout(&mut self, current: Option<Hkl>) -> HidLayoutProgress {
        let Some(current) = current else {
            return HidLayoutProgress::Refused;
        };
        if current == self.target {
            return HidLayoutProgress::Ready;
        }
        if current == self.before {
            return HidLayoutProgress::Waiting;
        }
        if current.lang() == self.target.lang() || self.remaining <= 1 {
            return HidLayoutProgress::Refused;
        }
        self.remaining -= 1;
        self.before = current;
        HidLayoutProgress::Retry
    }
}

fn layout(focus: usize) -> Option<Hkl> {
    // SAFETY: window handle checked by Win32, no output pointer.
    let thread = unsafe { GetWindowThreadProcessId(HWND(focus as *mut _), None) };
    if thread == 0 {
        return None;
    }
    // SAFETY: known window thread ID.
    let layout = unsafe { GetKeyboardLayout(thread) };
    (!layout.0.is_null()).then_some(Hkl(layout.0 as usize))
}

pub struct DirectHid {
    device: platform::FencedDevice,
    local_stop: Arc<AtomicBool>,
    input_generation: Option<(Arc<AtomicU64>, u64)>,
    input_authority: Option<Arc<dyn Fn() -> bool + Send + Sync>>,
}

#[derive(Debug)]
pub struct HidInputPaused;

impl std::fmt::Display for HidInputPaused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("HID report refused after input pause")
    }
}

impl std::error::Error for HidInputPaused {}

impl DirectHid {
    pub fn open_installed(local_stop: Arc<AtomicBool>) -> Result<Self> {
        platform::FencedDevice::open()?
            .map(|device| Self {
                device,
                local_stop,
                input_generation: None,
                input_authority: None,
            })
            .ok_or_else(|| anyhow::anyhow!("the provisioned FakerInput device is not installed"))
    }

    pub fn bind_input_generation(&mut self, signal: Arc<AtomicU64>, generation: u64) {
        self.input_generation = Some((signal, generation));
    }

    pub fn bind_input_authority(&mut self, authority: Arc<dyn Fn() -> bool + Send + Sync>) {
        self.input_authority = Some(authority);
    }

    fn write(&self, report: &super::Report, positive: bool) -> Result<()> {
        if !positive {
            return self.device.write(report, None, None, None);
        }
        let (signal, generation) = self.input_generation.as_ref().ok_or(HidInputPaused)?;
        let authority = self.input_authority.as_deref().ok_or(HidInputPaused)?;
        self.device.write(
            report,
            Some(&self.local_stop),
            Some((signal, *generation)),
            Some(authority),
        )
    }

    pub fn console_has_input() -> bool {
        platform::evaluate_target().target == Target::Allowed
    }

    pub fn keyboard(&mut self, keys: &BTreeSet<HidKey>) -> Result<()> {
        ensure!(HidKey::rollover_ok(keys), "HID rollover limit");
        ensure!(
            HidKey::chord_allowed(keys, 0, &BTreeSet::new()),
            "HID chord outside policy"
        );
        let usages = keys
            .iter()
            .filter_map(|key| match key.0 {
                Key::Usage(usage) => Some(usage),
                _ => None,
            })
            .collect();
        self.write(
            &keyboard(HidKey::modifiers(keys), &usages),
            !keys.is_empty(),
        )
    }

    /// Resolve every character up front with the product's actual-layout HID mapper. Prefer the
    /// current layout, and keep it until a different installed layout is needed.
    /// No AltGr/system shortcut or Unicode/clipboard fallback.
    pub fn plan_text(text: &str, focus: usize) -> Option<Vec<HidTextStroke>> {
        let current = layout(focus)?;
        let mut keyboard = layouts::WinKeyboard;
        let layouts = keyboard.installed_layouts();
        let caps = layouts::caps_for_window(Some(HWND(focus as *mut _)));
        plan_text(text, current, &layouts, |c, layout| {
            typing::stroke_on(&mut keyboard, c, layout, caps).ok()
        })
    }

    pub fn text(&mut self, stroke: HidTextStroke, down: bool) -> Result<()> {
        let mut keys = BTreeSet::new();
        if down {
            keys.insert(stroke.stroke.usage);
        }
        self.write(
            &keyboard(if stroke.uses_shift() { 2 } else { 0 }, &keys),
            down || stroke.uses_shift(),
        )
    }

    pub fn language_hotkey(&mut self, switch: HidLanguageSwitch, index: usize) -> Result<()> {
        let (modifiers, _) = switch
            .report(index)
            .ok_or_else(|| anyhow::anyhow!("invalid language hotkey stage"))?;
        self.write(&keyboard(modifiers, &BTreeSet::new()), modifiers != 0)
    }

    pub fn mouse(&mut self, buttons: u8, x: i16, y: i16, wheel: i8, pan: i8) -> Result<()> {
        ensure!(
            buttons & !0b111 == 0
                && i32::from(x).abs() <= MAX_HID_MOTION_COMPONENT
                && i32::from(y).abs() <= MAX_HID_MOTION_COMPONENT
                && i32::from(wheel).abs() <= MAX_HID_WHEEL_COMPONENT
                && i32::from(pan).abs() <= MAX_HID_WHEEL_COMPONENT,
            "HID mouse report outside limits"
        );
        self.write(
            &mouse(buttons, x, y, wheel, pan),
            (buttons, x, y, wheel, pan) != (0, 0, 0, 0, 0),
        )
    }

    /// The caller has verified the physical target and game-owned route. The HID collection
    /// maps to the primary screen, so never clamp an out-of-range point into that screen.
    pub fn absolute_mouse(&mut self, x: i32, y: i32) -> Result<bool> {
        let (width, height) = platform::screen_size();
        let Some(report) = hid_absolute_report(x, y, width, height) else {
            return Ok(false);
        };
        self.write(&report, true)?;
        Ok(true)
    }

    pub fn reset(&mut self, deadline: Option<Instant>) -> Result<()> {
        if let Some(deadline) = deadline {
            return neutral_before(deadline, |kind| self.device.neutral(kind, deadline));
        }
        let keyboard = self.write(&keyboard(0, &BTreeSet::new()), false);
        let mouse = self.write(&mouse(0, 0, 0, 0, 0), false);
        keyboard.and(mouse)
    }
}

fn hid_absolute_report(x: i32, y: i32, width: i32, height: i32) -> Option<super::Report> {
    if !(0..width).contains(&x) || !(0..height).contains(&y) {
        return None;
    }
    let (x, y) = absolute_wire(x, y, width, height);
    Some(absolute_mouse(x, y))
}

/// The input worker owns both confirmations for one cleanup. A pending write still fences
/// the device, but a completed report is never sent again while waiting for the other one.
fn neutral_before(
    deadline: Instant,
    mut send: impl FnMut(NeutralReport) -> Result<()>,
) -> Result<()> {
    let mut remaining = [Some(NeutralReport::Keyboard), Some(NeutralReport::Mouse)];
    let mut rounds = 0;
    loop {
        rounds += 1;
        for report in &mut remaining {
            let Some(kind) = *report else { continue };
            if Instant::now() >= deadline {
                break;
            }
            match send(kind) {
                Ok(()) => *report = None,
                Err(error) => {
                    tracing::trace!(target: afklink_core::EMBED_LOG_TARGET, ?kind, %error, "neutral report still unconfirmed")
                }
            }
        }
        if Instant::now() >= deadline {
            tracing::warn!(target: afklink_core::EMBED_LOG_TARGET, rounds, keyboard = remaining[0].is_none(), mouse = remaining[1].is_none(), "neutral cleanup deadline elapsed");
            anyhow::bail!("neutral cleanup deadline elapsed");
        }
        if remaining.iter().all(Option::is_none) {
            tracing::debug!(target: afklink_core::EMBED_LOG_TARGET, rounds, "neutral cleanup confirmed");
            return Ok(());
        }
        std::thread::sleep(CLEANUP_RETRY.min(deadline.saturating_duration_since(Instant::now())));
    }
}

#[cfg(test)]
mod cleanup_tests {
    use super::*;

    #[test]
    fn neutral_retry_remembers_each_confirmed_report_and_attempts_both() {
        use NeutralReport::{Keyboard, Mouse};

        let mut calls = Vec::new();
        neutral_before(Instant::now() + Duration::from_secs(2), |kind| {
            calls.push(kind);
            match calls.len() {
                // A keyboard-specific error lets the mouse still make progress. Both reports
                // may need one more round to observe completion of their respective writes.
                1..=3 => anyhow::bail!("report not yet confirmed"),
                4 | 5 => Ok(()),
                _ => panic!("already confirmed report must not be sent again"),
            }
        })
        .unwrap();
        assert_eq!(calls, [Keyboard, Mouse, Keyboard, Mouse, Keyboard]);

        calls.clear();
        neutral_before(Instant::now() + Duration::from_secs(2), |kind| {
            calls.push(kind);
            if calls.len() == 2 {
                anyhow::bail!("mouse report still pending");
            }
            Ok(())
        })
        .unwrap();
        assert_eq!(calls, [Keyboard, Mouse, Mouse]);
    }

    #[test]
    fn neutral_retry_refuses_unconfirmed_or_late_reports() {
        let deadline = Instant::now() + Duration::from_millis(30);
        assert!(neutral_before(deadline, |_| {
            std::thread::sleep(deadline.saturating_duration_since(Instant::now()));
            Ok(())
        })
        .is_err());
        assert!(neutral_before(Instant::now(), |_| {
            panic!("must not submit after the cleanup deadline")
        })
        .is_err());
    }
}

fn plan_text(
    text: &str,
    mut preferred: Hkl,
    layouts: &[Hkl],
    mut map: impl FnMut(char, Hkl) -> Option<Stroke>,
) -> Option<Vec<HidTextStroke>> {
    if text.chars().any(char::is_control) {
        return None;
    }
    let normalized = typing::normalize(text);
    if normalized.newlines != 0 || !(1..=HID_TEXT_LIMIT).contains(&normalized.chars.len()) {
        return None;
    }
    normalized
        .chars
        .into_iter()
        .map(|c| {
            let stroke = std::iter::once(preferred)
                .chain(layouts.iter().copied().take(16))
                .find_map(|layout| {
                    let stroke = map(c, layout).filter(|stroke| !stroke.altgr)?;
                    Some(HidTextStroke { layout, stroke })
                })?;
            preferred = stroke.layout;
            Some(stroke)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::super::{fake, Host};
    use super::*;

    #[test]
    fn language_fallback_requires_exact_layout_and_only_configured_reports() {
        let en = Hkl(0x409);
        let ru = Hkl(0x419);
        let de = Hkl(0x407);
        let other_ru = Hkl(0x1234_0419);
        let installed = [en, ru, de, other_ru];
        for hotkey in [LanguageHotkey::Grave, LanguageHotkey::Off] {
            assert!(HidLanguageSwitch::new(en, ru, hotkey, &installed).is_none());
        }
        assert!(
            HidLanguageSwitch::new(ru, other_ru, LanguageHotkey::AltShift, &installed).is_none()
        );
        let mut alt = HidLanguageSwitch::new(en, ru, LanguageHotkey::AltShift, &installed).unwrap();
        assert_eq!(
            (0..4).map(|i| alt.report(i).unwrap().0).collect::<Vec<_>>(),
            [4, 6, 4, 0]
        );
        assert!(alt.report(4).is_none());
        assert_eq!(alt.observe_layout(Some(en)), HidLayoutProgress::Waiting);
        assert_eq!(alt.observe_layout(Some(de)), HidLayoutProgress::Retry);
        assert_eq!(
            alt.observe_layout(Some(other_ru)),
            HidLayoutProgress::Refused
        );
        assert_eq!(alt.observe_layout(Some(ru)), HidLayoutProgress::Ready);
        let ctrl = HidLanguageSwitch::new(en, ru, LanguageHotkey::CtrlShift, &installed).unwrap();
        assert_eq!(
            (0..4)
                .map(|i| ctrl.report(i).unwrap().0)
                .collect::<Vec<_>>(),
            [1, 3, 1, 0]
        );
    }

    #[test]
    fn mixed_latin_and_cyrillic_reuse_caps_aware_product_strokes() {
        let en = fake::us().hkl;
        let ru = fake::ru().hkl;
        let mut harness = fake::Harness::new();
        for caps in [false, true] {
            let plan = plan_text("AbЯя", en, &[en, ru], |ch, hkl| {
                typing::stroke_on(harness.rt.host.keyboard(), ch, hkl, caps).ok()
            })
            .unwrap();
            assert_eq!(
                plan.iter().map(|stroke| stroke.layout).collect::<Vec<_>>(),
                [en, en, ru, ru]
            );
            assert_eq!(
                plan.iter()
                    .map(|stroke| stroke.uses_shift())
                    .collect::<Vec<_>>(),
                [!caps, caps, !caps, caps]
            );
        }
    }

    #[test]
    fn text_plan_keeps_latin_and_cyrillic_order_and_rejects_controls() {
        let latin = Hkl(0x409);
        let cyrillic = Hkl(0x419);
        let map = |c: char, layout| {
            let supported = match c {
                ' ' => true,
                'a'..='z' | 'A'..='Z' => layout == latin,
                'а'..='я' | 'А'..='Я' => layout == cyrillic,
                _ => false,
            };
            supported.then_some(Stroke {
                usage: 4,
                shift: c.is_uppercase(),
                altgr: false,
            })
        };
        let plan = plan_text("Hi Да a", latin, &[latin, cyrillic], map).unwrap();
        assert_eq!(
            plan.iter().map(|s| s.layout.0).collect::<Vec<_>>(),
            [0x409, 0x409, 0x409, 0x419, 0x419, 0x419, 0x409]
        );
        assert!(plan[0].uses_shift() && plan[3].uses_shift());
        for bad in ["a\nb", "a\u{2028}b", "a\tb", "a😀", ""] {
            assert!(plan_text(bad, latin, &[latin, cyrillic], map).is_none());
        }
        assert!(plan_text(&"a".repeat(65), latin, &[latin], map).is_none());
    }

    #[test]
    fn absolute_report_reuses_the_product_pixel_mapping_and_rejects_off_primary() {
        let (x, y) = absolute_wire(1919, 1016, 1920, 1080);
        assert_eq!(
            hid_absolute_report(1919, 1016, 1920, 1080),
            Some(absolute_mouse(x, y))
        );
        for (x, y) in [(-1, 100), (1920, 100), (100, -1), (100, 1080)] {
            assert!(hid_absolute_report(x, y, 1920, 1080).is_none());
        }
        assert!(hid_absolute_report(0, 0, 0, 0).is_none());
    }
}
