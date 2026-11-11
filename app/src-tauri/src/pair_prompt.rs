//! The pairing request's window: when it is shown, its size and its place.
//!
//! A request is shown in one place only: the small always-on-top `pair-request` window near the
//! tray, whether the main window is open, minimized or in the tray. The main window never draws it,
//! so the request does not move as the main window is opened or hidden. The window is shown without
//! taking focus (`"focus": false` in `tauri.conf.json`), so a key meant for another app never lands
//! on it. An answer closes it at once ([`Router::answer`]), without waiting for the orchestrator to
//! clear the request.
//!
//! This module's thread decides; `get_status` hands the request (and its step) to both windows, and
//! only the request window draws it. The thread ticks every [`TICK`] and is woken at once by what
//! can change the answer: an answer, «Разрешить», the window's size report, the main window shown
//! from the tray (which brings back a request window closed by hand: [`PairPrompt::reveal`]). Both
//! windows get [`EVENT`] whenever a request is raised or goes, so neither waits for its next poll.
//!
//! A toast goes out only when the request window is missing or could not be shown: beside a shown
//! request window it would duplicate it, in the same corner.
//!
//! The window is sized to its content: the page reports its height (`fit_pair_window`) and the
//! window is shown only then, so it never appears empty or at a wrong size; after [`FIT_WAIT`]
//! without a report it is shown anyway at the last height known (a missing convenience, never a
//! missed decision). It goes to the work area's corner nearest the notification area
//! ([`popup_position`]), in physical pixels at the display scale times Windows' text size
//! ([`TextScale`]): by the display scale alone, at 150 % text its buttons would be cut off. The
//! size is read back and set again when it came out otherwise ([`size_exactly`]), and read again
//! once the window is shown.
//!
//! On a PC with no owner the prompt has two steps: «Отклонить» / «Разрешить», then «Кто это?» with
//! «Владелец» / «Гость» ([`PairStep`]). The step is decided here ([`PairPrompt::allow`]), so a
//! window reloaded meanwhile comes back at it; the window is sized for the step it shows, never by
//! a height reported for the other step ([`PairStep::default_height`] is the fallback).
//!
//! No lock here is held across a Tauri window call: a getter waits for the main thread, and the
//! main thread runs `get_status`, which takes the same lock.

use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager, PhysicalPosition, PhysicalSize, State, WebviewWindow};

use afklink_core::{AgentControl, PersonName};
use afklink_i18n::{Locale, NativeText};

/// The request window's label (`tauri.conf.json`).
pub const WINDOW: &str = "pair-request";

/// Sent to every window whenever a request is raised or goes, so each re-reads the status at once.
/// The payload is informational (`PromptEvent`); the status is what the windows draw.
pub const EVENT: &str = "pair-prompt";

/// The thread's pace when nothing wakes it — the same as the state watcher's.
const TICK: Duration = Duration::from_millis(500);

/// How long the request window waits for its page's height before it is shown anyway.
pub const FIT_WAIT: Duration = Duration::from_millis(1500);

/// The request window's width, in CSS (logical) pixels: within the 360–400 the design asks for.
pub const POPUP_WIDTH: u32 = 380;

/// Heights the page may ask for, CSS px: one line of title up to three, plus room for nothing odd.
const POPUP_MIN_HEIGHT: u32 = 96;
const POPUP_MAX_HEIGHT: u32 = 360;

/// Before the page has reported a height for «Отклонить» / «Разрешить»: its tallest. Measured in the
/// window's own page at 100, 125 and 150 %, which change nothing in CSS px: 144 for a title
/// of one line without a handle, 150 with one, 172 for two lines; and 194 for three lines — a long
/// name at 380 / 1.25 CSS px, the page's width under Windows' «Размер текста» 125 % (and 380 / 1.5
/// at 150 % draws no more lines). Room to spare under a shorter prompt is the card's own ground; a
/// button cut off is a prompt that cannot be answered; it is at least the tallest ordinary request,
/// 180. Placed at the text scale too ([`TextScale`]).
const POPUP_DEFAULT_HEIGHT: u32 = 196;

/// Before the page has reported a height for «Кто это?»: 170 CSS px whatever the name and the
/// scale (the question and the name are one line each, cut with an ellipsis), and a little over.
const POPUP_ROLE_DEFAULT_HEIGHT: u32 = 176;

/// Which of the prompt's steps a request is at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairStep {
    /// «Отклонить» / «Разрешить».
    Consent,
    /// «Кто это?» — «Владелец» / «Гость»: after «Разрешить» on a PC with no owner.
    Role,
}

impl PairStep {
    /// `PendingPairDto::step` and log fields.
    pub fn as_str(self) -> &'static str {
        match self {
            PairStep::Consent => "consent",
            PairStep::Role => "role",
        }
    }

    /// The window's spelling, from `fit_pair_window`.
    pub fn parse(s: &str) -> Option<PairStep> {
        match s {
            "consent" => Some(PairStep::Consent),
            "role" => Some(PairStep::Role),
            _ => None,
        }
    }

    /// The request window's height for this step before its page has reported one, CSS px.
    pub const fn default_height(self) -> u32 {
        match self {
            PairStep::Consent => POPUP_DEFAULT_HEIGHT,
            PairStep::Role => POPUP_ROLE_DEFAULT_HEIGHT,
        }
    }
}

/// Between the request window and the work area's edges, CSS px — the gap Windows leaves around
/// its own notifications.
const POPUP_MARGIN: u32 = 12;

// ---------- The decision ----------

/// A change of the request shown.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Change {
    /// A request to show: a new one, or one that replaced `replaced`.
    Raised {
        request_id: String,
        replaced: Option<String>,
    },
    /// Gone: answered here (`answered_here`), or withdrawn or expired by the server.
    Resolved {
        request_id: String,
        answered_here: bool,
    },
}

impl Change {
    /// The request shown after this change; `None` once it is gone.
    pub fn shown(&self) -> Option<&str> {
        match self {
            Change::Raised { request_id, .. } => Some(request_id.as_str()),
            Change::Resolved { .. } => None,
        }
    }

    pub fn request_id(&self) -> &str {
        match self {
            Change::Raised { request_id, .. } | Change::Resolved { request_id, .. } => request_id,
        }
    }
}

/// Which request is shown, across ticks.
#[derive(Debug, Default)]
pub struct Router {
    shown: Option<String>,
    /// A request answered, while the orchestrator may still hold it: it counts as gone, so the
    /// window closes at once. Forgotten when the pending request is another one.
    answered: Option<String>,
}

impl Router {
    /// The owner answered `request_id`.
    pub fn answer(&mut self, request_id: &str) {
        self.answered = Some(request_id.to_string());
    }

    /// Whether `request_id` is the one shown.
    pub fn is_shown(&self, request_id: &str) -> bool {
        self.shown.as_deref() == Some(request_id)
    }

    /// The request shown, if any.
    pub fn shown(&self) -> Option<&str> {
        self.shown.as_deref()
    }

    /// The pending request (the orchestrator's) now: the change, if any.
    pub fn update(&mut self, pending: Option<&str>) -> Option<Change> {
        let live = pending.filter(|id| self.answered.as_deref() != Some(*id));
        let change = match (self.shown.take(), live) {
            (None, None) => None,
            (None, Some(id)) => {
                self.shown = Some(id.to_string());
                Some(Change::Raised {
                    request_id: id.to_string(),
                    replaced: None,
                })
            }
            (Some(old), None) => {
                let answered_here = self.answered.as_deref() == Some(old.as_str());
                Some(Change::Resolved {
                    request_id: old,
                    answered_here,
                })
            }
            (Some(old), Some(id)) if old == id => {
                self.shown = Some(old);
                None
            }
            (Some(old), Some(id)) => {
                self.shown = Some(id.to_string());
                Some(Change::Raised {
                    request_id: id.to_string(),
                    replaced: Some(old),
                })
            }
        };
        if self.answered.is_some() && self.answered.as_deref() != pending {
            self.answered = None;
        }
        change
    }
}

// ---------- The request window's showing ----------

/// What to do with the request window now ([`Popup::step`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PopupStep {
    /// Nothing to do.
    Idle,
    /// Routed here, waiting for the page to report its height.
    Wait,
    /// Place it for `height` and show it; `fitted` is false when the page did not report in time.
    Show { height: u32, fitted: bool },
    /// Shown already; the page's height changed (a longer name, the language) or the scale it is
    /// drawn at did (Windows' text size): place it again.
    Resize { height: u32 },
}

/// The request window's side of the decision: shown once the page has drawn the request.
#[derive(Debug)]
pub struct Popup {
    /// The request routed to the window, and since when.
    routed: Option<(String, Instant)>,
    /// Shown for `routed` (or closed by hand — parked, not shown again for it until
    /// [`Popup::reveal`]).
    shown: bool,
    /// Closed by hand (Alt+F4, the taskbar's «Закрыть окно») while `routed` was up.
    parked: bool,
    /// The last height the page reported: for which request, at which step (CSS px). The page
    /// draws the pending request before the window is shown, so it is shown at once, at that height.
    fitted: Option<(String, PairStep, u32)>,
    /// The text scale the page's last report implied ([`TextScale::from_page`]); `None` before any.
    page_scale: Option<f64>,
    /// The height and the page's text scale (in hundredths) the window was last placed for.
    placed: Option<(u32, Option<u32>)>,
    /// The step the routed request is at: only a height reported for it sizes the window.
    at: PairStep,
    /// The step changed while the window was up, and its height has not come yet: since when.
    restepped: Option<Instant>,
}

impl Default for Popup {
    fn default() -> Self {
        Popup {
            routed: None,
            shown: false,
            parked: false,
            fitted: None,
            page_scale: None,
            placed: None,
            at: PairStep::Consent,
            restepped: None,
        }
    }
}

impl Popup {
    /// Route `request_id` here, at `step`.
    pub fn route(&mut self, request_id: &str, step: PairStep, now: Instant) {
        self.routed = Some((request_id.to_string(), now));
        self.shown = false;
        self.parked = false;
        self.at = step;
        self.restepped = None;
    }

    /// Nothing is routed here any more. True when the window was up (or parked) for it.
    pub fn clear(&mut self) -> bool {
        let was = self.shown;
        self.routed = None;
        self.shown = false;
        self.parked = false;
        self.restepped = None;
        was
    }

    /// The window was closed by hand while up: parked. True when a request was routed here.
    pub fn park(&mut self) -> bool {
        if self.routed.is_none() {
            return false;
        }
        self.parked = true;
        true
    }

    /// Show a parked window again (the owner opened the main window, where one looks for the
    /// request): the next [`Popup::step`] shows it, at the height known. True when it was parked.
    pub fn reveal(&mut self) -> bool {
        if !self.parked || self.routed.is_none() {
            return false;
        }
        self.parked = false;
        self.shown = false;
        true
    }

    /// The request routed here is at `step` now. True when that is a change.
    pub fn set_step(&mut self, step: PairStep, now: Instant) -> bool {
        if self.at == step {
            return false;
        }
        self.at = step;
        if self.shown {
            self.restepped = Some(now);
        }
        true
    }

    /// The page reports `height` (CSS px, clamped) for `request_id` at `step`, drawn at
    /// `page_scale` (its text scale, when it said its pixel ratio). True when that is the request
    /// routed here, at the step it is at.
    pub fn fit(
        &mut self,
        request_id: &str,
        step: PairStep,
        height: u32,
        page_scale: Option<f64>,
    ) -> bool {
        self.fitted = Some((request_id.to_string(), step, height));
        if page_scale.is_some() {
            self.page_scale = page_scale;
        }
        step == self.at
            && self
                .routed
                .as_ref()
                .is_some_and(|(routed, _)| routed == request_id)
    }

    /// The text scale the page last implied, for the placement.
    pub fn page_scale(&self) -> Option<f64> {
        self.page_scale
    }

    /// What the window was last placed for, to compare a new placement with.
    fn placement(&self, height: u32) -> (u32, Option<u32>) {
        (height, self.page_scale.map(|s| (s * 100.0).round() as u32))
    }

    /// The height to show the window at without a report for the request: the step's default, or
    /// the last height reported for that step (another request's) when it is taller.
    fn fallback_height(&self) -> u32 {
        let known = self
            .fitted
            .as_ref()
            .filter(|(_, step, _)| *step == self.at)
            .map_or(0, |(_, _, h)| *h);
        known.max(self.at.default_height())
    }

    /// What to do now.
    pub fn step(&mut self, now: Instant) -> PopupStep {
        let Some((routed, since)) = &self.routed else {
            return PopupStep::Idle;
        };
        let at = self.at;
        let fitted = self
            .fitted
            .as_ref()
            .filter(|(id, step, _)| id == routed && *step == at)
            .map(|(_, _, h)| *h);
        if !self.shown {
            let step = match fitted {
                Some(height) => PopupStep::Show {
                    height,
                    fitted: true,
                },
                None if now.saturating_duration_since(*since) >= FIT_WAIT => PopupStep::Show {
                    height: self.fallback_height(),
                    fitted: false,
                },
                None => return PopupStep::Wait,
            };
            if let PopupStep::Show { height, .. } = step {
                self.shown = true;
                self.placed = Some(self.placement(height));
            }
            return step;
        }
        if self.parked {
            // Closed by hand: nothing is placed or shown for it until it is revealed.
            return PopupStep::Idle;
        }
        match fitted {
            Some(height) => {
                self.restepped = None;
                let placement = self.placement(height);
                if self.placed == Some(placement) {
                    return PopupStep::Idle;
                }
                self.placed = Some(placement);
                PopupStep::Resize { height }
            }
            // A new step whose page has not reported in time: its own fallback, once.
            None => match self.restepped {
                Some(t) if now.saturating_duration_since(t) >= FIT_WAIT => {
                    self.restepped = None;
                    let placement = self.placement(self.fallback_height());
                    if self.placed == Some(placement) {
                        return PopupStep::Idle;
                    }
                    self.placed = Some(placement);
                    PopupStep::Resize {
                        height: placement.0,
                    }
                }
                _ => PopupStep::Idle,
            },
        }
    }
}

/// A height from the page, CSS px, into the range the window takes. `None` for nonsense.
pub fn clamp_height(css_px: f64) -> Option<u32> {
    if !css_px.is_finite() || css_px <= 0.0 {
        return None;
    }
    let px = css_px.ceil().min(f64::from(POPUP_MAX_HEIGHT));
    Some((px as u32).max(POPUP_MIN_HEIGHT))
}

// ---------- Windows' text size ----------

/// Windows' «Размер текста» (Settings → Accessibility → Text size) runs from 100 to 225 %.
const TEXT_SCALE_MAX: f64 = 2.25;

/// How much larger WebView2 draws a CSS pixel than the display scale alone would: Windows' text
/// size, as the request window is placed at. 1.0 at the default text size, which changes nothing.
/// Sized by the display scale alone, the window is shorter than its page, and at 150 % its buttons
/// are gone.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct TextScale {
    pub factor: f64,
    /// Where it came from, for the log: `"page"` (the page's pixel ratio over the window's display
    /// scale), `"windows"` (the setting, before the page has said), `"default"` (neither known).
    pub source: &'static str,
}

impl TextScale {
    /// From the page's `devicePixelRatio` and the display scale of the window it is in. `None`
    /// for nonsense. Under 1 (a zoomed-out page) counts as 1: the window is never made shorter than
    /// the display scale makes it; over 225 % is cut to it.
    pub fn from_page(ratio: f64, display_scale: f64) -> Option<f64> {
        if !ratio.is_finite() || !display_scale.is_finite() || ratio <= 0.0 || display_scale <= 0.0
        {
            return None;
        }
        let factor = ratio / display_scale;
        Some(((factor * 100.0).round() / 100.0).clamp(1.0, TEXT_SCALE_MAX))
    }

    /// Windows' setting as a factor, from its registry value (`TextScaleFactor`, a percentage);
    /// absent, the default 100 %.
    pub fn from_setting(percent: Option<u32>) -> f64 {
        percent.map_or(1.0, |p| (f64::from(p) / 100.0).clamp(1.0, TEXT_SCALE_MAX))
    }
}

/// `HKCU\Software\Microsoft\Accessibility\TextScaleFactor`, where Settings keeps the text size:
/// `Ok(None)` when it was never changed (no key, no value). The main window is sized by it too
/// (`window_fit`).
#[cfg(windows)]
pub(crate) fn text_scale_setting() -> Result<Option<u32>, String> {
    use winreg::enums::HKEY_CURRENT_USER;
    use winreg::RegKey;
    let key =
        match RegKey::predef(HKEY_CURRENT_USER).open_subkey(r"Software\Microsoft\Accessibility") {
            Ok(key) => key,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(format!("Accessibility key: {e}")),
        };
    match key.get_value::<u32, _>("TextScaleFactor") {
        Ok(percent) => Ok(Some(percent)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("TextScaleFactor: {e}")),
    }
}

#[cfg(not(windows))]
pub(crate) fn text_scale_setting() -> Result<Option<u32>, String> {
    Ok(None)
}

/// The text scale to place the window at: the page's, once it has said; before that Windows'
/// setting; the default when that cannot be read (said in the log).
fn text_scale(page: Option<f64>) -> TextScale {
    if let Some(factor) = page {
        return TextScale {
            factor,
            source: "page",
        };
    }
    match text_scale_setting() {
        Ok(percent) => TextScale {
            factor: TextScale::from_setting(percent),
            source: "windows",
        },
        Err(e) => {
            tracing::debug!("request window: Windows' text size not read ({e}); placed at 100 %");
            TextScale {
                factor: 1.0,
                source: "default",
            }
        }
    }
}

// ---------- The request window's place ----------

/// A rectangle in physical pixels (a monitor, its work area).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rect {
    pub x: i32,
    pub y: i32,
    pub width: u32,
    pub height: u32,
}

impl Rect {
    pub(crate) fn right(self) -> i64 {
        i64::from(self.x) + i64::from(self.width)
    }

    pub(crate) fn bottom(self) -> i64 {
        i64::from(self.y) + i64::from(self.height)
    }
}

/// Which edge of the monitor the taskbar takes, read from what it leaves of the monitor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskbarEdge {
    Bottom,
    Top,
    Left,
    Right,
    /// The work area is the whole monitor: an auto-hidden taskbar (or none on this monitor).
    None,
}

impl TaskbarEdge {
    pub fn as_str(self) -> &'static str {
        match self {
            TaskbarEdge::Bottom => "bottom",
            TaskbarEdge::Top => "top",
            TaskbarEdge::Left => "left",
            TaskbarEdge::Right => "right",
            TaskbarEdge::None => "none",
        }
    }
}

pub fn taskbar_edge(monitor: Rect, work: Rect) -> TaskbarEdge {
    if work.bottom() < monitor.bottom() {
        TaskbarEdge::Bottom
    } else if work.y > monitor.y {
        TaskbarEdge::Top
    } else if work.x > monitor.x {
        TaskbarEdge::Left
    } else if work.right() < monitor.right() {
        TaskbarEdge::Right
    } else {
        TaskbarEdge::None
    }
}

/// The request window's top-left corner, in physical pixels: in the work area's corner nearest the
/// notification area, which sits at the far end of the taskbar — bottom-right for a bottom, right or
/// hidden taskbar (where Windows puts its own notifications), top-right for a top one, bottom-left
/// for a left one — `margin` in from both edges. Never above or left of the work area, even on a
/// screen smaller than the window.
pub fn popup_position(monitor: Rect, work: Rect, size: (u32, u32), margin: u32) -> (i32, i32) {
    let margin = i64::from(margin);
    let left = i64::from(work.x) + margin;
    let top = i64::from(work.y) + margin;
    let right = work.right() - i64::from(size.0) - margin;
    let bottom = work.bottom() - i64::from(size.1) - margin;
    let (x, y) = match taskbar_edge(monitor, work) {
        TaskbarEdge::Bottom | TaskbarEdge::Right | TaskbarEdge::None => (right, bottom),
        TaskbarEdge::Top => (right, top),
        TaskbarEdge::Left => (left, bottom),
    };
    let clamp = |v: i64, min: i32| {
        v.max(i64::from(min))
            .clamp(i64::from(i32::MIN), i64::from(i32::MAX)) as i32
    };
    (clamp(x, work.x), clamp(y, work.y))
}

/// CSS px at `scale`, in physical pixels.
pub fn scaled(css_px: u32, scale: f64) -> u32 {
    (f64::from(css_px) * scale).round().max(1.0) as u32
}

// ---------- Shared state, the thread, the command ----------

#[derive(Debug, Default)]
struct Inner {
    router: Router,
    popup: Popup,
    /// The request whose «Разрешить» was pressed on a PC with no owner: it shows «Кто это?» until
    /// it is answered or goes ([`PairPrompt::allow`]).
    role_step: Option<String>,
}

impl Inner {
    fn step_for(&self, request_id: &str) -> PairStep {
        if self.role_step.as_deref() == Some(request_id) {
            PairStep::Role
        } else {
            PairStep::Consent
        }
    }
}

/// The decision and the request window's state, shared by the thread and the commands.
pub struct PairPrompt {
    inner: Mutex<Inner>,
    wake: Sender<&'static str>,
}

impl PairPrompt {
    /// The shared state, and the receiving end of its wake-ups for [`spawn`].
    pub fn new() -> (PairPrompt, Receiver<&'static str>) {
        let (wake, woken) = mpsc::channel();
        (
            PairPrompt {
                inner: Mutex::new(Inner::default()),
                wake,
            },
            woken,
        )
    }

    /// Have the thread look again now: `why` is for its trace line.
    pub fn wake(&self, why: &'static str) {
        if self.wake.send(why).is_err() {
            // Only after the thread has stopped, which it does when this is dropped: at exit.
            tracing::trace!(why, "pairing prompt: thread gone; wake-up dropped");
        }
    }

    /// The owner answered `request_id`: the window closes at once.
    pub fn answer(&self, request_id: &str) {
        let shown = {
            let mut inner = afklink_core::lock(&self.inner);
            let shown = inner.router.is_shown(request_id);
            inner.router.answer(request_id);
            shown
        };
        tracing::debug!(
            %request_id,
            shown,
            "pairing prompt answered: closing the request window"
        );
        self.wake("answered");
    }

    /// The step `request_id` is at, for `PendingPairDto::step`: «Кто это?» once «Разрешить» was
    /// pressed on a prompt that asks it, else «Отклонить» / «Разрешить».
    pub fn step_for(&self, request_id: &str) -> PairStep {
        afklink_core::lock(&self.inner).step_for(request_id)
    }

    /// «Разрешить» on a prompt that asks «Кто это?»: the request turns into the question, and
    /// nothing goes to the server until a role is chosen (`respond_pair`). True when it was not at
    /// that step already.
    pub fn allow(&self, request_id: &str) -> bool {
        let (changed, shown) = {
            let mut inner = afklink_core::lock(&self.inner);
            let changed = inner.role_step.as_deref() != Some(request_id);
            inner.role_step = Some(request_id.to_string());
            (changed, inner.router.is_shown(request_id))
        };
        tracing::debug!(
            %request_id,
            shown,
            changed,
            "pairing prompt: «Разрешить» pressed on a PC with no owner; «Кто это?» next"
        );
        self.wake("allowed");
        changed
    }

    /// The request window was closed by hand while a request was up: it stays hidden (the request
    /// still waits) until the owner opens the main window ([`PairPrompt::reveal`]) or the request
    /// goes.
    pub fn parked(&self) {
        let (parked, request) = {
            let mut inner = afklink_core::lock(&self.inner);
            let parked = inner.popup.park();
            (parked, inner.router.shown().map(str::to_string))
        };
        if parked {
            tracing::debug!(
                request_id = request.as_deref().unwrap_or("-"),
                "request window closed by hand while the request waits: hidden until the main \
                 window is opened (the tray, a second launch) or the request goes"
            );
        } else {
            tracing::debug!("request window closed by hand with no request up");
        }
    }

    /// The owner opened the main window (`why`): a request window closed by hand comes back — the
    /// request is answerable nowhere else, since the main window does not hold it.
    pub fn reveal(&self, why: &'static str) {
        let (revealed, request) = {
            let mut inner = afklink_core::lock(&self.inner);
            (
                inner.popup.reveal(),
                inner.router.shown().map(str::to_string),
            )
        };
        if revealed {
            tracing::debug!(
                request_id = request.as_deref().unwrap_or("-"),
                why,
                "request window closed by hand earlier: shown again"
            );
            self.wake("revealed");
        } else {
            tracing::trace!(why, "main window shown; no request window to bring back");
        }
    }

    /// The request window's page drew `request_id` at `step`, `height` CSS px tall, at
    /// `page_scale` ([`TextScale::from_page`]).
    fn fit(&self, request_id: &str, step: PairStep, height: u32, page_scale: Option<f64>) -> bool {
        afklink_core::lock(&self.inner)
            .popup
            .fit(request_id, step, height, page_scale)
    }
}

/// «Разрешить» on a prompt that asks «Кто это?» (`PendingPairDto::asks_role`): it becomes the
/// question at once, and both windows re-read the status. Nothing is sent: the answer goes with the
/// role (`respond_pair`). A request that is not pending, or does not ask, is left as it is (said in
/// the log): the window's «Разрешить» then answers it directly.
#[tauri::command]
pub fn allow_pair(
    app: AppHandle,
    control: State<'_, AgentControl>,
    prompt: State<'_, PairPrompt>,
    request_id: String,
) -> bool {
    let asks = afklink_core::lock(&control.state)
        .pending_pair
        .as_ref()
        .filter(|p| p.request_id == request_id)
        .map(afklink_core::agent::PendingPair::asks_role);
    match asks {
        Some(true) => {}
        Some(false) => {
            tracing::debug!(
                %request_id,
                "pairing prompt: «Кто это?» not asked — the PC has an owner, or the server knows \
                 no roles; the window answers «Разрешить» as it is"
            );
            return false;
        }
        None => {
            tracing::debug!(
                %request_id,
                "pairing prompt: «Разрешить» for a request no longer pending (withdrawn or \
                 expired); nothing to do"
            );
            return false;
        }
    }
    prompt.allow(&request_id);
    let payload = PromptEvent {
        request_id: &request_id,
        shown: true,
    };
    if let Err(e) = app.emit(EVENT, payload) {
        // Each window still sees the step on its next poll (within a second).
        tracing::debug!(%request_id, "pairing prompt: windows not told of «Кто это?» at once: {e}");
    }
    true
}

/// The main view's step 3 pressed while a request waits (the step that says to press «Разрешить»
/// there, its row a link to the request then): the request window to the front. Closed by hand,
/// it is shown again
/// ([`PairPrompt::reveal`]); up, it is activated, so the owner lands on it — on the prompt itself,
/// never a button (`usePromptFocus`), so no key answers it. Not shown yet (its page has not reported
/// its height), it shows by itself. False when no request is up.
#[tauri::command]
pub fn show_pair_request(app: AppHandle, prompt: State<'_, PairPrompt>) -> bool {
    let (request, parked, shown) = {
        let inner = afklink_core::lock(&prompt.inner);
        (
            inner.router.shown().map(str::to_string),
            inner.popup.parked,
            inner.popup.shown,
        )
    };
    let Some(request_id) = request else {
        tracing::debug!("main view: step 3 pressed with no request up; nothing to bring forward");
        return false;
    };
    if parked {
        tracing::debug!(
            %request_id,
            "main view: step 3 pressed; the request window closed by hand comes back"
        );
        prompt.reveal("step 3 pressed");
        return true;
    }
    if !shown {
        tracing::debug!(
            %request_id,
            "main view: step 3 pressed before the request window's first show; it shows by itself"
        );
        return true;
    }
    let Some(w) = app.get_webview_window(WINDOW) else {
        tracing::warn!(%request_id, "main view: step 3 pressed, and there is no request window");
        return false;
    };
    // Not under the lock: a window call waits for the main thread (see the module docs).
    match w.set_focus() {
        Ok(()) => tracing::debug!(
            %request_id,
            "main view: step 3 pressed; the request window brought to the front and activated"
        ),
        // Still on top of everything (always-on-top): it is in front, only not active.
        Err(e) => tracing::debug!(
            %request_id,
            "main view: step 3 pressed; the request window not activated: {e}"
        ),
    }
    true
}

/// The request window's page: it has drawn `request_id` at `step` (`"consent"` or `"role"`; absent
/// from an older page: `"consent"`), and this is its height in CSS px, drawn at `ratio`
/// (`devicePixelRatio`; absent from an older page). The window is shown or re-placed from the
/// thread, woken for it.
///
/// The ratio over the window's display scale is Windows' text size as WebView2 applies it
/// ([`TextScale::from_page`]): the window is made that much taller than the display scale alone
/// would make it, so the page fits. Windows' own setting is read beside it for the log, so a
/// difference between the two shows there.
#[tauri::command]
pub fn fit_pair_window(
    window: WebviewWindow,
    prompt: State<'_, PairPrompt>,
    request_id: String,
    height: f64,
    step: Option<String>,
    ratio: Option<f64>,
) {
    let Some(css_px) = clamp_height(height) else {
        tracing::debug!(%request_id, height, "request window: height report ignored (not a height)");
        return;
    };
    let step = match step.as_deref().map(PairStep::parse) {
        None => PairStep::Consent,
        Some(Some(step)) => step,
        Some(None) => {
            tracing::debug!(
                %request_id,
                step = step.as_deref().unwrap_or("-"),
                "request window: height report for a step this build does not know; ignored"
            );
            return;
        }
    };
    // Before the lock: a window getter.
    let dpi_scale = match window.scale_factor() {
        Ok(scale) => Some(scale),
        Err(e) => {
            tracing::debug!(%request_id, "request window: display scale unknown ({e})");
            None
        }
    };
    let page_scale = match (ratio, dpi_scale) {
        (Some(r), Some(d)) => TextScale::from_page(r, d),
        _ => None,
    };
    let setting = text_scale_setting();
    let routed_here = prompt.fit(&request_id, step, css_px, page_scale);
    tracing::debug!(
        %request_id,
        step = step.as_str(),
        reported = height,
        height = css_px,
        ratio = ratio.unwrap_or(0.0),
        display_scale = dpi_scale.unwrap_or(0.0),
        text_scale = page_scale.unwrap_or(0.0),
        windows_text_size = %setting
            .as_ref()
            .map_or_else(|e| format!("unread: {e}"), |p| format!("{}%", p.unwrap_or(100))),
        routed_here,
        "request window: the page reports its height"
    );
    if let (Some(page), Ok(percent)) = (page_scale, &setting) {
        let windows = TextScale::from_setting(*percent);
        if (page - windows).abs() > 0.02 {
            tracing::warn!(
                %request_id,
                page,
                windows,
                "request window: the page's text scale is not Windows' text size; placed at the \
                 page's, which is what it is drawn at"
            );
        }
    }
    prompt.wake("fit");
}

/// The request window, once at startup: its title, and no shadow on Windows 10.
///
/// The title is what Windows shows for it in the taskbar and in Alt+Tab, next to the main window's
/// «AFKLink». tauri.conf.json can hold one language only, so the translated «Запрос на доступ» is
/// set here, like the tray strings — and made sure of again each time the window is shown
/// ([`title_popup`]). The window has no frame (a notification card, not a dialog):
/// Windows 11 gives it rounded corners and a shadow through `shadow`, Windows 10 would give it a
/// white one-pixel border instead, so there it goes without.
pub fn setup_window(app: &AppHandle, locale: Locale) {
    let Some(w) = app.get_webview_window(WINDOW) else {
        tracing::warn!("no pairing prompt window to set up");
        return;
    };
    let title = NativeText::NotifyPairRequestTitle.t(locale);
    match w.set_title(title) {
        Ok(()) => tracing::debug!(title, "pairing prompt window titled"),
        Err(e) => tracing::warn!("pairing prompt window title not set: {e}"),
    }
    match windows_build() {
        Ok(build) if build < WINDOWS_11_BUILD => match w.set_shadow(false) {
            Ok(()) => tracing::debug!(build, "request window: Windows 10, no frame shadow"),
            Err(e) => tracing::debug!(build, "request window: shadow not turned off: {e}"),
        },
        Ok(build) => tracing::debug!(build, "request window: Windows 11, frame shadow kept"),
        Err(e) => tracing::debug!("request window: Windows build unknown ({e}); frame shadow kept"),
    }
}

/// The first build of Windows 11.
const WINDOWS_11_BUILD: u32 = 22_000;

/// This Windows' build (`CurrentBuild`); also read by `capture_guard`.
#[cfg(windows)]
pub(crate) fn windows_build() -> Result<u32, String> {
    use winreg::enums::HKEY_LOCAL_MACHINE;
    use winreg::RegKey;
    let key = RegKey::predef(HKEY_LOCAL_MACHINE)
        .open_subkey(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion")
        .map_err(|e| format!("CurrentVersion key: {e}"))?;
    let build: String = key
        .get_value("CurrentBuild")
        .map_err(|e| format!("CurrentBuild: {e}"))?;
    build
        .trim()
        .parse()
        .map_err(|e| format!("CurrentBuild {build:?}: {e}"))
}

#[cfg(not(windows))]
pub(crate) fn windows_build() -> Result<u32, String> {
    Err("not Windows".to_string())
}

/// Start the thread that decides and carries out when the request window is shown.
pub fn spawn(app: AppHandle, locale: Locale, woken: Receiver<&'static str>) {
    let started = std::thread::Builder::new()
        .name("pair-prompt".to_string())
        .spawn(move || {
            let mut toasted: Option<String> = None;
            loop {
                match woken.recv_timeout(TICK) {
                    Ok(why) => {
                        // Several wake-ups at once are one look.
                        let extra = woken.try_iter().count();
                        tracing::trace!(why, extra, "pairing prompt: woken");
                    }
                    Err(RecvTimeoutError::Timeout) => {}
                    Err(RecvTimeoutError::Disconnected) => {
                        tracing::debug!("pairing prompt: state gone; thread stops");
                        return;
                    }
                }
                tick(&app, locale, &mut toasted);
            }
        });
    if let Err(e) = started {
        // Without it no request is ever shown: each would time out unseen.
        tracing::error!(
            "pairing prompt thread not started: {e}; pairing requests will not be shown"
        );
    }
}

/// The payload of [`EVENT`].
#[derive(Serialize, Clone)]
struct PromptEvent<'a> {
    request_id: &'a str,
    /// Whether it is up now; false once it is gone.
    shown: bool,
}

fn tick(app: &AppHandle, locale: Locale, toasted: &mut Option<String>) {
    let (Some(control), Some(prompt)) = (
        app.try_state::<AgentControl>(),
        app.try_state::<PairPrompt>(),
    ) else {
        return;
    };
    let pending: Option<(String, PersonName)> = afklink_core::lock(&control.state)
        .pending_pair
        .as_ref()
        .map(|p| (p.request_id.clone(), p.name()));
    let (showing, forgot_role) = {
        let mut inner = afklink_core::lock(&prompt.inner);
        // The request at «Кто это?» is gone (answered, withdrawn, expired): its step with it.
        let forgot_role = match (&inner.role_step, &pending) {
            (Some(at_role), Some((id, _))) if at_role == id => None,
            (Some(_), _) => inner.role_step.take(),
            (None, _) => None,
        };
        (inner.router.shown().is_some(), forgot_role)
    };
    if let Some(request_id) = &forgot_role {
        tracing::debug!(
            %request_id,
            "pairing prompt: the request that was at «Кто это?» is gone (answered, withdrawn or \
             expired); its step is forgotten"
        );
    }
    if pending.is_none() && !showing {
        return;
    }
    let now = Instant::now();
    let (change, step, page_scale, restep) = {
        let mut inner = afklink_core::lock(&prompt.inner);
        let change = inner
            .router
            .update(pending.as_ref().map(|(id, _)| id.as_str()));
        if let Some(change) = &change {
            match change.shown() {
                Some(id) => {
                    let at = inner.step_for(id);
                    inner.popup.route(id, at, now);
                }
                None => {
                    inner.popup.clear();
                }
            }
        }
        // «Разрешить» pressed: the request window now waits for the question's height.
        let restep = match inner.router.shown().map(str::to_string) {
            Some(id) => {
                let at = inner.step_for(&id);
                inner.popup.set_step(at, now).then_some((id, at))
            }
            None => None,
        };
        let step = inner.popup.step(now);
        (change, step, inner.popup.page_scale(), restep)
    };
    if let Some((request_id, at)) = &restep {
        tracing::debug!(
            %request_id,
            step = at.as_str(),
            "request window: the request is at another step; sized for it once its page reports"
        );
    }
    if let Some(change) = &change {
        let name = pending
            .as_ref()
            .filter(|(id, _)| id == change.request_id())
            .map(|(_, name)| name);
        apply_change(app, change, name, locale, toasted);
    }
    apply_step(app, step, page_scale, pending.as_ref(), locale, toasted);
}

fn apply_change(
    app: &AppHandle,
    change: &Change,
    name: Option<&PersonName>,
    locale: Locale,
    toasted: &mut Option<String>,
) {
    let request_id = change.request_id();
    let payload = PromptEvent {
        request_id,
        shown: change.shown().is_some(),
    };
    if let Err(e) = app.emit(EVENT, payload) {
        // Each window still sees it on its next poll (within a second).
        tracing::debug!(%request_id, "pairing prompt: windows not told at once: {e}");
    }
    match change {
        Change::Raised { replaced, .. } => {
            // The line the log has always had for a new request.
            tracing::debug!(
                %request_id,
                on = "popup",
                replaced = replaced.as_deref().unwrap_or("-"),
                "pairing prompt raised"
            );
            if app.get_webview_window(WINDOW).is_some() {
                tracing::debug!(
                    %request_id,
                    "no toast: the request window shows it once its page has drawn it"
                );
            } else {
                tracing::warn!(%request_id, "no pairing prompt window to show");
                send_toast(app, locale, request_id, name, "no request window", toasted);
            }
        }
        Change::Resolved { answered_here, .. } => {
            hide_popup(app, request_id, "resolved");
            if toasted.as_deref() == Some(request_id) {
                *toasted = None;
            }
            // The line the log has always had when a request goes.
            tracing::debug!(
                %request_id,
                from = "popup",
                answered_here,
                "pairing request resolved; prompt hidden"
            );
        }
    }
}

fn apply_step(
    app: &AppHandle,
    step: PopupStep,
    page_scale: Option<f64>,
    pending: Option<&(String, PersonName)>,
    locale: Locale,
    toasted: &mut Option<String>,
) {
    let (height, show, fitted) = match step {
        PopupStep::Idle | PopupStep::Wait => return,
        PopupStep::Show { height, fitted } => (height, true, fitted),
        PopupStep::Resize { height } => (height, false, true),
    };
    let request_id = pending.map_or("-", |(id, _)| id.as_str());
    let Some(w) = app.get_webview_window(WINDOW) else {
        // Said once, when the request was raised; the toast went out then.
        return;
    };
    let text = text_scale(page_scale);
    let asked = match place_popup(app, &w, request_id, height, text.factor) {
        Ok(placed) => {
            tracing::debug!(
                %request_id,
                height,
                fitted,
                monitor = placed.monitor.as_deref().unwrap_or("-"),
                scale = placed.scale,
                text_scale = text.factor,
                text_scale_from = text.source,
                taskbar = placed.edge.as_str(),
                x = placed.x,
                y = placed.y,
                width_px = placed.width,
                height_px = placed.height,
                size_tries = placed.sizing.tries,
                read_back = %placed.sizing.got_text(),
                "request window placed near the tray"
            );
            Some((placed.width, placed.height))
        }
        // Shown where it last was (or centred, the first time): still on top, still answerable.
        Err(e) => {
            tracing::warn!(%request_id, height, "request window not placed: {e}");
            None
        }
    };
    if !show {
        return;
    }
    let title = title_popup(&w, locale, request_id);
    match w.show() {
        Ok(()) => {
            // What the window is once shown: Windows (or DWM) must not have made it another size.
            if let Some(asked) = asked {
                check_shown_size(request_id, asked, read_size(&w));
            }
            if fitted {
                tracing::debug!(
                    %request_id,
                    height,
                    title = %title,
                    "request window shown (without focus)"
                );
            } else {
                tracing::warn!(
                    %request_id,
                    height,
                    title = %title,
                    wait_ms = FIT_WAIT.as_millis() as u64,
                    "request window shown before its page reported a height"
                );
            }
        }
        Err(e) => {
            tracing::warn!(%request_id, "pairing prompt window not shown: {e}");
            let name = pending.map(|(_, name)| name);
            send_toast(
                app,
                locale,
                request_id,
                name,
                "the request window did not show",
                toasted,
            );
        }
    }
}

/// Where the request window went.
struct Placed {
    monitor: Option<String>,
    scale: f64,
    edge: TaskbarEdge,
    x: i32,
    y: i32,
    width: u32,
    height: u32,
    /// How the size came out ([`size_exactly`]).
    sizing: Sizing,
}

/// How many times the request window's size is set before what Windows gives is taken as it is.
/// Two: the first `set_size` of a window never resized since it was created comes out too tall (see
/// [`size_exactly`]); the second, with the frame known, is exact.
const SIZE_TRIES: u32 = 2;

/// What sizing the request window came to.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Sizing {
    /// `set_size` calls made.
    tries: u32,
    /// The client area read back after the last one, physical px; the error when it was not read.
    got: Result<(u32, u32), String>,
}

impl Sizing {
    /// For the log.
    fn got_text(&self) -> String {
        match &self.got {
            Ok((w, h)) => format!("{w}x{h}"),
            Err(e) => format!("unread ({e})"),
        }
    }
}

/// Size the window's client area to `asked` (physical px) with `set`, read it back with `read`, and
/// set it once more when it came out another size.
///
/// Why once more (measured on the first request after a start at 150 %: 570×225 asked, 570×268
/// got — a blank band under the buttons): the window has no frame but keeps its shadow
/// (`decorations: false`, `shadow: true`), and tao's `set_inner_size` adds to the size asked the
/// frame it measures as the window rect less the client rect. Until the window is first resized,
/// that is the frame of its creation — Windows' default one with a title bar (56 px tall at 150 %),
/// since tao leaves the `WM_NCCALCSIZE` sent by `CreateWindowEx` (wParam FALSE) to `DefWindowProc` —
/// and not tao's own thin frame (13 px), which the resize itself then puts in place. The first size
/// is too tall by the difference (43 px at 150 %, 29 CSS px); from then on the frame is tao's and a
/// size comes out exact (reproduced with tao 0.37.1 alone, hidden or shown).
///
/// A failed `set` ends it with the error; a failed `read` ends it too (the size was asked, it is
/// only not known), said in the log.
fn size_exactly(
    request_id: &str,
    asked: (u32, u32),
    mut set: impl FnMut((u32, u32)) -> Result<(), String>,
    mut read: impl FnMut() -> Result<(u32, u32), String>,
) -> Result<Sizing, String> {
    let mut tries = 0;
    loop {
        set(asked)?;
        tries += 1;
        let got = read();
        match &got {
            Ok(got) if *got == asked => {
                tracing::debug!(
                    %request_id,
                    tries,
                    width_px = asked.0,
                    height_px = asked.1,
                    "request window: size read back as asked"
                );
            }
            Ok(got) if tries < SIZE_TRIES => {
                tracing::debug!(
                    %request_id,
                    tries,
                    asked = %format!("{}x{}", asked.0, asked.1),
                    got = %format!("{}x{}", got.0, got.1),
                    "request window: size read back off (a frame measured before Windows \
                     recalculated it); set again"
                );
                continue;
            }
            Ok(got) => {
                tracing::warn!(
                    %request_id,
                    tries,
                    asked = %format!("{}x{}", asked.0, asked.1),
                    got = %format!("{}x{}", got.0, got.1),
                    "request window: size still off after setting it again; left as Windows made it"
                );
            }
            Err(e) => {
                tracing::debug!(
                    %request_id,
                    tries,
                    width_px = asked.0,
                    height_px = asked.1,
                    "request window: size not read back ({e}); taken as asked"
                );
            }
        }
        return Ok(Sizing { tries, got });
    }
}

/// The window's client area, physical px. A getter: waits for the main thread.
fn read_size(w: &WebviewWindow) -> Result<(u32, u32), String> {
    w.inner_size()
        .map(|s| (s.width, s.height))
        .map_err(|e| format!("inner_size: {e}"))
}

/// The size read back once the window is shown, against the size it was placed at: said in the log,
/// a warning when they differ (Windows or DWM resized it on showing). Returns whether they match.
fn check_shown_size(request_id: &str, asked: (u32, u32), got: Result<(u32, u32), String>) -> bool {
    match got {
        Ok(got) if got == asked => {
            tracing::debug!(
                %request_id,
                width_px = got.0,
                height_px = got.1,
                "request window: shown at the size it was placed at"
            );
            true
        }
        Ok(got) => {
            tracing::warn!(
                %request_id,
                asked = %format!("{}x{}", asked.0, asked.1),
                got = %format!("{}x{}", got.0, got.1),
                "request window: shown at another size than it was placed at"
            );
            false
        }
        Err(e) => {
            tracing::debug!(%request_id, "request window: size once shown not read ({e})");
            false
        }
    }
}

/// Place the window for `css_height` near the tray: its width at the display scale (the page then
/// lays out narrower under a larger text size), its height at the display scale times `text_scale`,
/// so the page's CSS pixels — drawn that much larger — all fit.
fn place_popup(
    app: &AppHandle,
    w: &WebviewWindow,
    request_id: &str,
    css_height: u32,
    text_scale: f64,
) -> Result<Placed, String> {
    // The notification area is on the primary monitor's taskbar.
    let monitor = match app.primary_monitor() {
        Ok(Some(m)) => m,
        Ok(None) => w
            .current_monitor()
            .map_err(|e| format!("current monitor: {e}"))?
            .ok_or("no primary monitor and no current one")?,
        Err(e) => return Err(format!("primary monitor: {e}")),
    };
    let scale = monitor.scale_factor();
    let bounds = Rect {
        x: monitor.position().x,
        y: monitor.position().y,
        width: monitor.size().width,
        height: monitor.size().height,
    };
    let area = monitor.work_area();
    let work = Rect {
        x: area.position.x,
        y: area.position.y,
        width: area.size.width,
        height: area.size.height,
    };
    let size = (
        scaled(POPUP_WIDTH, scale),
        scaled(css_height, scale * text_scale),
    );
    let (x, y) = popup_position(bounds, work, size, scaled(POPUP_MARGIN, scale));
    // Moved first: onto a monitor at another scale, Windows resizes it for that scale, and the
    // size below is that monitor's. Sized even when the move fails: a window left at its last size
    // — the first step's, or tauri.conf.json's — would cut «Кто это?» off.
    let moved = w
        .set_position(PhysicalPosition::new(x, y))
        .map_err(|e| format!("set_position: {e}"));
    let sized = size_exactly(
        request_id,
        size,
        |(width, height)| {
            w.set_size(PhysicalSize::new(width, height))
                .map_err(|e| format!("set_size: {e}"))
        },
        || read_size(w),
    );
    let sizing = match (moved, sized) {
        (Ok(()), Ok(sizing)) => sizing,
        (Err(m), Ok(sizing)) => {
            return Err(format!(
                "{m} (sized all the same: {} tries, read back {})",
                sizing.tries,
                sizing.got_text()
            ))
        }
        (Ok(()), Err(s)) => return Err(s),
        (Err(m), Err(s)) => return Err(format!("{m}; {s}")),
    };
    Ok(Placed {
        monitor: monitor.name().cloned(),
        scale,
        edge: taskbar_edge(bounds, work),
        x,
        y,
        width: size.0,
        height: size.1,
        sizing,
    })
}

/// The request window's title made sure of as it is shown: «Запрос на доступ» / "Access request",
/// what Windows shows for it in the taskbar and Alt+Tab beside the main window's «AFKLink».
/// [`setup_window`] sets it at startup; tauri.conf.json's «AFKLink» — one
/// language only — must never be what the owner sees there. In `locale`, the app's at launch: the
/// language the window's page was drawn in. Returns the title the window is shown with, for the log.
fn title_popup(w: &WebviewWindow, locale: Locale, request_id: &str) -> String {
    let wanted = NativeText::NotifyPairRequestTitle.t(locale);
    let was = match w.title() {
        Ok(title) if title == wanted => return title,
        Ok(title) => title,
        Err(e) => format!("unknown ({e})"),
    };
    match w.set_title(wanted) {
        Ok(()) => {
            tracing::debug!(
                %request_id,
                was = %was,
                locale = locale.tag(),
                title = wanted,
                "request window titled as it is shown: it had not kept the title set at startup"
            );
            wanted.to_string()
        }
        Err(e) => {
            tracing::warn!(
                %request_id,
                was = %was,
                "request window title not set as it is shown: {e}; Windows shows it as it was"
            );
            was
        }
    }
}

fn hide_popup(app: &AppHandle, request_id: &str, why: &'static str) {
    let Some(w) = app.get_webview_window(WINDOW) else {
        return;
    };
    // Hiding a hidden window is harmless; asking first would be a getter on the main thread.
    match w.hide() {
        Ok(()) => tracing::trace!(%request_id, why, "request window hidden"),
        Err(e) => tracing::debug!(%request_id, why, "request window not hidden: {e}"),
    }
}

/// The pairing request's toast, at most once per request — only when the request window is missing
/// or could not be shown. Its own title, «Запрос на доступ», over «Вера просит доступ к этому ПК»,
/// the request window's heading (no full stop: toasts end without one) — not the «AFKLink» title
/// the other toasts go without (`crate::toast`).
fn send_toast(
    app: &AppHandle,
    locale: Locale,
    request_id: &str,
    name: Option<&PersonName>,
    why: &'static str,
    toasted: &mut Option<String>,
) {
    use tauri_plugin_notification::NotificationExt;
    if toasted.as_deref() == Some(request_id) {
        tracing::debug!(%request_id, why, "pairing request toast already shown");
        return;
    }
    let Some(name) = name else {
        tracing::debug!(%request_id, why, "pairing request toast skipped: the request is gone");
        return;
    };
    let title = NativeText::NotifyPairRequestTitle.t(locale);
    let body = NativeText::NotifyPairRequestBody.with_user(locale, &name.text);
    // `Ok` means handed to Windows, not seen: the plugin shows the toast on a task of its own and
    // drops that result.
    match app.notification().builder().title(title).body(body).show() {
        Ok(()) => tracing::debug!(
            %request_id,
            name_source = name.source.as_str(),
            why,
            bold = title,
            under = NativeText::NotifyPairRequestBody.t(locale),
            "pairing request toast handed to Windows"
        ),
        Err(e) => tracing::warn!(%request_id, why, "pairing request toast not shown: {e}"),
    }
    *toasted = Some(request_id.to_string());
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- One place: a request is raised once, and goes once ----

    #[test]
    fn a_request_is_raised_once_whatever_else_happens() {
        let mut r = Router::default();
        assert_eq!(
            r.update(Some("r1")),
            Some(Change::Raised {
                request_id: "r1".into(),
                replaced: None
            })
        );
        assert!(r.is_shown("r1"));
        assert_eq!(r.shown(), Some("r1"));
        // The same state again changes nothing: no second raise, no second toast. (The main
        // window being opened or hidden does not move it anywhere.)
        assert_eq!(r.update(Some("r1")), None);
        assert!(!r.is_shown("other"));
    }

    #[test]
    fn an_answer_closes_it_at_once() {
        let mut r = Router::default();
        r.update(Some("r1"));
        r.answer("r1");
        // The orchestrator has not cleared the request yet: it is gone all the same.
        assert_eq!(
            r.update(Some("r1")),
            Some(Change::Resolved {
                request_id: "r1".into(),
                answered_here: true
            })
        );
        assert!(!r.is_shown("r1"));
        assert_eq!(r.update(Some("r1")), None, "it does not come back");
        // The orchestrator clears it: nothing more to do.
        assert_eq!(r.update(None), None);
        // The next request is a new one.
        assert!(matches!(r.update(Some("r2")), Some(Change::Raised { .. })));
    }

    #[test]
    fn a_request_withdrawn_by_the_server_closes() {
        let mut r = Router::default();
        r.update(Some("r1"));
        assert_eq!(
            r.update(None),
            Some(Change::Resolved {
                request_id: "r1".into(),
                answered_here: false
            })
        );
        assert_eq!(r.shown(), None);
    }

    #[test]
    fn a_new_request_replaces_the_one_shown() {
        let mut r = Router::default();
        r.update(Some("r1"));
        assert_eq!(
            r.update(Some("r2")),
            Some(Change::Raised {
                request_id: "r2".into(),
                replaced: Some("r1".into())
            })
        );
        assert!(!r.is_shown("r1"));
        assert!(r.is_shown("r2"));
    }

    #[test]
    fn an_answer_for_another_request_is_forgotten() {
        let mut r = Router::default();
        r.answer("old");
        assert!(matches!(r.update(Some("r1")), Some(Change::Raised { .. })));
        assert!(r.is_shown("r1"));
    }

    // ---- The request window: shown once drawn, re-placed on a new height ----

    #[test]
    fn the_request_window_waits_for_its_page_then_shows() {
        let t0 = Instant::now();
        let mut p = Popup::default();
        assert_eq!(p.step(t0), PopupStep::Idle);
        p.route("r1", PairStep::Consent, t0);
        assert_eq!(p.step(t0), PopupStep::Wait);
        // A report for another request (the page is behind) does not show it.
        assert!(!p.fit("r0", PairStep::Consent, 200, None));
        assert_eq!(p.step(t0 + Duration::from_millis(100)), PopupStep::Wait);
        assert!(p.fit("r1", PairStep::Consent, 172, None));
        assert_eq!(
            p.step(t0 + Duration::from_millis(200)),
            PopupStep::Show {
                height: 172,
                fitted: true
            }
        );
        // Shown once: the next look has nothing to do.
        assert_eq!(p.step(t0 + Duration::from_millis(300)), PopupStep::Idle);
        // The name wraps onto another line: placed again, not shown again.
        p.fit("r1", PairStep::Consent, 194, None);
        assert_eq!(
            p.step(t0 + Duration::from_millis(400)),
            PopupStep::Resize { height: 194 }
        );
        assert_eq!(p.step(t0 + Duration::from_millis(500)), PopupStep::Idle);
    }

    #[test]
    fn the_request_window_shows_anyway_when_its_page_is_silent() {
        let t0 = Instant::now();
        let mut p = Popup::default();
        p.route("r1", PairStep::Consent, t0);
        assert_eq!(
            p.step(t0 + FIT_WAIT - Duration::from_millis(1)),
            PopupStep::Wait
        );
        assert_eq!(
            p.step(t0 + FIT_WAIT),
            PopupStep::Show {
                height: POPUP_DEFAULT_HEIGHT,
                fitted: false
            }
        );
        // With a taller height known from an earlier request, that one.
        let mut p = Popup::default();
        p.fit("r0", PairStep::Consent, POPUP_DEFAULT_HEIGHT + 20, None);
        p.route("r1", PairStep::Consent, t0);
        assert_eq!(
            p.step(t0 + FIT_WAIT),
            PopupStep::Show {
                height: POPUP_DEFAULT_HEIGHT + 20,
                fitted: false
            }
        );
        // A shorter one (a one-line name) never makes the fallback shorter than the step's own.
        let mut p = Popup::default();
        p.fit("r0", PairStep::Consent, 150, None);
        p.route("r1", PairStep::Consent, t0);
        assert_eq!(
            p.step(t0 + FIT_WAIT),
            PopupStep::Show {
                height: POPUP_DEFAULT_HEIGHT,
                fitted: false
            }
        );
        // At «Кто это?» the fallback is the question's.
        let mut p = Popup::default();
        p.route("r1", PairStep::Role, t0);
        assert_eq!(
            p.step(t0 + FIT_WAIT),
            PopupStep::Show {
                height: POPUP_ROLE_DEFAULT_HEIGHT,
                fitted: false
            }
        );
    }

    /// Before the page has said, the window holds the tallest ordinary request (180 CSS px, the
    /// floor) — and the tallest one measured, three lines of a long name.
    #[test]
    fn the_fallback_holds_the_tallest_ordinary_request() {
        const { assert!(POPUP_DEFAULT_HEIGHT >= 180) };
        assert!(PairStep::Consent.default_height() >= 194);
    }

    // ---- Windows' text size ----

    /// The page's pixel ratio over the display scale is the text size; it sizes the window, and a
    /// change of it with the same CSS height places the window again.
    #[test]
    fn the_text_scale_comes_from_the_page_and_re_places_the_window() {
        assert_eq!(TextScale::from_page(1.0, 1.0), Some(1.0));
        assert_eq!(TextScale::from_page(1.875, 1.5), Some(1.25));
        assert_eq!(TextScale::from_page(2.25, 1.5), Some(1.5));
        assert_eq!(TextScale::from_page(1.5, 1.0), Some(1.5));
        // A zoomed-out page never makes the window shorter; past 225 % is cut to it.
        assert_eq!(TextScale::from_page(0.8, 1.0), Some(1.0));
        assert_eq!(TextScale::from_page(4.0, 1.0), Some(TEXT_SCALE_MAX));
        assert_eq!(TextScale::from_page(f64::NAN, 1.0), None);
        assert_eq!(TextScale::from_page(1.0, 0.0), None);
        // Windows' setting, before the page has said.
        let near = |a: f64, b: f64| (a - b).abs() < 1e-9;
        assert!(near(TextScale::from_setting(None), 1.0));
        assert!(near(TextScale::from_setting(Some(100)), 1.0));
        assert!(near(TextScale::from_setting(Some(150)), 1.5));
        assert!(near(TextScale::from_setting(Some(400)), TEXT_SCALE_MAX));

        let t0 = Instant::now();
        let mut p = Popup::default();
        p.route("r1", PairStep::Consent, t0);
        assert!(p.fit("r1", PairStep::Consent, 150, Some(1.0)));
        assert!(matches!(p.step(t0), PopupStep::Show { height: 150, .. }));
        assert_eq!(p.page_scale(), Some(1.0));
        // The owner turns the text size up while the request waits: same CSS height, larger scale.
        p.fit("r1", PairStep::Consent, 150, Some(1.5));
        assert_eq!(p.step(t0), PopupStep::Resize { height: 150 });
        assert_eq!(p.page_scale(), Some(1.5));
        assert_eq!(p.step(t0), PopupStep::Idle);
        // A report without a ratio (an older page) keeps the scale known.
        p.fit("r1", PairStep::Consent, 150, None);
        assert_eq!(p.page_scale(), Some(1.5));
        assert_eq!(p.step(t0), PopupStep::Idle);
    }

    /// At 100 % text the window is exactly as before; at 125 and 150 % it is that much taller, and
    /// the measured requests (the page at 380 / text CSS px) fit with their buttons.
    #[test]
    fn the_window_holds_the_page_at_every_text_size() {
        // (text scale, the page's height at that text scale, its buttons' bottom), CSS px.
        for (text, page, buttons) in [
            (1.0, 150, 134),
            (1.25, 172, 156),
            (1.5, 172, 156),
            (1.25, 194, 178),
            (1.5, 194, 178),
        ] {
            for display in [1.0, 1.25, 1.5] {
                let physical = scaled(page, display * text);
                // What the page sees of the window, CSS px: physical over the page's own ratio.
                let visible = f64::from(physical) / (display * text);
                assert!(
                    visible + 0.5 >= f64::from(buttons),
                    "text {text}, display {display}: {visible} < {buttons}"
                );
                if (text - 1.0_f64).abs() < 1e-9 {
                    assert_eq!(physical, scaled(page, display), "100 % text: unchanged");
                }
            }
        }
    }

    /// «Разрешить» while the window is up: it waits for the question's height and is placed again
    /// for it; a late report for the first step does not shrink it back.
    #[test]
    fn the_request_window_is_resized_for_the_role_question() {
        let t0 = Instant::now();
        let mut p = Popup::default();
        p.route("r1", PairStep::Consent, t0);
        p.fit("r1", PairStep::Consent, 150, None);
        assert!(matches!(p.step(t0), PopupStep::Show { height: 150, .. }));

        assert!(p.set_step(PairStep::Role, t0));
        assert!(!p.set_step(PairStep::Role, t0), "once");
        assert_eq!(
            p.step(t0),
            PopupStep::Idle,
            "waits for the question's height"
        );
        assert!(
            !p.fit("r1", PairStep::Consent, 150, None),
            "the old step's height is not it"
        );
        assert_eq!(p.step(t0), PopupStep::Idle);
        assert!(p.fit("r1", PairStep::Role, 170, None));
        assert_eq!(p.step(t0), PopupStep::Resize { height: 170 });
        assert_eq!(p.step(t0), PopupStep::Idle);
    }

    /// The question's page silent past the wait: the question's own fallback, once.
    #[test]
    fn a_silent_role_question_gets_its_fallback_height() {
        let t0 = Instant::now();
        let mut p = Popup::default();
        p.route("r1", PairStep::Consent, t0);
        p.fit("r1", PairStep::Consent, 150, None);
        p.step(t0);
        p.set_step(PairStep::Role, t0);
        assert_eq!(
            p.step(t0 + FIT_WAIT - Duration::from_millis(1)),
            PopupStep::Idle
        );
        assert_eq!(
            p.step(t0 + FIT_WAIT),
            PopupStep::Resize {
                height: POPUP_ROLE_DEFAULT_HEIGHT
            }
        );
        assert_eq!(p.step(t0 + FIT_WAIT * 2), PopupStep::Idle);
    }

    /// A request drawn at «Кто это?» before it is routed (a window reloaded at the question) is
    /// shown at the question's height, never at the first step's.
    #[test]
    fn a_request_routed_at_the_role_question_shows_at_its_height() {
        let t0 = Instant::now();
        let mut p = Popup::default();
        p.fit("r1", PairStep::Consent, 150, None);
        p.fit("r1", PairStep::Role, 170, None);
        p.route("r1", PairStep::Role, t0);
        assert_eq!(
            p.step(t0),
            PopupStep::Show {
                height: 170,
                fitted: true
            }
        );
        // Only the first step's height known: it waits for the question's.
        let mut p = Popup::default();
        p.fit("r1", PairStep::Consent, 150, None);
        p.route("r1", PairStep::Role, t0);
        assert_eq!(p.step(t0), PopupStep::Wait);
    }

    /// Closed by hand while the request waits: nothing is placed or shown for it, until the owner
    /// opens the main window — then it is shown again at once, at its height. A request that goes
    /// meanwhile is not brought back.
    #[test]
    fn a_window_closed_by_hand_comes_back_when_the_main_window_is_opened() {
        let t0 = Instant::now();
        let mut p = Popup::default();
        assert!(!p.park(), "nothing routed");
        assert!(!p.reveal(), "nothing parked");
        p.route("r1", PairStep::Consent, t0);
        p.fit("r1", PairStep::Consent, 150, None);
        assert!(matches!(p.step(t0), PopupStep::Show { .. }));
        assert!(p.park());
        // A report or the question meanwhile places nothing.
        p.fit("r1", PairStep::Consent, 172, None);
        assert_eq!(p.step(t0), PopupStep::Idle);
        assert!(p.reveal());
        assert_eq!(
            p.step(t0),
            PopupStep::Show {
                height: 172,
                fitted: true
            }
        );
        assert!(!p.reveal(), "shown: nothing to bring back");
        // Gone while parked: a later reveal does nothing.
        assert!(p.park());
        assert!(p.clear());
        assert!(!p.reveal());
        assert_eq!(p.step(t0), PopupStep::Idle);
    }

    /// The fallbacks hold each step's tallest drawing — measured in the window's own page at 100,
    /// 125 and 150 % (CSS px do not grow with the display scale; the window is placed at the
    /// monitor's scale, `scaled`) — and still fit a 768 px tall screen at 150 %.
    #[test]
    fn the_fallback_heights_hold_both_steps_at_every_scale() {
        /// Tallest heights the page reported (CSS px): a three-line title under Windows'
        /// larger text (`POPUP_DEFAULT_HEIGHT`); the question, one line each.
        const CONSENT_TALLEST: u32 = 194;
        const ROLE_TALLEST: u32 = 170;
        assert!(PairStep::Consent.default_height() >= CONSENT_TALLEST);
        assert!(PairStep::Role.default_height() >= ROLE_TALLEST);
        for scale in [1.0, 1.25, 1.5] {
            for step in [PairStep::Consent, PairStep::Role] {
                let px = scaled(step.default_height(), scale);
                let tallest = match step {
                    PairStep::Consent => CONSENT_TALLEST,
                    PairStep::Role => ROLE_TALLEST,
                };
                assert!(px >= scaled(tallest, scale), "{step:?} at {scale}");
                assert!(
                    px + scaled(POPUP_MARGIN, scale) * 2 <= 768,
                    "{step:?} at {scale}: {px}"
                );
            }
        }
        const { assert!(POPUP_ROLE_DEFAULT_HEIGHT <= POPUP_MAX_HEIGHT) };
        // The window's size before any placement (tauri.conf.json, logical px, which Windows scales
        // by DPI alone) is where a window that could not be placed stays: it holds both steps too.
        let conf: serde_json::Value =
            serde_json::from_str(include_str!("../tauri.conf.json")).expect("tauri.conf.json");
        let window = conf["app"]["windows"]
            .as_array()
            .and_then(|w| w.iter().find(|w| w["label"] == WINDOW))
            .expect("the request window in tauri.conf.json");
        assert_eq!(window["width"].as_u64(), Some(u64::from(POPUP_WIDTH)));
        let height = window["height"].as_u64().expect("a height");
        assert!(
            height >= u64::from(CONSENT_TALLEST.max(ROLE_TALLEST)),
            "{height}"
        );
        assert_eq!(PairStep::parse("role"), Some(PairStep::Role));
        assert_eq!(PairStep::parse("consent"), Some(PairStep::Consent));
        assert_eq!(PairStep::parse("x"), None);
    }

    #[test]
    fn heights_from_the_page_are_clamped() {
        assert_eq!(clamp_height(163.2), Some(164));
        assert_eq!(clamp_height(10.0), Some(POPUP_MIN_HEIGHT));
        assert_eq!(clamp_height(5000.0), Some(POPUP_MAX_HEIGHT));
        assert_eq!(clamp_height(0.0), None);
        assert_eq!(clamp_height(f64::NAN), None);
        assert_eq!(clamp_height(-3.0), None);
    }

    // ---- The size: exactly the one asked, read back ----

    /// tao's undecorated window with a shadow, as measured on Windows 11 at 150 %: created
    /// with Windows' default frame (outer 592×307, client 570×251), its own thin frame (22×13) only
    /// once resized. `set_inner_size` adds the frame it measures (outer less client) to the size.
    struct TaoWindow {
        outer: (u32, u32),
        client: (u32, u32),
        sets: u32,
    }

    impl TaoWindow {
        const FRAME: (u32, u32) = (22, 13);

        fn fresh() -> Self {
            TaoWindow {
                outer: (592, 307),
                client: (570, 251),
                sets: 0,
            }
        }

        fn set(&mut self, asked: (u32, u32)) {
            self.sets += 1;
            self.outer = (
                asked.0 + self.outer.0 - self.client.0,
                asked.1 + self.outer.1 - self.client.1,
            );
            self.client = (self.outer.0 - Self::FRAME.0, self.outer.1 - Self::FRAME.1);
        }
    }

    #[test]
    fn the_first_size_of_a_fresh_window_is_set_again_and_comes_out_exact() {
        let w = std::cell::RefCell::new(TaoWindow::fresh());
        // What the owner got with one `set_size`: 43 px too tall.
        let mut once = TaoWindow::fresh();
        once.set((570, 225));
        assert_eq!(once.client, (570, 268));

        let sizing = size_exactly(
            "r1",
            (570, 225),
            |s| {
                w.borrow_mut().set(s);
                Ok(())
            },
            || Ok(w.borrow().client),
        )
        .unwrap();
        assert_eq!(sizing.tries, 2);
        assert_eq!(sizing.got, Ok((570, 225)));
        assert_eq!(w.borrow().client, (570, 225));

        // Once resized, a new size (the next request, a taller step) is exact at once.
        let sizing = size_exactly(
            "r2",
            (570, 264),
            |s| {
                w.borrow_mut().set(s);
                Ok(())
            },
            || Ok(w.borrow().client),
        )
        .unwrap();
        assert_eq!(sizing.tries, 1);
        assert_eq!(sizing.got, Ok((570, 264)));
        assert_eq!(w.borrow().sets, 3);
    }

    #[test]
    fn a_size_that_stays_off_is_set_twice_at_most_and_said() {
        let mut sets = 0;
        let sizing = size_exactly(
            "r1",
            (570, 225),
            |_| {
                sets += 1;
                Ok(())
            },
            || Ok((570, 294)),
        )
        .unwrap();
        assert_eq!(sets, SIZE_TRIES);
        assert_eq!(sizing.tries, SIZE_TRIES);
        assert_eq!(sizing.got, Ok((570, 294)));
    }

    #[test]
    fn a_size_not_set_or_not_read_back_ends_the_sizing() {
        let failed = size_exactly(
            "r1",
            (570, 225),
            |_| Err("set_size: gone".to_string()),
            || unreachable!("nothing to read after a failed set"),
        );
        assert_eq!(failed, Err("set_size: gone".to_string()));

        let mut sets = 0;
        let unread = size_exactly(
            "r1",
            (570, 225),
            |_| {
                sets += 1;
                Ok(())
            },
            || Err("inner_size: gone".to_string()),
        )
        .unwrap();
        assert_eq!(sets, 1, "an unread size is not set again blindly");
        assert_eq!(unread.got, Err("inner_size: gone".to_string()));
    }

    #[test]
    fn the_size_once_shown_is_checked_against_the_size_placed() {
        assert!(check_shown_size("r1", (570, 225), Ok((570, 225))));
        assert!(!check_shown_size("r1", (570, 225), Ok((570, 294))));
        assert!(!check_shown_size("r1", (570, 225), Err("gone".to_string())));
    }

    // ---- The place: near the tray, at the monitor's scale, whichever edge the taskbar is on ----

    const FULL_HD: Rect = Rect {
        x: 0,
        y: 0,
        width: 1920,
        height: 1080,
    };

    fn work(x: i32, y: i32, width: u32, height: u32) -> Rect {
        Rect {
            x,
            y,
            width,
            height,
        }
    }

    #[test]
    fn bottom_right_above_a_bottom_taskbar_at_100_percent() {
        let area = work(0, 0, 1920, 1032);
        assert_eq!(taskbar_edge(FULL_HD, area), TaskbarEdge::Bottom);
        let size = (scaled(POPUP_WIDTH, 1.0), scaled(164, 1.0));
        assert_eq!(size, (380, 164));
        assert_eq!(
            popup_position(FULL_HD, area, size, scaled(POPUP_MARGIN, 1.0)),
            (1920 - 380 - 12, 1032 - 164 - 12)
        );
    }

    #[test]
    fn bottom_right_at_150_percent_in_physical_pixels() {
        // 2560×1440 at 150 %: a 72 px taskbar.
        let monitor = work(0, 0, 2560, 1440);
        let area = work(0, 0, 2560, 1368);
        let size = (scaled(POPUP_WIDTH, 1.5), scaled(164, 1.5));
        assert_eq!(size, (570, 246));
        assert_eq!(
            popup_position(monitor, area, size, scaled(POPUP_MARGIN, 1.5)),
            (2560 - 570 - 18, 1368 - 246 - 18)
        );
    }

    #[test]
    fn follows_the_taskbar_to_the_top_left_and_right() {
        let size = (380, 164);
        let top = work(0, 48, 1920, 1032);
        assert_eq!(taskbar_edge(FULL_HD, top), TaskbarEdge::Top);
        assert_eq!(
            popup_position(FULL_HD, top, size, 12),
            (1920 - 380 - 12, 48 + 12)
        );
        let left = work(62, 0, 1858, 1080);
        assert_eq!(taskbar_edge(FULL_HD, left), TaskbarEdge::Left);
        assert_eq!(
            popup_position(FULL_HD, left, size, 12),
            (62 + 12, 1080 - 164 - 12)
        );
        let right = work(0, 0, 1858, 1080);
        assert_eq!(taskbar_edge(FULL_HD, right), TaskbarEdge::Right);
        assert_eq!(
            popup_position(FULL_HD, right, size, 12),
            (1858 - 380 - 12, 1080 - 164 - 12)
        );
        // Auto-hidden: the work area is the monitor; bottom-right, like Windows' notifications.
        assert_eq!(taskbar_edge(FULL_HD, FULL_HD), TaskbarEdge::None);
        assert_eq!(
            popup_position(FULL_HD, FULL_HD, size, 12),
            (1920 - 380 - 12, 1080 - 164 - 12)
        );
    }

    #[test]
    fn a_primary_monitor_off_the_origin_and_a_tiny_screen() {
        // A primary monitor left of another one: negative coordinates.
        let monitor = work(-1920, 0, 1920, 1080);
        let area = work(-1920, 0, 1920, 1040);
        assert_eq!(
            popup_position(monitor, area, (380, 164), 12),
            (-380 - 12, 1040 - 164 - 12)
        );
        // Smaller than the window: pinned to the work area's top-left, never off it.
        let small = work(0, 0, 300, 120);
        assert_eq!(popup_position(small, small, (380, 164), 12), (0, 0));
    }

    /// «Разрешить» on a prompt that asks «Кто это?» puts that request at the question, and only
    /// that request.
    #[test]
    fn allow_puts_the_request_at_the_role_question() {
        let (prompt, _woken) = PairPrompt::new();
        assert_eq!(prompt.step_for("r1"), PairStep::Consent);
        assert!(prompt.allow("r1"));
        assert!(!prompt.allow("r1"), "once");
        assert_eq!(prompt.step_for("r1"), PairStep::Role);
        assert_eq!(
            prompt.step_for("r2"),
            PairStep::Consent,
            "another request starts at the first step"
        );
    }
}
