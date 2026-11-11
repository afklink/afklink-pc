//! «Only the game window»: the viewer sees one window the owner bound on this PC — the game — and
//! nothing else, never the desktop and never another window.
//!
//! Everything here is platform-free; the Windows halves (the window list read with `EnumWindows`
//! and the WGC window capture) are `afklink_capture::game`, behind [`WindowSource`] and
//! [`WindowCaptureBackend`]. What lives here:
//!
//! - the binding stored in config.json ([`GameBinding`]) and the capture mode it selects for a
//!   session ([`CaptureMode`], [`CaptureModeCell`], [`SessionCapture`]);
//! - the finder: which top-level window is the game, and in what state ([`GameFinder`]);
//! - the crop from a window capture's frame to the window's client area, a window Windows stretches
//!   for DPI included ([`client_crop`]), and where that picture is on screen;
//! - the capturer the session runs in this mode ([`GameCapturer`]): it polls the finder, starts the
//!   window capture on the game's window, re-creates it on a new window (a relaunch), and sends
//!   black frames whenever the window cannot be shown;
//! - what the heartbeat, the pipeline line and the input side read ([`GameStatus`]).
//!
//! ## Fail closed
//!
//! In this mode the monitor capturer is never constructed. [`SessionCapture`] is the only place a
//! session makes capturers, at its start and on every restart the pipeline supervisor makes; in
//! game mode it calls the game factory and nothing else, whatever failed before. The game capturer
//! has two sources of frames and no third: the window capture of a window the finder matched on the
//! bound exe path **and** window class, cropped to its client area, and black frames. Any error
//! (the window list unreadable, the capture refusing to start, a frame that cannot be read or
//! cropped, the window closing) ends in black frames, never in anything wider. WGC's window capture
//! composes the window alone: other windows over it do not appear in its frames, and
//! `IncludeSecondaryWindows`, which lets other processes' windows in (measured), is never set.
//!
//! A frame of a capture made for another mode never reaches the encoder either
//! ([`SessionCapture::admits_frames`]). How input is confined to the game is on
//! [`GameStatus::game_scope`].

use std::collections::HashSet;
use std::sync::atomic::AtomicU8;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use afklink_protocol::{GameHeartbeat, GameWindowState};
use serde::{Deserialize, Serialize};
use tokio::sync::Notify;

use crate::agent::Backends;
use crate::config::Config;
use crate::quality::QualityTarget;
use crate::scale::fit_within;
use crate::sync::lock;
use crate::traits::{Capturer, GameInputWindow, GameScope};
use crate::types::Frame;

/// How often the finder looks for the game's window.
///
/// A quarter of a second: a minimize or a relaunch reaches the viewer as black frames within that,
/// and one poll — a process snapshot and a walk of the top-level windows — costs about a
/// millisecond on the capture's own thread, off the frame path.
pub const FINDER_POLL: Duration = Duration::from_millis(250);

/// How often a black frame goes out while the window cannot be shown.
///
/// Often enough that a viewer's keyframe request is answered within half a second (the encoder
/// needs a frame to make one), rare enough that encoding black costs nothing.
pub const BLACK_EVERY: Duration = Duration::from_millis(500);

/// The black frames' size before any frame of the game was captured this session: 16:9 at 720
/// lines, scaled to the rung like any frame. Afterwards they have the game picture's last size, so
/// the viewer's picture does not change shape when the game is minimized.
pub const BLACK_SOURCE: (u32, u32) = (1280, 720);

/// A window capture that has not delivered one frame this long after it started is given up on and
/// started again. WGC's first frame of a window comes in about 20 ms (measured); a crop refused
/// frame after frame looks the same from here.
pub const FIRST_FRAME_WITHIN: Duration = Duration::from_secs(3);

/// The pause before the window capture is started again after it failed, doubling to
/// [`RETRY_MAX`], and back to this once a capture has run for [`RETRY_RESET_AFTER`].
const RETRY_MIN: Duration = Duration::from_secs(1);
const RETRY_MAX: Duration = Duration::from_secs(10);
const RETRY_RESET_AFTER: Duration = Duration::from_secs(10);

/* ── The binding and the mode ──────────────────────────────────────────────────────────────── */

/// The game the owner bound on this PC: its window is matched on the process's full exe path and
/// the window's class, never on the title (the owner's game changes it to the character's name).
///
/// Stored in config.json as `game`; set only by the desktop app on this PC.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GameBinding {
    /// The full path of the exe that owns the game's window (`QueryFullProcessImageNameW`), e.g.
    /// `D:\Games\Scryde\Scryde\ScrydeGame.bin` — the process holding the window, not its launcher.
    pub exe_path: String,
    /// The window's class, e.g. `ScrydeGameUnrealWWindowsViewportWindow`.
    pub window_class: String,
    /// What the desktop app shows for it: the exe's file name.
    #[serde(default)]
    pub display_name: String,
}

impl GameBinding {
    /// A binding for the window of `exe_path` with class `window_class`, named by the exe's file
    /// name.
    pub fn new(exe_path: &str, window_class: &str) -> Self {
        let exe_path = exe_path.trim().to_string();
        Self {
            display_name: exe_file_name(&exe_path).to_string(),
            window_class: window_class.trim().to_string(),
            exe_path,
        }
    }

    /// Why this binding can match nothing, if it cannot: a hand-edited config.json.
    pub fn unusable(&self) -> Option<&'static str> {
        if self.exe_path.trim().is_empty() {
            Some("the bound exe path is empty")
        } else if self.window_class.trim().is_empty() {
            Some("the bound window class is empty")
        } else {
            None
        }
    }

    /// The name the window shows: the stored one, else the exe's file name.
    pub fn shown_name(&self) -> &str {
        if self.display_name.trim().is_empty() {
            exe_file_name(&self.exe_path)
        } else {
            &self.display_name
        }
    }

    /// The exe's file name, for the process snapshot's first filter.
    pub fn exe_file_name(&self) -> &str {
        exe_file_name(&self.exe_path)
    }

    /// `path` is the bound exe. Windows paths are case-insensitive, and either slash is a
    /// separator.
    pub fn exe_matches(&self, path: &str) -> bool {
        normalized_path(&self.exe_path) == normalized_path(path)
    }

    /// `class` is the bound window class. Class names are case-insensitive in Win32.
    pub fn class_matches(&self, class: &str) -> bool {
        self.window_class.trim().to_lowercase() == class.trim().to_lowercase()
    }
}

/// The file name at the end of a Windows path.
pub fn exe_file_name(path: &str) -> &str {
    let path = path.trim();
    path.rsplit(['\\', '/']).next().unwrap_or(path)
}

fn normalized_path(path: &str) -> String {
    path.trim().replace('/', "\\").to_lowercase()
}

/// What a session captures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CaptureMode {
    /// The primary monitor: the whole desktop, as always.
    Monitor,
    /// The bound game's window and nothing else. `None`: the mode is on and no game is bound —
    /// black frames only, which is the fail-closed reading of a hand-edited config.json.
    GameWindow { binding: Option<GameBinding> },
}

impl CaptureMode {
    /// The mode config.json asks for a session game-only applies to. Whether it applies to a given
    /// session — with «Только для гостей» on, only to guests' — is `crate::game_access`'s decision.
    pub fn from_config(config: &Config) -> Self {
        if config.game_only {
            Self::GameWindow {
                binding: config.game.clone(),
            }
        } else {
            Self::Monitor
        }
    }

    pub fn is_game(&self) -> bool {
        matches!(self, Self::GameWindow { .. })
    }

    /// For log lines.
    pub fn describe(&self) -> String {
        match self {
            Self::Monitor => "the primary monitor (game-only off)".to_string(),
            Self::GameWindow { binding: None } => {
                "the game window only, with no game bound (black frames only)".to_string()
            }
            Self::GameWindow {
                binding: Some(binding),
            } => format!(
                "the game window only: {} (exe {:?}, class {:?})",
                binding.shown_name(),
                binding.exe_path,
                binding.window_class
            ),
        }
    }
}

/// The capture mode in force for one session — the monitor, or the bound game's window only — as
/// `crate::game_access` decides it from the owner's settings and the role the server gave the
/// viewer, and decides it again whenever either changes. Shared by everything of the session that
/// asks: its pipeline supervisor ([`SessionCapture`]), its input scope (`crate::game_input`) and
/// its clipboard (`crate::clipboard`).
///
/// A change is picked up by the session within `pipeline::SUPERVISE_EVERY`: the owner who turns the
/// mode on while someone is connected — or a guest who becomes the owner with «Только для гостей»
/// on — is not left with the old picture until they reconnect. The generation tells the session
/// that its capture was made for an older mode.
#[derive(Debug)]
pub struct CaptureModeCell {
    /// Whose mode this is, for the log: a session's id, or `-`.
    session: String,
    mode: Mutex<CaptureMode>,
    generation: AtomicU64,
}

impl CaptureModeCell {
    /// A cell of no particular session (tests).
    pub fn new(mode: CaptureMode) -> Self {
        Self::for_session("-", mode)
    }

    /// Session `session`'s cell, starting in `mode`.
    pub fn for_session(session: &str, mode: CaptureMode) -> Self {
        Self {
            session: session.to_string(),
            mode: Mutex::new(mode),
            generation: AtomicU64::new(0),
        }
    }

    /// The mode, and the generation it is.
    pub fn current(&self) -> (CaptureMode, u64) {
        let mode = lock(&self.mode);
        (mode.clone(), self.generation.load(Ordering::SeqCst))
    }

    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::SeqCst)
    }

    /// The game-only mode is in force now. Under the lock, like [`Self::set`]: whoever flips the
    /// setting is seen by the next call, with nothing cloned (input asks on every event).
    pub fn is_game(&self) -> bool {
        lock(&self.mode).is_game()
    }

    /// `mode` is the one in force now (under the lock, as [`Self::is_game`]).
    pub fn is(&self, mode: &CaptureMode) -> bool {
        *lock(&self.mode) == *mode
    }

    /// Put `mode` in force. True if it changed, which moves the session to it.
    pub fn set(&self, mode: CaptureMode, why: &str) -> bool {
        let mut current = lock(&self.mode);
        if *current == mode {
            tracing::debug!(
                session = %self.session,
                mode = %mode.describe(),
                why,
                "capture mode unchanged"
            );
            return false;
        }
        tracing::info!(
            session = %self.session,
            from = %current.describe(),
            to = %mode.describe(),
            why,
            "capture mode changed; the session switches to it"
        );
        *current = mode;
        // Under the lock, so a reader that sees the new generation also reads the new mode.
        self.generation.fetch_add(1, Ordering::SeqCst);
        true
    }
}

/// The PC's game helper (the desktop app's «Запускать игру автоматически», `afklink_game_helper`)
/// has launched the bound game itself during a session and waits for its window: from its launch to
/// the window, a failed start or its giving up — or is about to launch it again: its window gone
/// while its process runs (a crash report keeping it alive) and while the helper closes it
/// as hung, when a launch follows. Never for a game started by hand before its window is up, one
/// Windows refused to close, or the pause before the next launch after a failed start.
///
/// Set only by the desktop app, from the helper's `state.json` (`launch_pending`, while the app
/// lets the helper act); never by the CLI, which has no helper. Shared by every live session's
/// heartbeat, which says `game.launching` while the window is `absent` or `starting` — the viewer's
/// «Игра запускается» in place of «Игра не запущена»
/// (`afklink_protocol::GameHeartbeat::with_launching`).
#[derive(Debug, Default)]
pub struct HelperLaunch {
    launching: AtomicBool,
    /// Wakes every live session's heartbeat on a change, so the viewer hears it at once.
    changed: Notify,
}

impl HelperLaunch {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_launching(&self) -> bool {
        self.launching.load(Ordering::SeqCst)
    }

    /// Put `launching` in force; `why` is what the desktop app read. A change is logged with it and
    /// wakes the heartbeats; the same value again does nothing. True when it changed.
    pub fn set(&self, launching: bool, why: &str) -> bool {
        if self.launching.swap(launching, Ordering::SeqCst) == launching {
            return false;
        }
        tracing::info!(
            launching,
            why,
            "game helper's launch: {}",
            if launching {
                "the helper launched the game and waits for its window; heartbeats say `launching` \
                 while the window is absent or starting"
            } else {
                "no launch of the helper's waits for the window any more; heartbeats stop saying \
                 `launching`"
            }
        );
        self.changed.notify_waiters();
        true
    }

    /// Resolves on the next change. For the heartbeat task's `select!`.
    pub fn changed(&self) -> &Notify {
        &self.changed
    }
}

/// What the game factory is handed: the binding, and where the capturer publishes what it sees.
pub struct GameCaptureRequest {
    pub binding: Option<GameBinding>,
    pub status: Arc<GameStatus>,
}

/// How one session makes its capturers: in the mode in force when it started, and in the new one
/// once its cell changes — the owner's settings or the viewer's role, `crate::game_access`. The
/// only caller of either capturer factory for a session (the module's «Fail closed»).
pub struct SessionCapture {
    backends: Arc<Backends>,
    modes: Arc<CaptureModeCell>,
    mode: CaptureMode,
    generation: u64,
    game: Arc<GameStatus>,
}

impl SessionCapture {
    pub fn new(
        backends: Arc<Backends>,
        modes: Arc<CaptureModeCell>,
        game: Arc<GameStatus>,
    ) -> Self {
        let (mode, generation) = modes.current();
        game.set_active(mode.is_game());
        Self {
            backends,
            modes,
            mode,
            generation,
            game,
        }
    }

    pub fn mode(&self) -> &CaptureMode {
        &self.mode
    }

    pub fn backends(&self) -> &Arc<Backends> {
        &self.backends
    }

    /// Make a capturer for this session's mode. In game mode the monitor factory is not called —
    /// not as a first choice, and not after anything failed.
    pub fn make(&self) -> anyhow::Result<Box<dyn Capturer>> {
        match &self.mode {
            CaptureMode::Monitor => (self.backends.make_capturer)(),
            CaptureMode::GameWindow { binding } => {
                (self.backends.make_game_capturer)(&GameCaptureRequest {
                    binding: binding.clone(),
                    status: self.game.clone(),
                })
            }
        }
    }

    /// The session's mode changed since it last looked (the owner's settings, or the viewer's role
    /// with «Только для гостей» on): take the new one and return the one it replaces. The caller
    /// restarts the capture.
    pub fn take_change(&mut self) -> Option<CaptureMode> {
        if self.modes.generation() == self.generation {
            return None;
        }
        let (mode, generation) = self.modes.current();
        self.generation = generation;
        if mode == self.mode {
            return None;
        }
        self.game.set_active(mode.is_game());
        Some(std::mem::replace(&mut self.mode, mode))
    }

    /// Whether an absolute pointer move on the screen must produce a frame of this capture. Not in
    /// game mode: the cursor can be outside the game's window, and the game's own capturer knows
    /// better than the pointer why nothing comes (a minimized window, black frames).
    pub fn answers_pointer_moves(&self) -> bool {
        !self.mode.is_game()
    }

    /// Whether a frame of this session's capture may reach the encoder now: only while the mode it
    /// was made for is still the one in force. Read for every frame, under the mode's lock, so the
    /// frames of the monitor's capture stop the moment the owner turns game-only on — before the
    /// supervisor's next look ([`Self::take_change`]) replaces the capture — and those of a game
    /// capture the moment the owner binds another game.
    pub fn admits_frames(&self) -> bool {
        self.modes.is(&self.mode)
    }
}

/* ── Geometry and the crop ─────────────────────────────────────────────────────────────────── */

/// A rectangle on screen, physical pixels, right and bottom exclusive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ScreenRect {
    pub left: i32,
    pub top: i32,
    pub right: i32,
    pub bottom: i32,
}

impl ScreenRect {
    pub fn width(&self) -> i64 {
        i64::from(self.right) - i64::from(self.left)
    }

    pub fn height(&self) -> i64 {
        i64::from(self.bottom) - i64::from(self.top)
    }

    pub fn is_empty(&self) -> bool {
        self.width() <= 0 || self.height() <= 0
    }
}

impl std::fmt::Display for ScreenRect {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "[{},{},{},{}]",
            self.left, self.top, self.right, self.bottom
        )
    }
}

/// How a window handles the display's scale (`GetWindowDpiAwarenessContext`), for the log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DpiAwareness {
    Unaware,
    /// Unaware, with its GDI drawing done at a higher resolution before the stretch.
    UnawareGdiScaled,
    System,
    PerMonitor,
    PerMonitorV2,
    /// Windows named none of the above (a window being destroyed).
    Unknown,
}

impl DpiAwareness {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unaware => "unaware",
            Self::UnawareGdiScaled => "unaware (GDI scaled)",
            Self::System => "system aware",
            Self::PerMonitor => "per-monitor aware",
            Self::PerMonitorV2 => "per-monitor aware v2",
            Self::Unknown => "unknown",
        }
    }
}

/// The DPI a window draws at and the DPI of the monitor it is on. Where they differ, DWM stretches
/// the window's pixels by their ratio («bitmap stretching», Microsoft's High DPI guide): an unaware
/// window draws at 96 on every monitor, a system-aware one at the DPI the session started with; a
/// per-monitor aware one draws at its monitor's and is never stretched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WindowDpi {
    pub awareness: DpiAwareness,
    /// `GetDpiForWindow`: 96 for an unaware window; 0 when it could not be read.
    pub window: u32,
    /// The effective DPI of the monitor the window is mostly on; 0 when it could not be read.
    pub monitor: u32,
}

impl WindowDpi {
    /// Neither DPI known: the crop takes the client area as Windows reports it.
    pub const UNKNOWN: Self = Self {
        awareness: DpiAwareness::Unknown,
        window: 0,
        monitor: 0,
    };

    /// The factor DWM stretches the window's own pixels by — the monitor's DPI over the window's —
    /// or `None` when it does not stretch it (the two DPIs the same) or either DPI is unknown.
    pub fn stretch(&self) -> Option<f64> {
        (self.window > 0 && self.monitor > 0 && self.window != self.monitor)
            .then(|| f64::from(self.monitor) / f64::from(self.window))
    }
}

impl std::fmt::Display for WindowDpi {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}/{} {}",
            self.window,
            self.monitor,
            self.awareness.as_str()
        )
    }
}

/// What a stretched window's crop is worked out from, beside the per-monitor rectangles.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OwnRects {
    /// The whole window rectangle as a per-monitor aware thread reads it, invisible resize borders
    /// included: DWM's bounds are this one inset by whole pixels, and the frame starts there.
    pub window_px: ScreenRect,
    /// The window rectangle in the window's own units (read with the thread switched to the
    /// window's DPI awareness): exact, where the per-monitor one is rounded.
    pub window: ScreenRect,
    /// The client area on screen in the window's own units: exact, like `window`.
    pub client: ScreenRect,
}

/// Where a window is, as a window capture's frame needs it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WindowGeometry {
    /// What DWM draws of the window (`DWMWA_EXTENDED_FRAME_BOUNDS`, never DPI-virtualised): the
    /// area a window capture's frame shows, title bar and borders included.
    pub bounds: ScreenRect,
    /// The client area on screen, as a per-monitor aware thread reads it: the game's own picture.
    /// Physical pixels — for a stretched window each edge rounded to a whole pixel by Windows.
    pub client: ScreenRect,
    /// The DPI the window draws at, and its monitor's.
    pub dpi: WindowDpi,
    /// A stretched window's own rectangles ([`WindowDpi::stretch`]); `None` for a window that is
    /// not stretched, whose per-monitor rectangles are exact — and for a stretched one whose own
    /// rectangles could not be read (the reader says why, and [`client_crop`] falls back).
    pub own: Option<OwnRects>,
}

/// A rectangle of a frame, in the frame's pixels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Crop {
    pub x: u32,
    pub y: u32,
    pub w: u32,
    pub h: u32,
}

impl std::fmt::Display for Crop {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}x{}+{}+{}", self.w, self.h, self.x, self.y)
    }
}

/// Why a frame could not be cropped to the client area. The frame is dropped: its uncropped pixels
/// never go out.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CropRefusal {
    /// The frame has no pixels to speak of.
    EmptyFrame { w: u32, h: u32 },
    /// The window's bounds or client area are empty (minimized, being destroyed).
    EmptyWindow,
    /// The frame's size does not follow from the window's bounds — a resize between the frame and
    /// the reading. The next frame has the new size.
    SizeMismatch { sx: f64, sy: f64 },
    /// The client area lies outside the frame.
    Outside,
}

impl std::fmt::Display for CropRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyFrame { w, h } => write!(f, "the frame is {w}x{h}"),
            Self::EmptyWindow => write!(f, "the window's bounds or client area are empty"),
            Self::SizeMismatch { sx, sy } => write!(
                f,
                "the frame does not match the window's bounds (scale {sx:.4} x {sy:.4}): a resize \
                 in flight"
            ),
            Self::Outside => write!(f, "the client area lies outside the frame"),
        }
    }
}

/// Frame and bounds this close in size are the same size: the frame is the window's bounds.
const SAME_SIZE_PX: i64 = 2;

/// A scale between the frame and the bounds this close to 1 is a resize in flight, not a scaled
/// capture.
const SCALE_NEAR_ONE: f64 = 0.03;

/// Two axes' scales this far apart are a resize in flight, not a scaled capture.
const SCALE_SKEW: f64 = 0.01;

/// A fraction this close to a whole pixel is that pixel: the scales are ratios of DPIs (1.2 is not
/// exact in binary), and an edge on a whole pixel must not round a pixel further in.
const EDGE_EPSILON: f64 = 1e-6;

/// What [`client_crop`] decided, and the numbers behind it for the log.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ClientCrop {
    /// The rectangle of the frame that goes out.
    pub crop: Crop,
    /// The same rectangle on screen, physical pixels: the picture the viewer sees, which the input
    /// side maps `m` and `r.x/y` into ([`CaptureGeometry::client`]). For a stretched window it is
    /// the frame's placement by DWM's bounds — within half a pixel of where DWM shows it.
    pub on_screen: ScreenRect,
    /// The client area as Windows reports it, in the frame's pixels and clamped to the frame
    /// (left, top, right, bottom): what the crop was before stretched windows were worked out.
    pub reported: [i64; 4],
    /// How far each edge of the crop lies inside `reported` (left, top, right, bottom): rounding
    /// inward on a stretched window, and an odd size's last column or row.
    pub inset: [i64; 4],
    /// A stretched window's numbers; `None` when the window is not stretched.
    pub stretched: Option<StretchedCrop>,
    /// Why the crop is what it is, in words, for the log.
    pub why: &'static str,
}

/// How a stretched window's crop was worked out, in the frame's pixels.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct StretchedCrop {
    /// The factor DWM stretches the window by ([`WindowDpi::stretch`]).
    pub scale: f64,
    /// The client area's own rectangle times `scale`, unsnapped (left, top, right, bottom);
    /// `None` when the own rectangles are unknown.
    pub exact: Option<[f64; 4]>,
    /// The fractional edges the crop rounds inward (ceil on the left and top, floor on the right
    /// and bottom).
    pub edges: [f64; 4],
}

impl ClientCrop {
    /// `inset` as the log says it: `l1 t2 r1 b0`.
    pub fn inset_text(&self) -> String {
        let [l, t, r, b] = self.inset;
        format!("l{l} t{t} r{r} b{b}")
    }
}

/// `x` rounded to the nearest whole number, halves up: how Windows rounds a stretched window's
/// coordinates (measured: 46.5 → 47, 508.5 → 509).
fn round_half_up(x: f64) -> f64 {
    (x + 0.5 + EDGE_EPSILON).floor()
}

/// The edges of a stretched window's client area that hold nothing but its own pixels, in the
/// bounds' pixels (left, top, right, bottom; fractional, to be rounded inward) — and the client's
/// own rectangle times `scale`, unsnapped, for the log. `None` for an own rectangle with no size.
///
/// See [`client_crop`] for what was measured. Here, per axis, with `c` the client's offset in the
/// window and `n` its size, both in the window's own units:
///
/// - where DWM puts the client: `k·c`, snapped to a whole pixel or not, for each scale `k` it may
///   use — `scale`, or the window's whole-pixel size over its own (measured on a window without a
///   DWM frame: 509/339, not 1.5) — counted from the start of the frame, which is DWM's bounds'
///   inset into the whole window (`bounds - window_px`);
/// - the near edge: the latest of those places, the far edge: the earliest plus `n` times the
///   smallest `k` — so the crop holds whichever DWM used;
/// - both moved in by the bilinear filter's reach, `(k - 1) / 2` of a pixel past the edge when
///   stretching up: the pixel whose centre lies that close still mixes in what is past the edge.
fn stretched_edges(scale: f64, g: &WindowGeometry, own: &OwnRects) -> Option<([f64; 4], [f64; 4])> {
    let (window_w, window_h) = (own.window.width() as f64, own.window.height() as f64);
    let (client_w, client_h) = (own.client.width() as f64, own.client.height() as f64);
    if window_w <= 0.0 || window_h <= 0.0 || client_w <= 0.0 || client_h <= 0.0 {
        return None;
    }
    let scales = [
        scale,
        round_half_up(scale * window_w) / window_w,
        round_half_up(scale * window_h) / window_h,
    ];
    let k_lo = scales.iter().copied().fold(f64::INFINITY, f64::min);
    let k_hi = scales.iter().copied().fold(f64::NEG_INFINITY, f64::max);
    let reach = ((k_hi - 1.0) / 2.0).max(0.0);
    // Where the client's near edge may be in the whole window's pixels: (earliest, latest).
    let placed = |c: f64| {
        scales
            .iter()
            .fold((f64::INFINITY, f64::NEG_INFINITY), |(lo, hi), k| {
                let at = k * c;
                let snapped = round_half_up(at);
                (lo.min(at).min(snapped), hi.max(at).max(snapped))
            })
    };
    let c_left = f64::from(own.client.left) - f64::from(own.window.left);
    let c_top = f64::from(own.client.top) - f64::from(own.window.top);
    let inset_left = f64::from(g.bounds.left) - f64::from(own.window_px.left);
    let inset_top = f64::from(g.bounds.top) - f64::from(own.window_px.top);
    let (left_lo, left_hi) = placed(c_left);
    let (top_lo, top_hi) = placed(c_top);
    let exact = [
        scale * c_left - inset_left,
        scale * c_top - inset_top,
        scale * (c_left + client_w) - inset_left,
        scale * (c_top + client_h) - inset_top,
    ];
    let edges = [
        left_hi - inset_left + reach,
        top_hi - inset_top + reach,
        left_lo - inset_left + k_lo * client_w - reach,
        top_lo - inset_top + k_lo * client_h - reach,
    ];
    Some((edges, exact))
}

/// The part of a window capture's frame that is the window's client area: the title bar and borders
/// a windowed game has around its picture are cut off (measured: a windowed frame includes
/// them) — and on a window Windows stretches for DPI, the rows and columns the stretch blends with
/// them too.
///
/// The frame shows the window's DWM bounds. When the two have the same size (within
/// [`SAME_SIZE_PX`]), the frame's pixels are the bounds'. When they do not, the frame is either a
/// scaled capture — the same scale on both axes, clearly away from 1 — and every edge is scaled
/// with it, or a resize caught between the frame and the reading, and the frame is refused.
///
/// A window that is not stretched (per-monitor aware, or drawing at its monitor's DPI) is cropped
/// to its client area as Windows reports it: pixel-exact, nothing of the game lost.
///
/// ## A stretched window
///
/// An unaware game on a 150 % monitor draws at 96 DPI and DWM stretches it ×1.5; a system-aware one
/// is stretched on a monitor whose DPI differs from the session's. Measured on Windows 11 26100 at
/// 150 % with a probe window of the agent's own (green client, coloured frame, read pixel by
/// pixel); a real game's logged numbers fit the same rules to the pixel:
///
/// - the frame is the window's own bitmap stretched, aligned to the window, not to the screen:
///   moving the window by one of its own pixels — half a physical one — leaves the frame identical,
///   while the client rectangle a per-monitor aware thread reads, each edge rounded on its own,
///   moves a pixel against DWM's bounds. So the reported client area can start a row early: the
///   owner's game (bounds `[562,191,3444,1859]`, client `[563,237,3443,1857]`) was cropped from row
///   46, which is the title bar's last row — the white line at the top of the picture;
/// - DWM puts the client area on a whole pixel of the window (its 46.5 at 47) and stretches it
///   with a bilinear filter: the first row and column take a sixth of what lies past the edge (at
///   150 %), a faint line even where the edge sits on a whole pixel.
///
/// So a stretched window's crop is worked out from its own rectangles, which are exact
/// (`stretched_edges`), then rounded inward. It gives up the blended row or column on each side —
/// one more where it cannot tell which placement DWM used — and never reaches past the client area
/// Windows reports. When a stretched window's own rectangles could not be read (switching the
/// reading thread to the window's DPI awareness failed, or a read in it — the reader logs why once
/// per change), its frames are not refused: each edge moves in a pixel past the filter's reach from
/// the reported one instead, which holds wherever the reported edge's rounding put it.
///
/// The crop is clamped to the frame and made even on both sides — the right column and bottom row
/// go (I420 needs even dimensions; an odd one would be resampled on every frame).
pub fn client_crop(
    frame_w: u32,
    frame_h: u32,
    g: &WindowGeometry,
) -> Result<ClientCrop, CropRefusal> {
    if frame_w < 2 || frame_h < 2 {
        return Err(CropRefusal::EmptyFrame {
            w: frame_w,
            h: frame_h,
        });
    }
    if g.bounds.is_empty() || g.client.is_empty() {
        return Err(CropRefusal::EmptyWindow);
    }
    let (fw, fh) = (i64::from(frame_w), i64::from(frame_h));
    let (bw, bh) = (g.bounds.width(), g.bounds.height());
    // The frame's pixels per bounds pixel.
    let (sx, sy) = if (fw - bw).abs() <= SAME_SIZE_PX && (fh - bh).abs() <= SAME_SIZE_PX {
        (1.0, 1.0)
    } else {
        let sx = fw as f64 / bw as f64;
        let sy = fh as f64 / bh as f64;
        let skewed = (sx - sy).abs() > SCALE_SKEW * sx.max(sy);
        let near_one = (sx - 1.0).abs() < SCALE_NEAR_ONE;
        if skewed || near_one {
            return Err(CropRefusal::SizeMismatch { sx, sy });
        }
        (sx, sy)
    };
    let offset = |v: i32, origin: i32| (i64::from(v) - i64::from(origin)) as f64;
    // The client area as Windows reports it, in the bounds' pixels.
    let reported_b = [
        offset(g.client.left, g.bounds.left),
        offset(g.client.top, g.bounds.top),
        offset(g.client.right, g.bounds.left),
        offset(g.client.bottom, g.bounds.top),
    ];
    let to_frame = |e: [f64; 4]| [e[0] * sx, e[1] * sy, e[2] * sx, e[3] * sy];
    let reported_f = to_frame(reported_b);
    let reported = [
        (reported_f[0].round() as i64).clamp(0, fw),
        (reported_f[1].round() as i64).clamp(0, fh),
        (reported_f[2].round() as i64).clamp(0, fw),
        (reported_f[3].round() as i64).clamp(0, fh),
    ];
    let (edges, stretched, why) = match g.dpi.stretch() {
        None if g.dpi.window == 0 || g.dpi.monitor == 0 => (
            reported.map(|v| v as f64),
            None,
            "the window's DPI is unknown: the client area as Windows reports it",
        ),
        None => (
            reported.map(|v| v as f64),
            None,
            "not stretched (the window draws at its monitor's DPI): the client area as Windows \
             reports it, pixel-exact",
        ),
        Some(scale) => match g
            .own
            .as_ref()
            .and_then(|own| stretched_edges(scale, g, own))
        {
            Some((edges, exact)) => {
                let edges = to_frame(edges);
                (
                    edges,
                    Some(StretchedCrop {
                        scale,
                        exact: Some(to_frame(exact)),
                        edges,
                    }),
                    "stretched by DWM: worked out from the window's own client rect, moved in past \
                     its whole-pixel placement and the filter's reach",
                )
            }
            None => {
                let away = 1.0 + ((scale - 1.0) / 2.0).max(0.0);
                let edges = to_frame([
                    reported_b[0] + away,
                    reported_b[1] + away,
                    reported_b[2] - away,
                    reported_b[3] - away,
                ]);
                (
                    edges,
                    Some(StretchedCrop {
                        scale,
                        exact: None,
                        edges,
                    }),
                    "stretched by DWM, its own rectangles unread: every edge moved in a pixel past \
                     the filter's reach from the client area Windows reports",
                )
            }
        },
    };
    // Inward, and never past what Windows calls the client area (which is clamped to the frame).
    let left = ((edges[0] - EDGE_EPSILON).ceil() as i64).max(reported[0]);
    let top = ((edges[1] - EDGE_EPSILON).ceil() as i64).max(reported[1]);
    let right = ((edges[2] + EDGE_EPSILON).floor() as i64).min(reported[2]);
    let bottom = ((edges[3] + EDGE_EPSILON).floor() as i64).min(reported[3]);
    let (w, h) = ((right - left) & !1, (bottom - top) & !1);
    if w < 2 || h < 2 {
        return Err(CropRefusal::Outside);
    }
    // Every value is inside 0..=frame size, which came in as u32.
    let v = |n: i64| u32::try_from(n).unwrap_or(0);
    let crop = Crop {
        x: v(left),
        y: v(top),
        w: v(w),
        h: v(h),
    };
    // Back on screen through DWM's bounds, inward again when the frame is scaled.
    let screen = |frame_px: i64, s: f64, origin: i32, inward_up: bool| {
        let at = frame_px as f64 / s;
        let at = if inward_up {
            (at - EDGE_EPSILON).ceil()
        } else {
            (at + EDGE_EPSILON).floor()
        };
        i32::try_from(i64::from(origin) + at as i64).unwrap_or(origin)
    };
    let on_screen = ScreenRect {
        left: screen(left, sx, g.bounds.left, true),
        top: screen(top, sy, g.bounds.top, true),
        right: screen(left + w, sx, g.bounds.left, false),
        bottom: screen(top + h, sy, g.bounds.top, false),
    };
    Ok(ClientCrop {
        crop,
        on_screen,
        reported,
        inset: [
            left - reported[0],
            top - reported[1],
            reported[2] - (left + w),
            reported[3] - (top + h),
        ],
        stretched,
        why,
    })
}

/// Where the picture of the window's next frame will be on screen — [`client_crop`] of a frame the
/// size of DWM's bounds, which is what a window capture's frame is (measured) — for keeping the
/// input side's rectangle current while the window only moves and no frame comes.
pub fn picture_on_screen(g: &WindowGeometry) -> Result<ScreenRect, CropRefusal> {
    let size = |v: i64| u32::try_from(v).unwrap_or(0);
    client_crop(size(g.bounds.width()), size(g.bounds.height()), g).map(|c| c.on_screen)
}

/* ── The window list and the finder ────────────────────────────────────────────────────────── */

/// One top-level window as the finder sees it — read without sending its process anything, and
/// without opening the process beyond `PROCESS_QUERY_LIMITED_INFORMATION`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct WindowInfo {
    pub hwnd: usize,
    pub pid: u32,
    pub class: String,
    pub title: String,
    /// The process's exe file name, from a process snapshot (nothing opened).
    pub exe_name: String,
    /// The process's full exe path: read only for a process named like the bound exe; `Err` with
    /// why it could not be read.
    pub exe_path: Option<Result<String, String>>,
    pub visible: bool,
    pub minimized: bool,
    /// Hidden by the shell or by its app (`DWMWA_CLOAKED`): another virtual desktop, a suspended
    /// app.
    pub cloaked: bool,
    /// What is drawn of it, in physical pixels²; 0 when nothing is.
    pub area: u64,
}

/// The windows a binding concerns: the platform half of the finder.
pub trait WindowSource: Send {
    /// The top-level windows of the bound class, and those of a process named like the bound exe
    /// (the rest cannot match and are not read).
    fn windows(&mut self, binding: &GameBinding) -> Result<Vec<WindowInfo>, String>;

    /// Where `hwnd` is now.
    fn geometry(&mut self, hwnd: usize) -> Result<WindowGeometry, String>;
}

/// What one look at the windows found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FinderVerdict {
    pub state: GameWindowState,
    /// The game's window, when there is one.
    pub window: Option<WindowInfo>,
    /// Why, for the log.
    pub why: String,
}

/// Which window is the game, and in what state, across polls: the same window as long as it
/// matches, another one — a new window, a new process — once it is gone.
pub struct GameFinder {
    binding: Option<GameBinding>,
    state: Option<GameWindowState>,
    bound: Option<usize>,
    /// The process of the bound window: gone with its process still showing other windows (a
    /// crash report), the log says what they are.
    bound_pid: Option<u32>,
    /// Mismatches already logged, by window: each is said once while the window exists.
    noted: HashSet<(usize, &'static str)>,
    /// The window list could not be read on the last poll.
    source_failing: bool,
}

impl GameFinder {
    pub fn new(binding: Option<GameBinding>) -> Self {
        Self {
            binding,
            state: None,
            bound: None,
            bound_pid: None,
            noted: HashSet::new(),
            source_failing: false,
        }
    }

    /// The state as of the last poll; `None` before the first.
    pub fn state(&self) -> Option<GameWindowState> {
        self.state
    }

    /// Look at the windows now.
    pub fn poll(&mut self, source: &mut dyn WindowSource) -> FinderVerdict {
        let Some(binding) = self.binding.clone() else {
            return self.settle(
                GameWindowState::Absent,
                None,
                "no game is bound".to_string(),
            );
        };
        if let Some(why) = binding.unusable() {
            return self.settle(GameWindowState::Absent, None, why.to_string());
        }
        match source.windows(&binding) {
            Ok(windows) => {
                if std::mem::take(&mut self.source_failing) {
                    tracing::debug!("game finder: the window list reads again");
                }
                self.decide(windows)
            }
            Err(e) => {
                if !std::mem::replace(&mut self.source_failing, true) {
                    tracing::warn!(
                        "game finder: the window list could not be read ({e}); the game counts as \
                         absent until it can"
                    );
                }
                self.bound = None;
                self.bound_pid = None;
                self.settle(
                    GameWindowState::Absent,
                    None,
                    format!("the window list could not be read: {e}"),
                )
            }
        }
    }

    /// Decide from a window list. Only for a finder with a usable binding (`poll` checks).
    pub fn decide(&mut self, windows: Vec<WindowInfo>) -> FinderVerdict {
        let Some(binding) = self.binding.clone() else {
            return self.settle(
                GameWindowState::Absent,
                None,
                "no game is bound".to_string(),
            );
        };
        let present: HashSet<usize> = windows.iter().map(|w| w.hwnd).collect();
        self.noted.retain(|(hwnd, _)| present.contains(hwnd));

        let mut matches: Vec<WindowInfo> = Vec::new();
        let mut same_exe_other_class = 0usize;
        // The bound exe's windows of another class (pid, class, title): what is left of a game
        // whose window went. Titles as read with the list, on this finder's own thread.
        let mut others: Vec<(u32, String, String)> = Vec::new();
        for w in windows {
            let class_ok = binding.class_matches(&w.class);
            let exe = match &w.exe_path {
                Some(Ok(path)) => Ok(binding.exe_matches(path)),
                Some(Err(why)) => Err(why.clone()),
                None => Ok(false),
            };
            match (class_ok, exe) {
                (true, Ok(true)) => matches.push(w),
                (true, Ok(false)) => self.note(&w, "class-not-exe", || {
                    format!(
                        "has the bound class but belongs to {} ({})",
                        w.exe_name,
                        match &w.exe_path {
                            Some(Ok(path)) => path.as_str(),
                            _ => "a process not named like the bound exe",
                        }
                    )
                }),
                (true, Err(why)) => self.note(&w, "path-unreadable", || {
                    format!(
                        "has the bound class, but its process's exe path could not be read \
                         ({why}); not matched"
                    )
                }),
                (false, Ok(true)) => {
                    same_exe_other_class += 1;
                    if self.bound.is_some() {
                        others.push((w.pid, w.class.clone(), w.title.clone()));
                    }
                    self.note(&w, "exe-not-class", || {
                        format!(
                            "belongs to the bound exe but has class {:?}, not the bound one",
                            w.class
                        )
                    });
                }
                (false, Err(why)) => self.note(&w, "path-unreadable", || {
                    format!("its process's exe path could not be read ({why}); not matched")
                }),
                (false, Ok(false)) => {}
            }
        }

        if matches.is_empty() {
            if let Some(hwnd) = self.bound.take() {
                let pid = self.bound_pid.take();
                tracing::debug!(
                    hwnd = %format!("{hwnd:#x}"),
                    "game finder: the bound window is gone"
                );
                // Its process still has windows: the game crashed behind its crash report, or a
                // dialog of its own is up — said once, with what they are.
                if let Some(what) = pid.and_then(|pid| process_runs_on(pid, &others)) {
                    tracing::debug!(
                        hwnd = %format!("{hwnd:#x}"),
                        pid = pid.unwrap_or_default(),
                        exe = %binding.shown_name(),
                        from = self.state.map_or("-", GameWindowState::as_str),
                        "game finder: the bound window went, its process runs: {what}"
                    );
                }
            }
            return if same_exe_other_class > 0 {
                self.settle(
                    GameWindowState::Starting,
                    None,
                    format!(
                        "the game's process has {same_exe_other_class} window(s), none of class \
                         {:?} yet",
                        binding.window_class
                    ),
                )
            } else {
                self.settle(
                    GameWindowState::Absent,
                    None,
                    format!(
                        "no window of {} with class {:?}",
                        binding.shown_name(),
                        binding.window_class
                    ),
                )
            };
        }

        let count = matches.len();
        let sticky = self
            .bound
            .and_then(|hwnd| matches.iter().position(|w| w.hwnd == hwnd));
        let (index, how) = match sticky {
            Some(i) => (i, "the window bound before"),
            None => (best_match(&matches), "the best of the matching windows"),
        };
        let chosen = matches.swap_remove(index);
        if self.bound != Some(chosen.hwnd) {
            tracing::debug!(
                hwnd = %format!("{:#x}", chosen.hwnd),
                pid = chosen.pid,
                title = %chosen.title,
                visible = chosen.visible,
                minimized = chosen.minimized,
                cloaked = chosen.cloaked,
                area = chosen.area,
                matching = count,
                how,
                "game finder: bound to the game's window (exe path and class match)"
            );
            self.bound = Some(chosen.hwnd);
        }
        self.bound_pid = Some(chosen.pid);
        let (state, why) = if !chosen.visible {
            (
                GameWindowState::Starting,
                "the game's window exists but is not shown yet",
            )
        } else if chosen.minimized {
            (GameWindowState::Minimized, "the game's window is minimized")
        } else if chosen.cloaked {
            (
                GameWindowState::Minimized,
                "the game's window is cloaked (another virtual desktop, or hidden by the shell)",
            )
        } else if chosen.area == 0 {
            (
                GameWindowState::Minimized,
                "the game's window has nothing on screen",
            )
        } else {
            (GameWindowState::Shown, "the game's window is on screen")
        };
        self.settle(state, Some(chosen), why.to_string())
    }

    fn note(&mut self, w: &WindowInfo, kind: &'static str, what: impl FnOnce() -> String) {
        if self.noted.insert((w.hwnd, kind)) {
            tracing::debug!(
                hwnd = %format!("{:#x}", w.hwnd),
                pid = w.pid,
                exe = %w.exe_name,
                class = %w.class,
                "game finder: a window that does not match: {}",
                what()
            );
        }
    }

    fn settle(
        &mut self,
        state: GameWindowState,
        window: Option<WindowInfo>,
        why: String,
    ) -> FinderVerdict {
        if self.state != Some(state) {
            tracing::debug!(
                from = self.state.map_or("-", GameWindowState::as_str),
                to = state.as_str(),
                hwnd = %window.as_ref().map_or_else(|| "-".to_string(), |w| format!("{:#x}", w.hwnd)),
                "game window state changed: {why}"
            );
            self.state = Some(state);
        }
        FinderVerdict { state, window, why }
    }
}

/// At most this many of a process's other windows are named when its bound window goes.
const OTHERS_SHOWN: usize = 8;
/// A title named there is cut to this many characters.
const TITLE_SHOWN: usize = 80;

/// The bound window gone, the windows its process `pid` still has among `others` (pid, class,
/// title): a crash report («Scryde Crash Report», class `#32770`), a dialog — for the log. `None`
/// when that process has none (it is closing, or gone).
fn process_runs_on(pid: u32, others: &[(u32, String, String)]) -> Option<String> {
    let own: Vec<&(u32, String, String)> = others.iter().filter(|(p, ..)| *p == pid).collect();
    if own.is_empty() {
        return None;
    }
    let named: Vec<String> = own
        .iter()
        .take(OTHERS_SHOWN)
        .map(|(_, class, title)| {
            let mut shown: String = title.chars().take(TITLE_SHOWN).collect();
            if title.chars().count() > TITLE_SHOWN {
                shown.push('…');
            }
            format!("{class:?} {shown:?}")
        })
        .collect();
    Some(format!(
        "{} other top-level window(s) of it: {}{}",
        own.len(),
        named.join(", "),
        if own.len() > OTHERS_SHOWN {
            format!(" and {} more", own.len() - OTHERS_SHOWN)
        } else {
            String::new()
        }
    ))
}

/// Of several matching windows, the one most likely the game's picture: shown before minimized
/// before hidden, then the largest.
fn best_match(windows: &[WindowInfo]) -> usize {
    let rank = |w: &WindowInfo| {
        let on_screen = w.visible && !w.minimized && !w.cloaked && w.area > 0;
        (u8::from(on_screen) * 2 + u8::from(w.visible), w.area)
    };
    windows
        .iter()
        .enumerate()
        .max_by_key(|(_, w)| rank(w))
        .map_or(0, |(i, _)| i)
}

/* ── What the session reads ────────────────────────────────────────────────────────────────── */

/// Where the game's picture is, as the capture last saw it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CaptureGeometry {
    pub hwnd: usize,
    /// The part of the client area the picture shows, on screen, physical pixels — the crop placed
    /// back on screen ([`ClientCrop::on_screen`]), not the client area Windows reports: what the
    /// input side maps `m` and `r.x/y` into, so a point of the picture lands where the viewer sees
    /// it (module docs, «Input»).
    pub client: ScreenRect,
    /// The picture's size: the crop, before it is scaled to the rung.
    pub source: (u32, u32),
}

/// The game window as the session sees it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GameSnapshot {
    /// The session is in game mode (the heartbeat carries `game`).
    pub active: bool,
    pub state: GameWindowState,
    /// The last picture size captured this session.
    pub source: Option<(u32, u32)>,
    /// Only while the window is shown and captured.
    pub geometry: Option<CaptureGeometry>,
    /// The window the finder bound while it was shown, and the process that owns it (from the
    /// window list: never opened for it). Input lands only on a window of this process.
    pub window: Option<(usize, u32)>,
    /// Another window has the front (the input side's focus watch says so): the heartbeat says
    /// `unfocused` while the window is shown.
    pub unfocused: bool,
}

impl GameSnapshot {
    fn idle() -> Self {
        Self {
            active: false,
            state: GameWindowState::Absent,
            source: None,
            geometry: None,
            window: None,
            unfocused: false,
        }
    }

    /// The state the viewer is told: `unfocused` while the window is shown and another has the
    /// front, else the finder's.
    pub fn told_state(&self) -> GameWindowState {
        if self.state == GameWindowState::Shown && self.unfocused {
            GameWindowState::Unfocused
        } else {
            self.state
        }
    }
}

/// The game window's state for the heartbeat, the pipeline line and the input side: written by the
/// game capturer's thread and its capture's frame handler, read once a second (and by input, next).
#[derive(Debug)]
pub struct GameStatus {
    snap: Mutex<GameSnapshot>,
    /// Wakes the heartbeat on a change, so a minimize reaches the viewer at once.
    changed: Notify,
}

impl Default for GameStatus {
    fn default() -> Self {
        Self::new()
    }
}

impl GameStatus {
    pub fn new() -> Self {
        Self {
            snap: Mutex::new(GameSnapshot::idle()),
            changed: Notify::new(),
        }
    }

    /// The session enters or leaves game mode. Either way the window starts out unknown.
    pub fn set_active(&self, active: bool) {
        let mut snap = lock(&self.snap);
        if snap.active == active {
            return;
        }
        *snap = GameSnapshot {
            active,
            ..GameSnapshot::idle()
        };
        drop(snap);
        tracing::debug!(active, "game status: the session's game mode");
        self.changed.notify_one();
    }

    /// The finder's state. Leaving `shown` forgets where the picture was and whose window it was:
    /// input must never map into a window that is not on screen.
    pub fn set_state(&self, state: GameWindowState) -> bool {
        let mut snap = lock(&self.snap);
        if snap.state == state {
            return false;
        }
        snap.state = state;
        if state != GameWindowState::Shown {
            snap.geometry = None;
            snap.window = None;
            snap.unfocused = false;
        }
        drop(snap);
        self.changed.notify_one();
        true
    }

    /// The window the finder bound, shown, and the process that owns it. Said at `debug` when it
    /// changes (a relaunch is a new window of a new process).
    pub fn set_window(&self, hwnd: usize, pid: u32) {
        let mut snap = lock(&self.snap);
        if snap.window == Some((hwnd, pid)) {
            return;
        }
        let before = snap.window.replace((hwnd, pid));
        drop(snap);
        tracing::debug!(
            hwnd = %format!("{hwnd:#x}"),
            pid,
            before = %before.map_or_else(|| "-".to_string(), |(h, p)| format!("{h:#x} pid {p}")),
            "game status: the game's window and its process, for input"
        );
    }

    /// What the input side's focus watch sees: whether the game's window has the front. Only
    /// meaningful while the window is shown; a change wakes the heartbeat, so `unfocused` reaches
    /// the viewer at once. True when it changed what the viewer is told.
    pub fn set_focus(&self, focused: bool) -> bool {
        let mut snap = lock(&self.snap);
        let told = snap.told_state();
        // Nothing to be in front of while the window is not shown.
        snap.unfocused = !focused && snap.state == GameWindowState::Shown;
        let changed = snap.told_state() != told;
        drop(snap);
        if changed {
            self.changed.notify_one();
        }
        changed
    }

    /// Where the picture is, from a frame that went out. Ignored unless the window is shown (a late
    /// frame of a capture being stopped). True when the picture's size changed.
    pub fn set_geometry(&self, geometry: CaptureGeometry) -> bool {
        let mut snap = lock(&self.snap);
        if snap.state != GameWindowState::Shown {
            return false;
        }
        snap.geometry = Some(geometry);
        let resized = snap.source != Some(geometry.source);
        snap.source = Some(geometry.source);
        drop(snap);
        if resized {
            self.changed.notify_one();
        }
        resized
    }

    /// The window moved without its picture changing (no frame came): keep the picture's rectangle
    /// on screen ([`CaptureGeometry::client`], from [`picture_on_screen`]) current for the input
    /// side. Only for the window already captured.
    pub fn refresh_client(&self, hwnd: usize, client: ScreenRect) {
        let mut snap = lock(&self.snap);
        if let Some(g) = snap.geometry.as_mut() {
            if g.hwnd == hwnd && g.client != client {
                tracing::trace!(from = %g.client, to = %client, "game window moved");
                g.client = client;
            }
        }
    }

    pub fn snapshot(&self) -> GameSnapshot {
        *lock(&self.snap)
    }

    /// The game's client area on screen and the picture's size — `Some` only while the window is
    /// shown and captured.
    pub fn geometry(&self) -> Option<CaptureGeometry> {
        lock(&self.snap).geometry
    }

    /// The game window as input sees it: the finder's state, and where input goes — the captured
    /// window's client area and the process that owns it, `Some` only while the window is shown and
    /// captured and the window captured is the one the finder bound (its process known). The seam
    /// the input side reads (`crate::game_input`).
    ///
    /// The client area is the part of it the picture shows: the crop placed back on screen
    /// ([`ClientCrop::on_screen`]). `afklink_input`'s game guard maps `m` and `r.x/y` into that
    /// area, keeps the cursor in it, injects only while the game's window is in front, and blocks
    /// the keys that leave it; the session's focus watch writes what it sees back here
    /// ([`Self::set_focus`]), and the heartbeat says `unfocused` while another window has the
    /// front.
    ///
    /// The picture and the pointer share that one rectangle on purpose. On a window Windows
    /// stretches, the client area Windows reports can start on a row that is still title bar (the
    /// reported edge rounded a half pixel up), and the pointer kept inside it could land there (a
    /// click on the caption, a drag of the window) where the viewer saw no such row. Inside the
    /// crop, every pixel is the game's.
    pub fn game_scope(&self) -> GameScope {
        let snap = lock(&self.snap);
        let window = snap.geometry.and_then(|g| {
            let (hwnd, pid) = snap.window.filter(|&(hwnd, _)| hwnd == g.hwnd)?;
            Some(GameInputWindow {
                hwnd,
                pid,
                client: g.client,
            })
        });
        GameScope {
            state: snap.state,
            window,
        }
    }

    /// The session is in game mode now: what the connection journal's «Только игра» counts
    /// (`crate::journal`).
    pub fn is_active(&self) -> bool {
        lock(&self.snap).active
    }

    /// The heartbeat's `game`: `None` outside game mode.
    pub fn heartbeat(&self) -> Option<GameHeartbeat> {
        let snap = self.snapshot();
        snap.active
            .then(|| GameHeartbeat::new(snap.told_state(), snap.source))
    }

    /// The pipeline line's `game` and `game_src`: `-` outside game mode, and for a size not known.
    pub fn line_fields(&self) -> (&'static str, String) {
        let snap = self.snapshot();
        if !snap.active {
            return ("-", "-".to_string());
        }
        (
            snap.told_state().as_str(),
            snap.source
                .map_or_else(|| "-".to_string(), |(w, h)| format!("{w}x{h}")),
        )
    }

    /// Resolves on the next change. For the heartbeat task's `select!`.
    pub fn changed(&self) -> &Notify {
        &self.changed
    }
}

/* ── The frame gate ────────────────────────────────────────────────────────────────────────── */

/// What became of a frame handed to the [`FrameGate`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateSend {
    Sent,
    /// Not this frame's turn: a window frame from a capture that is no longer the live one, or a
    /// black frame while a capture is live.
    Refused,
    /// The consumer is gone (the session ended).
    Closed,
}

/// The one door frames go through to the encoder in game mode: either the live window capture's or
/// black ones, never both, and never a frame of a capture that was stopped or replaced — its frames
/// carry the generation it was started with.
pub struct FrameGate {
    inner: Mutex<GateInner>,
    target_source: Option<TargetSource>,
    native_tap: Option<NativeSampleTap>,
}

struct GateInner {
    sink: Option<FrameSink>,
    live: Option<u64>,
    last_generation: u64,
    live_frames: u64,
}

/// A frame for a [`FrameGate::bounded`] consumer: timestamped at the window callback boundary,
/// with the quality target it was paced and scaled against.
pub struct TimedFrame {
    pub frame: Frame,
    pub observed: Instant,
    pub target: Option<Arc<crate::quality::QualityTarget>>,
}

#[derive(Default)]
struct NativeSampleTap {
    state: AtomicU8,
    spare: Mutex<Vec<u8>>,
    sample: Mutex<Option<TimedFrame>>,
}

const PREVIEW_IDLE: u8 = 0;
const PREVIEW_REQUESTED: u8 = 1;
const PREVIEW_ACQUIRING: u8 = 2;
const PREVIEW_READY: u8 = 3;

/// One pending frame, replaced by a newer one when the reader is busy. Only the consumer
/// waits, and the condition variable releases the slot lock for that wait. Frames displaced
/// by a newer acquisition are counted alongside it for the ordinary encoder's accounting.
pub struct LatestFrame<T> {
    slot: Mutex<(bool, Option<(T, u32)>)>,
    available: std::sync::Condvar,
}

impl<T> LatestFrame<T> {
    pub fn new(enabled: bool) -> Self {
        Self {
            slot: Mutex::new((enabled, None)),
            available: std::sync::Condvar::new(),
        }
    }

    pub fn publish(&self, frame: T) -> bool {
        let previous = {
            let mut slot = lock(&self.slot);
            if !slot.0 {
                return false;
            }
            let offered = slot.1.as_ref().map_or(1, |(_, n)| n.saturating_add(1));
            slot.1.replace((frame, offered))
        };
        if previous.is_none() {
            self.available.notify_one();
        }
        true
    }

    pub fn take_timeout(&self, wait: Duration) -> Option<(T, u32)> {
        let (mut slot, _) = self
            .available
            .wait_timeout_while(lock(&self.slot), wait, |slot| slot.1.is_none())
            .unwrap_or_else(|err| err.into_inner());
        slot.1.take()
    }

    pub fn clear(&self) {
        let pending = lock(&self.slot).1.take();
        drop(pending);
    }

    pub fn reset(&self, enabled: bool) {
        let pending = {
            let mut slot = lock(&self.slot);
            slot.0 = enabled;
            slot.1.take()
        };
        drop(pending);
    }
}

/// The quality target a [`FrameGate::bounded`] consumer paces frames against, read per frame, so a
/// host can change it without replacing the window capture.
pub type TargetSource = Arc<dyn Fn() -> Option<Arc<crate::quality::QualityTarget>> + Send + Sync>;

type FrameTarget = Option<Arc<crate::quality::QualityTarget>>;

enum FrameSink {
    Normal(Sender<Frame>),
    Bounded(Arc<LatestFrame<TimedFrame>>),
}

impl FrameGate {
    pub fn new(sink: Sender<Frame>) -> Self {
        Self::with_sink(FrameSink::Normal(sink))
    }

    /// A gate for a host's own consumer instead of the agent's frame channel: the newest frame
    /// waits in `sink` with its timestamp and the target `target` names, black frames never pass,
    /// and the native-resolution sample tap is available ([`Self::request_native_sample`]).
    pub fn bounded(sink: Arc<LatestFrame<TimedFrame>>, target: TargetSource) -> Self {
        Self {
            target_source: Some(target),
            native_tap: Some(NativeSampleTap::default()),
            ..Self::with_sink(FrameSink::Bounded(sink))
        }
    }

    /// The target a [`Self::bounded`] gate's frames follow now, if its source names one.
    pub fn source_target(&self) -> Option<Arc<crate::quality::QualityTarget>> {
        self.target_source.as_ref().and_then(|target| target())
    }

    /// Whether this is a [`Self::bounded`] gate: its window geometry is read in physical pixels
    /// on the capture callback's own thread.
    pub fn has_target_source(&self) -> bool {
        self.target_source.is_some()
    }

    /// Ask for one native-resolution crop of the next live frame, reusing `spare`'s buffer.
    /// Idle requests only: one sample is in flight at a time.
    pub fn request_native_sample(&self, spare: &mut Vec<u8>) {
        if let Some(tap) = &self.native_tap {
            if tap.state.load(Ordering::Acquire) == PREVIEW_IDLE {
                // One worker is the only requester. The callback can reserve
                // only after it sees the request with the reusable buffer already in place.
                *lock(&tap.spare) = std::mem::take(spare);
                tap.state.store(PREVIEW_REQUESTED, Ordering::Release);
                tracing::trace!("one native-resolution sample requested");
            }
        }
    }

    /// Tap the native client crop, before the live quality rung can discard detail (a host's
    /// thumbnail, for example). The callback hands off live video first. On all other frames this
    /// is one atomic read.
    pub fn sample_native(
        &self,
        generation: u64,
        pixels: &[u8],
        width: u32,
        height: u32,
        observed: Instant,
    ) {
        let Some(tap) = &self.native_tap else {
            return;
        };
        if tap.state.load(Ordering::Relaxed) != PREVIEW_REQUESTED {
            return;
        }
        // A window on an unusually wide virtual screen cannot make a best-effort sample retain
        // unbounded native data. Normal 8K crops fit here.
        if pixels.len() > 128 * 1024 * 1024 {
            tracing::trace!("native sample crop exceeds its pixel budget");
            return;
        }
        if tap
            .state
            .compare_exchange(
                PREVIEW_REQUESTED,
                PREVIEW_ACQUIRING,
                Ordering::AcqRel,
                Ordering::Relaxed,
            )
            .is_err()
        {
            return;
        }
        let mut data = std::mem::take(&mut *lock(&tap.spare));
        data.clear();
        data.extend_from_slice(pixels);
        let sample = TimedFrame {
            frame: Frame {
                data,
                width,
                height,
                timestamp_ms: 0,
            },
            observed,
            target: None,
        };
        // Close/invalidate cannot race past this final generation check and retain a sample.
        let inner = lock(&self.inner);
        if inner.live == Some(generation) {
            *lock(&tap.sample) = Some(sample);
            tap.state.store(PREVIEW_READY, Ordering::Release);
        } else {
            tracing::trace!("native sample ignored: its capture generation closed");
        }
    }

    /// The requested native-resolution sample, once the callback has taken one.
    pub fn take_native_sample(&self) -> Option<TimedFrame> {
        let tap = self.native_tap.as_ref()?;
        if tap.state.load(Ordering::Acquire) != PREVIEW_READY {
            return None;
        }
        let sample = lock(&tap.sample).take()?;
        tap.state.store(PREVIEW_IDLE, Ordering::Release);
        Some(sample)
    }

    fn clear_native_sample(&self) {
        if let Some(tap) = &self.native_tap {
            tap.state.store(PREVIEW_IDLE, Ordering::Release);
            let pending = lock(&tap.sample).take();
            drop(pending);
        }
    }

    /// A crop refusal invalidates a bounded consumer's stream instead of retaining its last
    /// picture. `true` when it did.
    pub fn invalidate_bounded(&self, generation: u64) -> bool {
        let mut inner = lock(&self.inner);
        if inner.live == Some(generation) && matches!(inner.sink, Some(FrameSink::Bounded(_))) {
            inner.live = None;
            if let Some(FrameSink::Bounded(sink)) = &inner.sink {
                sink.reset(false);
            }
            self.clear_native_sample();
            return true;
        }
        false
    }

    fn with_sink(sink: FrameSink) -> Self {
        Self {
            target_source: None,
            native_tap: None,
            inner: Mutex::new(GateInner {
                sink: Some(sink),
                live: None,
                last_generation: 0,
                live_frames: 0,
            }),
        }
    }

    /// A new window capture takes over: its generation, which its frames carry.
    pub fn open(&self) -> u64 {
        let mut inner = lock(&self.inner);
        inner.last_generation += 1;
        let generation = inner.last_generation;
        inner.live = Some(generation);
        inner.live_frames = 0;
        generation
    }

    /// Back to black frames: nothing from the capture that was live passes any more.
    pub fn close(&self) -> Option<u64> {
        lock(&self.inner).live.take()
    }

    pub fn is_live(&self) -> bool {
        lock(&self.inner).live.is_some()
    }

    /// Whether a frame of `generation` would pass — for the frame handler, before it spends
    /// anything on the frame.
    pub fn admits(&self, generation: u64) -> bool {
        lock(&self.inner).live == Some(generation)
    }

    /// Frames the live capture has passed so far.
    pub fn live_frames(&self) -> u64 {
        lock(&self.inner).live_frames
    }

    /// A window capture's frame.
    pub fn send_live(&self, generation: u64, frame: Frame) -> GateSend {
        self.send_window(generation, frame, None)
    }

    /// A window capture's frame, paced and scaled against `target` (a [`Self::bounded`] gate's).
    pub fn send_live_with_target(
        &self,
        generation: u64,
        frame: Frame,
        target: &Arc<crate::quality::QualityTarget>,
    ) -> GateSend {
        self.send_window(generation, frame, Some(target.clone()))
    }

    fn send_window(&self, generation: u64, frame: Frame, target: FrameTarget) -> GateSend {
        let mut inner = lock(&self.inner);
        if inner.live != Some(generation) {
            return GateSend::Refused;
        }
        let sent = Self::send(&mut inner, frame, target);
        if sent == GateSend::Sent {
            inner.live_frames += 1;
        }
        sent
    }

    /// A black frame: only while no capture is live.
    pub fn send_black(&self, frame: Frame) -> GateSend {
        if self.target_source.is_some() {
            tracing::trace!(target: crate::EMBED_LOG_TARGET, "frame gate with a target source refused a synthetic frame");
            return GateSend::Refused;
        }
        let mut inner = lock(&self.inner);
        if inner.live.is_some() {
            return GateSend::Refused;
        }
        Self::send(&mut inner, frame, None)
    }

    /// Nothing passes any more: the capturer is stopping.
    pub fn shut(&self) {
        let mut inner = lock(&self.inner);
        inner.live = None;
        if let Some(FrameSink::Bounded(sink)) = &inner.sink {
            sink.reset(false);
            self.clear_native_sample();
        }
        inner.sink = None;
    }

    fn send(inner: &mut GateInner, frame: Frame, target: FrameTarget) -> GateSend {
        let Some(sink) = inner.sink.as_ref() else {
            return GateSend::Closed;
        };
        let disconnected = match sink {
            FrameSink::Normal(sink) => sink.send(frame).is_err(),
            FrameSink::Bounded(sink) => !sink.publish(TimedFrame {
                frame,
                observed: Instant::now(),
                target,
            }),
        };
        if disconnected {
            inner.sink = None;
            return GateSend::Closed;
        }
        GateSend::Sent
    }
}

/// A black frame for a picture of `source`, scaled to the rung like any frame.
pub fn black_frame(source: (u32, u32), max_h: u32) -> Frame {
    let (w, h) = fit_within(source.0.max(2), source.1.max(2), u32::MAX / 2, max_h);
    Frame {
        // Zero is black in BGRA; the encoder ignores alpha.
        data: vec![0; w as usize * h as usize * 4],
        width: w,
        height: h,
        timestamp_ms: 0,
    }
}

/* ── The window capture, as the game capturer drives it ────────────────────────────────────── */

/// What a window capture is started with. `Clone` so a start that Windows refused over an optional
/// session setting can be tried again with the same context (`afklink_capture::session_options`).
#[derive(Clone)]
pub struct WindowCaptureContext {
    pub hwnd: usize,
    /// Frames go through here, with `generation`.
    pub gate: Arc<FrameGate>,
    pub generation: u64,
    /// The rung each frame is scaled to; the capture reports the picture's size to it.
    pub target: Arc<QualityTarget>,
    /// Where the capture says where the picture is ([`GameStatus::set_geometry`]).
    pub status: Arc<GameStatus>,
}

/// One running window capture.
pub trait WindowCapture: Send {
    /// It ended by itself: the window closed, a frame could not be read.
    fn finished(&mut self) -> bool;
    /// Stop it and collect it; why it ended, when it ended by itself.
    fn stop(self: Box<Self>) -> Option<String>;
}

/// Starts window captures: WGC on Windows (`afklink_capture::game`), a script in tests.
pub trait WindowCaptureBackend: Send {
    fn start(&mut self, ctx: WindowCaptureContext) -> anyhow::Result<Box<dyn WindowCapture>>;
}

/* ── The game capturer ─────────────────────────────────────────────────────────────────────── */

/// The capturer a session runs in game mode.
///
/// One thread (`game-capture`) polls the finder every [`FINDER_POLL`], keeps a window capture on
/// the game's window while it is shown — started again on a new window (a relaunch) and after it
/// fails — and sends a black frame every [`BLACK_EVERY`] whenever no capture is live. It never ends
/// by itself: every failure ends in black frames. [`Capturer::check`] reports only the thread
/// itself dying (a panic), which the pipeline supervisor answers with a new game capturer.
pub struct GameCapturer {
    binding: Option<GameBinding>,
    status: Arc<GameStatus>,
    parts: Option<(Box<dyn WindowSource>, Box<dyn WindowCaptureBackend>)>,
    running: Option<(Arc<AtomicBool>, JoinHandle<()>)>,
    /// The background hold (`crate::bg_hold`), as the pipeline supervisor set it with
    /// [`Capturer::hold`]: read by the thread on every step.
    held: Arc<AtomicBool>,
}

impl GameCapturer {
    pub fn new(
        request: &GameCaptureRequest,
        source: Box<dyn WindowSource>,
        backend: Box<dyn WindowCaptureBackend>,
    ) -> Self {
        Self {
            binding: request.binding.clone(),
            status: request.status.clone(),
            parts: Some((source, backend)),
            running: None,
            held: Arc::new(AtomicBool::new(false)),
        }
    }
}

impl Capturer for GameCapturer {
    fn start(&mut self, sink: Sender<Frame>, target: Arc<QualityTarget>) -> anyhow::Result<()> {
        let (source, backend) = self
            .parts
            .take()
            .ok_or_else(|| anyhow::anyhow!("a game capturer is started once"))?;
        let stop = Arc::new(AtomicBool::new(false));
        let director = Director::new(
            self.binding.clone(),
            source,
            backend,
            Arc::new(FrameGate::new(sink)),
            self.status.clone(),
            target,
            self.held.clone(),
        );
        let thread_stop = stop.clone();
        let thread = std::thread::Builder::new()
            .name("game-capture".into())
            .spawn(move || director.run(&thread_stop))
            .map_err(|e| anyhow::anyhow!("spawn the game capture thread: {e}"))?;
        self.running = Some((stop, thread));
        Ok(())
    }

    fn stop(&mut self) {
        let Some((stop, thread)) = self.running.take() else {
            return;
        };
        stop.store(true, Ordering::SeqCst);
        thread.thread().unpark();
        match thread.join() {
            Ok(()) => tracing::debug!("game capture stopped"),
            Err(panic) => tracing::warn!(
                "game capture thread had panicked: {}",
                panic_text(panic.as_ref())
            ),
        }
    }

    fn check(&mut self) -> anyhow::Result<()> {
        match self.running.take() {
            None => Err(anyhow::anyhow!("game capture is not running")),
            Some((_stop, thread)) if thread.is_finished() => {
                let why = match thread.join() {
                    Ok(()) => "ended without being stopped".to_string(),
                    Err(panic) => format!("panicked: {}", panic_text(panic.as_ref())),
                };
                Err(anyhow::anyhow!("the game capture thread {why}"))
            }
            Some(running) => {
                self.running = Some(running);
                Ok(())
            }
        }
    }

    /// The background hold: the thread stops the window capture and its black frames and goes on
    /// watching the game's window — its state, its process, where its client area is — which the
    /// heartbeat's `game` and the input's scope read through the hold. Released, it captures again
    /// at once. False when its thread is not running (never started, or ended): the supervisor
    /// then replaces it as it replaces any capturer that cannot hold.
    fn hold(&mut self, held: bool) -> bool {
        let Some((_, thread)) = self.running.as_ref() else {
            tracing::debug!(
                held,
                "game capture: hold refused: its thread is not running"
            );
            return false;
        };
        if thread.is_finished() {
            tracing::debug!(held, "game capture: hold refused: its thread has ended");
            return false;
        }
        self.held.store(held, Ordering::SeqCst);
        thread.thread().unpark();
        true
    }
}

impl Drop for GameCapturer {
    fn drop(&mut self) {
        self.stop();
    }
}

fn panic_text(payload: &(dyn std::any::Any + Send)) -> String {
    payload
        .downcast_ref::<&str>()
        .map(|s| (*s).to_string())
        .or_else(|| payload.downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "a panic with no message".to_string())
}

/// The window capture that is live.
struct LiveCapture {
    capture: Box<dyn WindowCapture>,
    hwnd: usize,
    generation: u64,
    started: Instant,
}

/// The game capturer's thread, as steps on a clock of the caller's (tests drive it directly).
struct Director {
    finder: GameFinder,
    source: Box<dyn WindowSource>,
    backend: Box<dyn WindowCaptureBackend>,
    gate: Arc<FrameGate>,
    status: Arc<GameStatus>,
    target: Arc<QualityTarget>,
    live: Option<LiveCapture>,
    next_poll: Option<Instant>,
    /// `Some` while black frames go out: when the next one is due.
    next_black: Option<Instant>,
    /// The black episode: since when, why, and how many frames.
    black: Option<(Instant, String, u64)>,
    retry_at: Option<Instant>,
    retry_gap: Duration,
    /// The geometry could not be read on the last poll (said once per episode).
    geometry_failing: bool,
    consumer_gone: bool,
    /// The background hold as the supervisor set it ([`Capturer::hold`]), and as this thread last
    /// acted on it: while held, no window capture and no black frame — only the finder.
    held: Arc<AtomicBool>,
    holding: Option<Instant>,
}

impl Director {
    #[allow(
        clippy::too_many_arguments,
        reason = "the capturer's parts, handed to its thread"
    )]
    fn new(
        binding: Option<GameBinding>,
        source: Box<dyn WindowSource>,
        backend: Box<dyn WindowCaptureBackend>,
        gate: Arc<FrameGate>,
        status: Arc<GameStatus>,
        target: Arc<QualityTarget>,
        held: Arc<AtomicBool>,
    ) -> Self {
        Self {
            finder: GameFinder::new(binding),
            source,
            backend,
            gate,
            status,
            target,
            live: None,
            next_poll: None,
            next_black: None,
            black: None,
            retry_at: None,
            retry_gap: RETRY_MIN,
            geometry_failing: false,
            consumer_gone: false,
            held,
            holding: None,
        }
    }

    /// Act on a change of the background hold. Held: the window capture stops and so do black
    /// frames; the finder goes on, so the window's state, its process and its client area stay
    /// current for the heartbeat and for input. Released: the next step polls at once and starts
    /// the window capture (or sends a black frame at once when the window cannot be shown).
    fn follow_hold(&mut self, now: Instant) {
        let held = self.held.load(Ordering::SeqCst);
        match (held, self.holding) {
            (true, None) => {
                self.holding = Some(now);
                self.stop_live(now, "background hold");
                if let Some((since, why, frames)) = self.black.take() {
                    tracing::debug!(
                        black_frames = frames,
                        black_ms = now.saturating_duration_since(since).as_millis() as u64,
                        began_with = %why,
                        "game capture: black frames stop: background hold"
                    );
                }
                self.next_black = None;
                tracing::debug!(
                    state = self.finder.state().map_or("-", GameWindowState::as_str),
                    poll_ms = FINDER_POLL.as_millis() as u64,
                    "game capture: background hold — no window capture and no black frames; the \
                     finder keeps watching the game's window"
                );
            }
            (false, Some(since)) => {
                self.holding = None;
                self.next_poll = None;
                tracing::debug!(
                    held_ms = now.saturating_duration_since(since).as_millis() as u64,
                    state = self.finder.state().map_or("-", GameWindowState::as_str),
                    "game capture: background hold over — capturing again at once"
                );
            }
            _ => {}
        }
    }

    fn run(mut self, stop: &AtomicBool) {
        tracing::debug!(
            binding = %self.finder.binding.as_ref().map_or_else(
                || "none".to_string(),
                |b| format!("{} (exe {:?}, class {:?})", b.shown_name(), b.exe_path, b.window_class)
            ),
            poll_ms = FINDER_POLL.as_millis() as u64,
            "game capture started: black frames until the game's window is found and shown"
        );
        while !stop.load(Ordering::SeqCst) && !self.consumer_gone {
            let wake = self.step(Instant::now());
            let wait = wake.saturating_duration_since(Instant::now());
            if !wait.is_zero() {
                std::thread::park_timeout(wait);
            }
        }
        self.finish(if self.consumer_gone {
            "the frame consumer is gone"
        } else {
            "stopped"
        });
    }

    /// One step at `now`: poll when due, watch the live capture, send a black frame when due.
    /// Returns when the next step is due.
    fn step(&mut self, now: Instant) -> Instant {
        self.follow_hold(now);
        if self.next_poll.is_none_or(|due| now >= due) {
            self.next_poll = Some(now + FINDER_POLL);
            self.poll(now);
        }
        self.watch(now);
        if self.next_black.is_some_and(|due| now >= due) {
            self.send_black(now);
        }
        let mut wake = self.next_poll.unwrap_or(now + FINDER_POLL);
        if let Some(due) = self.next_black {
            wake = wake.min(due);
        }
        wake
    }

    fn poll(&mut self, now: Instant) {
        let verdict = self.finder.poll(&mut *self.source);
        match (verdict.state, verdict.window) {
            (GameWindowState::Shown, Some(window)) => {
                self.status.set_state(GameWindowState::Shown);
                // Whose window it is, for input: a press lands only on a window of this process.
                self.status.set_window(window.hwnd, window.pid);
                if self.holding.is_some() {
                    // Held: nothing is captured, but where the window is stays current for input
                    // (only for the window last captured; a new one has no geometry until it is).
                    self.refresh_geometry(window.hwnd);
                    return;
                }
                if let Some(live) = &self.live {
                    if live.hwnd == window.hwnd {
                        self.refresh_geometry(window.hwnd);
                        return;
                    }
                    let why = format!(
                        "the game's window changed: {:#x} → {:#x} (pid {}; a relaunch?)",
                        live.hwnd, window.hwnd, window.pid
                    );
                    self.stop_live(now, &why);
                    // A new window is not a failure: no pause before capturing it.
                    self.retry_at = None;
                }
                if self.retry_at.is_some_and(|at| now < at) {
                    tracing::trace!("game capture: waiting out the pause before trying again");
                    return;
                }
                self.start_live(now, &window);
            }
            (state, _) => {
                if self.live.is_some() {
                    self.stop_live(now, &format!("the game's window is {}", state.as_str()));
                }
                // After the capture is closed: a frame still in flight is refused by the gate, and
                // the state's change clears the geometry the input side reads.
                self.status.set_state(state);
                if self.holding.is_none() {
                    self.go_black(now, &format!("the game's window is {}", state.as_str()));
                }
            }
        }
    }

    fn start_live(&mut self, now: Instant, window: &WindowInfo) {
        let generation = self.gate.open();
        let ctx = WindowCaptureContext {
            hwnd: window.hwnd,
            gate: self.gate.clone(),
            generation,
            target: self.target.clone(),
            status: self.status.clone(),
        };
        match self.backend.start(ctx) {
            Ok(capture) => {
                tracing::debug!(
                    hwnd = %format!("{:#x}", window.hwnd),
                    pid = window.pid,
                    title = %window.title,
                    generation,
                    area = window.area,
                    "game capture: window capture started (cropped to the client area; which \
                     optional session settings Windows took is in the `WGC session options` line \
                     before)"
                );
                self.live = Some(LiveCapture {
                    capture,
                    hwnd: window.hwnd,
                    generation,
                    started: now,
                });
                self.go_live(now);
            }
            Err(e) => {
                self.gate.close();
                tracing::warn!(
                    hwnd = %format!("{:#x}", window.hwnd),
                    retry_in_ms = self.retry_gap.as_millis() as u64,
                    "game capture: the window capture could not start: {e:#}; black frames until \
                     it does"
                );
                self.schedule_retry(now);
                self.go_black(now, "the window capture could not start");
            }
        }
    }

    /// Stop the live capture (the gate first: nothing of it passes from here on).
    fn stop_live(&mut self, now: Instant, why: &str) {
        let Some(live) = self.live.take() else {
            return;
        };
        self.gate.close();
        let frames = self.gate.live_frames();
        let ended = live.capture.stop();
        tracing::debug!(
            hwnd = %format!("{:#x}", live.hwnd),
            generation = live.generation,
            frames,
            ran_ms = now.saturating_duration_since(live.started).as_millis() as u64,
            ended_by_itself = ended.as_deref().unwrap_or("-"),
            "game capture: window capture stopped: {why}"
        );
    }

    /// The live capture: did it end by itself, and has it delivered?
    fn watch(&mut self, now: Instant) {
        let Some(live) = self.live.as_mut() else {
            return;
        };
        let frames = self.gate.live_frames();
        let ran = now.saturating_duration_since(live.started);
        if live.capture.finished() {
            let hwnd = live.hwnd;
            self.gate.close();
            let reason = self
                .live
                .take()
                .and_then(|l| l.capture.stop())
                .unwrap_or_else(|| "no reason given".to_string());
            tracing::warn!(
                hwnd = %format!("{hwnd:#x}"),
                frames,
                ran_ms = ran.as_millis() as u64,
                retry_in_ms = self.retry_gap.as_millis() as u64,
                "game capture: the window capture ended by itself ({reason}); black frames until \
                 it is back"
            );
            self.schedule_retry(now);
            self.go_black(now, "the window capture ended");
        } else if frames == 0 && ran >= FIRST_FRAME_WITHIN {
            let hwnd = live.hwnd;
            tracing::warn!(
                hwnd = %format!("{hwnd:#x}"),
                waited_ms = ran.as_millis() as u64,
                retry_in_ms = self.retry_gap.as_millis() as u64,
                "game capture: no frame of the window since its capture started (every frame \
                 refused, or none delivered); starting it again"
            );
            self.stop_live(now, "no frame since it started");
            self.schedule_retry(now);
            self.go_black(now, "the window capture delivered nothing");
        } else if frames > 0 && ran >= RETRY_RESET_AFTER && self.retry_gap != RETRY_MIN {
            tracing::debug!(
                "game capture: the window capture has run well; the pause after a failure is reset"
            );
            self.retry_gap = RETRY_MIN;
        }
    }

    fn schedule_retry(&mut self, now: Instant) {
        self.retry_at = Some(now + self.retry_gap);
        self.retry_gap = (self.retry_gap * 2).min(RETRY_MAX);
    }

    /// Keep the rectangle the input side reads current while the window only moves: the picture
    /// placed on screen the way the frame handler places it ([`picture_on_screen`]), so the two
    /// never disagree.
    fn refresh_geometry(&mut self, hwnd: usize) {
        let placed = self.source.geometry(hwnd).and_then(|g| {
            picture_on_screen(&g).map_err(|why| {
                format!(
                    "the picture could not be placed: {why} (bounds {}, client {}, dpi {})",
                    g.bounds, g.client, g.dpi
                )
            })
        });
        match placed {
            Ok(picture) => {
                if std::mem::take(&mut self.geometry_failing) {
                    tracing::debug!("game capture: the window's geometry reads again");
                }
                self.status.refresh_client(hwnd, picture);
            }
            Err(e) => {
                if !std::mem::replace(&mut self.geometry_failing, true) {
                    tracing::debug!(
                        hwnd = %format!("{hwnd:#x}"),
                        "game capture: the window's geometry could not be read: {e}"
                    );
                }
            }
        }
    }

    /// Black frames from now on, the first at once.
    fn go_black(&mut self, now: Instant, why: &str) {
        if self.black.is_none() {
            tracing::debug!(
                every_ms = BLACK_EVERY.as_millis() as u64,
                "game capture: black frames start: {why}"
            );
            self.black = Some((now, why.to_string(), 0));
            self.next_black = Some(now);
        }
    }

    /// The window capture takes over from black frames.
    fn go_live(&mut self, now: Instant) {
        self.next_black = None;
        if let Some((since, why, frames)) = self.black.take() {
            tracing::debug!(
                black_frames = frames,
                black_ms = now.saturating_duration_since(since).as_millis() as u64,
                began_with = %why,
                "game capture: black frames stop: the window capture takes over"
            );
        }
    }

    fn send_black(&mut self, now: Instant) {
        self.next_black = Some(now + BLACK_EVERY);
        let source = self.status.snapshot().source.unwrap_or(BLACK_SOURCE);
        let frame = black_frame(source, self.target.max_h());
        let (w, h) = (frame.width, frame.height);
        match self.gate.send_black(frame) {
            GateSend::Sent => {
                if let Some((_, _, frames)) = self.black.as_mut() {
                    *frames += 1;
                }
                tracing::trace!(w, h, "game capture: black frame");
            }
            GateSend::Refused => {
                tracing::trace!("game capture: black frame refused: a capture is live");
            }
            GateSend::Closed => {
                tracing::debug!("game capture: the frame consumer is gone; stopping");
                self.consumer_gone = true;
            }
        }
    }

    fn finish(&mut self, why: &str) {
        let now = Instant::now();
        self.stop_live(now, why);
        self.gate.shut();
        tracing::debug!(
            state = self.finder.state().map_or("-", GameWindowState::as_str),
            "game capture finished: {why}"
        );
    }
}

/// A scripted window list and window capture, for tests here and in `crate::agent` that drive the
/// real game capturer.
#[cfg(test)]
pub(crate) mod fakes {
    use super::*;

    pub(crate) const EXE: &str = r"D:\Games\Scryde\Scryde\ScrydeGame.bin";
    pub(crate) const CLASS: &str = "ScrydeGameUnrealWWindowsViewportWindow";

    pub(crate) fn binding() -> GameBinding {
        GameBinding::new(EXE, CLASS)
    }

    /// The owner's game's window, borderless, on screen.
    pub(crate) fn game_window(hwnd: usize, pid: u32) -> WindowInfo {
        WindowInfo {
            hwnd,
            pid,
            class: CLASS.into(),
            title: "Scryde Game".into(),
            exe_name: "ScrydeGame.bin".into(),
            exe_path: Some(Ok(EXE.into())),
            visible: true,
            minimized: false,
            cloaked: false,
            area: 3600 * 2328,
        }
    }

    pub(crate) type Windows = Arc<Mutex<Result<Vec<WindowInfo>, String>>>;

    pub(crate) struct ScriptedSource {
        pub(crate) windows: Windows,
        pub(crate) geometry: Arc<Mutex<Result<WindowGeometry, String>>>,
    }

    impl ScriptedSource {
        pub(crate) fn new(windows: Windows) -> Self {
            Self {
                windows,
                geometry: Arc::new(Mutex::new(Ok(WindowGeometry {
                    bounds: ScreenRect {
                        left: 0,
                        top: 0,
                        right: 3600,
                        bottom: 2328,
                    },
                    client: ScreenRect {
                        left: 0,
                        top: 0,
                        right: 3600,
                        bottom: 2328,
                    },
                    dpi: WindowDpi::UNKNOWN,
                    own: None,
                }))),
            }
        }
    }

    impl WindowSource for ScriptedSource {
        fn windows(&mut self, _binding: &GameBinding) -> Result<Vec<WindowInfo>, String> {
            lock(&self.windows).clone()
        }
        fn geometry(&mut self, _hwnd: usize) -> Result<WindowGeometry, String> {
            lock(&self.geometry).clone()
        }
    }

    /// What a running scripted capture was started with.
    #[derive(Clone)]
    pub(crate) struct Running {
        pub(crate) gate: Arc<FrameGate>,
        pub(crate) generation: u64,
        pub(crate) status: Arc<GameStatus>,
        pub(crate) target: Arc<QualityTarget>,
        pub(crate) hwnd: usize,
    }

    #[derive(Default)]
    pub(crate) struct BackendWorld {
        pub(crate) started: Vec<(usize, u64)>,
        pub(crate) stopped: u32,
        pub(crate) fail_starts: u32,
        /// The running capture's context, for the test to deliver frames through.
        pub(crate) running: Option<Running>,
        /// The running capture "ended by itself".
        pub(crate) finished: bool,
    }

    impl BackendWorld {
        /// The running capture delivers one frame of the game's picture at `w`x`h`, the way the
        /// frame handler does: the picture's size to the rung, the frame through the gate, then
        /// where the picture is.
        pub(crate) fn deliver(&self, w: u32, h: u32) -> GateSend {
            let Some(run) = self.running.clone() else {
                return GateSend::Refused;
            };
            run.target.set_source(w, h);
            let sent = run.gate.send_live(
                run.generation,
                Frame {
                    data: vec![7; w as usize * h as usize * 4],
                    width: w,
                    height: h,
                    timestamp_ms: 0,
                },
            );
            if sent == GateSend::Sent {
                run.status.set_geometry(CaptureGeometry {
                    hwnd: run.hwnd,
                    client: ScreenRect {
                        left: 0,
                        top: 0,
                        right: w as i32,
                        bottom: h as i32,
                    },
                    source: (w, h),
                });
            }
            sent
        }
    }

    pub(crate) struct ScriptedBackend(pub(crate) Arc<Mutex<BackendWorld>>);

    struct ScriptedCapture(Arc<Mutex<BackendWorld>>);

    impl WindowCaptureBackend for ScriptedBackend {
        fn start(&mut self, ctx: WindowCaptureContext) -> anyhow::Result<Box<dyn WindowCapture>> {
            let mut w = lock(&self.0);
            if w.fail_starts > 0 {
                w.fail_starts -= 1;
                anyhow::bail!("CreateForWindow: 0x80070005 Access is denied.");
            }
            w.started.push((ctx.hwnd, ctx.generation));
            w.running = Some(Running {
                gate: ctx.gate,
                generation: ctx.generation,
                status: ctx.status,
                target: ctx.target,
                hwnd: ctx.hwnd,
            });
            w.finished = false;
            Ok(Box::new(ScriptedCapture(self.0.clone())))
        }
    }

    impl WindowCapture for ScriptedCapture {
        fn finished(&mut self) -> bool {
            lock(&self.0).finished
        }
        fn stop(self: Box<Self>) -> Option<String> {
            let mut w = lock(&self.0);
            w.stopped += 1;
            w.running = None;
            w.finished.then(|| "the capture item closed".to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::fakes::*;
    use super::*;
    use std::sync::mpsc::{self, Receiver};

    /* ── The binding ── */

    #[test]
    fn a_binding_matches_its_exe_path_in_any_case_and_its_class_only() {
        let b = binding();
        assert_eq!(b.display_name, "ScrydeGame.bin");
        assert!(b.exe_matches(r"d:\games\scryde\scryde\scrydegame.bin"));
        assert!(b.exe_matches("D:/Games/Scryde/Scryde/ScrydeGame.bin"));
        assert!(!b.exe_matches(r"D:\Games\Scryde\Scryde\ScrydeGame.exe"));
        assert!(!b.exe_matches(r"E:\Games\Scryde\Scryde\ScrydeGame.bin"));
        assert!(b.class_matches("scrydegameunrealwwindowsviewportwindow"));
        assert!(!b.class_matches("NSplashWnd"));
        // Cyrillic in a path folds too.
        let ru = GameBinding::new(r"C:\Игры\Игра.exe", "Game");
        assert!(ru.exe_matches(r"c:\игры\ИГРА.EXE"));
        assert_eq!(ru.shown_name(), "Игра.exe");
        assert_eq!(
            GameBinding::new("", CLASS).unusable(),
            Some("the bound exe path is empty")
        );
        assert_eq!(
            GameBinding::new(EXE, " ").unusable(),
            Some("the bound window class is empty")
        );
        assert_eq!(b.unusable(), None);
    }

    /* ── The finder ── */

    #[test]
    fn nothing_bound_or_nothing_running_is_absent() {
        let mut f = GameFinder::new(None);
        assert_eq!(
            f.decide(vec![game_window(1, 10)]).state,
            GameWindowState::Absent
        );

        let mut f = GameFinder::new(Some(binding()));
        let v = f.decide(vec![]);
        assert_eq!(v.state, GameWindowState::Absent);
        assert!(v.window.is_none());
    }

    #[test]
    fn the_game_process_without_its_window_is_starting() {
        let mut f = GameFinder::new(Some(binding()));
        // The splash and the loader's windows of the same exe (measured: `NSplashWnd` at +5.0 s,
        // the viewport at +8.7 s).
        let splash = WindowInfo {
            class: "NSplashWnd".into(),
            ..game_window(0x20, 6888)
        };
        let v = f.decide(vec![splash.clone()]);
        assert_eq!(v.state, GameWindowState::Starting);
        // A matching window created hidden is still starting.
        let hidden = WindowInfo {
            visible: false,
            ..game_window(0x40666, 6888)
        };
        let v = f.decide(vec![splash, hidden]);
        assert_eq!(v.state, GameWindowState::Starting);
        assert_eq!(v.window.map(|w| w.hwnd), Some(0x40666));
    }

    #[test]
    fn the_window_is_matched_on_exe_path_and_class_together() {
        let mut f = GameFinder::new(Some(binding()));
        // The right class in another process (another client, a copy elsewhere): not the game.
        let other_copy = WindowInfo {
            exe_path: Some(Ok(r"E:\Other\ScrydeGame.bin".into())),
            ..game_window(0x10, 1)
        };
        // The right class, a process not named like the exe: not looked up, not the game.
        let other_exe = WindowInfo {
            exe_name: "chrome.exe".into(),
            exe_path: None,
            ..game_window(0x11, 2)
        };
        // The right class, but the path could not be read: fail closed.
        let unreadable = WindowInfo {
            exe_path: Some(Err("OpenProcess: 0x80070005 Access is denied.".into())),
            ..game_window(0x12, 3)
        };
        let v = f.decide(vec![
            other_copy.clone(),
            other_exe.clone(),
            unreadable.clone(),
        ]);
        assert_eq!(v.state, GameWindowState::Absent, "{}", v.why);
        assert!(v.window.is_none());

        let v = f.decide(vec![
            other_copy,
            other_exe,
            unreadable,
            game_window(0x40666, 6888),
        ]);
        assert_eq!(v.state, GameWindowState::Shown);
        assert_eq!(v.window.map(|w| w.hwnd), Some(0x40666));
    }

    #[test]
    fn minimized_and_cloaked_windows_are_not_shown() {
        let mut f = GameFinder::new(Some(binding()));
        let min = WindowInfo {
            minimized: true,
            ..game_window(0x40666, 6888)
        };
        assert_eq!(f.decide(vec![min]).state, GameWindowState::Minimized);
        let cloaked = WindowInfo {
            cloaked: true,
            ..game_window(0x40666, 6888)
        };
        assert_eq!(f.decide(vec![cloaked]).state, GameWindowState::Minimized);
        let empty = WindowInfo {
            area: 0,
            ..game_window(0x40666, 6888)
        };
        assert_eq!(f.decide(vec![empty]).state, GameWindowState::Minimized);
        assert_eq!(
            f.decide(vec![game_window(0x40666, 6888)]).state,
            GameWindowState::Shown
        );
    }

    #[test]
    fn a_relaunch_is_followed_to_the_new_window() {
        let mut f = GameFinder::new(Some(binding()));
        assert_eq!(
            f.decide(vec![game_window(0x40666, 6888)]).state,
            GameWindowState::Shown
        );
        // Closed: the window goes, the process lingers a few seconds with none.
        assert_eq!(f.decide(vec![]).state, GameWindowState::Absent);
        // Relaunched: a new process, a new window.
        let v = f.decide(vec![game_window(0x90abc, 7777)]);
        assert_eq!(v.state, GameWindowState::Shown);
        assert_eq!(v.window.map(|w| (w.hwnd, w.pid)), Some((0x90abc, 7777)));
    }

    /// The game's window gone behind its crash reporter, its process alive: starting, as ever; the
    /// log names what the process still shows (class and title, capped and cut).
    #[test]
    fn a_bound_window_gone_behind_a_crash_report_is_starting_and_its_windows_are_named() {
        let mut f = GameFinder::new(Some(binding()));
        assert_eq!(
            f.decide(vec![game_window(0x16f10d2, 52204)]).state,
            GameWindowState::Shown
        );
        assert_eq!(f.bound_pid, Some(52204));
        let report = WindowInfo {
            class: "#32770".into(),
            title: "Scryde Crash Report".into(),
            ..game_window(0x520b82, 52204)
        };
        let ime = WindowInfo {
            class: "IME".into(),
            title: "Default IME".into(),
            ..game_window(0x520b84, 52204)
        };
        let v = f.decide(vec![report.clone(), ime.clone()]);
        assert_eq!(v.state, GameWindowState::Starting, "{}", v.why);
        assert_eq!((f.bound, f.bound_pid), (None, None), "said once");

        let others: Vec<(u32, String, String)> = [&report, &ime]
            .iter()
            .map(|w| (w.pid, w.class.clone(), w.title.clone()))
            .collect();
        assert_eq!(
            process_runs_on(52204, &others).as_deref(),
            Some(
                "2 other top-level window(s) of it: \"#32770\" \"Scryde Crash Report\", \"IME\" \
                 \"Default IME\""
            )
        );
        // Another process's windows only: not this one's.
        assert_eq!(process_runs_on(7, &others), None);
        // Capped at 8, titles cut at 80 characters.
        let many: Vec<(u32, String, String)> = (0..10)
            .map(|i| (1, format!("C{i}"), "я".repeat(100)))
            .collect();
        let said = process_runs_on(1, &many).unwrap();
        assert!(
            said.starts_with("10 other top-level window(s) of it: "),
            "{said}"
        );
        assert!(said.ends_with(" and 2 more"), "{said}");
        assert!(
            said.contains(&format!("\"C0\" \"{}…\"", "я".repeat(80))),
            "{said}"
        );
        assert!(!said.contains("\"C8\""), "{said}");
    }

    #[test]
    fn with_several_matching_windows_the_bound_one_stays_and_the_best_is_taken_first() {
        let mut f = GameFinder::new(Some(binding()));
        let small = WindowInfo {
            area: 800 * 600,
            ..game_window(0x1, 1)
        };
        let minimized_big = WindowInfo {
            minimized: true,
            ..game_window(0x2, 2)
        };
        let big = game_window(0x3, 3);
        let v = f.decide(vec![small.clone(), minimized_big.clone(), big.clone()]);
        assert_eq!(
            v.window.map(|w| w.hwnd),
            Some(0x3),
            "shown before minimized, then largest"
        );
        // Minimized now: the bound window stays bound rather than jumping to another client.
        let big_min = WindowInfo {
            minimized: true,
            ..big
        };
        let v = f.decide(vec![small, minimized_big, big_min]);
        assert_eq!(v.window.map(|w| w.hwnd), Some(0x3));
        assert_eq!(v.state, GameWindowState::Minimized);
    }

    #[test]
    fn an_unreadable_window_list_is_absent_and_an_unusable_binding_matches_nothing() {
        let windows: Windows = Arc::new(Mutex::new(Ok(vec![game_window(0x40666, 6888)])));
        let mut source = ScriptedSource::new(windows.clone());
        let mut f = GameFinder::new(Some(binding()));
        assert_eq!(f.poll(&mut source).state, GameWindowState::Shown);
        *lock(&windows) = Err("EnumWindows: 0x80004005".into());
        assert_eq!(f.poll(&mut source).state, GameWindowState::Absent);
        *lock(&windows) = Ok(vec![game_window(0x40666, 6888)]);
        assert_eq!(f.poll(&mut source).state, GameWindowState::Shown);

        let mut f = GameFinder::new(Some(GameBinding::new(EXE, "")));
        assert_eq!(f.poll(&mut source).state, GameWindowState::Absent);
    }

    /* ── The crop ── */

    fn rect(left: i32, top: i32, right: i32, bottom: i32) -> ScreenRect {
        ScreenRect {
            left,
            top,
            right,
            bottom,
        }
    }

    /// A window that is not stretched: per-monitor aware, at its monitor's 144 DPI.
    fn unstretched(bounds: ScreenRect, client: ScreenRect) -> WindowGeometry {
        WindowGeometry {
            bounds,
            client,
            dpi: WindowDpi {
                awareness: DpiAwareness::PerMonitorV2,
                window: 144,
                monitor: 144,
            },
            own: None,
        }
    }

    fn crop_of(frame_w: u32, frame_h: u32, g: &WindowGeometry) -> Result<Crop, CropRefusal> {
        client_crop(frame_w, frame_h, g).map(|c| c.crop)
    }

    #[test]
    fn a_borderless_window_is_captured_whole() {
        // The owner's game, borderless (measured): frame, bounds and client all 3600x2328.
        let g = unstretched(rect(0, 0, 3600, 2328), rect(0, 0, 3600, 2328));
        assert_eq!(
            crop_of(3600, 2328, &g),
            Ok(Crop {
                x: 0,
                y: 0,
                w: 3600,
                h: 2328
            })
        );
    }

    #[test]
    fn a_windowed_window_loses_its_title_bar_and_borders() {
        // A real game in windowed mode, measured with the probe: frame 3578x2317, DWM bounds
        // [11,0,3589,2317], client on screen [12,47,3588,2315] — read
        // here as a window that is not stretched (the probe did not record the DPIs).
        let g = unstretched(rect(11, 0, 3589, 2317), rect(12, 47, 3588, 2315));
        assert_eq!(
            crop_of(3578, 2317, &g),
            Ok(Crop {
                x: 1,
                y: 47,
                w: 3576,
                h: 2268
            })
        );
    }

    #[test]
    fn the_crop_is_even_and_inside_the_frame() {
        // An odd client area loses its last column and row rather than being resampled.
        let g = unstretched(rect(100, 100, 1101, 801), rect(108, 131, 1093, 793));
        let c = client_crop(1001, 701, &g).expect("crop");
        assert_eq!((c.crop.x, c.crop.y, c.crop.w, c.crop.h), (8, 31, 984, 662));
        assert_eq!(
            c.inset_text(),
            "l0 t0 r1 b0",
            "the odd column, nothing else"
        );
        // A client area hanging past the frame (a reading a pixel off) is clamped to it.
        let g = unstretched(rect(0, 0, 1000, 800), rect(-4, 30, 1006, 810));
        assert_eq!(
            crop_of(1000, 800, &g),
            Ok(Crop {
                x: 0,
                y: 30,
                w: 1000,
                h: 770
            })
        );
    }

    #[test]
    fn a_scaled_capture_scales_the_crop_and_a_resize_in_flight_is_refused() {
        // Two thirds on both axes: a frame smaller than DWM's bounds.
        let g = unstretched(rect(100, 100, 1600, 1300), rect(110, 160, 1590, 1290));
        let c = client_crop(1000, 800, &g).expect("a scaled crop");
        assert_eq!((c.crop.x, c.crop.y, c.crop.w, c.crop.h), (7, 40, 986, 752));
        // On screen inward of the client area: the frame's edges divided back, rounded in.
        assert_eq!(c.on_screen, rect(111, 160, 1589, 1288));
        // A frame of the old size against the new bounds (borderless → windowed): refused.
        let g = unstretched(rect(11, 0, 3589, 2317), rect(12, 47, 3588, 2315));
        assert!(matches!(
            crop_of(3600, 2328, &g),
            Err(CropRefusal::SizeMismatch { .. })
        ));
        // Different scales on the two axes: refused.
        assert!(matches!(
            crop_of(1000, 1200, &g),
            Err(CropRefusal::SizeMismatch { .. })
        ));
    }

    #[test]
    fn nothing_to_crop_is_refused() {
        let g = unstretched(rect(0, 0, 1000, 800), rect(0, 0, 1000, 800));
        assert_eq!(
            crop_of(1, 1, &g),
            Err(CropRefusal::EmptyFrame { w: 1, h: 1 })
        );
        let minimized = unstretched(rect(-32000, -32000, -31840, -31972), rect(0, 0, 0, 0));
        assert_eq!(
            crop_of(1000, 800, &minimized),
            Err(CropRefusal::EmptyWindow)
        );
        let outside = unstretched(rect(0, 0, 1000, 800), rect(1200, 900, 1500, 1000));
        assert_eq!(crop_of(1000, 800, &outside), Err(CropRefusal::Outside));
        // The same refusals for a stretched window: its numbers change nothing of them.
        let owner = owners_game();
        assert_eq!(
            crop_of(1, 1, &owner),
            Err(CropRefusal::EmptyFrame { w: 1, h: 1 })
        );
        let gone = WindowGeometry {
            client: rect(0, 0, 0, 0),
            ..owner
        };
        assert_eq!(crop_of(2882, 1668, &gone), Err(CropRefusal::EmptyWindow));
        assert!(matches!(
            crop_of(3600, 2328, &owner),
            Err(CropRefusal::SizeMismatch { .. })
        ));
        let past = WindowGeometry {
            client: rect(4000, 2000, 4400, 2300),
            ..owner
        };
        assert_eq!(crop_of(2882, 1668, &past), Err(CropRefusal::Outside));
    }

    /* ── The crop of a window Windows stretches ── */

    /// A window Windows stretches from its own `window_dpi` to its monitor's, as the reader reads
    /// it: the own rectangles exact, the per-monitor ones and DWM's bounds in physical pixels.
    fn stretched(
        window_dpi: u32,
        monitor_dpi: u32,
        own_window: ScreenRect,
        own_client: ScreenRect,
        window_px: ScreenRect,
        bounds: ScreenRect,
        client: ScreenRect,
    ) -> WindowGeometry {
        WindowGeometry {
            bounds,
            client,
            dpi: WindowDpi {
                awareness: DpiAwareness::Unaware,
                window: window_dpi,
                monitor: monitor_dpi,
            },
            own: Some(OwnRects {
                window_px,
                window: own_window,
                client: own_client,
            }),
        }
    }

    /// A real game as its game-only sessions log it: 1920x1080 in a standard window, unaware on a
    /// 150 % (144 DPI) panel. DWM bounds, client area and frame (2882x1668) are the session log's;
    /// the rest follows from them the way the probe window measured it —
    /// the own window at 367,127 (1936x1119: 8, 31, 8 and 8 own pixels around the client), read on
    /// a per-monitor thread as origin times 1.5 and size times 1.5, each rounded half up
    /// ([551,191,3455,1870]); DWM's bounds that rectangle inset by 11, 0, 11 and 11.
    fn owners_game() -> WindowGeometry {
        stretched(
            96,
            144,
            rect(367, 127, 2303, 1246),
            rect(375, 158, 2295, 1238),
            rect(551, 191, 3455, 1870),
            rect(562, 191, 3444, 1859),
            rect(563, 237, 3443, 1857),
        )
    }

    #[test]
    fn the_owners_game_loses_the_title_bars_row_and_the_blended_edges() {
        let c = client_crop(2882, 1668, &owners_game()).expect("crop");
        // What Windows reports, the crop before this: 2880x1620+1+46, its first row the title bar's
        // last (the frame is the window's own bitmap, the client placed at 46.5 → 47; the reported
        // edge, 237.5 rounded on screen, counts from 191).
        assert_eq!(c.reported, [1, 46, 2881, 1666]);
        // Row 47 and column 1 take a sixth of the title bar and the border through the stretch's
        // filter; row 46 is the title bar. The crop starts past both.
        assert_eq!(
            c.crop,
            Crop {
                x: 2,
                y: 48,
                w: 2878,
                h: 1618
            }
        );
        assert_eq!(c.inset_text(), "l1 t2 r1 b0");
        let stretched = c.stretched.expect("stretched");
        assert!((stretched.scale - 1.5).abs() < 1e-12, "{}", stretched.scale);
        assert_eq!(stretched.exact, Some([1.0, 46.5, 2881.0, 1666.5]));
        // The picture on screen, which input maps `m` into: the same rectangle.
        assert_eq!(c.on_screen, rect(564, 239, 3442, 1857));
        assert_eq!(picture_on_screen(&owners_game()), Ok(c.on_screen));
    }

    /// What the probe window measured at 150 % (unaware, green client, red caption, blue border; a
    /// white bitmap past the client when it drew its own frame): per placement the own window and
    /// client, the per-monitor window, client and DWM bounds, the frame, and the rows and columns
    /// of the frame (inclusive) that held pure green — the client's own pixels and nothing else.
    struct Measured {
        own_window: [i32; 4],
        own_client: [i32; 4],
        window_px: [i32; 4],
        client: [i32; 4],
        bounds: [i32; 4],
        frame: (u32, u32),
        rows: (u32, u32),
        cols: (u32, u32),
    }

    fn r4(r: [i32; 4]) -> ScreenRect {
        rect(r[0], r[1], r[2], r[3])
    }

    fn check_measured(name: &str, m: &Measured) {
        let g = stretched(
            96,
            144,
            r4(m.own_window),
            r4(m.own_client),
            r4(m.window_px),
            r4(m.bounds),
            r4(m.client),
        );
        let c = client_crop(m.frame.0, m.frame.1, &g)
            .unwrap_or_else(|e| panic!("{name}: no crop: {e}"))
            .crop;
        assert!(
            c.y >= m.rows.0 && c.y + c.h - 1 <= m.rows.1,
            "{name}: rows {}..={} hold more than the client's pure rows {:?}",
            c.y,
            c.y + c.h - 1,
            m.rows
        );
        assert!(
            c.x >= m.cols.0 && c.x + c.w - 1 <= m.cols.1,
            "{name}: columns {}..={} hold more than the client's pure columns {:?}",
            c.x,
            c.x + c.w - 1,
            m.cols
        );
        // And gives up little: a row or column past the measured pure ones on each side, one more
        // where the pure run was longer than the filter allows (stale green past the client) or the
        // size was odd.
        assert!(c.y - m.rows.0 <= 1 && c.x - m.cols.0 <= 1, "{name}: {c}");
        assert!(
            m.rows.1 - (c.y + c.h - 1) <= 2 && m.cols.1 - (c.x + c.w - 1) <= 2,
            "{name}: {c}"
        );
    }

    #[test]
    fn every_placement_the_probe_measured_is_cropped_to_pure_client_pixels() {
        // With DWM's frame (red caption, blue border): the client placed on whole pixels.
        let framed = [
            Measured {
                own_window: [200, 200, 616, 539],
                own_client: [208, 231, 608, 531],
                window_px: [300, 300, 924, 809],
                client: [312, 347, 912, 797],
                bounds: [311, 300, 913, 798],
                frame: (602, 498),
                rows: (48, 496),
                cols: (2, 600),
            },
            Measured {
                own_window: [201, 200, 617, 539],
                own_client: [209, 231, 609, 531],
                window_px: [302, 300, 926, 809],
                client: [314, 347, 914, 797],
                bounds: [313, 300, 915, 798],
                frame: (602, 498),
                rows: (48, 496),
                cols: (2, 600),
            },
            // The owner's case: the reported client one row early (rows 46..=495), the frame the
            // same as one own pixel higher.
            Measured {
                own_window: [200, 201, 616, 540],
                own_client: [208, 232, 608, 532],
                window_px: [300, 302, 924, 811],
                client: [312, 348, 912, 798],
                bounds: [311, 302, 913, 800],
                frame: (602, 498),
                rows: (48, 496),
                cols: (2, 600),
            },
            Measured {
                own_window: [201, 201, 618, 541],
                own_client: [209, 232, 610, 533],
                window_px: [302, 302, 928, 812],
                client: [314, 348, 915, 799],
                bounds: [313, 302, 917, 801],
                frame: (604, 499),
                rows: (48, 497),
                cols: (1, 602),
            },
            Measured {
                own_window: [203, 202, 620, 541],
                own_client: [211, 233, 612, 533],
                window_px: [305, 303, 931, 812],
                client: [317, 350, 918, 800],
                bounds: [316, 303, 920, 801],
                frame: (604, 498),
                rows: (47, 496),
                cols: (1, 601),
            },
        ];
        // Without one (the window drawing its own frame white): the whole bitmap stretched by its
        // rounded height over its own (509/339), the client not snapped.
        let frameless = [
            Measured {
                own_window: [200, 200, 616, 539],
                own_client: [208, 231, 608, 531],
                window_px: [300, 300, 924, 809],
                client: [312, 347, 912, 797],
                bounds: [300, 300, 924, 809],
                frame: (624, 509),
                rows: (47, 495),
                cols: (13, 611),
            },
            Measured {
                own_window: [201, 201, 618, 541],
                own_client: [209, 232, 610, 533],
                window_px: [302, 302, 928, 812],
                client: [314, 348, 915, 799],
                bounds: [302, 302, 928, 812],
                frame: (626, 510),
                rows: (47, 496),
                cols: (13, 612),
            },
            Measured {
                own_window: [203, 202, 620, 541],
                own_client: [211, 233, 612, 533],
                window_px: [305, 303, 931, 812],
                client: [317, 350, 918, 800],
                bounds: [305, 303, 931, 812],
                frame: (626, 509),
                rows: (47, 495),
                cols: (13, 612),
            },
        ];
        for (i, m) in framed.iter().enumerate() {
            check_measured(&format!("framed #{}", i + 1), m);
        }
        for (i, m) in frameless.iter().enumerate() {
            check_measured(&format!("frameless #{}", i + 1), m);
        }
    }

    /// Windows' reading of a standard window (8, 31, 8 and 8 own pixels around its client, 7 of
    /// them invisible on the left, right and bottom) at own `x`,`y` with a 1920x1080 client, that
    /// it stretches by `monitor / 96`, the way the probe measured it: origin and size times the
    /// scale, each rounded half up; DWM's bounds that inset by the invisible borders times the
    /// scale, rounded half up. Returns the geometry and the frame's size.
    fn modelled(monitor: u32, x: i32, y: i32, framed: bool) -> (WindowGeometry, (u32, u32)) {
        let s = f64::from(monitor) / 96.0;
        let r = |v: f64| round_half_up(v) as i32;
        let (ww, wh) = (1920 + 16, 1080 + 39);
        let own_window = rect(x, y, x + ww, y + wh);
        let own_client = rect(x + 8, y + 31, x + 8 + 1920, y + 31 + 1080);
        let (px, py) = (r(s * f64::from(x)), r(s * f64::from(y)));
        let window_px = rect(px, py, px + r(s * f64::from(ww)), py + r(s * f64::from(wh)));
        let (cx, cy) = (r(s * f64::from(x + 8)), r(s * f64::from(y + 31)));
        let client = rect(cx, cy, cx + r(s * 1920.0), cy + r(s * 1080.0));
        let side = if framed { r(s * 7.0) } else { 0 };
        let bounds = rect(
            window_px.left + side,
            window_px.top,
            window_px.right - side,
            window_px.bottom - side,
        );
        let frame = (bounds.width() as u32, bounds.height() as u32);
        (
            stretched(
                96, monitor, own_window, own_client, window_px, bounds, client,
            ),
            frame,
        )
    }

    /// Whether pixel `p` of the frame holds the client's own pixels alone when DWM puts its `n` own
    /// pixels at `origin`, stretched by `k` through a bilinear filter (the measured placement): the
    /// pixel's centre at `t = (p + 0.5 - origin) / k - 0.5` own pixels, both taps around it
    /// weighed.
    fn pure_pixel(p: u32, origin: f64, k: f64, n: f64) -> bool {
        let t = (f64::from(p) + 0.5 - origin) / k - 0.5;
        let first = t.floor();
        let next_weight = t - first;
        let inside = |i: f64| (0.0..=n - 1.0).contains(&i);
        inside(first) && (next_weight < 1e-9 || inside(first + 1.0))
    }

    /// Every way DWM may place and stretch the client of a [`modelled`] window — on a whole pixel
    /// or not, by the scale or by the window's rounded height over its own — and, per axis, the
    /// near and far pure pixels of the strictest one (inclusive): `(cols, rows)`.
    fn pure_runs(g: &WindowGeometry, frame: (u32, u32), framed: bool) -> ((u32, u32), (u32, u32)) {
        let own = g.own.expect("own rects");
        let s = g.dpi.stretch().expect("stretched");
        let k_height = round_half_up(s * own.window.height() as f64) / own.window.height() as f64;
        let run = |c: f64, inset: f64, n: f64, len: u32| {
            let placements: Vec<(f64, f64)> = if framed {
                vec![
                    (round_half_up(s * c) - inset, s),
                    (round_half_up(s * c) - inset, k_height),
                ]
            } else {
                vec![(k_height * c - inset, k_height), (s * c - inset, s)]
            };
            let pure = |p: u32| placements.iter().all(|&(o, k)| pure_pixel(p, o, k, n));
            let first = (0..len).find(|&p| pure(p)).expect("a pure pixel");
            let last = (0..len).rev().find(|&p| pure(p)).expect("a pure pixel");
            (first, last)
        };
        let inset_x = f64::from(g.bounds.left - own.window_px.left);
        let inset_y = f64::from(g.bounds.top - own.window_px.top);
        (
            run(8.0, inset_x, 1920.0, frame.0),
            run(31.0, inset_y, 1080.0, frame.1),
        )
    }

    #[test]
    fn at_every_scale_and_placement_the_crop_holds_only_the_clients_own_pixels() {
        for monitor in [120, 144, 168, 192, 216, 240] {
            for framed in [true, false] {
                for (x, y) in (0..4).flat_map(|x| (0..4).map(move |y| (100 + x, 80 + y))) {
                    let (g, frame) = modelled(monitor, x, y, framed);
                    let at = format!("{monitor} dpi, framed {framed}, own {x},{y}");
                    let c = client_crop(frame.0, frame.1, &g)
                        .unwrap_or_else(|e| panic!("{at}: {e}"))
                        .crop;
                    let (cols, rows) = pure_runs(&g, frame, framed);
                    assert!(
                        c.x >= cols.0 && c.x + c.w - 1 <= cols.1,
                        "{at}: columns {}..={} past the pure {cols:?}",
                        c.x,
                        c.x + c.w - 1
                    );
                    assert!(
                        c.y >= rows.0 && c.y + c.h - 1 <= rows.1,
                        "{at}: rows {}..={} past the pure {rows:?}",
                        c.y,
                        c.y + c.h - 1
                    );
                    // Nothing pure given up but a pixel a side, and the even size's last one.
                    assert!(c.x - cols.0 <= 1 && c.y - rows.0 <= 1, "{at}: {c}");
                    assert!(
                        cols.1 - (c.x + c.w - 1) <= 2 && rows.1 - (c.y + c.h - 1) <= 2,
                        "{at}: {c}"
                    );
                }
            }
        }
    }

    #[test]
    fn the_crop_at_125_175_and_200_percent() {
        // A 1920x1080 game at own 100,100 in a standard window: what Windows reports, and the crop.
        let cases = [
            // 125 %: the client's top at 38.75 → 39, the filter reaching an eighth further.
            (120, [1, 39, 2401, 1389], (2402, 1390), (2, 40, 2398, 1348)),
            // 175 %: 54.25 → 54, three eighths' reach; the window's rounded height (1958/1119)
            // stretches a hair less than 1.75.
            (168, [2, 54, 3362, 1944], (3364, 1946), (3, 55, 3358, 1888)),
            // 200 %: every edge on a whole pixel, and still a quarter of the title bar and the
            // border in the first row and column through the filter.
            (192, [2, 62, 3842, 2222], (3844, 2224), (3, 63, 3838, 2158)),
        ];
        for (monitor, reported, frame, (x, y, w, h)) in cases {
            let (g, size) = modelled(monitor, 100, 100, true);
            assert_eq!(size, frame, "{monitor} dpi: the frame");
            let c = client_crop(frame.0, frame.1, &g).expect("crop");
            assert_eq!(
                c.reported, reported,
                "{monitor} dpi: the reported client area"
            );
            assert_eq!(c.crop, Crop { x, y, w, h }, "{monitor} dpi");
            assert_eq!(c.inset_text(), "l1 t1 r1 b1", "{monitor} dpi");
        }
    }

    #[test]
    fn a_window_that_is_not_stretched_keeps_its_reported_client_area() {
        // Unaware on a 100 % monitor: drawn at its monitor's DPI, nothing to work out.
        let (mut at_100, frame) = modelled(96, 100, 100, true);
        at_100.own = None;
        assert_eq!(frame, (1922, 1112));
        let c = client_crop(frame.0, frame.1, &at_100).expect("crop");
        assert_eq!(c.stretched, None);
        assert_eq!(
            c.crop,
            Crop {
                x: 1,
                y: 31,
                w: 1920,
                h: 1080
            }
        );
        assert_eq!(c.inset, [0; 4]);
        assert_eq!(c.on_screen, at_100.client);
        // Per-monitor aware at 150 % (the probe window): its rectangles are exact and every
        // row and column of its client area pure — pixel-exact, not a pixel lost.
        let pm = unstretched(rect(209, 200, 613, 547), rect(211, 245, 611, 545));
        let c = client_crop(404, 347, &pm).expect("crop");
        assert_eq!(
            c.crop,
            Crop {
                x: 2,
                y: 45,
                w: 400,
                h: 300
            }
        );
        assert_eq!(c.inset, [0; 4]);
        assert_eq!(c.on_screen, pm.client);
        assert!(c.why.starts_with("not stretched"), "{}", c.why);
        // DPIs unknown: the reported client area too, and said so.
        let unknown = WindowGeometry {
            dpi: WindowDpi::UNKNOWN,
            ..pm
        };
        let c = client_crop(404, 347, &unknown).expect("crop");
        assert_eq!(c.crop.y, 45);
        assert!(c.why.contains("unknown"), "{}", c.why);
    }

    #[test]
    fn a_stretched_window_without_its_own_rects_moves_every_edge_in_past_the_filter() {
        // The own rectangles unread (the reader's thread could not switch to the window's DPI
        // awareness, or a read in it failed): the frame is still cropped, not refused.
        let g = WindowGeometry {
            own: None,
            ..owners_game()
        };
        let c = client_crop(2882, 1668, &g).expect("cropped, not refused");
        // A pixel and the filter's reach (a quarter at 150 %) in from 1, 46, 2881 and 1666.
        assert_eq!(
            c.crop,
            Crop {
                x: 3,
                y: 48,
                w: 2876,
                h: 1616
            }
        );
        assert_eq!(c.stretched.and_then(|s| s.exact), None);
        assert!(c.why.contains("own rectangles unread"), "{}", c.why);
        assert_eq!(c.inset_text(), "l2 t2 r2 b2");
        assert_eq!(picture_on_screen(&g), Ok(c.on_screen));
        // It holds the client's pure pixels alone whichever way the reported edge was rounded: the
        // probe's placements with the client reported on its row (the first) and a row early (the
        // second), pure rows 48..=496 and columns 2..=600 in both.
        for (window_px, bounds, client) in [
            (
                rect(300, 300, 924, 809),
                rect(311, 300, 913, 798),
                rect(312, 347, 912, 797),
            ),
            (
                rect(300, 302, 924, 811),
                rect(311, 302, 913, 800),
                rect(312, 348, 912, 798),
            ),
        ] {
            let mut g = stretched(
                96,
                144,
                rect(0, 0, 1, 1),
                rect(0, 0, 1, 1),
                window_px,
                bounds,
                client,
            );
            g.own = None;
            let c = client_crop(602, 498, &g).expect("crop").crop;
            assert!(c.y >= 48 && c.y + c.h - 1 <= 496, "{c}");
            assert!(c.x >= 2 && c.x + c.w - 1 <= 600, "{c}");
        }
    }

    /* ── The status and the gate ── */

    #[test]
    fn the_status_says_nothing_outside_game_mode_and_forgets_the_geometry_when_not_shown() {
        let s = GameStatus::new();
        assert_eq!(s.heartbeat(), None);
        assert_eq!(s.line_fields(), ("-", "-".to_string()));
        s.set_active(true);
        assert_eq!(
            s.heartbeat(),
            Some(GameHeartbeat::new(GameWindowState::Absent, None))
        );
        let g = CaptureGeometry {
            hwnd: 7,
            client: rect(12, 47, 3588, 2315),
            source: (3576, 2268),
        };
        assert!(!s.set_geometry(g), "ignored while the window is not shown");
        assert!(s.set_state(GameWindowState::Shown));
        assert!(s.set_geometry(g));
        assert_eq!(s.geometry(), Some(g));
        assert_eq!(s.line_fields(), ("shown", "3576x2268".to_string()));
        s.refresh_client(7, rect(112, 147, 3688, 2415));
        assert_eq!(
            s.geometry().map(|g| g.client),
            Some(rect(112, 147, 3688, 2415))
        );
        assert!(s.set_state(GameWindowState::Minimized));
        assert_eq!(
            s.geometry(),
            None,
            "no geometry for a window that is not on screen"
        );
        assert_eq!(
            s.heartbeat(),
            Some(GameHeartbeat::new(
                GameWindowState::Minimized,
                Some((3576, 2268))
            )),
            "the picture's last size stays"
        );
        s.set_active(false);
        assert_eq!(s.heartbeat(), None);
    }

    /// The helper's launch: a change is said once and wakes every heartbeat waiting on it; the same
    /// value again is no change.
    #[tokio::test]
    async fn the_helpers_launch_wakes_every_heartbeat_on_a_change_only() {
        let launch = HelperLaunch::new();
        assert!(!launch.is_launching());
        // Two sessions' heartbeats waiting, as each one's `select!` does between ticks.
        let first = launch.changed().notified();
        let second = launch.changed().notified();
        assert!(!launch.set(false, "nothing launched"), "no change");
        assert!(launch.set(true, "the helper launched the game"));
        assert!(launch.is_launching());
        tokio::time::timeout(Duration::from_secs(2), async {
            first.await;
            second.await;
        })
        .await
        .expect("every heartbeat is woken");
        let third = launch.changed().notified();
        assert!(!launch.set(true, "still launching"), "no change");
        assert!(
            tokio::time::timeout(Duration::from_millis(50), third)
                .await
                .is_err(),
            "the same value again wakes nobody"
        );
        assert!(launch.set(false, "its window is up"));
        assert!(!launch.is_launching());
    }

    /// What input reads: the client area and the window's process, only for the window captured and
    /// only while it is shown; and `unfocused` told only while it is shown.
    #[test]
    fn the_input_side_reads_the_window_its_process_and_its_focus() {
        let s = GameStatus::new();
        s.set_active(true);
        let g = CaptureGeometry {
            hwnd: 0x40666,
            client: rect(12, 47, 3588, 2315),
            source: (3576, 2268),
        };
        assert_eq!(s.game_scope().window, None, "nothing shown yet");
        s.set_state(GameWindowState::Shown);
        s.set_geometry(g);
        assert_eq!(
            s.game_scope().window,
            None,
            "captured, but whose window it is is not known yet: fail closed"
        );
        s.set_window(0x40666, 6888);
        let scope = s.game_scope();
        assert_eq!(scope.state, GameWindowState::Shown);
        assert_eq!(
            scope.window,
            Some(GameInputWindow {
                hwnd: 0x40666,
                pid: 6888,
                client: rect(12, 47, 3588, 2315),
            })
        );
        // Another window bound (a relaunch) while the old capture's geometry stands: not its pid.
        s.set_window(0x90abc, 7777);
        assert_eq!(s.game_scope().window, None);
        s.set_window(0x40666, 6888);

        // Another window takes the front: the viewer is told `unfocused`, and back.
        assert!(s.set_focus(false));
        assert_eq!(
            s.heartbeat().map(|h| h.state),
            Some(GameWindowState::Unfocused)
        );
        assert_eq!(s.line_fields().0, "unfocused");
        assert!(!s.set_focus(false), "no change, no wake-up");
        assert!(s.set_focus(true));
        assert_eq!(s.heartbeat().map(|h| h.state), Some(GameWindowState::Shown));

        // Minimized: its own state, whatever the focus; the window and its process forgotten.
        s.set_focus(false);
        s.set_state(GameWindowState::Minimized);
        assert_eq!(
            s.heartbeat().map(|h| h.state),
            Some(GameWindowState::Minimized)
        );
        assert_eq!(s.snapshot().window, None);
        assert!(!s.set_focus(false), "nothing to be in front of");
        s.set_state(GameWindowState::Shown);
        assert_eq!(
            s.heartbeat().map(|h| h.state),
            Some(GameWindowState::Shown),
            "shown again: not unfocused until the watch says so"
        );
    }

    /// The frames of a capture made for another mode are refused from the moment the setting
    /// flips, before the capture is replaced.
    #[test]
    fn a_session_capture_admits_frames_only_in_the_mode_it_was_made_for() {
        let backends = crate::pipeline::fakes::fake_backends(
            &Arc::new(Mutex::new(crate::pipeline::fakes::CaptureWorld::default())),
            &Arc::new(Mutex::new(crate::pipeline::fakes::EncoderWorld::default())),
        );
        let (mut capture, modes, _status) =
            crate::pipeline::fakes::session_capture(backends, CaptureMode::Monitor);
        assert!(capture.admits_frames());
        let game = CaptureMode::GameWindow {
            binding: Some(binding()),
        };
        modes.set(game.clone(), "test: on");
        assert!(
            !capture.admits_frames(),
            "the monitor's frames stop at once"
        );
        assert_eq!(capture.take_change(), Some(CaptureMode::Monitor));
        assert!(capture.admits_frames(), "the game's capture is the one now");
        modes.set(
            CaptureMode::GameWindow {
                binding: Some(GameBinding::new(r"C:\Other\Game.exe", "Other")),
            },
            "test: another game",
        );
        assert!(!capture.admits_frames(), "not the old game's either");
        // Back to the same mode before the capture was replaced: its frames pass again.
        modes.set(game, "test: back");
        assert!(capture.admits_frames());
    }

    #[test]
    fn the_gate_passes_the_live_capture_or_black_never_both_and_never_a_stale_capture() {
        let (tx, rx) = mpsc::channel();
        let gate = FrameGate::new(tx);
        let frame = || black_frame((4, 4), 1080);
        assert_eq!(gate.send_black(frame()), GateSend::Sent);
        assert_eq!(
            gate.send_live(1, frame()),
            GateSend::Refused,
            "nothing is live"
        );
        let first = gate.open();
        assert_eq!(
            gate.send_black(frame()),
            GateSend::Refused,
            "a capture is live"
        );
        assert_eq!(gate.send_live(first, frame()), GateSend::Sent);
        let second = gate.open();
        assert_eq!(
            gate.send_live(first, frame()),
            GateSend::Refused,
            "replaced"
        );
        assert_eq!(gate.send_live(second, frame()), GateSend::Sent);
        assert_eq!(gate.live_frames(), 1);
        gate.close();
        assert_eq!(gate.send_live(second, frame()), GateSend::Refused, "closed");
        assert_eq!(rx.try_iter().count(), 3);
        drop(rx);
        assert_eq!(gate.send_black(frame()), GateSend::Closed);
    }

    #[test]
    fn black_frames_are_black_and_scaled_like_any_frame() {
        let f = black_frame(BLACK_SOURCE, 1080);
        assert_eq!((f.width, f.height), (1280, 720));
        assert!(f.data.iter().all(|&b| b == 0));
        assert_eq!(f.data.len(), 1280 * 720 * 4);
        let f = black_frame((3576, 2268), 720);
        assert_eq!((f.width, f.height), (1134, 720));
    }

    /* ── The game capturer's thread, stepped on a test clock ── */

    struct Rig {
        t0: Instant,
        director: Director,
        windows: Windows,
        backend: Arc<Mutex<BackendWorld>>,
        status: Arc<GameStatus>,
        frames: Receiver<Frame>,
        /// The background hold, as the supervisor would set it through `Capturer::hold`.
        held: Arc<AtomicBool>,
    }

    impl Rig {
        fn new(binding: Option<GameBinding>) -> Self {
            let windows: Windows = Arc::new(Mutex::new(Ok(Vec::new())));
            let backend = Arc::new(Mutex::new(BackendWorld::default()));
            let status = Arc::new(GameStatus::new());
            status.set_active(true);
            let (tx, frames) = mpsc::channel();
            let held = Arc::new(AtomicBool::new(false));
            let director = Director::new(
                binding,
                Box::new(ScriptedSource::new(windows.clone())),
                Box::new(ScriptedBackend(backend.clone())),
                Arc::new(FrameGate::new(tx)),
                status.clone(),
                Arc::new(QualityTarget::default()),
                held.clone(),
            );
            Self {
                t0: Instant::now(),
                director,
                windows,
                backend,
                status,
                frames,
                held,
            }
        }

        fn at(&self, ms: u64) -> Instant {
            self.t0 + Duration::from_millis(ms)
        }

        /// Step every 50 ms from `from` to `to`, inclusive.
        fn run(&mut self, from: u64, to: u64) {
            let mut ms = from;
            while ms <= to {
                let now = self.at(ms);
                self.director.step(now);
                ms += 50;
            }
        }

        fn show(&self, windows: Vec<WindowInfo>) {
            *lock(&self.windows) = Ok(windows);
        }

        /// The running capture delivers one frame of `w`x`h`.
        fn deliver(&self, w: u32, h: u32) -> GateSend {
            lock(&self.backend).deliver(w, h)
        }

        /// What reached the encoder since the last call: (black?, width, height) per frame.
        fn received(&self) -> Vec<(bool, u32, u32)> {
            self.frames
                .try_iter()
                .map(|f| (f.data.iter().all(|&b| b == 0), f.width, f.height))
                .collect()
        }
    }

    #[test]
    fn with_no_game_only_black_frames_go_out_twice_a_second() {
        let mut r = Rig::new(Some(binding()));
        r.run(0, 2_000);
        let got = r.received();
        assert!(
            (4..=6).contains(&got.len()),
            "black at once, then every 500 ms: {got:?}"
        );
        assert!(got
            .iter()
            .all(|&(black, w, h)| black && (w, h) == (1280, 720)));
        assert!(lock(&r.backend).started.is_empty());
        assert_eq!(r.status.snapshot().state, GameWindowState::Absent);
    }

    #[test]
    fn a_shown_window_is_captured_and_black_frames_stop() {
        let mut r = Rig::new(Some(binding()));
        r.run(0, 300);
        assert!(r.received().iter().all(|f| f.0));
        r.show(vec![game_window(0x40666, 6888)]);
        r.run(350, 600);
        assert_eq!(lock(&r.backend).started, vec![(0x40666, 1)]);
        assert_eq!(r.deliver(1703, 1080), GateSend::Sent);
        r.run(650, 3_000);
        let got = r.received();
        assert_eq!(
            got,
            vec![(false, 1703, 1080)],
            "only the window's frame, no black"
        );
        assert_eq!(r.status.snapshot().state, GameWindowState::Shown);
        assert_eq!(r.status.snapshot().source, Some((1703, 1080)));
    }

    #[test]
    fn minimize_and_restore_go_black_and_back_on_a_new_capture() {
        let mut r = Rig::new(Some(binding()));
        r.show(vec![game_window(0x40666, 6888)]);
        r.run(0, 100);
        assert_eq!(r.deliver(3576, 2268), GateSend::Sent);
        r.received();

        r.show(vec![WindowInfo {
            minimized: true,
            ..game_window(0x40666, 6888)
        }]);
        r.run(250, 1_300);
        {
            let w = lock(&r.backend);
            assert_eq!(w.stopped, 1, "the capture is stopped while minimized");
            assert!(w.running.is_none());
        }
        let got = r.received();
        assert!(!got.is_empty() && got.iter().all(|f| f.0), "{got:?}");
        // The black frames keep the game picture's shape, scaled to the rung (1080 lines).
        assert!(
            got.iter().all(|&(_, w, h)| (w, h) == (1702, 1080)),
            "{got:?}"
        );
        assert_eq!(r.status.snapshot().state, GameWindowState::Minimized);
        assert_eq!(r.status.geometry(), None);

        r.show(vec![game_window(0x40666, 6888)]);
        r.run(1_350, 1_600);
        assert_eq!(
            lock(&r.backend).started.len(),
            2,
            "a new capture after the restore"
        );
        assert_eq!(r.deliver(3576, 2268), GateSend::Sent);
        r.run(1_650, 2_500);
        assert!(r.received().iter().all(|f| !f.0), "live again: no black");
    }

    /// The background hold: the window capture stops and no black frame goes out, while the finder
    /// keeps the heartbeat's `game` and the input's window current — a minimize, a relaunch, the
    /// window back. Released, the capture of the window as it is now starts at once.
    #[test]
    fn a_hold_stops_the_capture_and_black_frames_and_keeps_watching_the_window() {
        let mut r = Rig::new(Some(binding()));
        r.show(vec![game_window(0x40666, 6888)]);
        r.run(0, 100);
        assert_eq!(r.deliver(3576, 2268), GateSend::Sent);
        r.received();

        r.held.store(true, Ordering::SeqCst);
        r.run(150, 150);
        {
            let w = lock(&r.backend);
            assert_eq!(w.stopped, 1, "the window capture stops at once");
            assert!(w.running.is_none());
        }
        // Minimized during the hold: the state follows, and no black frame goes out.
        r.show(vec![WindowInfo {
            minimized: true,
            ..game_window(0x40666, 6888)
        }]);
        r.run(200, 5_000);
        assert_eq!(r.status.snapshot().state, GameWindowState::Minimized);
        assert!(r.received().is_empty(), "nothing at all while held");
        // Relaunched and shown again during the hold: the new window and its process are known, but
        // nothing is captured and input has no window until it is.
        r.show(vec![game_window(0x50777, 7001)]);
        r.run(5_050, 10_000);
        let snap = r.status.snapshot();
        assert_eq!(snap.state, GameWindowState::Shown);
        assert_eq!(snap.window, Some((0x50777, 7001)));
        assert_eq!(r.status.game_scope().window, None);
        assert_eq!(lock(&r.backend).started.len(), 1, "no capture while held");
        assert!(r.received().is_empty());

        r.held.store(false, Ordering::SeqCst);
        r.run(10_050, 10_050);
        assert_eq!(
            lock(&r.backend).started.last().map(|&(hwnd, _)| hwnd),
            Some(0x50777),
            "the window as it is now, captured on the first step after the release"
        );
        assert_eq!(r.deliver(3576, 2268), GateSend::Sent);
        assert_eq!(r.received(), vec![(false, 3576, 2268)]);

        // Held and released with the window gone: black at once on the release.
        r.held.store(true, Ordering::SeqCst);
        r.show(vec![]);
        r.run(10_100, 12_000);
        assert!(r.received().is_empty());
        assert_eq!(r.status.snapshot().state, GameWindowState::Absent);
        r.held.store(false, Ordering::SeqCst);
        r.run(12_050, 12_050);
        let got = r.received();
        assert_eq!(got.len(), 1, "one black frame at once: {got:?}");
        assert!(got[0].0);
    }

    #[test]
    fn a_relaunch_moves_the_capture_to_the_new_window() {
        let mut r = Rig::new(Some(binding()));
        r.show(vec![game_window(0x40666, 6888)]);
        r.run(0, 100);
        let old = lock(&r.backend).running.clone().expect("running");
        let (old_gate, old_generation) = (old.gate, old.generation);
        r.show(vec![]);
        r.run(250, 600);
        assert_eq!(r.status.snapshot().state, GameWindowState::Absent);
        r.show(vec![game_window(0x90abc, 7777)]);
        r.run(650, 800);
        let started = lock(&r.backend).started.clone();
        assert_eq!(started.last().map(|s| s.0), Some(0x90abc));
        // A late frame of the old capture cannot get through.
        assert_eq!(
            old_gate.send_live(old_generation, black_frame((4, 4), 1080)),
            GateSend::Refused
        );
        // Straight from one window to the next, without an absent poll between.
        r.show(vec![game_window(0xabcde, 8888)]);
        r.run(850, 1_100);
        let w = lock(&r.backend);
        assert_eq!(w.started.last().map(|s| s.0), Some(0xabcde));
        assert_eq!(w.stopped, 2);
    }

    #[test]
    fn a_capture_that_fails_or_ends_goes_black_and_is_tried_again_with_a_pause() {
        let mut r = Rig::new(Some(binding()));
        lock(&r.backend).fail_starts = 1;
        r.show(vec![game_window(0x40666, 6888)]);
        r.run(0, 900);
        assert!(lock(&r.backend).started.is_empty(), "the pause holds");
        assert!(
            r.received().iter().all(|f| f.0),
            "black while it cannot start"
        );
        r.run(950, 1_300);
        assert_eq!(
            lock(&r.backend).started.len(),
            1,
            "tried again after a second"
        );
        r.received();

        // It ends by itself (the item closed): black at once, then a new capture after the pause.
        lock(&r.backend).finished = true;
        r.run(1_350, 1_400);
        let got = r.received();
        assert_eq!(got.first().map(|f| f.0), Some(true), "{got:?}");
        r.run(1_450, 4_000);
        assert_eq!(lock(&r.backend).started.len(), 2);
    }

    #[test]
    fn a_capture_that_delivers_nothing_is_started_again() {
        let mut r = Rig::new(Some(binding()));
        r.show(vec![game_window(0x40666, 6888)]);
        r.run(0, 100);
        r.received();
        let limit = FIRST_FRAME_WITHIN.as_millis() as u64;
        r.run(150, limit + 100);
        assert_eq!(lock(&r.backend).stopped, 1, "given up on after {limit} ms");
        assert!(r.received().iter().all(|f| f.0), "black meanwhile");
        r.run(limit + 150, limit + 1_500);
        assert_eq!(lock(&r.backend).started.len(), 2);
    }

    #[test]
    fn an_unreadable_window_list_or_no_binding_is_black_frames_only() {
        let mut r = Rig::new(None);
        r.show(vec![game_window(0x40666, 6888)]);
        r.run(0, 1_000);
        assert!(
            lock(&r.backend).started.is_empty(),
            "no binding: nothing is captured"
        );
        assert!(r.received().iter().all(|f| f.0));

        let mut r = Rig::new(Some(binding()));
        *lock(&r.windows) = Err("EnumWindows: 0x80004005".into());
        r.run(0, 1_000);
        assert!(lock(&r.backend).started.is_empty());
        assert!(r.received().iter().all(|f| f.0));
    }

    /// The thread itself, on the real clock: it starts, sends black, and stops when asked.
    #[test]
    fn the_game_capturer_runs_on_its_own_thread_and_stops_when_asked() {
        let windows: Windows = Arc::new(Mutex::new(Ok(Vec::new())));
        let backend = Arc::new(Mutex::new(BackendWorld::default()));
        let status = Arc::new(GameStatus::new());
        let mut capturer = GameCapturer::new(
            &GameCaptureRequest {
                binding: Some(binding()),
                status,
            },
            Box::new(ScriptedSource::new(windows)),
            Box::new(ScriptedBackend(backend)),
        );
        let (tx, rx) = mpsc::channel();
        capturer
            .start(tx, Arc::new(QualityTarget::default()))
            .expect("starts");
        let first = rx
            .recv_timeout(Duration::from_secs(2))
            .expect("a black frame at once");
        assert!(first.data.iter().all(|&b| b == 0));
        assert!(capturer.check().is_ok());
        assert!(
            capturer
                .start(mpsc::channel().0, Arc::new(QualityTarget::default()))
                .is_err(),
            "started once"
        );
        capturer.stop();
        assert!(capturer.check().is_err(), "stopped");
    }
}
