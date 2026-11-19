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

/// After a background hold the window capture kept running through, its next frame is the one the
/// viewer resumes on (a keyframe: the pipeline asks for it). A game draws many a second, so one
/// comes at once; none this long after the release is a still window — WGC sends a window's frame
/// only when it changes — and the capture's last frame, retained exactly as it arrived
/// ([`WindowCapture::retained`]), is sent again instead. The capture itself is never stopped or started again for want of a frame:
/// a restart of a window capture that was stopped can fail with `0x800703EE`
/// (`ERROR_FILE_INVALID`) on every later start, after `CreateForWindow` succeeds. Well under the pipeline's own wait for the
/// first frame after a hold ([`crate::pipeline::HOLD_FIRST_FRAME_WITHIN`], a second), and long
/// enough for a game whose rendering Windows throttles while it is in the background (a few frames
/// a second) to send a fresh one first.
pub const RESUME_FIRST_FRAME_WITHIN: Duration = Duration::from_millis(300);

/// The retained frame could not be made after a hold — the frame handler busy with a frame of its
/// own, the GPU still busy with the read-back's copy, a read-back failing: tried again this long
/// after the failed try ended, for the same hold, while it stays due (no new hold, no fresh frame
/// passed, the capture still live). A transient failure must not cost a still window its picture
/// for good; one that cannot pass ([`Retained::Unusable`]) is not tried again.
pub const RESUME_RETRY_EVERY: Duration = Duration::from_millis(100);
/// Tries of the retained frame after one hold, the first included, and no try begun later than
/// [`RESUME_RETRY_FOR`] after the first began: about two seconds in all, each try bounded itself
/// (the handler's wait and the read-back's deadline, `afklink_capture::game`: under a second), so
/// the last one ends within about three.
pub const RESUME_TRIES: u32 = 8;
pub const RESUME_RETRY_FOR: Duration = Duration::from_secs(2);

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
    /// The window's frames that arrived during background holds this session (WGC activity), and
    /// those of them retained — copied as the capture's last frame ([`WindowCapture::retained`]),
    /// a GPU copy on Windows, which can fail where an arrival cannot: what a hold costs while the
    /// window capture runs through it, for the pipeline line ([`Self::held_frames`]).
    held_arrived: AtomicU64,
    held_retained: AtomicU64,
    /// Every GPU copy of a live frame into the retained texture submitted this session, held or
    /// not, and the bytes each writes (the client area's of a sent frame, the whole frame's of any
    /// other): the retention's standing cost, counted rather than claimed — a count of work queued
    /// on the GPU, not GPU time. The pipeline line shows both per second
    /// ([`Self::retain_copies`]).
    retain_copies: AtomicU64,
    retain_bytes: AtomicU64,
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
            held_arrived: AtomicU64::new(0),
            held_retained: AtomicU64::new(0),
            retain_copies: AtomicU64::new(0),
            retain_bytes: AtomicU64::new(0),
        }
    }

    /// One copy of a frame into the retained texture submitted to the GPU, `bytes` to be written
    /// (the frame handler's, for every live frame it retains). Two relaxed counters, no lock.
    pub fn note_retain_copy(&self, bytes: u64) {
        self.retain_copies.fetch_add(1, Ordering::Relaxed);
        self.retain_bytes.fetch_add(bytes, Ordering::Relaxed);
    }

    /// The copies into the retained texture submitted this session and the bytes they write
    /// ([`Self::note_retain_copy`]); the pipeline line shows them per second.
    pub fn retain_copies(&self) -> (u64, u64) {
        (
            self.retain_copies.load(Ordering::Relaxed),
            self.retain_bytes.load(Ordering::Relaxed),
        )
    }

    /// A frame of the window arrived during a background hold (the frame handler's); `retained`
    /// when it was copied as the capture's last frame. Two relaxed counters, no lock.
    pub fn note_held_frame(&self, retained: bool) {
        self.held_arrived.fetch_add(1, Ordering::Relaxed);
        if retained {
            self.held_retained.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// The window's frames that arrived during background holds this session, and those retained
    /// ([`Self::note_held_frame`]); the pipeline line shows them per second.
    pub fn held_frames(&self) -> (u64, u64) {
        (
            self.held_arrived.load(Ordering::Relaxed),
            self.held_retained.load(Ordering::Relaxed),
        )
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
    /// Not this frame's turn: a window frame from a capture that is no longer the live one, any
    /// frame during the background hold ([`FrameGate::hold`]), or a black frame while a capture is
    /// live.
    Refused,
    /// The consumer is gone (the session ended).
    Closed,
}

/// Whether a window capture's frame would pass the gate now ([`FrameGate::admit`]), asked by the
/// frame handler before it spends anything on the frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admit {
    Pass,
    /// The live capture's frame, during the background hold: retained as the capture's last
    /// frame, like every live frame, and otherwise dropped unread (and counted).
    Held,
    /// A capture that is no longer the live one.
    NotLive,
}

/// The one door frames go through to the encoder in game mode: either the live window capture's or
/// black ones, never both, and never a frame of a capture that was stopped or replaced — its frames
/// carry the generation it was started with. During the background hold ([`Self::hold`]) nothing
/// passes at all, and the live capture stays live.
///
/// ## The retained frame is the capture's, not the gate's
///
/// The picture the viewer resumes on after a hold when the window sends no fresh frame (a still
/// window — WGC sends a window's frame only when it changes) is the capture's own last frame,
/// every live frame retained exactly as it arrived ([`WindowCapture::retained`]: on Windows a GPU
/// copy into one texture, read back only for a resend). The gate holds no picture: it checks a
/// resend against the hold's record and passes it in its lock ([`Self::resend`]), and no copy of a
/// frame is ever made under its lock.
///
/// ## The hold's record
///
/// Each hold has an epoch, counted up as it begins, and the gate writes down, in the same lock as
/// the transition itself, what the game capture's thread acts on later: when the hold began and
/// ended, which capture was live then and how many frames it had passed at the release (the
/// baseline its first fresh frame is told by). However late that thread looks ([`Self::hold_view`]),
/// it sees every hold that began, a hold that began and ended between two of its looks included,
/// and a frame that passed after the release is never taken for one from before it. A decision of
/// that thread's that a hold begun since would undo — a resend, giving up on a capture — is checked
/// against the record in the lock that acts on it ([`Self::resend`], [`Self::close_unheld`]).
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
    hold: HoldState,
}

/// The background hold in force or the last one, as [`FrameGate::hold`] recorded it.
#[derive(Default)]
struct HoldState {
    /// No frame passes, live or black.
    held: bool,
    /// Holds begun on this gate (the one in force or the last one is this one).
    epoch: u64,
    since: Option<Instant>,
    /// The capture live when it began, and the frames it had passed by then.
    live_at_hold: Option<u64>,
    frames_at_hold: u64,
    /// The live capture's frames that arrived during it (WGC activity, each retained by the
    /// capture and dropped here), and when the last arrived.
    arrived: u64,
    last_arrival: Option<Instant>,
    released: Option<HoldRelease>,
}

/// The end of a background hold, as the gate recorded it at the release.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HoldRelease {
    pub epoch: u64,
    pub at: Instant,
    /// The capture live at the release, and the frames it had passed by then.
    pub live: Option<u64>,
    pub frames: u64,
}

/// The background hold as the gate has it now ([`FrameGate::hold_view`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HoldView {
    pub held: bool,
    /// The hold in force or the last one; 0 before the first.
    pub epoch: u64,
    pub since: Option<Instant>,
    pub live_at_hold: Option<u64>,
    pub frames_at_hold: u64,
    /// The live capture's frames that arrived during it (dropped here, retained by the capture).
    pub arrived: u64,
    /// How long ago the last of them arrived (`None`: none did — a still window, or no capture).
    pub last_arrival_ago: Option<Duration>,
    /// Its end, once it has ended.
    pub released: Option<HoldRelease>,
}

/// What [`FrameGate::resend`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resend {
    /// The capture's retained frame went out again, at this size.
    Sent { size: (u32, u32) },
    /// Not due any more, and why: a new hold began, the capture is no longer live, or a fresh frame
    /// passed meanwhile.
    Superseded(&'static str),
    /// The consumer is gone (the session ended).
    Closed,
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
                hold: HoldState::default(),
            }),
        }
    }

    /// The background hold, on (`held`) or off, at `now` (the caller's clock, which the game
    /// capture's thread steps on too). Held, no frame passes — neither the live capture's nor a
    /// black one — from the moment this returns, while the live capture stays live (its generation
    /// passes again once the hold is off). Each hold gets the next epoch, and its start and end are
    /// recorded with the live capture and its frame count in this same lock ([`Self`], «The
    /// hold's record»). False when the gate already was so (nothing changed).
    pub fn hold(&self, held: bool, now: Instant) -> bool {
        let mut inner = lock(&self.inner);
        if inner.hold.held == held {
            return false;
        }
        let (live, frames) = (inner.live, inner.live_frames);
        let hold = &mut inner.hold;
        if held {
            *hold = HoldState {
                held: true,
                epoch: hold.epoch + 1,
                since: Some(now),
                live_at_hold: live,
                frames_at_hold: frames,
                ..HoldState::default()
            };
        } else {
            hold.held = false;
            hold.released = Some(HoldRelease {
                epoch: hold.epoch,
                at: now,
                live,
                frames,
            });
        }
        true
    }

    /// The background hold as the gate has it now ([`HoldView`]).
    pub fn hold_view(&self, now: Instant) -> HoldView {
        let inner = lock(&self.inner);
        let h = &inner.hold;
        HoldView {
            held: h.held,
            epoch: h.epoch,
            since: h.since,
            live_at_hold: h.live_at_hold,
            frames_at_hold: h.frames_at_hold,
            arrived: h.arrived,
            last_arrival_ago: h.last_arrival.map(|at| now.saturating_duration_since(at)),
            released: h.released,
        }
    }

    /// Whether the captures behind this gate retain their last frame for a resend after a hold
    /// ([`WindowCapture::retained`]): only behind the agent's own frame channel ([`Self::new`]); a
    /// [`Self::bounded`] consumer is never held. No lock.
    pub fn retains_frames(&self) -> bool {
        self.target_source.is_none()
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

    /// The first-frame watchdog's decision to give up on `generation`, made in the gate's lock
    /// against what is true now: no hold in force and none begun since the thread's last look
    /// (`epoch`), the capture still live, and still nothing of it passed. Then it is closed here,
    /// as [`Self::close`] — the capture itself is stopped by the caller, outside this lock. Err:
    /// why it is not given up on after all.
    pub fn close_unheld(&self, generation: u64, epoch: u64) -> Result<(), &'static str> {
        let mut inner = lock(&self.inner);
        if inner.hold.held || inner.hold.epoch != epoch {
            return Err("a background hold began");
        }
        if inner.live != Some(generation) {
            return Err("the capture is no longer live");
        }
        if inner.live_frames != 0 {
            return Err("a frame of it passed meanwhile");
        }
        inner.live = None;
        Ok(())
    }

    pub fn is_live(&self) -> bool {
        lock(&self.inner).live.is_some()
    }

    /// Whether a frame of `generation` would pass — for the frame handler, before it spends
    /// anything on the frame (pacing included). A live frame refused by the hold is counted here.
    pub fn admit(&self, generation: u64) -> Admit {
        self.admit_at(generation, Instant::now())
    }

    /// [`Self::admit`] at `now`.
    pub fn admit_at(&self, generation: u64, now: Instant) -> Admit {
        let mut inner = lock(&self.inner);
        if inner.live != Some(generation) {
            return Admit::NotLive;
        }
        if !inner.hold.held {
            return Admit::Pass;
        }
        inner.hold.arrived += 1;
        inner.hold.last_arrival = Some(now);
        Admit::Held
    }

    /// Frames the live capture has passed so far (a resend included).
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
        // Admitted before the hold began, and done with after: dropped like the hold's own (the
        // capture retained it when it arrived).
        if inner.hold.held {
            inner.hold.arrived += 1;
            return GateSend::Refused;
        }
        let sent = Self::send(&mut inner, frame, target);
        if sent == GateSend::Sent {
            inner.live_frames += 1;
        }
        sent
    }

    /// Whether a resend after hold `epoch` is still due — the check [`Self::resend`] makes again
    /// when it sends, here before the capture spends a read-back on the frame.
    pub fn resend_due(&self, epoch: u64, generation: u64, frames: u64) -> Result<(), &'static str> {
        Self::due(&lock(&self.inner), epoch, generation, frames)
    }

    fn due(
        inner: &GateInner,
        epoch: u64,
        generation: u64,
        frames: u64,
    ) -> Result<(), &'static str> {
        if inner.hold.held || inner.hold.epoch != epoch {
            return Err("a new background hold began");
        }
        if inner.live != Some(generation) {
            return Err("the capture is no longer live");
        }
        if inner.live_frames != frames {
            return Err("a fresh frame passed meanwhile");
        }
        Ok(())
    }

    /// After hold `epoch` ended with `generation` live at `frames` passed and no fresh frame has
    /// come: send `frame` — the capture's retained frame, read back and made like a live one by
    /// its caller ([`WindowCapture::retained`]) — as the keyframe the viewer resumes on, checked
    /// in the same lock against what is true now: the hold still `epoch` and over, the capture
    /// still live, nothing passed since. The frame is moved, never copied, and one refused is
    /// freed after the lock.
    ///
    /// `on_sent` runs once the frame is sent, still in this lock: where the resent picture is
    /// ([`GameStatus::set_geometry`]) is published there, so it can never land after a newer live
    /// frame's. A live frame passes only in this lock and publishes its own geometry after it, so
    /// one that passes after the resend publishes after it too, and one that passed before makes
    /// the resend not due. `on_sent` must not wait on anything (the status's own short lock and a
    /// notify are all it takes).
    pub fn resend(
        &self,
        epoch: u64,
        generation: u64,
        frames: u64,
        frame: Frame,
        on_sent: impl FnOnce(),
    ) -> Resend {
        let size = (frame.width, frame.height);
        let (done, refused) = {
            let mut inner = lock(&self.inner);
            match Self::due(&inner, epoch, generation, frames) {
                Err(why) => (Resend::Superseded(why), Some(frame)),
                Ok(()) => match Self::send(&mut inner, frame, None) {
                    GateSend::Sent => {
                        inner.live_frames += 1;
                        on_sent();
                        (Resend::Sent { size }, None)
                    }
                    GateSend::Closed => (Resend::Closed, None),
                    GateSend::Refused => (Resend::Superseded("refused"), None),
                },
            }
        };
        drop(refused);
        done
    }

    /// A black frame: only while no capture is live, and never during the hold.
    pub fn send_black(&self, frame: Frame) -> GateSend {
        if self.target_source.is_some() {
            tracing::trace!(target: crate::EMBED_LOG_TARGET, "frame gate with a target source refused a synthetic frame");
            return GateSend::Refused;
        }
        let mut inner = lock(&self.inner);
        if inner.live.is_some() || inner.hold.held {
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
    /// Stop it and collect it; why it ended, when it ended by itself. Its retained frame goes
    /// with it.
    fn stop(self: Box<Self>) -> Option<String>;
    /// Its last frame, made now like a live frame — cropped to the client area and scaled to the
    /// rung — for a resend after a background hold that a still window sent nothing fresh after
    /// (`Director::recover`, on the game capture's thread: once per hold, and a few times more
    /// when it fails — [`RESUME_TRIES`] at most).
    ///
    /// Every frame of the live capture that arrives (passed, paced out, or dropped by the hold)
    /// is retained exactly, as the newest one, by the capture: the gate drops a held frame, but
    /// the capture has kept it, so the picture resumed on is never older than the window's last
    /// update. On Windows that is a GPU copy of each frame into one texture — a sent frame's
    /// client area, any other frame whole; the read-back, crop and scale happen only here
    /// (`afklink_capture::game`), the GPU polled for a bounded time. `now` is the caller's clock,
    /// for the age in the log.
    fn retained(&mut self, now: Instant) -> Retained;
}

/// What [`WindowCapture::retained`] made.
#[derive(Debug)]
pub enum Retained {
    /// The last frame, made like a live one: where the picture is (for the status once it is sent
    /// — [`GameStatus::set_geometry`]), how old the frame is and whether it arrived during a hold.
    Frame {
        frame: Frame,
        geometry: CaptureGeometry,
        age: Duration,
        in_hold: bool,
    },
    /// No frame has arrived since the capture started.
    Nothing,
    /// One is retained but could not be made this time (the handler or the GPU busy, a read-back
    /// failing), and why: a later try may do better.
    Failed(String),
    /// None can be made of what is retained, and why — the window's client area is not inside
    /// the region kept of its last frame, the frame's format is not read back, the capture keeps
    /// no frame at all: no try of this frame can pass, and the resend is given up at once.
    Unusable(String),
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
/// fails — and sends a black frame every [`BLACK_EVERY`] whenever no capture is live. During the
/// background hold nothing goes out, and a capture that is live keeps running ([`Capturer::hold`]
/// below). It never ends by itself: every failure ends in black frames. [`Capturer::check`]
/// reports only the thread itself dying (a panic), which the pipeline supervisor answers with a
/// new game capturer.
pub struct GameCapturer {
    binding: Option<GameBinding>,
    status: Arc<GameStatus>,
    parts: Option<(Box<dyn WindowSource>, Box<dyn WindowCaptureBackend>)>,
    running: Option<(Arc<AtomicBool>, JoinHandle<()>)>,
    /// The gate the thread's frames go through, from [`Capturer::start`] on. The background hold
    /// (`crate::bg_hold`) is set on it in the supervisor's own call ([`Capturer::hold`]), so nothing
    /// passes from the moment `hold(true)` returns; the thread reads the hold's record from it.
    gate: Option<Arc<FrameGate>>,
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
            gate: None,
        }
    }
}

/// The background hold as [`Capturer::hold`] sets it: on the gate, synchronously — no frame passes
/// once a hold is on, and frames pass again at once once it is off; the gate records the
/// transition for the capturer's thread, which acts on the rest at its next step. A repeated hold
/// or a release with no hold changes nothing, and is said.
fn set_hold(gate: &FrameGate, held: bool, now: Instant) {
    if !gate.hold(held, now) {
        tracing::debug!(
            held,
            "game capture: {}",
            if held {
                "hold asked while already held; nothing changes"
            } else {
                "release asked with no hold in force; nothing changes"
            }
        );
    }
}

impl Capturer for GameCapturer {
    fn start(&mut self, sink: Sender<Frame>, target: Arc<QualityTarget>) -> anyhow::Result<()> {
        let (source, backend) = self
            .parts
            .take()
            .ok_or_else(|| anyhow::anyhow!("a game capturer is started once"))?;
        let stop = Arc::new(AtomicBool::new(false));
        let gate = Arc::new(FrameGate::new(sink));
        self.gate = Some(gate.clone());
        let director = Director::new(
            self.binding.clone(),
            source,
            backend,
            gate,
            self.status.clone(),
            target,
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

    /// The background hold: nothing goes out — no window frame, no black frame — from the moment
    /// this returns. A window capture that is live keeps running through the hold and its frames
    /// are dropped as they arrive (each retained by the capture as its last frame, a GPU copy, and
    /// nothing more spent on it): a restart of a window capture that was stopped can
    /// fail with `0x800703EE` (`ERROR_FILE_INVALID`) on every later start. The
    /// thread goes on watching the game's window — its state, its process, where its client area
    /// is — which the heartbeat's `game` and the input's scope read through the hold, and still
    /// stops the capture when the window goes away or changes. Released, frames pass again at
    /// once: the kept capture's next frame — or, a still window sending none, the capture's
    /// retained last frame ([`WindowCapture::retained`]) — or, with none live, a capture started
    /// at once (or a black frame). False when its thread is not running (never started, or ended):
    /// the supervisor then replaces it as it replaces any capturer that cannot hold. Never blocks:
    /// one short lock of the gate, which nothing holds across a wait.
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
        let Some(gate) = &self.gate else {
            // Not reached: the thread runs only after `start` set the gate.
            tracing::debug!(held, "game capture: hold refused: no frame gate");
            return false;
        };
        set_hold(gate, held, Instant::now());
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
    /// Since when its first frame is waited for ([`FIRST_FRAME_WITHIN`]): its start, and the end
    /// of a hold it ran through — the wait never counts a hold.
    first_frame_from: Instant,
}

/// A background hold the thread is acting on: its epoch on the gate, and when it began.
struct Holding {
    epoch: u64,
    since: Instant,
}

/// A hold over with its window capture kept: waiting for that capture's next frame, and for
/// [`RESUME_FIRST_FRAME_WITHIN`] at most before the retained frame is sent again.
struct Resuming {
    /// The hold it follows, as the gate counts them: the recovery is due only while that one is
    /// the last hold and over ([`FrameGate::resend`]).
    epoch: u64,
    /// The release, as the gate recorded it.
    since: Instant,
    generation: u64,
    /// The capture's frames passed at the release, so the first one after it is told.
    frames_before: u64,
    held_ms: u64,
    /// Tries of the retained frame so far ([`Director::recover`]), when the first began, and when
    /// the next is due after one failed ([`RESUME_RETRY_EVERY`]).
    tries: u32,
    first_try: Option<Instant>,
    next_try: Option<Instant>,
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
    /// The last hold epoch this thread has acted on ([`FrameGate::hold_view`]).
    seen_epoch: u64,
    /// The background hold as this thread acts on it: while held, no capture is started and no
    /// black frame goes out; a capture live when it began keeps running (the gate drops its frames,
    /// the capture retains the newest), and the finder goes on.
    holding: Option<Holding>,
    resuming: Option<Resuming>,
    /// The time now, read when a try of the retained frame ends ([`Self::recover`]), which can
    /// take well over the step's own time: `Instant::now`, or the test's clock.
    clock: Box<dyn Fn() -> Instant + Send>,
}

impl Director {
    fn new(
        binding: Option<GameBinding>,
        source: Box<dyn WindowSource>,
        backend: Box<dyn WindowCaptureBackend>,
        gate: Arc<FrameGate>,
        status: Arc<GameStatus>,
        target: Arc<QualityTarget>,
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
            seen_epoch: 0,
            holding: None,
            resuming: None,
            clock: Box::new(Instant::now),
        }
    }

    /// Act on what the background hold did since the last step. The gate itself was held or
    /// released in the supervisor's own call ([`set_hold`]) and recorded each transition with
    /// its epoch, time and frame count ([`FrameGate`], «The hold's record»); this is the thread's
    /// part, read from that record — so a hold that began and ended between two steps is acted on
    /// all the same, and the baseline of the first fresh frame is the gate's, taken at the release.
    ///
    /// Held: a window capture that is live keeps running — the gate drops its frames as they
    /// arrive, the capture retaining each as its last frame — and black frames stop; the finder
    /// goes on, so the window's state, its process and its client area stay current for the
    /// heartbeat and for input, and a window that goes away or changes still stops the capture
    /// (none is started until the release). Released: with the capture kept, its next frame is the
    /// viewer's, or the retained frame once [`RESUME_FIRST_FRAME_WITHIN`] passes without one
    /// ([`Self::watch`]); without, the next step polls at once and starts the window capture with
    /// no pause (or sends a black frame at once when the window cannot be shown).
    fn follow_hold(&mut self, now: Instant) {
        let view = self.gate.hold_view(now);
        if view.epoch != self.seen_epoch {
            let missed = view.epoch.saturating_sub(self.seen_epoch).saturating_sub(1);
            if let Some(old) = self.holding.take() {
                // Its release and the next hold's start both came between two steps: the newer
                // hold is the one in force, and nothing of the older one is due any more.
                tracing::debug!(
                    epoch = old.epoch,
                    next_epoch = view.epoch,
                    held_ms = now.saturating_duration_since(old.since).as_millis() as u64,
                    "game capture: background hold over and the next one already begun, both \
                     between two steps; acting on the newer one"
                );
            }
            self.seen_epoch = view.epoch;
            self.begin_hold(now, &view, missed);
        }
        if self.holding.is_some() && !view.held {
            self.end_hold(now, &view);
        }
    }

    /// A hold began (the gate's record in `view`); `missed` holds began and ended before it
    /// unseen (only their count is known).
    fn begin_hold(&mut self, now: Instant, view: &HoldView, missed: u64) {
        let since = view.since.unwrap_or(now);
        self.holding = Some(Holding {
            epoch: view.epoch,
            since,
        });
        if let Some(resuming) = self.resuming.take() {
            tracing::debug!(
                epoch = resuming.epoch,
                waited_ms = since.saturating_duration_since(resuming.since).as_millis() as u64,
                "game capture: a new background hold began before the first frame after the last \
                 one; that one's recovery is cancelled"
            );
        }
        if let Some((black_since, why, frames)) = self.black.take() {
            tracing::debug!(
                black_frames = frames,
                black_ms = now.saturating_duration_since(black_since).as_millis() as u64,
                began_with = %why,
                "game capture: black frames stop for the background hold"
            );
        }
        self.next_black = None;
        let state = self.finder.state().map_or("-", GameWindowState::as_str);
        let seen_after_ms = now.saturating_duration_since(since).as_millis() as u64;
        match &self.live {
            Some(live) => tracing::debug!(
                epoch = view.epoch,
                missed,
                seen_after_ms,
                hwnd = %format!("{:#x}", live.hwnd),
                generation = live.generation,
                live_at_hold = ?view.live_at_hold,
                frames = view.frames_at_hold,
                ran_ms = since.saturating_duration_since(live.started).as_millis() as u64,
                state,
                kept = true,
                "game capture: background hold — the window capture keeps running; its frames \
                 are dropped as they arrive, the newest retained by the capture as the picture \
                 to resume on; no frame and no black frame goes out; the finder keeps watching \
                 the game's window"
            ),
            None => tracing::debug!(
                epoch = view.epoch,
                missed,
                seen_after_ms,
                state,
                kept = false,
                poll_ms = FINDER_POLL.as_millis() as u64,
                "game capture: background hold — no window capture is live, none is started and \
                 no black frame goes out until it ends; the finder keeps watching the game's window"
            ),
        }
    }

    /// The hold this thread acts on is over (the gate's record in `view`).
    fn end_hold(&mut self, now: Instant, view: &HoldView) {
        let Some(hold) = self.holding.take() else {
            return;
        };
        let release = view
            .released
            .filter(|r| r.epoch == hold.epoch)
            .unwrap_or_else(|| {
                // Not reached: a gate not held has recorded the release of its last hold.
                tracing::debug!(
                    epoch = hold.epoch,
                    "game capture: the hold is over but its release is not recorded; taken as now"
                );
                HoldRelease {
                    epoch: hold.epoch,
                    at: now,
                    live: self.live.as_ref().map(|l| l.generation),
                    frames: self.gate.live_frames(),
                }
            });
        let held_ms = release.at.saturating_duration_since(hold.since).as_millis() as u64;
        let seen_after_ms = now.saturating_duration_since(release.at).as_millis() as u64;
        let state = self.finder.state().map_or("-", GameWindowState::as_str);
        let last_arrival_ago_ms = view
            .last_arrival_ago
            .map_or_else(|| "-".to_string(), |d| d.as_millis().to_string());
        match self.live.as_mut() {
            Some(live) if release.live == Some(live.generation) => {
                // A capture that has passed nothing yet waits for its first frame from here: the
                // hold's time is not its.
                live.first_frame_from = live.first_frame_from.max(release.at);
                self.resuming = Some(Resuming {
                    epoch: hold.epoch,
                    since: release.at,
                    generation: live.generation,
                    frames_before: release.frames,
                    held_ms,
                    tries: 0,
                    first_try: None,
                    next_try: None,
                });
                tracing::debug!(
                    epoch = hold.epoch,
                    held_ms,
                    seen_after_ms,
                    arrived = view.arrived,
                    last_arrival_ago_ms = %last_arrival_ago_ms,
                    hwnd = %format!("{:#x}", live.hwnd),
                    generation = live.generation,
                    frames = release.frames,
                    state,
                    kept = true,
                    resume_within_ms = RESUME_FIRST_FRAME_WITHIN.as_millis() as u64,
                    "game capture: background hold over — the window capture kept running \
                     through it; its next frame goes out at once, or its retained last frame if \
                     none comes in time"
                );
            }
            _ => {
                // No pause either way: a hold is not a failure, and the pause before the next try
                // after one has run out in most holds anyway.
                self.next_poll = None;
                let pause_cut_ms = self
                    .retry_at
                    .take()
                    .map(|at| at.saturating_duration_since(now).as_millis() as u64);
                tracing::debug!(
                    epoch = hold.epoch,
                    held_ms,
                    seen_after_ms,
                    arrived = view.arrived,
                    state,
                    kept = false,
                    live_at_hold = ?view.live_at_hold,
                    live_at_release = ?release.live,
                    retry_pause_cut_ms = ?pause_cut_ms,
                    "game capture: background hold over — no window capture is live (none was, \
                     or it stopped during the hold); capturing again at once"
                );
            }
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
        if let Some(resuming) = &self.resuming {
            wake = wake.min(
                resuming
                    .next_try
                    .unwrap_or(resuming.since + RESUME_FIRST_FRAME_WITHIN),
            );
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
                if let Some(live) = &self.live {
                    // Held or not: a capture kept through a hold runs on, its frames dropped.
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
                if self.holding.is_some() {
                    // Held: no capture is started, but where the window is stays current for input
                    // (only for the window last captured; a new one has no geometry until it is).
                    tracing::trace!(
                        "game capture: held; the window is captured once the hold ends"
                    );
                    self.refresh_geometry(window.hwnd);
                    return;
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
                    first_frame_from: now,
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
        if self.resuming.take().is_some() {
            tracing::debug!(
                "game capture: the capture kept through the hold stops before its first frame \
                 after it"
            );
        }
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

    /// The live capture: did it end by itself, and has it delivered? During a hold only the
    /// first: its frames are dropped, so none passing says nothing. Right after a hold it kept
    /// running through, whether its next frame came ([`RESUME_FIRST_FRAME_WITHIN`]) — and if none
    /// did, its retained last frame is sent again ([`Self::recover`]). A capture that is live and
    /// has not ended is never stopped for want of a fresh frame after a hold; only one with no
    /// usable frame at all — none passed, a resent one included — for [`FIRST_FRAME_WITHIN`]
    /// since it started, holds not counted, is: frames that merely arrived (WGC activity) and
    /// could not be made into a picture do not count. That decision is made in the gate's lock
    /// against the hold ([`FrameGate::close_unheld`]): a hold that began since this step's look at
    /// it keeps the capture.
    fn watch(&mut self, now: Instant) {
        let Some(live) = self.live.as_mut() else {
            return;
        };
        let frames = self.gate.live_frames();
        let ran = now.saturating_duration_since(live.started);
        if live.capture.finished() {
            let hwnd = live.hwnd;
            self.gate.close();
            let resuming = self.resuming.take().is_some();
            let reason = self
                .live
                .take()
                .and_then(|l| l.capture.stop())
                .unwrap_or_else(|| "no reason given".to_string());
            let held = self.holding.is_some();
            tracing::warn!(
                hwnd = %format!("{hwnd:#x}"),
                frames,
                ran_ms = ran.as_millis() as u64,
                retry_in_ms = self.retry_gap.as_millis() as u64,
                held,
                resuming,
                "game capture: the window capture ended by itself ({reason}); {}",
                if held {
                    "nothing goes out during the background hold; captured again once it ends"
                } else {
                    "black frames until it is back"
                }
            );
            self.schedule_retry(now);
            if !held {
                self.go_black(now, "the window capture ended");
            }
        } else if self.holding.is_some() {
            tracing::trace!("game capture: held; the capture's delivery is not judged");
        } else if let Some(resuming) = &self.resuming {
            let waited = now.saturating_duration_since(resuming.since);
            if resuming.generation != live.generation {
                // Not reached: a capture stopped or replaced ends the wait (`stop_live`).
                tracing::debug!(
                    "game capture: the capture after the hold is another one; its wait is dropped"
                );
                self.resuming = None;
            } else if frames > resuming.frames_before {
                tracing::debug!(
                    epoch = resuming.epoch,
                    first_frame_ms = waited.as_millis() as u64,
                    held_ms = resuming.held_ms,
                    hwnd = %format!("{:#x}", live.hwnd),
                    generation = live.generation,
                    "game capture: the first frame after the background hold went out (the capture \
                     kept through it)"
                );
                self.resuming = None;
            } else if waited >= RESUME_FIRST_FRAME_WITHIN
                && resuming.next_try.is_none_or(|at| now >= at)
            {
                self.recover(now);
            }
        } else if frames == 0
            && now.saturating_duration_since(live.first_frame_from) >= FIRST_FRAME_WITHIN
        {
            let (hwnd, generation) = (live.hwnd, live.generation);
            let waited_ms = now
                .saturating_duration_since(live.first_frame_from)
                .as_millis() as u64;
            // Closed in the gate's lock only while no hold has begun since `follow_hold` looked
            // and nothing passed meanwhile; the capture is stopped after, outside it.
            match self.gate.close_unheld(generation, self.seen_epoch) {
                Ok(()) => {
                    tracing::warn!(
                        hwnd = %format!("{hwnd:#x}"),
                        generation,
                        waited_ms,
                        ran_ms = ran.as_millis() as u64,
                        retry_in_ms = self.retry_gap.as_millis() as u64,
                        "game capture: no usable frame of the window since its capture started, \
                         holds not counted (every frame refused, none delivered, or a retained \
                         one that could not be made); starting it again"
                    );
                    self.stop_live(now, "no frame since it started");
                    self.schedule_retry(now);
                    self.go_black(now, "the window capture delivered nothing");
                }
                Err(why) => tracing::debug!(
                    hwnd = %format!("{hwnd:#x}"),
                    generation,
                    waited_ms,
                    epoch = self.seen_epoch,
                    why,
                    "game capture: the first-frame watchdog keeps the capture after all"
                ),
            }
        } else if frames > 0 && ran >= RETRY_RESET_AFTER && self.retry_gap != RETRY_MIN {
            tracing::debug!(
                "game capture: the window capture has run well; the pause after a failure is reset"
            );
            self.retry_gap = RETRY_MIN;
        }
    }

    /// No fresh frame of the capture kept through the hold within [`RESUME_FIRST_FRAME_WITHIN`]
    /// of the release: a still window. The capture's retained last frame goes out again — the
    /// keyframe the pipeline asked for at the release. Asked of the gate first (a hold begun since,
    /// another capture or a fresh frame cancels it), then made by the capture on this thread
    /// ([`WindowCapture::retained`]: on Windows a read-back of one GPU texture, no gate lock held),
    /// then sent in the gate's lock after the same check again ([`FrameGate::resend`]), where
    /// the picture's place is published too. The capture is not touched either way.
    ///
    /// A retained frame that could not be made (the handler busy, the GPU busy, a read-back
    /// failing) is tried again [`RESUME_RETRY_EVERY`] after that try ended — a try can hold this
    /// thread most of a second — for the same hold: [`RESUME_TRIES`] tries at most, none begun
    /// past [`RESUME_RETRY_FOR`] after the first began, checked when the next is scheduled and
    /// again as it begins (a late step). While it stays due: a new hold ([`Self::begin_hold`]), a
    /// fresh frame ([`Self::watch`]), the capture ending or stopping, or the gate's own check ends
    /// the wait. One that cannot be made at all ([`Retained::Unusable`]) is given up at once.
    fn recover(&mut self, now: Instant) {
        if self.resuming.is_none() {
            return;
        }
        // The time this try would begin, read now: the step's `now` is stale by whatever the step
        // did before (the finder's poll, the window's geometry).
        let started = (self.clock)().max(now);
        let Some(resuming) = self.resuming.as_mut() else {
            return;
        };
        if let Some(first_try) = resuming.first_try {
            let late = started.saturating_duration_since(first_try);
            if late > RESUME_RETRY_FOR {
                tracing::warn!(
                    epoch = resuming.epoch,
                    tries = resuming.tries,
                    since_first_ms = late.as_millis() as u64,
                    budget_ms = RESUME_RETRY_FOR.as_millis() as u64,
                    due_late_ms = resuming
                        .next_try
                        .map(|at| started.saturating_duration_since(at).as_millis() as u64),
                    step_lag_ms = started.saturating_duration_since(now).as_millis() as u64,
                    "game capture: the retry of the retained frame after the background hold \
                     came due past its budget (this thread was late); not begun, the resend is \
                     given up and the capture is kept as it is (its next frame goes out)"
                );
                self.resuming = None;
                return;
            }
        }
        resuming.tries += 1;
        resuming.next_try = None;
        let first_try = *resuming.first_try.get_or_insert(started);
        let (epoch, frames, held_ms, tries) = (
            resuming.epoch,
            resuming.frames_before,
            resuming.held_ms,
            resuming.tries,
        );
        let waited_ms = now.saturating_duration_since(resuming.since).as_millis() as u64;
        let Some(live) = self.live.as_mut() else {
            // Not reached: `watch` recovers only a live capture.
            self.resuming = None;
            return;
        };
        let (hwnd, generation) = (live.hwnd, live.generation);
        if let Err(why) = self.gate.resend_due(epoch, generation, frames) {
            tracing::debug!(
                epoch,
                waited_ms,
                tries,
                why,
                "game capture: the retained frame is not sent again after the background hold"
            );
            self.resuming = None;
            return;
        }
        let making = (self.clock)().max(started);
        let retained = live.capture.retained(now);
        // When the try ended: the next is counted from here, not from the step's `now` — the try
        // itself can take most of a second (the handler's wait, then the GPU's).
        let done = (self.clock)().max(making);
        let made_us = done.saturating_duration_since(making).as_micros() as u64;
        let failed = match retained {
            Retained::Frame {
                frame,
                geometry,
                age,
                in_hold,
            } => {
                self.resuming = None;
                let status = &self.status;
                // Where the picture is, as a passed frame says it — in the gate's lock that sends
                // it, so a newer live frame's place is never overwritten by this older one's.
                match self.gate.resend(epoch, generation, frames, frame, || {
                    status.set_geometry(geometry);
                }) {
                    Resend::Sent { size } => tracing::debug!(
                        epoch,
                        waited_ms,
                        held_ms,
                        tries,
                        hwnd = %format!("{hwnd:#x}"),
                        generation,
                        retained_age_ms = age.as_millis() as u64,
                        arrived = if in_hold { "during the hold" } else { "before the hold" },
                        size = %format!("{}x{}", size.0, size.1),
                        source = %format!("{}x{}", geometry.source.0, geometry.source.1),
                        made_us,
                        "game capture: no fresh frame after the background hold (a still window: \
                         WGC sends only changes); the capture's last frame went out again as the \
                         picture to resume on; the capture is kept as it is"
                    ),
                    Resend::Superseded(why) => tracing::debug!(
                        epoch,
                        waited_ms,
                        tries,
                        why,
                        made_us,
                        "game capture: the retained frame is not sent again after the background \
                         hold (decided after it was made)"
                    ),
                    Resend::Closed => {
                        tracing::debug!("game capture: the frame consumer is gone; stopping");
                        self.consumer_gone = true;
                    }
                }
                return;
            }
            Retained::Nothing => {
                self.resuming = None;
                tracing::debug!(
                    epoch,
                    waited_ms,
                    tries,
                    hwnd = %format!("{hwnd:#x}"),
                    generation,
                    "game capture: no fresh frame after the background hold and nothing retained \
                     (no frame of this capture has arrived since it started); the capture is kept \
                     as it is, its first frame goes out, and the first-frame watchdog counts from \
                     the release"
                );
                return;
            }
            Retained::Unusable(why) => {
                self.resuming = None;
                tracing::warn!(
                    epoch,
                    waited_ms,
                    tries,
                    hwnd = %format!("{hwnd:#x}"),
                    generation,
                    made_us,
                    "game capture: no fresh frame after the background hold, and no picture can \
                     be made of the retained last frame: {why}; not tried again (no try of this \
                     frame can pass); the capture is kept as it is and its next frame goes out"
                );
                return;
            }
            Retained::Failed(why) => why,
        };
        let next = done + RESUME_RETRY_EVERY;
        let again =
            tries < RESUME_TRIES && next.saturating_duration_since(first_try) <= RESUME_RETRY_FOR;
        if again {
            if let Some(resuming) = self.resuming.as_mut() {
                resuming.next_try = Some(next);
            }
            tracing::debug!(
                epoch,
                waited_ms,
                tries,
                max_tries = RESUME_TRIES,
                retry_in_ms = RESUME_RETRY_EVERY.as_millis() as u64,
                hwnd = %format!("{hwnd:#x}"),
                generation,
                made_us,
                "game capture: no fresh frame after the background hold, and the retained last \
                 frame could not be made this time: {failed}; trying again for the same hold \
                 (a fresh frame, a new hold or the capture ending cancels it)"
            );
        } else {
            self.resuming = None;
            tracing::warn!(
                epoch,
                waited_ms,
                tries,
                tried_ms = done.saturating_duration_since(first_try).as_millis() as u64,
                ended_by = if tries >= RESUME_TRIES {
                    "the tries"
                } else {
                    "the time budget (the next try would begin past it)"
                },
                hwnd = %format!("{hwnd:#x}"),
                generation,
                made_us,
                "game capture: no fresh frame after the background hold, and the retained last \
                 frame could not be made after every try: {failed}; the capture is kept as it is \
                 and its next frame goes out (the first-frame watchdog counts from the release \
                 if none has passed)"
            );
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
                tracing::trace!(
                    "game capture: black frame refused: a capture is live, or the hold is on"
                );
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
        /// Every start after a capture was stopped fails, for good — as a window capture can
        /// (`0x800703EE` on every start after a stop).
        pub(crate) reject_after_stop: bool,
        /// The running capture's last frame as it arrived — its size, when, and whether during a
        /// hold — retained the way the WGC handler retains every live frame (a GPU copy there).
        pub(crate) retained: Option<(u32, u32, Instant, bool)>,
        /// The retained frame cannot be made this many times more (a read-back or crop failing
        /// on Windows, the handler busy); `u32::MAX`: never again.
        pub(crate) retained_fails: u32,
        /// Tries to make the retained frame, failed ones included.
        pub(crate) retained_tries: u32,
        /// No picture can ever be made of the retained frame ([`Retained::Unusable`]: on Windows
        /// a crop not inside the region kept of the last frame).
        pub(crate) retained_unusable: bool,
        /// How long each try takes on the test's clock (on Windows the handler's wait and the
        /// GPU's can add up to most of a second).
        pub(crate) retained_takes: Duration,
        /// Each try's start and end, on the test's clock.
        pub(crate) retained_log: Vec<(Instant, Instant)>,
        /// The test's clock as the director reads it: the step's time, moved on by every try's
        /// [`Self::retained_takes`] and by [`Self::step_work`].
        pub(crate) clock: Option<Instant>,
        /// What the step spends before its recovery reads the clock (the finder's poll, the
        /// window's geometry): added once, at the director's next reading of the clock.
        pub(crate) step_work: Option<Duration>,
    }

    impl BackendWorld {
        /// The running capture delivers one frame of the game's picture at `w`x`h`, the way the
        /// frame handler does: asked of the gate first and retained as the capture's last frame
        /// (during a hold then dropped unread), the picture's size to the rung, the frame through
        /// the gate, then where the picture is.
        pub(crate) fn deliver(&mut self, w: u32, h: u32) -> GateSend {
            self.deliver_at(w, h, Instant::now())
        }

        /// [`Self::deliver`] at `now`, on the test's clock.
        pub(crate) fn deliver_at(&mut self, w: u32, h: u32, now: Instant) -> GateSend {
            match self.arrive_at(w, h, now) {
                Some(admitted) => self.finish(admitted),
                None => GateSend::Refused,
            }
        }

        /// The first half of a delivery, for a test that interleaves the supervisor in the middle
        /// of the frame handler's work: the frame arrives, is asked of the gate and retained (every
        /// live frame, passed or held, as the handler does before any other work). `Some` — its
        /// size — when it is to be made and sent ([`Self::finish`]); `None` when it is dropped
        /// here (held, or of a capture that is not live).
        pub(crate) fn arrive_at(&mut self, w: u32, h: u32, now: Instant) -> Option<(u32, u32)> {
            let run = self.running.clone()?;
            let admit = run.gate.admit_at(run.generation, now);
            if admit == Admit::NotLive {
                return None;
            }
            let held = admit == Admit::Held;
            self.retained = Some((w, h, now, held));
            if held {
                run.status.note_held_frame(true);
                return None;
            }
            Some((w, h))
        }

        /// The second half: the frame, made, through the gate (which refuses it if a hold began
        /// meanwhile), and where the picture is once it passed.
        pub(crate) fn finish(&self, (w, h): (u32, u32)) -> GateSend {
            let Some(run) = self.running.clone() else {
                return GateSend::Refused;
            };
            run.target.set_source(w, h);
            let sent = run.gate.send_live(run.generation, picture(w, h));
            if sent == GateSend::Sent {
                run.status.set_geometry(placed(run.hwnd, w, h));
            }
            sent
        }
    }

    /// A frame of the game's picture as the scripted capture makes it.
    fn picture(w: u32, h: u32) -> Frame {
        Frame {
            data: vec![7; w as usize * h as usize * 4],
            width: w,
            height: h,
            timestamp_ms: 0,
        }
    }

    fn placed(hwnd: usize, w: u32, h: u32) -> CaptureGeometry {
        CaptureGeometry {
            hwnd,
            client: ScreenRect {
                left: 0,
                top: 0,
                right: w as i32,
                bottom: h as i32,
            },
            source: (w, h),
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
            if w.reject_after_stop && w.stopped > 0 {
                anyhow::bail!(
                    "Graphics capture error: Windows API error: The operation identifier is not \
                     valid. (0x800703EE)"
                );
            }
            w.started.push((ctx.hwnd, ctx.generation));
            w.retained = None;
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
            w.retained = None;
            w.finished.then(|| "the capture item closed".to_string())
        }
        fn retained(&mut self, now: Instant) -> Retained {
            let mut w = lock(&self.0);
            w.retained_tries += 1;
            let start = w.clock.unwrap_or(now).max(now);
            let end = start + w.retained_takes;
            w.clock = Some(end);
            w.retained_log.push((start, end));
            let (Some(run), Some((fw, fh, at, in_hold))) = (w.running.clone(), w.retained) else {
                return Retained::Nothing;
            };
            if w.retained_unusable {
                return Retained::Unusable(
                    "the crop is not inside the retained region of the frame".into(),
                );
            }
            if w.retained_fails > 0 {
                if w.retained_fails != u32::MAX {
                    w.retained_fails -= 1;
                }
                return Retained::Failed("the frame handler stayed busy past 500 ms".into());
            }
            run.target.set_source(fw, fh);
            Retained::Frame {
                frame: picture(fw, fh),
                geometry: placed(run.hwnd, fw, fh),
                age: now.saturating_duration_since(at),
                in_hold,
            }
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
    fn a_held_gate_passes_nothing_and_keeps_the_capture_live() {
        let (tx, rx) = mpsc::channel();
        let gate = FrameGate::new(tx);
        assert!(gate.retains_frames());
        let t0 = Instant::now();
        let at = |ms: u64| t0 + Duration::from_millis(ms);
        let frame = |w: u32| black_frame((w, w), 1080);
        let live = gate.open();
        assert_eq!(gate.admit_at(live, at(0)), Admit::Pass);
        assert!(gate.hold(true, at(10)));
        assert!(!gate.hold(true, at(20)), "already held");
        // Every live frame of the hold is held (the capture retains it), however many.
        for ms in [30, 500, 1_029, 1_030] {
            assert_eq!(gate.admit_at(live, at(ms)), Admit::Held);
        }
        assert_eq!(
            gate.admit_at(live + 1, at(1_040)),
            Admit::NotLive,
            "not counted: not live"
        );
        assert_eq!(gate.send_live(live, frame(4)), GateSend::Refused);
        let view = gate.hold_view(at(1_100));
        assert!(view.held);
        assert_eq!((view.epoch, view.since), (1, Some(at(10))));
        assert_eq!(view.arrived, 5, "the late send counted too");
        assert_eq!(view.last_arrival_ago, Some(Duration::from_millis(70)));
        assert_eq!(view.live_at_hold, Some(live));
        gate.close();
        assert_eq!(
            gate.send_black(frame(4)),
            GateSend::Refused,
            "no black frame while held"
        );
        let live = gate.open();
        assert!(gate.hold(false, at(2_000)));
        assert!(!gate.hold(false, at(2_010)), "no hold to release");
        assert_eq!(
            gate.hold_view(at(2_000)).released,
            Some(HoldRelease {
                epoch: 1,
                at: at(2_000),
                live: Some(live),
                frames: 0,
            })
        );
        assert_eq!(gate.admit_at(live, at(2_020)), Admit::Pass);
        assert_eq!(gate.send_live(live, frame(4)), GateSend::Sent);
        assert!(gate.hold(true, at(3_000)));
        let view = gate.hold_view(at(3_000));
        assert_eq!((view.epoch, view.arrived), (2, 0), "counted per hold");
        assert_eq!(view.released, None);
        assert_eq!(view.frames_at_hold, 1);
        assert_eq!(rx.try_iter().count(), 1);
        // A bounded consumer's captures retain nothing: it is never held.
        let bounded = FrameGate::bounded(
            Arc::new(LatestFrame::new(true)),
            Arc::new(|| Some(Arc::new(QualityTarget::default()))),
        );
        assert!(!bounded.retains_frames());
    }

    /// A resend after a hold — the capture's retained frame, made by its caller — passes only for
    /// the hold it was asked for, while nothing fresher passed, and only for the live capture; the
    /// gate itself holds no picture, so a closed or shut gate has none to send.
    #[test]
    fn a_resend_passes_only_while_it_is_due() {
        let (tx, rx) = mpsc::channel();
        let gate = FrameGate::new(tx);
        let t0 = Instant::now();
        let at = |ms: u64| t0 + Duration::from_millis(ms);
        let sized = |w: u32| Frame {
            data: vec![9; w as usize * 4 * 4],
            width: w,
            height: 4,
            timestamp_ms: 0,
        };
        let live = gate.open();
        for w in [10, 12, 14] {
            assert_eq!(gate.send_live(live, sized(w)), GateSend::Sent);
        }
        assert_eq!(rx.try_iter().count(), 3);

        assert!(gate.hold(true, at(1_000)));
        assert_eq!(
            gate.resend_due(1, live, 3),
            Err("a new background hold began"),
            "not while held"
        );
        assert_eq!(
            gate.resend(1, live, 3, sized(14), || {}),
            Resend::Superseded("a new background hold began")
        );
        assert!(gate.hold(false, at(2_000)));
        assert_eq!(
            gate.resend(0, live, 3, sized(14), || {}),
            Resend::Superseded("a new background hold began"),
            "an older hold's recovery"
        );
        assert_eq!(
            gate.resend(1, live + 1, 3, sized(14), || {}),
            Resend::Superseded("the capture is no longer live")
        );
        assert_eq!(
            gate.resend(1, live, 2, sized(14), || {}),
            Resend::Superseded("a fresh frame passed meanwhile")
        );
        assert_eq!(rx.try_iter().count(), 0, "nothing of those went out");
        assert_eq!(gate.resend_due(1, live, 3), Ok(()));
        assert_eq!(
            gate.resend(1, live, 3, sized(14), || {}),
            Resend::Sent { size: (14, 4) }
        );
        let again: Vec<Frame> = rx.try_iter().collect();
        assert_eq!(again.len(), 1);
        assert_eq!(again[0].width, 14);
        assert_eq!(gate.live_frames(), 4, "counted as passed");
        assert_eq!(
            gate.resend(1, live, 3, sized(14), || {}),
            Resend::Superseded("a fresh frame passed meanwhile"),
            "once per hold: the resend itself is the frame after the release"
        );

        // Closed, then shut: no capture is live, so nothing is due — the picture was the closed
        // capture's, and it went with it.
        gate.close();
        assert_eq!(
            gate.resend(1, live, 4, sized(14), || {}),
            Resend::Superseded("the capture is no longer live")
        );
        let fresh = gate.open();
        assert!(gate.hold(true, at(3_000)));
        assert!(gate.hold(false, at(3_100)));
        gate.shut();
        assert_eq!(
            gate.resend(2, fresh, 0, sized(14), || {}),
            Resend::Superseded("the capture is no longer live")
        );
        assert_eq!(rx.try_iter().count(), 0);
    }

    /// The resend is accepted, and before its sender could publish where its picture is, a live
    /// frame of a new size passes and publishes its own: the resend's place is published in the
    /// gate's lock that accepted it, so the live frame — which can pass only once that lock is
    /// free — publishes after it, and the newer place stands (input coordinates and the picture's
    /// size never regress to the older frame's).
    #[test]
    fn a_resend_never_overwrites_a_newer_live_frames_geometry() {
        let (tx, rx) = mpsc::channel();
        let gate = Arc::new(FrameGate::new(tx));
        let status = Arc::new(GameStatus::new());
        status.set_active(true);
        status.set_state(GameWindowState::Shown);
        let t0 = Instant::now();
        let sized = |w: u32| Frame {
            data: vec![9; w as usize * 4 * 4],
            width: w,
            height: 4,
            timestamp_ms: 0,
        };
        let placed = |w: u32| CaptureGeometry {
            hwnd: 0x40666,
            client: ScreenRect {
                left: 0,
                top: 0,
                right: w as i32,
                bottom: 4,
            },
            source: (w, 4),
        };
        let live = gate.open();
        assert_eq!(gate.send_live(live, sized(14)), GateSend::Sent);
        status.set_geometry(placed(14));
        assert!(gate.hold(true, t0));
        assert!(gate.hold(false, t0 + Duration::from_secs(1)));

        let (entered_tx, entered_rx) = mpsc::channel::<()>();
        let resized = {
            let (gate, status) = (gate.clone(), status.clone());
            std::thread::spawn(move || {
                entered_rx.recv().expect("the resend is in the gate's lock");
                // The frame handler's order: through the gate, then where the picture is.
                let sent = gate.send_live(live, sized(20));
                if sent == GateSend::Sent {
                    status.set_geometry(placed(20));
                }
                sent
            })
        };
        let done = gate.resend(1, live, 1, sized(14), || {
            entered_tx.send(()).expect("the live frame's thread waits");
            // The live frame tries to pass meanwhile and waits for this lock.
            std::thread::sleep(Duration::from_millis(50));
            status.set_geometry(placed(14));
        });
        assert_eq!(done, Resend::Sent { size: (14, 4) });
        assert_eq!(resized.join().expect("no panic"), GateSend::Sent);
        let snap = status.snapshot();
        assert_eq!(
            snap.source,
            Some((20, 4)),
            "the newer picture's size stands"
        );
        assert_eq!(snap.geometry, Some(placed(20)), "and its place");
        let widths: Vec<u32> = rx.try_iter().map(|f| f.width).collect();
        assert_eq!(
            widths,
            vec![14, 14, 20],
            "the resend went out before the newer frame"
        );
    }

    /// The first-frame watchdog gives a capture up only in the gate's lock, against the hold: a
    /// hold that began since the thread's look, or a frame that passed meanwhile, keeps it.
    #[test]
    fn the_watchdog_closes_a_capture_only_unheld_and_with_nothing_passed() {
        let (tx, _rx) = mpsc::channel();
        let gate = FrameGate::new(tx);
        let t0 = Instant::now();
        let live = gate.open();
        assert!(gate.hold(true, t0));
        assert_eq!(gate.close_unheld(live, 0), Err("a background hold began"));
        assert!(gate.hold(false, t0));
        assert_eq!(
            gate.close_unheld(live, 0),
            Err("a background hold began"),
            "begun and ended since the look at epoch 0"
        );
        assert_eq!(
            gate.close_unheld(live + 1, 1),
            Err("the capture is no longer live")
        );
        assert_eq!(
            gate.send_live(live, black_frame((4, 4), 1080)),
            GateSend::Sent
        );
        assert_eq!(
            gate.close_unheld(live, 1),
            Err("a frame of it passed meanwhile")
        );
        let next = gate.open();
        assert_eq!(gate.close_unheld(next, 1), Ok(()));
        assert!(!gate.is_live(), "closed in that same lock");
    }

    /// The hold's record is taken in the gate's lock with the transition: a frame that passes after
    /// the release, however soon, is after the baseline the game capture's thread reads later.
    #[test]
    fn the_release_baseline_is_the_gates_and_a_frame_after_it_is_after_it() {
        let (tx, _rx) = mpsc::channel();
        let gate = FrameGate::new(tx);
        let t0 = Instant::now();
        let live = gate.open();
        assert_eq!(
            gate.send_live(live, black_frame((4, 4), 1080)),
            GateSend::Sent
        );
        gate.hold(true, t0);
        gate.hold(false, t0);
        assert_eq!(
            gate.send_live(live, black_frame((4, 4), 1080)),
            GateSend::Sent
        );
        let view = gate.hold_view(t0);
        assert_eq!(view.released.map(|r| r.frames), Some(1));
        assert_eq!(gate.live_frames(), 2);
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
        gate: Arc<FrameGate>,
        /// The last step's time, in ms: when a hold set or a frame delivered between steps happens.
        last: u64,
    }

    impl Rig {
        fn new(binding: Option<GameBinding>) -> Self {
            let windows: Windows = Arc::new(Mutex::new(Ok(Vec::new())));
            let backend = Arc::new(Mutex::new(BackendWorld::default()));
            let status = Arc::new(GameStatus::new());
            status.set_active(true);
            let (tx, frames) = mpsc::channel();
            let gate = Arc::new(FrameGate::new(tx));
            let mut director = Director::new(
                binding,
                Box::new(ScriptedSource::new(windows.clone())),
                Box::new(ScriptedBackend(backend.clone())),
                gate.clone(),
                status.clone(),
                Arc::new(QualityTarget::default()),
            );
            let world = backend.clone();
            director.clock = Box::new(move || {
                let mut w = lock(&world);
                let at = w.clock.unwrap_or_else(Instant::now);
                let at = w.step_work.take().map_or(at, |work| at + work);
                w.clock = Some(at);
                at
            });
            Self {
                t0: Instant::now(),
                director,
                windows,
                backend,
                status,
                frames,
                gate,
                last: 0,
            }
        }

        /// The background hold on or off, as `Capturer::hold` sets it: the gate at once (at the
        /// last step's time), the thread at its next step.
        fn hold(&self, held: bool) {
            set_hold(&self.gate, held, self.at(self.last));
        }

        fn at(&self, ms: u64) -> Instant {
            self.t0 + Duration::from_millis(ms)
        }

        /// Step every 50 ms from `from` to `to`, inclusive. A step that took time on the test's
        /// clock (a try of the retained frame, [`BackendWorld::retained_takes`]) moves the next
        /// step past its end, as on the thread.
        fn run(&mut self, from: u64, to: u64) {
            let mut ms = from;
            while ms <= to {
                let now = self.at(ms);
                lock(&self.backend).clock = Some(now);
                self.director.step(now);
                self.last = ms;
                let ended = lock(&self.backend).clock.map_or(ms, |c| {
                    c.saturating_duration_since(self.t0).as_millis() as u64
                });
                ms = (ms + 50).max(ended);
            }
        }

        fn show(&self, windows: Vec<WindowInfo>) {
            *lock(&self.windows) = Ok(windows);
        }

        /// The running capture delivers one frame of `w`x`h` (at the last step's time).
        fn deliver(&self, w: u32, h: u32) -> GateSend {
            lock(&self.backend).deliver_at(w, h, self.at(self.last))
        }

        /// A delivery split in two, for the supervisor to act in its middle: the frame arrives
        /// (asked of the gate and retained)…
        fn arrive(&self, w: u32, h: u32) -> Option<(u32, u32)> {
            lock(&self.backend).arrive_at(w, h, self.at(self.last))
        }

        /// …and is made and sent.
        fn finish(&self, admitted: (u32, u32)) -> GateSend {
            lock(&self.backend).finish(admitted)
        }

        /// One step's parts at `ms`, for a test that interleaves the supervisor between them.
        fn follow_hold(&mut self, ms: u64) {
            self.director.follow_hold(self.at(ms));
            self.last = ms;
        }

        fn watch(&mut self, ms: u64) {
            self.director.watch(self.at(ms));
            self.last = ms;
        }

        fn black_received(&self) -> Vec<bool> {
            self.received().into_iter().map(|f| f.0).collect()
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

    /// A rig with the game's window shown, captured, and one frame of it passed (and retained).
    fn captured(reject_after_stop: bool) -> Rig {
        let mut r = Rig::new(Some(binding()));
        lock(&r.backend).reject_after_stop = reject_after_stop;
        r.show(vec![game_window(0x40666, 6888)]);
        r.run(0, 100);
        assert_eq!(r.deliver(3576, 2268), GateSend::Sent);
        assert_eq!(r.received(), vec![(false, 3576, 2268)]);
        r
    }

    /// The background hold with a window capture live: it keeps running — never stopped, never
    /// started again — and nothing of it reaches the encoder until the release, when its next
    /// frame passes at once. Each frame of the hold is retained by the capture, none sent.
    #[test]
    fn a_hold_keeps_the_live_capture_and_drops_its_frames_until_the_release() {
        let mut r = captured(false);
        r.hold(true);
        // Nothing passes from the moment the hold is set, before the thread's own step: the
        // frames of the hold are retained by the capture, not sent.
        assert_eq!(r.deliver(3576, 2268), GateSend::Refused);
        assert_eq!(r.deliver(3576, 2268), GateSend::Refused);
        r.run(150, 150);
        {
            let w = lock(&r.backend);
            assert_eq!(
                w.stopped, 0,
                "the window capture is not stopped for the hold"
            );
            assert!(w.running.is_some());
        }
        // Long past every watchdog of the capture's delivery: it is neither given up on nor
        // started again, and neither its frames nor black ones go out.
        let mut delivered = Vec::new();
        for ms in (200..=8_000).step_by(50) {
            r.run(ms, ms);
            if ms % 500 == 0 {
                delivered.push(r.deliver(3576, 2268));
            }
        }
        assert!(r.received().is_empty(), "nothing at all while held");
        assert!(delivered.iter().all(|&d| d == GateSend::Refused));
        {
            let w = lock(&r.backend);
            assert_eq!(w.started.len(), 1, "one capture all through the hold");
            assert_eq!(w.stopped, 0);
        }
        let view = r.gate.hold_view(r.at(8_000));
        assert_eq!(view.arrived, 18);
        assert_eq!(
            r.status.held_frames(),
            (18, 18),
            "for the pipeline line: every one retained"
        );
        let snap = r.status.snapshot();
        assert_eq!(snap.state, GameWindowState::Shown);
        assert_eq!(snap.window, Some((0x40666, 6888)));
        assert!(
            r.status.game_scope().window.is_some(),
            "input keeps the window it was captured on"
        );

        // Released: the capture's next frame passes at once, before the thread's own step.
        r.hold(false);
        assert_eq!(r.deliver(1920, 1080), GateSend::Sent);
        r.run(8_050, 8_050);
        assert!(
            r.director.resuming.is_none(),
            "the first frame after it is told"
        );
        r.run(8_100, 10_000);
        assert_eq!(r.received(), vec![(false, 1920, 1080)], "and nothing else");
        let w = lock(&r.backend);
        assert_eq!(
            (w.started.len(), w.stopped),
            (1, 0),
            "the same capture after the hold"
        );
    }

    /// A still window sends no frame after the release (WGC sends only changes), on a capture that
    /// cannot be started again once stopped: the frame retained before the hold goes out
    /// again within the pipeline's wait, and the capture is never stopped — never black.
    #[test]
    fn a_still_window_after_a_hold_resumes_on_the_retained_frame_and_keeps_its_capture() {
        let mut r = captured(true);
        r.hold(true);
        r.run(150, 30_000);
        r.hold(false);
        let within = RESUME_FIRST_FRAME_WITHIN.as_millis() as u64;
        r.run(30_050, 30_000 + within - 50);
        assert!(r.received().is_empty(), "waited for a fresh frame first");
        r.run(30_000 + within, 30_000 + within);
        assert_eq!(
            r.received(),
            vec![(false, 3576, 2268)],
            "the retained frame, at once"
        );
        assert!(
            Duration::from_millis(within) < crate::pipeline::HOLD_FIRST_FRAME_WITHIN,
            "inside the pipeline's own wait"
        );
        // A long still minute after: nothing stopped, nothing started, no black frame.
        r.run(30_000 + within + 50, 90_000);
        assert!(r.received().is_empty());
        {
            let w = lock(&r.backend);
            assert_eq!((w.started.len(), w.stopped), (1, 0));
        }
        // The window draws again: its frames pass on the same capture.
        assert_eq!(r.deliver(3576, 2268), GateSend::Sent);
        assert_eq!(r.received(), vec![(false, 3576, 2268)]);

        // And the next hold of the same still window resumes the same way.
        r.hold(true);
        r.run(90_050, 100_000);
        r.hold(false);
        r.run(100_050, 101_000);
        assert_eq!(r.received(), vec![(false, 3576, 2268)]);
        let w = lock(&r.backend);
        assert_eq!((w.started.len(), w.stopped), (1, 0));
    }

    /// The window changed during the hold — twice, the second time half a second after the
    /// first — and was still by its end: the viewer resumes on its very last update, never on an
    /// older one (no frame of the hold is skipped: each is retained as it arrives).
    #[test]
    fn a_window_that_changed_during_the_hold_resumes_on_its_last_frame() {
        let mut r = captured(true);
        r.hold(true);
        r.run(150, 1_000);
        assert_eq!(r.deliver(1920, 1080), GateSend::Refused);
        r.run(1_050, 1_500);
        assert_eq!(r.deliver(1280, 720), GateSend::Refused);
        r.run(1_550, 5_000);
        r.hold(false);
        r.run(5_050, 6_000);
        assert_eq!(r.received(), vec![(false, 1280, 720)], "the last one");
        assert_eq!(lock(&r.backend).stopped, 0);
    }

    /// The window is resized during the hold (WGC's next frame is of the new size) and is still
    /// after: the frame resumed on is the resized one, and the picture's size and place follow it.
    #[test]
    fn a_window_resized_during_the_hold_resumes_on_the_resized_frame() {
        let mut r = captured(true);
        assert_eq!(r.status.snapshot().source, Some((3576, 2268)));
        r.hold(true);
        r.run(150, 2_000);
        assert_eq!(r.deliver(2560, 1440), GateSend::Refused);
        r.run(2_050, 4_000);
        r.hold(false);
        r.run(4_050, 5_000);
        assert_eq!(r.received(), vec![(false, 2560, 1440)]);
        assert_eq!(
            r.status.snapshot().source,
            Some((2560, 1440)),
            "where the picture is, from the frame resumed on"
        );
    }

    /// A capture started just before the hold that has delivered nothing at all: its first-frame
    /// watchdog does not run during the hold, there is nothing to send again after it, and the
    /// capture is kept; the watchdog counts from the release.
    #[test]
    fn a_capture_with_no_frame_before_a_hold_is_kept_and_its_watchdog_skips_the_hold() {
        let mut r = Rig::new(Some(binding()));
        r.show(vec![game_window(0x40666, 6888)]);
        r.run(0, 0);
        assert_eq!(lock(&r.backend).started.len(), 1);
        r.hold(true);
        r.run(50, 10_000);
        assert_eq!(lock(&r.backend).stopped, 0, "no watchdog during the hold");
        r.hold(false);
        r.run(10_050, 12_950);
        assert!(r.received().is_empty(), "nothing retained, nothing sent");
        assert_eq!(lock(&r.backend).stopped, 0, "kept after the release");
        assert!(r.director.resuming.is_none(), "the recovery found nothing");
        // Three seconds after the release with nothing at all: the capture that never delivered
        // is given up on, as before any hold.
        r.run(13_000, 13_000);
        assert_eq!(lock(&r.backend).stopped, 1);
        assert_eq!(r.black_received(), vec![true]);
    }

    /// A capture whose only frames arrived during the hold: what it retained is the picture the
    /// viewer resumes on, and that usable frame — passed by the resend — keeps it from being
    /// given up on.
    #[test]
    fn a_capture_whose_first_frames_came_during_the_hold_is_never_given_up_on() {
        let mut r = Rig::new(Some(binding()));
        lock(&r.backend).reject_after_stop = true;
        r.show(vec![game_window(0x40666, 6888)]);
        r.run(0, 0);
        r.hold(true);
        r.run(50, 50);
        assert_eq!(r.deliver(3576, 2268), GateSend::Refused, "held, retained");
        r.run(100, 5_000);
        r.hold(false);
        r.run(5_050, 20_000);
        assert_eq!(r.received(), vec![(false, 3576, 2268)]);
        assert_eq!(lock(&r.backend).stopped, 0);
    }

    /// The hold began and ended between two of the thread's steps, the window still since: the
    /// gate's record still makes the thread act on it — the frame retained during it goes out.
    #[test]
    fn a_hold_and_its_release_between_two_steps_are_both_acted_on() {
        let mut r = captured(true);
        r.hold(true);
        assert_eq!(r.deliver(1920, 1080), GateSend::Refused, "held, retained");
        r.hold(false);
        r.run(150, 150);
        assert!(r.director.resuming.is_some(), "the release is acted on");
        r.run(200, 3_000);
        assert_eq!(r.received(), vec![(false, 1920, 1080)]);
        assert_eq!(lock(&r.backend).stopped, 0);
        // Two whole holds unseen, then a third in force: the thread acts on the newest.
        r.hold(true);
        r.hold(false);
        r.hold(true);
        r.hold(false);
        r.hold(true);
        r.run(3_050, 3_050);
        let holding = r.director.holding.as_ref().map(|h| h.epoch);
        assert_eq!(holding, Some(4));
        r.hold(false);
        r.run(3_100, 4_000);
        assert_eq!(r.received(), vec![(false, 1920, 1080)]);
    }

    /// The thread saw the hold; then, before its next look, the release came and a fresh frame
    /// passed at once: that frame is after the release's baseline (the gate's, taken with the
    /// release), so it is the first frame after the hold, and nothing is sent again.
    #[test]
    fn a_frame_that_passes_right_after_the_release_is_never_taken_for_one_before_it() {
        let mut r = captured(true);
        r.hold(true);
        r.run(150, 1_000);
        r.follow_hold(1_020);
        assert!(r.director.holding.is_some());
        r.hold(false);
        assert_eq!(r.deliver(1920, 1080), GateSend::Sent);
        r.run(1_050, 1_050);
        assert!(r.director.resuming.is_none(), "the fresh frame is told");
        r.run(1_100, 3_000);
        assert_eq!(r.received(), vec![(false, 1920, 1080)], "and nothing else");
    }

    /// A new hold that begins between the thread's look at the hold and its look at the capture,
    /// while a recovery is due: the recovery checks the gate's epoch in the gate's lock and is
    /// cancelled; the new hold's own release recovers.
    #[test]
    fn a_new_hold_cancels_a_due_recovery() {
        let mut r = captured(true);
        r.hold(true);
        r.run(150, 1_000);
        r.hold(false);
        r.run(1_050, 1_250);
        let due = 1_000 + RESUME_FIRST_FRAME_WITHIN.as_millis() as u64;
        r.follow_hold(due);
        assert!(r.director.resuming.is_some(), "due");
        r.hold(true);
        r.watch(due);
        assert!(r.received().is_empty(), "cancelled: held again");
        assert!(r.director.resuming.is_none());
        r.run(due + 50, 5_000);
        assert!(r.received().is_empty());
        r.hold(false);
        r.run(5_050, 6_000);
        assert_eq!(r.received(), vec![(false, 3576, 2268)]);
        assert_eq!(lock(&r.backend).stopped, 0);
    }

    /// A hold that begins while the thread waits for the first frame after the last one: that
    /// wait ends unsent, and the new hold resumes on its own release.
    #[test]
    fn a_hold_that_begins_while_resuming_resumes_on_its_own_release() {
        let mut r = captured(true);
        r.hold(true);
        r.run(150, 1_000);
        r.hold(false);
        r.run(1_050, 1_100);
        assert!(r.director.resuming.is_some());
        r.hold(true);
        r.run(1_150, 1_150);
        assert!(r.director.resuming.is_none());
        r.run(1_200, 4_000);
        assert!(r.received().is_empty(), "nothing while held");
        r.hold(false);
        r.run(4_050, 5_000);
        assert_eq!(r.received(), vec![(false, 3576, 2268)]);
    }

    /// The capture ends by itself (the window's item closed) while the thread waits for the first
    /// frame after a hold: the wait ends, black frames start, and the capture is tried again.
    #[test]
    fn a_capture_that_ends_while_resuming_goes_black_and_is_tried_again() {
        let mut r = captured(false);
        r.hold(true);
        r.run(150, 1_000);
        r.hold(false);
        r.run(1_050, 1_100);
        assert!(r.director.resuming.is_some());
        lock(&r.backend).finished = true;
        r.run(1_150, 1_150);
        assert!(r.director.resuming.is_none());
        assert_eq!(lock(&r.backend).stopped, 1);
        r.run(1_200, 2_000);
        let got = r.black_received();
        assert!(
            !got.is_empty() && got.iter().all(|&b| b),
            "black only: {got:?}"
        );
        r.run(2_050, 3_000);
        assert_eq!(
            lock(&r.backend).started.len(),
            2,
            "tried again after the pause"
        );
    }

    /// The retained frame cannot be made on the first try after the release (the frame handler
    /// busy past its wait, the GPU still busy): the same hold's recovery tries again
    /// [`RESUME_RETRY_EVERY`] later, and the still window resumes on its retained frame with no
    /// further frame of its own.
    #[test]
    fn a_retained_frame_that_fails_once_is_tried_again_for_the_same_hold() {
        let mut r = captured(true);
        r.hold(true);
        r.run(150, 1_000);
        r.hold(false);
        lock(&r.backend).retained_fails = 1;
        let first = 1_000 + RESUME_FIRST_FRAME_WITHIN.as_millis() as u64;
        r.run(1_050, first);
        assert!(r.received().is_empty(), "the first try failed");
        assert_eq!(lock(&r.backend).retained_tries, 1);
        assert!(
            r.director.resuming.is_some(),
            "the recovery is kept for the same hold"
        );
        let retry = first + RESUME_RETRY_EVERY.as_millis() as u64;
        r.run(first + 50, retry - 50);
        assert_eq!(lock(&r.backend).retained_tries, 1, "not before its time");
        r.run(retry, retry);
        assert_eq!(r.received(), vec![(false, 3576, 2268)], "the second try");
        assert!(r.director.resuming.is_none());
        r.run(retry + 50, 10_000);
        assert!(r.received().is_empty(), "once");
        let w = lock(&r.backend);
        assert_eq!((w.retained_tries, w.started.len(), w.stopped), (2, 1, 0));
    }

    /// The retained frame can never be made: the recovery stops after its tries, within about
    /// two seconds of the first, and the capture is kept.
    #[test]
    fn a_retained_frame_that_keeps_failing_is_given_up_after_its_tries() {
        let mut r = captured(true);
        r.hold(true);
        r.run(150, 1_000);
        r.hold(false);
        lock(&r.backend).retained_fails = u32::MAX;
        let first = 1_000 + RESUME_FIRST_FRAME_WITHIN.as_millis() as u64;
        let last = first + RESUME_RETRY_FOR.as_millis() as u64;
        r.run(1_050, last);
        assert!(r.director.resuming.is_none(), "given up");
        let tries = lock(&r.backend).retained_tries;
        assert!(
            (2..=RESUME_TRIES).contains(&tries),
            "bounded by the tries and the time: {tries}"
        );
        r.run(last + 50, 20_000);
        assert_eq!(lock(&r.backend).retained_tries, tries, "no try after");
        assert!(r.received().is_empty());
        let w = lock(&r.backend);
        assert_eq!((w.started.len(), w.stopped), (1, 0), "the capture is kept");
    }

    /// No picture can be made of the retained frame at all (on Windows: the client area moved out
    /// of the region kept of the last frame): given up after the first try, with no retry, and the
    /// capture is kept.
    #[test]
    fn a_retained_frame_that_cannot_be_made_is_not_tried_again() {
        let mut r = captured(true);
        r.hold(true);
        r.run(150, 1_000);
        r.hold(false);
        lock(&r.backend).retained_unusable = true;
        let first = 1_000 + RESUME_FIRST_FRAME_WITHIN.as_millis() as u64;
        r.run(1_050, first);
        assert_eq!(lock(&r.backend).retained_tries, 1);
        assert!(r.director.resuming.is_none(), "given up at once");
        r.run(first + 50, 10_000);
        assert_eq!(lock(&r.backend).retained_tries, 1, "no further try");
        assert!(r.received().is_empty());
        let w = lock(&r.backend);
        assert_eq!((w.started.len(), w.stopped), (1, 0), "the capture is kept");
    }

    /// Each failing try takes 700 ms (the handler's wait and the GPU's): the next is due
    /// [`RESUME_RETRY_EVERY`] after the last one ended, not after it began, and none begins past
    /// [`RESUME_RETRY_FOR`] after the first began.
    #[test]
    fn slow_failing_tries_are_spaced_from_their_end_and_kept_within_the_budget() {
        let mut r = captured(true);
        r.hold(true);
        r.run(150, 1_000);
        r.hold(false);
        {
            let mut w = lock(&r.backend);
            w.retained_fails = u32::MAX;
            w.retained_takes = Duration::from_millis(700);
        }
        r.run(1_050, 10_000);
        assert!(r.director.resuming.is_none(), "given up");
        assert!(r.received().is_empty());
        let w = lock(&r.backend);
        let log = &w.retained_log;
        assert!(log.len() >= 2, "tried again: {log:?}");
        let first = log[0].0;
        assert_eq!(
            first,
            r.at(1_000 + RESUME_FIRST_FRAME_WITHIN.as_millis() as u64),
            "the first try when the fresh frame was due"
        );
        for (i, pair) in log.windows(2).enumerate() {
            let ((_, ended), (began, _)) = (pair[0], pair[1]);
            assert!(
                began.saturating_duration_since(ended) >= RESUME_RETRY_EVERY,
                "try {} began {} ms after try {} ended",
                i + 2,
                began.saturating_duration_since(ended).as_millis(),
                i + 1
            );
        }
        for (i, (began, _)) in log.iter().enumerate() {
            assert!(
                began.saturating_duration_since(first) <= RESUME_RETRY_FOR,
                "try {} began {} ms after the first",
                i + 1,
                began.saturating_duration_since(first).as_millis()
            );
        }
        // 1300–2000, 2100–2800, 2900–3600; a fourth would begin at 3700, past 3300.
        assert_eq!(log.len(), 3, "{log:?}");
        assert_eq!((w.started.len(), w.stopped), (1, 0), "the capture is kept");
    }

    /// The thread steps late, past the budget, when a retry was due: the retry is not begun.
    #[test]
    fn a_retry_that_comes_due_past_the_budget_is_not_begun() {
        let mut r = captured(true);
        r.hold(true);
        r.run(150, 1_000);
        r.hold(false);
        lock(&r.backend).retained_fails = u32::MAX;
        let first = 1_000 + RESUME_FIRST_FRAME_WITHIN.as_millis() as u64;
        r.run(1_050, first);
        assert_eq!(lock(&r.backend).retained_tries, 1);
        assert!(r.director.resuming.is_some(), "a retry is due");
        let late = first + RESUME_RETRY_FOR.as_millis() as u64 + 100;
        r.run(late, late);
        assert!(r.director.resuming.is_none(), "given up");
        assert_eq!(lock(&r.backend).retained_tries, 1, "not begun");
        r.run(late + 50, 10_000);
        assert_eq!(lock(&r.backend).retained_tries, 1);
        assert!(r.received().is_empty());
    }

    /// A step begins within the budget, but its own work before the recovery (the finder's poll,
    /// the window's geometry) takes it past: the retry is not begun — the deadline is checked on
    /// the clock as the try would begin, not on the step's time.
    #[test]
    fn a_retry_pushed_past_the_budget_by_its_own_step_is_not_begun() {
        let mut r = captured(true);
        r.hold(true);
        r.run(150, 1_000);
        r.hold(false);
        lock(&r.backend).retained_fails = u32::MAX;
        let first = 1_000 + RESUME_FIRST_FRAME_WITHIN.as_millis() as u64;
        r.run(1_050, first);
        assert_eq!(lock(&r.backend).retained_tries, 1);
        let step = first + RESUME_RETRY_FOR.as_millis() as u64 - 100;
        lock(&r.backend).step_work = Some(Duration::from_millis(250));
        r.run(step, step);
        assert!(r.director.resuming.is_none(), "given up");
        assert_eq!(
            lock(&r.backend).retained_tries,
            1,
            "not begun past the budget"
        );
        r.run(step + 300, 10_000);
        assert_eq!(lock(&r.backend).retained_tries, 1);
        assert!(r.received().is_empty());
    }

    /// A fresh frame passes while a retry is due: the retry is cancelled, and only the fresh frame
    /// goes out.
    #[test]
    fn a_fresh_frame_cancels_a_retry_of_the_retained_frame() {
        let mut r = captured(true);
        r.hold(true);
        r.run(150, 1_000);
        r.hold(false);
        lock(&r.backend).retained_fails = 1;
        let first = 1_000 + RESUME_FIRST_FRAME_WITHIN.as_millis() as u64;
        r.run(1_050, first);
        assert_eq!(r.deliver(1920, 1080), GateSend::Sent);
        r.run(first + 50, 5_000);
        assert_eq!(
            r.received(),
            vec![(false, 1920, 1080)],
            "the fresh frame only"
        );
        assert!(r.director.resuming.is_none());
        assert_eq!(lock(&r.backend).retained_tries, 1, "no retry");
    }

    /// A new hold begins while a retry is due: the retry is cancelled, and the new hold's own
    /// release recovers.
    #[test]
    fn a_new_hold_cancels_a_retry_of_the_retained_frame() {
        let mut r = captured(true);
        r.hold(true);
        r.run(150, 1_000);
        r.hold(false);
        lock(&r.backend).retained_fails = 1;
        let first = 1_000 + RESUME_FIRST_FRAME_WITHIN.as_millis() as u64;
        r.run(1_050, first);
        r.hold(true);
        r.run(first + 50, 4_000);
        assert!(r.received().is_empty(), "nothing while held");
        assert_eq!(lock(&r.backend).retained_tries, 1, "no retry while held");
        r.hold(false);
        r.run(4_050, 5_000);
        assert_eq!(r.received(), vec![(false, 3576, 2268)]);
        assert_eq!(lock(&r.backend).retained_tries, 2);
    }

    /// The first-frame watchdog is due — a capture with nothing passed for three seconds — and the
    /// thread has looked at the hold (none) when the supervisor holds: the watchdog decides in the
    /// gate's lock, against the hold, so the capture is kept through it and, its window drawing
    /// once during the hold and then still, resumes on that frame and is never stopped.
    #[test]
    fn a_hold_between_the_threads_look_and_the_watchdog_keeps_the_capture() {
        let mut r = Rig::new(Some(binding()));
        lock(&r.backend).reject_after_stop = true;
        r.show(vec![game_window(0x40666, 6888)]);
        r.run(0, 0);
        assert_eq!(lock(&r.backend).started.len(), 1);
        let due = FIRST_FRAME_WITHIN.as_millis() as u64;
        r.run(50, due - 50);
        assert_eq!(lock(&r.backend).stopped, 0, "not due yet");
        r.follow_hold(due);
        assert!(r.director.holding.is_none(), "no hold at the look");
        r.hold(true);
        r.watch(due);
        assert_eq!(
            lock(&r.backend).stopped,
            0,
            "kept: a hold began since the look"
        );
        assert!(r.gate.is_live());
        r.run(due + 50, due + 1_000);
        assert_eq!(r.deliver(3576, 2268), GateSend::Refused, "held, retained");
        r.run(due + 1_050, 10_000);
        assert!(r.received().is_empty());
        r.hold(false);
        r.run(10_050, 20_000);
        assert_eq!(r.received(), vec![(false, 3576, 2268)]);
        let w = lock(&r.backend);
        assert_eq!((w.started.len(), w.stopped), (1, 0));
    }

    /// The capture's first frame passed the gate's first look before the hold and was handed to
    /// it, made, after the hold began: the gate refuses it — but the capture retained it as it
    /// arrived, so the still window resumes on it after the release, and that frame passed keeps
    /// the watchdog off the capture for good.
    #[test]
    fn a_first_frame_refused_as_the_hold_began_is_the_one_resumed_on() {
        let mut r = Rig::new(Some(binding()));
        lock(&r.backend).reject_after_stop = true;
        r.show(vec![game_window(0x40666, 6888)]);
        r.run(0, 0);
        let admitted = r.arrive(3576, 2268).expect("before the hold: to be sent");
        r.hold(true);
        assert_eq!(
            r.finish(admitted),
            GateSend::Refused,
            "the hold began meanwhile"
        );
        r.run(50, 5_000);
        assert!(r.received().is_empty());
        r.hold(false);
        r.run(5_050, 20_000);
        assert_eq!(r.received(), vec![(false, 3576, 2268)]);
        let w = lock(&r.backend);
        assert_eq!((w.started.len(), w.stopped), (1, 0));
    }

    /// A frame in flight across a whole hold — through the gate's first look before it, sent after
    /// its release — is the newest picture: it is the first frame after that hold, and a second,
    /// quiet hold of the then still window resumes on it, never on the one before it.
    #[test]
    fn a_frame_in_flight_across_a_hold_is_the_one_the_next_quiet_hold_resumes_on() {
        let mut r = captured(true);
        r.run(150, 1_000);
        let admitted = r.arrive(1920, 1080).expect("not held yet");
        r.hold(true);
        r.hold(false);
        assert_eq!(
            r.finish(admitted),
            GateSend::Sent,
            "released by the time it is sent"
        );
        r.run(1_050, 2_000);
        assert_eq!(
            r.received(),
            vec![(false, 1920, 1080)],
            "the fresh frame after the hold, and no resend"
        );
        r.hold(true);
        r.run(2_050, 5_000);
        r.hold(false);
        r.run(5_050, 6_000);
        assert_eq!(r.received(), vec![(false, 1920, 1080)], "the newest again");
        assert_eq!(lock(&r.backend).stopped, 0);
    }

    /// Frames that arrived during the hold but whose retained copy cannot be made into a picture
    /// (a read-back failing on Windows) are WGC activity, not delivery: they keep no capture that
    /// has never passed a frame, and three seconds after the release the watchdog gives it up, as
    /// it would before any hold.
    #[test]
    fn held_frames_that_cannot_be_made_do_not_keep_a_capture_that_never_delivered() {
        let mut r = Rig::new(Some(binding()));
        r.show(vec![game_window(0x40666, 6888)]);
        r.run(0, 0);
        r.hold(true);
        r.run(50, 50);
        assert_eq!(r.deliver(3576, 2268), GateSend::Refused);
        assert_eq!(r.status.held_frames(), (1, 1));
        lock(&r.backend).retained_fails = u32::MAX;
        r.run(100, 5_000);
        r.hold(false);
        let watchdog = 5_000 + FIRST_FRAME_WITHIN.as_millis() as u64;
        r.run(5_050, watchdog - 50);
        assert!(r.received().is_empty(), "the resend failed: nothing sent");
        assert_eq!(lock(&r.backend).stopped, 0);
        r.run(watchdog, watchdog);
        assert_eq!(
            lock(&r.backend).stopped,
            1,
            "given up on, as before any hold"
        );
        assert_eq!(r.black_received(), vec![true]);
    }

    /// The retained frame is the capture's: one stopped (the window minimized) takes it along, so
    /// a new capture on the restored window that has delivered nothing has nothing to resume on
    /// after a hold — never the old capture's picture.
    #[test]
    fn a_stopped_capture_takes_its_retained_frame_with_it() {
        let mut r = captured(false);
        r.show(vec![WindowInfo {
            minimized: true,
            ..game_window(0x40666, 6888)
        }]);
        r.run(150, 1_000);
        {
            let w = lock(&r.backend);
            assert_eq!(w.stopped, 1);
            assert!(w.retained.is_none());
        }
        r.show(vec![game_window(0x40666, 6888)]);
        r.run(1_050, 1_500);
        assert_eq!(lock(&r.backend).started.len(), 2);
        r.received();
        r.hold(true);
        r.run(1_550, 2_500);
        r.hold(false);
        r.run(2_550, 3_500);
        assert!(r.received().is_empty(), "nothing of the old capture");
        assert_eq!(lock(&r.backend).stopped, 1);
    }

    /// The capturer finishing (`Capturer::stop`) stops the capture, which takes its retained frame
    /// along, and shuts the gate: nothing is due to be sent again.
    #[test]
    fn a_finished_capturer_forgets_the_retained_frame() {
        let mut r = captured(false);
        r.hold(true);
        r.run(150, 500);
        assert_eq!(r.deliver(1920, 1080), GateSend::Refused);
        assert!(lock(&r.backend).retained.is_some());
        r.director.finish("stopped");
        {
            let w = lock(&r.backend);
            assert!(w.running.is_none() && w.retained.is_none());
            assert_eq!(w.stopped, 1);
        }
        r.hold(false);
        assert_eq!(
            r.gate.resend(1, 1, 1, black_frame((4, 4), 1080), || {}),
            Resend::Superseded("the capture is no longer live")
        );
        assert!(r.received().is_empty());
    }

    /// During a hold with its capture kept, the window still decides: minimized, it stops; a new
    /// window (a relaunch) stops it too; nothing is started and no black frame goes out until the
    /// release, which captures the window as it is then, at once.
    #[test]
    fn window_changes_during_a_hold_stop_the_kept_capture_and_start_none() {
        let mut r = Rig::new(Some(binding()));
        r.show(vec![game_window(0x40666, 6888)]);
        r.run(0, 100);
        assert_eq!(r.deliver(3576, 2268), GateSend::Sent);
        r.received();

        r.hold(true);
        r.run(150, 150);
        // Minimized during the hold: the capture stops, the state follows, no black frame.
        r.show(vec![WindowInfo {
            minimized: true,
            ..game_window(0x40666, 6888)
        }]);
        r.run(200, 2_000);
        {
            let w = lock(&r.backend);
            assert_eq!(w.stopped, 1, "minimized: the kept capture stops");
            assert!(w.running.is_none());
        }
        assert_eq!(r.status.snapshot().state, GameWindowState::Minimized);
        // Relaunched and shown again during the hold: the new window and its process are known,
        // but nothing is captured and input has no window until it is.
        r.show(vec![game_window(0x50777, 7001)]);
        r.run(2_050, 5_000);
        let snap = r.status.snapshot();
        assert_eq!(snap.state, GameWindowState::Shown);
        assert_eq!(snap.window, Some((0x50777, 7001)));
        assert_eq!(r.status.game_scope().window, None);
        assert_eq!(lock(&r.backend).started.len(), 1, "no capture while held");
        assert!(r.received().is_empty(), "nothing at all while held");

        r.hold(false);
        r.run(5_050, 5_050);
        assert_eq!(
            lock(&r.backend).started.last().map(|&(hwnd, _)| hwnd),
            Some(0x50777),
            "the window as it is now, captured on the first step after the release"
        );
        assert_eq!(r.deliver(3576, 2268), GateSend::Sent);
        assert_eq!(r.received(), vec![(false, 3576, 2268)]);

        // Held again, and the game relaunched straight into a new window: the kept capture stops,
        // the new one waits for the release.
        r.hold(true);
        r.run(5_100, 5_100);
        r.show(vec![game_window(0x60888, 7002)]);
        r.run(5_150, 6_000);
        {
            let w = lock(&r.backend);
            assert_eq!(w.stopped, 2, "a new window stops the kept capture");
            assert_eq!(w.started.len(), 2, "and none is started while held");
        }
        assert!(r.received().is_empty());
        r.hold(false);
        r.run(6_050, 6_050);
        assert_eq!(
            lock(&r.backend).started.last().map(|&(hwnd, _)| hwnd),
            Some(0x60888)
        );
    }

    /// A kept capture that ends by itself during the hold (the item closed) sends no black frame;
    /// the release captures again at once.
    #[test]
    fn a_kept_capture_that_ends_during_a_hold_goes_out_nothing_until_the_release() {
        let mut r = Rig::new(Some(binding()));
        r.show(vec![game_window(0x40666, 6888)]);
        r.run(0, 100);
        assert_eq!(r.deliver(3576, 2268), GateSend::Sent);
        r.received();
        r.hold(true);
        r.run(150, 150);
        lock(&r.backend).finished = true;
        r.run(200, 3_000);
        assert_eq!(lock(&r.backend).stopped, 1);
        assert!(r.received().is_empty(), "no black frame while held");
        assert_eq!(lock(&r.backend).started.len(), 1);
        r.hold(false);
        r.run(3_050, 3_050);
        assert_eq!(
            lock(&r.backend).started.len(),
            2,
            "started again at once on the release"
        );
    }

    /// The background hold with no capture live (black frames, a start that keeps failing): as
    /// before — none is started and no black frame goes out while it lasts, and the release
    /// captures at once, the pause after a failure cut short, or sends a black frame at once.
    #[test]
    fn a_hold_with_no_live_capture_starts_none_and_sends_nothing_until_the_release() {
        let mut r = Rig::new(Some(binding()));
        lock(&r.backend).fail_starts = 1;
        r.show(vec![game_window(0x40666, 6888)]);
        r.run(0, 100);
        assert!(lock(&r.backend).started.is_empty(), "the start failed");
        r.received();
        r.hold(true);
        r.run(150, 150);
        r.run(200, 5_000);
        assert!(r.received().is_empty(), "nothing at all while held");
        assert!(lock(&r.backend).started.is_empty(), "no retry while held");
        r.hold(false);
        r.run(5_050, 5_050);
        assert_eq!(lock(&r.backend).started, vec![(0x40666, 2)], "at once");
        assert_eq!(r.deliver(3576, 2268), GateSend::Sent);
        r.received();

        // A failure just before a short hold: the release does not wait out the pause.
        lock(&r.backend).finished = true;
        r.run(5_100, 5_100);
        assert_eq!(r.received().first().map(|f| f.0), Some(true), "black");
        r.hold(true);
        r.run(5_150, 5_300);
        r.hold(false);
        r.run(5_350, 5_350);
        assert_eq!(
            lock(&r.backend).started.len(),
            2,
            "the pause after the failure is cut short by the release"
        );

        // Held and released with the window gone: black at once on the release.
        r.show(vec![]);
        r.run(5_400, 5_700);
        r.received();
        r.hold(true);
        r.run(5_750, 7_000);
        assert!(r.received().is_empty());
        assert_eq!(r.status.snapshot().state, GameWindowState::Absent);
        r.hold(false);
        r.run(7_050, 7_050);
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
        // Held: nothing from the moment the call returns — not even the next black frame.
        assert!(capturer.hold(true));
        rx.try_iter().count();
        assert!(
            rx.recv_timeout(BLACK_EVERY + Duration::from_millis(300))
                .is_err(),
            "nothing while held"
        );
        // Released: a black frame at once.
        assert!(capturer.hold(false));
        assert!(rx.recv_timeout(Duration::from_secs(2)).is_ok());
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
