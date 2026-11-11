//! Platform-abstraction traits. Concrete implementations live in the
//! `capture`, `encode` and `input` crates so a DXGI/SYSTEM-service variant
//! (path A) can be added later without touching the
//! orchestrator.

use std::sync::mpsc::Sender;

use afklink_protocol::{GameWindowState, InputMessage};

use crate::game::ScreenRect;
use crate::types::{EncodedFrame, Frame};

/// Screen capture source. MVP impl: `WgcCapturer` (Windows.Graphics.Capture).
/// Future: a DXGI Desktop Duplication impl for dirty-rects and unattended use.
pub trait Capturer: Send {
    /// Begin capturing, delivering frames to `sink`. Frames are produced on an
    /// internal thread; the newest frame should win if the consumer is slow.
    ///
    /// Frames arrive already scaled to `target`, which the capturer re-reads per frame so a
    /// mid-session quality change takes effect without restarting the capture. Scaling here
    /// rather than in the encoder is deliberate: it balances the two threads and removes a
    /// full-resolution copy — see `afklink_core::scale`.
    fn start(
        &mut self,
        sink: Sender<Frame>,
        target: std::sync::Arc<crate::quality::QualityTarget>,
    ) -> anyhow::Result<()>;
    /// Stop capturing and release resources.
    fn stop(&mut self);

    /// Has the capture ended by itself?
    ///
    /// `Ok(())` while it is running — including while the screen is still and nothing is being
    /// delivered, which is not an end: a change-driven source is silent on a still desktop by
    /// design. `Err(why)` once it has stopped for good without being asked to: its thread exited,
    /// the item it captured went away, its frame handler failed. After an `Err` nothing more will
    /// arrive until the caller stops it and starts a capture again.
    ///
    /// Polled a few times a second by the pipeline supervisor (`crate::pipeline`), so it must be
    /// cheap and must not block. The default says "running", for a backend that cannot tell — which
    /// is what every backend effectively said before this existed, when a capture thread that died
    /// left the picture frozen with nothing anywhere saying so.
    fn check(&mut self) -> anyhow::Result<()> {
        Ok(())
    }

    /// The background hold (`crate::bg_hold`): stop capturing and delivering (`held`), or start
    /// again (`!held`), while staying alive for what only a running capturer can keep watching.
    ///
    /// True when this capturer did: held, it captures and delivers nothing — no frame, no black
    /// frame — and released, it delivers again at once (a fresh capture's first frame, or a black
    /// one). False when it cannot (the default): the pipeline supervisor stops it for the hold and
    /// starts a fresh one after. The game capturer can, and must — its thread watches the game's
    /// window, which the heartbeat's `game` and the input's scope read all through a hold
    /// (`crate::game::GameCapturer`). Never blocks.
    fn hold(&mut self, held: bool) -> bool {
        let _ = held;
        false
    }
}

/// H.264 encoder. MVP impl: `OpenH264Encoder` (software, Constrained Baseline).
/// Future: Media Foundation / NVENC hardware impls behind the same trait.
pub trait Encoder: Send {
    /// Encode one BGRA frame. Returns `None` if the encoder produced no output
    /// (e.g. a skipped frame). Output is Annex-B H.264.
    fn encode(&mut self, frame: &Frame) -> anyhow::Result<Option<EncodedFrame>>;
    /// Ask the encoder to emit an IDR on the next frame (used on PLI/FIR).
    fn request_keyframe(&mut self);

    /// Set the target bitrate in kbps and the frame rate it is spread over.
    ///
    /// Both, together, because bitrate alone is only half a budget. Rate control allocates bits
    /// per frame as roughly `bitrate / frame_rate`, so an encoder told 1000 kbps at 30 fps while
    /// actually being fed 12 gives each frame a third of what it should have — a softer picture
    /// and more frames declined, for no reason anyone chose. Measured on this project: the same
    /// content at the same target and the same feed rate produced 334 kbps with a mismatched
    /// frame rate against 766 kbps with a matched one, and skipped 25 of 29 frames against 17.
    ///
    /// This is what keeps a manually chosen resolution safe. The bitrate must follow what the
    /// link can carry whatever the user picked: an encoder left targeting 3 Mbps on a 400 kbps
    /// link does not produce a beautiful picture, it produces a queue — and the queue is in front
    /// of the input packets too, so the first thing that breaks is the thing this product is
    /// good at.
    ///
    /// Implementations may ignore small changes; the caller is expected to ask often and let the
    /// encoder decide what is worth acting on. Default is a no-op so a backend that cannot
    /// retarget (a future hardware encoder, a test double) is not forced to pretend.
    fn set_target(&mut self, _kbps: u32, _fps: u32) {}

    /// The quantiser used on the frame just encoded, if the backend can say.
    ///
    /// The quality ladder's primary signal, and the one libwebrtc's `QualityScaler` steers on. A
    /// high QP means rate control has run out of room — the picture is already as coarse as this
    /// many pixels gets and it still does not fit — which is the only condition under which fewer
    /// pixels is the right answer rather than fewer bits.
    ///
    /// Must be read per encoded frame, not polled: implementations report the *last* frame, so a
    /// timer that ticks slower than the frame rate reads one frame repeatedly and lets it decide
    /// the rung on its own.
    ///
    /// `None` by default, and `None` from a backend that has no such number. A ladder that cannot
    /// see QP has to fall back on its other signals rather than pretend.
    fn last_frame_qp(&mut self) -> Option<u32> {
        None
    }

    /// The coarsest quantiser this encoder is allowed to use, if it has one.
    ///
    /// The ladder needs this to tell two situations apart that look identical in every other
    /// number: an encoder comfortably hitting its target, and an encoder that has spent every bit
    /// of quality it has and *still* cannot fit the budget. The second is a rung whose floor
    /// exceeds what it was given, and no budget can fix it — the only remedy is fewer pixels.
    ///
    /// This distinction was got wrong once, expensively. "Production exceeded the budget"
    /// (`spend_ratio > 1.0`) was used to mean "the target was unreachable", and it does not: a
    /// rate controller jitters either side of its aim, so that condition holds on about half of
    /// all healthy ticks. Acting on it shed rungs on a link with an empty queue and a quantiser at
    /// 36 against a guard of 37. The quantiser being *at its ceiling* is the part that was
    /// missing, and only the encoder knows where its ceiling is.
    ///
    /// `None` from a backend with no such concept, and the ladder then simply does not learn a
    /// floor — which is what it did for its whole life before this existed.
    fn max_qp(&self) -> Option<u32> {
        None
    }
}

/// Remote input injection. MVP impl: `SendInputInjector` (WinAPI SendInput).
///
/// An injector owns the *held* state — which buttons and keys it has pressed and not
/// yet released — because it is the only component that knows what it actually sent to
/// the OS. That state is what [`InputInjector::release_all`] unwinds.
pub trait InputInjector: Send + Sync {
    /// Execute a single decoded input event.
    fn inject(&self, event: &InputMessage) -> anyhow::Result<()>;

    /// A session started; called once before any [`Self::inject`] for it.
    ///
    /// An injector that talks to an OS device only while a viewer is connected opens the device
    /// here, so that between sessions nothing is held open and — since the device is shut — nothing
    /// can be sent. Backends with no such resource (WinAPI `SendInput`, the bench's no-op) keep the
    /// empty default.
    ///
    /// Sessions can overlap ([`crate::Agent`] holds a map of them), so an implementation that opens
    /// a shared device reference-counts: it opens on the first `begin_session` and closes on the
    /// last matching [`Self::end_session`]. A late `end_session` from a session that has already
    /// finished must not close a device a newer session opened — the count, not any single session,
    /// decides.
    fn begin_session(&self) {}

    /// A session ended; called once, after that session's final [`Self::release_all`].
    ///
    /// The counterpart of [`Self::begin_session`]: the reference-counting backend releases anything
    /// still held for this session and, when this was the last session, closes the device. The
    /// empty default suits a backend that opened nothing.
    fn end_session(&self) {}

    /// Release every button and key this injector is currently holding down.
    ///
    /// Called on session end, on the kill switch, and after an input silence timeout —
    /// three independent triggers, because each one alone is defeatable. A viewer that
    /// is killed mid-drag sends nothing at all, so the agent cannot rely on being told.
    /// Idempotent, and a no-op when nothing is held.
    fn release_all(&self);

    /// Whether an absolute pointer move handed to [`Self::inject`] really moves the pointer on the
    /// screen being captured.
    ///
    /// The pipeline supervisor reads pointer moves that no frame follows as a stalled capture
    /// (`crate::pipeline::PointerProbe`: WGC composites the cursor, so a move is a change it must
    /// deliver). That only holds when the move happens. An injector that injects nothing — the
    /// bench's `--no-input` — says `false`, and the evidence is not gathered, so a still stretch of
    /// the bench's recorded screen is not "restarted" for pointer moves that never took place.
    /// `true` by default.
    fn moves_pointer(&self) -> bool {
        true
    }

    /// Where the OS cursor is right now, for the viewer's cursor marker (`cp`, see
    /// `afklink_protocol::cursor`), and which numbered relative moves that position does not show
    /// yet ([`CursorSample::unshown`]).
    ///
    /// Polled about thirty times a second while a session runs, so it must be cheap and must not
    /// block for longer than a planner's look at the cursor. `None` from a backend that cannot tell
    /// (the default, and the bench's no-op injector), in which case the agent sends no cursor
    /// reports and the viewer draws no marker.
    fn cursor(&self) -> Option<CursorSample> {
        None
    }

    /// What the cursor of `sample` looks like and what it is over ([`CursorShape`]), for the cursor
    /// report's one line per new shape a session (`crate::cursor_report`). Asked once per new
    /// [`CursorSample::shape`], never per poll; may take a few Win32 reads. `None` from a backend
    /// that cannot tell (the default).
    fn cursor_shape(&self, sample: &CursorSample) -> Option<CursorShape> {
        let _ = sample;
        None
    }

    /// One event, for a session whose input may go only where `scope` says (`crate::game`, «only
    /// the game window»).
    ///
    /// [`InputScope::Desktop`] is [`Self::inject`]. In [`InputScope::Game`] the injector maps `m`
    /// and `r.x/y` into the game's client area, keeps the cursor in it, injects only while the game's
    /// window is the foreground window, blocks the keys that escape it and types text through the
    /// driver — see `afklink_input`'s game guard. The default, for an injector that cannot confine
    /// anything (the bench's no-op, test doubles), fails closed: in game scope only releases go
    /// through, so nothing it cannot confine is ever injected and nothing it holds can stick.
    fn inject_scoped(&self, event: &InputMessage, scope: &InputScope) -> anyhow::Result<()> {
        match scope {
            InputScope::Desktop => self.inject(event),
            InputScope::Game(_) if is_release(event) => self.inject(event),
            InputScope::Game(_) => {
                tracing::trace!(
                    "input dropped: game-only mode, and this injector cannot confine input"
                );
                Ok(())
            }
        }
    }

    /// Whether a press — a key-down or a button-down — handed to [`Self::inject_scoped`] with
    /// `scope` can leave anything held on the PC. A session's own ledger of what it holds
    /// (`crate::input_session`, the source of its own release) notes a press only when this says
    /// it can: a press that goes nowhere — a code no key has, or game-only mode on an injector that
    /// cannot confine input — never fills it. Called once per press under the session's gate, so
    /// it must be cheap and must not block: a pure look at the event.
    ///
    /// When in doubt, true: a press noted that held nothing costs one harmless key-up later; one
    /// that held something and went unnoted would stay down past the session's own release. The
    /// default answers for the default [`Self::inject_scoped`] — in game scope it drops every press,
    /// on the desktop it may hold anything — so an injector that overrides that overrides this too.
    fn press_may_hold(&self, event: &InputMessage, scope: &InputScope) -> bool {
        let _ = event;
        !matches!(scope, InputScope::Game(_))
    }

    /// Game-only mode, between the viewer's events: is the game's window the foreground window?
    ///
    /// Polled by the session a few times a second (`crate::game_input`), so a window that takes the
    /// front while the viewer is idle is seen at once: an injector that holds keys or buttons
    /// releases them the moment the game loses the front (a held key would otherwise auto-repeat
    /// into the other window), and the heartbeat says `unfocused`. Never brings the game forward —
    /// that is tried only on the viewer's input. Cheap and non-blocking but for that release.
    /// [`GameFocus::Unknown`] by default: an injector that cannot tell.
    fn game_focus(&self, game: &GameScope) -> GameFocus {
        let _ = game;
        GameFocus::Unknown
    }

    /// Whether the viewer's input reaches the window in front, and whether the input driver is
    /// there to make it ([`InputReach`]): read by each session's heartbeat once a second for its
    /// `no_driver` and `input_blocked`, and by the orchestrator at a session's start and end
    /// (`crate::input_reach`). Cheap — a lock and a copy. The default, for an injector that cannot
    /// tell (the bench's no-op, test doubles, `SendInput` off Windows): nothing known, nothing
    /// blocked.
    fn input_reach(&self) -> InputReach {
        InputReach::default()
    }

    /// The process that owns the window `target` names, right now, and whether that window never
    /// takes the front: for the guard that keeps a guest's input off AFKLink's own windows
    /// (`crate::own_windows`). The process id is compared with this process's there, nothing
    /// more: no process is opened for it.
    ///
    /// [`WindowTarget::UnderPress`] is judged where a press sent now would land — the pixel the
    /// move just sent is taking the cursor to, as game-only mode's press check judges it — and by
    /// the top-level window there (a child window another process draws into ours, WebView2's, is
    /// ours; [`WindowOwner::no_activate`] is that top-level window's `WS_EX_NOACTIVATE`). Called for
    /// every press, key-down, wheel and text of a guest's session and a few times a second between
    /// them, so cheap: window-manager reads only. `None` when it cannot be read — no window there, a
    /// window gone — and by default: an injector that cannot tell (the bench's no-op, test doubles,
    /// `SendInput` off Windows).
    fn window_owner(&self, target: WindowTarget) -> Option<WindowOwner> {
        let _ = target;
        None
    }

    /// Whether Windows' Mouse Keys is on (`SPI_GETMOUSEKEYS`): the numeric keypad then moves and
    /// clicks the pointer, so a key is a click wherever the pointer is (`crate::own_windows`). Read
    /// for a guest's key-downs; one system call. `None` when it cannot be read, and by default.
    fn mouse_keys_on(&self) -> Option<bool> {
        None
    }
}

/// The window an input event would reach, as [`InputInjector::window_owner`] reads it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WindowOwner {
    /// The process that owns it (its top-level window's, for [`WindowTarget::UnderPress`]).
    pub pid: u32,
    /// Its top-level window has `WS_EX_NOACTIVATE`: clicking it does not bring it forward — the
    /// on-screen keyboard is one, and what it types goes to the window that has the front. Read for
    /// [`WindowTarget::UnderPress`] only; false otherwise.
    pub no_activate: bool,
}

/// Which window an input event would reach ([`InputInjector::window_owner`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowTarget {
    /// The foreground window: where keys, text and combos go.
    Foreground,
    /// The window under the pixel a mouse button pressed now would land on: where a press and the
    /// wheel go, whichever window has the front — a click on a window behind brings it forward and
    /// lands on it.
    UnderPress,
}

impl WindowTarget {
    /// For log lines.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Foreground => "foreground",
            Self::UnderPress => "under_press",
        }
    }
}

/// The input driver (FakerInput, the virtual HID mouse and keyboard), as the injector sees it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DriverPresence {
    /// This injector cannot tell, or this PC cannot have the driver (not Windows x64).
    #[default]
    Unknown,
    /// Open for the live sessions: input goes through it where `SendInput` cannot.
    Open,
    /// Not open — not installed, or installed and not working: input goes by `SendInput` alone.
    Missing,
}

impl DriverPresence {
    /// For log lines.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Open => "open",
            Self::Missing => "missing",
        }
    }
}

/// Whether the viewer's input reaches the window in front ([`InputInjector::input_reach`]).
///
/// The counts are the injector's since the process started, never reset, so whoever reads them at a
/// session's start and end can say what happened in between (`crate::input_reach`): concurrent
/// sessions share one desktop and one injector, and see each other's presses in them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct InputReach {
    pub driver: DriverPresence,
    /// The viewer's presses are being dropped right now: three in a row did not reach the window in
    /// front within two seconds (it runs as administrator, the agent does not, the driver is not
    /// open: Windows' UIPI), and the last of them was less than ten seconds ago.
    pub blocked: bool,
    /// Presses (clicks, keys, text) that did not reach the window in front.
    pub lost: u64,
    /// Presses that did: through the driver, or by `SendInput` to a window it reaches.
    pub delivered: u64,
    /// How often `blocked` began.
    pub episodes: u64,
}

/// The most distinct keys one session may hold at once (KB-6). Ten fingers, and a driver that
/// holds six keys besides the modifiers: a viewer past this is not typing, it is filling the
/// agent's memory and the length of its own release (`InputSession::release_own`). A press of a
/// new key past it is refused — not injected, not noted — and the keys already held stay as they
/// are; a repeat of a held key, and every release, still go. Enforced per session by
/// `crate::input_session`; public so the input backend can size its process-wide books by it.
pub const MAX_HELD_KEYS: usize = 32;

/// Releases: a button up, a key up, `ra`. They always go through, whatever limits input — a release
/// is what keeps something from sticking.
pub fn is_release(event: &InputMessage) -> bool {
    matches!(
        event,
        InputMessage::Up { .. } | InputMessage::Key { d: 0, .. } | InputMessage::ReleaseAll
    )
}

/// Where a session's input may go.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputScope {
    /// Game-only mode is off: the primary monitor, as always.
    Desktop,
    /// Game-only mode is on: the game's window and nothing else.
    Game(GameScope),
}

impl InputScope {
    /// The game's window when the scope is the game's and the window can take input.
    pub fn game_window(&self) -> Option<GameInputWindow> {
        match self {
            Self::Desktop => None,
            Self::Game(game) => game.window,
        }
    }
}

/// The game window as input sees it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GameScope {
    /// The finder's state of the window (`shown` whenever `window` is `Some`).
    pub state: GameWindowState,
    /// `Some` only while the window is shown and captured, and its process is known: where input
    /// goes. `None` — absent, starting, minimized, not captured yet — and nothing but releases is
    /// injected.
    pub window: Option<GameInputWindow>,
}

/// The game's window, for input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GameInputWindow {
    pub hwnd: usize,
    /// The process that owns it, from the window list (never opened for it): a press lands only on
    /// a window of this process.
    pub pid: u32,
    /// The part of its client area the picture shows, on screen, physical pixels, right and bottom
    /// exclusive — the capture's crop placed back on screen (`crate::game::ClientCrop::on_screen`):
    /// the picture the viewer sees, which `m`, `r.x/y` and `cp` are fractions of.
    pub client: ScreenRect,
}

/// Whether the game's window has the front, as the injector sees it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GameFocus {
    /// It is the foreground window: input goes to it.
    Focused,
    /// Another window is in front: input is held back (releases pass), and the heartbeat says
    /// `unfocused`.
    Unfocused,
    /// The window cannot take input (absent, starting, minimized, not captured yet).
    NotShown,
    /// This injector cannot tell.
    Unknown,
}

impl GameFocus {
    /// For log lines.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Focused => "focused",
            Self::Unfocused => "unfocused",
            Self::NotShown => "not_shown",
            Self::Unknown => "unknown",
        }
    }
}

/// One reading of the OS cursor, in the captured screen's own pixels.
///
/// Raw integers rather than fractions, so "has it moved" is an exact comparison and the
/// normalization lives in one place (the agent's cursor reporter).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CursorSample {
    /// Position relative to the captured screen's top-left corner. May lie outside
    /// `0..width` / `0..height` when the cursor is on another monitor.
    pub x: i32,
    pub y: i32,
    /// The captured screen's size in the same pixels. Non-positive means unknown.
    pub width: i32,
    pub height: i32,
    /// The OS says the cursor is drawn (an application can hide it, and touch input suppresses
    /// it).
    pub visible: bool,
    /// The cursor's shape as the OS names it (`HCURSOR`), 0 for none or when the injector cannot
    /// say. Only compared: a value not seen before this session gets one line describing it
    /// ([`InputInjector::cursor_shape`]).
    pub shape: usize,
    /// The lowest relative-move number (`r.s`) handed to the injector whose effect this position
    /// does not show yet — its report is still on its way to the cursor (Windows shows a HID report
    /// about 2 ms after it is written), or it waits behind other input — or `None` when every
    /// numbered move shows, none was numbered, or the injector cannot tell. The report's `ack`
    /// stays below it (`crate::cursor_report`): a report must not claim a move its position does
    /// not include, or the viewer takes the move off its marker and the marker steps back.
    pub unshown: Option<u32>,
}

/// What the cursor looks like and what it is over: the cursor report's line for a new shape
/// (`crate::cursor_report`). Read once per new shape; whatever could not be read says why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CursorShape {
    /// The picture: its size, the hotspot and where it draws.
    pub image: Result<CursorImage, String>,
    /// The window under the cursor when the shape was first seen.
    pub under: Result<CursorWindow, String>,
}

/// A cursor's picture (`GetIconInfo`), in its own pixels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CursorImage {
    pub width: i32,
    pub height: i32,
    /// The hotspot: the picture's pixel a click lands on, and the one `GetCursorInfo`'s position is.
    pub hotspot_x: i32,
    pub hotspot_y: i32,
    /// A colour cursor (`hbmColor`), or a monochrome one (an AND/XOR mask pair).
    pub color: bool,
    /// The drawn pixels' box relative to the hotspot — left, top, right, bottom, inclusive; `(0, 0)`
    /// is the hotspot's pixel — or `None` when the picture draws nothing or its pixels could not be
    /// read (the reader says which).
    pub drawn: Option<(i32, i32, i32, i32)>,
}

/// The window under the cursor, for the shape's line: whose it is, and how Windows scales it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CursorWindow {
    pub hwnd: usize,
    /// Its process's exe file name, or why it is unknown.
    pub exe: String,
    pub class: String,
    /// Its DPI awareness in words (`unaware`, `system aware`, `per-monitor aware`, …): an unaware
    /// window on a scaled monitor is drawn stretched by Windows, its own cursor too.
    pub awareness: &'static str,
    /// The DPI it draws at (`GetDpiForWindow`; 96 for an unaware one), and its monitor's; 0 when
    /// unknown.
    pub dpi: u32,
    pub monitor_dpi: u32,
}

impl CursorSample {
    /// The cursor is over the captured screen.
    pub fn on_screen(&self) -> bool {
        self.width > 0
            && self.height > 0
            && (0..self.width).contains(&self.x)
            && (0..self.height).contains(&self.y)
    }

    /// Position as fractions of the captured screen, clamped to `[0..1]` — the `m` convention.
    /// `None` while the screen size is unknown.
    pub fn normalized(&self) -> Option<(f64, f64)> {
        if self.width <= 0 || self.height <= 0 {
            return None;
        }
        let x = (f64::from(self.x) / f64::from(self.width)).clamp(0.0, 1.0);
        let y = (f64::from(self.y) / f64::from(self.height)).clamp(0.0, 1.0);
        Some((x, y))
    }
}
