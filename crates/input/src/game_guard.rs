//! «Only the game window», the injector's half: what each viewer event may do while the owner limits
//! the viewer to the game's window (the session's half is `afklink_core::game_input`). The backend
//! asks this guard, per event and with its scope ([`InputScope`]), before either path (HID or
//! `SendInput`) sees it: release everything held, drop the event, or pass it on (text rewritten to
//! the driver's typing). Moves are confined to the game's client area by the cursor-sync planner
//! (`crate::cursor_sync::Space`).
//!
//! ## The rules, in game-only mode
//!
//! - **Only while the game has the front** (`GetForegroundWindow`, per event and a few times a
//!   second). Otherwise moves, presses, new key-downs, the wheel, text and combos are dropped;
//!   releases (`u`, key-up, `ra`) always pass, and everything held is released the moment the game
//!   loses the front (a held key would auto-repeat into the other window). At most every
//!   [`FOCUS_ATTEMPT_EVERY`] the game is asked back (`SetForegroundWindow`; Windows usually refuses
//!   and flashes its taskbar button); no other window is ever minimized or touched. While the window
//!   is not shown only releases pass.
//! - **A press lands only on the game.** The window under the pixel a button press will land on
//!   (`WindowFromPoint` at the planner's target), or its top-level window, must belong to the game's
//!   process — compared by process id, no process opened. An always-on-top window swallows no click.
//! - **No escape keys.** Win (alone or in any combination), Alt+Tab, Alt+Esc, Ctrl+Esc and
//!   Ctrl+Shift+Esc are dropped before injection, whichever key comes second, as is every `combo`
//!   (`ctrl_alt_del`). A dropped key-down's release is dropped with it, and a release of a key that
//!   went through always passes, so no modifier is ever stranded.
//! - **Alt+F4 passes, for everyone** — owner and guest, in every mode. It may close the game; it is
//!   also how a stuck window is closed. Each one let through is logged at `debug`.
//! - **Text goes by the driver's typing**: the game's chat hears only HID keys.
//!
//! Outside game-only mode the guard only routes text: to the driver's typing when the foreground
//! window runs elevated and the agent does not (UIPI blocks `SendInput`'s Unicode) and the driver is
//! open, else Unicode ([`Reach`]). It still drops the release of a key it blocked while the mode was
//! on. An unmarked wheel takes the same [`Reach`] decision in the FakerInput router when it is sent.
//!
//! ## Logs
//!
//! `debug`: every change of where input may go, with what was held then (`released=true` says
//! releases were sent; `held_*` say what was held); each focus attempt and Windows' answer; each
//! blocked key or combo with its source (`src`); each Alt+F4 let through; each dropped press with
//! why; every change of the text's route; one `game input` line a second while anything was dropped
//! or blocked. `trace`: every event held back. The guard also feeds the key log (`crate::key_log`),
//! which names only the viewer's own keys (`k.src`) or the combination a line is about.

use std::collections::BTreeSet;
use std::time::{Duration, Instant};

use afklink_core::traits::{GameFocus, GameInputWindow, GameScope, InputScope};
use afklink_protocol::{GameWindowState, InputMessage, KeySource};

use crate::cursor_sync::{Elevation, ForegroundInfo};
use crate::key_log::{self, HeldNow, KeyLog};
use crate::line_gate::LineGate;

#[cfg(windows)]
pub(crate) mod system;
#[cfg(test)]
mod tests;

/// The game is asked back to the front at most this often, and only on the viewer's input: each
/// refused attempt flashes the game's taskbar button.
pub(crate) const FOCUS_ATTEMPT_EVERY: Duration = Duration::from_secs(2);

/// The aggregate line: one per this long while anything happens.
const STATS_EVERY: Duration = Duration::from_secs(1);

/// How many sessions can feed the guard's books at once. The server keeps at most one live session
/// a device — a new connect supersedes the old (`createSession` in the backend's
/// `server/src/signaling/sessions.ts`: "At most one live session per device", ending the old one
/// `superseded` before the new is created). The agent does not enforce that itself: it keeps a map
/// of live sessions, and the old one's end and the new one's start overlap — the end is sent
/// first on the same socket, but a stuck end does not keep the next from starting (`agent.rs`, "A
/// session's start and end never hold the runtime"). The ending session's gate refuses its input
/// the moment its end is decided, so it adds nothing more; what it booked stays until its close
/// releases everything (`released`). So two at once: the ending one's books and the new one's.
const LIVE_SESSIONS_AT_ONCE: usize = 2;

/// The most keys the guard books as held, or as blocked, at once — for every session of the process
/// together (KB-6): each session holds at most [`afklink_core::traits::MAX_HELD_KEYS`] (its own
/// gate refuses a new key past that), and [`LIVE_SESSIONS_AT_ONCE`] can overlap. The guard's codes
/// are only those a key maps to (the backend refuses the rest before it asks), so this is never
/// reached but by a viewer filling the books — or by more sessions than the server allows, where it
/// fails safe: a press of a new key past it is dropped (its release passes, as every release
/// does), and the first is warned once until the guard resets.
pub(crate) const MAX_GUARD_KEYS: usize =
    afklink_core::traits::MAX_HELD_KEYS * LIVE_SESSIONS_AT_ONCE;

/// The Windows key, by every name a viewer uses for it.
const META: [&str; 4] = ["MetaLeft", "MetaRight", "OSLeft", "OSRight"];
const ALT: [&str; 2] = ["AltLeft", "AltRight"];
const CTRL: [&str; 2] = ["ControlLeft", "ControlRight"];
const SHIFT: [&str; 2] = ["ShiftLeft", "ShiftRight"];

fn is_meta(code: &str) -> bool {
    META.contains(&code)
}

/// The window at a screen pixel (`WindowFromPoint`), and its top-level window.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct WindowAt {
    pub(crate) hwnd: usize,
    /// 0 when it could not be read.
    pub(crate) pid: u32,
    /// Its top-level window (`GetAncestor(GA_ROOT)`): a child window of another process embedded in
    /// the game's window is the game's.
    pub(crate) root: usize,
    pub(crate) root_pid: u32,
}

/// What the guard reads of the PC — behind a trait, so the tests drive a fake one.
pub(crate) trait GuardHost {
    /// `GetForegroundWindow`: 0 for none.
    fn foreground(&mut self) -> usize;
    /// The process that owns a window (`GetWindowThreadProcessId`: nothing opened); 0 when it
    /// cannot be read.
    fn window_pid(&mut self, window: usize) -> u32;
    /// A window's process and exe, for the log (opened with limited information only; never asked
    /// for the game's own windows).
    fn describe(&mut self, window: usize) -> ForegroundInfo;
    /// `SetForegroundWindow`: whether Windows said yes.
    fn set_foreground(&mut self, window: usize) -> Result<bool, String>;
    /// `WindowFromPoint` at this pixel of the virtual screen.
    fn window_at(&mut self, px: i32, py: i32) -> Result<WindowAt, String>;
    /// Where a mouse button pressed now would land (the planner's: see
    /// `CursorSync::press_target`). `None` when the cursor cannot be read.
    fn press_target(&mut self) -> Option<(i32, i32)>;
    /// The foreground window's elevation, afresh. `None` when it cannot be read.
    fn foreground_elevation(&mut self) -> Option<Elevation>;
    /// The driver is open: text can be typed through it.
    fn driver_open(&self) -> bool;
    /// Mouse buttons held down on either path, from the paths' own books (nothing read from
    /// Windows): for the transition line.
    fn held_buttons(&mut self) -> u32;
}

/// Where a key message came from in the viewer (`k.src`); `None` for any other message.
fn key_src(event: &InputMessage) -> Option<KeySource> {
    match event {
        InputMessage::Key { src, .. } => *src,
        _ => None,
    }
}

/// Would `code` going down now — with `held` down on the PC through us, and `blocked` swallowed —
/// make an escape from the game's window? Its name if so. Whichever key of a combination comes
/// second is the one blocked, so the combination never exists on the PC.
///
/// One list for every session: Alt+F4 is not on it, for a guest either — see [`alt_f4`].
fn escape(code: &str, held: &BTreeSet<String>, blocked: &BTreeSet<String>) -> Option<&'static str> {
    let down = |codes: &[&str]| codes.iter().any(|c| held.contains(*c));
    if is_meta(code) {
        return Some("Win");
    }
    // The viewer holds Win (swallowed, or through us before the mode was on): the whole
    // combination is the viewer's Win shortcut, and none of it goes.
    if META
        .iter()
        .any(|c| held.contains(*c) || blocked.contains(*c))
    {
        return Some("Win+key");
    }
    let (alt, ctrl, shift) = (down(&ALT), down(&CTRL), down(&SHIFT));
    match code {
        "Tab" if alt => Some("Alt+Tab"),
        "Escape" if ctrl && shift => Some("Ctrl+Shift+Esc"),
        "Escape" if ctrl => Some("Ctrl+Esc"),
        "Escape" if alt => Some("Alt+Esc"),
        "AltLeft" | "AltRight" if down(&["Tab"]) => Some("Alt+Tab"),
        "AltLeft" | "AltRight" if down(&["Escape"]) => Some("Alt+Esc"),
        "ControlLeft" | "ControlRight" if down(&["Escape"]) => Some("Ctrl+Esc"),
        _ => None,
    }
}

/// Whether `code` would be a new entry of `book` (the guard's held or blocked keys) past
/// [`MAX_GUARD_KEYS`].
fn over_cap(book: &BTreeSet<String>, code: &str) -> bool {
    book.len() >= MAX_GUARD_KEYS && !book.contains(code)
}

/// Whether `code` going down now, with `held` down through us, makes Alt+F4 — which passes, for a
/// guest too, and is logged, since it may close the game.
fn alt_f4(code: &str, held: &BTreeSet<String>) -> bool {
    match code {
        "F4" => ALT.iter().any(|c| held.contains(*c)),
        "AltLeft" | "AltRight" => held.contains("F4"),
        _ => false,
    }
}

/// Where input may go, as the guard last looked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Look {
    /// Game-only mode is off.
    Desktop,
    /// The game's window has the front.
    Focused { game: usize },
    /// Another window has the front (0: none has). `game_pid`: the game's process, so a window of
    /// its own (a dialog) is told apart without opening anything.
    Away {
        game: usize,
        game_pid: u32,
        foreground: usize,
    },
    /// The game's window cannot take input.
    NotShown { state: GameWindowState },
}

impl Look {
    fn name(self) -> &'static str {
        match self {
            Self::Desktop => "desktop",
            Self::Focused { .. } => "focused",
            Self::Away { .. } => "unfocused",
            Self::NotShown { .. } => "not_shown",
        }
    }
}

/// How text is sent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TextRoute {
    /// `SendInput`'s Unicode.
    Unicode,
    /// The driver's typing (`text.game`): real key presses on the PC's layout.
    Driver,
}

impl TextRoute {
    fn name(self) -> &'static str {
        match self {
            Self::Unicode => "unicode",
            Self::Driver => "driver",
        }
    }
}

/// What the foreground window's elevation means for input `SendInput` carries by default outside
/// game-only mode — Unicode text (this guard) and the smooth wheel (the FakerInput router): one
/// decision for both, each with its own words for the log.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Reach {
    /// The window runs elevated and the agent does not, and the driver is open: Windows' UIPI takes
    /// `SendInput` there, answers success and drops it, so the input goes through the driver.
    Driver,
    /// The same, but the driver is not open: `SendInput` all the same, which Windows may drop there.
    ElevatedNoDriver,
    /// The window runs elevated, and so does the agent: `SendInput` reaches it.
    BothElevated,
    /// An ordinary window: `SendInput`.
    Ordinary,
    /// The window's elevation (or the agent's) cannot be read: `SendInput`, as before.
    Unknown,
}

impl Reach {
    /// The decision, from the foreground window's elevation (looked at afresh by the caller) and
    /// whether the driver is open.
    pub(crate) fn of(elevation: Option<&Elevation>, driver_open: bool) -> Self {
        match elevation {
            Some(e) if e.blocks_sendinput() && driver_open => Self::Driver,
            Some(e) if e.blocks_sendinput() => Self::ElevatedNoDriver,
            Some(e) if e.foreground => Self::BothElevated,
            Some(_) => Self::Ordinary,
            None => Self::Unknown,
        }
    }
}

const TEXT_GAME_ONLY: &str =
    "game-only mode: text goes to the game by the driver's typing, whatever the viewer's mode";
const TEXT_MARKED_GAME: &str = "the viewer's game mode marked it (text.game)";
const TEXT_ELEVATED: &str = "the foreground window runs elevated and the agent does not: Unicode \
                             SendInput cannot reach it (UIPI), so it is typed through the driver";
const TEXT_ELEVATED_NO_DRIVER: &str = "the foreground window runs elevated, but the driver is not \
                                       open: Unicode, which Windows may drop there (UIPI)";
const TEXT_BOTH_ELEVATED: &str =
    "the foreground window runs elevated, and so does the agent: Unicode reaches it";
const TEXT_ORDINARY: &str = "an ordinary window: Unicode SendInput";
const TEXT_UNKNOWN: &str = "the foreground window's elevation cannot be read: Unicode SendInput";

/// The per-second aggregate.
#[derive(Debug, Default)]
struct Stats {
    since: Option<Instant>,
    moves_dropped: u32,
    presses_dropped: u32,
    /// Presses dropped because the window under them is not the game's.
    presses_off_game: u32,
    keys_dropped: u32,
    keys_blocked: u32,
    /// The wheel, text and combos held back.
    other_dropped: u32,
    focus_attempts: u32,
    /// Attempts after which the game had the front.
    focus_won: u32,
    /// Everything held released because the game lost the front.
    releases: u32,
}

impl Stats {
    fn any(&self) -> bool {
        self.moves_dropped
            + self.presses_dropped
            + self.presses_off_game
            + self.keys_dropped
            + self.keys_blocked
            + self.other_dropped
            + self.focus_attempts
            + self.releases
            > 0
    }
}

/// What the guard says about one event.
#[derive(Debug, PartialEq)]
pub(crate) struct Admission {
    /// Release everything held on both paths first: the game just lost the front (or game-only mode
    /// just began, and what the viewer held was the desktop's).
    pub(crate) release: bool,
    /// What to inject — the event, or text rewritten to the driver's typing — or nothing.
    pub(crate) event: Option<InputMessage>,
}

/// The guard: one per process-wide backend, asked for every event of every session.
#[derive(Debug, Default)]
pub(crate) struct GameGuard {
    /// Keys the viewer pressed through us and has not released (DOM codes), in any mode: what a
    /// combination is judged against.
    held: BTreeSet<String>,
    /// Keys whose press was blocked: their release is dropped with it.
    blocked: BTreeSet<String>,
    look: Option<Look>,
    attempted_at: Option<Instant>,
    text: Option<(TextRoute, &'static str)>,
    stats: Stats,
    /// Which keys reached the PC, for the log (`crate::key_log`).
    keys: KeyLog,
    /// The key being judged makes Alt+F4, let through: the recorder is written out once it is noted.
    alt_f4: bool,
    /// The per-event lines (a key or combo blocked, a press dropped) a flood must not repeat.
    lines: LineGate,
    /// A press dropped at [`MAX_GUARD_KEYS`] has been warned about since the guard's reset.
    cap_warned: bool,
}

impl GameGuard {
    /// The first session begins or the last ends: nothing carried over.
    pub(crate) fn reset(&mut self, why: &'static str, now: Instant) {
        self.flush(now, why);
        self.keys.flush(now, why);
        *self = Self::default();
        tracing::trace!(why, "game input: guard reset");
    }

    /// Everything held was released (`ra`, silence, the session's end): no key is down through us,
    /// and a later release of a blocked key has nothing to be consistent with.
    pub(crate) fn released(&mut self) {
        self.held.clear();
        self.blocked.clear();
        self.keys.released();
    }

    /// The sizes of the guard's books — held, blocked, and its key log's keys down — for the
    /// flood tests (KB-6).
    #[cfg(test)]
    pub(crate) fn books(&self) -> (usize, usize, usize) {
        (self.held.len(), self.blocked.len(), self.keys.down_len())
    }

    /// Put codes in the held and blocked books directly, for tests that check what leaves them.
    #[cfg(test)]
    pub(crate) fn book(&mut self, held: &[&str], blocked: &[&str]) {
        self.held.extend(held.iter().map(|c| (*c).to_owned()));
        self.blocked.extend(blocked.iter().map(|c| (*c).to_owned()));
    }

    /// The key log's line for the second, if it is due — between events too (the cursor poll), so
    /// the last second of a burst of keys is said on time.
    pub(crate) fn flush_keys_if_due(&mut self, now: Instant) {
        self.keys.flush_if_due(now);
    }

    /// One viewer event under `scope`.
    pub(crate) fn admit(
        &mut self,
        event: &InputMessage,
        scope: &InputScope,
        host: &mut dyn GuardHost,
        now: Instant,
    ) -> Admission {
        self.flush_if_due(now);
        self.keys.flush_if_due(now);
        let (look, release) = self.look(scope, host, now);
        self.alt_f4 = false;
        let admitted = self.decide(event, look, scope.game_window(), host, now);
        if let InputMessage::Key { d, code, src, .. } = event {
            // After the guard's word, so the key log holds what reached the PC.
            self.keys.note(code, *d == 1, *src, admitted.is_some(), now);
            if std::mem::take(&mut self.alt_f4) {
                self.keys.dump("Alt+F4 let through to the game", now);
            }
        }
        Admission {
            release,
            event: admitted,
        }
    }

    /// Between events (the session's focus watch): where the game stands, and whether everything
    /// held must be released now. Never asks the game back to the front.
    pub(crate) fn watch(
        &mut self,
        game: &GameScope,
        host: &mut dyn GuardHost,
        now: Instant,
    ) -> (GameFocus, bool) {
        self.flush_if_due(now);
        self.keys.flush_if_due(now);
        let (look, release) = self.look(&InputScope::Game(*game), host, now);
        let focus = match look {
            Look::Focused { .. } => GameFocus::Focused,
            Look::Away { .. } => GameFocus::Unfocused,
            Look::NotShown { .. } => GameFocus::NotShown,
            Look::Desktop => GameFocus::Unknown,
        };
        (focus, release)
    }

    /// Look at where input may go now; say a change, and whether it calls for releasing everything
    /// held: when game-only mode begins (what was held was the desktop's), and when the game loses
    /// the front or stops being shown (a held key would auto-repeat into the other window).
    fn look(&mut self, scope: &InputScope, host: &mut dyn GuardHost, now: Instant) -> (Look, bool) {
        let next = match scope {
            InputScope::Desktop => Look::Desktop,
            InputScope::Game(GameScope {
                window: None,
                state,
            }) => Look::NotShown { state: *state },
            InputScope::Game(GameScope {
                window: Some(window),
                ..
            }) => {
                let foreground = host.foreground();
                if foreground == window.hwnd {
                    Look::Focused { game: window.hwnd }
                } else {
                    Look::Away {
                        game: window.hwnd,
                        game_pid: window.pid,
                        foreground,
                    }
                }
            }
        };
        let before = self.look.replace(next);
        if before == Some(next) {
            return (next, false);
        }
        let release = match (before, next) {
            (_, Look::Desktop) | (None, _) => false,
            (Some(Look::Desktop), _) => true,
            (Some(Look::Focused { .. }), Look::Away { .. } | Look::NotShown { .. }) => true,
            _ => false,
        };
        // What is down through us at this moment, before the release forgets it: `released` alone
        // says releases were sent, not that anything was held.
        let held = self.keys.held_now(host.held_buttons());
        if release {
            self.held.clear();
            self.keys.released();
            self.stats.since.get_or_insert(now);
            self.stats.releases += 1;
        }
        self.say(before, next, release, &held, host);
        // The game's window stops taking input — it lost the front, or is not shown any more (gone,
        // minimized, not captured): what were our last keys before it? (A game can quit a second
        // after the viewer's key cells; the log must say which keys.)
        let stops = match (before, next) {
            (Some(Look::Focused { .. }), Look::Away { .. }) => {
                Some("the game's window lost the front")
            }
            (Some(Look::Focused { .. } | Look::Away { .. }), Look::NotShown { .. }) => {
                Some("the game's window is no longer shown (gone, minimized or not captured)")
            }
            _ => None,
        };
        if let Some(why) = stops {
            self.keys.dump(why, now);
        }
        (next, release)
    }

    fn say(
        &self,
        before: Option<Look>,
        next: Look,
        released: bool,
        held: &HeldNow,
        host: &mut dyn GuardHost,
    ) {
        let from = before.map_or("-", Look::name);
        match next {
            Look::Desktop => tracing::debug!(
                from,
                "game input: game-only mode is off: input goes to the desktop as before"
            ),
            // The game's own process is never opened for this line: its window and nothing more.
            Look::Focused { game } => tracing::debug!(
                target: crate::KEY_NAMES_TARGET,
                from,
                window = %format!("{game:#x}"),
                released,
                held_keys = held.keys,
                held_mods = held.mods,
                held_buttons = held.buttons,
                held_ours = %held.ours,
                held_other = held.other,
                "game input: the game's window has the front: input goes to it (released=true: \
                 releases were sent whether or not anything was held; held_* say what was)"
            ),
            Look::Away {
                game,
                game_pid,
                foreground,
            } => {
                if foreground == 0 {
                    tracing::debug!(
                        target: crate::KEY_NAMES_TARGET,
                        from,
                        game = %format!("{game:#x}"),
                        released,
                        held_keys = held.keys,
                        held_mods = held.mods,
                        held_buttons = held.buttons,
                        held_ours = %held.ours,
                        held_other = held.other,
                        "game input: no window has the front: input is held back (releases \
                         pass; released=true: releases were sent whether or not anything was \
                         held; held_* say what was)"
                    );
                } else if host.window_pid(foreground) == game_pid {
                    // The game's own other window (a dialog, a launcher's): not the picture the
                    // viewer sees, so still held back — and its process is not opened for the line.
                    tracing::debug!(
                        target: crate::KEY_NAMES_TARGET,
                        from,
                        game = %format!("{game:#x}"),
                        foreground = %format!("{foreground:#x}"),
                        pid = game_pid,
                        released,
                        held_keys = held.keys,
                        held_mods = held.mods,
                        held_buttons = held.buttons,
                        held_ours = %held.ours,
                        held_other = held.other,
                        "game input: another window of the game's own process has the front (a \
                         dialog?): input is held back (releases pass; released=true: releases \
                         were sent whether or not anything was held; held_* say what was)"
                    );
                } else {
                    let info = host.describe(foreground);
                    tracing::debug!(
                        target: crate::KEY_NAMES_TARGET,
                        from,
                        game = %format!("{game:#x}"),
                        foreground = %format!("{foreground:#x}"),
                        pid = info.pid,
                        exe = %info.exe.clone().unwrap_or_else(|e| format!("unknown ({e})")),
                        elevated = %info.elevated.clone().map_or_else(|e| format!("unknown ({e})"), |v| v.to_string()),
                        released,
                        held_keys = held.keys,
                        held_mods = held.mods,
                        held_buttons = held.buttons,
                        held_ours = %held.ours,
                        held_other = held.other,
                        "game input: another window has the front: input is held back (releases \
                         pass) until the game has it again (released=true: releases were sent \
                         whether or not anything was held; held_* say what was)"
                    );
                }
            }
            Look::NotShown { state } => tracing::debug!(
                target: crate::KEY_NAMES_TARGET,
                from,
                state = state.as_str(),
                released,
                held_keys = held.keys,
                held_mods = held.mods,
                held_buttons = held.buttons,
                held_ours = %held.ours,
                held_other = held.other,
                "game input: the game's window cannot take input (not shown, or not captured \
                 yet): only releases go through (released=true: releases were sent whether or \
                 not anything was held; held_* say what was)"
            ),
        }
    }

    fn decide(
        &mut self,
        event: &InputMessage,
        look: Look,
        window: Option<GameInputWindow>,
        host: &mut dyn GuardHost,
        now: Instant,
    ) -> Option<InputMessage> {
        match event {
            // Releases always pass: they are what keeps anything from sticking.
            InputMessage::ReleaseAll => {
                self.released();
                Some(event.clone())
            }
            InputMessage::Up { .. } => Some(event.clone()),
            InputMessage::Key { d: 0, code, .. } => self.key_up(code, event, look),
            _ => match (look, window) {
                (Look::Desktop, _) => self.desktop(event, host, now),
                (Look::Focused { .. }, Some(window)) => self.focused(event, window, host, now),
                (Look::Away { game, .. }, _) => {
                    self.try_focus(game, host, now);
                    self.hold_back(event, "another window has the front", now);
                    None
                }
                (Look::NotShown { state }, _) => {
                    self.hold_back(event, state.as_str(), now);
                    None
                }
                // Focused, with no window to confine to: cannot happen (a focused look has one).
                (Look::Focused { .. }, None) => {
                    self.hold_back(event, "no window to confine to", now);
                    None
                }
            },
        }
    }

    fn key_up(&mut self, code: &str, event: &InputMessage, look: Look) -> Option<InputMessage> {
        let src = key_src(event);
        if self.blocked.remove(code) {
            // A blocked key is a key of a system combination, but under a held Win it can be any
            // key at all: named only when ours or a system key (`key_log::loggable`).
            tracing::trace!(
                target: crate::KEY_NAMES_TARGET,
                key = key_log::loggable(code, src),
                src = key_log::source_name(src),
                "game input: a blocked key's release goes with it"
            );
            return None;
        }
        let held = self.held.remove(code);
        if !held && is_meta(code) && look != Look::Desktop {
            // Nothing of ours is down there, and a lone Win release is what opens Start.
            tracing::trace!(
                target: crate::KEY_NAMES_TARGET,
                key = code,
                src = key_log::source_name(src),
                "game input: a Win release with no press of ours dropped"
            );
            return None;
        }
        Some(event.clone())
    }

    fn desktop(
        &mut self,
        event: &InputMessage,
        host: &mut dyn GuardHost,
        now: Instant,
    ) -> Option<InputMessage> {
        match event {
            InputMessage::Key { code, .. } => {
                if over_cap(&self.held, code) {
                    self.dropped_at_cap("held", now);
                    return None;
                }
                // Pressed on the desktop: down through us, and not blocked any more (its release
                // must pass now).
                self.blocked.remove(code.as_str());
                self.held.insert(code.clone());
                Some(event.clone())
            }
            InputMessage::Text { text, game } => Some(self.desktop_text(text, *game, event, host)),
            _ => Some(event.clone()),
        }
    }

    /// A key press dropped (or, when blocked, not booked) because `which` of the guard's books is
    /// full ([`over_cap`]). Warned once until the guard resets; no key is named (under a held Win it
    /// can be any key of the viewer's keyboard).
    fn dropped_at_cap(&mut self, which: &'static str, now: Instant) {
        self.stats.since.get_or_insert(now);
        if which == "held" {
            self.stats.keys_dropped += 1;
        }
        if !self.cap_warned {
            self.cap_warned = true;
            tracing::warn!(
                which,
                cap = MAX_GUARD_KEYS,
                "game input: the guard's book of keys is full (a flood of distinct keys): a new \
                 key's press is dropped (held) or blocked without booking it (blocked); said once \
                 until the guard resets, the rest counted"
            );
        } else {
            tracing::trace!(which, "game input: the guard's book of keys is full");
        }
    }

    fn desktop_text(
        &mut self,
        text: &str,
        game: Option<bool>,
        event: &InputMessage,
        host: &mut dyn GuardHost,
    ) -> InputMessage {
        if game == Some(true) {
            self.note_text(TextRoute::Driver, TEXT_MARKED_GAME, None);
            return event.clone();
        }
        let elevation = host.foreground_elevation();
        let (route, reason) = match Reach::of(elevation.as_ref(), host.driver_open()) {
            Reach::Driver => (TextRoute::Driver, TEXT_ELEVATED),
            Reach::ElevatedNoDriver => (TextRoute::Unicode, TEXT_ELEVATED_NO_DRIVER),
            Reach::BothElevated => (TextRoute::Unicode, TEXT_BOTH_ELEVATED),
            Reach::Ordinary => (TextRoute::Unicode, TEXT_ORDINARY),
            Reach::Unknown => (TextRoute::Unicode, TEXT_UNKNOWN),
        };
        self.note_text(route, reason, elevation.as_ref());
        match route {
            TextRoute::Driver => InputMessage::Text {
                text: text.to_owned(),
                game: Some(true),
            },
            TextRoute::Unicode => event.clone(),
        }
    }

    /// Say the text's route when it changes (never the text).
    fn note_text(&mut self, route: TextRoute, reason: &'static str, elevation: Option<&Elevation>) {
        if self.text == Some((route, reason)) {
            tracing::trace!(route = route.name(), reason, "text route");
            return;
        }
        self.text = Some((route, reason));
        tracing::debug!(
            route = route.name(),
            reason,
            foreground = %elevation.map_or("-", |e| e.exe.as_str()),
            "text route"
        );
    }

    fn focused(
        &mut self,
        event: &InputMessage,
        window: GameInputWindow,
        host: &mut dyn GuardHost,
        now: Instant,
    ) -> Option<InputMessage> {
        match event {
            // A key going down (`d: 0` was taken as a release above).
            InputMessage::Key { code, .. } => self.game_key_down(code, event, now),
            InputMessage::Combo { name } => {
                self.stats.since.get_or_insert(now);
                self.stats.keys_blocked += 1;
                if self.lines.admit(now, "combo blocked") {
                    tracing::debug!(
                        target: crate::KEY_NAMES_TARGET,
                        combo = %name,
                        "game input: combo blocked (game-only mode: a system combination leaves \
                         the game's window)"
                    );
                } else {
                    tracing::trace!(target: crate::KEY_NAMES_TARGET, "game input: combo blocked");
                }
                None
            }
            InputMessage::Text { text, .. } => {
                self.note_text(TextRoute::Driver, TEXT_GAME_ONLY, None);
                Some(InputMessage::Text {
                    text: text.clone(),
                    game: Some(true),
                })
            }
            InputMessage::Down { b } => self.press(*b, event, window, host, now),
            _ => Some(event.clone()),
        }
    }

    fn game_key_down(
        &mut self,
        code: &String,
        event: &InputMessage,
        now: Instant,
    ) -> Option<InputMessage> {
        if self.held.contains(code) {
            // A repeat of a key already down through us: it adds nothing to what is held.
            return Some(event.clone());
        }
        if over_cap(&self.held, code) {
            self.dropped_at_cap("held", now);
            return None;
        }
        let src = key_src(event);
        if self.blocked.contains(code) {
            tracing::trace!(
                target: crate::KEY_NAMES_TARGET,
                key = %key_log::loggable(code, src),
                src = key_log::source_name(src),
                "game input: a repeat of a blocked key dropped"
            );
            return None;
        }
        if let Some(combo) = escape(code, &self.held, &self.blocked) {
            self.stats.since.get_or_insert(now);
            self.stats.keys_blocked += 1;
            // Past the cap the press is still blocked, only not booked: its release then passes,
            // a release of a key the PC never got (harmless).
            if over_cap(&self.blocked, code) {
                self.dropped_at_cap("blocked", now);
            } else {
                self.blocked.insert(code.clone());
            }
            // The combination is said for every source: a protection decision, not typed input.
            // The key itself only when ours or a key of the combination — under a held Win
            // (`Win+key`) it can be any key of the viewer's keyboard. A flood of them (every key
            // under a held Win) is said up to the line gate's burst, the rest counted.
            if self.lines.admit(now, "key blocked") {
                tracing::debug!(
                    target: crate::KEY_NAMES_TARGET,
                    key = %key_log::loggable(code, src),
                    combo,
                    src = key_log::source_name(src),
                    "game input: key blocked: it would leave the game's window (its release is \
                     dropped with it)"
                );
            } else {
                tracing::trace!(target: crate::KEY_NAMES_TARGET, combo, "game input: key blocked");
            }
            return None;
        }
        if alt_f4(code, &self.held) {
            // Once per press: a repeat of a key already held returned above. The key is F4 or an
            // Alt, the combination's own. The recorder is written out once the key is noted.
            self.alt_f4 = true;
            tracing::debug!(
                target: crate::KEY_NAMES_TARGET,
                key = %code,
                src = key_log::source_name(src),
                "game input: Alt+F4 passes — not blocked for anyone, a guest too (the owner, 6 \
                 Oct); it may close the game's window"
            );
        }
        self.held.insert(code.clone());
        Some(event.clone())
    }

    /// A mouse button going down: only onto a window of the game's process.
    fn press(
        &mut self,
        button: u8,
        event: &InputMessage,
        window: GameInputWindow,
        host: &mut dyn GuardHost,
        now: Instant,
    ) -> Option<InputMessage> {
        let Some((px, py)) = host.press_target() else {
            self.stats.since.get_or_insert(now);
            self.stats.presses_off_game += 1;
            if self.lines.admit(now, "press dropped") {
                tracing::debug!(
                    button,
                    "game input: press dropped: where it would land cannot be read (the cursor is \
                     unreadable)"
                );
            }
            return None;
        };
        match host.window_at(px, py) {
            Ok(at) if at.pid == window.pid || at.root_pid == window.pid => {
                tracing::trace!(button, px, py, "game input: press onto the game's window");
                Some(event.clone())
            }
            Ok(at) => {
                self.stats.since.get_or_insert(now);
                self.stats.presses_off_game += 1;
                if !self.lines.admit(now, "press dropped") {
                    tracing::trace!(
                        button,
                        "game input: press dropped: another program's window"
                    );
                    return None;
                }
                let info = host.describe(at.root);
                tracing::debug!(
                    button,
                    px,
                    py,
                    window = %format!("{:#x}", at.hwnd),
                    top_level = %format!("{:#x}", at.root),
                    pid = at.root_pid,
                    exe = %info.exe.unwrap_or_else(|e| format!("unknown ({e})")),
                    game_pid = window.pid,
                    "game input: press dropped: another program's window is over the game there \
                     (an always-on-top window?)"
                );
                None
            }
            Err(error) => {
                self.stats.since.get_or_insert(now);
                self.stats.presses_off_game += 1;
                if self.lines.admit(now, "press dropped") {
                    tracing::debug!(
                        button,
                        px,
                        py,
                        %error,
                        "game input: press dropped: the window under it cannot be read"
                    );
                }
                None
            }
        }
    }

    /// Ask the game back to the front — on the viewer's input only, at most every
    /// [`FOCUS_ATTEMPT_EVERY`].
    fn try_focus(&mut self, game: usize, host: &mut dyn GuardHost, now: Instant) {
        if self
            .attempted_at
            .is_some_and(|at| now.saturating_duration_since(at) < FOCUS_ATTEMPT_EVERY)
        {
            return;
        }
        self.attempted_at = Some(now);
        self.stats.since.get_or_insert(now);
        self.stats.focus_attempts += 1;
        let answer = host.set_foreground(game);
        let in_front = host.foreground() == game;
        if in_front {
            self.stats.focus_won += 1;
        }
        match answer {
            Ok(accepted) => tracing::debug!(
                window = %format!("{game:#x}"),
                accepted,
                in_front,
                "game input: SetForegroundWindow on the game's window (the viewer's input while \
                 another window has the front; a refusal flashes its taskbar button)"
            ),
            Err(error) => tracing::debug!(
                window = %format!("{game:#x}"),
                %error,
                in_front,
                "game input: SetForegroundWindow on the game's window failed"
            ),
        }
    }

    /// An event dropped because input may not go now. A press is said at `debug` (presses are
    /// discrete: a tap, a click); moves, keys and the rest at `trace`, all counted.
    fn hold_back(&mut self, event: &InputMessage, why: &str, now: Instant) {
        self.stats.since.get_or_insert(now);
        let kind = match event {
            InputMessage::Move { .. } | InputMessage::Rel { .. } => {
                self.stats.moves_dropped += 1;
                "move"
            }
            InputMessage::Down { b } => {
                self.stats.presses_dropped += 1;
                if self.lines.admit(now, "press dropped") {
                    tracing::debug!(button = b, why, "game input: press dropped");
                } else {
                    tracing::trace!(button = b, why, "game input: press dropped");
                }
                return;
            }
            InputMessage::Key { .. } => {
                self.stats.keys_dropped += 1;
                "key"
            }
            _ => {
                self.stats.other_dropped += 1;
                "other"
            }
        };
        tracing::trace!(kind, why, "game input: held back");
    }

    fn flush_if_due(&mut self, now: Instant) {
        if self
            .stats
            .since
            .is_some_and(|t| now.saturating_duration_since(t) >= STATS_EVERY)
        {
            self.flush(now, "second");
        }
    }

    fn flush(&mut self, now: Instant, why: &'static str) {
        let s = std::mem::take(&mut self.stats);
        let Some(since) = s.since else {
            return;
        };
        if !s.any() {
            return;
        }
        tracing::debug!(
            why,
            window_ms = now.saturating_duration_since(since).as_millis() as u64,
            look = self.look.map_or("-", Look::name),
            moves_dropped = s.moves_dropped,
            presses_dropped = s.presses_dropped,
            presses_off_game = s.presses_off_game,
            keys_dropped = s.keys_dropped,
            keys_blocked = s.keys_blocked,
            other_dropped = s.other_dropped,
            focus_attempts = s.focus_attempts,
            focus_won = s.focus_won,
            releases = s.releases,
            "game input"
        );
    }
}
