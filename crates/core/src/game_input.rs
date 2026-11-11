//! «Only the game window», the session's half of the input side.
//!
//! The injector (`afklink_input`'s game guard) does the confining: it maps `m` and `r.x/y` into the
//! game's client area, keeps the cursor in it, injects only while the game's window is in front and
//! blocks the keys that leave it. What it needs from a session, and what a session needs back, is
//! here:
//!
//! - [`InputScopeSource`] — for every event, where the session's input may go: the desktop, or the
//!   game's window as the session's game capture last saw it ([`crate::game::GameStatus`]). The
//!   owner's switch is read for every event, so input is confined from the moment it flips —
//!   before the capture is replaced — and a window that is not shown takes nothing but releases;
//! - [`to_scope`] — the cursor report (`cp`) in the same space as `m`: fractions of the game's
//!   client area, and `hidden` outside it;
//! - [`focus_watch_task`] — a few times a second, whether the game's window has the front, when the
//!   viewer is idle too: the injector releases what it holds the moment the game loses the front,
//!   and the heartbeat says `unfocused`.
//!
//! Logging: the focus watch says each change at `debug` (the injector says the foreground
//! window's exe with it); the cursor report says its coordinate space at start and on every change.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use crate::game::{CaptureModeCell, GameStatus};
use crate::traits::{CursorSample, GameFocus, InputInjector, InputScope};

/// How often the focus watch looks at the foreground window. A held key auto-repeats into another
/// window after 250–500 ms, so a window taking the front must be seen well inside that; one look is
/// a `GetForegroundWindow` call.
pub const GAME_FOCUS_EVERY: Duration = Duration::from_millis(100);

/// Where one session's input may go: the owner's switch (the process-wide mode) and the session's
/// view of the game's window.
pub struct InputScopeSource {
    modes: Arc<CaptureModeCell>,
    game: Arc<GameStatus>,
}

impl InputScopeSource {
    pub fn new(modes: Arc<CaptureModeCell>, game: Arc<GameStatus>) -> Self {
        Self { modes, game }
    }

    /// The scope now. Game-only on: the game's window as the session's capture last saw it — with
    /// no window yet (the capture not replaced yet, the game absent or minimized) that is a scope
    /// that takes nothing but releases. Read for every event: two short locks, nothing cloned.
    pub fn scope(&self) -> InputScope {
        if self.modes.is_game() {
            InputScope::Game(self.game.game_scope())
        } else {
            InputScope::Desktop
        }
    }

    /// The session's game window status, for what the focus watch sees.
    pub fn game(&self) -> &Arc<GameStatus> {
        &self.game
    }
}

/// A cursor sample in the scope's space, for the viewer's marker (`cp`): the whole primary monitor,
/// or the game's client area — the picture the viewer sees — outside which the cursor counts as off
/// the picture (`hidden`, its position clamped to the edge). With no game window to measure against
/// (absent, minimized) the cursor is hidden.
pub fn to_scope(sample: CursorSample, scope: &InputScope) -> CursorSample {
    match scope {
        InputScope::Desktop => sample,
        InputScope::Game(game) => match game.window {
            Some(window) => {
                let client = window.client;
                let size = |v: i64| i32::try_from(v).unwrap_or(0);
                CursorSample {
                    x: sample.x.saturating_sub(client.left),
                    y: sample.y.saturating_sub(client.top),
                    width: size(client.width()),
                    height: size(client.height()),
                    ..sample
                }
            }
            None => CursorSample {
                x: -1,
                y: -1,
                width: 1,
                height: 1,
                visible: false,
                ..sample
            },
        },
    }
}

/// The scope's space in words, for the cursor report's line.
pub fn describe_space(scope: &InputScope) -> String {
    match scope {
        InputScope::Desktop => "the primary monitor".to_string(),
        InputScope::Game(game) => match game.window {
            Some(window) => format!(
                "the game's client area {}x{} at {},{} (window {:#x})",
                window.client.width(),
                window.client.height(),
                window.client.left,
                window.client.top,
                window.hwnd
            ),
            None => format!(
                "none: game-only mode, the game's window is {} (the cursor is reported hidden)",
                game.state.as_str()
            ),
        },
    }
}

/// Watch, while the session runs, whether the game's window has the front, and tell the session's
/// game status (the heartbeat's `unfocused`). The injector releases what it holds the moment the
/// game loses the front ([`InputInjector::game_focus`]); it never brings the game forward from
/// here — that is tried only on the viewer's input.
pub async fn focus_watch_task(
    injector: Arc<dyn InputInjector>,
    scope: Arc<InputScopeSource>,
    stop: Arc<AtomicBool>,
    sid: String,
) {
    let mut tick = tokio::time::interval(GAME_FOCUS_EVERY);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut last: Option<GameFocus> = None;
    tracing::debug!(
        session = %sid,
        every_ms = GAME_FOCUS_EVERY.as_millis() as u64,
        "game focus watch started (it looks only while game-only mode is on)"
    );
    loop {
        tick.tick().await;
        if stop.load(Ordering::SeqCst) {
            tracing::debug!(session = %sid, "game focus watch stopped: the session is ending");
            break;
        }
        let InputScope::Game(game) = scope.scope() else {
            if last.take().is_some() {
                tracing::debug!(
                    session = %sid,
                    "game focus watch: game-only mode is off; nothing to watch"
                );
                scope.game().set_focus(true);
            }
            continue;
        };
        // A release on focus loss writes to the device: off the async worker, like the session's
        // own input.
        let focus = crate::input_session::blocking(|| injector.game_focus(&game));
        let told = scope.game().set_focus(focus != GameFocus::Unfocused);
        if last != Some(focus) {
            tracing::debug!(
                session = %sid,
                focus = focus.as_str(),
                from = last.map_or("-", GameFocus::as_str),
                state = game.state.as_str(),
                heartbeat_changed = told,
                "game focus watch: the game's window {}",
                match focus {
                    GameFocus::Focused => "has the front",
                    GameFocus::Unfocused =>
                        "lost the front: input is held back and the viewer is told `unfocused`",
                    GameFocus::NotShown => "cannot take input (not shown)",
                    GameFocus::Unknown => "focus: the injector cannot tell",
                }
            );
            last = Some(focus);
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::game::{CaptureGeometry, CaptureMode, GameBinding, ScreenRect};
    use crate::traits::{GameInputWindow, GameScope};
    use afklink_protocol::{GameWindowState, InputMessage};

    fn rect(left: i32, top: i32, right: i32, bottom: i32) -> ScreenRect {
        ScreenRect {
            left,
            top,
            right,
            bottom,
        }
    }

    fn game_mode() -> CaptureMode {
        CaptureMode::GameWindow {
            binding: Some(GameBinding::new(
                r"D:\Games\Scryde\Scryde\ScrydeGame.bin",
                "ScrydeGameUnrealWWindowsViewportWindow",
            )),
        }
    }

    fn windowed(status: &GameStatus) {
        status.set_active(true);
        status.set_state(GameWindowState::Shown);
        status.set_window(0x40666, 6888);
        status.set_geometry(CaptureGeometry {
            hwnd: 0x40666,
            client: rect(12, 47, 3588, 2315),
            source: (3576, 2268),
        });
    }

    #[test]
    fn the_scope_follows_the_owners_switch_at_once_and_the_window_as_captured() {
        let modes = Arc::new(CaptureModeCell::new(CaptureMode::Monitor));
        let status = Arc::new(GameStatus::new());
        let source = InputScopeSource::new(modes.clone(), status.clone());
        assert_eq!(source.scope(), InputScope::Desktop);

        // On, before the session's capture has noticed: game scope with no window — nothing but
        // releases goes.
        modes.set(game_mode(), "test: on");
        assert_eq!(
            source.scope(),
            InputScope::Game(GameScope {
                state: GameWindowState::Absent,
                window: None
            })
        );
        windowed(&status);
        assert_eq!(
            source.scope().game_window(),
            Some(GameInputWindow {
                hwnd: 0x40666,
                pid: 6888,
                client: rect(12, 47, 3588, 2315),
            })
        );
        status.set_state(GameWindowState::Minimized);
        assert_eq!(source.scope().game_window(), None);
        modes.set(CaptureMode::Monitor, "test: off");
        assert_eq!(source.scope(), InputScope::Desktop);
    }

    /// `cp` in game-only mode: fractions of the client area (a windowed game at +12+47), hidden
    /// outside it and while the window is not shown.
    #[test]
    fn the_cursor_report_is_in_the_game_client_space() {
        use crate::cursor_report::CursorReporter;
        let status = GameStatus::new();
        windowed(&status);
        let scope = InputScope::Game(status.game_scope());
        let at = |x: i32, y: i32| CursorSample {
            x,
            y,
            width: 3600,
            height: 2400,
            visible: true,
            shape: 0x10003,
            unshown: None,
        };
        let mut r = CursorReporter::new();
        let now = std::time::Instant::now();

        // The shape and the moves not shown yet are the reading's, whatever the space.
        let busy = CursorSample {
            unshown: Some(7),
            ..at(500, 600)
        };
        for space in [scope, InputScope::Desktop] {
            let scoped = to_scope(busy, &space);
            assert_eq!((scoped.shape, scoped.unshown), (0x10003, Some(7)));
        }

        // The client area's top-left pixel and its centre.
        let (cp, _) = r.decide(now, to_scope(at(12, 47), &scope), None).unwrap();
        assert!(!cp.hidden);
        assert!(cp.x.abs() < 1e-9 && cp.y.abs() < 1e-9, "{cp:?}");
        let (cp, _) = r
            .decide(now, to_scope(at(12 + 1788, 47 + 1134), &scope), None)
            .unwrap();
        assert!(
            (cp.x - 0.5).abs() < 1e-9 && (cp.y - 0.5).abs() < 1e-9,
            "{cp:?}"
        );

        // On the title bar above the client area, and right of it: hidden, clamped to the edge.
        let (cp, vis) = r.decide(now, to_scope(at(500, 20), &scope), None).unwrap();
        assert!(cp.hidden);
        assert!(cp.y.abs() < 1e-9, "{cp:?}");
        assert!(vis.unwrap().contains("outside the captured picture"));
        let (cp, _) = r
            .decide(now, to_scope(at(3595, 900), &scope), None)
            .unwrap();
        assert!(cp.hidden && (cp.x - 1.0).abs() < 1e-9, "{cp:?}");

        // The game minimized: no window to measure against, the cursor hidden.
        let not_shown = InputScope::Game(GameScope {
            state: GameWindowState::Minimized,
            window: None,
        });
        let (cp, _) = r
            .decide(now, to_scope(at(1000, 1000), &not_shown), None)
            .unwrap();
        assert!(cp.hidden);

        // Game-only off: the primary monitor, as ever.
        let (cp, _) = r
            .decide(now, to_scope(at(1800, 1200), &InputScope::Desktop), None)
            .unwrap();
        assert!((cp.x - 0.5).abs() < 1e-9 && (cp.y - 0.5).abs() < 1e-9 && !cp.hidden);

        assert!(describe_space(&scope).contains("3576x2268 at 12,47"));
        assert!(describe_space(&not_shown).contains("minimized"));
    }

    /// An injector whose game focus the test sets.
    struct FocusInjector {
        focus: std::sync::Mutex<GameFocus>,
        looks: std::sync::atomic::AtomicU32,
    }

    impl InputInjector for FocusInjector {
        fn inject(&self, _event: &InputMessage) -> anyhow::Result<()> {
            Ok(())
        }
        fn release_all(&self) {}
        fn game_focus(&self, _game: &GameScope) -> GameFocus {
            self.looks.fetch_add(1, Ordering::SeqCst);
            *self.focus.lock().unwrap()
        }
    }

    #[tokio::test]
    async fn the_focus_watch_tells_the_heartbeat_unfocused_and_back() {
        let modes = Arc::new(CaptureModeCell::new(game_mode()));
        let status = Arc::new(GameStatus::new());
        windowed(&status);
        let injector = Arc::new(FocusInjector {
            focus: std::sync::Mutex::new(GameFocus::Focused),
            looks: std::sync::atomic::AtomicU32::new(0),
        });
        let stop = Arc::new(AtomicBool::new(false));
        let task = tokio::spawn(focus_watch_task(
            injector.clone(),
            Arc::new(InputScopeSource::new(modes.clone(), status.clone())),
            stop.clone(),
            "s1".into(),
        ));
        let told = |status: &GameStatus| status.heartbeat().map(|h| h.state);
        let wait_for = |want: GameWindowState| {
            let status = status.clone();
            async move {
                for _ in 0..50 {
                    if told(&status) == Some(want) {
                        return;
                    }
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
                assert_eq!(told(&status), Some(want));
            }
        };
        wait_for(GameWindowState::Shown).await;
        *injector.focus.lock().unwrap() = GameFocus::Unfocused;
        wait_for(GameWindowState::Unfocused).await;
        *injector.focus.lock().unwrap() = GameFocus::Focused;
        wait_for(GameWindowState::Shown).await;

        // Game-only off: no more looks.
        modes.set(CaptureMode::Monitor, "test: off");
        tokio::time::sleep(Duration::from_millis(250)).await;
        let looks = injector.looks.load(Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(250)).await;
        assert_eq!(injector.looks.load(Ordering::SeqCst), looks);

        stop.store(true, Ordering::SeqCst);
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .expect("stops with the session")
            .expect("no panic");
    }
}
