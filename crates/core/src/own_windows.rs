//! A guest does not drive AFKLink's own windows: a speed bump, not a boundary.
//!
//! The windows of this process are where access is given and taken: «Разрешить» and «Кто это?» in
//! the request window, «Отвязать» and «Сделать владельцем» in «Доступ», «Только для гостей» in
//! Settings, the tray menu's «Возобновить» and «Выход». A guest whose clicks reached them could let
//! a second account of his own in, or switch off what limits him. So while a session's viewer is
//! not the PC's owner as the server says (`crate::game_access::ViewerRole::is_owner`: a guest,
//! everyone on a PC with no owner, an account with no role), its input stops short of them:
//!
//! - a key going down, text and a combo: not while the foreground window is one of ours;
//! - a mouse button going down and the wheel: not onto a window of ours, judged at the pixel the
//!   press lands on and by its top-level window ([`WindowTarget::UnderPress`]) whichever window has
//!   the front (a click on a window behind brings it forward and lands on it all the same);
//! - while one of ours has the front, not a press onto a window that never takes the front
//!   (`WS_EX_NOACTIVATE` on its top-level window: the on-screen keyboard and its kin), which types
//!   into whatever has it (ours);
//! - while Windows' Mouse Keys is on (the numeric keypad moves and clicks the pointer), not a key
//!   going down while the pointer is over one of ours either: the key is a click there;
//! - moves and releases always go: moving is how the pointer leaves our window, and a release keeps
//!   nothing stuck.
//!
//! When a stretch of held-back input begins, what this session holds is released (a key held down
//! into our window would repeat there), and between events the session's watch ([`watch_task`])
//! looks a few times a second whether one of our windows took the front, and releases then too.
//! Only this session's own presses (`InputSession::release_own`): an owner's session alongside
//! keeps what it holds.
//!
//! **This does not stop a determined guest.** Windows has more ways into a window than these
//! looks: an accessibility tool or another program of the guest's choosing that types or clicks for
//! him, a window that sits over ours without taking the front, timing between a look and the input
//! landing. It makes the obvious path (click «Разрешить», untick «Только для гостей») not work.
//! What protects the owner is that he is told: the new-guest notice in the bot and on this PC (the
//! toast, the journal), so a second account let in this way is seen and removed.
//!
//! The owner's sessions are untouched, and a session whose viewer becomes the owner (or stops being
//! it) is judged so from its next event: the role is read for every event ([`RoleCell`]).
//!
//! Where the window cannot be read (the injector cannot tell, no window there) the event goes:
//! holding a guest back whenever a read fails would freeze sessions on the lock screen or a UAC
//! prompt, which are not ours anyway. The first such event of a session is said.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use afklink_protocol::InputMessage;

use crate::game_access::RoleCell;
use crate::input_session::InputSession;
use crate::sync::lock;
use crate::traits::{InputInjector, WindowOwner, WindowTarget};

/// How often the watch looks at the foreground window between events: as often as game-only mode's
/// focus watch (`crate::game_input::GAME_FOCUS_EVERY`), well inside a held key's first repeat
/// (250–500 ms). One look is `GetForegroundWindow` and the window's process id.
pub const OWN_WINDOW_EVERY: Duration = Duration::from_millis(100);

/// A read of where a guest's event lands that takes this long is said at warn: it is two or three
/// window-manager calls, well under a millisecond, unless the input planner's lock is held by a
/// stuck injection.
const SLOW_READ: Duration = Duration::from_millis(250);

/// What an event is, for the counts and the rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Press,
    Wheel,
    Key,
    Text,
    Combo,
}

impl Kind {
    /// What `event` is; `None` for what always goes — moves, releases, everything not input.
    fn of(event: &InputMessage) -> Option<Self> {
        match event {
            InputMessage::Down { .. } => Some(Self::Press),
            InputMessage::Wheel { .. } => Some(Self::Wheel),
            InputMessage::Key { d, .. } if *d != 0 => Some(Self::Key),
            InputMessage::Text { .. } => Some(Self::Text),
            InputMessage::Combo { .. } => Some(Self::Combo),
            _ => None,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Press => "press",
            Self::Wheel => "wheel",
            Self::Key => "key",
            Self::Text => "text",
            Self::Combo => "combo",
        }
    }
}

/// Why an event is held back: which rule of the module's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Why {
    /// A key, text or a combo while one of our windows has the front.
    OursInFront,
    /// A press or the wheel onto one of our windows.
    OursUnderPress,
    /// A press onto a window that never takes the front, while one of ours has it.
    NoActivateOverOurs,
    /// A key while Mouse Keys is on and the pointer is over one of ours.
    MouseKeysOverOurs,
}

impl Why {
    fn as_str(self) -> &'static str {
        match self {
            Self::OursInFront => "an AFKLink window has the front",
            Self::OursUnderPress => "an AFKLink window is under the press",
            Self::NoActivateOverOurs => {
                "a window that never takes the front (WS_EX_NOACTIVATE) is under the press while an \
                 AFKLink window has it: what it types goes there"
            }
            Self::MouseKeysOverOurs => {
                "Mouse Keys is on and the pointer is over an AFKLink window: the key is a click there"
            }
        }
    }

    fn code(self) -> &'static str {
        match self {
            Self::OursInFront => "ours_in_front",
            Self::OursUnderPress => "ours_under_press",
            Self::NoActivateOverOurs => "no_activate_over_ours",
            Self::MouseKeysOverOurs => "mouse_keys_over_ours",
        }
    }
}

/// Where an event would land, as the guard judges it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Lands {
    /// On one of ours, by `Why`.
    Ours(Why),
    /// Elsewhere.
    Elsewhere,
    /// The window it would reach cannot be read.
    Unreadable(WindowTarget),
}

impl Lands {
    /// For the log.
    fn code(&self) -> &'static str {
        match self {
            Self::Ours(why) => why.code(),
            Self::Elsewhere => "elsewhere",
            Self::Unreadable(_) => "unreadable",
        }
    }
}

/// Held-back events by kind, for the line that ends a stretch.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct Counts {
    presses: u32,
    wheel: u32,
    keys: u32,
    text: u32,
    combos: u32,
}

impl Counts {
    fn add(&mut self, kind: Kind) {
        let n = match kind {
            Kind::Press => &mut self.presses,
            Kind::Wheel => &mut self.wheel,
            Kind::Key => &mut self.keys,
            Kind::Text => &mut self.text,
            Kind::Combo => &mut self.combos,
        };
        *n = n.saturating_add(1);
    }

    fn total(self) -> u32 {
        self.presses + self.wheel + self.keys + self.text + self.combos
    }
}

/// A stretch of held-back input: since when, why it began, and the counts.
#[derive(Debug)]
struct Stretch {
    since: Instant,
    why: Why,
    counts: Counts,
}

#[derive(Debug, Default)]
struct State {
    stretch: Option<Stretch>,
    /// The guard applies to the session (its viewer is not the owner), as last said.
    applies: Option<bool>,
    /// One of our windows had the front at the watch's last look.
    in_front: bool,
    /// An event whose window could not be read went through: said once a session.
    unreadable_said: bool,
    /// Mouse Keys as last read (`None`: not read yet, or unreadable), for the line at each change.
    mouse_keys: Option<bool>,
}

/// What becomes of one event ([`OwnWindowGuard::admit`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Admit {
    Pass,
    /// Not injected; `release`: a stretch begins — release what this session holds first.
    HoldBack {
        release: bool,
    },
}

/// One session's guard (see the module).
///
/// Logs: one `debug` line when a stretch of held-back input begins (what was held back and why,
/// which of the rules) and one when it ends, with how long it lasted and the counts by kind; one
/// when the guard starts or stops applying to the session (its viewer's role); one when one of our
/// windows takes or leaves the front between events; one when Mouse Keys is seen on or off. Nothing
/// per event: the session's `input` line counts `held_back`.
pub(crate) struct OwnWindowGuard {
    /// This process: AFKLink's windows are the ones it owns.
    pid: u32,
    role: Arc<RoleCell>,
    sid: String,
    state: Mutex<State>,
}

impl OwnWindowGuard {
    pub(crate) fn new(role: Arc<RoleCell>, sid: &str) -> Self {
        Self::for_process(std::process::id(), role, sid)
    }

    fn for_process(pid: u32, role: Arc<RoleCell>, sid: &str) -> Self {
        Self {
            pid,
            role,
            sid: sid.to_string(),
            state: Mutex::new(State::default()),
        }
    }

    /// Whether the guard applies now (the viewer is not the owner), saying a change.
    fn applies(&self, s: &mut State, now: Instant) -> bool {
        let role = self.role.get();
        let applies = !role.is_owner();
        if s.applies != Some(applies) {
            tracing::debug!(
                session = %self.sid,
                role = role.as_str(),
                pid = self.pid,
                "own windows: {}",
                if applies {
                    "the viewer is not the PC's owner (as the server says): presses, keys and text \
                     do not reach AFKLink's windows"
                } else {
                    "the viewer is the PC's owner: input reaches AFKLink's windows as any other"
                }
            );
            s.applies = Some(applies);
            if !applies {
                self.end_stretch(s, now, "the viewer is the PC's owner now");
                s.in_front = false;
            }
        }
        applies
    }

    fn ours(&self, owner: Option<WindowOwner>) -> Option<bool> {
        owner.map(|o| o.pid == self.pid)
    }

    /// Mouse Keys as the injector read it (`on`, by [`Self::lands`] without the state's lock), its
    /// change said.
    fn note_mouse_keys(&self, s: &mut State, on: Option<bool>) {
        if on != s.mouse_keys {
            tracing::debug!(
                session = %self.sid,
                mouse_keys = ?on,
                "own windows: Mouse Keys {}",
                match on {
                    Some(true) => {
                        "is on: a guest's keys are held back while the pointer is over an AFKLink \
                         window too"
                    }
                    Some(false) => "is off",
                    None => "cannot be read: taken as off",
                }
            );
            s.mouse_keys = on;
        }
    }

    /// Where an event of `kind` would land (the module's rules, in order), and Mouse Keys as read
    /// for it (`None`: not read). Reads the window manager and the injector only — the state's lock
    /// is not held here: a read can wait (the input planner's lock for the press target), and
    /// whoever else wants the lock (the watch between events, the next event) must not wait with
    /// it.
    fn lands(&self, kind: Kind, injector: &dyn InputInjector) -> (Lands, Option<Option<bool>>) {
        match kind {
            Kind::Key | Kind::Text | Kind::Combo => {
                let front = self.ours(injector.window_owner(WindowTarget::Foreground));
                if front == Some(true) {
                    return (Lands::Ours(Why::OursInFront), None);
                }
                let mut mouse_keys = None;
                if kind == Kind::Key {
                    let on = injector.mouse_keys_on();
                    mouse_keys = Some(on);
                    if on == Some(true) {
                        let under = self.ours(injector.window_owner(WindowTarget::UnderPress));
                        if under == Some(true) {
                            return (Lands::Ours(Why::MouseKeysOverOurs), mouse_keys);
                        }
                    }
                }
                let lands = match front {
                    Some(_) => Lands::Elsewhere,
                    None => Lands::Unreadable(WindowTarget::Foreground),
                };
                (lands, mouse_keys)
            }
            Kind::Press | Kind::Wheel => {
                let Some(under) = injector.window_owner(WindowTarget::UnderPress) else {
                    return (Lands::Unreadable(WindowTarget::UnderPress), None);
                };
                if under.pid == self.pid {
                    return (Lands::Ours(Why::OursUnderPress), None);
                }
                if kind == Kind::Press
                    && under.no_activate
                    && self.ours(injector.window_owner(WindowTarget::Foreground)) == Some(true)
                {
                    return (Lands::Ours(Why::NoActivateOverOurs), None);
                }
                (Lands::Elsewhere, None)
            }
        }
    }

    /// One event of the session: whether it may be injected.
    ///
    /// The state's lock is taken twice, each time for a short decision, and never across the
    /// window reads: those can wait on the input planner's lock, and the lock here is also taken by
    /// the watch between events ([`watch_task`]) — a read stuck under it would stall that, and the
    /// next event's wait for it would sit on a runtime worker.
    pub(crate) fn admit(
        &self,
        event: &InputMessage,
        injector: &dyn InputInjector,
        now: Instant,
    ) -> Admit {
        if !self.applies(&mut lock(&self.state), now) {
            return Admit::Pass;
        }
        let Some(kind) = Kind::of(event) else {
            return Admit::Pass;
        };
        // Window-manager reads and the planner's lock for the press target: off the worker
        // (`block_in_place`) — a stuck holder of that lock must stall this session's events, not
        // the runtime's timers and I/O. Only for the events that are judged (presses, keys, text).
        let read_at = Instant::now();
        let (mut lands, mut mouse_keys) =
            crate::input_session::blocking(|| self.lands(kind, injector));
        let read = read_at.elapsed();
        if read >= SLOW_READ {
            // A slow answer is an old one: the windows may have changed while it waited — one of
            // ours taking the front (the request window opening) is exactly what must not be
            // missed. So the whole judgement is read again, fresh (the foreground alone would not
            // do: a press is judged by the window under it). Still slow, the windows cannot be
            // known now: the guest's event is held back, without beginning a stretch.
            let again_at = Instant::now();
            let fresh = crate::input_session::blocking(|| self.lands(kind, injector));
            let again = again_at.elapsed();
            tracing::warn!(
                session = %self.sid,
                kind = kind.as_str(),
                took_ms = read.as_millis() as u64,
                again_ms = again.as_millis() as u64,
                first = lands.code(),
                fresh = fresh.0.code(),
                "own windows: reading where a guest's input lands took long (the window manager or \
                 the input planner's lock was busy); read again before deciding"
            );
            if again >= SLOW_READ {
                // The role may have changed meanwhile: an owner's event is never held back.
                if !self.applies(&mut lock(&self.state), now) {
                    return Admit::Pass;
                }
                tracing::warn!(
                    session = %self.sid,
                    kind = kind.as_str(),
                    "own windows: the windows cannot be read in time; the guest's event is held back"
                );
                return Admit::HoldBack { release: false };
            }
            (lands, mouse_keys) = fresh;
        }
        let mut s = lock(&self.state);
        if let Some(on) = mouse_keys {
            self.note_mouse_keys(&mut s, on);
        }
        // The role may have changed while the windows were read: judged by the role now.
        if !self.applies(&mut s, now) {
            return Admit::Pass;
        }
        match lands {
            Lands::Ours(why) => {
                if let Some(stretch) = s.stretch.as_mut() {
                    stretch.counts.add(kind);
                    tracing::trace!(
                        session = %self.sid,
                        kind = kind.as_str(),
                        why = why.code(),
                        "own windows: guest input held back"
                    );
                    return Admit::HoldBack { release: false };
                }
                tracing::debug!(
                    session = %self.sid,
                    kind = kind.as_str(),
                    why = why.code(),
                    role = self.role.get().as_str(),
                    "own windows: a guest's {} would reach an AFKLink window ({}): held back until \
                     it would not, and what this session holds is released",
                    kind.as_str(),
                    why.as_str()
                );
                let mut counts = Counts::default();
                counts.add(kind);
                s.stretch = Some(Stretch {
                    since: now,
                    why,
                    counts,
                });
                Admit::HoldBack { release: true }
            }
            Lands::Elsewhere => {
                self.end_stretch(&mut s, now, "the input reaches another window again");
                Admit::Pass
            }
            Lands::Unreadable(target) => {
                if !s.unreadable_said {
                    s.unreadable_said = true;
                    tracing::debug!(
                        session = %self.sid,
                        kind = kind.as_str(),
                        window = target.as_str(),
                        "own windows: the window this input reaches cannot be read (none there, or \
                         the injector cannot tell): it goes (said once a session)"
                    );
                }
                self.end_stretch(&mut s, now, "the window it reaches cannot be read");
                Admit::Pass
            }
        }
    }

    /// Between events: whether one of our windows just took the front of a guest's session, so what
    /// it holds must be released now. Says each change.
    ///
    /// The window is read without the state's lock (see [`Self::admit`]): a read stuck on the
    /// planner's lock stalls this watch only, never an event waiting for the lock.
    pub(crate) fn watch(&self, injector: &dyn InputInjector, now: Instant) -> bool {
        if !self.applies(&mut lock(&self.state), now) {
            return false;
        }
        let front = self.ours(injector.window_owner(WindowTarget::Foreground)) == Some(true);
        let mut s = lock(&self.state);
        if !self.applies(&mut s, now) {
            return false;
        }
        if front == s.in_front {
            return false;
        }
        s.in_front = front;
        tracing::debug!(
            session = %self.sid,
            "own windows: an AFKLink window {}",
            if front {
                "took the front during a guest's session: what the viewer holds is released, and \
                 their keys and text are held back while it has it"
            } else {
                "no longer has the front"
            }
        );
        front
    }

    /// The session ended: a stretch still open is said.
    pub(crate) fn finish(&self, now: Instant) {
        let mut s = lock(&self.state);
        self.end_stretch(&mut s, now, "the session ended");
    }

    fn end_stretch(&self, s: &mut State, now: Instant, why: &str) {
        let Some(stretch) = s.stretch.take() else {
            return;
        };
        let c = stretch.counts;
        // not-a-key-name: counts of input events
        tracing::debug!(
            session = %self.sid,
            lasted_ms = now.saturating_duration_since(stretch.since).as_millis() as u64,
            began_by = stretch.why.code(),
            held_back = c.total(),
            presses = c.presses,
            wheel = c.wheel,
            keys = c.keys,
            text = c.text,
            combos = c.combos,
            "own windows: guest input goes again: {why}"
        );
    }
}

/// The session's watch between events (see the module): every [`OWN_WINDOW_EVERY`] while it runs,
/// whether one of our windows took the front of a guest's session — then what this session holds is
/// released (its own only). Ends with the session, saying a stretch still open.
pub(crate) async fn watch_task(
    guard: Arc<OwnWindowGuard>,
    input: Arc<InputSession>,
    injector: Arc<dyn InputInjector>,
    stop: Arc<AtomicBool>,
) {
    let mut tick = tokio::time::interval(OWN_WINDOW_EVERY);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    tracing::debug!(
        session = %guard.sid,
        every_ms = OWN_WINDOW_EVERY.as_millis() as u64,
        "own windows: watch started (it looks only while the viewer is not the owner)"
    );
    loop {
        tick.tick().await;
        if stop.load(Ordering::SeqCst) || !input.is_active() {
            break;
        }
        // Off the worker (`block_in_place`): the window read can wait on the input planner's lock,
        // and a stuck holder must stall this task only, not the worker's timers and I/O. The
        // guard's own lock is not held across the read (`OwnWindowGuard::watch`). A few times a
        // second: the hand-off's cost is nothing.
        let took_front = crate::input_session::blocking(|| guard.watch(&*injector, Instant::now()));
        if took_front {
            input.release_own("an AFKLink window took the front of a guest's session");
        }
    }
    crate::input_session::blocking(|| guard.finish(Instant::now()));
    tracing::debug!(session = %guard.sid, "own windows: watch stopped: the session is ending");
}

#[cfg(test)]
pub(crate) mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::game_access::ViewerRole;
    use std::sync::Mutex as StdMutex;

    /// What the session's viewer is.
    fn role(role: ViewerRole) -> Arc<RoleCell> {
        Arc::new(RoleCell::fixed(role))
    }

    const OURS: u32 = 4242;
    const OTHER: u32 = 7;

    /// An injector whose windows the test places: who owns the foreground window and the one under
    /// the press (and whether that one never takes the front), whether Mouse Keys is on; what it
    /// was asked, what it injected and how often everything was released.
    #[derive(Default)]
    pub(crate) struct Desk {
        foreground: StdMutex<Option<u32>>,
        under: StdMutex<Option<WindowOwner>>,
        mouse_keys: StdMutex<Option<bool>>,
        asked: StdMutex<Vec<WindowTarget>>,
        pub(crate) injected: StdMutex<Vec<String>>,
        pub(crate) releases: StdMutex<u32>,
    }

    impl Desk {
        pub(crate) fn place(&self, foreground: Option<u32>, under: Option<u32>) {
            *self.foreground.lock().unwrap() = foreground;
            *self.under.lock().unwrap() = under.map(|pid| WindowOwner {
                pid,
                no_activate: false,
            });
        }

        fn under_no_activate(&self, pid: u32) {
            *self.under.lock().unwrap() = Some(WindowOwner {
                pid,
                no_activate: true,
            });
        }

        fn mouse_keys(&self, on: Option<bool>) {
            *self.mouse_keys.lock().unwrap() = on;
        }
    }

    impl InputInjector for Desk {
        fn inject(&self, event: &InputMessage) -> anyhow::Result<()> {
            self.injected.lock().unwrap().push(format!("{event:?}"));
            Ok(())
        }
        fn release_all(&self) {
            *self.releases.lock().unwrap() += 1;
        }
        fn window_owner(&self, target: WindowTarget) -> Option<WindowOwner> {
            self.asked.lock().unwrap().push(target);
            match target {
                WindowTarget::Foreground => {
                    self.foreground.lock().unwrap().map(|pid| WindowOwner {
                        pid,
                        no_activate: false,
                    })
                }
                WindowTarget::UnderPress => *self.under.lock().unwrap(),
            }
        }
        fn mouse_keys_on(&self) -> Option<bool> {
            *self.mouse_keys.lock().unwrap()
        }
    }

    fn key(d: u8) -> InputMessage {
        key_of("KeyA", d)
    }

    fn key_of(code: &str, d: u8) -> InputMessage {
        InputMessage::Key {
            d,
            code: code.into(),
            key: None,
            mods: None,
            src: None,
        }
    }

    fn down() -> InputMessage {
        InputMessage::Down { b: 0 }
    }

    /// A guest's presses, keys, text, combos and wheel stop short of our windows — keys by the
    /// foreground window, presses and the wheel by the window under the press, whichever has the
    /// front — while moves and releases always go; the stretch releases what is held once, at its
    /// start, and ends when input reaches another window again.
    #[test]
    fn a_guests_input_stops_short_of_afklinks_windows() {
        let desk = Desk::default();
        let guard = OwnWindowGuard::for_process(OURS, role(ViewerRole::Guest), "s1");
        let now = Instant::now();

        // Another window in front and under the pointer: everything goes.
        desk.place(Some(OTHER), Some(OTHER));
        for e in [
            key(1),
            down(),
            InputMessage::Text {
                text: "hi".into(),
                game: None,
            },
        ] {
            assert_eq!(guard.admit(&e, &desk, now), Admit::Pass, "{e:?}");
        }

        // Our window in front: keys, text and combos are held back; the first releases what is held.
        desk.place(Some(OURS), Some(OTHER));
        assert_eq!(
            guard.admit(&key(1), &desk, now),
            Admit::HoldBack { release: true }
        );
        assert_eq!(
            guard.admit(
                &InputMessage::Text {
                    text: "x".into(),
                    game: None
                },
                &desk,
                now
            ),
            Admit::HoldBack { release: false }
        );
        assert_eq!(
            guard.admit(
                &InputMessage::Combo {
                    name: "ctrl_alt_del".into()
                },
                &desk,
                now
            ),
            Admit::HoldBack { release: false }
        );
        // A press on another window, behind ours, goes: that is how the guest leaves it.
        assert_eq!(guard.admit(&down(), &desk, now), Admit::Pass);
        // Moves and releases always go, and judge nothing.
        desk.asked.lock().unwrap().clear();
        for e in [
            InputMessage::Move { x: 0.5, y: 0.5 },
            InputMessage::Rel {
                dx: 0.1,
                dy: 0.0,
                s: None,
                x: None,
                y: None,
            },
            InputMessage::Up { b: 0 },
            key(0),
            InputMessage::ReleaseAll,
        ] {
            assert_eq!(guard.admit(&e, &desk, now), Admit::Pass, "{e:?}");
        }
        assert!(
            desk.asked.lock().unwrap().is_empty(),
            "nothing read for them"
        );

        // A press or the wheel onto our window — the request window over another one in front —
        // is held back.
        desk.place(Some(OTHER), Some(OURS));
        assert_eq!(
            guard.admit(&down(), &desk, now),
            Admit::HoldBack { release: true }
        );
        assert_eq!(
            guard.admit(
                &InputMessage::Wheel {
                    dx: 0.0,
                    dy: 1.0,
                    mode: None,
                    game: None
                },
                &desk,
                now
            ),
            Admit::HoldBack { release: false }
        );
        // But a key goes to the window in front, which is not ours.
        assert_eq!(guard.admit(&key(1), &desk, now), Admit::Pass);
    }

    /// 6a: while one of ours has the front, a press onto a window that never takes it (the
    /// on-screen keyboard) is held back — it would type into ours; with another window in front it
    /// goes, and so does the wheel over it.
    #[test]
    fn a_press_on_a_no_activate_window_is_held_back_while_ours_is_in_front() {
        let desk = Desk::default();
        let guard = OwnWindowGuard::for_process(OURS, role(ViewerRole::Guest), "s1");
        let now = Instant::now();
        desk.place(Some(OURS), None);
        desk.under_no_activate(OTHER);
        assert_eq!(
            guard.admit(&down(), &desk, now),
            Admit::HoldBack { release: true }
        );
        let wheel = InputMessage::Wheel {
            dx: 0.0,
            dy: 1.0,
            mode: None,
            game: None,
        };
        assert_eq!(
            guard.admit(&wheel, &desk, now),
            Admit::Pass,
            "a wheel types nothing"
        );
        // Another window in front: what it types goes there, not to us.
        *desk.foreground.lock().unwrap() = Some(OTHER);
        assert_eq!(guard.admit(&down(), &desk, now), Admit::Pass);
        // An ordinary window under the press with ours in front: the press brings it forward.
        desk.place(Some(OURS), Some(OTHER));
        assert_eq!(guard.admit(&down(), &desk, now), Admit::Pass);
    }

    /// 6b: while Mouse Keys is on, a key going down while the pointer is over one of ours is held
    /// back whatever has the front; off or unreadable, keys are judged by the front alone.
    #[test]
    fn with_mouse_keys_on_a_key_over_our_window_is_held_back() {
        let desk = Desk::default();
        let guard = OwnWindowGuard::for_process(OURS, role(ViewerRole::Guest), "s1");
        let now = Instant::now();
        desk.place(Some(OTHER), Some(OURS));
        for off in [None, Some(false)] {
            desk.mouse_keys(off);
            assert_eq!(guard.admit(&key(1), &desk, now), Admit::Pass, "{off:?}");
        }
        desk.mouse_keys(Some(true));
        assert_eq!(
            guard.admit(&key_of("Numpad5", 1), &desk, now),
            Admit::HoldBack { release: true }
        );
        // Text is not a numpad key: judged by the front as ever.
        assert_eq!(
            guard.admit(
                &InputMessage::Text {
                    text: "5".into(),
                    game: None
                },
                &desk,
                now
            ),
            Admit::Pass
        );
        // The pointer elsewhere: the key goes.
        desk.place(Some(OTHER), Some(OTHER));
        assert_eq!(guard.admit(&key(1), &desk, now), Admit::Pass);
    }

    /// The owner's sessions are untouched — nothing is even read — and the role is read for every
    /// event: a guest made the owner mid-session is let through from the next one, and back.
    #[test]
    fn the_owner_is_untouched_and_the_role_is_read_per_event() {
        let desk = Desk::default();
        desk.place(Some(OURS), Some(OURS));
        desk.mouse_keys(Some(true));
        let cell = role(ViewerRole::Owner);
        let guard = OwnWindowGuard::for_process(OURS, cell.clone(), "s1");
        let now = Instant::now();
        for e in [key(1), down()] {
            assert_eq!(guard.admit(&e, &desk, now), Admit::Pass);
        }
        assert!(
            desk.asked.lock().unwrap().is_empty(),
            "nothing read for the owner"
        );
        assert!(!guard.watch(&desk, now), "nor watched");

        for not_owner in [
            ViewerRole::Guest,
            ViewerRole::GuestNoOwner,
            ViewerRole::Unknown,
        ] {
            cell.put(not_owner);
            assert_eq!(
                guard.admit(&key(1), &desk, now),
                Admit::HoldBack { release: true },
                "{not_owner:?}"
            );
            cell.put(ViewerRole::Owner);
            assert_eq!(guard.admit(&key(1), &desk, now), Admit::Pass);
        }
    }

    /// A window that cannot be read lets the input go — nothing ours can be told there.
    #[test]
    fn an_unreadable_window_lets_the_input_go() {
        let desk = Desk::default();
        let guard = OwnWindowGuard::for_process(OURS, role(ViewerRole::Guest), "s1");
        desk.place(None, None);
        let now = Instant::now();
        assert_eq!(guard.admit(&key(1), &desk, now), Admit::Pass);
        assert_eq!(guard.admit(&down(), &desk, now), Admit::Pass);
        // The default injector cannot tell either.
        struct Blind;
        impl InputInjector for Blind {
            fn inject(&self, _: &InputMessage) -> anyhow::Result<()> {
                Ok(())
            }
            fn release_all(&self) {}
        }
        assert_eq!(guard.admit(&key(1), &Blind, now), Admit::Pass);
        assert_eq!(guard.admit(&down(), &Blind, now), Admit::Pass);
    }

    /// Between events: our window taking the front of a guest's session releases what is held,
    /// once per change.
    #[test]
    fn our_window_taking_the_front_releases_once() {
        let desk = Desk::default();
        let guard = OwnWindowGuard::for_process(OURS, role(ViewerRole::Guest), "s1");
        let now = Instant::now();
        desk.place(Some(OTHER), None);
        assert!(!guard.watch(&desk, now));
        desk.place(Some(OURS), None);
        assert!(guard.watch(&desk, now), "took the front: release");
        assert!(!guard.watch(&desk, now), "still in front: nothing more");
        desk.place(Some(OTHER), None);
        assert!(!guard.watch(&desk, now));
        desk.place(Some(OURS), None);
        assert!(guard.watch(&desk, now), "again");
    }

    /// End to end through the session's gate: a held-back event is not injected, and the stretch's
    /// start releases what this session held — as its own key-up, not the injector's release of
    /// everything — once.
    #[test]
    fn the_session_gate_holds_back_and_releases_its_own() {
        let desk = Arc::new(Desk::default());
        let guard = Arc::new(OwnWindowGuard::for_process(
            OURS,
            role(ViewerRole::Guest),
            "s1",
        ));
        let session = InputSession::new(desk.clone()).with_own_window_guard(guard);
        desk.place(Some(OTHER), Some(OTHER));
        assert!(!session.held_back(&key(1)));
        session.inject(&key(1)).unwrap();
        desk.place(Some(OURS), Some(OURS));
        assert!(session.held_back(&key(1)));
        assert!(session.held_back(&down()));
        let injected = desk.injected.lock().unwrap().clone();
        assert_eq!(injected.len(), 2, "the key, then its release: {injected:?}");
        assert!(
            injected[1].contains("d: 0") && injected[1].contains("KeyA"),
            "{injected:?}"
        );
        assert_eq!(*desk.releases.lock().unwrap(), 0, "nothing else released");
        // Without a guard (the owner's sessions as built before, the tests'): nothing is held back.
        let plain = InputSession::new(desk.clone());
        assert!(!plain.held_back(&key(1)));
    }

    /// The owner's concurrent session keeps what it holds when a guest's stretch begins: only the
    /// guest's own presses are released.
    #[test]
    fn a_guests_release_leaves_the_owners_held_keys() {
        let desk = Arc::new(Desk::default());
        let owner = InputSession::new(desk.clone()).with_own_window_guard(Arc::new(
            OwnWindowGuard::for_process(OURS, role(ViewerRole::Owner), "s-owner"),
        ));
        let guest = InputSession::new(desk.clone()).with_own_window_guard(Arc::new(
            OwnWindowGuard::for_process(OURS, role(ViewerRole::Guest), "s-guest"),
        ));
        desk.place(Some(OTHER), Some(OTHER));
        owner.inject(&key_of("ShiftLeft", 1)).unwrap();
        owner.inject(&InputMessage::Down { b: 2 }).unwrap();
        guest.inject(&key_of("KeyW", 1)).unwrap();
        guest.inject(&InputMessage::Down { b: 0 }).unwrap();
        desk.injected.lock().unwrap().clear();
        desk.place(Some(OURS), Some(OURS));
        assert!(guest.held_back(&key(1)));
        let released = desk.injected.lock().unwrap().clone();
        assert_eq!(released.len(), 2, "{released:?}");
        assert!(released
            .iter()
            .any(|e| e.contains("KeyW") && e.contains("d: 0")));
        assert!(released.iter().any(|e| e.contains("Up { b: 0 }")));
        assert!(!released
            .iter()
            .any(|e| e.contains("ShiftLeft") || e.contains("b: 2")));
        assert_eq!(
            *desk.releases.lock().unwrap(),
            0,
            "no release of everything"
        );
        // The owner's session still holds them, and passes.
        assert!(!owner.held_back(&key(1)));
    }

    /// The watch task stops with the session and releases this session's held key when our window
    /// takes the front.
    #[tokio::test]
    async fn the_watch_task_releases_and_stops_with_the_session() {
        let desk = Arc::new(Desk::default());
        let guard = Arc::new(OwnWindowGuard::for_process(
            OURS,
            role(ViewerRole::Guest),
            "s1",
        ));
        let input = Arc::new(InputSession::new(desk.clone()));
        input.inject(&key(1)).unwrap();
        desk.place(Some(OTHER), None);
        let stop = Arc::new(AtomicBool::new(false));
        let task = tokio::spawn(watch_task(
            guard,
            input.clone(),
            desk.clone() as Arc<dyn InputInjector>,
            stop.clone(),
        ));
        let injected = || desk.injected.lock().unwrap().len();
        tokio::time::sleep(OWN_WINDOW_EVERY * 2).await;
        assert_eq!(injected(), 1, "only the key so far");
        desk.place(Some(OURS), None);
        for _ in 0..50 {
            if injected() > 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(injected(), 2, "its key-up");
        assert_eq!(*desk.releases.lock().unwrap(), 0);
        stop.store(true, Ordering::SeqCst);
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .expect("stops with the session")
            .expect("no panic");
    }

    /// A [`Desk`] whose window reads wait at a gate while `stuck`, and then `slow` more: a read
    /// behind the input planner's lock, held by an injection that does not come back. What it
    /// returns is what it saw before the wait — as old as the wait.
    #[derive(Default)]
    struct GatedDesk {
        desk: Desk,
        stuck: AtomicBool,
        /// Injections wait at the gate too: an injection stuck on the driver, holding the input
        /// session's gate.
        stuck_inject: AtomicBool,
        gate: crate::offload::tests::Gate,
        slow: StdMutex<Duration>,
    }

    impl InputInjector for GatedDesk {
        fn inject(&self, event: &InputMessage) -> anyhow::Result<()> {
            if self.stuck_inject.load(Ordering::SeqCst) {
                self.gate.wait();
            }
            self.desk.inject(event)
        }
        fn release_all(&self) {
            self.desk.release_all();
        }
        fn window_owner(&self, target: WindowTarget) -> Option<WindowOwner> {
            let seen = self.desk.window_owner(target);
            if self.stuck.load(Ordering::SeqCst) {
                self.gate.wait();
            }
            let slow = *self.slow.lock().unwrap();
            if !slow.is_zero() {
                std::thread::sleep(slow);
            }
            seen
        }
        fn mouse_keys_on(&self) -> Option<bool> {
            self.desk.mouse_keys_on()
        }
    }

    /// The watch between events is stuck reading the front (the planner's lock held): it does not
    /// hold the guard's lock meanwhile, and the guest's next key — whose own read waits too — waits
    /// off the runtime's only worker, so its timers keep going. Once let go, both finish, the key
    /// goes, and the slow read is said.
    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn a_stuck_window_read_holds_neither_the_guards_lock_nor_the_runtime() {
        let gated = Arc::new(GatedDesk::default());
        gated.desk.place(Some(OTHER), Some(OTHER));
        let guard = Arc::new(OwnWindowGuard::for_process(
            OURS,
            role(ViewerRole::Guest),
            "s1",
        ));
        let input = Arc::new(
            InputSession::new(gated.clone() as Arc<dyn InputInjector>)
                .with_own_window_guard(guard.clone()),
        );
        let ticks = Arc::new(std::sync::atomic::AtomicU32::new(0));
        let t = ticks.clone();
        let ticker = tokio::spawn(async move {
            let mut every = tokio::time::interval(Duration::from_millis(10));
            loop {
                every.tick().await;
                t.fetch_add(1, Ordering::SeqCst);
            }
        });
        // Waits on the test's own thread, never on the runtime's worker.
        let wait_for = |what: &str, cond: &dyn Fn() -> bool| {
            let deadline = Instant::now() + Duration::from_secs(5);
            while !cond() {
                assert!(Instant::now() < deadline, "timed out waiting for {what}");
                std::thread::sleep(Duration::from_millis(5));
            }
        };

        gated.stuck.store(true, Ordering::SeqCst);
        let (g, d) = (guard.clone(), gated.clone());
        let watching = std::thread::spawn(move || g.watch(&*d, Instant::now()));
        wait_for("the watch's read to hang", &|| {
            gated.gate.waiting.load(Ordering::SeqCst) == 1
        });
        assert!(
            guard.state.try_lock().is_ok(),
            "the guard's lock is not held across a window read"
        );

        let i = input.clone();
        let keyed = tokio::spawn(async move { i.held_back(&key(1)) });
        wait_for("the key's read to hang", &|| {
            gated.gate.waiting.load(Ordering::SeqCst) == 2
        });
        let before = ticks.load(Ordering::SeqCst);
        std::thread::sleep(Duration::from_millis(200));
        let after = ticks.load(Ordering::SeqCst);
        assert!(
            after - before >= 2,
            "the runtime stalled while the key waited: {} ticks in 200 ms",
            after - before
        );

        gated.stuck.store(false, Ordering::SeqCst);
        gated.gate.open();
        let held = tokio::time::timeout(Duration::from_secs(5), keyed)
            .await
            .expect("the key's judgement comes back once let go")
            .expect("no panic");
        assert!(!held, "another window in front: the key goes");
        assert!(
            !watching.join().expect("no panic"),
            "ours did not take the front"
        );
        ticker.abort();
    }

    /// KB-3: an injection stuck on the driver holds the input session's gate. The watch between
    /// events, on the runtime's only worker, keeps looking — it does not wait for that gate to know
    /// whether the session still goes — so the runtime's timers keep going; and once the session
    /// is refused the watch ends within a tick or two, the injection still stuck.
    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn the_watch_neither_waits_for_nor_stalls_on_an_injection_stuck_on_the_driver() {
        let gated = Arc::new(GatedDesk::default());
        gated.desk.place(Some(OTHER), Some(OTHER));
        let guard = Arc::new(OwnWindowGuard::for_process(
            OURS,
            role(ViewerRole::Guest),
            "s1",
        ));
        let input = Arc::new(InputSession::new(gated.clone() as Arc<dyn InputInjector>));
        let ticks = Arc::new(std::sync::atomic::AtomicU32::new(0));
        let t = ticks.clone();
        let ticker = tokio::spawn(async move {
            let mut every = tokio::time::interval(Duration::from_millis(10));
            loop {
                every.tick().await;
                t.fetch_add(1, Ordering::SeqCst);
            }
        });
        // Waits on the test's own thread, never on the runtime's worker; false when out of time.
        let wait_for = |cond: &dyn Fn() -> bool, within: Duration| {
            let deadline = Instant::now() + within;
            while !cond() {
                if Instant::now() >= deadline {
                    return false;
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            true
        };

        gated.stuck_inject.store(true, Ordering::SeqCst);
        let i = input.clone();
        let injecting = std::thread::spawn(move || i.inject(&key(1)));
        assert!(
            wait_for(
                &|| gated.gate.waiting.load(Ordering::SeqCst) == 1,
                Duration::from_secs(5)
            ),
            "the injection hangs on the driver"
        );

        let stop = Arc::new(AtomicBool::new(false));
        let watch = tokio::spawn(watch_task(
            guard,
            input.clone(),
            gated.clone() as Arc<dyn InputInjector>,
            stop.clone(),
        ));
        let looked = || gated.desk.asked.lock().unwrap().len();
        let before = ticks.load(Ordering::SeqCst);
        std::thread::sleep(OWN_WINDOW_EVERY * 4 + Duration::from_millis(50));
        let ticked = ticks.load(Ordering::SeqCst) - before;
        let watched = looked();
        input.refuse("test: the session's end is decided");
        let ended = wait_for(&|| watch.is_finished(), Duration::from_secs(2));

        // Let the stuck injection go before judging, so a failure fails rather than hangs.
        gated.stuck_inject.store(false, Ordering::SeqCst);
        gated.gate.open();
        let landed = injecting.join().expect("no panic");
        ticker.abort();
        assert!(
            ticked >= 10,
            "the runtime stalled behind the watch: {ticked} ticks in 450 ms"
        );
        assert!(watched >= 3, "the watch looked {watched} times in 4 ticks");
        assert!(ended, "the watch ends once the session is refused");
        assert!(
            landed.expect("no error"),
            "the event already inside the injector lands"
        );
        input.close();
    }

    /// A guest's key whose read is stuck (the planner's lock), and during the stall one of our
    /// windows takes the front: the stale answer ("another window") is not trusted — read again,
    /// the key is held back. `role_during` flips the viewer's role while it waits.
    fn key_after_a_stuck_read(role_during: &[ViewerRole]) -> Admit {
        let gated = Arc::new(GatedDesk::default());
        gated.desk.place(Some(OTHER), Some(OTHER));
        let cell = role(ViewerRole::Guest);
        let guard = Arc::new(OwnWindowGuard::for_process(OURS, cell.clone(), "s1"));
        gated.stuck.store(true, Ordering::SeqCst);
        let (g, d) = (guard.clone(), gated.clone());
        let keyed = std::thread::spawn(move || g.admit(&key(1), &*d, Instant::now()));
        let deadline = Instant::now() + Duration::from_secs(5);
        while gated.gate.waiting.load(Ordering::SeqCst) == 0 {
            assert!(Instant::now() < deadline, "the key's read hangs");
            std::thread::sleep(Duration::from_millis(5));
        }
        // During the stall: our window takes the front, the role changes as asked.
        gated.desk.place(Some(OURS), Some(OTHER));
        for r in role_during {
            cell.put(*r);
        }
        std::thread::sleep(SLOW_READ + Duration::from_millis(30));
        gated.stuck.store(false, Ordering::SeqCst);
        gated.gate.open();
        keyed.join().expect("no panic")
    }

    #[test]
    fn a_guests_key_after_a_stale_read_is_judged_on_a_fresh_one() {
        assert_eq!(
            key_after_a_stuck_read(&[]),
            Admit::HoldBack { release: true },
            "our window took the front during the stall: held back"
        );
    }

    /// The role changes during a stuck read: judged by the role at the decision. Became the owner:
    /// the key goes, our window in front or not. Owner and back to guest: held back.
    #[test]
    fn a_role_change_during_a_stuck_read_is_judged_by_the_role_at_the_decision() {
        assert_eq!(
            key_after_a_stuck_read(&[ViewerRole::Owner]),
            Admit::Pass,
            "guest -> owner: an owner's key is never held back"
        );
        assert_eq!(
            key_after_a_stuck_read(&[ViewerRole::Owner, ViewerRole::Guest]),
            Admit::HoldBack { release: true },
            "guest -> owner -> guest: a guest's again"
        );
    }

    /// Both reads slow (the planner's lock busy throughout): the windows cannot be known in time,
    /// so a guest's key is held back without beginning a stretch; an owner's goes.
    #[test]
    fn a_guests_key_is_held_back_when_the_windows_cannot_be_read_in_time() {
        let gated = Arc::new(GatedDesk::default());
        gated.desk.place(Some(OTHER), Some(OTHER));
        *gated.slow.lock().unwrap() = SLOW_READ + Duration::from_millis(20);
        let guard = OwnWindowGuard::for_process(OURS, role(ViewerRole::Guest), "s1");
        assert_eq!(
            guard.admit(&key(1), &*gated, Instant::now()),
            Admit::HoldBack { release: false }
        );
        assert!(
            guard.state.lock().unwrap().stretch.is_none(),
            "no stretch begun"
        );
        let owner = OwnWindowGuard::for_process(OURS, role(ViewerRole::Owner), "s2");
        assert_eq!(owner.admit(&key(1), &*gated, Instant::now()), Admit::Pass);
    }
}
