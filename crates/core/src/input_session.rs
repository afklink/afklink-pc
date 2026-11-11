//! Serialize a session's final release with input already queued by its peer.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use afklink_protocol::{InputMessage, INPUT_SILENCE_RELEASE_MS};
use afklink_transport::PeerEvent;
use anyhow::Result;

use crate::game_input::InputScopeSource;
use crate::own_windows::{Admit, OwnWindowGuard};
use crate::traits::{InputInjector, InputScope};

/// Transfer a potentially blocking driver operation off a Tokio worker, including gate waits.
/// Synchronous callers and current-thread mock runtimes execute directly.
///
/// Only wrap operations that can actually block on the OS device: a single HID report is bounded at
/// 250 ms and a full `release_all` with retries at ~2 s worst case, and either would stall an async
/// worker if run on it directly. The gate reads (`is_active`) must *not* go through here — they
/// are two atomic loads, take no lock and never wait (KB-3), and run on the hot path (one check per
/// viewer event), where the `block_in_place` accounting is pure overhead and needs a multi-thread
/// runtime it may not be on.
pub(crate) fn blocking<R>(operation: impl FnOnce() -> R) -> R {
    if tokio::runtime::Handle::try_current()
        .is_ok_and(|handle| handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread)
    {
        tokio::task::block_in_place(operation)
    } else {
        operation()
    }
}

struct State {
    needs_release: bool,
    /// What this session pressed and has not released ([`InputSession::release_own`]).
    pressed: Pressed,
    /// Whether a press refused past [`MAX_HELD_KEYS`] has been warned about: once a session, the
    /// rest go to the input tally's failure count.
    cap_warned: bool,
}

/// The session's cap on distinct held keys ([`crate::traits::MAX_HELD_KEYS`], KB-6).
pub(crate) use crate::traits::MAX_HELD_KEYS;

/// The buttons and keys one session pressed through the injector and has not released, by the
/// viewer's own names — what [`InputSession::release_own`] releases: this session's, where
/// [`InputSession::release_all`] releases everything the process-wide injector holds, a concurrent
/// session's included (the injector keeps one ledger for the whole process).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct Pressed {
    buttons: BTreeSet<u8>,
    /// Each held key by its `code` — what every injector presses and releases a key by — with the
    /// `key` its latest press carried, for the key-up that names it. One entry a code: a press of
    /// it again under another `key` (Shift changes `a` to `A`) is the same key on the PC, and its
    /// key-up releases it whatever `key` that carries. At most [`MAX_HELD_KEYS`].
    ///
    /// A key-up the injector refused leaves its entry (the key may still be down); so a code whose
    /// key-ups keep failing stays here, and counts toward the cap, until a key-up of it goes, a
    /// `ra` ([`InputMessage::ReleaseAll`]) or the session's own release or close. Such entries are
    /// few — only codes an injector can press are noted ([`InputInjector::press_may_hold`]).
    keys: BTreeMap<String, Option<String>>,
}

impl Pressed {
    /// Whether a press of `event` would be a key beyond [`MAX_HELD_KEYS`]: a key-down of a code
    /// not held while the cap is full. `may_hold`: whether the press can hold anything at all
    /// ([`InputInjector::press_may_hold`]) — one that cannot is never noted, so it is not refused.
    fn over_cap(&self, event: &InputMessage, may_hold: bool) -> bool {
        match event {
            InputMessage::Key { d, code, .. } if *d != 0 && may_hold => {
                self.keys.len() >= MAX_HELD_KEYS && !self.keys.contains_key(code)
            }
            _ => false,
        }
    }

    /// `event` was handed to the injector (`applied`: it said so). A press that can hold
    /// something (`may_hold`, [`InputInjector::press_may_hold`]) counts either way — an injector
    /// may apply part of one and fail — and one that cannot (dropped by game-only mode, a code no
    /// key has) is never noted: it left nothing to release. A release only once it went.
    fn note(&mut self, event: &InputMessage, applied: bool, may_hold: bool) {
        match event {
            InputMessage::Down { b } if may_hold => {
                self.buttons.insert(*b);
            }
            InputMessage::Up { b } if applied => {
                self.buttons.remove(b);
            }
            InputMessage::Key { d, code, key, .. } => {
                if *d != 0 {
                    if may_hold {
                        // Bounded by the caller: a new code past the cap never gets here
                        // ([`Self::over_cap`]).
                        self.keys.insert(code.clone(), key.clone());
                    }
                } else if applied {
                    self.keys.remove(code);
                }
            }
            InputMessage::ReleaseAll if applied => *self = Self::default(),
            _ => {}
        }
    }

    fn is_empty(&self) -> bool {
        self.buttons.is_empty() && self.keys.is_empty()
    }
}

pub(crate) struct InputSession {
    injector: Arc<dyn InputInjector>,
    /// Set the moment the session's end is decided ([`Self::refuse`]), without a lock: from then
    /// on no event of it is injected, even while the gate's close ([`Self::close_gate`]) still waits
    /// for `state` behind an injection stuck on the driver. Checked before `state` is taken and
    /// again under it, so only an event already inside the injector lands.
    refused: AtomicBool,
    /// The gate is open: no [`Self::close_gate`] has closed it. Written only under `state` (where it
    /// flips, once, to false), so a holder of `state` sees it as the gate stands; read without a
    /// lock by [`Self::is_active`], which must never wait for `state` (KB-3: an injection stuck on
    /// the driver holds it, and the readers between events are async tasks on a shared worker).
    open: AtomicBool,
    state: Mutex<State>,
    /// Where this session's input may go (game-only mode, `crate::game_input`); `None`: always the
    /// desktop.
    scope: Option<Arc<InputScopeSource>>,
    /// A guest's input stops short of AFKLink's own windows (`crate::own_windows`); `None`:
    /// nothing is held back (the tests' sessions).
    own: Option<Arc<OwnWindowGuard>>,
}

impl InputSession {
    /// A session whose input always goes to the desktop (tests; the agent's sessions have a scope).
    #[cfg(test)]
    pub(crate) fn new(injector: Arc<dyn InputInjector>) -> Self {
        Self::build(injector, None)
    }

    /// A session whose input goes where `scope` says, event by event: the desktop, or — while the
    /// owner has «only the game window» on — the game's window alone.
    pub(crate) fn with_scope(
        injector: Arc<dyn InputInjector>,
        scope: Arc<InputScopeSource>,
    ) -> Self {
        Self::build(injector, Some(scope))
    }

    fn build(injector: Arc<dyn InputInjector>, scope: Option<Arc<InputScopeSource>>) -> Self {
        // `begin_session` opens the OS device on the first session (driver enumeration and a HID
        // handle open), which is blocking driver work, so it goes off the async worker.
        blocking(|| injector.begin_session());
        Self {
            injector,
            refused: AtomicBool::new(false),
            open: AtomicBool::new(true),
            state: Mutex::new(State {
                needs_release: false,
                pressed: Pressed::default(),
                cap_warned: false,
            }),
            scope,
            own: None,
        }
    }

    /// Hold a guest's input back from AFKLink's own windows through `guard` ([`Self::held_back`]).
    #[must_use]
    pub(crate) fn with_own_window_guard(mut self, guard: Arc<OwnWindowGuard>) -> Self {
        self.own = Some(guard);
        self
    }

    /// Whether `event` stops short of AFKLink's own windows — a guest's session, an AFKLink window in
    /// front or under the press (`crate::own_windows`). When a stretch of it begins, what this
    /// session holds is released first ([`Self::release_own`]: not a concurrent owner's session's).
    /// The caller then does not inject it.
    ///
    /// A refused session judges nothing (no window is read, nothing released): its event goes on to
    /// [`Self::inject`], which refuses it.
    pub(crate) fn held_back(&self, event: &InputMessage) -> bool {
        let Some(guard) = &self.own else {
            return false;
        };
        if self.is_refused() {
            return false;
        }
        match guard.admit(event, &*self.injector, Instant::now()) {
            Admit::Pass => false,
            Admit::HoldBack { release } => {
                if release {
                    self.release_own("a stretch of input held back from an AFKLink window began");
                }
                true
            }
        }
    }

    /// Release what this session holds — its own presses, as a key-up and a button-up each, through
    /// the injector like any of its events — and nothing a concurrent session holds: where
    /// [`Self::release_all`] releases the whole process-wide injector, an owner's session alongside
    /// a guest's keeps its held keys here (`why`: what asked, for the log). A key both sessions hold
    /// is one key on the PC, and goes up. Through the session's gate: nothing after its end.
    ///
    /// Nothing once the session is refused: its gate's close releases what it holds.
    pub(crate) fn release_own(&self, why: &str) {
        if self.is_refused() {
            tracing::trace!(
                why,
                "own release: the session is refused (its close releases)"
            );
            return;
        }
        blocking(|| {
            let mut state = self.state();
            if !self.is_open() || self.is_refused() {
                tracing::trace!(why, "own release: the session already ended");
                return;
            }
            let pressed = std::mem::take(&mut state.pressed);
            if pressed.is_empty() {
                tracing::trace!(why, "own release: this session holds nothing");
                return;
            }
            let scope = self
                .scope
                .as_ref()
                .map_or(InputScope::Desktop, |scope| scope.scope());
            let (buttons, keys) = (pressed.buttons.len(), pressed.keys.len());
            let mut failed = 0usize;
            let ups = pressed
                .buttons
                .into_iter()
                .map(|b| InputMessage::Up { b })
                .chain(
                    pressed
                        .keys
                        .into_iter()
                        .map(|(code, key)| InputMessage::Key {
                            d: 0,
                            code,
                            key,
                            mods: None,
                            src: None,
                        }),
                );
            for up in ups {
                if let Err(e) = self.injector.inject_scoped(&up, &scope) {
                    failed += 1;
                    tracing::debug!(why, "own release: a release not injected: {e:#}");
                }
            }
            // not-a-key-name: counts of held buttons and keys
            tracing::debug!(
                why,
                buttons,
                keys,
                failed,
                "own release: this session's held buttons and keys released (not other sessions')"
            );
        });
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|error| {
            tracing::warn!("input session gate poisoned; recovering to allow final release");
            error.into_inner()
        })
    }

    /// The session's end is decided: no event of it is injected from now on (see `refused`). On the
    /// caller's thread, without a lock and without waiting — the orchestrator's, at an end, a kill
    /// switch or the exit. True when this call refused it (`why`: for the log).
    pub(crate) fn refuse(&self, why: &str) -> bool {
        let first = !self.refused.swap(true, Ordering::SeqCst);
        if first {
            tracing::debug!(
                why,
                "input session refused: no event of it is injected from now on"
            );
        }
        first
    }

    fn is_refused(&self) -> bool {
        self.refused.load(Ordering::SeqCst)
    }

    /// Whether the gate is open; under `state` this is the gate as it stands (see `open`).
    fn is_open(&self) -> bool {
        self.open.load(Ordering::SeqCst)
    }

    /// Whether the session's input still goes: not refused, and its gate not closed. Never takes
    /// `state` and never waits (KB-3): it is read between events by async tasks on the shared
    /// runtime — the viewer's event task, the own-windows watch (`crate::own_windows`) — while an
    /// injection may hold `state` stuck on the driver, and a wait there would take a worker. Called
    /// once per viewer event, so it stays off the `block_in_place` path (see `blocking`). Refused
    /// is not active, even while the gate's close still waits for `state`.
    pub(crate) fn is_active(&self) -> bool {
        !self.is_refused() && self.is_open()
    }

    /// False means teardown won the gate (or the session is refused); the queued event must not be
    /// acknowledged.
    pub(crate) fn inject(&self, event: &InputMessage) -> Result<bool> {
        if self.is_refused() {
            tracing::debug!("queued input discarded: its session is refused (its end is decided)");
            return Ok(false);
        }
        blocking(|| {
            let mut state = self.state();
            // Again under the lock: the refusal may have come while this waited for it.
            if !self.is_open() || self.is_refused() {
                tracing::debug!("queued input discarded: its session already ended");
                return Ok(false);
            }
            // Read per event: the owner's switch and the game's window take effect at once.
            let scope = self
                .scope
                .as_ref()
                .map_or(InputScope::Desktop, |scope| scope.scope());
            let may_hold = self.injector.press_may_hold(event, &scope);
            if state.pressed.over_cap(event, may_hold) {
                // A flood is a hot path: the first refusal of a session is warned, the rest are
                // counted by the caller's tally as failures. No key is named.
                if !state.cap_warned {
                    state.cap_warned = true;
                    tracing::warn!(
                        held = state.pressed.keys.len(),
                        cap = MAX_HELD_KEYS,
                        "key press refused: this session already holds the most keys it may \
                         (said once a session; the rest are counted as failures)"
                    );
                } else {
                    tracing::trace!("key press refused: the session's held keys are at the cap");
                }
                anyhow::bail!("key press refused: the session holds {MAX_HELD_KEYS} keys already");
            }
            if !may_hold
                && matches!(
                    event,
                    InputMessage::Down { .. } | InputMessage::Key { d: 1.., .. }
                )
            {
                tracing::trace!("press not noted: the injector says it can hold nothing");
            }
            // An injector can partially apply an event before returning an error.
            state.needs_release = true;
            let injected = self.injector.inject_scoped(event, &scope);
            state.pressed.note(event, injected.is_ok(), may_hold);
            injected?;
            // ReleaseAll also returns Ok from injectors whose void release_all logged a failure.
            // Keep the final close eligible to retry their pending neutral reports.
            Ok(true)
        })
    }

    pub(crate) fn release_all(&self) {
        blocking(|| {
            let mut state = self.state();
            if self.is_open() && state.needs_release {
                // Everything the injector holds goes, this session's own included.
                state.pressed = Pressed::default();
                self.injector.release_all();
                // The trait cannot report release failure. Keep the final close eligible to retry;
                // the backend's held-state ledger decides whether anything remains to release.
            }
        });
    }

    /// Close the gate, release what the session holds, and end its injector session.
    pub(crate) fn close(&self) {
        if self.close_gate() {
            self.end_injector_session();
        }
    }

    /// The first half of [`Self::close`]: the gate closes — no event of this session is injected
    /// once this returns — and what the session holds is released. True when this call closed it;
    /// its injector session is then still open, for [`Self::end_injector_session`]. False when the
    /// gate was already closed (by another close: that one ends the injector session).
    pub(crate) fn close_gate(&self) -> bool {
        self.refuse("its gate closes");
        blocking(|| {
            let mut state = self.state();
            if !self.is_open() {
                tracing::debug!("input session gate already closed");
                return false;
            }
            // Under `state`, after `refuse` above: whoever reads it closed already sees the refusal.
            self.open.store(false, Ordering::SeqCst);
            tracing::debug!(
                needs_release = state.needs_release,
                "input session gate closed"
            );
            if state.needs_release {
                self.injector.release_all();
                state.needs_release = false;
            }
            state.pressed = Pressed::default();
            true
        })
    }

    /// The second half of [`Self::close`], once per session after a [`Self::close_gate`] that
    /// returned true: the injector's session count goes down (the last one closes the driver).
    pub(crate) fn end_injector_session(&self) {
        blocking(|| self.injector.end_session());
    }
}

/// Every viewer data-channel message proves liveness, including telemetry and malformed data.
/// Local transport events never postpone the clock. Poll before receiving, even when the event
/// queue is continuously ready, so a hot queue cannot starve the release deadline.
pub(crate) struct InputSilence {
    deadline: Option<Instant>,
}

impl InputSilence {
    const TIMEOUT: Duration = Duration::from_millis(INPUT_SILENCE_RELEASE_MS);

    pub(crate) fn new() -> Self {
        Self { deadline: None }
    }

    pub(crate) fn note_peer_event(&mut self, now: Instant, event: &PeerEvent) {
        if matches!(event, PeerEvent::InputData(_)) {
            self.deadline = Some(now + Self::TIMEOUT);
        }
    }

    pub(crate) fn disarm(&mut self) {
        self.deadline = None;
    }

    pub(crate) fn release_due(&mut self, now: Instant) -> bool {
        if self.deadline.is_some_and(|deadline| now >= deadline) {
            self.deadline = None;
            true
        } else {
            false
        }
    }

    pub(crate) fn remaining(&self, now: Instant) -> Duration {
        self.deadline
            .map(|deadline| deadline.saturating_duration_since(now))
            .unwrap_or(Self::TIMEOUT)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use std::sync::{mpsc, Barrier};

    fn key() -> InputMessage {
        InputMessage::Key {
            d: 1,
            code: "KeyW".into(),
            key: None,
            mods: None,
            src: None,
        }
    }

    #[derive(Default)]
    struct Recorder(Mutex<Vec<&'static str>>);

    impl InputInjector for Recorder {
        fn inject(&self, _: &InputMessage) -> Result<()> {
            self.0.lock().unwrap().push("input");
            Ok(())
        }

        fn release_all(&self) {
            self.0.lock().unwrap().push("release");
        }
    }

    #[test]
    fn local_transport_events_do_not_postpone_viewer_silence() {
        let recorder = Arc::new(Recorder::default());
        let session = InputSession::new(recorder.clone());
        let mut silence = InputSilence::new();
        let start = Instant::now();
        session.inject(&key()).unwrap();
        silence.note_peer_event(
            start,
            &PeerEvent::InputData(br#"{"t":"k","d":1,"code":"KeyW"}"#.to_vec()),
        );
        // Continuously ready local events: no recv timeout can fire in this scenario.
        for ms in (0..=3_000).step_by(100) {
            let now = start + Duration::from_millis(ms);
            if silence.release_due(now) {
                session.release_all();
            }
            silence.note_peer_event(now, &PeerEvent::BitrateEstimate { kbps: 4_000 });
            silence.note_peer_event(
                now,
                &PeerEvent::LinkStats {
                    rtt_ms: Some(20),
                    loss: Some(0.0),
                    plis: 0,
                    nacks: 0,
                    firs: 0,
                },
            );
        }
        assert_eq!(*recorder.0.lock().unwrap(), ["input", "release"]);
        assert!(!silence.release_due(start + Duration::from_secs(20)));
    }

    #[test]
    fn viewer_data_extends_deadline_and_release_all_disarms_it() {
        let mut silence = InputSilence::new();
        let start = Instant::now();
        assert!(!silence.release_due(start + Duration::from_secs(20)));
        silence.note_peer_event(
            start,
            &PeerEvent::InputData(br#"{"t":"k","d":1,"code":"ShiftLeft"}"#.to_vec()),
        );
        silence.note_peer_event(
            start + Duration::from_secs(1),
            &PeerEvent::InputData(br#"{"t":"q","q":"auto"}"#.to_vec()),
        );
        assert!(!silence.release_due(start + Duration::from_secs(2)));
        assert_eq!(
            silence.remaining(start + Duration::from_secs(2)),
            Duration::from_secs(1)
        );
        silence.note_peer_event(
            start + Duration::from_secs(2),
            &PeerEvent::InputData(br#"{"t":"ra"}"#.to_vec()),
        );
        silence.disarm();
        assert!(!silence.release_due(start + Duration::from_secs(3)));
    }

    #[derive(Default)]
    struct HeldRecorder {
        held: Mutex<(bool, bool)>,
        releases: Mutex<usize>,
    }

    impl InputInjector for HeldRecorder {
        fn inject(&self, event: &InputMessage) -> Result<()> {
            match event {
                InputMessage::Down { b: 2 } => self.held.lock().unwrap().0 = true,
                InputMessage::Key { d: 1, code, .. } if code == "ShiftLeft" => {
                    self.held.lock().unwrap().1 = true;
                }
                InputMessage::ReleaseAll => self.release_all(),
                _ => {}
            }
            Ok(())
        }

        fn release_all(&self) {
            *self.held.lock().unwrap() = (false, false);
            *self.releases.lock().unwrap() += 1;
        }
    }

    fn hold_right_mouse_and_shift(session: &InputSession) {
        session.inject(&InputMessage::Down { b: 2 }).unwrap();
        session
            .inject(&InputMessage::Key {
                d: 1,
                code: "ShiftLeft".into(),
                key: None,
                mods: None,
                src: None,
            })
            .unwrap();
    }

    #[test]
    fn viewer_reports_keep_stationary_right_mouse_and_shift_held_until_viewer_goes_silent() {
        for report in [
            br#"{"t":"vv"}"#.as_slice(),
            br#"{"t":"vl","jbuf_ms":10,"frames":60,"jitter_ms":0}"#.as_slice(),
            br#"{"t":"q","q":"auto"}"#.as_slice(),
            b"malformed JSON".as_slice(),
            &[0xff], // Invalid UTF-8 is also data from the authorized viewer.
        ] {
            let recorder = Arc::new(HeldRecorder::default());
            let session = InputSession::new(recorder.clone());
            let mut silence = InputSilence::new();
            let start = Instant::now();
            hold_right_mouse_and_shift(&session);
            silence.note_peer_event(start, &PeerEvent::InputData(br#"{"t":"d","b":2}"#.to_vec()));
            for second in 1..=5 {
                let now = start + Duration::from_secs(second);
                assert!(!silence.release_due(now));
                silence.note_peer_event(now, &PeerEvent::InputData(report.to_vec()));
                assert_eq!(*recorder.held.lock().unwrap(), (true, true));
                assert_eq!(*recorder.releases.lock().unwrap(), 0);
            }
            assert!(!silence.release_due(start + Duration::from_millis(6_999)));
            assert!(silence.release_due(start + Duration::from_secs(7)));
            session.release_all();
            assert_eq!(*recorder.held.lock().unwrap(), (false, false));
            assert_eq!(*recorder.releases.lock().unwrap(), 1);
        }
    }

    #[test]
    fn viewer_disconnect_and_explicit_release_clear_held_input_without_waiting() {
        for explicit_release in [false, true] {
            let recorder = Arc::new(HeldRecorder::default());
            let session = InputSession::new(recorder.clone());
            hold_right_mouse_and_shift(&session);
            if explicit_release {
                session.inject(&InputMessage::ReleaseAll).unwrap();
                assert!(session.is_active());
            } else {
                session.close();
                assert!(!session.inject(&InputMessage::Down { b: 2 }).unwrap());
            }
            assert_eq!(*recorder.held.lock().unwrap(), (false, false));
            assert_eq!(*recorder.releases.lock().unwrap(), 1);
        }
    }

    #[test]
    fn session_hooks_bracket_final_release_once() {
        #[derive(Default)]
        struct LifecycleRecorder(Mutex<Vec<&'static str>>);
        impl InputInjector for LifecycleRecorder {
            fn begin_session(&self) {
                self.0.lock().unwrap().push("begin");
            }
            fn end_session(&self) {
                self.0.lock().unwrap().push("end");
            }
            fn inject(&self, _: &InputMessage) -> Result<()> {
                self.0.lock().unwrap().push("input");
                Ok(())
            }
            fn release_all(&self) {
                self.0.lock().unwrap().push("release");
            }
        }
        let recorder = Arc::new(LifecycleRecorder::default());
        let session = InputSession::new(recorder.clone());
        session.inject(&key()).unwrap();
        session.close();
        session.close();
        assert_eq!(
            *recorder.0.lock().unwrap(),
            ["begin", "input", "release", "end"]
        );
    }

    struct BlockingInjector {
        entered: Barrier,
        resume: Barrier,
        events: Mutex<Vec<&'static str>>,
    }

    impl InputInjector for BlockingInjector {
        fn inject(&self, _: &InputMessage) -> Result<()> {
            self.entered.wait();
            self.resume.wait();
            self.events.lock().unwrap().push("input");
            Ok(())
        }

        fn release_all(&self) {
            self.events.lock().unwrap().push("release");
        }
    }

    #[test]
    fn concurrent_close_waits_for_input_and_rejects_queued_input() {
        let injector = Arc::new(BlockingInjector {
            entered: Barrier::new(2),
            resume: Barrier::new(2),
            events: Mutex::new(Vec::new()),
        });
        let session = Arc::new(InputSession::new(injector.clone()));
        let injecting = {
            let session = session.clone();
            std::thread::spawn(move || session.inject(&key()).unwrap())
        };
        injector.entered.wait();
        assert!(
            session.state.try_lock().is_err(),
            "in-flight injection owns the gate"
        );
        let (started, ready) = mpsc::channel();
        let closing = {
            let session = session.clone();
            std::thread::spawn(move || {
                started.send(()).unwrap();
                session.close();
            })
        };
        ready.recv().unwrap();
        injector.resume.wait();
        assert!(injecting.join().unwrap());
        closing.join().unwrap();
        assert!(!session.inject(&key()).unwrap());
        session.close();
        session.release_all();
        assert_eq!(*injector.events.lock().unwrap(), ["input", "release"]);
    }

    #[test]
    fn late_release_from_ended_session_does_not_release_a_new_session() {
        let recorder = Arc::new(Recorder::default());
        let old = InputSession::new(recorder.clone());
        old.inject(&key()).unwrap();
        old.close();
        let new = InputSession::new(recorder.clone());
        new.inject(&key()).unwrap();
        old.release_all();
        old.close();
        assert_eq!(*recorder.0.lock().unwrap(), ["input", "release", "input"]);
        new.close();
    }

    /// In game-only mode the session hands every event over with its scope; an injector that cannot
    /// confine input (the trait's default) lets only releases through.
    #[test]
    fn in_game_only_mode_an_injector_that_cannot_confine_passes_only_releases() {
        use crate::game::{CaptureMode, CaptureModeCell, GameBinding, GameStatus};
        let modes = Arc::new(CaptureModeCell::new(CaptureMode::Monitor));
        let scope = Arc::new(InputScopeSource::new(
            modes.clone(),
            Arc::new(GameStatus::new()),
        ));
        let recorder = Arc::new(Recorder::default());
        let session = InputSession::with_scope(recorder.clone(), scope);
        session.inject(&key()).unwrap();
        modes.set(
            CaptureMode::GameWindow {
                binding: Some(GameBinding::new(r"C:\Game\Game.exe", "GameWindow")),
            },
            "test: on",
        );
        session.inject(&key()).unwrap();
        session.inject(&InputMessage::Down { b: 0 }).unwrap();
        session
            .inject(&InputMessage::Key {
                d: 0,
                code: "KeyW".into(),
                key: None,
                mods: None,
                src: None,
            })
            .unwrap();
        session.inject(&InputMessage::Up { b: 0 }).unwrap();
        assert_eq!(
            *recorder.0.lock().unwrap(),
            ["input", "input", "input"],
            "the desktop key, then the two releases"
        );
    }

    fn key_event(d: u8, code: &str, key: Option<&str>) -> InputMessage {
        InputMessage::Key {
            d,
            code: code.into(),
            key: key.map(Into::into),
            mods: None,
            src: None,
        }
    }

    /// KB-3: while an injection holds the gate stuck on the driver, `is_active` answers at once —
    /// true, then false the moment the session is refused — instead of waiting for the gate (which
    /// would take the async worker that asks).
    #[test]
    fn is_active_does_not_wait_for_an_injection_stuck_on_the_driver() {
        let injector = Arc::new(BlockingInjector {
            entered: Barrier::new(2),
            resume: Barrier::new(2),
            events: Mutex::new(Vec::new()),
        });
        let session = Arc::new(InputSession::new(injector.clone()));
        let injecting = {
            let session = session.clone();
            std::thread::spawn(move || session.inject(&key()).unwrap())
        };
        injector.entered.wait();
        assert!(
            session.state.try_lock().is_err(),
            "the injection holds the gate"
        );
        let ask = |session: &Arc<InputSession>| {
            let (tx, rx) = mpsc::channel();
            let session = session.clone();
            std::thread::spawn(move || tx.send(session.is_active()).unwrap());
            rx.recv_timeout(Duration::from_secs(1))
        };
        let open = ask(&session);
        session.refuse("test: the session's end is decided");
        let refused = ask(&session);
        // Let the stuck injection go before judging, so a failure fails rather than hangs.
        injector.resume.wait();
        assert!(injecting.join().unwrap(), "the event already inside lands");
        assert_eq!(open, Ok(true), "answered without waiting for the gate");
        assert_eq!(
            refused,
            Ok(false),
            "refused is not active, the gate still held"
        );
        session.close();
        assert!(!session.is_active());
    }

    /// KB-6: a flood of distinct keys stays within the cap. Ten thousand `key`s under one code are
    /// one key on the PC (one entry); ten thousand codes fill the cap, and every new one past it is
    /// refused — not injected — while a held key's repeat and every release still go. The own
    /// release then sends at most the cap's key-ups.
    #[test]
    fn a_flood_of_distinct_keys_keeps_the_held_keys_and_the_own_release_within_the_cap() {
        let recorder = Arc::new(Recorder::default());
        let session = InputSession::new(recorder.clone());
        let held = || session.state().pressed.keys.len();
        for i in 0..10_000 {
            let k = format!("k{i}");
            assert!(session.inject(&key_event(1, "KeyA", Some(&k))).unwrap());
        }
        assert_eq!(held(), 1, "one code is one key, whatever key it carries");

        let mut refused = 0;
        for i in 0..10_000 {
            match session.inject(&key_event(1, &format!("C{i}"), None)) {
                Ok(true) => {}
                Ok(false) => panic!("the session is open"),
                Err(_) => refused += 1,
            }
            assert!(held() <= MAX_HELD_KEYS);
        }
        assert_eq!(held(), MAX_HELD_KEYS);
        assert_eq!(refused, 10_000 - (MAX_HELD_KEYS - 1));
        let injected = recorder.0.lock().unwrap().len();
        assert_eq!(
            injected,
            10_000 + MAX_HELD_KEYS - 1,
            "a refused press is not injected"
        );

        assert!(
            session.inject(&key_event(1, "KeyA", Some("A"))).unwrap(),
            "a held key's repeat goes at the cap"
        );
        assert!(session.inject(&key_event(0, "C0", None)).unwrap());
        assert_eq!(
            held(),
            MAX_HELD_KEYS - 1,
            "its release goes, and frees a place"
        );
        assert!(session.inject(&key_event(1, "Fresh", None)).unwrap());
        assert_eq!(held(), MAX_HELD_KEYS);

        recorder.0.lock().unwrap().clear();
        session.release_own("test");
        assert_eq!(
            recorder.0.lock().unwrap().len(),
            MAX_HELD_KEYS,
            "one key-up a held key, no more"
        );
        assert_eq!(held(), 0);
    }

    /// A key-up releases its code whatever `key` it carries: Shift between the down and the up
    /// turns `a` into `A`, and the key is still the one key on the PC.
    #[test]
    fn a_key_up_under_another_key_releases_the_held_code() {
        let recorder = Arc::new(Recorder::default());
        let session = InputSession::new(recorder.clone());
        session.inject(&key_event(1, "KeyA", Some("a"))).unwrap();
        session.inject(&key_event(0, "KeyA", Some("A"))).unwrap();
        assert!(session.state().pressed.is_empty());
        recorder.0.lock().unwrap().clear();
        session.release_own("test");
        assert!(
            recorder.0.lock().unwrap().is_empty(),
            "nothing left to release"
        );
    }

    /// A press the injector drops in game-only mode (the trait's default cannot confine input)
    /// leaves nothing held, so it is not noted: the own release then has nothing to send. Back on
    /// the desktop a press is noted again.
    #[test]
    fn a_press_dropped_in_game_scope_is_not_noted() {
        use crate::game::{CaptureMode, CaptureModeCell, GameBinding, GameStatus};
        let modes = Arc::new(CaptureModeCell::new(CaptureMode::GameWindow {
            binding: Some(GameBinding::new(r"C:\Game\Game.exe", "GameWindow")),
        }));
        let scope = Arc::new(InputScopeSource::new(
            modes.clone(),
            Arc::new(GameStatus::new()),
        ));
        let recorder = Arc::new(Recorder::default());
        let session = InputSession::with_scope(recorder.clone(), scope);
        session.inject(&key()).unwrap();
        session.inject(&InputMessage::Down { b: 0 }).unwrap();
        assert!(
            recorder.0.lock().unwrap().is_empty(),
            "dropped by the scope"
        );
        assert!(session.state().pressed.is_empty(), "and not noted");
        session.release_own("test");
        assert!(recorder.0.lock().unwrap().is_empty(), "no key-up for it");

        modes.set(CaptureMode::Monitor, "test: off");
        session.inject(&key()).unwrap();
        assert_eq!(
            session.state().pressed.keys.len(),
            1,
            "a desktop press is noted"
        );
    }

    /// A press the injector says can hold nothing (a code no key has) is not noted, and does not
    /// count toward the cap: such presses never crowd out a real key.
    #[test]
    fn a_press_the_injector_cannot_hold_is_neither_noted_nor_capped() {
        #[derive(Default)]
        struct Unmapped(Mutex<usize>);
        impl InputInjector for Unmapped {
            fn inject(&self, _: &InputMessage) -> Result<()> {
                *self.0.lock().unwrap() += 1;
                Ok(())
            }
            fn release_all(&self) {}
            fn press_may_hold(&self, event: &InputMessage, _: &InputScope) -> bool {
                !matches!(event, InputMessage::Key { code, .. } if code.starts_with("Bogus"))
            }
        }
        let injector = Arc::new(Unmapped::default());
        let session = InputSession::new(injector.clone());
        for i in 0..1_000 {
            assert!(session
                .inject(&key_event(1, &format!("Bogus{i}"), None))
                .unwrap());
        }
        assert!(session.state().pressed.is_empty());
        assert!(session.inject(&key()).unwrap(), "a real key still goes");
        assert_eq!(session.state().pressed.keys.len(), 1);
        assert_eq!(*injector.0.lock().unwrap(), 1_001);
    }

    /// What an injector was handed, as `(d, code)` for keys and `b±` for buttons.
    #[derive(Default)]
    struct Log(Mutex<Vec<String>>);

    impl Log {
        fn push(&self, event: &InputMessage) {
            let line = match event {
                InputMessage::Key { d, code, .. } => format!("{d}{code}"),
                InputMessage::Down { b } => format!("+{b}"),
                InputMessage::Up { b } => format!("-{b}"),
                other => format!("{other:?}"),
            };
            self.0.lock().unwrap().push(line);
        }

        fn take(&self) -> Vec<String> {
            std::mem::take(&mut *self.0.lock().unwrap())
        }
    }

    /// An injector that confines input to the game (as the HID backend does): in game scope its
    /// guard may drop a press — here every one — and yet says the press may hold, since it cannot
    /// tell the session which it dropped. Such a press is noted, and the own release sends its
    /// key-up and button-up (each a harmless release of what may not be down).
    #[test]
    fn in_game_scope_a_press_a_confining_injector_drops_is_still_noted_and_released() {
        use crate::game::{CaptureMode, CaptureModeCell, GameBinding, GameStatus};
        #[derive(Default)]
        struct Confining(Log);
        impl InputInjector for Confining {
            fn inject(&self, event: &InputMessage) -> Result<()> {
                self.0.push(event);
                Ok(())
            }
            fn release_all(&self) {}
            fn inject_scoped(&self, event: &InputMessage, scope: &InputScope) -> Result<()> {
                if matches!(scope, InputScope::Game(_)) && !crate::traits::is_release(event) {
                    return Ok(()); // the guard dropped it: nothing went
                }
                self.inject(event)
            }
            fn press_may_hold(&self, _: &InputMessage, _: &InputScope) -> bool {
                true
            }
        }
        let modes = Arc::new(CaptureModeCell::new(CaptureMode::GameWindow {
            binding: Some(GameBinding::new(r"C:\Game\Game.exe", "GameWindow")),
        }));
        let scope = Arc::new(InputScopeSource::new(modes, Arc::new(GameStatus::new())));
        let injector = Arc::new(Confining::default());
        let session = InputSession::with_scope(injector.clone(), scope);
        session.inject(&key()).unwrap();
        session.inject(&InputMessage::Down { b: 2 }).unwrap();
        assert!(injector.0.take().is_empty(), "the guard dropped both");
        session.release_own("test");
        assert_eq!(
            injector.0.take(),
            ["-2", "0KeyW"],
            "both released all the same"
        );
    }

    /// Two codes the PC has as one key (Enter and NumpadEnter share VK_RETURN): down one, down the
    /// other, up the first — the injector's ledger, by VK, now holds nothing, while the session's,
    /// by code, still has the second. A superset: the own release sends its key-up (harmless), and
    /// no key is left down that the session forgot.
    #[test]
    fn two_codes_of_one_key_leave_the_ledger_a_superset() {
        #[derive(Default)]
        struct Plain(Log);
        impl InputInjector for Plain {
            fn inject(&self, event: &InputMessage) -> Result<()> {
                self.0.push(event);
                Ok(())
            }
            fn release_all(&self) {}
        }
        let injector = Arc::new(Plain::default());
        let session = InputSession::new(injector.clone());
        session.inject(&key_event(1, "Enter", None)).unwrap();
        session.inject(&key_event(1, "NumpadEnter", None)).unwrap();
        session.inject(&key_event(0, "Enter", None)).unwrap();
        injector.0.take();
        session.release_own("test");
        assert_eq!(injector.0.take(), ["0NumpadEnter"]);
    }

    #[test]
    fn explicit_release_does_not_suppress_final_cleanup_retry() {
        let recorder = Arc::new(Recorder::default());
        let session = InputSession::new(recorder.clone());
        session.inject(&key()).unwrap();
        session.inject(&InputMessage::ReleaseAll).unwrap();
        // The trait's void release cannot prove all OS writes succeeded. Closing must retry.
        session.close();
        assert_eq!(*recorder.0.lock().unwrap(), ["input", "input", "release"]);
    }
}
