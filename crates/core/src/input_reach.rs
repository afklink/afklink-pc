//! «Управление не доходит»: what the agent does with the injector's word on whether the viewer's input
//! reaches the window in front ([`InputReach`], `afklink_input`'s reach watch — three presses in a
//! row dropped within two seconds by an administrator's window, without the driver).
//!
//! - **The heartbeat** says it to the viewer once a second ([`ReachMonitor::poll`]): `no_driver`
//!   while the driver is not open where it could be (the viewer's status for 5 s on entering a game
//!   mode), `input_blocked` while presses are being dropped (the viewer's status while it lasts).
//! - **The window's highlight** — the «Управление в играх» row in red with a lime «Установить»
//!   ([`AgentState::input_not_reaching`], kept in config.json so it outlives a restart and is seen
//!   whenever the window is next opened) — is set the moment presses are found blocked, and cleared
//!   when the driver is open for a session, when the desktop app reads it installed
//!   (`AgentControl::driver_installed`), or after a session whose input got through: at least
//!   [`REACHED_PRESSES`] presses delivered and none found blocked ([`SessionVerdict`]).
//! - **The live flag** [`AgentState::input_blocked`], which the desktop app's toast follows.
//!
//! ## Logs
//!
//! `debug`: every change of the highlight, with why and the numbers it was decided from, and each
//! session's account at its end (presses dropped and delivered in it, how often blocked began, the
//! verdict, and the driver the session had — [`SessionDriver`]: by then the injector may have
//! closed the device already, so the end's reading alone would say `missing`). What the heartbeat
//! says is in its own «heartbeat changed» line. Nothing per heartbeat.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::agent::AgentState;
use crate::config::Config;
use crate::sync::lock;
use crate::traits::{DriverPresence, InputInjector, InputReach};

/// The driver as a session had it, from what it was read as while the session lived: at its start
/// ([`ReachMonitor::read`]) and on every heartbeat ([`ReachMonitor::poll`]).
///
/// The session's account is written when the session ends, and by then the last session's input may
/// have closed the device already (the viewer's own hang-up closes the input before the agent tears
/// the session down: a session that ran on the driver throughout logged «input device closed» and
/// then `driver="missing"`). So the account says the driver the session had: open if it
/// was ever read open in it, else the last reading in it; the end's reading is said beside it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SessionDriver {
    /// Read open at least once while the session lived.
    open: bool,
    /// The last reading while it lived.
    last: DriverPresence,
}

impl SessionDriver {
    fn new(reading: DriverPresence) -> Self {
        Self {
            open: reading == DriverPresence::Open,
            last: reading,
        }
    }

    fn saw(&mut self, reading: DriverPresence) {
        self.open |= reading == DriverPresence::Open;
        self.last = reading;
    }

    /// What the session's account says.
    pub(crate) fn had(self) -> DriverPresence {
        if self.open {
            DriverPresence::Open
        } else {
            self.last
        }
    }
}

/// Sessions whose heartbeat has not been seen this long are forgotten (one that never reached its
/// end — the agent's teardown missed it — must not be kept for the process's life).
const SESSION_DRIVER_KEPT: std::time::Duration = std::time::Duration::from_secs(600);

/// A session whose input got through: at least this many presses delivered, and none of its
/// presses found blocked. As many as it takes to find them blocked: a session that only watched,
/// or pressed once or twice, says nothing either way.
pub(crate) const REACHED_PRESSES: u64 = 3;

/// What a session's input says about the highlight, at its end.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SessionVerdict {
    /// Presses were found blocked in it: the highlight stays.
    Blocked,
    /// Its input got through: the highlight goes.
    GotThrough,
    /// Too few presses to say: the highlight stays as it is.
    TooLittle,
}

impl SessionVerdict {
    /// From the presses dropped and delivered in the session, and how often blocked began in it.
    pub(crate) fn of(delivered: u64, episodes: u64) -> Self {
        if episodes > 0 {
            Self::Blocked
        } else if delivered >= REACHED_PRESSES {
            Self::GotThrough
        } else {
            Self::TooLittle
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Blocked => "blocked",
            Self::GotThrough => "got_through",
            Self::TooLittle => "too_little",
        }
    }
}

/// Set or clear the highlight, in memory and in config.json; says the change with `why` and the
/// numbers it was decided from (`reach`, when there are any). True when it changed. The two locks
/// are taken one after the other, never together.
pub(crate) fn set_highlight(
    state: &Mutex<AgentState>,
    config: &Mutex<Config>,
    on: bool,
    why: &str,
    reach: Option<&InputReach>,
) -> bool {
    {
        let mut s = lock(state);
        if s.input_not_reaching == on {
            return false;
        }
        s.input_not_reaching = on;
    }
    tracing::debug!(
        highlight = on,
        driver = reach.map_or("-", |r| r.driver.as_str()),
        blocked = reach.is_some_and(|r| r.blocked),
        lost = reach.map_or(0, |r| r.lost),
        delivered = reach.map_or(0, |r| r.delivered),
        episodes = reach.map_or(0, |r| r.episodes),
        "the window's «Управление не доходит» highlight {}: {why}",
        if on { "set" } else { "cleared" }
    );
    let mut c = lock(config);
    c.input_not_reaching = on;
    if let Err(e) = c.save() {
        tracing::warn!(
            highlight = on,
            "the «Управление не доходит» highlight not saved to config.json: {e:#}; in force until \
             exit"
        );
    }
    true
}

/// The agent's side of the reach watch: one per agent, shared with every session's heartbeat.
pub(crate) struct ReachMonitor {
    injector: Arc<dyn InputInjector>,
    state: Arc<Mutex<AgentState>>,
    config: Arc<Mutex<Config>>,
    /// The driver each live session's heartbeat read, and when it last did ([`SessionDriver`]).
    drivers: Mutex<HashMap<String, (SessionDriver, std::time::Instant)>>,
}

impl ReachMonitor {
    pub(crate) fn new(
        injector: Arc<dyn InputInjector>,
        state: Arc<Mutex<AgentState>>,
        config: Arc<Mutex<Config>>,
    ) -> Self {
        Self {
            injector,
            state,
            config,
            drivers: Mutex::new(HashMap::new()),
        }
    }

    /// The injector's word now: a session's baseline at its start.
    pub(crate) fn read(&self) -> InputReach {
        self.injector.input_reach()
    }

    /// A heartbeat of `session` read the driver as `reading`: kept for the session's account.
    /// Sessions not heard of for [`SESSION_DRIVER_KEPT`] are forgotten here.
    fn note_driver(&self, session: &str, reading: DriverPresence) {
        let now = std::time::Instant::now();
        let mut drivers = lock(&self.drivers);
        match drivers.get_mut(session) {
            Some((driver, at)) => {
                driver.saw(reading);
                *at = now;
            }
            None => {
                drivers.insert(session.to_owned(), (SessionDriver::new(reading), now));
            }
        }
        let before = drivers.len();
        drivers.retain(|_, (_, at)| now.saturating_duration_since(*at) < SESSION_DRIVER_KEPT);
        let forgotten = before - drivers.len();
        if forgotten > 0 {
            tracing::debug!(
                forgotten,
                kept = drivers.len(),
                "input reach: sessions whose heartbeat stopped long ago (no end was told) forgotten"
            );
        }
    }

    /// The driver `session` had, from its start's reading and its heartbeats' (taken off the books).
    fn session_driver(&self, session: &str, start: DriverPresence) -> SessionDriver {
        let mut driver = lock(&self.drivers)
            .remove(session)
            .map_or(SessionDriver::new(start), |(driver, _)| driver);
        driver.open |= start == DriverPresence::Open;
        driver
    }

    /// One heartbeat's look, for its `no_driver` and `input_blocked`: the live flag follows it, the
    /// highlight is set while presses are found blocked and cleared while the driver is open.
    /// Blocked counts only where the driver is missing and could be installed — on a PC that cannot
    /// have it nobody is asked to install it.
    pub(crate) fn poll(&self, session: &str) -> InputReach {
        let mut reach = self.injector.input_reach();
        self.note_driver(session, reach.driver);
        reach.blocked &= reach.driver == DriverPresence::Missing;
        {
            let mut s = lock(&self.state);
            if s.input_blocked != reach.blocked {
                s.input_blocked = reach.blocked;
                tracing::debug!(
                    session,
                    blocked = reach.blocked,
                    driver = reach.driver.as_str(),
                    "input reach: the viewer's presses {} the window in front (the desktop app's \
                     toast follows this)",
                    if reach.blocked {
                        "do not reach"
                    } else {
                        "are no longer found dropped at"
                    }
                );
            }
        }
        if reach.blocked {
            set_highlight(
                &self.state,
                &self.config,
                true,
                &format!(
                    "session {session}: presses in a row did not reach a window running as \
                     administrator, and the driver is not open"
                ),
                Some(&reach),
            );
        } else if reach.driver == DriverPresence::Open {
            set_highlight(
                &self.state,
                &self.config,
                false,
                &format!("session {session}: the driver is open"),
                Some(&reach),
            );
        }
        reach
    }

    /// A session ended — `start` is what [`Self::read`] said at its start, `sessions_left` how many
    /// are still live: its account, and the highlight cleared when its input got through. With the
    /// last session gone nothing is blocked any more. The account names the driver the session had
    /// ([`SessionDriver`]), and the one read now beside it.
    pub(crate) fn session_ended(
        &self,
        session: &str,
        start: InputReach,
        sessions_left: usize,
    ) -> SessionVerdict {
        let end = self.injector.input_reach();
        let driver = self.session_driver(session, start.driver).had();
        let lost = end.lost.saturating_sub(start.lost);
        let delivered = end.delivered.saturating_sub(start.delivered);
        let episodes = end.episodes.saturating_sub(start.episodes);
        let verdict = SessionVerdict::of(delivered, episodes);
        if verdict == SessionVerdict::GotThrough {
            set_highlight(
                &self.state,
                &self.config,
                false,
                &format!(
                    "session {session} ended, and its input got through ({delivered} presses \
                     delivered, none found blocked)"
                ),
                Some(&InputReach { driver, ..end }),
            );
        }
        let highlight = {
            let mut s = lock(&self.state);
            if sessions_left == 0 && s.input_blocked {
                s.input_blocked = false;
                tracing::debug!(
                    session,
                    "input reach: no session left, so nothing is blocked (the desktop app's toast \
                     follows this)"
                );
            }
            s.input_not_reaching
        };
        tracing::debug!(
            session,
            lost,
            delivered,
            episodes,
            driver = driver.as_str(),
            driver_now = end.driver.as_str(),
            verdict = verdict.as_str(),
            highlight,
            sessions_left,
            "input reach: the session's account (driver: the one the session had; driver_now: \
             read at its end, after the last session's input may have closed it)"
        );
        verdict
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use afklink_protocol::InputMessage;

    /// An injector whose word on the input's reach the test sets.
    #[derive(Default)]
    pub(crate) struct ReachInjector(pub(crate) Mutex<InputReach>);

    impl InputInjector for ReachInjector {
        fn inject(&self, _: &InputMessage) -> anyhow::Result<()> {
            Ok(())
        }
        fn release_all(&self) {}
        fn input_reach(&self) -> InputReach {
            *lock(&self.0)
        }
    }

    /// A config with no file behind it: `save` writes nothing.
    pub(crate) fn config() -> Arc<Mutex<Config>> {
        Arc::new(Mutex::new(
            serde_json::from_str(r#"{"device_id":"d","server_url":"ws://x","name":"n"}"#)
                .expect("a config"),
        ))
    }

    pub(crate) fn monitor(injector: Arc<ReachInjector>) -> ReachMonitor {
        ReachMonitor::new(
            injector,
            Arc::new(Mutex::new(AgentState::default())),
            config(),
        )
    }

    fn set(injector: &ReachInjector, reach: InputReach) {
        *lock(&injector.0) = reach;
    }

    fn highlight(m: &ReachMonitor) -> (bool, bool) {
        (
            lock(&m.state).input_not_reaching,
            lock(&m.config).input_not_reaching,
        )
    }

    const MISSING: InputReach = InputReach {
        driver: DriverPresence::Missing,
        blocked: false,
        lost: 0,
        delivered: 0,
        episodes: 0,
    };

    /// Blocked sets the highlight, in memory and in config.json, and the live flag; neither is
    /// set by a missing driver alone (an administrator's window nobody presses into).
    #[test]
    fn blocked_presses_set_the_highlight_and_a_missing_driver_alone_does_not() {
        let injector = Arc::new(ReachInjector::default());
        let m = monitor(injector.clone());
        set(&injector, MISSING);
        let reach = m.poll("s1");
        assert_eq!(reach.driver, DriverPresence::Missing);
        assert_eq!(highlight(&m), (false, false));
        assert!(!lock(&m.state).input_blocked);

        set(
            &injector,
            InputReach {
                blocked: true,
                lost: 3,
                episodes: 1,
                ..MISSING
            },
        );
        assert!(m.poll("s1").blocked);
        assert_eq!(highlight(&m), (true, true));
        assert!(lock(&m.state).input_blocked);

        // Not blocked any more (10 s after the last dropped press): the live flag goes, the
        // highlight stays for the window.
        set(
            &injector,
            InputReach {
                lost: 3,
                episodes: 1,
                ..MISSING
            },
        );
        m.poll("s1");
        assert!(!lock(&m.state).input_blocked);
        assert_eq!(highlight(&m), (true, true));
    }

    /// The driver opened for a session — installed meanwhile, or some other way: the highlight goes.
    #[test]
    fn an_open_driver_clears_the_highlight() {
        let injector = Arc::new(ReachInjector::default());
        let m = monitor(injector.clone());
        set_highlight(&m.state, &m.config, true, "test", None);
        set(
            &injector,
            InputReach {
                driver: DriverPresence::Open,
                ..MISSING
            },
        );
        m.poll("s1");
        assert_eq!(highlight(&m), (false, false));
    }

    /// Each change once: setting it twice changes nothing the second time, and clearing it (the
    /// desktop app read the driver installed) clears config.json too.
    #[test]
    fn set_highlight_says_whether_it_changed() {
        let m = monitor(Arc::new(ReachInjector::default()));
        assert!(set_highlight(&m.state, &m.config, true, "test", None));
        assert!(!set_highlight(&m.state, &m.config, true, "test", None));
        assert!(set_highlight(&m.state, &m.config, false, "installed", None));
        assert_eq!(highlight(&m), (false, false));
    }

    /// A session whose input got through clears the highlight; one where presses were found blocked,
    /// or with too few presses to say, leaves it. The counts are diffed against the session's start.
    #[test]
    fn a_session_whose_input_got_through_clears_the_highlight() {
        let injector = Arc::new(ReachInjector::default());
        let m = monitor(injector.clone());
        let before = InputReach {
            lost: 7,
            delivered: 40,
            episodes: 2,
            ..MISSING
        };

        // Blocked in this session: stays, whatever else got through.
        set_highlight(&m.state, &m.config, true, "test", None);
        set(
            &injector,
            InputReach {
                lost: 10,
                delivered: 60,
                episodes: 3,
                ..MISSING
            },
        );
        assert_eq!(m.session_ended("s1", before, 0), SessionVerdict::Blocked);
        assert_eq!(highlight(&m), (true, true));

        // Two presses delivered: too little to say.
        set(
            &injector,
            InputReach {
                lost: 8,
                delivered: 42,
                episodes: 2,
                ..MISSING
            },
        );
        assert_eq!(m.session_ended("s2", before, 0), SessionVerdict::TooLittle);
        assert_eq!(highlight(&m), (true, true));

        // Three delivered, a stray drop, never blocked: got through.
        set(
            &injector,
            InputReach {
                lost: 8,
                delivered: 43,
                episodes: 2,
                ..MISSING
            },
        );
        assert_eq!(m.session_ended("s3", before, 0), SessionVerdict::GotThrough);
        assert_eq!(highlight(&m), (false, false));
    }

    /// The last session gone, nothing is blocked; another still live keeps the live flag.
    #[test]
    fn the_live_flag_ends_with_the_last_session() {
        let injector = Arc::new(ReachInjector::default());
        let m = monitor(injector.clone());
        lock(&m.state).input_blocked = true;
        m.session_ended("s1", MISSING, 1);
        assert!(lock(&m.state).input_blocked, "a session is still live");
        m.session_ended("s2", MISSING, 0);
        assert!(!lock(&m.state).input_blocked);
    }

    /// The account says the driver the session had: open when it was read open at the session's
    /// start or by any heartbeat — even if the last session's input closed the device before the end
    /// was read — else the last reading; a session with no heartbeat, its start's.
    /// Each session is taken off the books at its end.
    #[test]
    fn the_account_names_the_driver_the_session_had() {
        let injector = Arc::new(ReachInjector::default());
        let m = monitor(injector.clone());
        let open = InputReach {
            driver: DriverPresence::Open,
            ..MISSING
        };
        set(&injector, open);
        let start = m.read();
        m.poll("s1");
        m.poll("s2");
        // The viewer hung up: the input closed the device before the session was torn down.
        set(&injector, MISSING);
        assert_eq!(
            m.session_driver("s1", start.driver).had(),
            DriverPresence::Open
        );
        assert!(!lock(&m.drivers).contains_key("s1"), "off the books");

        // Installed mid-session: open since, whatever the start said.
        m.poll("s3");
        set(&injector, open);
        m.poll("s3");
        set(&injector, MISSING);
        assert_eq!(
            m.session_driver("s3", DriverPresence::Missing).had(),
            DriverPresence::Open
        );
        // Never had it.
        m.poll("s4");
        assert_eq!(
            m.session_driver("s4", DriverPresence::Missing).had(),
            DriverPresence::Missing
        );
        // No heartbeat came: the start says.
        assert_eq!(
            m.session_driver("s5", DriverPresence::Open).had(),
            DriverPresence::Open
        );

        // The end itself takes the session off the books.
        assert_eq!(m.session_ended("s2", start, 0), SessionVerdict::TooLittle);
        assert!(lock(&m.drivers).is_empty());
    }

    #[test]
    fn the_verdict_follows_its_numbers() {
        assert_eq!(SessionVerdict::of(100, 1), SessionVerdict::Blocked);
        assert_eq!(SessionVerdict::of(3, 0), SessionVerdict::GotThrough);
        assert_eq!(SessionVerdict::of(2, 0), SessionVerdict::TooLittle);
        assert_eq!(SessionVerdict::of(0, 0), SessionVerdict::TooLittle);
    }
}
