//! When a downloaded update may be applied, and whether a version is newer.
//!
//! Applying restarts the app: every session ends, a pairing prompt disappears, a FakerInput wizard
//! loses its owner. So an update waits ([`Defer`]) while someone is connected (or connecting), a
//! pairing is under way, a driver operation runs, another update is in flight, or the app cannot
//! reach the server (the new version proves itself by connecting; applying while offline would only
//! buy a rollback) — and not a moment longer: once nothing is in the way it goes, with no pause
//! after a session (a wait after the last viewer left would have the window say
//! «Установится после сеанса» with nobody connected). Automatic updates switched off wait for
//! the owner's «Установить».
//!
//! Nothing is installed while the PC is paused («Приостановить доступ», [`Defer::Paused`]), not even
//! on the owner's «Установить»: the pause is kept in config.json and the new version starts paused,
//! but a version that fails its health check is rolled back to the previous exe, and a rollback
//! target built before the pause was kept in config.json would start unpaused and, saving its
//! config, drop it. The update goes the moment the owner resumes.

use semver::Version;

/// Why a downloaded update is not applied yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Defer {
    /// Another update's watchdog has not finished (or its attempt was not settled).
    InFlight,
    /// The PC is paused («Приостановить доступ», `AgentState::paused`): no update until the owner
    /// resumes, whoever asked.
    Paused,
    /// «Обновлять автоматически» is off and the owner has not pressed «Установить».
    AutoOff,
    /// A FakerInput install or removal is running.
    Maintenance,
    /// A pairing code is on screen or a pairing request waits for the owner.
    Pairing,
    /// Someone is connected (or connecting).
    Session,
    /// The server cannot be reached.
    Offline,
}

impl Defer {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::InFlight => "another update is in flight",
            Self::Paused => "connections are paused on this PC (until the owner resumes)",
            Self::AutoOff => "automatic updates are off",
            Self::Maintenance => "FakerInput maintenance is running",
            Self::Pairing => "pairing is under way",
            Self::Session => "a session is active",
            Self::Offline => "the server is not reachable",
        }
    }
}

/// What the decision looks at, sampled together.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Conditions {
    pub(crate) auto_update: bool,
    /// The owner pressed «Установить» (or «Повторить» on a failed update).
    pub(crate) owner_asked: bool,
    pub(crate) in_flight: bool,
    /// The kill switch paused connections and the owner has not resumed (`AgentState::paused`).
    pub(crate) paused: bool,
    pub(crate) maintenance: bool,
    pub(crate) pairing: bool,
    /// Sessions, connecting ones included.
    pub(crate) sessions: usize,
    /// Connected to the server, or refused as outdated (the server wants exactly this update).
    pub(crate) online: bool,
}

/// Apply now, or why not. The first reason in this order is the one reported.
pub(crate) fn decide(c: &Conditions) -> Result<(), Defer> {
    if c.in_flight {
        return Err(Defer::InFlight);
    }
    // Before the switch: the owner's «Установить» does not lift it (see the module).
    if c.paused {
        return Err(Defer::Paused);
    }
    if !c.auto_update && !c.owner_asked {
        return Err(Defer::AutoOff);
    }
    if c.maintenance {
        return Err(Defer::Maintenance);
    }
    if c.pairing {
        return Err(Defer::Pairing);
    }
    if c.sessions > 0 {
        return Err(Defer::Session);
    }
    if !c.online {
        return Err(Defer::Offline);
    }
    Ok(())
}

/// Whether `candidate` is newer than `current` (SemVer: a pre-release is older than its release).
pub(crate) fn is_newer(current: &Version, candidate: &Version) -> bool {
    candidate > current
}

#[cfg(test)]
mod tests {
    use super::*;

    fn idle() -> Conditions {
        Conditions {
            auto_update: true,
            owner_asked: false,
            in_flight: false,
            paused: false,
            maintenance: false,
            pairing: false,
            sessions: 0,
            online: true,
        }
    }

    /// Nothing is installed while the PC is paused — automatically or on the owner's
    /// «Установить» — and the update goes the moment the owner resumes.
    #[test]
    fn a_paused_pc_installs_nothing_until_the_owner_resumes() {
        for (auto_update, owner_asked) in [(true, false), (false, true), (true, true)] {
            let paused = Conditions {
                paused: true,
                auto_update,
                owner_asked,
                ..idle()
            };
            assert_eq!(decide(&paused), Err(Defer::Paused), "{paused:?}");
            assert_eq!(
                decide(&Conditions {
                    paused: false,
                    ..paused
                }),
                Ok(()),
                "resumed: {paused:?}"
            );
        }
        // Automatic updates off and nobody asked: still the pause that is reported — «Установить»
        // would not help.
        let off = Conditions {
            paused: true,
            auto_update: false,
            ..idle()
        };
        assert_eq!(decide(&off), Err(Defer::Paused));
        // Only another update in flight comes first.
        assert_eq!(
            decide(&Conditions {
                in_flight: true,
                ..off
            }),
            Err(Defer::InFlight)
        );
        // Paused with a session or a pairing too: the pause is what is said.
        assert_eq!(
            decide(&Conditions {
                sessions: 1,
                pairing: true,
                ..off
            }),
            Err(Defer::Paused)
        );
        assert!(Defer::Paused.as_str().contains("paused"));
    }

    #[test]
    fn nobody_connected_is_enough_there_is_no_wait_after_a_session() {
        // A wait after the start or a session would leave «Установится после сеанса» on screen
        // with nobody connected. Nothing measures that time: a PC nobody is connected to installs
        // at once.
        assert_eq!(decide(&idle()), Ok(()));
    }

    #[test]
    fn a_session_defers_until_it_ends_whoever_asked() {
        for owner_asked in [false, true] {
            let live = Conditions {
                sessions: 1,
                owner_asked,
                ..idle()
            };
            assert_eq!(decide(&live), Err(Defer::Session), "{live:?}");
            // The moment it ends, the update goes.
            assert_eq!(
                decide(&Conditions {
                    sessions: 0,
                    ..live
                }),
                Ok(())
            );
        }
    }

    #[test]
    fn each_condition_defers_on_its_own() {
        for (c, want) in [
            (
                Conditions {
                    in_flight: true,
                    ..idle()
                },
                Defer::InFlight,
            ),
            (
                Conditions {
                    paused: true,
                    ..idle()
                },
                Defer::Paused,
            ),
            (
                Conditions {
                    auto_update: false,
                    ..idle()
                },
                Defer::AutoOff,
            ),
            (
                Conditions {
                    maintenance: true,
                    ..idle()
                },
                Defer::Maintenance,
            ),
            (
                Conditions {
                    pairing: true,
                    ..idle()
                },
                Defer::Pairing,
            ),
            (
                Conditions {
                    sessions: 2,
                    ..idle()
                },
                Defer::Session,
            ),
            (
                Conditions {
                    online: false,
                    ..idle()
                },
                Defer::Offline,
            ),
        ] {
            assert_eq!(decide(&c), Err(want), "{c:?}");
        }
    }

    #[test]
    fn the_owners_install_skips_the_switch_but_never_a_session() {
        let asked = Conditions {
            auto_update: false,
            owner_asked: true,
            ..idle()
        };
        assert_eq!(decide(&asked), Ok(()));
        for c in [
            Conditions {
                sessions: 1,
                ..asked
            },
            Conditions {
                pairing: true,
                ..asked
            },
            Conditions {
                maintenance: true,
                ..asked
            },
            Conditions {
                in_flight: true,
                ..asked
            },
            Conditions {
                paused: true,
                ..asked
            },
        ] {
            assert!(decide(&c).is_err(), "{c:?}");
        }
    }

    #[test]
    fn the_first_reason_is_the_one_reported() {
        // A session during maintenance says maintenance: the order is fixed.
        let c = Conditions {
            maintenance: true,
            sessions: 2,
            online: false,
            ..idle()
        };
        assert_eq!(decide(&c), Err(Defer::Maintenance));
    }

    #[test]
    fn versions_compare_as_semver() {
        let v = |s: &str| Version::parse(s).unwrap();
        assert!(is_newer(&v("0.1.0"), &v("0.1.1")));
        assert!(is_newer(&v("0.1.9"), &v("0.1.10")), "numeric, not text");
        assert!(is_newer(&v("0.9.0"), &v("1.0.0")));
        assert!(!is_newer(&v("0.1.1"), &v("0.1.1")));
        assert!(!is_newer(&v("0.1.1"), &v("0.1.0")), "never a downgrade");
        assert!(
            !is_newer(&v("0.1.1"), &v("0.1.1-rc.1")),
            "a pre-release is older"
        );
        assert!(is_newer(&v("0.1.1-rc.1"), &v("0.1.1")));
    }
}
