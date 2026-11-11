//! The agent's goodbye to the backend, and the hold on reconnecting that follows it.
//!
//! Without a goodbye the backend learns that a PC went away only from its heartbeat — up to twenty
//! seconds — and the owner's «Мои ПК» shows the PC online all that time; a PC shutting down can go
//! without so much as a close frame (the connection fails at shutdown, a VPN probably going first).
//! So whatever is leaving says so first: `agent_goodbye` with the reason, then
//! a normal close, written on the connection's own pump (`afklink_transport::GoodbyeHandle`) — past
//! whatever the orchestrator is doing — and waited for at most [`GOODBYE_BUDGET`]:
//!
//! | reason     | who says it                                                                     |
//! |------------|---------------------------------------------------------------------------------|
//! | `quit`     | the desktop app on its way out (the tray's «Выход»), the CLI on Ctrl-C          |
//! | `update`   | the desktop app before it exits for the update's watchdog                       |
//! | `shutdown` | the desktop app when Windows asks to end the session (log off, shut down)       |
//! | `sleep`    | the desktop app when Windows announces a suspend                                |
//!
//! A goodbye also **holds** the agent: no reconnecting by itself — a reconnect a second later (the
//! usual backoff after a connection ends) would put the PC back online while it shuts down, sleeps
//! or exits. The hold ends when the desktop app says so ([`crate::AgentControl::welcome_back`]: the
//! system resumed, Windows cancelled the shutdown), when the owner asks to retry, or after
//! [`hold_limit`] in case neither ever comes. A goodbye asked while no connection is up (offline, or
//! a connect in flight) sends nothing and holds all the same; a connection that completes its
//! handshake during the hold is told goodbye at once and not served.
//!
//! One goodbye per hold: asked again while held (the shutdown's second message, the exit after an
//! update's goodbye), nothing more is sent — the connection is closed already — and the hold takes
//! the newer reason and the later limit.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::watch;

pub use afklink_protocol::GoodbyeReason;
use afklink_transport::{GoodbyeHandle, GoodbyeResult};

use crate::sync::lock;

/// The longest a goodbye holds up whatever is leaving — the exit, Windows' shutdown, the suspend
/// (which allows about two seconds in all) — before it goes ahead regardless.
pub const GOODBYE_BUDGET: Duration = Duration::from_millis(500);

/// How long a goodbye keeps the agent from reconnecting when nothing lifts the hold: a suspend that
/// did not happen, a cancelled shutdown that went unannounced, an exit that hung. The process is
/// usually gone, or the system asleep, long before.
pub fn hold_limit(reason: GoodbyeReason) -> Duration {
    match reason {
        GoodbyeReason::Sleep => Duration::from_secs(30),
        GoodbyeReason::Quit | GoodbyeReason::Update | GoodbyeReason::Shutdown => {
            Duration::from_secs(60)
        }
    }
}

/// What a goodbye came to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GoodbyeOutcome {
    /// Said on connection `link`; `result` is how far it got within the budget.
    Said { link: u64, result: GoodbyeResult },
    /// No connection was up (offline, or still connecting): nothing said. The hold begins all the
    /// same, and a connection that comes up during it is told at once.
    NoConnection,
    /// A goodbye (`reason`, `ago`) already holds the agent: nothing more to say.
    AlreadySaid {
        reason: GoodbyeReason,
        ago: Duration,
    },
}

impl GoodbyeOutcome {
    /// For log lines.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Said { result, .. } => result.kind(),
            Self::NoConnection => "no_connection",
            Self::AlreadySaid { .. } => "already_said",
        }
    }

    /// Whether this call put a goodbye on the wire (written and flushed).
    pub fn sent(&self) -> bool {
        matches!(self, Self::Said { result, .. } if result.sent())
    }
}

/// The hold a goodbye puts on reconnecting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Hold {
    /// The latest goodbye's reason.
    pub(crate) reason: GoodbyeReason,
    /// When the first goodbye of this hold was asked.
    pub(crate) since: Instant,
    /// When the hold ends by itself.
    pub(crate) until: Instant,
}

impl Hold {
    /// How long it still has to run by itself.
    pub(crate) fn remaining(&self, now: Instant) -> Duration {
        self.until.saturating_duration_since(now)
    }
}

/// The goodbye's shared state: the current connection's handle and the hold. Shared by the
/// orchestrator, which installs each connection's handle, and [`crate::AgentControl`], whose
/// callers say goodbye from any thread.
pub(crate) struct Goodbyes {
    /// The current connection's handle and link id. Every change of the hold is made under this lock
    /// too, so a connection coming up and a goodbye cannot pass each other: either the goodbye finds
    /// the handle, or the connection finds the hold.
    link: Mutex<Option<(u64, GoodbyeHandle)>>,
    hold: watch::Sender<Option<Hold>>,
}

/// What [`Goodbyes::begin`] found.
enum Begun {
    Say {
        link: u64,
        handle: GoodbyeHandle,
    },
    NoConnection,
    AlreadySaid {
        reason: GoodbyeReason,
        ago: Duration,
    },
}

impl Goodbyes {
    pub(crate) fn new() -> Arc<Self> {
        let (hold, _) = watch::channel(None);
        Arc::new(Self {
            link: Mutex::new(None),
            hold,
        })
    }

    /// Connection `link` is up: its handle becomes the one a goodbye uses — unless a goodbye holds
    /// the agent, which is then returned, and the caller says goodbye on the new connection at once.
    pub(crate) fn install(&self, link: u64, handle: GoodbyeHandle) -> Result<(), Hold> {
        let mut slot = lock(&self.link);
        if let Some(hold) = self.held() {
            tracing::debug!(
                link,
                reason = hold.reason.as_str(),
                held_ms = hold.since.elapsed().as_millis() as u64,
                "a signaling connection came up during the goodbye's hold: not served; the goodbye \
                 is said on it at once"
            );
            return Err(hold);
        }
        if let Some((old, _)) = slot.replace((link, handle)) {
            tracing::debug!(
                old,
                link,
                "goodbye handle replaced (the old connection was not retired first)"
            );
        } else {
            tracing::trace!(link, "goodbye handle installed");
        }
        Ok(())
    }

    /// Connection `link` ended: its handle goes, unless a newer one took its place already.
    pub(crate) fn retire(&self, link: u64) {
        let mut slot = lock(&self.link);
        match slot.as_ref().map(|(id, _)| *id) {
            Some(id) if id == link => {
                *slot = None;
                tracing::trace!(link, "goodbye handle retired with its connection");
            }
            current => tracing::trace!(
                link,
                ?current,
                "goodbye handle not retired: not the current one (taken by a goodbye, or replaced)"
            ),
        }
    }

    /// The hold in force, if any: a copy, the watch's read guard dropped on return. Never
    /// `if let … = *self.hold.borrow()` in this file — that guard lives through the block, and a
    /// `send_replace` inside it waits for it forever.
    pub(crate) fn held(&self) -> Option<Hold> {
        *self.hold.borrow()
    }

    /// Hears every change of the hold.
    pub(crate) fn subscribe(&self) -> watch::Receiver<Option<Hold>> {
        self.hold.subscribe()
    }

    /// End the hold (`why`, for the log): reconnecting goes on as usual. Whether there was one.
    pub(crate) fn lift(&self, why: &str) -> bool {
        let _slot = lock(&self.link);
        match self.hold.send_replace(None) {
            Some(hold) => {
                tracing::info!(
                    reason = hold.reason.as_str(),
                    held_ms = hold.since.elapsed().as_millis() as u64,
                    why,
                    "goodbye hold lifted: the agent connects to the backend again"
                );
                true
            }
            None => {
                tracing::debug!(why, "nothing to lift: no goodbye holds the agent");
                false
            }
        }
    }

    /// Start a goodbye: the hold, and the connection to say it on.
    fn begin(&self, reason: GoodbyeReason) -> Begun {
        let now = Instant::now();
        let mut slot = lock(&self.link);
        let limit = hold_limit(reason);
        if let Some(hold) = self.held() {
            let until = hold.until.max(now + limit);
            self.hold.send_replace(Some(Hold {
                reason,
                since: hold.since,
                until,
            }));
            tracing::debug!(
                was = hold.reason.as_str(),
                now = reason.as_str(),
                ends_in_ms = until.saturating_duration_since(now).as_millis() as u64,
                "goodbye asked while one already holds the agent: the hold takes the newer reason \
                 and the later end"
            );
            return Begun::AlreadySaid {
                reason: hold.reason,
                ago: now.saturating_duration_since(hold.since),
            };
        }
        self.hold.send_replace(Some(Hold {
            reason,
            since: now,
            until: now + limit,
        }));
        tracing::info!(
            reason = reason.as_str(),
            limit_s = limit.as_secs(),
            "goodbye: no reconnecting until the hold is lifted (resume, a cancelled shutdown, the \
             owner's retry) or its limit passes"
        );
        match slot.take() {
            Some((link, handle)) => Begun::Say { link, handle },
            None => Begun::NoConnection,
        }
    }

    /// Say goodbye on the current connection and hold, waiting at most `budget` for it. Blocks the
    /// calling thread, so not an async task's (see [`crate::AgentControl::goodbye`]).
    pub(crate) fn say_blocking(&self, reason: GoodbyeReason, budget: Duration) -> GoodbyeOutcome {
        let outcome = match self.begin(reason) {
            Begun::AlreadySaid { reason, ago } => GoodbyeOutcome::AlreadySaid { reason, ago },
            Begun::NoConnection => GoodbyeOutcome::NoConnection,
            Begun::Say { link, handle } => GoodbyeOutcome::Said {
                link,
                result: handle.request(reason, budget).wait(),
            },
        };
        log_outcome(reason, &outcome, budget, "asked");
        outcome
    }
}

/// Say goodbye on connection `link` through `handle`, which came up during a hold (`install`
/// refused it). Blocks, as [`Goodbyes::say_blocking`] does.
pub(crate) fn say_on(
    link: u64,
    handle: &GoodbyeHandle,
    reason: GoodbyeReason,
    budget: Duration,
) -> GoodbyeOutcome {
    let outcome = GoodbyeOutcome::Said {
        link,
        result: handle.request(reason, budget).wait(),
    };
    log_outcome(
        reason,
        &outcome,
        budget,
        "a connection made during the hold",
    );
    outcome
}

/// The one line every goodbye gets, at info — warn when it did not get out.
fn log_outcome(reason: GoodbyeReason, outcome: &GoodbyeOutcome, budget: Duration, on: &str) {
    let reason = reason.as_str();
    let budget_ms = budget.as_millis() as u64;
    match outcome {
        GoodbyeOutcome::Said { link, result } => {
            let took_ms = result.took().as_millis() as u64;
            match result {
                GoodbyeResult::Confirmed { .. } => tracing::info!(
                    reason,
                    link,
                    outcome = result.kind(),
                    took_ms,
                    budget_ms,
                    on,
                    "goodbye said: the backend has it (it answered the close)"
                ),
                GoodbyeResult::Flushed { .. } => tracing::info!(
                    reason,
                    link,
                    outcome = result.kind(),
                    took_ms,
                    budget_ms,
                    on,
                    "goodbye said: written and flushed; the backend's close did not come within the \
                     budget"
                ),
                GoodbyeResult::TimedOut { .. } => tracing::warn!(
                    reason,
                    link,
                    outcome = result.kind(),
                    took_ms,
                    budget_ms,
                    on,
                    "goodbye not written within the budget (the path is dying, or the runtime is \
                     starved): the backend learns of it from its heartbeat"
                ),
                GoodbyeResult::Failed { error, .. } => tracing::warn!(
                    reason,
                    link,
                    outcome = result.kind(),
                    took_ms,
                    budget_ms,
                    on,
                    %error,
                    "goodbye failed: the backend learns of it from its heartbeat"
                ),
                GoodbyeResult::NoConnection => tracing::info!(
                    reason,
                    link,
                    outcome = result.kind(),
                    on,
                    "goodbye skipped: the connection ended just as it was asked"
                ),
            }
        }
        GoodbyeOutcome::NoConnection => tracing::info!(
            reason,
            outcome = outcome.kind(),
            on,
            "goodbye skipped: no connection to the backend (offline, or still connecting); a \
             connection made during the hold is told at once"
        ),
        GoodbyeOutcome::AlreadySaid { reason: was, ago } => tracing::info!(
            reason,
            was = was.as_str(),
            ago_ms = ago.as_millis() as u64,
            outcome = outcome.kind(),
            on,
            "goodbye already said: nothing more to send"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// No connection: nothing said, but the hold begins; asked again, it is the same hold with the
    /// newer reason; lifted, it is gone, and a second lift finds nothing.
    #[test]
    fn a_goodbye_without_a_connection_still_holds_and_is_said_once() {
        let g = Goodbyes::new();
        assert_eq!(g.held(), None);
        assert_eq!(
            g.say_blocking(GoodbyeReason::Sleep, GOODBYE_BUDGET),
            GoodbyeOutcome::NoConnection
        );
        let first = g.held().expect("held");
        assert_eq!(first.reason, GoodbyeReason::Sleep);
        assert!(first.remaining(Instant::now()) <= hold_limit(GoodbyeReason::Sleep));
        match g.say_blocking(GoodbyeReason::Shutdown, GOODBYE_BUDGET) {
            GoodbyeOutcome::AlreadySaid { reason, .. } => assert_eq!(reason, GoodbyeReason::Sleep),
            other => panic!("expected already said, got {other:?}"),
        }
        let second = g.held().expect("still held");
        assert_eq!(second.reason, GoodbyeReason::Shutdown, "the newer reason");
        assert_eq!(second.since, first.since, "the same hold");
        assert!(second.until >= first.until, "the later end");
        assert!(g.lift("resumed"));
        assert_eq!(g.held(), None);
        assert!(!g.lift("again"));
    }

    // The handle's side — a connection installed, taken by a goodbye, refused during a hold — runs
    // through the real signaling client in `agent.rs`'s tests (`a_goodbye_*`).

    #[test]
    fn the_hold_limits() {
        assert_eq!(hold_limit(GoodbyeReason::Sleep), Duration::from_secs(30));
        for reason in [
            GoodbyeReason::Quit,
            GoodbyeReason::Update,
            GoodbyeReason::Shutdown,
        ] {
            assert_eq!(hold_limit(reason), Duration::from_secs(60));
        }
        assert!(GOODBYE_BUDGET <= Duration::from_millis(500));
    }
}
