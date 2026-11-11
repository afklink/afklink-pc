//! How long the agent waits before its next signaling attempt, and when it waits for the owner
//! instead.
//!
//! The backend's `error` frame carries a code, and the contract says of every code whether retrying
//! can help (`afklink_protocol::errors`, mirroring `ERROR_CODES` in
//! `packages/protocol/src/errors.ts`). One backoff for every failure would have an agent the
//! backend will never accept (a protocol version it does not serve, a device key that does not
//! match the one it pinned) knock every thirty seconds for as long as the PC is on, and two
//! processes with the same device identity take the connection from each other every few seconds.
//! So what follows an attempt depends on how it ended:
//!
//! | how the attempt ended                     | what follows                                      |
//! |-------------------------------------------|---------------------------------------------------|
//! | a connection that was up [`STABLE_AFTER`] | the backoff from its start, 1 s                   |
//! | or longer went away                       |                                                   |
//! | a connection that went away sooner, a     | the backoff where it stood: 1 s doubling to 30 s  |
//! | failure with no code, a transient code,   |                                                   |
//! | or a code this build does not know        |                                                   |
//! | `replaced`                                | no automatic retry ([`OnReplaced`])               |
//! | `device_blocked`                          | a retry every [`SLOW_RETRY`]; the window offers   |
//! |                                           | no Retry («ПК заблокирован»), and the agent ends  |
//! |                                           | what sessions it still has                        |
//! | any other fatal code                      | a retry every [`SLOW_RETRY`], and at once on the  |
//! |                                           | owner's retry                                     |
//!
//!
//! Each wait of the backoff is drawn evenly from nothing up to the backoff's value ([`Jitter`]), so
//! agents a deploy dropped do not all come back in the same second. [`Refusal`] and [`OnReplaced`]
//! explain the codes that stop the ordinary backoff.
//!
//! Whatever the wait, the orchestrator serves the offline-safe commands (the kill switch above all)
//! and the session signals through it, exactly as through the ordinary backoff (`Agent::run`).

use std::time::Duration;

use afklink_protocol::errors;

/// The first wait of the ordinary backoff, and the wait after a connection that stayed up
/// [`STABLE_AFTER`] went away — at most: each wait is drawn up to it ([`Jitter`]).
pub const BACKOFF_FIRST: Duration = Duration::from_secs(1);

/// The ordinary backoff doubles up to this.
pub const BACKOFF_MAX: Duration = Duration::from_secs(30);

/// How long a connection has to stay up for the backoff to start again from [`BACKOFF_FIRST`] once
/// it goes away. A fixed 1 s after any handshake would have a server that takes agents and drops
/// them again at once see the whole fleet knock in step every second. A minute: longer than a
/// server that accepts and drops at once, a handshake followed by a crash, or a path that freezes
/// after a few kilobytes (`crate::entry`) keeps a connection; shorter than any real stretch of
/// service.
pub const STABLE_AFTER: Duration = Duration::from_secs(60);

/// The backoff after a connection that was up went away: back to [`BACKOFF_FIRST`] when it stayed
/// up [`STABLE_AFTER`] or longer (`lived`), else as it stood (`backoff`) — the next wait's end
/// doubles it as after any failed attempt. `lived` unknown (it ended before it was served): as it
/// stood. Says which, and why.
pub(crate) fn after_disconnect(backoff: Duration, lived: Option<Duration>) -> Duration {
    match lived {
        Some(lived) if lived >= STABLE_AFTER => {
            tracing::debug!(
                lived_s = lived.as_secs(),
                was_ms = backoff.as_millis() as u64,
                stable_after_s = STABLE_AFTER.as_secs(),
                "reconnect: the connection stayed up long enough; the backoff starts again from 1 s"
            );
            BACKOFF_FIRST
        }
        Some(lived) => {
            tracing::debug!(
                lived_ms = lived.as_millis() as u64,
                backoff_ms = backoff.as_millis() as u64,
                stable_after_s = STABLE_AFTER.as_secs(),
                "reconnect: the connection went away before it proved stable; the backoff goes on \
                 where it stood"
            );
            backoff
        }
        None => {
            tracing::debug!(
                backoff_ms = backoff.as_millis() as u64,
                "reconnect: how long the connection lived is unknown (it ended before it was \
                 served); the backoff goes on where it stood"
            );
            backoff
        }
    }
}

/// "Full jitter" for the ordinary backoff: each wait is drawn evenly from zero up to the
/// backoff's value, so agents dropped together — a deploy, a network blip at the server — come back
/// spread over that span instead of in one second, and keep apart while the backoff grows.
///
/// SplitMix64 rather than a crate: twenty lines, nothing to keep current, the same sequence for a
/// seed forever (the tests rely on it). Not for anything secret — it spreads waits, nothing more.
#[derive(Debug, Clone)]
pub(crate) struct Jitter {
    state: u64,
    /// Every wait is the backoff's value itself, without jitter: for the tests whose timing assumes
    /// exact waits.
    off: bool,
}

impl Jitter {
    /// Seeded from the operating system's generator; from the clock and the process id, said at
    /// debug, if that fails (never seen on Windows).
    pub(crate) fn from_os() -> Self {
        let mut seed = [0u8; 8];
        let seed = match getrandom::getrandom(&mut seed) {
            Ok(()) => u64::from_le_bytes(seed),
            Err(e) => {
                let nanos = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |d| d.as_nanos() as u64);
                tracing::debug!(
                    "reconnect jitter: no random seed from the system ({e}); seeded from the clock \
                     and the process id"
                );
                nanos ^ (u64::from(std::process::id()) << 32)
            }
        };
        Self::seeded(seed)
    }

    /// A generator whose waits follow from `seed` alone.
    pub(crate) fn seeded(seed: u64) -> Self {
        Self {
            state: seed,
            off: false,
        }
    }

    /// No jitter: every wait is the backoff's value.
    #[cfg(test)]
    pub(crate) fn off() -> Self {
        Self {
            state: 0,
            off: true,
        }
    }

    fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// The wait for a backoff of `cap`: drawn evenly from zero to `cap`, to the microsecond.
    pub(crate) fn full(&mut self, cap: Duration) -> Duration {
        if self.off {
            return cap;
        }
        let cap_us = u64::try_from(cap.as_micros()).unwrap_or(u64::MAX);
        if cap_us == 0 {
            return Duration::ZERO;
        }
        Duration::from_micros(self.next_u64() % cap_us.saturating_add(1))
    }
}

/// How often an agent the backend refused with a fatal code (other than `replaced`) tries again.
///
/// Slow enough that an unattended agent on an old build is not a load on the backend — every PC
/// that never gets updated knocks at this rate for as long as it is on — and fast enough that a
/// server-side fix or rollback brings it back within the quarter of an hour.
///
/// Every fatal code but `replaced` is about this agent and this backend (a protocol window, a key,
/// a signature), and the PC may be unattended: a fix or a rollback on the server should bring it
/// back without anyone walking to it, hence the slow retry rather than a stop.
pub const SLOW_RETRY: Duration = Duration::from_secs(15 * 60);

/// The backend does not serve this build's protocol version: [`Refusal::kind`] tells the window
/// apart, since only an update brings such an agent back.
const PROTOCOL_UNSUPPORTED: &str = "protocol_unsupported";

/// Why the backend will not have this agent, when it will not.
///
/// `device_blocked` is the invite-only beta's: an admin blocked this PC, and the server says so
/// once the agent's signature proves it, or on the live connection when the block comes, then
/// closes. No press of the owner's can help, so the window says why and offers nothing
/// ([`Refusal::kind`] `blocked`); but the block may be lifted («доступ возвращается сам»), so the
/// slow retry stays: the first attempt after the lift connects, with nobody at the PC.
///
/// The contract's other two beta codes, `account_blocked` and `beta_required`, answer a viewer (its
/// account, its membership): the agent signs in as a device, and the server's only check on its
/// socket is the PC's block. Were one ever sent here, it would be an ordinary fatal refusal (the
/// slow retry and «Сервер отказал»), which is right for a code that means "not you, and not now".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// `replaced`: another process with this device's identity is connected.
    Replaced,
    /// Any other fatal code. The code is for the log; the owner is shown only that it is an error.
    Fatal { code: String },
}

impl Refusal {
    /// The refusal a wire code amounts to, or `None` when retrying at the usual pace can help: a
    /// transient code, or one this build does not know (a newer backend may send it).
    pub fn from_code(code: &str) -> Option<Self> {
        if code == errors::REPLACED {
            Some(Self::Replaced)
        } else if errors::is_fatal(code) {
            Some(Self::Fatal {
                code: code.to_string(),
            })
        } else {
            None
        }
    }

    /// The wire code.
    pub fn code(&self) -> &str {
        match self {
            Self::Replaced => errors::REPLACED,
            Self::Fatal { code } => code,
        }
    }

    /// What the desktop window keys its text and its offer on: `"replaced"` (Retry takes the
    /// connection over), `"outdated"` (`protocol_unsupported`: this build is older than anything
    /// the backend serves — an update is the only way back, so the window offers no Retry of its
    /// own), `"blocked"` (`device_blocked`: an admin blocked this PC — «ПК заблокирован», no Retry
    /// either: only lifting the block helps, and the slow retry finds that by itself) or `"fatal"`
    /// (any other fatal code; the code is in the log).
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Replaced => "replaced",
            Self::Fatal { code } if code == PROTOCOL_UNSUPPORTED => "outdated",
            Self::Fatal { code } if code == errors::DEVICE_BLOCKED => "blocked",
            Self::Fatal { .. } => "fatal",
        }
    }

    /// `device_blocked`: an admin blocked this PC.
    pub fn is_blocked(&self) -> bool {
        matches!(self, Self::Fatal { code } if code == errors::DEVICE_BLOCKED)
    }
}

/// What `replaced` does to the agent.
///
/// `replaced` means another process with this device's identity connected, and the backend keeps
/// only the latest connection. Retrying would take the connection back, the other process would do
/// the same, and neither would ever hold it; so the desktop app waits for the owner (its Retry
/// button, or a restart) and the CLI stops.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OnReplaced {
    /// Wait for the owner's [`crate::AgentCommand::Retry`] (the desktop app's Retry button), or a
    /// restart. The default: the desktop app is the product, and it can always be asked.
    #[default]
    WaitForOwner,
    /// Stop: `Agent::run` returns an error naming the code. The CLI, which has no Retry and whose
    /// exit is the clearest stop there is.
    Stop,
}

/// The wait before the next attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Wait {
    /// The ordinary backoff, this long.
    Backoff(Duration),
    /// After a fatal refusal: this long ([`SLOW_RETRY`] outside tests), or until the owner asks.
    Slow(Duration),
    /// After `replaced`: until the owner asks.
    UntilOwner,
    /// After a goodbye (`crate::goodbye`): until the hold is lifted — the system resumed, the
    /// shutdown was cancelled, the owner asked — or for this long at most, the hold's own limit.
    Held(Duration),
}

impl Wait {
    /// When the wait ends by itself; `None` for never.
    pub(crate) fn limit(self) -> Option<Duration> {
        match self {
            Self::Backoff(d) | Self::Slow(d) | Self::Held(d) => Some(d),
            Self::UntilOwner => None,
        }
    }

    /// For log lines.
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Backoff(_) => "backoff",
            Self::Slow(_) => "slow_retry",
            Self::UntilOwner => "until_owner",
            Self::Held(_) => "goodbye_hold",
        }
    }
}

/// What follows an attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Next {
    Wait(Wait),
    /// `replaced` under [`OnReplaced::Stop`]: the agent stops.
    Stop,
}

/// What follows an attempt that ended in `refusal` (`None`: no refusal), with the ordinary backoff
/// standing at `backoff` and the slow retry at `slow`.
pub(crate) fn next(
    refusal: Option<&Refusal>,
    backoff: Duration,
    slow: Duration,
    on_replaced: OnReplaced,
) -> Next {
    match (refusal, on_replaced) {
        (None, _) => Next::Wait(Wait::Backoff(backoff)),
        (Some(Refusal::Replaced), OnReplaced::WaitForOwner) => Next::Wait(Wait::UntilOwner),
        (Some(Refusal::Replaced), OnReplaced::Stop) => Next::Stop,
        (Some(Refusal::Fatal { .. }), _) => Next::Wait(Wait::Slow(slow)),
    }
}

/// The ordinary backoff after a wait of `current`: doubled, at most [`BACKOFF_MAX`].
pub(crate) fn next_backoff(current: Duration) -> Duration {
    (current * 2).min(BACKOFF_MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_code_is_a_refusal_only_when_the_contract_says_retrying_cannot_help() {
        assert_eq!(Refusal::from_code("replaced"), Some(Refusal::Replaced));
        for code in [
            "protocol_unsupported",
            "not_authenticated",
            "already_hello",
            "invalid_pubkey",
            "pubkey_mismatch",
            "no_challenge",
            "bad_signature",
        ] {
            assert_eq!(
                Refusal::from_code(code),
                Some(Refusal::Fatal { code: code.into() }),
                "{code}"
            );
        }
        // Transient codes the backend sends agents, and one from a newer backend.
        for code in [
            "auth_timeout",
            "bad_json",
            "bad_message",
            "internal",
            "a_new_code",
        ] {
            assert_eq!(Refusal::from_code(code), None, "{code}");
        }
        assert_eq!(Refusal::Replaced.code(), "replaced");
        assert_eq!(Refusal::Replaced.kind(), "replaced");
        let fatal = Refusal::Fatal {
            code: "bad_signature".into(),
        };
        assert_eq!(fatal.code(), "bad_signature");
        assert_eq!(fatal.kind(), "fatal");
        let outdated = Refusal::from_code("protocol_unsupported").expect("fatal");
        assert_eq!(outdated.code(), "protocol_unsupported");
        assert_eq!(
            outdated.kind(),
            "outdated",
            "only an update helps: the window says so"
        );
        assert!(
            errors::is_fatal(PROTOCOL_UNSUPPORTED),
            "the contract still has the code"
        );
        assert!(!fatal.is_blocked() && !outdated.is_blocked());
        assert!(!Refusal::Replaced.is_blocked());
    }

    /// The beta's codes: `device_blocked` is a refusal of its own kind — the window's
    /// «ПК заблокирован», no Retry — and retried slowly like every other fatal code, so a lifted
    /// block brings the PC back by itself. The viewer's two, were they ever sent here, are ordinary
    /// fatal refusals.
    #[test]
    fn the_beta_codes() {
        let blocked = Refusal::from_code("device_blocked").expect("fatal in the contract");
        assert_eq!(
            blocked,
            Refusal::Fatal {
                code: "device_blocked".into()
            }
        );
        assert_eq!(blocked.kind(), "blocked");
        assert_eq!(blocked.code(), errors::DEVICE_BLOCKED);
        assert!(blocked.is_blocked());
        for policy in [OnReplaced::WaitForOwner, OnReplaced::Stop] {
            assert_eq!(
                next(Some(&blocked), BACKOFF_FIRST, SLOW_RETRY, policy),
                Next::Wait(Wait::Slow(SLOW_RETRY)),
                "a slow retry, never a stop or a wait for the owner"
            );
        }
        for code in ["account_blocked", "beta_required"] {
            let r = Refusal::from_code(code).expect("fatal in the contract");
            assert_eq!(r.kind(), "fatal", "{code}");
            assert!(!r.is_blocked(), "{code}");
            assert_eq!(
                next(
                    Some(&r),
                    BACKOFF_FIRST,
                    SLOW_RETRY,
                    OnReplaced::WaitForOwner
                ),
                Next::Wait(Wait::Slow(SLOW_RETRY)),
                "{code}"
            );
        }
    }

    #[test]
    fn what_follows_each_ending() {
        let b = Duration::from_secs(4);
        let fatal = Refusal::Fatal {
            code: "protocol_unsupported".into(),
        };
        for policy in [OnReplaced::WaitForOwner, OnReplaced::Stop] {
            assert_eq!(
                next(None, b, SLOW_RETRY, policy),
                Next::Wait(Wait::Backoff(b))
            );
            assert_eq!(
                next(Some(&fatal), b, SLOW_RETRY, policy),
                Next::Wait(Wait::Slow(SLOW_RETRY))
            );
        }
        assert_eq!(
            next(
                Some(&Refusal::Replaced),
                b,
                SLOW_RETRY,
                OnReplaced::WaitForOwner
            ),
            Next::Wait(Wait::UntilOwner)
        );
        assert_eq!(
            next(Some(&Refusal::Replaced), b, SLOW_RETRY, OnReplaced::Stop),
            Next::Stop
        );
        assert_eq!(Wait::UntilOwner.limit(), None);
        assert_eq!(Wait::Slow(SLOW_RETRY).limit(), Some(SLOW_RETRY));
        assert_eq!(SLOW_RETRY, Duration::from_secs(900));
    }

    /// Each wait is drawn within the backoff, from a seed the same way every time, spread over
    /// the whole span rather than bunched at its end — and a backoff of nothing is no wait.
    #[test]
    fn full_jitter_spreads_each_wait_over_the_backoff() {
        let mut a = Jitter::seeded(42);
        let mut b = Jitter::seeded(42);
        let cap = Duration::from_secs(8);
        let waits: Vec<Duration> = (0..1000).map(|_| a.full(cap)).collect();
        let again: Vec<Duration> = (0..1000).map(|_| b.full(cap)).collect();
        assert_eq!(waits, again, "a seed gives the same waits");
        assert!(waits.iter().all(|w| *w <= cap), "never past the backoff");
        // Spread: every eighth of the span is hit, and the mean is near the middle.
        let mut buckets = [0u32; 8];
        for w in &waits {
            let i = (w.as_micros() * 8 / (cap.as_micros() + 1)) as usize;
            buckets[i] += 1;
        }
        assert!(buckets.iter().all(|n| *n > 60), "{buckets:?}");
        let mean_ms = waits.iter().map(Duration::as_millis).sum::<u128>() / 1000;
        assert!((3500..=4500).contains(&mean_ms), "{mean_ms} ms");
        // Another seed, other waits: two agents dropped together do not come back together.
        let mut c = Jitter::seeded(43);
        let other: Vec<Duration> = (0..20).map(|_| c.full(cap)).collect();
        assert_ne!(other, waits[..20]);
        assert_eq!(Jitter::seeded(1).full(Duration::ZERO), Duration::ZERO);
        // Off (the tests that time exact waits): the backoff itself.
        assert_eq!(Jitter::off().full(cap), cap);
        // From the system: within the span too.
        let mut os = Jitter::from_os();
        assert!(os.full(BACKOFF_FIRST) <= BACKOFF_FIRST);
    }

    /// Only a connection that stayed up a minute takes the backoff back to its start; one that went
    /// away sooner — or whose life is unknown — leaves it where it stood, to double at the next
    /// wait's end.
    #[test]
    fn the_backoff_restarts_only_after_a_stable_connection() {
        let b = Duration::from_secs(16);
        assert_eq!(after_disconnect(b, Some(STABLE_AFTER)), BACKOFF_FIRST);
        assert_eq!(
            after_disconnect(b, Some(Duration::from_secs(3600))),
            BACKOFF_FIRST
        );
        assert_eq!(
            after_disconnect(b, Some(STABLE_AFTER - Duration::from_millis(1))),
            b
        );
        assert_eq!(after_disconnect(b, Some(Duration::from_millis(200))), b);
        assert_eq!(after_disconnect(b, None), b);
        // A server that takes the agent and drops it at once: the waits grow as for failures.
        let mut backoff = BACKOFF_FIRST;
        let mut caps = Vec::new();
        for _ in 0..6 {
            backoff = after_disconnect(backoff, Some(Duration::from_secs(2)));
            caps.push(backoff.as_secs());
            backoff = next_backoff(backoff);
        }
        assert_eq!(caps, [1, 2, 4, 8, 16, 30]);
        assert_eq!(STABLE_AFTER, Duration::from_secs(60));
    }

    #[test]
    fn the_ordinary_backoff_doubles_to_thirty_seconds() {
        let mut d = BACKOFF_FIRST;
        let mut seen = vec![d.as_secs()];
        for _ in 0..6 {
            d = next_backoff(d);
            seen.push(d.as_secs());
        }
        assert_eq!(seen, [1, 2, 4, 8, 16, 30, 30]);
    }
}
