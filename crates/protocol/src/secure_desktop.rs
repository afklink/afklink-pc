//! The PC's input on another Windows desktop — a UAC prompt, the lock screen: the agent's side of
//! the contract's `secure-desktop.ts` (the kinds and the limits). The three places that carry it are
//! the heartbeat's [`crate::Heartbeat::secure_desktop`], [`crate::AgentToServer::SecureDesktopOngoing`]
//! and the `agent_event` [`crate::metrics::AgentEventKind::SecureDesktopEnded`]; what the agent
//! observes and when it says it is `afklink_core::secure_desktop`.
//!
//! Held to the contract by `tests/secure_desktop.rs` (the kinds and the limits against the source
//! and the schemas) and by the golden fixtures in `tests/fixtures.rs`.

use serde::{Deserialize, Serialize};

/// Which desktop has the PC's input, when it is not the ordinary one (`SECURE_DESKTOP_KINDS`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecureDesktopKind {
    /// Windows' UAC consent prompt on the secure desktop: only someone at the PC can answer it.
    Uac,
    /// The session is locked: the lock screen, or the sign-in screen over it.
    Lock,
    /// Another desktop has the input, and it is neither of the above.
    Other,
}

impl SecureDesktopKind {
    /// Every kind, in the contract's order.
    pub const ALL: [Self; 3] = [Self::Uac, Self::Lock, Self::Other];

    /// The wire word.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Uac => "uac",
            Self::Lock => "lock",
            Self::Other => "other",
        }
    }
}

/// `SECURE_DESKTOP_LIMITS.ongoingAfterMs`: an episode during a session this long is sent to the
/// server as `secure_desktop_ongoing`, once per episode, counted from the episode's start.
pub const SECURE_DESKTOP_ONGOING_AFTER_MS: u64 = 10_000;

/// `SECURE_DESKTOP_LIMITS.durationMaxMs`: a finished episode's longest `duration_ms` (30 days); a
/// longer one is reported at this, and the server refuses more.
pub const SECURE_DESKTOP_DURATION_MAX_MS: u64 = 2_592_000_000;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_kinds_are_spelled_as_on_the_wire() {
        for k in SecureDesktopKind::ALL {
            assert_eq!(
                serde_json::to_value(k).expect("serialises"),
                serde_json::json!(k.as_str())
            );
        }
    }
}
