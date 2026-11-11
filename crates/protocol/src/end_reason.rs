//! The `session_end` reasons the agent sends, in one place.
//!
//! Every reason the agent can put in a `session_end` is a constant here, and every call site uses
//! the constant: the backend stores the reason as the session's `ended_reason` and the viewer maps
//! it to a sentence, so the set is agreed rather than invented at each call site. The agreed
//! vocabulary is `SESSION_END_REASONS` in `packages/protocol/src/errors.ts`; `tests/vocabulary.rs`
//! checks every reason in [`AGENT_SENT`] against `packages/protocol/fixtures/session-end-reasons.json`,
//! which `packages/protocol/scripts/emit.ts` emits from that list.
//!
//! The wire field stays a bounded free string (an older or newer peer may send a reason not
//! listed), so this is a vocabulary, not a validator.
//!
//! [`local`] holds the reasons that never go on the wire: they label an end in the agent's own
//! events and log lines (and the CLI's `BENCH SESSION_END`), and are kept apart so that nothing
//! sends one by mistake.

/// The owner pressed the kill switch: every session ended at once.
pub const KILL_SWITCH: &str = "kill_switch";
/// The owner stopped all sessions and has not resumed: a new session request is refused.
pub const PAUSED_ON_PC: &str = "paused_on_pc";
/// The peer closed: the orchestrator closed it, the viewer said goodbye (its DTLS `close_notify`
/// or SCTP ABORT/SHUTDOWN: `RTCPeerConnection.close()`), or str0m closed the connection by itself.
/// The agent tells the viewer's goodbye apart locally (`PeerEnd::ViewerClosed` in the transport,
/// the connection journal); on the wire all three are this.
pub const PEER_CLOSED: &str = "peer_closed";
/// No peer could be created from the viewer's offer, or the peer's run loop failed.
pub const PEER_ERROR: &str = "peer_error";
/// ICE lost the path and nothing brought it back within the grace window.
pub const ICE_TIMEOUT: &str = "ice_timeout";
/// The viewer's re-offer (an ICE restart) could not be applied to the running peer.
pub const ICE_RESTART_FAILED: &str = "ice_restart_failed";
/// The capture could not be brought back (it ended, or stalled past every restart).
pub const CAPTURE_LOST: &str = "capture_lost";
/// The capture could not be created or started when the session was set up.
pub const CAPTURE_ERROR: &str = "capture_error";
/// The encoder could not be created, or kept failing past every restart.
pub const ENCODER_ERROR: &str = "encoder_error";
/// The agent's own bookkeeping failed mid-setup; not expected to happen.
pub const INTERNAL_ERROR: &str = "internal_error";
/// An offer arrived for a session nobody requested.
pub const NO_SESSION_REQUEST: &str = "no_session_request";
/// The requesting user is not bound to this device (or has been unbound).
pub const UNBOUND: &str = "unbound";
/// A request from before a signaling reconnect, whose offer cannot reach the agent any more.
pub const AGENT_DISCONNECTED: &str = "agent_disconnected";
/// The agent is leaving on purpose — the owner's «Выход», the exit for an update, Windows ending the
/// session — and ends every live session first, with its final report, just before its goodbye:
/// the viewer hears at once that the session ended (not that the connection was lost), and the
/// session is not left to the backend's grace window and `agent_disconnected`.
pub const AGENT_ENDED: &str = "agent_ended";

/// Every reason the agent sends. What `tests/vocabulary.rs` holds against the contract; a new
/// constant above belongs here too.
pub const AGENT_SENT: &[&str] = &[
    KILL_SWITCH,
    PAUSED_ON_PC,
    PEER_CLOSED,
    PEER_ERROR,
    ICE_TIMEOUT,
    ICE_RESTART_FAILED,
    CAPTURE_LOST,
    CAPTURE_ERROR,
    ENCODER_ERROR,
    INTERNAL_ERROR,
    NO_SESSION_REQUEST,
    UNBOUND,
    AGENT_DISCONNECTED,
    AGENT_ENDED,
];

/// Received from the backend and acted on, never sent by the agent: the backend does not have a
/// session the agent named (its grace window ran out, or the viewer ended it while the agent's
/// socket was gone).
pub const UNKNOWN_SESSION: &str = "unknown_session";

/// Received from the backend, never sent by the agent: the PC's owner pressed «Прервать сеанс»
/// under the bot's message about a guest connecting. The guest keeps
/// access and may connect again; the journal shows the end as an ordinary one.
pub const OWNER_ENDED: &str = "owner_ended";

/// Received from the backend, never sent by the agent: an admin blocked the account or this PC
/// (the invite-only beta), and every session of it ended at once.
/// The journal shows it as «Доступ отозван». The agent also labels with it the sessions it ends
/// itself when the backend refuses it with `device_blocked` — locally only: those ends tell the
/// backend nothing (it ended them first).
pub const BLOCKED: &str = "blocked";

/// Reasons that label an end locally and are never sent.
pub mod local {
    /// The backend (or the viewer, through it) ended the session: the end came in a `session_end`
    /// and nothing goes back. Carried by the agent's `SessionEnded` event and the CLI's
    /// `BENCH SESSION_END` line only.
    pub const SERVER_ENDED: &str = "server_ended";

    /// Every local-only reason. `tests/vocabulary.rs` checks that none is a wire reason, so a
    /// reader of the agent's events can always tell a local label from what the backend was told.
    pub const ALL: &[&str] = &[SERVER_ENDED];
}
