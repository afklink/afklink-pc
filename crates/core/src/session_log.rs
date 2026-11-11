//! A session's life, told at the moment each step happens to whoever keeps a log file per session.
//!
//! The desktop app writes one file per session (`afklink_app_lib::log_route`), and which file a line
//! goes to is decided when the line is written. So it has to know a session exists before the
//! session's first line and that it is over before the lines of whatever comes next. The
//! [`crate::AgentEvent`]s cannot tell it that: they reach a subscriber through a channel, after the
//! lines they are about, and `SessionStarted` comes only once the setup — the offer, the peer, the
//! capture, some four hundred milliseconds of lines — is behind the session. These calls are made on
//! the thread that takes the step, before or right after its own line.
//!
//! The agent is given one with [`crate::Agent::with_session_log`]; the CLI gives none, and nothing
//! is called.
//!
//! # The calls, in the order a session makes them
//!
//! 1. [`SessionLog::opened`] — a `session_request` is accepted, just before its
//!    `session_request … from user …` line. A request refused (unbound, paused) is never opened.
//! 2. [`SessionLog::started`] — capture, encoder and peer are running (with
//!    `AgentEvent::SessionStarted`).
//! 3. [`SessionLog::ended`] — it is over: with every `AgentEvent::SessionEnded`, and when a request
//!    that never became a session is dropped without one (the backend ended it before its offer, an
//!    unbind swept it, its offer came from a user not bound any more). Can come more than once for one
//!    session, and for ids never opened (a refused request): the first end of an opened session is
//!    the one that counts.
//! 4. [`SessionLog::finished`] — its telemetry task, the last of its tasks to notice the end (it
//!    looks every `TELEMETRY_INTERVAL_MS`), has stopped: nothing more of it will be logged.
//!
//! A session that never started gets neither `started` nor `finished`.
//!
//! Every call is made between the orchestrator's steps (or from the telemetry task): it must be
//! quick and must not block on a disk.

/// See the [module docs](self).
pub trait SessionLog: Send + Sync {
    /// A session request was accepted; the session's lines start now.
    fn opened(&self, session_id: &str, telegram_user_id: i64);
    /// The session's capture, encoder and peer are running.
    fn started(&self, session_id: &str);
    /// The session is over, with the reason the backend is told (or why its setup failed); its
    /// teardown lines follow.
    fn ended(&self, session_id: &str, reason: &str);
    /// The session's last task has stopped: nothing more of it is logged.
    fn finished(&self, session_id: &str);
}
