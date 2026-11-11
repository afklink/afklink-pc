//! WebSocket signaling client for `/ws/agent`.
//!
//! Handles the Ed25519 challenge-response handshake, then pumps messages
//! between the backend and the orchestrator over tokio mpsc channels.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use base64::prelude::*;
use futures_util::{SinkExt, StreamExt};
use tokio::sync::{mpsc, oneshot};
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
use tokio_tungstenite::tungstenite::protocol::CloseFrame;
use tokio_tungstenite::tungstenite::Message;

use afklink_protocol::{
    agent_challenge_message, AgentToServer, BindingInfo, GoodbyeReason, ServerToAgent,
    AGENT_CHALLENGE_NONCE_BYTES, PROTOCOL_VERSION,
};

/// How long a backend that pings at the fast cadence may say nothing at all before the connection
/// is taken as dead.
///
/// The backend pings every socket every five seconds and closes one that has sent it nothing for
/// twenty (`HEARTBEAT_MS` in `server/src/index.ts`). Without a limit of its own the agent would
/// notice a half-open connection — the PC's network changed under it — only when a write failed,
/// which can take the TCP retransmission timeout (minutes). Twenty seconds is four missed pings:
/// after a network switch the agent is back in about twenty-two seconds (about fifty with
/// [`LEGACY_SILENCE_LIMIT`]).
///
/// Only once the pings are seen to come that often ([`PingCadence`]): against a backend that pings
/// every twenty seconds — an older backend build — a
/// twenty-second limit would race each ping and drop a healthy connection every few minutes, so
/// until then [`LEGACY_SILENCE_LIMIT`] holds.
pub const BACKEND_SILENCE_LIMIT: Duration = Duration::from_secs(20);

/// The silence limit until the backend's pings are seen to come at the fast cadence: two missed
/// pings of a backend that pings every twenty seconds, and a margin.
pub const LEGACY_SILENCE_LIMIT: Duration = Duration::from_secs(45);

/// A gap between two pings at most this long is the fast cadence (five seconds, with room for a
/// late one); a longer one is the old twenty-second cadence.
const FAST_PING_CADENCE: Duration = Duration::from_secs(10);

/// Two pings closer together than this say nothing about the cadence: a backlog delivered at once
/// after the path stalled.
const MIN_PING_GAP: Duration = Duration::from_secs(1);

/// How long the pump keeps at a goodbye after its caller stopped waiting: to finish writing it,
/// and to hear the backend's close for the log. Then it drops the connection.
const GOODBYE_LINGER: Duration = Duration::from_secs(2);

/// The close frame's reason after a goodbye. For the backend's log; `agent_goodbye` says why.
const GOODBYE_CLOSE_REASON: &str = "goodbye";

/// The close frame's reason when the challenge's nonce is not 32 bytes. For the backend's log.
const CHALLENGE_REFUSED_REASON: &str = "challenge nonce must be 32 bytes";

/// How long opening the WebSocket (TCP, TLS, HTTP upgrade) may take before the attempt is given up
/// and the reconnect loop's backoff takes over.
///
/// Without a bound, a connect into a network that drops packets rather than refusing them waits
/// for the operating system's own timeout (about 21 s on Windows) — longer than the backend's whole
/// grace window for this agent's sessions (`AGENT_GRACE_MS`, 20 s), so one unlucky attempt would be
/// enough to lose them. A healthy connect takes well under a second even over a poor mobile link.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// How long the handshake may hear nothing at all from the backend — no `challenge`, no
/// `agent_ready`, not even its heartbeat ping — before the connection is given up as one that
/// delivers nothing (seen behind a provider that let a socket to Cloudflare open and then froze
/// everything the server sent on it, with no reset).
///
/// The backend answers `agent_hello` with `challenge`, and `agent_auth` with `agent_ready`, within a
/// round trip, and pings every socket every five seconds whether it is authenticated or not
/// (`server/src/index.ts`): ten seconds of nothing is the answer missing for a hundred round trips
/// and two missed pings. The same ten seconds as [`CONNECT_TIMEOUT`], for the same reason — a
/// healthy step takes well under a second — and well inside the backend's own deadline for an
/// unauthenticated socket (thirty seconds), whose close a frozen path never delivers. Reset by every frame, so a slow but living backend is never cut off.
pub const HANDSHAKE_SILENCE_LIMIT: Duration = Duration::from_secs(10);

/// How long one write of the pump — a `pong`, a message the orchestrator queued, a WebSocket pong —
/// may take before the connection is given up as one that takes nothing more ([`EndCause::SendTimeout`]).
///
/// A write had no bound: one that stuck (the socket's send buffer full on a path that stopped
/// draining it) held the pump inside it, and with it the silence timer and everything the backend
/// said meanwhile — the link stayed «up» with nothing moving either way. A healthy write of a
/// signaling message is a copy into the socket's buffer, well under a millisecond; ten seconds is a
/// path that has stopped carrying anything, and half the backend's own silence limit for this agent,
/// so the reconnect starts before the backend gives the device up. The silence limit is still in force
/// while a write is pending: whichever comes first ends it.
pub const SEND_TIMEOUT: Duration = Duration::from_secs(10);

/// The time limits of a connection — [`LIMITS`] in production; a parameter so tests (here and in
/// `afklink_core`) need not wait for the real ones.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// [`CONNECT_TIMEOUT`]: the name, TCP, TLS and the upgrade, together.
    pub connect: Duration,
    /// [`HANDSHAKE_SILENCE_LIMIT`]: from `agent_hello` on, between two frames of the handshake.
    pub handshake_silence: Duration,
    /// [`BACKEND_SILENCE_LIMIT`]: against a backend seen to ping at the fast cadence.
    pub silence: Duration,
    /// [`LEGACY_SILENCE_LIMIT`]: until then.
    pub legacy_silence: Duration,
    /// [`FAST_PING_CADENCE`].
    pub fast_cadence: Duration,
    /// [`MIN_PING_GAP`].
    pub min_ping_gap: Duration,
    /// [`SEND_TIMEOUT`]: one write of the pump, after the handshake.
    pub send: Duration,
}

/// Production's limits.
pub const LIMITS: Limits = Limits {
    connect: CONNECT_TIMEOUT,
    handshake_silence: HANDSHAKE_SILENCE_LIMIT,
    silence: BACKEND_SILENCE_LIMIT,
    legacy_silence: LEGACY_SILENCE_LIMIT,
    fast_cadence: FAST_PING_CADENCE,
    min_ping_gap: MIN_PING_GAP,
    send: SEND_TIMEOUT,
};

/// How far opening a connection got when it failed ([`ConnectFailed`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectStage {
    /// Looking up the host's addresses.
    Dns,
    /// The TCP connection.
    Tcp,
    /// TLS and the HTTP upgrade.
    Upgrade,
}

impl ConnectStage {
    /// For log lines.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Dns => "dns",
            Self::Tcp => "tcp",
            Self::Upgrade => "upgrade",
        }
    }
}

/// What went wrong while opening a connection ([`ConnectFailed`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectFailure {
    /// The stage did not end within [`CONNECT_TIMEOUT`] (counted from the start of the attempt).
    Timeout,
    /// The name gave no address, or the lookup failed.
    NotResolved,
    /// The host refused the TCP connection.
    Refused,
    /// No route to the host, or no local address to come from: this PC's own network is down.
    Unreachable,
    /// The connection was reset or closed under the TLS handshake or the upgrade.
    Reset,
    /// TLS failed: a certificate, an alert.
    Tls,
    /// The upgrade was answered with this HTTP status instead of 101.
    Status(u16),
    /// Anything else: a malformed answer, an address this build cannot use.
    Other,
}

impl ConnectFailure {
    /// For log lines.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Timeout => "timeout",
            Self::NotResolved => "not_resolved",
            Self::Refused => "refused",
            Self::Unreachable => "unreachable",
            Self::Reset => "reset",
            Self::Tls => "tls",
            Self::Status(_) => "status",
            Self::Other => "other",
        }
    }
}

/// Opening the connection failed — typed, so whoever chooses the way to the server
/// (`afklink_core::entry`) can tell a path that drops or refuses from this PC being offline or the
/// server answering. In the `anyhow` chain [`connect`] returns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectFailed {
    /// The address tried.
    pub url: String,
    pub stage: ConnectStage,
    pub failure: ConnectFailure,
    /// From the start of the attempt.
    pub elapsed: Duration,
    /// The address TCP connected to, when it got that far.
    pub peer: Option<std::net::SocketAddr>,
    /// What the failing layer said.
    pub detail: String,
}

impl std::fmt::Display for ConnectFailed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "ws connect to {} ({} {}, {} ms): {}",
            self.url,
            self.stage.as_str(),
            self.failure.as_str(),
            self.elapsed.as_millis(),
            self.detail
        )
    }
}

impl std::error::Error for ConnectFailed {}

/// The connection opened and `agent_hello` went out, and then the backend said nothing at all for
/// [`HANDSHAKE_SILENCE_LIMIT`] — a path that lets a socket open and delivers nothing from the
/// server (`afklink_core::entry`). In the `anyhow` chain [`connect`] returns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandshakeSilent {
    /// The step that never came: `challenge` or `agent_ready`.
    pub awaiting: &'static str,
    /// How long nothing came.
    pub silent_for: Duration,
    /// Frames heard from the backend since the upgrade, its pings included.
    pub frames: u32,
}

impl std::fmt::Display for HandshakeSilent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "the backend said nothing for {} ms while this agent waited for {} ({} frame(s) heard \
             since the upgrade): the connection delivers nothing",
            self.silent_for.as_millis(),
            self.awaiting,
            self.frames
        )
    }
}

impl std::error::Error for HandshakeSilent {}

/// Why a connection's pump ended ([`LinkEnd`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndCause {
    /// The backend said nothing, not even its heartbeat, for the silence limit.
    Silence,
    /// The backend closed it with a close frame (its code, when it gave one).
    ClosedByBackend { code: Option<u16> },
    /// The stream ended without a close frame.
    StreamEnded,
    /// The WebSocket failed (a reset, a protocol error).
    WsError,
    /// A write failed.
    SendFailed,
    /// A write did not finish within [`SEND_TIMEOUT`]: the path takes nothing more from this agent.
    SendTimeout,
    /// This agent said its goodbye on it.
    Goodbye,
    /// Every sender went: the orchestrator retired the link.
    Retired,
    /// The orchestrator stopped reading.
    OrchestratorGone,
}

impl EndCause {
    /// For log lines.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Silence => "silence",
            Self::ClosedByBackend { .. } => "closed_by_backend",
            Self::StreamEnded => "stream_ended",
            Self::WsError => "ws_error",
            Self::SendFailed => "send_failed",
            Self::SendTimeout => "send_timeout",
            Self::Goodbye => "goodbye",
            Self::Retired => "retired",
            Self::OrchestratorGone => "orchestrator_gone",
        }
    }
}

/// How a connection that completed its handshake ended, as its pump saw it: why, and what the
/// backend had sent over it — what tells a path that froze after a few kilobytes
/// (`afklink_core::entry`) from a network that went away under a connection that carried plenty.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinkEnd {
    pub cause: EndCause,
    /// Bytes of every frame the backend sent after the handshake (payloads; its pings included).
    pub received_bytes: u64,
    /// Frames the backend sent after the handshake, its pings included.
    pub frames: u64,
    /// From the end of the handshake to the end of the pump.
    pub lived: Duration,
}

/// Which silence limit fits the backend's heartbeat, learned from the gaps between its pings.
///
/// [`LEGACY_SILENCE_LIMIT`] until a gap of at most [`FAST_PING_CADENCE`] is seen, then
/// [`BACKEND_SILENCE_LIMIT`]; a longer gap later (a backend rolled back, a long stall that did not
/// kill the path) goes back to the legacy limit. A gap under [`MIN_PING_GAP`] is a backlog, not a
/// cadence, and changes nothing.
struct PingCadence {
    limits: Limits,
    last_ping: Option<Instant>,
    /// `None` until the first gap is measured.
    fast: Option<bool>,
}

impl PingCadence {
    fn new(limits: Limits) -> Self {
        Self {
            limits,
            last_ping: None,
            fast: None,
        }
    }

    /// The silence limit in force.
    fn limit(&self) -> Duration {
        if self.fast == Some(true) {
            self.limits.silence
        } else {
            self.limits.legacy_silence
        }
    }

    /// A ping arrived at `at`: the new limit when the verdict changed, `None` when it did not.
    fn ping(&mut self, at: Instant) -> Option<Duration> {
        let previous = self.last_ping.replace(at)?;
        let gap = at.saturating_duration_since(previous);
        if gap < self.limits.min_ping_gap {
            tracing::trace!(
                gap_ms = gap.as_millis() as u64,
                "signaling: two pings close together (a backlog): the cadence is not judged by them"
            );
            return None;
        }
        let fast = gap <= self.limits.fast_cadence;
        if self.fast == Some(fast) {
            return None;
        }
        let was = self.limit();
        self.fast = Some(fast);
        let limit = self.limit();
        tracing::debug!(
            gap_ms = gap.as_millis() as u64,
            fast_cadence_ms = self.limits.fast_cadence.as_millis() as u64,
            silence_limit_ms = limit.as_millis() as u64,
            was_ms = was.as_millis() as u64,
            "signaling: the backend's ping cadence decides the silence limit ({})",
            if fast {
                "it pings often: the short limit"
            } else {
                "it pings rarely (an older backend): the long limit, so no ping races it"
            }
        );
        Some(limit)
    }
}

/// What became of a goodbye, as far as its caller waited.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GoodbyeResult {
    /// The backend answered the close frame that followed `agent_goodbye`: it has read the goodbye.
    Confirmed { took: Duration },
    /// `agent_goodbye` and the close frame were written and flushed to the socket, and the backend
    /// did not answer the close within the budget.
    Flushed { took: Duration },
    /// Not even written within the budget: a write stuck on a dying path, or a starved runtime.
    TimedOut { took: Duration },
    /// The write failed.
    Failed { took: Duration, error: String },
    /// The connection's pump was gone, or ended before it got to the goodbye.
    NoConnection,
}

impl GoodbyeResult {
    /// For log lines.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Confirmed { .. } => "confirmed",
            Self::Flushed { .. } => "flushed",
            Self::TimedOut { .. } => "timed_out",
            Self::Failed { .. } => "failed",
            Self::NoConnection => "no_connection",
        }
    }

    /// How long the caller waited; zero for [`Self::NoConnection`].
    pub fn took(&self) -> Duration {
        match self {
            Self::Confirmed { took }
            | Self::Flushed { took }
            | Self::TimedOut { took }
            | Self::Failed { took, .. } => *took,
            Self::NoConnection => Duration::ZERO,
        }
    }

    /// Whether the goodbye left this PC: written and flushed, confirmed or not.
    pub fn sent(&self) -> bool {
        matches!(self, Self::Confirmed { .. } | Self::Flushed { .. })
    }
}

/// One step of a goodbye, as the pump reports it to the caller (at most two: written, then
/// confirmed; or failed).
#[derive(Debug, Clone, PartialEq, Eq)]
enum GoodbyeStep {
    Written,
    Confirmed,
    Failed(String),
}

/// What the pump is asked to do by [`GoodbyeHandle::request`].
struct GoodbyeRequest {
    reason: GoodbyeReason,
    asked: Instant,
    /// The caller's budget runs out here.
    deadline: Instant,
    /// How long after `deadline` the pump keeps at it ([`GOODBYE_LINGER`]).
    linger: Duration,
    /// Never blocks the pump: capacity for every step it can report.
    report: std::sync::mpsc::SyncSender<GoodbyeStep>,
}

/// Asks this connection's pump to say the agent's goodbye and close the connection. Cloneable and
/// usable from any thread: the waiting is the [`GoodbyeTicket`]'s.
#[derive(Clone)]
pub struct GoodbyeHandle {
    tx: mpsc::UnboundedSender<GoodbyeRequest>,
}

impl GoodbyeHandle {
    /// Ask for the goodbye, to be done within `budget` from now. Never blocks; the ticket waits.
    pub fn request(&self, reason: GoodbyeReason, budget: Duration) -> GoodbyeTicket {
        let asked = Instant::now();
        let (report, rx) = std::sync::mpsc::sync_channel(2);
        let rx = match self.tx.send(GoodbyeRequest {
            reason,
            asked,
            deadline: asked + budget,
            linger: GOODBYE_LINGER,
            report,
        }) {
            Ok(()) => {
                tracing::debug!(
                    reason = reason.as_str(),
                    budget_ms = budget.as_millis() as u64,
                    "signaling: goodbye asked of the connection's pump"
                );
                Some(rx)
            }
            Err(_) => {
                tracing::debug!(
                    reason = reason.as_str(),
                    "signaling: goodbye not asked: this connection's pump has ended"
                );
                None
            }
        };
        GoodbyeTicket {
            asked,
            deadline: asked + budget,
            rx,
        }
    }

    /// Whether the connection's pump has ended (nothing could say a goodbye on it).
    pub fn is_closed(&self) -> bool {
        self.tx.is_closed()
    }
}

/// A goodbye asked for: wait on it with [`Self::wait`].
pub struct GoodbyeTicket {
    asked: Instant,
    deadline: Instant,
    rx: Option<std::sync::mpsc::Receiver<GoodbyeStep>>,
}

impl GoodbyeTicket {
    /// Block this thread until the backend has confirmed the goodbye or the budget has run out —
    /// never longer. Not for an async task's own thread: the pump may need it to make progress
    /// (`tokio::task::spawn_blocking` is the way there).
    pub fn wait(self) -> GoodbyeResult {
        let Some(rx) = self.rx else {
            return GoodbyeResult::NoConnection;
        };
        let mut written = false;
        loop {
            let left = self.deadline.saturating_duration_since(Instant::now());
            let took = || self.asked.elapsed();
            match rx.recv_timeout(left) {
                Ok(GoodbyeStep::Written) => written = true,
                Ok(GoodbyeStep::Confirmed) => return GoodbyeResult::Confirmed { took: took() },
                Ok(GoodbyeStep::Failed(error)) => {
                    return GoodbyeResult::Failed {
                        took: took(),
                        error,
                    }
                }
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                    return if written {
                        GoodbyeResult::Flushed { took: took() }
                    } else {
                        GoodbyeResult::TimedOut { took: took() }
                    };
                }
                // The pump let go of the request: after writing it, the connection ended without
                // the backend's close; before, the pump ended without getting to it.
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                    return if written {
                        GoodbyeResult::Flushed { took: took() }
                    } else {
                        GoodbyeResult::NoConnection
                    };
                }
            }
        }
    }
}

/// Signs the challenge message and returns the raw 64-byte Ed25519 signature.
///
/// The handshake hands it [`agent_challenge_message`] of the nonce — the domain prefix and the 32
/// nonce bytes — and nothing else; the signer signs whatever bytes it is given.
pub type Signer = Arc<dyn Fn(&[u8]) -> Vec<u8> + Send + Sync>;

/// The backend answered a handshake step with an `error` frame instead of the next step.
///
/// A type rather than a sentence, because what the agent does next depends on the code: the
/// reconnect loop (`afklink_core::reconnect`) finds this in the `anyhow` chain [`connect`] returns
/// and decides by the code's severity (`afklink_protocol::errors`) whether to back off and retry,
/// retry slowly, or wait for the owner. Every code comes through here, known or not, transient or
/// fatal: classifying is the caller's business.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandshakeRefused {
    /// The wire code, as the backend sent it.
    pub code: String,
    /// The backend's detail, if any (`server speaks 2..3`). For the log, never for the owner's
    /// screen.
    pub message: Option<String>,
    /// The step that was answered with the error: `challenge` or `agent_ready`.
    pub awaiting: &'static str,
}

impl std::fmt::Display for HandshakeRefused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "the backend refused the handshake while this agent waited for {}: {} {:?}",
            self.awaiting, self.code, self.message
        )
    }
}

impl std::error::Error for HandshakeRefused {}

/// The `error` frame that answered a handshake step, as the error [`connect`] returns.
fn refused(code: String, message: Option<String>, awaiting: &'static str) -> anyhow::Error {
    // not-a-key-name: the server's error code
    tracing::debug!(
        %code,
        message = message.as_deref().unwrap_or("-"),
        awaiting,
        "handshake answered with an error frame"
    );
    HandshakeRefused {
        code,
        message,
        awaiting,
    }
    .into()
}

/// Static parameters for a signaling connection.
#[derive(Debug, Clone)]
pub struct SignalingConfig {
    /// Full WebSocket URL, e.g. `wss://host/ws/agent` or `ws://localhost:8787/ws/agent`.
    pub url: String,
    pub device_id: String,
    /// Base64-encoded 32-byte Ed25519 public key.
    pub pubkey_b64: String,
    /// The upgrade's `User-Agent`: `AFKLink/<version> (<channel>)`
    /// (`afklink_core::build_info::BuildInfo::user_agent`). The backend keeps it per device
    /// (`devices.last_agent`), which is how the PCs still on an old build are found. `None`: none
    /// sent, as every build before it.
    pub user_agent: Option<String>,
    /// Contract v2's fields of `agent_hello`: the build, this process's boot id and how the
    /// previous one ended. Empty: the hello of every build before them.
    pub hello: HelloInfo,
}

/// What `agent_hello` says beyond the device (contract v2): each optional, each left
/// out when unknown. Checked by whoever builds it (`afklink_core::run_state`, `afklink_core::hw`): a
/// hello the server's schema refuses would be refused on every attempt.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HelloInfo {
    pub build: Option<afklink_protocol::AgentBuildInfo>,
    pub boot_id: Option<String>,
    pub last_exit: Option<afklink_protocol::AgentLastExit>,
    /// The invite-only beta: the PC's hardware fingerprint (`afklink_core::hw`), read once per
    /// process. Its `Debug` hides the hash; the log names only its parts and the VM flag.
    pub hw: Option<afklink_protocol::AgentHw>,
}

/// What a connection's pump knows of its health, for whoever needs more than "it is up": when the
/// backend was last heard from (any frame, its heartbeat included), which silence limit the pump
/// holds the connection to ([`BACKEND_SILENCE_LIMIT`] or [`LEGACY_SILENCE_LIMIT`]), and whether the
/// pump still runs. Written by the pump, read by anyone (`afklink_core::agent_events` delivers an
/// event only once its connection outlived both the limit and a word from the backend after it).
#[derive(Debug, Clone)]
pub struct LinkHealth {
    inner: Arc<HealthInner>,
}

#[derive(Debug)]
struct HealthInner {
    /// What the stamps below count from: when the handshake ended (its `agent_ready` heard).
    epoch: Instant,
    /// Milliseconds from `epoch` to the last frame heard.
    heard_ms: AtomicU64,
    /// The silence limit in force, in milliseconds.
    limit_ms: AtomicU64,
    /// Cleared as the pump exits.
    up: AtomicBool,
    /// How the pump ended: set as it exits, before `incoming` ends.
    end: std::sync::Mutex<Option<LinkEnd>>,
}

impl LinkHealth {
    /// A connection whose handshake just ended: heard from now, held to `limit`.
    fn new(limit: Duration) -> Self {
        Self {
            inner: Arc::new(HealthInner {
                epoch: Instant::now(),
                heard_ms: AtomicU64::new(0),
                limit_ms: AtomicU64::new(duration_ms(limit)),
                up: AtomicBool::new(true),
                end: std::sync::Mutex::new(None),
            }),
        }
    }

    /// How the pump ended, once it has: there before `incoming` ends. `None` while it runs.
    pub fn end(&self) -> Option<LinkEnd> {
        *self
            .inner
            .end
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn set_end(&self, end: LinkEnd) {
        *self
            .inner
            .end
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(end);
    }

    /// When the backend was last heard from.
    pub fn last_heard(&self) -> Instant {
        self.inner.epoch + Duration::from_millis(self.inner.heard_ms.load(Ordering::Relaxed))
    }

    /// The silence limit the pump holds the connection to now.
    pub fn silence_limit(&self) -> Duration {
        Duration::from_millis(self.inner.limit_ms.load(Ordering::Relaxed))
    }

    /// Whether the pump still runs: the connection has not ended, as far as it knows.
    pub fn is_up(&self) -> bool {
        self.inner.up.load(Ordering::Relaxed)
    }

    fn heard(&self, at: Instant) {
        let ms = duration_ms(at.saturating_duration_since(self.inner.epoch));
        self.inner.heard_ms.fetch_max(ms, Ordering::Relaxed);
    }

    fn set_limit(&self, limit: Duration) {
        self.inner
            .limit_ms
            .store(duration_ms(limit), Ordering::Relaxed);
    }

    fn ended(&self) {
        self.inner.up.store(false, Ordering::Relaxed);
    }
}

fn duration_ms(d: Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
}

/// A connected, authenticated signaling channel.
pub struct Signaling {
    /// Send messages to the backend.
    pub outgoing: mpsc::UnboundedSender<AgentToServer>,
    /// Receive messages from the backend. Ends when the pump exits — and only after the pump has
    /// put what it did not write into [`Signaling::unsent`], so whoever sees this end can take the
    /// hand-back without waiting.
    pub incoming: mpsc::UnboundedReceiver<ServerToAgent>,
    /// What the pump had been given but had not written when it exited, in order: the message whose
    /// write failed first, then whatever was still queued in `outgoing`. Sent once, as the pump
    /// exits. A message the socket accepted is not in it, even if it never arrived: a write into a
    /// half-open connection succeeds. See `afklink_core::relay`, which holds these for the next
    /// connection.
    pub unsent: oneshot::Receiver<Vec<AgentToServer>>,
    /// Says the agent's goodbye on this connection and closes it, past whatever the orchestrator is
    /// doing: what a quit, an update, a shutdown or a sleep uses.
    pub goodbye: GoodbyeHandle,
    /// Bindings reported at `agent_ready`.
    pub initial_bindings: Vec<BindingInfo>,
    /// Protocol window the backend reported. Kept so a mismatch is diagnosable
    /// from a log line rather than from a message that silently does nothing.
    pub server_protocol: (u32, u32),
    /// When the backend was last heard from and the silence limit in force (see [`LinkHealth`]).
    pub health: LinkHealth,
    /// The address TCP connected to: which way the name led (a Cloudflare edge, the RU entry's box).
    pub peer: Option<std::net::SocketAddr>,
}

/// Connect, perform the challenge handshake, and start the message pump.
///
/// A failure to open the connection comes back as [`ConnectFailed`] in the error chain, a handshake
/// that heard nothing as [`HandshakeSilent`], an `error` frame as [`HandshakeRefused`].
pub async fn connect(cfg: SignalingConfig, signer: Signer) -> Result<Signaling> {
    connect_with(cfg, signer, LIMITS).await
}

/// [`connect`], with its time limits as a parameter (tests).
pub async fn connect_with(
    cfg: SignalingConfig,
    signer: Signer,
    limits: Limits,
) -> Result<Signaling> {
    let started = std::time::Instant::now();
    let request = upgrade_request(&cfg)?;
    let (mut ws, status, peer) = open(&cfg.url, request, limits).await?;
    tracing::debug!(
        url = %cfg.url,
        status,
        peer = %peer.map_or_else(|| "-".to_string(), |p| p.to_string()),
        elapsed_ms = started.elapsed().as_millis() as u64,
        "signaling websocket open; starting the handshake"
    );
    // Frames heard since the upgrade, for the line that says the handshake went silent.
    let mut heard = 0u32;

    // Step 1: agent_hello.
    send_within(
        &mut ws,
        &AgentToServer::AgentHello {
            protocol_version: PROTOCOL_VERSION,
            device_id: cfg.device_id.clone(),
            pubkey: cfg.pubkey_b64.clone(),
            build: cfg.hello.build.clone(),
            boot_id: cfg.hello.boot_id.clone(),
            last_exit: cfg.hello.last_exit,
            hw: cfg.hello.hw.clone(),
        },
        limits.send,
    )
    .await?;
    // The fingerprint by its parts and VM flag only: the hash never goes into a log.
    tracing::debug!(
        device_id = %cfg.device_id,
        protocol = PROTOCOL_VERSION,
        build = cfg.hello.build.as_ref().map_or("-", |b| b.version.as_str()),
        boot_id = cfg.hello.boot_id.as_deref().unwrap_or("-"),
        last_exit = cfg.hello.last_exit.map_or("-", |e| e.kind.as_str()),
        last_exit_at = ?cfg.hello.last_exit.and_then(|e| e.at),
        hw_parts = cfg.hello.hw.as_ref().map_or(0, |h| h.parts),
        hw_vm = cfg.hello.hw.as_ref().is_some_and(|h| h.vm),
        "agent_hello sent"
    );

    // Step 2: expect challenge.
    //
    // Anything else is named by its wire type, never `{:?}`: whatever the server sent may carry a
    // pairing code or a TURN credential, and this error ends up in the log. A keep-alive `ping` is
    // not anything else: see `recv_handshake`.
    let nonce_b64 =
        match recv_handshake(&mut ws, "challenge", limits.handshake_silence, &mut heard).await? {
            Some(ServerToAgent::Challenge { nonce }) => nonce,
            Some(ServerToAgent::Error { code, message }) => {
                return Err(refused(code, message, "challenge"));
            }
            Some(other) => bail!("expected challenge, got {}", other.kind()),
            None => bail!("expected challenge, the backend closed the connection"),
        };
    let nonce = BASE64_STANDARD
        .decode(nonce_b64.as_bytes())
        .context("decode challenge nonce")?;

    // Step 3: sign the prefixed nonce and send agent_auth.
    //
    // Only a nonce of exactly 32 bytes is signed: the prefix keeps the signature from being valid
    // for anything else the key signs, and a fixed length keeps the message from being anything
    // but a challenge. A backend that sends another length is broken or is not ours; the attempt
    // ends here, and the reconnect loop backs off. The nonce itself never goes into the log.
    let Some(message) = agent_challenge_message(&nonce) else {
        tracing::warn!(
            nonce_bytes = nonce.len(),
            expected = AGENT_CHALLENGE_NONCE_BYTES,
            "signaling: the challenge nonce is not {AGENT_CHALLENGE_NONCE_BYTES} bytes; nothing \
             signed, the connection is closed"
        );
        close_refusing(&mut ws, CHALLENGE_REFUSED_REASON, limits.send).await;
        bail!(
            "the backend's challenge nonce is {} bytes, not {AGENT_CHALLENGE_NONCE_BYTES}: \
             refused unsigned",
            nonce.len()
        );
    };
    let sig = signer(&message);
    let sig_b64 = BASE64_STANDARD.encode(sig);
    send_within(
        &mut ws,
        &AgentToServer::AgentAuth { signature: sig_b64 },
        limits.send,
    )
    .await?;
    tracing::debug!(
        nonce_bytes = nonce.len(),
        message_bytes = message.len(),
        "challenge signed behind the domain prefix; agent_auth sent"
    );

    // Step 4: expect agent_ready.
    let (initial_bindings, server_protocol) =
        match recv_handshake(&mut ws, "agent_ready", limits.handshake_silence, &mut heard).await? {
            Some(ServerToAgent::AgentReady {
                bindings,
                protocol_version,
                min_supported_protocol,
            }) => {
                tracing::info!(
                    "backend speaks protocol {min_supported_protocol}..{protocol_version}, \
                 this build speaks {PROTOCOL_VERSION}"
                );
                // Outside the window both sides still connect, and then disagree about messages; a
                // warning here is the difference between a log that explains that and one that does not.
                if !(min_supported_protocol..=protocol_version).contains(&PROTOCOL_VERSION) {
                    tracing::warn!(
                        ours = PROTOCOL_VERSION,
                        min_supported_protocol,
                        protocol_version,
                        "this build's protocol is outside the backend's window"
                    );
                }
                (bindings, (min_supported_protocol, protocol_version))
            }
            Some(ServerToAgent::Error { code, message }) => {
                return Err(refused(code, message, "agent_ready"));
            }
            Some(other) => bail!("expected agent_ready, got {}", other.kind()),
            None => bail!("expected agent_ready, the backend closed the connection"),
        };
    tracing::debug!(
        bindings = initial_bindings.len(),
        frames = heard,
        elapsed_ms = started.elapsed().as_millis() as u64,
        "signaling handshake complete"
    );

    // Handshake done — start the pump.
    let (out_tx, mut out_rx) = mpsc::unbounded_channel::<AgentToServer>();
    let (in_tx, in_rx) = mpsc::unbounded_channel::<ServerToAgent>();
    let (unsent_tx, unsent_rx) = oneshot::channel::<Vec<AgentToServer>>();
    let (goodbye_tx, mut goodbye_rx) = mpsc::unbounded_channel::<GoodbyeRequest>();
    let health = LinkHealth::new(PingCadence::new(limits).limit());
    let pump_health = health.clone();

    tokio::spawn(async move {
        let health = pump_health;
        let pump_started = Instant::now();
        // What went each way over this connection, for the line that says it ended.
        let (mut sent, mut received) = (0u64, 0u64);
        // Every frame the backend sent, and its bytes: what tells a path that froze after a few
        // kilobytes from one that carried plenty (`LinkEnd`).
        let (mut frames_in, mut bytes_in) = (0u64, 0u64);
        // The message whose write failed, handed back with whatever is still queued.
        let mut failed: Option<AgentToServer> = None;
        // Which silence limit is in force; see `BACKEND_SILENCE_LIMIT`.
        let mut cadence = PingCadence::new(limits);
        tracing::debug!(
            silence_limit_ms = cadence.limit().as_millis() as u64,
            send_limit_ms = limits.send.as_millis() as u64,
            "signaling pump started; the silence limit is the long one until the backend's pings \
             are seen to come often; every write is bounded by the send limit and the silence limit"
        );
        // Reset by every frame from the backend.
        let silence = tokio::time::sleep(cadence.limit());
        tokio::pin!(silence);
        // Until every goodbye handle is gone: then its branch is off, rather than answering `None`
        // at once on every turn.
        let mut goodbye_open = true;
        let (why, cause) = loop {
            tokio::select! {
                // Application -> backend.
                msg = out_rx.recv() => {
                    let Some(msg) = msg else {
                        break ("every sender is gone (the link was retired)", EndCause::Retired)
                    };
                    log_message("out", msg.kind(), msg.session_id());
                    let written =
                        write_bounded(send(&mut ws, &msg), limits.send, silence.deadline()).await;
                    if let Some(end) = write_end(written, msg.kind(), msg.session_id(), limits.send) {
                        failed = Some(msg);
                        break end;
                    }
                    sent += 1;
                }
                // The agent is leaving (`GoodbyeHandle`): the last thing this connection does.
                req = goodbye_rx.recv(), if goodbye_open => {
                    let Some(req) = req else {
                        goodbye_open = false;
                        tracing::trace!(
                            "signaling: every goodbye handle is gone; none can be asked of this \
                             connection any more"
                        );
                        continue;
                    };
                    break (
                        say_goodbye(&mut ws, &mut out_rx, req, &mut sent, &mut failed).await,
                        EndCause::Goodbye,
                    );
                }
                () = &mut silence => {
                    tracing::info!(
                        silent_ms = cadence.limit().as_millis() as u64,
                        received,
                        frames_in,
                        bytes_in,
                        lived_ms = pump_started.elapsed().as_millis() as u64,
                        "the backend has said nothing, not even its heartbeat ping, for too long: \
                         the connection is taken as dead"
                    );
                    break ("the backend went silent", EndCause::Silence);
                }
                // Backend -> application.
                frame = ws.next() => {
                    if let Some(Ok(f)) = &frame {
                        frames_in += 1;
                        bytes_in += f.len() as u64;
                        health.heard(Instant::now());
                        silence
                            .as_mut()
                            .reset(tokio::time::Instant::now() + cadence.limit());
                    }
                    match frame {
                        Some(Ok(Message::Text(t))) => {
                            match serde_json::from_str::<ServerToAgent>(t.as_str()) {
                                // The heartbeat is answered here, by the pump, and not by the
                                // orchestrator: its loop can be busy for seconds (starting a
                                // session waits for STUN; ending one stops the capture), and a
                                // `pong` that waits for it is what got a busy agent's socket reaped
                                // by the backend's heartbeat. Not handed on: there is nothing in it
                                // for anyone else.
                                Ok(ServerToAgent::Ping) => {
                                    received += 1;
                                    log_message("in", "ping", None);
                                    if let Some(limit) = cadence.ping(Instant::now()) {
                                        health.set_limit(limit);
                                        silence
                                            .as_mut()
                                            .reset(tokio::time::Instant::now() + limit);
                                    }
                                    log_message("out", "pong", None);
                                    let written = write_bounded(
                                        send(&mut ws, &AgentToServer::Pong),
                                        limits.send,
                                        silence.deadline(),
                                    )
                                    .await;
                                    if let Some(end) = write_end(written, "pong", None, limits.send) {
                                        break end;
                                    }
                                    sent += 1;
                                }
                                Ok(parsed) => {
                                    received += 1;
                                    log_message("in", parsed.kind(), parsed.session_id());
                                    if in_tx.send(parsed).is_err() {
                                        break (
                                            "the orchestrator stopped reading",
                                            EndCause::OrchestratorGone,
                                        );
                                    }
                                }
                                // The wire type and the size, not the text: an unparsable
                                // `session_request` carries a TURN credential, a `pairing_code`
                                // the code. The parse error names the field that failed.
                                Err(e) => tracing::debug!(
                                    kind = %wire_type(t.as_str()),
                                    bytes = t.as_str().len(),
                                    "unparsed ws message: {e}"
                                ),
                            }
                        }
                        Some(Ok(Message::Ping(p))) => {
                            // A missed pong is the server's reason to drop us, so its failure is
                            // said here rather than discovered as a disconnect later. A failed write
                            // shows again on the next read; one that does not finish in time is the
                            // pump's end, as for any write.
                            let pong = async {
                                ws.send(Message::Pong(p))
                                    .await
                                    .map_err(|e| anyhow!("ws pong: {e}"))
                            };
                            match write_bounded(pong, limits.send, silence.deadline()).await {
                                Written::Failed(e) => tracing::debug!("ws pong not sent: {e:#}"),
                                written => {
                                    if let Some(end) =
                                        write_end(written, "ws_pong", None, limits.send)
                                    {
                                        break end;
                                    }
                                }
                            }
                        }
                        Some(Ok(Message::Close(frame))) => {
                            let code = frame.as_ref().map(|f| u16::from(f.code));
                            // not-a-key-name: a WebSocket close code
                            tracing::info!(
                                code,
                                reason = frame.as_ref().map_or("", |f| f.reason.as_str()),
                                "signaling connection closed"
                            );
                            break ("closed by the backend", EndCause::ClosedByBackend { code });
                        }
                        None => {
                            tracing::info!("signaling connection closed");
                            break ("stream ended", EndCause::StreamEnded);
                        }
                        Some(Ok(other)) => tracing::trace!(
                            bytes = other.len(),
                            "ignored ws frame (binary, pong or raw)"
                        ),
                        Some(Err(e)) => {
                            tracing::warn!("signaling ws error: {e}");
                            break ("ws error", EndCause::WsError);
                        }
                    }
                }
            }
        };
        let end = LinkEnd {
            cause,
            received_bytes: bytes_in,
            frames: frames_in,
            lived: pump_started.elapsed(),
        };
        // Before `incoming` ends (below): whoever sees it end finds how it ended.
        health.set_end(end);
        health.ended();
        let unsent = take_unsent(failed, &mut out_rx);
        tracing::info!(
            why,
            cause = cause.as_str(),
            sent,
            received,
            frames_in,
            bytes_in,
            lived_ms = end.lived.as_millis() as u64,
            unsent = unsent.len(),
            "signaling pump exited"
        );
        // Before `incoming` ends (below), so whoever sees it end finds the hand-back already there.
        if let Err(unsent) = unsent_tx.send(unsent) {
            if !unsent.is_empty() {
                tracing::debug!(
                    unsent = unsent.len(),
                    "nobody took back the unsent signaling messages: discarded"
                );
            }
        }
        drop(in_tx);
    });

    Ok(Signaling {
        outgoing: out_tx,
        incoming: in_rx,
        unsent: unsent_rx,
        goodbye: GoodbyeHandle { tx: goodbye_tx },
        initial_bindings,
        server_protocol,
        health,
        peer,
    })
}

/// The connected socket [`open`] hands back.
type Socket =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

/// Open the WebSocket for `request` (to `url`, for the log): the name, TCP, TLS and the upgrade, one
/// stage at a time, all within `limits.connect` from the start — so a failure says which stage it
/// was and what went wrong there ([`ConnectFailed`]), and the TCP peer is known (which way the name
/// led). The socket, the upgrade's status and the peer.
async fn open(
    url: &str,
    request: tokio_tungstenite::tungstenite::handshake::client::Request,
    limits: Limits,
) -> std::result::Result<(Socket, u16, Option<std::net::SocketAddr>), ConnectFailed> {
    let started = Instant::now();
    let deadline = tokio::time::Instant::now() + limits.connect;
    let limit_ms = limits.connect.as_millis();
    let fail = |stage: ConnectStage,
                failure: ConnectFailure,
                peer: Option<std::net::SocketAddr>,
                detail: String| {
        let failed = ConnectFailed {
            url: url.to_string(),
            stage,
            failure,
            elapsed: started.elapsed(),
            peer,
            detail,
        };
        // not-a-key-name: an HTTP status code
        tracing::debug!(
            url,
            stage = stage.as_str(),
            failure = failed.failure.as_str(),
            status = match failure {
                ConnectFailure::Status(code) => Some(code),
                _ => None,
            },
            peer = %peer.map_or_else(|| "-".to_string(), |p| p.to_string()),
            elapsed_ms = failed.elapsed.as_millis() as u64,
            detail = %failed.detail,
            "signaling: opening the connection failed"
        );
        failed
    };
    let (host, port) = match host_port(request.uri()) {
        Some(hp) => hp,
        None => {
            return Err(fail(
                ConnectStage::Dns,
                ConnectFailure::Other,
                None,
                "the address has no host".into(),
            ))
        }
    };

    let addrs: Vec<std::net::SocketAddr> =
        match tokio::time::timeout_at(deadline, tokio::net::lookup_host((host.as_str(), port)))
            .await
        {
            Err(_) => {
                return Err(fail(
                    ConnectStage::Dns,
                    ConnectFailure::Timeout,
                    None,
                    format!(
                        "no answer within {limit_ms} ms (the name lookup); giving up this attempt"
                    ),
                ))
            }
            Ok(Err(e)) => {
                return Err(fail(
                    ConnectStage::Dns,
                    ConnectFailure::NotResolved,
                    None,
                    format!("{host}: {e}"),
                ))
            }
            Ok(Ok(found)) => found.collect(),
        };
    if addrs.is_empty() {
        return Err(fail(
            ConnectStage::Dns,
            ConnectFailure::NotResolved,
            None,
            format!("{host}: no address"),
        ));
    }
    let dns_ms = started.elapsed().as_millis() as u64;

    let tcp =
        match tokio::time::timeout_at(deadline, tokio::net::TcpStream::connect(&addrs[..])).await {
            Err(_) => {
                return Err(fail(
                    ConnectStage::Tcp,
                    ConnectFailure::Timeout,
                    None,
                    format!(
                        "no answer within {limit_ms} ms (TCP to {}); giving up this attempt",
                        list(&addrs)
                    ),
                ))
            }
            Ok(Err(e)) => {
                return Err(fail(
                    ConnectStage::Tcp,
                    io_failure(&e),
                    None,
                    format!("TCP to {}: {e}", list(&addrs)),
                ))
            }
            Ok(Ok(tcp)) => tcp,
        };
    let peer = tcp.peer_addr().ok();
    tracing::debug!(
        url,
        %host,
        peer = %peer.map_or_else(|| "-".to_string(), |p| p.to_string()),
        addresses = %list(&addrs),
        dns_ms,
        tcp_ms = started.elapsed().as_millis() as u64,
        "signaling: TCP connected; TLS and the upgrade next"
    );

    match tokio::time::timeout_at(deadline, tokio_tungstenite::client_async_tls(request, tcp)).await
    {
        Err(_) => Err(fail(
            ConnectStage::Upgrade,
            ConnectFailure::Timeout,
            peer,
            format!(
                "no answer within {limit_ms} ms (TCP, TLS or the upgrade); giving up this attempt"
            ),
        )),
        Ok(Err(e)) => Err(fail(
            ConnectStage::Upgrade,
            ws_failure(&e),
            peer,
            e.to_string(),
        )),
        Ok(Ok((ws, response))) => Ok((ws, response.status().as_u16(), peer)),
    }
}

/// The host to look up (an IPv6 literal without its brackets) and the port, the scheme's when the
/// address names none.
fn host_port(uri: &tokio_tungstenite::tungstenite::http::Uri) -> Option<(String, u16)> {
    let host = uri.host().filter(|h| !h.is_empty())?;
    let host = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    let port = uri.port_u16().unwrap_or(match uri.scheme_str() {
        Some("wss") | Some("https") => 443,
        _ => 80,
    });
    Some((host.to_string(), port))
}

/// Addresses for a log line.
fn list(addrs: &[std::net::SocketAddr]) -> String {
    addrs
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

/// What a failed TCP connect, or an I/O error under TLS or the upgrade, amounts to.
fn io_failure(e: &std::io::Error) -> ConnectFailure {
    use std::io::ErrorKind;
    match e.kind() {
        ErrorKind::ConnectionRefused => ConnectFailure::Refused,
        ErrorKind::TimedOut => ConnectFailure::Timeout,
        ErrorKind::NetworkUnreachable
        | ErrorKind::HostUnreachable
        | ErrorKind::NetworkDown
        | ErrorKind::AddrNotAvailable => ConnectFailure::Unreachable,
        ErrorKind::ConnectionReset
        | ErrorKind::ConnectionAborted
        | ErrorKind::UnexpectedEof
        | ErrorKind::BrokenPipe => ConnectFailure::Reset,
        _ => ConnectFailure::Other,
    }
}

/// What a failed TLS handshake or upgrade amounts to.
fn ws_failure(e: &tokio_tungstenite::tungstenite::Error) -> ConnectFailure {
    use tokio_tungstenite::tungstenite::error::ProtocolError;
    use tokio_tungstenite::tungstenite::Error;
    match e {
        Error::Http(response) => ConnectFailure::Status(response.status().as_u16()),
        Error::Tls(_) => ConnectFailure::Tls,
        Error::Io(io) => io_failure(io),
        Error::ConnectionClosed
        | Error::AlreadyClosed
        | Error::Protocol(
            ProtocolError::HandshakeIncomplete | ProtocolError::ResetWithoutClosingHandshake,
        ) => ConnectFailure::Reset,
        _ => ConnectFailure::Other,
    }
}

/// Say the agent's goodbye on this connection and close it: whatever was already queued, then
/// `agent_goodbye`, then a close frame (1000, `goodbye`), written together and flushed — so the
/// goodbye goes out in as few packets as possible while the path still works — and then the backend's
/// close, which answers ours once it has read everything before it. Each step is reported to the
/// caller; the whole is bounded by the caller's budget and [`GOODBYE_LINGER`]. Returns why the pump
/// ends.
async fn say_goodbye<S>(
    ws: &mut S,
    out_rx: &mut mpsc::UnboundedReceiver<AgentToServer>,
    req: GoodbyeRequest,
    sent: &mut u64,
    failed: &mut Option<AgentToServer>,
) -> &'static str
where
    S: StreamExt<Item = Result<Message, tokio_tungstenite::tungstenite::Error>>
        + SinkExt<Message>
        + Unpin,
    <S as futures_util::Sink<Message>>::Error: std::fmt::Display,
{
    let GoodbyeRequest {
        reason,
        asked,
        deadline,
        linger,
        report,
    } = req;
    let reason_str = reason.as_str();
    let stop_at = tokio::time::Instant::from_std(deadline + linger);
    tracing::debug!(
        reason = reason_str,
        queued = out_rx.len(),
        waited_ms = asked.elapsed().as_millis() as u64,
        budget_ms = deadline.saturating_duration_since(asked).as_millis() as u64,
        "signaling: saying goodbye — what is queued, then agent_goodbye and a close frame"
    );
    let tell = |step: GoodbyeStep| {
        if let Err(e) = report.try_send(step) {
            // Disconnected: the caller stopped waiting (its budget ran out) — the step still
            // happened, and the lines here say so.
            tracing::trace!("signaling: a goodbye step not reported: {e}");
        }
    };
    match tokio::time::timeout_at(stop_at, write_goodbye(ws, out_rx, reason, sent, failed)).await {
        Ok(Ok(ahead)) => {
            tracing::debug!(
                reason = reason_str,
                ahead,
                took_ms = asked.elapsed().as_millis() as u64,
                "signaling: agent_goodbye and the close frame written and flushed"
            );
            tell(GoodbyeStep::Written);
        }
        Ok(Err(e)) => {
            tracing::warn!(
                reason = reason_str,
                took_ms = asked.elapsed().as_millis() as u64,
                "signaling: the goodbye could not be written: {e:#}"
            );
            tell(GoodbyeStep::Failed(format!("{e:#}")));
            return "the goodbye could not be written";
        }
        Err(_) => {
            tracing::warn!(
                reason = reason_str,
                took_ms = asked.elapsed().as_millis() as u64,
                "signaling: the goodbye was not written in time (a write stuck on a dying path): \
                 the connection is dropped"
            );
            return "the goodbye was not written in time";
        }
    }
    // The backend answers our close with its own once it has read everything before it, the
    // goodbye included. Anything else it says meanwhile is not handed on: this agent is leaving.
    let answered = tokio::time::timeout_at(stop_at, async {
        loop {
            match ws.next().await {
                Some(Ok(Message::Close(frame))) => {
                    return Some(frame.map(|f| u16::from(f.code)));
                }
                Some(Ok(Message::Text(t))) => {
                    let text = t.as_str();
                    let kind = wire_type(text);
                    if kind == "error" {
                        // `bad_message` here is a backend older than `agent_goodbye`: it keeps the
                        // socket, and our close ends it all the same.
                        let code = serde_json::from_str::<serde_json::Value>(text)
                            .ok()
                            .and_then(|v| {
                                v.get("code").and_then(|c| c.as_str()).map(str::to_string)
                            })
                            .unwrap_or_else(|| "?".to_string());
                        // not-a-key-name: the server's error code
                        tracing::debug!(
                            %code,
                            "signaling: the backend answered with an error after the goodbye \
                             (bad_message: a backend older than agent_goodbye); the close goes on"
                        );
                    } else {
                        tracing::debug!(
                            %kind,
                            "signaling: a message after the goodbye, not handed on (this agent is \
                             leaving)"
                        );
                    }
                }
                Some(Ok(other)) => tracing::trace!(
                    bytes = other.len(),
                    "signaling: a frame after the goodbye, ignored"
                ),
                Some(Err(e)) => {
                    tracing::debug!("signaling: the connection failed after the goodbye: {e}");
                    return None;
                }
                None => return None,
            }
        }
    })
    .await;
    let took_ms = asked.elapsed().as_millis() as u64;
    match answered {
        Ok(Some(code)) => {
            // not-a-key-name: a WebSocket close code
            tracing::debug!(
                reason = reason_str,
                code,
                took_ms,
                late = Instant::now() > deadline,
                "signaling: the backend answered the goodbye's close: it has read the goodbye"
            );
            tell(GoodbyeStep::Confirmed);
            "said goodbye"
        }
        Ok(None) => {
            tracing::debug!(
                reason = reason_str,
                took_ms,
                "signaling: the connection ended after the goodbye without the backend's close"
            );
            "said goodbye (no close from the backend)"
        }
        Err(_) => {
            tracing::debug!(
                reason = reason_str,
                took_ms,
                "signaling: no close from the backend in time after the goodbye; the connection \
                 is dropped"
            );
            "said goodbye (no close from the backend in time)"
        }
    }
}

/// [`say_goodbye`]'s writing: the queue as it stands, `agent_goodbye`, the close frame, one flush.
/// The number of queued messages written ahead of the goodbye. A queued message whose write fails
/// goes to `failed`, to be handed back with the rest.
async fn write_goodbye<S>(
    ws: &mut S,
    out_rx: &mut mpsc::UnboundedReceiver<AgentToServer>,
    reason: GoodbyeReason,
    sent: &mut u64,
    failed: &mut Option<AgentToServer>,
) -> Result<usize>
where
    S: SinkExt<Message> + Unpin,
    <S as futures_util::Sink<Message>>::Error: std::fmt::Display,
{
    let mut ahead = 0usize;
    while let Ok(msg) = out_rx.try_recv() {
        log_message("out", msg.kind(), msg.session_id());
        if let Err(e) = feed(ws, &msg).await {
            *failed = Some(msg);
            return Err(e);
        }
        *sent += 1;
        ahead += 1;
    }
    let goodbye = AgentToServer::AgentGoodbye { reason };
    log_message("out", goodbye.kind(), None);
    feed(ws, &goodbye).await?;
    *sent += 1;
    ws.feed(Message::Close(Some(CloseFrame {
        code: CloseCode::Normal,
        reason: GOODBYE_CLOSE_REASON.into(),
    })))
    .await
    .map_err(|e| anyhow!("ws close frame: {e}"))?;
    ws.flush().await.map_err(|e| anyhow!("ws flush: {e}"))?;
    Ok(ahead)
}

/// The WebSocket upgrade for `cfg`: its URL, and the `User-Agent` when there is one. A value that is
/// not a valid header (it never is: the build writes it) is left out with a warning rather than
/// costing the connection.
fn upgrade_request(
    cfg: &SignalingConfig,
) -> Result<tokio_tungstenite::tungstenite::handshake::client::Request> {
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    use tokio_tungstenite::tungstenite::http::{header::USER_AGENT, HeaderValue};
    let mut request = cfg
        .url
        .as_str()
        .into_client_request()
        .with_context(|| format!("ws url {}", cfg.url))?;
    match cfg.user_agent.as_deref().map(HeaderValue::from_str) {
        Some(Ok(value)) => {
            tracing::debug!(user_agent = ?value, "signaling upgrade: User-Agent set");
            request.headers_mut().insert(USER_AGENT, value);
        }
        Some(Err(e)) => tracing::warn!(
            user_agent = cfg.user_agent.as_deref().unwrap_or("-"),
            "signaling upgrade: the User-Agent is not a valid header ({e}); sent without one"
        ),
        None => tracing::debug!("signaling upgrade: no User-Agent given; sent without one"),
    }
    Ok(request)
}

/// Everything the pump was given and did not write, in order: the message whose write failed, then
/// what was still queued. The queue is closed first, so a sender that tries after this is refused
/// (and holds its message) rather than queueing it into a channel nobody will read.
fn take_unsent(
    failed: Option<AgentToServer>,
    out_rx: &mut mpsc::UnboundedReceiver<AgentToServer>,
) -> Vec<AgentToServer> {
    out_rx.close();
    let mut unsent: Vec<AgentToServer> = failed.into_iter().collect();
    while let Ok(msg) = out_rx.try_recv() {
        tracing::debug!(
            kind = msg.kind(),
            session = msg.session_id().unwrap_or("-"),
            "signaling message queued but never written: handed back"
        );
        unsent.push(msg);
    }
    unsent
}

/// One line per signaling message, in either direction: its wire type and session, never its
/// payload.
///
/// Debug for everything a session is made of — a few dozen per session, the candidates included —
/// and trace for the keep-alive (`ping` in, `pong` out, every 5 s whether or not anything else is
/// happening), which would otherwise be most of an idle agent's log.
///
/// `kind` is the last field on purpose. `ladder_replay` splits a log into sessions at the text
/// `session_request ` (with the space), which this line must not contain; last, it is followed by
/// the end of the line.
fn log_message(dir: &'static str, kind: &'static str, session: Option<&str>) {
    let session = session.unwrap_or("-");
    if matches!(kind, "ping" | "pong") {
        tracing::trace!(dir, session, kind, "signaling message");
    } else {
        tracing::debug!(dir, session, kind, "signaling message");
    }
}

/// The `type` field of a signaling message that did not parse, for the log line saying so.
fn wire_type(text: &str) -> String {
    serde_json::from_str::<serde_json::Value>(text)
        .ok()
        .and_then(|v| v.get("type").and_then(|t| t.as_str()).map(str::to_string))
        .unwrap_or_else(|| "?".to_string())
}

/// How one of the pump's writes ended ([`write_bounded`]).
#[derive(Debug)]
enum Written {
    Done,
    /// The write failed.
    Failed(anyhow::Error),
    /// Not done within the send limit ([`SEND_TIMEOUT`]); pending this long.
    TimedOut {
        waited: Duration,
    },
    /// The silence limit ran out first while it was pending; pending this long.
    Silent {
        waited: Duration,
    },
}

/// `write`, bounded by `send_limit` from now and by the silence limit's deadline `silence_at`,
/// whichever comes first, so a write stuck on a path that stopped draining cannot hold the pump —
/// and with it the silence timer and the backend's frames — for as long as the operating system
/// keeps the socket.
async fn write_bounded<F>(
    write: F,
    send_limit: Duration,
    silence_at: tokio::time::Instant,
) -> Written
where
    F: std::future::Future<Output = Result<()>>,
{
    let started = tokio::time::Instant::now();
    let send_at = started + send_limit;
    let silence_first = silence_at < send_at;
    let at = if silence_first { silence_at } else { send_at };
    match tokio::time::timeout_at(at, write).await {
        Ok(Ok(())) => Written::Done,
        Ok(Err(e)) => Written::Failed(e),
        Err(_) if silence_first => Written::Silent {
            waited: started.elapsed(),
        },
        Err(_) => Written::TimedOut {
            waited: started.elapsed(),
        },
    }
}

/// The pump's end after a write that did not go through, said in the log; `None` when it did.
/// `kind` and `session`: what was written.
fn write_end(
    written: Written,
    kind: &'static str,
    session: Option<&str>,
    send_limit: Duration,
) -> Option<(&'static str, EndCause)> {
    let session = session.unwrap_or("-");
    match written {
        Written::Done => None,
        Written::Failed(e) => {
            tracing::warn!(kind, session, "signaling send failed: {e:#}");
            Some(("send failed", EndCause::SendFailed))
        }
        Written::TimedOut { waited } => {
            tracing::warn!(
                kind,
                session,
                waited_ms = duration_ms(waited),
                send_limit_ms = duration_ms(send_limit),
                "signaling: a write did not finish within the send limit (the path takes nothing \
                 more from this agent): the connection is given up and a reconnect follows"
            );
            Some(("send timed out", EndCause::SendTimeout))
        }
        Written::Silent { waited } => {
            tracing::info!(
                kind,
                session,
                waited_ms = duration_ms(waited),
                "the backend has said nothing for the silence limit while a write was pending: the \
                 connection is taken as dead"
            );
            Some(("the backend went silent", EndCause::Silence))
        }
    }
}

async fn send<S>(ws: &mut S, msg: &AgentToServer) -> Result<()>
where
    S: SinkExt<Message> + Unpin,
    <S as futures_util::Sink<Message>>::Error: std::fmt::Display,
{
    let json = serde_json::to_string(msg)?;
    ws.send(Message::text(json))
        .await
        .map_err(|e| anyhow!("ws send: {e}"))?;
    Ok(())
}

/// [`send`] within `limit`: a handshake write that does not finish is the attempt's failure (the
/// reconnect's backoff takes over), not a wait for as long as the operating system keeps the socket.
async fn send_within<S>(ws: &mut S, msg: &AgentToServer, limit: Duration) -> Result<()>
where
    S: SinkExt<Message> + Unpin,
    <S as futures_util::Sink<Message>>::Error: std::fmt::Display,
{
    match tokio::time::timeout(limit, send(ws, msg)).await {
        Ok(written) => written,
        Err(_) => {
            tracing::debug!(
                kind = msg.kind(),
                limit_ms = duration_ms(limit),
                "signaling: a handshake write did not finish within the limit; the attempt is \
                 given up"
            );
            bail!(
                "{} not written within {} ms: the path takes nothing from this agent",
                msg.kind(),
                limit.as_millis()
            )
        }
    }
}

/// Closes a handshake the agent refuses (1008, with `reason` for the backend's log), within
/// `limit`. Best effort: the attempt fails either way, so a close that does not get through is
/// logged and the socket dropped.
async fn close_refusing<S>(ws: &mut S, reason: &'static str, limit: Duration)
where
    S: SinkExt<Message> + Unpin,
    <S as futures_util::Sink<Message>>::Error: std::fmt::Display,
{
    let frame = Message::Close(Some(CloseFrame {
        code: CloseCode::Policy,
        reason: reason.into(),
    }));
    match tokio::time::timeout(limit, ws.send(frame)).await {
        Ok(Ok(())) => tracing::debug!(reason, "signaling: refused the handshake with a close"),
        Ok(Err(e)) => tracing::debug!(
            reason,
            error = %e,
            "signaling: the refusing close was not written; the socket is dropped"
        ),
        Err(_) => tracing::debug!(
            reason,
            limit_ms = duration_ms(limit),
            "signaling: the refusing close did not finish within the limit; the socket is dropped"
        ),
    }
}

/// [`send`] without the flush: the frame waits in the socket's buffer for the next flush.
async fn feed<S>(ws: &mut S, msg: &AgentToServer) -> Result<()>
where
    S: SinkExt<Message> + Unpin,
    <S as futures_util::Sink<Message>>::Error: std::fmt::Display,
{
    let json = serde_json::to_string(msg)?;
    ws.feed(Message::text(json))
        .await
        .map_err(|e| anyhow!("ws feed: {e}"))?;
    Ok(())
}

/// The next handshake message, with the backend's keep-alive answered on the way.
///
/// The backend pings every open socket every few seconds, authenticated or not
/// (`server/src/index.ts`, the heartbeat sweep), and closes one that has gone quiet. So a
/// `ping` can land between `agent_hello` and `challenge`, or between `agent_auth` and
/// `agent_ready`; taken for the answer, it would end the handshake (`signaling connect: expected
/// agent_ready, got ping`) and cost a reconnect. The ping is answered here exactly as the pump answers it once the
/// handshake is done — a `pong`, which is also what keeps the sweep from closing the socket — and
/// the wait for `expected` goes on: for as long as the backend keeps saying something, since its
/// own authentication deadline (thirty seconds) closes a socket that never gets further. A backend
/// that says nothing at all for `silence` ([`HANDSHAKE_SILENCE_LIMIT`]) ends it with
/// [`HandshakeSilent`]: on a path that froze what the server sends, that close never arrives.
/// `heard` counts every frame, for that line.
async fn recv_handshake<S>(
    ws: &mut S,
    expected: &'static str,
    silence: Duration,
    heard: &mut u32,
) -> Result<Option<ServerToAgent>>
where
    S: StreamExt<Item = Result<Message, tokio_tungstenite::tungstenite::Error>>
        + SinkExt<Message>
        + Unpin,
    <S as futures_util::Sink<Message>>::Error: std::fmt::Display,
{
    loop {
        match recv(ws, expected, silence, heard).await? {
            Some(ServerToAgent::Ping) => {
                tracing::debug!(
                    expected,
                    "server ping during the handshake: answered, still waiting"
                );
                // Bounded by the handshake's silence limit: a pong that cannot be written is a
                // path that takes nothing, as one that says nothing is.
                send_within(ws, &AgentToServer::Pong, silence)
                    .await
                    .with_context(|| format!("pong while waiting for {expected}"))?;
            }
            other => return Ok(other),
        }
    }
}

/// The next message of the handshake; `None` when the backend closed. Nothing at all — not a frame
/// of any kind — for `silence`: [`HandshakeSilent`].
async fn recv<S>(
    ws: &mut S,
    expected: &'static str,
    silence: Duration,
    heard: &mut u32,
) -> Result<Option<ServerToAgent>>
where
    S: StreamExt<Item = Result<Message, tokio_tungstenite::tungstenite::Error>> + Unpin,
{
    loop {
        let frame = match tokio::time::timeout(silence, ws.next()).await {
            Ok(Some(frame)) => frame,
            Ok(None) => return Ok(None),
            Err(_) => {
                tracing::debug!(
                    awaiting = expected,
                    silent_ms = silence.as_millis() as u64,
                    frames = *heard,
                    "signaling: nothing from the backend during the handshake for the limit: the \
                     connection opened but delivers nothing"
                );
                return Err(HandshakeSilent {
                    awaiting: expected,
                    silent_for: silence,
                    frames: *heard,
                }
                .into());
            }
        };
        *heard = heard.saturating_add(1);
        match frame? {
            Message::Text(t) => {
                return Ok(Some(
                    serde_json::from_str::<ServerToAgent>(t.as_str())
                        .with_context(|| format!("parse ws message: {}", t.as_str()))?,
                ));
            }
            Message::Ping(_) | Message::Pong(_) => continue,
            Message::Close(_) => return Ok(None),
            _ => continue,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A backend whose heartbeat fires in the middle of the handshake — once before `challenge`,
    /// once before `agent_ready` — as the real one's twenty-second sweep can. The agent must answer both and finish the handshake, not give up on the first.
    #[tokio::test]
    async fn a_ping_during_the_handshake_is_answered_and_the_handshake_completes() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let backend = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.expect("accept");
            let mut ws = tokio_tungstenite::accept_async(tcp)
                .await
                .expect("ws accept");
            let mut seen = Vec::new();
            let next = |ws_msg: Option<Result<Message, _>>| -> String {
                match ws_msg {
                    Some(Ok(Message::Text(t))) => {
                        let v: serde_json::Value =
                            serde_json::from_str(t.as_str()).expect("json from the agent");
                        v["type"].as_str().unwrap_or("?").to_string()
                    }
                    other => panic!("expected a text frame, got {other:?}"),
                }
            };
            seen.push(next(ws.next().await));
            ws.send(Message::text(r#"{"type":"ping"}"#))
                .await
                .expect("ping");
            let nonce = BASE64_STANDARD.encode([7u8; 32]);
            ws.send(Message::text(format!(
                r#"{{"type":"challenge","nonce":"{nonce}"}}"#
            )))
            .await
            .expect("challenge");
            seen.push(next(ws.next().await));
            seen.push(next(ws.next().await));
            ws.send(Message::text(r#"{"type":"ping"}"#))
                .await
                .expect("ping");
            ws.send(Message::text(format!(
                r#"{{"type":"agent_ready","protocol_version":{PROTOCOL_VERSION},"min_supported_protocol":{PROTOCOL_VERSION},"bindings":[]}}"#
            )))
            .await
            .expect("agent_ready");
            seen.push(next(ws.next().await));
            seen
        });

        let signaling = connect(test_config(addr), Arc::new(|_: &[u8]| vec![0u8; 64]))
            .await
            .expect("a ping mid-handshake must not fail the handshake");
        assert!(signaling.initial_bindings.is_empty());
        assert_eq!(
            signaling.server_protocol,
            (PROTOCOL_VERSION, PROTOCOL_VERSION)
        );
        let seen = backend.await.expect("backend task");
        assert_eq!(seen, ["agent_hello", "pong", "agent_auth", "pong"]);
    }

    /// An `error` frame in place of a handshake step comes back as [`HandshakeRefused`] in the
    /// error chain, with the code, the detail and the step — whatever the code — so the reconnect
    /// loop can decide by severity. Once in place of `challenge`, once in place of `agent_ready`.
    #[tokio::test]
    async fn an_error_frame_in_the_handshake_comes_back_typed_with_its_code() {
        for (answer_after_auth, code, message, awaiting) in [
            (
                false,
                "protocol_unsupported",
                Some("server speaks 2..3"),
                "challenge",
            ),
            (true, "bad_signature", None, "agent_ready"),
        ] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind");
            let addr = listener.local_addr().expect("addr");
            let frame = match message {
                Some(m) => format!(r#"{{"type":"error","code":"{code}","message":"{m}"}}"#),
                None => format!(r#"{{"type":"error","code":"{code}"}}"#),
            };
            let backend = tokio::spawn(async move {
                let (tcp, _) = listener.accept().await.expect("accept");
                let mut ws = tokio_tungstenite::accept_async(tcp)
                    .await
                    .expect("ws accept");
                let _hello = ws.next().await;
                if answer_after_auth {
                    let nonce = BASE64_STANDARD.encode([7u8; 32]);
                    ws.send(Message::text(format!(
                        r#"{{"type":"challenge","nonce":"{nonce}"}}"#
                    )))
                    .await
                    .expect("challenge");
                    let _auth = ws.next().await;
                }
                ws.send(Message::text(frame)).await.expect("error frame");
                let _ = ws.close(None).await;
                // Until the agent's side has gone too: a socket dropped with unread data is reset,
                // and a reset can discard the error frame before the agent reads it.
                while let Some(Ok(_)) = ws.next().await {}
            });

            let err = match connect(test_config(addr), Arc::new(|_: &[u8]| vec![0u8; 64])).await {
                Ok(_) => panic!("{code}: a refused handshake must fail"),
                Err(e) => e,
            };
            let refusal = err
                .chain()
                .find_map(|c| c.downcast_ref::<HandshakeRefused>())
                .unwrap_or_else(|| panic!("{code}: not typed: {err:#}"));
            assert_eq!(
                refusal,
                &HandshakeRefused {
                    code: code.into(),
                    message: message.map(str::to_string),
                    awaiting,
                }
            );
            backend.await.expect("backend task");
        }
    }

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
            .collect()
    }

    /// The contract's challenge vector.
    fn challenge_vector() -> serde_json::Value {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../contract/packages/protocol/vectors/agent-challenge-signature.json");
        let raw = std::fs::read_to_string(&path).expect("the contract's challenge vector");
        serde_json::from_str(&raw).expect("json")
    }

    /// For every case of the contract's vector: the handshake hands the signer exactly the case's
    /// message — the domain prefix and the nonce — and sends back exactly what the signer returned.
    /// (That the device key's signature over that message is the case's `signature` is
    /// `afklink_core::identity`'s test.)
    #[tokio::test]
    async fn the_handshake_signs_the_prefixed_nonce_and_sends_the_signature() {
        let vector = challenge_vector();
        for case in vector["cases"].as_array().expect("cases") {
            let nonce_b64 = case["nonce_base64"]
                .as_str()
                .expect("nonce_base64")
                .to_owned();
            let message = hex(case["message_hex"].as_str().expect("message_hex"));
            assert_eq!(
                BASE64_STANDARD.decode(&nonce_b64).expect("base64"),
                hex(case["nonce_hex"].as_str().expect("nonce_hex")),
                "the case's nonce_base64 carries its nonce"
            );

            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind");
            let addr = listener.local_addr().expect("addr");
            let backend = tokio::spawn(async move {
                let (tcp, _) = listener.accept().await.expect("accept");
                let mut ws = tokio_tungstenite::accept_async(tcp)
                    .await
                    .expect("ws accept");
                let _hello = ws.next().await;
                ws.send(Message::text(format!(
                    r#"{{"type":"challenge","nonce":"{nonce_b64}"}}"#
                )))
                .await
                .expect("challenge");
                let auth = match ws.next().await {
                    Some(Ok(Message::Text(t))) => {
                        serde_json::from_str::<serde_json::Value>(t.as_str()).expect("json")
                    }
                    other => panic!("expected agent_auth, got {other:?}"),
                };
                ws.send(Message::text(format!(
                    r#"{{"type":"agent_ready","protocol_version":{PROTOCOL_VERSION},"min_supported_protocol":{PROTOCOL_VERSION},"bindings":[]}}"#
                )))
                .await
                .expect("agent_ready");
                auth
            });

            let signed = Arc::new(std::sync::Mutex::new(Vec::<Vec<u8>>::new()));
            let seen = signed.clone();
            let signer: Signer = Arc::new(move |bytes: &[u8]| {
                seen.lock().expect("lock").push(bytes.to_vec());
                // Not a signature: a value the test can recognise on the wire.
                bytes.iter().rev().copied().collect()
            });
            let _signaling = connect(test_config(addr), signer)
                .await
                .expect("the handshake completes");
            let auth = backend.await.expect("backend task");

            let signed = signed.lock().expect("lock").clone();
            assert_eq!(signed, vec![message.clone()], "signed exactly the message");
            assert_eq!(auth["type"], "agent_auth");
            let reversed: Vec<u8> = message.iter().rev().copied().collect();
            assert_eq!(
                auth["signature"].as_str().expect("signature"),
                BASE64_STANDARD.encode(reversed),
                "agent_auth carries what the signer returned"
            );
        }
    }

    /// A nonce that is not exactly 32 bytes is signed with nothing: the signer is never called, no
    /// `agent_auth` goes out, the agent closes the socket (1008) and the attempt fails with an
    /// error that says why.
    #[tokio::test]
    async fn a_nonce_of_another_length_is_refused_unsigned() {
        for len in [0usize, 16, 31, 33, 64] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind");
            let addr = listener.local_addr().expect("addr");
            let backend = tokio::spawn(async move {
                let (tcp, _) = listener.accept().await.expect("accept");
                let mut ws = tokio_tungstenite::accept_async(tcp)
                    .await
                    .expect("ws accept");
                let _hello = ws.next().await;
                let nonce = BASE64_STANDARD.encode(vec![7u8; len]);
                ws.send(Message::text(format!(
                    r#"{{"type":"challenge","nonce":"{nonce}"}}"#
                )))
                .await
                .expect("challenge");
                let mut frames = Vec::new();
                while let Some(Ok(frame)) = ws.next().await {
                    frames.push(frame);
                }
                frames
            });

            let calls = Arc::new(AtomicU64::new(0));
            let counted = calls.clone();
            let signer: Signer = Arc::new(move |_: &[u8]| {
                counted.fetch_add(1, Ordering::SeqCst);
                vec![0u8; 64]
            });
            let err = match connect(test_config(addr), signer).await {
                Ok(_) => panic!("{len} bytes: the handshake must fail"),
                Err(e) => e,
            };
            assert!(
                format!("{err:#}").contains(&format!("nonce is {len} bytes, not 32")),
                "{len} bytes: {err:#}"
            );
            assert_eq!(
                calls.load(Ordering::SeqCst),
                0,
                "{len} bytes: nothing signed"
            );
            let frames = backend.await.expect("backend task");
            assert!(
                !frames.iter().any(|f| matches!(f, Message::Text(_))),
                "{len} bytes: no agent_auth: {frames:?}"
            );
            assert!(
                frames.iter().any(|f| matches!(
                    f,
                    Message::Close(Some(CloseFrame {
                        code: CloseCode::Policy,
                        ..
                    }))
                )),
                "{len} bytes: closed with 1008: {frames:?}"
            );
        }
    }

    fn ice(n: u32) -> AgentToServer {
        AgentToServer::Ice {
            session_id: "s1".into(),
            candidate: afklink_protocol::IceCandidate {
                candidate: format!("candidate:{n} 1 udp 1 10.0.0.1 9 typ host"),
                sdp_mid: None,
                sdp_mline_index: None,
                username_fragment: None,
            },
        }
    }

    /// The hand-back is the failed write first, then the queue in order; and once it is taken the
    /// queue refuses new messages, so none can be queued into a channel nobody reads.
    #[test]
    fn the_hand_back_is_the_failed_write_then_the_queue_in_order() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        tx.send(ice(2)).expect("open");
        tx.send(ice(3)).expect("open");
        let unsent = take_unsent(Some(ice(1)), &mut rx);
        assert_eq!(unsent, vec![ice(1), ice(2), ice(3)]);
        assert!(
            tx.send(ice(4)).is_err(),
            "after the hand-back the queue refuses, so the sender holds the message itself"
        );
        assert!(take_unsent(None, &mut rx).is_empty());
    }

    /// A backend that completes the handshake (without checking the signature) and returns the
    /// socket, for tests of what happens after it.
    async fn handshake(
        listener: &tokio::net::TcpListener,
    ) -> tokio_tungstenite::WebSocketStream<tokio::net::TcpStream> {
        let (tcp, _) = listener.accept().await.expect("accept");
        let mut ws = tokio_tungstenite::accept_async(tcp)
            .await
            .expect("ws accept");
        let _hello = ws.next().await;
        let nonce = BASE64_STANDARD.encode([7u8; 32]);
        ws.send(Message::text(format!(
            r#"{{"type":"challenge","nonce":"{nonce}"}}"#
        )))
        .await
        .expect("challenge");
        let _auth = ws.next().await;
        ws.send(Message::text(format!(
            r#"{{"type":"agent_ready","protocol_version":{PROTOCOL_VERSION},"min_supported_protocol":{PROTOCOL_VERSION},"bindings":[]}}"#
        )))
        .await
        .expect("agent_ready");
        ws
    }

    fn test_config(addr: std::net::SocketAddr) -> SignalingConfig {
        SignalingConfig {
            url: format!("ws://{addr}/ws/agent"),
            device_id: "test-device".into(),
            pubkey_b64: BASE64_STANDARD.encode([1u8; 32]),
            user_agent: None,
            hello: HelloInfo::default(),
        }
    }

    /// The hello carries contract v2's fields when given — the build, the boot id, the last exit —
    /// and the beta's fingerprint, and is exactly the old hello without them.
    #[tokio::test]
    async fn the_hello_carries_the_build_the_boot_and_the_last_exit_when_given() {
        use afklink_protocol::start_failure::BuildChannel;
        use afklink_protocol::{AgentBuildInfo, AgentExitKind, AgentHw, AgentLastExit};

        let full = HelloInfo {
            hw: Some(AgentHw {
                hash: "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8".into(),
                vm: true,
                parts: 3,
            }),
            build: Some(AgentBuildInfo {
                version: "0.5.1".into(),
                commit: Some("1d38642".into()),
                channel: BuildChannel::Dev,
                dirty: Some(false),
            }),
            boot_id: Some("6b1e0c2a-9f3d-4e57-8a21-c4d5e6f70812".into()),
            last_exit: Some(AgentLastExit {
                kind: AgentExitKind::Crash,
                at: Some(1_789_599_960_000),
            }),
        };
        for hello in [full, HelloInfo::default()] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind");
            let addr = listener.local_addr().expect("addr");
            let backend = tokio::spawn(async move {
                let (tcp, _) = listener.accept().await.expect("accept");
                let mut ws = tokio_tungstenite::accept_async(tcp)
                    .await
                    .expect("ws accept");
                let first = ws.next().await.expect("a frame").expect("readable");
                drop(ws);
                first.into_text().expect("text").to_string()
            });
            let config = SignalingConfig {
                hello: hello.clone(),
                ..test_config(addr)
            };
            // The handshake fails (the backend closes after the hello); the hello is what is
            // looked at.
            let _ = connect(config, Arc::new(|_: &[u8]| vec![0u8; 64])).await;
            let text = backend.await.expect("backend task");
            let v: serde_json::Value = serde_json::from_str(&text).expect("json");
            assert_eq!(v["type"], "agent_hello");
            match &hello.build {
                Some(_) => {
                    assert_eq!(
                        v["build"],
                        serde_json::json!({
                            "version": "0.5.1", "commit": "1d38642", "channel": "dev",
                            "dirty": false
                        })
                    );
                    assert_eq!(v["boot_id"], "6b1e0c2a-9f3d-4e57-8a21-c4d5e6f70812");
                    assert_eq!(
                        v["last_exit"],
                        serde_json::json!({ "kind": "crash", "at": 1_789_599_960_000u64 })
                    );
                    assert_eq!(
                        v["hw"],
                        serde_json::json!({
                            "hash": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
                            "vm": true,
                            "parts": 3
                        })
                    );
                }
                None => {
                    for key in ["build", "boot_id", "last_exit", "hw"] {
                        assert!(v.get(key).is_none(), "{key} absent: {text}");
                    }
                }
            }
        }
    }

    /// The upgrade names the build (`AFKLink/<version> (<channel>)`): the backend keeps it per
    /// device. Without one given, none is sent — what every older build looks like.
    #[tokio::test]
    #[allow(clippy::result_large_err, reason = "tungstenite's own callback type")]
    async fn the_upgrade_carries_the_user_agent_when_given() {
        for given in [Some("AFKLink/0.4.0 (release)"), None] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind");
            let addr = listener.local_addr().expect("addr");
            let backend = tokio::spawn(async move {
                let (tcp, _) = listener.accept().await.expect("accept");
                let mut seen: Option<String> = None;
                let ws = tokio_tungstenite::accept_hdr_async(
                    tcp,
                    |request: &tokio_tungstenite::tungstenite::handshake::server::Request,
                     response| {
                        seen = request
                            .headers()
                            .get("user-agent")
                            .and_then(|v| v.to_str().ok())
                            .map(str::to_string);
                        Ok(response)
                    },
                )
                .await
                .expect("ws accept");
                drop(ws);
                seen
            });
            let config = SignalingConfig {
                user_agent: given.map(str::to_string),
                ..test_config(addr)
            };
            // The handshake fails (the backend closes at once); the upgrade is what is looked at.
            let _ = connect(config, Arc::new(|_: &[u8]| vec![0u8; 64])).await;
            let seen = backend.await.expect("backend task");
            match given {
                Some(ua) => assert_eq!(seen.as_deref(), Some(ua)),
                // tungstenite adds none of its own.
                None => assert_eq!(seen, None),
            }
        }
    }

    /// When the backend closes the connection, `incoming` ends — and by then the hand-back is
    /// already there, so the relay that retires the link on seeing the end does not wait for it.
    #[tokio::test]
    async fn the_hand_back_is_ready_by_the_time_incoming_ends() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let backend = tokio::spawn(async move {
            let mut ws = handshake(&listener).await;
            ws.close(None).await.expect("close");
            // Drain until the agent's side has gone too.
            while let Some(Ok(_)) = ws.next().await {}
        });

        let mut signaling = connect(test_config(addr), Arc::new(|_: &[u8]| vec![0u8; 64]))
            .await
            .expect("handshake");
        let end = tokio::time::timeout(Duration::from_secs(5), signaling.incoming.recv())
            .await
            .expect("incoming ends once the backend closes");
        assert!(end.is_none(), "nothing but the end: got {end:?}");
        match signaling.unsent.try_recv() {
            Ok(unsent) => assert!(unsent.is_empty(), "nothing was queued: {unsent:?}"),
            Err(e) => panic!("the hand-back must be there before incoming ends: {e:?}"),
        }
        // How it ended is there by then too: the backend's close, one frame (the close itself).
        let how = signaling
            .health
            .end()
            .expect("the end is known once incoming ends");
        assert!(
            matches!(how.cause, EndCause::ClosedByBackend { .. }),
            "{how:?}"
        );
        assert_eq!(how.frames, 1, "{how:?}");
        assert_eq!(
            signaling.peer.map(|p| p.port()),
            Some(addr.port()),
            "the peer TCP connected to is known"
        );
        assert!(
            signaling.outgoing.send(AgentToServer::Pong).is_err(),
            "the dead connection refuses, so the relay holds instead of losing"
        );
        backend.await.expect("backend task");
    }

    /// A backend that stops talking — no heartbeat ping, nothing — while the TCP connection stays
    /// open is a half-open connection as far as the agent can tell, and the pump gives up on it
    /// instead of waiting for a write to fail.
    #[tokio::test]
    async fn a_backend_that_goes_silent_is_taken_as_gone() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let (hold_tx, hold_rx) = oneshot::channel::<()>();
        let backend = tokio::spawn(async move {
            let ws = handshake(&listener).await;
            // Keep the socket open and say nothing until the test is done.
            let _ = hold_rx.await;
            drop(ws);
        });

        let started = std::time::Instant::now();
        let mut signaling = connect_with(
            test_config(addr),
            Arc::new(|_: &[u8]| vec![0u8; 64]),
            Limits {
                // Never in force: no ping ever comes, so the long limit holds.
                silence: Duration::from_millis(50),
                legacy_silence: Duration::from_millis(300),
                ..fast_limits()
            },
        )
        .await
        .expect("handshake");
        let health = signaling.health.clone();
        assert!(health.is_up());
        assert_eq!(health.silence_limit(), Duration::from_millis(300));
        let heard_at_handshake = health.last_heard();
        let end = tokio::time::timeout(Duration::from_secs(5), signaling.incoming.recv())
            .await
            .expect("the pump gives up on a silent backend");
        assert!(end.is_none());
        assert!(
            started.elapsed() >= Duration::from_millis(300),
            "not before the long limit, the only one known without pings: {:?}",
            started.elapsed()
        );
        // What the event queue reads: the pump is gone, and nothing was heard after the handshake.
        assert!(!health.is_up());
        assert_eq!(health.last_heard(), heard_at_handshake);
        assert_eq!(health.silence_limit(), Duration::from_millis(300));
        // And what the choice of way reads: silence, with not a frame after the handshake.
        let how = health.end().expect("the end is known");
        assert_eq!(how.cause, EndCause::Silence);
        assert_eq!((how.frames, how.received_bytes), (0, 0));
        assert!(how.lived >= Duration::from_millis(300), "{how:?}");
        let _ = hold_tx.send(());
        backend.await.expect("backend task");
    }

    /// Test limits: a short limit of 400 ms once pings come at most 150 ms apart, a long one of
    /// 3 s until then; pings under 10 ms apart are a backlog.
    fn fast_limits() -> Limits {
        Limits {
            connect: CONNECT_TIMEOUT,
            handshake_silence: HANDSHAKE_SILENCE_LIMIT,
            silence: Duration::from_millis(400),
            legacy_silence: Duration::from_secs(3),
            fast_cadence: Duration::from_millis(150),
            min_ping_gap: Duration::from_millis(10),
            send: SEND_TIMEOUT,
        }
    }

    /// The pump's writes are bounded: one pending past the send limit is the write's end
    /// (`TimedOut`), one pending past the silence limit's deadline — when that comes first — the
    /// silence's (`Silent`); one that finishes or fails says so.
    #[tokio::test]
    async fn a_write_is_bounded_by_the_send_limit_or_the_silence_whichever_comes_first() {
        let ms = Duration::from_millis;
        let stuck = || std::future::pending::<Result<()>>();
        let now = tokio::time::Instant::now();
        match write_bounded(stuck(), ms(200), now + ms(5_000)).await {
            Written::TimedOut { waited } => {
                assert!(waited >= ms(200) && waited < ms(2_000), "{waited:?}")
            }
            other => panic!("expected the send limit: {other:?}"),
        }
        let now = tokio::time::Instant::now();
        match write_bounded(stuck(), ms(5_000), now + ms(150)).await {
            Written::Silent { waited } => {
                assert!(waited >= ms(100) && waited < ms(2_000), "{waited:?}")
            }
            other => panic!("expected the silence: {other:?}"),
        }
        let now = tokio::time::Instant::now();
        assert!(matches!(
            write_bounded(async { Ok(()) }, Duration::from_secs(10), now).await,
            Written::Done
        ));
        assert!(matches!(
            write_bounded(
                async { Err(anyhow!("reset")) },
                Duration::from_secs(10),
                now + Duration::from_secs(1)
            )
            .await,
            Written::Failed(_)
        ));
        // The causes the pump ends with.
        let end = |w| write_end(w, "pong", None, Duration::from_secs(10)).map(|(_, c)| c);
        assert_eq!(end(Written::Done), None);
        assert_eq!(
            end(Written::TimedOut {
                waited: Duration::from_secs(10)
            }),
            Some(EndCause::SendTimeout)
        );
        assert_eq!(
            end(Written::Silent {
                waited: Duration::from_secs(3)
            }),
            Some(EndCause::Silence)
        );
        assert_eq!(
            end(Written::Failed(anyhow!("reset"))),
            Some(EndCause::SendFailed)
        );
        // A handshake write into a sink that never takes it fails at its limit.
        struct Stuck;
        impl futures_util::Sink<Message> for Stuck {
            type Error = String;
            fn poll_ready(
                self: std::pin::Pin<&mut Self>,
                _: &mut std::task::Context<'_>,
            ) -> std::task::Poll<Result<(), String>> {
                std::task::Poll::Pending
            }
            fn start_send(self: std::pin::Pin<&mut Self>, _: Message) -> Result<(), String> {
                Ok(())
            }
            fn poll_flush(
                self: std::pin::Pin<&mut Self>,
                _: &mut std::task::Context<'_>,
            ) -> std::task::Poll<Result<(), String>> {
                std::task::Poll::Pending
            }
            fn poll_close(
                self: std::pin::Pin<&mut Self>,
                _: &mut std::task::Context<'_>,
            ) -> std::task::Poll<Result<(), String>> {
                std::task::Poll::Pending
            }
        }
        let started = std::time::Instant::now();
        let err = send_within(&mut Stuck, &AgentToServer::Pong, ms(150))
            .await
            .expect_err("a write that never finishes fails at its limit");
        assert!(err.to_string().contains("pong not written"), "{err:#}");
        assert!(started.elapsed() < ms(2_000));
        assert_eq!(EndCause::SendTimeout.as_str(), "send_timeout");
        assert_eq!(LIMITS.send, SEND_TIMEOUT);
        assert!(SEND_TIMEOUT < BACKEND_SILENCE_LIMIT);
    }

    /// A backend that stops reading the socket: what this agent sends piles up in the socket's
    /// buffers until a write cannot finish, and the pump gives the connection up at the send
    /// limit — handing back what it did not write — instead of sitting in the write for good.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_backend_that_stops_reading_is_given_up_at_the_send_limit() {
        // A small receive buffer on the backend's side, so the agent's writes stop sooner.
        let socket = tokio::net::TcpSocket::new_v4().expect("socket");
        socket.set_recv_buffer_size(8 * 1024).expect("recv buffer");
        socket
            .bind("127.0.0.1:0".parse().expect("addr"))
            .expect("bind");
        let listener = socket.listen(1).expect("listen");
        let addr = listener.local_addr().expect("addr");
        let (hold_tx, hold_rx) = oneshot::channel::<()>();
        let backend = tokio::spawn(async move {
            let ws = handshake(&listener).await;
            // Never read again; keep the socket open until the test is done.
            let _ = hold_rx.await;
            drop(ws);
        });
        let mut signaling = connect_with(
            test_config(addr),
            Arc::new(|_: &[u8]| vec![0u8; 64]),
            Limits {
                send: Duration::from_millis(500),
                // The silence limits far away: the write's own limit is what ends it.
                silence: Duration::from_secs(60),
                legacy_silence: Duration::from_secs(60),
                ..fast_limits()
            },
        )
        .await
        .expect("handshake");
        let health = signaling.health.clone();
        // A megabyte a message: the socket's buffers fill within a few.
        let big = |n: u32| AgentToServer::Ice {
            session_id: "s1".into(),
            candidate: afklink_protocol::IceCandidate {
                candidate: format!("candidate:{n} {}", "x".repeat(1 << 20)),
                sdp_mid: None,
                sdp_mline_index: None,
                username_fragment: None,
            },
        };
        let started = std::time::Instant::now();
        for n in 0..48 {
            if signaling.outgoing.send(big(n)).is_err() {
                break;
            }
        }
        let end = tokio::time::timeout(Duration::from_secs(20), signaling.incoming.recv())
            .await
            .expect("the pump gives up on a write that cannot finish");
        assert!(end.is_none());
        let how = health.end().expect("the end is known");
        assert_eq!(how.cause, EndCause::SendTimeout, "{how:?}");
        assert!(
            started.elapsed() < Duration::from_secs(15),
            "{:?}",
            started.elapsed()
        );
        let _ = hold_tx.send(());
        backend.await.expect("backend task");
    }

    /// A backend that pings at the WebSocket level and never reads the pongs: the pongs fill the
    /// socket's buffers until one cannot be written, and the pump ends at the send limit
    /// (`send_timeout`) rather than sit in the pong's write — the backend still talking, so the
    /// silence limit never comes.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_ws_pong_that_cannot_be_written_ends_the_pump_at_the_send_limit() {
        let socket = tokio::net::TcpSocket::new_v4().expect("socket");
        socket.set_recv_buffer_size(8 * 1024).expect("recv buffer");
        socket
            .bind("127.0.0.1:0".parse().expect("addr"))
            .expect("bind");
        let listener = socket.listen(1).expect("listen");
        let addr = listener.local_addr().expect("addr");
        let (hold_tx, hold_rx) = oneshot::channel::<()>();
        let backend = tokio::spawn(async move {
            let mut ws = handshake(&listener).await;
            // Pings, never a read: until the agent stops taking them (it is stuck writing a pong),
            // or a bound.
            let until = tokio::time::Instant::now() + Duration::from_secs(15);
            let mut sent = 0u64;
            while tokio::time::Instant::now() < until {
                let ping = ws.send(Message::Ping(vec![7u8; 125].into()));
                match tokio::time::timeout(Duration::from_secs(2), ping).await {
                    Ok(Ok(())) => sent += 1,
                    Ok(Err(_)) | Err(_) => break,
                }
            }
            let _ = hold_rx.await;
            drop(ws);
            sent
        });
        let mut signaling = connect_with(
            test_config(addr),
            Arc::new(|_: &[u8]| vec![0u8; 64]),
            Limits {
                send: Duration::from_millis(500),
                silence: Duration::from_secs(60),
                legacy_silence: Duration::from_secs(60),
                ..fast_limits()
            },
        )
        .await
        .expect("handshake");
        let health = signaling.health.clone();
        let end = tokio::time::timeout(Duration::from_secs(30), signaling.incoming.recv())
            .await
            .expect("the pump gives up on a pong that cannot be written");
        assert!(end.is_none());
        let how = health.end().expect("the end is known");
        assert_eq!(how.cause, EndCause::SendTimeout, "{how:?}");
        let _ = hold_tx.send(());
        let sent = tokio::time::timeout(Duration::from_secs(20), backend)
            .await
            .expect("the backend ends")
            .expect("backend task");
        assert!(sent > 0, "the backend pinged");
    }

    /// The silence limit stays in force while a write is pending: a backend that neither reads nor
    /// says anything is given up at the silence limit, not after the (longer) send limit.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_silence_limit_ends_a_connection_stuck_in_a_write() {
        let socket = tokio::net::TcpSocket::new_v4().expect("socket");
        socket.set_recv_buffer_size(8 * 1024).expect("recv buffer");
        socket
            .bind("127.0.0.1:0".parse().expect("addr"))
            .expect("bind");
        let listener = socket.listen(1).expect("listen");
        let addr = listener.local_addr().expect("addr");
        let (hold_tx, hold_rx) = oneshot::channel::<()>();
        let backend = tokio::spawn(async move {
            let ws = handshake(&listener).await;
            let _ = hold_rx.await;
            drop(ws);
        });
        let mut signaling = connect_with(
            test_config(addr),
            Arc::new(|_: &[u8]| vec![0u8; 64]),
            Limits {
                send: Duration::from_secs(120),
                silence: Duration::from_millis(1500),
                legacy_silence: Duration::from_millis(1500),
                ..fast_limits()
            },
        )
        .await
        .expect("handshake");
        let health = signaling.health.clone();
        let big = |n: u32| AgentToServer::Ice {
            session_id: "s1".into(),
            candidate: afklink_protocol::IceCandidate {
                candidate: format!("candidate:{n} {}", "x".repeat(1 << 20)),
                sdp_mid: None,
                sdp_mline_index: None,
                username_fragment: None,
            },
        };
        let started = std::time::Instant::now();
        for n in 0..48 {
            if signaling.outgoing.send(big(n)).is_err() {
                break;
            }
        }
        let end = tokio::time::timeout(Duration::from_secs(20), signaling.incoming.recv())
            .await
            .expect("the pump gives up at the silence limit");
        assert!(end.is_none());
        let how = health.end().expect("the end is known");
        assert_eq!(how.cause, EndCause::Silence, "{how:?}");
        assert!(
            started.elapsed() < Duration::from_secs(15),
            "the silence, not the two-minute send limit: {:?}",
            started.elapsed()
        );
        let _ = hold_tx.send(());
        backend.await.expect("backend task");
    }

    /// A backend that pings every `every` (`pings` times) and then goes silent, the socket left
    /// open. Returns the pongs it read back.
    fn pinging_backend(
        listener: tokio::net::TcpListener,
        every: Duration,
        pings: usize,
        hold: oneshot::Receiver<()>,
    ) -> tokio::task::JoinHandle<usize> {
        tokio::spawn(async move {
            let mut ws = handshake(&listener).await;
            let mut pongs = 0usize;
            for _ in 0..pings {
                ws.send(Message::text(r#"{"type":"ping"}"#))
                    .await
                    .expect("ping");
                let deadline = tokio::time::Instant::now() + every;
                while let Ok(Some(Ok(frame))) = tokio::time::timeout_at(deadline, ws.next()).await {
                    if let Message::Text(t) = frame {
                        if t.as_str().contains(r#""pong""#) {
                            pongs += 1;
                        }
                    }
                }
            }
            let _ = hold.await;
            pongs
        })
    }

    /// A backend seen to ping often is held to the short limit: once its pings stop, the pump gives
    /// up after the short limit, well before the long one.
    #[tokio::test]
    async fn a_backend_that_pinged_often_and_went_silent_is_given_up_at_the_short_limit() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let (hold_tx, hold_rx) = oneshot::channel::<()>();
        let backend = pinging_backend(listener, Duration::from_millis(50), 6, hold_rx);
        let mut signaling = connect_with(
            test_config(addr),
            Arc::new(|_: &[u8]| vec![0u8; 64]),
            fast_limits(),
        )
        .await
        .expect("handshake");
        let started = std::time::Instant::now();
        let health = signaling.health.clone();
        assert_eq!(
            health.silence_limit(),
            fast_limits().legacy_silence,
            "long until the pings are judged"
        );
        let end = tokio::time::timeout(Duration::from_secs(5), signaling.incoming.recv())
            .await
            .expect("the pump gives up");
        assert!(end.is_none(), "pings are not handed on: {end:?}");
        let gone_after = started.elapsed();
        // What the event queue reads: the short limit learned from the pings, the last ping heard
        // (six, 50 ms apart), and the pump gone.
        assert_eq!(health.silence_limit(), fast_limits().silence);
        // Silence after six pings of 15 bytes each: what the choice of way weighs.
        let how = health.end().expect("the end is known");
        assert_eq!(how.cause, EndCause::Silence);
        assert_eq!(how.frames, 6, "{how:?}");
        assert_eq!(
            how.received_bytes,
            6 * r#"{"type":"ping"}"#.len() as u64,
            "{how:?}"
        );
        assert!(
            health.last_heard() >= started + Duration::from_millis(150),
            "heard until the last ping: {:?}",
            health.last_heard().saturating_duration_since(started)
        );
        assert!(!health.is_up());
        // Six pings 50 ms apart (about 300 ms), then the short limit of 400 ms.
        assert!(
            gone_after >= Duration::from_millis(600) && gone_after < Duration::from_millis(2500),
            "given up at the short limit after the last ping, not the long one: {gone_after:?}"
        );
        let _ = hold_tx.send(());
        assert_eq!(
            backend.await.expect("backend task"),
            6,
            "every ping answered"
        );
    }

    /// A backend that pings only now and then (the old twenty-second cadence, scaled down) keeps
    /// the long limit: a gap longer than the short limit between its pings does not drop it.
    #[tokio::test]
    async fn a_backend_that_pings_rarely_keeps_the_long_limit() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let (hold_tx, hold_rx) = oneshot::channel::<()>();
        // 600 ms apart: slower than the fast cadence (150 ms), longer than the short limit
        // (400 ms), well inside the long one (3 s).
        let backend = pinging_backend(listener, Duration::from_millis(600), 4, hold_rx);
        let mut signaling = connect_with(
            test_config(addr),
            Arc::new(|_: &[u8]| vec![0u8; 64]),
            fast_limits(),
        )
        .await
        .expect("handshake");
        // The four pings take about 2.4 s; the connection must outlive them all.
        match tokio::time::timeout(Duration::from_millis(2300), signaling.incoming.recv()).await {
            Err(_) => {}
            Ok(end) => panic!("the connection ended under a rare but steady ping: {end:?}"),
        }
        let _ = hold_tx.send(());
        assert_eq!(
            backend.await.expect("backend task"),
            4,
            "every ping answered"
        );
    }

    /// The cadence's verdicts: nothing from the first ping, the short limit from a short gap, the
    /// long one back from a long gap, and a backlog judged by nothing.
    #[test]
    fn the_ping_cadence_picks_the_limit() {
        let limits = fast_limits();
        let mut cadence = PingCadence::new(limits);
        let t0 = Instant::now();
        assert_eq!(cadence.limit(), limits.legacy_silence, "long until judged");
        assert_eq!(cadence.ping(t0), None, "one ping is no cadence");
        assert_eq!(
            cadence.ping(t0 + Duration::from_millis(100)),
            Some(limits.silence)
        );
        assert_eq!(cadence.limit(), limits.silence);
        assert_eq!(
            cadence.ping(t0 + Duration::from_millis(200)),
            None,
            "unchanged"
        );
        assert_eq!(
            cadence.ping(t0 + Duration::from_millis(205)),
            None,
            "a backlog: not judged"
        );
        assert_eq!(cadence.limit(), limits.silence);
        assert_eq!(
            cadence.ping(t0 + Duration::from_millis(805)),
            Some(limits.legacy_silence),
            "a long gap: an older backend's cadence"
        );
        // The real numbers: a five-second cadence is fast, a twenty-second one is not.
        let mut real = PingCadence::new(LIMITS);
        real.ping(t0);
        assert_eq!(
            real.ping(t0 + Duration::from_secs(5)),
            Some(BACKEND_SILENCE_LIMIT)
        );
        assert_eq!(
            real.ping(t0 + Duration::from_secs(25)),
            Some(LEGACY_SILENCE_LIMIT)
        );
        assert_eq!(BACKEND_SILENCE_LIMIT, Duration::from_secs(20));
    }

    /// The backend's heartbeat is answered by the pump, with nobody reading `incoming` — the
    /// orchestrator busy for as long as it likes — and the ping is not handed on.
    #[tokio::test]
    async fn pings_are_answered_by_the_pump_while_nobody_reads() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let backend = tokio::spawn(async move {
            let mut ws = handshake(&listener).await;
            let mut answered = 0;
            for _ in 0..3 {
                ws.send(Message::text(r#"{"type":"ping"}"#))
                    .await
                    .expect("ping");
                let frame = tokio::time::timeout(Duration::from_secs(2), ws.next())
                    .await
                    .expect("the pong in time")
                    .expect("open")
                    .expect("a frame");
                match frame {
                    Message::Text(t) => {
                        let v: serde_json::Value =
                            serde_json::from_str(t.as_str()).expect("json from the agent");
                        assert_eq!(v["type"], "pong");
                        answered += 1;
                    }
                    other => panic!("expected the pong, got {other:?}"),
                }
            }
            ws.send(Message::text(
                r#"{"type":"binding_removed","telegram_user_id":7}"#,
            ))
            .await
            .expect("binding_removed");
            close_after_drain(ws).await;
            answered
        });
        let mut signaling = connect(test_config(addr), Arc::new(|_: &[u8]| vec![0u8; 64]))
            .await
            .expect("handshake");
        // Nobody reads `incoming` while the pings go back and forth.
        assert_eq!(backend.await.expect("backend task"), 3);
        let first = tokio::time::timeout(Duration::from_secs(5), signaling.incoming.recv())
            .await
            .expect("in time");
        assert_eq!(
            first.as_ref().map(ServerToAgent::kind),
            Some("binding_removed"),
            "the pings were not handed on: {first:?}"
        );
    }

    /// Close the backend's side once the agent has said what it had to, and wait for its side.
    async fn close_after_drain(mut ws: tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>) {
        let _ = ws.close(None).await;
        let _ = tokio::time::timeout(Duration::from_secs(5), async {
            while let Some(Ok(_)) = ws.next().await {}
        })
        .await;
    }

    /// The goodbye: what was queued first, then `agent_goodbye` with its reason, then a normal
    /// close; the backend's answering close confirms it to the caller, and the connection ends with
    /// nothing handed back.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_goodbye_goes_after_the_queue_and_closes_normally() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let backend = tokio::spawn(async move {
            let mut ws = handshake(&listener).await;
            let mut seen = Vec::new();
            let mut close = None;
            loop {
                match tokio::time::timeout(Duration::from_secs(5), ws.next()).await {
                    Ok(Some(Ok(Message::Text(t)))) => {
                        let v: serde_json::Value =
                            serde_json::from_str(t.as_str()).expect("json from the agent");
                        seen.push(v);
                    }
                    // tungstenite answers it on the next read; the agent then goes, which ends
                    // the loop.
                    Ok(Some(Ok(Message::Close(frame)))) => {
                        close = frame.map(|f| (u16::from(f.code), f.reason.to_string()));
                    }
                    Ok(Some(Ok(_))) => {}
                    _ => break,
                }
            }
            (seen, close)
        });
        let mut signaling = connect(test_config(addr), Arc::new(|_: &[u8]| vec![0u8; 64]))
            .await
            .expect("handshake");
        signaling.outgoing.send(ice(1)).expect("open");
        signaling.outgoing.send(ice(2)).expect("open");
        let ticket = signaling
            .goodbye
            .request(GoodbyeReason::Sleep, Duration::from_secs(3));
        let result = tokio::task::spawn_blocking(move || ticket.wait())
            .await
            .expect("the wait does not panic");
        assert!(
            matches!(result, GoodbyeResult::Confirmed { .. }),
            "the backend's close confirms it: {result:?}"
        );
        assert!(result.sent());
        let (seen, close) = backend.await.expect("backend task");
        let types: Vec<&str> = seen
            .iter()
            .map(|v| v["type"].as_str().unwrap_or("?"))
            .collect();
        assert_eq!(types, ["ice", "ice", "agent_goodbye"]);
        assert_eq!(seen[2]["reason"], "sleep");
        assert_eq!(close, Some((1000, GOODBYE_CLOSE_REASON.to_string())));
        let end = tokio::time::timeout(Duration::from_secs(5), signaling.incoming.recv())
            .await
            .expect("incoming ends after the goodbye");
        assert!(end.is_none());
        match signaling.unsent.try_recv() {
            Ok(unsent) => assert!(unsent.is_empty(), "everything was written: {unsent:?}"),
            Err(e) => panic!("the hand-back is there: {e:?}"),
        }
        // Asked again on the ended connection: nothing to say it on, at once.
        let again = signaling
            .goodbye
            .request(GoodbyeReason::Quit, Duration::from_secs(3));
        let started = std::time::Instant::now();
        assert_eq!(again.wait(), GoodbyeResult::NoConnection);
        assert!(started.elapsed() < Duration::from_millis(500));
        assert!(signaling.goodbye.is_closed());
    }

    /// A socket that takes frames and never flushes them (a path that died under a full send
    /// buffer): the caller's wait ends at its budget, not later, and the pump gives the goodbye up
    /// at the budget and the linger.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_goodbye_that_never_flushes_costs_the_budget_and_no_more() {
        use std::pin::Pin;
        use std::task::{Context as TaskContext, Poll};

        struct NeverFlushes;
        impl futures_util::Stream for NeverFlushes {
            type Item = Result<Message, tokio_tungstenite::tungstenite::Error>;
            fn poll_next(
                self: Pin<&mut Self>,
                _: &mut TaskContext<'_>,
            ) -> Poll<Option<Self::Item>> {
                Poll::Pending
            }
        }
        impl futures_util::Sink<Message> for NeverFlushes {
            type Error = tokio_tungstenite::tungstenite::Error;
            fn poll_ready(
                self: Pin<&mut Self>,
                _: &mut TaskContext<'_>,
            ) -> Poll<Result<(), Self::Error>> {
                Poll::Ready(Ok(()))
            }
            fn start_send(self: Pin<&mut Self>, _: Message) -> Result<(), Self::Error> {
                Ok(())
            }
            fn poll_flush(
                self: Pin<&mut Self>,
                _: &mut TaskContext<'_>,
            ) -> Poll<Result<(), Self::Error>> {
                Poll::Pending
            }
            fn poll_close(
                self: Pin<&mut Self>,
                _: &mut TaskContext<'_>,
            ) -> Poll<Result<(), Self::Error>> {
                Poll::Pending
            }
        }

        let budget = Duration::from_millis(200);
        let linger = Duration::from_millis(300);
        let (report, rx) = std::sync::mpsc::sync_channel(2);
        let asked = Instant::now();
        let ticket = GoodbyeTicket {
            asked,
            deadline: asked + budget,
            rx: Some(rx),
        };
        let waiting = std::thread::spawn(move || ticket.wait());
        let (_out_tx, mut out_rx) = mpsc::unbounded_channel::<AgentToServer>();
        let (mut sent, mut failed) = (0u64, None);
        let mut ws = NeverFlushes;
        let why = tokio::time::timeout(
            Duration::from_secs(5),
            say_goodbye(
                &mut ws,
                &mut out_rx,
                GoodbyeRequest {
                    reason: GoodbyeReason::Shutdown,
                    asked,
                    deadline: asked + budget,
                    linger,
                    report,
                },
                &mut sent,
                &mut failed,
            ),
        )
        .await
        .expect("the pump gives the goodbye up in bounded time");
        assert_eq!(why, "the goodbye was not written in time");
        let pump_took = asked.elapsed();
        assert!(
            pump_took >= budget + linger && pump_took < budget + linger + Duration::from_secs(1),
            "the pump keeps at it for the budget and the linger: {pump_took:?}"
        );
        let result = waiting.join().expect("the wait does not panic");
        match &result {
            GoodbyeResult::TimedOut { took } => assert!(
                *took >= budget && *took < budget + Duration::from_millis(250),
                "the caller waited its budget and no more: {took:?}"
            ),
            other => panic!("expected a timeout, got {other:?}"),
        }
        assert!(!result.sent());
    }

    /// A host that takes the TCP connection and never answers the upgrade — what a black-holed
    /// path looks like from here — costs the attempt its bounded time, not the operating system's.
    #[tokio::test]
    async fn a_connect_that_gets_no_answer_is_given_up_in_bounded_time() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let (hold_tx, hold_rx) = oneshot::channel::<()>();
        let backend = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.expect("accept");
            let _ = hold_rx.await;
            drop(tcp);
        });

        let started = std::time::Instant::now();
        let result = connect_with(
            test_config(addr),
            Arc::new(|_: &[u8]| vec![0u8; 64]),
            Limits {
                connect: Duration::from_millis(200),
                ..LIMITS
            },
        )
        .await;
        let err = match result {
            Ok(_) => panic!("a connect with no answer must fail"),
            Err(e) => e,
        };
        let text = format!("{err:#}");
        assert!(text.contains("no answer within 200 ms"), "{text}");
        let failed = connect_failed(&err);
        assert_eq!(
            (failed.stage, failed.failure),
            (ConnectStage::Upgrade, ConnectFailure::Timeout),
            "TCP connected, the upgrade never answered"
        );
        assert_eq!(failed.peer.map(|p| p.port()), Some(addr.port()));
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "bounded: {:?}",
            started.elapsed()
        );
        let _ = hold_tx.send(());
        backend.await.expect("backend task");
    }

    /// The [`ConnectFailed`] in `err`'s chain.
    fn connect_failed(err: &anyhow::Error) -> &ConnectFailed {
        err.chain()
            .find_map(|c| c.downcast_ref::<ConnectFailed>())
            .unwrap_or_else(|| panic!("not typed: {err:#}"))
    }

    /// A frozen path: the upgrade goes through, `agent_hello` reaches the server, and
    /// then nothing the server sends arrives — no reset, the socket just goes silent. The handshake
    /// gives it up at its silence limit, typed, rather than waiting for a close that never comes.
    #[tokio::test]
    async fn an_upgrade_then_silence_is_given_up_as_a_silent_handshake() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let (hold_tx, hold_rx) = oneshot::channel::<()>();
        let backend = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.expect("accept");
            let mut ws = tokio_tungstenite::accept_async(tcp)
                .await
                .expect("ws accept");
            let hello = ws.next().await;
            // The hello arrived; nothing goes back, and the socket stays open.
            let _ = hold_rx.await;
            drop(ws);
            hello.is_some()
        });
        let started = std::time::Instant::now();
        let result = connect_with(
            test_config(addr),
            Arc::new(|_: &[u8]| vec![0u8; 64]),
            Limits {
                handshake_silence: Duration::from_millis(300),
                ..LIMITS
            },
        )
        .await;
        let err = match result {
            Ok(_) => panic!("a silent handshake must fail"),
            Err(e) => e,
        };
        let silent = err
            .chain()
            .find_map(|c| c.downcast_ref::<HandshakeSilent>())
            .unwrap_or_else(|| panic!("not typed: {err:#}"));
        assert_eq!(
            silent,
            &HandshakeSilent {
                awaiting: "challenge",
                silent_for: Duration::from_millis(300),
                frames: 0,
            }
        );
        let took = started.elapsed();
        assert!(
            took >= Duration::from_millis(300) && took < Duration::from_secs(3),
            "at the limit, not before and not much after: {took:?}"
        );
        let _ = hold_tx.send(());
        assert!(backend.await.expect("backend task"), "the hello arrived");
    }

    /// The handshake's silence limit is between frames: a backend that keeps pinging while it takes
    /// its time is alive, and the handshake waits for it past the limit.
    #[tokio::test]
    async fn pings_keep_a_slow_handshake_alive_past_the_silence_limit() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let backend = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.expect("accept");
            let mut ws = tokio_tungstenite::accept_async(tcp)
                .await
                .expect("ws accept");
            let _hello = ws.next().await;
            // 8 pings 100 ms apart: 800 ms before the challenge, each gap under the 300 ms limit.
            for _ in 0..8 {
                tokio::time::sleep(Duration::from_millis(100)).await;
                ws.send(Message::text(r#"{"type":"ping"}"#))
                    .await
                    .expect("ping");
                let _pong = ws.next().await;
            }
            let nonce = BASE64_STANDARD.encode([7u8; 32]);
            ws.send(Message::text(format!(
                r#"{{"type":"challenge","nonce":"{nonce}"}}"#
            )))
            .await
            .expect("challenge");
            let _auth = ws.next().await;
            ws.send(Message::text(format!(
                r#"{{"type":"agent_ready","protocol_version":{PROTOCOL_VERSION},"min_supported_protocol":{PROTOCOL_VERSION},"bindings":[]}}"#
            )))
            .await
            .expect("agent_ready");
            close_after_drain(ws).await;
        });
        let started = std::time::Instant::now();
        let signaling = connect_with(
            test_config(addr),
            Arc::new(|_: &[u8]| vec![0u8; 64]),
            Limits {
                handshake_silence: Duration::from_millis(300),
                ..LIMITS
            },
        )
        .await
        .expect("a backend that keeps talking is waited for");
        assert!(
            started.elapsed() >= Duration::from_millis(800),
            "{:?}",
            started.elapsed()
        );
        drop(signaling);
        backend.await.expect("backend task");
    }

    /// Opening the connection fails typed by stage and kind: nobody listening is a TCP refusal; an
    /// HTTP answer other than 101 is its status; a name with no address is the lookup's.
    #[tokio::test]
    async fn a_failed_connect_says_its_stage_and_kind() {
        // Nobody listens: the local end of a connected client socket, which nobody can take while
        // the test runs (as in `start_failure`'s tests in the app).
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("a listener");
        let held = std::net::TcpStream::connect(listener.local_addr().expect("addr"))
            .expect("a client connection");
        let port = held.local_addr().expect("the client's port").port();
        let refused = connect(
            SignalingConfig {
                url: format!("ws://127.0.0.1:{port}/ws/agent"),
                ..test_config(listener.local_addr().expect("addr"))
            },
            Arc::new(|_: &[u8]| vec![0u8; 64]),
        )
        .await
        .err()
        .expect("nobody listens");
        let failed = connect_failed(&refused);
        assert_eq!(
            (failed.stage, failed.failure),
            (ConnectStage::Tcp, ConnectFailure::Refused),
            "{failed}"
        );
        drop((held, listener));

        // A plain HTTP server that answers the upgrade with 404.
        let http = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let http_addr = http.local_addr().expect("addr");
        let server = tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let (mut tcp, _) = http.accept().await.expect("accept");
            let mut buf = [0u8; 4096];
            let _ = tcp.read(&mut buf).await;
            let _ = tcp
                .write_all(
                    b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await;
            let _ = tcp.shutdown().await;
        });
        let not_found = connect(test_config(http_addr), Arc::new(|_: &[u8]| vec![0u8; 64]))
            .await
            .err()
            .expect("a 404 is no upgrade");
        let failed = connect_failed(&not_found);
        assert_eq!(
            (failed.stage, failed.failure),
            (ConnectStage::Upgrade, ConnectFailure::Status(404)),
            "{failed}"
        );
        server.await.expect("server task");

        // A name that has no address (RFC 6761: `.invalid` never resolves).
        let unresolved = connect_with(
            SignalingConfig {
                url: "ws://afklink-test.invalid/ws/agent".into(),
                ..test_config(http_addr)
            },
            Arc::new(|_: &[u8]| vec![0u8; 64]),
            Limits {
                connect: Duration::from_secs(5),
                ..LIMITS
            },
        )
        .await
        .err()
        .expect("no address");
        let failed = connect_failed(&unresolved);
        assert_eq!(failed.stage, ConnectStage::Dns, "{failed}");
        assert!(
            matches!(
                failed.failure,
                ConnectFailure::NotResolved | ConnectFailure::Timeout
            ),
            "{failed}"
        );
        assert_eq!(failed.peer, None);
    }

    /// The address a connection goes to: the host to look up — an IPv6 literal without brackets —
    /// and the scheme's port when none is given.
    #[test]
    fn the_host_and_port_to_connect_to() {
        let hp = |url: &str| {
            let uri: tokio_tungstenite::tungstenite::http::Uri = url.parse().expect("a uri");
            host_port(&uri)
        };
        assert_eq!(
            hp("wss://api.afklink.app/ws/agent"),
            Some(("api.afklink.app".into(), 443))
        );
        assert_eq!(
            hp("wss://api.ru.afklink.app/ws/agent"),
            Some(("api.ru.afklink.app".into(), 443))
        );
        assert_eq!(
            hp("ws://localhost:8787/ws/agent"),
            Some(("localhost".into(), 8787))
        );
        assert_eq!(
            hp("ws://example.test/ws/agent"),
            Some(("example.test".into(), 80))
        );
        assert_eq!(hp("ws://[::1]:8787/ws/agent"), Some(("::1".into(), 8787)));
        assert_eq!(hp("/ws/agent"), None);
    }
}
