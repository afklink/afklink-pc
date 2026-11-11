//! Server-reflexive discovery: a STUN Binding transaction (RFC 8489) on the peer's own socket.
//!
//! ## Why a transaction and not a request
//!
//! A single Binding request lets one lost datagram decide the session: the answer goes out with
//! host candidates only, and a phone on LTE whose only route to the PC is its TURN relay has no
//! address of ours to create a permission for, so ICE goes nowhere for twenty seconds.
//!
//! ## The schedule
//!
//! RFC 8489 §6.2.1 with an RTO of 250 ms: transmissions at 0, 250, 750, 1750, 3750, 7750 and
//! 15 750 ms (`Rc` = 7), then `Rm` = 16 RTOs for the last reply, 19.75 s in all. Every
//! retransmission reuses the transaction id, so a reply to *any* of them counts. 250 ms rather than
//! the RFC's 500 is libwebrtc's `STUN_INITIAL_RTO`, what the browser on the other end uses for this
//! job; since earlier replies stay valid, a short RTO costs at most a duplicate 20-byte datagram.
//!
//! ## Two phases, one transaction
//!
//! The answer waits for the first [`ANSWER_BUDGET`], because a candidate carried in the answer works
//! with any viewer. That budget covers three transmissions and gives the third 750 ms — longer than
//! the slowest successful gather recorded (666 ms, DNS included, median near 300). The rest runs on
//! the peer loop with the same socket and ids, and a later mapping is added to the `Rtc` and
//! trickled (`webrtc::PeerLoop::drive_srflx`).
//!
//! ## An ICE restart continues it
//!
//! The peer has one socket for its whole life, so the mapping a restart wants is the one the
//! running transaction is already asking for. Restarting the transaction would discard requests
//! still owed a reply (on a VPN starved of CPU, replies took 1.9-2.3 s, and each restart half a
//! second apart threw them away again). So [`Probe::renew`] starts a new round on every server
//! already asked — a new id on the schedule above — and keeps the earlier rounds' ids, so a reply to
//! any request ever sent still counts. RFC 8489 §6.2.1 allows several transactions to one server at
//! once and asks for no more than ten; [`MAX_ROUNDS`] keeps it to four.
//!
//! A relay-only viewer waits longer: see [`RELAY_ONLY_ANSWER_BUDGET`].
//!
//! Hand-rolled for the same reason as `crate::mdns`: one request type, one attribute, on a socket
//! we already own.

use std::collections::hash_map::RandomState;
use std::fmt::Write as _;
use std::hash::{BuildHasher, Hasher};
use std::io::ErrorKind;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use tokio::sync::mpsc;

use crate::socket::PeerSocket;

/// The fixed cookie that marks an RFC 5389/8489 message.
const MAGIC: u32 = 0x2112_A442;

const BINDING_REQUEST: u16 = 0x0001;
const BINDING_SUCCESS: u16 = 0x0101;
const BINDING_ERROR: u16 = 0x0111;

const ATTR_MAPPED_ADDRESS: u16 = 0x0001;
const ATTR_ERROR_CODE: u16 = 0x0009;
const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;

/// The initial retransmission timeout. See the module docs for why 250 ms.
pub(crate) const RTO: Duration = Duration::from_millis(250);

/// Transmissions per server: RFC 8489's default `Rc`.
pub(crate) const MAX_SENDS: u32 = 7;

/// How long the last transmission is given to be answered, in RTOs: RFC 8489's default `Rm`.
const FINAL_WAIT_RTOS: u32 = 16;

/// How long the SDP answer waits for a mapping before going out with host candidates only.
///
/// Three transmissions (0, 250, 750 ms) and 750 ms for the last of them. See the module docs for
/// the measurements behind it. The rest of the transaction continues after the answer.
pub(crate) const ANSWER_BUDGET: Duration = Duration::from_millis(1_500);

/// How long an answer waits for a mapping when the viewer has offered only relay candidates and
/// none of ours is public: the first answer, if the offer says so, and the answer to an ICE restart
/// (`webrtc::PeerLoop::renegotiate`), counted from that restart's offer. Also the
/// answer to an offer sent again — the Mini App's resume after its signalling socket died — when
/// that is the first word that the viewer is relay-only; one budget per offer however often it is
/// sent, so an offer whose first answer already waited it is answered again at once. The resume
/// gives the viewer at least 15 s from the re-sent offer (`RESUME_DEADLINE_MS`, same file as below):
/// one such hold and one held restart after it fit.
///
/// Such an answer cannot work without a srflx candidate. The viewer's TURN relay forwards only to
/// addresses the viewer has a permission for, and Cloudflare's refuses one for a private address —
/// the only kind a host candidate behind a NAT has. Answered with host candidates only, the viewer
/// fails at once, restarts ICE at most twice and ends the session: `ice_failed` 1.1-1.5 s after the
/// first answer. So waiting longer costs such a viewer
/// only time, and other viewers nothing.
///
/// 4.5 s: five transmissions (0, 250, 750, 1750 and 3750 ms) and 750 ms for the fifth to be
/// answered, the allowance [`ANSWER_BUDGET`] gives its third. A slow-STUN path measured at 1854 ms
/// answered the fourth transmission. The first answer
/// (1.5 s, while nothing says the viewer is relay-only) and two held restart answers come to about
/// 11 s, inside the viewer's own 30 s deadline for a first picture (`CONNECT_TIMEOUT_MS`,
/// `miniapp/src/session/useViewerSession.ts`). A budget reaching the sixth transmission (7750 ms)
/// would take that to about 19 s for sessions whose STUN path is dead, and the transaction goes on
/// after the answer anyway, so whatever comes later is still trickled.
pub(crate) const RELAY_ONLY_ANSWER_BUDGET: Duration = Duration::from_millis(4_500);

/// How many rounds' transaction ids one server keeps answering to: the current round's and the
/// three before it. See the module docs, «An ICE restart continues it».
const MAX_ROUNDS: usize = 4;

/// How many servers are queried at once.
///
/// The session's ICE config carries up to eight URLs, of which the UDP-capable ones are typically
/// two or three (`stun:` on 3478 and 53, `turn:` over UDP). Four bounds the traffic without ever
/// dropping one of those.
const MAX_SERVERS: usize = 4;

/// The port RFC 7064/7065 assign to `stun:` and `turn:` URLs that do not name one.
const DEFAULT_PORT: u16 = 3478;

/// When transmission `k` (zero-based) goes out, relative to the first: `RTO * (2^k - 1)`.
pub(crate) fn send_offset(k: u32) -> Duration {
    RTO * ((1u32 << k.min(MAX_SENDS)) - 1)
}

/// How long the whole transaction lives, from the moment it starts.
pub(crate) fn lifetime() -> Duration {
    send_offset(MAX_SENDS - 1) + RTO * FINAL_WAIT_RTOS
}

/// The STUN servers worth asking, as `host:port`, from a session's ICE URLs.
///
/// Only what a UDP socket can reach: `stun:` URLs, and `turn:` URLs over UDP — TURN servers
/// commonly answer a plain Binding too, and one that does not costs nothing but silence.
/// `stuns:`, `turns:` and `?transport=tcp` are TLS or TCP and cannot be asked from the socket ICE
/// will use, which is the whole point: the mapping has to be the one *that* socket has. `stun:`
/// first, since that is what those URLs are for. Duplicates removed, at most [`MAX_SERVERS`].
///
/// Replaces picking the first `stun:` URL, which made the whole session hang on one server.
pub fn stun_servers(urls: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for want_stun in [true, false] {
        for url in urls {
            let Some((is_stun, host_port)) = udp_host_port(url) else {
                continue;
            };
            if is_stun == want_stun && !out.contains(&host_port) {
                out.push(host_port);
            }
        }
    }
    out.truncate(MAX_SERVERS);
    out
}

/// `(is_stun, "host:port")` for a URL a UDP socket can send a Binding to.
fn udp_host_port(url: &str) -> Option<(bool, String)> {
    let (is_stun, rest) = match url.strip_prefix("stun:") {
        Some(rest) => (true, rest),
        None => (false, url.strip_prefix("turn:")?),
    };
    if rest.to_ascii_lowercase().contains("transport=tcp") {
        return None;
    }
    let host_port = rest.split(['?', ';']).next().unwrap_or(rest).trim();
    if host_port.is_empty() {
        return None;
    }
    // A port is a colon after the host — after the closing bracket, for an IPv6 literal.
    let has_port = match host_port.rfind(']') {
        Some(i) => host_port[i..].contains(':'),
        None => host_port.contains(':'),
    };
    Some(if has_port {
        (is_stun, host_port.to_string())
    } else {
        (is_stun, format!("{host_port}:{DEFAULT_PORT}"))
    })
}

/// A resolved server name, by index into [`Probe`]'s servers, or why it did not resolve.
pub(crate) type Resolved = (usize, Result<SocketAddr, String>);

/// Resolve every server name concurrently, off the caller.
///
/// Each lookup reports on the returned channel when it finishes, however late: the transaction
/// outlives the answer, so a name that resolves after the answer went out is still queried.
pub(crate) fn spawn_lookups(probe: &Probe) -> mpsc::UnboundedReceiver<Resolved> {
    let (tx, rx) = mpsc::unbounded_channel();
    for (idx, server) in probe.servers.iter().enumerate() {
        let tx = tx.clone();
        let name = server.name.clone();
        tokio::spawn(async move {
            let res = match tokio::net::lookup_host(name.as_str()).await {
                Ok(mut addrs) => addrs
                    .find(SocketAddr::is_ipv4)
                    .ok_or_else(|| "no IPv4 address".to_string()),
                Err(e) => Err(e.to_string()),
            };
            // A closed channel means the transaction was dropped — it found a mapping, the path
            // connected, or the peer ended — and nobody wants this answer any more.
            if tx.send((idx, res)).is_err() {
                tracing::trace!(%name, "STUN server lookup finished after its transaction ended");
            }
        });
    }
    rx
}

/// One Binding request to send.
#[derive(Debug)]
pub(crate) struct Transmit {
    /// Which server, for [`Probe::send_failed`].
    pub idx: usize,
    pub to: SocketAddr,
    pub bytes: [u8; 20],
}

/// What a datagram meant to the transaction.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Input {
    /// Not a reply to us. Pass it on: this is how every ICE and media packet looks.
    NotOurs,
    /// A reply to us that says nothing useful (an error, no address, a stray source).
    Consumed,
    /// Our public address, as seen by server `server`.
    Mapped { addr: SocketAddr, server: usize },
}

/// A mapping found within a deadline.
#[derive(Debug)]
pub(crate) struct Found {
    pub addr: SocketAddr,
    /// The `host:port` that answered.
    pub server: String,
}

/// The Binding transactions of one session, one per server. Sans-IO: the caller owns the socket
/// and the clock, which is what lets the same object run before the answer and then on the peer
/// loop, and be tested without either.
pub(crate) struct Probe {
    servers: Vec<Server>,
    /// When the discovery began, for the log. [`Self::renew`] does not move it.
    began: Instant,
    /// When the current round began: the transaction gives up [`lifetime`] after it.
    round_started: Instant,
    /// A receive error that ended a wait early, for the log.
    recv_error: Option<String>,
}

struct Server {
    /// `host:port`, as derived from the ICE URL.
    name: String,
    /// One id per round, reused by every retransmission of that round (RFC 8489 §6.2.1): the
    /// current round's last, earlier rounds' before it, [`MAX_ROUNDS`] at most. A reply to any of
    /// them counts.
    txids: Vec<[u8; 12]>,
    /// The current round's number: 1, and one more per [`Probe::renew`] that renewed this server.
    round: u32,
    state: State,
    /// Datagrams handed to the socket for this server in the current round, including ones the
    /// socket refused. Drives the schedule.
    sent: u32,
    /// The same over every round, for the log.
    sent_total: u32,
    /// When the current round's first request went out.
    first_send: Option<Instant>,
    /// The last error the socket gave for a send. Retransmission carries on regardless: a send
    /// error on UDP is usually a routing hiccup that the next one survives.
    send_error: Option<String>,
}

enum State {
    Resolving,
    Querying(SocketAddr),
    Stopped(Stop),
}

enum Stop {
    Dns(String),
    /// Resolved to an address another server already covers.
    Duplicate(String),
    ErrorResponse(u16),
    /// A success response without a usable IPv4 mapped address.
    NoAddress,
}

impl Probe {
    pub(crate) fn new(names: Vec<String>, now: Instant) -> Self {
        let servers = names
            .into_iter()
            .enumerate()
            .map(|(i, name)| Server {
                name,
                txids: vec![random_txid(i)],
                round: 1,
                state: State::Resolving,
                sent: 0,
                sent_total: 0,
                first_send: None,
                send_error: None,
            })
            .collect();
        Self {
            servers,
            began: now,
            round_started: now,
            recv_error: None,
        }
    }

    /// Ask every server that has already been asked again, at once and on the full schedule from
    /// `now`, keeping the earlier rounds' ids so their replies still count. For an ICE restart that
    /// comes while the transaction runs: see the module docs, «An ICE restart continues it».
    ///
    /// A server still resolving starts its first round when it resolves; one that has stopped (an
    /// error response, no address, DNS) stays stopped. The transaction's life runs from `now`.
    /// Returns how many servers were renewed.
    pub(crate) fn renew(&mut self, now: Instant) -> usize {
        let mut renewed = 0;
        for (i, s) in self.servers.iter_mut().enumerate() {
            if !matches!(s.state, State::Querying(_)) || s.sent == 0 {
                continue;
            }
            if s.txids.len() >= MAX_ROUNDS {
                s.txids.remove(0);
                // A reply to the forgotten id is passed on as not ours; str0m drops it as a
                // response to nothing it sent.
                tracing::debug!(
                    server = %s.name,
                    round = s.round + 1,
                    kept = MAX_ROUNDS - 1,
                    "STUN: the oldest round's transaction id is forgotten to keep the rounds in \
                     flight at the limit"
                );
            }
            s.txids.push(random_txid(i));
            s.round += 1;
            s.sent = 0;
            s.first_send = None;
            renewed += 1;
        }
        self.round_started = now;
        renewed
    }

    /// Record a finished lookup. A duplicate address is not queried twice.
    pub(crate) fn resolved(&mut self, idx: usize, res: Result<SocketAddr, String>) {
        if !matches!(
            self.servers.get(idx).map(|s| &s.state),
            Some(State::Resolving)
        ) {
            tracing::trace!(
                idx,
                "STUN lookup result for a server no longer resolving; ignored"
            );
            return;
        }
        // Every lookup's outcome at debug: a name that did not resolve, or resolved to a server
        // another URL already covers, is otherwise visible only in the final summary, and only if
        // the whole transaction failed.
        let name = self.servers[idx].name.as_str();
        let state = match res {
            Err(e) => {
                tracing::debug!(server = name, "STUN server lookup failed: {e}");
                State::Stopped(Stop::Dns(e))
            }
            Ok(addr) => match self
                .servers
                .iter()
                .find(|o| matches!(o.state, State::Querying(a) if a == addr))
            {
                Some(other) => {
                    tracing::debug!(
                        server = name,
                        %addr,
                        same_as = %other.name,
                        "STUN server resolves to one already queried; not asked twice"
                    );
                    State::Stopped(Stop::Duplicate(other.name.clone()))
                }
                None => {
                    tracing::debug!(server = name, %addr, "STUN server resolved");
                    State::Querying(addr)
                }
            },
        };
        self.servers[idx].state = state;
    }

    /// The next request that is due, if any. Call until `None`.
    pub(crate) fn poll_transmit(&mut self, now: Instant) -> Option<Transmit> {
        if now >= self.give_up_at() {
            return None;
        }
        for (idx, s) in self.servers.iter_mut().enumerate() {
            let State::Querying(to) = s.state else {
                continue;
            };
            if s.sent >= MAX_SENDS {
                continue;
            }
            let due = s
                .first_send
                .is_none_or(|first| now >= first + send_offset(s.sent));
            if !due {
                continue;
            }
            let Some(txid) = s.txids.last().copied() else {
                // Unreachable: a server is made with one id and `renew` only ever adds one.
                continue;
            };
            s.first_send.get_or_insert(now);
            s.sent += 1;
            s.sent_total += 1;
            // At most `MAX_SENDS` per server and round, a few servers per session: the schedule
            // itself, in the log, is what makes "the request never went out" tellable from "no
            // reply came".
            tracing::debug!(
                server = %s.name,
                %to,
                attempt = s.sent,
                of = MAX_SENDS,
                round = s.round,
                "STUN binding request"
            );
            return Some(Transmit {
                idx,
                to,
                bytes: binding_request(&txid),
            });
        }
        None
    }

    /// The socket refused a send. Kept for the log; the schedule carries on.
    pub(crate) fn send_failed(&mut self, idx: usize, err: String) {
        if let Some(s) = self.servers.get_mut(idx) {
            tracing::debug!(server = %s.name, attempt = s.sent, "STUN request not sent: {err}");
            s.send_error = Some(err);
        }
    }

    /// A receive error ended a wait. Kept for the log.
    pub(crate) fn recv_failed(&mut self, err: String) {
        tracing::debug!("STUN receive failed: {err}");
        self.recv_error = Some(err);
    }

    /// When something next needs doing: a retransmission, or giving up.
    pub(crate) fn next_wake(&self) -> Instant {
        self.servers
            .iter()
            .filter_map(|s| match (&s.state, s.first_send) {
                (State::Querying(_), _) if s.sent >= MAX_SENDS => None,
                (State::Querying(_), Some(first)) => Some(first + send_offset(s.sent)),
                // Resolved, or renewed, and not sent in this round yet: due now.
                (State::Querying(_), None) => Some(self.round_started),
                _ => None,
            })
            .fold(self.give_up_at(), Instant::min)
    }

    /// Whether a lookup is still outstanding.
    pub(crate) fn has_unresolved(&self) -> bool {
        self.servers
            .iter()
            .any(|s| matches!(s.state, State::Resolving))
    }

    /// Nothing left to wait for: out of time, or every server has stopped.
    pub(crate) fn is_finished(&self, now: Instant) -> bool {
        now >= self.give_up_at()
            || self
                .servers
                .iter()
                .all(|s| matches!(s.state, State::Stopped(_)))
    }

    /// Match a datagram against the transaction.
    ///
    /// Only a Binding response carrying one of our transaction ids, from the server it was sent
    /// to, is ours. str0m's connectivity checks are Binding responses too — with str0m's ids — so
    /// matching on the message type alone would swallow ICE.
    pub(crate) fn handle_input(&mut self, from: SocketAddr, msg: &[u8]) -> Input {
        if msg.len() < 20 || msg[4..8] != MAGIC.to_be_bytes() {
            return Input::NotOurs;
        }
        let kind = u16::from_be_bytes([msg[0], msg[1]]);
        if kind != BINDING_SUCCESS && kind != BINDING_ERROR {
            return Input::NotOurs;
        }
        let Some((idx, id_at)) = self.servers.iter().enumerate().find_map(|(i, s)| {
            s.txids
                .iter()
                .position(|t| msg[8..20] == t[..])
                .map(|at| (i, at))
        }) else {
            return Input::NotOurs;
        };
        let server = &mut self.servers[idx];
        // Which round the reply answers: the current one, or one an ICE restart renewed.
        let reply_round = server.round - (server.txids.len() - 1 - id_at) as u32;
        let State::Querying(addr) = server.state else {
            tracing::trace!(server = %server.name, "STUN reply for a server already stopped");
            return Input::Consumed;
        };
        if from != addr {
            // Our transaction id from somewhere else: a spoof, or a server answering from another
            // address. Either way not a mapping to trust.
            tracing::debug!(
                server = %server.name,
                expected = %addr,
                %from,
                "STUN reply from an unexpected source; ignored"
            );
            return Input::Consumed;
        }
        if kind == BINDING_ERROR {
            let code = parse_error_code(msg).unwrap_or(0);
            // not-a-key-name: a STUN error code
            tracing::debug!(server = %server.name, code, "STUN error response; this server is done");
            server.state = State::Stopped(Stop::ErrorResponse(code));
            return Input::Consumed;
        }
        match parse_mapped_address(msg) {
            Some(mapped) => {
                tracing::debug!(
                    server = %server.name,
                    %mapped,
                    attempts = server.sent_total,
                    reply_round,
                    rounds = server.round,
                    "STUN reply with a mapped address"
                );
                Input::Mapped {
                    addr: mapped,
                    server: idx,
                }
            }
            None => {
                tracing::debug!(
                    server = %server.name,
                    bytes = msg.len(),
                    "STUN success without an IPv4 mapped address; this server is done"
                );
                server.state = State::Stopped(Stop::NoAddress);
                Input::Consumed
            }
        }
    }

    pub(crate) fn server_name(&self, idx: usize) -> &str {
        self.servers.get(idx).map_or("?", |s| s.name.as_str())
    }

    /// Requests sent so far, across all servers and rounds.
    pub(crate) fn attempts(&self) -> u32 {
        self.servers.iter().map(|s| s.sent_total).sum()
    }

    /// Since the discovery began, across rounds.
    pub(crate) fn elapsed_ms(&self, now: Instant) -> u64 {
        now.saturating_duration_since(self.began).as_millis() as u64
    }

    /// Until the transaction gives up, as it stands.
    pub(crate) fn left_ms(&self, now: Instant) -> u64 {
        self.give_up_at().saturating_duration_since(now).as_millis() as u64
    }

    /// One word for why no mapping arrived: `dns`, `recv_error`, `send_error`, `bad_response` or
    /// `timeout`. [`Self::describe`] has the detail.
    pub(crate) fn cause(&self) -> &'static str {
        let queried: Vec<&Server> = self
            .servers
            .iter()
            .filter(|s| {
                matches!(
                    s.state,
                    State::Querying(_) | State::Stopped(Stop::ErrorResponse(_) | Stop::NoAddress)
                )
            })
            .collect();
        if queried.is_empty() {
            "dns"
        } else if self.recv_error.is_some() {
            "recv_error"
        } else if queried.iter().all(|s| s.send_error.is_some()) {
            "send_error"
        } else if !queried
            .iter()
            .any(|s| matches!(s.state, State::Querying(_)))
        {
            "bad_response"
        } else {
            "timeout"
        }
    }

    /// Every server and what became of it, for a log line.
    pub(crate) fn describe(&self) -> String {
        let mut out = String::new();
        for (i, s) in self.servers.iter().enumerate() {
            if i > 0 {
                out.push_str("; ");
            }
            let _ = write!(out, "{} [", s.name);
            let _ = match &s.state {
                State::Resolving => write!(out, "dns pending"),
                State::Querying(addr) if s.round > 1 => write!(
                    out,
                    "{addr}: {} sent over {} rounds, no reply",
                    s.sent_total, s.round
                ),
                State::Querying(addr) => write!(out, "{addr}: {} sent, no reply", s.sent_total),
                State::Stopped(Stop::Dns(e)) => write!(out, "dns failed: {e}"),
                State::Stopped(Stop::Duplicate(other)) => write!(out, "same address as {other}"),
                State::Stopped(Stop::ErrorResponse(code)) => write!(out, "error response {code}"),
                State::Stopped(Stop::NoAddress) => write!(out, "reply without an IPv4 address"),
            };
            if let Some(e) = &s.send_error {
                let _ = write!(out, ", send failed: {e}");
            }
            out.push(']');
        }
        if self.servers.is_empty() {
            out.push_str("no servers");
        }
        if let Some(e) = &self.recv_error {
            let _ = write!(out, "; recv failed: {e}");
        }
        out
    }

    fn give_up_at(&self) -> Instant {
        self.round_started + lifetime()
    }
}

/// Drive `probe` on `socket` until it finds a mapping, runs out of things to try, or `deadline`.
///
/// For the phase before the answer, while nothing else reads the socket. Anything that is not a
/// reply to us is dropped here, which is safe for the same reason: the viewer cannot send
/// anything to this socket before it has the answer that names it.
///
/// On the peer's [`PeerSocket`], so under the bench link shaper these requests and replies are
/// shaped like everything else (a blackout silences the STUN servers too).
pub(crate) async fn run_until(
    socket: &mut PeerSocket,
    probe: &mut Probe,
    lookups: &mut mpsc::UnboundedReceiver<Resolved>,
    deadline: Instant,
) -> Option<Found> {
    let mut buf = [0u8; 1500];
    loop {
        let now = Instant::now();
        while let Ok((idx, res)) = lookups.try_recv() {
            probe.resolved(idx, res);
        }
        while let Some(t) = probe.poll_transmit(now) {
            if let Err(e) = socket.send_stun_to(&t.bytes, t.to).await {
                probe.send_failed(t.idx, e.to_string());
            }
        }
        if now >= deadline || probe.is_finished(now) {
            return None;
        }
        // Never a zero sleep: a wake that is already due has just been served above.
        let wake = probe
            .next_wake()
            .min(deadline)
            .max(now + Duration::from_millis(1));
        tokio::select! {
            () = tokio::time::sleep_until(wake.into()) => {}
            Some((idx, res)) = lookups.recv() => probe.resolved(idx, res),
            res = socket.recv_from(&mut buf) => match res {
                Ok((n, from)) => {
                    if let Input::Mapped { addr, server } = probe.handle_input(from, &buf[..n]) {
                        return Some(Found { addr, server: probe.server_name(server).to_string() });
                    }
                }
                // Windows reports an ICMP port-unreachable for an earlier send as a reset on the
                // next receive. That is one server saying no, not the socket failing.
                Err(e) if e.kind() == ErrorKind::ConnectionReset => {
                    tracing::debug!("STUN: a server's port is unreachable (reported as a reset)");
                }
                Err(e) => {
                    probe.recv_failed(e.to_string());
                    return None;
                }
            },
        }
    }
}

/// A Binding request: type, zero length, the cookie, the transaction id.
fn binding_request(txid: &[u8; 12]) -> [u8; 20] {
    let mut req = [0u8; 20];
    req[0..2].copy_from_slice(&BINDING_REQUEST.to_be_bytes());
    req[4..8].copy_from_slice(&MAGIC.to_be_bytes());
    req[8..20].copy_from_slice(txid);
    req
}

/// 96 unpredictable bits, from the standard library's randomly keyed hasher.
///
/// The id is what stops anyone off-path from answering for the STUN server and planting an address
/// of their choosing in our candidates, so it wants real randomness — `RandomState` is seeded from
/// the OS per process and re-keyed per instance, which is enough without adding a crate.
fn random_txid(salt: usize) -> [u8; 12] {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let state = RandomState::new();
    let mut h = state.build_hasher();
    h.write_usize(salt);
    h.write_u128(nanos);
    let a = h.finish();
    let mut h = state.build_hasher();
    h.write_u64(a);
    let b = h.finish();
    let mut txid = [0u8; 12];
    txid[..8].copy_from_slice(&a.to_be_bytes());
    txid[8..].copy_from_slice(&b.to_be_bytes()[..4]);
    txid
}

/// Walk the attributes of a STUN message: `(type, value)` pairs, padding skipped.
fn attributes(msg: &[u8]) -> impl Iterator<Item = (u16, &[u8])> {
    let mut i = 20; // past the header
    std::iter::from_fn(move || {
        let head = msg.get(i..i + 4)?;
        let kind = u16::from_be_bytes([head[0], head[1]]);
        let len = u16::from_be_bytes([head[2], head[3]]) as usize;
        let value = msg.get(i + 4..i + 4 + len)?;
        // Attributes are padded to a 4-byte boundary.
        i += 4 + len + (4 - len % 4) % 4;
        Some((kind, value))
    })
}

/// XOR-MAPPED-ADDRESS (0x0020) or MAPPED-ADDRESS (0x0001), IPv4 only.
fn parse_mapped_address(msg: &[u8]) -> Option<SocketAddr> {
    let magic = MAGIC.to_be_bytes();
    attributes(msg).find_map(|(kind, a)| {
        // Family byte at a[1]: 0x01 is IPv4, a 4-byte address after the 4-byte head.
        if (kind != ATTR_XOR_MAPPED_ADDRESS && kind != ATTR_MAPPED_ADDRESS)
            || a.len() < 8
            || a[1] != 0x01
        {
            return None;
        }
        let mut port = u16::from_be_bytes([a[2], a[3]]);
        let mut ip = [a[4], a[5], a[6], a[7]];
        if kind == ATTR_XOR_MAPPED_ADDRESS {
            port ^= (MAGIC >> 16) as u16;
            for (b, m) in ip.iter_mut().zip(magic) {
                *b ^= m;
            }
        }
        Some(SocketAddr::from((Ipv4Addr::from(ip), port)))
    })
}

/// ERROR-CODE (0x0009) as a number: class * 100 + number.
fn parse_error_code(msg: &[u8]) -> Option<u16> {
    attributes(msg).find_map(|(kind, a)| {
        (kind == ATTR_ERROR_CODE && a.len() >= 4)
            .then(|| u16::from(a[2] & 0x07) * 100 + u16::from(a[3]))
    })
}

/// A local STUN server for tests, playing the part of a lossy path.
#[cfg(test)]
pub(crate) mod test_server {
    use std::net::SocketAddr;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;

    use tokio::net::UdpSocket;

    use super::{BINDING_REQUEST, BINDING_SUCCESS, MAGIC};

    /// A Binding success response carrying `mapped` as XOR-MAPPED-ADDRESS.
    pub(crate) fn success(txid: &[u8], mapped: SocketAddr) -> Vec<u8> {
        let SocketAddr::V4(v4) = mapped else {
            panic!("IPv4 only");
        };
        let mut out = Vec::with_capacity(32);
        out.extend_from_slice(&BINDING_SUCCESS.to_be_bytes());
        out.extend_from_slice(&12u16.to_be_bytes());
        out.extend_from_slice(&MAGIC.to_be_bytes());
        out.extend_from_slice(txid);
        out.extend_from_slice(&0x0020u16.to_be_bytes());
        out.extend_from_slice(&8u16.to_be_bytes());
        out.push(0);
        out.push(0x01);
        out.extend_from_slice(&(v4.port() ^ (MAGIC >> 16) as u16).to_be_bytes());
        for (b, m) in v4.ip().octets().iter().zip(MAGIC.to_be_bytes()) {
            out.push(b ^ m);
        }
        out
    }

    /// Bind on loopback and answer Binding requests with `mapped`, after silently dropping the
    /// first `drop_first` of them. Returns the address and a count of requests received.
    pub(crate) async fn spawn(drop_first: u32, mapped: SocketAddr) -> (SocketAddr, Arc<AtomicU32>) {
        spawn_mappings(drop_first, vec![mapped]).await
    }

    /// [`spawn`], answering the k-th answered request with `mappings[k]` and every one after the
    /// list with its last entry: a NAT whose mapping changes between two discoveries.
    pub(crate) async fn spawn_mappings(
        drop_first: u32,
        mappings: Vec<SocketAddr>,
    ) -> (SocketAddr, Arc<AtomicU32>) {
        let socket = UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind stun server");
        let addr = socket.local_addr().expect("stun server addr");
        let seen = Arc::new(AtomicU32::new(0));
        let counter = seen.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 1500];
            let mut answered = 0usize;
            while let Ok((n, from)) = socket.recv_from(&mut buf).await {
                if n < 20 || buf[0..2] != BINDING_REQUEST.to_be_bytes() {
                    continue;
                }
                let k = counter.fetch_add(1, Ordering::SeqCst);
                if k < drop_first {
                    continue;
                }
                let Some(&mapped) = mappings.get(answered).or(mappings.last()) else {
                    continue;
                };
                answered += 1;
                let _ = socket.send_to(&success(&buf[8..20], mapped), from).await;
            }
        });
        (addr, seen)
    }

    /// Bind on loopback and answer the first `answer_first` Binding requests, each `delay` after it
    /// arrived, and no other: a path that delivers late rather than loses, as a VPN starved of CPU
    /// does. Returns the address and a count of requests received.
    pub(crate) async fn spawn_slow(
        answer_first: u32,
        delay: std::time::Duration,
        mapped: SocketAddr,
    ) -> (SocketAddr, Arc<AtomicU32>) {
        let socket = Arc::new(
            UdpSocket::bind("127.0.0.1:0")
                .await
                .expect("bind stun server"),
        );
        let addr = socket.local_addr().expect("stun server addr");
        let seen = Arc::new(AtomicU32::new(0));
        let counter = seen.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 1500];
            while let Ok((n, from)) = socket.recv_from(&mut buf).await {
                if n < 20 || buf[0..2] != BINDING_REQUEST.to_be_bytes() {
                    continue;
                }
                if counter.fetch_add(1, Ordering::SeqCst) >= answer_first {
                    continue;
                }
                let reply = success(&buf[8..20], mapped);
                let socket = socket.clone();
                tokio::spawn(async move {
                    tokio::time::sleep(delay).await;
                    let _ = socket.send_to(&reply, from).await;
                });
            }
        });
        (addr, seen)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::Ordering;

    use tokio::net::UdpSocket;

    use super::*;

    const MAPPED: &str = "203.0.113.7:40000";

    fn mapped() -> SocketAddr {
        MAPPED.parse().expect("addr")
    }

    /// A probe on a loopback socket, with `server` already resolved.
    async fn loopback_probe(
        servers: &[SocketAddr],
    ) -> (PeerSocket, Probe, mpsc::UnboundedReceiver<Resolved>) {
        let socket = PeerSocket::from(UdpSocket::bind("127.0.0.1:0").await.expect("bind"));
        let mut probe = Probe::new(
            servers.iter().map(|s| s.to_string()).collect(),
            Instant::now(),
        );
        for (i, s) in servers.iter().enumerate() {
            probe.resolved(i, Ok(*s));
        }
        let (_tx, rx) = mpsc::unbounded_channel();
        (socket, probe, rx)
    }

    #[test]
    fn the_schedule_is_rfc_8489_at_a_250_ms_rto() {
        let at: Vec<u128> = (0..MAX_SENDS).map(|k| send_offset(k).as_millis()).collect();
        assert_eq!(at, [0, 250, 750, 1750, 3750, 7750, 15750]);
        assert_eq!(lifetime(), Duration::from_millis(19_750));
        // The answer waits for three transmissions, and gives the third at least as long as the
        // slowest gather ever recorded (666 ms, DNS included).
        assert!(send_offset(2) < ANSWER_BUDGET && send_offset(3) > ANSWER_BUDGET);
        assert!(ANSWER_BUDGET - send_offset(2) >= Duration::from_millis(666));
    }

    #[test]
    fn a_relay_only_viewer_waits_for_five_transmissions() {
        // Five transmissions, the fifth given what the ordinary budget gives its third — and a
        // measured slow reply (fourth transmission, 1854 ms) well inside.
        assert!(
            send_offset(4) < RELAY_ONLY_ANSWER_BUDGET && send_offset(5) > RELAY_ONLY_ANSWER_BUDGET
        );
        assert!(RELAY_ONLY_ANSWER_BUDGET - send_offset(4) >= ANSWER_BUDGET - send_offset(2));
        assert!(RELAY_ONLY_ANSWER_BUDGET > Duration::from_millis(1_854));
        // A first answer and two held restart answers stay far inside the viewer's 30 s.
        assert!(ANSWER_BUDGET + RELAY_ONLY_ANSWER_BUDGET * 2 < Duration::from_secs(15));
    }

    #[test]
    fn a_renewed_round_asks_at_once_and_an_earlier_rounds_reply_still_counts() {
        let t0 = Instant::now();
        let server: SocketAddr = "192.0.2.1:3478".parse().expect("addr");
        let mut probe = Probe::new(vec![server.to_string()], t0);
        probe.resolved(0, Ok(server));
        let first = probe.poll_transmit(t0).expect("first");
        let second = probe.poll_transmit(t0 + RTO).expect("second");
        assert_eq!(first.bytes, second.bytes);

        // An ICE restart 300 ms in.
        let restart = t0 + Duration::from_millis(300);
        assert_eq!(probe.renew(restart), 1);
        let renewed = probe.poll_transmit(restart).expect("asked again at once");
        assert_ne!(
            renewed.bytes[8..20],
            first.bytes[8..20],
            "a new round, a new id"
        );
        assert!(probe.poll_transmit(restart).is_none());
        assert_eq!(
            probe.next_wake(),
            restart + RTO,
            "the round keeps RFC 8489's schedule"
        );
        assert_eq!(probe.attempts(), 3);
        assert_eq!(
            probe.elapsed_ms(restart),
            300,
            "elapsed counts from the discovery's start"
        );
        // A full lifetime from the restart, not from the start.
        assert!(!probe.is_finished(t0 + lifetime()));
        assert!(probe.is_finished(restart + lifetime()));
        let d = probe.describe();
        assert!(d.contains("3 sent over 2 rounds, no reply"), "{d}");

        // A reply to the first round, sent before the restart, is still the mapping — and so is
        // one to the new round.
        let late = test_server::success(&first.bytes[8..20], mapped());
        assert_eq!(
            probe.handle_input(server, &late),
            Input::Mapped {
                addr: mapped(),
                server: 0
            }
        );
        let fresh = test_server::success(&renewed.bytes[8..20], mapped());
        assert_eq!(
            probe.handle_input(server, &fresh),
            Input::Mapped {
                addr: mapped(),
                server: 0
            }
        );
    }

    #[test]
    fn renewing_keeps_four_rounds_and_leaves_unasked_servers_alone() {
        let t0 = Instant::now();
        let a: SocketAddr = "192.0.2.1:3478".parse().expect("addr");
        let mut probe = Probe::new(vec![a.to_string(), "b:3478".into(), "c:3478".into()], t0);
        probe.resolved(0, Ok(a));
        probe.resolved(2, Err("no such host".into()));
        // `b` is still resolving and `c` has stopped: only `a` has been asked.
        let mut ids = vec![probe.poll_transmit(t0).expect("round 1").bytes];
        for k in 1..=4u64 {
            let at = t0 + Duration::from_millis(100 * k);
            assert_eq!(probe.renew(at), 1, "only the server already asked");
            ids.push(probe.poll_transmit(at).expect("a new round").bytes);
            assert!(probe.poll_transmit(at).is_none());
        }
        // Five rounds asked, four remembered: the first round's reply is no longer ours.
        let reply = |id: &[u8; 20]| test_server::success(&id[8..20], mapped());
        assert_eq!(probe.handle_input(a, &reply(&ids[0])), Input::NotOurs);
        for id in &ids[1..] {
            assert!(matches!(
                probe.handle_input(a, &reply(id)),
                Input::Mapped { .. }
            ));
        }
        let d = probe.describe();
        assert!(
            d.contains("dns pending") && d.contains("dns failed") && d.contains("over 5 rounds"),
            "{d}"
        );

        // A server resolved after the renewals starts its first round there and then.
        let b: SocketAddr = "192.0.2.2:3478".parse().expect("addr");
        probe.resolved(1, Ok(b));
        let at = t0 + Duration::from_millis(450);
        let t = probe.poll_transmit(at).expect("b's first request");
        assert_eq!(t.to, b);
    }

    #[tokio::test]
    async fn a_slow_reply_to_a_request_sent_before_a_renewal_is_still_the_mapping() {
        // Replies take 600 ms, and an ICE restart comes 300 ms in. Only the
        // very first request is ever answered, so the mapping can only come from the round the
        // restart renewed.
        let (server, seen) = test_server::spawn_slow(1, Duration::from_millis(600), mapped()).await;
        let (mut socket, mut probe, mut rx) = loopback_probe(&[server]).await;
        let t0 = Instant::now();
        let early = t0 + Duration::from_millis(300);
        assert!(run_until(&mut socket, &mut probe, &mut rx, early)
            .await
            .is_none());
        assert_eq!(probe.renew(Instant::now()), 1);
        let found = run_until(
            &mut socket,
            &mut probe,
            &mut rx,
            t0 + Duration::from_secs(2),
        )
        .await
        .expect("the first round's reply");
        assert_eq!(found.addr, mapped());
        let took = t0.elapsed();
        assert!(
            took >= Duration::from_millis(590) && took < Duration::from_millis(1_200),
            "{took:?}"
        );
        assert!(
            seen.load(Ordering::SeqCst) >= 3,
            "rounds 1 and 2 both asked"
        );
    }

    #[test]
    fn picks_every_udp_stun_target_from_a_cloudflare_config() {
        // The shape `server/src/turn.ts` hands out, from Cloudflare's generate-ice-servers.
        let urls: Vec<String> = [
            "stun:stun.cloudflare.com:3478",
            "stun:stun.cloudflare.com:53",
            "turn:turn.cloudflare.com:3478?transport=udp",
            "turn:turn.cloudflare.com:3478?transport=tcp",
            "turns:turn.cloudflare.com:5349?transport=tcp",
            "turn:turn.cloudflare.com:53?transport=udp",
            "turn:turn.cloudflare.com:80?transport=tcp",
            "turns:turn.cloudflare.com:443?transport=tcp",
        ]
        .map(String::from)
        .to_vec();
        assert_eq!(
            stun_servers(&urls),
            [
                "stun.cloudflare.com:3478",
                "stun.cloudflare.com:53",
                "turn.cloudflare.com:3478",
                "turn.cloudflare.com:53",
            ]
        );
    }

    #[test]
    fn url_edge_cases() {
        let s = |u: &[&str]| stun_servers(&u.iter().map(|x| x.to_string()).collect::<Vec<_>>());
        // The dev fallback, and a URL without a port.
        assert_eq!(
            s(&["stun:stun.cloudflare.com:3478"]),
            ["stun.cloudflare.com:3478"]
        );
        assert_eq!(s(&["stun:example.org"]), ["example.org:3478"]);
        assert_eq!(s(&["turn:example.org"]), ["example.org:3478"]);
        assert_eq!(s(&["stun:[2001:db8::1]"]), ["[2001:db8::1]:3478"]);
        assert_eq!(s(&["stun:[2001:db8::1]:19302"]), ["[2001:db8::1]:19302"]);
        // Nothing a UDP socket can ask, and duplicates.
        assert!(s(&[
            "turns:x:443",
            "stuns:x:5349",
            "turn:x:80?transport=tcp",
            "stun:",
            "https://x"
        ])
        .is_empty());
        assert_eq!(s(&["stun:a:1", "stun:a:1", "turn:a:1"]), ["a:1"]);
    }

    #[test]
    fn parses_xor_and_plain_mapped_addresses() {
        let txid = [7u8; 12];
        let msg = test_server::success(&txid, mapped());
        assert_eq!(parse_mapped_address(&msg), Some(mapped()));

        let mut plain = msg.clone();
        plain[20..22].copy_from_slice(&ATTR_MAPPED_ADDRESS.to_be_bytes());
        plain[26..28].copy_from_slice(&40000u16.to_be_bytes());
        plain[28..32].copy_from_slice(&[203, 0, 113, 7]);
        assert_eq!(parse_mapped_address(&plain), Some(mapped()));

        for cut in 0..msg.len() {
            let _ = parse_mapped_address(&msg[..cut]);
        }
    }

    #[test]
    fn a_str0m_binding_response_is_not_ours() {
        // ICE connectivity checks come back as Binding success responses too. Only the id tells
        // them apart, and swallowing one would break ICE on the very sessions this is for.
        let server: SocketAddr = "192.0.2.1:3478".parse().expect("addr");
        let mut probe = Probe::new(vec![server.to_string()], Instant::now());
        probe.resolved(0, Ok(server));
        let t = probe.poll_transmit(Instant::now()).expect("a request");
        let ours = &t.bytes[8..20];

        let foreign = test_server::success(&[9u8; 12], mapped());
        assert_eq!(probe.handle_input(server, &foreign), Input::NotOurs);
        assert_eq!(
            probe.handle_input(server, b"\x80\x60\x00\x01 an RTP header, then media"),
            Input::NotOurs
        );

        // Ours, but from somewhere else: not trusted, and not handed to str0m either.
        let reply = test_server::success(ours, mapped());
        let elsewhere: SocketAddr = "192.0.2.99:3478".parse().expect("addr");
        assert_eq!(probe.handle_input(elsewhere, &reply), Input::Consumed);

        assert_eq!(
            probe.handle_input(server, &reply),
            Input::Mapped {
                addr: mapped(),
                server: 0
            }
        );
    }

    #[test]
    fn retransmissions_follow_the_schedule_and_reuse_the_id() {
        let t0 = Instant::now();
        let server: SocketAddr = "192.0.2.1:3478".parse().expect("addr");
        let mut probe = Probe::new(vec![server.to_string()], t0);
        assert!(probe.poll_transmit(t0).is_none(), "nothing before DNS");
        probe.resolved(0, Ok(server));

        let first = probe.poll_transmit(t0).expect("first");
        assert!(probe.poll_transmit(t0).is_none());
        assert_eq!(probe.next_wake(), t0 + RTO);
        assert!(probe
            .poll_transmit(t0 + Duration::from_millis(249))
            .is_none());
        let second = probe.poll_transmit(t0 + RTO).expect("second");
        assert_eq!(
            first.bytes, second.bytes,
            "a retransmission is the same request"
        );
        assert_eq!(probe.next_wake(), t0 + Duration::from_millis(750));

        // All seven, then silence until the transaction gives up.
        let mut sent = 2;
        while let Some(_t) = probe.poll_transmit(t0 + Duration::from_secs(19)) {
            sent += 1;
        }
        // At 19 s the offsets up to 15.75 s are all due, one per call.
        assert_eq!(sent, MAX_SENDS);
        assert_eq!(probe.attempts(), MAX_SENDS);
        assert!(!probe.is_finished(t0 + Duration::from_millis(19_749)));
        assert!(probe.is_finished(t0 + lifetime()));
        assert_eq!(probe.cause(), "timeout");
    }

    #[test]
    fn a_second_name_for_the_same_address_is_not_asked_twice() {
        let t0 = Instant::now();
        let addr: SocketAddr = "192.0.2.1:3478".parse().expect("addr");
        let mut probe = Probe::new(vec!["a:3478".into(), "b:3478".into(), "c:3478".into()], t0);
        probe.resolved(0, Ok(addr));
        probe.resolved(1, Ok(addr));
        probe.resolved(2, Err("no such host".into()));
        assert!(probe.poll_transmit(t0).is_some());
        assert!(probe.poll_transmit(t0).is_none(), "one request, not two");
        let d = probe.describe();
        assert!(d.contains("same address as a:3478"), "{d}");
        assert!(d.contains("dns failed: no such host"), "{d}");
    }

    #[test]
    fn an_error_response_stops_that_server_only() {
        let t0 = Instant::now();
        let a: SocketAddr = "192.0.2.1:3478".parse().expect("addr");
        let b: SocketAddr = "192.0.2.2:3478".parse().expect("addr");
        let mut probe = Probe::new(vec![a.to_string(), b.to_string()], t0);
        probe.resolved(0, Ok(a));
        probe.resolved(1, Ok(b));
        let ta = probe.poll_transmit(t0).expect("a");
        let _tb = probe.poll_transmit(t0).expect("b");

        // 420 Unknown Attribute, as class 4 number 20.
        let mut err = Vec::new();
        err.extend_from_slice(&BINDING_ERROR.to_be_bytes());
        err.extend_from_slice(&8u16.to_be_bytes());
        err.extend_from_slice(&MAGIC.to_be_bytes());
        err.extend_from_slice(&ta.bytes[8..20]);
        err.extend_from_slice(&ATTR_ERROR_CODE.to_be_bytes());
        err.extend_from_slice(&4u16.to_be_bytes());
        err.extend_from_slice(&[0, 0, 4, 20]);
        assert_eq!(probe.handle_input(a, &err), Input::Consumed);
        assert!(probe.describe().contains("error response 420"));
        assert!(!probe.is_finished(t0), "the other server is still in play");

        // Only b retransmits now.
        let next = probe.poll_transmit(t0 + RTO).expect("retransmit");
        assert_eq!(next.to, b);
        assert!(probe.poll_transmit(t0 + RTO).is_none());
    }

    #[test]
    fn dns_failure_everywhere_is_reported_as_dns() {
        let mut probe = Probe::new(vec!["a:3478".into()], Instant::now());
        assert!(
            !probe.is_finished(Instant::now()),
            "a lookup is still outstanding"
        );
        probe.resolved(0, Err("no such host".into()));
        assert!(probe.is_finished(Instant::now()));
        assert_eq!(probe.cause(), "dns");
    }

    #[tokio::test]
    async fn one_lost_datagram_no_longer_costs_the_mapping() {
        // The first request vanishes. The retransmission at 250 ms is what gets the answer its
        // srflx candidate.
        let (server, seen) = test_server::spawn(1, mapped()).await;
        let (mut socket, mut probe, mut rx) = loopback_probe(&[server]).await;
        let t0 = Instant::now();
        let found = run_until(&mut socket, &mut probe, &mut rx, t0 + ANSWER_BUDGET)
            .await
            .expect("a mapping within the budget");
        let took = t0.elapsed();
        assert_eq!(found.addr, mapped());
        assert_eq!(found.server, server.to_string());
        assert_eq!(probe.attempts(), 2);
        assert_eq!(seen.load(Ordering::SeqCst), 2);
        assert!(
            took >= Duration::from_millis(240) && took < Duration::from_millis(740),
            "{took:?}"
        );
    }

    #[tokio::test]
    async fn two_lost_datagrams_are_still_inside_the_budget() {
        let (server, _seen) = test_server::spawn(2, mapped()).await;
        let (mut socket, mut probe, mut rx) = loopback_probe(&[server]).await;
        let t0 = Instant::now();
        let found = run_until(&mut socket, &mut probe, &mut rx, t0 + ANSWER_BUDGET).await;
        assert_eq!(found.map(|f| f.addr), Some(mapped()));
        assert_eq!(probe.attempts(), 3);
        assert!(t0.elapsed() >= Duration::from_millis(740));
    }

    #[tokio::test]
    async fn a_dead_path_ends_at_the_budget_and_the_transaction_goes_on() {
        // Three requests lost: the answer cannot wait for the fourth. The same probe, driven
        // further, still gets it — which is what the peer loop does after the answer is sent.
        let (server, seen) = test_server::spawn(3, mapped()).await;
        let (mut socket, mut probe, mut rx) = loopback_probe(&[server]).await;
        let t0 = Instant::now();
        assert!(
            run_until(&mut socket, &mut probe, &mut rx, t0 + ANSWER_BUDGET)
                .await
                .is_none()
        );
        let waited = t0.elapsed();
        assert!(
            waited >= ANSWER_BUDGET && waited < ANSWER_BUDGET + Duration::from_millis(300),
            "{waited:?}"
        );
        assert_eq!(probe.attempts(), 3);
        assert!(!probe.is_finished(Instant::now()));
        assert_eq!(probe.cause(), "timeout");
        assert!(
            probe.describe().contains("3 sent, no reply"),
            "{}",
            probe.describe()
        );

        let late = run_until(
            &mut socket,
            &mut probe,
            &mut rx,
            t0 + Duration::from_secs(3),
        )
        .await
        .expect("the fourth transmission, at 1750 ms, is answered");
        assert_eq!(late.addr, mapped());
        assert_eq!(seen.load(Ordering::SeqCst), 4);
        assert!(t0.elapsed() >= Duration::from_millis(1_740));
    }

    #[tokio::test]
    async fn a_second_server_answers_when_the_first_is_dead() {
        let (dead, _) = test_server::spawn(u32::MAX, mapped()).await;
        let (alive, _) = test_server::spawn(0, mapped()).await;
        let (mut socket, mut probe, mut rx) = loopback_probe(&[dead, alive]).await;
        let found = run_until(
            &mut socket,
            &mut probe,
            &mut rx,
            Instant::now() + ANSWER_BUDGET,
        )
        .await
        .expect("the live server answers the first round");
        assert_eq!(found.server, alive.to_string());
    }

    #[tokio::test]
    async fn names_are_resolved_before_they_are_asked() {
        let (server, _) = test_server::spawn(0, mapped()).await;
        let mut socket = PeerSocket::from(UdpSocket::bind("127.0.0.1:0").await.expect("bind"));
        let mut probe = Probe::new(vec![server.to_string()], Instant::now());
        let mut lookups = spawn_lookups(&probe);
        let found = run_until(
            &mut socket,
            &mut probe,
            &mut lookups,
            Instant::now() + ANSWER_BUDGET,
        )
        .await;
        assert_eq!(found.map(|f| f.addr), Some(mapped()));
    }

    #[tokio::test]
    async fn the_link_shaper_carries_the_transaction_and_a_blackout_silences_it() {
        use crate::shaper::{EgressProfile, IngressProfile, LinkProfile, LinkShaper};

        let (server, seen) = test_server::spawn(0, mapped()).await;
        // 80 ms each way: the mapping still comes, one round trip later.
        let delayed = LinkProfile {
            egress: EgressProfile {
                delay_ms: 80,
                ..EgressProfile::default()
            },
            ingress: IngressProfile {
                delay_ms: 80,
                ..IngressProfile::default()
            },
            ..LinkProfile::default()
        };
        let shaper = LinkShaper::new(delayed);
        let bound = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
        let mut socket = PeerSocket::new(bound, Some(shaper.clone())).expect("shaped socket");
        let (_tx, mut rx) = mpsc::unbounded_channel();

        let t0 = Instant::now();
        let mut probe = Probe::new(vec![server.to_string()], t0);
        probe.resolved(0, Ok(server));
        let found = run_until(&mut socket, &mut probe, &mut rx, t0 + ANSWER_BUDGET)
            .await
            .expect("a mapping through the shaper");
        assert_eq!(found.addr, mapped());
        let took = t0.elapsed();
        assert!(
            took >= Duration::from_millis(155) && took < Duration::from_millis(250),
            "{took:?}"
        );
        assert_eq!(
            probe.attempts(),
            1,
            "the reply beat the first retransmission"
        );

        // A blackout is a real one: not a single request reaches the STUN server.
        assert!(shaper.set_profile(
            LinkProfile {
                blackout: true,
                ..LinkProfile::default()
            },
            "test"
        ));
        let before = seen.load(Ordering::SeqCst);
        let t0 = Instant::now();
        let mut probe = Probe::new(vec![server.to_string()], t0);
        probe.resolved(0, Ok(server));
        let deadline = t0 + Duration::from_millis(800);
        assert!(run_until(&mut socket, &mut probe, &mut rx, deadline)
            .await
            .is_none());
        assert_eq!(probe.attempts(), 3, "0, 250 and 750 ms all went out");
        assert_eq!(
            seen.load(Ordering::SeqCst),
            before,
            "and none of them arrived"
        );
    }
}
