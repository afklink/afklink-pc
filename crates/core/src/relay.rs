//! The agent's one outgoing queue to the backend, and the task that carries it across signaling
//! reconnects.
//!
//! Every message for the backend — from the orchestrator, from a session's telemetry task, from a
//! session's event task (late local candidates, the answer to a viewer's ICE restart) — goes into
//! one outbox that lives as long as the agent. [`Relay`] forwards it to whichever signaling
//! connection is current, and holds what cannot go while there is none.
//!
//! It exists because a session outlives the connection it started on: the media is peer-to-peer,
//! so a WebSocket that drops and comes back must not take the session's signaling with it. Before
//! this, each session's tasks kept the sender of the connection that was current when the session
//! started and, after a reconnect, sent into a channel nobody read: the answer to the viewer's ICE
//! restart was lost, so were late srflx candidates, stats (the telemetry task stopped for good), and
//! the ends of sessions that ended while signaling was down.
//!
//! While no connection is up, every message is held (in order, at most [`HOLD_CAP`]) or dropped,
//! by kind: see [`class`]. What a dying connection had been given but had not written comes back
//! from its pump ([`afklink_transport::Signaling::unsent`]) and goes to the front of the held queue.
//!
//! **Final reports.** A session's last `session_stats` (`"final": true`) is held like its end, but
//! only while the server would still take it: for [`FINAL_HOLD`] (the server's tombstone,
//! `SESSION_TOMBSTONE_MS`) from the moment it reached the relay. A held final older than that is
//! dropped, with a line, when the next connection comes up — past it the server stores nothing and
//! answers `unknown_session`. Ordinary reports are still dropped while down: the next one says it all.
//!
//! **Ordering.** Link changes travel on their own channel, so before forwarding each outbox message
//! the relay first applies every link change already sent. The orchestrator sends `Up` before
//! anything it produces on that connection — the PC's name, the re-announce of each live session —
//! so by the time such a message reaches the relay, the link it belongs to is installed, and it is
//! not dropped as "offline". (The `pong` that answers the backend's heartbeat does not come through
//! here: the connection's pump answers it itself, so a busy orchestrator cannot get the socket
//! reaped.) The converse is harmless: a message still waiting in the
//! outbox when an `Up` is applied — the relay was busy, say waiting for a hand-back — goes to the
//! new connection after everything held, which is older, and before anything sent after it.

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

use tokio::sync::{mpsc, oneshot};

use afklink_transport::AgentToServer;

/// Messages held while signaling is down, at most. Past it the oldest are dropped, with one warn per
/// outage. An ordinary outage holds a handful (an answer, a few candidates, a session end); this is
/// a bound on a pathology, not a budget.
pub(crate) const HOLD_CAP: usize = 256;

/// How long a session's final report is worth holding: the server's tombstone, which takes a late
/// final for this long after the session ended (`afklink_protocol::SESSION_TOMBSTONE_MS`). Counted from when the final reached the relay — the session's end.
pub(crate) const FINAL_HOLD: Duration =
    Duration::from_millis(afklink_protocol::SESSION_TOMBSTONE_MS);

/// How long a retired connection's pump gets to hand back what it had been given but not written.
///
/// Normally no wait at all: the orchestrator retires a link once its `incoming` has ended, which
/// the pump does only after handing back. The bound is for a pump stuck in a write on a dead socket.
pub(crate) const HANDBACK_WAIT: Duration = Duration::from_secs(1);

/// One signaling connection, as the relay sees it.
pub(crate) struct Link {
    /// Counts connections, for log lines and for telling a stale `Down` from a current one.
    pub(crate) id: u64,
    /// The connection pump's queue ([`afklink_transport::Signaling::outgoing`]).
    pub(crate) tx: mpsc::UnboundedSender<AgentToServer>,
    /// What the pump had not written when it exited ([`afklink_transport::Signaling::unsent`]).
    pub(crate) unsent: oneshot::Receiver<Vec<AgentToServer>>,
}

/// Sent by the orchestrator as connections come and go.
pub(crate) enum LinkChange {
    /// Authenticated and serving. Sent before anything is produced on it; see the module docs.
    Up(Link),
    /// The connection ended (its `incoming` closed). A `Down` for a link that is no longer current
    /// — already retired after a refused send — is ignored.
    Down { id: u64 },
    /// Forward everything already in the outbox now, then answer: what the orchestrator put in it
    /// before sending this is in the current connection's pump queue (or held, or dropped) when the
    /// answer comes. The exit's session ends use it so the goodbye — which writes the pump's queue
    /// first — carries them (`Agent::end_all_for_exit`).
    Barrier(oneshot::Sender<Flushed>),
}

/// What a [`LinkChange::Barrier`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Flushed {
    /// Messages taken from the outbox for it.
    pub(crate) drained: u64,
    /// The connection they went to, `None` when none was up (held or dropped by kind).
    pub(crate) link: Option<u64>,
}

/// What becomes of a message that arrives while no connection is up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Class {
    /// Delivered, in order, on the next connection.
    Hold,
    /// Dropped with a count: by the time a connection is back it would be stale or harmful.
    Drop,
}

/// Hold or drop, by kind. Exhaustive on purpose: a new message kind has to be decided here.
pub(crate) fn class(msg: &AgentToServer) -> Class {
    match msg {
        // A session's own signaling: the answer to an ICE restart, a late srflx candidate (the only
        // one a relay-only viewer can use), and a session's end, which the backend otherwise only
        // learns from its own timeout. Owner revocations: an unbind or a closed pairing panel is
        // the PC owner's choice and must not evaporate because the network blinked. A request to the
        // owner and its withdrawal likewise: a person pressed it, and
        // the row says «Ждём подтверждения» until the server answers.
        AgentToServer::Sdp { .. }
        | AgentToServer::Ice { .. }
        | AgentToServer::SessionEnd { .. }
        | AgentToServer::Unbind { .. }
        | AgentToServer::OwnerRequest { .. }
        | AgentToServer::OwnerRequestCancel { .. }
        | AgentToServer::PairingCancel => Class::Hold,
        // A session's final report: nothing comes after it, so a dropped one is the session's last
        // numbers lost. Held — for [`FINAL_HOLD`] at most (`Relay::expire_finals`).
        AgentToServer::SessionStats { is_final: true, .. } => Class::Hold,
        // Something that happened on the PC (contract v2): dropped here, because it is not lost —
        // the agent keeps its events on disk until a connection stayed up after one
        // (`crate::agent_events`), and sends the queue on every new connection. Held here as well,
        // it would go twice on the next one.
        //
        // Stats are cumulative, so the next report says everything the dropped one did; the
        // re-announce after the reconnect is one. A `pong` answers a ping on a dead connection.
        // A pairing code requested now would appear after the panel may have closed, and a pair
        // request is cancelled by the backend when the agent's socket closes. The PC's name opens
        // every connection (`Agent::announce_after_connect`), so a rename made offline arrives with
        // the next one. The handshake frames never come through here (the transport sends them
        // itself), nor does the goodbye (`afklink_transport::GoodbyeHandle`, `crate::goodbye`),
        // which belongs to the connection it closes: on the next one it would say the opposite of
        // what that connection means.
        AgentToServer::AgentEvent(_)
        | AgentToServer::SessionStats { .. }
        | AgentToServer::Pong
        | AgentToServer::RequestPairing
        | AgentToServer::PairResponse { .. }
        | AgentToServer::DeviceName { .. }
        | AgentToServer::AgentHello { .. }
        | AgentToServer::AgentAuth { .. }
        | AgentToServer::AgentGoodbye { .. } => Class::Drop,
    }
}

/// What the relay did, over one outage or over its whole life.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Tally {
    /// Handed straight to a live connection.
    pub(crate) forwarded: u64,
    /// Put in the held queue (including what a dying pump handed back).
    pub(crate) held: u64,
    /// Held messages handed to a later connection.
    pub(crate) delivered: u64,
    /// Messages a dying pump handed back, before classification.
    pub(crate) handed_back: u64,
    pub(crate) dropped_stats: u64,
    pub(crate) dropped_other: u64,
    /// Held messages dropped because the queue was full.
    pub(crate) overflowed: u64,
    /// Final reports dropped because they had been held past [`FINAL_HOLD`].
    pub(crate) finals_expired: u64,
}

/// The relay task's state. Create with [`Relay::new`] and spawn [`Relay::run`].
pub(crate) struct Relay {
    outbox: mpsc::UnboundedReceiver<AgentToServer>,
    links: mpsc::UnboundedReceiver<LinkChange>,
    link: Option<Link>,
    held: VecDeque<AgentToServer>,
    /// When the current outage began (the relay's creation, before the first connection).
    down_since: Instant,
    /// Connections installed so far, to tell the first from a reconnect in the log.
    links_seen: u64,
    /// This outage, reported when the next connection comes up.
    outage: Tally,
    /// The relay's whole life, returned by [`Relay::run`].
    total: Tally,
    hold_cap: usize,
    handback_wait: Duration,
    /// When each session's final report reached the relay: what dates it against
    /// [`Self::final_hold`], whether it is held now or comes back from a dying pump later.
    finals: HashMap<String, Instant>,
    /// [`FINAL_HOLD`], shorter only in tests.
    final_hold: Duration,
}

impl Relay {
    pub(crate) fn new(
        outbox: mpsc::UnboundedReceiver<AgentToServer>,
        links: mpsc::UnboundedReceiver<LinkChange>,
    ) -> Self {
        Self::with_limits(outbox, links, HOLD_CAP, HANDBACK_WAIT)
    }

    pub(crate) fn with_limits(
        outbox: mpsc::UnboundedReceiver<AgentToServer>,
        links: mpsc::UnboundedReceiver<LinkChange>,
        hold_cap: usize,
        handback_wait: Duration,
    ) -> Self {
        Relay {
            outbox,
            links,
            link: None,
            held: VecDeque::new(),
            down_since: Instant::now(),
            links_seen: 0,
            outage: Tally::default(),
            total: Tally::default(),
            hold_cap,
            handback_wait,
            finals: HashMap::new(),
            final_hold: FINAL_HOLD,
        }
    }

    /// [`Self::with_limits`] with a final report's hold shortened, for the tests.
    #[cfg(test)]
    fn with_final_hold(mut self, final_hold: Duration) -> Self {
        self.final_hold = final_hold;
        self
    }

    /// Forward until the orchestrator is gone (no connection can ever come again) or every outbox
    /// sender is. Returns what it did, for the tests and the last log line.
    pub(crate) async fn run(mut self) -> Tally {
        tracing::debug!(
            hold_cap = self.hold_cap,
            handback_wait_ms = self.handback_wait.as_millis() as u64,
            "signaling relay started"
        );
        let why = loop {
            tokio::select! {
                // Link changes first whenever both are ready; the drain below covers the rest.
                biased;
                change = self.links.recv() => match change {
                    Some(change) => self.apply(change).await,
                    None => break "the orchestrator is gone",
                },
                msg = self.outbox.recv() => match msg {
                    Some(msg) => {
                        self.take_link_changes().await;
                        self.forward(msg).await;
                    }
                    None => break "every outbox sender is gone",
                },
            }
        };
        tracing::debug!(
            why,
            connected = self.link.is_some(),
            held_discarded = self.held.len(),
            total = ?self.total,
            "signaling relay stopped"
        );
        self.total
    }

    /// Every link change already sent, applied before the message that follows it. This is the
    /// ordering rule in the module docs: a `pong` sent after `Up` must find the link installed.
    async fn take_link_changes(&mut self) {
        while let Ok(change) = self.links.try_recv() {
            self.apply(change).await;
        }
    }

    async fn apply(&mut self, change: LinkChange) {
        match change {
            LinkChange::Up(link) => {
                if let Some(old) = self.link.as_ref().map(|l| l.id) {
                    // The orchestrator sends `Down` whenever a connection's serve loop ends, so this
                    // should not happen; handled rather than trusted.
                    tracing::warn!(
                        old,
                        new = link.id,
                        "a signaling link came up while another was still current: retiring the \
                         old one first"
                    );
                    self.retire("replaced by a newer link").await;
                }
                self.install(link).await;
            }
            LinkChange::Down { id } => match self.link.as_ref().map(|l| l.id) {
                Some(current) if current == id => self.retire("its connection ended").await,
                current => tracing::debug!(
                    id,
                    ?current,
                    "down for a signaling link that is not current (already retired): ignored"
                ),
            },
            LinkChange::Barrier(done) => {
                let mut drained = 0u64;
                while let Ok(msg) = self.outbox.try_recv() {
                    self.forward(msg).await;
                    drained += 1;
                }
                let flushed = Flushed {
                    drained,
                    link: self.link.as_ref().map(|l| l.id),
                };
                tracing::debug!(
                    drained,
                    link = ?flushed.link,
                    held = self.held.len(),
                    "signaling relay: barrier — everything queued before it is forwarded"
                );
                if done.send(flushed).is_err() {
                    tracing::debug!("signaling relay: the barrier's asker stopped waiting");
                }
            }
        }
    }

    /// Note when a session's final report reached the relay (the first time only: a final handed
    /// back by a dying pump keeps its first date), and forget the dates of finals long gone.
    fn note_final(&mut self, msg: &AgentToServer) {
        if !msg.is_final_report() {
            return;
        }
        let now = Instant::now();
        let forget_after = self.final_hold.saturating_mul(2);
        self.finals
            .retain(|_, at| now.saturating_duration_since(*at) <= forget_after);
        if let Some(session) = msg.session_id() {
            self.finals.entry(session.to_string()).or_insert(now);
        }
    }

    /// Drop every held final report held longer than [`Self::final_hold`]: the server would store
    /// nothing of it now and answer `unknown_session`. A final with no date (forgotten: past twice
    /// the window) is past it too.
    fn expire_finals(&mut self) {
        if !self.held.iter().any(AgentToServer::is_final_report) {
            return;
        }
        let now = Instant::now();
        let mut kept = VecDeque::with_capacity(self.held.len());
        while let Some(msg) = self.held.pop_front() {
            if !msg.is_final_report() {
                kept.push_back(msg);
                continue;
            }
            let session = msg.session_id().unwrap_or("-").to_string();
            let age = self
                .finals
                .get(&session)
                .map(|at| now.saturating_duration_since(*at));
            match age {
                Some(age) if age <= self.final_hold => {
                    tracing::debug!(
                        session = %session,
                        held_ms = age.as_millis() as u64,
                        window_ms = self.final_hold.as_millis() as u64,
                        "final session report still within the server's window: delivered"
                    );
                    kept.push_back(msg);
                }
                _ => {
                    self.finals.remove(&session);
                    self.count(|t| t.finals_expired += 1);
                    tracing::info!(
                        session = %session,
                        held_ms = age.map(|a| a.as_millis() as u64),
                        window_ms = self.final_hold.as_millis() as u64,
                        "final session report dropped: held past the server's window for late \
                         reports (it would store nothing)"
                    );
                }
            }
        }
        self.held = kept;
    }

    /// Make `link` current and deliver everything held, in order.
    async fn install(&mut self, link: Link) {
        let id = link.id;
        let down_ms = self.down_since.elapsed().as_millis() as u64;
        self.expire_finals();
        let waiting = self.held.len();
        let outage = std::mem::take(&mut self.outage);
        self.links_seen += 1;
        let first = self.links_seen == 1;
        let mut refused = false;
        let mut delivered = 0u64;
        while let Some(msg) = self.held.pop_front() {
            match link.tx.send(msg) {
                Ok(()) => delivered += 1,
                Err(mpsc::error::SendError(msg)) => {
                    tracing::debug!(
                        link = id,
                        kind = msg.kind(),
                        session = msg.session_id().unwrap_or("-"),
                        "the new signaling link refused a held message: it is already gone"
                    );
                    self.held.push_front(msg);
                    refused = true;
                    break;
                }
            }
        }
        self.total.delivered += delivered;
        self.link = Some(link);
        if outage == Tally::default() && waiting == 0 {
            tracing::debug!(
                link = id,
                first,
                down_ms,
                "signaling link up; nothing was held or dropped while it was down"
            );
        } else {
            tracing::info!(
                link = id,
                first,
                down_ms,
                delivered,
                held = outage.held,
                handed_back = outage.handed_back,
                dropped_stats = outage.dropped_stats,
                dropped_other = outage.dropped_other,
                overflowed = outage.overflowed,
                finals_expired = outage.finals_expired,
                "signaling link up: what was held while it was down is delivered, in order"
            );
        }
        if refused {
            self.retire("it refused a held message").await;
        }
    }

    /// The current link is gone: take back what its pump had not written and hold it.
    async fn retire(&mut self, why: &'static str) {
        let Some(Link { id, tx, unsent }) = self.link.take() else {
            return;
        };
        // Dropped first: a pump still running sees its queue close, exits, and hands back.
        drop(tx);
        self.down_since = Instant::now();
        let returned = match tokio::time::timeout(self.handback_wait, unsent).await {
            Ok(Ok(returned)) => returned,
            Ok(Err(_)) => {
                tracing::debug!(
                    link = id,
                    "the signaling pump ended without handing anything back"
                );
                Vec::new()
            }
            Err(_) => {
                tracing::warn!(
                    link = id,
                    wait_ms = self.handback_wait.as_millis() as u64,
                    "the signaling pump did not hand back its unsent messages in time: whatever \
                     it still had is lost"
                );
                Vec::new()
            }
        };
        let handed_back = returned.len() as u64;
        // To the front, in their own order: they were given to the pump before anything held now.
        let mut front = Vec::with_capacity(returned.len());
        for msg in returned {
            match class(&msg) {
                Class::Hold => {
                    tracing::debug!(
                        link = id,
                        kind = msg.kind(),
                        session = msg.session_id().unwrap_or("-"),
                        "handed back unsent by the dying connection: held for the next one"
                    );
                    front.push(msg);
                }
                Class::Drop => self.dropped(&msg, "handed back unsent by the dying connection"),
            }
        }
        let kept = front.len() as u64;
        self.count(|t| {
            t.handed_back += handed_back;
            t.held += kept;
        });
        for msg in front.into_iter().rev() {
            self.held.push_front(msg);
        }
        self.enforce_cap();
        if handed_back > 0 || !self.held.is_empty() {
            tracing::info!(
                link = id,
                why,
                handed_back,
                held = self.held.len(),
                "signaling link retired: session messages are held until the next connection"
            );
        } else {
            tracing::debug!(
                link = id,
                why,
                "signaling link retired; nothing was in flight"
            );
        }
    }

    async fn forward(&mut self, msg: AgentToServer) {
        self.note_final(&msg);
        let Some(link) = self.link.as_ref() else {
            self.hold_or_drop(msg);
            return;
        };
        let id = link.id;
        match link.tx.send(msg) {
            // The pump logs every message it writes; one more line per message here would double
            // the signaling log for nothing.
            Ok(()) => self.total.forwarded += 1,
            Err(mpsc::error::SendError(msg)) => {
                tracing::debug!(
                    link = id,
                    kind = msg.kind(),
                    session = msg.session_id().unwrap_or("-"),
                    "the signaling pump refused a message: its connection is gone"
                );
                self.retire("its pump refused a message").await;
                self.hold_or_drop(msg);
            }
        }
    }

    fn hold_or_drop(&mut self, msg: AgentToServer) {
        match class(&msg) {
            Class::Hold => {
                tracing::debug!(
                    kind = msg.kind(),
                    session = msg.session_id().unwrap_or("-"),
                    final_report = msg.is_final_report(),
                    held = self.held.len() + 1,
                    "signaling is down: message held for the next connection"
                );
                self.held.push_back(msg);
                self.count(|t| t.held += 1);
                self.enforce_cap();
            }
            Class::Drop => self.dropped(&msg, "signaling is down"),
        }
    }

    fn dropped(&mut self, msg: &AgentToServer, when: &'static str) {
        let stats = matches!(msg, AgentToServer::SessionStats { .. });
        self.count(|t| {
            if stats {
                t.dropped_stats += 1;
            } else {
                t.dropped_other += 1;
            }
        });
        tracing::debug!(
            when,
            kind = msg.kind(),
            session = msg.session_id().unwrap_or("-"),
            "message dropped: it would be stale by the time a connection is back"
        );
    }

    fn enforce_cap(&mut self) {
        while self.held.len() > self.hold_cap {
            let Some(old) = self.held.pop_front() else {
                break;
            };
            self.count(|t| t.overflowed += 1);
            if self.outage.overflowed == 1 {
                tracing::warn!(
                    cap = self.hold_cap,
                    kind = old.kind(),
                    session = old.session_id().unwrap_or("-"),
                    "signaling has been down long enough to fill the hold queue: dropping the \
                     oldest held messages"
                );
            } else {
                tracing::debug!(
                    kind = old.kind(),
                    session = old.session_id().unwrap_or("-"),
                    "held message dropped: the hold queue is full"
                );
            }
        }
    }

    /// Count into this outage and into the lifetime total at once.
    fn count(&mut self, f: impl Fn(&mut Tally)) {
        f(&mut self.outage);
        f(&mut self.total);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use afklink_transport::{IceCandidate, SdpType};

    fn sdp(session: &str) -> AgentToServer {
        AgentToServer::Sdp {
            session_id: session.into(),
            sdp_type: SdpType::Answer,
            sdp: "v=0".into(),
        }
    }

    fn ice(session: &str, n: u32) -> AgentToServer {
        AgentToServer::Ice {
            session_id: session.into(),
            candidate: IceCandidate {
                candidate: format!("candidate:{n} 1 udp 1 10.0.0.1 9 typ host"),
                sdp_mid: None,
                sdp_mline_index: None,
                username_fragment: None,
            },
        }
    }

    fn end(session: &str) -> AgentToServer {
        AgentToServer::SessionEnd {
            session_id: session.into(),
            reason: Some("ice_timeout".into()),
            detail: None,
        }
    }

    /// A session's final report.
    fn final_stats(session: &str) -> AgentToServer {
        match stats(session) {
            AgentToServer::SessionStats {
                session_id, stats, ..
            } => AgentToServer::SessionStats {
                session_id,
                stats,
                is_final: true,
            },
            other => other,
        }
    }

    fn stats(session: &str) -> AgentToServer {
        AgentToServer::SessionStats {
            session_id: session.into(),
            stats: afklink_transport::AgentSessionStats {
                duration_ms: 1,
                source_w: 0,
                source_h: 0,
                frames_captured: 0,
                frames_encoded: 0,
                frames_dropped_stale: 0,
                frames_dropped_paced: 0,
                frames_skipped_encoder: 0,
                encode_ms_avg: 0.0,
                encode_ms_max: 0.0,
                bytes_sent: 0,
                lowest_height: 0,
                quality_changes: 0,
                estimate_kbps: None,
                encode_errors: 0,
                bg_hold_ms: Some(0),
                bg_holds: Some(0),
                summary: None,
            },
            is_final: false,
        }
    }

    /// What a test sees of a connection's pump: its queue and its hand-back.
    struct FakePump {
        rx: mpsc::UnboundedReceiver<AgentToServer>,
        handback: oneshot::Sender<Vec<AgentToServer>>,
    }

    impl FakePump {
        /// The pump exits the way the real one does: queue closed, then the hand-back.
        fn exit_handing_back(mut self, unsent: Vec<AgentToServer>) {
            self.rx.close();
            self.handback
                .send(unsent)
                .expect("the relay still holds the link");
        }
    }

    fn link(id: u64) -> (Link, FakePump) {
        let (tx, rx) = mpsc::unbounded_channel();
        let (handback, unsent) = oneshot::channel();
        (Link { id, tx, unsent }, FakePump { rx, handback })
    }

    struct Rig {
        outbox: mpsc::UnboundedSender<AgentToServer>,
        links: mpsc::UnboundedSender<LinkChange>,
        task: tokio::task::JoinHandle<Tally>,
    }

    impl Rig {
        fn new(hold_cap: usize, handback_wait: Duration) -> Self {
            Self::with_final_hold(hold_cap, handback_wait, FINAL_HOLD)
        }

        fn with_final_hold(hold_cap: usize, handback_wait: Duration, final_hold: Duration) -> Self {
            let (outbox, outbox_rx) = mpsc::unbounded_channel();
            let (links, links_rx) = mpsc::unbounded_channel();
            let relay = Relay::with_limits(outbox_rx, links_rx, hold_cap, handback_wait)
                .with_final_hold(final_hold);
            Rig {
                outbox,
                links,
                task: tokio::spawn(relay.run()),
            }
        }

        fn send(&self, msg: AgentToServer) {
            self.outbox.send(msg).expect("the relay is running");
        }

        fn up(&self, link: Link) {
            self.links
                .send(LinkChange::Up(link))
                .expect("the relay is running");
        }

        fn down(&self, id: u64) {
            self.links
                .send(LinkChange::Down { id })
                .expect("the relay is running");
        }

        /// Stop the relay the way the agent does (the orchestrator goes) and return its tally.
        async fn finish(self) -> Tally {
            drop(self.links);
            drop(self.outbox);
            tokio::time::timeout(Duration::from_secs(5), self.task)
                .await
                .expect("the relay stops once the orchestrator is gone")
                .expect("and does not panic")
        }
    }

    /// Let the relay take everything sent so far. On these single-threaded test runtimes the relay
    /// is the only other task, and it runs until it has nothing left while the test sleeps; so a
    /// test can make "this arrived while down" true before it sends `Up`. (Without it, a message
    /// and an `Up` both queued before the relay runs are taken `Up` first — correct, since nothing
    /// was held yet, but not the case the test is about.)
    async fn settle() {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    async fn recv(pump: &mut FakePump) -> AgentToServer {
        tokio::time::timeout(Duration::from_secs(5), pump.rx.recv())
            .await
            .expect("a message in time")
            .expect("the relay still holds the link")
    }

    async fn recv_n(pump: &mut FakePump, n: usize) -> Vec<AgentToServer> {
        let mut out = Vec::with_capacity(n);
        for _ in 0..n {
            out.push(recv(pump).await);
        }
        out
    }

    /// Nothing more arrives on `pump` for a moment.
    async fn quiet(pump: &mut FakePump) {
        match tokio::time::timeout(Duration::from_millis(100), pump.rx.recv()).await {
            Err(_) => {}
            Ok(msg) => panic!("expected nothing more, got {msg:?}"),
        }
    }

    /// 1. While a connection is up everything goes straight to it, in order, whatever its kind.
    #[tokio::test]
    async fn forwards_everything_in_order_while_up() {
        let rig = Rig::new(HOLD_CAP, HANDBACK_WAIT);
        let (l1, mut p1) = link(1);
        rig.up(l1);
        let sent = vec![
            sdp("s1"),
            ice("s1", 1),
            stats("s1"),
            AgentToServer::Pong,
            end("s1"),
        ];
        for m in &sent {
            rig.send(m.clone());
        }
        assert_eq!(recv_n(&mut p1, sent.len()).await, sent);
        let total = rig.finish().await;
        assert_eq!(total.forwarded, 5);
        assert_eq!(total.held, 0);
    }

    /// 2. While down, session signaling and owner revocations are held and delivered in order on
    /// the next connection; stats, pongs and pairing requests are dropped and counted.
    #[tokio::test]
    async fn while_down_holds_session_signaling_and_drops_the_stale_kinds() {
        let rig = Rig::new(HOLD_CAP, HANDBACK_WAIT);
        // No connection yet: the relay starts down.
        let sent = vec![
            sdp("s1"),
            stats("s1"),
            ice("s1", 1),
            AgentToServer::Pong,
            end("s2"),
            AgentToServer::RequestPairing,
            AgentToServer::PairResponse {
                request_id: "r".into(),
                accept: true,
                name: Some("PC".into()),
                role: Some(afklink_protocol::BindingRole::Guest),
            },
            AgentToServer::Unbind {
                telegram_user_id: 7,
            },
            AgentToServer::PairingCancel,
        ];
        for m in &sent {
            rig.send(m.clone());
        }
        settle().await;
        let (l1, mut p1) = link(1);
        rig.up(l1);
        let expected = vec![
            sdp("s1"),
            ice("s1", 1),
            end("s2"),
            AgentToServer::Unbind {
                telegram_user_id: 7,
            },
            AgentToServer::PairingCancel,
        ];
        assert_eq!(recv_n(&mut p1, expected.len()).await, expected);
        quiet(&mut p1).await;
        let total = rig.finish().await;
        assert_eq!(total.held, 5);
        assert_eq!(total.delivered, 5);
        assert_eq!(total.dropped_stats, 1);
        assert_eq!(total.dropped_other, 3);
    }

    /// 3. A pump that went away is noticed by the send it refuses, before the orchestrator says so;
    /// that message is held, not lost, and so is the one after it.
    #[tokio::test]
    async fn a_refused_send_retires_the_link_and_the_message_is_held() {
        let rig = Rig::new(HOLD_CAP, HANDBACK_WAIT);
        let (l1, p1) = link(1);
        rig.up(l1);
        settle().await;
        p1.exit_handing_back(Vec::new());
        rig.send(sdp("s1"));
        rig.send(ice("s1", 1));
        rig.send(stats("s1"));
        settle().await;
        // The orchestrator's `Down` arrives after the relay already retired the link: ignored.
        rig.down(1);
        let (l2, mut p2) = link(2);
        rig.up(l2);
        assert_eq!(recv_n(&mut p2, 2).await, vec![sdp("s1"), ice("s1", 1)]);
        quiet(&mut p2).await;
        let total = rig.finish().await;
        assert_eq!(
            (total.held, total.delivered, total.dropped_stats),
            (2, 2, 1)
        );
    }

    /// 4. What the dying pump had been given but not written comes back ahead of everything held
    /// after it — typically the answer produced by the very network change that killed the socket.
    #[tokio::test]
    async fn the_pumps_hand_back_goes_ahead_of_later_held_messages() {
        let rig = Rig::new(HOLD_CAP, HANDBACK_WAIT);
        let (l1, mut p1) = link(1);
        rig.up(l1);
        rig.send(sdp("s1"));
        rig.send(ice("s1", 1));
        rig.send(stats("s1"));
        // The pump had these queued when its socket died: it never wrote them.
        let unsent = recv_n(&mut p1, 3).await;
        p1.exit_handing_back(unsent);
        rig.send(ice("s1", 2));
        rig.send(end("s1"));
        settle().await;
        let (l2, mut p2) = link(2);
        rig.up(l2);
        assert_eq!(
            recv_n(&mut p2, 4).await,
            vec![sdp("s1"), ice("s1", 1), ice("s1", 2), end("s1")]
        );
        quiet(&mut p2).await;
        let total = rig.finish().await;
        assert_eq!(total.handed_back, 3);
        assert_eq!(
            total.dropped_stats, 1,
            "the handed-back stats are stale too"
        );
    }

    /// A pump that never hands back costs its unsent messages, not the relay: it waits the bounded
    /// time, says so, and holds what arrives after.
    #[tokio::test]
    async fn a_pump_that_never_hands_back_is_waited_for_a_bounded_time() {
        let rig = Rig::new(HOLD_CAP, Duration::from_millis(50));
        let (l1, p1) = link(1);
        rig.up(l1);
        settle().await;
        let FakePump { mut rx, handback } = p1;
        rx.close();
        rig.send(sdp("s1"));
        rig.send(ice("s1", 1));
        // Longer than the hand-back wait, so both are held before the next link comes up.
        tokio::time::sleep(Duration::from_millis(100)).await;
        let (l2, mut p2) = link(2);
        rig.up(l2);
        assert_eq!(recv_n(&mut p2, 2).await, vec![sdp("s1"), ice("s1", 1)]);
        drop(handback);
        rig.finish().await;
    }

    /// 5. Past the cap the oldest held messages go, and the newest are kept.
    #[tokio::test]
    async fn past_the_cap_the_oldest_held_messages_are_dropped() {
        let rig = Rig::new(3, HANDBACK_WAIT);
        for n in 0..5 {
            rig.send(ice("s1", n));
        }
        settle().await;
        let (l1, mut p1) = link(1);
        rig.up(l1);
        assert_eq!(
            recv_n(&mut p1, 3).await,
            vec![ice("s1", 2), ice("s1", 3), ice("s1", 4)]
        );
        quiet(&mut p1).await;
        let total = rig.finish().await;
        assert_eq!(total.overflowed, 2);
    }

    /// 6. `Up` sent just before a `pong` never loses the `pong`, although the two travel on
    /// different channels: the relay takes link changes before each message. Many times over, on
    /// a runtime with more than one thread, where the race would show.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_pong_sent_right_after_up_is_never_dropped_as_offline() {
        let rig = Rig::new(HOLD_CAP, HANDBACK_WAIT);
        for id in 1..=300 {
            let (l, mut p) = link(id);
            rig.up(l);
            rig.send(AgentToServer::Pong);
            assert_eq!(recv(&mut p).await, AgentToServer::Pong, "link {id}");
            rig.down(id);
            p.exit_handing_back(Vec::new());
        }
        let total = rig.finish().await;
        assert_eq!(total.forwarded, 300);
        assert_eq!(total.dropped_other, 0, "no pong was taken for offline");
    }

    /// A message still in the outbox when `Up` is applied goes after everything held (older) and
    /// ahead of what comes after it.
    #[tokio::test]
    async fn held_messages_go_ahead_of_ones_still_queued_when_the_link_comes_up() {
        let rig = Rig::new(HOLD_CAP, HANDBACK_WAIT);
        rig.send(sdp("s1"));
        settle().await;
        // Both queued before the relay runs again: it applies `Up` first.
        rig.send(ice("s1", 1));
        let (l1, mut p1) = link(1);
        rig.up(l1);
        rig.send(ice("s1", 2));
        assert_eq!(
            recv_n(&mut p1, 3).await,
            vec![sdp("s1"), ice("s1", 1), ice("s1", 2)]
        );
        rig.finish().await;
    }

    /// A session that ends while signaling is down: its final report is held with its end, and both
    /// go to the next connection, in order, once it is up (after `agent_ready`: the orchestrator
    /// installs a link only then). Ordinary reports are still dropped.
    #[tokio::test]
    async fn a_final_report_is_held_through_an_outage_and_delivered_on_reconnect() {
        let rig = Rig::new(HOLD_CAP, HANDBACK_WAIT);
        rig.send(stats("s1"));
        rig.send(final_stats("s1"));
        rig.send(end("s1"));
        rig.send(stats("s2"));
        settle().await;
        let (l1, mut p1) = link(1);
        rig.up(l1);
        assert_eq!(recv_n(&mut p1, 2).await, vec![final_stats("s1"), end("s1")]);
        quiet(&mut p1).await;
        let total = rig.finish().await;
        assert_eq!(total.held, 2);
        assert_eq!(total.delivered, 2);
        assert_eq!(total.dropped_stats, 2, "the ordinary reports, as before");
        assert_eq!(total.finals_expired, 0);
    }

    /// A final held longer than the server's window is dropped when the next connection comes up —
    /// the server would store nothing of it — and the session's end still goes.
    #[tokio::test]
    async fn a_final_report_held_past_the_servers_window_is_dropped() {
        let rig = Rig::with_final_hold(HOLD_CAP, HANDBACK_WAIT, Duration::from_millis(300));
        rig.send(final_stats("old"));
        rig.send(end("old"));
        tokio::time::sleep(Duration::from_millis(400)).await;
        rig.send(final_stats("new"));
        settle().await;
        let (l1, mut p1) = link(1);
        rig.up(l1);
        assert_eq!(
            recv_n(&mut p1, 2).await,
            vec![end("old"), final_stats("new")]
        );
        quiet(&mut p1).await;
        let total = rig.finish().await;
        assert_eq!(total.finals_expired, 1);
        assert_eq!(total.delivered, 2);
    }

    /// A final the dying pump never wrote comes back and is held — dated by when it first reached
    /// the relay, not by the hand-back.
    #[tokio::test]
    async fn a_final_report_handed_back_by_a_dying_pump_is_held() {
        let rig = Rig::with_final_hold(HOLD_CAP, HANDBACK_WAIT, Duration::from_millis(300));
        let (l1, mut p1) = link(1);
        rig.up(l1);
        rig.send(final_stats("s1"));
        rig.send(end("s1"));
        let unsent = recv_n(&mut p1, 2).await;
        p1.exit_handing_back(unsent);
        rig.down(1);
        settle().await;
        let (l2, mut p2) = link(2);
        rig.up(l2);
        assert_eq!(recv_n(&mut p2, 2).await, vec![final_stats("s1"), end("s1")]);
        // Handed back again, now past the window counted from its first arrival: dropped.
        tokio::time::sleep(Duration::from_millis(400)).await;
        let unsent = vec![final_stats("s1")];
        p2.exit_handing_back(unsent);
        rig.down(2);
        settle().await;
        let (l3, mut p3) = link(3);
        rig.up(l3);
        quiet(&mut p3).await;
        let total = rig.finish().await;
        assert_eq!(total.finals_expired, 1);
    }

    #[test]
    fn classes() {
        assert_eq!(class(&sdp("s")), Class::Hold);
        assert_eq!(class(&ice("s", 0)), Class::Hold);
        assert_eq!(class(&end("s")), Class::Hold);
        assert_eq!(class(&stats("s")), Class::Drop);
        assert_eq!(
            class(&final_stats("s")),
            Class::Hold,
            "a final report is the session's last word"
        );
        assert_eq!(
            class(&AgentToServer::AgentEvent(
                afklink_protocol::metrics::AgentEvent {
                    at: 1,
                    event: afklink_protocol::metrics::AgentEventKind::PcSettingChanged {
                        key: afklink_protocol::metrics::PcSettingKey::Autostart,
                        value: afklink_protocol::metrics::PcSettingValue::Flag(false),
                    },
                }
            )),
            Class::Drop,
            "an event is carried by the agent's queue on disk, not held here (it would go twice)"
        );
        assert_eq!(class(&AgentToServer::Pong), Class::Drop);
        assert_eq!(class(&AgentToServer::RequestPairing), Class::Drop);
        assert_eq!(class(&AgentToServer::PairingCancel), Class::Hold);
        // A request to the owner and its withdrawal: a person pressed them.
        assert_eq!(
            class(&AgentToServer::OwnerRequest {
                kind: afklink_protocol::OwnerRequestKind::MakeOwner,
                telegram_user_id: 7,
            }),
            Class::Hold
        );
        assert_eq!(
            class(&AgentToServer::OwnerRequestCancel {
                request_id: "r".into()
            }),
            Class::Hold
        );
        // An approval does not wait: the backend withdraws the prompt when the agent's socket goes.
        assert_eq!(
            class(&AgentToServer::PairResponse {
                request_id: "r".into(),
                accept: true,
                name: None,
                role: None,
            }),
            Class::Drop
        );
        // A rename made offline reaches the backend anyway: every connection opens with the name.
        assert_eq!(
            class(&AgentToServer::DeviceName { name: "PC".into() }),
            Class::Drop
        );
        // A goodbye belongs to the connection it closes; never carried to the next one.
        assert_eq!(
            class(&AgentToServer::AgentGoodbye {
                reason: afklink_protocol::GoodbyeReason::Sleep,
            }),
            Class::Drop
        );
    }

    /// The exit's barrier: everything in the outbox before it is in the pump's queue when it answers
    /// — what the goodbye then writes first. Without a connection it answers too, `link` empty.
    #[tokio::test]
    async fn a_barrier_answers_once_everything_before_it_is_forwarded() {
        let rig = Rig::new(HOLD_CAP, HANDBACK_WAIT);
        let (l1, mut p1) = link(1);
        rig.up(l1);
        settle().await;
        rig.send(final_stats("s1"));
        rig.send(end("s1"));
        let (tx, rx) = oneshot::channel();
        rig.links
            .send(LinkChange::Barrier(tx))
            .expect("the relay is running");
        let flushed = tokio::time::timeout(Duration::from_secs(5), rx)
            .await
            .expect("an answer in time")
            .expect("answered");
        assert_eq!(flushed.link, Some(1));
        // Both are in the pump's queue already: no waiting needed.
        assert!(p1.rx.try_recv().expect("the final").is_final_report());
        assert!(matches!(
            p1.rx.try_recv(),
            Ok(AgentToServer::SessionEnd { .. })
        ));
        rig.down(1);
        settle().await;
        let (tx, rx) = oneshot::channel();
        rig.links
            .send(LinkChange::Barrier(tx))
            .expect("the relay is running");
        let flushed = tokio::time::timeout(Duration::from_secs(5), rx)
            .await
            .expect("an answer in time")
            .expect("answered");
        assert_eq!(flushed.link, None);
        rig.finish().await;
    }
}
