//! Which way the agent reaches the server: the configured address, or the RU entry.
//!
//! Some Russian providers freeze connections to Cloudflare after 14–32 KB from the server, per
//! connection, with no reset: the client's messages still reach the server, but nothing the server
//! sends arrives any more. A PC on such a network opens its socket to `api.afklink.app`, may finish
//! the handshake, and then hears nothing (no offers, no heartbeat); the updater's download and
//! «Отправить логи» stall the same way.
//!
//! The RU entry is a box in Moscow whose own names (`api.ru.afklink.app` for agents) resolve only
//! to it. It forwards the TCP stream as it is, TLS unopened, to the same server, which answers
//! exactly as on `api.afklink.app` (`/ws/agent`, `/api/diagnostics/agent`,
//! `/api/agent/start-failure`, `/download/*`). The certificate, the signatures and everything
//! inside are the same.
//!
//! # The two ways
//!
//! - **primary**: config.json's `server_url` as it is (`wss://api.afklink.app/ws/agent` for every
//!   portable and release build), through Cloudflare.
//! - **ru**: the same address on [`RU_API_HOST`] ([`ru_alternative`]). Only for the production host
//!   [`PRIMARY_API_HOST`]: a development or hand-set server has no alternative, and everything here
//!   then always says primary.
//!
//! # How it is used
//!
//! The reconnect loop asks [`Entry::next_attempt`] before each attempt, reports an authenticated
//! connection with [`Entry::connected`] and every ending with [`Entry::record`], weighed by
//! [`classify_failure`] or [`classify_end`]. [`Weight`] holds the table of what each ending counts
//! as; [`Entry`] holds the switching rules; [`Entry::http_order`] gives HTTP callers their order.
//! The choice of the RU entry survives restarts in `entry.json` ([`FILE_NAME`]).

use std::path::PathBuf;
use std::sync::Mutex;
use std::time::Duration;

use afklink_transport::signaling::{
    ConnectFailed, ConnectFailure, ConnectStage, EndCause, HandshakeSilent, LinkEnd,
};
use afklink_transport::HandshakeRefused;
use serde::{Deserialize, Serialize};

/// The agents' own hostname through Cloudflare: the only host with an RU alternative.
pub const PRIMARY_API_HOST: &str = "api.afklink.app";

/// The RU entry's name for what agents call: DNS-only to the Moscow box, the same paths.
pub const RU_API_HOST: &str = "api.ru.afklink.app";

/// How long the RU entry is kept after the primary failed before the primary is tried again.
pub const RU_HOLD: Duration = Duration::from_secs(24 * 3600);

/// Strikes count toward a switch only within this window: long enough for two connections that each
/// lived until the slowest freeze reported (32 KB at the server's heartbeat, about an hour idle).
///
/// The freeze kills each new connection after the same few kilobytes: about every 95 s at the
/// server's heartbeat in the observed case (AS56701, a packet count). An idle connection (a ping is
/// some 40 bytes of TLS) lives 20–60 min before 14–32 KB are spent, so two such deaths fall within
/// three hours. Two unrelated drops within three hours on connections that carried little do move
/// the agent; that is the cheap mistake (signalling goes through Moscow until the primary is tried
/// again), where missing a freeze leaves the PC unreachable.
pub const STRIKE_WINDOW: Duration = Duration::from_secs(3 * 3600);

/// Strikes within [`STRIKE_WINDOW`] that move the agent to the other way (one on probation).
pub const STRIKES_TO_SWITCH: usize = 2;

/// A connection that carried this much from the server (WebSocket payload) was not cut by the
/// per-connection freeze, whatever ended it: twice the largest threshold reported (32 KB of TLS
/// records, which carry more than their payload). A silence after fewer bytes is only a strike,
/// since a laptop's Wi-Fi drop looks the same.
pub const PROVEN_BYTES: u64 = 64 * 1024;

/// The record's file in the data directory (`crate::paths::afklink_dir`); its format and lifetime
/// are on `Record`.
pub const FILE_NAME: &str = "entry.json";

/// The record's format.
const VERSION: u32 = 1;

/// A record dated further than this in the future is a clock that moved: taken as past the hold.
const FUTURE_SLACK: Duration = Duration::from_secs(3600);

/// The address on the RU entry that serves what `url` (an agent's, `wss://` or `https://`) does —
/// the same scheme, path, query and fragment on [`RU_API_HOST`] — when `url` is on the production
/// host [`PRIMARY_API_HOST`] (any case, no port or 443, no credentials); `None` for anything else:
/// a development server, a hand-set one, a plain `ws://` or `http://`, another host.
pub fn ru_alternative(url: &str) -> Option<String> {
    let url = url.trim();
    let (scheme, rest) = url.split_once("://")?;
    let scheme = scheme.to_ascii_lowercase();
    if scheme != "wss" && scheme != "https" {
        return None;
    }
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, tail) = rest.split_at(end);
    if authority.contains('@') {
        return None;
    }
    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) => (host, Some(port)),
        None => (authority, None),
    };
    if !host.eq_ignore_ascii_case(PRIMARY_API_HOST) || !matches!(port, None | Some("443")) {
        return None;
    }
    Some(format!("{scheme}://{RU_API_HOST}{tail}"))
}

/// A way to the server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Endpoint {
    /// config.json's `server_url`, as it is.
    Primary,
    /// The same on [`RU_API_HOST`].
    Ru,
}

impl Endpoint {
    /// For log lines and `entry.json`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Primary => "primary",
            Self::Ru => "ru",
        }
    }

    fn other(self) -> Self {
        match self {
            Self::Primary => Self::Ru,
            Self::Ru => Self::Primary,
        }
    }
}

/// What an attempt counts as for the way it used.
///
/// | how it ended                                                   | counts as                   |
/// |----------------------------------------------------------------|-----------------------------|
/// | opened, `agent_hello` sent, then nothing at all for 10 s       | decisive (switch at once)   |
/// | authenticated, then not one frame until the silence limit      | decisive                    |
/// | authenticated, went silent after < [`PROVEN_BYTES`] from it    | a strike                    |
/// | TCP or TLS timed out, refused or reset; the upgrade got a 5xx  | a strike                    |
/// | the name did not resolve, no route (this PC offline) — primary | not counted                 |
/// | the same on the RU entry (its own name or box)                 | a strike                    |
/// | the upgrade got a 4xx (the server answered)                    | not counted                 |
/// | an `error` frame (refused: unbound, blocked, outdated)         | healthy: strikes cleared    |
/// | the server closed it with a close frame (a deploy)             | healthy: strikes cleared    |
/// | carried ≥ [`PROVEN_BYTES`] from the server, however it ended   | healthy, and proven         |
/// | a reset or a failed write mid-life; this agent's own goodbye   | not counted                 |
///
/// Ten seconds of a silent handshake is `signaling::HANDSHAKE_SILENCE_LIMIT` (the server answers
/// within a round trip and pings every 5 s). The silence limit mid-life is the pump's own
/// (`signaling::BACKEND_SILENCE_LIMIT`: 20 s at the server's 5-second heartbeat, 45 s until that
/// cadence is seen).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Weight {
    /// The path delivered nothing at all: switch now.
    Decisive,
    /// A path failure: [`STRIKES_TO_SWITCH`] within [`STRIKE_WINDOW`] switch.
    Strike,
    /// Says nothing about the path (this PC offline, the server's own answer, this agent's
    /// goodbye).
    Neutral,
    /// The path carried the server's word: strikes cleared. `proven`: it carried more than a
    /// freezing path lets through ([`PROVEN_BYTES`]) — the primary's probation ends.
    Healthy { proven: bool },
}

impl Weight {
    /// For log lines.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Decisive => "decisive",
            Self::Strike => "strike",
            Self::Neutral => "neutral",
            Self::Healthy { proven: false } => "healthy",
            Self::Healthy { proven: true } => "proven",
        }
    }
}

/// An attempt's weight and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    pub weight: Weight,
    pub why: String,
}

impl Verdict {
    fn new(weight: Weight, why: String) -> Self {
        Self { weight, why }
    }
}

/// What an attempt that never got to serve — opening the connection, or the handshake — counts as
/// on `endpoint` (the table on [`Weight`]).
pub fn classify_failure(endpoint: Endpoint, error: &anyhow::Error) -> Verdict {
    if let Some(failed) = error
        .chain()
        .find_map(|c| c.downcast_ref::<ConnectFailed>())
    {
        return classify_connect(endpoint, failed);
    }
    if let Some(silent) = error
        .chain()
        .find_map(|c| c.downcast_ref::<HandshakeSilent>())
    {
        return Verdict::new(
            Weight::Decisive,
            format!(
                "connected, then nothing at all from the server for {} ms while waiting for {} \
                 ({} frame(s) since the upgrade)",
                silent.silent_for.as_millis(),
                silent.awaiting,
                silent.frames
            ),
        );
    }
    if let Some(refused) = error
        .chain()
        .find_map(|c| c.downcast_ref::<HandshakeRefused>())
    {
        return Verdict::new(
            Weight::Healthy { proven: false },
            format!(
                "the server answered the handshake with an error ({}): the path works",
                refused.code
            ),
        );
    }
    Verdict::new(Weight::Neutral, format!("not a path failure: {error:#}"))
}

/// What a failure to open the connection counts as on `endpoint`.
pub fn classify_connect(endpoint: Endpoint, failed: &ConnectFailed) -> Verdict {
    let stage = failed.stage.as_str();
    let what = failed.failure.as_str();
    let ms = failed.elapsed.as_millis();
    match (failed.stage, failed.failure) {
        (_, ConnectFailure::Status(code)) if (500..600).contains(&code) => Verdict::new(
            Weight::Strike,
            format!("the upgrade was answered {code} (a gateway on the way failed) after {ms} ms"),
        ),
        (_, ConnectFailure::Status(code)) => Verdict::new(
            Weight::Neutral,
            format!("the server answered the upgrade with {code}: the path works"),
        ),
        (ConnectStage::Dns, _) | (_, ConnectFailure::Unreachable) => match endpoint {
            Endpoint::Primary => Verdict::new(
                Weight::Neutral,
                format!(
                    "{stage} {what} after {ms} ms: this PC's own network looks down (the name or \
                     the route), not the path to the server"
                ),
            ),
            Endpoint::Ru => Verdict::new(
                Weight::Strike,
                format!("{stage} {what} after {ms} ms: the RU entry's name or route failed"),
            ),
        },
        (_, ConnectFailure::Other) => Verdict::new(
            Weight::Neutral,
            format!(
                "{stage} failed after {ms} ms in a way that is not the path's: {}",
                failed.detail
            ),
        ),
        _ => Verdict::new(
            Weight::Strike,
            format!(
                "{stage} {what} after {ms} ms (peer {}): {}",
                failed
                    .peer
                    .map_or_else(|| "-".to_string(), |p| p.to_string()),
                failed.detail
            ),
        ),
    }
}

/// What an authenticated connection's end counts as (the table on [`Weight`]).
pub fn classify_end(end: &LinkEnd) -> Verdict {
    let (frames, bytes, lived_s) = (end.frames, end.received_bytes, end.lived.as_secs());
    if bytes >= PROVEN_BYTES {
        return Verdict::new(
            Weight::Healthy { proven: true },
            format!(
                "it carried {bytes} bytes from the server over {lived_s} s before it ended ({}): \
                 more than a freezing path lets through",
                end.cause.as_str()
            ),
        );
    }
    match end.cause {
        EndCause::Silence if frames == 0 => Verdict::new(
            Weight::Decisive,
            format!(
                "authenticated, then not a single frame from the server — not even its heartbeat — \
                 until the silence limit ({lived_s} s)"
            ),
        ),
        EndCause::Silence => Verdict::new(
            Weight::Strike,
            format!(
                "went silent after {frames} frame(s), {bytes} bytes from the server, {lived_s} s: \
                 what a path that freezes after a few kilobytes looks like (or a network drop)"
            ),
        ),
        EndCause::ClosedByBackend { code } => Verdict::new(
            Weight::Healthy { proven: false },
            format!(
                "the server closed it (code {}): the path carried its close",
                code.map_or_else(|| "-".to_string(), |c| c.to_string())
            ),
        ),
        // A write that never finished (`send_timeout`) is the way out, not the way in: the freeze
        // this weighs is of what the server sends, and a path that froze that ends in silence first.
        EndCause::StreamEnded
        | EndCause::WsError
        | EndCause::SendFailed
        | EndCause::SendTimeout => Verdict::new(
            Weight::Neutral,
            format!(
                "it ended by {} after {frames} frame(s), {bytes} bytes, {lived_s} s: a reset or a \
                 closed stream is not how the freeze looks",
                end.cause.as_str()
            ),
        ),
        EndCause::Goodbye | EndCause::Retired | EndCause::OrchestratorGone => Verdict::new(
            Weight::Neutral,
            format!("this agent ended it ({})", end.cause.as_str()),
        ),
    }
}

/// The next attempt: which way, its address, and why (for the line that says it connects).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attempt {
    pub endpoint: Endpoint,
    pub url: String,
    pub why: String,
}

/// `entry.json`, written whole (a temporary file, then a rename):
/// `{"v":1,"server_url":…,"prefer":"ru","since_ms":…,"why":…}` once a connection through the RU
/// entry is authenticated. Removed when the primary proves itself, or when the agent leaves the RU
/// entry because it failed.
///
/// At start: the RU entry when the record is for this `server_url` and younger than [`RU_HOLD`];
/// the primary on probation when it is older (or dated in the future: a clock that moved); the
/// primary when there is none. A development or hand-set server never reads or writes it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Record {
    v: u32,
    /// The `server_url` the record is for: another one's is ignored.
    server_url: String,
    /// `ru`: the only value written.
    prefer: String,
    /// When the primary failed and the agent took the RU entry, Unix ms.
    since_ms: u64,
    /// Why, for whoever reads the file.
    why: String,
}

/// The choice, behind the lock.
#[derive(Debug)]
struct State {
    current: Endpoint,
    /// When the agent last moved to the RU entry because the primary failed: the hold counts from
    /// it.
    ru_since_ms: Option<u64>,
    /// The primary failed here and has not proved itself since: one strike moves the agent.
    primary_suspect: bool,
    /// Strikes on `current`, Unix ms.
    strikes: Vec<u64>,
    /// Why the RU entry was taken, for the record.
    switch_why: String,
    /// What `entry.json` holds for this server, as far as this process knows.
    saved: Option<Record>,
}

/// The way to the server, shared: the orchestrator's reconnect loop decides
/// ([`Entry::next_attempt`], [`Entry::connected`], [`Entry::record`]); the updater,
/// «Отправить логи» and the start failure beacon read it ([`Entry::http_order`]).
///
/// When the way changes:
///
/// - A decisive failure, or [`STRIKES_TO_SWITCH`] strikes within [`STRIKE_WINDOW`], on the way in
///   use: the next attempt uses the other way. Attempts keep the reconnect loop's backoff
///   (`crate::reconnect`): a switch never shortens a wait, so two ways that both fail alternate at
///   the backoff's pace, never in a tight loop.
/// - Once the primary has failed here, it is on probation until it proves itself (a connection that
///   carried [`PROVEN_BYTES`]): one strike sends the agent back to the RU entry.
/// - [`RU_HOLD`] (24 h) after the switch to the RU entry, the next attempt (a reconnect, never a
///   cut of a working connection) tries the primary again, on probation, so a lifted block does not
///   pin the PC to Moscow for good.
#[derive(Debug)]
pub struct Entry {
    primary: String,
    ru: Option<String>,
    file: Option<PathBuf>,
    state: Mutex<State>,
}

/// Now, Unix ms.
fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

fn ms(d: Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
}

impl Entry {
    /// For `server_url`, remembering in the data directory's `entry.json` — the app's and the
    /// CLI's. Without a data directory: in memory only, and a warning.
    pub fn open_default(server_url: &str) -> Self {
        match crate::paths::afklink_dir() {
            Ok(dir) => Self::open(Some(dir.join(FILE_NAME)), server_url, now_ms()),
            Err(e) => {
                tracing::warn!(
                    "entry: no data directory ({e:#}); the way to the server is chosen for this run \
                     only"
                );
                Self::open(None, server_url, now_ms())
            }
        }
    }

    /// For `server_url`, remembering in `path`.
    pub fn open_at(path: PathBuf, server_url: &str) -> Self {
        Self::open(Some(path), server_url, now_ms())
    }

    /// For `server_url`, remembering nothing: what an agent built without one uses (the tests').
    pub fn in_memory(server_url: &str) -> Self {
        Self::open(None, server_url, now_ms())
    }

    /// `primary` with `alternative` as its RU entry, in memory: tests that cannot use the
    /// production hosts (a local server on two ports). Not an API.
    #[doc(hidden)]
    pub fn with_alternative(primary: &str, alternative: &str) -> Self {
        tracing::debug!(
            primary,
            alternative,
            "entry: an alternative given by hand (tests)"
        );
        Self::build(
            primary.to_string(),
            Some(alternative.to_string()),
            None,
            Endpoint::Primary,
        )
    }

    fn build(
        primary: String,
        ru: Option<String>,
        file: Option<PathBuf>,
        current: Endpoint,
    ) -> Self {
        Self {
            primary,
            ru,
            file,
            state: Mutex::new(State {
                current,
                ru_since_ms: None,
                primary_suspect: false,
                strikes: Vec::new(),
                switch_why: String::new(),
                saved: None,
            }),
        }
    }

    fn open(file: Option<PathBuf>, server_url: &str, now: u64) -> Self {
        let ru = ru_alternative(server_url);
        let Some(alternative) = ru else {
            tracing::debug!(
                server = server_url,
                "entry: the server address has no RU alternative (a development or hand-set \
                 server): every connection uses it"
            );
            return Self::build(server_url.to_string(), None, None, Endpoint::Primary);
        };
        let entry = Self::build(
            server_url.to_string(),
            Some(alternative.clone()),
            file,
            Endpoint::Primary,
        );
        let Some(path) = entry.file.clone() else {
            tracing::debug!(
                primary = server_url,
                ru = %alternative,
                "entry: the configured address first; nothing is remembered across starts"
            );
            return entry;
        };
        let record = match std::fs::read_to_string(&path) {
            Ok(text) => match serde_json::from_str::<Record>(&text) {
                Ok(record) => Some(record),
                Err(e) => {
                    tracing::warn!(
                        file = %path.display(),
                        "entry: the record is not readable ({e}); taken as nothing remembered"
                    );
                    None
                }
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                tracing::debug!(
                    file = %path.display(),
                    primary = server_url,
                    ru = %alternative,
                    "entry: nothing remembered: the configured address first"
                );
                None
            }
            Err(e) => {
                tracing::warn!(
                    file = %path.display(),
                    "entry: the record could not be read ({e}); taken as nothing remembered"
                );
                None
            }
        };
        let Some(record) = record else {
            return entry;
        };
        if record.server_url != server_url || record.prefer != Endpoint::Ru.as_str() {
            tracing::debug!(
                file = %path.display(),
                recorded_for = %record.server_url,
                prefer = %record.prefer,
                server = server_url,
                "entry: the record is for another server address (or prefers nothing this build \
                 knows): ignored; the configured address first"
            );
            return entry;
        }
        {
            let mut s = crate::lock(&entry.state);
            s.primary_suspect = true;
            s.ru_since_ms = Some(record.since_ms);
            s.switch_why = record.why.clone();
            let age = now.saturating_sub(record.since_ms);
            let future = record.since_ms > now.saturating_add(ms(FUTURE_SLACK));
            if age < ms(RU_HOLD) && !future {
                s.current = Endpoint::Ru;
                tracing::info!(
                    file = %path.display(),
                    since_ms = record.since_ms,
                    age_min = age / 60_000,
                    retry_primary_in_min = (ms(RU_HOLD) - age) / 60_000,
                    why = %record.why,
                    "entry: the RU entry is remembered (the configured address failed here): \
                     starting on it; the configured address is tried again when the hold ends"
                );
            } else {
                tracing::info!(
                    file = %path.display(),
                    since_ms = record.since_ms,
                    age_h = age / 3_600_000,
                    dated_in_future = future,
                    hold_h = RU_HOLD.as_secs() / 3600,
                    "entry: the RU entry remembered from before the hold's end: the configured \
                     address first, on probation (one path failure sends the agent back to the RU \
                     entry)"
                );
            }
            s.saved = Some(record);
        }
        entry
    }

    /// Whether the server address has an RU alternative at all.
    pub fn has_alternative(&self) -> bool {
        self.ru.is_some()
    }

    /// The way in use (the next attempt's, between attempts): what HTTP tries first.
    pub fn preferred(&self) -> Endpoint {
        if self.ru.is_none() {
            return Endpoint::Primary;
        }
        crate::lock(&self.state).current
    }

    /// The address of `endpoint`'s socket: the primary itself when there is no alternative.
    pub fn url_of(&self, endpoint: Endpoint) -> &str {
        match (endpoint, &self.ru) {
            (Endpoint::Ru, Some(ru)) => ru,
            _ => &self.primary,
        }
    }

    /// The addresses to try for `url` (an agent's HTTP address), in order: the way in use first,
    /// its RU alternative or the primary second — when `url` has one ([`ru_alternative`]); else
    /// `url` alone. Whatever the signaling server is: the updater's manifest is on the production
    /// host even for a build pointed elsewhere. Before any socket, the way in use is the remembered
    /// one.
    ///
    /// Each caller keeps its own fallback (the app's `updater`, `diagnostics::upload`,
    /// `start_failure`); what HTTP sees never moves the socket.
    pub fn http_order(&self, url: &str) -> Vec<(Endpoint, String)> {
        let Some(alternative) = ru_alternative(url) else {
            return vec![(Endpoint::Primary, url.to_string())];
        };
        match self.preferred() {
            Endpoint::Primary => vec![
                (Endpoint::Primary, url.to_string()),
                (Endpoint::Ru, alternative),
            ],
            Endpoint::Ru => vec![
                (Endpoint::Ru, alternative),
                (Endpoint::Primary, url.to_string()),
            ],
        }
    }

    /// Which way the next signaling attempt takes, and why. Past [`RU_HOLD`] on the RU entry, the
    /// primary again, on probation.
    pub fn next_attempt(&self) -> Attempt {
        self.next_attempt_at(now_ms())
    }

    fn next_attempt_at(&self, now: u64) -> Attempt {
        if self.ru.is_none() {
            return Attempt {
                endpoint: Endpoint::Primary,
                url: self.primary.clone(),
                why: "the configured address (it has no RU alternative)".into(),
            };
        }
        let mut s = crate::lock(&self.state);
        if s.current == Endpoint::Ru {
            if let Some(since) = s.ru_since_ms {
                let age = now.saturating_sub(since);
                let future = since > now.saturating_add(ms(FUTURE_SLACK));
                if age >= ms(RU_HOLD) || future {
                    s.current = Endpoint::Primary;
                    s.primary_suspect = true;
                    s.strikes.clear();
                    tracing::info!(
                        from = Endpoint::Ru.as_str(),
                        to = Endpoint::Primary.as_str(),
                        on_ru_h = age / 3_600_000,
                        hold_h = RU_HOLD.as_secs() / 3600,
                        dated_in_future = future,
                        "entry: switching: the RU entry has been in use for the hold since the \
                         configured address failed; the configured address is tried again, on \
                         probation"
                    );
                }
            }
        }
        let endpoint = s.current;
        let why = match (endpoint, s.primary_suspect) {
            (Endpoint::Primary, false) => "the configured address".to_string(),
            (Endpoint::Primary, true) => {
                "the configured address, on probation (it failed here \
                                          before; one path failure sends the agent to the RU entry)"
                    .to_string()
            }
            (Endpoint::Ru, _) => format!(
                "the RU entry (the configured address failed here {} min ago; it is tried again {} \
                 h after that)",
                s.ru_since_ms.map_or(0, |since| now.saturating_sub(since) / 60_000),
                RU_HOLD.as_secs() / 3600
            ),
        };
        let strikes = s.strikes.len();
        drop(s);
        tracing::debug!(
            endpoint = endpoint.as_str(),
            strikes,
            %why,
            "entry: the next attempt's way"
        );
        Attempt {
            endpoint,
            url: self.url_of(endpoint).to_string(),
            why,
        }
    }

    /// A connection through `endpoint` was authenticated: through the RU entry, remembered for the
    /// next start (`entry.json`).
    pub fn connected(&self, endpoint: Endpoint) {
        self.connected_at(endpoint, now_ms());
    }

    fn connected_at(&self, endpoint: Endpoint, now: u64) {
        if self.ru.is_none() || endpoint != Endpoint::Ru {
            return;
        }
        let mut s = crate::lock(&self.state);
        let since = *s.ru_since_ms.get_or_insert(now);
        let record = Record {
            v: VERSION,
            server_url: self.primary.clone(),
            prefer: Endpoint::Ru.as_str().into(),
            since_ms: since,
            why: if s.switch_why.is_empty() {
                "the configured address failed".into()
            } else {
                s.switch_why.clone()
            },
        };
        if s.saved.as_ref() == Some(&record) {
            tracing::trace!("entry: the RU entry is remembered already");
            return;
        }
        self.save(&record);
        s.saved = Some(record);
    }

    /// How an attempt through `endpoint` ended: strikes, probation, a switch, the record — each
    /// logged with its reason.
    pub fn record(&self, endpoint: Endpoint, verdict: &Verdict) {
        self.record_at(endpoint, verdict, now_ms());
    }

    fn record_at(&self, endpoint: Endpoint, verdict: &Verdict, now: u64) {
        let weight = verdict.weight.as_str();
        let why = verdict.why.as_str();
        if self.ru.is_none() {
            match verdict.weight {
                Weight::Decisive | Weight::Strike => tracing::warn!(
                    weight,
                    "entry: path failure on the configured address ({why}); it has no RU \
                     alternative, nothing to switch to"
                ),
                _ => tracing::debug!(weight, "entry: attempt on the configured address: {why}"),
            }
            return;
        }
        let mut s = crate::lock(&self.state);
        if endpoint != s.current {
            tracing::debug!(
                endpoint = endpoint.as_str(),
                current = s.current.as_str(),
                weight,
                "entry: an attempt on a way no longer in use; noted only: {why}"
            );
            return;
        }
        s.strikes
            .retain(|t| now.saturating_sub(*t) < ms(STRIKE_WINDOW));
        let decisive = match verdict.weight {
            Weight::Neutral => {
                tracing::debug!(
                    endpoint = endpoint.as_str(),
                    strikes = s.strikes.len(),
                    "entry: not a path failure: {why}"
                );
                return;
            }
            Weight::Healthy { proven } => {
                let cleared = s.strikes.len();
                s.strikes.clear();
                tracing::debug!(
                    endpoint = endpoint.as_str(),
                    proven,
                    strikes_cleared = cleared,
                    "entry: the way works: {why}"
                );
                if proven && endpoint == Endpoint::Primary {
                    if s.primary_suspect {
                        s.primary_suspect = false;
                        tracing::info!(
                            "entry: the configured address proved itself again ({why}): no \
                             longer on probation"
                        );
                    }
                    if s.saved.is_some() {
                        self.forget(&mut s, "the configured address proved itself again");
                    }
                }
                return;
            }
            Weight::Strike => false,
            Weight::Decisive => true,
        };
        s.strikes.push(now);
        let needed = if endpoint == Endpoint::Primary && s.primary_suspect {
            1
        } else {
            STRIKES_TO_SWITCH
        };
        let strikes = s.strikes.len();
        tracing::warn!(
            endpoint = endpoint.as_str(),
            url = self.url_of(endpoint),
            weight,
            strikes,
            needed,
            window_min = STRIKE_WINDOW.as_secs() / 60,
            probation = endpoint == Endpoint::Primary && s.primary_suspect,
            "entry: path failure: {why}"
        );
        if !decisive && strikes < needed {
            return;
        }
        let to = endpoint.other();
        let reason = if decisive {
            format!("a decisive failure on {}: {why}", endpoint.as_str())
        } else {
            format!(
                "{strikes} path failure(s) on {} within {} min (the last: {why})",
                endpoint.as_str(),
                STRIKE_WINDOW.as_secs() / 60
            )
        };
        s.current = to;
        s.strikes.clear();
        match to {
            Endpoint::Ru => {
                s.ru_since_ms = Some(now);
                s.primary_suspect = true;
                s.switch_why = reason.clone();
            }
            Endpoint::Primary => {
                if s.saved.is_some() {
                    self.forget(&mut s, "the RU entry failed");
                }
            }
        }
        tracing::info!(
            from = endpoint.as_str(),
            to = to.as_str(),
            url = self.url_of(to),
            "entry: switching: {reason}; the next attempt uses {} (at the reconnect loop's usual \
             backoff)",
            to.as_str()
        );
    }

    /// Write `record` to `entry.json` whole (a temporary file, then a rename).
    fn save(&self, record: &Record) {
        let Some(path) = &self.file else {
            tracing::debug!("entry: the RU entry is in use; nothing remembered across starts");
            return;
        };
        let written = serde_json::to_vec(record)
            .map_err(std::io::Error::other)
            .and_then(|bytes| {
                let tmp = path.with_extension("json.tmp");
                std::fs::write(&tmp, bytes).and_then(|()| std::fs::rename(&tmp, path))
            });
        match written {
            Ok(()) => tracing::debug!(
                file = %path.display(),
                since_ms = record.since_ms,
                why = %record.why,
                "entry: the RU entry remembered for the next start"
            ),
            Err(e) => tracing::warn!(
                file = %path.display(),
                "entry: the record not written ({e}); the RU entry holds for this run only"
            ),
        }
    }

    /// Remove `entry.json`: the RU entry is no longer the way to remember (`why`).
    fn forget(&self, s: &mut State, why: &str) {
        s.saved = None;
        let Some(path) = &self.file else {
            return;
        };
        match std::fs::remove_file(path) {
            Ok(()) => tracing::debug!(
                file = %path.display(),
                "entry: the remembered RU entry forgotten: {why}"
            ),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => tracing::debug!(
                file = %path.display(),
                "entry: the remembered RU entry was gone already: {why}"
            ),
            Err(e) => tracing::warn!(
                file = %path.display(),
                "entry: the remembered RU entry could not be removed ({e}); the next start may \
                 begin on it: {why}"
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PROD: &str = "wss://api.afklink.app/ws/agent";
    const RU: &str = "wss://api.ru.afklink.app/ws/agent";
    const H: u64 = 3_600_000;
    const MIN: u64 = 60_000;
    /// Some Unix time to start from.
    const T0: u64 = 1_790_000_000_000;

    fn strike() -> Verdict {
        Verdict::new(Weight::Strike, "test strike".into())
    }
    fn decisive() -> Verdict {
        Verdict::new(Weight::Decisive, "test decisive".into())
    }
    fn neutral() -> Verdict {
        Verdict::new(Weight::Neutral, "test neutral".into())
    }
    fn healthy(proven: bool) -> Verdict {
        Verdict::new(Weight::Healthy { proven }, "test healthy".into())
    }

    /// A file of its own under the temp dir, removed on drop.
    struct TempFile(PathBuf);

    impl TempFile {
        fn new() -> Self {
            let dir = std::env::temp_dir().join(format!("afklink-entry-{}", uuid::Uuid::new_v4()));
            std::fs::create_dir_all(&dir).expect("create temp dir");
            Self(dir.join(FILE_NAME))
        }
        fn read(&self) -> Option<Record> {
            let text = std::fs::read_to_string(&self.0).ok()?;
            Some(serde_json::from_str(&text).expect("a record"))
        }
    }

    impl Drop for TempFile {
        fn drop(&mut self) {
            if let Some(dir) = self.0.parent() {
                let _ = std::fs::remove_dir_all(dir);
            }
        }
    }

    #[test]
    fn only_the_production_host_has_an_ru_alternative() {
        let ru = |url: &str| ru_alternative(url);
        assert_eq!(ru(PROD).as_deref(), Some(RU));
        assert_eq!(
            ru("https://api.afklink.app/download/latest.json").as_deref(),
            Some("https://api.ru.afklink.app/download/latest.json")
        );
        assert_eq!(
            ru("https://api.afklink.app/download/AFKLink-0.6.0.exe").as_deref(),
            Some("https://api.ru.afklink.app/download/AFKLink-0.6.0.exe")
        );
        assert_eq!(
            ru("https://api.afklink.app/api/diagnostics/agent").as_deref(),
            Some("https://api.ru.afklink.app/api/diagnostics/agent")
        );
        // Any case, spaces around, the scheme's own port, a query, no path at all.
        assert_eq!(
            ru("  WSS://API.AFKLINK.APP/ws/agent ").as_deref(),
            Some("wss://api.ru.afklink.app/ws/agent")
        );
        assert_eq!(
            ru("wss://api.afklink.app:443/ws/agent").as_deref(),
            Some(RU)
        );
        assert_eq!(
            ru("https://api.afklink.app/download/latest.json?x=1#f").as_deref(),
            Some("https://api.ru.afklink.app/download/latest.json?x=1#f")
        );
        assert_eq!(
            ru("wss://api.afklink.app").as_deref(),
            Some("wss://api.ru.afklink.app")
        );
        // Development, hand-set, another host, plain transport, another port, credentials, the RU
        // entry itself: none.
        for none in [
            "ws://localhost:8787/ws/agent",
            "ws://127.0.0.1:8787/ws/agent",
            "wss://example.test/ws/agent",
            "wss://web.example.test/ws/agent",
            "ws://api.afklink.app/ws/agent",
            "http://api.afklink.app/download/latest.json",
            "wss://api.afklink.app:8443/ws/agent",
            "wss://user:pw@api.afklink.app/ws/agent",
            "wss://api.afklink.app.evil.test/ws/agent",
            "wss://xapi.afklink.app/ws/agent",
            RU,
            "not a url",
            "",
        ] {
            assert_eq!(ru(none), None, "{none}");
        }
    }

    fn connect_failed(stage: ConnectStage, failure: ConnectFailure) -> ConnectFailed {
        ConnectFailed {
            url: PROD.into(),
            stage,
            failure,
            elapsed: Duration::from_millis(1234),
            peer: None,
            detail: "test".into(),
        }
    }

    #[test]
    fn what_a_failed_connect_counts_as() {
        use ConnectFailure::*;
        use ConnectStage::*;
        let weight = |endpoint, stage, failure| {
            let failed = connect_failed(stage, failure);
            classify_failure(
                endpoint,
                &anyhow::Error::new(failed).context("signaling connect"),
            )
            .weight
        };
        for endpoint in [Endpoint::Primary, Endpoint::Ru] {
            // The path dropped, refused or reset us, or a gateway failed: a strike.
            for (stage, failure) in [
                (Tcp, Timeout),
                (Upgrade, Timeout),
                (Tcp, Refused),
                (Upgrade, Reset),
                (Upgrade, Tls),
                (Upgrade, Status(502)),
                (Upgrade, Status(522)),
            ] {
                assert_eq!(
                    weight(endpoint, stage, failure),
                    Weight::Strike,
                    "{endpoint:?} {stage:?} {failure:?}"
                );
            }
            // The server answered, or something not the path's.
            for (stage, failure) in [
                (Upgrade, Status(404)),
                (Upgrade, Status(403)),
                (Upgrade, Status(426)),
                (Upgrade, Other),
            ] {
                assert_eq!(
                    weight(endpoint, stage, failure),
                    Weight::Neutral,
                    "{endpoint:?} {stage:?} {failure:?}"
                );
            }
        }
        // The name or the route: this PC offline on the primary; the RU entry's own failure there.
        for (stage, failure) in [(Dns, NotResolved), (Dns, Timeout), (Tcp, Unreachable)] {
            assert_eq!(weight(Endpoint::Primary, stage, failure), Weight::Neutral);
            assert_eq!(weight(Endpoint::Ru, stage, failure), Weight::Strike);
        }
    }

    #[test]
    fn what_a_failed_handshake_counts_as() {
        let silent = anyhow::Error::new(HandshakeSilent {
            awaiting: "challenge",
            silent_for: Duration::from_secs(10),
            frames: 0,
        })
        .context("signaling connect");
        let v = classify_failure(Endpoint::Primary, &silent);
        assert_eq!(v.weight, Weight::Decisive);
        assert!(
            v.why.contains("10000 ms") && v.why.contains("challenge"),
            "{}",
            v.why
        );
        // Refused (unbound, blocked, outdated): the server answered.
        let refused = anyhow::Error::new(HandshakeRefused {
            code: "pubkey_mismatch".into(),
            message: None,
            awaiting: "agent_ready",
        })
        .context("signaling connect");
        assert_eq!(
            classify_failure(Endpoint::Primary, &refused).weight,
            Weight::Healthy { proven: false }
        );
        // Anything untyped (the backend closed during the handshake, a bad message): not counted.
        let other = anyhow::anyhow!("expected challenge, the backend closed the connection");
        assert_eq!(
            classify_failure(Endpoint::Ru, &other).weight,
            Weight::Neutral
        );
    }

    fn end(cause: EndCause, frames: u64, bytes: u64) -> LinkEnd {
        LinkEnd {
            cause,
            received_bytes: bytes,
            frames,
            lived: Duration::from_secs(95),
        }
    }

    #[test]
    fn what_an_ended_connection_counts_as() {
        let w = |e: LinkEnd| classify_end(&e).weight;
        // Silent with not one frame after the handshake: decisive.
        assert_eq!(w(end(EndCause::Silence, 0, 0)), Weight::Decisive);
        // Silent after a few kilobytes (the observed freeze: ~19 pings, then nothing): a strike.
        assert_eq!(w(end(EndCause::Silence, 19, 285)), Weight::Strike);
        assert_eq!(
            w(end(EndCause::Silence, 400, PROVEN_BYTES - 1)),
            Weight::Strike
        );
        // Silent after more than a freezing path lets through: proven, however it ended.
        for cause in [
            EndCause::Silence,
            EndCause::WsError,
            EndCause::ClosedByBackend { code: Some(1001) },
        ] {
            assert_eq!(
                w(end(cause, 5000, PROVEN_BYTES)),
                Weight::Healthy { proven: true },
                "{cause:?}"
            );
        }
        // The server's clean close (a deploy): healthy.
        assert_eq!(
            w(end(EndCause::ClosedByBackend { code: Some(1001) }, 3, 100)),
            Weight::Healthy { proven: false }
        );
        // A reset or a failed write, or this agent's own end: not counted.
        for cause in [
            EndCause::StreamEnded,
            EndCause::WsError,
            EndCause::SendFailed,
            EndCause::SendTimeout,
            EndCause::Goodbye,
            EndCause::Retired,
            EndCause::OrchestratorGone,
        ] {
            assert_eq!(w(end(cause, 3, 100)), Weight::Neutral, "{cause:?}");
        }
    }

    #[test]
    fn two_strikes_within_the_window_switch_and_one_does_not() {
        let entry = Entry::open(None, PROD, T0);
        assert_eq!(entry.next_attempt_at(T0).endpoint, Endpoint::Primary);
        entry.record_at(Endpoint::Primary, &strike(), T0);
        assert_eq!(
            entry.preferred(),
            Endpoint::Primary,
            "one strike is not enough"
        );
        // A neutral attempt changes nothing; a second strike within the window switches — here an
        // hour later, as two idle connections cut at the slowest freeze reported are.
        entry.record_at(Endpoint::Primary, &neutral(), T0 + MIN);
        assert_eq!(entry.preferred(), Endpoint::Primary);
        entry.record_at(Endpoint::Primary, &strike(), T0 + H + 5 * MIN);
        let next = entry.next_attempt_at(T0 + H + 6 * MIN);
        assert_eq!((next.endpoint, next.url.as_str()), (Endpoint::Ru, RU));
        assert!(next.why.contains("RU entry"), "{}", next.why);
    }

    #[test]
    fn strikes_further_apart_than_the_window_do_not_add_up() {
        assert_eq!(STRIKE_WINDOW, Duration::from_secs(3 * 3600));
        let entry = Entry::open(None, PROD, T0);
        entry.record_at(Endpoint::Primary, &strike(), T0);
        entry.record_at(Endpoint::Primary, &strike(), T0 + 3 * H + MIN);
        assert_eq!(entry.preferred(), Endpoint::Primary);
        entry.record_at(Endpoint::Primary, &strike(), T0 + 3 * H + 2 * MIN);
        assert_eq!(
            entry.preferred(),
            Endpoint::Ru,
            "the last two were within the window"
        );
    }

    #[test]
    fn a_healthy_attempt_clears_the_strikes() {
        let entry = Entry::open(None, PROD, T0);
        entry.record_at(Endpoint::Primary, &strike(), T0);
        entry.record_at(Endpoint::Primary, &healthy(false), T0 + MIN);
        entry.record_at(Endpoint::Primary, &strike(), T0 + 2 * MIN);
        assert_eq!(entry.preferred(), Endpoint::Primary, "cleared in between");
    }

    #[test]
    fn a_decisive_failure_switches_at_once_both_ways() {
        let entry = Entry::open(None, PROD, T0);
        entry.record_at(Endpoint::Primary, &decisive(), T0);
        assert_eq!(entry.next_attempt_at(T0 + 1000).endpoint, Endpoint::Ru);
        entry.record_at(Endpoint::Ru, &decisive(), T0 + 2000);
        let back = entry.next_attempt_at(T0 + 3000);
        assert_eq!(
            (back.endpoint, back.url.as_str()),
            (Endpoint::Primary, PROD)
        );
        assert!(back.why.contains("probation"), "{}", back.why);
    }

    #[test]
    fn on_probation_one_strike_sends_the_primary_back_and_proof_ends_it() {
        let entry = Entry::open(None, PROD, T0);
        entry.record_at(Endpoint::Primary, &decisive(), T0);
        // The RU entry fails twice: back to the primary, on probation.
        entry.record_at(Endpoint::Ru, &strike(), T0 + MIN);
        entry.record_at(Endpoint::Ru, &strike(), T0 + 2 * MIN);
        assert_eq!(entry.preferred(), Endpoint::Primary);
        entry.record_at(Endpoint::Primary, &strike(), T0 + 3 * MIN);
        assert_eq!(entry.preferred(), Endpoint::Ru, "one strike on probation");
        // Back once more; this time the primary proves itself: two strikes are needed again.
        entry.record_at(Endpoint::Ru, &decisive(), T0 + 4 * MIN);
        entry.record_at(Endpoint::Primary, &healthy(false), T0 + 5 * MIN);
        entry.record_at(Endpoint::Primary, &strike(), T0 + 6 * MIN);
        assert_eq!(
            entry.preferred(),
            Endpoint::Ru,
            "a clean close is not proof: still on probation"
        );
        entry.record_at(Endpoint::Ru, &decisive(), T0 + 7 * MIN);
        entry.record_at(Endpoint::Primary, &healthy(true), T0 + 8 * MIN);
        entry.record_at(Endpoint::Primary, &strike(), T0 + 9 * MIN);
        assert_eq!(
            entry.preferred(),
            Endpoint::Primary,
            "proven: off probation"
        );
    }

    #[test]
    fn the_primary_is_tried_again_after_the_hold_at_the_next_attempt() {
        let entry = Entry::open(None, PROD, T0);
        entry.record_at(Endpoint::Primary, &decisive(), T0);
        assert_eq!(
            entry.next_attempt_at(T0 + 23 * H).endpoint,
            Endpoint::Ru,
            "within the hold"
        );
        let again = entry.next_attempt_at(T0 + 24 * H);
        assert_eq!(again.endpoint, Endpoint::Primary);
        assert!(again.why.contains("probation"), "{}", again.why);
        // It fails once: straight back, with a new hold.
        entry.record_at(Endpoint::Primary, &strike(), T0 + 24 * H + MIN);
        assert_eq!(
            entry.next_attempt_at(T0 + 47 * H).endpoint,
            Endpoint::Ru,
            "the hold counts from the new failure"
        );
        assert_eq!(
            entry.next_attempt_at(T0 + 48 * H + 2 * MIN).endpoint,
            Endpoint::Primary
        );
    }

    #[test]
    fn an_attempt_on_a_way_no_longer_in_use_moves_nothing() {
        let entry = Entry::open(None, PROD, T0);
        entry.record_at(Endpoint::Primary, &decisive(), T0);
        entry.record_at(Endpoint::Primary, &decisive(), T0 + 1);
        assert_eq!(entry.preferred(), Endpoint::Ru);
    }

    #[test]
    fn a_server_without_an_alternative_never_switches() {
        for server in [
            "ws://localhost:8787/ws/agent",
            "wss://example.test/ws/agent",
        ] {
            let entry = Entry::open(None, server, T0);
            assert!(!entry.has_alternative());
            for t in 0..5 {
                entry.record_at(Endpoint::Primary, &decisive(), T0 + t);
            }
            let next = entry.next_attempt_at(T0 + 10);
            assert_eq!(
                (next.endpoint, next.url.as_str()),
                (Endpoint::Primary, server)
            );
            assert_eq!(entry.preferred(), Endpoint::Primary);
            // Nothing remembered for it either.
            entry.connected_at(Endpoint::Ru, T0 + 11);
        }
    }

    #[test]
    fn the_ru_entry_is_remembered_once_it_works_and_read_at_the_next_start() {
        let file = TempFile::new();
        let entry = Entry::open(Some(file.0.clone()), PROD, T0);
        assert_eq!(file.read(), None, "nothing written at start");
        entry.record_at(Endpoint::Primary, &decisive(), T0);
        assert_eq!(file.read(), None, "not before the RU entry works");
        entry.connected_at(Endpoint::Ru, T0 + 5000);
        let saved = file.read().expect("remembered");
        assert_eq!(saved.server_url, PROD);
        assert_eq!(saved.prefer, "ru");
        assert_eq!(
            saved.since_ms, T0,
            "dated by the primary's failure, not the connect"
        );
        assert!(saved.why.contains("decisive"), "{}", saved.why);

        // The next start, within the hold: on the RU entry, the primary on probation.
        let next_start = Entry::open(Some(file.0.clone()), PROD, T0 + 3 * H);
        let first = next_start.next_attempt_at(T0 + 3 * H);
        assert_eq!((first.endpoint, first.url.as_str()), (Endpoint::Ru, RU));
        assert_eq!(next_start.preferred(), Endpoint::Ru);
        // ... and the hold still counts from the failure.
        assert_eq!(
            next_start.next_attempt_at(T0 + 24 * H).endpoint,
            Endpoint::Primary
        );

        // A start after the hold: the primary first, on probation — one strike, back.
        let late = Entry::open(Some(file.0.clone()), PROD, T0 + 30 * H);
        let first = late.next_attempt_at(T0 + 30 * H);
        assert_eq!(first.endpoint, Endpoint::Primary);
        assert!(first.why.contains("probation"), "{}", first.why);
        late.record_at(Endpoint::Primary, &strike(), T0 + 30 * H + MIN);
        assert_eq!(late.preferred(), Endpoint::Ru);
        late.connected_at(Endpoint::Ru, T0 + 30 * H + 2 * MIN);
        assert_eq!(
            file.read().map(|r| r.since_ms),
            Some(T0 + 30 * H + MIN),
            "the new failure's time"
        );
    }

    #[test]
    fn the_record_is_forgotten_when_the_primary_proves_itself_or_the_ru_entry_fails() {
        let file = TempFile::new();
        // Proof: the primary, past the hold, carries more than a freezing path lets through.
        let entry = Entry::open(Some(file.0.clone()), PROD, T0);
        entry.record_at(Endpoint::Primary, &decisive(), T0);
        entry.connected_at(Endpoint::Ru, T0 + 1);
        assert!(file.read().is_some());
        assert_eq!(
            entry.next_attempt_at(T0 + 25 * H).endpoint,
            Endpoint::Primary
        );
        entry.record_at(Endpoint::Primary, &healthy(false), T0 + 25 * H);
        assert!(file.read().is_some(), "a clean close is not proof");
        entry.record_at(Endpoint::Primary, &healthy(true), T0 + 26 * H);
        assert_eq!(file.read(), None);
        let fresh = Entry::open(Some(file.0.clone()), PROD, T0 + 26 * H);
        let first = fresh.next_attempt_at(T0 + 26 * H);
        assert_eq!(first.endpoint, Endpoint::Primary);
        assert!(!first.why.contains("probation"), "{}", first.why);

        // The RU entry fails while remembered: forgotten as the agent leaves it.
        let entry = Entry::open(Some(file.0.clone()), PROD, T0);
        entry.record_at(Endpoint::Primary, &decisive(), T0);
        entry.connected_at(Endpoint::Ru, T0 + 1);
        assert!(file.read().is_some());
        entry.record_at(Endpoint::Ru, &strike(), T0 + 2);
        assert!(file.read().is_some(), "one strike");
        entry.record_at(Endpoint::Ru, &strike(), T0 + 3);
        assert_eq!(file.read(), None);
        assert_eq!(entry.preferred(), Endpoint::Primary);
    }

    #[test]
    fn a_record_for_another_server_a_bad_one_or_one_from_the_future_is_not_followed() {
        let file = TempFile::new();
        let write = |text: &str| std::fs::write(&file.0, text).expect("write");
        let starts_on = |now: u64| Entry::open(Some(file.0.clone()), PROD, now).preferred();

        write(&format!(
            r#"{{"v":1,"server_url":"wss://example.test/ws/agent","prefer":"ru","since_ms":{T0},"why":"x"}}"#
        ));
        assert_eq!(starts_on(T0 + H), Endpoint::Primary, "another server's");
        write("{ not json");
        assert_eq!(starts_on(T0 + H), Endpoint::Primary, "unreadable");
        write(&format!(
            r#"{{"v":1,"server_url":"{PROD}","prefer":"primary","since_ms":{T0},"why":"x"}}"#
        ));
        assert_eq!(
            starts_on(T0 + H),
            Endpoint::Primary,
            "prefers nothing known"
        );
        write(&format!(
            r#"{{"v":1,"server_url":"{PROD}","prefer":"ru","since_ms":{},"why":"x"}}"#,
            T0 + 100 * H
        ));
        assert_eq!(
            starts_on(T0),
            Endpoint::Primary,
            "dated in the future: a clock that moved"
        );
        write(&format!(
            r#"{{"v":1,"server_url":"{PROD}","prefer":"ru","since_ms":{T0},"why":"x"}}"#
        ));
        assert_eq!(starts_on(T0 + H), Endpoint::Ru, "a good one is followed");
        // A development server never reads it.
        assert_eq!(
            Entry::open(Some(file.0.clone()), "ws://localhost:8787/ws/agent", T0 + H).preferred(),
            Endpoint::Primary
        );
    }

    #[test]
    fn http_goes_the_way_in_use_first_and_the_other_second() {
        let entry = Entry::open(None, PROD, T0);
        let manifest = "https://api.afklink.app/download/latest.json";
        let ru_manifest = "https://api.ru.afklink.app/download/latest.json";
        assert_eq!(
            entry.http_order(manifest),
            vec![
                (Endpoint::Primary, manifest.to_string()),
                (Endpoint::Ru, ru_manifest.to_string())
            ]
        );
        entry.record_at(Endpoint::Primary, &decisive(), T0);
        assert_eq!(
            entry.http_order(manifest),
            vec![
                (Endpoint::Ru, ru_manifest.to_string()),
                (Endpoint::Primary, manifest.to_string())
            ]
        );
        // An address with no alternative: alone.
        assert_eq!(
            entry.http_order("https://example.test/latest.json"),
            vec![(
                Endpoint::Primary,
                "https://example.test/latest.json".to_string()
            )]
        );
        // A development build still falls back for the production host's files.
        let dev = Entry::open(None, "ws://localhost:8787/ws/agent", T0);
        assert_eq!(dev.http_order(manifest).len(), 2);
        assert_eq!(dev.http_order(manifest)[0].0, Endpoint::Primary);
    }
}
