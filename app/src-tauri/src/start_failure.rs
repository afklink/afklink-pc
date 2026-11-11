//! The start failure beacon: when the app cannot start (today: no WebView2 Runtime,
//! `webview_runtime`), one `POST /api/agent/start-failure` on its way out (the contract's
//! `start-failure.ts`, mirrored in `afklink_protocol::start_failure`). Such a PC never reaches the
//! signaling server, so without it «downloaded but could not start» is invisible.
//!
//! # The way out
//!
//! `run` finds the runtime missing and logs it, then:
//!
//! 1. [`start`], before the message box (which waits for the person): the body and address are
//!    built here and handed to a thread of its own, which sends once, no retry, within
//!    [`CONNECT_TIMEOUT`] and [`REQUEST_TIMEOUT`].
//! 2. The message box.
//! 3. [`Pending::finish`]: an answer that came while the box was open is taken at once; one still
//!    on its way is waited for at most [`EXIT_GRACE`]. Then one outcome line ([`Ended`]).
//! 4. The log is flushed and the process exits with `EXIT_NO_RUNTIME`.
//!
//! The answer changes nothing: the person is already looking at the box that says what to install.
//!
//! The outcome line says "not sent" only when no request can have left; whenever reqwest's error
//! ([`classify`]) cannot rule out that the request reached the server, it says "it may have
//! arrived". Through a VPN the server stored a beacon 6.2 s after it left, past a 4.75 s limit
//! that would have had the line say «not sent».
//!
//! # What is sent, and where
//!
//! Exactly the contract's fields, checked before sending ([`prepare`]): reason, device id, version
//! and channel, short commit, Windows version, the loader's HRESULT. No name, no account, no path;
//! nothing is signed (the device key is not loaded yet).
//!
//! The address is the signaling server's with `wss` → `https` ([`endpoint`]). For the production
//! host there are two ways in (the RU entry, `afklink_core::entry`): the one this PC remembers
//! working goes first, and the other gets the same beacon once when the first gets no answer at all
//! ([`routed`], `send_blocking`).

use std::convert::identity;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use afklink_core::build_info::{BuildInfo, Channel};
use afklink_protocol::start_failure::{
    is_os, limits, AgentStartFailure, BuildChannel, StartFailureReason, AGENT_START_FAILURE_PATH,
};
use reqwest::Url;

/// How long connecting may take: the name, TCP, a proxy and TLS — reqwest's `connect_timeout`
/// covers the whole connector. Generous for a slow link (a VPN, a far TLS edge): a limit set for
/// the exit, such as 3 s, is too short for the link. Shorter than [`REQUEST_TIMEOUT`] on purpose:
/// connecting has always ended before the whole request's limit runs out, so that limit's timeout
/// means the connection was made and the request may have arrived ([`classify`]).
pub(crate) const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// The whole request's own limit, connecting included. Generous, because it runs while the message
/// box is open and a person reading the box gives it that time (measured through a VPN: a
/// 4.75 s limit ran out, the server stored the beacon 6.2 s after it left); bounded, so a server
/// that never answers still ends in an outcome line while the box is open.
pub(crate) const REQUEST_TIMEOUT: Duration = Duration::from_secs(20);

/// How long the way out waits, once the box is closed, for an answer still on its way: a person who
/// closes the box at once waits at most this long for the exit. An answer that came while the box
/// was open is taken without waiting.
pub(crate) const EXIT_GRACE: Duration = Duration::from_secs(2);

// The classification relies on it: a timeout of the whole request comes after connecting has ended.
const _: () = assert!(CONNECT_TIMEOUT.as_millis() < REQUEST_TIMEOUT.as_millis());

/// The request's own limits: [`TIMEOUTS`] in the app, shorter in tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Timeouts {
    connect: Duration,
    request: Duration,
}

/// The app's limits.
const TIMEOUTS: Timeouts = Timeouts {
    connect: CONNECT_TIMEOUT,
    request: REQUEST_TIMEOUT,
};

/// The beacon ready to go: where, and the body as sent (the contract's JSON).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Prepared {
    pub(crate) url: Url,
    pub(crate) body: Vec<u8>,
    /// The same path on the other way to the server (the RU entry, or back from it), tried once when
    /// [`Prepared::url`] gets no answer ([`send_blocking`]); `None`: no other way.
    pub(crate) fallback: Option<Url>,
}

/// Where the beacon goes for the signaling address `server_url`: `wss` → `https`, `ws` → `http`, the
/// same host and port, [`AGENT_START_FAILURE_PATH`] in place of the path, no query, fragment or
/// credentials. Any other scheme, or no host: `Err`, and no beacon.
pub(crate) fn endpoint(server_url: &str) -> Result<Url, String> {
    let mut url = Url::parse(server_url.trim())
        .map_err(|e| format!("the server address {server_url:?} is not a URL: {e}"))?;
    let scheme = match url.scheme() {
        "wss" => "https",
        "ws" => "http",
        other => {
            return Err(format!(
                "the server address {server_url:?} has the scheme {other:?}, not ws or wss"
            ))
        }
    };
    if url.host_str().is_none_or(str::is_empty) {
        return Err(format!("the server address {server_url:?} has no host"));
    }
    url.set_scheme(scheme)
        .map_err(|()| format!("{server_url:?}: the scheme not changed to {scheme}"))?;
    url.set_path(AGENT_START_FAILURE_PATH);
    url.set_query(None);
    url.set_fragment(None);
    if url.set_username("").is_err() || url.set_password(None).is_err() {
        return Err(format!(
            "{server_url:?}: its credentials could not be removed"
        ));
    }
    Ok(url)
}

/// The channel as the contract names it.
pub(crate) fn channel(channel: Channel) -> BuildChannel {
    match channel {
        Channel::Dev => BuildChannel::Dev,
        Channel::Release => BuildChannel::Release,
    }
}

/// `detail_code` from the loader's error: its HRESULT as `0x` and 8 lowercase hex digits, or `None`
/// when the error has none (the empty-version answer).
pub(crate) fn detail_code(detail: &str) -> Option<String> {
    crate::webview_runtime::loader_hresult(detail).map(|hr| format!("0x{hr:08x}"))
}

/// `os` as the contract takes it: `major.minor.build`, and `.revision` when there is one that fits
/// (an update revision past six digits has never existed; it would be left out, not the beacon).
/// `Err` when the three numbers themselves do not fit.
pub(crate) fn os_text(
    major: u32,
    minor: u32,
    build: u32,
    revision: Option<u32>,
) -> Result<String, String> {
    let base = format!("{major}.{minor}.{build}");
    if !is_os(&base) {
        return Err(format!(
            "Windows {base} does not fit the contract's major.minor.build"
        ));
    }
    let Some(revision) = revision else {
        return Ok(base);
    };
    let full = format!("{base}.{revision}");
    if is_os(&full) {
        Ok(full)
    } else {
        tracing::debug!(
            %base,
            revision,
            "start failure beacon: the update revision does not fit the contract's os; left out"
        );
        Ok(base)
    }
}

/// This Windows for the beacon: `RtlGetVersion`'s numbers (the real ones, whatever the exe's
/// manifest declares) and the registry's `UBR` when it can be read.
pub(crate) fn windows_os() -> Result<String, String> {
    let (major, minor, build) = platform::version()?;
    let revision = platform::revision()
        .inspect_err(|e| {
            tracing::debug!("start failure beacon: no update revision for os, sent without: {e}");
        })
        .ok();
    let os = os_text(major, minor, build, revision)?;
    tracing::debug!(
        major,
        minor,
        build,
        revision = ?revision,
        %os,
        "start failure beacon: the Windows version (RtlGetVersion, UBR)"
    );
    Ok(os)
}

/// The beacon for `reason`, checked against the contract (`AgentStartFailure::check`), and where it
/// goes. `os` is [`windows_os`]'s answer (`major.minor.build[.UBR]` from `RtlGetVersion` and the
/// registry's `UBR`); `detail` the failing component's error text, of which only its HRESULT is
/// sent, as `0x` and 8 hex digits ([`detail_code`]). The commit is sent when the build was stamped.
///
/// `device_id` is config.json's, loaded before the probe: the very value `agent_hello` sends and
/// the diagnostics upload's `x-afklink-device`, so the server can tell when the same PC registers
/// later, after the runtime is installed. On a first run this launch wrote config.json and the id
/// with it; the next launch reads the same file.
pub(crate) fn prepare(
    reason: StartFailureReason,
    server_url: &str,
    device_id: &str,
    build: &BuildInfo,
    detail: &str,
    os: Result<String, String>,
) -> Result<Prepared, String> {
    let url = endpoint(server_url)?;
    tracing::debug!(
        server = server_url,
        %url,
        "start failure beacon: the signaling server's host over http(s), the contract's path"
    );
    let os =
        os.map_err(|e| format!("the Windows version is unknown ({e}); the contract needs it"))?;
    let detail_code = detail_code(detail);
    match &detail_code {
        Some(code) => {
            // not-a-key-name: an HRESULT
            tracing::debug!(%code, "start failure beacon: the loader's HRESULT as detail_code")
        }
        None => tracing::debug!(
            "start failure beacon: no HRESULT in the loader's error; detail_code left out"
        ),
    }
    let beacon = AgentStartFailure {
        reason,
        device_id: device_id.to_string(),
        version: build.version.clone(),
        channel: channel(build.channel),
        commit: build.short_commit().map(str::to_string),
        os,
        detail_code,
    };
    if let Err(e) = beacon.check() {
        let value = match e.field {
            "device_id" => beacon.device_id.as_str(),
            "version" => beacon.version.as_str(),
            "commit" => beacon.commit.as_deref().unwrap_or("-"),
            "os" => beacon.os.as_str(),
            "detail_code" => beacon.detail_code.as_deref().unwrap_or("-"),
            _ => "-",
        };
        return Err(format!("{e}: {value:?}"));
    }
    let body = serde_json::to_vec(&beacon).map_err(|e| format!("the body not serialized: {e}"))?;
    if body.len() > limits::BODY_BYTES {
        return Err(format!(
            "the body is {} bytes, over the contract's {}",
            body.len(),
            limits::BODY_BYTES
        ));
    }
    Ok(Prepared {
        url,
        body,
        fallback: None,
    })
}

/// `prepared` sent the way `entry` prefers — the RU entry when this PC remembers it worked
/// (`afklink_core::entry`; no socket has run yet) — with the other way as its fallback, when the
/// address has one.
pub(crate) fn routed(prepared: Prepared, entry: &afklink_core::entry::Entry) -> Prepared {
    let mut order = entry
        .http_order(prepared.url.as_str())
        .into_iter()
        .filter_map(|(way, url)| match Url::parse(&url) {
            Ok(parsed) => Some((way, parsed)),
            Err(e) => {
                tracing::debug!(
                    way = way.as_str(),
                    %url,
                    "start failure beacon: an address that is not a URL ({e}); skipped"
                );
                None
            }
        });
    let Some((first_way, first)) = order.next() else {
        return prepared;
    };
    let fallback = order.next();
    tracing::debug!(
        first = %first,
        first_way = first_way.as_str(),
        fallback = %fallback.as_ref().map_or_else(|| "-".to_string(), |(_, url)| url.to_string()),
        "start failure beacon: the way to the server, the remembered one first"
    );
    Prepared {
        url: first,
        fallback: fallback.map(|(_, url)| url),
        ..prepared
    }
}

/// How the request ended, as its thread saw it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Answer {
    /// The server answered: its status, and the contract's error code when a refusal had one.
    Status { status: u16, code: Option<String> },
    /// No request left, so the server cannot have it: the thread could not set it up, or no
    /// connection was made. Why.
    NotSent(String),
    /// The request left, or may have, and no answer came: why, and whether it was the whole
    /// request's limit that ran out (`timed_out`) rather than the connection breaking.
    Unanswered { why: String, timed_out: bool },
}

/// What the thread hands back: the answer, and how long the request took.
#[derive(Debug)]
struct Reply {
    answer: Answer,
    elapsed_ms: u64,
}

/// How the beacon ended, as [`Pending::finish`] logs it. `elapsed_ms`: the request's own time.
///
/// The lines: `start failure beacon sent` (a 2xx); `…sent, but the server refused it` (or
/// `…, but over the server's budget: not stored` for a 429), with the status and error code;
/// `…not sent: <why>` (could not be set up, or no connection was made: the name not resolved,
/// refused, unreachable, TLS failed, or connecting took longer than [`CONNECT_TIMEOUT`]);
/// `…got no answer in time; it may have arrived` (connected, then [`REQUEST_TIMEOUT`] ran out);
/// `…got no answer; it may have arrived` (the connection broke, the answer could not be read, or
/// the thread ended without a word); `…still in flight at exit: abandoned; it may have arrived`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Ended {
    /// A 2xx: the server took it.
    Sent { status: u16, elapsed_ms: u64 },
    /// The server answered with a refusal, and its error code when the body had one.
    Refused {
        status: u16,
        code: Option<String>,
        elapsed_ms: u64,
    },
    /// No request left — the server cannot have it: why (the request's time, when it was tried).
    NotSent {
        why: String,
        elapsed_ms: Option<u64>,
    },
    /// It left, or may have, and no answer came — it may have arrived: why, whether the whole
    /// request's limit ran out, and the request's time (none when its thread ended without a word).
    Unanswered {
        why: String,
        timed_out: bool,
        elapsed_ms: Option<u64>,
    },
    /// Still on its way when the grace after the message box ran out: abandoned to the exit — it
    /// may have arrived.
    InFlight,
}

/// HTTP 429: the server's budget for beacons is spent — expected under a burst, not a fault here.
const TOO_MANY_REQUESTS: u16 = 429;

impl Ended {
    /// How the beacon ended, from what the way out received from its thread.
    fn from_reply(received: Result<Reply, mpsc::RecvTimeoutError>) -> Self {
        match received {
            Ok(Reply {
                answer: Answer::Status { status, .. },
                elapsed_ms,
            }) if (200..300).contains(&status) => Self::Sent { status, elapsed_ms },
            Ok(Reply {
                answer: Answer::Status { status, code },
                elapsed_ms,
            }) => Self::Refused {
                status,
                code,
                elapsed_ms,
            },
            Ok(Reply {
                answer: Answer::NotSent(why),
                elapsed_ms,
            }) => Self::NotSent {
                why,
                elapsed_ms: Some(elapsed_ms),
            },
            Ok(Reply {
                answer: Answer::Unanswered { why, timed_out },
                elapsed_ms,
            }) => Self::Unanswered {
                why,
                timed_out,
                elapsed_ms: Some(elapsed_ms),
            },
            Err(mpsc::RecvTimeoutError::Timeout) => Self::InFlight,
            // A thread that ended without a word (a panic) may have ended after the request left.
            Err(mpsc::RecvTimeoutError::Disconnected) => Self::Unanswered {
                why: "its thread ended without an answer".into(),
                timed_out: false,
                elapsed_ms: None,
            },
        }
    }

    /// The outcome's line: `info` when the server took it (or only its budget refused it), `warn`
    /// otherwise.
    fn log(&self, since_start_ms: u64, grace_ms: u64) {
        match self {
            Self::Sent { status, elapsed_ms } => {
                tracing::info!(status, elapsed_ms, "start failure beacon sent");
            }
            Self::Refused {
                status,
                code,
                elapsed_ms,
            } => {
                let code = code.as_deref().unwrap_or("-");
                if *status == TOO_MANY_REQUESTS {
                    // not-a-key-name: the server's error code
                    tracing::info!(
                        status,
                        code,
                        elapsed_ms,
                        "start failure beacon sent, but over the server's budget: not stored"
                    );
                } else {
                    // not-a-key-name: the server's error code
                    tracing::warn!(
                        status,
                        code,
                        elapsed_ms,
                        "start failure beacon sent, but the server refused it"
                    );
                }
            }
            Self::NotSent { why, elapsed_ms } => {
                tracing::warn!(elapsed_ms = ?elapsed_ms, "start failure beacon not sent: {why}");
            }
            Self::Unanswered {
                why,
                timed_out: true,
                elapsed_ms,
            } => tracing::warn!(
                elapsed_ms = ?elapsed_ms,
                "start failure beacon got no answer in time; it may have arrived: {why}"
            ),
            Self::Unanswered {
                why,
                timed_out: false,
                elapsed_ms,
            } => tracing::warn!(
                elapsed_ms = ?elapsed_ms,
                "start failure beacon got no answer; it may have arrived: {why}"
            ),
            Self::InFlight => tracing::warn!(
                since_start_ms,
                grace_ms,
                "start failure beacon still in flight at exit: abandoned; it may have arrived"
            ),
        }
    }
}

/// A beacon on its way: what the way out waits for after the message box.
#[derive(Debug)]
pub(crate) struct Pending {
    started: Instant,
    timeouts: Timeouts,
    /// How long [`Pending::finish`] waits for an answer not there yet ([`EXIT_GRACE`]).
    grace: Duration,
    reply: mpsc::Receiver<Reply>,
}

/// Build the beacon for `reason` and send it on a thread of its own; `None` (and a `warn`) when there
/// is nothing to send or no thread for it. Call before anything that waits for the person; then
/// [`Pending::finish`].
pub(crate) fn start(
    reason: StartFailureReason,
    server_url: &str,
    entry: &afklink_core::entry::Entry,
    device_id: &str,
    build: &BuildInfo,
    detail: &str,
) -> Option<Pending> {
    let started = Instant::now();
    let prepared = match prepare(reason, server_url, device_id, build, detail, windows_os()) {
        Ok(prepared) => routed(prepared, entry),
        Err(why) => {
            tracing::warn!(%reason, "start failure beacon not sent: {why}");
            return None;
        }
    };
    // The client as built (proxy settings from the environment apply, as for «Отправить логи»).
    spawn(
        prepared,
        build.user_agent(),
        started,
        TIMEOUTS,
        EXIT_GRACE,
        identity,
    )
}

/// Send `prepared` on a thread named `start-failure-beacon`, within `timeouts`; [`Pending::finish`]
/// then waits at most `grace` for an answer not there yet. `started`: when [`start`] began, for the
/// log. `tune` adjusts the HTTP client (tests: no proxy).
fn spawn(
    prepared: Prepared,
    user_agent: String,
    started: Instant,
    timeouts: Timeouts,
    grace: Duration,
    tune: fn(reqwest::ClientBuilder) -> reqwest::ClientBuilder,
) -> Option<Pending> {
    tracing::debug!(
        url = %prepared.url,
        fallback = %prepared
            .fallback
            .as_ref()
            .map_or_else(|| "-".to_string(), ToString::to_string),
        body = %String::from_utf8_lossy(&prepared.body),
        bytes = prepared.body.len(),
        %user_agent,
        connect_timeout_ms = timeouts.connect.as_millis() as u64,
        request_timeout_ms = timeouts.request.as_millis() as u64,
        exit_grace_ms = grace.as_millis() as u64,
        "start failure beacon: sending once, on a thread of its own, before the message box"
    );
    let (tx, rx) = mpsc::channel();
    let spawned = std::thread::Builder::new()
        .name("start-failure-beacon".into())
        .spawn(move || {
            let Reply { answer, elapsed_ms } =
                send_blocking(&prepared, &user_agent, timeouts, tune);
            tracing::debug!(
                answer = ?answer,
                elapsed_ms,
                since_start_ms = started.elapsed().as_millis() as u64,
                "start failure beacon: the request ended"
            );
            if tx.send(Reply { answer, elapsed_ms }).is_err() {
                // The way out stopped waiting (its line says the beacon was abandoned); the
                // process is ending.
                tracing::debug!(
                    "start failure beacon: the request ended after the way out stopped waiting"
                );
            }
        });
    match spawned {
        Ok(_detached) => Some(Pending {
            started,
            timeouts,
            grace,
            reply: rx,
        }),
        Err(e) => {
            tracing::warn!("start failure beacon not sent: no thread for it: {e}");
            None
        }
    }
}

/// The request, from its own runtime and client, within `timeouts`.
fn send_blocking(
    prepared: &Prepared,
    user_agent: &str,
    timeouts: Timeouts,
    tune: fn(reqwest::ClientBuilder) -> reqwest::ClientBuilder,
) -> Reply {
    let started = Instant::now();
    let reply = |answer: Answer| Reply {
        answer,
        elapsed_ms: started.elapsed().as_millis() as u64,
    };
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(e) => return reply(Answer::NotSent(format!("no async runtime: {e}"))),
    };
    // No redirect followed: our server answers the beacon's address itself, so a redirect is
    // something in the way, and the beacon — the device id, the build, why it could not start — has
    // no business going where it points. A 3xx is said and taken as not sent (`post`).
    let client = match tune(
        reqwest::Client::builder()
            .connect_timeout(timeouts.connect)
            .timeout(timeouts.request)
            .user_agent(user_agent)
            .redirect(reqwest::redirect::Policy::none()),
    )
    .build()
    {
        Ok(client) => client,
        Err(e) => {
            return reply(Answer::NotSent(format!(
                "HTTP client not built: {}",
                error_chain(&e)
            )))
        }
    };
    let answer = runtime.block_on(async {
        let first = post(&client, &prepared.url, prepared.body.clone(), timeouts).await;
        let Some(fallback) = &prepared.fallback else {
            return first;
        };
        // No answer this way — no connection, or no word after it (a path that froze the answer):
        // once more the other way. An answer, even a refusal, is the server's and stands. A request
        // that may have arrived can arrive twice; a beacon lost is worse than one counted twice.
        let why = match &first {
            Answer::Status { .. } => return first,
            Answer::NotSent(why) => format!("not sent: {why}"),
            Answer::Unanswered { why, .. } => format!("no answer, it may have arrived: {why}"),
        };
        tracing::warn!(
            url = %prepared.url,
            %fallback,
            elapsed_ms = started.elapsed().as_millis() as u64,
            "start failure beacon: no answer this way ({why}); once more the other way"
        );
        let second = post(&client, fallback, prepared.body.clone(), timeouts).await;
        tracing::debug!(
            answer = ?second,
            elapsed_ms = started.elapsed().as_millis() as u64,
            "start failure beacon: the other way's answer"
        );
        second
    });
    // Not dropped: a drop would wait for a name lookup still running on the blocking pool.
    runtime.shutdown_background();
    reply(answer)
}

/// The server's `{ error, message? }`.
#[derive(Debug, serde::Deserialize)]
struct ErrorBody {
    error: Option<String>,
}

/// The one network call: `body` as JSON to `url`, and what came back. A refusal's body is read for
/// its error code only.
async fn post(client: &reqwest::Client, url: &Url, body: Vec<u8>, timeouts: Timeouts) -> Answer {
    let response = match client
        .post(url.clone())
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(body)
        .send()
        .await
    {
        Ok(response) => response,
        Err(e) => return classify(&e, timeouts),
    };
    let status = response.status().as_u16();
    if response.status().is_success() {
        return Answer::Status { status, code: None };
    }
    // Not followed (the client follows none). Our server never sends one, so it did not get the
    // beacon: not sent — and the other way is tried, as for no connection.
    if response.status().is_redirection() {
        let to = redirect_target(&response);
        tracing::warn!(
            status,
            %to,
            "start failure beacon: the address answered with a redirect, not followed (our server \
             never sends one: something is in the way)"
        );
        return Answer::NotSent(format!(
            "a redirect ({status}) to {to}, not followed: our server never sends one"
        ));
    }
    let code = match response.bytes().await {
        Ok(body) => match serde_json::from_slice::<ErrorBody>(&body) {
            Ok(refusal) => refusal.error,
            Err(e) => {
                tracing::debug!(
                    status,
                    bytes = body.len(),
                    "start failure beacon: the refusal's body has no error code: {e}"
                );
                None
            }
        },
        Err(e) => {
            tracing::debug!(
                status,
                "start failure beacon: the refusal's body not read: {e}"
            );
            None
        }
    };
    Answer::Status { status, code }
}

/// Where a redirect pointed, for the log: the scheme and host of its `Location`, never its path or
/// query; or why it could not be read.
fn redirect_target(response: &reqwest::Response) -> String {
    let Some(location) = response.headers().get(reqwest::header::LOCATION) else {
        return "- (no Location)".into();
    };
    let Ok(location) = location.to_str() else {
        return "- (Location not text)".into();
    };
    match response.url().join(location) {
        Ok(url) => format!("{}://{}", url.scheme(), url.host_str().unwrap_or("-")),
        Err(e) => format!("- (Location not a URL: {e})"),
    }
}

/// A request that failed without an answer: whether it can have reached the server, and why.
///
/// From reqwest's classification:
/// - `is_connect`: the connector failed — the name, TCP, a proxy or TLS, or connecting took longer
///   than `timeouts.connect` (`is_timeout` too). No connection was made, so not a byte of the
///   request was written: not sent.
/// - `is_builder`: the request was never made: not sent.
/// - a timeout that is not the connector's: the whole request's limit. Connecting has its own,
///   shorter limit ([`CONNECT_TIMEOUT`] < [`REQUEST_TIMEOUT`]), so by then the connection was made
///   and the request was being written or waited on: it may have arrived.
/// - anything else (the connection closed or reset, an answer that could not be read) may have come
///   after the request left: it may have arrived. (A redirect is an answer, not an error here: the
///   client follows none, and `post` says it.)
fn classify(e: &reqwest::Error, timeouts: Timeouts) -> Answer {
    // The error names the URL: the server's host and the beacon's path, nothing secret.
    let what = error_chain(e);
    if e.is_connect() {
        let why = if e.is_timeout() {
            format!(
                "no connection within {} ms: {what}",
                timeouts.connect.as_millis()
            )
        } else if e.is_dns() {
            format!("no connection, the server's name not resolved: {what}")
        } else {
            format!("no connection: {what}")
        };
        return Answer::NotSent(why);
    }
    if e.is_builder() {
        return Answer::NotSent(format!("the request not built: {what}"));
    }
    if e.is_timeout() {
        return Answer::Unanswered {
            why: format!(
                "connected, then no answer within the request's {} ms: {what}",
                timeouts.request.as_millis()
            ),
            timed_out: true,
        };
    }
    let kind = if e.is_redirect() {
        "redirect"
    } else if e.is_body() {
        "body"
    } else if e.is_decode() {
        "decode"
    } else {
        "request"
    };
    Answer::Unanswered {
        why: format!("{kind}: {what}"),
        timed_out: false,
    }
}

/// An error and its sources, on one line: reqwest's own text names only its kind and the URL, and
/// what happened (refused, timed out, reset) is in the sources.
fn error_chain(e: &dyn std::error::Error) -> String {
    let mut text = e.to_string();
    let mut source = e.source();
    while let Some(cause) = source {
        let cause_text = cause.to_string();
        // Some errors repeat their source in their own text.
        if !text.ends_with(&cause_text) {
            text.push_str(": ");
            text.push_str(&cause_text);
        }
        source = cause.source();
    }
    text
}

impl Pending {
    /// Take the answer — at once when it came while the message box was open, else waiting at most
    /// the grace — and log how the beacon ended, before the log is flushed and the process exits.
    pub(crate) fn finish(self) -> Ended {
        let grace_ms = self.grace.as_millis() as u64;
        let received = match self.reply.try_recv() {
            Ok(reply) => {
                tracing::debug!(
                    since_start_ms = self.started.elapsed().as_millis() as u64,
                    "start failure beacon: its request ended while the message box was open"
                );
                Ok(reply)
            }
            Err(mpsc::TryRecvError::Empty) => {
                tracing::debug!(
                    since_start_ms = self.started.elapsed().as_millis() as u64,
                    grace_ms,
                    request_timeout_ms = self.timeouts.request.as_millis() as u64,
                    "start failure beacon: still on its way when the message box closed; waiting \
                     at most the grace before the exit"
                );
                self.reply.recv_timeout(self.grace)
            }
            Err(mpsc::TryRecvError::Disconnected) => Err(mpsc::RecvTimeoutError::Disconnected),
        };
        let ended = Ended::from_reply(received);
        ended.log(self.started.elapsed().as_millis() as u64, grace_ms);
        ended
    }
}

#[cfg(windows)]
mod platform {
    use windows::Wdk::System::SystemServices::RtlGetVersion;
    use windows::Win32::System::SystemInformation::OSVERSIONINFOW;
    use winreg::enums::HKEY_LOCAL_MACHINE;
    use winreg::RegKey;

    /// Major, minor and build from `RtlGetVersion`, which unlike `GetVersionEx` does not answer what
    /// the exe's manifest lets it.
    pub(super) fn version() -> Result<(u32, u32, u32), String> {
        let mut info = OSVERSIONINFOW {
            dwOSVersionInfoSize: std::mem::size_of::<OSVERSIONINFOW>() as u32,
            ..Default::default()
        };
        // SAFETY: a live struct with its size set, as the call requires.
        let status = unsafe { RtlGetVersion(&mut info) };
        if status.is_ok() {
            Ok((info.dwMajorVersion, info.dwMinorVersion, info.dwBuildNumber))
        } else {
            Err(format!("RtlGetVersion: NTSTATUS {:#010x}", status.0 as u32))
        }
    }

    /// The update build revision (`UBR`), as `system.json` reads it (`diagnostics::system`).
    pub(super) fn revision() -> Result<u32, String> {
        RegKey::predef(HKEY_LOCAL_MACHINE)
            .open_subkey(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion")
            .and_then(|key| key.get_value::<u32, _>("UBR"))
            .map_err(|e| format!("UBR: {e}"))
    }
}

#[cfg(not(windows))]
mod platform {
    pub(super) fn version() -> Result<(u32, u32, u32), String> {
        Err("not Windows".into())
    }
    pub(super) fn revision() -> Result<u32, String> {
        Err("not Windows".into())
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};

    use super::*;
    use crate::webview_runtime::{assess, Runtime, SIMULATED_ERROR};
    use serde_json::Value;

    const DEVICE: &str = "a3f1c2d4-5b6e-4f7a-8c9d-0e1f2a3b4c5d";

    /// The loader's error as `assess` words it.
    fn missing(error: &str) -> String {
        match assess(Err(error.to_string())) {
            Runtime::Missing { detail } => detail,
            Runtime::Present { .. } => unreachable!("an error is never a runtime"),
        }
    }

    fn release() -> BuildInfo {
        BuildInfo::from_stamp("0.5.0", "7d537e2", "0", "2026-10-09T12:00:00Z", "release")
    }

    fn fixture() -> Value {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../contract/packages/protocol/fixtures/rest/agent_start_failure.json");
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| unreachable!("{}: {e} (the contract submodule)", path.display()));
        serde_json::from_str(&text).expect("the fixture parses")
    }

    #[test]
    fn the_endpoint_is_the_signaling_host_over_http() {
        let ok = |from: &str| endpoint(from).map(|u| u.to_string());
        assert_eq!(
            ok(afklink_core::config::PROD_SERVER_URL).as_deref(),
            Ok("https://api.afklink.app/api/agent/start-failure")
        );
        assert_eq!(
            ok("ws://localhost:8787/ws/agent").as_deref(),
            Ok("http://localhost:8787/api/agent/start-failure")
        );
        // Plain ws anywhere: the beacon carries nothing secret, and it goes where the socket would.
        assert_eq!(
            ok("ws://dev.example.test/ws/agent").as_deref(),
            Ok("http://dev.example.test/api/agent/start-failure")
        );
        // A trailing slash, no path at all, spaces around, upper case.
        assert_eq!(
            ok("wss://api.afklink.app/").as_deref(),
            Ok("https://api.afklink.app/api/agent/start-failure")
        );
        assert_eq!(
            ok("wss://api.afklink.app").as_deref(),
            Ok("https://api.afklink.app/api/agent/start-failure")
        );
        assert_eq!(
            ok("  WSS://API.AFKLINK.APP/WS/AGENT \n").as_deref(),
            Ok("https://api.afklink.app/api/agent/start-failure")
        );
        // A port kept; the scheme's own port dropped; query, fragment and credentials gone.
        assert_eq!(
            ok("wss://user:pw@example.test:8443/ws/agent?x=1#f").as_deref(),
            Ok("https://example.test:8443/api/agent/start-failure")
        );
        assert_eq!(
            ok("wss://example.test:443/ws/agent").as_deref(),
            Ok("https://example.test/api/agent/start-failure")
        );
        assert_eq!(
            ok("ws://127.0.0.1:80/ws/agent").as_deref(),
            Ok("http://127.0.0.1/api/agent/start-failure")
        );
        assert_eq!(
            ok("ws://[::1]:8787/ws/agent").as_deref(),
            Ok("http://[::1]:8787/api/agent/start-failure")
        );
        // Anything but ws and wss: no beacon.
        for bad in [
            "https://api.afklink.app/ws/agent",
            "http://localhost:8787/ws/agent",
            "ftp://example.test/",
            "file:///C:/x",
            "not a url",
            "",
            "wss://",
            "localhost:8787/ws/agent",
        ] {
            let refused = endpoint(bad);
            assert!(refused.is_err(), "{bad:?}: {refused:?}");
        }
    }

    #[test]
    fn os_is_major_minor_build_and_the_revision_that_fits() {
        assert_eq!(
            os_text(10, 0, 26100, Some(6584)).as_deref(),
            Ok("10.0.26100.6584")
        );
        assert_eq!(os_text(10, 0, 19045, None).as_deref(), Ok("10.0.19045"));
        assert_eq!(
            os_text(10, 0, 19045, Some(0)).as_deref(),
            Ok("10.0.19045.0")
        );
        // A revision past six digits is left out, not the beacon.
        assert_eq!(
            os_text(10, 0, 26100, Some(1_000_000)).as_deref(),
            Ok("10.0.26100")
        );
        assert!(os_text(1000, 0, 1, None).is_err());
        assert!(os_text(10, 0, 1_000_000, Some(1)).is_err());
    }

    /// On the machine running the tests: `RtlGetVersion` and the UBR give what the contract takes.
    #[cfg(windows)]
    #[test]
    fn this_pcs_windows_is_the_contracts_shape() {
        let os = windows_os().expect("RtlGetVersion answers");
        assert!(is_os(&os), "{os}");
        assert!(os.starts_with("10.0."), "Windows 10 and 11 are 10.0: {os}");
        assert_eq!(
            os.split('.').count(),
            4,
            "the UBR is read on Windows 10 and 11: {os}"
        );
        println!("this PC's os: {os}");
    }

    #[test]
    fn the_detail_code_is_the_loaders_hresult_in_lowercase() {
        assert_eq!(
            detail_code(&missing(SIMULATED_ERROR)).as_deref(),
            Some("0x80070002")
        );
        assert_eq!(
            detail_code(&missing(
                "Not enough memory resources are available. (0x8007000E)"
            ))
            .as_deref(),
            Some("0x8007000e")
        );
        let empty = match assess(Ok(String::new())) {
            Runtime::Missing { detail } => detail,
            Runtime::Present { .. } => unreachable!("an empty version is no runtime"),
        };
        assert_eq!(detail_code(&empty), None);
    }

    /// A release on Windows 10 22H2 without the runtime, the loader's «file not found»: byte for byte
    /// the contract's fixture.
    #[test]
    fn the_body_is_the_contracts_fixture() {
        let prepared = prepare(
            StartFailureReason::Webview2Missing,
            afklink_core::config::PROD_SERVER_URL,
            DEVICE,
            &release(),
            &missing("The system cannot find the file specified. (0x80070002)"),
            Ok("10.0.19045.5371".into()),
        )
        .expect("prepared");
        assert_eq!(
            prepared.url.as_str(),
            "https://api.afklink.app/api/agent/start-failure"
        );
        let sent: Value = serde_json::from_slice(&prepared.body).expect("JSON");
        assert_eq!(sent, fixture());
        assert_eq!(
            String::from_utf8(prepared.body).expect("UTF-8"),
            r#"{"reason":"webview2_missing","device_id":"a3f1c2d4-5b6e-4f7a-8c9d-0e1f2a3b4c5d","version":"0.5.0","channel":"release","commit":"7d537e2","os":"10.0.19045.5371","detail_code":"0x80070002"}"#
        );
    }

    /// An unstamped development build, the loader's empty version: no commit, no detail code — the
    /// keys absent, not null — and nothing but the contract's seven keys at most.
    #[test]
    fn an_unstamped_build_without_a_code_leaves_both_out() {
        let dev = BuildInfo::from_stamp("0.5.0", "", "", "", "");
        let empty = match assess(Ok(String::new())) {
            Runtime::Missing { detail } => detail,
            Runtime::Present { .. } => unreachable!("an empty version is no runtime"),
        };
        let prepared = prepare(
            StartFailureReason::Webview2Missing,
            "ws://localhost:8787/ws/agent",
            DEVICE,
            &dev,
            &empty,
            Ok("10.0.26100".into()),
        )
        .expect("prepared");
        assert_eq!(
            String::from_utf8(prepared.body).expect("UTF-8"),
            r#"{"reason":"webview2_missing","device_id":"a3f1c2d4-5b6e-4f7a-8c9d-0e1f2a3b4c5d","version":"0.5.0","channel":"dev","os":"10.0.26100"}"#
        );
    }

    /// Nothing personal can get in: the body's keys are the contract's, and a user or computer name
    /// from the environment is nowhere in it. This PC's Windows, this build, the simulated loader
    /// error — what the live check sends, but for the device id.
    #[cfg(windows)]
    #[test]
    fn the_body_holds_the_contracts_keys_only() {
        let prepared = prepare(
            StartFailureReason::Webview2Missing,
            afklink_core::config::PROD_SERVER_URL,
            DEVICE,
            &crate::build_info(),
            &missing(SIMULATED_ERROR),
            windows_os(),
        )
        .expect("prepared");
        let sent: Value = serde_json::from_slice(&prepared.body).expect("JSON");
        let keys: Vec<&str> = sent
            .as_object()
            .expect("an object")
            .keys()
            .map(String::as_str)
            .collect();
        for key in &keys {
            assert!(
                [
                    "reason",
                    "device_id",
                    "version",
                    "channel",
                    "commit",
                    "os",
                    "detail_code"
                ]
                .contains(key),
                "{key}"
            );
        }
        let text = String::from_utf8_lossy(&prepared.body).into_owned();
        for var in ["USERNAME", "COMPUTERNAME", "USERPROFILE"] {
            if let Ok(value) = std::env::var(var) {
                assert!(!text.contains(&value), "{var} is in the body: {text}");
            }
        }
        println!("this PC's body (simulated, placeholder device id): {text}");
    }

    #[test]
    fn nothing_is_prepared_that_the_contract_refuses() {
        let detail = missing(SIMULATED_ERROR);
        let try_with = |server: &str, device: &str, os: Result<String, String>| {
            prepare(
                StartFailureReason::Webview2Missing,
                server,
                device,
                &release(),
                &detail,
                os,
            )
        };
        let ok = || Ok("10.0.26100.6584".to_string());
        assert!(try_with(afklink_core::config::PROD_SERVER_URL, DEVICE, ok()).is_ok());
        // A device id edited by hand into something else: the server would refuse it.
        let refused =
            try_with(afklink_core::config::PROD_SERVER_URL, "my-pc", ok()).expect_err("not a UUID");
        assert!(
            refused.contains("device_id") && refused.contains("my-pc"),
            "{refused}"
        );
        // An unknown scheme: no beacon.
        let refused =
            try_with("https://api.afklink.app/ws/agent", DEVICE, ok()).expect_err("not ws");
        assert!(refused.contains("not ws or wss"), "{refused}");
        // No Windows version: the contract requires one.
        let refused = try_with(
            afklink_core::config::PROD_SERVER_URL,
            DEVICE,
            Err("RtlGetVersion: NTSTATUS 0xc0000001".into()),
        )
        .expect_err("no os");
        assert!(refused.contains("Windows version is unknown"), "{refused}");
    }

    /// What the mock server saw of one request.
    #[derive(Debug, Clone)]
    struct Seen {
        head: String,
        body: Vec<u8>,
    }

    impl Seen {
        fn header(&self, name: &str) -> Option<String> {
            self.head.lines().find_map(|line| {
                let (n, v) = line.split_once(':')?;
                n.trim()
                    .eq_ignore_ascii_case(name)
                    .then(|| v.trim().to_string())
            })
        }
    }

    /// How the mock answers a request it has read.
    #[derive(Debug, Clone, Copy)]
    enum Mock {
        /// `status` and `body`, after `delay`.
        Answer {
            status: &'static str,
            body: &'static str,
            delay: Duration,
        },
        /// `status` with a `Location` of `location`, and no body.
        Redirect {
            status: &'static str,
            location: &'static str,
        },
        /// Not a word: the connection held for [`HOLD`], past every limit a test waits for.
        Silent,
        /// The connection closed without a word.
        Close,
    }

    /// How long a silent mock holds its connection.
    const HOLD: Duration = Duration::from_secs(30);

    /// An answer at once.
    fn answer(status: &'static str, body: &'static str) -> Mock {
        Mock::Answer {
            status,
            body,
            delay: Duration::ZERO,
        }
    }

    /// A local mock server for one request.
    struct MockServer {
        /// The signaling address that leads to it.
        server: String,
        /// The requests it read.
        seen: Arc<Mutex<Vec<Seen>>>,
        /// A word once its answer is written.
        answered: mpsc::Receiver<()>,
    }

    /// A local server that reads one request and answers it as `mock` says.
    fn serve(mock: Mock) -> MockServer {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let server = format!("ws://{}/ws/agent", listener.local_addr().expect("addr"));
        let seen = Arc::new(Mutex::new(Vec::new()));
        let record = Arc::clone(&seen);
        let (tell, answered) = mpsc::channel();
        std::thread::spawn(move || {
            let Ok((mut stream, _)) = listener.accept() else {
                return;
            };
            let mut data = Vec::new();
            let mut chunk = [0u8; 4096];
            let head_end = loop {
                if let Some(at) = data.windows(4).position(|w| w == b"\r\n\r\n") {
                    break at + 4;
                }
                match stream.read(&mut chunk) {
                    Ok(0) | Err(_) => return,
                    Ok(n) => data.extend_from_slice(&chunk[..n]),
                }
            };
            let head = String::from_utf8_lossy(&data[..head_end]).into_owned();
            let length: usize = head
                .lines()
                .find_map(|l| {
                    let (n, v) = l.split_once(':')?;
                    n.trim()
                        .eq_ignore_ascii_case("content-length")
                        .then(|| v.trim().parse().ok())?
                })
                .unwrap_or(0);
            while data.len() < head_end + length {
                match stream.read(&mut chunk) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => data.extend_from_slice(&chunk[..n]),
                }
            }
            afklink_core::lock(&record).push(Seen {
                head,
                body: data[head_end..].to_vec(),
            });
            match mock {
                Mock::Redirect { status, location } => {
                    let written = write!(
                        stream,
                        "HTTP/1.1 {status}\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    );
                    if written.is_ok() {
                        tell.send(()).ok();
                    }
                }
                Mock::Silent => std::thread::sleep(HOLD),
                Mock::Close => {
                    // Everything was read, so this is a plain close, not a reset.
                    stream
                        .shutdown(std::net::Shutdown::Both)
                        .expect("the mock's connection closed");
                }
                Mock::Answer {
                    status,
                    body,
                    delay,
                } => {
                    std::thread::sleep(delay);
                    let written = write!(
                        stream,
                        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    // No word when the client was gone: a test waiting for it fails saying so. The
                    // test may not be listening for it.
                    if written.is_ok() {
                        tell.send(()).ok();
                    }
                }
            }
        });
        MockServer {
            server,
            seen,
            answered,
        }
    }

    /// A local server that takes the connection and never answers TLS's first message — a TLS
    /// handshake that does not finish: the signaling address (`wss`) that leads to it, and the
    /// first bytes it read.
    fn hold_tls() -> (String, mpsc::Receiver<Vec<u8>>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let server = format!("wss://{}/ws/agent", listener.local_addr().expect("addr"));
        let (tell, first) = mpsc::channel();
        std::thread::spawn(move || {
            let Ok((mut stream, _)) = listener.accept() else {
                return;
            };
            let mut chunk = [0u8; 4096];
            let n = stream.read(&mut chunk).unwrap_or(0);
            tell.send(chunk[..n].to_vec()).ok();
            std::thread::sleep(HOLD);
        });
        (server, first)
    }

    /// Short limits, for a test that waits for them to run out (connecting still the shorter).
    const SHORT: Timeouts = Timeouts {
        connect: Duration::from_millis(300),
        request: Duration::from_millis(800),
    };

    /// A grace that outlasts any limit here: the box held open, as a person reading it does.
    const BOX_OPEN: Duration = Duration::from_secs(10);

    /// Prepare for `server` (the simulated loader error) and send within `timeouts`, no proxy; the
    /// way out then waits at most `grace` for an answer not there yet.
    fn send(server: &str, timeouts: Timeouts, grace: Duration) -> (Pending, Prepared) {
        let prepared = prepare(
            StartFailureReason::Webview2Missing,
            server,
            DEVICE,
            &release(),
            &missing(SIMULATED_ERROR),
            Ok("10.0.26100.6584".into()),
        )
        .expect("prepared");
        let pending = spawn(
            prepared.clone(),
            "AFKLink/0.5.0 (release)".into(),
            Instant::now(),
            timeouts,
            grace,
            reqwest::ClientBuilder::no_proxy,
        )
        .expect("a thread");
        (pending, prepared)
    }

    #[test]
    fn a_204_is_sent_with_the_body_as_json() {
        let mock = serve(answer("204 No Content", ""));
        let (pending, prepared) = send(&mock.server, TIMEOUTS, BOX_OPEN);
        let ended = pending.finish();
        assert!(
            matches!(ended, Ended::Sent { status: 204, .. }),
            "{ended:?}"
        );
        let seen = afklink_core::lock(&mock.seen).clone();
        assert_eq!(seen.len(), 1, "once, no retry");
        let request = &seen[0];
        assert!(
            request
                .head
                .starts_with("POST /api/agent/start-failure HTTP/1.1"),
            "{}",
            request.head
        );
        assert_eq!(
            request.header("content-type").as_deref(),
            Some("application/json")
        );
        assert_eq!(
            request.header("user-agent").as_deref(),
            Some("AFKLink/0.5.0 (release)")
        );
        assert_eq!(request.body, prepared.body);
    }

    #[test]
    fn a_refusal_is_told_with_its_code_and_not_retried() {
        let refused = |status: &'static str, body: &'static str| {
            let mock = serve(answer(status, body));
            let (pending, _) = send(&mock.server, TIMEOUTS, BOX_OPEN);
            let ended = pending.finish();
            assert_eq!(afklink_core::lock(&mock.seen).len(), 1, "{status}: once");
            match ended {
                Ended::Refused { status, code, .. } => (status, code),
                other => unreachable!("expected a refusal, got {other:?}"),
            }
        };
        assert_eq!(
            refused("400 Bad Request", r#"{"error":"bad_message"}"#),
            (400, Some("bad_message".into()))
        );
        assert_eq!(
            refused("429 Too Many Requests", r#"{"error":"rate_limited"}"#),
            (429, Some("rate_limited".into()))
        );
        assert_eq!(refused("500 Internal Server Error", "oops"), (500, None));
    }

    /// A redirect is not followed, and the beacon is not taken for sent — our server never
    /// sends one, so it did not get it.
    #[test]
    fn a_redirect_is_not_followed_and_not_sent() {
        for status in ["302 Found", "308 Permanent Redirect"] {
            // To another host: a client that followed it would never be heard of here again.
            let mock = serve(Mock::Redirect {
                status,
                location: "http://elsewhere.invalid/collect?device=x",
            });
            let (pending, _) = send(&mock.server, TIMEOUTS, BOX_OPEN);
            match pending.finish() {
                Ended::NotSent { why, .. } => {
                    assert!(
                        why.contains(&format!("redirect ({})", &status[..3])),
                        "{why}"
                    );
                    assert!(why.contains("not followed"), "{why}");
                    // Where it pointed, without its path and query.
                    assert!(why.contains("http://elsewhere.invalid"), "{why}");
                    assert!(!why.contains("device=x"), "{why}");
                }
                other => unreachable!("expected not sent, got {other:?}"),
            }
            assert_eq!(afklink_core::lock(&mock.seen).len(), 1, "{status}: once");
        }
    }

    /// Measured through a VPN: the server took the beacon 6.2 s after it left, past a 4.75 s
    /// limit. With the app's limits, an answer 5.5 s late — while the box is still open —
    /// is «sent».
    #[test]
    fn an_answer_past_the_old_limit_is_sent_while_the_box_is_open() {
        let late = Duration::from_millis(5_500);
        let mock = serve(Mock::Answer {
            status: "204 No Content",
            body: "",
            delay: late,
        });
        let (pending, _) = send(&mock.server, TIMEOUTS, EXIT_GRACE);
        // The person reads the box until the server has answered.
        mock.answered
            .recv_timeout(late + Duration::from_secs(10))
            .expect("the mock answered");
        match pending.finish() {
            Ended::Sent {
                status: 204,
                elapsed_ms,
            } => assert!(elapsed_ms >= 5_500, "{elapsed_ms}"),
            other => unreachable!("expected sent, got {other:?}"),
        }
        assert_eq!(afklink_core::lock(&mock.seen).len(), 1, "once, no retry");
    }

    /// No connection the first way: the same beacon once the other way, which takes it.
    #[test]
    fn no_connection_the_first_way_sends_it_the_other_way() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("a listener");
        let held = std::net::TcpStream::connect(listener.local_addr().expect("addr"))
            .expect("a client connection");
        let port = held.local_addr().expect("the client's port").port();
        let other = serve(answer("204 No Content", ""));
        let prepared = prepare(
            StartFailureReason::Webview2Missing,
            &format!("ws://127.0.0.1:{port}/ws/agent"),
            DEVICE,
            &release(),
            &missing(SIMULATED_ERROR),
            Ok("10.0.26100.6584".into()),
        )
        .expect("prepared");
        let fallback = endpoint(&other.server).expect("the other way's address");
        let pending = spawn(
            Prepared {
                fallback: Some(fallback),
                ..prepared.clone()
            },
            "AFKLink/0.6.0 (release)".into(),
            Instant::now(),
            TIMEOUTS,
            BOX_OPEN,
            reqwest::ClientBuilder::no_proxy,
        )
        .expect("a thread");
        assert!(
            matches!(pending.finish(), Ended::Sent { status: 204, .. }),
            "the other way took it"
        );
        let seen = afklink_core::lock(&other.seen).clone();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].body, prepared.body, "the same beacon");
        drop((held, listener));
    }

    /// The server's answer is the answer: a refusal the first way is not sent again the other way.
    #[test]
    fn a_refusal_the_first_way_is_not_sent_again() {
        let first = serve(answer("400 Bad Request", r#"{"error":"bad_message"}"#));
        let other = serve(answer("204 No Content", ""));
        let prepared = prepare(
            StartFailureReason::Webview2Missing,
            &first.server,
            DEVICE,
            &release(),
            &missing(SIMULATED_ERROR),
            Ok("10.0.26100.6584".into()),
        )
        .expect("prepared");
        let pending = spawn(
            Prepared {
                fallback: Some(endpoint(&other.server).expect("address")),
                ..prepared
            },
            "AFKLink/0.6.0 (release)".into(),
            Instant::now(),
            TIMEOUTS,
            BOX_OPEN,
            reqwest::ClientBuilder::no_proxy,
        )
        .expect("a thread");
        assert!(
            matches!(pending.finish(), Ended::Refused { status: 400, .. }),
            "the refusal stands"
        );
        assert!(afklink_core::lock(&other.seen).is_empty());
    }

    /// The remembered way first: for the production host, the RU entry when the PC remembers it, the
    /// configured address otherwise, the other as the fallback; another host has none.
    #[test]
    fn the_beacon_goes_the_remembered_way_first() {
        let prepared = || {
            prepare(
                StartFailureReason::Webview2Missing,
                afklink_core::config::PROD_SERVER_URL,
                DEVICE,
                &release(),
                &missing(SIMULATED_ERROR),
                Ok("10.0.26100.6584".into()),
            )
            .expect("prepared")
        };
        let entry = afklink_core::entry::Entry::in_memory(afklink_core::config::PROD_SERVER_URL);
        let routed_now = routed(prepared(), &entry);
        assert_eq!(
            routed_now.url.as_str(),
            "https://api.afklink.app/api/agent/start-failure"
        );
        assert_eq!(
            routed_now.fallback.as_ref().map(Url::as_str),
            Some("https://api.ru.afklink.app/api/agent/start-failure")
        );
        // A PC that remembers the RU entry (a record younger than the hold).
        let dir = std::env::temp_dir().join(format!("afklink-beacon-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).expect("dir");
        let file = dir.join(afklink_core::entry::FILE_NAME);
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("after 1970")
            .as_millis();
        std::fs::write(
            &file,
            format!(
                r#"{{"v":1,"server_url":"{}","prefer":"ru","since_ms":{},"why":"test"}}"#,
                afklink_core::config::PROD_SERVER_URL,
                now_ms - 60_000
            ),
        )
        .expect("write");
        let remembering =
            afklink_core::entry::Entry::open_at(file, afklink_core::config::PROD_SERVER_URL);
        let routed_ru = routed(prepared(), &remembering);
        assert_eq!(
            routed_ru.url.as_str(),
            "https://api.ru.afklink.app/api/agent/start-failure"
        );
        assert_eq!(
            routed_ru.fallback.as_ref().map(Url::as_str),
            Some("https://api.afklink.app/api/agent/start-failure")
        );
        let _ = std::fs::remove_dir_all(&dir);
        // A development server: no other way.
        let dev = prepare(
            StartFailureReason::Webview2Missing,
            "ws://localhost:8787/ws/agent",
            DEVICE,
            &release(),
            &missing(SIMULATED_ERROR),
            Ok("10.0.26100.6584".into()),
        )
        .expect("prepared");
        let dev_entry = afklink_core::entry::Entry::in_memory("ws://localhost:8787/ws/agent");
        assert_eq!(routed(dev, &dev_entry).fallback, None);
    }

    #[test]
    fn no_server_is_not_sent() {
        // A port nobody listens on and nobody can take while the test runs: the local end of a
        // connected client socket (as in `diagnostics::upload`'s test).
        let listener = TcpListener::bind("127.0.0.1:0").expect("a listener");
        let held = std::net::TcpStream::connect(listener.local_addr().expect("addr"))
            .expect("a client connection");
        let port = held.local_addr().expect("the client's port").port();
        let (pending, _) = send(
            &format!("ws://127.0.0.1:{port}/ws/agent"),
            TIMEOUTS,
            BOX_OPEN,
        );
        match pending.finish() {
            Ended::NotSent { why, elapsed_ms } => {
                assert!(why.starts_with("no connection: "), "{why}");
                assert!(elapsed_ms.is_some());
                println!("refused: not sent: {why}");
            }
            other => unreachable!("expected not sent, got {other:?}"),
        }
        drop((held, listener));
    }

    /// Connected over TCP, but TLS never finishes within the connect limit: the request itself was
    /// never written — not sent. The server saw a TLS handshake, not an HTTP request.
    #[test]
    fn a_tls_handshake_that_never_ends_is_not_sent() {
        let (server, first) = hold_tls();
        // Room for SChannel to set up and send its first message on a cold start.
        let timeouts = Timeouts {
            connect: Duration::from_secs(1),
            request: Duration::from_secs(5),
        };
        let (pending, _) = send(&server, timeouts, BOX_OPEN);
        let started = Instant::now();
        match pending.finish() {
            Ended::NotSent { why, elapsed_ms } => {
                assert!(why.starts_with("no connection within 1000 ms: "), "{why}");
                assert!(elapsed_ms.is_some());
                println!("TLS never finished: not sent: {why}");
            }
            other => unreachable!("expected not sent, got {other:?}"),
        }
        assert!(started.elapsed() < Duration::from_secs(3));
        let first = first
            .recv_timeout(Duration::from_secs(5))
            .expect("the mock read the first bytes");
        // A TLS handshake record (0x16), not «POST».
        assert_eq!(first.first(), Some(&0x16), "{first:?}");
    }

    /// A server that reads the request and never answers: the request's own limit runs out after
    /// connecting — the server has it, so the line says it may have arrived, not «not sent».
    #[test]
    fn a_silent_server_gets_no_answer_in_time_and_may_have_it() {
        let mock = serve(Mock::Silent);
        let started = Instant::now();
        let (pending, _) = send(&mock.server, SHORT, BOX_OPEN);
        match pending.finish() {
            Ended::Unanswered {
                why,
                timed_out: true,
                elapsed_ms,
            } => {
                assert!(
                    why.starts_with("connected, then no answer within the request's 800 ms: "),
                    "{why}"
                );
                assert!(elapsed_ms.is_some_and(|ms| ms >= 700), "{elapsed_ms:?}");
                println!("silent: no answer in time: {why}");
            }
            other => unreachable!("expected no answer in time, got {other:?}"),
        }
        assert!(started.elapsed() < SHORT.request + Duration::from_secs(2));
        assert_eq!(afklink_core::lock(&mock.seen).len(), 1, "it did arrive");
    }

    /// A server that reads the request and closes the connection without a word: no answer, and it
    /// may have arrived (here it did).
    #[test]
    fn a_connection_closed_without_an_answer_may_have_arrived() {
        let mock = serve(Mock::Close);
        let (pending, _) = send(&mock.server, TIMEOUTS, BOX_OPEN);
        match pending.finish() {
            Ended::Unanswered {
                why,
                timed_out: false,
                elapsed_ms,
            } => {
                assert!(why.starts_with("request: "), "{why}");
                assert!(elapsed_ms.is_some());
                println!("closed: no answer: {why}");
            }
            other => unreachable!("expected no answer, got {other:?}"),
        }
        assert_eq!(afklink_core::lock(&mock.seen).len(), 1, "it did arrive");
    }

    /// The box closed at once, the server silent: the way out waits the grace — no less, not much
    /// more — and leaves the request to the exit.
    #[test]
    fn a_box_closed_at_once_waits_the_grace_then_abandons() {
        let mock = serve(Mock::Silent);
        let (pending, _) = send(&mock.server, TIMEOUTS, EXIT_GRACE);
        let closed = Instant::now();
        assert_eq!(pending.finish(), Ended::InFlight);
        let waited = closed.elapsed();
        assert!(
            waited >= EXIT_GRACE - Duration::from_millis(20),
            "{waited:?}"
        );
        assert!(waited < EXIT_GRACE + Duration::from_secs(1), "{waited:?}");
    }

    /// The way out's side alone: an answer already there is taken without waiting, even with no
    /// grace at all; none within the grace is abandoned; each answer ends as its kind.
    #[test]
    fn the_way_out_takes_what_came_and_waits_no_longer_than_the_grace() {
        let pending = |grace: Duration| {
            let (tx, rx) = mpsc::channel::<Reply>();
            let pending = Pending {
                started: Instant::now(),
                timeouts: TIMEOUTS,
                grace,
                reply: rx,
            };
            (tx, pending)
        };
        let reply = |answer: Answer| Reply {
            answer,
            elapsed_ms: 6_200,
        };

        // Answered while the box was open: taken at once, whatever the grace.
        let (tx, waiting) = pending(Duration::ZERO);
        tx.send(reply(Answer::Status {
            status: 204,
            code: None,
        }))
        .expect("sent");
        assert_eq!(
            waiting.finish(),
            Ended::Sent {
                status: 204,
                elapsed_ms: 6_200
            }
        );

        // Nothing within the grace: abandoned, after the grace and not much more.
        let (tx, waiting) = pending(Duration::from_millis(50));
        let closed = Instant::now();
        assert_eq!(waiting.finish(), Ended::InFlight);
        assert!(closed.elapsed() < Duration::from_secs(2));
        drop(tx);

        // An answer arriving within the grace is waited for.
        let (tx, waiting) = pending(Duration::from_secs(5));
        let late = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            tx.send(reply(Answer::NotSent("no connection: refused".into())))
                .expect("sent");
        });
        assert_eq!(
            waiting.finish(),
            Ended::NotSent {
                why: "no connection: refused".into(),
                elapsed_ms: Some(6_200)
            }
        );
        late.join().expect("the late answer's thread");

        // No answer in time, or none at all: it may have arrived.
        let (tx, waiting) = pending(Duration::ZERO);
        tx.send(reply(Answer::Unanswered {
            why: "connected, then no answer within the request's 20000 ms".into(),
            timed_out: true,
        }))
        .expect("sent");
        assert_eq!(
            waiting.finish(),
            Ended::Unanswered {
                why: "connected, then no answer within the request's 20000 ms".into(),
                timed_out: true,
                elapsed_ms: Some(6_200)
            }
        );

        // A thread that ended without a word: it may have ended after the request left.
        let (tx, waiting) = pending(Duration::from_secs(5));
        drop(tx);
        assert_eq!(
            waiting.finish(),
            Ended::Unanswered {
                why: "its thread ended without an answer".into(),
                timed_out: false,
                elapsed_ms: None
            }
        );
    }
}
