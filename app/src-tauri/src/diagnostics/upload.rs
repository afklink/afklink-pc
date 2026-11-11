//! The signed upload: `POST /api/diagnostics/agent`, the zip as the body and the
//! metadata and the device's signature in headers.
//!
//! The signature is the device identity's Ed25519 key — the one that answers the signaling
//! challenge — over the contract's eight-line canonical string
//! (`afklink_protocol::diagnostics::agent_request_canonical`), which names this exact request: its
//! path, the device, the time, a fresh nonce, the body's and the metadata's sha256. The key itself
//! never leaves `afklink_core::Identity`.
//!
//! # Answers
//!
//! - `201`: sent; the receipt's `report_id` goes to the log.
//! - `401 clock_skew`: the PC's clock is more than 5 min off. The answer carries the server's time,
//!   and the request is signed again once, with the timestamp moved by the difference and a new
//!   nonce; the skew is logged.
//! - `429`: over the budget (6 reports an hour per PC) — «Попробуй позже», with `Retry-After`.
//! - `413`, `503`, any other refusal, and a network failure: not sent; the owner may retry. (A
//!   manual report refused `413` at the full cap is packed again at the small one by the caller,
//!   `diagnostics::send_within_caps`.)
//! - a `3xx`: not followed — the client follows no redirect — and taken for a path in the way:
//!   the other way to the server is tried, as on no answer.
//!
//! The comment is inside the metadata header: neither the header nor the metadata is ever logged,
//! only their sizes.
//!
//! # Two ways to the same server (the RU entry)
//!
//! A Russian provider can let a connection to Cloudflare open and then freeze what the server sends
//! after a few kilobytes — its acknowledgements included, so an upload stops going out too (seen
//! at 84 KB). [`send_any`] tries the way the signaling socket uses first and the
//! other second (`afklink_core::entry`), on no answer at all — never after the server answered,
//! which says the same whichever way — and an attempt whose body the connection stops taking for
//! [`STALL`]`.body`, or whose answer does not come [`STALL`]`.answer` after the whole body went, is
//! given up as no answer rather than waiting out [`REQUEST_TIMEOUT`]. The signature names the path,
//! never the host, so the same report is signed alike on either.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use afklink_core::Identity;
use afklink_protocol::diagnostics::{
    agent_request_canonical, header, limits, AgentDiagnosticsMeta, AgentRequestSigned,
    DiagnosticsReceipt, DIAGNOSTICS_AGENT_PATH, SERVER_TIME_HEADER,
};
use base64::Engine;
use bytes::Bytes;
use reqwest::{StatusCode, Url};
use sha2::{Digest, Sha256};

/// How long connecting may take.
pub(crate) const CONNECT_TIMEOUT: Duration = Duration::from_secs(20);

/// How long the whole request may take: the server waits 10 min for a body, and 24 MiB over a slow
/// uplink (1 Mbit/s) takes about 3.
pub(crate) const REQUEST_TIMEOUT: Duration = Duration::from_secs(10 * 60);

/// When an upload is a stall rather than a slow line.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Stall {
    /// The connection took not one more byte of the body for this long. A slow uplink still drains
    /// its buffer steadily; TCP's retransmission backs off 1, 2, 4, 8 s, so four losses in a row are
    /// some 15 s without progress, and this is twice that. Longer than [`CONNECT_TIMEOUT`], which
    /// runs before the first byte is taken.
    pub(crate) body: Duration,
    /// The whole body was taken this long ago and no answer has come: what is still in the socket's
    /// buffer (Windows sizes it to about a round trip of the line) has long gone out, and the server
    /// answers as soon as it has stored the report.
    pub(crate) answer: Duration,
}

/// The app's.
pub(crate) const STALL: Stall = Stall {
    body: Duration::from_secs(30),
    answer: Duration::from_secs(60),
};

/// The body is handed to the connection this much at a time: the unit progress is seen in.
const CHUNK: usize = 64 * 1024;

/// How much of an attempt's body the connection has taken, and when it last took some.
#[derive(Debug)]
struct Progress {
    started: Instant,
    total: u64,
    taken: AtomicU64,
    /// Milliseconds from `started` to the last chunk taken.
    last_ms: AtomicU64,
}

impl Progress {
    fn new(total: usize) -> Self {
        Self {
            started: Instant::now(),
            total: total as u64,
            taken: AtomicU64::new(0),
            last_ms: AtomicU64::new(0),
        }
    }

    fn took(&self, bytes: usize) {
        self.taken.fetch_add(bytes as u64, Ordering::Relaxed);
        self.last_ms.store(
            u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX),
            Ordering::Relaxed,
        );
    }

    /// Why the attempt counts as stalled now, if it does.
    fn stalled(&self, stall: Stall) -> Option<String> {
        let taken = self.taken.load(Ordering::Relaxed);
        let now_ms = u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX);
        let idle =
            Duration::from_millis(now_ms.saturating_sub(self.last_ms.load(Ordering::Relaxed)));
        if taken < self.total && idle >= stall.body {
            Some(format!(
                "the connection took {taken} of {} bytes and nothing more for {} ms",
                self.total,
                idle.as_millis()
            ))
        } else if taken >= self.total && idle >= stall.answer {
            Some(format!(
                "the whole body ({} bytes) went {} ms ago and no answer came",
                self.total,
                idle.as_millis()
            ))
        } else {
            None
        }
    }
}

/// `body` as a stream of [`CHUNK`]s that tells `progress` of each one the connection takes.
fn tracked_body(body: &Bytes, progress: Arc<Progress>) -> reqwest::Body {
    use futures_util::StreamExt;
    let chunks: Vec<Bytes> = (0..body.len())
        .step_by(CHUNK)
        .map(|at| body.slice(at..(at + CHUNK).min(body.len())))
        .collect();
    let stream = futures_util::stream::iter(chunks).map(move |chunk| {
        progress.took(chunk.len());
        Ok::<Bytes, std::io::Error>(chunk)
    });
    reqwest::Body::wrap_stream(stream)
}

/// `sending`, given up as a stall when `progress` says so (`Err`, why).
async fn watched(
    sending: impl std::future::Future<Output = Result<reqwest::Response, reqwest::Error>>,
    progress: &Progress,
    stall: Stall,
) -> Result<Result<reqwest::Response, reqwest::Error>, String> {
    let every =
        (stall.body.min(stall.answer) / 4).clamp(Duration::from_millis(10), Duration::from_secs(1));
    let mut tick = tokio::time::interval(every);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    tokio::pin!(sending);
    loop {
        tokio::select! {
            sent = &mut sending => return Ok(sent),
            _ = tick.tick() => {
                if let Some(why) = progress.stalled(stall) {
                    return Err(why);
                }
            }
        }
    }
}

/// sha256 of `bytes`, 64 lowercase hex digits.
pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

/// The `x-afklink-meta` header: the metadata JSON as base64url without padding. Refused past the
/// server's [`limits::META_HEADER_CHARS`], which the report's own limits keep it far below.
pub(crate) fn meta_header(meta: &AgentDiagnosticsMeta) -> Result<String, String> {
    let json = serde_json::to_vec(meta).map_err(|e| format!("metadata not serialized: {e}"))?;
    let header = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(json);
    if header.len() > limits::META_HEADER_CHARS {
        return Err(format!(
            "metadata header of {} characters, over the server's {}",
            header.len(),
            limits::META_HEADER_CHARS
        ));
    }
    Ok(header)
}

/// One attempt's signed headers, in [`header::ALL`]'s order, and the string that was signed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Signed {
    pub(crate) headers: Vec<(&'static str, String)>,
    pub(crate) canonical: String,
}

/// Sign one attempt: `timestamp_ms` and `nonce` are this attempt's, the rest the report's.
pub(crate) fn sign(
    identity: &Identity,
    device: &str,
    timestamp_ms: u64,
    nonce: [u8; 16],
    content_sha256: &str,
    meta_header: &str,
) -> Result<Signed, String> {
    let timestamp = timestamp_ms.to_string();
    let nonce = hex(&nonce);
    let meta_sha256 = sha256_hex(meta_header.as_bytes());
    let canonical = agent_request_canonical(&AgentRequestSigned {
        method: "POST",
        path: DIAGNOSTICS_AGENT_PATH,
        device,
        timestamp: &timestamp,
        nonce: &nonce,
        content_sha256,
        meta_sha256: &meta_sha256,
    })
    .map_err(|e| e.to_string())?;
    let signature =
        base64::engine::general_purpose::STANDARD.encode(identity.sign(canonical.as_bytes()));
    Ok(Signed {
        headers: vec![
            (header::DEVICE, device.to_string()),
            (header::TIMESTAMP, timestamp),
            (header::NONCE, nonce),
            (header::CONTENT_SHA256, content_sha256.to_string()),
            (header::META, meta_header.to_string()),
            (header::SIGNATURE, signature),
        ],
        canonical,
    })
}

/// Where reports go for the signaling address `server_url`: the same host and port, `https`
/// (`wss`) — or `http` for a `ws://` server on this machine (local development) — and the report
/// path. A plain `ws://` server anywhere else gets no report: the logs never cross a network
/// unencrypted.
pub(crate) fn endpoint(server_url: &str) -> Result<Url, String> {
    let mut url = Url::parse(server_url.trim()).map_err(|e| format!("{server_url:?}: {e}"))?;
    let Some(host) = url.host_str() else {
        return Err(format!("{server_url:?} has no host"));
    };
    let loopback = host.eq_ignore_ascii_case("localhost")
        || host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback());
    let scheme = match url.scheme() {
        "wss" | "https" => "https",
        "ws" | "http" if loopback => "http",
        "ws" | "http" => {
            return Err(format!(
                "{server_url:?} is not encrypted and not on this machine; logs are sent over https \
                 only"
            ))
        }
        other => return Err(format!("{server_url:?}: scheme {other} is not a server's")),
    };
    url.set_scheme(scheme)
        .map_err(|()| format!("{server_url:?}: scheme not changed to {scheme}"))?;
    url.set_path(DIAGNOSTICS_AGENT_PATH);
    url.set_query(None);
    url.set_fragment(None);
    // No user or password in a report's address, whatever the signaling one holds.
    if url.set_username("").is_err() || url.set_password(None).is_err() {
        return Err(format!(
            "{server_url:?}: its credentials could not be removed"
        ));
    }
    Ok(url)
}

/// The client: TLS through SChannel (the updater's `native-tls`), bounded waits, this build's
/// `User-Agent` (`AFKLink/<version> (<channel>)`, `BuildInfo::user_agent`), and no redirects
/// followed: our server answers the report's address itself, so
/// a redirect is someone in the way — a captive portal, a proxy, a hijacked name — and following it
/// would hand the signed report, with its headers and logs, to wherever it points. A 3xx is a
/// failure of its own (`Failure::Redirected`), logged with where it pointed.
pub(crate) fn client(user_agent: &str) -> Result<reqwest::Client, String> {
    client_builder(user_agent)
        .build()
        .map_err(|e| format!("HTTP client not built: {e}"))
}

fn client_builder(user_agent: &str) -> reqwest::ClientBuilder {
    reqwest::Client::builder()
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(REQUEST_TIMEOUT)
        .user_agent(user_agent)
        .redirect(reqwest::redirect::Policy::none())
}

/// A report ready to go: everything but the per-attempt timestamp, nonce and signature.
#[derive(Debug, Clone)]
pub(crate) struct Prepared {
    pub(crate) endpoint: Url,
    pub(crate) device: String,
    pub(crate) body: Bytes,
    pub(crate) content_sha256: String,
    pub(crate) meta_header: String,
}

/// How an upload ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Outcome {
    /// `201`. The receipt, when its body could be read.
    Sent {
        receipt: Option<DiagnosticsReceipt>,
    },
    /// `429`: the budget is spent; `Retry-After`, seconds, when given.
    TooOften {
        retry_after_s: Option<u64>,
    },
    Failed(Failure),
}

/// Why a report was not sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Failure {
    /// No answer: no connection, a timeout, the body cut off.
    Network(String),
    /// `401 clock_skew` after the corrected retry too (or without the server's time).
    ClockSkew,
    /// `413`: the same body never fits.
    TooLarge,
    /// `503`: reports are off on the server, or its storage is full.
    Unavailable,
    /// Any other refusal, with the contract's code when the body had one.
    Refused { status: u16, code: Option<String> },
    /// A 3xx: something in the way sent the report elsewhere, and it was not followed.
    Redirected { status: u16 },
    /// The request could not be signed (a part with a line break — a device id hand-edited so).
    Signing(String),
    /// The whole body went and no answer came (a path that freezes what the server sends): the
    /// server may well have stored it. Only with [`AfterBody::Stop`] (the automatic report, which
    /// must never send a report twice); the owner's report sees this as `Network`.
    Unanswered(String),
}

/// What [`send_any`] does when the whole body went out and no answer came.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AfterBody {
    /// Try the other way, as on no answer at all: the owner's report (unchanged behaviour).
    FallBack,
    /// Stop there, as [`Failure::Unanswered`]: the automatic report counts it as sent.
    Stop,
}

impl Failure {
    /// For the log and the window's DTO.
    pub(crate) fn kind(&self) -> &'static str {
        match self {
            Self::Network(_) => "network",
            Self::ClockSkew => "clock_skew",
            Self::TooLarge => "too_large",
            Self::Unavailable => "unavailable",
            Self::Refused { .. } => "refused",
            Self::Redirected { .. } => "redirected",
            Self::Signing(_) => "signing",
            Self::Unanswered(_) => "unanswered",
        }
    }
}

/// The server's `{ error, message? }`.
#[derive(Debug, Default, serde::Deserialize)]
struct ErrorBody {
    error: Option<String>,
    message: Option<String>,
}

/// Whether an outcome says nothing of the server and the other way may do better: no answer at all,
/// a gateway's error (Cloudflare's 52x, a proxy's 502 or 504), or a redirect (something in the way:
/// our server never sends one) — not our server's own answer.
fn falls_back(outcome: &Outcome) -> bool {
    match outcome {
        Outcome::Failed(Failure::Network(_) | Failure::Redirected { .. }) => true,
        Outcome::Failed(Failure::Refused { status, .. }) => {
            matches!(status, 502 | 504 | 520..=530)
        }
        _ => false,
    }
}

/// [`send`] `report` to each of `endpoints` in turn — the same server on each way to it, the way the
/// signaling socket uses first — while the outcome says nothing of the server ([`falls_back`]). The
/// last outcome otherwise. `report.endpoint` is not used: each attempt gets its own.
///
/// `after_body`: with [`AfterBody::Stop`], an attempt whose whole body went and got no answer ends
/// here as [`Failure::Unanswered`] — not tried the other way, the server may have stored it.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn send_any(
    client: &reqwest::Client,
    report: &Prepared,
    endpoints: &[Url],
    identity: &Identity,
    now_ms: impl Fn() -> u64,
    mut nonce: impl FnMut() -> [u8; 16],
    stall: Stall,
    after_body: AfterBody,
) -> Outcome {
    let mut last = Outcome::Failed(Failure::Network("no address to send to".into()));
    for (i, endpoint) in endpoints.iter().enumerate() {
        let attempt = Prepared {
            endpoint: endpoint.clone(),
            ..report.clone()
        };
        let started = Instant::now();
        let mut body_went = false;
        let outcome = send_inner(
            client,
            &attempt,
            identity,
            &now_ms,
            &mut nonce,
            stall,
            &mut body_went,
        )
        .await;
        // No answer of our server's own after the whole body went — none at all, or a gateway's
        // error in its place: it may have stored the report.
        let unanswered = match &outcome {
            Outcome::Failed(Failure::Network(why)) => Some(why.clone()),
            Outcome::Failed(Failure::Refused { status, .. })
                if matches!(status, 502 | 504 | 520..=530) =>
            {
                Some(format!("a gateway answered {status}"))
            }
            _ => None,
        };
        if let Some(why) = unanswered.filter(|_| body_went && after_body == AfterBody::Stop) {
            tracing::warn!(
                host = endpoint.host_str().unwrap_or("-"),
                body_bytes = report.body.len(),
                elapsed_ms = started.elapsed().as_millis() as u64,
                "diagnostics: the whole report went and our server's answer did not come; not \
                 sent again, nor the other way (it may be stored): {why}"
            );
            return Outcome::Failed(Failure::Unanswered(why));
        }
        let next = endpoints.get(i + 1);
        match next {
            Some(next) if falls_back(&outcome) => {
                tracing::warn!(
                    host = endpoint.host_str().unwrap_or("-"),
                    next = next.host_str().unwrap_or("-"),
                    outcome = ?outcome,
                    elapsed_ms = started.elapsed().as_millis() as u64,
                    body_bytes = report.body.len(),
                    "diagnostics: the report did not get through this way; trying the other"
                );
                last = outcome;
            }
            _ => {
                if i > 0 {
                    tracing::info!(
                        host = endpoint.host_str().unwrap_or("-"),
                        tried = i + 1,
                        outcome = ?outcome,
                        "diagnostics: the report's last try went the other way"
                    );
                }
                return outcome;
            }
        }
    }
    last
}

/// Send `report`, signed by `identity`: once, and once more after `401 clock_skew` with the
/// timestamp corrected. `now_ms` is the PC's clock and `nonce` the source of nonces — the system's
/// in the app, fixed ones in the tests. An attempt that stalls ([`Stall`]) is a network failure.
/// The app goes through [`send_any`]; this one way alone is for the tests.
#[cfg(test)]
pub(crate) async fn send(
    client: &reqwest::Client,
    report: &Prepared,
    identity: &Identity,
    now_ms: impl Fn() -> u64,
    nonce: impl FnMut() -> [u8; 16],
    stall: Stall,
) -> Outcome {
    let mut body_went = false;
    send_inner(
        client,
        report,
        identity,
        now_ms,
        nonce,
        stall,
        &mut body_went,
    )
    .await
}

/// [`send`], and whether a network failure came after the connection had taken the whole body
/// (`body_went`: the server may have it).
async fn send_inner(
    client: &reqwest::Client,
    report: &Prepared,
    identity: &Identity,
    now_ms: impl Fn() -> u64,
    mut nonce: impl FnMut() -> [u8; 16],
    stall: Stall,
    body_went: &mut bool,
) -> Outcome {
    let host = report.endpoint.host_str().unwrap_or("-").to_string();
    let mut skew_ms: i64 = 0;
    for attempt in 1..=2u32 {
        let timestamp = now_ms().saturating_add_signed(skew_ms);
        let signed = match sign(
            identity,
            &report.device,
            timestamp,
            nonce(),
            &report.content_sha256,
            &report.meta_header,
        ) {
            Ok(signed) => signed,
            Err(e) => {
                tracing::warn!("diagnostics: report not signed: {e}");
                return Outcome::Failed(Failure::Signing(e));
            }
        };
        tracing::info!(
            attempt,
            %host,
            path = report.endpoint.path(),
            body_bytes = report.body.len(),
            meta_chars = report.meta_header.len(),
            timestamp,
            skew_ms,
            "diagnostics: uploading the report"
        );
        let started = Instant::now();
        // The body as chunks the connection takes one by one, so a stall is seen ([`Stall`]); its
        // length declared, as the server's limit check reads it before the body.
        let progress = Arc::new(Progress::new(report.body.len()));
        let mut request = client
            .post(report.endpoint.clone())
            .header(reqwest::header::CONTENT_TYPE, "application/zip")
            .header(reqwest::header::CONTENT_LENGTH, report.body.len())
            .body(tracked_body(&report.body, Arc::clone(&progress)));
        for (name, value) in &signed.headers {
            request = request.header(*name, value.as_str());
        }
        // Whether the connection has taken every byte of the body: a failure after that may have
        // reached the server.
        let whole_body_taken = |progress: &Progress| {
            progress.total > 0 && progress.taken.load(Ordering::Relaxed) >= progress.total
        };
        let response = match watched(request.send(), &progress, stall).await {
            Ok(Ok(response)) => response,
            Ok(Err(e)) => {
                *body_went = whole_body_taken(&progress);
                let why = network_error(&e);
                tracing::warn!(
                    attempt,
                    %host,
                    taken_bytes = progress.taken.load(Ordering::Relaxed),
                    elapsed_ms = started.elapsed().as_millis() as u64,
                    "diagnostics: report not sent, no answer: {why}"
                );
                return Outcome::Failed(Failure::Network(why));
            }
            Err(why) => {
                *body_went = whole_body_taken(&progress);
                tracing::warn!(
                    attempt,
                    %host,
                    taken_bytes = progress.taken.load(Ordering::Relaxed),
                    body_bytes = report.body.len(),
                    elapsed_ms = started.elapsed().as_millis() as u64,
                    stall_body_s = stall.body.as_secs(),
                    stall_answer_s = stall.answer.as_secs(),
                    "diagnostics: report not sent, the upload stalled: {why}"
                );
                return Outcome::Failed(Failure::Network(format!("stall: {why}")));
            }
        };
        // An answer came: whether the body went whole before it (a gateway's error after it may
        // hide a report our server stored).
        *body_went = whole_body_taken(&progress);
        let status = response.status();
        // Not followed (the client follows none) — said, with where it pointed, and given up.
        if status.is_redirection() {
            tracing::warn!(
                attempt,
                %host,
                status = status.as_u16(),
                to = %redirect_target(&response),
                elapsed_ms = started.elapsed().as_millis() as u64,
                "diagnostics: the report's address answered with a redirect, not followed (our \
                 server never sends one: something is in the way)"
            );
            return Outcome::Failed(Failure::Redirected {
                status: status.as_u16(),
            });
        }
        let server_time = header_u64(&response, SERVER_TIME_HEADER);
        let retry_after = header_u64(&response, reqwest::header::RETRY_AFTER.as_str());
        // The answer's body is small (the receipt, an error code): a path that freezes it is not
        // waited for past the answer's limit — the status already says what happened.
        let body = match tokio::time::timeout(stall.answer, response.bytes()).await {
            Ok(Ok(body)) => body,
            Ok(Err(e)) => {
                tracing::debug!(%status, "diagnostics: the answer's body not read: {e}");
                Bytes::new()
            }
            Err(_) => {
                tracing::debug!(
                    %status,
                    wait_s = stall.answer.as_secs(),
                    "diagnostics: the answer's body did not come in time; the status stands"
                );
                Bytes::new()
            }
        };
        let elapsed_ms = started.elapsed().as_millis() as u64;
        let refusal: ErrorBody = if status.is_success() {
            ErrorBody::default()
        } else {
            serde_json::from_slice(&body).unwrap_or_default()
        };
        // not-a-key-name: the server's error code
        tracing::info!(
            attempt,
            status = status.as_u16(),
            code = refusal.error.as_deref().unwrap_or("-"),
            message = refusal.message.as_deref().unwrap_or("-"),
            retry_after_s = ?retry_after,
            elapsed_ms,
            "diagnostics: the server answered"
        );
        match status {
            StatusCode::CREATED => {
                let receipt = serde_json::from_slice::<DiagnosticsReceipt>(&body)
                    .inspect_err(|e| {
                        tracing::warn!(
                            body_bytes = body.len(),
                            "diagnostics: sent, but the receipt did not parse: {e}"
                        );
                    })
                    .ok();
                if let Some(r) = &receipt {
                    tracing::info!(
                        report_id = %r.report_id,
                        stored_bytes = r.bytes,
                        attempt,
                        "diagnostics: report sent"
                    );
                }
                return Outcome::Sent { receipt };
            }
            StatusCode::UNAUTHORIZED if refusal.error.as_deref() == Some("clock_skew") => {
                match server_time {
                    Some(server) if attempt == 1 => {
                        let local = now_ms();
                        skew_ms = i64::try_from(server).unwrap_or(i64::MAX)
                            - i64::try_from(local).unwrap_or(i64::MAX);
                        tracing::warn!(
                            skew_ms,
                            server_time = server,
                            local_time = local,
                            "diagnostics: this PC's clock is off from the server's; signing again \
                             once with the server's time"
                        );
                    }
                    _ => {
                        tracing::warn!(
                            attempt,
                            server_time = ?server_time,
                            "diagnostics: report refused for the clock again (or without the \
                             server's time); not sent"
                        );
                        return Outcome::Failed(Failure::ClockSkew);
                    }
                }
            }
            StatusCode::TOO_MANY_REQUESTS => {
                tracing::info!(
                    retry_after_s = ?retry_after,
                    "diagnostics: over the server's report budget; the owner is told to try later"
                );
                return Outcome::TooOften {
                    retry_after_s: retry_after,
                };
            }
            StatusCode::PAYLOAD_TOO_LARGE => {
                tracing::warn!(
                    body_bytes = report.body.len(),
                    "diagnostics: the server refused the report's size"
                );
                return Outcome::Failed(Failure::TooLarge);
            }
            StatusCode::SERVICE_UNAVAILABLE => {
                tracing::warn!("diagnostics: the server takes no reports now (off, or full)");
                return Outcome::Failed(Failure::Unavailable);
            }
            other => {
                // not-a-key-name: the server's error code
                tracing::warn!(
                    status = other.as_u16(),
                    code = refusal.error.as_deref().unwrap_or("-"),
                    "diagnostics: the server refused the report"
                );
                return Outcome::Failed(Failure::Refused {
                    status: other.as_u16(),
                    code: refusal.error,
                });
            }
        }
    }
    // The loop returns on every answer but a first clock skew.
    Outcome::Failed(Failure::ClockSkew)
}

/// Where a redirect pointed, for the log: the scheme and host of its `Location` — not its path or
/// query, which may carry anything — or why it could not be read.
pub(crate) fn redirect_target(response: &reqwest::Response) -> String {
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

/// A header's value as a decimal number; `None` when absent or not one (a `Retry-After` given as a
/// date is not what this server sends).
fn header_u64(response: &reqwest::Response, name: &str) -> Option<u64> {
    response
        .headers()
        .get(name)?
        .to_str()
        .ok()?
        .trim()
        .parse()
        .ok()
}

/// A failed request, said with its kind.
fn network_error(e: &reqwest::Error) -> String {
    let kind = if e.is_timeout() {
        "timeout"
    } else if e.is_connect() {
        "connect"
    } else if e.is_body() {
        "body"
    } else {
        "request"
    };
    // The error names the URL: the host and the report path, nothing secret.
    format!("{kind}: {e}")
}

/// The PC's clock, Unix ms.
pub(crate) fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// 16 bytes from the system's generator. A generator that fails (never seen on Windows) leaves a
/// nonce from the clock and a counter, still unique for this device, and says so.
pub(crate) fn random_nonce() -> [u8; 16] {
    let mut nonce = [0u8; 16];
    if let Err(e) = getrandom::getrandom(&mut nonce) {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        tracing::warn!("diagnostics: no random bytes for the nonce ({e}); using the clock");
        let t = (u128::from(now_ms()) << 64) | u128::from(COUNTER.fetch_add(1, Ordering::Relaxed));
        nonce = t.to_le_bytes();
    }
    nonce
}

/// A local HTTP server for the upload's tests (this module's and `auto`'s): it answers requests in
/// turn and records each.
#[cfg(test)]
pub(crate) mod test_server {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};

    use super::*;

    /// What the mock server saw of one request.
    #[derive(Debug, Clone)]
    pub(crate) struct Seen {
        pub(crate) head: String,
        pub(crate) body: Vec<u8>,
    }

    impl Seen {
        pub(crate) fn header(&self, name: &str) -> Option<String> {
            self.head.lines().find_map(|line| {
                let (n, v) = line.split_once(':')?;
                n.trim()
                    .eq_ignore_ascii_case(name)
                    .then(|| v.trim().to_string())
            })
        }
    }

    /// A local server answering the requests in turn with `answers` (status line, extra headers,
    /// body), recording each request; the base URL.
    pub(crate) fn serve(
        answers: Vec<(&'static str, String, String)>,
    ) -> (Url, Arc<Mutex<Vec<Seen>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let url = Url::parse(&format!(
            "http://{}{DIAGNOSTICS_AGENT_PATH}",
            listener.local_addr().expect("addr")
        ))
        .expect("url");
        let seen = Arc::new(Mutex::new(Vec::new()));
        let record = Arc::clone(&seen);
        std::thread::spawn(move || {
            for (status, extra, body) in answers {
                let Ok((mut stream, _)) = listener.accept() else {
                    return;
                };
                let mut data = Vec::new();
                let mut chunk = [0u8; 8192];
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
                let _ = write!(
                    stream,
                    "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n{extra}Connection: close\r\n\r\n{body}",
                    body.len()
                );
            }
        });
        (url, seen)
    }

    /// An identity with the given secret key (standard base64), from a file of its own.
    pub(crate) fn identity_with(secret: &str) -> Identity {
        let dir = std::env::temp_dir().join(format!("afklink-sign-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).expect("dir");
        let path = dir.join("identity.json");
        std::fs::write(&path, format!(r#"{{"secret_key":"{secret}"}}"#)).expect("write");
        let identity = Identity::load_or_create_at(path).expect("loads");
        let _ = std::fs::remove_dir_all(&dir);
        identity
    }

    /// The app's client as the reports build it, without the system's proxy (the tests talk to
    /// 127.0.0.1).
    pub(crate) fn local_client() -> reqwest::Client {
        client_builder("AFKLink/0.7.2 (release)")
            .no_proxy()
            .build()
            .expect("client")
    }
}

#[cfg(test)]
mod tests {
    use std::io::Read;
    use std::net::TcpListener;

    use super::test_server::{identity_with, serve, Seen};
    use super::*;
    use serde_json::Value;

    fn vectors() -> Value {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../contract/packages/protocol/vectors/agent-request-signature.json");
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| unreachable!("{}: {e} (the contract submodule)", path.display()));
        serde_json::from_str(&text).expect("vectors parse")
    }

    fn s<'a>(v: &'a Value, key: &str) -> &'a str {
        v[key].as_str().expect("a string")
    }

    /// The device identity loaded from an identity.json holding `secret` — the app's own loader.
    fn nonce_of(hex_text: &str) -> [u8; 16] {
        let mut out = [0u8; 16];
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&hex_text[i * 2..i * 2 + 2], 16).expect("hex");
        }
        out
    }

    /// Every case of the contract's vectors, signed with the RFC 8032 TEST 1 key: the metadata
    /// header, both hashes, the canonical string, the signature and all six headers, byte for byte.
    #[test]
    fn signing_matches_the_contract_vectors() {
        let v = vectors();
        let identity = identity_with(s(&v, "secret_key"));
        assert_eq!(identity.public_key_b64(), s(&v, "public_key"));
        for case in v["cases"].as_array().expect("cases") {
            let why = s(case, "why");
            let meta: AgentDiagnosticsMeta =
                serde_json::from_str(s(case, "meta_json")).expect("meta parses");
            let header_text = meta_header(&meta).expect("fits");
            assert_eq!(header_text, s(case, "meta_header"), "{why}");
            assert_eq!(
                sha256_hex(header_text.as_bytes()),
                s(case, "meta_sha256"),
                "{why}"
            );
            let body = base64::engine::general_purpose::STANDARD
                .decode(s(case, "body_base64"))
                .expect("body");
            let content = sha256_hex(&body);
            assert_eq!(content, s(case, "body_sha256"), "{why}");

            let signed = sign(
                &identity,
                s(case, "device_id"),
                s(case, "timestamp").parse().expect("ms"),
                nonce_of(s(case, "nonce")),
                &content,
                &header_text,
            )
            .expect("signs");
            assert_eq!(signed.canonical, s(case, "canonical"), "{why}");
            let headers = &case["headers"];
            for (name, value) in &signed.headers {
                assert_eq!(value, s(headers, name), "{why}: {name}");
            }
            assert_eq!(signed.headers.len(), 6);
            assert_eq!(
                signed.headers.iter().map(|(n, _)| *n).collect::<Vec<_>>(),
                header::ALL
            );
        }
    }

    /// The encodings the server checks by shape: 32 lowercase hex, 64 lowercase hex, base64url
    /// without padding, 88-character standard base64.
    #[test]
    fn header_encodings_have_the_contracts_shape() {
        let identity = identity_with("nWGxne/9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A=");
        let meta: AgentDiagnosticsMeta = serde_json::from_str(
            r#"{"build":{"version":"0.1.0","commit":null,"dirty":null,"channel":"dev","built_at":null,"label":"0.1.0 · dev"},"client_time":1,"comment":"???>>>~~~ ÿ","files":[{"name":"build.json","bytes":2}]}"#,
        )
        .expect("meta");
        let header_text = meta_header(&meta).expect("fits");
        assert!(header_text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'));
        let signed = sign(
            &identity,
            "a3f1c2d4-5b6e-4f7a-8c9d-0e1f2a3b4c5d",
            1_790_590_530_123,
            [0xAB; 16],
            &sha256_hex(b"zip"),
            &header_text,
        )
        .expect("signs");
        let get = |name: &str| {
            signed
                .headers
                .iter()
                .find(|(n, _)| *n == name)
                .map(|(_, v)| v.as_str())
                .expect("present")
        };
        let lower_hex = |s: &str, len: usize| {
            s.len() == len
                && s.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        };
        assert!(lower_hex(get(header::NONCE), 32));
        assert_eq!(get(header::NONCE), "ab".repeat(16));
        assert!(lower_hex(get(header::CONTENT_SHA256), 64));
        assert_eq!(get(header::TIMESTAMP), "1790590530123");
        let signature = get(header::SIGNATURE);
        assert_eq!(signature.len(), 88);
        assert!(signature.ends_with("=="));
        // A device id with a line break is refused rather than signed.
        assert!(sign(&identity, "a\nb", 1, [0; 16], "c", &header_text).is_err());
    }

    #[test]
    fn the_metadata_header_is_refused_past_the_servers_limit() {
        let mut meta: AgentDiagnosticsMeta = serde_json::from_str(
            r#"{"build":{"version":"0.1.0","commit":null,"dirty":null,"channel":"dev","built_at":null,"label":"x"},"client_time":1,"files":[]}"#,
        )
        .expect("meta");
        meta.comment = Some("я".repeat(5000));
        assert!(meta_header(&meta).is_err());
    }

    #[test]
    fn the_endpoint_is_the_signaling_host_over_https() {
        let ok = |from: &str| endpoint(from).map(|u| u.to_string());
        // The agents' own hostname: the report goes where the socket does.
        assert_eq!(
            ok(afklink_core::config::PROD_SERVER_URL).as_deref(),
            Ok("https://api.afklink.app/api/diagnostics/agent")
        );
        // Any host is taken as given: the report goes where the socket does.
        assert_eq!(
            ok("wss://example.test/ws/agent").as_deref(),
            Ok("https://example.test/api/diagnostics/agent")
        );
        assert_eq!(
            ok("ws://localhost:8787/ws/agent").as_deref(),
            Ok("http://localhost:8787/api/diagnostics/agent")
        );
        assert_eq!(
            ok("ws://127.0.0.1:8787/ws/agent?x=1").as_deref(),
            Ok("http://127.0.0.1:8787/api/diagnostics/agent")
        );
        assert_eq!(
            ok("wss://user:pw@example.test:8443/ws/agent").as_deref(),
            Ok("https://example.test:8443/api/diagnostics/agent")
        );
        assert!(
            endpoint("ws://example.test/ws/agent").is_err(),
            "no plain http off this machine"
        );
        assert!(endpoint("not a url").is_err());
        assert!(endpoint("ftp://example.test/").is_err());
    }

    fn prepared(endpoint: Url) -> Prepared {
        let body = Bytes::from_static(b"PK\x05\x06\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0");
        Prepared {
            endpoint,
            device: "a3f1c2d4-5b6e-4f7a-8c9d-0e1f2a3b4c5d".into(),
            content_sha256: sha256_hex(&body),
            body,
            meta_header: "eyJ4IjoxfQ".into(),
        }
    }

    /// Upload against `answers` with a clock at `clock_ms` and nonces 1, 2, 3…
    fn run(answers: Vec<(&'static str, String, String)>, clock_ms: u64) -> (Outcome, Vec<Seen>) {
        let (url, seen) = serve(answers);
        let identity = identity_with("nWGxne/9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A=");
        // The app's own client, as `send_logs` builds it, but for the proxy and a shorter wait.
        let client = client_builder("AFKLink/0.4.0 (release)")
            .no_proxy()
            .timeout(Duration::from_secs(20))
            .build()
            .expect("client");
        let report = prepared(url);
        let mut n = 0u8;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let outcome = runtime.block_on(send(
            &client,
            &report,
            &identity,
            || clock_ms,
            || {
                n += 1;
                [n; 16]
            },
            STALL,
        ));
        let seen = afklink_core::lock(&seen).clone();
        (outcome, seen)
    }

    const RECEIPT: &str = r#"{"report_id":"5e0b1c2d-3f4a-4b5c-8d6e-7f8091a2b3c4","bytes":22}"#;

    #[test]
    fn a_201_is_sent_with_its_receipt_and_a_verifiable_signature() {
        let (outcome, seen) = run(
            vec![("201 Created", String::new(), RECEIPT.into())],
            1_790_590_530_123,
        );
        assert_eq!(
            outcome,
            Outcome::Sent {
                receipt: Some(DiagnosticsReceipt {
                    report_id: "5e0b1c2d-3f4a-4b5c-8d6e-7f8091a2b3c4".into(),
                    bytes: 22
                })
            }
        );
        assert_eq!(seen.len(), 1);
        let request = &seen[0];
        assert!(
            request
                .head
                .starts_with("POST /api/diagnostics/agent HTTP/1.1"),
            "{}",
            request.head
        );
        assert_eq!(
            request.header("content-type").as_deref(),
            Some("application/zip")
        );
        // The build, as the backend reads it from every agent request.
        assert_eq!(
            request.header("user-agent").as_deref(),
            Some("AFKLink/0.4.0 (release)")
        );
        assert_eq!(request.body.len(), 22);
        assert_eq!(
            request.header(header::CONTENT_SHA256),
            Some(sha256_hex(&request.body))
        );
        assert_eq!(
            request.header(header::TIMESTAMP).as_deref(),
            Some("1790590530123")
        );
        assert_eq!(request.header(header::NONCE), Some("01".repeat(16)));
        // The signature verifies with the device's public key over the string the headers make.
        let meta = request.header(header::META).expect("meta");
        let canonical = agent_request_canonical(&AgentRequestSigned {
            method: "POST",
            path: DIAGNOSTICS_AGENT_PATH,
            device: &request.header(header::DEVICE).expect("device"),
            timestamp: &request.header(header::TIMESTAMP).expect("timestamp"),
            nonce: &request.header(header::NONCE).expect("nonce"),
            content_sha256: &request.header(header::CONTENT_SHA256).expect("sha"),
            meta_sha256: &sha256_hex(meta.as_bytes()),
        })
        .expect("canonical");
        let key = base64::engine::general_purpose::STANDARD
            .decode("11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=")
            .expect("key");
        let key = ed25519_dalek::VerifyingKey::from_bytes(&key.try_into().expect("32 bytes"))
            .expect("key");
        let signature = base64::engine::general_purpose::STANDARD
            .decode(request.header(header::SIGNATURE).expect("signature"))
            .expect("base64");
        let signature =
            ed25519_dalek::Signature::from_bytes(&signature.try_into().expect("64 bytes"));
        key.verify_strict(canonical.as_bytes(), &signature)
            .expect("the signature verifies");
    }

    #[test]
    fn a_clock_skew_is_retried_once_with_the_servers_time_and_a_new_nonce() {
        let skew = format!("{SERVER_TIME_HEADER}: 1790590830123\r\n");
        let (outcome, seen) = run(
            vec![
                (
                    "401 Unauthorized",
                    skew,
                    r#"{"error":"clock_skew","message":"clock"}"#.into(),
                ),
                ("201 Created", String::new(), RECEIPT.into()),
            ],
            1_790_590_530_123,
        );
        assert!(
            matches!(outcome, Outcome::Sent { receipt: Some(_) }),
            "{outcome:?}"
        );
        assert_eq!(seen.len(), 2);
        assert_eq!(
            seen[1].header(header::TIMESTAMP).as_deref(),
            Some("1790590830123")
        );
        assert_ne!(seen[0].header(header::NONCE), seen[1].header(header::NONCE));
        assert_ne!(
            seen[0].header(header::SIGNATURE),
            seen[1].header(header::SIGNATURE)
        );
        assert_eq!(seen[0].header(header::META), seen[1].header(header::META));
    }

    #[test]
    fn a_second_clock_skew_is_not_retried() {
        let skew = || format!("{SERVER_TIME_HEADER}: 1790590830123\r\n");
        let refused = || r#"{"error":"clock_skew"}"#.to_string();
        let (outcome, seen) = run(
            vec![
                ("401 Unauthorized", skew(), refused()),
                ("401 Unauthorized", skew(), refused()),
                ("201 Created", String::new(), RECEIPT.into()),
            ],
            1,
        );
        assert_eq!(outcome, Outcome::Failed(Failure::ClockSkew));
        assert_eq!(seen.len(), 2);
        // Without the server's time there is nothing to correct by.
        let (outcome, seen) = run(vec![("401 Unauthorized", String::new(), refused())], 1);
        assert_eq!(outcome, Outcome::Failed(Failure::ClockSkew));
        assert_eq!(seen.len(), 1);
    }

    #[test]
    fn each_refusal_is_told_apart() {
        let (outcome, _) = run(
            vec![(
                "429 Too Many Requests",
                "Retry-After: 1200\r\n".into(),
                r#"{"error":"rate_limited"}"#.into(),
            )],
            1,
        );
        assert_eq!(
            outcome,
            Outcome::TooOften {
                retry_after_s: Some(1200)
            }
        );
        let (outcome, _) = run(
            vec![(
                "413 Payload Too Large",
                String::new(),
                r#"{"error":"payload_too_large"}"#.into(),
            )],
            1,
        );
        assert_eq!(outcome, Outcome::Failed(Failure::TooLarge));
        let (outcome, _) = run(
            vec![(
                "503 Service Unavailable",
                String::new(),
                r#"{"error":"service_unavailable"}"#.into(),
            )],
            1,
        );
        assert_eq!(outcome, Outcome::Failed(Failure::Unavailable));
        let (outcome, seen) = run(
            vec![(
                "401 Unauthorized",
                String::new(),
                r#"{"error":"bad_signature"}"#.into(),
            )],
            1,
        );
        assert_eq!(
            outcome,
            Outcome::Failed(Failure::Refused {
                status: 401,
                code: Some("bad_signature".into())
            })
        );
        assert_eq!(seen.len(), 1, "a bad signature is not retried");
        let (outcome, _) = run(
            vec![("500 Internal Server Error", String::new(), "oops".into())],
            1,
        );
        assert_eq!(
            outcome,
            Outcome::Failed(Failure::Refused {
                status: 500,
                code: None
            })
        );
        // Sent, with a receipt that does not parse: sent all the same.
        let (outcome, _) = run(vec![("201 Created", String::new(), "{".into())], 1);
        assert_eq!(outcome, Outcome::Sent { receipt: None });
    }

    /// A redirect is not followed — the signed report never goes where it points — and is a
    /// failure of its own, after which the other way to the server is tried.
    #[test]
    fn a_redirect_is_not_followed() {
        for status in [
            "301 Moved Permanently",
            "302 Found",
            "307 Temporary Redirect",
        ] {
            let (outcome, seen) = run(
                vec![
                    // Back to this very server: a client that followed it would make a second
                    // request, and get the 201.
                    (
                        status,
                        "Location: /api/diagnostics/agent?again=1\r\n".into(),
                        String::new(),
                    ),
                    ("201 Created", String::new(), RECEIPT.into()),
                ],
                1,
            );
            let code: u16 = status[..3].parse().expect("a status");
            assert_eq!(
                outcome,
                Outcome::Failed(Failure::Redirected { status: code }),
                "{status}"
            );
            assert_eq!(
                seen.len(),
                1,
                "{status}: one request, the redirect not followed"
            );
            assert!(falls_back(&outcome), "the other way is tried");
            assert_eq!(Failure::Redirected { status: code }.kind(), "redirected");
        }
    }

    #[test]
    fn no_server_is_a_network_failure() {
        // A port nobody listens on, and nobody can take while the test runs: the local end of a
        // connected client socket. A port merely bound and let go can be handed to another test's
        // server at once, and the request would reach that server.
        let listener = TcpListener::bind("127.0.0.1:0").expect("a listener");
        let held = std::net::TcpStream::connect(listener.local_addr().expect("addr"))
            .expect("a client connection");
        let port = held.local_addr().expect("the client's port").port();
        let url =
            Url::parse(&format!("http://127.0.0.1:{port}{DIAGNOSTICS_AGENT_PATH}")).expect("url");
        let identity = identity_with("nWGxne/9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A=");
        let client = reqwest::Client::builder()
            .no_proxy()
            .build()
            .expect("client");
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let outcome = runtime.block_on(send(
            &client,
            &prepared(url),
            &identity,
            || 1,
            || [7; 16],
            STALL,
        ));
        match outcome {
            Outcome::Failed(Failure::Network(why)) => assert!(why.starts_with("connect"), "{why}"),
            other => unreachable!("expected a network failure, got {other:?}"),
        }
        // Held to here: the port stays taken for the whole request.
        drop((held, listener));
    }

    #[test]
    fn nonces_differ() {
        assert_ne!(random_nonce(), random_nonce());
    }

    /// How a holding mock treats the request it takes.
    #[derive(Debug, Clone, Copy)]
    enum Hold {
        /// Reads the head, then nothing more: the client's body stops going out.
        AfterHead,
        /// Reads the whole body, then never answers.
        AfterBody,
    }

    /// A local server that takes one request and holds it as `hold` says until `release` is sent or
    /// dropped: the report path's URL. What it read of the body comes back on the receiver.
    fn holding(
        hold: Hold,
    ) -> (
        Url,
        std::sync::mpsc::Sender<()>,
        std::sync::mpsc::Receiver<usize>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let url = Url::parse(&format!(
            "http://{}{DIAGNOSTICS_AGENT_PATH}",
            listener.local_addr().expect("addr")
        ))
        .expect("url");
        let (release, released) = std::sync::mpsc::channel::<()>();
        let (tell, read) = std::sync::mpsc::channel::<usize>();
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
            if let Hold::AfterBody = hold {
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
            }
            tell.send(data.len() - head_end).ok();
            // Holds the connection, silent, until the test lets go.
            let _ = released.recv_timeout(Duration::from_secs(60));
            drop(stream);
        });
        (url, release, read)
    }

    /// Upload `report` to `endpoints` with `stall` and nonces 1, 2, 3…
    fn run_any(report: &Prepared, endpoints: &[Url], stall: Stall) -> Outcome {
        let identity = identity_with("nWGxne/9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A=");
        let client = client_builder("AFKLink/0.6.0 (release)")
            .no_proxy()
            .build()
            .expect("client");
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let mut n = 0u8;
        runtime.block_on(send_any(
            &client,
            report,
            endpoints,
            &identity,
            || 1_790_590_530_123,
            || {
                n += 1;
                [n; 16]
            },
            stall,
            AfterBody::FallBack,
        ))
    }

    /// Short stall limits, for tests that wait for them.
    const SHORT_STALL: Stall = Stall {
        body: Duration::from_millis(500),
        answer: Duration::from_millis(500),
    };

    /// The freeze in an upload: the first way's connection stops taking the body (nothing acknowledged
    /// any more) — given up at the stall limit, not the request's ten minutes, and the report goes the
    /// other way, whole and signed alike.
    #[test]
    fn an_upload_that_stalls_goes_the_other_way() {
        let (stalled, release, read) = holding(Hold::AfterHead);
        let (good, seen) = serve(vec![("201 Created", String::new(), RECEIPT.into())]);
        // Far more than the loopback's buffers can hold while nobody reads.
        let body = Bytes::from(vec![0x5a; 32 * 1024 * 1024]);
        let report = Prepared {
            content_sha256: sha256_hex(&body),
            body,
            ..prepared(stalled.clone())
        };
        let started = Instant::now();
        let outcome = run_any(&report, &[stalled, good], SHORT_STALL);
        assert!(
            matches!(outcome, Outcome::Sent { receipt: Some(_) }),
            "{outcome:?}"
        );
        let read_by_stalled = read
            .recv_timeout(Duration::from_secs(5))
            .expect("it took the head");
        assert!(
            read_by_stalled < report.body.len(),
            "it read at most what came with the head: {read_by_stalled}"
        );
        let seen = afklink_core::lock(&seen).clone();
        assert_eq!(seen.len(), 1);
        assert_eq!(
            seen[0].body.len(),
            report.body.len(),
            "the whole body the other way"
        );
        assert_eq!(
            seen[0].header(header::CONTENT_SHA256),
            Some(report.content_sha256.clone())
        );
        assert!(
            started.elapsed() < Duration::from_secs(30),
            "the stall limit, not the request's: {:?}",
            started.elapsed()
        );
        release.send(()).ok();

        // That way alone: the stall is the body's, mid-way — not the answer's.
        let (stalled, release, _read) = holding(Hold::AfterHead);
        let outcome = run_any(
            &Prepared {
                endpoint: stalled.clone(),
                ..report.clone()
            },
            &[stalled],
            SHORT_STALL,
        );
        match outcome {
            Outcome::Failed(Failure::Network(why)) => {
                assert!(why.starts_with("stall: the connection took "), "{why}");
                assert!(why.contains("and nothing more for"), "{why}");
            }
            other => unreachable!("expected a stall, got {other:?}"),
        }
        release.send(()).ok();
    }

    /// The body went out whole and no answer came (the server's answer frozen on its way): given up
    /// at the answer's limit, and the report goes the other way.
    #[test]
    fn an_upload_with_no_answer_goes_the_other_way() {
        let (silent, release, read) = holding(Hold::AfterBody);
        let (good, seen) = serve(vec![("201 Created", String::new(), RECEIPT.into())]);
        let report = prepared(silent.clone());
        let outcome = run_any(&report, &[silent, good], SHORT_STALL);
        assert!(
            matches!(outcome, Outcome::Sent { receipt: Some(_) }),
            "{outcome:?}"
        );
        assert_eq!(
            read.recv_timeout(Duration::from_secs(5))
                .expect("it read the body"),
            report.body.len()
        );
        assert_eq!(afklink_core::lock(&seen).len(), 1);
        release.send(()).ok();

        // That way alone: the stall is the answer's.
        let (silent, release, _read) = holding(Hold::AfterBody);
        match run_any(&prepared(silent.clone()), &[silent], SHORT_STALL) {
            Outcome::Failed(Failure::Network(why)) => {
                assert!(
                    why.starts_with("stall: the whole body (22 bytes) went "),
                    "{why}"
                );
            }
            other => unreachable!("expected a stall, got {other:?}"),
        }
        release.send(()).ok();
    }

    /// The server's own answer is the answer whichever way it came: a refusal is not tried again
    /// elsewhere; a gateway's error is.
    #[test]
    fn a_refusal_stays_and_a_gateways_error_goes_the_other_way() {
        let (first, _) = serve(vec![(
            "429 Too Many Requests",
            "Retry-After: 1200\r\n".into(),
            r#"{"error":"rate_limited"}"#.into(),
        )]);
        let (second, seen_second) = serve(vec![("201 Created", String::new(), RECEIPT.into())]);
        let outcome = run_any(&prepared(first.clone()), &[first, second], STALL);
        assert_eq!(
            outcome,
            Outcome::TooOften {
                retry_after_s: Some(1200)
            }
        );
        assert!(
            afklink_core::lock(&seen_second).is_empty(),
            "the refusal is the server's: not sent again"
        );

        let (gateway, _) = serve(vec![(
            "522 Origin Connection Time-out",
            String::new(),
            String::new(),
        )]);
        let (second, seen_second) = serve(vec![("201 Created", String::new(), RECEIPT.into())]);
        let outcome = run_any(&prepared(gateway.clone()), &[gateway, second], STALL);
        assert!(matches!(outcome, Outcome::Sent { .. }), "{outcome:?}");
        assert_eq!(afklink_core::lock(&seen_second).len(), 1);
    }
}
