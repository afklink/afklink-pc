//! The update check and download: this module's own requests, step for step those of
//! tauri-plugin-updater 2.13 (`check()` and `Update::download`; «the plugin» below), but each held
//! to a byte and time limit. The plugin is neither a dependency nor registered, and nothing here
//! resembles its `install()`, which runs an MSI or NSIS installer: this app is one portable exe.
//!
//! The check ([`check`]): GET the manifest, at most [`MAX_MANIFEST_BYTES`] of it; parse it into a
//! typed struct ([`manifest::parse`]: the plugin's two forms, never a `serde_json::Value`); accept
//! only a newer version, never a downgrade ([`super::policy::is_newer`]); take
//! `platforms[<target>]` ([`TARGET`]). `204 No Content` is "nothing newer", any other non-2xx a
//! failed check. Endpoint templates (`{{current_version}}`) are not filled in: our addresses have
//! none. Both requests carry this build's `User-Agent`, `AFKLink/<version> (<channel>)`.
//!
//! The download ([`download`]): the plugin's request, cut as soon as the body brings or announces
//! more than the manifest's `size` (at most [`MAX_EXE_BYTES`]), then verified on the blocking pool
//! ([`verify`]): the minisign signature; the signed `file:` and `version:`, exactly
//! `AFKLink-<version>.exe` and `<version>` (never a trial build's `-untagged-` exe, never a
//! signature that names no file or version); the manifest's `sha256` and `size`, both required.
//!
//! # Trust
//!
//! - One key: the pinned `updater.pub` handed in (`super::pubkey::embedded`), for the check and the
//!   download alike. `tauri.conf.json` has no `plugins.updater`, so there is no second key
//!   anywhere; an empty key is refused.
//! - The manifest only from our own API hosts, every redirect hop included ([`our_api_host`]). The
//!   exe from any https host, redirects included ([`download_url_allowed`]): the signature, not
//!   the host, is what is trusted. Plain http to this machine only with the tests'
//!   [`Limits::plain_http_loopback`].
//! - A signature made with another key is refused before its exe is fetched; a legacy (`Ed`)
//!   signature always ([`manifest::verify_signature`]: its algorithm bytes are not signed, so a
//!   flip from prehashed `ED` would pass the exe's digest off as the exe).
//!
//! # Two ways to the same files
//!
//! A Russian provider may let a connection to Cloudflare open and then freeze the reply after a few
//! kilobytes (`afklink_core::entry`): the manifest may still arrive while the exe stops. So the
//! check and the download each try a list of addresses, the signaling socket's way first
//! ([`check_any`], [`download_any`]), and a transfer that hears nothing for [`STALL`] fails instead
//! of waiting out the whole limit. Bytes that fail verification are never tried elsewhere: the host
//! changes nothing of what is checked.

use std::time::{Duration, Instant};

use futures_util::StreamExt;
use semver::Version;
use tauri::Url;

use super::manifest;

/// The manifest's key for this build: 64-bit Windows, no installer (`release-build.ts`'s `PLATFORM`).
pub(crate) const TARGET: &str = "windows-x86_64";
/// The manifest request's time limit, connecting to its last byte ([`LIMITS`]'s `check_total`).
pub const CHECK_TIMEOUT: Duration = Duration::from_secs(30);

/// The most a manifest may weigh: 64 KiB. The live one (0.7.1) is 868 bytes — the version,
/// some sixty characters of notes, one platform with its signature, URL, SHA-256 and size; notes
/// seventy times as long still fit. Past this the body is not read on, and a `Content-Length`
/// that says more is refused ([`check`]). The plugin's `res.json()` read the whole body, however
/// long, into a `serde_json::Value` (10–20 times its size) and cloned it, bounded only by the
/// 30 s limit times the line's rate: a hostile or broken server, or anything on the way (the RU
/// entry is a TCP forwarder), could take the agent's memory at every check.
pub const MAX_MANIFEST_BYTES: u64 = 64 * 1024;

/// What the check sends as `Accept` (the plugin's).
const JSON: &str = "application/json";

/// The longest exe address a manifest may name ([`release_of`]).
const MAX_URL_CHARS: usize = 2048;
/// The download's: tens of megabytes over a slow line.
const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(15 * 60);

/// The most a manifest may announce as the exe's `size` (and so the most a download may bring):
/// 256 MiB. The release exe weighs 26–35 MB (0.1.0: 26 MB, 0.7.1: 35 435 008 bytes —
/// the UI, OpenH264, the FakerInput MSI and WebView glue in one portable file), so this leaves more
/// than seven times today's size for growth and still bounds what a download holds in memory to a
/// size any PC that runs the app can spare.
pub const MAX_EXE_BYTES: u64 = 256 * 1024 * 1024;

/// What the download sends as `Accept` when the `Update`'s headers name none (the plugin's).
const OCTET_STREAM: &str = "application/octet-stream";

/// How long connecting may take — the name, TCP, TLS: as the signaling socket's
/// (`afklink_transport::signaling::CONNECT_TIMEOUT`), so a path that drops packets is left for the
/// other way in seconds, not at the operating system's own limit.
pub const CONNECT: Duration = Duration::from_secs(10);

/// How long a request may hear nothing from the server — the answer's head, then between two reads
/// of its body — before it is a stall (reqwest's `read_timeout`, which a byte resets). A healthy line
/// never goes that quiet: TCP's retransmission backs off 1, 2, 4, 8 s, so four losses in a row are
/// some 15 s of nothing, and this is twice that; a frozen path never resumes.
pub const STALL: Duration = Duration::from_secs(30);

/// The limits of the check and the download: [`LIMITS`] in the app, smaller in tests.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub connect: Duration,
    pub stall: Duration,
    /// The most a manifest may announce as the exe's size ([`MAX_EXE_BYTES`]).
    pub max_bytes: u64,
    /// Whether the download may use plain http to this machine (127.0.0.0/8, `::1`, `localhost`):
    /// the tests' local servers only — never in the app ([`LIMITS`]), where the exe comes over
    /// https only, redirects included ([`download_url_allowed`]). The same for the manifest.
    pub plain_http_loopback: bool,
    /// The whole manifest request's limit, connecting to its last byte ([`CHECK_TIMEOUT`]): a
    /// server that drips its answer faster than [`STALL`] still ends here.
    pub check_total: Duration,
    /// No proxy at all: the tests' local servers only. The app's requests (`false`) take the
    /// proxy reqwest finds in the system, as the plugin's did.
    pub no_proxy: bool,
}

/// The app's limits.
pub const LIMITS: Limits = Limits {
    connect: CONNECT,
    stall: STALL,
    max_bytes: MAX_EXE_BYTES,
    plain_http_loopback: false,
    check_total: CHECK_TIMEOUT,
    no_proxy: false,
};

/// Whether `url` names this machine (for [`Limits::plain_http_loopback`]).
fn is_loopback(url: &Url) -> bool {
    let Some(host) = url.host_str() else {
        return false;
    };
    host.eq_ignore_ascii_case("localhost")
        || host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
}

/// Whether `what` («the exe's», «the manifest's») may be fetched from (or redirected to) `url`:
/// https; plain http only to this machine and only with [`Limits::plain_http_loopback`]. Why not,
/// when not.
fn url_allowed(url: &Url, limits: Limits, what: &str) -> Result<(), String> {
    match url.scheme() {
        "https" => Ok(()),
        "http" if limits.plain_http_loopback && is_loopback(url) => Ok(()),
        "http" if is_loopback(url) => Err(format!(
            "{what} address {} is not https (plain http to this machine is for tests only)",
            shown_url(url)
        )),
        _ => Err(format!("{what} address {} is not https", shown_url(url))),
    }
}

/// An address the server named (a redirect's `Location`, the manifest's exe URL), as a log line or
/// an error may carry it: quoted, at most [`MAX_URL_CHARS`] characters.
fn shown_url(url: &Url) -> String {
    manifest::quoted(url.as_str(), MAX_URL_CHARS)
}

/// Whether the exe may be fetched from (or redirected to) `url` ([`url_allowed`]): any host over
/// https — the signature, not the host, is what is trusted.
pub(crate) fn download_url_allowed(url: &Url, limits: Limits) -> Result<(), String> {
    url_allowed(url, limits, "the exe's")
}

/// Whether `url` is one of our two API hosts, `api.afklink.app` or `api.ru.afklink.app`
/// (`afklink_core::entry`), as the URL parser read it: https, the host exactly one of them (any
/// case; no trailing dot, nothing before or after it, no IP address), no credentials, no port but
/// https's own (an explicit `:443` is dropped by the parser). Why not, when not. The manifest's
/// every address and redirect hop ([`manifest_url_allowed`]) and the `AFKLINK_UPDATE_ENDPOINT`
/// override (`super::override_allowed`) are held to it.
pub(crate) fn our_api_host(url: &Url) -> Result<(), String> {
    use afklink_core::entry::{PRIMARY_API_HOST, RU_API_HOST};
    if url.scheme() != "https" {
        return Err(format!("{}: is not https", url.scheme()));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err("carries credentials".to_string());
    }
    let Some(domain) = url.domain() else {
        return Err(match url.host_str() {
            Some(host) => format!("{host} is an IP address, not our host"),
            None => "has no host".to_string(),
        });
    };
    if ![PRIMARY_API_HOST, RU_API_HOST]
        .iter()
        .any(|ours| domain.eq_ignore_ascii_case(ours))
    {
        // The longest name DNS has is 253 characters; a parser may take more.
        let shown = if domain.len() > 253 {
            manifest::quoted(domain, 253)
        } else {
            domain.to_string()
        };
        return Err(format!(
            "{shown} is not {PRIMARY_API_HOST} or {RU_API_HOST}"
        ));
    }
    if let Some(port) = url.port() {
        return Err(format!("port {port}: only https's own port is ours"));
    }
    Ok(())
}

/// Whether the manifest may be asked for at (or redirected to) `url`: our own hosts only
/// ([`our_api_host`]; both answer `/download/latest.json` with no redirect) — and, with the
/// tests' [`Limits::plain_http_loopback`], this machine. Why not, when not.
fn manifest_url_allowed(url: &Url, limits: Limits) -> Result<(), String> {
    if limits.plain_http_loopback && is_loopback(url) && matches!(url.scheme(), "http" | "https") {
        return Ok(());
    }
    our_api_host(url).map_err(|why| format!("the manifest's address {}: {why}", shown_url(url)))
}

/// A newer release a check found: what the download needs of the manifest, as the plugin's
/// `Update` carried it.
#[derive(Debug, Clone)]
pub struct Release {
    /// The announced version as SemVer writes it (leading `v`s dropped, as the plugin drops them).
    pub version: String,
    pub download_url: Url,
    /// The manifest's `signature`: base64 of the `.sig` file.
    pub signature: String,
    /// The entry's `sha256` and `size`, or why they cannot be read — a refusal at the download, as
    /// it has always been ([`manifest::extras`]).
    pub extras: Result<manifest::Extras, String>,
    /// This build's `User-Agent`, on the download as on the check.
    pub(crate) user_agent: String,
    /// What identifies this manifest entry ([`manifest::identity`]): a download rejected once is
    /// not repeated for the same entry (`super::task`).
    pub(crate) identity: String,
}

impl Release {
    /// [`Self::identity`]: SHA-256 of the entry, upper hex.
    pub fn identity(&self) -> &str {
        &self.identity
    }
}

/// A check's answer.
pub struct Checked {
    /// A newer version, when there is one.
    pub update: Option<Release>,
    /// The version the manifest names, newer or not (for the log).
    pub remote: Option<Version>,
}

/// What [`manifest_body`] brought: the body, or the server's «nothing newer».
enum Body {
    Bytes(Vec<u8>),
    NoContent,
}

/// GET the manifest at `endpoint`, at most [`MAX_MANIFEST_BYTES`] of it: refused when its
/// `Content-Length` says more, cut at the first chunk past the cap — never more than the cap held.
/// Why not, when not (every refusal logged here, with the bytes, the cap and the host).
async fn manifest_body(endpoint: &Url, user_agent: &str, limits: Limits) -> Result<Body, String> {
    manifest_url_allowed(endpoint, limits).inspect_err(|why| {
        tracing::debug!(%endpoint, "update check: not asking, {why}");
    })?;
    let client = client(
        limits,
        limits.check_total,
        "the manifest's",
        manifest_url_allowed,
    )
    .map_err(|e| {
        let why = with_causes(&e);
        tracing::warn!(%endpoint, "update check: no HTTP client: {why}");
        why
    })?;
    let response = client
        .get(endpoint.clone())
        .header(reqwest::header::USER_AGENT, user_agent)
        .header(reqwest::header::ACCEPT, JSON)
        .send()
        .await
        .map_err(|e| with_causes(&e))?;
    let status = response.status();
    // Where the answer came from, after any redirect (for the log).
    let host = response.url().host_str().unwrap_or("-").to_string();
    if status == reqwest::StatusCode::NO_CONTENT {
        tracing::debug!(%endpoint, host, "update check: 204 No Content, nothing newer (as the plugin read it)");
        return Ok(Body::NoContent);
    }
    if !status.is_success() {
        return Err(format!("the server answered {status}"));
    }
    let announced: Option<u64> = response
        .headers()
        .get(reqwest::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse().ok());
    if let Some(length) = announced.filter(|n| *n > MAX_MANIFEST_BYTES) {
        tracing::warn!(
            %endpoint,
            host,
            content_length = length,
            cap = MAX_MANIFEST_BYTES,
            "update check: manifest refused, its Content-Length is over the cap; not read"
        );
        return Err(format!(
            "the manifest announces {length} bytes, more than the {MAX_MANIFEST_BYTES} allowed"
        ));
    }
    // The announced length is a hint for the buffer, never the limit: a chunked or a lying answer
    // is counted as it comes.
    let room = announced.unwrap_or(4096).min(MAX_MANIFEST_BYTES);
    let mut body = Vec::with_capacity(usize::try_from(room).unwrap_or(0));
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk =
            chunk.map_err(|e| format!("{} (after {} bytes)", with_causes(&e), body.len()))?;
        let received = body.len() as u64 + chunk.len() as u64;
        if received > MAX_MANIFEST_BYTES {
            // `stream` (the response) is dropped on return: the connection closes.
            tracing::warn!(
                %endpoint,
                host,
                received,
                buffered = body.len(),
                cap = MAX_MANIFEST_BYTES,
                content_length = announced.map_or_else(|| "-".to_string(), |n| n.to_string()),
                "update check: manifest cut, over its byte cap"
            );
            return Err(format!(
                "the manifest is longer than the {MAX_MANIFEST_BYTES} bytes allowed: {received} \
                 received, {} buffered, cut",
                body.len()
            ));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(Body::Bytes(body))
}

/// What a read manifest offers this build at `current`: the version it names, and the release
/// when that is newer. Refused as the plugin refused it: no entry for [`TARGET`] (whether newer or
/// not), or a flat manifest without `url` or `signature`.
pub(crate) fn release_of(
    m: &manifest::Manifest,
    current: &Version,
    user_agent: &str,
) -> Result<(Version, Option<Release>), String> {
    let version = m.version()?;
    let (url, signature, entry) = match &m.platforms {
        Some(platforms) => match platforms.get(TARGET) {
            Some(p) => (p.url.clone(), p.signature.clone(), Some(p)),
            None => {
                // The server's words: quoted (control characters escaped), each cut short, eight
                // at most — never a line of their own in the log.
                let mut named: Vec<&str> = platforms.keys().map(String::as_str).collect();
                named.sort_unstable();
                let shown: Vec<String> = named
                    .iter()
                    .take(8)
                    .map(|k| manifest::quoted(k, 64))
                    .collect();
                return Err(format!(
                    "the manifest has no {TARGET} entry ({} platforms: {}{})",
                    platforms.len(),
                    shown.join(", "),
                    if named.len() > 8 { ", …" } else { "" }
                ));
            }
        },
        None => match (&m.url, &m.signature) {
            (Some(url), Some(signature)) => (url.clone(), signature.clone(), None),
            (None, _) => return Err("the manifest has neither platforms nor a url".to_string()),
            (Some(_), None) => {
                return Err("the manifest has neither platforms nor a signature".to_string())
            }
        },
    };
    // Every log line and error that names the exe's address stays one bounded line (the live one
    // is 51 characters).
    let url_len = url.as_str().len();
    if url_len > MAX_URL_CHARS {
        return Err(format!(
            "the exe's address is {url_len} characters long, more than {MAX_URL_CHARS}"
        ));
    }
    // Newer only, never a downgrade, never the same version again.
    if !super::policy::is_newer(current, &version) {
        return Ok((version, None));
    }
    let announced = version.to_string();
    let identity = manifest::identity(&announced, &url, &signature, entry);
    Ok((
        version,
        Some(Release {
            extras: manifest::extras(entry, TARGET),
            version: announced,
            download_url: url,
            signature,
            user_agent: user_agent.to_string(),
            identity,
        }),
    ))
}

/// Ask `endpoint` whether there is a version newer than `current` (this build's). `user_agent` is
/// this build's; of `limits` the check uses the connect and stall limits, `check_total`, and the
/// tests' `plain_http_loopback` and `no_proxy` (the download's byte limit is [`download`]'s).
pub async fn check(
    key: &str,
    endpoint: &Url,
    current: &Version,
    user_agent: &str,
    limits: Limits,
) -> Result<Checked, String> {
    // Fail closed: no check is worth making without the key every download is verified with.
    if key.trim().is_empty() {
        tracing::warn!(%endpoint, "update check: no signature key given; not checking");
        return Err("no signature key".to_string());
    }
    let started = Instant::now();
    // reqwest's own total limit is set to the same; this one holds whatever reqwest does.
    let body = match tokio::time::timeout(
        limits.check_total,
        manifest_body(endpoint, user_agent, limits),
    )
    .await
    {
        Ok(body) => body?,
        Err(_) => {
            tracing::warn!(
                %endpoint,
                limit_s = limits.check_total.as_secs_f32(),
                "update check: no whole manifest within the time limit; given up"
            );
            return Err(format!(
                "no whole manifest within {} s",
                limits.check_total.as_secs_f32()
            ));
        }
    };
    let body = match body {
        Body::Bytes(body) => body,
        Body::NoContent => {
            return Ok(Checked {
                update: None,
                remote: None,
            })
        }
    };
    // Parsed on this worker: 64 KiB at most, microseconds of work.
    let m = manifest::parse(&body).inspect_err(|why| {
        tracing::debug!(%endpoint, bytes = body.len(), "update check: {why}");
    })?;
    // A test manifest for a test-key build only, and the other way round: before the version is
    // even looked at (`manifest::check_world`).
    let test_build = super::pubkey::TEST_SIGNING_KEY;
    manifest::check_world(&m, test_build).inspect_err(|why| {
        tracing::warn!(
            %endpoint,
            test_build,
            marked = ?m.afklink_test_key,
            "update check: {why}"
        );
    })?;
    tracing::debug!(
        test_build,
        marked = ?m.afklink_test_key,
        "update check: the manifest is for this build's world"
    );
    let (remote, update) = release_of(&m, current, user_agent).inspect_err(|why| {
        tracing::debug!(%endpoint, bytes = body.len(), "update check: refused, {why}");
    })?;
    tracing::debug!(
        %endpoint,
        elapsed_ms = started.elapsed().as_millis() as u64,
        bytes = body.len(),
        %remote,
        %current,
        newer = update.is_some(),
        downgrade = remote < *current,
        notes_chars = m.notes.as_deref().map_or(0, |n| n.chars().count()),
        pub_date = %m.pub_date.as_deref().map_or_else(|| "-".to_string(), |d| manifest::quoted(d, 64)),
        entry = update.as_ref().map_or("-", |r| manifest::short(&r.identity)),
        %user_agent,
        "update check: manifest read"
    );
    Ok(Checked {
        update,
        remote: Some(remote),
    })
}

/// [`check`] at each of `endpoints` in turn until one answers: the answer and the index of the one
/// that gave it. Every failure is logged with its address and time; all of them together are the
/// error.
pub async fn check_any(
    key: &str,
    endpoints: &[Url],
    current: &Version,
    user_agent: &str,
    limits: Limits,
) -> Result<(Checked, usize), String> {
    let mut failures: Vec<String> = Vec::new();
    for (i, endpoint) in endpoints.iter().enumerate() {
        let started = Instant::now();
        match check(key, endpoint, current, user_agent, limits).await {
            Ok(checked) => {
                if i > 0 {
                    tracing::info!(
                        %endpoint,
                        tried = i + 1,
                        "update check: the manifest came the other way"
                    );
                }
                return Ok((checked, i));
            }
            Err(e) => {
                let elapsed_ms = started.elapsed().as_millis() as u64;
                match endpoints.get(i + 1) {
                    Some(next) => tracing::warn!(
                        %endpoint,
                        %next,
                        elapsed_ms,
                        stall_s = limits.stall.as_secs(),
                        "update check: no manifest this way ({e}); trying the other"
                    ),
                    None => tracing::debug!(
                        %endpoint,
                        elapsed_ms,
                        "update check: no manifest this way either ({e})"
                    ),
                }
                failures.push(format!("{endpoint}: {e}"));
            }
        }
    }
    Err(if failures.is_empty() {
        "no address to check".to_string()
    } else {
        failures.join("; ")
    })
}

/// A downloaded update that passed every check.
pub struct Downloaded {
    pub version: Version,
    pub bytes: Vec<u8>,
    /// SHA-256, upper hex.
    pub sha256: String,
}

/// Why a download was not accepted.
#[derive(Debug)]
pub enum DownloadError {
    /// The transfer failed: worth another try later.
    Transfer(String),
    /// The bytes are not the release's: signature, size over the manifest's, hash or signed name
    /// (or the entry cannot be downloaded from at all: no sha256/size, plain http, another key) —
    /// never installed. What this says is about the manifest entry itself: the same entry is not
    /// downloaded again (`super::task::Rejected`).
    Rejected(String),
    /// Not accepted, and nothing learnt about whether the entry's bytes are the release's: a body
    /// that ended short of the manifest's size (a cut transfer that closed cleanly), a verification
    /// that did not finish (its task panicked or the runtime is going away). Never installed, shown
    /// and counted as a rejection (no strike), but not remembered against the entry.
    Unconfirmed(String),
}

impl std::fmt::Display for DownloadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Transfer(e) => write!(f, "download failed: {e}"),
            Self::Rejected(e) => write!(f, "download rejected: {e}"),
            Self::Unconfirmed(e) => write!(f, "download not accepted: {e}"),
        }
    }
}

/// The most bytes [`download`] takes, and where that number came from (for the log).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SizeLimit {
    pub(crate) bytes: u64,
    /// `"manifest size"` or `"ceiling"`.
    pub(crate) from: &'static str,
}

/// The limit for a download whose manifest names `size` (or not), with `ceiling` the most any
/// release may weigh ([`MAX_EXE_BYTES`] in the app). A manifest naming more than the ceiling is
/// refused before a byte is fetched: the manifest is not signed, and its `size` must not let the
/// plugin buffer gigabytes. (The download path always has a `size` — [`manifest::extras`] requires
/// it; `None` stays a rule here, the ceiling, should that ever change.)
pub(crate) fn size_limit(size: Option<u64>, ceiling: u64) -> Result<SizeLimit, String> {
    match size {
        Some(size) if size > ceiling => Err(format!(
            "the manifest announces {size} bytes, more than any release may weigh ({ceiling})"
        )),
        Some(size) => Ok(SizeLimit {
            bytes: size,
            from: "manifest size",
        }),
        None => Ok(SizeLimit {
            bytes: ceiling,
            from: "ceiling",
        }),
    }
}

/// Why a transfer did not bring the whole body.
enum Cut {
    /// It failed: worth another try, maybe the other way.
    Failed(String),
    /// More than the limit came, or was announced: the bytes are not the release's.
    Over {
        /// Off the wire, the chunk that crossed the limit included.
        received: u64,
        /// Kept: never past the limit.
        kept: u64,
        announced: Option<u64>,
    },
}

/// How many redirects the check and the download follow: reqwest's default.
const MAX_REDIRECTS: usize = 10;

/// Where a request may go: [`manifest_url_allowed`] or [`download_url_allowed`].
type UrlRule = fn(&Url, Limits) -> Result<(), String>;

/// The HTTP client for `what` («the manifest's», «the exe's»), as the plugin builds its own: the
/// request's whole time limit `total` ([`CHECK_TIMEOUT`] for the manifest, [`DOWNLOAD_TIMEOUT`]
/// for the exe), the system's proxy (none with the tests' [`Limits::no_proxy`]), and the connect and
/// stall limits of `limits`. Plus: every redirect hop held to `allowed` — the manifest to our own
/// hosts, the exe to https ([`url_allowed`]; plain http to this machine only with
/// [`Limits::plain_http_loopback`], the tests').
fn client(
    limits: Limits,
    total: Duration,
    what: &'static str,
    allowed: UrlRule,
) -> reqwest::Result<reqwest::Client> {
    let redirects = reqwest::redirect::Policy::custom(move |attempt| {
        let hop = attempt.previous().len();
        // The server's `Location`: one bounded line in the log ([`shown_url`]).
        let to = shown_url(attempt.url());
        if hop >= MAX_REDIRECTS {
            tracing::debug!(%to, hop, "update: {what} redirect refused, more than {MAX_REDIRECTS}");
            return attempt.error(format!("more than {MAX_REDIRECTS} redirects"));
        }
        match allowed(attempt.url(), limits) {
            Ok(()) => {
                tracing::debug!(%to, hop, "update: {what} redirect followed");
                attempt.follow()
            }
            Err(why) => {
                let why = format!("redirect refused: {why}");
                tracing::debug!(%to, hop, "update: {why}");
                attempt.error(why)
            }
        }
    });
    let mut builder = reqwest::Client::builder()
        .timeout(total)
        .https_only(!limits.plain_http_loopback)
        .redirect(redirects);
    if limits.no_proxy {
        builder = builder.no_proxy();
    }
    builder
        .connect_timeout(limits.connect)
        .read_timeout(limits.stall)
        .build()
}

/// `e` with its causes, for the log: reqwest's own message leaves them out (a refused redirect's
/// reason, a TLS error's).
fn with_causes(e: &(dyn std::error::Error + 'static)) -> String {
    let mut text = e.to_string();
    let mut cause = e.source();
    while let Some(c) = cause {
        text.push_str(": ");
        text.push_str(&c.to_string());
        cause = c.source();
    }
    text
}

/// GET `update`'s exe into memory, at most `limit` bytes: every chunk to `on_chunk(received,
/// announced)`. A body that brings or announces more is cut at once — the response dropped, the
/// connection with it — before a byte past the limit is kept.
async fn transfer(
    update: &Release,
    limits: Limits,
    limit: SizeLimit,
    on_chunk: &mut (dyn FnMut(u64, Option<u64>) + Send),
) -> Result<Vec<u8>, Cut> {
    let client = client(limits, DOWNLOAD_TIMEOUT, "the exe's", download_url_allowed)
        .map_err(|e| Cut::Failed(with_causes(&e)))?;
    let response = client
        .get(update.download_url.clone())
        .header(reqwest::header::USER_AGENT, update.user_agent.as_str())
        .header(reqwest::header::ACCEPT, OCTET_STREAM)
        .send()
        .await
        .map_err(|e| Cut::Failed(with_causes(&e)))?;
    if !response.status().is_success() {
        return Err(Cut::Failed(format!(
            "Download request failed with status: {}",
            response.status()
        )));
    }
    // As the plugin reads it, for the progress: the header, not the body's own hint.
    let announced: Option<u64> = response
        .headers()
        .get(reqwest::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse().ok());
    if announced.is_some_and(|total| total > limit.bytes) {
        return Err(Cut::Over {
            received: 0,
            kept: 0,
            announced,
        });
    }
    // Room for what is expected — the manifest's size (required), or the announced length when
    // smaller — so a 35 MB exe is not copied as the buffer doubles; never more than the limit.
    let expected = announced.map_or(limit.bytes, |total| total.min(limit.bytes));
    let mut body = Vec::with_capacity(usize::try_from(expected).unwrap_or(0));
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| Cut::Failed(with_causes(&e)))?;
        let received = body.len() as u64 + chunk.len() as u64;
        if received > limit.bytes {
            // `stream` (the response) is dropped on return: the connection closes.
            return Err(Cut::Over {
                received,
                kept: body.len() as u64,
                announced,
            });
        }
        body.extend_from_slice(&chunk);
        on_chunk(received, announced);
    }
    Ok(body)
}

/// Download `update`, verified with `key` (`updater.pub`'s line, as the check had it).
/// `on_progress(received, total)` hears of every chunk as it arrives (`total`: the size the server
/// announced, if it did); the caller thins it out for the window (`task::ProgressGate`). Of `limits`
/// the connect and stall limits hold the transfer, and `max_bytes` is the most a manifest may
/// announce ([`MAX_EXE_BYTES`] in the app; smaller in tests). The transfer is cut as soon as it
/// brings more than the manifest's `size` ([`size_limit`]), or announces more: at that chunk,
/// before a byte past the limit is kept, and the response is dropped, which closes the connection
/// ([`DownloadError::Rejected`]: those bytes are not the release's). Otherwise the request is the
/// plugin's: its headers, proxy and timeout, `Accept: application/octet-stream`, the status check,
/// the announced `Content-Length` for the progress.
///
/// Why not the plugin's own: `Update::download` collects the whole body in memory and its chunk
/// callback cannot stop it; dropping its future between polls is no bound either, since one poll
/// drains whatever the connection has ready (over loopback: the whole 100 MiB a test server
/// announced).
pub async fn download(
    update: &Release,
    key: &str,
    limits: Limits,
    on_progress: &mut (dyn FnMut(u64, Option<u64>) + Send),
) -> Result<Downloaded, DownloadError> {
    let max_bytes = limits.max_bytes;
    let version = Version::parse(&update.version)
        .map_err(|e| DownloadError::Rejected(format!("version {:?}: {e}", update.version)))?;
    if key.trim().is_empty() {
        tracing::warn!(version = %version, "update: no signature key given; not downloading");
        return Err(DownloadError::Rejected(
            "signature: no signature key".to_string(),
        ));
    }
    // Read before downloading: a manifest this app cannot read in full (`sha256` and `size`
    // included) is not one to install from.
    let extras = update.extras.clone().map_err(|why| {
        tracing::debug!(version = %version, "update: not downloading, {why}");
        DownloadError::Rejected(why)
    })?;
    let limit = size_limit(Some(extras.size), max_bytes).map_err(|why| {
        tracing::debug!(
            version = %version,
            ceiling = max_bytes,
            "update: not downloading, {why}"
        );
        DownloadError::Rejected(why)
    })?;
    // Never a plain-http exe (the manifest is not signed; the signature would still hold, but
    // nothing is fetched in the clear).
    download_url_allowed(&update.download_url, limits).map_err(|why| {
        tracing::debug!(version = %version, "update: not downloading, {why}");
        DownloadError::Rejected(why)
    })?;
    // A signature by another key is refused before its exe is fetched: no bytes spent on it. (Not
    // a verification — only the full check after the download accepts anything.)
    let key_id = match super::pubkey::parse(key) {
        super::pubkey::PubKey::Key { key_id, .. } => key_id,
        super::pubkey::PubKey::Missing => String::new(),
        super::pubkey::PubKey::Invalid(why) => {
            tracing::debug!(version = %version, "update: not downloading, the key: {why}");
            return Err(DownloadError::Rejected(format!(
                "signature: the key: {why}"
            )));
        }
    };
    match manifest::signature_key_id(&update.signature) {
        Ok(signed_by) if signed_by == key_id => {
            tracing::debug!(
                key_id,
                key_file = super::pubkey::KEY_FILE,
                "update: the signature names {}'s key",
                super::pubkey::KEY_FILE
            );
        }
        Ok(signed_by) => {
            tracing::debug!(
                version = %version,
                signed_by,
                key_id,
                key_file = super::pubkey::KEY_FILE,
                test_key = super::pubkey::TEST_SIGNING_KEY,
                "update: not downloading, the signature is by another key"
            );
            return Err(DownloadError::Rejected(format!(
                "signature: made with key {signed_by}, not {}'s {key_id}",
                super::pubkey::KEY_FILE
            )));
        }
        Err(why) => {
            tracing::debug!(version = %version, "update: not downloading, {why}");
            return Err(DownloadError::Rejected(format!("signature: {why}")));
        }
    }
    tracing::info!(
        version = %version,
        url = %update.download_url,
        size = extras.size,
        "update: downloading"
    );
    tracing::debug!(
        limit = limit.bytes,
        limit_from = limit.from,
        ceiling = max_bytes,
        "update: the download's byte limit"
    );
    let started = Instant::now();
    // How far it got, for a failure's message.
    let mut received = 0u64;
    let mut next_mark = 25u64;
    let outcome = transfer(update, limits, limit, &mut |so_far, total| {
        received = so_far;
        on_progress(so_far, total);
        // A quarter at a time at `debug`; each chunk is not worth a line.
        if let Some(total) = total.filter(|t| *t > 0) {
            let percent = so_far * 100 / total;
            if percent >= next_mark && next_mark < 100 {
                tracing::debug!(received = so_far, total, percent, "update: downloading");
                next_mark += 25;
            }
        }
    })
    .await;
    let bytes = match outcome {
        Ok(bytes) => bytes,
        Err(Cut::Over {
            received: off_the_wire,
            kept,
            announced,
        }) => {
            let why = format!(
                "the server sent more than the {} bytes allowed ({}): {off_the_wire} received, \
                 {kept} buffered in all, {} announced",
                limit.bytes,
                limit.from,
                announced.map_or_else(|| "none".to_string(), |t| t.to_string()),
            );
            tracing::debug!(
                version = %version,
                received = off_the_wire,
                buffered = kept,
                limit = limit.bytes,
                limit_from = limit.from,
                content_length = announced.map_or_else(|| "-".to_string(), |t| t.to_string()),
                elapsed_ms = started.elapsed().as_millis() as u64,
                "update: download cut, over its byte limit"
            );
            return Err(DownloadError::Rejected(why));
        }
        // How far it got: a stall after the first kilobytes is the freeze's signature.
        Err(Cut::Failed(e)) => {
            return Err(DownloadError::Transfer(format!(
                "{e} (after {received} bytes, {} ms)",
                started.elapsed().as_millis()
            )))
        }
    };
    // A body that ended cleanly before the manifest's size: a transfer cut short (a chunked or
    // close-delimited answer gives no other sign). Its bytes are not the release's — but that
    // says nothing about the manifest entry, so it is not a rejection of it.
    if (bytes.len() as u64) < extras.size {
        tracing::debug!(
            version = %version,
            received = bytes.len(),
            size = extras.size,
            elapsed_ms = started.elapsed().as_millis() as u64,
            "update: the body ended short of the manifest's size; not verified, not held against the entry"
        );
        return Err(DownloadError::Unconfirmed(format!(
            "the body ended after {} of the manifest's {} bytes",
            bytes.len(),
            extras.size
        )));
    }
    tracing::debug!(
        bytes = bytes.len(),
        "update: download complete; verifying the signature"
    );
    // Ed25519 over a BLAKE2b of the whole exe, then its SHA-256 — some 35 MB of hashing: off the
    // async runtime, on its blocking pool, so no worker that drives I/O and timers waits on it.
    let signature = update.signature.clone();
    let announced_version = update.version.clone();
    let key_line = key.to_string();
    let expected = extras.clone();
    let verified = tauri::async_runtime::spawn_blocking(move || {
        verify(bytes, &signature, &key_line, &announced_version, &expected)
    })
    .await;
    let (bytes, sha256) = match verified {
        Ok(Ok(accepted)) => accepted,
        Ok(Err(why)) => return Err(DownloadError::Rejected(why)),
        Err(e) => {
            // The check itself did not finish (it panicked or the runtime is going away): these
            // bytes are not accepted — and nothing is known about them, so nothing is held against
            // the manifest entry.
            tracing::error!(version = %version, "update: the download's check did not finish: {e}");
            return Err(DownloadError::Unconfirmed(format!(
                "the download's check did not finish: {e}"
            )));
        }
    };
    tracing::info!(
        version = %version,
        %sha256,
        size = extras.size,
        "update: download accepted, size and SHA-256 as the manifest says"
    );
    Ok(Downloaded {
        version,
        bytes,
        sha256,
    })
}

/// The downloaded `bytes` checked — the signature with `key`, then its trusted comment against
/// `announced` (the manifest's version), then the manifest's size and SHA-256 — and handed back
/// with their SHA-256 (upper hex); why not, when not. Blocking: hashes the whole exe (run on the
/// blocking pool, [`download`]).
fn verify(
    bytes: Vec<u8>,
    signature: &str,
    key: &str,
    announced: &str,
    extras: &manifest::Extras,
) -> Result<(Vec<u8>, String), String> {
    let started = Instant::now();
    if let Err(why) = manifest::verify_signature(&bytes, signature, key) {
        tracing::debug!(%announced, "update: the signature does not verify: {why}");
        return Err(format!("signature: {why}"));
    }
    tracing::info!(
        version = %announced,
        bytes = bytes.len(),
        verify_ms = started.elapsed().as_millis() as u64,
        "update: downloaded, signature verified"
    );
    let signed = manifest::signed_fields(signature)?;
    match manifest::check_signed(&signed, announced) {
        Ok(()) => tracing::debug!(
            file = signed.file.as_deref().unwrap_or("-"),
            signed_version = signed.version.as_deref().unwrap_or("-"),
            %announced,
            "update: the signature names this release's exe and version"
        ),
        Err(why) => {
            tracing::debug!(
                file = signed.file.as_deref().unwrap_or("-"),
                signed_version = signed.version.as_deref().unwrap_or("-"),
                %announced,
                "update: the signature does not name this release: {why}"
            );
            return Err(why);
        }
    }
    let sha256 = manifest::check_download(&bytes, extras).inspect_err(|why| {
        tracing::debug!(%announced, "update: the download is not the manifest's: {why}");
    })?;
    Ok((bytes, sha256))
}

/// [`download`] `update` from each of `urls` in turn — the same file on each way to the server — until
/// one transfers it; the manifest's own URL is replaced, nothing else. A download whose bytes are not
/// the release's ([`DownloadError::Rejected`]) is never tried elsewhere: the host changes nothing of
/// what is checked, and bytes that fail it are not a path's fault. `key`, `limits`: as
/// [`download`]'s.
pub async fn download_any(
    update: &Release,
    key: &str,
    urls: &[Url],
    limits: Limits,
    on_progress: &mut (dyn FnMut(u64, Option<u64>) + Send),
) -> Result<Downloaded, DownloadError> {
    let mut last: Option<DownloadError> = None;
    for (i, url) in urls.iter().enumerate() {
        let mut attempt = update.clone();
        attempt.download_url = url.clone();
        let started = Instant::now();
        match download(&attempt, key, limits, on_progress).await {
            Ok(downloaded) => {
                if i > 0 {
                    tracing::info!(
                        %url,
                        tried = i + 1,
                        "update: the exe came the other way"
                    );
                }
                return Ok(downloaded);
            }
            // Not tried elsewhere either (as a short body always was): the same file is served
            // both ways.
            Err(e @ (DownloadError::Rejected(_) | DownloadError::Unconfirmed(_))) => return Err(e),
            Err(DownloadError::Transfer(why)) => {
                let elapsed_ms = started.elapsed().as_millis() as u64;
                match urls.get(i + 1) {
                    Some(next) => tracing::warn!(
                        %url,
                        %next,
                        elapsed_ms,
                        "update: the download did not get through this way ({why}); trying the \
                         other"
                    ),
                    None => tracing::debug!(
                        %url,
                        elapsed_ms,
                        "update: the download did not get through this way either ({why})"
                    ),
                }
                last = Some(DownloadError::Transfer(format!("{url}: {why}")));
            }
        }
    }
    Err(last.unwrap_or_else(|| DownloadError::Transfer("no address to download from".into())))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The live release's size (0.7.1, from its `latest.json`).
    const LIVE_EXE: u64 = 35_435_008;

    #[test]
    fn the_ceiling_is_well_above_the_real_exe() {
        const { assert!(MAX_EXE_BYTES >= 4 * LIVE_EXE) };
        assert_eq!(LIMITS.max_bytes, MAX_EXE_BYTES);
        assert_eq!(
            size_limit(Some(LIVE_EXE), MAX_EXE_BYTES),
            Ok(SizeLimit {
                bytes: LIVE_EXE,
                from: "manifest size"
            })
        );
    }

    #[test]
    fn the_exe_comes_over_https_only() {
        // The app never allows plain http.
        const { assert!(!LIMITS.plain_http_loopback) };
        let tests = Limits {
            plain_http_loopback: true,
            ..LIMITS
        };
        let url = |u: &str| Url::parse(u).unwrap();
        for u in [
            "https://api.afklink.app/download/AFKLink-0.7.1.exe",
            "https://api.ru.afklink.app/download/AFKLink-0.7.1.exe",
        ] {
            assert_eq!(download_url_allowed(&url(u), LIMITS), Ok(()), "{u}");
            assert_eq!(download_url_allowed(&url(u), tests), Ok(()), "{u}");
        }
        for u in [
            "http://api.afklink.app/download/AFKLink-0.7.1.exe",
            "http://example.com/x.exe",
            "ftp://api.afklink.app/x.exe",
            "file:///C:/x.exe",
            "http://127.0.0.1:8080/x.exe",
            "http://localhost/x.exe",
        ] {
            assert!(download_url_allowed(&url(u), LIMITS).is_err(), "{u}");
        }
        // Plain http to this machine only with the tests' flag, and to no other host even then.
        for u in [
            "http://127.0.0.1:8080/x.exe",
            "http://127.0.0.2/x.exe",
            "http://localhost:1/x.exe",
            "http://[::1]:1/x.exe",
        ] {
            assert_eq!(download_url_allowed(&url(u), tests), Ok(()), "{u}");
        }
        for u in [
            "http://example.com/x.exe",
            "http://10.0.0.1/x.exe",
            "http://localhost.example.com/x.exe",
            "http://127.0.0.1.nip.io/x.exe",
        ] {
            assert!(download_url_allowed(&url(u), tests).is_err(), "{u}");
        }
    }

    /// The live `latest.json` of 0.7.1 (868 bytes), shared with `tests/updater_http.rs`.
    const LIVE_0_7_1: &[u8] = include_bytes!("../../tests/support/latest-0.7.1.json");
    const UA: &str = "AFKLink/0.7.0 (release)";

    fn live() -> manifest::Manifest {
        manifest::parse(LIVE_0_7_1).unwrap()
    }

    #[test]
    fn the_manifest_cap_is_well_above_the_live_manifest() {
        assert_eq!(LIVE_0_7_1.len(), 868);
        const { assert!(MAX_MANIFEST_BYTES >= 64 * 868) };
        assert_eq!(LIMITS.check_total, CHECK_TIMEOUT);
        const { assert!(!LIMITS.no_proxy) };
    }

    /// The live manifest offers 0.7.1 to an older build, exactly as the plugin read it, and nothing
    /// to 0.7.1 itself or to a newer build: never a downgrade.
    #[test]
    fn the_live_manifest_offers_its_release_to_older_builds_only() {
        let m = live();
        let (remote, release) = release_of(&m, &Version::new(0, 7, 0), UA).unwrap();
        assert_eq!(remote, Version::new(0, 7, 1));
        let r = release.expect("0.7.1 is newer than 0.7.0");
        assert_eq!(r.version, "0.7.1");
        assert_eq!(
            r.download_url.as_str(),
            "https://api.afklink.app/download/AFKLink-0.7.1.exe"
        );
        assert!(r.signature.starts_with("dW50cnVzdGVkIGNvbW1lbnQ6"));
        assert_eq!(
            r.extras,
            Ok(manifest::Extras {
                sha256: "74BF874FDC5E5A9EC6156CDB828477B0BCFD7589ABD7A4AD2AB3199DCACA1A16".into(),
                size: 35_435_008,
            })
        );
        assert_eq!(r.user_agent, UA);
        assert_eq!(r.identity().len(), 64);
        // The same entry read twice is the same release.
        let again = release_of(&live(), &Version::new(0, 6, 9), UA)
            .unwrap()
            .1
            .unwrap();
        assert_eq!(again.identity(), r.identity());
        for current in [
            Version::new(0, 7, 1),
            Version::new(0, 7, 2),
            Version::new(1, 0, 0),
        ] {
            let (remote, release) = release_of(&m, &current, UA).unwrap();
            assert_eq!(remote, Version::new(0, 7, 1));
            assert!(release.is_none(), "{current}: no downgrade, no reinstall");
        }
    }

    /// No entry for this build's target fails the check whether the version is newer or not (as the
    /// plugin's `get_urls` did); the flat form is found and refused at the download (no sha256).
    #[test]
    fn a_manifest_without_this_target_fails_and_the_flat_form_is_refused_at_the_download() {
        let other = manifest::parse(
            br#"{"version":"0.9.0","platforms":{"windows-aarch64":{"url":"https://x/y.exe","signature":"s"}}}"#,
        )
        .unwrap();
        for current in [Version::new(0, 1, 0), Version::new(1, 0, 0)] {
            let why = release_of(&other, &current, UA).unwrap_err();
            assert!(
                why.contains("no windows-x86_64 entry") && why.contains("windows-aarch64"),
                "{why}"
            );
        }
        let flat =
            manifest::parse(br#"{"version":"0.9.0","url":"https://x/y.exe","signature":"s"}"#)
                .unwrap();
        let r = release_of(&flat, &Version::new(0, 1, 0), UA)
            .unwrap()
            .1
            .unwrap();
        assert!(r.extras.unwrap_err().contains("no platforms"));
        let no_sig = manifest::parse(br#"{"version":"0.9.0","url":"https://x/y.exe"}"#).unwrap();
        assert!(release_of(&no_sig, &Version::new(0, 1, 0), UA).is_err());
    }

    /// The manifest, and every redirect of it, only from our own two hosts over https (this machine
    /// too with the tests' allowance); the exe from any https host.
    #[test]
    fn the_manifest_comes_from_our_hosts_only() {
        let url = |u: &str| Url::parse(u).unwrap();
        let tests = Limits {
            plain_http_loopback: true,
            ..LIMITS
        };
        for u in [
            "https://api.afklink.app/download/latest.json",
            "https://api.ru.afklink.app/download/latest.json",
            "https://API.afklink.app:443/x",
        ] {
            assert_eq!(manifest_url_allowed(&url(u), LIMITS), Ok(()), "{u}");
        }
        for (u, why) in [
            (
                "https://evil.test/download/latest.json",
                "is not api.afklink.app",
            ),
            (
                "https://api.afklink.app.evil.test/latest.json",
                "is not api.afklink.app",
            ),
            (
                "https://cdn.afklink.app/download/latest.json",
                "is not api.afklink.app",
            ),
            (
                "http://api.afklink.app/download/latest.json",
                "is not https",
            ),
            ("https://api.afklink.app:8443/latest.json", "port 8443"),
            ("https://u:p@api.afklink.app/latest.json", "credentials"),
            ("https://192.0.2.10/latest.json", "IP address"),
            ("http://127.0.0.1:8080/latest.json", "is not https"),
            ("https://127.0.0.1:8080/latest.json", "IP address"),
        ] {
            let refused = manifest_url_allowed(&url(u), LIMITS).unwrap_err();
            assert!(refused.contains(why), "{u}: {refused}");
        }
        // The tests' allowance: this machine, and still nothing else.
        assert_eq!(
            manifest_url_allowed(&url("http://127.0.0.1:8080/latest.json"), tests),
            Ok(())
        );
        assert!(manifest_url_allowed(&url("https://evil.test/latest.json"), tests).is_err());
        assert!(manifest_url_allowed(&url("http://example.invalid/latest.json"), tests).is_err());
        // The exe: any https host (the signature is what is trusted).
        assert_eq!(
            download_url_allowed(&url("https://cdn.example.com/AFKLink-0.7.1.exe"), LIMITS),
            Ok(())
        );
    }

    /// An address the server named (a redirect's `Location`) reaches a log line or an error
    /// bounded: at most 2048 characters of it, quoted; a long host name too.
    #[test]
    fn addresses_in_logs_and_errors_are_bounded() {
        let long = Url::parse(&format!("https://cdn.example.com/{}", "a".repeat(10_000))).unwrap();
        let s = shown_url(&long);
        assert!(
            s.chars().count() <= MAX_URL_CHARS + 3 && s.ends_with('…'),
            "{}",
            s.len()
        );
        let plain = Url::parse(&format!("http://example.com/{}", "a".repeat(10_000))).unwrap();
        let why = download_url_allowed(&plain, LIMITS).unwrap_err();
        assert!(why.chars().count() < MAX_URL_CHARS + 100, "{}", why.len());
        let why = manifest_url_allowed(&long, LIMITS).unwrap_err();
        assert!(why.chars().count() < MAX_URL_CHARS + 200, "{}", why.len());
        let host = format!(
            "https://{}.example.com/x",
            vec!["a".repeat(60); 20].join(".")
        );
        let why = our_api_host(&Url::parse(&host).unwrap()).unwrap_err();
        assert!(why.chars().count() < 340, "{}", why.len());
    }

    /// A platform key the server chose never reaches the error raw: escaped, cut at 64
    /// characters, eight keys at most.
    #[test]
    fn platform_keys_in_an_error_are_escaped_and_bounded() {
        let mut platforms = serde_json::Map::new();
        let entry = serde_json::json!({ "url": "https://x/y.exe", "signature": "s" });
        platforms.insert(
            "a\n2026-10-26T00:00:00Z  INFO afklink_app_lib: fake line".into(),
            entry.clone(),
        );
        platforms.insert(format!("b{}", "x".repeat(500)), entry.clone());
        for i in 0..20 {
            platforms.insert(format!("c{i:02}"), entry.clone());
        }
        let body = serde_json::json!({ "version": "0.9.0", "platforms": platforms });
        let m = manifest::parse(body.to_string().as_bytes()).unwrap();
        let why = release_of(&m, &Version::new(0, 1, 0), UA).unwrap_err();
        assert!(!why.contains('\n') && why.contains("\\n"), "{why}");
        assert!(
            why.contains("22 platforms") && why.ends_with(", …)"),
            "{why}"
        );
        assert!(!why.contains(&"x".repeat(65)), "{why}");
        assert!(!why.contains("c07"), "eight keys at most: {why}");
        // An exe address past 2048 characters is refused, so no log line carries one.
        let long = format!("https://api.afklink.app/{}", "a".repeat(3000));
        let body = serde_json::json!({ "version": "0.9.0", "platforms": {
            "windows-x86_64": { "url": long, "signature": "s" } } });
        let m = manifest::parse(body.to_string().as_bytes()).unwrap();
        let why = release_of(&m, &Version::new(0, 1, 0), UA).unwrap_err();
        assert!(why.contains("more than 2048"), "{why}");
    }

    #[test]
    fn the_limit_is_the_manifest_size_else_the_ceiling() {
        assert_eq!(
            size_limit(None, 1000),
            Ok(SizeLimit {
                bytes: 1000,
                from: "ceiling"
            })
        );
        assert_eq!(size_limit(Some(1000), 1000).map(|l| l.bytes), Ok(1000));
        assert_eq!(size_limit(Some(0), 1000).map(|l| l.bytes), Ok(0));
        let why = size_limit(Some(1001), 1000).unwrap_err();
        assert!(why.contains("1001") && why.contains("1000"), "{why}");
    }
}
