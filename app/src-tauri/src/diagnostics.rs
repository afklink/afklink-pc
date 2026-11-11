//! «Отправить логи» (Settings → Diagnostics): the owner's logs, sent to the developer on the
//! owner's press — and the one exception, the automatic report
//! («автоотчёт», [`auto`]): after a crash, an outage, a failed session or a hang, a
//! short tail of the log goes by itself, at most three a day, each under 200 KB, never with the
//! flight recorder, and never when the log is off.
//!
//! # What happens on the press
//!
//! 1. [`send_logs`], from the main window only, one report at a time. The comment is cleaned to the
//!    contract's rule ([`clean_comment`]); the log gets its length, never its text.
//! 2. What the app knows is gathered on the command's task: the config, the sessions (the live ones,
//!    then the most recent — [`Diagnostics::track_sessions`] keeps them), the build, the log level,
//!    the displays, and a snapshot of the flight recorder (`flight_recorder`).
//! 3. Off the UI thread (`spawn_blocking`): what is still queued for the log files is written
//!    first, then `system.json` ([`system`]) and the zip ([`package`]) — the system log, the last
//!    five sessions' files, the flight recorder — under the report's cap ([`manual_cap`]: 24 MiB
//!    for a PC bound to someone, under 2 MiB otherwise), the oldest sessions dropped first.
//! 4. The metadata (build, time, comment, files, sessions, Windows) goes into a header, and the
//!    request is signed with the device key and sent ([`upload`]) to the signaling server's host.
//!    A `413` to a report packed to the full cap — the server sees this PC bound to nobody — packs
//!    it once more to the small cap and sends that ([`send_within_caps`]).
//! 5. The window gets `sent` (with the report id, for its tooltip), `too_often` (the server's budget
//!    of six an hour, with `Retry-After`) or `failed` — why, in the log.
//!
//! `identity.json`, the device's private key, never goes in: the report reads only its own list of
//! files (`package`), and signs through `afklink_core::Identity`, which never hands the key out.

use std::collections::VecDeque;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use afklink_core::build_info::BuildInfo;
use afklink_core::logging::{default_log_level, RELEASE_PHASE};
use afklink_core::{AgentControl, AgentEvent, Identity};
use afklink_i18n::Locale;
use afklink_protocol::diagnostics::{is_uuid, limits, AgentBuild, AgentDiagnosticsMeta};
use bytes::Bytes;
use serde::Serialize;
use serde_json::{json, Map, Value};
use tauri::{AppHandle, Manager, WebviewWindow};
use tokio::sync::broadcast;

pub(crate) mod auto;
mod package;
mod system;
mod upload;
mod zip;

/// Sessions remembered for a report: as many as the metadata may name.
const RECENT_SESSIONS: usize = limits::SESSION_IDS;

/// How long packing waits for the log writer to put what it has queued on disk, so the files it
/// reads end at the press, not where the writer thread happened to be.
const FLUSH_WAIT: std::time::Duration = std::time::Duration::from_secs(2);

/// The report's state in the app: the key to sign with, the sessions seen, the one-at-a-time gate.
pub(crate) struct Diagnostics {
    identity: Arc<Identity>,
    /// The way to the server the signaling socket uses — the report goes that way first, the other
    /// second (`afklink_core::entry`, [`upload::send_any`]).
    entry: Arc<afklink_core::entry::Entry>,
    /// Session ids seen this run, oldest first, at most [`RECENT_SESSIONS`].
    recent_sessions: Arc<Mutex<VecDeque<String>>>,
    /// A report is being packed or sent.
    busy: AtomicBool,
    /// When the app started, for `app_uptime_s`.
    started: Instant,
}

impl Diagnostics {
    pub(crate) fn new(identity: Arc<Identity>, entry: Arc<afklink_core::entry::Entry>) -> Self {
        Self {
            identity,
            entry,
            recent_sessions: Arc::default(),
            busy: AtomicBool::new(false),
            started: Instant::now(),
        }
    }

    /// Remember every session that starts or ends, from `events` — subscribed before the agent
    /// runs, so the first session is not missed. The live ones are read from the agent's state at
    /// the press; these are the ones that were.
    pub(crate) fn track_sessions(&self, mut events: broadcast::Receiver<AgentEvent>) {
        let recent = Arc::clone(&self.recent_sessions);
        tauri::async_runtime::spawn(async move {
            loop {
                match events.recv().await {
                    Ok(
                        AgentEvent::SessionStarted { session_id, .. }
                        | AgentEvent::SessionEnded { session_id, .. },
                    ) => remember(&recent, session_id),
                    Ok(_) => {}
                    Err(broadcast::error::RecvError::Lagged(missed)) => tracing::debug!(
                        missed,
                        "diagnostics: agent events missed; a session may be missing from a report"
                    ),
                    Err(broadcast::error::RecvError::Closed) => {
                        tracing::debug!(
                            "diagnostics: the agent's events ended; sessions are no longer tracked"
                        );
                        break;
                    }
                }
            }
        });
    }
}

/// Put `id` last (the newest), once, keeping [`RECENT_SESSIONS`].
fn remember(recent: &Mutex<VecDeque<String>>, id: String) {
    let mut recent = afklink_core::lock(recent);
    recent.retain(|known| *known != id);
    recent.push_back(id);
    while recent.len() > RECENT_SESSIONS {
        recent.pop_front();
    }
}

/// The metadata's `session_ids`: the session the report is about first (`focus`, a journal entry's
/// «Отправить логи»), then the live sessions, then the most recent, each once, only ids the server
/// takes (UUIDs), at most [`limits::SESSION_IDS`].
fn session_ids(focus: Option<&str>, live: &[String], recent: &VecDeque<String>) -> Vec<String> {
    let mut ids: Vec<String> = Vec::new();
    let focus = focus.map(str::to_string);
    for id in focus.iter().chain(live.iter()).chain(recent.iter().rev()) {
        if ids.len() == limits::SESSION_IDS {
            break;
        }
        if !is_uuid(id) {
            tracing::debug!(id, "diagnostics: a session id that is not a UUID, left out");
            continue;
        }
        if !ids.contains(id) {
            ids.push(id.clone());
        }
    }
    ids
}

/// «Что случилось?» as the contract takes it: control characters other than tab and line breaks
/// removed, trimmed, cut to [`limits::COMMENT_CHARS`] characters; `None` when nothing is left. The
/// window already limits the field; this is the rule, whoever calls.
pub(crate) fn clean_comment(raw: &str) -> Option<String> {
    let kept: String = raw
        .chars()
        .filter(|c| !c.is_control() || matches!(c, '\t' | '\n' | '\r'))
        .collect();
    let cut: String = kept.trim().chars().take(limits::COMMENT_CHARS).collect();
    let cut = cut.trim_end();
    (!cut.is_empty()).then(|| cut.to_string())
}

/// What the window gets back.
#[derive(Serialize, Debug, PartialEq, Eq)]
pub(crate) struct SendLogsDto {
    /// `"sent"`, `"too_often"` or `"failed"`.
    outcome: &'static str,
    /// The server's id for the report, when sent.
    report_id: Option<String>,
    /// With `too_often`: when the server says to try again, seconds.
    retry_after_s: Option<u64>,
    /// With `failed`: `network`, `clock_skew`, `too_large`, `unavailable`, `refused`, `signing`,
    /// `packing` or `address` (no usable server address) — for the window's console; the owner sees
    /// «Не отправлено».
    failure: Option<&'static str>,
}

impl SendLogsDto {
    fn failed(kind: &'static str) -> Self {
        Self {
            outcome: "failed",
            report_id: None,
            retry_after_s: None,
            failure: Some(kind),
        }
    }
}

impl From<&upload::Outcome> for SendLogsDto {
    fn from(outcome: &upload::Outcome) -> Self {
        match outcome {
            upload::Outcome::Sent { receipt } => Self {
                outcome: "sent",
                report_id: receipt.as_ref().map(|r| r.report_id.clone()),
                retry_after_s: None,
                failure: None,
            },
            upload::Outcome::TooOften { retry_after_s } => Self {
                outcome: "too_often",
                report_id: None,
                retry_after_s: *retry_after_s,
                failure: None,
            },
            upload::Outcome::Failed(why) => Self::failed(why.kind()),
        }
    }
}

/// Holds [`Diagnostics::busy`] for one report.
struct Busy<'a>(&'a AtomicBool);

impl<'a> Busy<'a> {
    fn take(flag: &'a AtomicBool) -> Option<Self> {
        flag.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .ok()
            .map(|_| Self(flag))
    }
}

impl Drop for Busy<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

/// «Отправить»: pack the logs and send them, signed by this device. Answers with how it ended; an
/// `Err` only when nothing was started (another window, or a report already on its way).
///
/// `session_id`: the report is about that session — «Отправить логи» on its entry in the journal —
/// so its log goes in first, ahead of the newest, and its id leads the metadata's sessions.
#[tauri::command]
pub(crate) async fn send_logs(
    app: AppHandle,
    window: WebviewWindow,
    comment: Option<String>,
    session_id: Option<String>,
) -> Result<SendLogsDto, String> {
    if window.label() != "main" {
        tracing::warn!(
            window = window.label(),
            "diagnostics: send_logs from a window other than the main one; refused"
        );
        return Err("reports are sent from the main window only".into());
    }
    let diagnostics = app.state::<Diagnostics>();
    let Some(_busy) = Busy::take(&diagnostics.busy) else {
        tracing::info!("diagnostics: «Отправить» pressed while a report is on its way; ignored");
        return Err("a report is already being sent".into());
    };
    let started = Instant::now();
    let comment = clean_comment(comment.as_deref().unwrap_or(""));
    // Only a session id that could be one: it ends up in a file name match and the metadata.
    let focus = session_id.filter(|id| {
        let ok = is_uuid(id);
        if !ok {
            tracing::debug!(
                id = %id.chars().take(64).collect::<String>(),
                "diagnostics: the session asked for is not a UUID; the report has no session first"
            );
        }
        ok
    });
    tracing::info!(
        comment_chars = comment.as_ref().map_or(0, |c| c.chars().count()),
        session = focus.as_deref().unwrap_or("-"),
        "diagnostics: owner pressed «Отправить» (send logs){}",
        if focus.is_some() {
            ", from a journal entry: that session's log first"
        } else {
            ""
        }
    );
    let dto = report(&app, &window, &diagnostics, comment, focus).await;
    tracing::info!(
        outcome = dto.outcome,
        failure = dto.failure.unwrap_or("-"),
        report_id = dto.report_id.as_deref().unwrap_or("-"),
        retry_after_s = ?dto.retry_after_s,
        elapsed_ms = started.elapsed().as_millis() as u64,
        "diagnostics: «Отправить логи» finished"
    );
    Ok(dto)
}

/// Everything after the gate: gather, pack, sign, send. `focus`: the session the report is about,
/// whose log goes first.
async fn report(
    app: &AppHandle,
    window: &WebviewWindow,
    diagnostics: &Diagnostics,
    comment: Option<String>,
    focus: Option<String>,
) -> SendLogsDto {
    let control = app.state::<AgentControl>();
    let ConfigSnapshot {
        device_id,
        server_url,
        path: config_path,
        in_memory: config_in_memory,
    } = config_snapshot(&control);
    let live = live_sessions(&control);
    // How much this report may weigh: the server takes far less from a PC bound to nobody.
    let (heard, bound_now) = {
        let state = afklink_core::lock(&control.state);
        (state.bindings_known, state.bindings.len())
    };
    let last_list = app
        .try_state::<crate::access_cache::AccessCache>()
        .and_then(|cache| cache.last_list())
        .map(|list| list.len());
    let cap = manual_cap(heard, bound_now, last_list);
    tracing::debug!(
        heard,
        bound_now,
        last_list = ?last_list,
        cap = cap.bytes,
        why = cap.why,
        "diagnostics: the report's cap, from whether this PC is bound to anyone"
    );
    let session_ids = session_ids(
        focus.as_deref(),
        &live,
        &afklink_core::lock(&diagnostics.recent_sessions),
    );
    let endpoint = match upload::endpoint(&server_url) {
        Ok(endpoint) => endpoint,
        Err(e) => {
            tracing::warn!("diagnostics: no address to send the report to: {e}");
            return SendLogsDto::failed("address");
        }
    };
    let build = app.state::<BuildInfo>().inner().clone();
    let logging = app.state::<crate::Logging>();
    let files = Arc::clone(logging.files());
    let (recent_debug, recorder) = logging.recorder().snapshot(Instant::now());
    let recording = logging.recording();
    let log = logging.dto();
    let app_language = app.state::<Locale>().tag().to_string();
    let displays = displays(window);
    let uptime_s = diagnostics.started.elapsed().as_secs();
    let now_ms = upload::now_ms();
    tracing::debug!(
        live_sessions = live.len(),
        session_ids = session_ids.len(),
        recorder_lines = recorder.lines,
        recorder_bytes = recorder.bytes,
        recorder_span_s = recorder.span.map_or(0, |d| d.as_secs()),
        recording,
        %endpoint,
        "diagnostics: gathered what the app knows"
    );

    let mut about = Map::new();
    about.insert(
        "log".into(),
        json!({
            "level": log.level,
            "choice": log.choice,
            "default_level": log.default_level,
            "env_override": log.env_override,
        }),
    );
    about.insert(
        "recent_debug".into(),
        json!({
            "recording": recording,
            "filter": crate::flight_recorder::RECORDING.filter_directives(),
            "window_s": crate::flight_recorder::WINDOW.as_secs(),
            "max_bytes": crate::flight_recorder::MAX_BYTES,
            "lines": recorder.lines,
            "bytes": recorder.bytes,
            "span_s": recorder.span.map(|d| d.as_secs()),
            "evicted_by_age": recorder.evicted_by_age,
            "evicted_by_size": recorder.evicted_by_size,
        }),
    );
    about.insert("session_ids".into(), json!(session_ids));
    about.insert("app_uptime_s".into(), json!(uptime_s));
    // Which way to the server this PC uses now — the configured address or the RU entry — for whoever
    // reads the report (`afklink_core::entry`; why it moved is in the system log's `entry:` lines).
    about.insert("entry".into(), entry_json(&diagnostics.entry));
    let endpoint_text = endpoint.to_string();
    let build_for_system = build.clone();
    let gathered = tauri::async_runtime::spawn_blocking(move || {
        // The report reads the files: what is still queued for them goes to disk first.
        let flush_started = Instant::now();
        let flushed = files.flush(FLUSH_WAIT);
        tracing::debug!(
            flushed,
            elapsed_ms = flush_started.elapsed().as_millis() as u64,
            wait_ms = FLUSH_WAIT.as_millis() as u64,
            "diagnostics: log files flushed before they are read (false: none is open, or the \
             writer took longer than the wait and the newest lines may be missing)"
        );
        let (system, os) = system::collect(system::Known {
            displays,
            app_language,
            app_uptime_s: uptime_s,
        });
        let generated = vec![
            (
                "build.json".to_string(),
                pretty(&build_json(&build_for_system, &endpoint_text)),
            ),
            ("system.json".to_string(), pretty(&system)),
        ];
        (generated, os)
    })
    .await;
    let (generated, os) = match gathered {
        Ok(gathered) => gathered,
        Err(e) => {
            tracing::warn!("diagnostics: the gathering task failed: {e}");
            return SendLogsDto::failed("packing");
        }
    };
    let client = match upload::client(&build.user_agent()) {
        Ok(client) => client,
        Err(e) => {
            tracing::warn!("diagnostics: {e}; not sent");
            return SendLogsDto::failed("network");
        }
    };
    let endpoints = endpoints_in_order(&diagnostics.entry, &endpoint);
    let parts = ReportParts {
        device_id,
        endpoint,
        config: package::ConfigSource {
            path: config_path,
            in_memory: config_in_memory,
        },
        generated,
        recent_debug,
        now_ms,
        about,
        focus,
        comment,
        session_ids,
        os,
        build,
    };
    let identity: &Identity = &diagnostics.identity;
    let outcome = send_within_caps(cap, |cap| {
        pack_and_send(&parts, cap, &client, &endpoints, identity)
    })
    .await;
    match outcome {
        Ok(outcome) => SendLogsDto::from(&outcome),
        Err(dto) => dto,
    }
}

/// What a report is packed from, gathered once: packing again at a smaller cap reuses it.
struct ReportParts {
    device_id: String,
    endpoint: reqwest::Url,
    config: package::ConfigSource,
    /// `build.json` and `system.json`.
    generated: Vec<(String, Vec<u8>)>,
    /// The flight recorder's snapshot.
    recent_debug: Vec<u8>,
    now_ms: u64,
    /// `report.json`'s extras, without `cap` (each packing adds its own).
    about: Map<String, Value>,
    focus: Option<String>,
    comment: Option<String>,
    session_ids: Vec<String>,
    os: Option<String>,
    build: BuildInfo,
}

/// The cap a manual report is packed to once more after the server refused its size (`413`), and
/// why — `None`: not packed again. Only a report packed to the full cap: the server holds a PC it
/// sees bound to nobody to the small one (`package::UNBOUND_CAP`), and this PC's own idea of its
/// bindings ([`manual_cap`]) can be behind the server's — the last person unbound a moment ago, or
/// the list remembered from the last run. A report already at the small cap was refused for
/// something packing smaller does not fix.
fn repack_cap(outcome: &upload::Outcome, cap: ManualCap) -> Option<ManualCap> {
    (matches!(outcome, upload::Outcome::Failed(upload::Failure::TooLarge))
        && cap.bytes > package::UNBOUND_CAP)
        .then_some(ManualCap {
            bytes: package::UNBOUND_CAP,
            why: "too_large_at_full_cap",
        })
}

/// Packs and sends a manual report at `first`; when the server refuses its size and it was packed
/// to the full cap ([`repack_cap`]), packs and sends it once more at the small one. `attempt` packs
/// at the cap it is given and sends; an `Err` is the window's answer, ending here.
async fn send_within_caps<F, Fut>(
    first: ManualCap,
    mut attempt: F,
) -> Result<upload::Outcome, SendLogsDto>
where
    F: FnMut(ManualCap) -> Fut,
    Fut: std::future::Future<Output = Result<upload::Outcome, SendLogsDto>>,
{
    let outcome = attempt(first).await?;
    let Some(smaller) = repack_cap(&outcome, first) else {
        return Ok(outcome);
    };
    tracing::warn!(
        cap = first.bytes,
        why = first.why,
        repack_cap = smaller.bytes,
        "diagnostics: the server refused the report's size (413) at the full cap: it holds this PC \
         to the small cap of a PC bound to nobody (its list of people differs from this PC's); \
         packing once more at the small cap, the oldest log parts left out"
    );
    let again = attempt(smaller).await?;
    let dto = SendLogsDto::from(&again);
    tracing::info!(
        outcome = dto.outcome,
        failure = dto.failure.unwrap_or("-"),
        "diagnostics: the report packed at the small cap after the 413 has its answer"
    );
    Ok(again)
}

/// Packs `parts` to `cap` off the UI thread, signs and sends it: one attempt of
/// [`send_within_caps`].
async fn pack_and_send(
    parts: &ReportParts,
    cap: ManualCap,
    client: &reqwest::Client,
    endpoints: &[reqwest::Url],
    identity: &Identity,
) -> Result<upload::Outcome, SendLogsDto> {
    let mut about = parts.about.clone();
    about.insert("cap".into(), json!({ "bytes": cap.bytes, "why": cap.why }));
    let config = parts.config.clone();
    let generated = parts.generated.clone();
    let recent_debug = parts.recent_debug.clone();
    let now_unix_ms = parts.now_ms;
    let first_session = parts.focus.clone();
    // Off the runtime: the logs folder and the files are read from disk.
    let packed = tauri::async_runtime::spawn_blocking(move || {
        package::build(package::Inputs {
            logs_dir: crate::logs_dir()
                .inspect_err(|e| tracing::warn!("diagnostics: no logs folder: {e}"))
                .ok(),
            config,
            generated,
            recent_debug: Some(recent_debug),
            now_unix_ms,
            cap: cap.bytes,
            about,
            first_session,
        })
    })
    .await;
    let package = match packed {
        Ok(Ok(package)) => package,
        Ok(Err(e)) => {
            tracing::warn!("diagnostics: the report could not be packed: {e}");
            return Err(SendLogsDto::failed("packing"));
        }
        Err(e) => {
            tracing::warn!("diagnostics: the packing task failed: {e}");
            return Err(SendLogsDto::failed("packing"));
        }
    };

    let meta = AgentDiagnosticsMeta {
        build: agent_build(&parts.build),
        client_time: parts.now_ms,
        comment: parts.comment.clone(),
        files: package.files.clone(),
        session_ids: (!parts.session_ids.is_empty()).then(|| parts.session_ids.clone()),
        os: parts.os.clone(),
        // The owner pressed «Отправить»: not an automatic report.
        auto: None,
    };
    let meta_header = match upload::meta_header(&meta) {
        Ok(header) => header,
        Err(e) => {
            tracing::warn!("diagnostics: {e}; not sent");
            return Err(SendLogsDto::failed("packing"));
        }
    };
    let prepared = upload::Prepared {
        endpoint: parts.endpoint.clone(),
        device: parts.device_id.clone(),
        content_sha256: upload::sha256_hex(&package.zip),
        body: Bytes::from(package.zip),
        meta_header,
    };
    tracing::debug!(
        zip_bytes = prepared.body.len(),
        raw_bytes = package.raw_bytes,
        cap = cap.bytes,
        cap_why = cap.why,
        files = meta.files.len(),
        left_out = package.dropped.len(),
        unreadable = package.unreadable.len(),
        meta_chars = prepared.meta_header.len(),
        has_comment = meta.comment.is_some(),
        "diagnostics: report ready to send"
    );
    Ok(upload::send_any(
        client,
        &prepared,
        endpoints,
        identity,
        upload::now_ms,
        upload::random_nonce,
        upload::STALL,
        // The owner's report: on no answer, the other way, as always.
        upload::AfterBody::FallBack,
    )
    .await)
}

/// What a report needs of the config, copied under its lock and the lock let go at once.
struct ConfigSnapshot {
    device_id: String,
    server_url: String,
    /// The file the app loaded, read again (whitelisted) by the packer.
    path: Option<std::path::PathBuf>,
    /// The config in memory, for when the file cannot be read.
    in_memory: Value,
}

fn config_snapshot(control: &AgentControl) -> ConfigSnapshot {
    let c = afklink_core::lock(&control.config);
    ConfigSnapshot {
        device_id: c.device_id.clone(),
        server_url: c.server_url.clone(),
        path: c.path().map(Path::to_path_buf),
        in_memory: serde_json::to_value(&*c).unwrap_or_else(|e| {
            tracing::warn!("diagnostics: the config in memory not serialized: {e}");
            Value::Null
        }),
    }
}

/// A manual report's cap ([`manual_cap`]): the most its zip may weigh, and why that much.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ManualCap {
    bytes: u64,
    why: &'static str,
}

/// A manual report's cap. The server holds a PC bound to nobody to far less than one with people on
/// it (`package::UNBOUND_CAP` against `package::CAP`), and a person who cannot pair yet sends logs
/// exactly then: such a report is packed to the small cap, its oldest log parts left out first.
/// `heard`: the server's list came this run (`bindings_known`), `bound_now` people on it.
/// `last_list`: the people on the list the server sent last run (the access cache), `None` when
/// none was kept or this is a new device. Bound by either list: the full cap; otherwise — nobody, or
/// not known — the small one, which the server takes from any PC.
fn manual_cap(heard: bool, bound_now: usize, last_list: Option<usize>) -> ManualCap {
    let (bytes, why) = match (heard, last_list) {
        (true, _) if bound_now > 0 => (package::CAP, "bound"),
        (true, _) => (package::UNBOUND_CAP, "bound_to_nobody"),
        (false, Some(n)) if n > 0 => (package::CAP, "bound_last_run"),
        (false, Some(_)) => (package::UNBOUND_CAP, "bound_to_nobody_last_run"),
        (false, None) => (package::UNBOUND_CAP, "bindings_unknown"),
    };
    ManualCap { bytes, why }
}

/// The sessions live now, from the agent's state (its lock held only to copy the ids).
fn live_sessions(control: &AgentControl) -> Vec<String> {
    afklink_core::lock(&control.state)
        .sessions
        .iter()
        .map(|s| s.session_id.clone())
        .collect()
}

/// `report.json`'s `entry`: which way to the server this PC uses now.
fn entry_json(entry: &afklink_core::entry::Entry) -> Value {
    json!({
        "preferred": entry.preferred().as_str(),
        "primary": entry.url_of(afklink_core::entry::Endpoint::Primary),
        "ru": entry
            .has_alternative()
            .then(|| entry.url_of(afklink_core::entry::Endpoint::Ru)),
    })
}

/// Where a report for `endpoint` goes, in order: the way the signaling socket uses first, the other
/// second, when the address has one (`afklink_core::entry`).
fn endpoints_in_order(
    entry: &afklink_core::entry::Entry,
    endpoint: &reqwest::Url,
) -> Vec<reqwest::Url> {
    let endpoints: Vec<reqwest::Url> = entry
        .http_order(endpoint.as_str())
        .into_iter()
        .filter_map(|(way, url)| match reqwest::Url::parse(&url) {
            Ok(parsed) => Some(parsed),
            Err(e) => {
                tracing::warn!(
                    way = way.as_str(),
                    %url,
                    "diagnostics: an address that is not a URL ({e}); skipped"
                );
                None
            }
        })
        .collect();
    tracing::debug!(
        preferred = entry.preferred().as_str(),
        endpoints = %endpoints.iter().map(reqwest::Url::as_str).collect::<Vec<_>>().join(" "),
        "diagnostics: where the report goes, in order"
    );
    endpoints
}

/// The displays as Tauri sees them, through the window (a request to the event loop, answered
/// while this task waits: the command does not run on the UI thread).
fn displays(window: &WebviewWindow) -> Result<Vec<system::Display>, String> {
    let monitors = window
        .available_monitors()
        .map_err(|e| format!("available_monitors: {e}"))?;
    let primary = window
        .primary_monitor()
        .inspect_err(|e| tracing::debug!("diagnostics: primary monitor not read: {e}"))
        .ok()
        .flatten();
    Ok(monitors
        .iter()
        .map(|m| system::Display {
            name: m.name().cloned(),
            width: m.size().width,
            height: m.size().height,
            x: m.position().x,
            y: m.position().y,
            scale: m.scale_factor(),
            primary: primary
                .as_ref()
                .is_some_and(|p| p.name() == m.name() && p.position() == m.position()),
        })
        .collect())
}

/// The metadata's `build`.
fn agent_build(build: &BuildInfo) -> AgentBuild {
    AgentBuild {
        version: build.version.clone(),
        commit: build.commit.clone(),
        dirty: build.dirty,
        channel: build.channel.as_str().to_string(),
        built_at: build.built_at.clone(),
        label: build.label(),
    }
}

/// `build.json`: the build, the server it was built for, where reports go, the protocol and the
/// default log level (and why).
fn build_json(build: &BuildInfo, endpoint: &str) -> Value {
    json!({
        "version": build.version,
        "commit": build.commit,
        "dirty": build.dirty,
        "channel": build.channel.as_str(),
        "built_at": build.built_at,
        "label": build.label(),
        "server_url": afklink_core::config::DEFAULT_SERVER_URL,
        "user_agent": build.user_agent(),
        "report_endpoint": endpoint,
        "protocol_version": afklink_protocol::PROTOCOL_VERSION,
        "default_log_level": default_log_level(build.channel).as_str(),
        "release_phase": format!("{RELEASE_PHASE:?}"),
    })
}

fn pretty(value: &Value) -> Vec<u8> {
    serde_json::to_vec_pretty(value).unwrap_or_else(|e| {
        tracing::warn!("diagnostics: JSON not serialized: {e}");
        b"{}".to_vec()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A PC bound to nobody — by the server's list this run, by the last run's, or not known at all
    /// — packs to the small cap the server takes from it; one with people on it, to the full one.
    #[test]
    fn a_pc_bound_to_nobody_packs_its_report_to_the_small_cap() {
        let small = package::UNBOUND_CAP;
        let full = package::CAP;
        let cases = [
            ((true, 1, None), full, "bound"),
            ((true, 3, Some(0)), full, "bound"),
            ((true, 0, None), small, "bound_to_nobody"),
            // The server's list wins over the last run's.
            ((true, 0, Some(2)), small, "bound_to_nobody"),
            ((false, 0, Some(2)), full, "bound_last_run"),
            ((false, 0, Some(0)), small, "bound_to_nobody_last_run"),
            ((false, 0, None), small, "bindings_unknown"),
        ];
        for ((heard, bound_now, last_list), bytes, why) in cases {
            assert_eq!(
                manual_cap(heard, bound_now, last_list),
                ManualCap { bytes, why },
                "{heard} {bound_now} {last_list:?}"
            );
        }
        // Under the server's 2 MiB for such a PC (backend `UNBOUND_AGENT_BODY_BYTES`) with room.
        assert!(small < 2 * 1024 * 1024);
        assert!(small >= 3 * 2 * 1024 * 1024 / 4);
        assert!(full < limits::AGENT_BODY_BYTES);
    }

    /// A `413` to a report packed to the full cap: packed once more to the small one and sent, and
    /// the second answer is the report's. Only once, only from the full cap, only on `413`; an
    /// error of the attempt itself (packing) ends it there.
    #[test]
    fn a_413_at_the_full_cap_is_packed_again_at_the_small_one() {
        use upload::{Failure, Outcome};
        let full = ManualCap {
            bytes: package::CAP,
            why: "bound",
        };
        let small = ManualCap {
            bytes: package::UNBOUND_CAP,
            why: "bound_to_nobody",
        };
        let sent = || Outcome::Sent { receipt: None };
        let too_large = || Outcome::Failed(Failure::TooLarge);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("runtime");
        // `answers`, one per attempt, in order; the caps the attempts were packed to.
        let run = |first: ManualCap, answers: Vec<Result<Outcome, SendLogsDto>>| {
            let mut answers = answers.into_iter();
            let mut caps = Vec::new();
            let outcome = runtime.block_on(send_within_caps(first, |cap| {
                caps.push(cap);
                let answer = answers.next().expect("an answer per attempt");
                async move { answer }
            }));
            (outcome, caps)
        };

        let (outcome, caps) = run(full, vec![Ok(too_large()), Ok(sent())]);
        assert_eq!(outcome, Ok(sent()));
        assert_eq!(
            caps,
            [
                full,
                ManualCap {
                    bytes: package::UNBOUND_CAP,
                    why: "too_large_at_full_cap"
                }
            ]
        );

        // Refused again at the small cap: that is the answer, no third attempt.
        let (outcome, caps) = run(full, vec![Ok(too_large()), Ok(too_large())]);
        assert_eq!(outcome, Ok(too_large()));
        assert_eq!(caps.len(), 2);

        // Already at the small cap, or another answer: one attempt.
        for (first, answer) in [
            (small, too_large()),
            (full, sent()),
            (full, Outcome::Failed(Failure::Unavailable)),
            (
                full,
                Outcome::TooOften {
                    retry_after_s: Some(60),
                },
            ),
        ] {
            let (outcome, caps) = run(first, vec![Ok(answer.clone())]);
            assert_eq!(outcome, Ok(answer));
            assert_eq!(caps, [first]);
        }

        // The repack could not be packed: the window hears that.
        let (outcome, caps) = run(
            full,
            vec![Ok(too_large()), Err(SendLogsDto::failed("packing"))],
        );
        assert_eq!(outcome, Err(SendLogsDto::failed("packing")));
        assert_eq!(caps.len(), 2);
    }

    #[test]
    fn a_comment_is_cleaned_to_the_contracts_rule() {
        assert_eq!(clean_comment(""), None);
        assert_eq!(clean_comment("  \n\t "), None);
        assert_eq!(
            clean_comment("  Картинка замёрзла\r\nпосле сворачивания  ").as_deref(),
            Some("Картинка замёрзла\r\nпосле сворачивания")
        );
        // Control characters other than tab and line breaks go (U+0000–U+001F, DEL, U+0080–U+009F).
        assert_eq!(
            clean_comment("a\u{0}b\u{1b}[31mc\u{7f}d\u{85}e\tf").as_deref(),
            Some("ab[31mcde\tf")
        );
        // Cut at 500 characters — code points, not bytes or UTF-16 units.
        let long = "я".repeat(600);
        assert_eq!(clean_comment(&long).map(|c| c.chars().count()), Some(500));
        let emoji = "😀".repeat(501);
        assert_eq!(clean_comment(&emoji).map(|c| c.chars().count()), Some(500));
        // A cut that ends in spaces does not keep them.
        let spaced = format!("{} tail", "x".repeat(499));
        assert_eq!(
            clean_comment(&spaced).as_deref(),
            Some("x".repeat(499).as_str())
        );
    }

    #[test]
    fn sessions_are_the_live_ones_then_the_most_recent_uuids() {
        let id = |n: u8| format!("3fa85f64-5717-4562-b3fc-2c963f66af{n:02x}");
        let recent = Mutex::new(VecDeque::new());
        for n in 0..12 {
            remember(&recent, id(n));
        }
        remember(&recent, id(5)); // seen again: moves to the newest
        remember(&recent, "not-a-uuid".to_string());
        let recent = afklink_core::lock(&recent).clone();
        assert_eq!(recent.len(), RECENT_SESSIONS);
        let ids = session_ids(None, &[id(11), id(40)], &recent);
        assert_eq!(
            ids,
            [id(11), id(40), id(5), id(10), id(9), id(8), id(7), id(6)],
            "live first, then newest first, each once, UUIDs only, eight at most"
        );
        // From a journal entry: that session leads, and is not repeated.
        let ids = session_ids(Some(&id(8)), &[id(11)], &recent);
        assert_eq!(
            ids,
            [id(8), id(11), id(5), id(10), id(9), id(7), id(6)],
            "the session asked for first"
        );
    }

    #[test]
    fn the_window_learns_the_outcome_and_nothing_more() {
        let sent = SendLogsDto::from(&upload::Outcome::Sent {
            receipt: Some(afklink_protocol::diagnostics::DiagnosticsReceipt {
                report_id: "r".into(),
                bytes: 1,
            }),
        });
        assert_eq!(
            (sent.outcome, sent.report_id.as_deref()),
            ("sent", Some("r"))
        );
        let later = SendLogsDto::from(&upload::Outcome::TooOften {
            retry_after_s: Some(60),
        });
        assert_eq!(
            (later.outcome, later.retry_after_s),
            ("too_often", Some(60))
        );
        let failed = SendLogsDto::from(&upload::Outcome::Failed(upload::Failure::Unavailable));
        assert_eq!(
            (failed.outcome, failed.failure),
            ("failed", Some("unavailable"))
        );
    }

    #[test]
    fn build_json_names_the_build_and_the_server() {
        let build = BuildInfo::from_stamp(
            "0.1.0",
            "3a3bc46e0f1d2c3b4a5968778695a4b3c2d1e0f9",
            "0",
            "2026-09-28T20:15:07Z",
            "release",
        );
        let v = build_json(&build, "https://api.afklink.app/api/diagnostics/agent");
        assert_eq!(v["label"], "0.1.0");
        assert_eq!(v["channel"], "release");
        assert_eq!(v["server_url"], afklink_core::config::DEFAULT_SERVER_URL);
        assert_eq!(v["user_agent"], "AFKLink/0.1.0 (release)");
        let meta = agent_build(&build);
        assert_eq!(
            meta.commit.as_deref(),
            Some("3a3bc46e0f1d2c3b4a5968778695a4b3c2d1e0f9")
        );
        assert_eq!(meta.channel, "release");
    }
}
