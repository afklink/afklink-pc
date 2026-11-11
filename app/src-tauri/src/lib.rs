//! AFKLink agent desktop app (Tauri v2): system tray, a settings window, and
//! commands bridging the frontend to the `core` orchestrator.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use serde::Serialize;
use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::TrayIconBuilder;
use tauri::{Manager, State};
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::{reload, EnvFilter, Layer, Registry};

use afklink_capture::WgcCapturer;
use afklink_core::build_info::{BuildInfo, Channel};
use afklink_core::logging::{
    default_log_level, effective_level, LogLevel, StartupFilter, ENV_FILTER_VAR,
};
use afklink_core::traits::{Capturer, InputInjector};
use afklink_core::{
    Agent, AgentCommand, AgentControl, Backends, Config, Identity, Journal, PersonName, Refusal,
    SessionLog,
};
use afklink_encode::OpenH264Encoder;
use afklink_i18n::{Locale, NativeText};
use afklink_input::create_input_backend;

mod access_cache;
mod autostart;
mod capture_guard;
/// The orchestrator's fault on demand: a `dev-fault` build alone (tests compile it too), never a
/// release one.
#[cfg(any(test, feature = "dev-fault"))]
mod dev_fault;
mod diagnostics;
mod driver_hint;
mod fakerinput_setup;
mod flight_recorder;
mod game_helper;
mod game_only;
mod guest_toast;
mod home;
mod instance_probe;
mod journal_view;
mod log_file;
mod log_retention;
mod log_route;
mod main_thread;
mod pair_prompt;
mod staged_file;
mod stall_watch;
mod start_failure;
mod supervise;
mod system_events;
/// Deliberate breakage for the rollback live tests: a test-key build alone, never a production one.
#[cfg(feature = "updater-test-key")]
mod test_break;
mod toast;
mod toast_identity;
mod tray_status;
mod tray_theme;
mod updater;
mod webview_runtime;
mod window_fit;

/// For the integration tests only (`tests/updater_http.rs`); not an API.
#[doc(hidden)]
pub use updater::testing as updater_testing;

use flight_recorder::FlightRecorder;
use log_route::{LogFiles, SYSTEM_TARGET};
use tray_status::{Presence, SharedLink, TrayStatus};

/// The process's event queue in the tests (`afklink_core::agent_events`): in memory, installed by
/// the first test that asks for it; every test after shares it, and looks only at its own kind.
#[cfg(test)]
pub(crate) fn test_event_queue() -> Arc<afklink_core::agent_events::EventQueue> {
    if let Some(q) = afklink_core::agent_events::installed() {
        return Arc::clone(q);
    }
    let q = Arc::new(afklink_core::agent_events::EventQueue::in_memory());
    afklink_core::agent_events::install(Arc::clone(&q));
    afklink_core::agent_events::installed().map_or(q, Arc::clone)
}

// ---------- DTOs sent to the frontend ----------

#[derive(Serialize)]
struct LocaleDto {
    /// The locale in effect: `"ru"` or `"en"`.
    locale: String,
    /// What is stored in config.json: `"auto"`, `"ru"` or `"en"`.
    preference: String,
}

/// The Settings view's logging section: the three levels («Подробные», «Обычные», «Выключены»;
/// `afklink_core::logging`).
#[derive(Serialize, Debug, PartialEq, Eq)]
struct LoggingDto {
    /// The level in effect for our crates (`RUST_LOG` aside): the chosen one, else the build's
    /// default. `"off"`, `"info"` or `"debug"`; `"trace"` when config.json says so by hand.
    level: String,
    /// The level config.json holds, settled (`LogLevel::settled`); `None` while none is chosen (a
    /// fresh install, or a value this build does not know) and the build's default applies.
    choice: Option<String>,
    /// The picker's selected option, `level` as Settings shows it (`LogLevel::shown_as`): `"off"`,
    /// `"info"` or `"debug"` — `trace` shows as `"debug"`, «Подробные».
    option: String,
    /// The build's default: `"debug"` for a development build; for a release its phase's
    /// (`afklink_core::logging::RELEASE_PHASE`) — `"debug"` during the beta test, `"info"` after.
    default_level: String,
    /// Whether anything is written now — the files and the flight recorder: false when the level is
    /// off, or `RUST_LOG` says `off`. «Отправить логи» is disabled while it is false.
    writing: bool,
    /// `RUST_LOG`, when it overrides the setting. The picker still saves; this is why nothing
    /// changes until the app is started without it.
    env_override: Option<String>,
    /// `%APPDATA%\AFKLink\logs`, for the "open folder" button.
    dir: Option<String>,
}

/// What `set_log_level` was asked for: one of the three levels Settings offers. Anything else —
/// `trace`, `error`, `warn` or «auto» — is refused, not stored.
fn parse_offered_level(value: &str) -> Result<LogLevel, String> {
    let level: LogLevel = value.parse().map_err(|e| format!("{e}"))?;
    if level.is_offered() {
        Ok(level)
    } else {
        Err(format!(
            "log level {level} is not one Settings offers (off, info, debug)"
        ))
    }
}

/// Settings → Diagnostics' version row: which build this is (`afklink_core::build_info`).
#[derive(Serialize)]
struct BuildInfoDto {
    /// The workspace version (`agent/Cargo.toml`).
    version: String,
    /// «0.1.0» for a release; «0.1.0 · 3a3bc46 · dev», «0.1.0 · 3a3bc46-dirty · dev», or
    /// «0.1.0 · dev» for an unstamped development build (`BuildInfo::label`).
    label: String,
    /// `"release"` or `"dev"`.
    channel: &'static str,
    /// The full commit hash; `None` for a development build.
    commit: Option<String>,
    dirty: Option<bool>,
    /// `YYYY-MM-DDTHH:MM:SSZ`; `None` for a development build.
    built_at: Option<String>,
}

#[derive(Serialize)]
struct BindingDto {
    telegram_user_id: i64,
    /// Without its `@`; the first name. Both cleaned as the toasts clean them — no bidi controls,
    /// no invisible characters, trimmed, `None` when nothing is left (`binding_dto`).
    username: Option<String>,
    first_name: Option<String>,
    /// `"owner"` or `"guest"`; `None` from a server older than roles — the
    /// window then shows no role and offers no role action.
    role: Option<&'static str>,
    /// The PC's request to the owner on this person's row: in flight, or how it ended while that is
    /// shown (`afklink_core::owner_request`).
    owner_request: Option<OwnerRequestDto>,
}

/// A request to the owner on a person's row.
#[derive(Serialize, Debug, PartialEq, Eq)]
struct OwnerRequestDto {
    /// `"make_owner"` («Сделать владельцем» on a guest), `"unbind_owner"` («Отвязать» on the
    /// owner) or `"pc_allow"` (this PC's «Разрешить» held for the owner, on the newcomer's row:
    /// `StatusDto::held_pair`; its `confirmed` is «Разрешено»).
    kind: &'static str,
    /// `"asked"` (not answered by the server yet), `"pending"` (waiting for the owner), `"cancelling"`
    /// («Отменить запрос» pressed), `"rechecking"` (pending before a reconnect, not re-sent yet) or
    /// `"ended"` (`outcome` says how).
    stage: &'static str,
    /// A confirmation was actually asked of the owner: the server opened the request
    /// (`InFlight::owner_asked`). Only then does the row say «Ждём подтверждения» and offer
    /// «Отменить запрос»; while `asked` it holds its buttons and says nothing — on a PC with no
    /// owner the server applies it at once and asks nobody.
    owner_asked: bool,
    /// Unix ms the owner has until, once the server opened the request.
    expires_at: Option<i64>,
    /// With `"ended"`: `"confirmed"`, `"declined"`, `"expired"`, `"cancelled"`, `"busy"`,
    /// `"rate_limited"` or `"failed"`.
    outcome: Option<&'static str>,
}

/// The request on `telegram_user_id`'s row, as the window draws it: the one in flight if it is
/// theirs, else how their last one ended while that is shown.
fn owner_request_dto(
    requests: &afklink_core::owner_request::OwnerRequests,
    telegram_user_id: i64,
) -> Option<OwnerRequestDto> {
    if let Some(c) = requests.in_flight_for(telegram_user_id) {
        return Some(OwnerRequestDto {
            kind: c.kind.as_str(),
            stage: c.stage.as_str(),
            owner_asked: c.owner_asked(),
            expires_at: c.expires_at,
            outcome: None,
        });
    }
    requests
        .ended_for(telegram_user_id)
        .map(|e| OwnerRequestDto {
            kind: e.kind.as_str(),
            stage: "ended",
            owner_asked: false,
            expires_at: None,
            outcome: Some(e.outcome.as_str()),
        })
}

/// The newcomer of a pairing approved on this PC and held for the owner (`pc_allow`): a row of
/// their own at the end of «Доступ» while the owner decides and while how it
/// ended is shown — «Ждём подтверждения · 9:41» and «Отменить запрос», the words of the PC's own
/// requests. Not a binding: no «Отвязать», no role, not counted.
#[derive(Serialize, Debug, PartialEq, Eq)]
struct HeldPairDto {
    telegram_user_id: i64,
    /// Without its `@`; the first name. Cleaned as every name in the window.
    username: Option<String>,
    first_name: Option<String>,
    /// Kind `"pc_allow"`, in flight or ended (`OwnerRequestDto`).
    owner_request: OwnerRequestDto,
}

/// The `pc_allow` row, if there is one to draw: the newcomer's request in flight, or how it ended
/// while that is shown — and only while the list has no row for them (once their binding comes, the
/// outcome is on that row, `binding_dto`).
fn held_pair_dto(
    requests: &afklink_core::owner_request::OwnerRequests,
    bindings: &[access_cache::CachedBinding],
) -> Option<HeldPairDto> {
    let (uid, names) = requests.newcomer()?;
    if bindings.iter().any(|b| b.telegram_user_id == uid) {
        return None;
    }
    Some(HeldPairDto {
        telegram_user_id: uid,
        username: afklink_core::person_name::shown_username(
            names.and_then(|n| n.username.as_deref()),
        ),
        first_name: afklink_core::person_name::shown_first_name(
            names.and_then(|n| n.first_name.as_deref()),
        ),
        owner_request: owner_request_dto(requests, uid)?,
    })
}

/// A person with access as the window shows them: the first name and the username cleaned as the
/// toasts clean them (raw, bidi controls could turn a name around and invisible characters
/// make «Мама» of anything), blank ones as none; the role and the row's
/// request to the owner as they stand.
fn binding_dto(
    b: &access_cache::CachedBinding,
    owner_requests: &afklink_core::owner_request::OwnerRequests,
) -> BindingDto {
    BindingDto {
        owner_request: owner_request_dto(owner_requests, b.telegram_user_id),
        telegram_user_id: b.telegram_user_id,
        username: afklink_core::person_name::shown_username(b.username.as_deref()),
        first_name: afklink_core::person_name::shown_first_name(b.first_name.as_deref()),
        role: b.role.map(afklink_core::BindingRole::as_str),
    }
}

/// A pairing request as the request window shows it, its names cleaned as the toasts' are;
/// `step` at «consent» until `pair_prompt` says otherwise.
fn pending_pair_dto(p: &afklink_core::agent::PendingPair) -> PendingPairDto {
    PendingPairDto {
        request_id: p.request_id.clone(),
        display_name: p.display_name(),
        first_name: afklink_core::person_name::shown_first_name(p.first_name.as_deref()),
        username: afklink_core::person_name::shown_username(p.username.as_deref()),
        telegram_user_id: p.telegram_user_id,
        expires_at: p.expires_at,
        asks_role: p.asks_role(),
        // Set by the caller, from `pair_prompt`, not under the state's lock.
        step: pair_prompt::PairStep::Consent.as_str(),
        link: p.link.as_str(),
    }
}

#[derive(Serialize)]
struct SessionDto {
    session_id: String,
    telegram_user_id: i64,
    /// Without its `@`, cleaned as the toasts clean it.
    username: Option<String>,
    /// The viewer's name as the toasts and the tray say it: first name, else "@username", else
    /// "#id" (`SessionInfo::name`), so the window does not reinvent the fallback.
    display_name: String,
    connected: bool,
}

/// A pairing request waiting for the owner's answer.
#[derive(Serialize)]
struct PendingPairDto {
    request_id: String,
    /// Ready-made label — "Name (@username)" when both exist, else first name, "@username",
    /// "#id" (`PendingPair::name`), the same as the pairing toast. The prompt falls back to it
    /// when the two fields below are missing (a window from an older build).
    display_name: String,
    /// The requester's Telegram first name and username (without its `@`), cleaned as the toasts
    /// clean them — no bidi controls, no invisible characters, trimmed, `None` when nothing is left
    /// (`pending_pair_dto`): the prompt shows «{name} просит доступ к этому ПК» over «@handle»,
    /// or over «#id» when there is no username to tell the person by.
    first_name: Option<String>,
    username: Option<String>,
    telegram_user_id: i64,
    expires_at: i64,
    /// «Разрешить» leads to «Кто это?» («Владелец» / «Гость»): the PC has no owner
    /// (`pair_request.has_owner = false`, `PendingPair::asks_role`).
    asks_role: bool,
    /// Which step the prompt is at (`pair_prompt::PairStep`), kept in Rust so a reloaded request
    /// window comes back at it: `"consent"` — «Отклонить» / «Разрешить»; `"role"` — «Кто это?».
    step: &'static str,
    /// Where the request stands with the link its answer goes over (`afklink_core::pairing::PairLink`):
    /// `"live"` — answerable; `"lost"` — signaling dropped, the request kept (the backend keeps it
    /// too): the buttons wait, disabled, and «Нет связи» stands by the countdown; `"rechecking"` — the
    /// link is back and the backend's re-send of it is awaited (a moment): the buttons still wait.
    link: &'static str,
}

#[derive(Serialize)]
struct StatusDto {
    connected: bool,
    /// The server cannot reach this PC, as the tray says it (`tray_status::Link::offline`): the
    /// link has been down for three seconds without a break (since the launch, or since it dropped),
    /// or the backend refuses this agent — and, once said, until the link is back. The window says
    /// «Нет связи» under the monitor where «Готов к подключению» would be, and the
    /// «Нет связи с сервером» toast when there is no refusal to say instead. One watch for the
    /// tray and the window (`SharedLink`), so they say it from the same moment.
    offline: bool,
    /// Set while the backend refuses this agent and it is not reconnecting at the usual pace:
    /// `"replaced"` (another agent with this identity is running; waits for Retry), `"outdated"`
    /// (`protocol_unsupported`: only an update helps; retries slowly all the same), `"blocked"`
    /// (`device_blocked`: an admin blocked this PC — «ПК заблокирован», no Retry; retries slowly, so
    /// a lifted block brings it back by itself) or `"fatal"` (any other fatal code; retries slowly,
    /// and at once on Retry). The code and the backend's detail are in the log only. See
    /// `afklink_core::reconnect`.
    refusal: Option<&'static str>,
    /// Set after «Приостановить доступ»: every new session request is refused until the owner
    /// presses Resume (`resume_sessions`) — a restart or an update keeps it (`Config::paused`). See
    /// `AgentState::paused`.
    paused: bool,
    pairing_code: Option<String>,
    /// The pairing panel as the agent sees it: `"closed"`, `"open"`, `"redeemed"` (someone entered
    /// the code) or `"paired"` (a binding was made while it was open); the window closes it on the
    /// last two. See `afklink_core::pairing`.
    pairing_panel: &'static str,
    /// The code's ceiling, Unix ms: the backend refuses it after this. `None` without a code.
    pairing_expires_at: Option<i64>,
    deep_link: Option<String>,
    qr_svg: Option<String>,
    /// The pairing request waiting for the owner. Only the request window near the tray draws it
    /// (`pair_prompt`), whether the main window is open or not; the main window shows none.
    pending_pair: Option<PendingPairDto>,
    device_name: String,
    server_url: String,
    device_id: String,
    /// Mirrors `Config.autostart` (see `set_autostart`): the Settings checkbox
    /// needs a stable answer from config, not a live registry probe each poll.
    autostart: bool,
    /// Who has access, as the window shows it: the backend's list once heard this run, before that
    /// the one it sent last time (`access_cache`), and empty for a new device or while nothing is
    /// known — `access` says which.
    bindings: Vec<BindingDto>,
    /// The backend's list has been heard this run: true from the first handshake on
    /// (`AgentState::bindings_known`), and for the rest of the run (the last list, while offline).
    bindings_known: bool,
    /// Where `bindings` comes from: `"server"`, `"cache"` (the server's list from last time, until it
    /// answers), `"new_device"` (config.json written at this launch: nobody can have access yet) or
    /// `"unknown"` (nothing known: the main view's zone shows the loader).
    access: access_cache::AccessSource,
    /// A request to the owner is in flight on this PC (at most one): the window holds back the
    /// other owner-level buttons — «Сделать владельцем», «Отвязать» on the owner — disabled in
    /// place.
    owner_request_busy: bool,
    /// The newcomer of a pairing this PC allowed and the server holds for the owner (`pc_allow`):
    /// their row at the end of «Доступ» until the list has them (`held_pair_dto`).
    held_pair: Option<HeldPairDto>,
    sessions: Vec<SessionDto>,
    /// How long someone has been in control — «меньше минуты», «12 мин», «1 ч 05 мин» — for the
    /// muted line under «{name} управляет»; `None` while nobody is (or the PC is paused). The tray's
    /// menu line and tooltip carry the same text (`tray_status`), worded here in the window's
    /// language.
    live_for: Option<String>,
    /// The main view's card — its rows «Управление в играх», «Только игра» and «Журнал» — the
    /// one-off autostart question, and what the zone under the hero shows, decided in Rust (`home`).
    home: home::HomeDto,
}

/// The language the window renders in, from what it passed (`"ru"`, `"en"`), else the one the app
/// started in.
fn window_locale(lang: Option<&str>, startup: Locale) -> Locale {
    match lang {
        Some("ru") => Locale::Ru,
        Some("en") => Locale::En,
        _ => startup,
    }
}

// ---------- Commands ----------

/// The window's state, polled once a second.
///
/// `lang` is the language the window is rendering in (`"ru"` or `"en"`), for the one piece of
/// finished text in the answer, `live_for`: the window can switch language without a restart while
/// the tray keeps the one it started with. Absent or unknown, the startup language is used.
#[tauri::command]
#[allow(
    clippy::too_many_arguments,
    reason = "Tauri hands each piece of managed state in as an argument"
)]
fn get_status(
    app: tauri::AppHandle,
    control: State<'_, AgentControl>,
    locale: State<'_, Locale>,
    link: State<'_, SharedLink>,
    prompt: State<'_, pair_prompt::PairPrompt>,
    journal: State<'_, Arc<Journal>>,
    home_log: State<'_, home::HomeLog>,
    access_cache: State<'_, access_cache::AccessCache>,
    capture: State<'_, capture_guard::CaptureGuard>,
    lang: Option<String>,
) -> StatusDto {
    if let Some(other) = lang.as_deref().filter(|l| !matches!(*l, "ru" | "en")) {
        // Polled every second: said once per run. Only the timer's language is affected.
        static WARNED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
        if !WARNED.swap(true, std::sync::atomic::Ordering::Relaxed) {
            tracing::debug!(
                lang = other,
                fallback = locale.tag(),
                "window asked for status in a language this build does not know"
            );
        }
    }
    let window_locale = window_locale(lang.as_deref(), *locale);
    // The rows' requests to the owner as of now: an outcome shown long enough goes, a wait for the
    // server that ran out ends (logged once, where it happens).
    control.tick_owner_requests(afklink_core::journal::now_ms());
    let (
        connected,
        refusal,
        paused,
        pairing_code,
        pairing,
        mut pending_pair,
        server_bindings,
        bindings_known,
        owner_requests,
        sessions,
        live_for,
        input_not_reaching,
    ) = {
        let s = afklink_core::lock(&control.state);
        let presence = tray_status::presence(s.paused, &s.sessions, Instant::now());
        (
            s.connected,
            s.refused.as_ref().map(Refusal::kind),
            s.paused,
            s.pairing_code.clone(),
            (s.pairing_panel.kind(), s.pairing_expires_at),
            s.pending_pair.as_ref().map(pending_pair_dto),
            // Copied out: `access_cache.view` takes the cache's lock, never under this one (KB-4).
            s.bindings.clone(),
            s.bindings_known,
            s.owner_requests.clone(),
            s.sessions
                .iter()
                .map(|x| SessionDto {
                    session_id: x.session_id.clone(),
                    telegram_user_id: x.telegram_user_id,
                    username: afklink_core::person_name::shown_username(x.username.as_deref()),
                    display_name: x.name().text,
                    connected: x.connected,
                })
                .collect::<Vec<_>>(),
            tray_status::live_for(window_locale, &presence),
            s.input_not_reaching,
        )
    };
    // The server's list once heard; before it, what is known without it (`access_cache`). Not
    // under the state's lock: the orchestrator never waits on the cache through this window.
    let access = access_cache.view(&server_bindings, bindings_known);
    // Before a code can reach the window, the window is out of the video (and back in once
    // the panel is closed). Not under the state's lock; here, on the main thread (a command without
    // `async`), where the guard's window calls are answered in place (`capture_guard`).
    capture.sync(
        &app,
        capture_guard::wanted(pairing.0, pairing_code.is_some()),
        "the window's status",
    );
    // Not under the state's lock: neither caller (this, the tray's watcher) holds both at once.
    let offline = link
        .observe(connected, refusal.is_some(), Instant::now(), "window")
        .offline;
    // Not under the state's lock either: `pair_prompt`'s thread takes the two one after the other.
    if let Some(p) = pending_pair.as_mut() {
        p.step = prompt.step_for(&p.request_id).as_str();
    }
    let bindings = access
        .bindings
        .iter()
        .map(|b| binding_dto(b, &owner_requests))
        .collect::<Vec<_>>();
    let held_pair = held_pair_dto(&owner_requests, &access.bindings);
    let (
        device_name,
        server_url,
        device_id,
        autostart,
        autostart_offer,
        game_only,
        game_only_for_guests,
        game,
    ) = {
        let c = afklink_core::lock(&control.config);
        (
            c.name.clone(),
            c.server_url.clone(),
            c.device_id.clone(),
            c.autostart,
            c.autostart_offer(),
            c.game_only,
            c.game_only_for_guests,
            c.game.as_ref().map(|g| g.shown_name().to_string()),
        )
    };
    let home = home_log.home(
        &home::Inputs {
            install_supported: fakerinput_setup::install_supported(),
            driver: fakerinput_setup::last_read(),
            input_not_reaching,
            game_only,
            game_only_for_guests,
            game,
            autostart_offer,
            autostart,
            access: access.source,
            bindings: bindings.len(),
            sessions: sessions.len(),
            refused: refusal.is_some(),
            pairing_request: pending_pair.is_some(),
        },
        journal
            .last()
            .map(|v| journal_view::entry_dto(&v, window_locale, afklink_core::journal::now_ms())),
    );
    let deep_link = control.deep_link();
    let qr_svg =
        deep_link
            .as_deref()
            .and_then(|link| match afklink_core::qr::qr_svg_data_uri(link) {
                Ok(svg) => Some(svg),
                Err(e) => {
                    // The window polls this twice a second, so once per run. Never the link: it
                    // carries the live pairing code.
                    static WARNED: std::sync::atomic::AtomicBool =
                        std::sync::atomic::AtomicBool::new(false);
                    if !WARNED.swap(true, std::sync::atomic::Ordering::Relaxed) {
                        tracing::warn!("pairing QR code could not be rendered: {e:#}");
                    }
                    None
                }
            });

    StatusDto {
        connected,
        offline,
        refusal,
        paused,
        pairing_code,
        pairing_panel: pairing.0,
        pairing_expires_at: pairing.1,
        deep_link,
        qr_svg,
        pending_pair,
        device_name,
        server_url,
        device_id,
        autostart,
        bindings,
        bindings_known,
        access: access.source,
        owner_request_busy: owner_requests.busy(),
        held_pair,
        sessions,
        live_for,
        home,
    }
}

/// Hand a command from the window or the tray to the orchestrator.
///
/// The orchestrator logs what it does with each; this says where it came from, and warns when
/// nobody is there to take it — an owner pressing the kill switch into a stopped agent must not be
/// told nothing.
fn send_command(control: &AgentControl, cmd: AgentCommand, from: &'static str) {
    tracing::debug!(from, ?cmd, "owner command");
    if let Err(e) = control.commands.send(cmd) {
        tracing::warn!(from, cmd = ?e.0, "command not delivered: the agent has stopped");
    }
}

/// The pairing panel was opened. `reason` is why the window asks, for the log: `opened` (the
/// owner's button) or `retry` (no code came, and the owner pressed Retry).
#[tauri::command]
fn request_pairing(
    app: tauri::AppHandle,
    control: State<'_, AgentControl>,
    capture: State<'_, capture_guard::CaptureGuard>,
    reason: Option<String>,
) {
    tracing::debug!(
        reason = reason.as_deref().unwrap_or("-"),
        "window: pairing panel asks for a code"
    );
    // Out of the video before the code is even asked for (`capture_guard`).
    capture.opening(&app);
    send_command(&control, AgentCommand::RequestPairing, "window");
}

/// The pairing panel was closed. Invalidates the code immediately rather than
/// leaving it live and on screen, where a connected viewer could read it out of the
/// video stream and mint itself an independent binding.
///
/// `reason` is why the window closed it, for the log: `closed` (the owner), `redeemed` (someone
/// entered the code), `paired` (a binding was made while it was open) or `expired` (the code's
/// ceiling passed).
#[tauri::command]
fn cancel_pairing(
    control: State<'_, AgentControl>,
    capture: State<'_, capture_guard::CaptureGuard>,
    reason: Option<String>,
) {
    tracing::debug!(
        reason = reason.as_deref().unwrap_or("-"),
        "window: pairing panel closed"
    );
    send_command(&control, AgentCommand::CancelPairing, "window");
    // The window goes back into the video once the state says the panel is closed.
    capture.closing();
}

/// The owner's answer to a pairing prompt. Without this the six-digit code would be
/// a bearer secret; with it, a guessed code only produces a dialog that gets declined.
///
/// Answered, the request window closes at once (`pair_prompt`), without waiting for the
/// orchestrator to clear the request.
///
/// `role`: the answer to «Кто это?» (`"owner"` or `"guest"`) when the prompt asked it
/// (`PendingPairDto::asks_role`, after `allow_pair`); absent otherwise, and an approval then makes
/// the person a guest (`afklink_core`'s `pair_role`).
#[tauri::command]
fn respond_pair(
    control: State<'_, AgentControl>,
    prompt: State<'_, pair_prompt::PairPrompt>,
    request_id: String,
    accept: bool,
    role: Option<String>,
) {
    let role = match role.as_deref() {
        None => None,
        Some("owner") => Some(afklink_core::BindingRole::Owner),
        Some("guest") => Some(afklink_core::BindingRole::Guest),
        Some(other) => {
            // A window from another build: the approval stands, without a role it cannot name.
            tracing::warn!(
                %request_id,
                role = other,
                "window: a role this build does not know; the approval goes as not asked (a guest)"
            );
            None
        }
    };
    // Kept across a break of the link and not live again: the window's buttons are disabled then, so
    // this is a press that slipped past them. The request window stays: closed now, it would never
    // come back for this request (`pair_prompt::Router` takes an answered one for gone), and the
    // orchestrator would not send the answer anyway (`AgentCommand::RespondToPair`).
    let link = afklink_core::lock(&control.state)
        .pending_pair
        .as_ref()
        .filter(|p| p.request_id == request_id && !p.answerable())
        .map(|p| p.link.as_str());
    if let Some(link) = link {
        tracing::debug!(
            %request_id,
            accept,
            link,
            "window: pairing prompt answered while its link is down: not taken; the prompt stays"
        );
        return;
    }
    tracing::debug!(
        %request_id,
        accept,
        role = role.map_or("-", afklink_core::BindingRole::as_str),
        step = prompt.step_for(&request_id).as_str(),
        "window: pairing prompt answered"
    );
    prompt.answer(&request_id);
    send_command(
        &control,
        AgentCommand::RespondToPair {
            request_id,
            accept,
            role,
        },
        "window",
    );
}

/// «Отвязать» on a person (after its confirmation). A guest's access goes at once; the owner's waits
/// for the owner's confirmation in Telegram — the orchestrator decides by the roles it has
/// (`AgentCommand::Unbind`).
#[tauri::command]
fn unbind(control: State<'_, AgentControl>, telegram_user_id: i64) {
    send_command(&control, AgentCommand::Unbind(telegram_user_id), "window");
}

/// «Сделать владельцем» on a guest: a request the owner confirms in Telegram (applied at once on a
/// PC with no owner). The row says how it goes (`BindingDto::owner_request`).
#[tauri::command]
fn make_owner(control: State<'_, AgentControl>, telegram_user_id: i64) {
    send_command(
        &control,
        AgentCommand::MakeOwner(telegram_user_id),
        "window",
    );
}

/// «Отменить запрос» on the row of the PC's pending request to the owner.
#[tauri::command]
fn cancel_owner_request(control: State<'_, AgentControl>) {
    send_command(&control, AgentCommand::CancelOwnerRequest, "window");
}

/// «Приостановить доступ»: every session ends and new ones are refused until `resume_sessions`.
/// The PC is not locked.
#[tauri::command]
fn kill_switch(control: State<'_, AgentControl>) {
    send_command(&control, AgentCommand::KillSwitch, "window");
}

/// The window's Resume after «Приостановить доступ»: session requests are accepted again.
#[tauri::command]
fn resume_sessions(control: State<'_, AgentControl>) {
    let paused = afklink_core::lock(&control.state).paused;
    tracing::info!(paused, "owner pressed Resume in the window");
    send_command(&control, AgentCommand::Resume, "window");
}

#[tauri::command]
fn set_name(control: State<'_, AgentControl>, name: String) {
    send_command(&control, AgentCommand::SetName(name), "window");
}

/// The window's Retry, shown while the backend refuses this agent: connect now instead of waiting
/// for the owner (`replaced`) or for the slow retry (any other fatal code).
#[tauri::command]
fn retry_connection(control: State<'_, AgentControl>) {
    let refused = afklink_core::lock(&control.state)
        .refused
        .as_ref()
        .map(|r| r.code().to_string());
    tracing::info!(
        refused = refused.as_deref().unwrap_or("-"),
        "owner pressed Retry in the window"
    );
    send_command(&control, AgentCommand::Retry, "window");
}

/// Launch at sign-in. Explicit opt-in, OFF by default.
///
/// Applies immediately — no reboot, no relog: the OS entry (HKCU `...\Run` «AFKLink», see
/// `autostart`) is written or removed now, and config.json remembers the choice so every start can
/// bring the two back in line.
#[tauri::command]
fn set_autostart(control: State<'_, AgentControl>, enabled: bool) -> Result<(), String> {
    apply_autostart(&control, enabled, "Settings")
}

/// The one-off card «Запускать вместе с Windows?» on the main view (`home::autostart_card`):
/// «Включить» (`enable`) turns autostart on the way Settings' switch does; «Не надо» leaves it off.
/// Either answer is the last: the card never comes back (`Config::autostart_offer`). An «Включить»
/// whose entry could not be written leaves the card up, so the press visibly did not take.
#[tauri::command]
fn answer_autostart_offer(control: State<'_, AgentControl>, enable: bool) -> Result<(), String> {
    tracing::info!(
        target: SYSTEM_TARGET,
        enable,
        "main view: «Запускать вместе с Windows?» answered «{}»",
        if enable { "Включить" } else { "Не надо" }
    );
    if enable {
        // Settles the card itself once autostart is on.
        return apply_autostart(&control, true, "the main view's card");
    }
    let mut cfg = afklink_core::lock(&control.config);
    if !cfg.settle_autostart_offer("«Не надо» on the main view") {
        return Ok(());
    }
    cfg.save().map_err(|e| {
        // In force for this run: the card stays gone until a restart shows it again.
        tracing::warn!(target: SYSTEM_TARGET, "autostart card's answer not saved: {e:#}");
        e.to_string()
    })
}

/// Turn autostart on or off — `from` Settings' switch or the main view's card — and save it. On, it
/// also answers a waiting autostart card: there is nothing left for it to ask.
fn apply_autostart(
    control: &AgentControl,
    enabled: bool,
    from: &'static str,
) -> Result<(), String> {
    autostart::set(enabled).inspect_err(|e| {
        tracing::warn!(target: SYSTEM_TARGET, enabled, from, "autostart entry not changed: {e}");
    })?;
    tracing::info!(target: SYSTEM_TARGET, enabled, from, "autostart changed");
    let (changed, saved) = {
        let mut cfg = afklink_core::lock(&control.config);
        let changed = cfg.autostart != enabled;
        cfg.autostart = enabled;
        if enabled {
            cfg.settle_autostart_offer(from);
        }
        let saved = cfg.save().map_err(|e| {
            // The OS entry is already written; config.json disagreeing means the next launch
            // reconciles it back to the old choice.
            tracing::warn!(
                target: SYSTEM_TARGET,
                enabled,
                "autostart choice not saved to config.json: {e:#}"
            );
            e.to_string()
        });
        (changed, saved)
    };
    // `pc_setting_changed` (`afklink_core::agent_events`): the entry is written, so the change is in
    // force whatever config.json did. Recorded with the config's lock let go: recording writes the
    // queue's file.
    if changed {
        afklink_core::agent_events::setting_changed(
            afklink_protocol::metrics::PcSettingKey::Autostart,
            afklink_protocol::metrics::PcSettingValue::Flag(enabled),
        );
    }
    saved
}

/// Bring the main window forward: show, restore, focus.
///
/// Shared by the tray "show" item and the single-instance callback, so a tray
/// click and a second launch land in the same state — a visible, focused
/// window — rather than each growing its own triple.
fn focus_main<R: tauri::Runtime>(app: &tauri::AppHandle<R>) {
    if let Some(w) = app.get_webview_window("main") {
        // Each best effort: a window that will not take focus is still shown. Debug, because
        // Windows refuses focus to background processes by design and says so this way.
        if let Err(e) = w.show() {
            tracing::debug!("main window: show failed: {e}");
        }
        if let Err(e) = w.unminimize() {
            tracing::debug!("main window: unminimize failed: {e}");
        }
        if let Err(e) = w.set_focus() {
            tracing::debug!("main window: focus refused: {e}");
        }
        // A request window closed by hand comes back: the main window does not hold the request,
        // so this is where the owner goes looking for it.
        if let Some(prompt) = app.try_state::<pair_prompt::PairPrompt>() {
            prompt.reveal("main window shown");
        }
    } else {
        tracing::warn!("no main window to show");
    }
}

/// What language the window renders in, and whether that was chosen or inferred.
///
/// Resolved in Rust because only Rust can read the Windows UI locale, and because the tray menu —
/// built before any window exists — has to agree with what the window shows.
///
/// `preference` is returned alongside `locale` so the picker can show *why* it is in this
/// language: "Automatic (ru)" is a different statement from "Russian", and a picker that showed
/// only the resolved locale could not tell them apart.
#[tauri::command]
fn get_locale(control: State<'_, AgentControl>, locale: State<'_, Locale>) -> LocaleDto {
    let preference = afklink_core::lock(&control.config).lang.clone();
    LocaleDto {
        locale: locale.tag().to_string(),
        preference,
    }
}

/// Persist a language choice: `"auto"`, `"ru"` or `"en"`.
///
/// Takes effect on the next launch for everything Windows draws — the tray menu is built once, at
/// startup, and rebuilding it under a menu the user may have open is worse than waiting. The
/// window itself re-renders immediately, because it asks for the locale again after this returns.
///
/// Unknown values are rejected rather than stored: config.json is read by a future build too, and
/// a junk value there would be indistinguishable from one written by a newer version.
#[tauri::command]
fn set_lang(control: State<'_, AgentControl>, lang: String) -> Result<(), String> {
    if !matches!(lang.as_str(), "auto" | "ru" | "en") {
        tracing::debug!(target: SYSTEM_TARGET, %lang, "language refused: not one this build knows");
        return Err(format!("unsupported language: {lang}"));
    }
    let mut cfg = afklink_core::lock(&control.config);
    tracing::info!(
        target: SYSTEM_TARGET,
        from = %cfg.lang,
        to = %lang,
        "ui language changed (the tray follows on restart)"
    );
    cfg.lang = lang;
    cfg.save().map_err(|e| {
        tracing::warn!(target: SYSTEM_TARGET, "language choice not saved to config.json: {e:#}");
        e.to_string()
    })
}

#[tauri::command]
fn get_logging(logging: State<'_, Logging>) -> LoggingDto {
    logging.dto()
}

/// Which build this is, for Settings → Diagnostics (read once when Settings opens).
#[tauri::command]
fn get_build_info(build: State<'_, BuildInfo>) -> BuildInfoDto {
    BuildInfoDto {
        version: build.version.clone(),
        label: build.label(),
        channel: build.channel.as_str(),
        commit: build.commit.clone(),
        dirty: build.dirty,
        built_at: build.built_at.clone(),
    }
}

/// This build's identity: the workspace version, and the stamp `bun run portable`, `bun run
/// release:build` or `bun scripts/release-build.ts` passes in (empty for a development build),
/// through `build.rs` — and whether this is a test-key build (`updater::TEST_SIGNING_KEY`), which
/// its `User-Agent` names.
fn build_info() -> BuildInfo {
    BuildInfo::from_stamp(
        env!("CARGO_PKG_VERSION"),
        env!("AFKLINK_BUILD_COMMIT"),
        env!("AFKLINK_BUILD_DIRTY"),
        env!("AFKLINK_BUILD_TIME"),
        env!("AFKLINK_BUILD_CHANNEL"),
    )
    .with_test_signing_key(updater::TEST_SIGNING_KEY)
}

/// Change the log level to one of the three Settings offers — `"debug"` («Подробные»), `"info"`
/// («Обычные») or `"off"` («Выключены»). Applied at once (no restart), then saved to config.json as
/// `log_level` — any pick, the build's own default included (there is no «Automatic»), so a level
/// picked in the beta stays after it.
///
/// Applied first, because the effect is what the person asked for: a failed write means the
/// choice lasts this launch rather than that it did not happen. Anything else is rejected rather
/// than stored, as in `set_lang`.
#[tauri::command]
fn set_log_level(
    control: State<'_, AgentControl>,
    logging: State<'_, Logging>,
    level: String,
) -> Result<LoggingDto, String> {
    let chosen = parse_offered_level(&level).inspect_err(|e| {
        tracing::debug!(target: SYSTEM_TARGET, "log level refused: {e}");
    })?;
    logging.set_choice(chosen).inspect_err(|e| {
        tracing::warn!(target: SYSTEM_TARGET, "log level not applied: {e}");
    })?;
    let stored = chosen.as_str().to_string();
    let (changed, saved) = {
        let mut cfg = afklink_core::lock(&control.config);
        tracing::debug!(
            target: SYSTEM_TARGET,
            from = %cfg.log_level.as_deref().unwrap_or("- (none chosen: the channel's)"),
            to = %stored,
            "log level choice saved to config.json"
        );
        let changed = cfg.log_level.as_deref() != Some(stored.as_str());
        cfg.log_level = Some(stored.clone());
        let saved = cfg.save().map_err(|e| {
            // Applied for this run; the next one starts at the old level.
            tracing::warn!(
                target: SYSTEM_TARGET,
                %level,
                "log level not saved to config.json: {e:#}"
            );
            e.to_string()
        });
        (changed, saved)
    };
    // `pc_setting_changed` (`afklink_core::agent_events`): the level is applied already, saved or
    // not. Its value is one of the three words Settings offers — a short id. Recorded with the
    // config's lock let go: recording writes the queue's file.
    if changed {
        afklink_core::agent_events::setting_changed(
            afklink_protocol::metrics::PcSettingKey::LogLevel,
            afklink_protocol::metrics::PcSettingValue::Id(stored),
        );
    }
    saved?;
    Ok(logging.dto())
}

/// Show the logs folder in Explorer, creating it if logging has been off since install — an
/// empty folder is a truthful answer, an error dialog is not.
#[tauri::command]
fn open_logs_dir() -> Result<(), String> {
    open_logs_dir_inner()
        .inspect_err(|e| tracing::warn!(target: SYSTEM_TARGET, "logs folder not opened: {e}"))
}

fn open_logs_dir_inner() -> Result<(), String> {
    let dir = logs_dir()?;
    std::fs::create_dir_all(&dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
    tracing::debug!(target: SYSTEM_TARGET, dir = %dir.display(), "opening the logs folder in Explorer");
    let mut explorer = std::process::Command::new("explorer")
        .arg(&dir)
        .spawn()
        .map_err(|e| format!("start explorer: {e}"))?;
    // Reaped off the command thread. explorer.exe hands the window to the running shell and exits
    // at once — with status 1 even on success, so the status says nothing and is ignored.
    std::thread::spawn(move || {
        let _ = explorer.wait();
    });
    Ok(())
}

/// A planned write of the access cache, on the blocking pool (`access_cache`, KB-4); a task of its
/// own awaits it only for a write that never ran or did not finish (a panic, a cancelled task):
/// the cache then forgets it was on its way, and the next tick plans the list again.
fn write_access_cache(app: &tauri::AppHandle, job: access_cache::PendingWrite) {
    let generation = job.generation();
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        let writer = app.clone();
        let done = tauri::async_runtime::spawn_blocking(move || {
            match writer.try_state::<access_cache::AccessCache>() {
                Some(cache) => cache.write(job),
                None => tracing::warn!("access cache gone before its write: not written"),
            }
        })
        .await;
        if let Err(e) = done {
            match app.try_state::<access_cache::AccessCache>() {
                Some(cache) => cache.lost(generation, &e.to_string()),
                None => tracing::warn!(
                    generation,
                    "access cache: the write did not finish ({e}), and the cache is gone"
                ),
            }
        }
    });
}

/// Ambient signals for the tray-hidden case: sessions.
///
/// Polls the orchestrator state twice a second and turns edges into OS surfaces: a toast when a
/// session's peer connects and another when it ends ([`SessionToasts`]); the tray's account of who
/// is in control (`tray_status`: the menu's first line, the tooltip, the live icon, and «Нет связи»
/// when nobody is and the server cannot reach this PC), handed to the tray's own thread whenever
/// its text changes; and «Управление не доходит» (`driver_hint`): its toast, once a session while
/// the main window is not on screen, its highlight cleared once the driver is read installed. The
/// main window polls the same state itself; neither side trusts the other to be visible. Pairing
/// requests have their own thread (`pair_prompt`).
///
/// `initial` is the status the tray was built with.
fn spawn_state_watcher(
    app: tauri::AppHandle,
    locale: Locale,
    watch: SharedLink,
    initial: (Presence, TrayStatus),
) {
    tauri::async_runtime::spawn(async move {
        let mut session_toasts = SessionToasts::default();
        let mut driver_toast = driver_hint::DriverToast::default();
        let (mut last_presence, mut last_status) = initial;
        loop {
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            let Some(control) = app.try_state::<AgentControl>() else {
                continue;
            };
            // The rows' requests to the owner, whether the window is open or not: each wait for the
            // server ends, and each outcome goes, when it is due — and is logged then.
            control.tick_owner_requests(afklink_core::journal::now_ms());
            let now = Instant::now();
            let (
                sessions,
                presence,
                connected,
                refused,
                bindings,
                input_blocked,
                highlighted,
                shield,
            ) = {
                let s = afklink_core::lock(&control.state);
                (
                    s.sessions
                        .iter()
                        .map(|x| (x.session_id.clone(), x.name(), x.connected))
                        .collect::<Vec<_>>(),
                    tray_status::presence(s.paused, &s.sessions, now),
                    s.connected,
                    s.refused.is_some(),
                    s.bindings_known.then(|| s.bindings.clone()),
                    s.input_blocked,
                    s.input_not_reaching,
                    capture_guard::wanted(s.pairing_panel.kind(), s.pairing_code.is_some()),
                )
            };
            // The main window out of the video while the pairing panel is open, back in after —
            // whether the window is open or not. Not under the state's lock, and not on this task:
            // handed to the main thread, which owns the window, without waiting for it — a window
            // call from here waits for the main thread, which may be waiting for the guard's lock
            // in `get_status`, and the two hang each other (`capture_guard`).
            match app.try_state::<capture_guard::CaptureGuard>() {
                Some(capture) => capture.post(&app, shield, "state watcher"),
                None => tracing::trace!("no pairing shield to keep"),
            }
            // «Управление не доходит»: the highlight goes once the window has read the driver
            // installed; the toast goes out once a session while the presses are blocked and the
            // main window is not on screen (`driver_hint`). Not under the state's lock.
            driver_hint::clear_when_installed(&control, highlighted, input_blocked);
            let live: Vec<String> = sessions.iter().map(|(id, _, _)| id.clone()).collect();
            match driver_toast.poll(input_blocked, &live, || {
                driver_hint::main_window_presence(&app)
            }) {
                driver_hint::ToastStep::Nothing => {}
                driver_hint::ToastStep::Show { sessions: due, why } => {
                    // The event bold, what to do under it; no «AFKLink» title (`toast`).
                    let lines = NativeText::NotifyDriverNeeded.toast(locale, &[]);
                    match toast::show(&app, &lines) {
                        Ok(()) => tracing::debug!(
                            sessions = ?due,
                            window = why,
                            bold = lines.event_template,
                            under = lines.detail_template.unwrap_or("-"),
                            "driver toast handed to Windows: the viewer's presses do not reach an \
                             administrator's window, and the main window is not on screen"
                        ),
                        Err(e) => tracing::warn!(
                            sessions = ?due,
                            window = why,
                            "driver toast not shown: {e}"
                        ),
                    }
                }
                driver_hint::ToastStep::HeldBack {
                    sessions: due,
                    visible_pct,
                } => tracing::debug!(
                    sessions = ?due,
                    visible_pct,
                    "driver toast held back: the main window is on screen, and its driver row \
                     says it; the toast goes out if the window leaves the screen while the \
                     presses are still blocked"
                ),
            }
            // The access list for the next launch's main view: written when the server's differs
            // from the file (`access_cache`), whether the window is open or not. Not under the
            // state's lock. Planned here (a snapshot under the cache's lock, no file), written on
            // the blocking pool: no file on this runtime's worker, and the window's `view` never
            // waits for the disk (KB-4). Not awaited here, so a slow disk does not hold the tray
            // and the toasts; the cache keeps the writes in order.
            if let Some(bindings) = &bindings {
                match app.try_state::<access_cache::AccessCache>() {
                    Some(cache) => {
                        if let Some(job) = cache.plan(bindings, true, "state watcher") {
                            write_access_cache(&app, job);
                        }
                    }
                    None => tracing::trace!("no access cache to keep"),
                }
            }
            // Not under the state's lock (`get_status` does the same). A drop shorter than
            // `OFFLINE_SHOWN_AFTER` leaves «Готов к подключению» as it is.
            let link = watch.observe(connected, refused, now, "tray");
            let presence = presence.with_link(&link);

            let edges = session_toasts.poll(sessions);
            for id in &edges.connecting {
                tracing::debug!(
                    session = %id,
                    "session started; its toast waits for the peer to connect"
                );
            }
            for id in &edges.never_connected {
                tracing::debug!(
                    session = %id,
                    "session ended before the peer connected: no toast either way"
                );
            }
            // «Вера управляет ПК» / «Вера отключается» as the toast's one bold line: no «AFKLink»
            // title over it (`toast`), no full stop. The log has the
            // template, never the name.
            for (id, name) in &edges.started {
                let lines = NativeText::NotifySessionStarted.toast(locale, &[("user", &name.text)]);
                // Someone controlling this PC, and the owner not told: a warning.
                match toast::show(&app, &lines) {
                    Ok(()) => tracing::debug!(
                        session = %id,
                        name_source = name.source.as_str(),
                        bold = lines.event_template,
                        under = lines.detail_template.unwrap_or("-"),
                        "session-started toast handed to Windows"
                    ),
                    Err(e) => {
                        tracing::warn!(session = %id, "session-started toast not shown: {e}");
                    }
                }
            }
            for (id, name) in &edges.ended {
                let lines = NativeText::NotifySessionEnded.toast(locale, &[("user", &name.text)]);
                match toast::show(&app, &lines) {
                    Ok(()) => tracing::debug!(
                        session = %id,
                        name_source = name.source.as_str(),
                        bold = lines.event_template,
                        under = lines.detail_template.unwrap_or("-"),
                        "session-ended toast handed to Windows"
                    ),
                    Err(e) => tracing::debug!(session = %id, "session-ended toast not shown: {e}"),
                }
            }
            // The tray is the always-visible surface when the window is hidden, so it answers
            // "is someone in control, and for how long" without opening anything: the menu's
            // first line, the tooltip and the icon. Worded on every poll (a few short strings),
            // handed over only when the text changes — at a connect or disconnect, and once a
            // minute while someone is connected. The same moment as the toasts: video up, not
            // merely connecting. Nobody in control: «Готов к подключению», or «Нет связи» once the
            // link has been down for `OFFLINE_SHOWN_AFTER` or is refused (`Presence::with_link`).
            let status = TrayStatus::new(locale, &presence);
            if status != last_status {
                if presence.same_people(&last_presence) {
                    tracing::debug!(
                        state = presence.kind(),
                        minutes = presence.minutes(),
                        "tray status: the connection's minute turned"
                    );
                } else {
                    tracing::debug!(
                        from = last_presence.kind(),
                        to = presence.kind(),
                        viewers = presence.name_sources().len(),
                        name_sources = ?presence.name_sources(),
                        minutes = presence.minutes(),
                        live_icon = status.live,
                        link = link.kind(),
                        link_down_ms = link.down_ms(),
                        "tray status changed: {}",
                        presence.why(&link)
                    );
                }
                match app.try_state::<tray_theme::Nudge>() {
                    Some(nudge) => nudge.status(status.clone()),
                    None => tracing::warn!(
                        state = presence.kind(),
                        "tray status not shown: no tray watcher"
                    ),
                }
                last_status = status;
                last_presence = presence;
            }
        }
    });
}

/// Session edges from one poll of the state, for the toasts.
#[derive(Debug, Default, PartialEq, Eq)]
struct SessionEdges {
    /// Newly seen while the peer is still connecting: no toast yet.
    connecting: Vec<String>,
    /// The peer connected (ICE and DTLS up, media flowing): "{name} is controlling this PC".
    started: Vec<(String, PersonName)>,
    /// Announced, and now gone: "{name} disconnected", with the name the first toast used.
    ended: Vec<(String, PersonName)>,
    /// Gone without ever connecting: nobody saw the screen, so neither toast.
    never_connected: Vec<String>,
}

/// Which sessions the toasts have announced, across polls.
///
/// The start toast says the person is controlling the PC, so it waits for `SessionInfo::connected`
/// (str0m's `Event::Connected`: ICE and DTLS up, media flowing; set once, never cleared) rather than
/// firing when capture starts. A connection that fails before that shows nothing, instead of a
/// "controlling" followed at once by a "disconnecting".
#[derive(Debug, Default)]
struct SessionToasts {
    /// Sessions whose start toast went out, with the name it used.
    announced: HashMap<String, PersonName>,
    /// Sessions seen while still connecting, not yet announced.
    connecting: HashSet<String>,
}

impl SessionToasts {
    /// Compare this poll's sessions — id, viewer name, connected — with the last one.
    fn poll(&mut self, sessions: Vec<(String, PersonName, bool)>) -> SessionEdges {
        let mut edges = SessionEdges::default();
        let present: HashSet<&str> = sessions.iter().map(|(id, _, _)| id.as_str()).collect();

        let mut ended: Vec<String> = self
            .announced
            .keys()
            .filter(|id| !present.contains(id.as_str()))
            .cloned()
            .collect();
        ended.sort();
        for id in ended {
            if let Some(name) = self.announced.remove(&id) {
                edges.ended.push((id, name));
            }
        }
        let mut never: Vec<String> = self
            .connecting
            .iter()
            .filter(|id| !present.contains(id.as_str()))
            .cloned()
            .collect();
        never.sort();
        for id in &never {
            self.connecting.remove(id);
        }
        edges.never_connected = never;

        for (id, name, connected) in sessions {
            if self.announced.contains_key(&id) {
                continue;
            }
            if connected {
                self.connecting.remove(&id);
                self.announced.insert(id.clone(), name.clone());
                edges.started.push((id, name));
            } else if self.connecting.insert(id.clone()) {
                edges.connecting.push(id);
            }
        }
        edges
    }
}

// ---------- Logging ----------

/// The app's log files — the system log and a file per session (`log_route`) — for the way out.
///
/// Set once, by `init_logging`. Closed only on the way out (`flush_log`: `RunEvent::Exit`, a panic on
/// the main thread, an exit for an update), because Tauri's event loop ends the process with `exit()`
/// and never unwinds to a local that could have held them.
static LOG_FILES: OnceLock<Arc<LogFiles>> = OnceLock::new();

/// How long the way out waits for the writer thread to put what is queued on disk: what dropping
/// tracing-appender's guard waited, before this writer replaced it.
const LOG_CLOSE_WAIT: Duration = Duration::from_secs(1);

/// The live logging setup, kept as Tauri state so Settings can change the level without a restart.
struct Logging {
    /// Swaps the filter of stdout and the file in place (`log_layers`). The layers stay put.
    filter: reload::Handle<EnvFilter, Registry>,
    /// `RUST_LOG`, when it decides the filter. The setting is still saved, and waits.
    env_override: Option<String>,
    /// The build's channel, whose default applies while nothing is chosen.
    channel: Channel,
    /// The level chosen in Settings; `None` = the channel's default. The resulting level is in
    /// effect unless `env_override` is set.
    choice: Mutex<Option<LogLevel>>,
    /// The last quarter of an hour of `debug`, in memory, for «Отправить логи» (`flight_recorder`).
    /// On unless the log is `off`; the ring holds that state itself.
    recorder: Arc<FlightRecorder>,
    /// Switches the recorder's own filter, with the ring's state.
    recorder_filter: reload::Handle<EnvFilter, Registry>,
    /// The system log and the session files: opened when the level first writes anything, told
    /// the level for their headers.
    files: Arc<LogFiles>,
    /// How many times «Выключены» was chosen this run: an automatic report opened or packed before
    /// the latest is dropped, whatever the level is now (`diagnostics::auto`).
    off_generation: std::sync::atomic::AtomicU64,
}

/// The level as a session file's header states it: the level, or the `RUST_LOG` filter that
/// overrides it.
fn level_label(level: LogLevel, env_override: Option<&str>) -> String {
    env_override.map_or_else(
        || level.as_str().to_string(),
        |spec| format!("{ENV_FILTER_VAR}={spec}"),
    )
}

/// The logging section as the window shows it: the level in effect, what config.json holds, the
/// option selected, and whether anything is written.
fn logging_dto(
    choice: Option<LogLevel>,
    channel: Channel,
    env_override: Option<String>,
    writing: bool,
    dir: Option<String>,
) -> LoggingDto {
    let level = effective_level(choice, channel);
    LoggingDto {
        level: level.as_str().to_string(),
        choice: choice.map(|c| c.as_str().to_string()),
        option: level.shown_as().as_str().to_string(),
        default_level: default_log_level(channel).as_str().to_string(),
        writing,
        env_override,
        dir,
    }
}

/// A choice for the log: the level, or that none is chosen and the channel decides.
fn choice_label(choice: Option<LogLevel>) -> &'static str {
    choice.map_or("none (the channel's)", LogLevel::as_str)
}

impl Logging {
    fn dto(&self) -> LoggingDto {
        logging_dto(
            *afklink_core::lock(&self.choice),
            self.channel,
            self.env_override.clone(),
            self.recording(),
            logs_dir().ok().map(|d| d.display().to_string()),
        )
    }

    /// Switch to `chosen` now. Persisting it is the caller's job.
    fn set_choice(&self, chosen: LogLevel) -> Result<(), String> {
        let choice = Some(chosen);
        let mut held = afklink_core::lock(&self.choice);
        let old_choice = std::mem::replace(&mut *held, choice);
        if chosen == LogLevel::Off {
            // Before anything else, `RUST_LOG` or not: the automatic reports drop what they hold.
            let generation = self
                .off_generation
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
                + 1;
            tracing::debug!(
                target: SYSTEM_TARGET,
                generation,
                "log off chosen: automatic reports opened before it are dropped"
            );
        }
        let old = effective_level(old_choice, self.channel);
        let new = effective_level(choice, self.channel);
        if let Some(spec) = &self.env_override {
            tracing::info!(
                target: SYSTEM_TARGET,
                %old,
                %new,
                choice = %choice_label(choice),
                "log level setting changed; {ENV_FILTER_VAR}={spec:?} stays in effect until the \
                 app is started without it"
            );
            return Ok(());
        }
        if old == new {
            // The build's own level picked while none was chosen (it is stored now, and stays when
            // the build's default changes), or `trace` from a hand edit kept: nothing to swap.
            tracing::debug!(
                target: SYSTEM_TARGET,
                level = %new,
                from = %choice_label(old_choice),
                to = %choice_label(choice),
                "log level choice changed; the level in effect stays"
            );
            return Ok(());
        }

        // One line naming both levels, written under whichever of the two is more verbose: before
        // the switch when going quieter (above all to `off`, which would swallow it), after it
        // when going louder. Either way it is on record if either level records `info`.
        let announce = || {
            tracing::info!(
                target: SYSTEM_TARGET,
                %old,
                %new,
                choice = %choice_label(choice),
                channel = %self.channel,
                "log level changed"
            );
        };
        if new < old {
            announce();
        }
        // `off` stops the flight recorder too, while the file still takes the line that says so.
        if new == LogLevel::Off {
            self.set_recording(false, "the log level is off");
        }
        // Opened before the reload so the first lines at the new level have somewhere to go.
        let opened = if new == LogLevel::Off {
            Ok(None)
        } else {
            ensure_log_file(&self.files)
        };
        if let Err(e) = self.filter.reload(new.filter()) {
            // The old filter is still the one installed: say so in what the window reads back.
            *held = old_choice;
            self.set_recording(old != LogLevel::Off, "the log level did not change");
            return Err(format!("reload log filter: {e}"));
        }
        // The files follow the level: `off` opens no session file and writes no last line; on
        // again, the files of the sessions live now are opened (their headers say so).
        self.files
            .set_level(level_label(new, None), new != LogLevel::Off);
        if new > old {
            announce();
        }
        report_log_file(opened);
        if new != LogLevel::Off {
            self.set_recording(true, "the log level is on");
        }
        Ok(())
    }

    /// The flight recorder, for a report.
    fn recorder(&self) -> &Arc<FlightRecorder> {
        &self.recorder
    }

    /// The log files, for a report (flushed before it reads them) and for the agent's session log.
    fn files(&self) -> &Arc<LogFiles> {
        &self.files
    }

    /// Whether the flight recorder is on.
    fn recording(&self) -> bool {
        self.recorder.is_on()
    }

    /// Whether automatic reports may record and send now: the log writes (the recorder is on), and
    /// the stored choice is not «Выключены» — also while `RUST_LOG` keeps the log on.
    fn auto_reports_on(&self) -> bool {
        let choice = *afklink_core::lock(&self.choice);
        diagnostics::auto::log_lets_auto(
            self.recording(),
            choice,
            effective_level(choice, self.channel),
        )
    }

    /// How many times the log was turned off this run.
    fn off_generation(&self) -> u64 {
        self.off_generation
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Switch the flight recorder on or off; nothing when it already is. Only [`Self::set_choice`]
    /// calls it, under the choice's lock, so two switches never interleave.
    ///
    /// Off stops and empties the ring in one step under its lock (`FlightRecorder::set_on`) — a line
    /// already past the filter on another thread is dropped, not kept after `off` — then closes the
    /// filter, which only saves formatting lines that would be dropped. On opens the ring first, so
    /// the first lines the filter lets through have somewhere to go.
    fn set_recording(&self, on: bool, why: &str) {
        if self.recorder.is_on() == on {
            tracing::trace!(target: SYSTEM_TARGET, on, why, "flight recorder already so");
            return;
        }
        if on {
            self.recorder.set_on(true);
            if let Err(e) = self.recorder_filter.reload(flight_recorder::filter(true)) {
                // Its filter still says nothing: stay off, and say so in what a report records.
                self.recorder.set_on(false);
                tracing::warn!(target: SYSTEM_TARGET, why, "flight recorder not switched on: {e}");
                return;
            }
            tracing::info!(
                target: SYSTEM_TARGET,
                why,
                window_s = flight_recorder::WINDOW.as_secs(),
                max_bytes = flight_recorder::MAX_BYTES,
                filter = %flight_recorder::RECORDING.filter_directives(),
                "flight recorder on"
            );
        } else {
            // Said first, while the file (still on at this point) takes it.
            tracing::info!(
                target: SYSTEM_TARGET,
                why,
                "flight recorder off; what it held is dropped"
            );
            let cleared = self.recorder.set_on(false);
            if let Err(e) = self.recorder_filter.reload(flight_recorder::filter(false)) {
                // Off all the same: the ring drops every line it is handed.
                tracing::warn!(target: SYSTEM_TARGET, why, "flight recorder's filter not closed: {e}");
            }
            tracing::debug!(target: SYSTEM_TARGET, cleared, "flight recorder emptied");
        }
    }
}

/// The subscriber's layers, each behind its own filter: stdout and the file behind the log level
/// (`file_filter`, swapped at runtime by [`Logging::set_choice`]), the flight recorder behind its
/// own (`recorder_filter`, [`flight_recorder::filter`]).
///
/// Two filters rather than one in front of everything, so the recorder can take `debug` while the
/// file is at `info`: the file still gets exactly what its level lets through, and nothing more.
/// Boxed in a `Vec` so both filters' reload handles name the same subscriber type (`Registry`).
fn log_layers<O, W>(
    stdout: O,
    file: W,
    file_filter: reload::Layer<EnvFilter, Registry>,
    recorder: &Arc<FlightRecorder>,
    recorder_filter: reload::Layer<EnvFilter, Registry>,
) -> Vec<Box<dyn Layer<Registry> + Send + Sync>>
where
    O: for<'w> MakeWriter<'w> + Send + Sync + 'static,
    W: for<'w> MakeWriter<'w> + Send + Sync + 'static,
{
    // The file's lines carry their target; stdout's, as before, do not.
    let stdout = tracing_subscriber::fmt::layer()
        .with_target(false)
        .with_writer(stdout);
    vec![
        stdout
            .and_then(log_file::file_layer(file))
            .with_filter(file_filter)
            .boxed(),
        log_file::file_layer(recorder.writer())
            .with_filter(recorder_filter)
            .boxed(),
    ]
}

/// Stdout plus the log files next to config.json (the system log and a file per session,
/// `log_route`), at the level from Settings.
///
/// The filter comes from [`StartupFilter`] (`RUST_LOG` if set, else `config`'s chosen
/// `log_level`, else `build`'s channel default), shared with the CLI agent so a level means the
/// same thing in both. It sits behind a reload handle: [`Logging::set_choice`] swaps it at runtime.
///
/// The release build is a `windows_subsystem = "windows"` binary whose stdout is attached to
/// nothing, so the files are the only trace on the PC. Files that cannot be opened degrade to
/// stdout only rather than stopping the agent: losing the log is bad, losing remote access over it
/// is worse.
///
/// Beside them, the flight recorder (`flight_recorder`): the last quarter of an hour of `debug` in
/// memory, whatever the level unless it is `off`, for «Отправить логи».
///
/// The first line written is `build`'s: which build and which exe on disk this run is.
fn init_logging(config: Option<&Config>, build: &BuildInfo) -> Logging {
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;

    let startup = StartupFilter::resolve(config, build.channel);
    let (filter, handle) = reload::Layer::new(startup.filter());
    // `off` — from the setting or from `RUST_LOG=off` — records nothing in memory either.
    let recording = startup.writes_anything();
    let recorder = Arc::new(FlightRecorder::new(
        flight_recorder::WINDOW,
        flight_recorder::MAX_BYTES,
    ));
    recorder.set_on(recording);
    let (recorder_filter, recorder_handle) = reload::Layer::new(flight_recorder::filter(recording));
    // The files are written off-thread and lossy by design: the writer thread absorbs a slow disk,
    // and a burst it cannot absorb drops lines rather than stalling the capture/encode threads
    // that emit them — counted, and said in the file that lost them (`log_file`).
    let files = LogFiles::new(build.label(), log_route::RouteSettings::APP);
    files.set_level(
        level_label(startup.level, startup.env_override.as_deref()),
        startup.writes_anything(),
    );
    if LOG_FILES.set(Arc::clone(&files)).is_err() {
        // A second start of logging in one process (a test): the way out closes the first files.
        tracing::debug!("log files: set up before in this process; the first set closes on exit");
    }
    if let Err(e) = tracing_subscriber::registry()
        .with(log_layers(
            std::io::stdout,
            files.writer(),
            filter,
            &recorder,
            recorder_filter,
        ))
        .try_init()
    {
        // Only if something installed a subscriber first; this line goes to that one, which is the
        // only place left that can say the file log and the level setting are not in effect.
        tracing::warn!("log subscriber not installed: {e}");
    }

    // Where the system log stands before this process writes a line to it: where the previous one
    // stopped, for an automatic report after a crash (`diagnostics::auto`). Read before the files
    // open; said once the reports start.
    diagnostics::auto::note_log_at_start(logs_dir().ok().as_deref());
    // `off` — from the setting or from `RUST_LOG=off` — means no file at all, not an empty one.
    let opened = startup.writes_anything().then(|| ensure_log_file(&files));
    // The file is open (or there is none), so this is its first line, and stdout's.
    build.log_startup("afklink-app");
    if let Some(opened) = opened {
        report_log_file(opened);
    }
    startup.log_summary();
    if recording {
        tracing::info!(
            window_s = flight_recorder::WINDOW.as_secs(),
            max_bytes = flight_recorder::MAX_BYTES,
            filter = %flight_recorder::RECORDING.filter_directives(),
            "flight recorder on: recent debug lines kept in memory for «Отправить логи», whatever \
             the file's level"
        );
    }
    if let Some(path) = config.and_then(Config::path) {
        tracing::info!("config: {}", path.display());
    }

    Logging {
        filter: handle,
        env_override: startup.env_override.clone(),
        channel: build.channel,
        choice: Mutex::new(startup.choice),
        recorder,
        recorder_filter: recorder_handle,
        files,
        off_generation: std::sync::atomic::AtomicU64::new(0),
    }
}

/// `%APPDATA%\AFKLink\logs` — the same directory `Config` and `Identity` use
/// (`afklink_core::paths::afklink_dir`), so everything this agent keeps on disk is in one place for
/// whoever has to collect it.
fn logs_dir() -> Result<PathBuf, String> {
    Ok(afklink_core::paths::afklink_dir()
        .map_err(|e| format!("{e:#}"))?
        .join("logs"))
}

/// Open the log files in [`logs_dir`] unless they are open already, and start the check for lines
/// they lose (`log_route`). `Ok(Some(dir))` when this call opened them.
fn ensure_log_file(files: &Arc<LogFiles>) -> Result<Option<PathBuf>, String> {
    files.open(&logs_dir()?)
}

/// Say where the files went, or why there are none. Logged after the fact because the "log files"
/// line should itself land in the system log.
fn report_log_file(opened: Result<Option<PathBuf>, String>) {
    use log_retention::{
        SESSIONS_DIR, SESSION_MAX_AGE_DAYS, SESSION_MAX_BYTES, SESSION_MAX_FILES, SYSTEM_LOG,
        SYSTEM_MAX_BYTES, SYSTEM_ROTATIONS,
    };
    match opened {
        Ok(Some(dir)) => tracing::info!(
            target: SYSTEM_TARGET,
            version = env!("CARGO_PKG_VERSION"),
            queue_lines = log_file::QUEUE_LINES,
            lost_lines_check_s = log_file::CHECK_EVERY.as_secs(),
            teardown_s = log_route::TEARDOWN.as_secs(),
            tail_max_s = log_route::TAIL_MAX.as_secs(),
            "log files: {dir}\\{SYSTEM_LOG} (rotated at {SYSTEM_MAX_BYTES} bytes, \
             {SYSTEM_ROTATIONS} rotations kept) and a file per session in {dir}\\{SESSIONS_DIR} \
             ({SESSION_MAX_AGE_DAYS} days, at most {SESSION_MAX_FILES} files and \
             {SESSION_MAX_BYTES} bytes kept); lines a file loses are counted and reported in it",
            dir = dir.display()
        ),
        Ok(None) => {}
        Err(e) => tracing::warn!(target: SYSTEM_TARGET, "file log unavailable, stdout only: {e}"),
    }
}

/// Close the log files on the way out — `why` goes into each open session file's last line — after
/// a last report of any lines the system log lost, and wait (at most [`LOG_CLOSE_WAIT`]) until
/// everything queued is on disk.
///
/// The router's lock is only tried, briefly: this also runs inside the panic hook, where waiting on
/// a lock is how a crash becomes a hang.
fn flush_log(why: &'static str) {
    if let Some(files) = LOG_FILES.get() {
        // Nothing to say when it did not answer: there is no file left to say it in.
        let _closed = files.shutdown(why, LOG_CLOSE_WAIT);
    }
}

/// Route panics into the log, with where they happened.
///
/// The default hook prints to stderr, which the release build does not have, so a crash left
/// nothing behind. A panic on the main thread is the event loop dying and the process with it, so
/// the queue is flushed there and then; on any other thread the process usually survives (a tokio
/// task, the encode thread) and logging has to keep working, so the guard is left alone.
fn install_panic_hook() {
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let location = info.location().map_or_else(
            || "unknown location".to_string(),
            |l| format!("{}:{}:{}", l.file(), l.line(), l.column()),
        );
        let message = info.payload_as_str().unwrap_or("non-string panic payload");
        let current = std::thread::current();
        let thread = current.name().unwrap_or("unnamed");
        // A system event: the system log has it always, a live session's file too.
        tracing::error!(target: SYSTEM_TARGET, %location, thread, "panic: {message}");
        // The main thread's panic ends the process: the next start's `last_exit` is `panic`, and its
        // `agent_crashed` names the place hashed — never the message (`afklink_core::run_state`).
        // Before the flush, so its line is in the file.
        afklink_core::run_state::record_panic(current.name(), info.location());
        // A panic inside the orchestrator's task (a runtime worker's, survived by the process): its
        // place noted for the supervisor, which relaunches the app and records it (`supervise`).
        supervise::note_panic(current.name(), info.location());
        if thread == "main" {
            flush_log("panic");
        }
        previous(info);
    }));
}

// ---------- Backend wiring ----------

fn build_backends(injector: Arc<dyn InputInjector>) -> Backends {
    Backends {
        make_capturer: Box::new(|| Ok(Box::new(WgcCapturer::new()) as Box<dyn Capturer>)),
        // «Only the game window» (Settings → the game section): the bound game's window only.
        make_game_capturer: Box::new(|request| Ok(afklink_capture::game_capturer(request))),
        make_encoder: Box::new(|| {
            Ok(Box::new(OpenH264Encoder::with_defaults()?)
                as Box<dyn afklink_core::traits::Encoder>)
        }),
        injector,
    }
}

/// `--paused` (`updater::Early::paused`, only ever with `--relaunched-from`): the process that
/// relaunched this one was paused («Прервать все сеансы») and could not write it to config.json
/// (`supervise`): this start is paused too — `config.paused`, which the agent's state starts from
/// (`AgentState::paused`) — and tries the write again.
fn take_relaunch_pause(paused: bool, config: &mut Config) {
    if !paused {
        return;
    }
    config.paused = true;
    match config.save_even_in_place() {
        Ok(saved) => tracing::info!(
            ?saved,
            "started paused (--paused, from the process that relaunched this one); the pause \
             written to config.json"
        ),
        Err(e) => tracing::warn!(
            "started paused (--paused, from the process that relaunched this one); the pause \
             not written to config.json ({e:#}): in force for this run"
        ),
    }
}

pub fn run() {
    // First of all: as the game helper's elevated setup (`--game-helper-setup` as the first
    // argument), this process does its job and ends here — no log, config, Tauri or network.
    game_helper::early();
    // Before anything else — the log, config, Tauri and its single-instance lock: the self-update's
    // flags. As the update watchdog this process never gets past here (`updater::watchdog`); as the
    // new version it first waits (bounded) for the one it replaced to be gone. Logged below.
    let early = updater::early(std::env::args_os());
    // A pre-rename install (`%APPDATA%\Remoter`) moves to `%APPDATA%\AFKLink` before anything
    // reads config, identity or the log directory from there: the same identity is the same
    // device, so the owner's bindings survive. Logged once the log exists.
    let migration = afklink_core::paths::migrate_legacy_dir();
    let build = build_info();
    // Config before logging: its `log_level` (or, with none chosen, the build's channel) decides how
    // the log is built, down to whether a file is opened at all. A config that fails to load still
    // gets a log, at the channel's default level, so the failure is on record — as is one loading
    // identity below.
    let config = Config::load_or_create();
    let logging = init_logging(config.as_ref().ok(), &build);
    install_panic_hook();
    migration.log();
    early.log();

    let mut config = config.expect("load config");
    take_relaunch_pause(early.paused(), &mut config);
    // Resolved once at startup: the tray menu is built before any window exists, and a
    // language that changes under a menu the user has open is worse than one that waits for
    // a restart. The webview reads the same value through `get_locale`.
    let locale = Locale::resolve(Some(config.lang.as_str()));
    tracing::info!("ui language: {}", locale.tag());
    // Which way to the server — the configured address or the RU entry (`afklink_core::entry`):
    // read now, so even the start failure beacon below goes the way that worked last; then the
    // agent's reconnect loop decides, and the updater and «Отправить логи» follow it.
    let entry = Arc::new(afklink_core::entry::Entry::open_default(&config.server_url));
    // Every window is WebView2. Without the runtime Tauri cannot draw one, and this GUI binary
    // would end with nothing on screen: say so in a plain message box instead, in the language
    // just resolved, and stop before anything else starts.
    match webview_runtime::probe() {
        webview_runtime::Runtime::Present { version } => {
            tracing::info!(%version, "WebView2 Runtime found");
        }
        webview_runtime::Runtime::Missing { detail } => {
            tracing::error!(
                %detail,
                url = webview_runtime::DOWNLOAD_URL,
                exit_code = webview_runtime::EXIT_NO_RUNTIME,
                "Microsoft Edge WebView2 Runtime not found: AFKLink cannot draw its windows; \
                 telling the owner and exiting"
            );
            // One beacon to the server on the way out, so a PC that cannot start is counted
            // (`start_failure`): started before the box, which waits for the person and so gives
            // the request its time, and after it waited for at most a short grace — so its outcome
            // line is in the log the flush below closes.
            let beacon = start_failure::start(
                afklink_protocol::start_failure::StartFailureReason::Webview2Missing,
                &config.server_url,
                &entry,
                &config.device_id,
                &build,
                &detail,
            );
            webview_runtime::tell_owner(locale);
            if let Some(beacon) = beacon {
                // Logged inside: sent, refused, not sent, no answer (it may have arrived), or
                // abandoned to the exit.
                beacon.finish();
            }
            flush_log("no_webview2");
            std::process::exit(webview_runtime::EXIT_NO_RUNTIME);
        }
    }
    let identity = Arc::new(Identity::load_or_create().expect("load identity"));
    // config.json is read before the log exists, so this is the line that records which config
    // and which device this run is.
    tracing::info!(
        build = %build.label(),
        pid = std::process::id(),
        device_id = %config.device_id,
        server = %config.server_url,
        // config.json held an address this build does not connect to, replaced at load
        // (`afklink_core::config`'s `server_moves_to`).
        server_moved_from = config.server_moved_from().unwrap_or("-"),
        name = %config.name,
        autostart = config.autostart,
        public_key = %identity.public_key_b64(),
        "afklink-app starting"
    );
    // The timer resolution a live peer raises, and the opt-out that keeps Windows 11 honouring it
    // while this app sits in the tray with its window hidden. Logs the policy and the system's
    // current resolution.
    afklink_transport::timer::init_process();
    // The input backend, kept as a handle in managed state so the driver-maintenance commands can
    // switch a live session's backend the moment the owner installs or removes the driver.
    let input_backend = create_input_backend();
    // «Отправить логи» signs its upload with the same key the agent answers the server with.
    // It goes the way the socket goes (the RU entry or not), and falls back to the other.
    let diagnostics = diagnostics::Diagnostics::new(Arc::clone(&identity), Arc::clone(&entry));
    // Who has access, for the main view before the server answers: nobody on a new device (this
    // launch wrote config.json, and with it the device id), else the list the server sent last time.
    let access = access_cache::AccessCache::open_default(
        &config.device_id,
        &config.server_url,
        config.created(),
    );
    // How the previous process ended (`afklink_core::run_state`), read now — reading writes nothing
    // — and claimed in `setup`, once the single-instance lock has made this the one instance: a
    // second launch, ended by the lock at once, never touches the running one's record.
    let run_state = afklink_core::run_state::RunState::open_default().map(Arc::new);
    let hello = match &run_state {
        Some(state) => state.hello(&build),
        None => afklink_transport::HelloInfo {
            build: build.wire(),
            ..Default::default()
        },
    };
    // What happened on this PC outside sessions, for the server (`afklink_core::agent_events`): the
    // queue the last run left, read now — reading writes nothing — and claimed in `setup` with the
    // run state, once this is the one instance. Sent on every connection after its handshake.
    let events = afklink_core::agent_events::EventQueue::open_default().map(Arc::new);
    // For `agent_started`: the identity made by this start, and Windows' autostart as the launcher.
    let first_run = identity.created_now();
    let autostart_launch = early.autostart();
    // The signaling socket's way: the shared entry — in a test-key build compiled with a broken
    // server address (`test_break`), an entry of its own for that address instead.
    #[cfg(feature = "updater-test-key")]
    let signaling_entry = test_break::signaling_entry(&entry, &config.server_url);
    #[cfg(not(feature = "updater-test-key"))]
    let signaling_entry = Arc::clone(&entry);
    let (agent, control) = Agent::new(config, identity, build_backends(input_backend.injector()));
    // The same injector, for the supervisor to release every key and button should the
    // orchestrator end (`supervise`).
    let supervise_injector = input_backend.injector();
    let agent = agent.with_entry(signaling_entry);
    // Access given or taken away while the app was not running is journaled and announced at the
    // first handshake, as after a reconnect: the server's first list is compared with the one
    // it sent last time.
    let agent = match access.last_list() {
        Some(list) => agent.with_last_known_bindings(list),
        None => {
            tracing::debug!(
                "access: no list from the last run to compare the first one with (none kept, or a \
                 new device)"
            );
            agent
        }
    };
    // The updater reads the same choice for the manifest and the exe.
    let updater_entry = entry;
    let agent = match &events {
        Some(queue) => agent.with_event_queue(Arc::clone(queue)),
        None => agent,
    };
    // The upgrade names this build (`AFKLink/<version> (<channel>)`, kept by the backend per device),
    // `agent_hello` the build, this process and how the last one ended, and the sessions may sync
    // the clipboard for viewers that turn it on (`afklink_core::clipboard`; never in «Только игра»).
    // And every hello the PC's hardware fingerprint (the invite-only beta): read once, on a blocking
    // thread as the agent starts (`afklink_hw`), never logged but by its parts and the VM flag.
    let agent = agent
        .with_user_agent(build.user_agent())
        .with_hello(hello)
        .with_hw_reader(Arc::new(afklink_hw::system))
        .with_clipboard(Arc::new(afklink_clipboard::SystemClipboard::new()));
    // «Запускать игру автоматически» (the game helper) is not started here but in `setup`, past
    // the single-instance lock: its signal is a named event a second launch would reset under the
    // running instance's live session.
    // Each session's lines go to a file of its own: the agent says when a session opens and ends,
    // as it happens, on the thread that does it (`log_route`).
    let agent = agent.with_session_log(Arc::clone(logging.files()) as Arc<dyn SessionLog>);
    // The connection journal beside config.json (`afklink_core::journal`): read now, with any session
    // the last process left open closed as «Приложение закрыто»; written by the agent whatever the
    // log level, read by the window («Журнал»).
    let journal = Arc::new(Journal::open_default(afklink_core::journal::now_ms()));
    let agent = agent.with_journal(Arc::clone(&journal));
    // Subscribed before the agent runs, so the updater's health watcher cannot miss the first
    // connection to the server — what a new version on probation reports to the watchdog.
    let update_events = control.subscribe();
    // And so the report's list of recent sessions cannot miss the first one.
    let session_events = control.subscribe();
    // And so a guest the owner lets in by invite as the agent connects still gets his toast.
    let guest_events = control.subscribe();
    // And so the automatic reports see the first connection (not an outage) and every session's end.
    let auto_report_events = control.subscribe();
    let launch = early.launch().clone();
    // The link to the server as the tray and the window say it, dated from now: the agent is down
    // until its first handshake, and that wait counts toward «Нет связи» like any drop.
    let link = SharedLink::new(Instant::now());
    let tray_link = link.clone();
    // Where a pairing request is shown, shared by its thread (started in `setup`), `get_status`,
    // `respond_pair` and the request window's size report.
    let (pair_prompt, pair_woken) = pair_prompt::PairPrompt::new();

    // Before the single-instance lock, which would hand this launch to a running instance and wait
    // for it without a bound: a running instance that does not answer ends this launch here, said
    // in the log (`instance_probe`).
    instance_probe::check_or_exit(|| flush_log("hung_instance"));

    tauri::Builder::default()
        .manage(control)
        .manage(link)
        .manage(pair_prompt)
        .manage(input_backend)
        .manage(locale)
        .manage(logging)
        .manage(build)
        .manage(diagnostics)
        .manage(journal)
        .manage(home::HomeLog::default())
        .manage(access)
        // The main window out of the video while the pairing panel is open.
        .manage(capture_guard::CaptureGuard::default())
        // The text size the main window is sized for (`window_fit`).
        .manage(window_fit::MainWindowText::default())
        // One running agent. The plugin's own setup runs in `build`, before ours: in a second launch
        // it finds the lock taken, hands the running instance this launch's argv/cwd (both ignored
        // there — a second launch carries no new intent, it just surfaces the window), waits for it
        // to take them and ends this process; in the first it takes the lock. Everything above this
        // builder runs in both processes before that handover, so what is this process's alone —
        // the run state, the event queue, the game helper's signal — is claimed or made in `setup`.
        // (Should the lock be taken but the running instance's window not be found, the plugin lets
        // this launch run on.)
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            focus_main(app);
        }))
        .setup(move |app| {
            // Before anything else: this is the main thread (Tauri runs `setup` on its event loop),
            // which code called from anywhere asks about before a window call (`main_thread`).
            main_thread::note();
            // «Запускать игру автоматически»: the helper's signal (not set until a session is live
            // and the installation matches), its installation read, its and its setup's logs
            // mirrored into this one. Made only now, past the single-instance lock, as the one
            // instance: made in `run`, a second launch would reset the running instance's signal
            // before handing over. First in `setup`, so it is managed before the tray, the
            // windows' events or anything else can reach a command that reads it.
            tracing::debug!(
                pid = std::process::id(),
                "game helper: started in setup, past the single-instance lock — the one instance \
                 makes its signal now"
            );
            if !app.manage(game_helper::GameHelper::start(app)) {
                tracing::error!(
                    "game helper: one was managed already; this second one is dropped, its thread \
                     left running"
                );
            }
            // First, while the window has hardly been drawn: sized for Windows' text size (at
            // 100 % nothing changes), then inside its monitor's work area — left where Windows put
            // it when it is, centred (and shorter, when it must be) when it is not
            // (`window_fit`).
            window_fit::fit_main_window(app.handle());

            // The one instance now (the single-instance lock is past): this process's run state
            // is its own from here — running, kept alive every minute, its exit recorded on the
            // way out. Logs how the previous process ended.
            match &run_state {
                Some(state) => state.claim(),
                None => tracing::warn!(
                    "run state: none to claim; the next start will not know how this one ended"
                ),
            }
            // The event queue is this process's too, from here: this start — and the last one's
            // panic, when it ended in one — go into it first (`afklink_core::agent_events`).
            match &events {
                Some(queue) => {
                    afklink_core::agent_events::install(Arc::clone(queue));
                    match &run_state {
                        Some(state) => afklink_core::agent_events::record_start(
                            state,
                            &app.state::<BuildInfo>(),
                            first_run,
                            autostart_launch,
                        ),
                        None => tracing::debug!(
                            "agent events: no run state, so no agent_started (it needs the boot \
                             id and the last exit)"
                        ),
                    }
                }
                None => tracing::warn!(
                    "agent events: no queue; this PC's events (starts, updates, the driver, \
                     settings) are not sent"
                ),
            }

            // Run the orchestrator on Tauri's async runtime, supervised: an end while the app is not
            // leaving relaunches the app, within a limit (`supervise`). Its steps are read by the
            // stall watch (started last, below).
            let steps = agent.step_watch();
            // A `dev-fault` build of the dev channel may be told to fail its orchestrator on
            // purpose, to try the supervision by hand (`dev_fault`); any other build has no such
            // path.
            #[cfg(feature = "dev-fault")]
            let run = {
                let fault = dev_fault::from_env(app.state::<BuildInfo>().channel);
                dev_fault::run_with(agent.run(), fault)
            };
            #[cfg(not(feature = "dev-fault"))]
            let run = {
                let run = agent.run();
                async move { run.await.map_err(|e| format!("{e:#}")) }
            };
            supervise::spawn(
                app.handle().clone(),
                app.state::<AgentControl>().inner().clone(),
                supervise_injector,
                run,
            );
            // The goodbye to the backend when Windows ends the session or goes to sleep, and the
            // reconnect when it comes back (`system_events`).
            system_events::start(app.state::<AgentControl>().inner().clone());
            app.state::<diagnostics::Diagnostics>()
                .track_sessions(session_events);
            // The automatic report after a crash, an outage, a failed session or a hang
            // (`diagnostics::auto`): one task on the runtime; the previous run's end decides the
            // first.
            diagnostics::auto::start(
                app.handle().clone(),
                auto_report_events,
                run_state.as_ref().map(|state| state.last_exit()),
            );

            // System tray. These strings are drawn by Windows, not by the webview, so they come
            // from the generated Rust dictionary rather than @afklink/i18n — same source file,
            // emitted into `afklink_i18n::generated`.
            //
            // First, who is in control right now («Вера управляет · 12 мин»); clicking it opens the
            // window, as «Открыть окно» does. Rewritten by the tray's thread whenever the state
            // watcher's text changes. Windows does not redraw an open menu, so a minute that turns
            // while it is open shows on the next opening. Built idle and not paused: nobody can be
            // connected before the orchestrator has started; a pause kept in config.json from the last
            // run (`Config::paused`) is in the state already, and the watcher's first look (half a
            // second) puts «Возобновить» in place and says it on the status line.
            // Idle is «Готов к подключению» although the handshake is still to come: a drop is said
            // only after `OFFLINE_SHOWN_AFTER`, counted from the launch too, so a normal launch
            // (connected in about a second) never changes the text.
            let initial_presence = Presence::Idle;
            let initial_status = TrayStatus::new(locale, &initial_presence);
            let status_item = MenuItem::with_id(
                app,
                "status",
                initial_status.menu_text.as_str(),
                true,
                None::<&str>,
            )?;
            let separator = PredefinedMenuItem::separator(app)?;
            let show = MenuItem::with_id(
                app,
                "show",
                NativeText::TrayShow.t(locale),
                true,
                None::<&str>,
            )?;
            let kill = MenuItem::with_id(
                app,
                "kill",
                NativeText::TrayKill.t(locale),
                true,
                None::<&str>,
            )?;
            // «Возобновить» takes the kill switch's place while the PC is paused (the tray's thread
            // swaps them), so the owner who paused from the tray can resume from it too. Created
            // now, shown only then.
            let resume = MenuItem::with_id(
                app,
                "resume",
                NativeText::TrayResume.t(locale),
                true,
                None::<&str>,
            )?;
            let quit = MenuItem::with_id(
                app,
                "quit",
                NativeText::TrayQuit.t(locale),
                true,
                None::<&str>,
            )?;
            let menu = Menu::with_items(app, &[&status_item, &separator, &show, &kill, &quit])?;

            let mut tray = TrayIconBuilder::with_id(tray_theme::TRAY_ID)
                .tooltip(initial_status.tooltip.as_str())
                .menu(&menu)
                .on_menu_event(|app, event| match event.id.as_ref() {
                    "show" => {
                        tracing::debug!("tray: show window");
                        focus_main(app);
                    }
                    "status" => {
                        tracing::debug!("tray: status line clicked; showing the window");
                        focus_main(app);
                    }
                    "kill" => {
                        if let Some(control) = app.try_state::<AgentControl>() {
                            let paused = afklink_core::lock(&control.state).paused;
                            tracing::debug!(paused, "tray: «Приостановить доступ» pressed");
                            send_command(&control, AgentCommand::KillSwitch, "tray");
                        } else {
                            tracing::error!("tray: kill switch pressed, but the agent is not running");
                        }
                    }
                    "resume" => {
                        if let Some(control) = app.try_state::<AgentControl>() {
                            let paused = afklink_core::lock(&control.state).paused;
                            tracing::info!(paused, "owner pressed Resume in the tray");
                            send_command(&control, AgentCommand::Resume, "tray");
                        } else {
                            tracing::error!("tray: Resume pressed, but the agent is not running");
                        }
                    }
                    "quit" => {
                        tracing::info!(target: SYSTEM_TARGET, "tray: quit");
                        app.exit(0);
                    }
                    other => tracing::debug!(item = other, "tray: unknown menu item"),
                });

            // The tray's own one-colour icon, in the taskbar's ink and at the notification area's
            // pixel size (see `tray_theme`). The tray is the only way to reach the kill switch
            // once the window is hidden, so an icon that fails to load must not stop it from
            // existing: the app icon is the fallback, the platform default the last resort —
            // ugly, not fatal.
            let tray_icon = tray_theme::initial_choice(app.handle());
            match tray_theme::image(tray_icon) {
                Ok(icon) => tray = tray.icon(icon),
                Err(e) => {
                    tracing::warn!(icon = %tray_icon, "tray icon not decoded: {e}; using the app icon");
                    match app.default_window_icon() {
                        Some(icon) => tray = tray.icon(icon.clone()),
                        None => tracing::warn!("no bundled window icon; tray uses the platform default"),
                    }
                }
            }
            let _tray = tray.build(app)?;
            // Keeps that icon in step when the taskbar turns light or dark, or the scale changes,
            // and puts who is in control on the tray: the status line, the tooltip, the live icon,
            // «Возобновить» while paused.
            app.manage(tray_theme::spawn_watcher(
                app.handle().clone(),
                tray_icon,
                initial_status.clone(),
                tray_theme::TrayMenu {
                    menu: menu.clone(),
                    status: status_item.clone(),
                    kill: kill.clone(),
                    resume,
                },
            ));

            // The request window: its translated title (taskbar, Alt+Tab) and, on Windows 10, no
            // frame shadow (`pair_prompt::setup_window`).
            pair_prompt::setup_window(app.handle(), locale);

            // config.json is the source of truth for the autostart checkbox; the OS entry follows
            // it, and points at this exe — checked on every launch, so an exe that was moved or
            // renamed, a plugin-era entry, or one switched off in Task Manager is dealt with
            // (`autostart`). Failures only warn: a wrong startup entry must not stop the agent.
            autostart::reconcile_at_startup(&app.state::<AgentControl>());

            // Toasts from an exe outside target\debug and target\release — the portable one — go out
            // under `identifier` (`com.afklink.agent`), which no installer has registered with
            // Windows: registered here at every start, before the state watcher below can send the
            // first one. The log says which name this exe's toasts use. Failures only warn.
            let tauri_config = app.config();
            toast_identity::register_at_startup(
                &tauri_config.identifier,
                tauri_config.product_name.as_deref(),
            );

            // Ambient signals for the tray-hidden case. The main window polls the
            // same state for its own rendering; this task is the other half of that
            // contract: session arrivals/departures get toasts. Rare and
            // security-relevant — they deserve to reach the owner with windows closed.
            spawn_state_watcher(
                app.handle().clone(),
                locale,
                tray_link,
                (initial_presence, initial_status),
            );
            // A pairing decision goes to the request window near the tray, always on top, whether
            // the main window is open or not.
            pair_prompt::spawn(app.handle().clone(), locale, pair_woken);
            // A guest the owner let in from Telegram by his invite: «Новый гость: {user}» at once,
            // whether the main window is open or not. After the toasts' name is
            // registered above; the events wait in the channel until then.
            guest_toast::spawn(app.handle().clone(), locale, guest_events);

            // An update or a rollback started by the watchdog while the window was hidden (in the
            // tray) keeps it hidden: an update at night leaves nothing on the desktop.
            if launch.hidden() {
                match app.get_webview_window("main") {
                    Some(w) => match w.hide() {
                        Ok(()) => tracing::debug!(launch = launch.kind(), "main window starts hidden"),
                        Err(e) => tracing::warn!("main window not hidden at start: {e}"),
                    },
                    None => tracing::warn!("no main window to hide at start"),
                }
            }

            // Self-update: the health watcher (a new version reports its first connection to the
            // watchdog) and, in a release build with a key, the check/download/apply loop.
            let control = app.state::<AgentControl>().inner().clone();
            let updater = updater::start(
                app.handle(),
                control,
                &app.state::<BuildInfo>(),
                launch,
                update_events,
                locale,
                updater_entry,
            );
            app.manage(updater);

            // Last, so `setup` itself is not taken for a stall (the main thread is back in its event
            // loop once this returns): the watch on it and on the async runtime, which says in the
            // log when either stops answering, or the orchestrator stays in one step; and which
            // nudges the runtime from outside (`stall_watch`).
            stall_watch::start(app.handle(), steps);

            Ok(())
        })
        .plugin(tauri_plugin_notification::init())
        .on_window_event(|window, event| {
            match event {
                tauri::WindowEvent::CloseRequested { api, .. } => {
                    match window.label() {
                        // The tray keeps the app reachable, so closing a window parks
                        // it instead of destroying it — otherwise "Show window" would
                        // have nothing to show, and a dismissed prompt would take its
                        // window with it while the request is still pending (it comes
                        // back when the main window is opened: `PairPrompt::reveal`).
                        "main" | "pair-request" => {
                            api.prevent_close();
                            if let Err(e) = window.hide() {
                                tracing::debug!(window = window.label(), "window not hidden: {e}");
                            }
                            tracing::debug!(window = window.label(), "window closed: parked in the tray");
                            if window.label() == pair_prompt::WINDOW {
                                if let Some(prompt) = window.try_state::<pair_prompt::PairPrompt>() {
                                    prompt.parked();
                                }
                            }
                        }
                        other => tracing::debug!(window = other, "window closing"),
                    }
                }
                // Windows broadcasts a theme change to every top-level window, hidden ones too: the
                // moment to re-check the tray icon rather than wait for the watcher's next tick.
                tauri::WindowEvent::ThemeChanged(theme) => {
                    tracing::debug!(window = window.label(), ?theme, "window theme changed");
                    if let Some(nudge) = window.try_state::<tray_theme::Nudge>() {
                        nudge.send("theme changed");
                    }
                }
                tauri::WindowEvent::ScaleFactorChanged { scale_factor, .. } => {
                    tracing::debug!(window = window.label(), scale_factor, "window scale changed");
                    if let Some(nudge) = window.try_state::<tray_theme::Nudge>() {
                        nudge.send("scale changed");
                    }
                }
                // A click into the main window while a request waits brings a request window closed by
                // hand back, as opening the main window from the tray does: the main screen's steps
                // point at it (step 3), and it is answerable nowhere else. `reveal` says
                // whether there was one to bring back.
                tauri::WindowEvent::Focused(true) if window.label() == "main" => {
                    if let Some(prompt) = window.try_state::<pair_prompt::PairPrompt>() {
                        prompt.reveal("main window focused");
                    }
                }
                _ => {}
            }
        })
        .invoke_handler(tauri::generate_handler![
            get_status,
            request_pairing,
            cancel_pairing,
            respond_pair,
            unbind,
            make_owner,
            cancel_owner_request,
            kill_switch,
            resume_sessions,
            set_name,
            retry_connection,
            set_autostart,
            answer_autostart_offer,
            journal_view::get_journal,
            get_locale,
            set_lang,
            get_logging,
            set_log_level,
            open_logs_dir,
            diagnostics::send_logs,
            get_build_info,
            pair_prompt::fit_pair_window,
            pair_prompt::allow_pair,
            pair_prompt::show_pair_request,
            window_fit::main_window_ratio,
            fakerinput_setup::get_fakerinput_status,
            fakerinput_setup::install_fakerinput,
            fakerinput_setup::uninstall_fakerinput,
            fakerinput_setup::reinstall_fakerinput,
            game_only::get_game_only,
            game_helper::set_game_helper,
            game_helper::update_game_helper,
            game_helper::apply_found_launch,
            game_helper::choose_game_launch,
            game_only::set_game_only,
            game_only::set_game_only_for_guests,
            game_only::list_game_windows,
            game_only::set_game_window,
            updater::get_update_status,
            updater::check_for_updates,
            updater::apply_update,
            updater::set_auto_update
        ])
        .build(tauri::generate_context!())
        .expect("error while building AFKLink")
        .run(|app, event| {
            // From here an end of the orchestrator is part of the exit, not a failure to relaunch
            // the app for (`supervise`).
            if let tauri::RunEvent::ExitRequested {
                code: exit_code, ..
            } = &event
            {
                tracing::debug!(?exit_code, "exit requested");
                supervise::leaving("exit requested");
            }
            // The event loop ends the process without unwinding, so this is the last point at
            // which the lines still queued for the file can be written.
            if let tauri::RunEvent::Exit = event {
                supervise::leaving("exit");
                tracing::info!(target: SYSTEM_TARGET, "exiting");
                // The main thread spends what is left in the goodbye and the files below: no stall.
                stall_watch::stop("exit");
                // First, while the network is surely up: every live session ended properly — its
                // final report and `session_end agent_ended`, so the viewer hears it ended and the
                // server gets the agent's final rather than `agent_disconnected` — then the goodbye,
                // so «Мои ПК» shows this PC offline now rather than after the backend's heartbeat.
                // `quit` for the owner's «Выход»; a shutdown (tao ends its loop on WM_ENDSESSION) or
                // an update did both already and find nothing left. Bounded by the budgets
                // (`EXIT_END_BUDGET`, `GOODBYE_BUDGET`), and logged.
                match app.try_state::<AgentControl>() {
                    Some(control) => {
                        let reason = system_events::exit_reason();
                        let outcome =
                            control.leave_blocking(reason, afklink_core::GOODBYE_BUDGET);
                        tracing::debug!(
                            reason = reason.as_str(),
                            outcome = outcome.kind(),
                            "exit: goodbye done"
                        );
                    }
                    None => tracing::warn!("no agent at exit: no goodbye to the backend"),
                }
                // Sessions going on end with the process: «Приложение закрыто» in the journal, now
                // rather than at the next start.
                match app.try_state::<Arc<Journal>>() {
                    Some(journal) => journal.app_closing(afklink_core::journal::now_ms()),
                    None => tracing::warn!("no connection journal to close at exit"),
                }
                // A change of the access list in the watcher's last half second, or a write the
                // watcher planned that the blocking pool has not done yet, still reaches the next
                // launch's main view. Written here, on the main thread at exit (the window is gone),
                // after the agent's state is copied out and its lock let go.
                match (
                    app.try_state::<access_cache::AccessCache>(),
                    app.try_state::<AgentControl>(),
                ) {
                    (Some(cache), Some(control)) => {
                        let (bindings, heard) = {
                            let s = afklink_core::lock(&control.state);
                            (s.bindings.clone(), s.bindings_known)
                        };
                        cache.sync(&bindings, heard, access_cache::FROM_EXIT);
                    }
                    _ => tracing::warn!("no access cache or agent at exit: the cache is not checked"),
                }
                // A new version on probation tells its watchdog this is a clean exit, not a crash —
                // unless the supervisor ends it because its orchestrator ended (`supervise`).
                updater::on_exit(supervise::abnormal_exit());
                // The next start's `last_exit` (`afklink_core::run_state`): a shutdown's when
                // Windows is ending the session, else the owner's quit — and an update's exit,
                // recorded before it, stands.
                let (kind, why) = match system_events::exit_reason() {
                    afklink_core::GoodbyeReason::Shutdown => (
                        afklink_core::run_state::ExitKind::OsShutdown,
                        "exit: Windows ends the session",
                    ),
                    _ => (afklink_core::run_state::ExitKind::App, "exit"),
                };
                afklink_core::run_state::record_exit(kind, why);
                flush_log("app_exit");
            }
        });
}

#[cfg(test)]
mod relaunch_pause_tests {
    use super::*;

    /// Item 3: `--paused` reaches the config the agent's state starts from (`config.paused` →
    /// `AgentState::paused`, `afklink_core`'s `the_pause_outlives_a_restart_until_the_owner_resumes`)
    /// only with `--relaunched-from`, and is written to the file; alone it is ignored.
    #[test]
    fn paused_from_a_relaunch_only_reaches_the_config() {
        let dir = std::env::temp_dir().join(format!("afklink-app-paused-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("test dir");
        let path = dir.join("config.json");
        // This process's own id: nothing is waited for (`updater::RelaunchWait::OwnPid`).
        let own = std::process::id().to_string();
        let cases: [(&[&str], bool); 3] = [
            (
                &["afklink-app.exe", "--paused", "--relaunched-from", &own],
                true,
            ),
            (&["afklink-app.exe", "--paused"], false),
            (&["afklink-app.exe", "--relaunched-from", &own], false),
        ];
        for (args, paused) in cases {
            let _ = std::fs::remove_file(&path);
            let early = updater::early(args.iter().map(std::ffi::OsString::from));
            assert_eq!(early.paused(), paused, "{args:?}");
            let mut config = Config::load_or_create_at(path.clone()).expect("config");
            assert!(!config.paused);
            take_relaunch_pause(early.paused(), &mut config);
            assert_eq!(config.paused, paused, "{args:?}");
            let on_disk = Config::load_or_create_at(path.clone()).expect("reloads");
            assert_eq!(on_disk.paused, paused, "on disk: {args:?}");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[cfg(test)]
mod logging_tests {
    use super::*;
    use afklink_core::logging::RELEASE_PHASE;

    /// The whole lifecycle in one test, because a process gets one global subscriber: `off` from
    /// launch creates nothing, switching on at runtime opens the file, the change is announced on
    /// the side of each switch where it can be recorded, third-party debug stays out, «Обычные»
    /// keeps `info` in the file and `debug` in memory, and `off` writes nothing again.
    #[test]
    fn level_switches_at_runtime_and_off_writes_nothing() {
        let appdata = std::env::temp_dir().join(format!("afklink-app-log-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&appdata);
        std::fs::create_dir_all(appdata.join("AFKLink")).unwrap();
        // Safe on edition 2021, and this is the only test in this binary that reads either.
        std::env::set_var("APPDATA", &appdata);
        std::env::remove_var(ENV_FILTER_VAR);
        let mut config =
            Config::load_or_create_at(appdata.join("AFKLink").join("config.json")).unwrap();
        config.log_level = Some(LogLevel::Off.as_str().to_string());

        let build = BuildInfo::from_stamp(
            "0.1.0",
            "3a3bc46e0f1d2c3b4a5968778695a4b3c2d1e0f9",
            "0",
            "2026-09-28T20:15:07Z",
            "release",
        );
        let logging = init_logging(Some(&config), &build);
        let recorded =
            || String::from_utf8(logging.recorder().snapshot(Instant::now()).0).expect("utf-8");
        let dto = logging.dto();
        assert_eq!(
            (dto.choice.as_deref(), dto.option.as_str(), dto.writing),
            (Some("off"), "off", false)
        );
        assert!(!logging.recording(), "off records nothing in memory either");
        tracing::error!("written while off");
        let logs = appdata.join("AFKLink").join("logs");
        assert!(!logs.exists(), "off must not create the log directory");
        assert!(!recorded().contains("written while off"));

        // «Подробные».
        logging.set_choice(LogLevel::Debug).unwrap();
        let dto = logging.dto();
        assert_eq!(
            (dto.level.as_str(), dto.option.as_str(), dto.writing),
            ("debug", "debug", true)
        );
        assert!(logging.recording(), "a level turns the flight recorder on");
        tracing::debug!("ours at debug");
        tracing::debug!(target: "str0m::rtp", "theirs at debug");
        tracing::warn!(target: "str0m::rtp", "theirs at warn");

        // «Обычные»: the file at info; the recorder keeps debug all the same.
        logging.set_choice(LogLevel::Info).unwrap();
        assert_eq!(logging.dto().choice.as_deref(), Some("info"));
        tracing::info!("ours at info under info");
        tracing::debug!("ours at debug under info");
        let kept = recorded();
        assert!(kept.contains("ours at info under info"), "{kept}");
        assert!(kept.contains("ours at debug under info"), "{kept}");
        assert!(!kept.contains("theirs at debug"), "{kept}");
        // Picked again: nothing to swap.
        logging.set_choice(LogLevel::Info).unwrap();

        // «Выключены».
        logging.set_choice(LogLevel::Off).unwrap();
        tracing::error!("written after off");
        // `off` empties the recorder and keeps it empty.
        assert!(!logging.recording());
        assert!(!logging.dto().writing);
        assert_eq!(recorded(), "", "off keeps nothing in memory");
        flush_log("app_exit");

        // No session: the system log is the only file.
        let names: Vec<String> = std::fs::read_dir(&logs)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, ["system.log"]);
        let text = std::fs::read_to_string(logs.join("system.log")).unwrap();
        let _ = std::fs::remove_dir_all(&appdata);

        assert!(text.contains("log files: "), "{text}");
        assert!(
            text.contains(" INFO afklink_app_lib::system: log level changed"),
            "settings changes are system events: {text}"
        );
        assert!(
            text.contains("log level changed old=off new=debug choice=debug"),
            "{text}"
        );
        assert!(text.contains("ours at debug"), "{text}");
        assert!(text.contains("theirs at warn"), "{text}");
        assert!(!text.contains("theirs at debug"), "{text}");
        assert!(
            text.contains("log level changed old=debug new=info choice=info channel=release"),
            "{text}"
        );
        assert!(text.contains("ours at info under info"), "{text}");
        assert!(!text.contains("ours at debug under info"), "{text}");
        assert!(text.contains("flight recorder on"), "{text}");
        assert!(text.contains("flight recorder off"), "{text}");
        assert!(
            text.contains("log level changed old=info new=off choice=off"),
            "{text}"
        );
        assert!(!text.contains("written while off"), "{text}");
        assert!(!text.contains("written after off"), "{text}");
    }

    /// The level in effect, what config.json holds and the option selected, on both channels: with
    /// nothing chosen the build's default is selected (no «Automatic»); `trace` from a hand
    /// edit shows as «Подробные».
    #[test]
    fn the_dto_names_the_choice_the_level_and_the_option_selected() {
        let release = RELEASE_PHASE.default_log_level().as_str();
        let row = |dto: LoggingDto| {
            (
                dto.choice,
                dto.level,
                dto.option,
                dto.default_level,
                dto.writing,
            )
        };
        let s = |v: &str| v.to_string();
        assert_eq!(
            row(logging_dto(None, Channel::Release, None, true, None)),
            (None, s(release), s(release), s(release), true)
        );
        assert_eq!(
            row(logging_dto(None, Channel::Dev, None, true, None)),
            (None, s("debug"), s("debug"), s("debug"), true)
        );
        assert_eq!(
            row(logging_dto(
                Some(LogLevel::Info),
                Channel::Release,
                None,
                true,
                None
            )),
            (Some(s("info")), s("info"), s("info"), s(release), true)
        );
        assert_eq!(
            row(logging_dto(
                Some(LogLevel::Trace),
                Channel::Dev,
                None,
                true,
                None
            )),
            (Some(s("trace")), s("trace"), s("debug"), s("debug"), true)
        );
        assert_eq!(
            row(logging_dto(
                Some(LogLevel::Off),
                Channel::Dev,
                None,
                false,
                None
            )),
            (Some(s("off")), s("off"), s("off"), s("debug"), false)
        );
    }

    #[test]
    fn set_log_level_takes_the_three_levels_and_nothing_else() {
        assert_eq!(parse_offered_level("debug"), Ok(LogLevel::Debug));
        assert_eq!(parse_offered_level("info"), Ok(LogLevel::Info));
        assert_eq!(parse_offered_level("off"), Ok(LogLevel::Off));
        assert_eq!(parse_offered_level(" Debug "), Ok(LogLevel::Debug));
        for refused in ["trace", "warn", "error", "auto", "chatty", ""] {
            assert!(parse_offered_level(refused).is_err(), "{refused}");
        }
    }
}

/// The names the window gets are cleaned as the toasts' are.
#[cfg(test)]
mod name_dto_tests {
    use super::*;
    use afklink_core::owner_request::OwnerRequests;

    fn request(
        first_name: Option<&str>,
        username: Option<&str>,
    ) -> afklink_core::agent::PendingPair {
        afklink_core::agent::PendingPair {
            request_id: "7c4b1e90-2a3d-4f51-9b8e-6d5c4a3b2f10".into(),
            telegram_user_id: 5_000_000_001,
            username: username.map(str::to_string),
            first_name: first_name.map(str::to_string),
            expires_at: 1,
            has_owner: Some(true),
            link: afklink_core::pairing::PairLink::Live,
        }
    }

    /// The request window: bidi controls and invisible characters gone from both names, padding
    /// trimmed, the stored `@` dropped; a name of them alone is no name, and the label falls back as
    /// the toast's does.
    #[test]
    fn the_request_windows_names_are_cleaned() {
        let dto = pending_pair_dto(&request(
            Some("\u{202E}амаМ\u{200B} "),
            Some(" @ma\u{2060}ma "),
        ));
        assert_eq!(dto.first_name.as_deref(), Some("амаМ"));
        assert_eq!(dto.username.as_deref(), Some("mama"));
        assert_eq!(dto.display_name, "амаМ (@mama)");

        // «Мама» with no @username: the window shows `#id` beside it (the UI), so no handle here.
        let dto = pending_pair_dto(&request(Some("Мама"), None));
        assert_eq!(
            (dto.first_name.as_deref(), dto.username),
            (Some("Мама"), None)
        );
        assert_eq!(dto.telegram_user_id, 5_000_000_001);

        // Fillers only: no first name, no username — the label is the id.
        let dto = pending_pair_dto(&request(Some("\u{3164}\u{115F}"), Some("\u{200B}")));
        assert_eq!((dto.first_name, dto.username), (None, None));
        assert_eq!(dto.display_name, "#5000000001");
    }

    /// «Доступ»: the same cleaning for every row, the role and the id as they were.
    #[test]
    fn the_access_lists_names_are_cleaned() {
        let requests = OwnerRequests::default();
        let row = |first: Option<&str>, user: Option<&str>| {
            binding_dto(
                &access_cache::CachedBinding {
                    telegram_user_id: 42,
                    first_name: first.map(str::to_string),
                    username: user.map(str::to_string),
                    role: Some(afklink_core::BindingRole::Guest),
                },
                &requests,
            )
        };
        let dto = row(Some("\u{2066}Друг\u{2069}"), Some("@friend\u{FEFF}"));
        assert_eq!(dto.first_name.as_deref(), Some("Друг"));
        assert_eq!(dto.username.as_deref(), Some("friend"));
        assert_eq!((dto.telegram_user_id, dto.role), (42, Some("guest")));
        let dto = row(Some("   "), Some(""));
        assert_eq!((dto.first_name, dto.username), (None, None));
        let dto = row(Some("Вера\nМ"), None);
        assert_eq!(dto.first_name.as_deref(), Some("Вера М"));
    }
}

#[cfg(test)]
mod owner_request_tests {
    use super::*;
    use afklink_core::owner_request::OwnerRequests;
    use afklink_core::OwnerRequestKind;

    const T0: i64 = 1_789_600_000_000;

    /// The row the request is about carries it, in flight or ended; every other row nothing.
    #[test]
    fn a_rows_request_is_its_own() {
        let mut r = OwnerRequests::default();
        assert_eq!(owner_request_dto(&r, 7), None);
        r.ask(OwnerRequestKind::MakeOwner, 7, T0);
        assert_eq!(
            owner_request_dto(&r, 7),
            Some(OwnerRequestDto {
                kind: "make_owner",
                stage: "asked",
                owner_asked: false,
                expires_at: None,
                outcome: None,
            })
        );
        assert_eq!(owner_request_dto(&r, 8), None);
        // A second press elsewhere: its row says «Уже есть запрос», the first carries on.
        r.ask(OwnerRequestKind::UnbindOwner, 8, T0);
        assert_eq!(
            owner_request_dto(&r, 8),
            Some(OwnerRequestDto {
                kind: "unbind_owner",
                stage: "ended",
                owner_asked: false,
                expires_at: None,
                outcome: Some("busy"),
            })
        );
        assert_eq!(owner_request_dto(&r, 7).map(|d| d.stage), Some("asked"));
    }

    /// «Назначить владельцем» on a PC with no owner must not show «Ждём подтверждения» with nobody
    /// to confirm. The window says it only for `owner_asked`, which a request is only once the
    /// server opened it (`pending`); `applied` leaves the row nothing.
    #[test]
    fn the_window_is_told_the_owner_was_asked_only_once_the_server_opened_it() {
        use afklink_core::owner_request::{InFlight, Stage};
        use afklink_protocol::OwnerRequestState;
        let mut r = OwnerRequests::default();
        r.ask(OwnerRequestKind::MakeOwner, 7, T0);
        assert_eq!(owner_request_dto(&r, 7).map(|d| d.owner_asked), Some(false));
        r.on_state(
            Some("e1f2a3b4-c5d6-4e7f-8a9b-0c1d2e3f4a5b"),
            OwnerRequestKind::MakeOwner.into(),
            7,
            OwnerRequestState::Applied,
            None,
            None,
            None,
            T0 + 300,
        );
        assert_eq!(owner_request_dto(&r, 7), None, "applied: the role says it");

        // With an owner, the server's `pending` is the question asked.
        r.ask(OwnerRequestKind::MakeOwner, 7, T0 + 1_000);
        r.on_state(
            Some("e1f2a3b4-c5d6-4e7f-8a9b-0c1d2e3f4a5b"),
            OwnerRequestKind::MakeOwner.into(),
            7,
            OwnerRequestState::Pending,
            Some(T0 + 601_000),
            None,
            None,
            T0 + 1_300,
        );
        assert_eq!(
            owner_request_dto(&r, 7),
            Some(OwnerRequestDto {
                kind: "make_owner",
                stage: "pending",
                owner_asked: true,
                expires_at: Some(T0 + 601_000),
                outcome: None,
            })
        );
        assert!(r.in_flight_for(7).is_some_and(InFlight::owner_asked));
        assert_eq!(r.in_flight_for(7).map(|c| c.stage), Some(Stage::Pending));
    }

    /// `pc_allow`: the newcomer has a row of their own — named,
    /// cleaned as every name, «Ждём подтверждения» with the owner's deadline — until the list has
    /// them; then the request, and how it ended, is on their binding's row. An ending other than
    /// «Разрешить» stays on the newcomer's row while it is shown, then the row goes.
    #[test]
    fn a_pairing_held_for_the_owner_has_a_row_until_the_list_has_the_newcomer() {
        use afklink_core::owner_request::Newcomer;
        use afklink_core::OwnerStateKind;
        use afklink_protocol::OwnerRequestState;
        const ID: &str = "5e6f7a8b-9c0d-4e1f-a2b3-c4d5e6f7a8b9";
        const NEWCOMER: i64 = 35791;
        let state = |r: &mut OwnerRequests, state: OwnerRequestState, now: i64| {
            r.on_state(
                Some(ID),
                OwnerStateKind::PcAllow,
                NEWCOMER,
                state,
                (state == OwnerRequestState::Pending).then_some(T0 + 600_000),
                None,
                Some(Newcomer {
                    username: Some(" @va\u{200B}sya ".into()),
                    first_name: Some("\u{202E}Вася".into()),
                }),
                now,
            );
        };
        let owner = access_cache::CachedBinding {
            telegram_user_id: 12345,
            first_name: Some("Я".into()),
            username: None,
            role: Some(afklink_core::BindingRole::Owner),
        };
        let mut r = OwnerRequests::default();
        assert_eq!(held_pair_dto(&r, std::slice::from_ref(&owner)), None);

        state(&mut r, OwnerRequestState::Pending, T0);
        assert_eq!(
            held_pair_dto(&r, std::slice::from_ref(&owner)),
            Some(HeldPairDto {
                telegram_user_id: NEWCOMER,
                username: Some("vasya".into()),
                first_name: Some("Вася".into()),
                owner_request: OwnerRequestDto {
                    kind: "pc_allow",
                    stage: "pending",
                    owner_asked: true,
                    expires_at: Some(T0 + 600_000),
                    outcome: None,
                },
            })
        );
        // Nobody's binding row carries it: the newcomer has none.
        assert_eq!(owner_request_dto(&r, 12345), None);

        // Allowed: once the list has the newcomer, their binding's row says «Разрешено».
        let mut allowed = r.clone();
        state(&mut allowed, OwnerRequestState::Confirmed, T0 + 1);
        let guest = access_cache::CachedBinding {
            telegram_user_id: NEWCOMER,
            first_name: Some("Вася".into()),
            username: Some("vasya".into()),
            role: Some(afklink_core::BindingRole::Guest),
        };
        assert_eq!(
            held_pair_dto(&allowed, std::slice::from_ref(&owner))
                .map(|h| (h.owner_request.stage, h.owner_request.outcome)),
            Some(("ended", Some("confirmed"))),
            "before the binding comes"
        );
        assert_eq!(
            held_pair_dto(&allowed, &[owner.clone(), guest.clone()]),
            None
        );
        assert_eq!(
            binding_dto(&guest, &allowed)
                .owner_request
                .map(|o| (o.kind, o.outcome)),
            Some(("pc_allow", Some("confirmed")))
        );

        // Declined: on the newcomer's row while shown, then no row.
        state(&mut r, OwnerRequestState::Declined, T0 + 2);
        assert_eq!(
            held_pair_dto(&r, std::slice::from_ref(&owner))
                .map(|h| (h.telegram_user_id, h.owner_request.outcome)),
            Some((NEWCOMER, Some("declined")))
        );
        r.tick(
            T0 + 2 + afklink_core::owner_request::ENDED_SHOWN_MS,
            true,
            &[],
        );
        assert_eq!(held_pair_dto(&r, std::slice::from_ref(&owner)), None);
    }
}

#[cfg(test)]
mod session_toast_tests {
    use super::*;

    fn vera() -> PersonName {
        afklink_core::person_name(5_000_000_001, Some("Вера"), None)
    }

    fn row(id: &str, connected: bool) -> (String, PersonName, bool) {
        (id.to_string(), vera(), connected)
    }

    #[test]
    fn the_start_toast_waits_for_the_peer_and_fires_once() {
        let mut t = SessionToasts::default();

        let e = t.poll(vec![row("s1", false)]);
        assert_eq!(e.connecting, vec!["s1".to_string()]);
        assert!(e.started.is_empty(), "capture running is not controlling");

        // Still connecting: nothing new to say.
        assert_eq!(t.poll(vec![row("s1", false)]), SessionEdges::default());

        let e = t.poll(vec![row("s1", true)]);
        assert_eq!(e.started, vec![("s1".to_string(), vera())]);
        assert!(e.connecting.is_empty());

        // Connected and still there: no second toast.
        assert_eq!(t.poll(vec![row("s1", true)]), SessionEdges::default());

        let e = t.poll(vec![]);
        assert_eq!(e.ended, vec![("s1".to_string(), vera())]);
        assert!(e.never_connected.is_empty());
    }

    #[test]
    fn a_connection_that_never_came_up_shows_neither_toast() {
        let mut t = SessionToasts::default();
        t.poll(vec![row("s1", false)]);
        let e = t.poll(vec![]);
        assert_eq!(e.never_connected, vec!["s1".to_string()]);
        assert!(e.started.is_empty() && e.ended.is_empty());
        // And it is forgotten: a later poll has nothing to say about it.
        assert_eq!(t.poll(vec![]), SessionEdges::default());
    }

    #[test]
    fn a_session_already_connected_at_first_sight_is_announced_at_once() {
        // Connected within one 500 ms poll of starting.
        let mut t = SessionToasts::default();
        let e = t.poll(vec![row("s1", true)]);
        assert!(e.connecting.is_empty());
        assert_eq!(e.started, vec![("s1".to_string(), vera())]);
    }

    #[test]
    fn a_new_session_replacing_an_old_one_ends_the_old_and_waits_on_the_new() {
        // One session per device: a second connect supersedes the first.
        let mut t = SessionToasts::default();
        t.poll(vec![row("old", true)]);
        let e = t.poll(vec![row("new", false)]);
        assert_eq!(e.ended, vec![("old".to_string(), vera())]);
        assert_eq!(e.connecting, vec!["new".to_string()]);
        assert!(e.started.is_empty());
    }
}
