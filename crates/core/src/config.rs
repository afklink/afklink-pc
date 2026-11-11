//! Agent configuration — `%APPDATA%/AFKLink/config.json`.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::game::GameBinding;
use crate::logging::{LevelMoved, LogLevel, UnknownLogLevel};
use crate::paths::afklink_dir;

/// Default signaling endpoint.
///
/// Baked in at build time: release/prod builds set `AFKLINK_SERVER_URL`
/// (see below), dev builds fall back to localhost. The product has exactly one
/// server, so the address is not user configuration — nothing in the UI edits
/// it, and there is no `set_server` command.
///
/// Prod value: `wss://<API_DOMAIN>/ws/agent`, where `API_DOMAIN` is the agents'
/// own hostname from the backend's `infra/.env` (Caddy passes `/ws/agent` there
/// to the backend). The two are kept in sync by the release build, not by the
/// user: [`PROD_SERVER_URL`] (`agent/scripts/lib/common.ts`).
pub const DEFAULT_SERVER_URL: &str = match option_env!("AFKLINK_SERVER_URL") {
    Some(url) => url,
    None => "ws://localhost:8787/ws/agent",
};

/// The product's server as agents reach it: `api.afklink.app`, the agents' own hostname, kept apart
/// from the website's name. What portable and release builds
/// are stamped with (`PROD_SERVER_URL` in `agent/scripts/lib/common.ts`, which must say the same; a
/// scripts test holds the two to each other). The server answers there only what an agent calls —
/// this socket, the diagnostic upload, `/download/` — and a 404 to anything else (the backend's
/// Caddyfile, `API_DOMAIN`).
pub const PROD_SERVER_URL: &str = "wss://api.afklink.app/ws/agent";

/// The address of the editable era's untouched default.
const LEGACY_DEFAULT_SERVER_URL: &str = "ws://localhost:8787/ws/agent";

/// Whether `url` names a server on this machine in one of its canonical spellings: `ws://` or
/// `wss://` (any case) to `localhost`, a dotted-quad `127.x.x.x` address or `[::1]`, with at most a
/// port number (up to 65535) after the host, no credentials.
///
/// Only the wording of the log line depends on it ([`server_moves_to`]): a production build
/// replaces such an address like any other that is not the product's server, so a spelling this
/// does not recognise (`localhost.`, `[::ffff:127.0.0.1]`, `127.1`) only changes the reason logged,
/// never what the PC connects to.
fn is_loopback_server_url(url: &str) -> bool {
    let Some((scheme, rest)) = url.trim().split_once("://") else {
        return false;
    };
    if !scheme.eq_ignore_ascii_case("ws") && !scheme.eq_ignore_ascii_case("wss") {
        return false;
    }
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..end];
    if authority.contains('@') {
        return false;
    }
    let (host, after_host) = if let Some(bracketed) = authority.strip_prefix('[') {
        match bracketed.split_once(']') {
            Some(split) => split,
            None => return false,
        }
    } else {
        match authority.find(':') {
            Some(colon) => authority.split_at(colon),
            None => (authority, ""),
        }
    };
    // Nothing may follow the host but a port: `[::1]evil.test` is not `[::1]`.
    let port_ok = after_host.is_empty()
        || after_host.strip_prefix(':').is_some_and(|port| {
            port.bytes().all(|b| b.is_ascii_digit()) && port.parse::<u16>().is_ok()
        });
    port_ok
        && (host.eq_ignore_ascii_case("localhost")
            || host == "::1"
            || host
                .parse::<std::net::Ipv4Addr>()
                .is_ok_and(|ip| ip.is_loopback()))
}

/// Where a stored address moves at load, and why (for the log); `None`: it stays.
///
/// - the never-edited localhost default of the era when the address was editable in the UI → this
///   build's default, when that is another one (prod builds bake in the real server);
/// - in a build stamped with the product's server ([`PROD_SERVER_URL`]: every portable and release
///   build), any other address → that server. Such a build talks to one server, and the address is
///   not user configuration (nothing in the UI edits it): an address it does not know — a retired
///   name of the product's server, one set by hand, a broken one — is not a server this PC hands
///   its screen and input to, nor one it should sit offline trying to reach. A server on this
///   machine is no exception: whatever local process binds that port first would become the server
///   the PC trusts with its screen and input, so it moves too (the reason logged names it).
///
/// Anything else stays: every address under a build with another default (dev builds, an agent
/// built against another server).
fn server_moves_to<'a>(stored: &str, build_default: &'a str) -> Option<(&'a str, &'static str)> {
    if stored == build_default {
        return None;
    }
    if stored == LEGACY_DEFAULT_SERVER_URL && build_default != LEGACY_DEFAULT_SERVER_URL {
        return Some((
            build_default,
            "the never-edited legacy server address adopts this build's",
        ));
    }
    if build_default != PROD_SERVER_URL {
        return None;
    }
    let why = if is_loopback_server_url(stored) {
        "a production build connects only to the product's server: the stored address is on this \
         machine, where any local process able to bind its port would become the server, and is \
         replaced"
    } else {
        "a production build connects only to the product's server: the stored address is not it \
         (a retired name, set by hand, or broken) and is replaced"
    };
    Some((build_default, why))
}

/// `autostart_offer` while the card waits for an answer.
const AUTOSTART_OFFER_PENDING: &str = "pending";
/// `autostart_offer` once the card was answered.
const AUTOSTART_OFFER_ANSWERED: &str = "answered";

/// Where the one-off «Запускать вместе с Windows?» card stands ([`Config::autostart_offer`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AutostartOffer {
    /// Never offered: no first pairing yet, or autostart was on at it.
    NotYet,
    /// Offered after the first pairing; waiting for «Включить» or «Не надо».
    Pending,
    /// Answered, either way: never again.
    Answered,
}

impl AutostartOffer {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotYet => "not_yet",
            Self::Pending => "pending",
            Self::Answered => "answered",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// UUIDv4, generated on first run.
    pub device_id: String,
    /// `wss://host/ws/agent` (or `ws://` for dev).
    pub server_url: String,
    /// Human-friendly device name shown in the Mini App.
    pub name: String,
    /// A developer's override of the bot the pairing link opens. Normally unset:
    /// the backend names its bot with each code (`pairing_code`), and with neither there is no
    /// link at all (`crate::qr::resolve_target`).
    #[serde(default)]
    pub bot_username: Option<String>,
    /// A developer's override of the Mini App short name in that link (`t.me/<bot>/<app>`); unset,
    /// the backend's.
    #[serde(default)]
    pub miniapp_short_name: Option<String>,

    /// UI language: `"auto"` (default), `"ru"` or `"en"`.
    ///
    /// `auto` follows the Windows UI locale, which is the language the person already chose
    /// for everything else on the machine. An explicit value overrides it, because that
    /// guess is wrong more often than it looks — a laptop imaged in English by someone
    /// else, or a Telegram account in one language and a desktop in another.
    ///
    /// Stored as a free-form string rather than an enum so a value written by a newer build
    /// is ignored rather than making the whole config unparseable; unknown means `auto`.
    #[serde(default = "default_lang")]
    pub lang: String,

    /// Launch at Windows sign-in. Explicit opt-in, OFF by default: appearing in
    /// the user's startup sequence unasked is the kind of surprise that gets an
    /// agent uninstalled. Toggled from Settings; the OS entry (HKCU `...\Run`)
    /// is written immediately, this remembers the choice across launches.
    #[serde(default)]
    pub autostart: bool,

    /// The one-off «Запускать вместе с Windows?» card on the desktop app's main view:
    /// absent — never offered; `"pending"` — the
    /// first pairing came while `autostart` was off, and the card waits for an answer; `"answered"`
    /// — answered, either way, and never shown again. Read it through [`Config::autostart_offer`].
    ///
    /// A free-form string, like `lang`: a value a newer build writes must not make the file
    /// unparseable, and reads as answered (the card never comes back by accident).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub autostart_offer: Option<String>,

    /// How much the agent logs, when its owner has chosen: `"off"`, `"info"` or `"debug"` — Settings'
    /// «Выключены», «Обычные», «Подробные» (the three levels, [`crate::logging`]); or
    /// `"trace"`, written by hand, which works and is not offered. Applies to our own crates;
    /// third-party ones stay at `warn` below `trace`.
    ///
    /// Absent (or `null`) means nothing chosen: the build's channel decides
    /// (`crate::logging::default_log_level` — `debug` for a development build; for a release
    /// `debug` during the beta test and `info` after it, `crate::logging::RELEASE_PHASE`). A fresh
    /// config does not write it, so the first build that runs does not fix the level for every
    /// later one; Settings writes it whenever a level is picked.
    ///
    /// A value from before the three levels is rewritten at load ([`Config::log_level_moved`]):
    /// `"error"` and `"warn"` become `"info"`, a known name in another case or with spaces around
    /// it becomes the name. Any other value is kept as it is.
    ///
    /// A free-form string, like `lang` and for the same reason: a level a newer build adds must
    /// not make the whole file unparseable. Read it through [`Config::log_level`], which reports
    /// a value this build does not know instead of guessing silently.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub log_level: Option<String>,

    /// The desktop app installs a newer release by itself, once nobody is connected (Settings →
    /// «Обновления» → «Обновлять автоматически»). On by default — a config.json written before the
    /// field existed reads as on. Off, the app still checks and shows the new version, and installs
    /// it only when the owner presses «Установить». Only release builds update themselves; the CLI
    /// does not read this.
    #[serde(default = "default_auto_update")]
    pub auto_update: bool,

    /// «Only the game window» (`crate::game`): every session shows the bound game's window and
    /// nothing else — black frames while it cannot be shown, never the desktop. Off by default, and
    /// off in a config.json written before it existed. Set only by the desktop app on this PC
    /// (`AgentControl::set_game_only`); nothing from the network reaches it. Not written while off,
    /// like `log_level` while nothing is chosen.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub game_only: bool,

    /// Settings → «Только игра» → «Только для гостей»:
    /// `game_only` applies to guests' sessions only, and the PC's owner gets the whole desktop. Which
    /// session is whose is the server's word — the role of the viewer's binding
    /// (`crate::game_access`); with no role to go by (a server older than roles) every session is
    /// treated as a guest's. Off by default, and off in a config.json written before it existed:
    /// `game_only` then applies to everyone, as it always did. Set only by the desktop app on this
    /// PC (`AgentControl::set_game_only_for_guests`); the CLI reads it like the other game-only
    /// fields. Not written while off.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub game_only_for_guests: bool,

    /// Settings → «Только игра» → «Запускать игру автоматически» is on: the owner's wish. The helper
    /// itself never reads this file — what it may launch is in the record its elevated setup wrote
    /// (`afklink_game_helper::Record`); the desktop app lets it act only during a session, with
    /// `game_only` on, and this on, and the record matching `game` and `game_launch_exe`. Not
    /// written while off.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub game_helper: bool,

    /// The exe the helper launches for `game`, when the owner chose one in Settings; `None`: the
    /// one learned (`game_launch_learned`), else the guess — `game`'s exe if it is an `.exe`, else
    /// the `.exe` of the same name beside it (`afklink_game_helper::default_launch_exe`).
    /// Forgotten when another game is bound ([`crate::AgentControl::set_game_binding`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub game_launch_exe: Option<String>,

    /// The exe that started `game`'s window exe, learned by the desktop app from the game's parent
    /// process (`afklink_app_lib::game_helper`, the learner): the game's own launcher, in its folder
    /// or one above it. The launch exe when the owner chose none — before the guess by name. A
    /// helper already installed with another one keeps working; Settings offers the learned one.
    /// Forgotten when another game is bound, like `game_launch_exe`. Not written while unset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub game_launch_learned: Option<String>,

    /// The game `game_only` shows: its exe path, window class and the name the app shows for it.
    /// Kept when the mode is turned off, so turning it back on needs no new choice. `game_only` on
    /// with no game here sends black frames only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub game: Option<GameBinding>,

    /// The agent saw a viewer's controls not reach a window running as administrator for want of
    /// the input driver (`crate::input_reach`): the desktop app's «Управление в играх» row says
    /// «Управление не доходит» in red over a lime «Установить» until the driver is installed or a
    /// session's input gets through. Kept here so the highlight outlives a restart and is seen when
    /// the window is next opened. Not written while off, like `game_only`.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub input_not_reaching: bool,

    /// «Приостановить доступ» (the kill switch) paused connections on this PC, and the owner has not
    /// pressed «Возобновить» since: every session request is refused with `paused_on_pc`
    /// (`AgentState::paused`). Kept here so the pause outlives a restart of the process and an
    /// update: held in memory only, an automatic update would quietly let back in whoever the owner
    /// had shut out. Applied by `Agent::new`,
    /// before the first connection; written only by the orchestrator, on the owner's kill switch
    /// and «Возобновить» — nothing from the network reaches it. Not written while off, like
    /// `game_only`.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub paused: bool,

    #[serde(skip)]
    path: Option<PathBuf>,

    /// This load wrote the file: there was no config.json, so `device_id` was generated now. See
    /// [`Config::created`].
    #[serde(skip)]
    created: bool,

    /// The address this load moved `server_url` from (`server_moves_to`), for the binaries' first
    /// lines: config.json is read before their log exists. See [`Config::server_moved_from`].
    #[serde(skip)]
    server_moved_from: Option<String>,

    /// `log_level` as this load rewrote it in the three-level form, for the startup line
    /// (`crate::logging::StartupFilter`). See [`Config::log_level_moved`].
    #[serde(skip)]
    log_level_moved: Option<LevelMoved>,
}

fn default_lang() -> String {
    "auto".into()
}

fn default_auto_update() -> bool {
    true
}

impl Config {
    /// Load config from disk, or create defaults and persist them.
    pub fn load_or_create() -> Result<Self> {
        Self::load_or_create_at(afklink_dir()?.join("config.json"))
    }

    pub fn load_or_create_at(path: PathBuf) -> Result<Self> {
        // What a save that crashed halfway left beside the file (`write_whole`).
        remove_leftovers(&path);
        if path.exists() {
            let text = std::fs::read_to_string(&path)
                .with_context(|| format!("read {}", path.display()))?;
            let mut cfg: Config = serde_json::from_str(&text).context("parse config.json")?;
            // Usually read before any log exists (the level is in here), so the binaries log what
            // was loaded once they have one; this line is for a later reload.
            tracing::debug!(path = %path.display(), "config loaded");
            cfg.path = Some(path);
            cfg.adopt_build_default_server();
            cfg.settle_log_level();
            cfg.repair_name();
            cfg.note_game_only();
            Ok(cfg)
        } else {
            let mut cfg = Config::defaults();
            cfg.path = Some(path.clone());
            cfg.save()?;
            cfg.created = true;
            tracing::info!(
                device_id = %cfg.device_id,
                "wrote default config at {}: a new device",
                path.display()
            );
            Ok(cfg)
        }
    }

    fn defaults() -> Self {
        Config {
            device_id: uuid::Uuid::new_v4().to_string(),
            server_url: DEFAULT_SERVER_URL.to_string(),
            name: default_device_name(),
            bot_username: None,
            miniapp_short_name: None,
            lang: default_lang(),
            autostart: false,
            autostart_offer: None,
            // Nothing chosen yet: the build's channel decides (see the field).
            log_level: None,
            auto_update: default_auto_update(),
            game_only: false,
            game_only_for_guests: false,
            game_helper: false,
            game_launch_exe: None,
            game_launch_learned: None,
            game: None,
            input_not_reaching: false,
            paused: false,
            path: None,
            created: false,
            server_moved_from: None,
            log_level_moved: None,
        }
    }

    /// The address this load moved `server_url` from (`server_moves_to`: an address a production
    /// build does not connect to, or the editable era's localhost default) when it moved one; `None`
    /// otherwise. The binaries put it on their first line, since the move happens before their log
    /// exists: the one line that records it.
    pub fn server_moved_from(&self) -> Option<&str> {
        self.server_moved_from.as_deref()
    }

    /// Whether this load created config.json — and with it `device_id`, the id the backend keeps
    /// bindings under. A device id generated now is one the backend has never seen, so nobody can
    /// have access to this PC yet: the desktop app shows the pairing steps without waiting for the
    /// server's list. The identity key alone does not say this: a new key under an old device id is
    /// refused by the backend (`pubkey_mismatch`), not given an empty list.
    pub fn created(&self) -> bool {
        self.created
    }

    /// Say, once at load, what «only the game window» is set to — and warn when it cannot show
    /// anything but black.
    fn note_game_only(&self) {
        if self.game_only_for_guests {
            tracing::debug!(
                game_only = self.game_only,
                "config: «Только для гостей» is on: {}",
                if self.game_only {
                    "game-only applies to guests' sessions only; the owner's get the whole desktop \
                     (each session decided by its viewer's role, crate::game_access)"
                } else {
                    "nothing to apply while game-only is off"
                }
            );
        }
        match (self.game_only, &self.game) {
            (false, None) => {}
            (false, Some(game)) => tracing::debug!(
                game = %game.shown_name(),
                "config: game-only is off (a game stays bound for when it is turned on)"
            ),
            (true, None) => tracing::warn!(
                "config: game-only is on and no game is bound: sessions get black frames until a \
                 game is chosen"
            ),
            (true, Some(game)) => match game.unusable() {
                Some(why) => tracing::warn!(
                    exe = %game.exe_path,
                    class = %game.window_class,
                    "config: game-only is on, but the bound game can match no window ({why}): \
                     sessions get black frames"
                ),
                None => tracing::debug!(
                    game = %game.shown_name(),
                    exe = %game.exe_path,
                    class = %game.window_class,
                    "config: game-only is on: sessions show this game's window only"
                ),
            },
        }
    }

    /// The log level chosen in Settings (`None`: none chosen), settled in the three-level form
    /// ([`LogLevel::settled`]: `error` and `warn` mean `info`, even in a config this load could not
    /// rewrite) — or the stored value this build does not know.
    ///
    /// Callers use the build channel's default on `Ok(None)`, and on `Err` too, saying so once
    /// their log is up — [`crate::logging::level_from_config`] does both halves.
    pub fn log_level(&self) -> Result<Option<LogLevel>, UnknownLogLevel> {
        self.log_level
            .as_deref()
            .map(|stored| stored.parse().map(LogLevel::settled))
            .transpose()
    }

    /// `log_level` as this load rewrote it in the three-level form, when it did; `None` otherwise.
    /// The binaries say it on their startup line (`crate::logging::StartupFilter::log_summary`),
    /// since the rewrite happens before their log exists.
    pub fn log_level_moved(&self) -> Option<&LevelMoved> {
        self.log_level_moved.as_ref()
    }

    /// A stored level from before the three levels, rewritten in their form and saved:
    /// `error` and `warn` as `info` («Обычные»), a known name in another case or with spaces around
    /// it as the name. `off`, `info`, `debug` and `trace` as written stay; nothing stored stays
    /// nothing (the channel decides); a value this build does not know stays as it is — a newer
    /// build may have written it — and [`crate::logging::level_from_config`] warns about it.
    fn settle_log_level(&mut self) {
        let Some(stored) = self.log_level.as_deref() else {
            return;
        };
        let Ok(level) = stored.parse::<LogLevel>() else {
            // Usually before any log exists; the startup line warns about it (`level_from_config`).
            tracing::debug!(
                stored,
                "config: log level not known to this build; kept as it is"
            );
            return;
        };
        let to = level.settled();
        if to.as_str() == stored {
            return;
        }
        let from = stored.to_string();
        // Usually before any log exists: the binaries repeat it from `log_level_moved`.
        tracing::info!(%from, %to, "config: log level rewritten in the three-level form");
        self.log_level = Some(to.as_str().to_string());
        // In effect for this run either way ([`Self::log_level`] settles it too); not saved only
        // means the rewrite repeats at the next start.
        let not_saved = self.save().err().map(|e| format!("{e:#}"));
        if let Some(e) = &not_saved {
            tracing::warn!("rewritten log level not saved: {e}");
        }
        self.log_level_moved = Some(LevelMoved {
            from,
            to,
            not_saved,
        });
    }

    /// Where the one-off autostart card stands (the `autostart_offer` field).
    pub fn autostart_offer(&self) -> AutostartOffer {
        match self.autostart_offer.as_deref() {
            None => AutostartOffer::NotYet,
            Some(AUTOSTART_OFFER_PENDING) => AutostartOffer::Pending,
            Some(AUTOSTART_OFFER_ANSWERED) => AutostartOffer::Answered,
            Some(other) => {
                tracing::debug!(
                    value = other,
                    "config: an autostart_offer this build does not know; read as answered"
                );
                AutostartOffer::Answered
            }
        }
    }

    /// The first pairing on this PC was just made — nobody had access before it: the autostart card
    /// waits for the owner if autostart is off and the card was never offered. True when that
    /// changed the field (the caller saves); every outcome is logged with why.
    pub fn offer_autostart_after_first_pairing(&mut self) -> bool {
        let offer = self.autostart_offer();
        if offer != AutostartOffer::NotYet {
            tracing::debug!(
                offer = offer.as_str(),
                autostart = self.autostart,
                "autostart card: not offered again after the first pairing (offered before)"
            );
            return false;
        }
        if self.autostart {
            tracing::debug!(
                "autostart card: not offered after the first pairing: autostart is already on"
            );
            return false;
        }
        tracing::info!(
            "autostart card: offered — the first pairing on this PC was made and autostart is off"
        );
        self.autostart_offer = Some(AUTOSTART_OFFER_PENDING.to_string());
        true
    }

    /// The autostart card has its answer — `how`, for the log: «Включить», «Не надо», or autostart
    /// turned on in Settings while it waited. It never comes back. True when that changed the field
    /// (the caller saves).
    pub fn settle_autostart_offer(&mut self, how: &str) -> bool {
        let offer = self.autostart_offer();
        if offer == AutostartOffer::Answered {
            tracing::debug!(how, "autostart card: answered already; nothing to change");
            return false;
        }
        tracing::info!(
            how,
            was = offer.as_str(),
            "autostart card: answered; it is never shown again"
        );
        self.autostart_offer = Some(AUTOSTART_OFFER_ANSWERED.to_string());
        true
    }

    /// Where this config lives on disk, when it came from (or went to) a file.
    ///
    /// Worth logging: under MSIX virtualization `%APPDATA%` is not where it looks, and "which
    /// config did this run read" is otherwise a guess.
    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    /// Persist current values back to disk (if a path is known).
    pub fn save(&self) -> Result<()> {
        if let Some(path) = &self.path {
            self.save_to(path)?;
        }
        Ok(())
    }

    /// The stored address moved where it has to (see [`server_moves_to`]), and saved.
    fn adopt_build_default_server(&mut self) {
        let Some((to, why)) = server_moves_to(&self.server_url, DEFAULT_SERVER_URL) else {
            return;
        };
        // Usually before any log exists: the binaries repeat it from `server_moved_from`.
        tracing::info!(from = %self.server_url, to, "config: {why}");
        let from = std::mem::replace(&mut self.server_url, to.to_string());
        self.server_moved_from = Some(from);
        // In effect for this run either way; not saved only means the migration repeats.
        if let Err(e) = self.save() {
            tracing::warn!("migrated server address not saved: {e:#}");
        }
    }

    /// Bring a stored name inside the device-name rule (`afklink_protocol::device_name`).
    ///
    /// The desktop app did not cap the field before, and the file can be edited by hand. A name
    /// outside the rule is one the agent cannot send when the owner approves a pairing, and the
    /// Mini App would then list this PC under the backend's placeholder — so it is repaired to the
    /// nearest valid name (control characters dropped, trimmed, cut at the limit), or to the
    /// default when nothing of it survives. Whitespace around an otherwise valid name is trimmed,
    /// so the PC shows the name the Mini App gets.
    fn repair_name(&mut self) {
        let repaired = match afklink_protocol::validate_device_name(&self.name) {
            Ok(name) if name == self.name => return,
            Ok(name) => {
                tracing::info!(
                    from = ?self.name,
                    to = %name,
                    "config: whitespace around the device name trimmed"
                );
                name
            }
            Err(why) => {
                let name = afklink_protocol::sanitize_device_name(&self.name)
                    .unwrap_or_else(default_device_name);
                tracing::warn!(
                    from = ?self.name,
                    to = %name,
                    why = why.as_str(),
                    "config: the stored device name is not a valid one ({why}); repaired"
                );
                name
            }
        };
        self.name = repaired;
        // In effect for this run either way; not saved only means the repair repeats.
        if let Err(e) = self.save() {
            tracing::warn!("repaired device name not saved: {e:#}");
        }
    }

    /// Write this config to `path` whole ([`write_whole`]): a crash, a full disk or a power cut
    /// halfway leaves the file as it was, never half a new one that the next start cannot parse.
    pub fn save_to(&self, path: &Path) -> Result<()> {
        let text = serde_json::to_string_pretty(self)?;
        write_whole(path, text.as_bytes())?;
        // Nothing in here is a secret (the identity key lives in identity.json), so the values
        // that change behaviour are on the line.
        tracing::debug!(
            path = %path.display(),
            name = %self.name,
            lang = %self.lang,
            autostart = self.autostart,
            autostart_offer = %self.autostart_offer.as_deref().unwrap_or("-"),
            log_level = %self.log_level.as_deref().unwrap_or("- (none chosen: the channel's)"),
            auto_update = self.auto_update,
            game_only = self.game_only,
            game_only_for_guests = self.game_only_for_guests,
            game_helper = self.game_helper,
            game_launch_exe = %self.game_launch_exe.as_deref().unwrap_or("- (default)"),
            game_launch_learned = %self.game_launch_learned.as_deref().unwrap_or("-"),
            game = %self.game.as_ref().map_or("-", GameBinding::shown_name),
            input_not_reaching = self.input_not_reaching,
            paused = self.paused,
            "config written"
        );
        Ok(())
    }
}

impl Config {
    /// [`Self::save`], and when the file cannot be replaced whole — another program holds it past
    /// [`REPLACE_FOR`] — written over in place instead: for what must reach the disk even at that
    /// risk, the kill switch's pause (`Agent::save_pause`). How it went is the answer
    /// ([`Saved`]) and is logged here: the fallback at `warn`, with why the replace failed. `Err`
    /// only when both failed. A config with no file is [`Saved::NoFile`]: nothing written.
    pub fn save_even_in_place(&self) -> Result<Saved> {
        let Some(path) = &self.path else {
            return Ok(Saved::NoFile);
        };
        let replaced = match self.save_to(path) {
            Ok(()) => return Ok(Saved::Whole),
            Err(e) => e,
        };
        let text = serde_json::to_string_pretty(self)?;
        match std::fs::write(path, text.as_bytes()) {
            Ok(()) => {
                tracing::warn!(
                    path = %path.display(),
                    paused = self.paused,
                    "config: written over in place, not whole — the replace failed: {replaced:#} \
                     (a crash in this moment could leave it half written)"
                );
                Ok(Saved::InPlace)
            }
            Err(in_place) => Err(anyhow::anyhow!(
                "replace: {replaced:#}; in place: {in_place}"
            ))
            .with_context(|| format!("write {}", path.display())),
        }
    }
}

/// How [`Config::save_even_in_place`] wrote the file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Saved {
    /// Replaced whole, as every save.
    Whole,
    /// Written over in place: the replace failed (said at `warn`).
    InPlace,
    /// This config has no file (one parsed from text): nothing was written.
    NoFile,
}

/// How long [`write_whole`] keeps trying to put the new file in place: another program holding the
/// old one open without delete sharing (an antivirus scan, a backup tool, a cloud-sync client) makes
/// Windows refuse the rename for a moment — usually milliseconds, rarely most of a second.
const REPLACE_FOR: std::time::Duration = std::time::Duration::from_secs(1);

/// The first pause between two of those tries, doubled after each up to [`REPLACE_PAUSE_MAX`].
const REPLACE_PAUSE_FIRST: std::time::Duration = std::time::Duration::from_millis(25);
const REPLACE_PAUSE_MAX: std::time::Duration = std::time::Duration::from_millis(200);

/// A temporary file left beside the config this long ago is a leftover — a process that died
/// between writing it and putting it in place — not a save under way (one takes milliseconds).
const LEFTOVER_AFTER: std::time::Duration = std::time::Duration::from_secs(60);

/// Whether a failed replace is another program holding the old file — access denied, or Windows'
/// sharing and lock violations (32, 33) — which goes away by itself, rather than a lasting failure.
fn held_by_another(e: &std::io::Error) -> bool {
    e.kind() == std::io::ErrorKind::PermissionDenied || matches!(e.raw_os_error(), Some(32 | 33))
}

/// The temporary files [`write_whole`] writes beside `path`: `.{name}.{uuid}.tmp`.
fn is_temporary_of(file_name: &str, name: &str) -> bool {
    file_name
        .strip_prefix('.')
        .and_then(|rest| rest.strip_prefix(name))
        .and_then(|rest| rest.strip_prefix('.'))
        .is_some_and(|rest| rest.ends_with(".tmp") && rest.len() > ".tmp".len())
}

/// Remove the temporary files a crashed save left beside `path` ([`LEFTOVER_AFTER`]); called at
/// load and before every save. Each removal is said at `debug`, a failure at `warn`; nothing here
/// stops a load or a save.
fn remove_leftovers(path: &Path) {
    let (Some(dir), Some(name)) = (path.parent(), path.file_name()) else {
        return;
    };
    let name = name.to_string_lossy();
    let dir = if dir.as_os_str().is_empty() {
        Path::new(".")
    } else {
        dir
    };
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) => {
            tracing::debug!(dir = %dir.display(), "config: leftovers not looked for: {e}");
            return;
        }
    };
    for entry in entries.flatten() {
        let file_name = entry.file_name();
        if !is_temporary_of(&file_name.to_string_lossy(), &name) {
            continue;
        }
        let age = entry
            .metadata()
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| t.elapsed().ok());
        if age.is_some_and(|age| age < LEFTOVER_AFTER) {
            tracing::trace!(file = %entry.path().display(), "config: a fresh temporary file; left");
            continue;
        }
        match std::fs::remove_file(entry.path()) {
            Ok(()) => tracing::debug!(
                file = %entry.path().display(),
                age_s = age.map_or(-1, |a| a.as_secs() as i64),
                "config: a temporary file a crashed save left removed"
            ),
            Err(e) => tracing::warn!(
                file = %entry.path().display(),
                "config: a temporary file a crashed save left not removed: {e}"
            ),
        }
    }
}

/// Write `bytes` to `path` whole: into a temporary file of its own beside it (a fresh name, so two
/// writers never share one), flushed to the disk, then renamed over `path` — which Windows does in
/// one step — trying again for up to [`REPLACE_FOR`] while another program holds the old file.
/// Whatever fails leaves `path` as it was and removes the temporary file; every failure is in the
/// error, a replace that took more than one try is logged, and so is a temporary file that cannot be
/// removed. Leftovers of a crashed save are removed first ([`remove_leftovers`]).
fn write_whole(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write as _;
    remove_leftovers(path);
    let name = path
        .file_name()
        .map_or_else(|| "config.json".into(), |n| n.to_string_lossy());
    let tmp = path.with_file_name(format!(".{name}.{}.tmp", uuid::Uuid::new_v4()));
    let remove_tmp = |why: &str| {
        if let Err(e) = std::fs::remove_file(&tmp) {
            if e.kind() != std::io::ErrorKind::NotFound {
                tracing::warn!(tmp = %tmp.display(), why, "config: temporary file not removed: {e}");
            }
        }
    };
    let written = std::fs::File::create(&tmp).and_then(|mut file| {
        file.write_all(bytes)?;
        file.sync_all()
    });
    if let Err(e) = written {
        remove_tmp("not written");
        return Err(e).with_context(|| format!("write {}", tmp.display()));
    }
    let started = std::time::Instant::now();
    let mut pause = REPLACE_PAUSE_FIRST;
    let mut tries = 0u32;
    loop {
        tries += 1;
        match std::fs::rename(&tmp, path) {
            Ok(()) => {
                if tries > 1 {
                    tracing::debug!(
                        path = %path.display(),
                        tries,
                        took_ms = started.elapsed().as_millis() as u64,
                        "config: put in place once the old file was let go"
                    );
                }
                return Ok(());
            }
            Err(e) if held_by_another(&e) && started.elapsed() + pause < REPLACE_FOR => {
                tracing::debug!(
                    path = %path.display(),
                    tries,
                    "config: the old file is held by another program ({e}); trying again"
                );
                std::thread::sleep(pause);
                pause = (pause * 2).min(REPLACE_PAUSE_MAX);
            }
            Err(e) => {
                remove_tmp("not put in place");
                return Err(e).with_context(|| {
                    format!(
                        "replace {} (after {tries} tries in {} ms)",
                        path.display(),
                        started.elapsed().as_millis()
                    )
                });
            }
        }
    }
}

/// The name of a PC nobody has named yet, on a system without a computer name. Only then: the
/// backend's placeholder for a device it has no name for is the same words.
const FALLBACK_DEVICE_NAME: &str = "My PC";

/// What a PC is called before its owner names it: the Windows computer name (`COMPUTERNAME`) —
/// what the owner already sees for this machine everywhere else in Windows.
fn default_device_name() -> String {
    device_name_or_fallback(std::env::var("COMPUTERNAME").ok().as_deref())
}

/// `computer_name` made a valid device name, or [`FALLBACK_DEVICE_NAME`] when there is none.
fn device_name_or_fallback(computer_name: Option<&str>) -> String {
    match computer_name.and_then(afklink_protocol::sanitize_device_name) {
        Some(name) => name,
        None => {
            tracing::debug!(
                computer_name = ?computer_name,
                fallback = FALLBACK_DEVICE_NAME,
                "no usable computer name for the default device name"
            );
            FALLBACK_DEVICE_NAME.to_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A config.json path of its own under the temp dir, removed on drop.
    struct TempConfig(PathBuf);

    impl TempConfig {
        fn with(contents: Option<&str>) -> Self {
            let dir = std::env::temp_dir().join(format!("afklink-config-{}", uuid::Uuid::new_v4()));
            std::fs::create_dir_all(&dir).expect("create temp dir");
            let path = dir.join("config.json");
            if let Some(text) = contents {
                std::fs::write(&path, text).expect("write config");
            }
            Self(path)
        }
    }

    impl Drop for TempConfig {
        fn drop(&mut self) {
            if let Some(dir) = self.0.parent() {
                let _ = std::fs::remove_dir_all(dir);
            }
        }
    }

    /// A config.json as written before `log_level` existed.
    const LEGACY: &str = r#"{
  "device_id": "843eda6a-0000-4000-8000-000000000000",
  "server_url": "wss://example.test/ws/agent",
  "name": "PC",
  "bot_username": null,
  "miniapp_short_name": null,
  "lang": "ru",
  "autostart": true
}"#;

    /// `LEGACY` with `"log_level": <value>` after `autostart`.
    fn with_log_level(value: &str) -> String {
        LEGACY.replace(
            r#""autostart": true"#,
            &format!(r#""autostart": true, "log_level": {value}"#),
        )
    }

    #[test]
    fn a_config_without_log_level_has_no_choice_and_gains_none_on_save() {
        let tmp = TempConfig::with(Some(LEGACY));
        let cfg = Config::load_or_create_at(tmp.0.clone()).expect("legacy config loads");
        assert_eq!(cfg.log_level, None);
        assert_eq!(cfg.log_level(), Ok(None));
        // Everything else survives as it was.
        assert_eq!(cfg.lang, "ru");
        assert!(cfg.autostart);
        assert_eq!(cfg.path(), Some(tmp.0.as_path()));
        // Saving for any other reason does not write a level nobody chose.
        cfg.save().expect("save");
        let on_disk = std::fs::read_to_string(&tmp.0).expect("written");
        assert!(!on_disk.contains("log_level"), "{on_disk}");
    }

    #[test]
    fn null_is_no_choice() {
        let tmp = TempConfig::with(Some(&with_log_level("null")));
        let cfg = Config::load_or_create_at(tmp.0.clone()).expect("config loads");
        assert_eq!(cfg.log_level(), Ok(None));
    }

    #[test]
    fn a_stored_level_is_kept_as_it_is() {
        // The owner's config.json: `debug`, written explicitly by the first build that ran. A later
        // build — a release too — reads it as a choice and writes it back unchanged.
        let tmp = TempConfig::with(Some(&with_log_level(r#""debug""#)));
        let cfg = Config::load_or_create_at(tmp.0.clone()).expect("config loads");
        assert_eq!(cfg.log_level(), Ok(Some(LogLevel::Debug)));
        cfg.save().expect("save");
        let on_disk = std::fs::read_to_string(&tmp.0).expect("written");
        assert!(on_disk.contains(r#""log_level": "debug""#), "{on_disk}");
    }

    #[test]
    fn an_unknown_log_level_loads_and_is_reported_not_rewritten() {
        let tmp = TempConfig::with(Some(&with_log_level(r#""chatty""#)));
        let cfg = Config::load_or_create_at(tmp.0.clone()).expect("config loads");
        assert_eq!(cfg.log_level(), Err(UnknownLogLevel("chatty".to_string())));
        // Kept verbatim: a newer build may have written it, and this one must not erase it.
        assert_eq!(cfg.log_level.as_deref(), Some("chatty"));
        cfg.save().expect("save");
        let on_disk = std::fs::read_to_string(&tmp.0).expect("written");
        assert!(on_disk.contains(r#""log_level": "chatty""#), "{on_disk}");
    }

    #[test]
    fn a_choice_round_trips_and_none_means_the_channel() {
        let tmp = TempConfig::with(Some(LEGACY));
        let mut cfg = Config::load_or_create_at(tmp.0.clone()).expect("config loads");
        cfg.log_level = Some(LogLevel::Off.as_str().to_string());
        cfg.save().expect("save");
        let mut again = Config::load_or_create_at(tmp.0.clone()).expect("config reloads");
        assert_eq!(again.log_level(), Ok(Some(LogLevel::Off)));
        assert_eq!(again.log_level_moved(), None);

        // No field (Settings never removes it; a hand edit can):
        // the channel decides again.
        again.log_level = None;
        again.save().expect("save");
        let on_disk = std::fs::read_to_string(&tmp.0).expect("written");
        assert!(!on_disk.contains("log_level"), "{on_disk}");
        let last = Config::load_or_create_at(tmp.0.clone()).expect("config reloads");
        assert_eq!(last.log_level(), Ok(None));
    }

    /// The three levels: a level from before is rewritten at load, on disk too, and said
    /// for the startup line; the three, `trace` and nothing stay as they are, and so does a value
    /// this build does not know.
    #[test]
    fn an_old_level_is_rewritten_in_the_three_level_form_at_load() {
        for (stored, to, moved) in [
            // Rewritten: «Обычные».
            ("warn", LogLevel::Info, true),
            ("error", LogLevel::Info, true),
            // A known name, written oddly by hand: the name.
            (" Debug ", LogLevel::Debug, true),
            ("WARN", LogLevel::Info, true),
            // Kept: the three, and `trace` (works, not offered). The owner's config is `debug`.
            ("debug", LogLevel::Debug, false),
            ("info", LogLevel::Info, false),
            ("off", LogLevel::Off, false),
            ("trace", LogLevel::Trace, false),
        ] {
            let read = Some(to);
            let tmp = TempConfig::with(Some(&with_log_level(&format!("{stored:?}"))));
            let cfg = Config::load_or_create_at(tmp.0.clone()).expect("config loads");
            assert_eq!(cfg.log_level(), Ok(read), "{stored}");
            let text = std::fs::read_to_string(&tmp.0).expect("written");
            let on_disk = format!(r#""log_level": "{to}""#);
            assert!(text.contains(&on_disk), "{stored}: {text}");
            match cfg.log_level_moved() {
                Some(m) if moved => {
                    assert_eq!(m.from, stored);
                    assert_eq!(m.to, to);
                    assert_eq!(m.not_saved, None);
                }
                None if !moved => {}
                other => panic!("{stored}: {other:?}"),
            }
            // The next start reads the new form and moves nothing.
            let again = Config::load_or_create_at(tmp.0.clone()).expect("config reloads");
            assert_eq!(again.log_level(), Ok(read), "{stored}");
            assert_eq!(again.log_level_moved(), None, "{stored}");
        }
        // Nothing stored: nothing written, the channel decides.
        let tmp = TempConfig::with(Some(LEGACY));
        let cfg = Config::load_or_create_at(tmp.0.clone()).expect("config loads");
        assert_eq!((cfg.log_level(), cfg.log_level_moved()), (Ok(None), None));
        // Unknown: kept verbatim, nothing said here (the startup line warns).
        let tmp = TempConfig::with(Some(&with_log_level(r#""chatty""#)));
        let cfg = Config::load_or_create_at(tmp.0.clone()).expect("config loads");
        assert_eq!(cfg.log_level_moved(), None);
        assert_eq!(cfg.log_level.as_deref(), Some("chatty"));
    }

    /// A config never loaded from disk (the tests', or one parsed from text) holding an old level
    /// still means the settled one.
    #[test]
    fn an_old_level_read_without_a_load_is_settled_too() {
        let mut cfg: Config =
            serde_json::from_str(r#"{"device_id":"d","server_url":"ws://x","name":"n"}"#)
                .expect("parses");
        cfg.log_level = Some("warn".into());
        assert_eq!(cfg.log_level(), Ok(Some(LogLevel::Info)));
        cfg.log_level = Some("trace".into());
        assert_eq!(cfg.log_level(), Ok(Some(LogLevel::Trace)));
    }

    /// Before the owner names it, a PC is called what Windows calls it — the name the desktop app
    /// shows and the Mini App gets at pairing — and only without one the fallback.
    #[test]
    fn the_default_name_is_the_computer_name() {
        assert_eq!(device_name_or_fallback(Some("HVN2MMZR")), "HVN2MMZR");
        assert_eq!(device_name_or_fallback(Some(" DESK-1 ")), "DESK-1");
        assert_eq!(device_name_or_fallback(Some("")), FALLBACK_DEVICE_NAME);
        assert_eq!(device_name_or_fallback(None), FALLBACK_DEVICE_NAME);

        let tmp = TempConfig::with(None);
        let cfg = Config::load_or_create_at(tmp.0.clone()).expect("config created");
        match std::env::var("COMPUTERNAME") {
            Ok(computer) if !computer.trim().is_empty() => assert_eq!(cfg.name, computer.trim()),
            _ => assert_eq!(cfg.name, FALLBACK_DEVICE_NAME),
        }
    }

    /// A stored name the backend would refuse is repaired on load, on disk too, so an approval
    /// always has a name to carry.
    #[test]
    fn a_stored_name_outside_the_rule_is_repaired_on_load() {
        let long = "x".repeat(afklink_protocol::DEVICE_NAME_MAX + 6);
        for (stored, expected) in [
            (
                format!("{long}\\t"),
                "x".repeat(afklink_protocol::DEVICE_NAME_MAX),
            ),
            ("  PC  ".to_string(), "PC".to_string()),
            ("Office\\nPC".to_string(), "OfficePC".to_string()),
            (String::new(), default_device_name()),
        ] {
            let text = LEGACY.replace(r#""name": "PC""#, &format!(r#""name": "{stored}""#));
            let tmp = TempConfig::with(Some(&text));
            let cfg = Config::load_or_create_at(tmp.0.clone()).expect("config loads");
            assert_eq!(cfg.name, expected, "stored {stored:?}");
            let again = Config::load_or_create_at(tmp.0.clone()).expect("config reloads");
            assert_eq!(again.name, expected, "the repair is saved: {stored:?}");
        }
        // A valid name is left exactly as it is.
        let tmp = TempConfig::with(Some(LEGACY));
        let cfg = Config::load_or_create_at(tmp.0.clone()).expect("config loads");
        assert_eq!(cfg.name, "PC");
    }

    #[test]
    fn auto_update_is_on_unless_switched_off_and_survives_a_save() {
        // Written before the field existed: on.
        let tmp = TempConfig::with(Some(LEGACY));
        let mut cfg = Config::load_or_create_at(tmp.0.clone()).expect("legacy config loads");
        assert!(cfg.auto_update);
        cfg.auto_update = false;
        cfg.save().expect("save");
        let on_disk = std::fs::read_to_string(&tmp.0).expect("written");
        assert!(on_disk.contains(r#""auto_update": false"#), "{on_disk}");
        let again = Config::load_or_create_at(tmp.0.clone()).expect("config reloads");
        assert!(!again.auto_update);
        // A fresh config: on.
        let fresh = TempConfig::with(None);
        assert!(
            Config::load_or_create_at(fresh.0.clone())
                .expect("created")
                .auto_update
        );
    }

    /// A config.json from before the game-only mode loads with it off and no game, and a save for
    /// any other reason does not add either field.
    #[test]
    fn an_old_config_has_game_only_off_and_gains_nothing_on_save() {
        let tmp = TempConfig::with(Some(LEGACY));
        let cfg = Config::load_or_create_at(tmp.0.clone()).expect("legacy config loads");
        assert!(!cfg.game_only);
        assert!(!cfg.game_only_for_guests);
        assert!(!cfg.game_helper);
        assert_eq!(cfg.game, None);
        assert_eq!(
            crate::game::CaptureMode::from_config(&cfg),
            crate::game::CaptureMode::Monitor
        );
        cfg.save().expect("save");
        let on_disk = std::fs::read_to_string(&tmp.0).expect("written");
        assert!(!on_disk.contains("game"), "{on_disk}");
        // A fresh config: off too.
        let fresh = TempConfig::with(None);
        let cfg = Config::load_or_create_at(fresh.0.clone()).expect("created");
        assert!(!cfg.game_only && !cfg.game_only_for_guests && cfg.game.is_none());
    }

    /// «Только для гостей» is off by default — in a config.json from before it and in a fresh one —
    /// so an existing PC keeps game-only for everyone; once on, it survives a save and a load, and
    /// it is not written while off.
    #[test]
    fn game_only_for_guests_is_off_by_default_and_round_trips() {
        // Game-only on, written before the switch existed: still for everyone.
        let text = LEGACY.replace(
            r#""autostart": true"#,
            r#""autostart": true, "game_only": true"#,
        );
        let tmp = TempConfig::with(Some(&text));
        let mut cfg = Config::load_or_create_at(tmp.0.clone()).expect("loads");
        assert!(cfg.game_only);
        assert!(
            !cfg.game_only_for_guests,
            "an old config: game-only for everyone"
        );
        cfg.save().expect("save");
        let on_disk = std::fs::read_to_string(&tmp.0).expect("written");
        assert!(!on_disk.contains("game_only_for_guests"), "{on_disk}");

        cfg.game_only_for_guests = true;
        cfg.save().expect("save");
        let on_disk = std::fs::read_to_string(&tmp.0).expect("written");
        assert!(
            on_disk.contains(r#""game_only_for_guests": true"#),
            "{on_disk}"
        );
        let mut again = Config::load_or_create_at(tmp.0.clone()).expect("reloads");
        assert!(again.game_only_for_guests, "survives a restart");
        assert!(again.game_only, "the mode itself untouched");

        again.game_only_for_guests = false;
        again.save().expect("save");
        let on_disk = std::fs::read_to_string(&tmp.0).expect("written");
        assert!(!on_disk.contains("game_only_for_guests"), "{on_disk}");
        let last = Config::load_or_create_at(tmp.0.clone()).expect("reloads");
        assert!(!last.game_only_for_guests);

        // A fresh config: off.
        let fresh = TempConfig::with(None);
        let created = Config::load_or_create_at(fresh.0.clone()).expect("created");
        assert!(!created.game_only_for_guests);
        // Parsed from text without the field (the CLI's way of reading it is the same load).
        let parsed: Config =
            serde_json::from_str(r#"{"device_id":"d","server_url":"ws://x","name":"n"}"#)
                .expect("parses");
        assert!(!parsed.game_only_for_guests);
    }

    /// The helper's switch and launch exe survive a save and a load, and are not written while off
    /// and unset; neither touches the capture mode.
    #[test]
    fn game_helper_and_its_launch_exe_round_trip_and_go_when_unset() {
        let tmp = TempConfig::with(Some(LEGACY));
        let mut cfg = Config::load_or_create_at(tmp.0.clone()).expect("loads");
        assert!(!cfg.game_helper && cfg.game_launch_exe.is_none());
        assert!(cfg.game_launch_learned.is_none());
        cfg.game_helper = true;
        cfg.game_launch_exe = Some(r"D:\Games\Scryde\Scryde\ScrydeGame.exe".into());
        cfg.game_launch_learned = Some(r"D:\Games\Scryde\Launcher.exe".into());
        cfg.save().expect("save");
        let mut again = Config::load_or_create_at(tmp.0.clone()).expect("reload");
        assert!(again.game_helper);
        assert_eq!(
            again.game_launch_exe.as_deref(),
            Some(r"D:\Games\Scryde\Scryde\ScrydeGame.exe")
        );
        assert_eq!(
            again.game_launch_learned.as_deref(),
            Some(r"D:\Games\Scryde\Launcher.exe")
        );
        assert!(!again.game_only, "the helper does not change capture mode");
        again.game_helper = false;
        again.game_launch_exe = None;
        again.game_launch_learned = None;
        again.save().expect("save");
        let text = std::fs::read_to_string(&tmp.0).expect("read");
        assert!(
            !text.contains("game_helper") && !text.contains("game_launch"),
            "{text}"
        );
    }

    /// The mode and the game survive a save and a load; turning the mode off keeps the game.
    #[test]
    fn game_only_and_the_game_round_trip() {
        let tmp = TempConfig::with(Some(LEGACY));
        let mut cfg = Config::load_or_create_at(tmp.0.clone()).expect("loads");
        let game = GameBinding::new(
            r"D:\Games\Scryde\Scryde\ScrydeGame.bin",
            "ScrydeGameUnrealWWindowsViewportWindow",
        );
        cfg.game_only = true;
        cfg.game = Some(game.clone());
        cfg.save().expect("save");
        let on_disk = std::fs::read_to_string(&tmp.0).expect("written");
        assert!(on_disk.contains(r#""game_only": true"#), "{on_disk}");
        assert!(
            on_disk.contains(r#""display_name": "ScrydeGame.bin""#),
            "{on_disk}"
        );
        let mut again = Config::load_or_create_at(tmp.0.clone()).expect("reloads");
        assert!(again.game_only);
        assert_eq!(again.game.as_ref(), Some(&game));
        assert_eq!(
            crate::game::CaptureMode::from_config(&again),
            crate::game::CaptureMode::GameWindow {
                binding: Some(game.clone())
            }
        );

        again.game_only = false;
        again.save().expect("save");
        let on_disk = std::fs::read_to_string(&tmp.0).expect("written");
        assert!(!on_disk.contains("game_only"), "{on_disk}");
        let last = Config::load_or_create_at(tmp.0.clone()).expect("reloads");
        assert!(!last.game_only);
        assert_eq!(last.game, Some(game), "the game stays bound for next time");
    }

    /// On with no game — a hand edit — is black frames only, never the desktop; a game written by
    /// hand without a display name loads, named by its exe.
    #[test]
    fn game_only_without_a_game_captures_no_monitor() {
        let text = LEGACY.replace(
            r#""autostart": true"#,
            r#""autostart": true, "game_only": true"#,
        );
        let tmp = TempConfig::with(Some(&text));
        let cfg = Config::load_or_create_at(tmp.0.clone()).expect("loads");
        assert_eq!(
            crate::game::CaptureMode::from_config(&cfg),
            crate::game::CaptureMode::GameWindow { binding: None }
        );

        let text = LEGACY.replace(
            r#""autostart": true"#,
            r#""autostart": true, "game_only": true, "game": { "exe_path": "C:\\G\\g.exe", "window_class": "W" }"#,
        );
        let tmp = TempConfig::with(Some(&text));
        let cfg = Config::load_or_create_at(tmp.0.clone()).expect("loads");
        let game = cfg.game.expect("a game");
        assert_eq!(game.display_name, "");
        assert_eq!(game.shown_name(), "g.exe");
    }

    /// The autostart card is offered once, after the first pairing, only while autostart is off;
    /// any answer ends it for good, and the state survives a restart.
    #[test]
    fn the_autostart_card_is_offered_once_and_never_after_an_answer() {
        let tmp = TempConfig::with(Some(
            &LEGACY.replace(r#""autostart": true"#, r#""autostart": false"#),
        ));
        let mut cfg = Config::load_or_create_at(tmp.0.clone()).expect("loads");
        assert_eq!(cfg.autostart_offer(), AutostartOffer::NotYet);
        // A save before any offer writes no field.
        cfg.save().expect("save");
        let on_disk = std::fs::read_to_string(&tmp.0).expect("written");
        assert!(!on_disk.contains("autostart_offer"), "{on_disk}");

        assert!(cfg.offer_autostart_after_first_pairing());
        assert_eq!(cfg.autostart_offer(), AutostartOffer::Pending);
        // A second first pairing (everyone unbound, then paired again) does not re-offer.
        assert!(!cfg.offer_autostart_after_first_pairing());
        cfg.save().expect("save");
        let mut again = Config::load_or_create_at(tmp.0.clone()).expect("reloads");
        assert_eq!(
            again.autostart_offer(),
            AutostartOffer::Pending,
            "survives a restart"
        );

        assert!(again.settle_autostart_offer("«Не надо»"));
        assert_eq!(again.autostart_offer(), AutostartOffer::Answered);
        assert!(!again.settle_autostart_offer("«Не надо»"), "once is enough");
        again.save().expect("save");
        let mut last = Config::load_or_create_at(tmp.0.clone()).expect("reloads");
        assert_eq!(last.autostart_offer(), AutostartOffer::Answered);
        assert!(
            !last.offer_autostart_after_first_pairing(),
            "never again after an answer"
        );

        // Autostart already on at the first pairing: nothing to ask.
        let tmp = TempConfig::with(Some(LEGACY));
        let mut on = Config::load_or_create_at(tmp.0.clone()).expect("loads");
        assert!(on.autostart);
        assert!(!on.offer_autostart_after_first_pairing());
        assert_eq!(on.autostart_offer(), AutostartOffer::NotYet);

        // A value from a newer build reads as answered: the card never comes back by accident.
        let text = LEGACY.replace(
            r#""autostart": true"#,
            r#""autostart": false, "autostart_offer": "snoozed""#,
        );
        let tmp = TempConfig::with(Some(&text));
        let newer = Config::load_or_create_at(tmp.0.clone()).expect("loads");
        assert_eq!(newer.autostart_offer(), AutostartOffer::Answered);
    }

    /// «Управление не доходит» survives a restart while set, and an old config.json — or a save with
    /// it off — has no such field.
    #[test]
    fn the_input_highlight_round_trips_and_is_not_written_while_off() {
        let tmp = TempConfig::with(Some(LEGACY));
        let mut cfg = Config::load_or_create_at(tmp.0.clone()).expect("legacy config loads");
        assert!(!cfg.input_not_reaching);
        cfg.save().expect("save");
        let on_disk = std::fs::read_to_string(&tmp.0).expect("written");
        assert!(!on_disk.contains("input_not_reaching"), "{on_disk}");

        cfg.input_not_reaching = true;
        cfg.save().expect("save");
        let on_disk = std::fs::read_to_string(&tmp.0).expect("written");
        assert!(
            on_disk.contains(r#""input_not_reaching": true"#),
            "{on_disk}"
        );
        let mut again = Config::load_or_create_at(tmp.0.clone()).expect("reloads");
        assert!(again.input_not_reaching, "survives a restart");

        again.input_not_reaching = false;
        again.save().expect("save");
        let on_disk = std::fs::read_to_string(&tmp.0).expect("written");
        assert!(!on_disk.contains("input_not_reaching"), "{on_disk}");
    }

    /// The kill switch's pause survives a restart while set; an old config.json — or a save with
    /// it off — has no such field, and a save leaves nothing beside the file.
    #[test]
    fn the_pause_round_trips_and_is_not_written_while_off() {
        let tmp = TempConfig::with(Some(LEGACY));
        let mut cfg = Config::load_or_create_at(tmp.0.clone()).expect("legacy config loads");
        assert!(!cfg.paused, "a config from before the field: not paused");
        cfg.save().expect("save");
        let on_disk = std::fs::read_to_string(&tmp.0).expect("written");
        assert!(!on_disk.contains("paused"), "{on_disk}");

        cfg.paused = true;
        cfg.save().expect("save");
        let on_disk = std::fs::read_to_string(&tmp.0).expect("written");
        assert!(on_disk.contains(r#""paused": true"#), "{on_disk}");
        let mut again = Config::load_or_create_at(tmp.0.clone()).expect("reloads");
        assert!(again.paused, "survives a restart");
        assert_eq!(again.name, "PC", "the rest as it was");

        again.paused = false;
        again.save().expect("save");
        let on_disk = std::fs::read_to_string(&tmp.0).expect("written");
        assert!(!on_disk.contains("paused"), "{on_disk}");
        assert!(
            !Config::load_or_create_at(tmp.0.clone())
                .expect("reloads")
                .paused
        );

        // Written whole: nothing but config.json is left in its directory.
        let dir = tmp.0.parent().expect("a directory");
        let names: Vec<String> = std::fs::read_dir(dir)
            .expect("listed")
            .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, ["config.json"], "no temporary file left behind");
        // A fresh config: not paused.
        let fresh = TempConfig::with(None);
        assert!(
            !Config::load_or_create_at(fresh.0.clone())
                .expect("created")
                .paused
        );
    }

    /// A save that cannot put the new file in place (here: `path` is a directory) leaves what was
    /// there and no temporary file, and says why.
    #[test]
    fn a_save_that_cannot_replace_the_file_leaves_it_and_no_temporary() {
        let tmp = TempConfig::with(Some(LEGACY));
        let cfg = Config::load_or_create_at(tmp.0.clone()).expect("loads");
        let dir = tmp.0.parent().expect("a directory").to_path_buf();
        let blocked = dir.join("blocked.json");
        std::fs::create_dir_all(blocked.join("inside")).expect("a directory in the way");
        let err = cfg
            .save_to(&blocked)
            .expect_err("a directory cannot be replaced");
        assert!(format!("{err:#}").contains("blocked.json"), "{err:#}");
        let leftovers: Vec<String> = std::fs::read_dir(&dir)
            .expect("listed")
            .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
            .filter(|n| n.ends_with(".tmp"))
            .collect();
        assert!(leftovers.is_empty(), "{leftovers:?}");
        assert!(blocked.join("inside").is_dir(), "what was there stays");
    }

    /// What a crashed save left beside config.json goes at the next load and the next save; a
    /// temporary file of a save under way (fresh) and every other file stay.
    #[test]
    fn a_crashed_saves_leftover_goes_and_nothing_else() {
        let tmp = TempConfig::with(Some(LEGACY));
        let dir = tmp.0.parent().expect("a directory").to_path_buf();
        let old = dir.join(".config.json.0b5e7a1c-0000-4000-8000-000000000001.tmp");
        let fresh = dir.join(".config.json.0b5e7a1c-0000-4000-8000-000000000002.tmp");
        let others = [
            dir.join("identity.json"),
            dir.join(".identity.json.0b5e7a1c-0000-4000-8000-000000000003.tmp"),
            dir.join("config.json.tmp"),
        ];
        let an_hour_ago = std::time::SystemTime::now() - std::time::Duration::from_secs(3600);
        for path in [&old, &fresh].into_iter().chain(others.iter()) {
            std::fs::write(path, b"{").expect("written");
        }
        for path in [&old].into_iter().chain(others.iter()) {
            std::fs::File::options()
                .write(true)
                .open(path)
                .and_then(|f| f.set_modified(an_hour_ago))
                .expect("dated");
        }
        let cfg = Config::load_or_create_at(tmp.0.clone()).expect("loads");
        assert!(!old.exists(), "a crashed save's leftover goes at the load");
        assert!(fresh.exists(), "a save under way is left");
        for other in &others {
            assert!(other.exists(), "{}", other.display());
        }
        // And at a save, once it is old.
        std::fs::File::options()
            .write(true)
            .open(&fresh)
            .and_then(|f| f.set_modified(an_hour_ago))
            .expect("dated");
        cfg.save().expect("save");
        assert!(!fresh.exists());
        assert!(is_temporary_of(".config.json.x.tmp", "config.json"));
        assert!(!is_temporary_of(".config.json.tmp", "config.json"));
        assert!(!is_temporary_of("config.json.x.tmp", "config.json"));
        assert!(!is_temporary_of(".config.jsonx.tmp", "config.json"));
    }

    /// The pause's save (`save_even_in_place`): whole when it can be; written over in place when
    /// another program holds the file so that it cannot be replaced (here: open without delete
    /// sharing); nothing for a config with no file.
    #[cfg(windows)]
    #[test]
    fn the_pause_is_written_in_place_when_the_file_cannot_be_replaced() {
        use std::os::windows::fs::OpenOptionsExt;
        let tmp = TempConfig::with(Some(LEGACY));
        let mut cfg = Config::load_or_create_at(tmp.0.clone()).expect("loads");
        cfg.paused = true;
        assert_eq!(cfg.save_even_in_place().expect("saved"), Saved::Whole);
        cfg.paused = false;
        // FILE_SHARE_READ | FILE_SHARE_WRITE, not FILE_SHARE_DELETE: no rename over it.
        let holder = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(0x1 | 0x2)
            .open(&tmp.0)
            .expect("held");
        let started = std::time::Instant::now();
        assert!(cfg.save().is_err(), "a whole save cannot replace it");
        assert!(
            started.elapsed() >= std::time::Duration::from_millis(700),
            "it kept trying for most of a second: {:?}",
            started.elapsed()
        );
        assert_eq!(cfg.save_even_in_place().expect("saved"), Saved::InPlace);
        drop(holder);
        let again = Config::load_or_create_at(tmp.0.clone()).expect("reloads");
        assert!(!again.paused, "the in-place write is the file");
        let leftovers = std::fs::read_dir(tmp.0.parent().expect("dir"))
            .expect("listed")
            .filter(|e| {
                e.as_ref()
                    .is_ok_and(|e| e.file_name().to_string_lossy().ends_with(".tmp"))
            })
            .count();
        assert_eq!(leftovers, 0, "no temporary file left behind");
        let parsed: Config =
            serde_json::from_str(r#"{"device_id":"d","server_url":"ws://x","name":"n"}"#)
                .expect("parses");
        assert_eq!(parsed.save_even_in_place().expect("nothing"), Saved::NoFile);
    }

    /// A config.json written by this load is a new device (its id was generated now); one read from
    /// disk is not, whatever is in it — the next launch included.
    #[test]
    fn only_a_config_written_now_is_a_new_device() {
        let fresh = TempConfig::with(None);
        let created = Config::load_or_create_at(fresh.0.clone()).expect("created");
        assert!(
            created.created(),
            "no config.json: a device id generated now"
        );
        let again = Config::load_or_create_at(fresh.0.clone()).expect("reloads");
        assert!(!again.created(), "the next launch reads it");
        assert_eq!(again.device_id, created.device_id);

        let tmp = TempConfig::with(Some(LEGACY));
        let legacy = Config::load_or_create_at(tmp.0.clone()).expect("loads");
        assert!(!legacy.created());
        // Parsed from text (the CLI's and the tests' way): not a file written now either.
        let parsed: Config =
            serde_json::from_str(r#"{"device_id":"d","server_url":"ws://x","name":"n"}"#)
                .expect("parses");
        assert!(!parsed.created());
    }

    /// A production build connects only to the product's server: a config.json holding any other
    /// address — a retired name of the server, one set by hand, a server on this machine — moves to
    /// it at load, on disk too, and says so once (`server_moved_from`, the binaries' first line). A
    /// dev build (these tests are one) leaves every address alone but the editable era's untouched
    /// default.
    #[test]
    fn a_production_build_replaces_an_address_it_does_not_connect_to() {
        assert_eq!(PROD_SERVER_URL, "wss://api.afklink.app/ws/agent");
        let staging = "wss://staging.example.test/ws/agent";
        let elsewhere = [
            "wss://example.test/ws/agent",
            "wss://old.example.test/ws/agent",
            "wss://api.afklink.app.evil.test/ws/agent",
            "wss://user@localhost/ws/agent",
            "ws://api.afklink.app/ws/agent",
            "wss://api.afklink.app:8443/ws/agent",
            "WSS://API.AFKLINK.APP/ws/agent",
            " wss://api.afklink.app/ws/agent",
            "not a url",
            "",
            // A server on this machine is whichever local process binds the port first.
            "ws://localhost:9000/ws/agent",
            "ws://LOCALHOST/ws/agent",
            "WS://LocalHost:8787/ws/agent",
            "ws://127.0.0.1:8787/ws/agent",
            "ws://127.1.2.3:8787/ws/agent",
            "ws://[::1]:8787/ws/agent",
            "wss://localhost:8443/ws/agent",
            // Spellings that only look like one (or are one the predicate does not name).
            "ws://localhost@evil.test/ws/agent",
            "ws://[::ffff:127.0.0.1]/ws/agent",
            "ws://localhost./ws/agent",
            "ws://127.0.0.1.evil.test/ws/agent",
            "ws://[::1]evil.test/ws/agent",
        ];
        for stored in elsewhere {
            let (to, why) = server_moves_to(stored, PROD_SERVER_URL)
                .unwrap_or_else(|| panic!("{stored:?} stays under a production build"));
            assert_eq!(to, PROD_SERVER_URL, "{stored:?}");
            // The log names a server on this machine as such.
            assert_eq!(
                why.contains("on this machine"),
                is_loopback_server_url(stored),
                "{stored:?}: {why}"
            );
            // A dev build connects where it is told.
            assert_eq!(
                server_moves_to(stored, LEGACY_DEFAULT_SERVER_URL),
                None,
                "{stored:?}"
            );
            // A build stamped with another server: only the untouched default would move.
            assert_eq!(server_moves_to(stored, staging), None, "{stored:?}");
        }
        // The production server itself is left alone.
        assert_eq!(server_moves_to(PROD_SERVER_URL, PROD_SERVER_URL), None);
        // The editable era's untouched default adopts a build's own, when it has another.
        assert_eq!(
            server_moves_to(LEGACY_DEFAULT_SERVER_URL, PROD_SERVER_URL).map(|(to, _)| to),
            Some(PROD_SERVER_URL)
        );
        assert_eq!(
            server_moves_to(LEGACY_DEFAULT_SERVER_URL, LEGACY_DEFAULT_SERVER_URL),
            None
        );
        assert_eq!(
            server_moves_to(LEGACY_DEFAULT_SERVER_URL, staging).map(|(to, _)| to),
            Some(staging)
        );

        // Under this (dev) build a hand-set address stays, on disk too, and nothing is reported.
        let tmp = TempConfig::with(Some(LEGACY));
        let cfg = Config::load_or_create_at(tmp.0.clone()).expect("loads");
        assert_eq!(cfg.server_url, "wss://example.test/ws/agent");
        assert_eq!(cfg.server_moved_from(), None);
        // The untouched default moves where the build's default is another (a prod build), saved
        // and reported; only once: the next load finds the build's own.
        if DEFAULT_SERVER_URL != LEGACY_DEFAULT_SERVER_URL {
            let old = LEGACY.replace("wss://example.test/ws/agent", LEGACY_DEFAULT_SERVER_URL);
            let tmp = TempConfig::with(Some(&old));
            let cfg = Config::load_or_create_at(tmp.0.clone()).expect("loads");
            assert_eq!(cfg.server_url, DEFAULT_SERVER_URL);
            assert_eq!(cfg.server_moved_from(), Some(LEGACY_DEFAULT_SERVER_URL));
            let again = Config::load_or_create_at(tmp.0.clone()).expect("reloads");
            assert_eq!(again.server_moved_from(), None);
        }
    }

    /// Which spellings name a server on this machine (the reason logged when a production build
    /// replaces one): the canonical ones only. Lookalikes — credentials before the host, a host that
    /// merely starts with `localhost` or `127.0.0.1`, anything glued to `[::1]` — are not.
    #[test]
    fn a_loopback_server_url_is_only_a_canonical_spelling() {
        for loopback in [
            "ws://localhost/ws/agent",
            "ws://localhost:8787/ws/agent",
            "wss://localhost:8443",
            "WS://LOCALHOST:8787/ws/agent",
            "Wss://LocalHost/ws/agent",
            "ws://127.0.0.1:8787/ws/agent",
            "ws://127.255.255.254/ws/agent",
            "ws://[::1]/ws/agent",
            "ws://[::1]:8787/ws/agent",
            "ws://localhost?x=1",
            "ws://localhost#x",
            " ws://localhost:8787/ws/agent ",
        ] {
            assert!(is_loopback_server_url(loopback), "{loopback:?}");
        }
        for not_loopback in [
            "ws://localhost@evil.test/ws/agent",
            "ws://user@localhost/ws/agent",
            "ws://user:pass@127.0.0.1/ws/agent",
            "ws://[::ffff:127.0.0.1]/ws/agent",
            "ws://[0:0:0:0:0:0:0:1]/ws/agent",
            "ws://localhost./ws/agent",
            "ws://localhost.evil.test/ws/agent",
            "ws://127.0.0.1.evil.test/ws/agent",
            "ws://127.1/ws/agent",
            "ws://0x7f.0.0.1/ws/agent",
            "ws://2130706433/ws/agent",
            "ws://[::1]evil.test/ws/agent",
            "ws://[::1].evil.test/ws/agent",
            "ws://[::1]:/ws/agent",
            "ws://[::1]:8787x/ws/agent",
            "ws://[::1/ws/agent",
            "ws://localhost:/ws/agent",
            "ws://localhost:87870/ws/agent",
            "ws://localhost:8787:9000/ws/agent",
            "ws://localhost:evil.test/ws/agent",
            "ws://10.0.0.1/ws/agent",
            "ws://128.0.0.1/ws/agent",
            "http://localhost/ws/agent",
            "https://127.0.0.1/ws/agent",
            "localhost:8787",
            "ws:/localhost",
            "",
        ] {
            assert!(!is_loopback_server_url(not_loopback), "{not_loopback:?}");
        }
    }

    #[test]
    fn a_fresh_config_chooses_no_level() {
        let tmp = TempConfig::with(None);
        let cfg = Config::load_or_create_at(tmp.0.clone()).expect("config created");
        assert_eq!(cfg.log_level(), Ok(None));
        // Not written: the first build to run must not fix the level for every later one.
        let on_disk = std::fs::read_to_string(&tmp.0).expect("written");
        assert!(!on_disk.contains("log_level"), "{on_disk}");
    }
}
