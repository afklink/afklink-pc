//! Log levels: the one place that turns the level picked in Settings into a `tracing` filter.
//!
//! Both binaries build their filter here (the desktop app: stdout plus a daily file, switchable at
//! runtime; the CLI agent: stdout), so a level cannot come to mean one thing in one of them and
//! something else in the other, and `RUST_LOG` takes precedence the same way in both.
//!
//! The chosen level applies to **our** crates: every `afklink_*` target, `afklink_app_lib` and
//! `afklink_agent` included. Third-party crates (str0m, tokio-tungstenite, tauri, wry, tao, ...)
//! are capped at `warn` for every level below `trace` (`THIRD_PARTY_CAP`): their warnings and
//! errors are ours to know about, their chatter is not. Settings offers three levels
//! ([`LogLevel::OFFERED`]).
//!
//! # Where the level comes from
//!
//! `RUST_LOG` if set; else the level chosen in Settings, which config.json keeps as `log_level`;
//! else the build channel's default ([`default_log_level`]): `debug` for a development build, and
//! for a release whatever [`RELEASE_PHASE`] says (`debug` during the beta test, `info` after it).
//! config.json holds `log_level` only once someone has picked a level (a fresh config does not
//! write it), so a fresh install follows its build's channel, and a beta install moves to `info`
//! with the release after the beta, until its owner picks one. Settings has no «Automatic»: it
//! shows the level in effect selected, and any pick is saved.

use std::fmt;
use std::str::FromStr;

use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::EnvFilter;

use crate::build_info::Channel;
use crate::config::Config;

/// Where the product is in its life, as far as a release build's log is concerned.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ReleasePhase {
    /// The beta test: releases log at `debug` by default until it ends, then at `info`. A tester's
    /// session is a test like a development build's, and its log is what gets read after a bad
    /// one — so a release logs at [`LogLevel::Debug`] until a level is chosen.
    Beta,
    /// After the beta: [`LogLevel::Info`]. An end user's machine has no one reading debug lines,
    /// and it should not be writing them; the once-a-second `pipeline` line is `info` and stays.
    General,
}

/// The phase every release is built in: [`ReleasePhase::Beta`] while the beta test lasts.
///
/// **Set it back to [`ReleasePhase::General`] when the beta ends** — this line is the whole switch:
/// the default, the startup log line that explains it, the level Settings shows selected while none
/// is chosen, and the tests all follow it. Development builds log at `debug` either way.
pub const RELEASE_PHASE: ReleasePhase = ReleasePhase::Beta;

impl ReleasePhase {
    /// The level a release built in this phase runs at when nothing is chosen.
    pub const fn default_log_level(self) -> LogLevel {
        match self {
            Self::Beta => LogLevel::Debug,
            Self::General => LogLevel::Info,
        }
    }
}

/// The level a build runs at when config.json has no chosen `log_level`.
///
/// - [`Channel::Release`] → [`RELEASE_PHASE`]'s: [`LogLevel::Debug`] during the beta test,
///   [`LogLevel::Info`] after it (see [`ReleasePhase`]).
/// - [`Channel::Dev`] → [`LogLevel::Debug`]: every session is a test, and its log is the first
///   thing read afterwards.
pub const fn default_log_level(channel: Channel) -> LogLevel {
    match channel {
        Channel::Dev => LogLevel::Debug,
        Channel::Release => RELEASE_PHASE.default_log_level(),
    }
}

/// Why [`default_log_level`] is what it is for `channel`, for the startup line
/// ([`StartupFilter::log_summary`]): with a release, the phase that decided it.
pub const fn default_log_level_reason(channel: Channel) -> &'static str {
    match channel {
        Channel::Dev => "every session of a development build is a test",
        Channel::Release => match RELEASE_PHASE {
            ReleasePhase::Beta => "releases log at debug during the beta test and at info after it",
            ReleasePhase::General => "an end user's machine has no one reading debug lines",
        },
    }
}

/// The level in effect for our crates (`RUST_LOG` aside): the one chosen, else the channel's
/// default.
pub const fn effective_level(choice: Option<LogLevel>, channel: Channel) -> LogLevel {
    match choice {
        Some(level) => level,
        None => default_log_level(channel),
    }
}

/// The environment variable that overrides the setting — the standard one, so a developer's
/// habit (`$env:RUST_LOG = "afklink_core=trace"`) works unchanged against either binary.
pub const ENV_FILTER_VAR: &str = "RUST_LOG";

/// The target prefix of every crate in this workspace.
///
/// One prefix rather than a list of crates: `EnvFilter` matches a directive's target as a string
/// prefix of the event's target (its module path), so `afklink=debug` covers `afklink_core::agent`,
/// `afklink_app_lib` and `afklink_agent` alike — and a crate added later cannot be forgotten here.
/// The tests below pin that behaviour against the real `EnvFilter`.
const OUR_TARGETS: &str = "afklink";

/// The most a third-party crate is allowed to say below [`LogLevel::Trace`]. From the sources at
/// the versions in Cargo.lock:
///
/// - str0m has no `info` lines at all. Its `debug` lines are connection state (ICE, DTLS, SCTP,
///   SDP), few per session. Our patch to its delay detector (vendor/VENDORED.md) logs under
///   `afklink_str0m::trendline`, so it is ours (an `afklink` target): `debug` writes its decisions.
///   Its `trace` lines include every datagram in (`IN`) and out (`OUT`), every RTP packet polled,
///   every data-channel message and every stats event: two to three lines per packet, and a 1080p60
///   session sends 400–500 packets a second.
/// - tao, wry and tauri are close to silent below `warn` on Windows (tao has a single `trace` site
///   there).
///
/// `trace` opens everything, str0m's packet trace and its bandwidth-estimator internals included.
/// Estimated from the code at a session's packet rate: on the order of a thousand lines and a few
/// hundred kilobytes a second. It is for a short capture of a WebRTC problem, not for leaving on.
const THIRD_PARTY_CAP: LogLevel = LogLevel::Warn;

/// How much the agent writes, from nothing to everything.
///
/// Ordered by verbosity, so `a < b` means `a` writes less than `b`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LogLevel {
    /// Nothing at all: no file is created, stdout stays silent.
    Off,
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

impl LogLevel {
    /// Every level, least to most verbose: every name config.json or a `set_log_level` may hold.
    pub const ALL: [Self; 6] = [
        Self::Off,
        Self::Error,
        Self::Warn,
        Self::Info,
        Self::Debug,
        Self::Trace,
    ];

    /// The three Settings offers, in its order: «Выключены», «Обычные», «Подробные». Every level
    /// settles on one of these or stays `trace`.
    ///
    /// A user needs a detailed level for development, a minimal one for product use that is still
    /// enough to work out a user's problem, and off; config.json is written with one of them:
    ///
    /// - «Подробные», `debug`: development, and every build's default during the beta test;
    /// - «Обычные», `info`: the product's level and a release's default after the beta (the session
    ///   files and the system log at `info`, enough to work out a user's problem);
    /// - «Выключены», `off`: nothing is written.
    ///
    /// The other names still parse, so an older config.json (six levels) loads: `error` and `warn`
    /// read as `info` ([`Self::settled`]) and are written back as `info` at load
    /// (`Config::load_or_create_at`, said on the startup line); `trace` (a developer's hand edit,
    /// or `RUST_LOG`) keeps working as it is and shows in Settings as «Подробные»
    /// ([`Self::shown_as`]).
    pub const OFFERED: [Self; 3] = [Self::Off, Self::Info, Self::Debug];

    /// What a stored level means since the three levels: `error` and `warn` — offered before — read
    /// as `info` («Обычные»), the least Settings offers short of off; every other level is itself.
    /// `trace` stays `trace`: it is not offered, but a developer who wrote it by hand gets it.
    pub const fn settled(self) -> Self {
        match self {
            Self::Error | Self::Warn => Self::Info,
            other => other,
        }
    }

    /// The option Settings shows selected for this level in effect: the level [`Self::settled`]
    /// on, and `trace` as «Подробные» (`debug`), the option it is a louder form of.
    pub const fn shown_as(self) -> Self {
        match self.settled() {
            Self::Trace => Self::Debug,
            other => other,
        }
    }

    /// Whether Settings offers this level ([`Self::OFFERED`]).
    pub fn is_offered(self) -> bool {
        Self::OFFERED.contains(&self)
    }

    /// The name stored in config.json and shown in the log.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Error => "error",
            Self::Warn => "warn",
            Self::Info => "info",
            Self::Debug => "debug",
            Self::Trace => "trace",
        }
    }

    /// The `EnvFilter` directives for this level (see the module docs for why they look so).
    ///
    /// | level   | directives           |
    /// |---------|----------------------|
    /// | `off`   | `off`                |
    /// | `error` | `error`              |
    /// | `warn`  | `warn`               |
    /// | `info`  | `warn,afklink=info`  |
    /// | `debug` | `warn,afklink=debug` |
    /// | `trace` | `trace`              |
    pub fn filter_directives(self) -> String {
        match self {
            Self::Off | Self::Trace => self.as_str().to_string(),
            ours => {
                let theirs = ours.min(THIRD_PARTY_CAP);
                if theirs == ours {
                    ours.as_str().to_string()
                } else {
                    format!("{theirs},{OUR_TARGETS}={ours}")
                }
            }
        }
    }

    /// [`Self::filter_directives`], parsed and ready to install.
    pub fn filter(self) -> EnvFilter {
        // Lossy parse, which cannot fail: the directives above are fixed, and the tests parse
        // every one of them strictly.
        EnvFilter::new(self.filter_directives())
    }
}

impl fmt::Display for LogLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A level name this build does not know — a hand edit, or a level a newer build added.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownLogLevel(pub String);

impl fmt::Display for UnknownLogLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "unknown log level {:?} (expected off, info or debug; also trace, error, warn)",
            self.0
        )
    }
}

impl std::error::Error for UnknownLogLevel {}

impl FromStr for LogLevel {
    type Err = UnknownLogLevel;

    /// Exact names, ignoring case and surrounding whitespace — what a person editing
    /// config.json by hand might reasonably type.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let wanted = s.trim();
        Self::ALL
            .into_iter()
            .find(|level| level.as_str().eq_ignore_ascii_case(wanted))
            .ok_or_else(|| UnknownLogLevel(s.to_string()))
    }
}

/// `RUST_LOG`, when it is set to something.
///
/// Blank counts as unset: `set RUST_LOG=` in cmd leaves an empty variable behind, and an empty
/// filter would silently mean "errors only" rather than "use the setting".
pub fn env_filter_override() -> Option<String> {
    std::env::var(ENV_FILTER_VAR)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

/// The level config.json chose — settled ([`LogLevel::settled`]: `error` and `warn` mean `info`) —
/// and a warning when what it holds could not be used.
///
/// `(None, None)`: nothing chosen — the channel's default applies, and that is not worth a warning.
/// `(None, Some(why))`: a value this build does not know, or a config that could not be read at
/// all (`config` is `None`) — the channel's default applies, and the log says why.
///
/// The warning is returned rather than logged: this runs before there is a subscriber, because the
/// level is what decides how the subscriber is built.
pub fn level_from_config(
    config: Option<&Config>,
    channel: Channel,
) -> (Option<LogLevel>, Option<String>) {
    let default = default_log_level(channel);
    match config.map(Config::log_level) {
        Some(Ok(choice)) => (choice, None),
        Some(Err(unknown)) => (
            None,
            Some(format!(
                "config.json: {unknown}; using the {channel} build's default, {default}"
            )),
        ),
        None => (
            None,
            Some(format!(
                "config.json could not be read; logging at the {channel} build's default, {default}"
            )),
        ),
    }
}

/// A level config.json held in its old form, rewritten at load in the three-level one
/// (`Config::log_level_moved`): `warn` or `error` as `info`, or a name in other case or with spaces
/// around it as the name itself. Kept for the startup line: config.json is read before the log
/// exists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LevelMoved {
    /// What config.json held, verbatim.
    pub from: String,
    /// What it holds now.
    pub to: LogLevel,
    /// Why the rewrite did not reach the disk, when it did not. In effect for this run either way;
    /// the next start reads the old value and rewrites it again.
    pub not_saved: Option<String>,
}

/// The filter a binary starts with, and where it came from.
///
/// Precedence: `RUST_LOG` if it is set and parses (a developer's override), else the level chosen
/// in config.json, else the channel's [`default_log_level`].
#[derive(Debug, Clone)]
pub struct StartupFilter {
    /// The level for our crates: [`Self::choice`], else [`Self::default_level`]. In effect unless
    /// [`Self::env_override`] is set.
    pub level: LogLevel,
    /// The level chosen in Settings (config.json `log_level`); `None` when none is chosen or the
    /// stored one is unusable — then the channel's default applies.
    pub choice: Option<LogLevel>,
    /// The build channel's default, [`default_log_level`].
    pub default_level: LogLevel,
    /// The channel the default comes from.
    pub channel: Channel,
    /// `RUST_LOG`, when it decides the filter instead of [`Self::level`].
    pub env_override: Option<String>,
    /// The directives in effect: `env_override` verbatim, or `level`'s.
    directives: String,
    /// What had to be assumed on the way, for the log once it exists.
    warnings: Vec<String>,
    /// config.json's level as this load rewrote it, for the log once it exists.
    moved: Option<LevelMoved>,
}

impl StartupFilter {
    /// Resolve against this process's `RUST_LOG`, for a build of `channel`.
    pub fn resolve(config: Option<&Config>, channel: Channel) -> Self {
        Self::resolve_with(config, channel, env_filter_override())
    }

    fn resolve_with(config: Option<&Config>, channel: Channel, env: Option<String>) -> Self {
        let (choice, level_warning) = level_from_config(config, channel);
        let default_level = default_log_level(channel);
        let level = effective_level(choice, channel);
        let mut warnings: Vec<String> = level_warning.into_iter().collect();
        let env_override = env.and_then(|spec| match EnvFilter::try_new(&spec) {
            Ok(_) => Some(spec),
            Err(e) => {
                warnings.push(format!(
                    "{ENV_FILTER_VAR}={spec:?} does not parse ({e}); using the configured level"
                ));
                None
            }
        });
        let directives = env_override
            .clone()
            .unwrap_or_else(|| level.filter_directives());
        Self {
            level,
            choice,
            default_level,
            channel,
            env_override,
            directives,
            warnings,
            moved: config.and_then(Config::log_level_moved).cloned(),
        }
    }

    /// The filter to install.
    pub fn filter(&self) -> EnvFilter {
        // Lossy parse, which cannot fail here: an override that did not parse strictly was
        // dropped in `resolve_with`, and a level's directives always parse.
        EnvFilter::new(&self.directives)
    }

    /// Whether this filter lets anything through at all. False for `off` — from the setting or
    /// from `RUST_LOG=off` — and the desktop app then creates no log file.
    pub fn writes_anything(&self) -> bool {
        self.filter().max_level_hint() != Some(LevelFilter::OFF)
    }

    /// Where [`Self::level`] comes from, for [`Self::log_summary`]: the choice, or the channel's
    /// default — named, with why it is that ([`default_log_level_reason`]) either way, so a log
    /// from a release says whether it was built for the beta.
    fn source(&self) -> String {
        let why = default_log_level_reason(self.channel);
        match self.choice {
            Some(_) => format!(
                "chosen in config.json; the {} build's default is {}, because {why}",
                self.channel, self.default_level
            ),
            None => format!(
                "the {} build's default, because {why}; none chosen in config.json",
                self.channel
            ),
        }
    }

    /// Log which filter is in effect and why, and anything that had to be assumed. Call once, right
    /// after the subscriber is installed.
    pub fn log_summary(&self) {
        let source = self.source();
        match &self.env_override {
            Some(spec) => tracing::info!(
                "log filter {spec:?} from {ENV_FILTER_VAR}, overriding the configured level {} \
                 ({source})",
                self.level
            ),
            None => tracing::info!(
                "log level {} ({source}; filter {:?}; {ENV_FILTER_VAR} overrides it)",
                self.level,
                self.directives
            ),
        }
        if let Some(moved) = &self.moved {
            match &moved.not_saved {
                None => tracing::info!(
                    from = %moved.from,
                    to = %moved.to,
                    "config.json: log level {:?} is now {} — the window's three levels (off, info, \
                     debug; error and warn read as info); written back",
                    moved.from,
                    moved.to
                ),
                Some(e) => tracing::warn!(
                    from = %moved.from,
                    to = %moved.to,
                    "config.json: log level {:?} is read as {} (the window's three levels), but \
                     not written back: {e}; the next start reads it so again",
                    moved.from,
                    moved.to
                ),
            }
        }
        for warning in &self.warnings {
            tracing::warn!("{warning}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tracing_subscriber::layer::SubscriberExt;

    /// Whether an event at `$level` from `$target` gets through `$directives`, asked of a real
    /// `EnvFilter` behind a real subscriber — the target matching is the part worth testing, and
    /// re-implementing it here would test nothing.
    macro_rules! passes {
        ($directives:expr, $target:literal, $level:ident) => {{
            let filter = EnvFilter::try_new($directives).expect("directives parse strictly");
            let subscriber = tracing_subscriber::registry().with(filter);
            tracing::subscriber::with_default(subscriber, || {
                tracing::enabled!(target: $target, tracing::Level::$level)
            })
        }};
    }

    #[test]
    fn the_default_follows_the_channel_and_a_release_follows_its_phase() {
        assert_eq!(ReleasePhase::Beta.default_log_level(), LogLevel::Debug);
        assert_eq!(ReleasePhase::General.default_log_level(), LogLevel::Info);
        assert_eq!(
            default_log_level(Channel::Release),
            RELEASE_PHASE.default_log_level()
        );
        assert_eq!(default_log_level(Channel::Dev), LogLevel::Debug);
        // Never quieter than `info`, whatever the phase: the `pipeline` line is `info`.
        assert!(default_log_level(Channel::Release) >= LogLevel::Info);
        // A choice wins over either default, whichever way it points.
        for channel in [Channel::Dev, Channel::Release] {
            assert_eq!(effective_level(None, channel), default_log_level(channel));
            for level in LogLevel::ALL {
                assert_eq!(effective_level(Some(level), channel), level);
            }
        }
    }

    #[test]
    fn names_round_trip() {
        for level in LogLevel::ALL {
            assert_eq!(level.as_str().parse::<LogLevel>(), Ok(level));
            assert_eq!(level.to_string(), level.as_str());
        }
    }

    #[test]
    fn parsing_forgives_case_and_whitespace_only() {
        assert_eq!(" Debug\n".parse::<LogLevel>(), Ok(LogLevel::Debug));
        assert_eq!("OFF".parse::<LogLevel>(), Ok(LogLevel::Off));
        for junk in ["", "verbose", "warning", "dbg", "5", "info,afklink=debug"] {
            assert_eq!(
                junk.parse::<LogLevel>(),
                Err(UnknownLogLevel(junk.to_string())),
                "{junk:?}"
            );
        }
    }

    #[test]
    fn levels_are_ordered_by_verbosity() {
        assert!(LogLevel::ALL.windows(2).all(|w| w[0] < w[1]));
        assert!(LogLevel::OFFERED.windows(2).all(|w| w[0] < w[1]));
    }

    /// The three levels: what Settings offers, what each older name means now, and the
    /// option each level in effect shows as.
    #[test]
    fn three_levels_are_offered_and_every_other_settles_or_shows_as_one() {
        assert_eq!(
            LogLevel::OFFERED,
            [LogLevel::Off, LogLevel::Info, LogLevel::Debug]
        );
        let got: Vec<(LogLevel, LogLevel, LogLevel, bool)> = LogLevel::ALL
            .into_iter()
            .map(|l| (l, l.settled(), l.shown_as(), l.is_offered()))
            .collect();
        use LogLevel::*;
        assert_eq!(
            got,
            [
                (Off, Off, Off, true),
                // «Обычные»: the least Settings offers short of off.
                (Error, Info, Info, false),
                (Warn, Info, Info, false),
                (Info, Info, Info, true),
                (Debug, Debug, Debug, true),
                // Kept working, shown as «Подробные».
                (Trace, Trace, Debug, false),
            ]
        );
        // Every level in effect shows as one of the three.
        assert!(LogLevel::ALL.iter().all(|l| l.shown_as().is_offered()));
        // A release after the beta defaults to «Обычные», which the product's logs are written at.
        assert!(ReleasePhase::General.default_log_level().is_offered());
        assert!(ReleasePhase::Beta.default_log_level().is_offered());
    }

    /// A config.json level from before the three levels means its settled one, in both binaries:
    /// `warn` and `error` run at `info`; `trace` at `trace`.
    #[test]
    fn an_old_level_in_config_reads_as_its_settled_one() {
        for channel in CHANNELS {
            for (stored, want) in [
                ("warn", LogLevel::Info),
                ("error", LogLevel::Info),
                ("ERROR", LogLevel::Info),
                ("trace", LogLevel::Trace),
                ("off", LogLevel::Off),
            ] {
                assert_eq!(
                    level_from_config(Some(&config_with(stored)), channel),
                    (Some(want), None),
                    "{stored} on {channel}"
                );
                let s = StartupFilter::resolve_with(Some(&config_with(stored)), channel, None);
                assert_eq!(s.level, want, "{stored} on {channel}");
                assert_eq!(s.directives, want.filter_directives());
            }
        }
    }

    #[test]
    fn directives_per_level() {
        let got: Vec<(LogLevel, String)> = LogLevel::ALL
            .into_iter()
            .map(|l| (l, l.filter_directives()))
            .collect();
        let want = [
            (LogLevel::Off, "off"),
            (LogLevel::Error, "error"),
            (LogLevel::Warn, "warn"),
            (LogLevel::Info, "warn,afklink=info"),
            (LogLevel::Debug, "warn,afklink=debug"),
            (LogLevel::Trace, "trace"),
        ]
        .map(|(l, d)| (l, d.to_string()));
        assert_eq!(got, want);
        for level in LogLevel::ALL {
            EnvFilter::try_new(level.filter_directives()).expect("parses strictly");
        }
    }

    #[test]
    fn debug_opens_every_crate_of_ours() {
        let d = LogLevel::Debug.filter_directives();
        assert!(passes!(&d, "afklink_core::agent", DEBUG));
        assert!(passes!(&d, "afklink_transport::webrtc", DEBUG));
        assert!(passes!(&d, "afklink_encode", DEBUG));
        assert!(passes!(&d, "afklink_app_lib", DEBUG));
        assert!(passes!(&d, "afklink_agent", DEBUG));
        assert!(!passes!(&d, "afklink_core::agent", TRACE));
        // Our patch inside the vendored str0m (vendor/VENDORED.md) logs its delay detector's
        // decisions under this target so that `debug` writes them though str0m's own stay at `warn`.
        assert!(passes!(&d, "afklink_str0m::trendline", DEBUG));
        assert!(!passes!(&d, "afklink_str0m::trendline", TRACE));
        let info = LogLevel::Info.filter_directives();
        assert!(!passes!(&info, "afklink_str0m::trendline", DEBUG));
    }

    #[test]
    fn third_party_stays_at_warn_below_trace() {
        for level in [LogLevel::Info, LogLevel::Debug] {
            let d = level.filter_directives();
            assert!(passes!(&d, "str0m::rtp", WARN), "{level}");
            assert!(!passes!(&d, "str0m::rtp", INFO), "{level}");
            assert!(!passes!(&d, "tungstenite::protocol", INFO), "{level}");
            assert!(!passes!(&d, "tauri::app", INFO), "{level}");
        }
        // Quieter levels are not louder for third parties than for us.
        let d = LogLevel::Error.filter_directives();
        assert!(!passes!(&d, "str0m::rtp", WARN));
        assert!(passes!(&d, "str0m::rtp", ERROR));
        assert!(!passes!(&d, "afklink_core::agent", WARN));
    }

    #[test]
    fn info_keeps_the_pipeline_line() {
        // The once-a-second `pipeline` line is `info` from `afklink_core::agent`: the first thing
        // read after a bad session must survive the default of any release.
        let d = LogLevel::Info.filter_directives();
        assert!(passes!(&d, "afklink_core::agent", INFO));
        assert!(!passes!(&d, "afklink_core::agent", DEBUG));
    }

    #[test]
    fn trace_opens_everything() {
        let d = LogLevel::Trace.filter_directives();
        assert!(passes!(&d, "afklink_core::agent", TRACE));
        assert!(passes!(&d, "str0m::rtp", TRACE));
    }

    #[test]
    fn off_lets_nothing_through() {
        let d = LogLevel::Off.filter_directives();
        assert!(!passes!(&d, "afklink_core::agent", ERROR));
        assert!(!passes!(&d, "str0m::rtp", ERROR));
        assert_eq!(
            LogLevel::Off.filter().max_level_hint(),
            Some(LevelFilter::OFF)
        );
    }

    /// A config with nothing chosen: `log_level` absent, as a fresh config.json is written.
    fn config_without_choice() -> Config {
        serde_json::from_str(r#"{"device_id":"d","server_url":"ws://x","name":"n"}"#)
            .expect("minimal config parses")
    }

    fn config_with(log_level: &str) -> Config {
        let mut c = config_without_choice();
        c.log_level = Some(log_level.to_string());
        c
    }

    const CHANNELS: [Channel; 2] = [Channel::Dev, Channel::Release];

    #[test]
    fn a_choice_in_config_is_taken_on_either_channel() {
        for channel in CHANNELS {
            assert_eq!(
                level_from_config(Some(&config_with("info")), channel),
                (Some(LogLevel::Info), None)
            );
            // The owner's config.json, written `debug` by the first build that ran: still debug on
            // a release build, because it is there — «Подробные» in Settings, until he picks another.
            let s = StartupFilter::resolve_with(Some(&config_with("debug")), channel, None);
            assert_eq!(s.level, LogLevel::Debug, "{channel}");
            assert_eq!(s.choice, Some(LogLevel::Debug));
            assert!(s.warnings.is_empty());
        }
    }

    #[test]
    fn no_choice_runs_at_the_channel_default_without_a_warning() {
        let config = config_without_choice();
        assert_eq!(config.log_level, None);
        for (channel, want) in [
            (Channel::Release, RELEASE_PHASE.default_log_level()),
            (Channel::Dev, LogLevel::Debug),
        ] {
            assert_eq!(level_from_config(Some(&config), channel), (None, None));
            let s = StartupFilter::resolve_with(Some(&config), channel, None);
            assert_eq!(s.level, want, "{channel}");
            assert_eq!(s.choice, None);
            assert_eq!(s.default_level, want);
            assert_eq!(s.channel, channel);
            assert_eq!(s.directives, want.filter_directives());
            assert!(s.warnings.is_empty(), "{:?}", s.warnings);
        }
    }

    #[test]
    fn an_unusable_config_runs_at_the_channel_default_with_a_warning() {
        for (channel, want) in [
            (Channel::Release, RELEASE_PHASE.default_log_level()),
            (Channel::Dev, LogLevel::Debug),
        ] {
            let (choice, warning) = level_from_config(Some(&config_with("chatty")), channel);
            assert_eq!(choice, None);
            let warning = warning.expect("warns");
            assert!(warning.contains("\"chatty\""), "{warning}");
            assert!(warning.contains(want.as_str()), "{warning}");

            let (choice, warning) = level_from_config(None, channel);
            assert_eq!(choice, None);
            assert!(warning.expect("warns").contains(want.as_str()));

            let s = StartupFilter::resolve_with(None, channel, None);
            assert_eq!(s.level, want, "{channel}");
            assert_eq!(s.warnings.len(), 1);
        }
    }

    #[test]
    fn env_overrides_config() {
        let s = StartupFilter::resolve_with(
            Some(&config_with("off")),
            Channel::Release,
            Some("afklink_core=trace".into()),
        );
        assert_eq!(s.level, LogLevel::Off);
        assert_eq!(s.env_override.as_deref(), Some("afklink_core=trace"));
        assert!(s.writes_anything());
        assert!(s.warnings.is_empty());

        // And the channel default alike.
        let s = StartupFilter::resolve_with(
            Some(&config_without_choice()),
            Channel::Release,
            Some("off".into()),
        );
        assert_eq!(s.level, default_log_level(Channel::Release));
        assert!(!s.writes_anything());
    }

    #[test]
    fn the_startup_line_names_the_default_and_why() {
        for channel in CHANNELS {
            let why = default_log_level_reason(channel);
            let unchosen =
                StartupFilter::resolve_with(Some(&config_without_choice()), channel, None).source();
            assert!(unchosen.contains(why), "{unchosen}");
            assert!(
                unchosen.contains(&format!("the {channel} build's default")),
                "{unchosen}"
            );
            // A choice still names the default it overrides, and why the default is that.
            let chosen =
                StartupFilter::resolve_with(Some(&config_with("warn")), channel, None).source();
            let default = default_log_level(channel);
            assert!(chosen.contains(why), "{chosen}");
            assert!(
                chosen.contains(&format!("default is {default}")),
                "{chosen}"
            );
        }
        // A release's line says which phase it was built in: a log from the beta says so.
        let release = default_log_level_reason(Channel::Release);
        assert_eq!(
            release.contains("beta"),
            RELEASE_PHASE == ReleasePhase::Beta,
            "{release}"
        );
    }

    #[test]
    fn unparsable_env_falls_back_to_config_with_a_warning() {
        let s = StartupFilter::resolve_with(
            Some(&config_with("info")),
            Channel::Dev,
            Some("afklink_core=loud".into()),
        );
        assert_eq!(s.env_override, None);
        assert_eq!(s.directives, LogLevel::Info.filter_directives());
        assert_eq!(s.warnings.len(), 1);
    }

    #[test]
    fn off_from_either_source_writes_nothing() {
        for channel in CHANNELS {
            let from_config = StartupFilter::resolve_with(Some(&config_with("off")), channel, None);
            assert!(!from_config.writes_anything());
            let from_env = StartupFilter::resolve_with(
                Some(&config_with("debug")),
                channel,
                Some("off".into()),
            );
            assert!(!from_env.writes_anything());
            let on = StartupFilter::resolve_with(Some(&config_with("error")), channel, None);
            assert!(on.writes_anything());
        }
    }
}
