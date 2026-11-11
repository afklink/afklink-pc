//! Which build this is: the version, the commit of the agent repository it was built from, whether
//! that tree had uncommitted changes, when it was built and for which channel — for the first line
//! of both binaries' logs and for the desktop app's Settings → Diagnostics («0.1.0» for a release,
//! «0.1.0 · 3a3bc46 · dev» for a development build).
//!
//! # Where the values come from
//!
//! The version is the workspace's (`[workspace.package] version` in `agent/Cargo.toml`, the one
//! place it is written): every crate inherits it, so `CARGO_PKG_VERSION` is the same in both
//! binaries, and Tauri takes it from there too (`tauri.conf.json` has no `version`).
//!
//! The rest comes from the build's environment, not git: `bun run portable`, `bun run
//! release:build` and `bun scripts/release-build.ts` (`agent/scripts/`) compute them and pass
//! [`COMMIT_VAR`], [`DIRTY_VAR`], [`TIME_VAR`] and [`CHANNEL_VAR`] to `cargo tauri build`. Each
//! binary's build script declares `cargo:rerun-if-env-changed` for all of them and hands them on
//! with `cargo:rustc-env` — empty when unset — so the binary reads them with `env!`, and a build
//! without them is rebuilt as one without them rather than keeping the last stamp.
//!
//! Asking git from a build script instead would be wrong in exactly the case that matters: a build
//! script reruns only when something it declared changes, so after an edit to a source file the
//! binary would still say the commit (and the clean tree) of whenever the script last ran. An
//! ordinary development build therefore carries no stamp and says so — «dev» — rather than a commit
//! that may be stale.
//!
//! # Channels
//!
//! [`Channel::Release`] only when the build says so (`AFKLINK_BUILD_CHANNEL=release`, see
//! [`CHANNEL_VAR`], which only the release builds set: `bun run release:build`, the official one,
//! and `bun scripts/release-build.ts`); everything else — a plain `cargo build`, `bun run
//! portable`, a value this build does not know — is [`Channel::Dev`]. The channel decides the log
//! level a config.json without a chosen one runs at (`crate::logging::default_log_level`), so an
//! unknown value errs towards the louder development log rather than towards a quiet one.
//!
//! Garbage in a variable (a hand-set value, a script bug) is not shown as a stamp: the value is
//! dropped and [`BuildInfo::log_startup`] warns about it.

use std::fmt;

/// The full commit hash of the agent repository (40 hex digits; 7 or more accepted).
pub const COMMIT_VAR: &str = "AFKLINK_BUILD_COMMIT";
/// `1` when the tree had uncommitted changes (tracked, untracked or in the `contract` submodule),
/// `0` when it was clean.
pub const DIRTY_VAR: &str = "AFKLINK_BUILD_DIRTY";
/// When the build started, UTC: `YYYY-MM-DDTHH:MM:SSZ`.
pub const TIME_VAR: &str = "AFKLINK_BUILD_TIME";
/// `release` for a release build (`bun run release:build`, `bun scripts/release-build.ts`), `dev`
/// or unset for anything else.
pub const CHANNEL_VAR: &str = "AFKLINK_BUILD_CHANNEL";
/// All four, for build scripts that forward them.
pub const STAMP_VARS: [&str; 4] = [COMMIT_VAR, DIRTY_VAR, TIME_VAR, CHANNEL_VAR];

/// How many hex digits of the commit the short form shows — git's default abbreviation.
const SHORT_COMMIT: usize = 7;

/// Who a build is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Channel {
    /// Development: every build that is not a release. Logs at `debug` unless a level was chosen.
    Dev,
    /// A published release, built from its tag. Logs at its phase's level unless one was chosen
    /// (`crate::logging::RELEASE_PHASE`): `debug` during the beta test, `info` after it.
    Release,
}

impl Channel {
    /// The name in [`CHANNEL_VAR`], the log and Settings → Diagnostics.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Dev => "dev",
            Self::Release => "release",
        }
    }
}

impl fmt::Display for Channel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A build's identity, as stamped by the build (see the module docs).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuildInfo {
    /// The workspace version (`agent/Cargo.toml`), the same in both binaries.
    pub version: String,
    /// The full commit hash, lowercase; `None` for a development build.
    pub commit: Option<String>,
    /// Whether the tree had uncommitted changes; `None` when the build did not say.
    pub dirty: Option<bool>,
    /// `YYYY-MM-DDTHH:MM:SSZ`; `None` for a development build.
    pub built_at: Option<String>,
    /// Release or development; [`Channel::Dev`] unless the build said `release`.
    pub channel: Channel,
    /// The desktop app built with its TEST signing key (`afklink-app`'s feature `updater-test-key`,
    /// for the rollback live tests): named in the `User-Agent` and the first log line, so a test
    /// build is recognisable wherever it shows up. Set by [`BuildInfo::with_test_signing_key`].
    pub test_signing_key: bool,
    /// Stamp values that were set but not usable, as `VAR=value (why)`: logged as warnings.
    rejected: Vec<String>,
}

impl BuildInfo {
    /// Read a stamp: the values of [`COMMIT_VAR`], [`DIRTY_VAR`], [`TIME_VAR`] and [`CHANNEL_VAR`]
    /// as the build script handed them on, each empty when the build did not set it.
    pub fn from_stamp(
        version: &str,
        commit: &str,
        dirty: &str,
        built_at: &str,
        channel: &str,
    ) -> Self {
        let mut rejected = Vec::new();
        let commit = parse_commit(commit).unwrap_or_else(|why| {
            rejected.push(format!("{COMMIT_VAR}={commit:?} ({why})"));
            None
        });
        let dirty = parse_dirty(dirty).unwrap_or_else(|why| {
            rejected.push(format!("{DIRTY_VAR}={dirty:?} ({why})"));
            None
        });
        let built_at = parse_time(built_at).unwrap_or_else(|why| {
            rejected.push(format!("{TIME_VAR}={built_at:?} ({why})"));
            None
        });
        let channel = parse_channel(channel).unwrap_or_else(|why| {
            rejected.push(format!("{CHANNEL_VAR}={channel:?} ({why}; taken as dev)"));
            Channel::Dev
        });
        Self {
            version: version.trim().to_string(),
            commit,
            dirty,
            built_at,
            channel,
            test_signing_key: false,
            rejected,
        }
    }

    /// Mark this build as one that trusts the TEST signing key (`on`: the app's
    /// `updater::TEST_SIGNING_KEY`). Only the desktop app's test-key build sets it.
    #[must_use]
    pub fn with_test_signing_key(mut self, on: bool) -> Self {
        self.test_signing_key = on;
        self
    }

    /// The commit's first seven hex digits, as `git log --oneline` shows it.
    pub fn short_commit(&self) -> Option<&str> {
        self.commit
            .as_deref()
            .map(|c| c.get(..SHORT_COMMIT).unwrap_or(c))
    }

    /// Whether this is exactly a published release: the release channel, a commit, a clean tree.
    fn is_exact_release(&self) -> bool {
        self.channel == Channel::Release && self.commit.is_some() && self.dirty == Some(false)
    }

    /// What the log's first line and the version row of Settings → «Обновления» call this build.
    ///
    /// - a release: «0.1.0» — the version is the whole identity, the commit is in the tooltip;
    /// - a development build: «0.1.0 · 3a3bc46 · dev», «0.1.0 · 3a3bc46-dirty · dev», or
    ///   «0.1.0 · dev» without a stamp. A commit whose tree state the build did not give ends in
    ///   `?`: it may not be the exact source.
    ///
    /// A release-channel build that is not exactly a release (dirty, or without a commit — only a
    /// trial `release-build.ts --allow-untagged` makes one) is spelled out like a development
    /// build, «0.1.0 · 3a3bc46-dirty · release», so it never passes for the real thing.
    pub fn label(&self) -> String {
        if self.is_exact_release() {
            return self.version.clone();
        }
        let mut out = self.version.clone();
        if let Some(short) = self.short_commit() {
            out.push_str(" · ");
            out.push_str(short);
            match self.dirty {
                Some(true) => out.push_str("-dirty"),
                Some(false) => {}
                None => out.push('?'),
            }
        }
        out.push_str(" · ");
        out.push_str(self.channel.as_str());
        out
    }

    /// The `User-Agent` this build sends — on the signaling upgrade, the update check and the
    /// diagnostics upload: `AFKLink/<version> (<channel>)`, e.g. `AFKLink/0.4.0 (release)`. The
    /// backend keeps it per device (`devices.last_agent`), which is how the PCs still on an old build
    /// (or an old address) are found. A plain ASCII header value: the version is SemVer.
    ///
    /// A test-key build adds `; test-key`: `AFKLink/0.7.2 (release; test-key)` — so a test build
    /// that left the test PC is seen on the server (`devices.last_agent`). Only the backend's
    /// parsers of this header, which read `(dev|release)`, leave it out of «release only». The
    /// hello's build ([`BuildInfo::wire`], `agent_hello.build`) is unchanged — channel `release` —
    /// so `sessions.agent_build` stores a test build as a release.
    pub fn user_agent(&self) -> String {
        if self.test_signing_key {
            format!("AFKLink/{} ({}; test-key)", self.version, self.channel)
        } else {
            format!("AFKLink/{} ({})", self.version, self.channel)
        }
    }

    /// Values the build set that were not usable, for the log.
    pub fn rejected(&self) -> &[String] {
        &self.rejected
    }

    /// This build as `agent_hello.build` carries it (contract v2): the version, the commit, the
    /// channel and the tree state — or `None`, with a warning, when the version does not fit the
    /// contract's pattern (a hand-edited workspace version): a hello the server's schema refuses is
    /// refused on every attempt, and the build is worth less than the connection.
    pub fn wire(&self) -> Option<afklink_protocol::AgentBuildInfo> {
        let build = afklink_protocol::AgentBuildInfo {
            version: self.version.clone(),
            commit: self.commit.clone(),
            channel: match self.channel {
                Channel::Dev => afklink_protocol::start_failure::BuildChannel::Dev,
                Channel::Release => afklink_protocol::start_failure::BuildChannel::Release,
            },
            dirty: self.dirty,
        };
        match build.check() {
            Ok(()) => Some(build),
            Err(e) => {
                tracing::warn!(
                    version = %self.version,
                    commit = self.commit.as_deref().unwrap_or("-"),
                    "this build's {e}: agent_hello goes without its build (the server then knows \
                     the version from the User-Agent)"
                );
                None
            }
        }
    }

    /// The first line of a binary's log: which build, which channel, and which exe on disk is
    /// running — the one fact a portable copy renamed or moved by its owner does not otherwise
    /// leave anywhere.
    pub fn log_startup(&self, binary: &str) {
        let exe = match std::env::current_exe() {
            Ok(path) => path.display().to_string(),
            Err(e) => format!("? (current_exe failed: {e})"),
        };
        tracing::info!(
            version = %self.version,
            channel = %self.channel,
            commit = self.commit.as_deref().unwrap_or("dev"),
            dirty = %self.dirty.map_or("?", |d| if d { "yes" } else { "no" }),
            built_at = self.built_at.as_deref().unwrap_or("-"),
            test_signing_key = self.test_signing_key,
            exe = %exe,
            "{binary} {}{}",
            self.label(),
            if self.test_signing_key {
                " (TEST signing key)"
            } else {
                ""
            }
        );
        for value in &self.rejected {
            tracing::warn!("build stamp value ignored: {value}");
        }
        if self.commit.is_none() {
            tracing::debug!(
                "no build stamp ({} not given): a development build; `bun run portable` stamps one",
                STAMP_VARS.join(", ")
            );
        }
    }
}

/// Empty or `dev` → [`Channel::Dev`]; `release` → [`Channel::Release`]; anything else refused (and
/// taken as dev by the caller). Case and surrounding whitespace are forgiven.
fn parse_channel(value: &str) -> Result<Channel, &'static str> {
    match value.trim().to_ascii_lowercase().as_str() {
        "" | "dev" => Ok(Channel::Dev),
        "release" => Ok(Channel::Release),
        _ => Err("expected dev or release"),
    }
}

/// Empty → `None`; 7 to 40 hex digits → the lowercase hash; anything else refused.
fn parse_commit(value: &str) -> Result<Option<String>, &'static str> {
    let value = value.trim();
    if value.is_empty() {
        return Ok(None);
    }
    if !(SHORT_COMMIT..=40).contains(&value.len()) {
        return Err("not 7 to 40 hex digits");
    }
    if !value.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("not a hex commit hash");
    }
    Ok(Some(value.to_ascii_lowercase()))
}

/// Empty → `None`; `1`/`true` and `0`/`false` → the flag; anything else refused.
fn parse_dirty(value: &str) -> Result<Option<bool>, &'static str> {
    match value.trim().to_ascii_lowercase().as_str() {
        "" => Ok(None),
        "1" | "true" => Ok(Some(true)),
        "0" | "false" => Ok(Some(false)),
        _ => Err("expected 1 or 0"),
    }
}

/// Empty → `None`; `YYYY-MM-DDTHH:MM:SSZ` → itself; anything else refused. The shape is checked,
/// not the calendar: this is a label for people, and the script writes it from `Date`.
fn parse_time(value: &str) -> Result<Option<String>, &'static str> {
    let value = value.trim();
    if value.is_empty() {
        return Ok(None);
    }
    const SHAPE: &[u8; 20] = b"0000-00-00T00:00:00Z";
    let bytes = value.as_bytes();
    let fits = bytes.len() == SHAPE.len()
        && bytes.iter().zip(SHAPE).all(|(&b, &s)| {
            if s == b'0' {
                b.is_ascii_digit()
            } else {
                b == s
            }
        });
    if fits {
        Ok(Some(value.to_string()))
    } else {
        Err("expected YYYY-MM-DDTHH:MM:SSZ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FULL: &str = "3a3bc46e0f1d2c3b4a5968778695a4b3c2d1e0f9";
    const TIME: &str = "2026-09-28T20:15:07Z";

    #[test]
    fn a_portable_stamp_reads_back_whole() {
        // `bun run portable`: the dev channel, whether said or left unset.
        for channel in ["dev", ""] {
            let b = BuildInfo::from_stamp("0.1.0", FULL, "0", TIME, channel);
            assert_eq!(b.commit.as_deref(), Some(FULL));
            assert_eq!(b.short_commit(), Some("3a3bc46"));
            assert_eq!(b.dirty, Some(false));
            assert_eq!(b.built_at.as_deref(), Some(TIME));
            assert_eq!(b.channel, Channel::Dev);
            assert_eq!(b.label(), "0.1.0 · 3a3bc46 · dev");
            assert!(b.rejected().is_empty());
        }

        let dirty = BuildInfo::from_stamp("0.1.0", FULL, "1", TIME, "dev");
        assert_eq!(dirty.label(), "0.1.0 · 3a3bc46-dirty · dev");
    }

    #[test]
    fn a_release_is_its_version_alone() {
        let b = BuildInfo::from_stamp("0.1.0", FULL, "0", TIME, "release");
        assert_eq!(b.channel, Channel::Release);
        assert_eq!(b.label(), "0.1.0");
        // The commit is still there, for the tooltip and the log's fields.
        assert_eq!(b.commit.as_deref(), Some(FULL));
        assert!(b.rejected().is_empty());
    }

    #[test]
    fn a_release_channel_build_that_is_not_exact_says_what_it_is() {
        let dirty = BuildInfo::from_stamp("0.1.0", FULL, "1", TIME, "release");
        assert_eq!(dirty.label(), "0.1.0 · 3a3bc46-dirty · release");
        let unknown_tree = BuildInfo::from_stamp("0.1.0", FULL, "", TIME, "release");
        assert_eq!(unknown_tree.label(), "0.1.0 · 3a3bc46? · release");
        let no_commit = BuildInfo::from_stamp("0.1.0", "", "", "", "release");
        assert_eq!(no_commit.label(), "0.1.0 · release");
    }

    #[test]
    fn the_channel_forgives_case_and_refuses_the_unknown_as_dev() {
        let b = BuildInfo::from_stamp("0.1.0", FULL, "0", TIME, " Release\t");
        assert_eq!(b.channel, Channel::Release);
        let b = BuildInfo::from_stamp("0.1.0", FULL, "0", TIME, "beta");
        assert_eq!(
            b.channel,
            Channel::Dev,
            "unknown errs towards the louder log"
        );
        assert_eq!(b.rejected().len(), 1, "{:?}", b.rejected());
        assert!(b.rejected()[0].starts_with(CHANNEL_VAR));
        assert_eq!(Channel::Release.to_string(), "release");
        assert_eq!(Channel::Dev.to_string(), "dev");
    }

    #[test]
    fn the_user_agent_names_the_version_and_the_channel() {
        let release = BuildInfo::from_stamp("0.4.0", FULL, "0", TIME, "release");
        assert_eq!(release.user_agent(), "AFKLink/0.4.0 (release)");
        let dev = BuildInfo::from_stamp("0.4.0", FULL, "1", TIME, "");
        assert_eq!(dev.user_agent(), "AFKLink/0.4.0 (dev)");
        // Unmarked unless asked: every build but the app's test-key one.
        assert!(!release.test_signing_key);
        assert_eq!(
            release.clone().with_test_signing_key(false).user_agent(),
            "AFKLink/0.4.0 (release)"
        );
    }

    /// A test-key build is named in the `User-Agent`, in a form the backend's `(dev|release)`
    /// parsers do not take for a release; the label and the hello's build are unchanged.
    #[test]
    fn a_test_key_build_says_so_in_the_user_agent() {
        let plain = BuildInfo::from_stamp("0.7.2", FULL, "1", TIME, "release");
        let test = plain.clone().with_test_signing_key(true);
        assert!(test.test_signing_key);
        assert_eq!(test.user_agent(), "AFKLink/0.7.2 (release; test-key)");
        assert!(!test.user_agent().contains("(release)"));
        assert_eq!(test.label(), plain.label());
        assert_eq!(test.wire(), plain.wire());
    }

    #[test]
    fn a_development_build_says_dev_and_claims_no_commit() {
        let b = BuildInfo::from_stamp("0.1.0", "", "", "", "");
        assert_eq!(b.commit, None);
        assert_eq!(b.dirty, None);
        assert_eq!(b.built_at, None);
        assert_eq!(b.channel, Channel::Dev);
        assert_eq!(b.label(), "0.1.0 · dev");
        assert!(b.rejected().is_empty(), "unset is not an error");
    }

    #[test]
    fn a_commit_without_a_tree_state_is_not_shown_as_exact() {
        let b = BuildInfo::from_stamp("0.1.0", "3A3BC46", "", "", "");
        assert_eq!(b.commit.as_deref(), Some("3a3bc46"), "lowercased");
        assert_eq!(b.label(), "0.1.0 · 3a3bc46? · dev");
    }

    #[test]
    fn garbage_is_dropped_and_reported_not_shown() {
        let b = BuildInfo::from_stamp("0.1.0", "HEAD", "maybe", "yesterday", "");
        assert_eq!(b.commit, None);
        assert_eq!(b.dirty, None);
        assert_eq!(b.built_at, None);
        assert_eq!(b.label(), "0.1.0 · dev");
        assert_eq!(b.rejected().len(), 3, "{:?}", b.rejected());
        assert!(b.rejected()[0].starts_with(COMMIT_VAR));

        // Too short, too long, not hex.
        for commit in ["3a3bc4", &format!("{FULL}0"), "3a3bc4g"] {
            assert!(parse_commit(commit).is_err(), "{commit}");
        }
        // A time with fractions, or local rather than UTC, is not the shape the script writes.
        for time in [
            "2026-09-28T20:15:07.123Z",
            "2026-09-28 20:15:07",
            "2026-09-28T20:15:07+03:00",
        ] {
            assert!(parse_time(time).is_err(), "{time}");
        }
    }

    /// `agent_hello.build`: the stamp's values as the contract has them; an unstamped build without
    /// a commit or a tree state (no key for either); a version the contract would refuse, no build.
    #[test]
    fn the_wire_build_is_the_stamp_or_nothing() {
        let stamped = BuildInfo::from_stamp("0.5.1", FULL, "1", TIME, "dev")
            .wire()
            .expect("a build");
        assert_eq!(
            serde_json::to_value(&stamped).expect("serialises"),
            serde_json::json!({ "version": "0.5.1", "commit": FULL, "channel": "dev", "dirty": true })
        );
        let release = BuildInfo::from_stamp("0.6.0-beta.1", FULL, "0", TIME, "release")
            .wire()
            .expect("a pre-release version is one");
        assert_eq!(
            release.channel,
            afklink_protocol::start_failure::BuildChannel::Release
        );
        let plain = BuildInfo::from_stamp("0.5.1", "", "", "", "")
            .wire()
            .expect("a build");
        assert_eq!(
            serde_json::to_value(&plain).expect("serialises"),
            serde_json::json!({ "version": "0.5.1", "channel": "dev" })
        );
        assert_eq!(
            BuildInfo::from_stamp("0.5", FULL, "0", TIME, "").wire(),
            None
        );
        assert_eq!(BuildInfo::from_stamp("", "", "", "", "").wire(), None);
    }

    #[test]
    fn surrounding_whitespace_is_forgiven() {
        let b = BuildInfo::from_stamp(
            " 0.1.0 ",
            &format!(" {FULL}\t"),
            " true ",
            " 2026-09-28T20:15:07Z ",
            " dev ",
        );
        assert_eq!(b.label(), "0.1.0 · 3a3bc46-dirty · dev");
        assert_eq!(b.built_at.as_deref(), Some(TIME));
    }
}
