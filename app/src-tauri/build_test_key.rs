//! Whether the build script refuses a test-key build (the feature `updater-test-key`,
//! `src/updater/pubkey.rs`, «The test key»).
//!
//! Shared by `build.rs` and its test (`tests/build_test_key.rs`): a build script has no tests of its
//! own.

use std::ffi::OsStr;

/// The variable that marks the one sanctioned release-channel test-key build: set to `1` by
/// `bun scripts/release-build.ts --test-key` alone (`TEST_KEY_BUILD_VAR`, scripts/lib/common.ts),
/// and to an empty value by every other build that script makes.
pub const ACK_VAR: &str = "AFKLINK_TEST_KEY_BUILD";

/// The variables that say a build runs in CI, where releases are built: GitHub Actions'
/// own and its runner's, and the generic `CI` most CI systems set. `build.rs` declares each one.
pub const CI_VARS: [&str; 4] = ["GITHUB_ACTIONS", "RUNNER_NAME", "RUNNER_ENVIRONMENT", "CI"];

/// The first of [`CI_VARS`] that says this build runs in CI, given each one's value (`None`:
/// unset). Any non-blank value counts, and so does one that is not UTF-8 (it is set, whatever it
/// says); `CI` alone may also say no with `0` or `false`, as some tools set it.
pub fn ci_marker<'a>(values: &[(&'a str, Option<&OsStr>)]) -> Option<&'a str> {
    values.iter().find_map(|&(name, value)| {
        let value = value?;
        let set = match value.to_str() {
            None => true,
            Some(v) => {
                let v = v.trim();
                !v.is_empty() && !(name == "CI" && (v == "0" || v.eq_ignore_ascii_case("false")))
            }
        };
        set.then_some(name)
    })
}

/// Why this build must not be made, or `None`.
///
/// Any release-channel build with the test key is refused, wherever it is made, unless it is the
/// test PC's rollback build: that one is release-channel because updates run only in a release
/// build, and it says so with [`ACK_VAR`]` = 1`. In CI even that is refused: a release is built
/// there, and a published release must never trust the test key. A test-key build of any other
/// channel is let through: the gates' `cargo test` / `cargo clippy` with
/// `--features afklink-app/updater-test-key`, a check with `--all-features` (no channel: dev,
/// updates off).
///
/// `feature`: `CARGO_FEATURE_UPDATER_TEST_KEY` is set. `ci`: [`ci_marker`] of [`CI_VARS`].
/// `channel`: `AFKLINK_BUILD_CHANNEL` (`afklink_core::build_info::CHANNEL_VAR`, read as it reads it:
/// case and blanks forgiven). `acknowledged`: [`ACK_VAR`].
pub fn refusal(
    feature: bool,
    ci: Option<&str>,
    channel: Option<&str>,
    acknowledged: Option<&str>,
) -> Option<String> {
    if !feature {
        return None;
    }
    let release = channel.is_some_and(|c| c.trim().eq_ignore_ascii_case("release"));
    if !release {
        return None;
    }
    if let Some(var) = ci {
        return Some(format!(
            "the feature updater-test-key (the TEST signing key) in a release-channel build in CI \
             ({var} is set): a published release must never trust the test key. Test builds are \
             made only on the test PC with `bun scripts/release-build.ts --test-key` \
             (agent/README.md, «Тестовый ключ подписи»)"
        ));
    }
    if acknowledged.map(str::trim) != Some("1") {
        return Some(format!(
            "the feature updater-test-key (the TEST signing key) in a release-channel build: a \
             release must never trust the test key. The rollback tests' test-key build is made \
             only with `bun scripts/release-build.ts --test-key`, which sets {ACK_VAR}=1; a \
             development build with the feature leaves AFKLINK_BUILD_CHANNEL unset or `dev`"
        ));
    }
    None
}
