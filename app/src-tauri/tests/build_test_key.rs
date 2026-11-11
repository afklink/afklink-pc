//! The build script's refusal of a test-key build where a release is built (`build_test_key.rs`).

#![allow(clippy::panic, reason = "test")]

#[path = "../build_test_key.rs"]
mod build_test_key;

use build_test_key::{ci_marker, refusal, ACK_VAR, CI_VARS};
use std::ffi::OsStr;

/// Every spelling of the release channel the stamp reads as release.
const RELEASE: [&str; 3] = ["release", "Release", " release\t"];

/// What `ci_marker` makes of one CI variable set to `value`, the others unset.
fn only(var: &'static str, value: &OsStr) -> Option<&'static str> {
    let values: Vec<(&str, Option<&OsStr>)> = CI_VARS
        .iter()
        .map(|&v| (v, (v == var).then_some(value)))
        .collect();
    ci_marker(&values)
}

#[test]
fn each_ci_variable_says_ci_and_one_that_is_not_utf8_too() {
    for var in CI_VARS {
        for value in ["true", "1", " TRUE ", "github-hosted", "Hosted Agent"] {
            assert_eq!(only(var, OsStr::new(value)), Some(var), "{var}={value:?}");
        }
        for value in ["", "  "] {
            assert_eq!(only(var, OsStr::new(value)), None, "{var}={value:?}");
        }
        #[cfg(windows)]
        {
            use std::os::windows::ffi::OsStringExt;
            // A lone surrogate: set, and not UTF-8.
            let odd = std::ffi::OsString::from_wide(&[0xD800]);
            assert!(odd.to_str().is_none());
            assert_eq!(only(var, &odd), Some(var), "{var}: not UTF-8");
        }
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt;
            let odd = OsStr::from_bytes(&[0xFF]);
            assert_eq!(only(var, odd), Some(var), "{var}: not UTF-8");
        }
    }
    // `CI` alone may say no.
    for value in ["0", "false", "FALSE", " false "] {
        assert_eq!(only("CI", OsStr::new(value)), None, "CI={value:?}");
        assert_eq!(
            only("GITHUB_ACTIONS", OsStr::new(value)),
            Some("GITHUB_ACTIONS"),
            "GITHUB_ACTIONS={value:?}"
        );
    }
    let none: Vec<(&str, Option<&OsStr>)> = CI_VARS.iter().map(|&v| (v, None)).collect();
    assert_eq!(ci_marker(&none), None);
    assert_eq!(
        CI_VARS,
        ["GITHUB_ACTIONS", "RUNNER_NAME", "RUNNER_ENVIRONMENT", "CI"]
    );
}

#[test]
fn a_release_channel_test_key_build_in_ci_is_refused_even_when_acknowledged() {
    for ci in CI_VARS {
        for channel in RELEASE {
            for ack in [None, Some("1"), Some("")] {
                let why = refusal(true, Some(ci), Some(channel), ack);
                assert!(
                    why.as_deref()
                        .is_some_and(|w| w.contains("updater-test-key")
                            && w.contains("in CI")
                            && w.contains(ci)),
                    "{ci:?} {channel:?} {ack:?}: {why:?}"
                );
            }
        }
    }
}

/// Outside CI too: a release-channel build with the test key is refused unless it is the test
/// PC's rollback build, which says so with exactly `1`.
#[test]
fn a_release_channel_test_key_build_anywhere_else_is_refused_without_the_mark() {
    for channel in RELEASE {
        for ack in [
            None,
            Some(""),
            Some("0"),
            Some("yes"),
            Some("true"),
            Some("11"),
        ] {
            let why = refusal(true, None, Some(channel), ack);
            assert!(
                why.as_deref()
                    .is_some_and(|w| w.contains("updater-test-key") && w.contains(ACK_VAR)),
                "{channel:?} {ack:?}: {why:?}"
            );
        }
    }
}

#[test]
fn the_test_pcs_marked_rollback_build_is_let_through() {
    for channel in RELEASE {
        for ack in [Some("1"), Some(" 1 ")] {
            assert_eq!(
                refusal(true, None, Some(channel), ack),
                None,
                "{channel:?} {ack:?}"
            );
        }
    }
}

/// The gates' `--features afklink-app/updater-test-key` builds and an `--all-features` check have no
/// channel or a development one: let through, in CI or not, marked or not.
#[test]
fn a_test_key_build_outside_the_release_channel_is_let_through() {
    for ci in [None, Some("GITHUB_ACTIONS"), Some("CI")] {
        for channel in [None, Some(""), Some("dev"), Some("beta")] {
            for ack in [None, Some("1")] {
                assert_eq!(
                    refusal(true, ci, channel, ack),
                    None,
                    "{ci:?} {channel:?} {ack:?}"
                );
            }
        }
    }
}

/// The body of `fn <name>(…) {` in `text`: up to the first line that is just `}`.
fn body<'a>(text: &'a str, name: &str) -> &'a str {
    let start = text
        .find(&format!("fn {name}("))
        .unwrap_or_else(|| panic!("build.rs has no fn {name}"));
    let rest = &text[start..];
    let end = rest.find("\n}\n").expect("the function ends");
    &rest[..end]
}

/// The refusal is wired: build.rs's `main` calls it first, and it panics on what
/// `build_test_key::refusal` says — removing either call fails here.
#[test]
fn the_build_script_runs_the_refusal() {
    let build = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/build.rs")).unwrap();
    let main = body(&build, "main");
    let first = main
        .lines()
        .skip(1)
        .map(str::trim)
        .find(|l| !l.is_empty() && !l.starts_with("//"));
    assert_eq!(first, Some("refuse_test_key_release();"), "{main}");
    let refuse = body(&build, "refuse_test_key_release");
    assert!(refuse.contains("std::env::var_os(\"CARGO_FEATURE_UPDATER_TEST_KEY\")"));
    assert!(
        refuse.contains("std::env::var(build_test_key::ACK_VAR)"),
        "{refuse}"
    );
    assert!(
        refuse.contains("for var in build_test_key::CI_VARS {"),
        "{refuse}"
    );
    assert!(
        refuse.contains("println!(\"cargo:rerun-if-env-changed={var}\");"),
        "{refuse}"
    );
    assert!(
        refuse.contains(".map(|&var| (var, std::env::var_os(var)))"),
        "{refuse}"
    );
    assert!(
        refuse.contains("let ci = build_test_key::ci_marker(&ci_refs);"),
        "{refuse}"
    );
    let call: String = refuse
        .split("build_test_key::refusal(")
        .nth(1)
        .and_then(|rest| rest.split('{').next())
        .unwrap_or_default()
        .split_whitespace()
        .collect();
    assert_eq!(
        call, "feature,ci,channel.as_deref(),acknowledged.as_deref())",
        "{refuse}"
    );
    assert!(refuse.contains("panic!(\"{why}\")"), "{refuse}");
}

#[test]
fn without_the_feature_nothing_is_refused() {
    assert_eq!(
        refusal(false, Some("GITHUB_ACTIONS"), Some("release"), None),
        None
    );
    assert_eq!(refusal(false, None, Some("release"), None), None);
    assert_eq!(refusal(false, None, None, None), None);
}
