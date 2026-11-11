//! The start failure beacon: `POST /api/agent/start-failure`, the one request the desktop app sends
//! when it cannot start (today: the Microsoft Edge WebView2 Runtime is missing) — once, on its way
//! out, before it has spoken to the signaling server — so a PC that never starts is counted.
//!
//! Mirrors the contract's `start-failure.ts` (`AGENT_START_FAILURE_PATH`,
//! `AGENT_START_FAILURE_REASONS`, `AGENT_BUILD_CHANNELS`, `AGENT_START_FAILURE_LIMITS`,
//! `agentStartFailureSchema`). Held to it by `tests/start_failure.rs`: the fixture
//! `rest/agent_start_failure.json` by round-trip, the fields, enums, limits and patterns against the
//! emitted `schema/rest-agent-start-failure.json`.
//!
//! Anonymous and unsigned (the device key is not loaded at that point): exactly the fields below,
//! each with a fixed alphabet and length, so none can carry a name, a path or a sentence. The server
//! answers `204` when it took the beacon and a refusal otherwise; the app sends it once and acts on
//! no answer.

use std::fmt;

use serde::{Deserialize, Serialize};

/// `POST` target of the beacon on the server the agent is configured with
/// (`AGENT_START_FAILURE_PATH`).
pub const AGENT_START_FAILURE_PATH: &str = "/api/agent/start-failure";

/// The sizes the server holds the beacon to (`AGENT_START_FAILURE_LIMITS`). Characters are Unicode
/// code points; every field here is ASCII, so they are bytes too.
pub mod limits {
    /// The whole body as sent, JSON. Past it: `413 payload_too_large`.
    pub const BODY_BYTES: usize = 2 * 1024;
    /// `version`.
    pub const VERSION_CHARS: usize = 32;
    /// `os`: `major.minor.build.revision` at their widest is 21.
    pub const OS_CHARS: usize = 24;
    /// `detail_code`.
    pub const DETAIL_CODE_CHARS: usize = 32;
}

/// Why the app could not start (`AGENT_START_FAILURE_REASONS`): a closed list.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum StartFailureReason {
    /// The WebView2 Runtime is not installed (or its loader found no usable version): the window
    /// cannot exist.
    #[serde(rename = "webview2_missing")]
    Webview2Missing,
}

impl StartFailureReason {
    /// Every reason, in the contract's order.
    pub const ALL: [Self; 1] = [Self::Webview2Missing];

    /// The wire word.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Webview2Missing => "webview2_missing",
        }
    }
}

impl fmt::Display for StartFailureReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The build channel (`AGENT_BUILD_CHANNELS`), as `afklink_core::build_info::Channel` names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BuildChannel {
    Dev,
    Release,
}

impl BuildChannel {
    /// Every channel, in the contract's order.
    pub const ALL: [Self; 2] = [Self::Dev, Self::Release];

    /// The wire word.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Dev => "dev",
            Self::Release => "release",
        }
    }
}

impl fmt::Display for BuildChannel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The body of `POST /api/agent/start-failure` (`agentStartFailureSchema`), JSON with
/// `Content-Type: application/json`. The optional fields are left out rather than sent as `null`
/// (the contract takes either).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentStartFailure {
    pub reason: StartFailureReason,
    /// The id this PC has or will have in `agent_hello` — config.json's `device_id`, a v4 UUID.
    /// Unverified by the server: nothing is signed at this point.
    pub device_id: String,
    /// `CARGO_PKG_VERSION`: `0.5.0`, or `0.6.0-beta.1` ([`is_version`]).
    pub version: String,
    pub channel: BuildChannel,
    /// The commit the build was stamped with, 7 to 40 lowercase hex digits ([`is_commit`]); absent
    /// for an unstamped build.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commit: Option<String>,
    /// Windows as numbers: `major.minor.build`, and `.revision` (the UBR) when it was read —
    /// `10.0.19045.5371` ([`is_os`]).
    pub os: String,
    /// A short code from the component that failed: for `webview2_missing` the loader's HRESULT as
    /// `0x` and 8 hex digits ([`is_detail_code`]); absent when there is none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail_code: Option<String>,
}

/// A field of a beacon that the contract refuses (the server would answer `400 bad_message`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidField {
    /// The field's wire name.
    pub field: &'static str,
}

impl fmt::Display for InvalidField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "the start failure beacon's {} is not the contract's shape",
            self.field
        )
    }
}

impl std::error::Error for InvalidField {}

impl AgentStartFailure {
    /// Every field against the contract's rules; the first that fails is named. The size of the
    /// whole body is the caller's to check against [`limits::BODY_BYTES`] once it is serialized —
    /// though every beacon that passes this is far under it.
    pub fn check(&self) -> Result<(), InvalidField> {
        let checks = [
            ("device_id", crate::diagnostics::is_uuid(&self.device_id)),
            ("version", is_version(&self.version)),
            ("commit", self.commit.as_deref().is_none_or(is_commit)),
            ("os", is_os(&self.os)),
            (
                "detail_code",
                self.detail_code.as_deref().is_none_or(is_detail_code),
            ),
        ];
        match checks.into_iter().find(|(_, ok)| !ok) {
            Some((field, _)) => Err(InvalidField { field }),
            None => Ok(()),
        }
    }
}

/// `min..=max` ASCII digits — JavaScript's `\d{min,max}` (without the `u` flag `\d` is ASCII only).
fn digits(s: &str, min: usize, max: usize) -> bool {
    (min..=max).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_digit())
}

/// `version`: `^\d{1,5}\.\d{1,5}\.\d{1,5}(-[0-9A-Za-z.-]{1,24})?$`, at most
/// [`limits::VERSION_CHARS`].
pub fn is_version(s: &str) -> bool {
    if s.len() > limits::VERSION_CHARS {
        return false;
    }
    // The core has no `-`, so the first one starts the pre-release (which may hold more).
    let (core, pre) = match s.split_once('-') {
        Some((core, pre)) => (core, Some(pre)),
        None => (s, None),
    };
    let mut parts = core.split('.');
    let core_ok =
        (0..3).all(|_| parts.next().is_some_and(|p| digits(p, 1, 5))) && parts.next().is_none();
    let pre_ok = pre.is_none_or(|p| {
        (1..=24).contains(&p.len())
            && p.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
    });
    core_ok && pre_ok
}

/// `commit`: `^[0-9a-f]{7,40}$`.
pub fn is_commit(s: &str) -> bool {
    (7..=40).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// `os`: `^\d{1,3}\.\d{1,3}\.\d{1,6}(\.\d{1,6})?$`, at most [`limits::OS_CHARS`].
pub fn is_os(s: &str) -> bool {
    if s.len() > limits::OS_CHARS {
        return false;
    }
    let parts: Vec<&str> = s.split('.').collect();
    let widths: &[(usize, usize)] = match parts.len() {
        3 => &[(1, 3), (1, 3), (1, 6)],
        4 => &[(1, 3), (1, 3), (1, 6), (1, 6)],
        _ => return false,
    };
    parts
        .iter()
        .zip(widths)
        .all(|(p, &(min, max))| digits(p, min, max))
}

/// `detail_code`: `^[0-9A-Za-z_.-]{1,32}$`.
pub fn is_detail_code(s: &str) -> bool {
    (1..=limits::DETAIL_CODE_CHARS).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn beacon() -> AgentStartFailure {
        AgentStartFailure {
            reason: StartFailureReason::Webview2Missing,
            device_id: "a3f1c2d4-5b6e-4f7a-8c9d-0e1f2a3b4c5d".into(),
            version: "0.5.0".into(),
            channel: BuildChannel::Release,
            commit: Some("7d537e2".into()),
            os: "10.0.19045.5371".into(),
            detail_code: Some("0x80070002".into()),
        }
    }

    #[test]
    fn the_body_is_the_contracts_and_leaves_absent_fields_out() {
        let full = serde_json::to_string(&beacon()).expect("serializes");
        assert_eq!(
            full,
            r#"{"reason":"webview2_missing","device_id":"a3f1c2d4-5b6e-4f7a-8c9d-0e1f2a3b4c5d","version":"0.5.0","channel":"release","commit":"7d537e2","os":"10.0.19045.5371","detail_code":"0x80070002"}"#
        );
        let bare = AgentStartFailure {
            commit: None,
            detail_code: None,
            channel: BuildChannel::Dev,
            os: "10.0.26100".into(),
            ..beacon()
        };
        assert_eq!(
            serde_json::to_string(&bare).expect("serializes"),
            r#"{"reason":"webview2_missing","device_id":"a3f1c2d4-5b6e-4f7a-8c9d-0e1f2a3b4c5d","version":"0.5.0","channel":"dev","os":"10.0.26100"}"#
        );
        // `null` from the other side reads as absent.
        let with_nulls: AgentStartFailure = serde_json::from_str(
            r#"{"reason":"webview2_missing","device_id":"a3f1c2d4-5b6e-4f7a-8c9d-0e1f2a3b4c5d","version":"0.5.0","channel":"dev","commit":null,"os":"10.0.26100","detail_code":null}"#,
        )
        .expect("parses");
        assert_eq!(with_nulls, bare);
        assert!(full.len() < limits::BODY_BYTES);
    }

    #[test]
    fn the_largest_beacon_is_far_under_the_body_limit() {
        let largest = AgentStartFailure {
            version: format!("99999.99999.99999-{}", "a".repeat(14)),
            commit: Some("f".repeat(40)),
            os: "999.999.999999.999999".into(),
            detail_code: Some("x".repeat(limits::DETAIL_CODE_CHARS)),
            ..beacon()
        };
        assert_eq!(largest.check(), Ok(()));
        let json = serde_json::to_vec(&largest).expect("serializes");
        assert!(json.len() < 300, "{} bytes", json.len());
    }

    #[test]
    fn check_names_the_first_field_the_contract_refuses() {
        assert_eq!(beacon().check(), Ok(()));
        let bad = |b: AgentStartFailure| b.check().map_err(|e| e.field);
        assert_eq!(
            bad(AgentStartFailure {
                device_id: "not-a-uuid".into(),
                ..beacon()
            }),
            Err("device_id")
        );
        assert_eq!(
            bad(AgentStartFailure {
                version: "0.5".into(),
                ..beacon()
            }),
            Err("version")
        );
        assert_eq!(
            bad(AgentStartFailure {
                commit: Some("7D537E2".into()),
                ..beacon()
            }),
            Err("commit")
        );
        assert_eq!(
            bad(AgentStartFailure {
                os: "Windows 10".into(),
                ..beacon()
            }),
            Err("os")
        );
        assert_eq!(
            bad(AgentStartFailure {
                detail_code: Some("no spaces".into()),
                ..beacon()
            }),
            Err("detail_code")
        );
        assert_eq!(
            InvalidField { field: "os" }.to_string(),
            "the start failure beacon's os is not the contract's shape"
        );
    }

    #[test]
    fn versions_as_the_schema_takes_them() {
        for ok in [
            "0.5.0",
            "0.6.0-beta.1",
            "12345.0.1",
            "1.2.3-rc-1",
            "0.1.0-a",
        ] {
            assert!(is_version(ok), "{ok}");
        }
        let long_pre = format!("1.2.3-{}", "a".repeat(25));
        for bad in [
            "",
            "0.5",
            "0.5.0.1",
            "v0.5.0",
            "0.5.0-",
            "0.5.0+build",
            "123456.0.0",
            "0.5.0-beta_1",
            "٠.5.0",
            long_pre.as_str(),
        ] {
            assert!(!is_version(bad), "{bad}");
        }
    }

    #[test]
    fn commits_are_lowercase_hex_of_7_to_40() {
        assert!(is_commit("7d537e2"));
        assert!(is_commit(&"a".repeat(40)));
        for bad in ["7d537e", "7D537E2", "7d537eg", &"a".repeat(41)] {
            assert!(!is_commit(bad), "{bad}");
        }
    }

    #[test]
    fn os_is_three_or_four_numbers() {
        for ok in [
            "10.0.26100",
            "10.0.19045.5371",
            "6.3.9600",
            "999.999.999999.999999",
        ] {
            assert!(is_os(ok), "{ok}");
        }
        for bad in [
            "",
            "10.0",
            "10.0.26100.1.2",
            "10.0.26100.",
            "1000.0.1",
            "10.0.1234567",
            "10.0.26100.1234567",
            "10.0.x",
            "Windows 11",
        ] {
            assert!(!is_os(bad), "{bad}");
        }
    }

    #[test]
    fn detail_codes_are_short_words() {
        for ok in ["0x80070002", "empty_version", "a", "A.b-c_d"] {
            assert!(is_detail_code(ok), "{ok}");
        }
        let long = "a".repeat(limits::DETAIL_CODE_CHARS + 1);
        for bad in ["", "0x8007 0002", "путь", "a/b", long.as_str()] {
            assert!(!is_detail_code(bad), "{bad}");
        }
    }

    #[test]
    fn the_words_are_the_wire_words() {
        assert_eq!(
            serde_json::to_value(StartFailureReason::Webview2Missing).expect("serializes"),
            "webview2_missing"
        );
        for reason in StartFailureReason::ALL {
            assert_eq!(
                serde_json::to_value(reason).expect("serializes"),
                reason.as_str()
            );
        }
        for channel in BuildChannel::ALL {
            assert_eq!(
                serde_json::to_value(channel).expect("serializes"),
                channel.as_str()
            );
        }
    }
}
