//! Diagnostic reports: the desktop app's «Отправить логи» —
//! `POST /api/diagnostics/agent`, a zip signed by the device. The path, the limits, the header names,
//! the string the device signs, and the shapes of the metadata and of the receipt.
//!
//! Mirrors `diagnostics-wire.ts` (the runtime constants, `AGENT_AUTO_REPORT_TRIGGERS` and
//! `agentRequestCanonical`) and the agent's half of `diagnostics.ts` (`agentDiagnosticsMetaSchema`
//! with its `auto` marker, `diagnosticsReceiptSchema`). Held to them by `tests/diagnostics.rs`: the
//! limits against the emitted JSON Schemas and `diagnostics-wire.ts`, the metadata (manual and
//! automatic) and receipt fixtures by round-trip, and the canonical string rebuilt from every case
//! of `vectors/agent-request-signature.json`, byte for byte.
//!
//! The signing itself — sha256, base64, Ed25519 with the device's key — is the desktop app's
//! (`afklink_app_lib`'s `diagnostics::upload`), so this crate stays free of crypto.

use std::fmt;

use serde::{Deserialize, Serialize};

/// `POST` target for the desktop app's zip (`DIAGNOSTICS_AGENT_PATH`).
pub const DIAGNOSTICS_AGENT_PATH: &str = "/api/diagnostics/agent";

/// First line of the signed string: names the scheme and its version, and keeps a report signature
/// from ever passing for the signaling challenge's, which is 32 random bytes the server chose
/// (`AGENT_REQUEST_SCHEME`).
pub const AGENT_REQUEST_SCHEME: &str = "AFKLINK-AGENT-REQUEST-V1";

/// On `401 clock_skew` the server's clock, Unix milliseconds (`SERVER_TIME_HEADER`): the agent may
/// retry once with its timestamp moved by the difference, and a new nonce.
pub const SERVER_TIME_HEADER: &str = "x-afklink-server-time";

/// The signed request's headers, lowercase, as the server looks them up (`AGENT_REQUEST_HEADERS`).
pub mod header {
    /// The device id, exactly as in `agent_hello` (config.json's value).
    pub const DEVICE: &str = "x-afklink-device";
    /// The agent's clock, Unix milliseconds, decimal, no sign or leading zeros.
    pub const TIMESTAMP: &str = "x-afklink-timestamp";
    /// 16 random bytes as 32 lowercase hex digits, fresh for every request, a retry included.
    pub const NONCE: &str = "x-afklink-nonce";
    /// sha256 of the body as sent, 64 lowercase hex digits.
    pub const CONTENT_SHA256: &str = "x-afklink-content-sha256";
    /// The metadata JSON (UTF-8) as base64url without padding.
    pub const META: &str = "x-afklink-meta";
    /// Ed25519 over [`super::agent_request_canonical`], standard base64 with padding (88
    /// characters) — the same encoding as `agent_auth.signature`.
    pub const SIGNATURE: &str = "x-afklink-signature";

    /// All six, in the order the canonical string takes their values (the signature last, over
    /// the rest).
    pub const ALL: [&str; 6] = [DEVICE, TIMESTAMP, NONCE, CONTENT_SHA256, META, SIGNATURE];
}

/// The agent's half of `DIAGNOSTICS_LIMITS`: what the server refuses past, so a report packed to
/// these never meets that refusal.
pub mod limits {
    /// The zip as sent. Past it: `413 payload_too_large`.
    pub const AGENT_BODY_BYTES: u64 = 25 * 1024 * 1024;
    /// «Что случилось?», in Unicode code points — as the schema's zod counts them, and Rust's
    /// `chars()`.
    pub const COMMENT_CHARS: usize = 500;
    /// The `x-afklink-meta` header (base64url characters).
    pub const META_HEADER_CHARS: usize = 12 * 1024;
    /// Entries in the metadata's `files` list.
    pub const FILES: usize = 32;
    /// The longest file name in that list.
    pub const FILE_NAME: usize = 96;
    /// Session ids one report may name: the live one first, then the most recent.
    pub const SESSION_IDS: usize = 8;
    /// The longest `os`, in code points.
    pub const OS_CHARS: usize = 128;
    /// How far the agent's clock may be from the server's, either way.
    pub const SIGNATURE_WINDOW_MS: u64 = 5 * 60_000;

    /* An automatic report («автоотчёт», [`super::AgentAutoReport`]): hard limits. A report the
     * person sends is held to none of these. */

    /// An automatic report's zip, as sent (`agentAutoBodyBytes`). Past it: `413`.
    pub const AGENT_AUTO_BODY_BYTES: u64 = 200_000;
    /// Automatic reports one PC may send in any [`AGENT_AUTO_WINDOW_MS`] (`agentAutoPerWindow`).
    pub const AGENT_AUTO_PER_WINDOW: usize = 3;
    /// The rolling window of [`AGENT_AUTO_PER_WINDOW`] (`agentAutoWindowMs`): 24 hours.
    pub const AGENT_AUTO_WINDOW_MS: u64 = 24 * 60 * 60_000;
    /// Automatic reports from all PCs together in an hour, the server's cap
    /// (`agentAutoServicePerHour`). The agent does not count it; mirrored to stay pinned.
    pub const AGENT_AUTO_SERVICE_PER_HOUR: usize = 60;
    /// How long the link to the server must have been down before coming back counts as
    /// `offline` (`agentAutoOutageMs`).
    pub const AGENT_AUTO_OUTAGE_MS: u64 = 60_000;
    /// The agent's own spacing between two automatic reports, whatever their triggers
    /// (`agentAutoMinGapMs`).
    pub const AGENT_AUTO_MIN_GAP_MS: u64 = 15 * 60_000;
    /// The longest `auto.detail` (`agentAutoReportSchema.detail`).
    pub const AUTO_DETAIL_CHARS: usize = 64;
}

/// Why the agent sent a report by itself (`AGENT_AUTO_REPORT_TRIGGERS`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentAutoTrigger {
    /// The previous run ended in a crash or a panic.
    Crash,
    /// The link to the server was down for [`limits::AGENT_AUTO_OUTAGE_MS`] or longer, and came
    /// back.
    Offline,
    /// A session ended on the agent's side with an error reason.
    SessionFailed,
    /// The stall watch logged an error: the main thread or the async runtime hung for 30 s.
    Stall,
}

impl AgentAutoTrigger {
    /// Every trigger, in the contract's order.
    pub const ALL: [Self; 4] = [Self::Crash, Self::Offline, Self::SessionFailed, Self::Stall];

    /// The wire name.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Crash => "crash",
            Self::Offline => "offline",
            Self::SessionFailed => "session_failed",
            Self::Stall => "stall",
        }
    }

    /// The trigger a wire name names.
    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|t| t.as_str() == s)
    }
}

/// What makes a report automatic (`agentAutoReportSchema`, strict): the trigger, when it fired on
/// the PC's clock, and a short machine word about it ([`is_auto_detail`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentAutoReport {
    pub trigger: AgentAutoTrigger,
    /// Unix ms, positive.
    pub at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// Whether `s` may be an `auto.detail`: 1 to [`limits::AUTO_DETAIL_CHARS`] of lowercase letters,
/// digits and `_ . : = -` (`^[a-z0-9_.:=-]+$`).
pub fn is_auto_detail(s: &str) -> bool {
    (1..=limits::AUTO_DETAIL_CHARS).contains(&s.len())
        && s.bytes().all(|b| {
            b.is_ascii_lowercase()
                || b.is_ascii_digit()
                || matches!(b, b'_' | b'.' | b':' | b'=' | b'-')
        })
}

/// The build that sent the report (`agentBuildSchema`): `afklink_core::build_info::BuildInfo` as
/// the wire has it. Every field is present; the nullable ones as `null`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentBuild {
    pub version: String,
    /// Lowercase hex, 7 to 40 digits; `None` for an unstamped development build.
    pub commit: Option<String>,
    /// Whether the tree had uncommitted changes; `None` when the build did not say.
    pub dirty: Option<bool>,
    /// `"dev"` or `"release"`.
    pub channel: String,
    /// `YYYY-MM-DDTHH:MM:SSZ`, or `None`.
    pub built_at: Option<String>,
    /// What Settings → Diagnostics shows: «0.1.0», «0.1.0 · 3a3bc46 · dev».
    pub label: String,
}

/// One entry of the zip (`diagnosticFileSchema`): its name ([`is_file_name`]) and its size before
/// compression; `truncated` when only the end of the file was kept, to stay under the size limit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiagnosticFile {
    pub name: String,
    pub bytes: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub truncated: Option<bool>,
}

/// The metadata behind `x-afklink-meta` (`agentDiagnosticsMetaSchema`). No device: the device is
/// who signed the request.
///
/// The field order is the schema's, and the JSON the tests compare against the signature vectors
/// byte for byte — though nothing depends on it: the signature covers the header's text, whatever
/// JSON it decodes to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentDiagnosticsMeta {
    pub build: AgentBuild,
    /// The PC's clock when the report was packed, Unix ms.
    pub client_time: u64,
    /// «Что случилось?»: trimmed, never blank (absent instead), at most
    /// [`limits::COMMENT_CHARS`], no control characters but tab and line breaks.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    /// What is in the zip, 1 to [`limits::FILES`] entries.
    pub files: Vec<DiagnosticFile>,
    /// The live session first, then the most recent; at most [`limits::SESSION_IDS`], each
    /// [`is_uuid`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_ids: Option<Vec<String>>,
    /// Windows as the agent sees it, e.g. «Windows 11 Pro 24H2 (26100)».
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub os: Option<String>,
    /// Present: an automatic report, held to the `AGENT_AUTO_*` limits; absent: one the person
    /// sent. Inside the signed header, so it cannot be stripped or added on the way.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auto: Option<AgentAutoReport>,
}

/// `201` from the endpoint (`diagnosticsReceiptSchema`): the report's id, and its size as stored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiagnosticsReceipt {
    pub report_id: String,
    pub bytes: u64,
}

/// The parts of a signed agent request, each exactly as it goes on the wire (`AgentRequestSigned`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AgentRequestSigned<'a> {
    /// `POST`.
    pub method: &'a str,
    /// The path alone: [`DIAGNOSTICS_AGENT_PATH`].
    pub path: &'a str,
    pub device: &'a str,
    pub timestamp: &'a str,
    pub nonce: &'a str,
    pub content_sha256: &'a str,
    /// sha256 of the `x-afklink-meta` header's value — the base64url text, not the JSON it decodes
    /// to — as 64 lowercase hex digits.
    pub meta_sha256: &'a str,
}

/// A signed part held a line break, which would let one request's string pass for another's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LineBreakInPart {
    /// Which part: `method`, `path`, `device`, `timestamp`, `nonce`, `content_sha256` or
    /// `meta_sha256`.
    pub part: &'static str,
}

impl fmt::Display for LineBreakInPart {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "the signed part {} holds a line break", self.part)
    }
}

impl std::error::Error for LineBreakInPart {}

/// The string the agent signs, byte for byte (`agentRequestCanonical`): eight lines joined by `\n`,
/// no trailing newline —
///
/// ```text
/// AFKLINK-AGENT-REQUEST-V1
/// POST
/// /api/diagnostics/agent
/// <device>
/// <timestamp>
/// <nonce>
/// <content_sha256>
/// <meta_sha256>
/// ```
///
/// A part holding a line break is refused, as the contract refuses it.
pub fn agent_request_canonical(p: &AgentRequestSigned<'_>) -> Result<String, LineBreakInPart> {
    let parts = [
        ("scheme", AGENT_REQUEST_SCHEME),
        ("method", p.method),
        ("path", p.path),
        ("device", p.device),
        ("timestamp", p.timestamp),
        ("nonce", p.nonce),
        ("content_sha256", p.content_sha256),
        ("meta_sha256", p.meta_sha256),
    ];
    for (part, value) in parts {
        if value.contains(['\n', '\r']) {
            return Err(LineBreakInPart { part });
        }
    }
    Ok(parts.map(|(_, value)| value).join("\n"))
}

/// Whether `name` may name a file in the zip (`diagnosticFileSchema.name`): plain relative segments
/// of letters, digits, `.`, `_` and `-`, each starting with a letter or digit, joined by `/`, at
/// most [`limits::FILE_NAME`] characters — so no `..`, no absolute path, no drive letter and no
/// dotfile, whatever unpacks it later.
pub fn is_file_name(name: &str) -> bool {
    name.len() <= limits::FILE_NAME
        && name.split('/').all(|segment| {
            let mut bytes = segment.bytes();
            bytes.next().is_some_and(|b| b.is_ascii_alphanumeric())
                && bytes.all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        })
}

/// Whether `s` is a UUID as the contract's `z.uuid()` takes one (the emitted pattern): 8-4-4-4-12
/// hex digits with a version digit 1–8 and a variant digit 8, 9, a or b — or the nil or max UUID.
pub fn is_uuid(s: &str) -> bool {
    if s == "00000000-0000-0000-0000-000000000000"
        || s.eq_ignore_ascii_case("ffffffff-ffff-ffff-ffff-ffffffffffff")
    {
        return true;
    }
    let bytes = s.as_bytes();
    bytes.len() == 36
        && bytes.iter().enumerate().all(|(i, &b)| match i {
            8 | 13 | 18 | 23 => b == b'-',
            14 => (b'1'..=b'8').contains(&b),
            19 => matches!(b, b'8' | b'9' | b'a' | b'b' | b'A' | b'B'),
            _ => b.is_ascii_hexdigit(),
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parts<'a>(device: &'a str, nonce: &'a str) -> AgentRequestSigned<'a> {
        AgentRequestSigned {
            method: "POST",
            path: DIAGNOSTICS_AGENT_PATH,
            device,
            timestamp: "1790590530123",
            nonce,
            content_sha256: "c",
            meta_sha256: "m",
        }
    }

    #[test]
    fn the_canonical_string_is_eight_lines_without_a_trailing_newline() {
        let s = agent_request_canonical(&parts("d", "n")).expect("no line breaks");
        assert_eq!(
            s,
            "AFKLINK-AGENT-REQUEST-V1\nPOST\n/api/diagnostics/agent\nd\n1790590530123\nn\nc\nm"
        );
        assert_eq!(s.lines().count(), 8);
    }

    #[test]
    fn a_part_with_a_line_break_is_refused() {
        assert_eq!(
            agent_request_canonical(&parts("d\nx", "n")),
            Err(LineBreakInPart { part: "device" })
        );
        assert_eq!(
            agent_request_canonical(&parts("d", "n\r")),
            Err(LineBreakInPart { part: "nonce" })
        );
    }

    #[test]
    fn file_names_are_plain_relative_segments() {
        for ok in [
            "recent-debug.log",
            "afklink-app.2026-09-29.log",
            "msiexec-fakerinput-install-20260928-124950Z.log",
            "logs/afklink-app.2026-09-29.log",
            "a",
        ] {
            assert!(is_file_name(ok), "{ok}");
        }
        let long = "a".repeat(limits::FILE_NAME + 1);
        for bad in [
            "",
            ".hidden",
            "../identity.json",
            "logs/../identity.json",
            "/abs.log",
            "C:\\x.log",
            "C:/x.log",
            "a//b",
            "a/",
            "name with space.log",
            "журнал.log",
            long.as_str(),
        ] {
            assert!(!is_file_name(bad), "{bad}");
        }
    }

    #[test]
    fn auto_details_are_short_machine_words() {
        for ok in [
            "panic",
            "crash",
            "outage_s=73",
            "side=main_thread",
            "encoder_error",
            "a.b:c-d",
        ] {
            assert!(is_auto_detail(ok), "{ok}");
        }
        let long = "a".repeat(limits::AUTO_DETAIL_CHARS + 1);
        for bad in ["", "Panic", "two words", "x/y", "ошибка", long.as_str()] {
            assert!(!is_auto_detail(bad), "{bad}");
        }
        for trigger in AgentAutoTrigger::ALL {
            assert_eq!(AgentAutoTrigger::parse(trigger.as_str()), Some(trigger));
            assert_eq!(
                serde_json::to_value(trigger).expect("serializes"),
                serde_json::Value::from(trigger.as_str())
            );
        }
        assert_eq!(AgentAutoTrigger::parse("unknown"), None);
    }

    #[test]
    fn uuids_as_the_schema_takes_them() {
        assert!(is_uuid("3fa85f64-5717-4562-b3fc-2c963f66afa6"));
        assert!(is_uuid("A3F1C2D4-5B6E-4F7A-8C9D-0E1F2A3B4C5D"));
        assert!(is_uuid("00000000-0000-0000-0000-000000000000"));
        for bad in [
            "",
            "3fa85f64-5717-0562-b3fc-2c963f66afa6", // version 0
            "3fa85f64-5717-4562-73fc-2c963f66afa6", // variant 7
            "3fa85f6457174562b3fc2c963f66afa6",
            "3fa85f64-5717-4562-b3fc-2c963f66afa6x",
            "3fa85f64-5717-4562-b3fc-2c963f66afaz",
        ] {
            assert!(!is_uuid(bad), "{bad}");
        }
    }
}
