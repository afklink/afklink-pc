//! The diagnostics upload's Rust side against the contract: the metadata and
//! receipt fixtures round-trip, the limits are the emitted JSON Schemas', and the canonical string of
//! every case in `vectors/agent-request-signature.json` is rebuilt byte for byte.
//!
//! The signature itself (sha256, base64url, Ed25519 with the device key) is checked against the same
//! vectors by the desktop app, which does the signing (`afklink_app_lib`'s `diagnostics::upload`).

// A failing contract test *should* abort, and the panic message is the diagnostic. See the same
// allowance in `tests/fixtures.rs`.
#![allow(clippy::panic)]

use std::fs;
use std::path::{Path, PathBuf};

use afklink_protocol::diagnostics::{
    agent_request_canonical, header, is_auto_detail, is_file_name, is_uuid, limits,
    AgentAutoTrigger, AgentDiagnosticsMeta, AgentRequestSigned, DiagnosticsReceipt,
    AGENT_REQUEST_SCHEME, DIAGNOSTICS_AGENT_PATH,
};
use serde_json::Value;

fn protocol_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../contract/packages/protocol")
        .canonicalize()
        .expect(
            "contract/packages/protocol not found - the contract submodule is not checked out \
             (`git submodule update --init`)",
        )
}

fn read(rel: &str) -> Value {
    let path = protocol_root().join(rel);
    let raw = fs::read_to_string(&path).unwrap_or_else(|e| panic!("reading {path:?}: {e}"));
    serde_json::from_str(&raw).unwrap_or_else(|e| panic!("{rel} is not valid JSON: {e}"))
}

fn str_of<'a>(v: &'a Value, key: &str) -> &'a str {
    v[key]
        .as_str()
        .unwrap_or_else(|| panic!("{key} is not a string in {v}"))
}

/// The metadata fixture parses into [`AgentDiagnosticsMeta`] and comes back out the same: a field
/// renamed or dropped here fails.
#[test]
fn the_metadata_fixture_round_trips() {
    let original = read("fixtures/rest/diagnostics_agent_meta.json");
    let meta: AgentDiagnosticsMeta = serde_json::from_value(original.clone())
        .unwrap_or_else(|e| panic!("the metadata fixture does not parse: {e}"));
    assert_eq!(
        serde_json::to_value(&meta).expect("serializes"),
        original,
        "round-trip changed the metadata"
    );
    assert!(meta.files.iter().all(|f| is_file_name(&f.name)));
    assert!(meta.session_ids.iter().flatten().all(|id| is_uuid(id)));
}

/// The automatic report's metadata fixture: parses, with its `auto` marker, and comes back out the
/// same; the marker's detail is one the agent may write.
#[test]
fn the_automatic_metadata_fixture_round_trips() {
    let original = read("fixtures/rest/diagnostics_agent_meta_auto.json");
    let meta: AgentDiagnosticsMeta = serde_json::from_value(original.clone())
        .unwrap_or_else(|e| panic!("the automatic metadata fixture does not parse: {e}"));
    assert_eq!(
        serde_json::to_value(&meta).expect("serializes"),
        original,
        "round-trip changed the automatic metadata"
    );
    let auto = meta
        .auto
        .as_ref()
        .expect("the fixture is an automatic report");
    assert_eq!(auto.trigger, AgentAutoTrigger::SessionFailed);
    assert!(auto.at > 0);
    assert!(auto.detail.as_deref().is_some_and(is_auto_detail));
    // A manual report's metadata has no marker, and writes none.
    let manual: AgentDiagnosticsMeta =
        serde_json::from_value(read("fixtures/rest/diagnostics_agent_meta.json")).expect("parses");
    assert_eq!(manual.auto, None);
    assert!(serde_json::to_value(&manual).expect("serializes")["auto"].is_null());
    // The marker is strict, as the schema is: an unknown key is refused.
    let mut extra = original;
    extra["auto"]["extra"] = Value::from(1);
    assert!(serde_json::from_value::<AgentDiagnosticsMeta>(extra).is_err());
}

/// `auto` as the emitted schema has it: the triggers in order, the detail's length and pattern,
/// nothing else allowed.
#[test]
fn the_automatic_marker_is_the_schemas() {
    let meta = read("schema/rest-diagnostics-agent-meta.json");
    let auto = &meta["properties"]["auto"];
    let triggers: Vec<&str> = auto["properties"]["trigger"]["enum"]
        .as_array()
        .expect("an enum")
        .iter()
        .map(|v| v.as_str().expect("a name"))
        .collect();
    let ours: Vec<&str> = AgentAutoTrigger::ALL.iter().map(|t| t.as_str()).collect();
    assert_eq!(triggers, ours);
    let detail = &auto["properties"]["detail"];
    assert_eq!(
        detail["maxLength"].as_u64().map(|n| n as usize),
        Some(limits::AUTO_DETAIL_CHARS)
    );
    assert_eq!(
        str_of(detail, "pattern"),
        "^[a-z0-9_.:=-]+$",
        "the detail rule changed: update `is_auto_detail`"
    );
    assert_eq!(auto["additionalProperties"], Value::Bool(false));
}

/// The value of `name: <expression>,` in `DIAGNOSTICS_LIMITS` of `diagnostics-wire.ts`: a product of
/// integer literals (`24 * 60 * 60_000`), the only shape the automatic limits are written in.
fn wire_limit(source: &str, name: &str) -> u64 {
    let prefix = format!("{name}:");
    let line = source
        .lines()
        .map(str::trim)
        .find(|line| line.starts_with(&prefix))
        .unwrap_or_else(|| panic!("{name} is not in DIAGNOSTICS_LIMITS"));
    let expression = line[prefix.len()..].trim().trim_end_matches(',');
    expression
        .split('*')
        .map(|factor| {
            factor
                .trim()
                .replace('_', "")
                .parse::<u64>()
                .unwrap_or_else(|e| panic!("{name}: {factor:?} is not an integer ({e})"))
        })
        .product()
}

/// The automatic report's limits are the contract's, as `diagnostics-wire.ts` writes them (no JSON
/// Schema carries them).
#[test]
fn the_automatic_limits_are_the_contracts() {
    let path = protocol_root().join("src/diagnostics-wire.ts");
    let source = fs::read_to_string(&path).unwrap_or_else(|e| panic!("reading {path:?}: {e}"));
    assert_eq!(
        wire_limit(&source, "agentAutoBodyBytes"),
        limits::AGENT_AUTO_BODY_BYTES
    );
    assert_eq!(
        wire_limit(&source, "agentAutoPerWindow"),
        limits::AGENT_AUTO_PER_WINDOW as u64
    );
    assert_eq!(
        wire_limit(&source, "agentAutoWindowMs"),
        limits::AGENT_AUTO_WINDOW_MS
    );
    assert_eq!(
        wire_limit(&source, "agentAutoServicePerHour"),
        limits::AGENT_AUTO_SERVICE_PER_HOUR as u64
    );
    assert_eq!(
        wire_limit(&source, "agentAutoOutageMs"),
        limits::AGENT_AUTO_OUTAGE_MS
    );
    assert_eq!(
        wire_limit(&source, "agentAutoMinGapMs"),
        limits::AGENT_AUTO_MIN_GAP_MS
    );
    assert_eq!(
        wire_limit(&source, "agentBodyBytes"),
        limits::AGENT_BODY_BYTES
    );
    assert_eq!(
        wire_limit(&source, "signatureWindowMs"),
        limits::SIGNATURE_WINDOW_MS
    );
    assert!(
        source.contains(
            r#"AGENT_AUTO_REPORT_TRIGGERS = ["crash", "offline", "session_failed", "stall"] as const"#
        ),
        "the triggers changed: update `AgentAutoTrigger`"
    );
}

#[test]
fn the_receipt_fixture_round_trips() {
    let original = read("fixtures/rest/diagnostics_receipt.json");
    let receipt: DiagnosticsReceipt = serde_json::from_value(original.clone())
        .unwrap_or_else(|e| panic!("the receipt fixture does not parse: {e}"));
    assert_eq!(
        serde_json::to_value(&receipt).expect("serializes"),
        original
    );
    assert!(is_uuid(&receipt.report_id));
}

/// The headers fixture names exactly the six headers this crate sends.
#[test]
fn the_header_names_are_the_contracts() {
    let fixture = read("fixtures/rest/diagnostics_agent_headers.json");
    let mut names: Vec<&str> = fixture
        .as_object()
        .expect("an object")
        .keys()
        .map(String::as_str)
        .collect();
    names.sort_unstable();
    let mut ours = header::ALL.to_vec();
    ours.sort_unstable();
    assert_eq!(names, ours);
}

/// Every vector's canonical string, rebuilt from its headers — and its metadata JSON, serialized
/// from this crate's type, byte for byte the vector's.
#[test]
fn every_vector_case_rebuilds_its_canonical_string() {
    let vectors = read("vectors/agent-request-signature.json");
    assert_eq!(str_of(&vectors, "scheme"), AGENT_REQUEST_SCHEME);
    let cases = vectors["cases"].as_array().expect("cases");
    assert!(cases.len() >= 2, "the contract has two cases");
    for case in cases {
        let why = str_of(case, "why");
        let headers = &case["headers"];
        assert_eq!(str_of(case, "method"), "POST", "{why}");
        assert_eq!(str_of(case, "path"), DIAGNOSTICS_AGENT_PATH, "{why}");
        let canonical = agent_request_canonical(&AgentRequestSigned {
            method: str_of(case, "method"),
            path: str_of(case, "path"),
            device: str_of(headers, header::DEVICE),
            timestamp: str_of(headers, header::TIMESTAMP),
            nonce: str_of(headers, header::NONCE),
            content_sha256: str_of(headers, header::CONTENT_SHA256),
            meta_sha256: str_of(case, "meta_sha256"),
        })
        .unwrap_or_else(|e| panic!("{why}: {e}"));
        assert_eq!(canonical, str_of(case, "canonical"), "{why}");

        let meta_json = str_of(case, "meta_json");
        let meta: AgentDiagnosticsMeta =
            serde_json::from_str(meta_json).unwrap_or_else(|e| panic!("{why}: {e}"));
        assert_eq!(
            serde_json::to_string(&meta).expect("serializes"),
            meta_json,
            "{why}: the metadata JSON this crate writes differs from the vector's"
        );
    }
}

/// The limits this crate packs to are the ones the server's schemas hold.
#[test]
fn the_limits_are_the_schemas() {
    let meta = read("schema/rest-diagnostics-agent-meta.json");
    let props = &meta["properties"];
    let n = |v: &Value| usize::try_from(v.as_u64().expect("a number")).expect("fits");
    assert_eq!(n(&props["comment"]["maxLength"]), limits::COMMENT_CHARS);
    assert_eq!(n(&props["files"]["maxItems"]), limits::FILES);
    assert_eq!(n(&props["files"]["minItems"]), 1);
    let name = &props["files"]["items"]["properties"]["name"];
    assert_eq!(n(&name["maxLength"]), limits::FILE_NAME);
    assert_eq!(
        str_of(name, "pattern"),
        "^[A-Za-z0-9][A-Za-z0-9._-]*(\\/[A-Za-z0-9][A-Za-z0-9._-]*)*$",
        "the file-name rule changed: update `is_file_name`"
    );
    assert_eq!(n(&props["session_ids"]["maxItems"]), limits::SESSION_IDS);
    assert_eq!(n(&props["os"]["maxLength"]), limits::OS_CHARS);

    let headers = read("schema/rest-diagnostics-agent-headers.json");
    let meta_header = &headers["properties"][header::META];
    assert_eq!(n(&meta_header["maxLength"]), limits::META_HEADER_CHARS);
    let required: Vec<&str> = headers["required"]
        .as_array()
        .expect("required")
        .iter()
        .map(|v| v.as_str().expect("a name"))
        .collect();
    assert_eq!(required, header::ALL.to_vec());
}
