//! The start failure beacon's Rust side against the contract (`start-failure.ts`): the fixture the
//! manifest lists in its `rest` group round-trips through [`AgentStartFailure`] and passes its
//! checks; the emitted schema has exactly these fields, required ones, words, lengths and patterns;
//! and the path is the TypeScript constant's.
//!
//! The patterns are compared as text: a rule changed in the zod schema fails here, and the
//! hand-written checks in `afklink_protocol::start_failure` are updated to match — the same way the
//! diagnostics file-name rule is held (`tests/diagnostics.rs`).

// A failing contract test *should* abort, and the panic message is the diagnostic. See the same
// allowance in `tests/fixtures.rs`.
#![allow(clippy::panic)]

use std::fs;
use std::path::{Path, PathBuf};

use afklink_protocol::start_failure::{
    is_commit, is_detail_code, is_os, is_version, limits, AgentStartFailure, BuildChannel,
    StartFailureReason, AGENT_START_FAILURE_PATH,
};
use serde_json::Value;

/// The fixture's file, as the manifest names it.
const FIXTURE: &str = "rest/agent_start_failure.json";

fn protocol_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../contract/packages/protocol")
        .canonicalize()
        .expect(
            "contract/packages/protocol not found - the contract submodule is not checked out \
             (`git submodule update --init`)",
        )
}

fn read_text(rel: &str) -> String {
    let path = protocol_root().join(rel);
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("reading {path:?}: {e}"))
}

fn read(rel: &str) -> Value {
    serde_json::from_str(&read_text(rel)).unwrap_or_else(|e| panic!("{rel} is not valid JSON: {e}"))
}

fn words(v: &Value) -> Vec<&str> {
    v.as_array()
        .unwrap_or_else(|| panic!("not a list: {v}"))
        .iter()
        .map(|w| w.as_str().unwrap_or_else(|| panic!("not a word: {w}")))
        .collect()
}

fn pattern(v: &Value) -> &str {
    v["pattern"]
        .as_str()
        .unwrap_or_else(|| panic!("no pattern in {v}"))
}

fn max_length(v: &Value) -> usize {
    usize::try_from(
        v["maxLength"]
            .as_u64()
            .unwrap_or_else(|| panic!("no maxLength in {v}")),
    )
    .expect("fits")
}

/// The manifest lists the fixture in its `rest` group, with no variant tag (a REST body has none).
#[test]
fn the_manifest_lists_the_fixture_in_its_rest_group() {
    let manifest = read("fixtures/manifest.json");
    let rest = manifest["groups"]
        .as_array()
        .expect("manifest.groups is a list")
        .iter()
        .find(|g| g["name"] == "rest")
        .expect("the manifest has a rest group");
    let entry = rest["fixtures"]
        .as_array()
        .expect("rest.fixtures is a list")
        .iter()
        .find(|f| f["file"] == FIXTURE)
        .unwrap_or_else(|| panic!("the rest group does not list {FIXTURE}"));
    assert!(entry["variant"].is_null(), "{entry}");
}

/// The fixture parses into [`AgentStartFailure`], comes back out the same (a field renamed or
/// dropped here fails), and passes the checks the app runs before sending.
#[test]
fn the_fixture_round_trips_and_passes_the_checks() {
    let original = read(&format!("fixtures/{FIXTURE}"));
    let beacon: AgentStartFailure = serde_json::from_value(original.clone())
        .unwrap_or_else(|e| panic!("{FIXTURE} does not parse: {e}"));
    assert_eq!(
        serde_json::to_value(&beacon).expect("serializes"),
        original,
        "round-trip changed the beacon"
    );
    assert_eq!(beacon.check(), Ok(()));
    // Every optional field is in the fixture, so the round-trip above covers them all.
    assert!(beacon.commit.is_some() && beacon.detail_code.is_some());
    assert!(serde_json::to_vec(&beacon).expect("serializes").len() < limits::BODY_BYTES);
}

/// The schema's fields, required ones, words, lengths and patterns are the ones this crate checks.
#[test]
fn the_schema_is_the_one_this_crate_checks() {
    let schema = read("schema/rest-agent-start-failure.json");
    let props = &schema["properties"];
    let mut fields: Vec<&str> = props
        .as_object()
        .expect("properties")
        .keys()
        .map(String::as_str)
        .collect();
    fields.sort_unstable();
    assert_eq!(
        fields,
        [
            "channel",
            "commit",
            "detail_code",
            "device_id",
            "os",
            "reason",
            "version"
        ],
        "the beacon's fields changed: update AgentStartFailure"
    );
    let mut required = words(&schema["required"]);
    required.sort_unstable();
    assert_eq!(
        required,
        ["channel", "device_id", "os", "reason", "version"],
        "commit and detail_code are optional, the rest required"
    );

    let reasons: Vec<&str> = StartFailureReason::ALL.iter().map(|r| r.as_str()).collect();
    assert_eq!(
        words(&props["reason"]["enum"]),
        reasons,
        "AGENT_START_FAILURE_REASONS and StartFailureReason::ALL"
    );
    let channels: Vec<&str> = BuildChannel::ALL.iter().map(|c| c.as_str()).collect();
    assert_eq!(
        words(&props["channel"]["enum"]),
        channels,
        "AGENT_BUILD_CHANNELS and BuildChannel::ALL"
    );

    assert_eq!(max_length(&props["version"]), limits::VERSION_CHARS);
    assert_eq!(max_length(&props["os"]), limits::OS_CHARS);
    assert_eq!(
        pattern(&props["version"]),
        r"^\d{1,5}\.\d{1,5}\.\d{1,5}(-[0-9A-Za-z.-]{1,24})?$",
        "the version rule changed: update `is_version`"
    );
    assert_eq!(
        pattern(&props["os"]),
        r"^\d{1,3}\.\d{1,3}\.\d{1,6}(\.\d{1,6})?$",
        "the os rule changed: update `is_os`"
    );
    // The optional two are `anyOf: [string, null]`.
    let nullable = |field: &str| -> &Value {
        let any = props[field]["anyOf"]
            .as_array()
            .unwrap_or_else(|| panic!("{field} is anyOf"));
        assert!(
            any.iter().any(|v| v["type"] == "null"),
            "{field} takes null"
        );
        any.iter()
            .find(|v| v["type"] == "string")
            .unwrap_or_else(|| panic!("{field} is a string"))
    };
    assert_eq!(
        pattern(nullable("commit")),
        "^[0-9a-f]{7,40}$",
        "the commit rule changed: update `is_commit`"
    );
    assert_eq!(
        pattern(nullable("detail_code")),
        format!("^[0-9A-Za-z_.-]{{1,{}}}$", limits::DETAIL_CODE_CHARS),
        "the detail code rule changed: update `is_detail_code`"
    );
    assert_eq!(
        pattern(&props["device_id"]),
        "^([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-8][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}\
         |00000000-0000-0000-0000-000000000000|ffffffff-ffff-ffff-ffff-ffffffffffff)$",
        "the device id rule changed: update `afklink_protocol::diagnostics::is_uuid`"
    );

    // The fixture's values pass the hand-written checks one by one, too.
    let fixture = read(&format!("fixtures/{FIXTURE}"));
    let s = |k: &str| fixture[k].as_str().unwrap_or_else(|| panic!("{k}"));
    assert!(is_version(s("version")));
    assert!(is_os(s("os")));
    assert!(is_commit(s("commit")));
    assert!(is_detail_code(s("detail_code")));
}

/// The path is `AGENT_START_FAILURE_PATH` in `start-failure.ts` (the schema does not carry it).
#[test]
fn the_path_is_the_contracts() {
    let source = read_text("src/start-failure.ts");
    let marker = "export const AGENT_START_FAILURE_PATH = \"";
    let at = source
        .find(marker)
        .unwrap_or_else(|| panic!("start-failure.ts no longer declares AGENT_START_FAILURE_PATH"));
    let rest = &source[at + marker.len()..];
    let end = rest.find('"').expect("the constant's closing quote");
    assert_eq!(&rest[..end], AGENT_START_FAILURE_PATH);
}
