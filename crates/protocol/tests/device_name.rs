//! The device-name rule against the contract: the cases the TypeScript schema is tested with
//! (`contract/packages/protocol/vectors/device-names.json`, read by `src/device-name.test.ts` there
//! too), and
//! the limit the emitted JSON Schema carries.
//!
//! A name this crate accepts and the backend refuses is not stored, so the Mini App keeps listing
//! the device under the backend's placeholder — the bug the rule was written for. Hence one list of
//! cases for both.

// A failing contract test *should* abort, and the panic message is the diagnostic. See the same
// allowance in `tests/fixtures.rs`.
#![allow(clippy::panic)]

use std::fs;
use std::path::{Path, PathBuf};

use afklink_protocol::{validate_device_name, DEVICE_NAME_MAX};
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

fn read_json(rel: &str) -> Value {
    let path = protocol_root().join(rel);
    let raw = fs::read_to_string(&path).unwrap_or_else(|e| panic!("reading {path:?}: {e}"));
    serde_json::from_str(&raw).unwrap_or_else(|e| panic!("{rel} is not valid JSON: {e}"))
}

fn str_field<'a>(case: &'a Value, key: &str) -> &'a str {
    case[key]
        .as_str()
        .unwrap_or_else(|| panic!("case {case} has no string {key:?}"))
}

#[test]
fn the_shared_cases_use_this_crates_limit() {
    let v = read_json("vectors/device-names.json");
    assert_eq!(
        v["max"].as_u64(),
        Some(DEVICE_NAME_MAX as u64),
        "the shared cases and DEVICE_NAME_MAX disagree about the limit"
    );
}

#[test]
fn every_valid_case_is_accepted_and_trimmed_the_same_way() {
    let v = read_json("vectors/device-names.json");
    let cases = v["valid"].as_array().expect("valid is an array");
    assert!(!cases.is_empty());
    for case in cases {
        let raw = str_field(case, "raw");
        let why = str_field(case, "why");
        assert_eq!(
            validate_device_name(raw).as_deref(),
            Ok(str_field(case, "name")),
            "{why}: {raw:?}"
        );
    }
}

#[test]
fn every_invalid_case_is_refused_for_the_same_reason() {
    let v = read_json("vectors/device-names.json");
    let cases = v["invalid"].as_array().expect("invalid is an array");
    assert!(!cases.is_empty());
    for case in cases {
        let raw = str_field(case, "raw");
        let why = str_field(case, "why");
        match validate_device_name(raw) {
            Ok(name) => panic!("{why}: {raw:?} was accepted as {name:?}"),
            Err(e) => assert_eq!(e.as_str(), str_field(case, "error"), "{why}: {raw:?}"),
        }
    }
}

/// The emitted schema of a Mini App label carries the limit the backend applies: its name is blank
/// (clears the label) or a device name (`deviceNameSchema`), and the second branch is the rule.
#[test]
fn the_limit_is_the_one_the_contract_emits() {
    let schema = read_json("schema/rest-patch-device-request.json");
    let branches = schema["properties"]["name"]["anyOf"]
        .as_array()
        .expect("name is blank or a device name");
    let rule = branches
        .iter()
        .find(|b| b["minLength"].as_u64() == Some(1))
        .unwrap_or_else(|| panic!("no device-name branch in {branches:?}"));
    assert_eq!(rule["maxLength"].as_u64(), Some(DEVICE_NAME_MAX as u64));
}
