//! The signed challenge's bytes against the contract: this crate's
//! `AGENT_CHALLENGE_PREFIX` is the contract's, byte for byte, and every case's message in
//! `vectors/agent-challenge-signature.json` is rebuilt from its nonce.
//!
//! The signatures themselves (Ed25519 with the vector's seed, prefixed and legacy) are checked
//! against the same vector by `afklink_core::identity`, which signs; that the handshake signs this
//! message and sends what came back, by `afklink_transport::signaling`.

// A failing contract test *should* abort, and the panic message is the diagnostic. See the same
// allowance in `tests/fixtures.rs`.
#![allow(clippy::panic)]

use std::fs;
use std::path::Path;

use afklink_protocol::{
    agent_challenge_message, AGENT_CHALLENGE_MESSAGE_BYTES, AGENT_CHALLENGE_NONCE_BYTES,
    AGENT_CHALLENGE_PREFIX,
};
use serde_json::Value;

fn vector() -> Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../contract/packages/protocol/vectors/agent-challenge-signature.json");
    let raw = fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "reading {path:?}: {e} - the contract submodule is not checked out \
             (`git submodule update --init`)"
        )
    });
    serde_json::from_str(&raw).unwrap_or_else(|e| panic!("the vector is not valid JSON: {e}"))
}

fn str_of<'a>(v: &'a Value, key: &str) -> &'a str {
    v[key]
        .as_str()
        .unwrap_or_else(|| panic!("{key}: not a string"))
}

fn hex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "odd hex length: {s}");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap_or_else(|e| panic!("{s}: {e}")))
        .collect()
}

/// The prefix is the contract's: as text (with its NUL) and as bytes, 30 of them.
#[test]
fn the_prefix_is_the_contracts_byte_for_byte() {
    let v = vector();
    assert_eq!(str_of(&v, "prefix").as_bytes(), AGENT_CHALLENGE_PREFIX);
    assert_eq!(hex(str_of(&v, "prefix_hex")), AGENT_CHALLENGE_PREFIX);
    assert_eq!(AGENT_CHALLENGE_PREFIX.len(), 30);
    assert_eq!(AGENT_CHALLENGE_PREFIX.last(), Some(&0));
    assert_eq!(AGENT_CHALLENGE_MESSAGE_BYTES, 62);
}

/// Every case's message is the prefix followed by its nonce, rebuilt by the function the agent
/// signs through.
#[test]
fn every_case_rebuilds_its_message() {
    let v = vector();
    let cases = v["cases"].as_array().expect("cases");
    assert!(cases.len() >= 2, "the contract has two cases");
    for case in cases {
        let nonce = hex(str_of(case, "nonce_hex"));
        assert_eq!(nonce.len(), AGENT_CHALLENGE_NONCE_BYTES);
        let message = agent_challenge_message(&nonce).expect("a 32-byte nonce has a message");
        assert_eq!(message.as_slice(), hex(str_of(case, "message_hex")));
    }
}

/// A nonce of any other length has no message: the agent signs nothing for it.
#[test]
fn a_nonce_of_another_length_has_no_message() {
    for len in [0, 1, 16, 31, 33, 64] {
        assert_eq!(
            agent_challenge_message(&vec![7u8; len]),
            None,
            "{len} bytes"
        );
    }
}
