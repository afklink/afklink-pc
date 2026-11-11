//! The two vocabularies against the contract: error codes with their severity, and the
//! `session_end` reasons the agent sends.
//!
//! Both are emitted by `packages/protocol/scripts/emit.ts` from `packages/protocol/src/errors.ts`
//! (`ERROR_CODES` into `fixtures/error-codes.json`, `SESSION_END_REASONS` into
//! `fixtures/session-end-reasons.json`), and CI re-emits and diffs them, so a change to either list
//! in TypeScript reaches this test in the same commit.

// A failing contract test *should* abort, and the panic message is the diagnostic. See the same
// allowance in `tests/fixtures.rs`.
#![allow(clippy::panic)]

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use afklink_protocol::{end_reason, error_severity, ERROR_CODES};

fn fixtures_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../contract/packages/protocol/fixtures")
        .canonicalize()
        .expect(
            "shared fixtures not found in contract/packages/protocol/fixtures - the contract \
             submodule is not checked out (`git submodule update --init`); the fixtures are \
             committed there, so a missing directory means a broken checkout",
        )
}

fn read_json<T: serde::de::DeserializeOwned>(name: &str) -> T {
    let path = fixtures_root().join(name);
    let raw = fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!("reading {path:?}: {e} - run `bun run emit` in the contract repository")
    });
    serde_json::from_str(&raw).unwrap_or_else(|e| panic!("{name} is not what emit writes: {e}"))
}

/// `ERROR_CODES` as the contract emits it: code -> "transient" | "fatal".
fn contract_error_codes() -> BTreeMap<String, String> {
    read_json("error-codes.json")
}

/// `SESSION_END_REASONS` as the contract emits it.
fn contract_end_reasons() -> BTreeSet<String> {
    let list: Vec<String> = read_json("session-end-reasons.json");
    let set: BTreeSet<String> = list.iter().cloned().collect();
    assert_eq!(
        set.len(),
        list.len(),
        "session-end-reasons.json repeats a reason"
    );
    set
}

/// Every code this crate knows has the contract's severity: a code that became fatal in the
/// contract and stayed transient here is an agent hammering the backend with a connection that can
/// never succeed; the other way round, an agent that gives up on one that could.
#[test]
fn every_error_code_this_crate_knows_has_the_contract_severity() {
    let contract = contract_error_codes();
    let mut wrong = Vec::new();
    let mut unknown_to_contract = Vec::new();
    for (code, severity) in ERROR_CODES {
        match contract.get(*code) {
            Some(s) if s == severity.as_str() => {}
            Some(s) => wrong.push(format!("{code}: here {}, contract {s}", severity.as_str())),
            None => unknown_to_contract.push(*code),
        }
    }
    assert!(
        wrong.is_empty(),
        "severities differ from ERROR_CODES in errors.ts: {wrong:?}"
    );
    assert!(
        unknown_to_contract.is_empty(),
        "codes the contract no longer has - remove them from afklink_protocol::errors: \
         {unknown_to_contract:?}"
    );
}

/// And this crate knows every code the contract has. An unknown code is treated as transient at
/// run time (a newer backend may send one), which is right for a code from the future and wrong for
/// a fatal code this build simply forgot.
#[test]
fn this_crate_knows_every_error_code_in_the_contract() {
    let missing: Vec<String> = contract_error_codes()
        .into_keys()
        .filter(|code| error_severity(code).is_none())
        .collect();
    assert!(
        missing.is_empty(),
        "the contract grew {missing:?} - add them to afklink_protocol::errors::ERROR_CODES"
    );
}

/// The codes the agent tells apart by name — `replaced` (wait for the owner) and `device_blocked`
/// («ПК заблокирован», no Retry) — are in the contract and fatal there: a rename on the TypeScript
/// side would otherwise turn either into an unknown, transient code, and the agent back into one that
/// knocks every thirty seconds.
#[test]
fn the_codes_the_agent_names_are_fatal_in_the_contract() {
    let contract = contract_error_codes();
    for code in [
        afklink_protocol::errors::REPLACED,
        afklink_protocol::errors::DEVICE_BLOCKED,
    ] {
        assert_eq!(
            contract.get(code).map(String::as_str),
            Some("fatal"),
            "{code} in ERROR_CODES"
        );
    }
}

/// Every reason the agent sends is in the agreed vocabulary, so the viewer has a sentence for it and
/// the session history a name everyone agrees on.
#[test]
fn every_reason_the_agent_sends_is_in_the_contract() {
    let contract = contract_end_reasons();
    let missing: Vec<&str> = end_reason::AGENT_SENT
        .iter()
        .copied()
        .filter(|r| !contract.contains(*r))
        .collect();
    assert!(
        missing.is_empty(),
        "the agent sends session_end reasons that SESSION_END_REASONS in errors.ts does not have: \
         {missing:?}"
    );
    let mut seen = BTreeSet::new();
    for r in end_reason::AGENT_SENT {
        assert!(seen.insert(*r), "{r} is listed twice in AGENT_SENT");
    }
}

/// The reasons the agent receives and names (`unknown_session`, which it acts on; `owner_ended` and
/// `blocked`, which its journal classifies) are in the vocabulary too: a rename on the TypeScript
/// side would otherwise leave the agent comparing against a string nobody sends. None is ever sent.
#[test]
fn the_reasons_the_agent_receives_by_name_are_in_the_contract() {
    let contract = contract_end_reasons();
    for r in [
        end_reason::UNKNOWN_SESSION,
        end_reason::OWNER_ENDED,
        end_reason::BLOCKED,
    ] {
        assert!(
            contract.contains(r),
            "{r} is no longer in SESSION_END_REASONS"
        );
        assert!(
            !end_reason::AGENT_SENT.contains(&r),
            "{r} is the backend's to send, not the agent's"
        );
    }
}

/// A local-only label must never be a wire reason, or a reader of the agent's events could not tell
/// "the backend ended it" from "the agent told the backend this".
#[test]
fn local_only_reasons_are_not_wire_reasons() {
    let contract = contract_end_reasons();
    for r in end_reason::local::ALL {
        assert!(
            !contract.contains(*r),
            "{r} is local only, but SESSION_END_REASONS now has it"
        );
        assert!(
            !end_reason::AGENT_SENT.contains(r),
            "{r} is local only and must not be sent"
        );
    }
}
