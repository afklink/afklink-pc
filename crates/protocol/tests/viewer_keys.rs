//! Viewer device keys against the contract: the constants and vocabularies of `viewer-keys.ts` and
//! `metrics.ts`, the `ks` message against the emitted JSON Schema, strict base64url against
//! `vectors/viewer-keys/encoding.json`, and every device-key golden fixture against the agent's own
//! form checks and limits (`afklink_protocol::viewer_keys`). Parties, which stand on the keys, the
//! same way: the limits and lists of `party.ts`, the party messages' schemas, and every party fixture
//! against `afklink_protocol::party`.
//!
//! The round trip of those fixtures is `tests/fixtures.rs`; this file checks what a round trip
//! cannot see — that a value the contract emits is one the agent's checks accept, and that the
//! numbers the agent will enforce are the contract's.

// A failing contract test *should* abort, and the panic message is the diagnostic. See the same
// allowance in `tests/fixtures.rs`.
#![allow(clippy::panic)]

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use afklink_protocol::party;
use afklink_protocol::viewer_keys::{
    self as vk, b64url_decode, bytes, check_proof_wire, check_viewer_key_wire, is_b64url,
    is_device_desc, is_nonce_batch, KeyAdmit, KeyEndReason, KeyMode, KsVerdict,
};
use afklink_protocol::{
    AgentDataMessage, AgentToServer, PartyAckOp, PartyAckResult, ServerToAgent,
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

fn read(rel: &[&str]) -> String {
    let path = rel.iter().fold(protocol_root(), |p, part| p.join(part));
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("reading {path:?}: {e}"))
}

fn json(rel: &[&str]) -> Value {
    serde_json::from_str(&read(rel)).unwrap_or_else(|e| panic!("{rel:?} is not JSON: {e}"))
}

/// The files of one manifest group.
fn group(name: &str) -> Vec<String> {
    let manifest = json(&["fixtures", "manifest.json"]);
    manifest["groups"]
        .as_array()
        .expect("manifest.groups")
        .iter()
        .find(|g| g["name"] == name)
        .unwrap_or_else(|| panic!("manifest has no group {name:?}"))["fixtures"]
        .as_array()
        .expect("group.fixtures")
        .iter()
        .map(|f| f["file"].as_str().expect("fixture.file").to_string())
        .collect()
}

fn fixture(file: &str) -> Value {
    json(&["fixtures", file])
}

/// `export const <name> = <number>;` in a contract source file, `_` separators allowed.
fn ts_number(source: &str, name: &str) -> u64 {
    let marker = format!("export const {name} = ");
    let start = source
        .find(&marker)
        .unwrap_or_else(|| panic!("no `{marker}` in the contract source"))
        + marker.len();
    let rest = &source[start..];
    let end = rest.find(';').expect("a semicolon");
    rest[..end]
        .replace('_', "")
        .trim()
        .parse()
        .unwrap_or_else(|e| panic!("{name}: {e}"))
}

/// The words between `[` and the next `]` after `from`, a `...NAME` spread expanded from `source`;
/// a `//` comment between them (with no `]` in it) is not a word.
fn words_at(source: &str, from: usize) -> Vec<String> {
    let rest = &source[from..];
    let open = rest.find('[').expect("an opening bracket");
    let close = rest.find(']').expect("a closing bracket");
    let uncommented: String = rest[open + 1..close]
        .lines()
        .map(|line| line.split("//").next().unwrap_or(""))
        .collect::<Vec<_>>()
        .join("\n");
    uncommented
        .split(',')
        .map(str::trim)
        .filter(|w| !w.is_empty())
        .flat_map(|w| match w.strip_prefix("...") {
            Some(spread) => ts_list(source, spread),
            None => vec![w.trim_matches('"').to_string()],
        })
        .collect()
}

/// `export const <name> = [ ... ] as const;`, spreads expanded.
fn ts_list(source: &str, name: &str) -> Vec<String> {
    let marker = format!("export const {name} = [");
    let at = source
        .find(&marker)
        .unwrap_or_else(|| panic!("no `{marker}` in the contract source"));
    words_at(source, at)
}

/// One reason's list in `SESSION_END_DETAILS` (`metrics.ts`); empty when the reason has none.
fn end_details(metrics: &str, reason: &str) -> Vec<String> {
    let table = metrics
        .find("export const SESSION_END_DETAILS = {")
        .expect("SESSION_END_DETAILS");
    let end = table + metrics[table..].find("} as const;").expect("its end");
    match metrics[table..end].find(&format!("\n  {reason}: [")) {
        Some(at) => words_at(metrics, table + at),
        None => vec![],
    }
}

fn strings<T: Copy>(all: &[T], word: impl Fn(T) -> &'static str) -> Vec<String> {
    all.iter().map(|x| word(*x).to_string()).collect()
}

/// Every number the agent will enforce or schedule by is the contract's.
#[test]
fn the_constants_are_the_contracts() {
    let src = read(&["src", "viewer-keys.ts"]);
    let usize_of = |name| usize::try_from(ts_number(&src, name)).expect("fits");
    for (name, ours) in [
        ("NONCE_BYTES", vk::NONCE_BYTES),
        ("NONCE_BATCH", vk::NONCE_BATCH),
        ("NONCE_BOOK_MAX_BATCHES", vk::NONCE_BOOK_MAX_BATCHES),
        ("ADMIT_MAX", vk::ADMIT_MAX),
        ("KEYS_PER_PERSON", vk::KEYS_PER_PERSON),
        ("KEYS_MAX", vk::KEYS_MAX),
        ("REVOKED_MAX", vk::REVOKED_MAX),
        ("PROOF_MAX_BYTES", vk::PROOF_MAX_BYTES),
        ("PROOF_MAX_DEPTH", vk::PROOF_MAX_DEPTH),
        ("VIEWER_KEY_MAX_BYTES", vk::VIEWER_KEY_MAX_BYTES),
        ("ATTEST_INIT_DATA_MAX_BYTES", vk::ATTEST_INIT_DATA_MAX_BYTES),
        ("KEY_ID_LOG_CHARS", vk::KEY_ID_LOG_CHARS),
    ] {
        assert_eq!(usize_of(name), ours, "{name}");
    }
    for (name, ours) in [
        ("NONCE_ROTATE_MS", vk::NONCE_ROTATE_MS),
        ("NONCE_REFILL_MIN_MS", vk::NONCE_REFILL_MIN_MS),
        ("NONCE_SERVE_MS", vk::NONCE_SERVE_MS),
        ("NONCE_TTL_MS", vk::NONCE_TTL_MS),
        ("NONCE_BOOK_KEEP_MS", vk::NONCE_BOOK_KEEP_MS),
        ("INVITE_GRANT_WINDOW_MS", vk::INVITE_GRANT_WINDOW_MS),
        ("INVITE_GRANT_SKEW_MS", vk::INVITE_GRANT_SKEW_MS),
        ("VERIFY_RATE_PER_S", u64::from(vk::VERIFY_RATE_PER_S)),
        ("VIEWER_KEYS_VERSION", u64::from(vk::VIEWER_KEYS_VERSION)),
    ] {
        assert_eq!(ts_number(&src, name), ours, "{name}");
    }
    assert!(src.contains(&format!(
        "export const RECOVER_START_PARAM_PREFIX = \"{}\";",
        vk::RECOVER_START_PARAM_PREFIX
    )));
    // `VIEWER_KEY_BYTES`: one `name: n,` line each.
    let table = src
        .find("export const VIEWER_KEY_BYTES = {")
        .expect("VIEWER_KEY_BYTES");
    let table = &src[table..table + src[table..].find("} as const;").expect("its end")];
    for (name, ours) in [
        ("keyId", bytes::KEY_ID),
        ("fingerprint", bytes::FINGERPRINT),
        ("nonce", bytes::NONCE),
        ("id", bytes::ID),
        ("spki", bytes::SPKI),
        ("signature", bytes::SIGNATURE),
        ("hmac", bytes::HMAC),
    ] {
        assert!(
            table.contains(&format!("\n  {name}: {ours},")),
            "VIEWER_KEY_BYTES.{name}"
        );
    }
}

/// The vocabularies, word for word and in order: the reasons with their `ended_detail` lists, the
/// verdicts, the admits, the modes, the device descriptions.
#[test]
fn the_vocabularies_are_the_contracts() {
    let src = read(&["src", "viewer-keys.ts"]);
    let reasons = strings(&KeyEndReason::ALL, KeyEndReason::as_str);
    assert_eq!(ts_list(&src, "KEY_END_REASONS"), reasons);
    assert_eq!(
        ts_list(&src, "KS_VERDICTS"),
        strings(&KsVerdict::ALL, KsVerdict::as_str)
    );
    let mut verdicts = vec!["signed".to_string(), vk::KEY_VERDICT_UNSIGNED.to_string()];
    verdicts.extend(reasons.iter().cloned());
    assert_eq!(ts_list(&src, "KEY_VERDICTS"), verdicts);
    assert_eq!(
        ts_list(&src, "KEY_ADMITS"),
        strings(&KeyAdmit::ALL, KeyAdmit::as_str)
    );
    assert_eq!(
        ts_list(&src, "KEY_MODES"),
        strings(&KeyMode::ALL, KeyMode::as_str)
    );
    assert_eq!(ts_list(&src, "DEVICE_KINDS"), vk::DEVICE_KINDS);
    assert_eq!(ts_list(&src, "DEVICE_PLATFORMS"), vk::DEVICE_PLATFORMS);
    assert!(src.contains("export const DEVICE_DESC_PATTERN = /^[a-z0-9_]{1,24}$/;"));

    let metrics = read(&["src", "metrics.ts"]);
    for r in KeyEndReason::ALL {
        assert_eq!(end_details(&metrics, r.as_str()), r.details(), "{r}");
    }
    // The reasons are in `SESSION_END_REASONS`, as the contract emits it.
    let emitted: BTreeSet<String> =
        serde_json::from_value(json(&["fixtures", "session-end-reasons.json"])).expect("a list");
    for r in &reasons {
        assert!(emitted.contains(r), "{r} is not in SESSION_END_REASONS");
    }
}

/// `ks` as the contract's schema has it: the fields, the enums in order, the patterns.
#[test]
fn the_key_status_is_the_contracts() {
    let schema = json(&["schema", "agent-to-viewer.json"]);
    let ks = schema["oneOf"]
        .as_array()
        .or_else(|| schema["anyOf"].as_array())
        .expect("a union")
        .iter()
        .find(|v| v["properties"]["t"]["const"] == "ks")
        .expect("the schema has ks")
        .clone();
    let props = ks["properties"].as_object().expect("properties");
    assert_eq!(
        props.keys().map(String::as_str).collect::<BTreeSet<_>>(),
        ["t", "kid", "verdict", "detail", "admit", "mode"]
            .into_iter()
            .collect(),
        "ks grew a field: mirror it in KeyStatus"
    );
    let required: BTreeSet<&str> = ks["required"]
        .as_array()
        .expect("required")
        .iter()
        .map(|v| v.as_str().expect("a name"))
        .collect();
    assert_eq!(
        required,
        ["t", "kid", "verdict", "mode"].into_iter().collect()
    );
    let enum_of = |name: &str| -> Vec<String> {
        serde_json::from_value(props[name]["enum"].clone()).expect("an enum")
    };
    assert_eq!(
        enum_of("verdict"),
        strings(&KsVerdict::ALL, KsVerdict::as_str)
    );
    assert_eq!(enum_of("admit"), strings(&KeyAdmit::ALL, KeyAdmit::as_str));
    assert_eq!(enum_of("mode"), strings(&KeyMode::ALL, KeyMode::as_str));
    assert_eq!(props["detail"]["pattern"], "^[a-z0-9_:]{1,32}$");
    // `kid`'s pattern: 42 free characters and a last one with its unused bits zero. The agent's
    // strict decoder agrees on every possible last character.
    assert_eq!(
        props["kid"]["pattern"],
        "^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$"
    );
    let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    for last in alphabet.chars() {
        let kid = format!("{}{last}", "x".repeat(42));
        assert_eq!(
            is_b64url(&kid, bytes::KEY_ID),
            "AEIMQUYcgkosw048".contains(last),
            "{kid}"
        );
    }
}

/// Strict base64url (§1.2) against the contract's vectors: every good case decodes to its bytes,
/// every bad one is refused.
#[test]
fn base64url_follows_the_vectors() {
    let vectors = json(&["vectors", "viewer-keys", "encoding.json"]);
    let cases = vectors["cases"].as_array().expect("cases");
    let (mut ok, mut bad) = (0, 0);
    for case in cases {
        let name = case["name"].as_str().expect("a name");
        let n = usize::try_from(case["bytes"].as_u64().expect("bytes")).expect("fits");
        let text = case["b64url"].as_str().expect("b64url");
        let got = b64url_decode(text, n);
        match case["expect"].as_str() {
            Some("ok") => {
                let hex: String = got
                    .unwrap_or_else(|| panic!("{name}: refused"))
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect();
                assert_eq!(hex, case["hex"].as_str().expect("hex"), "{name}");
                ok += 1;
            }
            Some(_) => {
                assert!(got.is_none(), "{name}: accepted");
                bad += 1;
            }
            None => panic!("{name}: no expect"),
        }
    }
    assert!(ok >= 4 && bad >= 4, "{ok} good, {bad} bad");
}

/// Every device-key fixture the agent receives is within the agent's limits and of the form its
/// checks take, and what it sends passes the checks it runs before sending: a fixture the agent
/// would refuse is a contract the two sides read differently.
#[test]
fn every_device_key_fixture_passes_the_agents_checks() {
    let (mut proofs, mut keys, mut nonces, mut pools, mut takes_token) = (0, 0, 0, 0, 0);
    for file in group("server-to-agent") {
        let msg: ServerToAgent =
            serde_json::from_value(fixture(&file)).unwrap_or_else(|e| panic!("{file}: {e}"));
        match msg {
            ServerToAgent::Sdp {
                proof: Some(proof), ..
            } => {
                assert_eq!(check_proof_wire(&proof), Ok(()), "{file}");
                for field in ["key_id", "nonce_pc", "sig"] {
                    assert!(proof.get(field).is_some(), "{file}: {field}");
                }
                // An admit of a kind this build does not know rides along, to be skipped.
                let kinds: Vec<&str> = proof["admit"]
                    .as_array()
                    .expect("admit")
                    .iter()
                    .filter_map(|a| a["kind"].as_str())
                    .collect();
                assert!(
                    kinds.iter().any(|k| KeyAdmit::from_admit_kind(k).is_none()),
                    "{file}: {kinds:?}"
                );
                proofs += 1;
            }
            ServerToAgent::PairRequest {
                viewer_key: Some(key),
                ..
            } => {
                assert_eq!(check_viewer_key_wire(&key), Ok(()), "{file}");
                let desc = |f: &str| key[f].as_str().is_some_and(is_device_desc);
                assert!(desc("kind") && desc("platform"), "{file}");
                for f in ["spki", "rpk"] {
                    assert!(
                        key[f].as_str().is_some_and(|s| is_b64url(s, bytes::SPKI)),
                        "{file}: {f}"
                    );
                }
                keys += 1;
            }
            ServerToAgent::SessionRequest {
                nonce_pc: Some(n), ..
            } => {
                assert!(is_b64url(&n, bytes::NONCE), "{file}");
                nonces += 1;
            }
            ServerToAgent::AgentReady {
                nonce_pool,
                grant_token,
                ..
            } => {
                if let Some(pool) = nonce_pool {
                    assert!(pool, "{file}: the contract's literal true");
                    pools += 1;
                }
                if let Some(takes) = grant_token {
                    assert!(takes, "{file}: the contract's literal true");
                    takes_token += 1;
                }
            }
            _ => {}
        }
    }
    assert!(
        proofs >= 1 && keys >= 1 && nonces >= 1 && pools >= 1 && takes_token >= 1,
        "{proofs} proofs, {keys} keys, {nonces} nonces, {pools} pools, {takes_token} grant_token"
    );

    let (mut batches, mut key_ids, mut summaries, mut ends) = (0, 0, 0, 0);
    let (mut tokens, mut empty_tokens) = (0, 0);
    for file in group("agent-to-server") {
        let msg: AgentToServer =
            serde_json::from_value(fixture(&file)).unwrap_or_else(|e| panic!("{file}: {e}"));
        match msg {
            AgentToServer::SessionNonces { nonces, .. } => {
                assert!(is_nonce_batch(&nonces), "{file}");
                batches += 1;
            }
            AgentToServer::GrantToken { token } => {
                assert!(vk::is_grant_token(&token.0), "{file}");
                if token.0.is_empty() {
                    empty_tokens += 1;
                } else {
                    tokens += 1;
                }
            }
            AgentToServer::PairResponse {
                key_id: Some(k), ..
            } => {
                assert!(is_b64url(&k, bytes::KEY_ID), "{file}");
                key_ids += 1;
            }
            AgentToServer::SessionStats { stats, .. } => {
                if let Some(s) = stats.summary.filter(|s| s.key_verdict.is_some()) {
                    assert_eq!(s.check(), Ok(()), "{file}");
                    assert!(s.key_mode.is_some(), "{file}");
                    summaries += 1;
                }
            }
            AgentToServer::SessionEnd {
                reason: Some(reason),
                detail,
                ..
            } => {
                if let Some(r) = KeyEndReason::ALL.iter().find(|r| r.as_str() == reason) {
                    let d = detail
                        .and_then(|d| d.base.ended_detail)
                        .expect("ended_detail");
                    assert!(r.details().contains(&d.as_str()), "{file}: {d}");
                    ends += 1;
                }
            }
            _ => {}
        }
    }
    assert!(
        batches >= 1 && key_ids >= 1 && summaries >= 1 && ends >= 1,
        "{batches} batches, {key_ids} key ids, {summaries} summaries, {ends} ends"
    );
    assert!(
        tokens >= 1 && empty_tokens >= 1,
        "{tokens} grant tokens, {empty_tokens} empty ones"
    );
    // The token's form is exact: one character more or less, padding, or the standard alphabet is
    // not one.
    for bad in [
        "AQEBAQEBAQEBAQEBAQEBA",
        "AQEBAQEBAQEBAQEBAQEBAQA",
        "AQEBAQEBAQEBAQEBAQEBAQ==",
        "AQEBAQEBAQEBAQEBAQEB+Q",
        "AQEBAQEBAQEBAQEBAQEBAR",
    ] {
        assert!(!vk::is_grant_token(bad), "{bad}");
    }

    let (mut with_admit, mut with_detail) = (false, false);
    for file in group("agent-to-viewer") {
        let msg: AgentDataMessage =
            serde_json::from_value(fixture(&file)).unwrap_or_else(|e| panic!("{file}: {e}"));
        if let AgentDataMessage::KeyStatus(ks) = msg {
            assert_eq!(ks.check(), Ok(()), "{file}");
            if let (Some(reason), Some(d)) = (ks.verdict.reason(), ks.detail.as_deref()) {
                assert!(reason.details().contains(&d), "{file}: {d}");
            }
            with_admit |= ks.admit.is_some();
            with_detail |= ks.detail.is_some();
        }
    }
    assert!(
        with_admit && with_detail,
        "need a ks with an admit and one with a detail"
    );
}

/* --- «Пати» (docs/design/party-protocol.md) ------------------------------------------------------ */

/// One message of an emitted schema (`oneOf`), by its `type`.
fn message_schema(file: &str, kind: &str) -> Value {
    let schema = json(&["schema", file]);
    schema["oneOf"]
        .as_array()
        .expect("the schema is a oneOf")
        .iter()
        .find(|v| v["properties"]["type"]["const"] == kind)
        .unwrap_or_else(|| panic!("{file} has no {kind}"))
        .clone()
}

fn required(message: &Value) -> BTreeSet<String> {
    serde_json::from_value(message["required"].clone()).expect("required is a list")
}

/// The party limits and closed lists the agent holds to are the contract's (`party.ts`), and so are
/// the shapes of the four party messages as the contract emits their schema.
#[test]
fn the_party_constants_and_lists_are_the_contracts() {
    let src = read(&["src", "party.ts"]);
    let usize_of = |name| usize::try_from(ts_number(&src, name)).expect("fits");
    for (name, ours) in [
        ("PARTY_ID_BYTES", party::PARTY_ID_BYTES),
        ("PARTY_NAME_MAX", party::PARTY_NAME_MAX),
        ("PARTY_LEADER_NAME_MAX", party::PARTY_LEADER_NAME_MAX),
        (
            "PARTY_LEADER_USERNAME_MAX",
            party::PARTY_LEADER_USERNAME_MAX,
        ),
        ("PARTY_DELEGATIONS_MAX", party::PARTY_DELEGATIONS_MAX),
    ] {
        assert_eq!(usize_of(name), ours, "{name}");
    }
    assert_eq!(
        ts_number(&src, "PARTY_STATEMENT_VERSION"),
        u64::from(party::PARTY_STATEMENT_VERSION)
    );
    // The statement's bound is the keys' grant bound, by name.
    assert!(src.contains("export const PARTY_STATEMENT_MAX_BYTES = GRANT_MAX_BYTES;"));
    assert_eq!(
        ts_number(&read(&["src", "viewer-keys.ts"]), "GRANT_MAX_BYTES"),
        u64::try_from(party::PARTY_STATEMENT_MAX_BYTES).expect("fits")
    );
    let ops = strings(&PartyAckOp::ALL, PartyAckOp::as_str);
    let results = strings(&PartyAckResult::ALL, PartyAckResult::as_str);
    assert_eq!(ts_list(&src, "PARTY_ACK_OPS"), ops);
    assert_eq!(ts_list(&src, "PARTY_ACK_RESULTS"), results);

    let ack = message_schema("agent-to-server.json", "party_ack");
    let enum_of = |name: &str| -> Vec<String> {
        serde_json::from_value(ack["properties"][name]["enum"].clone()).expect("an enum")
    };
    assert_eq!(enum_of("op"), ops);
    assert_eq!(enum_of("result"), results);
    assert_eq!(
        required(&ack),
        ["type", "party_id", "op", "result"]
            .map(String::from)
            .into()
    );
    let id_pattern = "^[A-Za-z0-9_-]{21}[AQgw]$";
    assert_eq!(ack["properties"]["party_id"]["pattern"], id_pattern);
    let state = message_schema("agent-to-server.json", "party_state");
    let parties = &state["properties"]["parties"];
    assert_eq!(
        parties["maxItems"].as_u64(),
        Some(u64::try_from(party::PARTY_DELEGATIONS_MAX).expect("fits"))
    );
    assert_eq!(
        required(&state),
        ["type", "parties"].map(String::from).into()
    );
    assert_eq!(
        required(&parties["items"]),
        ["party_id", "leader"].map(String::from).into()
    );
    assert_eq!(
        parties["items"]["properties"]["party_id"]["pattern"],
        id_pattern
    );

    let ready = message_schema("server-to-agent.json", "agent_ready");
    assert_eq!(ready["properties"]["party"]["const"], true);
    assert!(!required(&ready).contains("party"), "party is optional");
    let join = message_schema("server-to-agent.json", "party_join");
    assert_eq!(required(&join), ["type", "join"].map(String::from).into());
    assert_eq!(join["properties"]["join"]["type"], "object");
    let leave = message_schema("server-to-agent.json", "party_leave");
    assert_eq!(
        required(&leave),
        ["type", "party_id"].map(String::from).into()
    );
    assert_eq!(leave["properties"]["party_id"]["pattern"], id_pattern);

    // The id's pattern: 21 free characters and a last one with its unused bits zero. The agent's
    // strict decoder agrees on every possible last character.
    let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    for last in alphabet.chars() {
        let id = format!("{}{last}", "x".repeat(21));
        assert_eq!(party::is_party_id(&id), "AQgw".contains(last), "{id}");
    }
}

/// Every party fixture the agent receives is of the form its checks take and within its limits, and
/// what it sends passes the checks it runs before sending. The member's offer is the viewer's fixture
/// (`sdp_proof_party`): the server relays its `proof` unchanged, so it is what reaches the agent.
#[test]
fn every_party_fixture_passes_the_agents_checks() {
    let (mut joins, mut leaves, mut ready) = (0, 0, 0);
    for file in group("server-to-agent") {
        let msg: ServerToAgent =
            serde_json::from_value(fixture(&file)).unwrap_or_else(|e| panic!("{file}: {e}"));
        match msg {
            ServerToAgent::PartyJoin { join } => {
                assert_eq!(party::check_party_statement_wire(&join), Ok(()), "{file}");
                let text = |f: &str| join[f].as_str().unwrap_or_else(|| panic!("{file}: {f}"));
                assert_eq!(
                    join["v"].as_u64(),
                    Some(u64::from(party::PARTY_STATEMENT_VERSION))
                );
                assert!(party::is_party_id(text("party_id")), "{file}");
                assert!(party::is_party_name(text("party")), "{file}");
                assert!(vk::is_grant_token(text("grant_token")), "{file}");
                assert!(is_b64url(text("by"), bytes::KEY_ID), "{file}");
                assert!(is_b64url(text("sig"), bytes::SIGNATURE), "{file}");
                let leader = &join["leader"];
                assert!(
                    leader["spki"]
                        .as_str()
                        .is_some_and(|s| is_b64url(s, bytes::SPKI)),
                    "{file}"
                );
                assert!(leader["telegram_user_id"].as_u64().is_some_and(|n| n >= 1));
                for (f, max) in [
                    ("name", party::PARTY_LEADER_NAME_MAX),
                    ("username", party::PARTY_LEADER_USERNAME_MAX),
                ] {
                    assert!(
                        leader[f].is_null()
                            || leader[f].as_str().is_some_and(|s| s.chars().count() <= max),
                        "{file}: leader.{f}"
                    );
                }
                joins += 1;
            }
            ServerToAgent::PartyLeave { party_id } => {
                assert!(party::is_party_id(&party_id), "{file}");
                leaves += 1;
            }
            ServerToAgent::AgentReady {
                party: Some(takes), ..
            } => {
                assert!(takes, "{file}: the contract's literal true");
                ready += 1;
            }
            _ => {}
        }
    }
    assert!(
        joins >= 1 && leaves >= 1 && ready >= 1,
        "{joins} joins, {leaves} leaves, {ready} agent_ready with party"
    );

    let (mut acks, mut states) = (0, 0);
    for file in group("agent-to-server") {
        let msg: AgentToServer =
            serde_json::from_value(fixture(&file)).unwrap_or_else(|e| panic!("{file}: {e}"));
        match msg {
            AgentToServer::PartyAck { party_id, .. } => {
                assert!(party::is_party_id(&party_id), "{file}");
                acks += 1;
            }
            AgentToServer::PartyState { parties } => {
                assert_eq!(party::check_party_state(&parties), Ok(()), "{file}");
                states += 1;
            }
            _ => {}
        }
    }
    assert!(acks >= 2 && states >= 2, "{acks} acks, {states} states");

    // The tree may hold only this group's offer fixtures, so only those are read.
    let offers: Vec<String> = group("viewer-to-server")
        .into_iter()
        .filter(|f| f.rsplit('/').next().is_some_and(|n| n.starts_with("sdp")))
        .collect();
    assert!(!offers.is_empty(), "the manifest lists no offer fixtures");
    let mut grants = 0;
    for file in offers {
        let raw = fixture(&file);
        if raw["type"] != "sdp" {
            continue;
        }
        let Some(proof) = raw.get("proof") else {
            continue;
        };
        assert_eq!(check_proof_wire(proof), Ok(()), "{file}");
        for admit in proof["admit"].as_array().map_or(&[][..], Vec::as_slice) {
            if KeyAdmit::from_admit_kind(admit["kind"].as_str().unwrap_or(""))
                != Some(KeyAdmit::Party)
            {
                continue;
            }
            assert!(
                admit.get("invite").is_none(),
                "{file}: a party grant has no invite"
            );
            let grant = &admit["grant"];
            assert_eq!(party::check_party_statement_wire(grant), Ok(()), "{file}");
            let text = |f: &str| grant[f].as_str().unwrap_or_else(|| panic!("{file}: {f}"));
            assert_eq!(
                grant["v"].as_u64(),
                Some(u64::from(vk::VIEWER_KEYS_VERSION))
            );
            assert_eq!(text("role"), "guest", "{file}");
            assert_eq!(
                text("key_id"),
                proof["key_id"],
                "{file}: the grant is for this key"
            );
            assert!(party::is_party_id(text("party_id")), "{file}");
            assert!(is_b64url(text("grant_id"), bytes::ID), "{file}");
            assert!(vk::is_grant_token(text("grant_token")), "{file}");
            assert!(is_b64url(text("by"), bytes::KEY_ID), "{file}");
            assert!(is_b64url(text("sig"), bytes::SIGNATURE), "{file}");
            for f in ["name", "username"] {
                assert!(grant[f].is_null() || grant[f].is_string(), "{file}: {f}");
            }
            grants += 1;
        }
    }
    assert!(grants >= 1, "need a member's offer with a party grant");
}
