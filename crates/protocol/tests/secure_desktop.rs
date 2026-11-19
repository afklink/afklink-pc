//! The PC's input on another Windows desktop against the contract: the kinds and limits of
//! `secure-desktop.ts`, the heartbeat's `secure_desktop`, `secure_desktop_ongoing`,
//! `agent_ready.secure_desktop` and the `agent_event` `secure_desktop_ended` against the emitted
//! JSON Schemas, and every golden fixture of them against the agent's own types and checks.
//!
//! The round trip of the fixtures is `tests/fixtures.rs`; this file checks what a round trip cannot
//! see — that the words and numbers the agent sends and enforces are the contract's.

// A failing contract test *should* abort, and the panic message is the diagnostic. See the same
// allowance in `tests/fixtures.rs`.
#![allow(clippy::panic)]

use std::fs;
use std::path::{Path, PathBuf};

use afklink_protocol::metrics::AgentEventKind;
use afklink_protocol::{
    AgentDataMessage, AgentToServer, SecureDesktopKind, ServerToAgent,
    SECURE_DESKTOP_DURATION_MAX_MS, SECURE_DESKTOP_ONGOING_AFTER_MS,
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
    let mut path = protocol_root();
    for part in rel {
        path = path.join(part);
    }
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("reading {path:?}: {e}"))
}

fn json(rel: &[&str]) -> Value {
    serde_json::from_str(&read(rel)).unwrap_or_else(|e| panic!("{rel:?} is not JSON: {e}"))
}

/// The words of `export const <name> = [ ... ] as const;` in a contract source file.
fn ts_list(source: &str, name: &str) -> Vec<String> {
    let start = source
        .find(&format!("export const {name} = ["))
        .unwrap_or_else(|| panic!("no `export const {name} = [` in the contract source"));
    let rest = &source[start..];
    let open = rest.find('[').expect("an opening bracket");
    let close = rest.find(']').expect("a closing bracket");
    rest[open + 1..close]
        .split(',')
        .map(str::trim)
        .filter(|w| !w.is_empty())
        .map(|w| w.trim_matches('"').trim_matches('\'').to_string())
        .collect()
}

/// The number after `<key>:` in a contract source file, `_` separators and simple products
/// (`5 * 60_000`) read as TypeScript does.
fn ts_number(source: &str, key: &str) -> u64 {
    let start = source
        .find(&format!("{key}:"))
        .unwrap_or_else(|| panic!("no `{key}:` in the contract source"));
    let rest = &source[start + key.len() + 1..];
    let end = rest.find(',').expect("a comma after the number");
    rest[..end]
        .split('*')
        .map(|n| {
            n.trim()
                .replace('_', "")
                .parse::<u64>()
                .unwrap_or_else(|e| panic!("{key}: {n:?} is not a number: {e}"))
        })
        .product()
}

fn kinds() -> Vec<String> {
    SecureDesktopKind::ALL
        .iter()
        .map(|k| k.as_str().to_string())
        .collect()
}

fn schema_enum(v: &Value) -> Vec<String> {
    v["enum"]
        .as_array()
        .unwrap_or_else(|| panic!("not an enum: {v}"))
        .iter()
        .map(|w| w.as_str().expect("a word").to_string())
        .collect()
}

/// Every object in a schema (depth first) whose `properties` hold `field`.
fn with_property<'a>(v: &'a Value, field: &str, out: &mut Vec<&'a Value>) {
    match v {
        Value::Object(o) => {
            if v["properties"].get(field).is_some() {
                out.push(v);
            }
            for x in o.values() {
                with_property(x, field, out);
            }
        }
        Value::Array(a) => {
            for x in a {
                with_property(x, field, out);
            }
        }
        _ => {}
    }
}

#[test]
fn the_kinds_and_the_limits_are_the_contracts() {
    let source = read(&["src", "secure-desktop.ts"]);
    assert_eq!(ts_list(&source, "SECURE_DESKTOP_KINDS"), kinds());
    assert_eq!(
        ts_number(&source, "ongoingAfterMs"),
        SECURE_DESKTOP_ONGOING_AFTER_MS
    );
    assert_eq!(
        ts_number(&source, "durationMaxMs"),
        SECURE_DESKTOP_DURATION_MAX_MS
    );
}

/// The heartbeat's field, the cue's and the event's: the same three words, the event's duration
/// bounded as the agent bounds it, the cue's and the event's `at` the epoch bound, and the event's
/// `session_id` and `game_only` optional.
#[test]
fn the_messages_are_the_schemas() {
    let viewer = json(&["schema", "agent-to-viewer.json"]);
    let mut found = Vec::new();
    with_property(&viewer, "secure_desktop", &mut found);
    assert!(
        !found.is_empty(),
        "the heartbeat's schema has secure_desktop"
    );
    for hb in &found {
        assert_eq!(schema_enum(&hb["properties"]["secure_desktop"]), kinds());
        let required = hb["required"].to_string();
        assert!(!required.contains("secure_desktop"), "{required}");
    }

    let server = json(&["schema", "agent-to-server.json"]);
    let mut cues = Vec::new();
    with_property(&server, "desktop", &mut cues);
    let cue = cues
        .iter()
        .find(|v| v["properties"]["type"]["const"] == "secure_desktop_ongoing")
        .expect("the schema has secure_desktop_ongoing");
    let p = &cue["properties"];
    assert_eq!(schema_enum(&p["desktop"]), kinds());
    assert_eq!(p["at"]["maximum"], afklink_protocol::metrics::EPOCH_MS_MAX);
    let required = cue["required"].to_string();
    for field in ["session_id", "desktop", "at"] {
        assert!(required.contains(field), "{field}: {required}");
    }
    let ended = cues
        .iter()
        .find(|v| {
            v["properties"]["type"]["const"] == "agent_event"
                && v["properties"]["kind"]["const"] == "secure_desktop_ended"
        })
        .expect("the schema has agent_event secure_desktop_ended");
    let p = &ended["properties"];
    assert_eq!(schema_enum(&p["desktop"]), kinds());
    assert_eq!(p["duration_ms"]["maximum"], SECURE_DESKTOP_DURATION_MAX_MS);
    assert_eq!(p["duration_ms"]["minimum"], 0);
    assert_eq!(p["game_only"]["type"], "boolean");
    assert_eq!(p["session_id"]["format"], "uuid");
    let required = ended["required"].to_string();
    assert!(!required.contains("session_id"), "{required}");
    assert!(!required.contains("game_only"), "{required}");

    let to_agent = json(&["schema", "server-to-agent.json"]);
    let mut readies = Vec::new();
    with_property(&to_agent, "secure_desktop", &mut readies);
    let ready = readies
        .iter()
        .find(|v| v["properties"]["type"]["const"] == "agent_ready")
        .expect("agent_ready has secure_desktop");
    assert_eq!(ready["properties"]["secure_desktop"]["const"], true);
    assert!(!ready["required"].to_string().contains("secure_desktop"));
}

/// Every golden fixture of these: what the server and the viewer take, the agent's types read and
/// its checks pass.
#[test]
fn every_secure_desktop_fixture_is_the_agents() {
    let hb = json(&[
        "fixtures",
        "agent-to-viewer",
        "heartbeat_secure_desktop_uac.json",
    ]);
    let AgentDataMessage::Heartbeat(hb) = serde_json::from_value(hb).expect("a heartbeat") else {
        panic!("not a heartbeat");
    };
    assert_eq!(hb.secure_desktop, Some(SecureDesktopKind::Uac));
    assert!(
        hb.still && hb.state == afklink_protocol::PipelineState::Ok,
        "a secure desktop is a still, healthy pipeline: {hb:?}"
    );

    let cue = json(&["fixtures", "agent-to-server", "secure_desktop_ongoing.json"]);
    let AgentToServer::SecureDesktopOngoing {
        session_id,
        desktop,
        at,
    } = serde_json::from_value(cue).expect("the cue")
    else {
        panic!("not secure_desktop_ongoing");
    };
    assert!(afklink_protocol::diagnostics::is_uuid(&session_id));
    assert_eq!(desktop, SecureDesktopKind::Uac);
    assert!(at <= afklink_protocol::metrics::EPOCH_MS_MAX);

    let ended = json(&[
        "fixtures",
        "agent-to-server",
        "agent_event_secure_desktop.json",
    ]);
    let AgentToServer::AgentEvent(event) = serde_json::from_value(ended).expect("the event") else {
        panic!("not an agent_event");
    };
    assert_eq!(event.check(), Ok(()));
    let AgentEventKind::SecureDesktopEnded {
        desktop,
        duration_ms,
        session_id,
        game_only,
    } = event.event
    else {
        panic!("not secure_desktop_ended");
    };
    assert_eq!(desktop, SecureDesktopKind::Uac);
    assert!(duration_ms <= SECURE_DESKTOP_DURATION_MAX_MS);
    assert!(session_id.is_some() && game_only == Some(true));

    let ready = json(&[
        "fixtures",
        "server-to-agent",
        "agent_ready_secure_desktop.json",
    ]);
    assert!(matches!(
        serde_json::from_value(ready).expect("agent_ready"),
        ServerToAgent::AgentReady {
            secure_desktop: Some(true),
            ..
        }
    ));
}
