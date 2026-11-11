//! Contract v2 of the telemetry against the contract: the checks `afklink_protocol::metrics` makes
//! before a field goes out, against the JSON Schema the contract emits (`schema/agent-to-server.json`),
//! and the vocabularies the agent sends, against `metrics.ts` and `relay.ts` themselves.
//!
//! The checks are hand-written mirrors of zod's patterns (the crate has no regex engine), so this
//! test pins the pattern each was written against: a pattern changed in the contract fails here until
//! the mirror is looked at again. A value the server refuses costs a whole frame — for `agent_hello`
//! every handshake — which is why the agent checks before it sends.

// A failing contract test *should* abort, and the panic message is the diagnostic. See the same
// allowance in `tests/fixtures.rs`.
#![allow(clippy::panic)]

use std::fs;
use std::path::{Path, PathBuf};

use afklink_protocol::metrics::{
    ended_detail, is_end_detail_code, AgentEvent, AgentEventKind, AgentExitKind, CaptureMode,
    DriverInstallOutcome, DriverState, InputPath, PcSettingKey, PeerStage, PreviousRecord,
    QualityProfileSource, SessionEpisodeKind, UpdateOutcome, CANDIDATE_KINDS, COUNT_MAX,
    DRIVER_CODE_MAX, DRIVER_CODE_MIN, DTLS_VERDICTS, ENCODE_MS_P95_MAX, END_DETAIL_CODE_MAX,
    EPOCH_MS_MAX, QUALITY_PROFILE_LABEL_MAX, RELAY_TRANSPORTS, SESSION_MS_MAX, SESSION_SECONDS_MAX,
    SHORT_ID_MAX, SUMMARY_EPISODES_MAX, UPTIME_SECONDS_MAX,
};
use afklink_protocol::AgentToServer;
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

fn message_schema(kind: &str) -> Value {
    let schema: Value = serde_json::from_str(&read(&["schema", "agent-to-server.json"]))
        .expect("agent-to-server.json is not JSON");
    schema["oneOf"]
        .as_array()
        .expect("the schema is a oneOf")
        .iter()
        .find(|v| v["properties"]["type"]["const"] == kind)
        .unwrap_or_else(|| panic!("the schema has no {kind}"))
        .clone()
}

/// The words of `export const <name> = [ ... ] as const;` in a contract source file: the strings
/// between the brackets, in order.
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

/// `agent_hello`'s three fields: the patterns the build's checks mirror, the exit kinds, and the
/// bound on `at`. All three optional (absent from an older agent).
#[test]
fn the_hello_fields_are_the_contracts() {
    let hello = message_schema("agent_hello");
    let props = &hello["properties"];
    let required: Vec<&str> = hello["required"]
        .as_array()
        .expect("required")
        .iter()
        .filter_map(Value::as_str)
        .collect();
    for field in ["build", "boot_id", "last_exit"] {
        assert!(props.get(field).is_some(), "agent_hello has no {field}");
        assert!(!required.contains(&field), "{field} is optional");
    }
    let build = &props["build"]["properties"];
    // `afklink_protocol::start_failure::is_version` and `is_commit`.
    assert_eq!(
        build["version"]["pattern"],
        r"^\d{1,5}\.\d{1,5}\.\d{1,5}(-[0-9A-Za-z.-]{1,24})?$"
    );
    assert_eq!(build["version"]["maxLength"], 32);
    assert_eq!(build["commit"]["anyOf"][0]["pattern"], "^[0-9a-f]{7,40}$");
    let channels: Vec<&str> = build["channel"]["enum"]
        .as_array()
        .expect("channel enum")
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert_eq!(channels, ["dev", "release"]);
    // `afklink_protocol::diagnostics::is_uuid`.
    assert_eq!(
        props["boot_id"]["pattern"],
        "^([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-8][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}|00000000-0000-0000-0000-000000000000|ffffffff-ffff-ffff-ffff-ffffffffffff)$"
    );
    let exit = &props["last_exit"]["properties"];
    let kinds: Vec<&str> = exit["kind"]["enum"]
        .as_array()
        .expect("kind enum")
        .iter()
        .filter_map(Value::as_str)
        .collect();
    let ours: Vec<&str> = AgentExitKind::ALL.iter().map(|k| k.as_str()).collect();
    assert_eq!(kinds, ours, "AGENT_EXIT_KINDS and AgentExitKind::ALL");
    assert_eq!(exit["at"]["maximum"], EPOCH_MS_MAX);
    assert_eq!(exit["at"]["minimum"], 0);
}

/// `agent_hello.hw` (the invite-only beta): optional; `hash`, `vm` and `parts` all required inside
/// it; the hash's pattern the one `afklink_protocol::hw::is_hw_hash` mirrors; `parts` 1 to
/// `AGENT_HW_PARTS` (an agent that read nothing sends no `hw`).
#[test]
fn the_hello_fingerprint_is_the_contracts() {
    use afklink_protocol::hw::{is_hw_hash, AGENT_HW_HASH_LEN};
    use afklink_protocol::AGENT_HW_PARTS;

    let hello = message_schema("agent_hello");
    let required: Vec<&str> = hello["required"]
        .as_array()
        .expect("required")
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert!(!required.contains(&"hw"), "hw is optional");
    let hw = &hello["properties"]["hw"];
    assert_eq!(hw["type"], "object");
    let mut inner: Vec<&str> = hw["required"]
        .as_array()
        .expect("hw.required")
        .iter()
        .filter_map(Value::as_str)
        .collect();
    inner.sort_unstable();
    assert_eq!(inner, ["hash", "parts", "vm"]);
    let mut fields: Vec<&str> = hw["properties"]
        .as_object()
        .expect("hw.properties")
        .keys()
        .map(String::as_str)
        .collect();
    fields.sort_unstable();
    assert_eq!(fields, ["hash", "parts", "vm"], "nothing more in hw");
    let props = &hw["properties"];
    assert_eq!(
        props["hash"]["pattern"],
        format!("^[A-Za-z0-9_-]{{{AGENT_HW_HASH_LEN}}}$")
    );
    assert_eq!(props["vm"]["type"], "boolean");
    assert_eq!(props["parts"]["type"], "integer");
    assert_eq!(props["parts"]["minimum"], 1);
    assert_eq!(props["parts"]["maximum"], AGENT_HW_PARTS);
    // The mirror against the golden sample's hash.
    let sample: Value = serde_json::from_str(&read(&[
        "fixtures",
        "agent-to-server",
        "agent_hello_hw.json",
    ]))
    .expect("the golden hello with hw");
    assert!(is_hw_hash(
        sample["hw"]["hash"].as_str().expect("a hash string")
    ));
}

/// `session_end.detail`: every code to one pattern (`is_end_detail_code`), the duration to its
/// bound; `final` a plain flag on `session_stats`.
#[test]
fn the_end_detail_and_the_final_flag_are_the_contracts() {
    let end = message_schema("session_end");
    let detail = &end["properties"]["detail"]["properties"];
    for code in [
        "ended_detail",
        "stage",
        "verdict",
        "pair_local_kind",
        "pair_remote_kind",
        "relay_transport",
    ] {
        assert_eq!(
            detail[code]["pattern"],
            format!("^[a-z0-9_:]{{1,{END_DETAIL_CODE_MAX}}}$"),
            "{code}"
        );
    }
    assert_eq!(detail["dtls_after_ice_ms"]["maximum"], SESSION_MS_MAX);
    let fields = detail.as_object().expect("detail's properties").len();
    assert_eq!(
        fields, 7,
        "the detail grew a field: mirror it in SessionEndDetail"
    );

    let stats = message_schema("session_stats");
    assert_eq!(stats["properties"]["final"]["type"], "boolean");
}

/// The words the agent puts in `session_end.detail` are the contract's lists, word for word — the
/// server drops a word it does not know — and each fits the wire's pattern.
#[test]
fn the_detail_vocabularies_are_the_contracts() {
    let metrics = read(&["src", "metrics.ts"]);
    assert_eq!(ts_list(&metrics, "DTLS_VERDICTS"), DTLS_VERDICTS);
    assert_eq!(ts_list(&metrics, "CANDIDATE_KINDS"), CANDIDATE_KINDS);
    let stages: Vec<&str> = PeerStage::ALL.iter().map(|s| s.as_str()).collect();
    assert_eq!(ts_list(&metrics, "PEER_STAGES"), stages);
    // `SESSION_END_DETAILS.peer_closed`, the one split the agent sends.
    let peer_closed = metrics
        .find("peer_closed: [")
        .map(|at| &metrics[at..])
        .and_then(|rest| rest.find(']').map(|end| &rest["peer_closed: [".len()..end]))
        .expect("SESSION_END_DETAILS.peer_closed");
    let words: Vec<&str> = peer_closed
        .split(',')
        .map(|w| w.trim().trim_matches('"'))
        .filter(|w| !w.is_empty())
        .collect();
    assert_eq!(words, ended_detail::PEER_CLOSED);
    let relay = read(&["src", "relay.ts"]);
    assert_eq!(ts_list(&relay, "RELAY_TRANSPORTS"), RELAY_TRANSPORTS);
    for word in DTLS_VERDICTS
        .iter()
        .chain(&CANDIDATE_KINDS)
        .chain(&RELAY_TRANSPORTS)
        .chain(&stages)
        .chain(&ended_detail::PEER_CLOSED)
    {
        assert!(is_end_detail_code(word), "{word}");
    }
}

/// The words of an `enum` in the schema.
fn schema_enum(v: &Value) -> Vec<String> {
    v["enum"]
        .as_array()
        .unwrap_or_else(|| panic!("not an enum: {v}"))
        .iter()
        .map(|w| w.as_str().expect("a word").to_string())
        .collect()
}

/// The schema of `agent_event` of `kind`: one branch of its discriminated union, which the schema
/// nests as a `oneOf` (or `anyOf`) of its own among the messages.
fn event_schema(kind: &str) -> Value {
    let schema: Value = serde_json::from_str(&read(&["schema", "agent-to-server.json"]))
        .expect("agent-to-server.json is not JSON");
    let top = schema["oneOf"].as_array().expect("the schema is a oneOf");
    top.iter()
        .flat_map(|v| {
            let nested = v["oneOf"]
                .as_array()
                .or_else(|| v["anyOf"].as_array())
                .cloned()
                .unwrap_or_default();
            std::iter::once(v.clone()).chain(nested)
        })
        .find(|v| {
            v["properties"]["type"]["const"] == "agent_event"
                && v["properties"]["kind"]["const"] == kind
        })
        .unwrap_or_else(|| panic!("the schema has no agent_event {kind}"))
}

/// The summary's bounds and vocabularies — what `AgentSessionSummary::check` and the agent's
/// summary are built on — are the schema's, number for number.
#[test]
fn the_summary_bounds_are_the_contracts() {
    let stats = message_schema("session_stats");
    let summary = &stats["properties"]["stats"]["properties"]["summary"]["properties"];
    let rungs = &summary["rung_s"];
    assert_eq!(rungs["propertyNames"]["pattern"], r"^\d{2,5}$");
    assert_eq!(
        rungs["additionalProperties"]["maximum"].as_f64(),
        Some(SESSION_SECONDS_MAX)
    );
    assert_eq!(
        summary["freeze_s"]["maximum"].as_f64(),
        Some(SESSION_SECONDS_MAX)
    );
    let episodes = &summary["episodes"];
    assert_eq!(episodes["maxItems"], SUMMARY_EPISODES_MAX);
    let episode = &episodes["items"]["properties"];
    let kinds: Vec<String> = SessionEpisodeKind::ALL
        .iter()
        .map(|k| k.as_str().to_string())
        .collect();
    assert_eq!(schema_enum(&episode["kind"]), kinds);
    assert_eq!(episode["at_ms"]["maximum"], SESSION_MS_MAX);
    assert_eq!(episode["dur_ms"]["maximum"], SESSION_MS_MAX);
    assert_eq!(
        episode["code"]["pattern"],
        format!("^[a-z0-9_]{{1,{SHORT_ID_MAX}}}$")
    );
    assert_eq!(
        summary["encode_ms_p95"]["anyOf"][0]["maximum"].as_f64(),
        Some(ENCODE_MS_P95_MAX)
    );
    for count in [
        "episodes_dropped",
        "input_blocked_n",
        "dropped_rate",
        "bytes_socket",
        "bytes_relay",
    ] {
        assert_eq!(summary[count]["maximum"], COUNT_MAX, "{count}");
    }
    let paths: Vec<String> = InputPath::ALL.iter().map(|p| p.as_str().into()).collect();
    assert_eq!(schema_enum(&summary["input_path"]), paths);
    let modes: Vec<String> = CaptureMode::ALL.iter().map(|m| m.as_str().into()).collect();
    assert_eq!(schema_enum(&summary["capture_mode"]), modes);
    let drivers: Vec<String> = DriverState::ALL.iter().map(|d| d.as_str().into()).collect();
    assert_eq!(schema_enum(&summary["driver"]), drivers);
    let sources: Vec<String> = QualityProfileSource::ALL
        .iter()
        .map(|s| s.as_str().into())
        .collect();
    assert_eq!(schema_enum(&summary["quality_profile_source"]), sources);
    assert_eq!(
        summary["quality_profile"]["maxLength"],
        QUALITY_PROFILE_LABEL_MAX
    );
    assert_eq!(
        ts_list(
            &read(&["src", "metrics-wire.ts"]),
            "QUALITY_PROFILE_SOURCES"
        ),
        sources
    );
    let fields = summary.as_object().expect("the summary's properties").len();
    assert_eq!(
        fields, 15,
        "the summary grew a field: mirror it in AgentSessionSummary"
    );

    // The vocabularies against metrics.ts itself, and the limits the agent keeps.
    let metrics = read(&["src", "metrics.ts"]);
    assert_eq!(ts_list(&metrics, "SESSION_EPISODE_KINDS"), kinds);
    assert_eq!(ts_list(&metrics, "INPUT_PATHS"), paths);
    assert_eq!(ts_list(&metrics, "CAPTURE_MODES"), modes);
    assert_eq!(ts_list(&metrics, "DRIVER_STATES"), drivers);
    for (limit, value) in [
        ("episodes: ", SUMMARY_EPISODES_MAX.to_string()),
        ("rungs: ", "16".to_string()),
        ("uptimeSeconds: ", "31_536_000".to_string()),
    ] {
        assert!(
            metrics.contains(&format!("{limit}{value},")),
            "TELEMETRY_LIMITS.{limit}{value}"
        );
    }
}

/// `agent_event`: every kind's props to the schema's shapes and bounds, and the vocabularies to
/// `metrics.ts` — what `AgentEvent::check` holds an event to before the agent queues it.
#[test]
fn the_agent_event_shapes_are_the_contracts() {
    let metrics = read(&["src", "metrics.ts"]);
    assert_eq!(
        ts_list(&metrics, "AGENT_EVENT_KINDS"),
        AgentEventKind::KINDS
    );
    let keys: Vec<String> = PcSettingKey::ALL
        .iter()
        .map(|k| k.as_str().into())
        .collect();
    assert_eq!(ts_list(&metrics, "PC_SETTING_KEYS"), keys);
    let updates: Vec<String> = UpdateOutcome::ALL
        .iter()
        .map(|o| o.as_str().into())
        .collect();
    assert_eq!(ts_list(&metrics, "UPDATE_OUTCOMES"), updates);
    let installs: Vec<String> = DriverInstallOutcome::ALL
        .iter()
        .map(|o| o.as_str().into())
        .collect();
    assert_eq!(ts_list(&metrics, "DRIVER_INSTALL_OUTCOMES"), installs);

    let short = format!("^[a-z0-9_]{{1,{SHORT_ID_MAX}}}$");
    let crashed = event_schema("agent_crashed");
    let p = &crashed["properties"];
    assert_eq!(p["place_hash"]["pattern"], "^[0-9a-f]{8,64}$");
    assert_eq!(p["thread"]["pattern"], "^[A-Za-z0-9_.:-]{1,32}$");
    assert_eq!(p["uptime_s"]["maximum"], UPTIME_SECONDS_MAX);
    assert_eq!(p["at"]["maximum"], EPOCH_MS_MAX);
    let update = event_schema("update_finished");
    assert_eq!(schema_enum(&update["properties"]["outcome"]), updates);
    assert_eq!(update["properties"]["reason"]["pattern"], short.as_str());
    let driver = event_schema("driver_install_finished");
    let p = &driver["properties"];
    assert_eq!(schema_enum(&p["outcome"]), installs);
    assert_eq!(p["step"]["pattern"], short.as_str());
    assert_eq!(p["code"]["minimum"], DRIVER_CODE_MIN);
    assert_eq!(p["code"]["maximum"], DRIVER_CODE_MAX);
    assert_eq!(p["ms"]["maximum"], SESSION_MS_MAX);
    let setting = event_schema("pc_setting_changed");
    assert_eq!(schema_enum(&setting["properties"]["key"]), keys);
    let value = setting["properties"]["value"].to_string();
    assert!(value.contains("boolean"), "{value}");
    assert!(value.contains(&short.replace('\\', "\\\\")), "{value}");
    let started = event_schema("agent_started");
    for field in [
        "boot_id",
        "first_run",
        "build",
        "last_exit",
        "autostart",
        "previous_record",
        "pc_restarted",
    ] {
        assert!(
            started["properties"].get(field).is_some(),
            "agent_started.{field}"
        );
    }
    let records: Vec<String> = PreviousRecord::ALL
        .iter()
        .map(|r| r.as_str().into())
        .collect();
    assert_eq!(ts_list(&metrics, "PREVIOUS_RECORD_STATES"), records);
    assert_eq!(
        schema_enum(&started["properties"]["previous_record"]),
        records
    );
    assert_eq!(started["properties"]["pc_restarted"]["type"], "boolean");
    // Both optional: a build before them, and a start that cannot tell, leave them out.
    let required = started["required"].to_string();
    assert!(!required.contains("previous_record"), "{required}");
    assert!(!required.contains("pc_restarted"), "{required}");
}

/// `agent_started.previous_record` and `pc_restarted` serialize as the schema has them, are left out
/// (not `null`) when unknown, and a queue entry written before them still reads.
#[test]
fn agent_started_previous_record_and_restart_on_the_wire() {
    let text = read(&["fixtures", "agent-to-server", "agent_event_started.json"]);
    let golden: Value = serde_json::from_str(&text).expect("the fixture");
    let AgentToServer::AgentEvent(fixture) = serde_json::from_str(&text).expect("an agent_event")
    else {
        panic!("agent_event_started.json is not an agent_event");
    };
    let AgentEventKind::AgentStarted {
        previous_record,
        pc_restarted,
        ..
    } = &fixture.event
    else {
        panic!("agent_event_started.json is not agent_started");
    };
    assert_eq!(
        (*previous_record, *pc_restarted),
        (Some(PreviousRecord::Found), Some(false)),
        "the golden fixture carries both"
    );
    assert_eq!(fixture.check(), Ok(()));
    let mut wire = serde_json::to_value(AgentToServer::AgentEvent(fixture.clone())).unwrap();
    assert_eq!(wire, golden, "the golden fixture round-trips");

    let with = |previous_record, pc_restarted| {
        let mut e = fixture.clone();
        if let AgentEventKind::AgentStarted {
            previous_record: p,
            pc_restarted: r,
            ..
        } = &mut e.event
        {
            *p = previous_record;
            *r = pc_restarted;
        }
        e
    };
    for state in PreviousRecord::ALL {
        let e = with(Some(state), Some(true));
        assert_eq!(e.check(), Ok(()));
        let v = serde_json::to_value(&e).unwrap();
        assert_eq!(v["previous_record"], state.as_str());
        assert_eq!(v["pc_restarted"], true);
    }
    // Unknown: left out, never `null` (the schema takes neither null).
    let bare = with(None, None);
    let v = serde_json::to_value(&bare).unwrap();
    assert!(v.get("previous_record").is_none(), "{v}");
    assert!(v.get("pc_restarted").is_none(), "{v}");
    // A queue entry written by a build before them still reads.
    if let Some(o) = wire.as_object_mut() {
        o.remove("previous_record");
        o.remove("pc_restarted");
        o.remove("type");
    }
    let older: AgentEvent = serde_json::from_value(wire).expect("an older entry");
    assert_eq!(older, bare);
}

/// Every golden fixture passes the agent's own checks: what the server takes, the agent would send.
#[test]
fn every_v2_fixture_passes_the_agents_checks() {
    let dir = protocol_root().join("fixtures").join("agent-to-server");
    let mut summaries = 0;
    let mut events = 0;
    for entry in fs::read_dir(&dir).expect("the fixtures") {
        let path = entry.expect("an entry").path();
        let text = fs::read_to_string(&path).expect("a fixture");
        let msg: AgentToServer =
            serde_json::from_str(&text).unwrap_or_else(|e| panic!("{path:?}: {e}"));
        match msg {
            AgentToServer::SessionStats { stats, .. } => {
                if let Some(s) = stats.summary {
                    assert_eq!(s.check(), Ok(()), "{path:?}");
                    summaries += 1;
                }
            }
            AgentToServer::AgentEvent(e) => {
                assert_eq!(e.check(), Ok(()), "{path:?}");
                events += 1;
            }
            _ => {}
        }
    }
    assert!(
        summaries >= 1 && events >= 5,
        "{summaries} summaries, {events} events"
    );
}
