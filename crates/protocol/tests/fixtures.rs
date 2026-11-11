//! Conformance against the shared golden fixtures.
//!
//! This is the test that makes the contract real on the Rust side. It walks the
//! manifest emitted by `contract/packages/protocol` (the afklink-contract
//! submodule), parses every fixture the agent is
//! supposed to understand into the types in this crate, and re-serializes each one
//! to check the result is structurally identical to the file.
//!
//! Both halves matter:
//!
//!   parse      catches a field renamed or a message added in the zod schema —
//!              the Rust type cannot read the new shape.
//!   round-trip catches a field this crate quietly drops — it parses fine, but
//!              what comes back out is missing something the contract promised.
//!
//! Neither is detectable by a typecheck in any one language, which is exactly how
//! three hand-maintained copies drifted before.

// A failing contract test *should* abort, and the panic message is the diagnostic —
// "reading fixture X: no such file" is what tells you the emit step did not run. The
// workspace denies `panic!` because a running agent must not take down someone's remote
// session over a bad frame; a test binary has no session to take down.
#![allow(clippy::panic)]

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use afklink_protocol::{
    AgentDataMessage, AgentToServer, InputMessage, PipelineState, ServerToAgent, CHANNEL_CURSOR,
    CHANNEL_INPUT, PROTOCOL_VERSION,
};
use serde_json::Value;

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

fn manifest() -> Value {
    let path = fixtures_root().join("manifest.json");
    let raw = fs::read_to_string(&path).unwrap_or_else(|e| panic!("reading {path:?}: {e}"));
    serde_json::from_str(&raw).expect("manifest.json is not valid JSON")
}

/// Entries of one manifest group as (relative file path, expected variant tag).
fn group(name: &str) -> Vec<(String, Option<String>)> {
    let m = manifest();
    let groups = m["groups"].as_array().expect("manifest.groups is an array");
    let g = groups
        .iter()
        .find(|g| g["name"] == name)
        .unwrap_or_else(|| panic!("manifest has no group {name:?}"));
    g["fixtures"]
        .as_array()
        .expect("group.fixtures is an array")
        .iter()
        .map(|f| {
            (
                f["file"]
                    .as_str()
                    .expect("fixture.file is a string")
                    .to_string(),
                f["variant"].as_str().map(str::to_string),
            )
        })
        .collect()
}

fn read_fixture(rel: &str) -> Value {
    let path = fixtures_root().join(rel);
    let raw = fs::read_to_string(&path).unwrap_or_else(|e| panic!("reading {path:?}: {e}"));
    serde_json::from_str(&raw).unwrap_or_else(|e| panic!("{rel} is not valid JSON: {e}"))
}

/// Structural equality that treats numbers as values rather than as spellings.
///
/// JSON has one number type; Rust does not. A fixture written as `0` parses into an
/// `f64` and comes back out as `0.0`, which `Value::eq` calls different. That is a
/// difference in representation, not in content, and this test exists to catch
/// dropped and renamed fields — not to police how serde spells a float.
fn json_eq(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Number(x), Value::Number(y)) => match (x.as_f64(), y.as_f64()) {
            (Some(x), Some(y)) => x == y,
            _ => x == y,
        },
        (Value::Array(x), Value::Array(y)) => {
            x.len() == y.len() && x.iter().zip(y).all(|(x, y)| json_eq(x, y))
        }
        (Value::Object(x), Value::Object(y)) => {
            x.len() == y.len()
                && x.iter()
                    .all(|(k, xv)| y.get(k).is_some_and(|yv| json_eq(xv, yv)))
        }
        _ => a == b,
    }
}

/// Parse, check the discriminant, and assert the value survives a round-trip.
fn check<T>(rel: &str, expected_variant: Option<&str>, tag: &str)
where
    T: serde::de::DeserializeOwned + serde::Serialize,
{
    let original = read_fixture(rel);

    if let Some(v) = expected_variant {
        assert_eq!(
            original[tag].as_str(),
            Some(v),
            "{rel}: manifest says variant {v:?} but the file disagrees",
        );
    }

    let parsed: T = serde_json::from_value(original.clone()).unwrap_or_else(|e| {
        panic!("{rel}: this crate cannot parse a fixture the contract emits: {e}")
    });

    let round_tripped = serde_json::to_value(&parsed)
        .unwrap_or_else(|e| panic!("{rel}: re-serializing failed: {e}"));

    assert!(
        json_eq(&round_tripped, &original),
        "{rel}: round-trip changed the message - a field is being dropped or renamed here\n\
         wrote: {round_tripped}\n  read: {original}",
    );
}

#[test]
fn manifest_version_matches_this_build() {
    let m = manifest();
    assert_eq!(
        m["protocol_version"].as_u64(),
        Some(u64::from(PROTOCOL_VERSION)),
        "the contract and this crate disagree about the protocol version",
    );
}

#[test]
fn agent_to_server_fixtures_round_trip() {
    let entries = group("agent-to-server");
    assert!(!entries.is_empty(), "no agent-to-server fixtures found");
    for (file, variant) in &entries {
        check::<AgentToServer>(file, variant.as_deref(), "type");
    }
}

#[test]
fn server_to_agent_fixtures_round_trip() {
    let entries = group("server-to-agent");
    assert!(!entries.is_empty(), "no server-to-agent fixtures found");
    for (file, variant) in &entries {
        check::<ServerToAgent>(file, variant.as_deref(), "type");
    }
}

#[test]
fn input_fixtures_round_trip() {
    let entries = group("input");
    assert!(!entries.is_empty(), "no input fixtures found");
    for (file, variant) in &entries {
        check::<InputMessage>(file, variant.as_deref(), "t");
    }
}

#[test]
fn agent_to_viewer_fixtures_round_trip() {
    let entries = group("agent-to-viewer");
    assert!(!entries.is_empty(), "no agent-to-viewer fixtures found");
    for (file, variant) in &entries {
        check::<AgentDataMessage>(file, variant.as_deref(), "t");
    }
}

/// The two heartbeat fixtures exist for their differences: `cause` present only when not ok, and
/// the ages `null` before the first frame. Both are optional-looking fields a mirror could drop
/// while still round-tripping the other fixture, so each shape is checked for what it carries.
#[test]
fn heartbeat_fixtures_cover_both_shapes() {
    let mut saw_ok = false;
    let mut saw_not_ok = false;
    let mut saw_rel_exact = false;
    let mut saw_game_sized = false;
    let mut saw_game_unsized = false;
    let mut saw_game_launching = false;
    let mut saw_no_game = false;
    let mut saw_no_driver_alone = false;
    let mut saw_input_blocked = false;
    let mut saw_driver_flags_absent = false;
    let mut saw_vis_ok_alone = false;
    let mut saw_bg_hold = false;
    let mut saw_vis_absent = false;
    for (file, _) in group("agent-to-viewer") {
        let raw = read_fixture(&file);
        let AgentDataMessage::Heartbeat(hb) =
            serde_json::from_value(raw.clone()).unwrap_or_else(|e| panic!("{file}: {e}"))
        else {
            // The cursor reports have their own test below.
            continue;
        };
        // The game window only in the «only the game window» mode; its picture's size both sides or
        // neither — a mirror that dropped `game`, or one side of it, still round-trips the others.
        match hb.game {
            None => {
                saw_no_game = true;
                assert!(
                    raw.get("game").is_none(),
                    "{file}: game is absent, not null"
                );
            }
            Some(game) => {
                assert_eq!(
                    game.w.is_some(),
                    game.h.is_some(),
                    "{file}: the game picture's size comes whole"
                );
                if game.w.is_some() {
                    saw_game_sized = true;
                } else {
                    saw_game_unsized = true;
                    assert!(
                        raw["game"].get("w").is_none() && raw["game"].get("h").is_none(),
                        "{file}: an unknown size is absent, not null"
                    );
                }
                // «Игра запускается»: only while the window is not there, absent while false — a
                // mirror that dropped it still round-trips every other fixture.
                if game.launching {
                    saw_game_launching = true;
                    assert!(
                        game.state.window_missing(),
                        "{file}: launching only while the window is absent or starting"
                    );
                } else {
                    assert!(
                        raw["game"].get("launching").is_none(),
                        "{file}: launching is absent while false"
                    );
                }
            }
        }
        // «Нужен драйвер на ПК»: each flag absent while
        // false, so an older agent's heartbeat and this one's with the driver working read alike;
        // `input_blocked` only ever with `no_driver`.
        for (flag, set) in [
            ("no_driver", hb.no_driver),
            ("input_blocked", hb.input_blocked),
        ] {
            if !set {
                assert!(
                    raw.get(flag).is_none(),
                    "{file}: {flag} is absent while false"
                );
            }
        }
        assert!(
            !hb.input_blocked || hb.no_driver,
            "{file}: input is only blocked for want of the driver"
        );
        match (hb.no_driver, hb.input_blocked) {
            (false, false) => saw_driver_flags_absent = true,
            (true, false) => saw_no_driver_alone = true,
            (true, true) => saw_input_blocked = true,
            (false, true) => {}
        }
        // The background hold (`vis`): `vis_ok` from an agent that honours it, `bg_hold` only beside
        // it, each absent while false — a mirror that dropped either still round-trips the rest. The
        // pipeline is fine through a hold: `ok`, and `still` (nothing captured for a while).
        for (flag, set) in [("vis_ok", hb.vis_ok), ("bg_hold", hb.bg_hold)] {
            if !set {
                assert!(
                    raw.get(flag).is_none(),
                    "{file}: {flag} is absent while false"
                );
            }
        }
        assert!(
            !hb.bg_hold || hb.vis_ok,
            "{file}: bg_hold only from an agent that says vis_ok"
        );
        if hb.bg_hold {
            assert_eq!(
                hb.state,
                PipelineState::Ok,
                "{file}: a hold is not a failure"
            );
            assert!(hb.still, "{file}: nothing is captured through a hold");
        }
        match (hb.vis_ok, hb.bg_hold) {
            (false, false) => saw_vis_absent = true,
            (true, false) => saw_vis_ok_alone = true,
            (true, true) => saw_bg_hold = true,
            (false, true) => {}
        }
        // An agent that moves the cursor by exactly the `r` fraction says so; an older one's
        // heartbeat has no such field at all.
        saw_rel_exact |= hb.rel_exact;
        if !hb.rel_exact {
            assert!(
                raw.get("rel_exact").is_none(),
                "{file}: rel_exact is absent while false"
            );
        }
        if hb.state == PipelineState::Ok {
            saw_ok = true;
            assert!(
                hb.cause.is_none(),
                "{file}: an ok heartbeat carries no cause"
            );
            assert!(
                raw.get("cause").is_none(),
                "{file}: cause must be absent, not null"
            );
        } else {
            saw_not_ok = true;
            assert!(
                hb.cause.is_some(),
                "{file}: a heartbeat that is not ok names its cause"
            );
        }
        for age in ["since_capture_ms", "since_encode_ms"] {
            assert!(
                raw.get(age).is_some(),
                "{file}: {age} is required on the wire, null included"
            );
        }
    }
    assert!(saw_ok && saw_not_ok, "need one ok and one not-ok heartbeat");
    assert!(saw_rel_exact, "need a heartbeat with rel_exact");
    assert!(
        saw_no_game && saw_game_sized && saw_game_unsized,
        "need heartbeats without game, with a sized game and with an unsized one"
    );
    assert!(
        saw_game_launching,
        "need a heartbeat whose game the helper is launching"
    );
    assert!(
        saw_driver_flags_absent && saw_no_driver_alone && saw_input_blocked,
        "need heartbeats without the driver flags, with no_driver alone and with input_blocked"
    );
    assert!(
        saw_vis_absent && saw_vis_ok_alone && saw_bg_hold,
        "need heartbeats without vis_ok, with vis_ok alone and with bg_hold"
    );
}

/// The background hold's signal, both values, `why` present and absent — through the agent's own
/// parser, which also bounds `why` — and the agent's hold counters on its session report.
#[test]
fn visibility_and_hold_stats_fixtures_cover_both_shapes() {
    let (mut saw_hidden, mut saw_visible, mut saw_why, mut saw_no_why) =
        (false, false, false, false);
    for (file, variant) in group("input") {
        if variant.as_deref() != Some("vis") {
            continue;
        }
        let raw = read_fixture(&file);
        let InputMessage::Visibility { hidden, why } = InputMessage::parse(&raw.to_string())
            .unwrap_or_else(|e| panic!("{file}: the agent's parser refuses it: {e}"))
        else {
            panic!("{file}: not a vis");
        };
        saw_hidden |= hidden;
        saw_visible |= !hidden;
        match why {
            Some(w) => {
                saw_why = true;
                assert!(
                    w.chars().count() <= afklink_protocol::VIS_WHY_MAX_CHARS,
                    "{file}"
                );
            }
            None => {
                saw_no_why = true;
                assert!(raw.get("why").is_none(), "{file}: why is absent, not null");
            }
        }
    }
    assert!(
        saw_hidden && saw_visible && saw_why && saw_no_why,
        "need vis hidden and visible, with a why and without"
    );

    let mut saw_hold_stats = false;
    for (file, variant) in group("agent-to-server") {
        if variant.as_deref() != Some("session_stats") {
            continue;
        }
        let AgentToServer::SessionStats { stats, .. } =
            serde_json::from_value(read_fixture(&file)).unwrap_or_else(|e| panic!("{file}: {e}"))
        else {
            panic!("{file}: not session_stats");
        };
        assert_eq!(
            stats.bg_hold_ms.is_some(),
            stats.bg_holds.is_some(),
            "{file}: the hold's two counters go together"
        );
        saw_hold_stats |= stats.bg_hold_ms.is_some();
    }
    assert!(
        saw_hold_stats,
        "need a session_stats with the hold's counters"
    );
}

/// A relative move with the viewer's pointer and one without: a mirror that dropped `x`/`y` would
/// still round-trip the plain one, and the agent's `parse` refuses half a target, so both shapes are
/// checked for what they carry.
#[test]
fn relative_move_fixtures_cover_a_target_and_none() {
    let mut saw_target = false;
    let mut saw_plain = false;
    for (file, variant) in group("input") {
        if variant.as_deref() != Some("r") {
            continue;
        }
        let raw = read_fixture(&file);
        let parsed = InputMessage::parse(&raw.to_string())
            .unwrap_or_else(|e| panic!("{file}: the agent's parser refuses it: {e}"));
        let InputMessage::Rel { x, y, .. } = parsed else {
            panic!("{file}: not a relative move");
        };
        match (x, y) {
            (Some(x), Some(y)) => {
                saw_target = true;
                assert!(
                    (0.0..=1.0).contains(&x) && (0.0..=1.0).contains(&y),
                    "{file}: a target is on the screen"
                );
            }
            (None, None) => saw_plain = true,
            _ => panic!("{file}: half a target"),
        }
    }
    assert!(
        saw_target && saw_plain,
        "need a relative move with a target and one without"
    );
}

/// The two cursor-report fixtures exist for their optional fields: `ack` once a numbered move was
/// applied, `hidden` only while true. A mirror that dropped either would still round-trip the
/// other fixture, so each is checked for what it carries.
#[test]
fn cursor_fixtures_cover_ack_and_hidden() {
    let mut saw_ack = false;
    let mut saw_hidden = false;
    for (file, _) in group("agent-to-viewer") {
        let raw = read_fixture(&file);
        let AgentDataMessage::Cursor(cp) =
            serde_json::from_value(raw.clone()).unwrap_or_else(|e| panic!("{file}: {e}"))
        else {
            continue;
        };
        assert!(
            (0.0..=1.0).contains(&cp.x) && (0.0..=1.0).contains(&cp.y),
            "{file}: a position is normalized to the screen"
        );
        saw_ack |= cp.ack.is_some();
        saw_hidden |= cp.hidden;
        if !cp.hidden {
            assert!(
                raw.get("hidden").is_none(),
                "{file}: hidden is absent while false"
            );
        }
    }
    assert!(
        saw_ack && saw_hidden,
        "need a report with ack and a hidden one"
    );
}

/// Clipboard sync's fixtures carry what a mirror could drop while still round-tripping another:
/// `cb_state` on both ways and on towards the PC only, `cb_ack` with and without `why` (absent, not
/// null, on a success), and chunks that are whole and within their count. The agent's joiner takes
/// the viewer's chunk as the second of its text.
#[test]
fn clipboard_fixtures_cover_both_answers_and_whole_chunks() {
    use afklink_protocol::clipboard::{Joined, Joiner};
    use afklink_protocol::{ClipboardChunk, ClipboardPc};
    let (mut saw_ready, mut saw_to_pc_only, mut saw_ok, mut saw_refused, mut saw_pc) =
        (false, false, false, false, false);
    for (file, _) in group("agent-to-viewer") {
        let raw = read_fixture(&file);
        match serde_json::from_value(raw.clone()).unwrap_or_else(|e| panic!("{file}: {e}")) {
            AgentDataMessage::ClipboardState(state) => {
                assert!(
                    !state.on || state.pc.takes_text(),
                    "{file}: on only while the PC allows it"
                );
                saw_ready |= state.on && state.pc == ClipboardPc::Ready;
                saw_to_pc_only |= state.on && state.pc == ClipboardPc::ToPcOnly;
            }
            AgentDataMessage::ClipboardAck(ack) => {
                assert_eq!(ack.ok, ack.why.is_none(), "{file}: why only on a refusal");
                if ack.ok {
                    saw_ok = true;
                    assert!(raw.get("why").is_none(), "{file}: why is absent, not null");
                } else {
                    saw_refused = true;
                }
            }
            AgentDataMessage::ClipboardPc(chunk) => {
                saw_pc = true;
                assert!(chunk.i < chunk.n && !chunk.text.is_empty(), "{file}");
            }
            AgentDataMessage::Heartbeat(_) | AgentDataMessage::Cursor(_) => {}
        }
    }
    assert!(
        saw_ready && saw_to_pc_only && saw_ok && saw_refused && saw_pc,
        "need cb_state on with ready and with to_pc_only, cb_ack ok and refused, and a cb_pc chunk"
    );
    let mut saw_set = false;
    for (file, variant) in group("input") {
        if variant.as_deref() != Some("cb_set") {
            continue;
        }
        let InputMessage::ClipboardSet(chunk) =
            InputMessage::parse(&read_fixture(&file).to_string())
                .unwrap_or_else(|e| panic!("{file}: the agent's parser refuses it: {e}"))
        else {
            panic!("{file}: not a cb_set");
        };
        saw_set = true;
        let mut joiner = Joiner::new();
        for i in 0..chunk.i {
            let before = ClipboardChunk {
                i,
                text: "x".into(),
                ..chunk.clone()
            };
            assert_eq!(joiner.accept(&before), Joined::Partial, "{file}");
        }
        let joined = joiner.accept(&chunk);
        assert!(
            matches!(joined, Joined::Done { .. } | Joined::Partial),
            "{file}: {joined:?}"
        );
    }
    assert!(saw_set, "need a cb_set chunk");
}

/// The roles' fixtures carry what a mirror could drop while still round-tripping another: a role on
/// each binding and on `binding_added`, `has_owner` on the prompt, the role an approval gives,
/// `owner_changed` to an account and to nobody (`null`, present), and `owner_request_state` waiting
/// (with its deadline, no reason), withdrawn (with why, no deadline) and refused (with why, and no
/// id: there is no request). Each optional field is checked absent where the contract says so.
///
/// And `pc_allow`: pending with the newcomer's names (a mirror that dropped them would still
/// round-trip a state without them) and withdrawn `by_requester`, the reason that comes with
/// `pc_allow` only; the PC's own two kinds name nobody.
#[test]
fn role_fixtures_cover_every_shape() {
    use afklink_protocol::{BindingRole, OwnerRequestReason, OwnerRequestState, OwnerStateKind};

    let (mut saw_owner, mut saw_guest) = (false, false);
    let (mut saw_pending, mut saw_cancelled, mut saw_refused) = (false, false, false);
    let (mut saw_pc_allow_named, mut saw_by_requester) = (false, false);
    let (mut saw_new_owner, mut saw_no_owner) = (false, false);
    let mut saw_has_owner = false;
    let mut saw_added_role = false;
    for (file, _) in group("server-to-agent") {
        let raw = read_fixture(&file);
        let msg: ServerToAgent =
            serde_json::from_value(raw.clone()).unwrap_or_else(|e| panic!("{file}: {e}"));
        match msg {
            ServerToAgent::AgentReady { bindings, .. } => {
                for b in &bindings {
                    match b.role {
                        Some(BindingRole::Owner) => saw_owner = true,
                        Some(BindingRole::Guest) => saw_guest = true,
                        None => {}
                    }
                }
                assert!(
                    bindings
                        .iter()
                        .filter(|b| b.role == Some(BindingRole::Owner))
                        .count()
                        <= 1,
                    "{file}: one owner at most"
                );
            }
            ServerToAgent::BindingAdded { role, .. } => saw_added_role |= role.is_some(),
            ServerToAgent::PairRequest { has_owner, .. } => saw_has_owner |= has_owner.is_some(),
            ServerToAgent::OwnerChanged { telegram_user_id } => {
                assert!(
                    raw.get("telegram_user_id").is_some(),
                    "{file}: telegram_user_id is required, null included"
                );
                match telegram_user_id {
                    Some(_) => saw_new_owner = true,
                    None => saw_no_owner = true,
                }
            }
            ServerToAgent::OwnerRequestState {
                request_id,
                kind,
                state,
                expires_at,
                reason,
                username,
                first_name,
                ..
            } => {
                if reason == Some(OwnerRequestReason::ByRequester) {
                    assert_eq!(
                        kind,
                        OwnerStateKind::PcAllow,
                        "{file}: by_requester comes with pc_allow only"
                    );
                    saw_by_requester = true;
                }
                if kind == OwnerStateKind::PcAllow {
                    saw_pc_allow_named |= state == OwnerRequestState::Pending
                        && username.is_some()
                        && first_name.is_some();
                } else {
                    assert!(
                        raw.get("username").is_none() && raw.get("first_name").is_none(),
                        "{file}: the PC's own kinds name nobody: the person is in its list"
                    );
                }
                for (field, present) in [
                    ("username", username.is_some()),
                    ("first_name", first_name.is_some()),
                ] {
                    if !present {
                        assert!(
                            raw.get(field).is_none_or(Value::is_null),
                            "{file}: {field} absent or null"
                        );
                    }
                }
                assert_eq!(
                    state == OwnerRequestState::Refused,
                    request_id.is_none(),
                    "{file}: request_id on every state but refused"
                );
                assert_eq!(
                    matches!(
                        state,
                        OwnerRequestState::Cancelled | OwnerRequestState::Refused
                    ),
                    reason.is_some(),
                    "{file}: a reason with cancelled and refused, and only with them"
                );
                if state == OwnerRequestState::Pending {
                    assert!(expires_at.is_some(), "{file}: pending says when it expires");
                }
                for (field, present) in [
                    ("request_id", request_id.is_some()),
                    ("expires_at", expires_at.is_some()),
                    ("reason", reason.is_some()),
                ] {
                    if !present {
                        assert!(raw.get(field).is_none(), "{file}: {field} absent, not null");
                    }
                }
                match state {
                    OwnerRequestState::Pending => saw_pending = true,
                    OwnerRequestState::Cancelled => saw_cancelled = true,
                    OwnerRequestState::Refused => saw_refused = true,
                    _ => {}
                }
            }
            _ => {}
        }
    }
    assert!(
        saw_owner && saw_guest,
        "need an owner and a guest in agent_ready"
    );
    assert!(saw_added_role, "need a binding_added with its role");
    assert!(saw_has_owner, "need a pair_request with has_owner");
    assert!(
        saw_new_owner && saw_no_owner,
        "need owner_changed to an account and to nobody"
    );
    assert!(
        saw_pending && saw_cancelled && saw_refused,
        "need owner_request_state pending, cancelled and refused"
    );
    assert!(
        saw_pc_allow_named && saw_by_requester,
        "need owner_request_state pc_allow pending with the newcomer's names, and one cancelled \
         by_requester"
    );

    let mut saw_approval_role = false;
    for (file, variant) in group("agent-to-server") {
        if variant.as_deref() != Some("pair_response") {
            continue;
        }
        let msg: AgentToServer =
            serde_json::from_value(read_fixture(&file)).unwrap_or_else(|e| panic!("{file}: {e}"));
        if let AgentToServer::PairResponse { accept, role, .. } = msg {
            assert!(accept || role.is_none(), "{file}: a refusal gives no role");
            saw_approval_role |= role.is_some();
        }
    }
    assert!(
        saw_approval_role,
        "need a pair_response with the role chosen"
    );
}

/// `binding_added` from the owner's invite (`binding_added_invite`) and from the PC's own «Разрешить»
/// (`binding_added`): a mirror that dropped `via` would still round-trip the plain one, so both are
/// checked for what they carry — `via: invite` with the guest's role, and no `via` key at all.
#[test]
fn binding_added_fixtures_cover_an_invite_and_none() {
    use afklink_protocol::{BindingRole, BindingVia};

    let (mut saw_invite, mut saw_none) = (false, false);
    for (file, variant) in group("server-to-agent") {
        if variant.as_deref() != Some("binding_added") {
            continue;
        }
        let raw = read_fixture(&file);
        let ServerToAgent::BindingAdded { role, via, .. } =
            serde_json::from_value(raw.clone()).unwrap_or_else(|e| panic!("{file}: {e}"))
        else {
            panic!("{file}: not a binding_added");
        };
        match via {
            Some(BindingVia::Invite) => {
                saw_invite = true;
                assert_eq!(
                    role,
                    Some(BindingRole::Guest),
                    "{file}: an invite always makes a guest"
                );
            }
            Some(BindingVia::Other(word)) => {
                panic!("{file}: the contract's own via {word:?} is unknown to this crate")
            }
            None => {
                saw_none = true;
                assert!(raw.get("via").is_none(), "{file}: via is absent, not null");
            }
        }
    }
    assert!(
        saw_invite && saw_none,
        "need a binding_added by invite and one without via"
    );
}

/// Every `via` the contract's schema allows (`BINDING_VIAS`) is a word this crate knows: a new one
/// would otherwise read as [`afklink_protocol::BindingVia::Other`] — no `via` at all — and the PC
/// would quietly say nothing about how the binding came about. Adding one has to be a decision here.
#[test]
fn every_binding_via_in_the_contract_is_known() {
    use afklink_protocol::BindingVia;

    // Beside the fixtures, both emitted from the same zod schemas. Joined part by part: the root is
    // canonical, which on Windows is a verbatim path that takes no `..`.
    let path = fixtures_root()
        .parent()
        .expect("the fixtures have a parent")
        .join("schema")
        .join("server-to-agent.json");
    let raw = fs::read_to_string(&path).unwrap_or_else(|e| panic!("reading {path:?}: {e}"));
    let schema: Value = serde_json::from_str(&raw).expect("server-to-agent.json is not JSON");
    let added = schema["oneOf"]
        .as_array()
        .expect("the schema is a oneOf")
        .iter()
        .find(|v| v["properties"]["type"]["const"] == "binding_added")
        .expect("the schema has binding_added");
    let words: Vec<&str> = added["properties"]["via"]["enum"]
        .as_array()
        .expect("binding_added.via is an enum in the schema")
        .iter()
        .map(|w| w.as_str().expect("a via is a word"))
        .collect();
    assert!(!words.is_empty(), "the schema's via enum is empty");
    for word in words {
        let via = BindingVia::from_wire(word);
        assert!(
            !matches!(via, BindingVia::Other(_)),
            "the contract grew via {word:?} - add it to afklink_protocol::invites::BindingVia"
        );
        assert_eq!(via.as_str(), word);
    }
    assert!(
        !added["required"]
            .as_array()
            .expect("required is a list")
            .iter()
            .any(|f| f == "via"),
        "via is optional in the contract"
    );
}

/// `agent_goodbye` is exactly the contract's: `type` and a required `reason`, nothing else, and the
/// reasons are `AGENT_GOODBYE_REASONS` — the same words in the same order as
/// [`afklink_protocol::GoodbyeReason::ALL`]. A reason added there (or here) fails this until the
/// other side has it: the server takes the PC offline by the reason, so a word it does not know
/// would cost the whole goodbye (`bad_message`).
#[test]
fn the_goodbye_and_its_reasons_are_the_contracts() {
    use afklink_protocol::GoodbyeReason;

    let path = fixtures_root()
        .parent()
        .expect("the fixtures have a parent")
        .join("schema")
        .join("agent-to-server.json");
    let raw = fs::read_to_string(&path).unwrap_or_else(|e| panic!("reading {path:?}: {e}"));
    let schema: Value = serde_json::from_str(&raw).expect("agent-to-server.json is not JSON");
    let goodbye = schema["oneOf"]
        .as_array()
        .expect("the schema is a oneOf")
        .iter()
        .find(|v| v["properties"]["type"]["const"] == "agent_goodbye")
        .expect("the schema has agent_goodbye");
    let mut fields: Vec<&str> = goodbye["properties"]
        .as_object()
        .expect("agent_goodbye has properties")
        .keys()
        .map(String::as_str)
        .collect();
    fields.sort_unstable();
    assert_eq!(fields, ["reason", "type"], "agent_goodbye's fields");
    let mut required: Vec<&str> = goodbye["required"]
        .as_array()
        .expect("required is a list")
        .iter()
        .map(|f| f.as_str().expect("a field name"))
        .collect();
    required.sort_unstable();
    assert_eq!(required, ["reason", "type"], "the reason is required");
    let words: Vec<&str> = goodbye["properties"]["reason"]["enum"]
        .as_array()
        .expect("agent_goodbye.reason is an enum in the schema")
        .iter()
        .map(|w| w.as_str().expect("a reason is a word"))
        .collect();
    let ours: Vec<&str> = GoodbyeReason::ALL.iter().map(|r| r.as_str()).collect();
    assert_eq!(words, ours, "AGENT_GOODBYE_REASONS and GoodbyeReason::ALL");
    for word in words {
        let parsed: AgentToServer = serde_json::from_value(serde_json::json!({
            "type": "agent_goodbye",
            "reason": word,
        }))
        .unwrap_or_else(|e| panic!("{word}: {e}"));
        assert_eq!(
            serde_json::to_value(&parsed).expect("serialises")["reason"],
            word
        );
    }
}

/// Contract v2's agent shapes, each checked for what it carries — a mirror that dropped one of these
/// optional fields would still round-trip the older fixture of the same message: a hello with its
/// build, boot and last exit and one without; a `session_end` with its detail and one without; a
/// final report with its summary and an ordinary one without either; every agent event kind.
#[test]
fn telemetry_v2_fixtures_cover_every_new_shape() {
    use afklink_protocol::metrics::AgentEventKind;
    use afklink_protocol::AgentExitKind;

    let (mut hello_v2, mut hello_old) = (false, false);
    let (mut end_detail, mut end_plain) = (false, false);
    let (mut final_report, mut plain_report) = (false, false);
    let mut event_kinds = BTreeSet::new();
    for (file, _) in group("agent-to-server") {
        let raw = read_fixture(&file);
        let msg: AgentToServer =
            serde_json::from_value(raw.clone()).unwrap_or_else(|e| panic!("{file}: {e}"));
        match msg {
            AgentToServer::AgentHello {
                build,
                boot_id,
                last_exit,
                ..
            } => match (build, boot_id, last_exit) {
                (Some(build), Some(boot), Some(exit)) => {
                    hello_v2 = true;
                    assert_eq!(build.check(), Ok(()), "{file}");
                    assert!(afklink_protocol::diagnostics::is_uuid(&boot), "{file}");
                    assert!(
                        exit.kind.is_crash() && exit.at.is_some(),
                        "{file}: the fixture's exit is a crash with its time, which is what lets \
                         the server rewrite the sessions it left behind"
                    );
                    assert_ne!(exit.kind, AgentExitKind::Unknown);
                }
                (None, None, None) => {
                    hello_old = true;
                    for key in ["build", "boot_id", "last_exit"] {
                        assert!(raw.get(key).is_none(), "{file}: {key} absent, not null");
                    }
                }
                other => panic!("{file}: a hello with some of the v2 fields: {other:?}"),
            },
            AgentToServer::SessionEnd { detail, .. } => match detail {
                Some(d) => {
                    end_detail = true;
                    let (kept, dropped) = d.clone().keep_valid();
                    assert!(dropped.is_empty(), "{file}: {dropped:?}");
                    assert_eq!(kept, d);
                    assert!(d.ended_detail.is_some() && d.stage.is_some(), "{file}");
                }
                None => {
                    end_plain = true;
                    assert!(
                        raw.get("detail").is_none(),
                        "{file}: detail absent, not null"
                    );
                }
            },
            AgentToServer::SessionStats {
                stats, is_final, ..
            } => {
                if is_final {
                    final_report = true;
                    assert!(
                        stats.summary.is_some(),
                        "{file}: the final fixture has a summary"
                    );
                } else {
                    plain_report = true;
                    assert!(
                        raw.get("final").is_none(),
                        "{file}: final absent while false"
                    );
                    assert!(stats.summary.is_none(), "{file}");
                }
            }
            AgentToServer::AgentEvent(e) => {
                event_kinds.insert(match e.event {
                    AgentEventKind::AgentStarted { .. } => "agent_started",
                    AgentEventKind::AgentCrashed { .. } => "agent_crashed",
                    AgentEventKind::UpdateFinished { .. } => "update_finished",
                    AgentEventKind::DriverInstallFinished { .. } => "driver_install_finished",
                    AgentEventKind::PcSettingChanged { .. } => "pc_setting_changed",
                });
            }
            _ => {}
        }
    }
    assert!(
        hello_v2 && hello_old,
        "need a hello with the v2 fields and one without"
    );
    assert!(
        end_detail && end_plain,
        "need a session_end with a detail and one without"
    );
    assert!(
        final_report && plain_report,
        "need a final report and an ordinary one"
    );
    assert_eq!(
        event_kinds.into_iter().collect::<Vec<_>>(),
        [
            "agent_crashed",
            "agent_started",
            "driver_install_finished",
            "pc_setting_changed",
            "update_finished"
        ],
        "an agent_event fixture per kind"
    );
}

/// The beta's `agent_hello.hw`: the contract's golden hello with a fingerprint (`agent_hello_hw.json`)
/// parses into [`afklink_protocol::AgentHw`] whole and passes the agent's own check, and a hello
/// without one has no `hw` key at all — a mirror that dropped the field would still round-trip that
/// one, and an agent that sent `"hw": null` would be refused by the server's schema.
#[test]
fn hello_fixtures_cover_a_fingerprint_and_none() {
    let (mut with_hw, mut without) = (false, false);
    for (file, variant) in group("agent-to-server") {
        if variant.as_deref() != Some("agent_hello") {
            continue;
        }
        let raw = read_fixture(&file);
        let AgentToServer::AgentHello { hw, .. } =
            serde_json::from_value(raw.clone()).unwrap_or_else(|e| panic!("{file}: {e}"))
        else {
            panic!("{file}: not an agent_hello");
        };
        match hw {
            Some(hw) => {
                with_hw = true;
                assert_eq!(hw.check(), Ok(()), "{file}: the agent's check refuses it");
                assert_eq!(
                    serde_json::to_value(&hw).expect("serialises"),
                    raw["hw"],
                    "{file}: hw whole"
                );
                assert!(
                    (1..=afklink_protocol::AGENT_HW_PARTS).contains(&hw.parts),
                    "{file}: parts"
                );
            }
            None => {
                without = true;
                assert!(raw.get("hw").is_none(), "{file}: hw absent, not null");
            }
        }
    }
    assert!(
        with_hw && without,
        "need a hello with the fingerprint and one without"
    );
}

#[test]
fn session_request_fixtures_cover_a_quality_profile_and_none() {
    let (mut with_profile, mut without) = (false, false);
    for (file, variant) in group("server-to-agent") {
        if variant.as_deref() != Some("session_request") {
            continue;
        }
        let raw = read_fixture(&file);
        let ServerToAgent::SessionRequest {
            quality_profile, ..
        } = serde_json::from_value(raw.clone()).unwrap_or_else(|e| panic!("{file}: {e}"))
        else {
            panic!("{file}: not a session_request");
        };
        match quality_profile {
            Some(profile) => {
                with_profile = true;
                // Raw, so the floats are the fixture's text and not an f32 widened back.
                assert_eq!(profile, raw["quality_profile"], "{file}: the profile whole");
                assert!(profile["values"].is_object(), "{file}: values");
            }
            None => {
                without = true;
                assert!(
                    raw.get("quality_profile").is_none(),
                    "{file}: absent, not null"
                );
            }
        }
    }
    assert!(
        with_profile && without,
        "need a session_request with a quality profile and one without"
    );
}

#[test]
fn every_message_the_agent_speaks_has_a_fixture() {
    // Guards the case the round-trip tests cannot see: a variant added to the
    // contract with no example, leaving the other implementations nothing to test
    // against. The expected sets are written out by hand on purpose - adding a
    // message should be a deliberate edit here, not something that slips through.
    let expected_agent_to_server: BTreeSet<&str> = [
        "agent_hello",
        "agent_auth",
        "request_pairing",
        "pairing_cancel",
        "pair_response",
        "device_name",
        "unbind",
        "owner_request",
        "owner_request_cancel",
        "sdp",
        "ice",
        "session_end",
        "session_stats",
        "pong",
        "agent_goodbye",
        "agent_event",
    ]
    .into_iter()
    .collect();

    let expected_server_to_agent: BTreeSet<&str> = [
        "challenge",
        "agent_ready",
        "pairing_code",
        "pair_request",
        "pair_cancelled",
        "binding_added",
        "binding_removed",
        "owner_changed",
        "owner_request_state",
        "session_request",
        "sdp",
        "ice",
        "session_end",
        "ping",
        "error",
    ]
    .into_iter()
    .collect();

    let expected_input: BTreeSet<&str> = [
        "m", "r", "w", "d", "u", "k", "text", "combo", "ra", "q", "vl", "vv", "kf", "vis",
        "cb_sync", "cb_set",
    ]
    .into_iter()
    .collect();

    let expected_agent_to_viewer: BTreeSet<&str> = ["hb", "cp", "cb_state", "cb_pc", "cb_ack"]
        .into_iter()
        .collect();

    for (name, expected) in [
        ("agent-to-server", expected_agent_to_server),
        ("server-to-agent", expected_server_to_agent),
        ("input", expected_input),
        ("agent-to-viewer", expected_agent_to_viewer),
    ] {
        let actual: BTreeSet<String> = group(name)
            .into_iter()
            .filter_map(|(_, variant)| variant)
            .collect();
        let actual: BTreeSet<&str> = actual.iter().map(String::as_str).collect();

        let missing: Vec<_> = expected.difference(&actual).collect();
        let unexpected: Vec<_> = actual.difference(&expected).collect();

        assert!(
            missing.is_empty(),
            "{name}: contract lost fixtures for {missing:?}",
        );
        assert!(
            unexpected.is_empty(),
            "{name}: contract grew {unexpected:?} - add them to this crate and to this list",
        );
    }
}

#[test]
fn input_fixtures_land_on_the_channel_the_contract_assigns() {
    for (file, _) in group("input") {
        let msg: InputMessage =
            serde_json::from_value(read_fixture(&file)).unwrap_or_else(|e| panic!("{file}: {e}"));
        // Channel, not must_arrive: the latency report rides the reliable channel
        // without being required (a lost one costs a diagnostic sample, not stuck
        // state), so the two predicates legitimately disagree on it.
        let is_cursor = matches!(
            msg,
            InputMessage::Move { .. } | InputMessage::Rel { .. } | InputMessage::Wheel { .. }
        );
        assert_eq!(
            msg.channel().label(),
            if is_cursor {
                CHANNEL_CURSOR
            } else {
                CHANNEL_INPUT
            },
            "{file}: wrong channel - losing a discrete event leaves state stuck on the desktop",
        );
    }
}
