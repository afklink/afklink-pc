#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines,
    reason = "tests"
)]
//! The contract's vectors (`contract/packages/protocol/vectors/viewer-keys/`) as table tests:
//! `scenarios.json` step by step through the engine, the store applied synchronously; the
//! per-ground case files (`endorse`, `grant`, `recover`, `first-use`) as one-offer scenarios; and
//! the parsers' files (`offer-proof`, `key-reg`, `sdp-fingerprint`, `encoding`, `key-id`,
//! `telegram-attest`) against the parsers alone.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::Arc;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use serde_json::{json, Value};

use super::*;
use crate::viewer_keys::wire::{b64url_exact, offer_message};
use crate::viewer_keys::{GrantToken, KnownBinding, Removal, TelegramEnvironment, TrustStore};

fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../contract/packages/protocol/vectors/viewer-keys")
}

fn load(name: &str) -> Value {
    let path = vectors_dir().join(name);
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    serde_json::from_str(&text).unwrap()
}

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn hex32(s: &str) -> [u8; 32] {
    hex(s).try_into().unwrap()
}

fn kid(s: &str) -> KeyId {
    KeyId::parse(s).unwrap_or_else(|| panic!("key id {s}"))
}

fn role(s: Option<&str>) -> BindingRole {
    match s {
        Some("owner") => BindingRole::Owner,
        _ => BindingRole::Guest,
    }
}

fn test_verifier() -> TelegramVerifier {
    let keys = load("keys.json");
    let bot_id = keys["bot_id"].as_u64().unwrap();
    let key = hex32(
        keys["telegram_test_ed25519"]["public_hex"]
            .as_str()
            .unwrap(),
    );
    TelegramVerifier::with_key(Some(bot_id), key, TelegramEnvironment::Injected)
}

struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!("afklink-admission-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Every ground id the steps name, by set: a vector's flat `spent` list goes to the set whose
/// grounds name the id (an endorse_id by default).
fn ground_ids(steps: &[Value]) -> (BTreeSet<String>, BTreeSet<String>) {
    let mut grants = BTreeSet::new();
    let mut invites = BTreeSet::new();
    for step in steps {
        for a in step["proof"]["admit"].as_array().into_iter().flatten() {
            if let Some(g) = a["grant"]["grant_id"].as_str() {
                grants.insert(g.to_string());
            }
            for v in [&a["grant"]["inv_id"], &a["invite"]["inv_id"]] {
                if let Some(i) = v.as_str() {
                    invites.insert(i.to_string());
                }
            }
        }
    }
    (grants, invites)
}

/// The vector's PC state as `viewer_keys.json` (the store's format), loaded by the store itself.
fn write_state(dir: &std::path::Path, state: &Value, steps: &[Value]) {
    let keys: Vec<Value> = state["keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|k| {
            let mut f = json!({
                "key_id": k["key_id"], "spki": k["spki"], "person": k["person"],
                "role": k["role"], "kind": k["kind"], "platform": k["platform"],
                "source": k["source"], "unconfirmed": k["unconfirmed"].as_bool().unwrap_or(false),
                "added_at": 0,
            });
            if let Some(r) = k["rpk"].as_str() {
                f["rpk"] = r.into();
            }
            f
        })
        .collect();
    let tombstones: Vec<Value> = state["revoked"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| {
            let origin = match t["origin"].as_str().unwrap() {
                "replaced" => json!({"kind": "replaced", "new_key_id": t["key_id"]}),
                o => json!({ "kind": o }),
            };
            // A tombstone keeps the source of the record it was (its ancestry edges).
            let source = t.get("source").cloned().unwrap_or(json!({"kind": "pair"}));
            let mut f = json!({
                "key_id": t["key_id"], "spki": t["spki"],
                "telegram_user_id": t["telegram_user_id"], "origin": origin,
                "source": source,
            });
            // The vectors' `removed_at` is the file's `at` (the same field, §10); a tombstone
            // without it stays without it — the product's parser decides (damaged).
            if let Some(at) = t.get("removed_at") {
                f["at"] = at.clone();
            }
            f
        })
        .collect();
    let (grants, invites) = ground_ids(steps);
    let (mut e, mut g, mut i) = (Vec::new(), Vec::new(), Vec::new());
    for id in state["spent"].as_array().unwrap() {
        let s = id.as_str().unwrap().to_string();
        if grants.contains(&s) {
            g.push(s);
        } else if invites.contains(&s) {
            i.push(s);
        } else {
            e.push(s);
        }
    }
    // A record's or a tombstone's ground missing from `spent` stays missing: the store must read
    // such a state as damaged (`expect_initial`), never have it patched here. A spent id that
    // names a record's ground goes to that ground's set (the flat list does not say which).
    for k in state["keys"]
        .as_array()
        .unwrap()
        .iter()
        .chain(state["revoked"].as_array().unwrap())
    {
        let src = &k["source"];
        for (field, set) in [("grant_id", &mut g), ("inv_id", &mut i)] {
            if let Some(id) = src[field].as_str() {
                if let Some(at) = e.iter().position(|x| x == id) {
                    set.push(e.remove(at));
                }
            }
        }
    }
    let mut file = json!({
        "version": crate::viewer_keys::FORMAT_VERSION,
        "switches": {"trusted_devices_mode": state["mode"] == "strict"},
        "keys": keys, "tombstones": tombstones,
        "spent": {"endorse_ids": e, "grant_ids": g, "invite_ids": i},
    });
    let people = state["snapshot"].as_array().unwrap();
    if !people.is_empty() {
        file["first_use_snapshot"] = json!({
            "taken_at": 0,
            "people": people.iter().map(|p| json!({
                "person": {"telegram_user_id": p["telegram_user_id"]}, "role": p["role"],
            })).collect::<Vec<_>>(),
        });
    }
    // The notes (§10, §10.2) and the grant token (§7, `""` for a new PC): the one format, every
    // field.
    for field in ["attempts"] {
        if let Some(v) = state
            .get(field)
            .filter(|v| v.as_array().is_some_and(|a| !a.is_empty()))
        {
            file[field] = v.clone();
        }
    }
    file["grant_token"] = state
        .get("grant_token")
        .cloned()
        .unwrap_or_else(|| "".into());
    // The PC's bindings are the list it last knew too (the rule keeps the stored list as the
    // current one): leaving it is a removal the PC learned of.
    if let Some(bindings) = state["bindings"].as_array() {
        let mut stored: Vec<Value> = bindings
            .iter()
            .map(|b| {
                json!({"telegram_user_id": b["telegram_user_id"],
                       "role": b["role"].as_str().unwrap_or("guest")})
            })
            .collect();
        stored.sort_by_key(|b| b["telegram_user_id"].as_i64());
        file["last_bindings"] = stored.into();
    }
    std::fs::write(
        dir.join(crate::viewer_keys::FILE_NAME),
        serde_json::to_vec(&file).unwrap(),
    )
    .unwrap();
}

struct Harness {
    dir: Scratch,
    trusted: Trusted,
    engine: Admission,
    confirm_token: Option<u64>,
    name: String,
    device_id: String,
    /// Sessions a `session_request` step made Pending (no offer yet): the offer step of the same
    /// id brings the request's own fields.
    requested: BTreeSet<String>,
    /// The PC's wall clock at `at_ms` 0 (`pc_clock_at_0_ms`).
    wall0: i64,
    /// The journal of the last step that had one (nested steps' events go into the offer's).
    last_journal: Vec<String>,
    /// The offer whose checks are running (its nested steps land meanwhile): not counted against
    /// the window, as in the reference (past Pending, not yet live).
    deciding: Option<String>,
    /// Sessions a removal ended (their verdicts), for an offer whose session ends while its
    /// change is queued.
    gone: BTreeMap<String, Verdict>,
}

/// The engine and the trust list as a fresh process makes them from the stored files.
fn boot(name: &str, dir: &std::path::Path, device_id: &str) -> (Trusted, Admission) {
    let store = TrustStore::open_in(dir);
    boot_store(name, store, device_id)
}

fn boot_store(name: &str, store: TrustStore, device_id: &str) -> (Trusted, Admission) {
    assert!(
        !store.is_damaged(),
        "{name}: the stored state did not load: {:?}",
        store.damage()
    );
    let notify: crate::trusted::Notify = Arc::new(|_| {});
    let (mut trusted, _view) = Trusted::new(notify);
    trusted.attach(store);
    (
        trusted,
        Admission::new(device_id.to_string(), test_verifier()),
    )
}

/// The expectation fields each step kind may carry: a field the harness does not check fails
/// the run, so a vector never passes on a rule nobody asserted.
fn known_expect(kind: &str) -> &'static [&'static str] {
    match kind {
        "offer" => &[
            "verdict",
            "detail",
            "why",
            "admit",
            "admitted",
            "ks",
            "journal",
            "warn",
            "session",
            "state_after",
            "ended_sessions",
            "during_verify",
            "during_ground_verify",
            "absent",
        ],
        "reoffer" => &["result", "verdict", "detail", "session"],
        "revoke" | "set" | "pause" => &["ended_sessions"],
        // `upgraded`: never built (a walk changes no tombstone); a vector names it only as
        // `absent`.
        "delete_tree" => &[
            "revoked",
            "upgraded",
            "refused",
            "ended_sessions",
            "state_after",
            "absent",
        ],
        "server_event" => &["sessions"],
        "remote_input" => &["accepted"],
        "pair_request" => &["viewer_key"],
        "pair_allow" => &[
            "already",
            "key_added",
            "unconfirmed",
            "rpk_stored",
            "role",
            "verdict",
            "detail",
            "warn",
            "journal",
            "second_step_required",
            "refused",
            "absent",
            "state_after",
        ],
        "binding_added" => &[
            "key_added",
            "role",
            "unconfirmed",
            "verdict",
            "detail",
            "refused",
            "warn",
            "absent",
            "state_after",
        ],
        "confirm" => &["unconfirmed", "absent", "state_after"],
        "binding_removed" => &["revoked", "ended_sessions", "state_after"],
        "remove_person" => &[
            "revoked",
            "upgraded",
            "refused",
            "ended_sessions",
            "state_after",
            "absent",
        ],
        "attempt_hide" => &["key_added", "refused", "state_after"],
        "attempt_allow" => &[
            "key_added",
            "unconfirmed",
            "refused",
            "second_step_required",
            "verdict",
            "detail",
            "warn",
            "journal",
            "absent",
            "state_after",
        ],
        "reload" => &["state_after"],
        _ => &[],
    }
}

/// `expect.absent` (the vectors' rule): every field it names must be missing from the step's
/// result — a field set at all, even to null, is present. `modeled`: the result fields this
/// harness builds for the step; an absent field outside them fails (it would pass vacuously).
fn check_absent(ctx: &str, expect: &Value, result: &Value, modeled: &[&str]) {
    let Some(names) = expect.get("absent") else {
        return;
    };
    for f in names.as_array().expect("absent: a list") {
        let f = f.as_str().expect("absent: field names");
        assert!(
            modeled.contains(&f),
            "{ctx}: absent {f}: a field this harness does not build"
        );
        assert!(
            result.get(f).is_none(),
            "{ctx}: {f} must be absent: {result}"
        );
    }
}

/// `expect[field]`, or `[]` when the vector leaves it out (none).
fn expect_or_empty(expect: &Value, field: &str) -> Value {
    expect.get(field).cloned().unwrap_or_else(|| json!([]))
}

fn tree_json(out: &crate::viewer_keys::TreeRemoval, ended: &[EndSession]) -> Value {
    json!({
        "revoked": out.removed.iter().map(|k| k.as_str()).collect::<Vec<_>>(),
        "ended_sessions": ended_json(ended),
    })
}

fn ended_json(ended: &[EndSession]) -> Value {
    Value::Array(
        ended
            .iter()
            .map(|e| json!({"session_id": e.session_id, "verdict": e.verdict.code}))
            .collect(),
    )
}

impl Harness {
    fn new(name: &str, state: &Value, steps: &[Value]) -> Self {
        Self::with(name, state, steps, 1_789_600_000_000)
    }

    fn with(name: &str, state: &Value, steps: &[Value], wall0: i64) -> Self {
        let dir = Scratch::new();
        write_state(&dir.0, state, steps);
        let device_id = state["device_id"].as_str().unwrap().to_string();
        let (mut trusted, mut engine) = boot(name, &dir.0, &device_id);
        engine.set_wall_clock(wall0);
        if let Some(store) = trusted.store_mut() {
            store.set_wall_now(wall0);
        }
        // As the agent's list sets them (`sync_game_roles`): the trust list's owners with them.
        engine.set_bindings(
            &mut trusted,
            state["bindings"].as_array().into_iter().flatten().map(|b| {
                (
                    b["telegram_user_id"].as_i64().unwrap(),
                    role(b["role"].as_str()),
                )
            }),
        );
        for b in state["nonce_batches"].as_array().unwrap() {
            let nonces = b["nonces"]
                .as_array()
                .unwrap()
                .iter()
                .map(|n| b64url_array::<NONCE_PC_LEN>(n.as_str().unwrap()).unwrap())
                .collect();
            engine.insert_nonce_batch(b["issued_at_ms"].as_u64().unwrap(), nonces);
        }
        Self {
            dir,
            trusted,
            engine,
            confirm_token: None,
            name: name.to_string(),
            device_id,
            requested: BTreeSet::new(),
            wall0,
            last_journal: Vec::new(),
            deciding: None,
            gone: BTreeMap::new(),
        }
    }

    /// The PC's wall clock at `at_ms`.
    fn wall(&self, at_ms: u64) -> i64 {
        self.wall0 + i64::try_from(at_ms).unwrap()
    }

    /// The PC restarts: the stored state is read back; sessions, Pending requests, windows, rate
    /// limits and the nonce book start afresh (§2.2: the book lives in memory only).
    fn reload(&mut self) {
        let bindings: Vec<(i64, BindingRole)> =
            self.engine.bindings.iter().map(|(u, r)| (*u, *r)).collect();
        let (mut trusted, mut engine) = boot(&self.name, &self.dir.0, &self.device_id);
        engine.set_wall_clock(self.wall0);
        if let Some(store) = trusted.store_mut() {
            store.set_wall_now(self.wall0);
        }
        engine.set_bindings(&mut trusted, bindings);
        self.trusted = trusted;
        self.engine = engine;
        self.confirm_token = None;
        self.requested.clear();
    }

    fn store(&mut self) -> &mut TrustStore {
        self.trusted.store_mut().unwrap()
    }

    /// The engine told of removed keys; the sessions it ends are noted ([`Self::gone`]).
    fn keys_removed(&mut self, key_ids: &[KeyId]) -> Vec<EndSession> {
        let ended = self.engine.keys_removed(&mut self.trusted, key_ids);
        for e in &ended {
            self.gone.insert(e.session_id.clone(), e.verdict);
        }
        ended
    }

    /// Stage, write and install synchronously, as the queue would — its stage with the trust
    /// list's own check of the bindings' rules first ([`Trusted::admit_stage_check`]).
    fn apply(&mut self, op: AdmitOp, now: i64) -> Landed {
        let checked = self.trusted.admit_stage_check(&op.op);
        let store = self.store();
        let result = match checked.and_then(|()| op.op.stage(store, now)) {
            Ok(None) => Ok(LandedOutcome::Unit),
            Ok(Some(StagedChange::Unit(s))) => match s.write() {
                Ok(w) => store
                    .install(w)
                    .map(|()| LandedOutcome::Unit)
                    .map_err(|n| n.error),
                Err(f) => {
                    let e = f.error().clone();
                    store.abandon(f);
                    Err(e)
                }
            },
            Ok(Some(StagedChange::Add(s))) => match s.write() {
                Ok(w) => store
                    .install(w)
                    .map(LandedOutcome::Added)
                    .map_err(|n| n.error),
                Err(f) => {
                    let e = f.error().clone();
                    store.abandon(f);
                    Err(e)
                }
            },
            Ok(Some(StagedChange::Recover(s))) => match s.write() {
                Ok(w) => store
                    .install(w)
                    .map(LandedOutcome::Recovered)
                    .map_err(|n| n.error),
                Err(f) => {
                    let e = f.error().clone();
                    store.abandon(f);
                    Err(e)
                }
            },
            Err(e) => Err(e),
        };
        Landed {
            ticket: op.ticket,
            slow: false,
            result,
        }
    }

    fn ctx(&self, i: usize, step: &Value) -> String {
        format!(
            "{} step {i} ({} at {})",
            self.name, step["kind"], step["at_ms"]
        )
    }

    fn check_verdict(&self, ctx: &str, expect: &Value, v: Verdict) {
        if let Some(code) = expect["verdict"].as_str() {
            assert_eq!(v.code, code, "{ctx}: verdict (detail {:?})", v.detail);
        }
        if expect.get("verdict").is_some() || expect.get("detail").is_some() {
            assert_eq!(v.detail, expect["detail"].as_str(), "{ctx}: detail");
        }
    }

    fn check_state(&mut self, ctx: &str, expect: &Value) {
        let Some(after) = expect.get("state_after") else {
            return;
        };
        let store = self.store();
        let keys: BTreeSet<String> = store
            .keys()
            .unwrap()
            .iter()
            .map(|k| k.key_id().as_str().to_string())
            .collect();
        let revoked: BTreeSet<String> = store
            .tombstones()
            .unwrap()
            .iter()
            .map(|t| t.key_id().as_str().to_string())
            .collect();
        let (e, g, i) = store.spent().unwrap();
        let spent: BTreeSet<String> = e
            .iter()
            .chain(g)
            .chain(i)
            .map(|x| x.as_str().to_string())
            .collect();
        let set = |v: &Value| -> BTreeSet<String> {
            v.as_array()
                .unwrap()
                .iter()
                .map(|x| x.as_str().unwrap().to_string())
                .collect()
        };
        assert_eq!(keys, set(&after["keys"]), "{ctx}: state_after keys");
        assert_eq!(
            revoked,
            set(&after["revoked"]),
            "{ctx}: state_after revoked"
        );
        assert_eq!(spent, set(&after["spent"]), "{ctx}: state_after spent");
        if let Some(want) = after.get("attempts") {
            let got: BTreeSet<String> = store
                .attempts()
                .iter()
                .map(|a| format!("{}:{}:{}", a.telegram_user_id, a.key_id().as_str(), a.count))
                .collect();
            let want: BTreeSet<String> = want
                .as_array()
                .unwrap()
                .iter()
                .map(|a| {
                    format!(
                        "{}:{}:{}",
                        a["telegram_user_id"],
                        a["key_id"].as_str().unwrap(),
                        a["count"]
                    )
                })
                .collect();
            assert_eq!(got, want, "{ctx}: state_after attempts");
        }
        if let Some(want) = after.get("unconfirmed") {
            let got: BTreeSet<String> = store
                .keys()
                .unwrap()
                .iter()
                .filter(|k| k.unconfirmed)
                .map(|k| k.key_id().as_str().to_string())
                .collect();
            assert_eq!(got, set(want), "{ctx}: state_after unconfirmed");
        }
        if let Some(want) = after.get("roles").and_then(Value::as_object) {
            for (id, r) in want {
                let got = store
                    .keys()
                    .unwrap()
                    .iter()
                    .find(|k| k.key_id().as_str() == id)
                    .map(|k| k.role);
                assert_eq!(got, Some(role(r.as_str())), "{ctx}: state_after roles {id}");
            }
        }
    }

    /// The steps that land while a signature is checked. The PC verifies synchronously on its
    /// main loop; its one real wait is the list's queue between the decision and the write's
    /// stage, where every rule is decided again (`plan_add`) and the landing re-reads the record
    /// and the mode. So `during_verify` (after the offer's own signature: no ground, nothing
    /// queued) lands right before the decision, and `during_ground_verify` between the decision
    /// and the queued change's stage — the states the reference re-reads after its awaits.
    /// Their results, and the journal they add.
    fn nested(&mut self, ctx: &str, step: &Value, field: &str) -> Vec<String> {
        let mut journal = Vec::new();
        {
            let Some(list) = step.get(field).and_then(Value::as_array) else {
                return journal;
            };
            let mut results = Vec::new();
            for (j, n) in list.iter().enumerate() {
                let nctx = format!("{ctx} {field}[{j}]");
                self.last_journal.clear();
                let r = match n["kind"].as_str().unwrap() {
                    "delete_tree" => self.delete_tree_result(n),
                    "binding_removed" => self.binding_removed_result(n),
                    "binding_added" => self.binding_added_result(&nctx, n),
                    _ => {
                        self.step(usize::MAX, n);
                        Value::Null
                    }
                };
                tracing::debug!(step = %nctx, result = %r, "harness: a nested step landed");
                journal.append(&mut self.last_journal);
                results.push(r);
            }
            if let Some(want) = step["expect"].get(field) {
                assert_eq!(&Value::Array(results), want, "{ctx}: {field}");
            }
        }
        journal
    }

    /// Whether the signature check `during_ground_verify` names (`during_ground_verify_of`, the
    /// grant's by default) fails, by the product's own verify over the signer the list has: the
    /// PC verifies synchronously, so a refusal at that check has no wait after it — the steps
    /// "during" it are, for the PC, steps before the decision (the reference decides on the state
    /// after its last await). A check that passes leads to the one real wait (the list's queue).
    /// Grants only: the vectors name no failing check of another ground.
    fn named_check_fails(&mut self, step: &Value) -> bool {
        use crate::viewer_keys::proof::{Grant, InviteSig};
        if step.get("during_ground_verify").is_none() {
            return false;
        }
        let named = step["during_ground_verify_of"].as_str();
        let store = self.store();
        let signer = |by: &KeyId| match store.lookup(by) {
            Lookup::Active(r) => Some(r.key.clone()),
            _ => None,
        };
        for a in step["proof"]["admit"].as_array().into_iter().flatten() {
            if a["kind"] != "grant" {
                continue;
            }
            return match named {
                Some("invite") => InviteSig::parse(&a["invite"])
                    .is_ok_and(|inv| signer(&inv.by).is_some_and(|k| !inv.verify(&k))),
                None | Some("grant") => Grant::parse(&a["grant"])
                    .is_ok_and(|g| signer(&g.by).is_some_and(|k| !g.verify(&k))),
                Some(_) => false,
            };
        }
        false
    }

    fn offer(&mut self, ctx: &str, step: &Value) {
        let early = self.named_check_fails(step);
        let mut nested_journal = self.nested(ctx, step, "during_verify");
        if early {
            tracing::debug!(
                step = %ctx,
                "harness: the named signature check fails: its nested steps land before the \
                 decision"
            );
            nested_journal.extend(self.nested(ctx, step, "during_ground_verify"));
        }
        let at = step["at_ms"].as_u64().unwrap();
        let sid = step["session_id"].as_str().unwrap();
        let req = &step["session_request"];
        if self.requested.remove(sid) {
            // Pending since its `session_request` step: the request is this step's own (with its
            // nonce and role), as the server sends it.
            self.engine.session_ended(&mut self.trusted, sid);
        }
        // The request the offer carries is answered by it at once (the reference never holds it
        // Pending): it counts against no window until the offer's checks are over. The product
        // counts it from its request on (the safe side).
        self.engine.quiet = Some(sid.to_string());
        self.engine.session_requested(
            &mut self.trusted,
            &SessionRequest {
                session_id: sid,
                telegram_user_id: req["telegram_user_id"].as_i64().unwrap(),
                role: role(req["role"].as_str()),
                first_name: None,
                username: None,
                nonce_pc: req["nonce_pc"].as_str(),
            },
        );
        let proof = step.get("proof");
        let d = self.engine.first_offer(
            &mut self.trusted,
            &FirstOffer {
                session_id: sid,
                sdp: step["sdp"].as_str().unwrap(),
                proof,
                is_bound: true,
            },
            at,
        );
        let mut journal: Vec<String> = nested_journal;
        journal.extend(d.journal.iter().map(JournalEvent::name));
        self.deciding = Some(sid.to_string());
        if !early {
            journal.extend(self.nested(ctx, step, "during_ground_verify"));
        }
        self.deciding = None;
        self.engine.quiet = None;
        self.engine.sync(&mut self.trusted);
        let mut verdict = d.verdict;
        let mut why = d.why;
        let mut admit = d.admit;
        let mut ended = Vec::new();
        // The `ks` the viewer gets: the offer's, or — for a session that waited for its write —
        // the one rebuilt from the landed result (none when the session is refused).
        let mut ks = d.ks.clone();
        let admitted = match d.outcome.clone() {
            Outcome::Admit => true,
            Outcome::Refuse => false,
            Outcome::AfterWrite(op) => {
                let landed = self.apply(*op, at as i64);
                let ld = self.engine.landed(&mut self.trusted, landed);
                if ld.why.is_some() {
                    why = ld.why;
                }
                admit = ld.ks.as_ref().and_then(|k| k.admit);
                ks.clone_from(&ld.ks);
                journal.extend(ld.journal.iter().map(JournalEvent::name));
                ended.extend(ld.end_sessions.iter().cloned());
                match ld.session.clone() {
                    Some((_, admitted, v)) => {
                        verdict = v;
                        admitted
                    }
                    // Ended while its change was queued (a removal of its key at the PC): its
                    // end's verdict is the offer's.
                    None => {
                        let gone = self
                            .gone
                            .remove(sid)
                            .unwrap_or_else(|| panic!("{ctx}: the waiting session vanished"));
                        verdict = gone;
                        false
                    }
                }
            }
        };
        // A recovery's commit ends the replaced keys' live sessions (left out when none).
        if step["expect"].is_object() {
            assert_eq!(
                ended_json(&ended),
                expect_or_empty(&step["expect"], "ended_sessions"),
                "{ctx}: ended_sessions"
            );
        }
        if let Some(w) = step["expect"].get("why") {
            assert_eq!(why, w.as_str(), "{ctx}: why");
        }
        if let Some(t) = d.touch.clone() {
            self.apply(t, at as i64);
        }
        let expect = &step["expect"];
        self.check_verdict(ctx, expect, verdict);
        if let Some(a) = expect.get("admitted") {
            assert_eq!(admitted, a.as_bool().unwrap(), "{ctx}: admitted");
        }
        if expect.get("verdict").is_some() {
            assert_eq!(admit, expect["admit"].as_str(), "{ctx}: admit");
        }
        match expect.get("ks") {
            None => {}
            Some(Value::Null) => assert!(ks.is_none(), "{ctx}: ks must be none: {ks:?}"),
            Some(want_ks) => {
                let got = ks
                    .as_ref()
                    .unwrap_or_else(|| panic!("{ctx}: no ks"))
                    .to_json();
                let mut want = want_ks.clone();
                want["t"] = "ks".into();
                assert_eq!(got, want, "{ctx}: ks");
            }
        }
        if let Some(j) = expect.get("journal") {
            let want: Vec<String> = j
                .as_array()
                .unwrap()
                .iter()
                .map(|x| x.as_str().unwrap().to_string())
                .collect();
            assert_eq!(journal, want, "{ctx}: journal");
        }
        self.last_journal = journal;
        if let Some(w) = expect.get("warn") {
            assert_eq!(d.warn, w.as_str(), "{ctx}: warn");
        }
        let mut result = json!({ "verdict": verdict.code, "admitted": admitted });
        for (f, v) in [("warn", d.warn), ("why", why), ("admit", admit)] {
            if let Some(v) = v {
                result[f] = v.into();
            }
        }
        if let Some(k) = &ks {
            result["ks"] = k.to_json();
        }
        check_absent(ctx, expect, &result, &["warn", "why", "admit", "ks"]);
        if let Some(s) = expect.get("session") {
            let (_, _, identity) = self
                .engine
                .session(sid)
                .unwrap_or_else(|| panic!("{ctx}: no session"));
            assert_eq!(
                identity.telegram_user_id,
                s["telegram_user_id"].as_i64().unwrap(),
                "{ctx}: session person"
            );
            assert_eq!(
                identity.role,
                role(s["role"].as_str()),
                "{ctx}: session role"
            );
        }
        self.check_state(ctx, expect);
    }

    /// A pairing's refusal as the vectors name it. The store's answer `StoreError::Removed` (§5,
    /// §10: an unconfirmed pairing — `pc_allow` at `binding_added`, a dirty window — lifts no
    /// removal) is pinned as the store's own code `removed`; the admission reports it as
    /// `key_revoked` (`store_fail`). That answer is read back from the store: the key's tombstone
    /// as it looks it up. Every other refusal is the admission's verdict as it stands.
    fn pair_refusal(&mut self, ctx: &str, d: &PairAllowDecision, v: Verdict) -> Verdict {
        if v != Verdict::KEY_REVOKED {
            return v;
        }
        let kid = d
            .key_id
            .clone()
            .unwrap_or_else(|| panic!("{ctx}: key_revoked without the pairing's key"));
        let removed = match self.store().lookup(&kid) {
            Lookup::Removed(t) => StoreError::Removed {
                key_id: kid.clone(),
                origin: t.origin.as_str(),
            },
            other => panic!("{ctx}: key_revoked, but the store has no tombstone: {other:?}"),
        };
        Verdict {
            code: removed.as_str(),
            detail: None,
        }
    }

    fn pair_result(&mut self, ctx: &str, step: &Value, d: PairAllowDecision) -> Value {
        let at = step["at_ms"].as_i64().unwrap();
        let expect = &step["expect"];
        let mut journal = Vec::new();
        let mut added: Option<(KeyId, bool, bool)> = None;
        if let Some(op) = d.op.clone() {
            let landed = self.apply(op, at);
            let ld = self.engine.landed(&mut self.trusted, landed);
            journal.extend(ld.journal.iter().map(JournalEvent::name));
            added = ld.pair_key;
        }
        match expect.get("key_added") {
            Some(Value::Null) => assert!(added.is_none(), "{ctx}: no key expected: {added:?}"),
            Some(k) => {
                let (id, unconfirmed, rpk) = added
                    .clone()
                    .unwrap_or_else(|| panic!("{ctx}: no key ({:?})", d.refused));
                assert_eq!(id.as_str(), k.as_str().unwrap(), "{ctx}: key_added");
                if let Some(u) = expect.get("unconfirmed") {
                    assert_eq!(unconfirmed, u.as_bool().unwrap(), "{ctx}: unconfirmed");
                }
                if let Some(r) = expect.get("rpk_stored") {
                    assert_eq!(rpk, r.as_bool().unwrap(), "{ctx}: rpk_stored");
                }
                if let Some(r) = expect.get("role") {
                    let rec_role = self
                        .store()
                        .keys()
                        .unwrap()
                        .iter()
                        .find(|x| x.key_id() == &id)
                        .unwrap()
                        .role;
                    assert_eq!(rec_role, role(r.as_str()), "{ctx}: role");
                }
            }
            None => {}
        }
        // §5: a press naming another role than the derived one — the vectors' `refused: "role"`
        // (nothing written, the request still waits).
        let role_refused = d.role_refused;
        let refused = d.refused.map(|v| self.pair_refusal(ctx, &d, v));
        assert_eq!(
            role_refused.then_some("role"),
            expect.get("refused").and_then(Value::as_str),
            "{ctx}: refused"
        );
        if let Some(code) = expect["verdict"].as_str() {
            let v = refused.unwrap_or_else(|| panic!("{ctx}: no refusal"));
            assert_eq!(v.code, code, "{ctx}: verdict");
            assert_eq!(v.detail, expect["detail"].as_str(), "{ctx}: detail");
        }
        if let Some(w) = expect.get("warn") {
            assert_eq!(d.warn, w.as_str(), "{ctx}: warn");
        }
        // §5: the owner's second step.
        if let Some(w) = expect.get("second_step_required") {
            assert_eq!(
                d.second_step_required,
                w.as_bool().unwrap(),
                "{ctx}: second_step_required"
            );
        }
        let mut result = json!({
            "key_added": added.as_ref().map(|(id, _, _)| id.as_str().to_string()),
            "journal": journal,
        });
        if let Some((_, unconfirmed, rpk)) = &added {
            result["unconfirmed"] = (*unconfirmed).into();
            result["rpk_stored"] = (*rpk).into();
        }
        if let Some(w) = d.warn {
            result["warn"] = w.into();
        }
        if let Some(v) = refused {
            result["verdict"] = v.code.into();
            if let Some(detail) = v.detail {
                result["detail"] = detail.into();
            }
        }
        if role_refused {
            result["refused"] = "role".into();
        }
        if d.second_step_required {
            result["second_step_required"] = true.into();
        }
        check_absent(
            ctx,
            expect,
            &result,
            &[
                "unconfirmed",
                "rpk_stored",
                "warn",
                "verdict",
                "detail",
                "refused",
                "second_step_required",
            ],
        );
        if let Some(j) = expect.get("journal") {
            let want: Vec<String> = j
                .as_array()
                .unwrap()
                .iter()
                .map(|x| x.as_str().unwrap().to_string())
                .collect();
            assert_eq!(journal, want, "{ctx}: journal");
        }
        self.last_journal = journal;
        self.check_state(ctx, expect);
        let mut out = json!({ "key_added": result["key_added"].clone() });
        for f in ["verdict", "detail", "refused", "warn"] {
            if let Some(v) = result.get(f) {
                out[f] = v.clone();
            }
        }
        out
    }

    /// `binding_added` (§5, §10) as the agent takes it: the binding applied first (the agent's
    /// list rule, [`Admission::note_binding`], its owners to the trust list), then a `pc_allow`
    /// key waiting for it ([`Admission::binding_added`]). Its result as a nested step names it.
    fn binding_added_result(&mut self, ctx: &str, step: &Value) -> Value {
        let uid = step["telegram_user_id"].as_i64().unwrap();
        self.engine.note_binding(
            &mut self.trusted,
            uid,
            role(step["role"].as_str().or(Some("guest"))),
        );
        let d = self.engine.binding_added(&self.trusted, uid);
        self.pair_result(ctx, step, d)
    }

    /// «Удалить» at the PC (§10.1): refused `window_unavailable` while anything counts against
    /// the trust window (the gate of `Trusted::command`, which refuses `session` then), else the
    /// key and its walk removed in one write, the removed keys' live sessions ended.
    fn delete_tree(&mut self, ctx: &str, step: &Value) {
        let got = self.delete_tree_result(step);
        self.compare(ctx, step, &got, &["revoked", "upgraded"]);
    }

    /// The trust window's gate (`Trusted::command` refuses `session` then): anything that counts.
    fn window_closed(&self) -> bool {
        match &self.deciding {
            Some(sid) => self.engine.counting_except(sid) > 0,
            None => self.trusted.counting() > 0,
        }
    }

    /// The write of memory a removal's op stages (`stage_flush`, written and installed at once):
    /// what the step decided in memory goes to the disk, as the queue's write would take it.
    fn write_memory(&mut self) {
        self.store().flush().unwrap();
    }

    /// As the product decides «Удалить» at the press ([`TrustStore::deny_tree_now`]), then its
    /// write of memory.
    fn delete_tree_result(&mut self, step: &Value) -> Value {
        if self.window_closed() {
            return json!({"revoked": [], "refused": "window_unavailable"});
        }
        // The PC's clock at the step: a removed record's `removed_at` (§10).
        let at = self.wall(step["at_ms"].as_u64().unwrap());
        let k = kid(step["key_id"].as_str().unwrap());
        let out = match self.store().deny_tree_now(&k, at) {
            Ok(out) => out,
            Err(e) => {
                let refusal = crate::trusted::TrustedError::of(&e);
                return json!({"revoked": [], "refused": refusal.as_str()});
            }
        };
        self.write_memory();
        let ended = self.keys_removed(&out.removed);
        tree_json(&out, &ended)
    }

    /// `binding_removed` (§10), as the product decides it (`Admission::remove_person` with origin
    /// `server`): its guards ([`super::removal_touches`]: not the owner, not a holder of a working
    /// owner-role key, a person the PC knows), their guest-role keys denied and carried
    /// ([`TrustStore::deny_guest_keys_now`], owner-role keys stay; the shared step with them), then
    /// the write of memory — the revoked keys' sessions end.
    ///
    /// The product's handler then runs the binding list's rule ([`TrustStore::bring_to_rule`]);
    /// this step does not (the stored list is noted as the rule notes it), so the vectors pin the
    /// explicit removal alone, not what the rule after it changes.
    fn binding_removed_result(&mut self, step: &Value) -> Value {
        // The PC's clock at the step: a removed record's `removed_at` (§10).
        let at = self.wall(step["at_ms"].as_u64().unwrap());
        let uid = step["telegram_user_id"].as_i64().unwrap();
        let was = self.engine.forget_binding(&mut self.trusted, uid);
        // Not touched (the owner by binding at the message, a working owner-role key, a person
        // the PC does not know): no rule at this message either, the stored list keeps them.
        let touched = super::removal_touches(self.store(), uid, was, Removal::Server);
        let revoked = if touched {
            self.store()
                .deny_guest_keys_now(uid, Removal::Server, at)
                .unwrap()
                .0
        } else {
            Vec::new()
        };
        if touched {
            self.note_bindings();
        }
        self.write_memory();
        let ended = self.keys_removed(&revoked);
        json!({
            "revoked": revoked.iter().map(|k| k.as_str()).collect::<Vec<_>>(),
            "ended_sessions": ended_json(&ended),
        })
    }

    /// «Удалить человека» at the PC (§10.2), decided as the press decides it
    /// ([`crate::trusted::press_remove_person`]: its owner guard, the walk denied),
    /// then its write of memory. The latest known list's owner guard is the orchestrator's state
    /// (`bound_owners`, the stored list before `agent_ready`); the vectors bind through the
    /// server's bindings alone, which the press reads as `bound`.
    fn remove_person_result(&mut self, step: &Value) -> Value {
        if self.window_closed() {
            return json!({"revoked": [], "refused": "window_unavailable"});
        }
        // The PC's clock at the step: a removed record's `removed_at` (§10).
        let at = self.wall(step["at_ms"].as_u64().unwrap());
        let uid = step["telegram_user_id"].as_i64().unwrap();
        let bound = self.engine.bound_role(uid);
        let decided = crate::trusted::press_remove_person(self.store(), uid, bound, false, at);
        let out = match decided {
            Ok(out) => out,
            Err(e) => return json!({"revoked": [], "refused": e.as_str()}),
        };
        self.write_memory();
        let ended = self.keys_removed(&out.removed);
        tree_json(&out, &ended)
    }

    /// «Разрешить» / «Скрыть» at an attempt (§10.2).
    fn attempt_result(&mut self, step: &Value) -> Value {
        if self.window_closed() {
            return json!({"key_added": null, "refused": "window_unavailable"});
        }
        let at = step["at_ms"].as_u64().unwrap();
        let uid = step["telegram_user_id"].as_i64().unwrap();
        let k = kid(step["key_id"].as_str().unwrap());
        let Some(a) = self.store().attempt(uid, &k).cloned() else {
            return json!({ "key_added": null });
        };
        if step["kind"] == "attempt_hide" {
            self.store().drop_attempt(uid, &k);
            self.store().flush().unwrap();
            return json!({ "key_added": null });
        }
        // As the press decides it ([`crate::trusted::attempt_allow_check`]): the role the press
        // names against the derived one, the second step for the owner.
        let owner_here = self.trusted.owner_on_pc(uid);
        let pressed = role(step["role"].as_str());
        let mut out = json!({});
        let checked = crate::trusted::attempt_allow_check(
            self.store(),
            uid,
            &k,
            step["second_step"] == true,
            (owner_here, pressed),
        );
        match checked {
            Ok(()) => {}
            Err(crate::trusted::TrustedError::SecondStep) => {
                out["key_added"] = Value::Null;
                out["second_step_required"] = true.into();
                return out;
            }
            Err(e) => {
                out["key_added"] = Value::Null;
                out["refused"] = e.as_str().into();
                return out;
            }
        }
        // The role it gives, as its stage reads it ([`crate::trusted::Trusted::owner_on_pc`]).
        let role = if owner_here {
            BindingRole::Owner
        } else {
            BindingRole::Guest
        };
        // As its stage decides (`tainted`): a session since the dialog opened writes nothing, in
        // both modes — the vectors' `key_unconfirmed`.
        if self
            .confirm_token
            .is_some_and(|t| !self.trusted.window_clean(t))
        {
            out["key_added"] = Value::Null;
            out["verdict"] = "key_unconfirmed".into();
            out["journal"] = json!([]);
            return out;
        }
        let added = self.store().add(
            NewKey {
                key: a.key.clone(),
                rpk: a.rpk.clone(),
                kind: a.kind.clone(),
                platform: a.platform.clone(),
            },
            Ground::Pair {
                person: Person {
                    telegram_user_id: uid,
                    first_name: None,
                    username: None,
                },
                role,
                unconfirmed: false,
            },
            at as i64,
        );
        match added {
            Ok(o) => {
                out["key_added"] = o.key_id.as_str().into();
                out["unconfirmed"] = o.unconfirmed.into();
                out["journal"] = json!(["key_added:pair"]);
                self.last_journal = vec!["key_added:pair".into()];
            }
            Err(StoreError::Full(_)) => {
                out["key_added"] = Value::Null;
                out["verdict"] = "admit_refused".into();
                out["detail"] = "limit".into();
                out["journal"] = json!([]);
            }
            // §10.2: the key is at another person: nothing written, the attempt stays.
            Err(StoreError::OtherPerson(_)) => {
                out["key_added"] = Value::Null;
                out["warn"] = "key_other_person".into();
            }
            Err(e) => panic!("attempt_allow: {e}"),
        }
        out
    }

    /// Compare a step's result with its `expect` (every field but `state_after`; `sets` as sets),
    /// then the state.
    fn compare(&mut self, ctx: &str, step: &Value, got: &Value, sets: &[&str]) {
        let expect = &step["expect"];
        let Some(fields) = expect.as_object() else {
            return;
        };
        let as_set = |v: &Value| -> BTreeSet<String> {
            v.as_array()
                .into_iter()
                .flatten()
                .map(|x| x.as_str().unwrap().to_string())
                .collect()
        };
        for (f, want) in fields {
            // `grant_token` is the step's, compared around it ([`Self::step`]).
            if f == "state_after" || f == "grant_token" || f == "absent" {
                continue;
            }
            let have = got.get(f).cloned().unwrap_or(Value::Null);
            if sets.contains(&f.as_str()) {
                assert_eq!(as_set(&have), as_set(want), "{ctx}: {f}");
            } else {
                assert_eq!(&have, want, "{ctx}: {f}");
            }
        }
        let kind = step["kind"].as_str().unwrap_or("");
        check_absent(ctx, expect, got, known_expect(kind));
        // A result field the vector leaves out must be one it may leave out (none or empty). The
        // reference compares one way (listed fields only); stricter here.
        if let Some(o) = got.as_object() {
            for (f, v) in o {
                if !fields.contains_key(f) {
                    let empty = v.is_null()
                        || v.as_array().is_some_and(Vec::is_empty)
                        || matches!(f.as_str(), "journal" | "unconfirmed");
                    assert!(empty, "{ctx}: {f} = {v} not expected");
                }
            }
        }
        self.check_state(ctx, expect);
    }

    fn step(&mut self, i: usize, step: &Value) {
        let ctx = self.ctx(i, step);
        let at = step["at_ms"].as_u64().unwrap();
        let expect = &step["expect"];
        let kind = step["kind"].as_str().unwrap();
        if let Some(fields) = expect.as_object() {
            for f in fields.keys() {
                assert!(
                    f == "grant_token" || known_expect(kind).contains(&f.as_str()),
                    "{ctx}: an expectation the harness does not check: {f}"
                );
            }
        }
        // §10.2: the list reads the attempts' age against the PC's clock (no prune here,
        // the store's own rule) — the vectors' clock at this step.
        let wall = self.wall(at);
        if let Some(store) = self.trusted.store_mut() {
            store.set_wall_now(wall);
        }
        // §7: whether the step replaced the grant token (its value is never named), the steps
        // that landed during it included.
        let token_before = self.grant_token();
        let bound_before = self.engine.bindings.clone();
        self.step_kind(&ctx, step);
        // `binding_removed` runs the rule itself, only when it touched the person.
        if self.engine.bindings != bound_before && step["kind"] != "binding_removed" {
            self.note_bindings();
        }
        if let Some(want) = expect.get("grant_token").and_then(Value::as_str) {
            let got = if self.grant_token() == token_before {
                "kept"
            } else {
                "rotated"
            };
            assert_eq!(got, want, "{ctx}: grant_token");
        }
    }

    /// The PC's grant token now (`None` while the list is damaged or absent).
    fn grant_token(&self) -> Option<GrantToken> {
        self.trusted.store().and_then(TrustStore::grant_token)
    }

    /// The stored last binding list kept as the current one, as the binding list's rule keeps it
    /// after each binding message (`TrustStore::note_last_bindings`: a person leaving it is a
    /// removal the PC learned of), and written as the rule's write would be (a write in flight
    /// carries it later).
    fn note_bindings(&mut self) {
        let list: Vec<KnownBinding> = self
            .engine
            .bindings
            .iter()
            .map(|(u, r)| KnownBinding {
                telegram_user_id: *u,
                role: *r,
            })
            .collect();
        let Some(store) = self.trusted.store_mut() else {
            return;
        };
        if store.note_last_bindings(list) {
            let _ = store.flush();
        }
    }

    /// One step of its kind ([`Self::step`] around it).
    fn step_kind(&mut self, ctx: &str, step: &Value) {
        let ctx = ctx.to_string();
        let at = step["at_ms"].as_u64().unwrap();
        let expect = &step["expect"];
        let sid = step["session_id"].as_str().unwrap_or("");
        let kind = step["kind"].as_str().unwrap();
        let wall = self.wall(at);
        match kind {
            "binding_removed" => {
                let got = self.binding_removed_result(step);
                self.compare(&ctx, step, &got, &[]);
            }
            "remove_person" => {
                let got = self.remove_person_result(step);
                self.compare(&ctx, step, &got, &["upgraded"]);
            }
            "attempt_allow" | "attempt_hide" => {
                let got = self.attempt_result(step);
                self.compare(&ctx, step, &got, &[]);
            }
            "offer" => self.offer(&ctx, step),
            "reoffer" => {
                // The orchestrator routes an offer to the re-offer check only for a session that
                // had its first offer (`offered`; agent.rs: live or offered). A session that is
                // gone — ended, or never requested — is `no_session`; one still Pending (its
                // request, no offer yet) has this offer decided as its first, as in the product:
                // admitted → `continue`, refused → `ended` with its verdict. Either way the step's
                // common checks (`verdict`/`detail`, `session`) follow.
                if self.engine.offered(sid) {
                    let r =
                        self.engine
                            .reoffer(sid, step["sdp"].as_str().unwrap(), step.get("proof"));
                    match (expect["result"].as_str().unwrap(), r) {
                        ("continue", Reoffer::Continue) => {}
                        ("ended", Reoffer::End(v)) => {
                            self.check_verdict(&ctx, expect, v);
                            self.engine.session_ended(&mut self.trusted, sid);
                        }
                        (want, got) => panic!("{ctx}: re-offer {want} but {got:?}"),
                    }
                } else {
                    if self.engine.session(sid).is_none() {
                        assert_eq!(expect["result"], "no_session", "{ctx}: the session is gone");
                        return;
                    }
                    self.requested.remove(sid);
                    let d = self.engine.first_offer(
                        &mut self.trusted,
                        &FirstOffer {
                            session_id: sid,
                            sdp: step["sdp"].as_str().unwrap(),
                            proof: step.get("proof"),
                            is_bound: true,
                        },
                        at,
                    );
                    let (admitted, verdict) = match d.outcome.clone() {
                        Outcome::Admit => (true, d.verdict),
                        Outcome::Refuse => (false, d.verdict),
                        Outcome::AfterWrite(op) => {
                            let landed = self.apply(*op, at as i64);
                            let ld = self.engine.landed(&mut self.trusted, landed);
                            let (_, admitted, v) = ld.session.clone().unwrap();
                            (admitted, v)
                        }
                    };
                    if let Some(t) = d.touch.clone() {
                        self.apply(t, at as i64);
                    }
                    match (expect["result"].as_str().unwrap(), admitted) {
                        ("continue", true) | ("ended", false) => {
                            self.check_verdict(&ctx, expect, verdict);
                        }
                        (want, _) => panic!(
                            "{ctx}: the offer of a Pending session is its first: {want}, but \
                             admitted {admitted} ({verdict:?})"
                        ),
                    }
                }
                if let Some(s) = expect.get("session") {
                    let (signed, verdict, _) = self
                        .engine
                        .session(sid)
                        .unwrap_or_else(|| panic!("{ctx}: no session"));
                    assert_eq!(signed, s["signed"].as_bool().unwrap(), "{ctx}: signed");
                    assert_eq!(
                        verdict.code,
                        s["verdict"].as_str().unwrap(),
                        "{ctx}: verdict"
                    );
                }
            }
            "end" => {
                self.requested.remove(sid);
                self.engine.session_ended(&mut self.trusted, sid);
            }
            "session_request" => {
                // Pending, with no offer yet (and no nonce: the vector's request names none).
                let d = self.engine.session_requested(
                    &mut self.trusted,
                    &SessionRequest {
                        session_id: sid,
                        telegram_user_id: step["telegram_user_id"].as_i64().unwrap(),
                        role: role(step["role"].as_str()),
                        first_name: None,
                        username: None,
                        nonce_pc: None,
                    },
                );
                assert!(!d.ignored, "{ctx}: a new session request");
                self.requested.insert(sid.to_string());
            }
            "pause" => {
                // The kill switch (`agent::kill_switch`): every live session ends, then every
                // Pending request, `kill_switch`; the orchestrator tells the admission of each.
                let mut live = Vec::new();
                let mut pending = Vec::new();
                for (id, s) in &self.engine.sessions {
                    if s.live {
                        live.push(id.clone());
                    } else {
                        pending.push(id.clone());
                    }
                }
                live.sort();
                pending.sort();
                let ended: Vec<EndSession> = live
                    .into_iter()
                    .chain(pending)
                    .map(|session_id| EndSession {
                        session_id,
                        verdict: Verdict::of("kill_switch"),
                    })
                    .collect();
                for e in &ended {
                    self.engine.session_ended(&mut self.trusted, &e.session_id);
                }
                self.requested.clear();
                if let Some(want) = expect.get("ended_sessions") {
                    assert_eq!(&ended_json(&ended), want, "{ctx}: ended_sessions");
                }
            }
            "reload" => {
                self.reload();
                if let Some(store) = self.trusted.store_mut() {
                    store.set_wall_now(wall);
                }
                self.check_state(&ctx, expect);
            }
            "revoke" => {
                let k = kid(step["key_id"].as_str().unwrap());
                let by = if step["origin"] == "server" {
                    Removal::Server
                } else {
                    Removal::Pc
                };
                self.store().remove(&k, by, wall).unwrap();
                let ended = self.keys_removed(&[k]);
                if let Some(want) = expect.get("ended_sessions") {
                    assert_eq!(&ended_json(&ended), want, "{ctx}: ended_sessions");
                }
            }
            "delete_tree" => self.delete_tree(&ctx, step),
            "set" => {
                let strict = step["mode"] == "strict";
                let was = self.store().switches().unwrap().trusted_devices_mode;
                self.store().set_trusted_devices_mode(strict).unwrap();
                // The orchestrator tells the admission of a change only (`agent::sweep_keys`).
                let ended = if was == strict {
                    Vec::new()
                } else {
                    self.engine.mode_changed(&mut self.trusted, strict)
                };
                if let Some(want) = expect.get("ended_sessions") {
                    assert_eq!(&ended_json(&ended), want, "{ctx}: ended_sessions");
                }
            }
            "sleep_resume" => {
                self.engine.resumed_from_sleep(at);
            }
            "nonce_batch" => {
                let nonces = step["nonces"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|n| b64url_array::<NONCE_PC_LEN>(n.as_str().unwrap()).unwrap())
                    .collect();
                self.engine.insert_nonce_batch(at, nonces);
            }
            "server_event" => {
                assert_eq!(step["event"], "owner_changed", "{ctx}");
                // `null`: the PC has no owner now.
                let roles = self
                    .engine
                    .owner_changed(&mut self.trusted, step["telegram_user_id"].as_i64());
                let got: serde_json::Map<String, Value> = roles
                    .into_iter()
                    .map(|(id, r)| (id, r.as_str().into()))
                    .collect();
                // A vector may say only what the step did to the token (`grant_token`).
                if let Some(want) = expect.get("sessions") {
                    assert_eq!(&Value::Object(got), want, "{ctx}: sessions");
                }
            }
            "remote_input" => {
                let control = match step["target"].as_str().unwrap() {
                    "pairing_panel" => TrustControl::PairingPanel,
                    "pair_allow" => TrustControl::PairAllow,
                    "strict_toggle" => TrustControl::StrictToggle,
                    "list_edit" => TrustControl::ListEdit,
                    t => panic!("{ctx}: target {t}"),
                };
                assert_eq!(
                    self.engine.remote_input(sid, control),
                    expect["accepted"].as_bool().unwrap(),
                    "{ctx}: accepted"
                );
            }
            "pairing_panel" => {
                let open = step["open"].as_bool().unwrap();
                self.engine.pairing_panel(&self.trusted, open);
            }
            "confirm_window" => {
                self.confirm_token = step["open"]
                    .as_bool()
                    .unwrap()
                    .then(|| self.trusted.window_token());
            }
            "pair_request" => {
                let got = self.engine.pair_request(&PairRequest {
                    request_id: step["request_id"].as_str().unwrap(),
                    telegram_user_id: step["telegram_user_id"].as_i64().unwrap(),
                    first_name: step["first_name"].as_str(),
                    username: step["username"].as_str(),
                    viewer_key: step.get("viewer_key").filter(|v| !v.is_null()),
                });
                assert_eq!(
                    got.as_str(),
                    expect["viewer_key"].as_str().unwrap(),
                    "{ctx}: viewer_key"
                );
            }
            "pair_allow" => {
                let id = step["request_id"].as_str().unwrap();
                let (pressed, via) = (role(step["role"].as_str()), step["via"] == "pc_allow");
                // The vectors' `already` (works | waiting): the person's own listed key, nothing
                // written — the product's one reading of the press ([`Admission::pair_plan`]),
                // and the press then wrote, refused and warned nothing.
                let plan = self.engine.pair_plan(&self.trusted, id, pressed, via);
                let d = self.engine.pair_allow(
                    &self.trusted,
                    id,
                    None,
                    pressed,
                    via,
                    step["second_step"] == true,
                );
                let quiet = d.op.is_none()
                    && d.refused.is_none()
                    && d.warn.is_none()
                    && !d.second_step_required
                    && !d.role_refused;
                let already = match plan {
                    Some(PairPlan::Already { works }) if quiet => {
                        Some(if works { "works" } else { "waiting" })
                    }
                    _ => None,
                };
                assert_eq!(
                    already,
                    expect.get("already").and_then(Value::as_str),
                    "{ctx}: already"
                );
                self.pair_result(&ctx, step, d);
            }
            "binding_added" => {
                self.binding_added_result(&ctx, step);
            }
            "confirm" => {
                let k = kid(step["key_id"].as_str().unwrap());
                // §10.1: «Подтвердить» is one press, attempts or not: no second step asked.
                check_absent(&ctx, expect, &json!({}), &["second_step_required"]);
                if self
                    .confirm_token
                    .is_some_and(|t| self.trusted.window_clean(t))
                {
                    self.store().confirm(&k).unwrap();
                }
                let unconfirmed = self
                    .store()
                    .keys()
                    .unwrap()
                    .iter()
                    .find(|r| r.key_id() == &k)
                    .unwrap()
                    .unconfirmed;
                assert_eq!(
                    unconfirmed,
                    expect["unconfirmed"].as_bool().unwrap(),
                    "{ctx}: unconfirmed"
                );
                self.check_state(&ctx, expect);
            }
            other => panic!("{ctx}: unknown step kind {other}"),
        }
    }
}

#[test]
fn scenarios_json_all_pass() {
    let v = load("scenarios.json");
    assert_eq!(v["nonce_ttl_ms"], 180_000);
    assert_eq!(v["nonce_book_keep_ms"], 360_000);
    assert_eq!(v["verify_rate_per_s"], VERIFY_RATE_PER_S);
    let wall0 = v["pc_clock_at_0_ms"].as_i64().unwrap();
    let scenarios = v["scenarios"].as_array().unwrap();
    assert_eq!(scenarios.len(), 181);
    let mut failed = Vec::new();
    for s in scenarios {
        let name = s["name"].as_str().unwrap();
        let steps = s["steps"].as_array().unwrap();
        let run = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            if let Some(want) = s.get("expect_initial") {
                // A damaged initial store: reading it is refused so, and there are no steps.
                assert!(steps.is_empty(), "{name}: steps after a damaged store");
                let dir = Scratch::new();
                write_state(&dir.0, &s["initial"], steps);
                let store = TrustStore::open_in(&dir.0);
                let damage = store
                    .damage()
                    .unwrap_or_else(|| panic!("{name}: the store loaded"));
                assert_eq!(want["verdict"], "key_list_damaged", "{name}");
                assert_eq!(want["detail"], "read_failed", "{name}");
                // What the product's own reading said, by the vector's `why`.
                match want["why"].as_str() {
                    Some("ground_not_spent") => assert!(
                        damage
                            .to_string()
                            .contains("its ground is not among the spent"),
                        "{name}: {damage}"
                    ),
                    // The file's `at` is the spec's `removed_at`, a required field: the parser
                    // refuses the file (its detail names where, never serde's message). The same
                    // state with every removed record dated reads: the missing time is the damage.
                    Some("removed_at") => {
                        assert_eq!(
                            damage.kind,
                            crate::viewer_keys::DamageKind::NotParsable,
                            "{name}: {damage}"
                        );
                        let mut dated = s["initial"].clone();
                        for t in dated["revoked"].as_array_mut().unwrap() {
                            t["removed_at"] = wall0.into();
                        }
                        let dir = Scratch::new();
                        write_state(&dir.0, &dated, steps);
                        let control = TrustStore::open_in(&dir.0);
                        assert!(
                            control.damage().is_none(),
                            "{name}: dated, it reads: {:?}",
                            control.damage()
                        );
                    }
                    other => panic!("{name}: a damage the harness does not know: {other:?}"),
                }
                return;
            }
            let mut h = Harness::with(name, &s["initial"], steps, wall0);
            for (i, step) in steps.iter().enumerate() {
                h.step(i, step);
            }
        }));
        if let Err(e) = run {
            let msg = e
                .downcast_ref::<String>()
                .cloned()
                .or_else(|| e.downcast_ref::<&str>().map(|s| (*s).to_string()))
                .unwrap_or_default();
            if known_conflict(name, &msg) {
                tracing::warn!(
                    scenario = name,
                    "known conflict: the store refuses the state"
                );
                continue;
            }
            failed.push(format!("{name}: {msg}"));
        } else {
            assert!(
                !STORE_REFUSES_STATE.contains(&name),
                "{name} passes now: drop it from STORE_REFUSES_STATE"
            );
        }
    }
    assert!(
        failed.is_empty(),
        "{} of {} scenarios failed:\n{}",
        failed.len(),
        scenarios.len(),
        failed.join("\n")
    );
}

/// A re-offer step of a session still Pending (requested, not offered) is
/// decided as its first offer, as the orchestrator does — not `no_session`, which only a session
/// that is gone gets.
#[test]
fn a_reoffer_of_a_pending_session_is_its_first_offer() {
    let v = load("scenarios.json");
    let scenarios = v["scenarios"].as_array().unwrap();
    let base = scenarios
        .iter()
        .find(|s| s["name"] == "pause_ends_pending_request")
        .unwrap();
    let sdp = scenarios
        .iter()
        .flat_map(|s| s["steps"].as_array().unwrap())
        .find_map(|st| st["sdp"].as_str())
        .unwrap()
        .to_string();
    let mut initial = base["initial"].clone();
    initial["mode"] = "strict".into();
    let sid = "00000000-0000-4000-8000-000000000001";
    let steps_with = |result: &str, end_first: bool| -> Vec<Value> {
        let mut steps = vec![json!({
            "at_ms": 1000, "kind": "session_request", "session_id": sid,
            "telegram_user_id": 1001
        })];
        if end_first {
            steps.push(json!({"at_ms": 1050, "kind": "end", "session_id": sid}));
        }
        let mut expect = json!({ "result": result });
        if result == "ended" {
            // The request named no nonce of the PC's.
            expect["verdict"] = "nonce_stale".into();
            expect["detail"] = "no_nonce".into();
        }
        steps.push(json!({
            "at_ms": 1100, "kind": "reoffer", "session_id": sid, "sdp": sdp, "expect": expect
        }));
        steps
    };
    let run = |steps: &[Value]| {
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut h = Harness::new("pending_reoffer", &initial, steps);
            for (i, step) in steps.iter().enumerate() {
                h.step(i, step);
            }
        }))
        .is_ok()
    };
    // Pending: decided as its first offer (its request had no nonce: `nonce_stale:no_nonce`).
    assert!(
        run(&steps_with("ended", false)),
        "a Pending session's offer is its first"
    );
    assert!(
        !run(&steps_with("no_session", false)),
        "a Pending session is not gone"
    );
    // Gone (its request ended): `no_session`.
    assert!(
        run(&steps_with("no_session", true)),
        "an ended session is gone"
    );
    assert!(!run(&steps_with("ended", true)));
    // The step's common checks run on that path too. Observe mode admits
    // the unsigned offer; a `session` expectation is checked against it.
    let mut observe = initial.clone();
    observe["mode"] = "observe".into();
    let with_session = |session: Value| -> Vec<Value> {
        vec![
            json!({
                "at_ms": 1000, "kind": "session_request", "session_id": sid,
                "telegram_user_id": 1001
            }),
            json!({
                "at_ms": 1100, "kind": "reoffer", "session_id": sid, "sdp": sdp,
                "expect": {"result": "continue", "session": session}
            }),
        ]
    };
    let run_observe = |steps: &[Value]| {
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut h = Harness::new("pending_reoffer", &observe, steps);
            for (i, step) in steps.iter().enumerate() {
                h.step(i, step);
            }
        }))
        .is_ok()
    };
    assert!(run_observe(&with_session(
        json!({"signed": false, "verdict": "unsigned"})
    )));
    assert!(
        !run_observe(&with_session(
            json!({"signed": true, "verdict": "unsigned"})
        )),
        "a signed expectation fails against an unsigned admission"
    );
    assert!(!run_observe(&with_session(
        json!({"signed": false, "verdict": "signed"})
    )));
}

/// The per-ground case files: each case is one first offer on a PC state.
fn run_cases(file: &str) {
    let v = load(file);
    let mut failed = Vec::new();
    for c in v["cases"].as_array().unwrap() {
        let name = format!("{file}:{}", c["name"].as_str().unwrap());
        let mut step = c["step"].clone();
        step["expect"] = c["expect"].clone();
        let run = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut h = Harness::new(&name, &c["state"], std::slice::from_ref(&step));
            h.step(0, &step);
            // A recovery's replaced records and the new record's role.
            if let Some(replaced) = c.get("replaced") {
                let tombs: BTreeSet<String> = h
                    .store()
                    .tombstones()
                    .unwrap()
                    .iter()
                    .map(|t| t.key_id().as_str().to_string())
                    .collect();
                for r in replaced.as_array().unwrap() {
                    assert!(tombs.contains(r.as_str().unwrap()), "{name}: replaced {r}");
                }
            }
            if let Some(r) = c["new_role"].as_str() {
                let new_id = kid(c["step"]["proof"]["key_id"].as_str().unwrap());
                let rec = h
                    .store()
                    .keys()
                    .unwrap()
                    .iter()
                    .find(|k| k.key_id() == &new_id)
                    .cloned()
                    .unwrap();
                assert_eq!(rec.role, role(Some(r)), "{name}: new_role");
            }
        }));
        if let Err(e) = run {
            let msg = e
                .downcast_ref::<String>()
                .cloned()
                .or_else(|| e.downcast_ref::<&str>().map(|s| (*s).to_string()))
                .unwrap_or_default();
            if known_conflict(&name, &msg) {
                continue;
            }
            failed.push(format!("{name}: {msg}"));
        } else {
            assert!(
                !STORE_REFUSES_STATE.contains(&name.as_str()),
                "{name} passes now: drop it from STORE_REFUSES_STATE"
            );
        }
    }
    assert!(
        failed.is_empty(),
        "{} failed:\n{}",
        failed.len(),
        failed.join("\n")
    );
}

#[test]
fn endorse_json_cases() {
    run_cases("endorse.json");
}

#[test]
fn grant_json_cases() {
    run_cases("grant.json");
}

/// §7: the bytes a grant is signed over are the vectors' `grant_message_hex` — the domain
/// `AFKLINK-GRANT-V2`, the token framed between `grant_id` and `issued_at` (`""` as `LP("")`).
#[test]
fn grant_message_bytes_are_the_vectors() {
    use crate::viewer_keys::proof::Grant;
    let v = load("grant.json");
    let mut checked = 0;
    for c in v["cases"].as_array().unwrap() {
        let Some(want) = c["grant_message_hex"].as_str() else {
            continue;
        };
        let name = c["name"].as_str().unwrap();
        let entry = c["step"]["proof"]["admit"]
            .as_array()
            .unwrap()
            .iter()
            .find(|a| a["kind"] == "grant")
            .unwrap();
        let g = Grant::parse(&entry["grant"]).unwrap();
        let m = grant_message(&GrantFields {
            device_id: &g.device_id,
            key_id: &g.key_id,
            telegram_user_id: g.telegram_user_id,
            name: g.name.as_deref(),
            username: g.username.as_deref(),
            inv_id: g.inv_id.as_ref(),
            grant_id: &g.grant_id,
            grant_token: &g.grant_token,
            issued_at: g.issued_at,
            by: &g.by,
        });
        assert_eq!(m, hex(want), "{name}");
        checked += 1;
    }
    assert!(checked >= 4, "{checked} grant messages");
}

#[test]
fn recover_json_cases() {
    run_cases("recover.json");
}

#[test]
fn first_use_json_cases() {
    run_cases("first-use.json");
}

/// Vector states the trust store refuses to load, if any (none: two people with one recovery key
/// are not damage). A listed case must fail exactly so.
const STORE_REFUSES_STATE: &[&str] = &[];

fn known_conflict(name: &str, msg: &str) -> bool {
    STORE_REFUSES_STATE.contains(&name)
        && msg.contains("its recovery key is another person's key's too")
}

fn is_ok(c: &Value) -> bool {
    c["expect"] == "ok"
}

#[test]
fn offer_proof_json_cases() {
    let v = load("offer-proof.json");
    for c in v["cases"].as_array().unwrap() {
        let name = c["name"].as_str().unwrap();
        let spki = b64url_exact(c["spki"].as_str().unwrap(), crate::viewer_keys::SPKI_LEN).unwrap();
        let key = ViewerKey::from_spki(&spki).unwrap();
        let fp = hex32(c["fp_viewer_hex"].as_str().unwrap());
        let sid = c["session_id"].as_str().unwrap();
        let dev = c["device_id"].as_str().unwrap();
        let got: Result<(), (&str, &str)> = match OfferProof::parse(&c["proof"]) {
            Err(why) => Err(("malformed", why)),
            Ok(p) if key.key_id() != &p.key_id => Err(("key_mismatch", "key_id")),
            Ok(p) => {
                if name == "main" {
                    let m = offer_message(sid, dev, &p.key_id, &p.nonce_pc, &fp);
                    assert_eq!(m, hex(c["message_hex"].as_str().unwrap()), "{name}: m");
                }
                if p.verify(&key, sid, dev, &fp) {
                    Ok(())
                } else {
                    Err(("bad_sig", "signature"))
                }
            }
        };
        if is_ok(c) {
            assert_eq!(got, Ok(()), "{name}");
        } else {
            let (detail, why) = got.expect_err(name);
            assert_eq!(
                detail,
                c["expect"]["detail"].as_str().unwrap(),
                "{name}: detail"
            );
            assert_eq!(why, c["why"].as_str().unwrap(), "{name}: why");
        }
    }
}

#[test]
fn key_reg_json_cases() {
    let v = load("key-reg.json");
    for c in v["cases"].as_array().unwrap() {
        let name = c["name"].as_str().unwrap();
        match KeyReg::parse_verify(&c["key_reg"]) {
            Ok(r) => {
                assert!(is_ok(c), "{name}: accepted, expected {}", c["expect"]);
                assert_eq!(
                    r.key.key_id().as_str(),
                    c["key_id"].as_str().unwrap(),
                    "{name}"
                );
                let shown = |known: bool, s: &str| {
                    if known {
                        s.to_string()
                    } else {
                        "unknown".into()
                    }
                };
                assert_eq!(
                    shown(r.kind.is_known(), r.kind.as_str()),
                    c["display"]["kind"].as_str().unwrap(),
                    "{name}: display kind"
                );
                assert_eq!(
                    shown(r.platform.is_known(), r.platform.as_str()),
                    c["display"]["platform"].as_str().unwrap(),
                    "{name}: display platform"
                );
            }
            Err(why) => {
                assert!(!is_ok(c), "{name}: refused ({why})");
                assert_eq!(c["expect"]["detail"], "key_reg_bad", "{name}");
                assert_eq!(why, c["why"].as_str().unwrap(), "{name}: why");
            }
        }
    }
}

#[test]
fn sdp_fingerprint_json_cases() {
    let v = load("sdp-fingerprint.json");
    for c in v["cases"].as_array().unwrap() {
        let name = c["name"].as_str().unwrap();
        match crate::viewer_keys::sdp::viewer_fingerprint(c["sdp"].as_str().unwrap()) {
            Ok(fp) => {
                assert!(is_ok(c), "{name}: accepted");
                assert_eq!(
                    fp.to_vec(),
                    hex(c["fp_viewer_hex"].as_str().unwrap()),
                    "{name}"
                );
            }
            Err(e) => {
                assert!(!is_ok(c), "{name}: refused {e:?}");
                assert_eq!(e.as_str(), c["why"].as_str().unwrap(), "{name}: why");
            }
        }
    }
}

#[test]
fn encoding_json_cases() {
    let v = load("encoding.json");
    for c in v["cases"].as_array().unwrap() {
        let name = c["name"].as_str().unwrap();
        let bytes = usize::try_from(c["bytes"].as_u64().unwrap()).unwrap();
        let got = b64url_exact(c["b64url"].as_str().unwrap(), bytes);
        if is_ok(c) {
            assert_eq!(got, Some(hex(c["hex"].as_str().unwrap())), "{name}");
        } else {
            assert_eq!(got, None, "{name}");
        }
    }
}

#[test]
fn key_id_json_cases() {
    let v = load("key-id.json");
    for c in v["cases"].as_array().unwrap() {
        let name = c["name"].as_str().unwrap();
        let got = ViewerKey::from_spki(&hex(c["spki_hex"].as_str().unwrap()));
        if is_ok(c) {
            assert_eq!(
                got.unwrap().key_id().as_str(),
                c["key_id"].as_str().unwrap(),
                "{name}"
            );
        } else {
            assert!(got.is_err(), "{name}");
        }
    }
}

/// [`AttestationError`] as the vectors' `why` names the rule.
fn attest_why(e: &AttestationError) -> &'static str {
    match e {
        AttestationError::EmptyPair | AttestationError::NoEquals => "parse_no_equals",
        AttestationError::BadPercent => "parse_percent",
        AttestationError::NotUtf8 => "parse_utf8",
        AttestationError::EmptyKey => "parse_empty_key",
        AttestationError::LineBreak => "lf",
        AttestationError::CarriageReturn => "cr",
        AttestationError::EqualsInKey => "key_eq",
        AttestationError::Duplicate(_) => "parse_duplicate",
        AttestationError::HasHash => "hash",
        AttestationError::NoAuthDate => "missing_auth_date",
        AttestationError::NoUser => "missing_user",
        AttestationError::NoSignature => "missing_signature",
        AttestationError::NoStartParam => "missing_start_param",
        AttestationError::BadSignatureEncoding => "signature_format",
        AttestationError::PlaceholderKey => "zero_key",
        AttestationError::StandInSignature | AttestationError::BadSignature => "signature",
        AttestationError::WrongStartParam => "start_param",
        AttestationError::BadUser | AttestationError::BadUserId => "user_id",
        other => other.as_str(),
    }
}

#[test]
fn telegram_attest_json_cases() {
    let v = load("telegram-attest.json");
    let bot_id = v["bot_id"].as_u64().unwrap();
    for c in v["cases"].as_array().unwrap() {
        let name = c["name"].as_str().unwrap();
        let key = c["verify_key_hex"]
            .as_str()
            .or_else(|| v["telegram_public_hex"].as_str())
            .unwrap();
        let verifier =
            TelegramVerifier::with_key(Some(bot_id), hex32(key), TelegramEnvironment::Injected);
        let new_key = kid(c["new_key_id"].as_str().unwrap());
        match verifier.verify_attestation(c["init_data"].as_str().unwrap(), &new_key) {
            Ok(id) => {
                assert!(is_ok(c), "{name}: accepted");
                assert_eq!(id.user_id(), c["user_id"].as_i64().unwrap(), "{name}");
            }
            Err(e) => {
                assert!(!is_ok(c), "{name}: refused {e}");
                let detail = if e == AttestationError::HasHash {
                    "attest_has_hash"
                } else {
                    "attest_bad"
                };
                assert_eq!(detail, c["expect"]["detail"].as_str().unwrap(), "{name}");
                // The rule that refused first (§8.2's order).
                assert_eq!(attest_why(&e), c["why"].as_str().unwrap(), "{name}: why");
            }
        }
    }
}

#[test]
fn nonce_batches_are_fresh_and_four() {
    let mut book = NonceBook::new();
    let a = book.new_batch(0).unwrap();
    let b = book.new_batch(1).unwrap();
    assert_eq!((a.batch, b.batch), (1, 2));
    assert_eq!(a.nonces.len(), 4);
    let all: BTreeSet<&String> = a.nonces.iter().chain(&b.nonces).collect();
    assert_eq!(all.len(), 8);
    for n in &a.nonces {
        let raw = b64url_array::<NONCE_PC_LEN>(n).unwrap();
        assert_eq!(URL_SAFE_NO_PAD.encode(raw), *n);
        assert_eq!(book.check(&raw, 180_000), Ok(()));
    }
}

fn empty_state(mode: &str) -> Value {
    json!({
        "device_id": "8d3b1f42-6c7a-4e09-b5d8-2a9e7c1f3b64", "mode": mode,
        "keys": [], "revoked": [], "spent": [], "snapshot": [], "nonce_batches": [],
    })
}

fn request(h: &mut Harness, sid: &str, nonce: Option<&str>) -> RequestDecision {
    h.engine.session_requested(
        &mut h.trusted,
        &SessionRequest {
            session_id: sid,
            telegram_user_id: 1001,
            role: BindingRole::Owner,
            first_name: None,
            username: None,
            nonce_pc: nonce,
        },
    )
}

/// The store's mode file beside the list (`viewer_keys.mode`).
fn mode_file(h: &Harness) -> PathBuf {
    h.dir.0.join("viewer_keys.mode")
}

/// Damage the list on disk and attach the store reopened from it.
fn damage_list(h: &mut Harness) {
    std::fs::write(h.dir.0.join(crate::viewer_keys::FILE_NAME), b"{not json").unwrap();
    let store = TrustStore::open_in(&h.dir.0);
    assert!(store.is_damaged());
    h.trusted.attach(store);
}

fn unsigned_offer(h: &mut Harness, sid: &str, is_bound: bool) -> OfferDecision {
    h.engine.first_offer(
        &mut h.trusted,
        &FirstOffer {
            session_id: sid,
            sdp: "",
            proof: None,
            is_bound,
        },
        1000,
    )
}

#[test]
fn a_damaged_list_without_a_mode_file_refuses_in_either_mode_and_a_repeated_request_is_ignored() {
    for mode in ["observe", "strict"] {
        damaged_without_mode_file_refuses(mode);
    }
}

fn damaged_without_mode_file_refuses(mode: &str) {
    let mut h = Harness::new("damaged", &empty_state(mode), &[]);
    // An upgrade's list: the open wrote the mode file; take it away (missing reads as strict).
    std::fs::remove_file(mode_file(&h)).unwrap();
    damage_list(&mut h);
    assert_eq!(h.store().damaged_mode(), None);
    assert!(!request(&mut h, "s1", None).ignored);
    assert!(
        request(&mut h, "s1", None).ignored,
        "a repeated session_request"
    );
    assert_eq!(h.engine.counting(), 1, "a pending session counts");
    let d = unsigned_offer(&mut h, "s1", true);
    assert_eq!(
        d.verdict,
        Verdict::key_list_damaged("read_failed"),
        "{mode}"
    );
    assert!(!d.admitted() && d.ks.is_none(), "{mode}");
    assert_eq!(d.mode, Mode::Strict, "{mode}");
    assert_eq!(h.engine.counting(), 0);
    assert!(!h.engine.remote_input("s1", TrustControl::PairingPanel));
}

#[test]
fn a_damaged_list_whose_mode_file_says_observe_admits_by_the_binding() {
    let mut h = Harness::new("damaged observe", &empty_state("observe"), &[]);
    assert_eq!(
        std::fs::read_to_string(mode_file(&h)).unwrap(),
        r#"{"version":1,"trusted_devices_mode":false}"#,
        "the open wrote the mode file of an upgrade's list"
    );
    damage_list(&mut h);
    assert_eq!(h.store().damaged_mode(), Some(false));
    assert!(!request(&mut h, "s1", None).ignored);
    let d = unsigned_offer(&mut h, "s1", true);
    assert_eq!(d.verdict, Verdict::key_list_damaged("read_failed"));
    assert_eq!(d.mode, Mode::Observe);
    assert!(d.admitted(), "observe admits a bound viewer by the binding");
    assert!(d.ks.is_none(), "no key named, nothing to tell");
    assert!(d.admit.is_none(), "nothing is written to a damaged list");

    assert!(!request(&mut h, "s2", None).ignored);
    let d = unsigned_offer(&mut h, "s2", false);
    assert_eq!(d.verdict, Verdict::key_list_damaged("read_failed"));
    assert!(!d.admitted(), "not bound: refused, as in observe");
}

#[test]
fn a_damaged_list_whose_mode_file_says_strict_or_is_garbage_refuses() {
    for garbage in [false, true] {
        let mode = if garbage { "observe" } else { "strict" };
        let mut h = Harness::new("damaged strict", &empty_state(mode), &[]);
        if garbage {
            // Even a garbage mode file beside an observe list: unusable reads as strict.
            std::fs::write(mode_file(&h), b"{\"trusted_devices_mode\":false").unwrap();
        } else {
            assert_eq!(
                std::fs::read_to_string(mode_file(&h)).unwrap(),
                r#"{"version":1,"trusted_devices_mode":true}"#
            );
        }
        damage_list(&mut h);
        assert_eq!(
            h.store().damaged_mode(),
            if garbage { None } else { Some(true) }
        );
        assert!(!request(&mut h, "s1", None).ignored);
        let d = unsigned_offer(&mut h, "s1", true);
        assert_eq!(d.verdict, Verdict::key_list_damaged("read_failed"));
        assert_eq!(d.mode, Mode::Strict);
        assert!(!d.admitted() && d.ks.is_none(), "garbage={garbage}");
    }
}

/// §7, §14: a damaged list has no grant token; strict refuses a grant `key_list_damaged` — the
/// list's word, never `grant_stale` — whatever token it carries, the one the list had included.
#[test]
fn a_damaged_list_refuses_a_grant_in_strict_mode() {
    let vera = Signer::new();
    let mut h = Harness::new(
        "damaged grant",
        &state_of("strict", vec![vera.record(1001, "owner")]),
        &[],
    );
    h.engine.insert_nonce_batch(0, vec![nonce(1)]);
    let token = h.grant_token().unwrap();
    damage_list(&mut h);
    assert_eq!(h.grant_token(), None, "no token while damaged");
    let petya = Signer::new();
    request_as(&mut h, "s1", 456, &nonce(1));
    let p = petya.proof(
        "s1",
        &nonce(1),
        true,
        vec![vera.grant_entry_at(&petya.kid, 456, 1, 1_000, token)],
    );
    let d = offer_as(&mut h, "s1", &p, true);
    assert_eq!(d.verdict.code, "key_list_damaged", "{:?}", d.verdict);
    assert!(!d.admitted() && d.admit.is_none());
}

#[test]
fn an_offer_without_a_request_and_a_reoffer_of_an_unknown_session_are_refused() {
    let mut h = Harness::new("no request", &empty_state("observe"), &[]);
    let d = h.engine.first_offer(
        &mut h.trusted,
        &FirstOffer {
            session_id: "nobody",
            sdp: "",
            proof: None,
            is_bound: true,
        },
        1000,
    );
    assert!(!d.admitted());
    assert_eq!(
        h.engine.reoffer("nobody", "", None),
        Reoffer::End(Verdict::FINGERPRINT_CHANGED)
    );
}

#[test]
fn a_viewer_key_over_a_kilobyte_is_invalid_and_uses_no_window() {
    let mut h = Harness::new("vk size", &empty_state("strict"), &[]);
    h.engine.pairing_panel(&h.trusted, true);
    let big = json!({"spki": "x", "pad": "a".repeat(MAX_VIEWER_KEY_BYTES)});
    let req = |id| PairRequest {
        request_id: id,
        telegram_user_id: 456,
        first_name: None,
        username: None,
        viewer_key: Some(&big),
    };
    assert_eq!(h.engine.pair_request(&req("r1")), ViewerKeyOutcome::Invalid);
    assert_eq!(h.engine.pair_request(&req("r2")), ViewerKeyOutcome::Invalid);
    assert_eq!(
        h.engine
            .pair_allow(&h.trusted, "r1", None, BindingRole::Guest, false, false)
            .op
            .map(|o| o.ticket),
        None
    );
}

/// endorse.json's main case, with the write failing or outliving its limit instead of landing.
fn endorse_main_waiting(mode: &str) -> (Harness, Box<AdmitOp>) {
    endorse_main_waiting_bound(mode, true)
}

/// [`endorse_main_waiting`] with the binding check's answer at the offer.
fn endorse_main_waiting_bound(mode: &str, is_bound: bool) -> (Harness, Box<AdmitOp>) {
    let v = load("endorse.json");
    let c = &v["cases"][0];
    assert_eq!(c["name"], "main");
    let mut state = c["state"].clone();
    state["mode"] = mode.into();
    let step = c["step"].clone();
    let mut h = Harness::new("endorse main", &state, std::slice::from_ref(&step));
    let req = &step["session_request"];
    h.engine.session_requested(
        &mut h.trusted,
        &SessionRequest {
            session_id: step["session_id"].as_str().unwrap(),
            telegram_user_id: req["telegram_user_id"].as_i64().unwrap(),
            role: BindingRole::Owner,
            first_name: None,
            username: None,
            nonce_pc: req["nonce_pc"].as_str(),
        },
    );
    let d = h.engine.first_offer(
        &mut h.trusted,
        &FirstOffer {
            session_id: step["session_id"].as_str().unwrap(),
            sdp: step["sdp"].as_str().unwrap(),
            proof: step.get("proof"),
            is_bound,
        },
        1000,
    );
    let Outcome::AfterWrite(op) = d.outcome else {
        panic!("no candidate: {:?}", d.verdict)
    };
    assert_eq!(
        h.engine.counting(),
        1,
        "a session waiting for its write counts"
    );
    (h, op)
}

#[test]
fn a_failed_write_refuses_the_session_in_both_modes() {
    for mode in ["strict", "observe"] {
        let (mut h, op) = endorse_main_waiting(mode);
        let ld = h.engine.landed(
            &mut h.trusted,
            Landed {
                ticket: op.ticket,
                slow: false,
                result: Err(StoreError::Write("disk full".into())),
            },
        );
        let (_, admitted, verdict) = ld.session.unwrap();
        assert!(!admitted, "{mode}");
        assert_eq!(verdict, Verdict::key_list_damaged("write_failed"), "{mode}");
        assert!(
            ld.journal.is_empty(),
            "{mode}: no journal without the write"
        );
        assert_eq!(h.engine.counting(), 0, "{mode}");
    }
}

#[test]
fn a_slow_write_refuses_the_session_then_journals_the_key_when_it_lands() {
    let (mut h, op) = endorse_main_waiting("strict");
    let ticket = op.ticket;
    let ld = h.engine.landed(
        &mut h.trusted,
        Landed {
            ticket,
            slow: true,
            result: Err(StoreError::Write("slow".into())),
        },
    );
    let (sid, admitted, verdict) = ld.session.unwrap();
    assert!(!admitted);
    assert_eq!(verdict, Verdict::key_list_damaged("write_failed"));
    assert!(h.engine.session(&sid).is_none());
    let landed = h.apply(*op, 1000);
    let ld = h.engine.landed(&mut h.trusted, landed);
    assert!(ld.session.is_none(), "the session heard its answer already");
    assert_eq!(
        ld.journal
            .iter()
            .map(JournalEvent::name)
            .collect::<Vec<_>>(),
        ["key_added:endorse"]
    );
}

#[test]
fn ks_is_the_wire_message() {
    let ks = Ks {
        kid: kid("YVhNhIO0oNUQ7QGNmdFedcd_rhVoZvM1gcz8RJ9fEcI"),
        verdict: Verdict::admit_refused("endorse_spent"),
        admit: None,
        mode: Mode::Observe,
    };
    assert_eq!(
        ks.to_json(),
        json!({"t": "ks", "kid": "YVhNhIO0oNUQ7QGNmdFedcd_rhVoZvM1gcz8RJ9fEcI",
               "verdict": "admit_refused", "detail": "endorse_spent", "mode": "observe"})
    );
}

// --- §7 «Новое устройство уже привязанного гостя» -------------------------------------------------

/// grant.json's `main` case: Petya (456) offers key C with Vera's (1001, key A) grant and
/// invitation, strict mode; the PC has only Vera's key.
fn grant_main() -> Value {
    let v = load("grant.json");
    let c = v["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "main")
        .unwrap()
        .clone();
    assert_eq!(
        c["step"]["proof"]["admit"][0]["grant"]["telegram_user_id"],
        456
    );
    c
}

/// A fresh P-256 key as a vector key record of `uid` with `role` (source `pair`), its SPKI made
/// with the prefix of a vector key's SPKI.
fn fresh_record(state: &Value, uid: i64, role: &str) -> Value {
    use aws_lc_rs::signature::{EcdsaKeyPair, KeyPair as _, ECDSA_P256_SHA256_FIXED_SIGNING};
    let model = URL_SAFE_NO_PAD
        .decode(state["keys"][0]["spki"].as_str().unwrap())
        .unwrap();
    let pair = EcdsaKeyPair::generate(&ECDSA_P256_SHA256_FIXED_SIGNING).unwrap();
    let mut spki = model[..model.len() - 65].to_vec();
    spki.extend_from_slice(pair.public_key().as_ref());
    let key = ViewerKey::from_spki(&spki).unwrap();
    json!({
        "key_id": key.key_id().as_str(), "spki": URL_SAFE_NO_PAD.encode(&spki), "role": role,
        "person": {"telegram_user_id": uid, "first_name": "Петя", "username": "petya"},
        "kind": "telegram", "platform": "iphone", "source": {"kind": "pair"},
    })
}

/// The main case's state with `n` more keys of Petya (456) in `role`; their key ids.
fn with_petya(state: &mut Value, n: usize, role: &str) -> Vec<String> {
    (0..n)
        .map(|_| {
            let r = fresh_record(state, 456, role);
            let id = r["key_id"].as_str().unwrap().to_string();
            state["keys"].as_array_mut().unwrap().push(r);
            id
        })
        .collect()
}

/// Key C (the offering key) removed with `origin`, as the vector's `revoked` entry.
fn with_c_removed(state: &mut Value, step: &Value, origin: &str) {
    let reg = &step["proof"]["key_reg"];
    state["revoked"] = json!([{
        "key_id": step["proof"]["key_id"], "spki": reg["spki"],
        "telegram_user_id": 456, "origin": origin, "removed_at": 0,
    }]);
}

/// The first offer through the engine, its write landed synchronously: the final verdict, whether
/// the session goes on, and every journal event.
fn offer_through(h: &mut Harness, step: &Value) -> (Verdict, bool, Vec<JournalEvent>) {
    let sid = step["session_id"].as_str().unwrap();
    let at = step["at_ms"].as_u64().unwrap();
    h.engine.session_requested(
        &mut h.trusted,
        &SessionRequest {
            session_id: sid,
            telegram_user_id: 456,
            role: BindingRole::Guest,
            first_name: Some("Петя"),
            username: Some("petya"),
            nonce_pc: step["session_request"]["nonce_pc"].as_str(),
        },
    );
    let d = h.engine.first_offer(
        &mut h.trusted,
        &FirstOffer {
            session_id: sid,
            sdp: step["sdp"].as_str().unwrap(),
            proof: step.get("proof"),
            is_bound: true,
        },
        at,
    );
    let mut journal = d.journal.clone();
    match d.outcome {
        Outcome::Admit => (d.verdict, true, journal),
        Outcome::Refuse => (d.verdict, false, journal),
        Outcome::AfterWrite(op) => {
            let landed = h.apply(*op, i64::try_from(at).unwrap());
            let ld = h.engine.landed(&mut h.trusted, landed);
            journal.extend(ld.journal);
            let (_, admitted, v) = ld.session.unwrap();
            (v, admitted, journal)
        }
    }
}

/// The list's key ids, revoked ids and spent ids (all sets).
fn list_state(h: &mut Harness) -> (BTreeSet<String>, BTreeSet<String>, BTreeSet<String>) {
    let store = h.store();
    let keys = store
        .keys()
        .unwrap()
        .iter()
        .map(|k| k.key_id().as_str().to_string())
        .collect();
    let revoked = store
        .tombstones()
        .unwrap()
        .iter()
        .map(|t| t.key_id().as_str().to_string())
        .collect();
    let (e, g, i) = store.spent().unwrap();
    let spent = e
        .iter()
        .chain(g)
        .chain(i)
        .map(|x| x.as_str().to_string())
        .collect();
    (keys, revoked, spent)
}

fn set_of(ids: &[&str]) -> BTreeSet<String> {
    ids.iter().map(|s| (*s).to_string()).collect()
}

#[test]
fn a_grant_for_a_guest_the_pc_has_adds_the_key_to_that_guest() {
    let c = grant_main();
    let step = c["step"].clone();
    let mut state = c["state"].clone();
    let petya = with_petya(&mut state, 1, "guest");
    let mut h = Harness::new("known guest", &state, std::slice::from_ref(&step));
    let (verdict, admitted, journal) = offer_through(&mut h, &step);
    assert_eq!(verdict, Verdict::SIGNED);
    assert!(admitted);
    let kid_c = kid(step["proof"]["key_id"].as_str().unwrap());
    let [JournalEvent::KeyAdded {
        ground,
        key_id,
        telegram_user_id,
        role,
        unconfirmed,
        by,
        guest_new_device,
    }] = journal.as_slice()
    else {
        panic!("one key_added event: {journal:?}")
    };
    assert_eq!(*ground, "grant");
    assert_eq!(key_id, &kid_c);
    assert_eq!(*telegram_user_id, 456);
    assert_eq!(*role, BindingRole::Guest);
    assert!(!unconfirmed);
    assert_eq!(
        by.as_ref().map(KeyId::as_str),
        state["keys"][0]["key_id"].as_str()
    );
    assert!(
        *guest_new_device,
        "a known guest's new device, not a new guest"
    );
    assert_eq!(journal[0].name(), "key_added:grant");
    // One person, two keys, both guest; the new one's source is the grant.
    let people: Vec<(i64, Vec<KeyId>)> = h
        .store()
        .listed_people()
        .unwrap()
        .into_iter()
        .map(|(uid, keys)| {
            (
                uid,
                keys.iter().map(|l| l.record.key_id().clone()).collect(),
            )
        })
        .collect();
    assert_eq!(people.len(), 2, "Vera and Petya, no second Petya");
    assert_eq!(people[1].0, 456);
    assert_eq!(people[1].1, vec![kid(&petya[0]), kid_c.clone()]);
    let rec = h
        .store()
        .keys()
        .unwrap()
        .iter()
        .find(|k| k.key_id() == &kid_c)
        .cloned()
        .unwrap();
    assert_eq!(rec.role, BindingRole::Guest);
    assert!(matches!(
        rec.source,
        crate::viewer_keys::KeySource::Grant { .. }
    ));
    let (_, _, identity) = h
        .engine
        .session(step["session_id"].as_str().unwrap())
        .unwrap();
    assert_eq!(
        (identity.telegram_user_id, identity.role),
        (456, BindingRole::Guest)
    );
    assert_eq!(
        list_state(&mut h).2,
        set_of(&["4uMhDelF585RzLESeS6xXg", "uZbNp7HC98KWjWvBUUQicQ"])
    );

    // A new guest (the main case as is) is not a new device.
    let mut h = Harness::new("new guest", &c["state"], std::slice::from_ref(&step));
    let (verdict, _, journal) = offer_through(&mut h, &step);
    assert_eq!(verdict, Verdict::SIGNED);
    assert!(
        matches!(
            journal.as_slice(),
            [JournalEvent::KeyAdded {
                guest_new_device: false,
                ..
            }]
        ),
        "{journal:?}"
    );
}

/// A refusal case: its name, how it changes the main case's state, and the verdict.
type RefusalCase = (&'static str, fn(&mut Value, &Value), Verdict);

/// The refusals of §7 for a person the PC has: each refuses in strict mode and changes nothing.
#[test]
fn a_known_persons_grant_is_refused_by_the_rules_of_a_new_guests() {
    let c = grant_main();
    let cases: [RefusalCase; 5] = [
        // The person is an owner here: a guest's grant never touches an owner.
        (
            "owner",
            |s, _| {
                with_petya(s, 1, "owner");
            },
            Verdict::admit_refused("grant_role"),
        ),
        // A guest and an owner key of the same person: still the owner.
        (
            "guest_and_owner",
            |s, _| {
                with_petya(s, 1, "guest");
                with_petya(s, 1, "owner");
            },
            Verdict::admit_refused("grant_role"),
        ),
        (
            "limit",
            |s, _| {
                with_petya(s, crate::viewer_keys::MAX_KEYS_PER_PERSON, "guest");
            },
            Verdict::admit_refused("limit"),
        ),
        (
            "grant_replayed",
            |s, _| {
                with_petya(s, 1, "guest");
                s["spent"] = json!(["4uMhDelF585RzLESeS6xXg"]);
            },
            Verdict::admit_refused("grant_spent"),
        ),
        (
            "invite_replayed",
            |s, _| {
                with_petya(s, 1, "guest");
                s["spent"] = json!(["uZbNp7HC98KWjWvBUUQicQ"]);
            },
            Verdict::admit_refused("invite_spent"),
        ),
    ];
    for (name, prepare, want) in cases {
        let step = c["step"].clone();
        let mut state = c["state"].clone();
        prepare(&mut state, &step);
        let mut h = Harness::new(name, &state, std::slice::from_ref(&step));
        let before = list_state(&mut h);
        let (verdict, admitted, journal) = offer_through(&mut h, &step);
        assert_eq!(verdict, want, "{name}");
        assert!(!admitted, "{name}");
        assert!(journal.is_empty(), "{name}: {journal:?}");
        assert_eq!(list_state(&mut h), before, "{name}: the list is unchanged");
    }
}

/// §10 for a known guest's removed key: a `server` removal lifts only by a grant with a new,
/// unspent invitation; the old request again (its invitation or its grant spent) is no ground on
/// the removed key (§10 «Повтор основания»): `key_revoked`; without an invitation (observe) it
/// stays removed.
#[test]
fn a_server_removed_key_of_a_known_guest_comes_back_only_by_a_new_invitation() {
    let c = grant_main();
    let step = c["step"].clone();
    let kid_c = step["proof"]["key_id"].as_str().unwrap();
    let grant_id = "4uMhDelF585RzLESeS6xXg";
    let inv_id = "uZbNp7HC98KWjWvBUUQicQ";

    // A new invitation: the removal lifts, the key joins the guest.
    let mut state = c["state"].clone();
    let petya = with_petya(&mut state, 1, "guest");
    with_c_removed(&mut state, &step, "server");
    let mut h = Harness::new("server removed", &state, std::slice::from_ref(&step));
    let (verdict, admitted, journal) = offer_through(&mut h, &step);
    assert_eq!(verdict, Verdict::SIGNED);
    assert!(admitted);
    assert!(
        matches!(
            journal.as_slice(),
            [JournalEvent::KeyAdded {
                ground: "grant",
                guest_new_device: true,
                ..
            }]
        ),
        "{journal:?}"
    );
    let (keys, revoked, spent) = list_state(&mut h);
    let owner = state["keys"][0]["key_id"].as_str().unwrap();
    assert_eq!(keys, set_of(&[owner, &petya[0], kid_c]));
    assert!(revoked.is_empty(), "the server removal is lifted");
    assert_eq!(spent, set_of(&[grant_id, inv_id]));

    // The old request again (its invitation spent, a fresh grant_id or not): key_revoked.
    let mut state = c["state"].clone();
    with_petya(&mut state, 1, "guest");
    with_c_removed(&mut state, &step, "server");
    state["spent"] = json!([inv_id]);
    let mut h = Harness::new(
        "server removed, old invite",
        &state,
        std::slice::from_ref(&step),
    );
    let before = list_state(&mut h);
    let (verdict, admitted, _) = offer_through(&mut h, &step);
    assert_eq!(verdict, Verdict::KEY_REVOKED);
    assert!(!admitted);
    assert_eq!(list_state(&mut h), before);

    // The old grant again: key_revoked.
    let mut state = c["state"].clone();
    with_petya(&mut state, 1, "guest");
    with_c_removed(&mut state, &step, "server");
    state["spent"] = json!([grant_id]);
    let mut h = Harness::new(
        "server removed, old grant",
        &state,
        std::slice::from_ref(&step),
    );
    let (verdict, _, _) = offer_through(&mut h, &step);
    assert_eq!(verdict, Verdict::KEY_REVOKED);

    // Observe mode, the grant without its invitation: the removal stays (`invite_missing`).
    let mut state = c["state"].clone();
    state["mode"] = "observe".into();
    with_petya(&mut state, 1, "guest");
    with_c_removed(&mut state, &step, "server");
    let mut bare = step.clone();
    bare["proof"]["admit"][0]
        .as_object_mut()
        .unwrap()
        .remove("invite");
    let mut h = Harness::new(
        "server removed, no invite",
        &state,
        std::slice::from_ref(&bare),
    );
    let before = list_state(&mut h);
    let (verdict, _, journal) = offer_through(&mut h, &bare);
    assert_eq!(verdict, Verdict::admit_refused("invite_missing"));
    assert!(journal.is_empty());
    assert_eq!(list_state(&mut h), before);
}

// --- Signed by the test: keys whose private halves the test holds ---------------------------------

use crate::trusted::TrustedDone;
use crate::viewer_keys::wire::{grant_message, invite_message, key_reg_message, GrantFields};
use aws_lc_rs::signature::{EcdsaKeyPair, KeyPair as _, ECDSA_P256_SHA256_FIXED_SIGNING};

/// The vectors' PC.
const DEV: &str = "8d3b1f42-6c7a-4e09-b5d8-2a9e7c1f3b64";
/// The viewer's DTLS fingerprint in [`sdp_with`]'s offers.
const FP: [u8; FINGERPRINT_LEN] = [0x5a; FINGERPRINT_LEN];
/// The canonical SPKI prefix of a P-256 key.
const SPKI_PREFIX: [u8; 26] = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
];

fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn nonce(n: u8) -> [u8; NONCE_PC_LEN] {
    [n; NONCE_PC_LEN]
}

/// An offer's SDP with the fingerprint `fp`.
fn sdp_with(fp: &[u8; FINGERPRINT_LEN]) -> String {
    let hex: Vec<String> = fp.iter().map(|b| format!("{b:02X}")).collect();
    format!(
        "v=0\r\no=- 1 1 IN IP4 0.0.0.0\r\ns=-\r\nt=0 0\r\na=fingerprint:sha-256 {}\r\n",
        hex.join(":")
    )
}

/// A viewer device key the test signs with.
struct Signer {
    pair: EcdsaKeyPair,
    spki: Vec<u8>,
    kid: KeyId,
}

impl Signer {
    fn new() -> Self {
        let pair = EcdsaKeyPair::generate(&ECDSA_P256_SHA256_FIXED_SIGNING).unwrap();
        let mut spki = SPKI_PREFIX.to_vec();
        spki.extend_from_slice(pair.public_key().as_ref());
        let kid = ViewerKey::from_spki(&spki).unwrap().key_id().clone();
        Self { pair, spki, kid }
    }

    fn sign(&self, m: &[u8]) -> String {
        let sig = self
            .pair
            .sign(&aws_lc_rs::rand::SystemRandom::new(), m)
            .unwrap();
        b64(sig.as_ref())
    }

    /// Its key card (§4), no recovery key.
    fn key_reg(&self) -> Value {
        let m = key_reg_message(&self.kid, "telegram", "iphone", None);
        json!({"spki": b64(&self.spki), "kind": "telegram", "platform": "iphone",
               "sig": self.sign(&m)})
    }

    /// A key record of the vector state's shape (source `pair`).
    fn record(&self, uid: i64, role: &str) -> Value {
        json!({
            "key_id": self.kid.as_str(), "spki": b64(&self.spki), "role": role,
            "person": {"telegram_user_id": uid, "first_name": null, "username": null},
            "kind": "telegram", "platform": "iphone", "source": {"kind": "pair"},
        })
    }

    /// The offer proof of `sid` with `nonce` (fingerprint [`FP`]), its card or not, its grounds.
    fn proof(&self, sid: &str, nonce: &[u8; NONCE_PC_LEN], card: bool, admit: Vec<Value>) -> Value {
        let m = offer_message(sid, DEV, &self.kid, nonce, &FP);
        let mut p = json!({"v": 1, "key_id": self.kid.as_str(), "nonce_pc": b64(nonce),
                           "sig": self.sign(&m), "admit": admit});
        if card {
            p["key_reg"] = self.key_reg();
        }
        p
    }

    /// An owner's invitation (§7).
    fn invite(&self, inv_id: [u8; 16], issued_at: u64) -> Value {
        let m = invite_message(DEV, &inv_id, issued_at, &self.kid);
        json!({"v": 1, "device_id": DEV, "inv_id": b64(&inv_id), "issued_at": issued_at,
               "by": self.kid.as_str(), "sig": self.sign(&m)})
    }

    /// An owner's `grant` ground for `key` of guest `uid`, with a new invitation (ids from `n`),
    /// over a new PC's grant token (`""`).
    fn grant_entry(&self, key: &KeyId, uid: i64, n: u8) -> Value {
        self.grant_entry_at(key, uid, n, 1_000, GrantToken::default())
    }

    /// [`Self::grant_entry`] signed (grant and invitation) at `at` (unix ms) over `token`.
    fn grant_entry_at(&self, key: &KeyId, uid: i64, n: u8, at: u64, token: GrantToken) -> Value {
        self.grant_entry_ids(key, uid, ([n; 16], [n.wrapping_add(100); 16]), at, token)
    }

    /// [`Self::grant_entry_at`] with its own `(inv_id, grant_id)`.
    fn grant_entry_ids(
        &self,
        key: &KeyId,
        uid: i64,
        (inv_id, grant_id): ([u8; 16], [u8; 16]),
        at: u64,
        token: GrantToken,
    ) -> Value {
        let m = grant_message(&GrantFields {
            device_id: DEV,
            key_id: key,
            telegram_user_id: uid,
            name: Some("Петя"),
            username: Some("petya"),
            inv_id: Some(&inv_id),
            grant_id: &grant_id,
            grant_token: &token,
            issued_at: at,
            by: &self.kid,
        });
        json!({"kind": "grant", "invite": self.invite(inv_id, at), "grant": {
            "v": 1, "device_id": DEV, "key_id": key.as_str(), "telegram_user_id": uid,
            "name": "Петя", "username": "petya", "role": "guest", "inv_id": b64(&inv_id),
            "grant_id": b64(&grant_id), "grant_token": token.to_wire(), "issued_at": at,
            "by": self.kid.as_str(), "sig": self.sign(&m)}})
    }
}

/// A PC state of `mode` with `keys` (records), nothing else.
fn state_of(mode: &str, keys: Vec<Value>) -> Value {
    let mut s = empty_state(mode);
    s["keys"] = Value::Array(keys);
    s
}

/// A `session_request` of `uid` with `nonce` (the server's word: owner for 1001, else guest).
fn request_as(h: &mut Harness, sid: &str, uid: i64, nonce: &[u8; NONCE_PC_LEN]) {
    let n = b64(nonce);
    let d = h.engine.session_requested(
        &mut h.trusted,
        &SessionRequest {
            session_id: sid,
            telegram_user_id: uid,
            role: if uid == 1001 {
                BindingRole::Owner
            } else {
                BindingRole::Guest
            },
            first_name: None,
            username: None,
            nonce_pc: Some(&n),
        },
    );
    assert!(!d.ignored);
}

/// A first offer of `sid` with `proof` and [`FP`].
fn offer_as(h: &mut Harness, sid: &str, proof: &Value, is_bound: bool) -> OfferDecision {
    h.engine.first_offer(
        &mut h.trusted,
        &FirstOffer {
            session_id: sid,
            sdp: &sdp_with(&FP),
            proof: Some(proof),
            is_bound,
        },
        1000,
    )
}

/// The harness's queue run for real: the list reopened under a `Trusted` whose blocking jobs'
/// results come back on the returned channel ([`settle`]).
fn with_queue(h: &mut Harness) -> tokio::sync::mpsc::UnboundedReceiver<TrustedDone> {
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    let (mut t, _view) = Trusted::new(Arc::new(move |d: TrustedDone| {
        let _ = tx.send(d);
    }));
    let mut store = TrustStore::open_in(&h.dir.0);
    store.set_wall_now(h.wall0);
    t.attach(store);
    h.trusted = t;
    rx
}

async fn settle(h: &mut Harness, rx: &mut tokio::sync::mpsc::UnboundedReceiver<TrustedDone>) {
    while !h.trusted.settled() {
        let done = tokio::time::timeout(std::time::Duration::from_secs(10), rx.recv())
            .await
            .expect("a job's result in time")
            .expect("the channel is open");
        h.trusted.on_done(done, 0, None);
    }
}

// --- Fix round: a second first offer (§2.6, §3.5) --------------------------------------------------

/// A session waiting for its key's write has had its first offer: another offer of it is a
/// re-offer — the same fingerprint and proof continue (the orchestrator drops it), another
/// fingerprint or proof ends it — in both modes, and nothing of the first is overwritten. One
/// that is not routed so is never decided again: the session ends, and the first offer's write
/// landing later answers nobody.
#[test]
fn a_second_first_offer_is_a_reoffer_and_never_decided_again() {
    let v = load("endorse.json");
    let step = v["cases"][0]["step"].clone();
    let sid = step["session_id"].as_str().unwrap();
    let sdp = step["sdp"].as_str().unwrap();
    let proof = &step["proof"];
    let mut other_proof = proof.clone();
    other_proof["nonce_pc"] = b64(&nonce(77)).into();
    for mode in ["strict", "observe"] {
        let (mut h, op) = endorse_main_waiting(mode);
        assert!(h.engine.offered(sid), "{mode}: waiting for its write");
        assert!(!h.engine.offered("nobody"));
        let before = h
            .engine
            .session(sid)
            .map(|(s, v, i)| (s, v, i.clone()))
            .unwrap();
        assert_eq!(
            h.engine.reoffer(sid, sdp, Some(proof)),
            Reoffer::Continue,
            "{mode}: the same offer again"
        );
        assert_eq!(h.engine.reoffer(sid, sdp, None), Reoffer::Continue);
        let fp_bad = sdp.replace("87:35:00", "88:35:00");
        assert_ne!(fp_bad, sdp);
        assert_eq!(
            h.engine.reoffer(sid, &fp_bad, Some(proof)),
            Reoffer::End(Verdict::FINGERPRINT_CHANGED),
            "{mode}: another fingerprint"
        );
        assert_eq!(
            h.engine.reoffer(sid, sdp, Some(&other_proof)),
            Reoffer::End(Verdict::proof_invalid("proof_mismatch")),
            "{mode}: another proof"
        );
        let after = h
            .engine
            .session(sid)
            .map(|(s, v, i)| (s, v, i.clone()))
            .unwrap();
        assert_eq!(after, before, "{mode}: nothing of the first overwritten");
        assert_eq!(h.engine.counting(), 1);

        // Not routed: never decided again; the session ends.
        let d = h.engine.first_offer(
            &mut h.trusted,
            &FirstOffer {
                session_id: sid,
                sdp,
                proof: Some(proof),
                is_bound: true,
            },
            1000,
        );
        assert!(matches!(d.outcome, Outcome::Refuse), "{mode}");
        assert_eq!(d.verdict, Verdict::FINGERPRINT_CHANGED, "{mode}");
        assert!(d.journal.is_empty() && d.touch.is_none() && d.ks.is_none() && d.admit.is_none());
        assert!(h.engine.session(sid).is_none(), "{mode}");
        assert_eq!(h.engine.counting(), 0, "{mode}");
        // The first offer's write lands: its key's events stand, no second answer.
        let landed = h.apply(*op, 1000);
        let ld = h.engine.landed(&mut h.trusted, landed);
        assert!(ld.session.is_none(), "{mode}: no second end");
        assert!(ld.ks.is_none() && ld.kid.is_none() && ld.identity.is_none());
        assert_eq!(
            ld.journal
                .iter()
                .map(JournalEvent::name)
                .collect::<Vec<_>>(),
            ["key_added:endorse"]
        );
    }
}

// --- Fix round: what landed decides (§3.4 step 9) --------------------------------------------------

/// Two admissions race for a guest's last key slot. The first lands; the second's stage is
/// refused `limit`: in strict mode the session is refused with it; in observe mode the bound
/// session goes on with the final verdict — its `ks` says `limit`, no key of its is the session's,
/// and its identity is the server's word, not the offer's guess.
#[test]
fn two_admissions_racing_for_the_last_slot_take_the_landed_result() {
    for mode in ["observe", "strict"] {
        let vera = Signer::new();
        let mut keys = vec![vera.record(1001, "owner")];
        for _ in 0..crate::viewer_keys::MAX_KEYS_PER_PERSON - 1 {
            keys.push(Signer::new().record(456, "guest"));
        }
        let mut h = Harness::new("race", &state_of(mode, keys), &[]);
        h.engine.insert_nonce_batch(0, vec![nonce(1), nonce(2)]);
        let (k1, k2) = (Signer::new(), Signer::new());
        let mut ops = Vec::new();
        for (sid, k, n) in [("s1", &k1, 1u8), ("s2", &k2, 2u8)] {
            request_as(&mut h, sid, 456, &nonce(n));
            let p = k.proof(sid, &nonce(n), true, vec![vera.grant_entry(&k.kid, 456, n)]);
            let d = offer_as(&mut h, sid, &p, true);
            assert_eq!(d.verdict, Verdict::SIGNED, "{mode} {sid}");
            let Outcome::AfterWrite(op) = d.outcome else {
                panic!("{mode} {sid}: no candidate")
            };
            ops.push(op);
        }
        let op2 = ops.pop().unwrap();
        let op1 = ops.pop().unwrap();
        let l1 = h.apply(*op1, 1000);
        let ld1 = h.engine.landed(&mut h.trusted, l1);
        assert_eq!(ld1.session, Some(("s1".into(), true, Verdict::SIGNED)));
        assert_eq!(ld1.kid.as_ref(), Some(&k1.kid));
        assert_eq!(
            ld1.ks.as_ref().map(|k| (k.verdict, k.admit)),
            Some((Verdict::SIGNED, Some("grant")))
        );
        let id1 = ld1.identity.unwrap();
        assert_eq!(
            (id1.telegram_user_id, id1.role, id1.from_record),
            (456, BindingRole::Guest, true)
        );

        let l2 = h.apply(*op2, 1000);
        assert!(
            matches!(l2.result, Err(StoreError::Full(_))),
            "{mode}: {:?}",
            l2.result
        );
        let ld2 = h.engine.landed(&mut h.trusted, l2);
        let limit = Verdict::admit_refused("limit");
        if mode == "observe" {
            assert_eq!(ld2.session, Some(("s2".into(), true, limit)));
            assert_eq!(ld2.kid, None, "no key of its is the session's");
            assert_eq!(
                ld2.ks,
                Some(Ks {
                    kid: k2.kid.clone(),
                    verdict: limit,
                    admit: None,
                    mode: Mode::Observe,
                })
            );
            let (signed, verdict, id) = h.engine.session("s2").unwrap();
            assert!(!signed);
            assert_eq!(verdict, limit);
            assert!(!id.from_record && id.telegram_user_id == 456);
        } else {
            assert_eq!(ld2.session, Some(("s2".into(), false, limit)));
            assert!(ld2.ks.is_none() && ld2.kid.is_none() && ld2.identity.is_none());
            assert!(h.engine.session("s2").is_none());
        }
    }
}

/// The key's change is dropped because the list turned damaged (the queue answers it as its
/// landing with `damaged`): the waiting session is answered at once — refused, no key of its —
/// in both modes, never left to its timeout.
#[test]
fn a_change_dropped_at_damage_refuses_its_session_at_once() {
    for mode in ["observe", "strict"] {
        let (mut h, op) = endorse_main_waiting(mode);
        let v = load("endorse.json");
        let sid = v["cases"][0]["step"]["session_id"]
            .as_str()
            .unwrap()
            .to_string();
        let ld = h.engine.landed(
            &mut h.trusted,
            Landed {
                ticket: op.ticket,
                slow: false,
                result: Err(StoreError::Damaged),
            },
        );
        let (s, admitted, verdict) = ld.session.expect("answered at once");
        assert_eq!(s, sid, "{mode}");
        assert!(!admitted, "{mode}: refused");
        assert_eq!(verdict.code, "key_list_damaged", "{mode}");
        assert_eq!(ld.kid, None, "{mode}");
        assert!(h.engine.session(&sid).is_none(), "{mode}: nothing waits");
    }
}

/// A landing for a session that ended meanwhile answers nothing (no second end), and an observe
/// session refused at its landing (not bound) ends `unbound`, never with a success verdict.
#[test]
fn a_landing_after_the_session_ended_answers_nothing_and_never_ends_signed() {
    for mode in ["strict", "observe"] {
        for ok in [true, false] {
            let (mut h, op) = endorse_main_waiting(mode);
            let v = load("endorse.json");
            let sid = v["cases"][0]["step"]["session_id"]
                .as_str()
                .unwrap()
                .to_string();
            h.engine.session_ended(&mut h.trusted, &sid);
            let landed = if ok {
                h.apply(*op, 1000)
            } else {
                Landed {
                    ticket: op.ticket,
                    slow: false,
                    result: Err(StoreError::Write("disk full".into())),
                }
            };
            let ld = h.engine.landed(&mut h.trusted, landed);
            assert!(ld.session.is_none(), "{mode} ok={ok}: no second end");
            assert_eq!(
                ld.journal.len(),
                usize::from(ok),
                "{mode}: the key's own event"
            );
        }
    }
    let (mut h, op) = endorse_main_waiting_bound("observe", false);
    let landed = h.apply(*op, 1000);
    let ld = h.engine.landed(&mut h.trusted, landed);
    let (_, admitted, reason) = ld.session.unwrap();
    assert!(!admitted);
    assert_eq!(reason, Verdict::UNBOUND, "never `signed` as an end reason");
}

// --- Fix round: a guest removed on the server (§10, origin server) --------------------------------

/// `BindingRemoved` of a guest: their guest-role keys leave the list as tombstones `server`
/// (an owner-role key of the same person stays); the next offer with such a key is
/// `key_revoked`, also after the list is reopened; a grant signed before the removal is
/// `grant_stale` (the removal replaced the grant token, §7); a fresh grant of the owner over the
/// current token on a new invitation lifts it (§10).
#[tokio::test]
async fn a_guest_removed_on_the_server_is_revoked_until_a_new_grant() {
    let vera = Signer::new();
    let petya = Signer::new();
    let both_owner = Signer::new();
    let both_guest = Signer::new();
    let state = state_of(
        "strict",
        vec![
            vera.record(1001, "owner"),
            petya.record(456, "guest"),
            both_owner.record(9, "owner"),
            both_guest.record(9, "guest"),
        ],
    );
    let mut h = Harness::new("server removes", &state, &[]);
    let mut rx = with_queue(&mut h);
    h.engine
        .insert_nonce_batch(0, (1..=4).map(nonce).collect::<Vec<_>>());
    h.trusted.guest_removed_on_server(456, 0);
    h.trusted.guest_removed_on_server(9, 0);
    h.trusted.guest_removed_on_server(1001, 0);
    settle(&mut h, &mut rx).await;
    let origin = |h: &mut Harness, k: &KeyId| match h.store().lookup(k) {
        Lookup::Removed(t) => t.origin.as_str(),
        Lookup::Active(_) => "active",
        other => panic!("{other:?}"),
    };
    assert_eq!(origin(&mut h, &petya.kid), "server");
    assert_eq!(origin(&mut h, &both_guest.kid), "server");
    assert_eq!(
        origin(&mut h, &both_owner.kid),
        "active",
        "an owner-role key never"
    );
    assert_eq!(origin(&mut h, &vera.kid), "active");

    request_as(&mut h, "s1", 456, &nonce(1));
    let d = offer_as(
        &mut h,
        "s1",
        &petya.proof("s1", &nonce(1), false, vec![]),
        true,
    );
    assert_eq!(d.verdict, Verdict::KEY_REVOKED);
    assert!(!d.admitted());

    // Reopened: still revoked.
    h.trusted.attach(TrustStore::open_in(&h.dir.0));
    assert_eq!(origin(&mut h, &petya.kid), "server");
    request_as(&mut h, "s2", 456, &nonce(2));
    let d = offer_as(
        &mut h,
        "s2",
        &petya.proof("s2", &nonce(2), true, vec![]),
        true,
    );
    assert_eq!(d.verdict, Verdict::KEY_REVOKED);

    // A grant over the token before the removal: stale.
    let token = h.grant_token().unwrap();
    assert!(!token.is_empty(), "the removal replaced the token");
    request_as(&mut h, "s3", 456, &nonce(3));
    let p = petya.proof(
        "s3",
        &nonce(3),
        true,
        vec![vera.grant_entry(&petya.kid, 456, 3)],
    );
    let d = offer_as(&mut h, "s3", &p, true);
    assert_eq!(d.verdict, Verdict::admit_refused("grant_stale"));

    // A fresh grant over the current token on a new invitation lifts it.
    request_as(&mut h, "s4", 456, &nonce(4));
    let p = petya.proof(
        "s4",
        &nonce(4),
        true,
        vec![vera.grant_entry_at(&petya.kid, 456, 4, 1_000, token)],
    );
    let d = offer_as(&mut h, "s4", &p, true);
    assert_eq!(d.verdict, Verdict::SIGNED);
    let Outcome::AfterWrite(op) = d.outcome else {
        panic!("no candidate")
    };
    let landed = h.apply(*op, 1000);
    let ld = h.engine.landed(&mut h.trusted, landed);
    assert_eq!(ld.session, Some(("s4".into(), true, Verdict::SIGNED)));
    assert_eq!(origin(&mut h, &petya.kid), "active");
}

// --- Fix round: `pc_allow` keys (§5) ---------------------------------------------------------------

/// Observe mode, a key accepted at the pairing panel and allowed during a guest's session
/// (`pc_allow`): it waits for `BindingAdded`.
fn pc_allow_waiting() -> Harness {
    let vera = Signer::new();
    let mut h = Harness::new(
        "pc_allow",
        &state_of("observe", vec![vera.record(1001, "owner")]),
        &[],
    );
    h.engine.pairing_panel(&h.trusted, true);
    let card = Signer::new().key_reg();
    assert_eq!(
        h.engine.pair_request(&PairRequest {
            request_id: "r1",
            telegram_user_id: 456,
            first_name: Some("Петя"),
            username: None,
            viewer_key: Some(&card),
        }),
        ViewerKeyOutcome::Accepted
    );
    let d = h
        .engine
        .pair_allow(&h.trusted, "r1", None, BindingRole::Guest, true, false);
    assert!(
        d.op.is_none() && d.key_id.is_none(),
        "waits for BindingAdded"
    );
    h
}

/// A `pc_allow` key is forgotten at the owner's decline, the request's expiry (the owner's word
/// or the agent's own bound), `PairCancelled` and a decline at the PC: a `BindingAdded` after
/// that adds nothing. Before it, `BindingAdded` adds the key, unconfirmed.
#[test]
fn pc_allow_keys_are_forgotten_at_decline_expiry_and_cancel() {
    let mut h = pc_allow_waiting();
    h.engine
        .pc_allow_state(Some("r1"), 456, OwnerRequestState::Pending, None);
    h.engine
        .pc_allow_state(Some("r1"), 456, OwnerRequestState::Confirmed, None);
    let d = h.engine.binding_added(&h.trusted, 456);
    assert!(
        d.op.is_some() && d.unconfirmed,
        "in time: added, unconfirmed"
    );

    type Forget = fn(&mut Admission);
    let cases: [(&str, Forget); 6] = [
        ("owner declined", |e| {
            e.pc_allow_state(Some("r1"), 456, OwnerRequestState::Declined, None);
        }),
        ("owner request expired", |e| {
            e.pc_allow_state(None, 456, OwnerRequestState::Expired, None);
        }),
        ("withdrawn", |e| {
            e.pc_allow_state(Some("r1"), 456, OwnerRequestState::Cancelled, None);
        }),
        ("the agent's own bound", |e| e.age_pc_allow(PC_ALLOW_WAIT)),
        ("the request's sooner expiry", |e| {
            e.pc_allow_state(
                Some("r1"),
                456,
                OwnerRequestState::Pending,
                Some(std::time::Duration::from_secs(5)),
            );
            e.age_pc_allow(std::time::Duration::from_secs(6));
        }),
        ("PairCancelled or a decline at the PC", |e| {
            e.pair_cancelled("r1")
        }),
    ];
    for (name, forget) in cases {
        let mut h = pc_allow_waiting();
        forget(&mut h.engine);
        let d = h.engine.binding_added(&h.trusted, 456);
        assert!(
            d.op.is_none() && d.key_id.is_none(),
            "{name}: a late BindingAdded adds nothing"
        );
    }
    // Another request's answer leaves this key waiting.
    let mut h = pc_allow_waiting();
    h.engine
        .pc_allow_state(Some("r2"), 456, OwnerRequestState::Declined, None);
    assert!(h.engine.binding_added(&h.trusted, 456).op.is_some());
}

// --- Fix round: other devices' attempts (§9, §10.1) ------------------------------------------------

/// Another device's `key_unknown` is kept for the window only after its offer's signature
/// verified, only for a person with a key here, at most three per person (newest), the same
/// device once; it is journaled when new, three a day per person.
#[test]
fn another_devices_attempt_is_kept_only_after_its_signature_and_bounded() {
    let vera = Signer::new();
    let mut h = Harness::new(
        "attempts",
        &state_of("strict", vec![vera.record(1001, "owner")]),
        &[],
    );
    h.engine
        .set_bindings(&mut h.trusted, [(1001, BindingRole::Owner)]);
    h.engine
        .insert_nonce_batch(0, (1..=12).map(nonce).collect::<Vec<_>>());
    let x = Signer::new();
    // No card: `key_unknown` at step 6, before any signature: nothing.
    request_as(&mut h, "s1", 1001, &nonce(1));
    let d = offer_as(&mut h, "s1", &x.proof("s1", &nonce(1), false, vec![]), true);
    assert_eq!(d.verdict, Verdict::KEY_UNKNOWN);
    assert!(d.attempts.is_empty() && h.trusted.attempts_of(1001).is_empty());
    // A card, a signature over another session: bad_sig, nothing.
    request_as(&mut h, "s2", 1001, &nonce(2));
    let d = offer_as(
        &mut h,
        "s2",
        &x.proof("other", &nonce(2), true, vec![]),
        true,
    );
    assert_eq!(d.verdict, Verdict::proof_invalid("bad_sig"));
    assert!(d.attempts.is_empty() && h.trusted.attempts_of(1001).is_empty());
    // Signed, a valid card, no ground: kept and journaled.
    request_as(&mut h, "s3", 1001, &nonce(3));
    let d = offer_as(&mut h, "s3", &x.proof("s3", &nonce(3), true, vec![]), true);
    assert_eq!(d.verdict, Verdict::KEY_UNKNOWN);
    let [a] = <[_; 1]>::try_from(d.attempts).expect("one journaled");
    assert_eq!((a.telegram_user_id, a.reason), (1001, "key_unknown"));
    assert_eq!(a.key_id, x.kid);
    assert!(a.device.is_some());
    assert_eq!(h.trusted.attempts_of(1001).len(), 1);
    // The same device again: kept once, not journaled again.
    request_as(&mut h, "s4", 1001, &nonce(4));
    let d = offer_as(&mut h, "s4", &x.proof("s4", &nonce(4), true, vec![]), true);
    assert!(d.attempts.is_empty());
    assert_eq!(h.trusted.attempts_of(1001).len(), 1);
    // A person not in the bindings: not kept.
    request_as(&mut h, "s5", 777, &nonce(5));
    let d = offer_as(&mut h, "s5", &x.proof("s5", &nonce(5), true, vec![]), true);
    assert!(d.attempts.is_empty() && h.trusted.attempts_of(777).is_empty());
    // Four more devices: the newest four kept (§10.2); three journaled a day.
    let mut journaled = 1;
    let mut last = None;
    for n in 6..=9u8 {
        let y = Signer::new();
        let sid = format!("s{n}");
        request_as(&mut h, &sid, 1001, &nonce(n));
        let d = offer_as(&mut h, &sid, &y.proof(&sid, &nonce(n), true, vec![]), true);
        journaled += d.attempts.len();
        last = Some(y.kid.clone());
    }
    assert_eq!(journaled, 3, "three a day per person");
    let kept = h.trusted.attempts_of(1001);
    assert_eq!(kept.len(), crate::viewer_keys::ATTEMPTS_PER_PERSON);
    assert_eq!(kept.last().map(|a| &a.key_id), last.as_ref(), "newest last");
    assert!(kept.iter().all(|a| a.key_id != x.kid), "the oldest went");
}

/// first-use.json `person_has_key`: a `first_use` of a person who has a key here, its signature
/// verified, is refused `first_use_closed` and kept as that person's attempt.
#[test]
fn a_first_use_closed_attempt_is_kept_for_its_person() {
    let v = load("first-use.json");
    let c = v["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "person_has_key")
        .unwrap();
    let step = &c["step"];
    let mut h = Harness::new("first_use closed", &c["state"], std::slice::from_ref(step));
    h.engine
        .note_binding(&mut h.trusted, 1001, BindingRole::Owner);
    let sid = step["session_id"].as_str().unwrap();
    let req = &step["session_request"];
    h.engine.session_requested(
        &mut h.trusted,
        &SessionRequest {
            session_id: sid,
            telegram_user_id: req["telegram_user_id"].as_i64().unwrap(),
            role: BindingRole::Owner,
            first_name: None,
            username: None,
            nonce_pc: req["nonce_pc"].as_str(),
        },
    );
    let d = h.engine.first_offer(
        &mut h.trusted,
        &FirstOffer {
            session_id: sid,
            sdp: step["sdp"].as_str().unwrap(),
            proof: step.get("proof"),
            is_bound: true,
        },
        step["at_ms"].as_u64().unwrap(),
    );
    assert_eq!(d.verdict, Verdict::admit_refused("first_use_closed"));
    let [a] = <[_; 1]>::try_from(d.attempts).expect("one journaled");
    assert_eq!((a.telegram_user_id, a.reason), (1001, "first_use_closed"));
    assert_eq!(h.trusted.attempts_of(1001).len(), 1);
}

// --- Fix round: the window count, one source (§3.4) -----------------------------------------------

/// `window_live` counts the orchestrator's sessions but the confirmed owner's signed one, and
/// the unknown ones; the engine's own updates between two calls say the same number, so the
/// window token moves once per change. A re-offer of a session the engine has no record of
/// ends `fingerprint_changed`.
#[test]
fn the_window_count_has_one_source_and_unknown_sessions_fail_closed() {
    let vera = Signer::new();
    let mut h = Harness::new(
        "window",
        &state_of("observe", vec![vera.record(1001, "owner")]),
        &[],
    );
    h.engine.insert_nonce_batch(0, vec![nonce(1)]);
    request_as(&mut h, "s-owner", 1001, &nonce(1));
    let d = offer_as(
        &mut h,
        "s-owner",
        &vera.proof("s-owner", &nonce(1), false, vec![]),
        true,
    );
    assert!(d.admitted() && d.verdict == Verdict::SIGNED);
    unsigned_request(&mut h, "s-guest");
    assert_eq!(h.engine.counting(), 1, "the guest's pending session");
    let ids = ["s-owner", "s-guest", "s-unknown"];
    let live = h.engine.window_live(ids);
    assert_eq!(live, 2, "the guest's and the unknown one");
    h.trusted.sync_live(live);
    let token = h.trusted.window_token();
    // The engine's own update (an unrelated end) says the same: the token stays.
    h.engine.session_ended(&mut h.trusted, "nobody");
    assert_eq!(h.trusted.window_token(), token, "one change, one move");
    assert_eq!(h.trusted.counting(), 2);
    // The unknown one goes: one move.
    h.trusted
        .sync_live(h.engine.window_live(["s-owner", "s-guest"]));
    assert_ne!(h.trusted.window_token(), token);
    // A re-offer of a session the engine does not know fails closed.
    assert_eq!(
        h.engine.reoffer("s-unknown", &sdp_with(&FP), None),
        Reoffer::End(Verdict::FINGERPRINT_CHANGED)
    );
    // Removed from the engine (its key revoked): a re-offer fails closed too.
    let ended = h
        .engine
        .keys_removed(&mut h.trusted, std::slice::from_ref(&vera.kid));
    assert_eq!(ended.len(), 1);
    assert_eq!(
        h.engine.reoffer("s-owner", &sdp_with(&FP), None),
        Reoffer::End(Verdict::FINGERPRINT_CHANGED)
    );
}

fn unsigned_request(h: &mut Harness, sid: &str) {
    h.engine.session_requested(
        &mut h.trusted,
        &SessionRequest {
            session_id: sid,
            telegram_user_id: 456,
            role: BindingRole::Guest,
            first_name: None,
            username: None,
            nonce_pc: None,
        },
    );
}

/// An owner's `endorse` ground for `key`, signed by `by` (issued now).
fn endorse_entry(by: &Signer, key: &KeyId, n: u8) -> Value {
    endorse_entry_at(by, key, n, u64::try_from(crate::journal::now_ms()).unwrap())
}

/// [`endorse_entry`] issued at `issued_at` (unix ms, the signing device's clock).
fn endorse_entry_at(by: &Signer, key: &KeyId, n: u8, issued_at: u64) -> Value {
    let endorse_id = [n; 16];
    let m = crate::viewer_keys::wire::endorse_message(key, &by.kid, &endorse_id, issued_at);
    json!({"kind": "endorse", "endorse": {"v": 1, "key_id": key.as_str(), "by": by.kid.as_str(),
           "endorse_id": b64(&endorse_id), "issued_at": issued_at, "sig": by.sign(&m)}})
}

/// Item 1: the server ends S while its owner write waits, and gives the id S to a guest whose
/// grant waits too. The old write landing — slow first, then for real — answers nothing of the
/// new S: no end, no owner identity, no key of its; the new S lands with its own.
#[test]
fn a_stale_write_never_lands_on_a_session_reusing_its_id() {
    let vera = Signer::new();
    let mut h = Harness::new(
        "reuse",
        &state_of("strict", vec![vera.record(1001, "owner")]),
        &[],
    );
    h.engine.insert_nonce_batch(0, vec![nonce(1), nonce(2)]);
    let (owner_dev, petya) = (Signer::new(), Signer::new());
    request_as(&mut h, "s", 1001, &nonce(1));
    let p = owner_dev.proof(
        "s",
        &nonce(1),
        true,
        vec![endorse_entry(&vera, &owner_dev.kid, 1)],
    );
    let Outcome::AfterWrite(old) = offer_as(&mut h, "s", &p, true).outcome else {
        panic!("the owner's write waits")
    };
    h.engine.session_ended(&mut h.trusted, "s");
    request_as(&mut h, "s", 456, &nonce(2));
    let p = petya.proof(
        "s",
        &nonce(2),
        true,
        vec![vera.grant_entry(&petya.kid, 456, 2)],
    );
    let Outcome::AfterWrite(new) = offer_as(&mut h, "s", &p, true).outcome else {
        panic!("the guest's write waits")
    };
    assert_ne!(old.ticket, new.ticket);
    let guest_waiting = |h: &Harness| {
        let (signed, verdict, id) = h.engine.session("s").expect("the new s");
        assert!(signed && verdict == Verdict::SIGNED);
        assert_eq!((id.telegram_user_id, id.role), (456, BindingRole::Guest));
    };
    // The old write outlives its limit: nothing of the new S ends.
    let ld = h.engine.landed(
        &mut h.trusted,
        Landed {
            ticket: old.ticket,
            slow: true,
            result: Err(StoreError::Write("slow".into())),
        },
    );
    assert!(ld.session.is_none(), "no end for the new s");
    guest_waiting(&h);
    // The old write lands: its key's own event stands, nothing applies to the new S.
    let landed = h.apply(*old, 1000);
    let ld = h.engine.landed(&mut h.trusted, landed);
    assert!(ld.session.is_none() && ld.ks.is_none() && ld.kid.is_none() && ld.identity.is_none());
    assert_eq!(
        ld.journal
            .iter()
            .map(JournalEvent::name)
            .collect::<Vec<_>>(),
        ["key_added:endorse"]
    );
    guest_waiting(&h);
    assert_eq!(h.engine.counting(), 1, "the new s still waits and counts");
    // The new one lands as its own.
    let landed = h.apply(*new, 1000);
    let ld = h.engine.landed(&mut h.trusted, landed);
    assert_eq!(ld.session, Some(("s".into(), true, Verdict::SIGNED)));
    assert_eq!(ld.kid.as_ref(), Some(&petya.kid));
    let id = ld.identity.unwrap();
    assert_eq!((id.telegram_user_id, id.role), (456, BindingRole::Guest));
}

/// Item 4: a recovery with a valid offer signature and a valid attestation but a recovery
/// signature that does not check is another device's attempt as that person: kept for the
/// window and journaled, by the same bounds.
#[test]
fn a_bad_recovery_signature_is_another_devices_attempt() {
    let v = load("recover.json");
    let c = v["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "rsig_by_other_rk")
        .unwrap();
    let step = &c["step"];
    let mut h = Harness::new("recover bad rsig", &c["state"], std::slice::from_ref(step));
    let sid = step["session_id"].as_str().unwrap();
    let req = &step["session_request"];
    h.engine.note_binding(
        &mut h.trusted,
        req["telegram_user_id"].as_i64().unwrap(),
        BindingRole::Owner,
    );
    h.engine.session_requested(
        &mut h.trusted,
        &SessionRequest {
            session_id: sid,
            telegram_user_id: req["telegram_user_id"].as_i64().unwrap(),
            role: BindingRole::Owner,
            first_name: None,
            username: None,
            nonce_pc: req["nonce_pc"].as_str(),
        },
    );
    let d = h.engine.first_offer(
        &mut h.trusted,
        &FirstOffer {
            session_id: sid,
            sdp: step["sdp"].as_str().unwrap(),
            proof: step.get("proof"),
            is_bound: true,
        },
        step["at_ms"].as_u64().unwrap_or(1000),
    );
    assert_eq!(d.verdict, Verdict::admit_refused("recover_bad_sig"));
    let [a] = <[_; 1]>::try_from(d.attempts).expect("one journaled");
    assert_eq!(a.reason, "recover_bad_sig");
    assert_eq!(h.trusted.attempts_of(a.telegram_user_id).len(), 1);
    assert_eq!(
        d.journal.iter().map(JournalEvent::name).collect::<Vec<_>>(),
        ["recover_attempt"],
        "the recovery's own event stands"
    );
}

/// On the list (§10.2): an offer refused after its signature verified is
/// ONE attempt of the server's person, whichever ground refused first (a badly signed endorsement
/// ahead of a recovery with a wrong recovery signature, or of a closed `first_use`): it reaches
/// the window and the journal's path (`attempts`) with the verdict's reason.
#[test]
fn an_offer_refused_by_any_ground_is_one_attempt() {
    for (file, case, reason) in [
        ("recover.json", "rsig_by_other_rk", "recover_bad_sig"),
        ("first-use.json", "person_has_key", "first_use_closed"),
    ] {
        let v = load(file);
        let c = v["cases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["name"] == case)
            .unwrap();
        let mut step = c["step"].clone();
        // A badly signed endorsement ahead of the vector's ground: by the active key of the
        // state, signed by a stranger.
        let kid = KeyId::parse(step["proof"]["key_id"].as_str().unwrap()).unwrap();
        let by = KeyId::parse(c["state"]["keys"][0]["key_id"].as_str().unwrap()).unwrap();
        let (endorse_id, issued_at) = ([9u8; 16], u64::try_from(crate::journal::now_ms()).unwrap());
        let m = crate::viewer_keys::wire::endorse_message(&kid, &by, &endorse_id, issued_at);
        let bad = json!({"kind": "endorse", "endorse": {"v": 1, "key_id": kid.as_str(),
            "by": by.as_str(), "endorse_id": b64(&endorse_id), "issued_at": issued_at,
            "sig": Signer::new().sign(&m)}});
        let admit = step["proof"]["admit"].as_array_mut().unwrap();
        admit.insert(0, bad);
        let mut h = Harness::new(case, &c["state"], std::slice::from_ref(&step));
        let sid = step["session_id"].as_str().unwrap();
        let req = &step["session_request"];
        h.engine.note_binding(
            &mut h.trusted,
            req["telegram_user_id"].as_i64().unwrap(),
            BindingRole::Owner,
        );
        h.engine.session_requested(
            &mut h.trusted,
            &SessionRequest {
                session_id: sid,
                telegram_user_id: req["telegram_user_id"].as_i64().unwrap(),
                role: BindingRole::Owner,
                first_name: None,
                username: None,
                nonce_pc: req["nonce_pc"].as_str(),
            },
        );
        let d = h.engine.first_offer(
            &mut h.trusted,
            &FirstOffer {
                session_id: sid,
                sdp: step["sdp"].as_str().unwrap(),
                proof: step.get("proof"),
                is_bound: true,
            },
            step["at_ms"].as_u64().unwrap_or(1000),
        );
        assert_eq!(
            d.verdict,
            Verdict::admit_refused("endorse_bad_sig"),
            "{case}: the first refusal is the verdict"
        );
        let reasons: Vec<_> = d.attempts.iter().map(|a| a.reason).collect();
        assert_eq!(
            reasons,
            ["endorse_bad_sig"],
            "{case} ({reason}): the verdict's reason"
        );
        assert_eq!(d.attempts[0].key_id, kid);
        let uid = d.attempts[0].telegram_user_id;
        assert_eq!(uid, 1001, "{case}");
        assert_eq!(
            h.trusted.attempts_of(uid).len(),
            1,
            "{case}: kept for the window"
        );
    }
}

/// On the list (§10.2: an attempt is a REFUSED offer): an earlier ground
/// refused (a `first_use` as an owner who has a key here, closed) and a later one (the owner's
/// grant for a guest) admits the key: no attempt, for either person.
#[test]
fn an_admitted_key_is_no_attempt() {
    let vera = Signer::new();
    let mut h = Harness::new(
        "attempt then grant",
        &state_of("strict", vec![vera.record(1001, "owner")]),
        &[],
    );
    h.engine.set_bindings(
        &mut h.trusted,
        [(1001, BindingRole::Owner), (456, BindingRole::Guest)],
    );
    h.engine.insert_nonce_batch(0, vec![nonce(1)]);
    let x = Signer::new();
    let m = crate::viewer_keys::wire::first_use_message(DEV, &x.kid, 1001);
    let first_use = json!({"kind": "first_use", "uid": 1001, "sig": x.sign(&m)});
    request_as(&mut h, "s1", 456, &nonce(1));
    let p = x.proof(
        "s1",
        &nonce(1),
        true,
        vec![first_use, vera.grant_entry(&x.kid, 456, 1)],
    );
    let d = offer_as(&mut h, "s1", &p, true);
    assert!(
        matches!(d.outcome, Outcome::AfterWrite(_)),
        "the grant wins: {:?}",
        d.verdict
    );
    assert_eq!(d.admit, Some("grant"));
    assert!(d.attempts.is_empty(), "{:?}", d.attempts);
    assert!(h.trusted.attempts_of(1001).is_empty());
    assert!(h.trusted.attempts_of(456).is_empty());
}

/// On the removal (§10): a guest's first key is being written when the server removes the guest
/// (`binding_removed`: no guest key to deny; they leave the stored list, as the orchestrator's
/// rule notes it, so the token is replaced). In flight: it lands denied at once and leaves as a
/// tombstone `server` (the install decides again by the token). Still queued behind another
/// change: refused at its stage (`grant_stale`), never written. Either way the waiting session
/// ends `grant_stale`; the device is refused after a reopen too, and the same grant replayed is
/// refused (spent on the removed key: no ground, `key_revoked`; or over the token before the
/// removal); a fresh grant over the current token on
/// a new invitation lets the device in again (§10: it lifts the tombstone).
#[tokio::test]
async fn a_first_guest_key_written_during_its_removal_is_removed_too() {
    for queued in [false, true] {
        let vera = Signer::new();
        let mut h = Harness::new(
            "removed during write",
            &state_of("strict", vec![vera.record(1001, "owner")]),
            &[],
        );
        let mut rx = with_queue(&mut h);
        h.engine
            .insert_nonce_batch(0, (1..=6).map(nonce).collect::<Vec<_>>());
        if queued {
            // Another change in flight ahead of the guest's.
            let dev = Signer::new();
            request_as(&mut h, "s0", 1001, &nonce(6));
            let p = dev.proof(
                "s0",
                &nonce(6),
                true,
                vec![endorse_entry(&vera, &dev.kid, 4)],
            );
            let Outcome::AfterWrite(op) = offer_as(&mut h, "s0", &p, true).outcome else {
                panic!("waits")
            };
            h.trusted.admit(*op);
        }
        let petya = Signer::new();
        request_as(&mut h, "s1", 456, &nonce(1));
        let p = petya.proof(
            "s1",
            &nonce(1),
            true,
            vec![vera.grant_entry(&petya.kid, 456, 1)],
        );
        let Outcome::AfterWrite(op) = offer_as(&mut h, "s1", &p, true).outcome else {
            panic!("the grant waits")
        };
        h.trusted.admit(*op);
        assert!(
            !h.trusted.settled(),
            "queued {queued}: the write is not done"
        );
        h.engine.set_bindings(
            &mut h.trusted,
            [(1001, BindingRole::Owner), (456, BindingRole::Guest)],
        );
        // The stored list names them first (the server's list before the unbind).
        h.store().note_last_bindings([
            KnownBinding {
                telegram_user_id: 1001,
                role: BindingRole::Owner,
            },
            KnownBinding {
                telegram_user_id: 456,
                role: BindingRole::Guest,
            },
        ]);
        assert!(h.engine.remove_person(
            &mut h.trusted,
            456,
            Some(BindingRole::Guest),
            Removal::Server,
            1
        ));
        // The handler's rule notes the list without them: their departure replaces the token.
        assert!(h.store().note_last_bindings([KnownBinding {
            telegram_user_id: 1001,
            role: BindingRole::Owner,
        }]));
        settle(&mut h, &mut rx).await;
        let mut s1 = None;
        for landed in h.trusted.take_landed() {
            let d = h.engine.landed(&mut h.trusted, landed);
            if let Some(s) = d.session.filter(|s| s.0 == "s1") {
                s1 = Some(s);
            }
        }
        // Queued: staged after the removal replaced the grant token; in flight: installed after
        // it. Either way `grant_stale`.
        assert_eq!(
            s1,
            Some((
                "s1".to_string(),
                false,
                Verdict::admit_refused("grant_stale")
            )),
            "queued {queued}: the waiting session"
        );
        // In flight: written, then removed `server`; queued: never written.
        let tomb = |h: &mut Harness| match h.store().lookup(&petya.kid) {
            Lookup::Removed(t) => t.origin.as_str(),
            Lookup::Unknown => "unknown",
            other => panic!("queued {queued}: {other:?}"),
        };
        let (gone, refused) = if queued {
            ("unknown", Verdict::KEY_UNKNOWN)
        } else {
            ("server", Verdict::KEY_REVOKED)
        };
        assert_eq!(tomb(&mut h), gone, "queued {queued}");
        request_as(&mut h, "s2", 456, &nonce(2));
        let d = offer_as(
            &mut h,
            "s2",
            &petya.proof("s2", &nonce(2), true, vec![]),
            true,
        );
        assert_eq!(d.verdict, refused, "queued {queued}");
        h.trusted.attach(TrustStore::open_in(&h.dir.0));
        assert_eq!(tomb(&mut h), gone, "queued {queued}: after a reopen");
        // The same grant replayed: spent (it was written) — on the removed key no ground there
        // (§10 «Повтор основания»): `key_revoked` — or over the token before the removal.
        request_as(&mut h, "s3", 456, &nonce(3));
        let d = offer_as(
            &mut h,
            "s3",
            &petya.proof(
                "s3",
                &nonce(3),
                true,
                vec![vera.grant_entry(&petya.kid, 456, 1)],
            ),
            true,
        );
        assert_eq!(
            d.verdict,
            if queued {
                Verdict::admit_refused("grant_stale")
            } else {
                Verdict::KEY_REVOKED
            },
            "queued {queued}: the old grant replayed"
        );
        // The owner's fresh grant on a new invitation, over the token the removal wrote, lets the
        // device in.
        request_as(&mut h, "s4", 456, &nonce(4));
        let at = u64::try_from(h.wall(1)).unwrap();
        let token = h.grant_token().unwrap();
        let p = petya.proof(
            "s4",
            &nonce(4),
            true,
            vec![vera.grant_entry_at(&petya.kid, 456, 5, at, token)],
        );
        let Outcome::AfterWrite(op) = offer_as(&mut h, "s4", &p, true).outcome else {
            panic!("queued {queued}: the fresh grant waits")
        };
        h.trusted.admit(*op);
        settle(&mut h, &mut rx).await;
        // With it lands the notes' write of the refused offers' attempts (§10.2).
        let mut s4 = None;
        for landed in h.trusted.take_landed() {
            let d = h.engine.landed(&mut h.trusted, landed);
            if let Some(s) = d.session.filter(|s| s.0 == "s4") {
                assert!(s4.is_none(), "queued {queued}: one landing of s4");
                s4 = Some(s);
            }
        }
        assert_eq!(
            s4,
            Some(("s4".to_string(), true, Verdict::SIGNED)),
            "queued {queued}: the fresh grant"
        );
        assert!(
            matches!(h.store().lookup(&petya.kid), Lookup::Active(r) if r.role == BindingRole::Guest),
            "queued {queued}: active again"
        );
    }
}

/// §7, §5: a grant is decided by the token at its install too — the agent's commit. The owner's
/// grant for guest G's key K (the current token, a new invitation) is written; while it is in
/// flight the token is replaced:
/// - `left`: G is removed on the server (no guest key to deny; G leaves the stored list: a new
///   token);
/// - `other`: another person's removal replaces the token;
/// - `none`: nothing in between (the control).
///
/// After a replacement the landing is stale: K never works (denied, its removal `server`), the
/// token stays the new one, and the strict session is refused `grant_stale`. The control admits
/// as before.
#[tokio::test]
async fn a_grant_whose_token_is_replaced_during_its_write_lands_stale() {
    for case in ["left", "other", "none"] {
        let vera = Signer::new();
        let mut state = state_of("strict", vec![vera.record(1001, "owner")]);
        state["bindings"] = json!([
            {"telegram_user_id": 1001, "role": "owner"},
            {"telegram_user_id": 456, "role": "guest"},
        ]);
        let mut h = Harness::new("stale at the install", &state, &[]);
        let mut rx = with_queue(&mut h);
        h.engine.insert_nonce_batch(0, vec![nonce(1)]);
        let token_a = h.grant_token().unwrap();
        let k = Signer::new();
        request_as(&mut h, "s1", 456, &nonce(1));
        let p = k.proof(
            "s1",
            &nonce(1),
            true,
            vec![vera.grant_entry_at(&k.kid, 456, 3, 1_000, token_a)],
        );
        let d = offer_as(&mut h, "s1", &p, true);
        assert_eq!(d.verdict, Verdict::SIGNED, "{case}");
        let Outcome::AfterWrite(op) = d.outcome else {
            panic!("{case}: the grant's write waits")
        };
        h.trusted.admit(*op);
        assert!(!h.trusted.settled(), "{case}: in flight");
        match case {
            "left" => {
                // `binding_removed(G)`: G leaves the stored list.
                assert!(h.store().note_last_bindings([KnownBinding {
                    telegram_user_id: 1001,
                    role: BindingRole::Owner,
                }]));
            }
            "other" => assert!(h.store().person_removed(789, "test: another removal")),
            _ => {}
        }
        let token_now = h.grant_token().unwrap();
        assert_eq!(token_now != token_a, case != "none", "{case}");
        settle(&mut h, &mut rx).await;
        let mut s1 = None;
        for landed in h.trusted.take_landed() {
            let d = h.engine.landed(&mut h.trusted, landed);
            if let Some(s) = d.session.filter(|s| s.0 == "s1") {
                s1 = Some(s);
            }
        }
        let works = matches!(h.store().lookup(&k.kid), Lookup::Active(_));
        if case == "none" {
            assert_eq!(s1, Some(("s1".into(), true, Verdict::SIGNED)), "{case}");
            assert!(works, "{case}: admitted as before");
            continue;
        }
        assert_eq!(
            s1,
            Some(("s1".into(), false, Verdict::admit_refused("grant_stale"))),
            "{case}"
        );
        assert!(
            !works,
            "{case}: K never works: {:?}",
            h.store().lookup(&k.kid)
        );
        // Its removal `server`: decided, or written by now.
        let origin = |s: &TrustStore| match s.lookup(&k.kid) {
            Lookup::Removed(t) => Some(t.origin.as_str()),
            _ => s.removal_decided(&k.kid),
        };
        assert_eq!(origin(&*h.store()), Some("server"), "{case}");
        assert_eq!(
            h.grant_token(),
            Some(token_now),
            "{case}: the new token stays"
        );
        settle(&mut h, &mut rx).await;
        let disk = TrustStore::open_in(&h.dir.0);
        assert_eq!(origin(&disk), Some("server"), "{case}: on disk");
    }
}

/// The offer `proof` of guest 456 as session `sid` (nonce `n`); when it waits for its write,
/// `between` runs while the write is in flight and the queue then runs out. The session's final
/// word, how many landings answered it, and the journal lines of the offer and of every landing.
async fn offer_landing(
    h: &mut Harness,
    rx: &mut tokio::sync::mpsc::UnboundedReceiver<TrustedDone>,
    sid: &str,
    n: &[u8; NONCE_PC_LEN],
    proof: &Value,
    between: impl FnOnce(&mut Harness),
) -> (Option<(String, bool, Verdict)>, usize, Vec<String>) {
    request_as(h, sid, 456, n);
    let d = offer_as(h, sid, proof, true);
    let mut journal: Vec<String> = d.journal.iter().map(JournalEvent::name).collect();
    let Outcome::AfterWrite(op) = d.outcome else {
        let admitted = matches!(d.outcome, Outcome::Admit);
        return (Some((sid.to_string(), admitted, d.verdict)), 1, journal);
    };
    h.trusted.admit(*op);
    assert!(!h.trusted.settled(), "{sid}: in flight");
    between(h);
    settle(h, rx).await;
    let (mut word, mut answers) = (None, 0);
    for landed in h.trusted.take_landed() {
        let ld = h.engine.landed(&mut h.trusted, landed);
        journal.extend(ld.journal.iter().map(JournalEvent::name));
        if let Some(s) = ld.session.filter(|s| s.0 == sid) {
            answers += 1;
            word = Some(s);
        }
    }
    settle(h, rx).await;
    (word, answers, journal)
}

/// Guest 456's key as the list has it: `Some(origin)` when removed, `None` when unknown, else
/// "active".
fn key_state(store: &TrustStore, k: &KeyId) -> Option<&'static str> {
    match store.lookup(k) {
        Lookup::Removed(t) => Some(t.origin.as_str()),
        Lookup::Active(_) => Some("active"),
        Lookup::Unknown => None,
        other => panic!("{other:?}"),
    }
}

/// Observe mode (§7, §10): guest 456's grant without its invitation (observe-only) lands stale —
/// another person's removal replaced the token during its write: the key is refused
/// `grant_stale` and removed `server`; the session goes on by its binding (observe). A fresh
/// grant without an invitation for the same device cannot take that tombstone back
/// (`invite_missing`, nothing changes); a grant with a new invitation over the current token can
/// (signed, the key active and confirmed). Refutes a stale landing that keeps an observe-only
/// key, and a key returning without the owner's invitation.
#[tokio::test]
async fn an_observe_grant_without_an_invitation_lands_stale_then_only_an_invitation_returns_it() {
    let vera = Signer::new();
    let mut state = state_of("observe", vec![vera.record(1001, "owner")]);
    state["bindings"] = json!([
        {"telegram_user_id": 1001, "role": "owner"},
        {"telegram_user_id": 456, "role": "guest"},
    ]);
    let mut h = Harness::new("observe, stale", &state, &[]);
    let mut rx = with_queue(&mut h);
    h.engine
        .insert_nonce_batch(0, vec![nonce(1), nonce(2), nonce(3)]);
    let bare = |mut e: Value| {
        e.as_object_mut().unwrap().remove("invite");
        e
    };
    let k = Signer::new();
    let token_a = h.grant_token().unwrap();
    let p = k.proof(
        "s1",
        &nonce(1),
        true,
        vec![bare(vera.grant_entry_at(&k.kid, 456, 3, 1_000, token_a))],
    );
    let (s1, answers, _) = offer_landing(&mut h, &mut rx, "s1", &nonce(1), &p, |h| {
        assert!(h.store().person_removed(789, "test: another removal"));
    })
    .await;
    assert_eq!(
        s1,
        Some(("s1".into(), true, Verdict::admit_refused("grant_stale")))
    );
    assert_eq!(answers, 1);
    assert_eq!(key_state(h.store(), &k.kid), Some("server"));
    let token_b = h.grant_token().unwrap();
    assert!(token_b != token_a);
    let before = list_state(&mut h);
    let p = k.proof(
        "s2",
        &nonce(2),
        true,
        vec![bare(vera.grant_entry_at(&k.kid, 456, 4, 1_000, token_b))],
    );
    let (s2, _, _) = offer_landing(&mut h, &mut rx, "s2", &nonce(2), &p, |_| {}).await;
    // The session goes on by its binding (observe); the key stays out: a removed key comes back
    // only with an invitation (§10.1).
    assert_eq!(
        s2,
        Some(("s2".into(), true, Verdict::admit_refused("invite_missing")))
    );
    assert_eq!(list_state(&mut h), before, "nothing changes");
    let p = k.proof(
        "s3",
        &nonce(3),
        true,
        vec![vera.grant_entry_at(&k.kid, 456, 5, 1_000, token_b)],
    );
    let (s3, _, _) = offer_landing(&mut h, &mut rx, "s3", &nonce(3), &p, |_| {}).await;
    assert_eq!(s3, Some(("s3".into(), true, Verdict::SIGNED)));
    assert!(matches!(
        h.store().lookup(&k.kid),
        Lookup::Active(r) if !r.unconfirmed
    ));
}

/// A stale landing over the key's own `server` tombstone (§7, §10): guest 456's key K was removed
/// by the server; the owner's invited grant over the current token would take it back, and is in
/// flight when another person's removal replaces the token. It lands stale: one answer,
/// `grant_stale`, no journal line of the admission's (the PC's journal has the key's removal
/// once: the trusted queue's test); K removed `server` again; the grant's id and its invitation's
/// spent (the write landed with them). The same grant again is no ground on the removed key
/// (§10 «Повтор основания»): `key_revoked`, K still removed. Refutes a stale
/// landing that leaves K back, or whose ids could be played again.
#[tokio::test]
async fn a_stale_grant_over_a_server_tombstone_leaves_it_and_spends_its_ids() {
    let vera = Signer::new();
    let k = Signer::new();
    let mut state = state_of("strict", vec![vera.record(1001, "owner")]);
    state["bindings"] = json!([
        {"telegram_user_id": 1001, "role": "owner"},
        {"telegram_user_id": 456, "role": "guest"},
    ]);
    state["revoked"] = json!([{
        "key_id": k.kid.as_str(), "spki": b64(&k.spki), "telegram_user_id": 456,
        "origin": "server", "removed_at": 0,
    }]);
    let mut h = Harness::new("stale over a tombstone", &state, &[]);
    let mut rx = with_queue(&mut h);
    h.engine.insert_nonce_batch(0, vec![nonce(1), nonce(2)]);
    assert_eq!(key_state(h.store(), &k.kid), Some("server"));
    let token_a = h.grant_token().unwrap();
    let entry = vera.grant_entry_at(&k.kid, 456, 3, 1_000, token_a);
    let p = k.proof("s1", &nonce(1), true, vec![entry.clone()]);
    let (s1, answers, journal) = offer_landing(&mut h, &mut rx, "s1", &nonce(1), &p, |h| {
        assert!(h.store().person_removed(789, "test: another removal"));
    })
    .await;
    assert_eq!(
        s1,
        Some(("s1".into(), false, Verdict::admit_refused("grant_stale")))
    );
    assert_eq!(answers, 1, "one answer");
    assert!(journal.is_empty(), "{journal:?}");
    assert_eq!(key_state(h.store(), &k.kid), Some("server"));
    assert_eq!(
        key_state(&TrustStore::open_in(&h.dir.0), &k.kid),
        Some("server"),
        "on disk"
    );
    let (_, _, spent) = list_state(&mut h);
    for id in [b64(&[3u8; 16]), b64(&[103u8; 16])] {
        assert!(spent.contains(&id), "{id} spent: {spent:?}");
    }
    let p = k.proof("s2", &nonce(2), true, vec![entry]);
    let (s2, _, _) = offer_landing(&mut h, &mut rx, "s2", &nonce(2), &p, |_| {}).await;
    assert_eq!(s2, Some(("s2".into(), false, Verdict::KEY_REVOKED)));
    assert_eq!(key_state(h.store(), &k.kid), Some("server"));
}

/// Item 11, on the list (§10.2): the window is published for a new device's attempt, and for the
/// same device again only once its shown time is a minute old — a device that keeps trying does
/// not republish it on every offer. The list counts every try all the same.
#[test]
fn a_repeated_attempt_republishes_the_window_only_when_due() {
    let vera = Signer::new();
    let mut h = Harness::new(
        "republish",
        &state_of("strict", vec![vera.record(1001, "owner")]),
        &[],
    );
    let (mut t, view) = Trusted::new(Arc::new(|_| {}));
    t.attach(TrustStore::open_in(&h.dir.0));
    h.trusted = t;
    let x = Signer::new();
    let note = |h: &mut Harness, x: &Signer, at: i64| {
        let store = h.trusted.store_for_notes().unwrap();
        let new = store.note_attempt(
            crate::viewer_keys::Attempt {
                telegram_user_id: 1001,
                role: BindingRole::Owner,
                key: crate::viewer_keys::ViewerKey::from_spki(&x.spki).unwrap(),
                kind: crate::viewer_keys::ClientKind::parse("telegram").unwrap(),
                platform: crate::viewer_keys::Platform::parse("iphone").unwrap(),
                rpk: None,
                first_at: at,
                last_at: at,
                count: 1,
            },
            at,
        );
        h.trusted.attempt_noted(1001, &x.kid, new, at);
        new
    };
    let rev = |v: &tokio::sync::watch::Receiver<Arc<crate::trusted::TrustedView>>| v.borrow().rev;
    let shown = |v: &tokio::sync::watch::Receiver<Arc<crate::trusted::TrustedView>>| {
        v.borrow().people[0]
            .attempts
            .iter()
            .map(|a| (a.last_at_ms, a.count))
            .collect::<Vec<_>>()
    };
    let t0 = crate::journal::now_ms();
    let r0 = rev(&view);
    assert!(note(&mut h, &x, t0));
    let r1 = rev(&view);
    assert!(r1 > r0, "a new device's attempt is published");
    for at in [t0 + 500, t0 + 30_000, t0 + 59_999] {
        assert!(!note(&mut h, &x, at));
        assert_eq!(rev(&view), r1, "the same device again at {at}: no new view");
    }
    assert_eq!(shown(&view), [(t0, 1)], "the shown time");
    assert!(!note(&mut h, &x, t0 + 60_000));
    assert!(rev(&view) > r1, "a minute on: the time is shown anew");
    assert_eq!(shown(&view), [(t0 + 60_000, 5)], "every try counted");
    let r2 = rev(&view);
    assert!(note(&mut h, &Signer::new(), t0 + 60_001));
    assert!(rev(&view) > r2, "another device: published");
}

/// §10.2: an offer whose ground passed at the decision and whose key the list refuses at
/// the queue's turn — `admit_refused:grant_stale` (another person's removal replaced the grant
/// token meanwhile) — is
/// another device's attempt as a refusal at the decision is — kept for the window and for the
/// journal's path — once the final decision is known; before it, nothing is noted.
#[test]
fn a_refusal_at_the_queues_turn_is_another_devices_attempt() {
    let reason = "grant_stale";
    let vera = Signer::new();
    let mut h = Harness::new(
        "attempt at the queue",
        &state_of("strict", vec![vera.record(1001, "owner")]),
        &[],
    );
    h.engine.set_bindings(
        &mut h.trusted,
        [(1001, BindingRole::Owner), (456, BindingRole::Guest)],
    );
    h.engine.insert_nonce_batch(0, vec![nonce(1)]);
    let wall = h.wall(1000);
    let token = h.grant_token().unwrap();
    let petya = Signer::new();
    request_as(&mut h, "s1", 456, &nonce(1));
    let p = petya.proof(
        "s1",
        &nonce(1),
        true,
        vec![vera.grant_entry_at(&petya.kid, 456, 1, 1_000, token)],
    );
    let d = offer_as(&mut h, "s1", &p, true);
    let Outcome::AfterWrite(op) = d.outcome else {
        panic!("{reason}: the grant's write waits: {:?}", d.verdict)
    };
    assert!(d.attempts.is_empty());
    assert!(
        h.trusted.attempts_of(456).is_empty(),
        "{reason}: not before the end"
    );
    assert!(h.store().person_removed(777, "test: another removal"));
    assert_ne!(h.grant_token(), Some(token));
    let landed = h.apply(*op, wall);
    let ld = h.engine.landed(&mut h.trusted, landed);
    assert_eq!(
        ld.session,
        Some(("s1".into(), false, Verdict::admit_refused(reason)))
    );
    let kept = h.trusted.attempts_of(456);
    assert_eq!(kept.len(), 1, "{reason}: kept for the window: {kept:?}");
    assert_eq!(kept[0].key_id, petya.kid);
    assert_eq!(kept[0].device.platform.as_str(), "iphone");
    let [a] = <[_; 1]>::try_from(ld.attempts).expect("one for the journal");
    assert_eq!((a.telegram_user_id, a.reason), (456, reason));
    assert_eq!(a.key_id, petya.kid);
    assert!(h.trusted.store().unwrap().notes_unsaved());
    assert!(
        !h.trusted.settled(),
        "{reason}: a write of the notes is queued"
    );
}

/// Contract 7593e83 (§5, `ignored_repeat`): every `pair_request` waits by its id, with or without
/// a key, and the first wins — a repeat under a waiting id changes neither its person nor its
/// key. The waiting requests are bounded: over [`PAIR_WAITING_MAX`] the one that came first is
/// forgotten; a cancel or [`PAIR_WAIT`] ends one too, and then the id is a new request.
#[test]
fn waiting_pair_requests_are_bounded_and_the_first_wins() {
    let mut h = Harness::new("pair waits", &empty_state("observe"), &[]);
    fn req(id: &str, uid: i64) -> PairRequest<'_> {
        PairRequest {
            request_id: id,
            telegram_user_id: uid,
            first_name: None,
            username: None,
            viewer_key: None,
        }
    }
    let ids: Vec<String> = (0..=PAIR_WAITING_MAX).map(|i| format!("r{i}")).collect();
    assert_eq!(
        h.engine.pair_request(&req(&ids[0], 100)),
        ViewerKeyOutcome::Absent
    );
    // The repeat of a waiting id names another person: the first stays.
    assert_eq!(
        h.engine.pair_request(&req(&ids[0], 666)),
        ViewerKeyOutcome::Absent
    );
    let first = |h: &Harness, id: &str| h.engine.pair_waiting(id).map(|(p, _)| p.telegram_user_id);
    assert_eq!(first(&h, &ids[0]), Some(100));
    for (i, id) in ids.iter().enumerate().skip(1) {
        h.engine.pair_request(&req(id, 100 + i as i64));
    }
    assert_eq!(
        first(&h, &ids[0]),
        None,
        "the first that came is forgotten at the bound"
    );
    assert_eq!(first(&h, &ids[1]), Some(101));
    assert_eq!(
        first(&h, &ids[PAIR_WAITING_MAX]),
        Some(100 + PAIR_WAITING_MAX as i64)
    );
    // Gone, the id is a new request.
    h.engine.pair_request(&req(&ids[0], 666));
    assert_eq!(first(&h, &ids[0]), Some(666));
    h.engine.pair_cancelled(&ids[1]);
    assert_eq!(first(&h, &ids[1]), None, "a cancel ends it");
    h.engine.age_pairs(PAIR_WAIT);
    h.engine.pair_request(&req("fresh", 7));
    assert_eq!(first(&h, &ids[2]), None, "past PAIR_WAIT it is forgotten");
    assert_eq!(first(&h, "fresh"), Some(7));
}

// --- G1: freshness of a press -------------------------------------------------------------------

/// The request on screen is never the one forgotten at
/// [`PAIR_WAITING_MAX`]: the oldest other one goes instead.
#[test]
fn the_request_on_screen_is_never_forgotten_at_the_bound() {
    let mut h = Harness::new("on screen", &empty_state("observe"), &[]);
    fn req(id: &str, uid: i64) -> PairRequest<'_> {
        PairRequest {
            request_id: id,
            telegram_user_id: uid,
            first_name: None,
            username: None,
            viewer_key: None,
        }
    }
    h.engine.pair_request(&req("shown", 5));
    h.engine.pair_shown(Some("shown"));
    for i in 0..PAIR_WAITING_MAX {
        h.engine
            .pair_request(&req(&format!("r{i}"), 100 + i as i64));
    }
    assert!(h.engine.pair_waiting("shown").is_some(), "on screen: kept");
    assert!(
        h.engine.pair_waiting("r0").is_none(),
        "the oldest other one is forgotten"
    );
    assert!(h.engine.pair_waiting("r1").is_some());
}

// --- What «Разрешить» on a pairing request gives (§5): the window's word is the press's ----------

/// State by state — the mode, a clean or tainted opening, a key, none, `pc_allow` — the plan the
/// window reads ([`Admission::pair_plan`]) is what the press then writes ([`Admission::pair_allow`]),
/// and whether the person can connect after it is said from that plan: strict only with a
/// confirmed key, observe by the binding. Refutes a window that offers «Разрешить» whose press
/// cannot let the person in, or a second copy of the press's rules drifting from it.
#[test]
fn the_pairing_plan_the_window_reads_is_what_the_press_writes() {
    for mode in ["observe", "strict"] {
        for dirty in [false, true] {
            for (what, with_key, via) in [
                ("a key", true, false),
                ("no key", false, false),
                ("pc_allow", true, true),
            ] {
                let case = format!(
                    "{mode}, {}, {what}",
                    if dirty { "tainted" } else { "clean" }
                );
                let vera = Signer::new();
                let mut h = Harness::new(
                    "pair_plan",
                    &state_of(mode, vec![vera.record(1001, "owner")]),
                    &[],
                );
                h.engine.pairing_panel(&h.trusted, true);
                let card = Signer::new().key_reg();
                h.engine.pair_request(&PairRequest {
                    request_id: "r1",
                    telegram_user_id: 456,
                    first_name: Some("Петя"),
                    username: None,
                    viewer_key: with_key.then_some(&card),
                });
                if dirty {
                    h.trusted.session_began("session_request", "s9");
                }
                let plan = h
                    .engine
                    .pair_plan(&h.trusted, "r1", BindingRole::Guest, via)
                    .expect("the request waits");
                let d = h
                    .engine
                    .pair_allow(&h.trusted, "r1", None, BindingRole::Guest, via, false);
                let did = match (&d.op, d.key_id.is_some()) {
                    (Some(_), _) => PairPlan::Writes {
                        unconfirmed: d.unconfirmed,
                    },
                    (None, true) => PairPlan::Refused {
                        tainted: dirty,
                        cause: KeyRefusal::Unavailable,
                    },
                    // `BindingAdded` adds it (observe) — strict refuses an unconfirmed key.
                    (None, false) if with_key && via => PairPlan::PcAllow {
                        lands: if mode == "strict" {
                            KeyLanding::Refused(KeyRefusal::Unavailable)
                        } else {
                            KeyLanding::Writes
                        },
                    },
                    (None, false) => PairPlan::NoKey,
                };
                assert_eq!(plan, did, "{case}: the plan is the press");
                let strict = mode == "strict";
                let connects = !strict || (with_key && !via && !dirty);
                assert_eq!(plan.gives(strict).connects(), connects, "{case}: connects");
            }
        }
    }
}

/// One pairing state of [`the_pairing_reading_is_the_press_and_the_next_session_in_every_state`].
#[derive(Clone, Copy)]
struct PairState {
    what: &'static str,
    uid: i64,
    via: bool,
    /// A session ran since the panel opened.
    dirty: bool,
    /// The plan, observe then strict.
    plan: [PairPlan; 2],
    /// What the window says, observe then strict.
    gives: [PairGives; 2],
    /// The device line, observe then strict.
    device: [PairDevice; 2],
}

/// The request window's reading, state by state in both modes: the plan the window reads is what
/// the press takes, what it says to the person is what their NEXT SESSION then gets, and the
/// device line never promises a key the list does not write. Each state is pressed, its write
/// installed, and a session of the person run. Pins the listed-but-not-working record
/// (unconfirmed): nothing written, and in strict the window says it waits for «Подтвердить».
/// Refutes a window that
/// offers a press whose person is then refused, or says «Станет доверенным» for a key not written.
#[test]
fn the_pairing_reading_is_the_press_and_the_next_session_in_every_state() {
    use PairDevice as D;
    use PairGives as G;
    let refused = |cause| PairPlan::Refused {
        tainted: false,
        cause,
    };
    let state = |what, uid, plan: [PairPlan; 2], gives: [PairGives; 2], device| PairState {
        what,
        uid,
        via: false,
        dirty: false,
        plan,
        gives,
        device,
    };
    let fresh = PairPlan::Writes { unconfirmed: false };
    let waiting = PairPlan::Already { works: false };
    let cases = [
        state(
            "a new key",
            456,
            [fresh; 2],
            [G::Connects; 2],
            [D::Trusted { again: false }; 2],
        ),
        state(
            "another person's key",
            456,
            [refused(KeyRefusal::OtherPerson); 2],
            [G::Connects, G::OtherPerson],
            [D::OtherPerson; 2],
        ),
        state(
            "a full list",
            456,
            [refused(KeyRefusal::Full); 2],
            [G::Connects, G::ListClosed],
            [D::ListFull; 2],
        ),
        state(
            "a damaged list",
            456,
            [refused(KeyRefusal::Unavailable); 2],
            [G::Connects, G::ListClosed],
            [D::ListUnavailable; 2],
        ),
        state(
            "the person's own key, listed",
            456,
            [PairPlan::Already { works: true }; 2],
            [G::Added; 2],
            [D::Added; 2],
        ),
        state(
            "the person's own key, listed unconfirmed",
            456,
            [waiting; 2],
            [G::Connects, G::ListedWaiting],
            [D::ListedWaiting; 2],
        ),
        PairState {
            dirty: true,
            ..state(
                "a new key, dirty",
                456,
                [
                    PairPlan::Writes { unconfirmed: true },
                    PairPlan::Refused {
                        tainted: true,
                        cause: KeyRefusal::Unavailable,
                    },
                ],
                [G::Connects, G::Session],
                [D::Unconfirmed { again: false }, D::NotTrusted],
            )
        },
        state(
            "the owner's own owner key, listed",
            1001,
            [PairPlan::Already { works: true }; 2],
            [G::Added; 2],
            [D::Added; 2],
        ),
        PairState {
            via: true,
            ..state(
                "the owner via pc_allow",
                1001,
                [PairPlan::OwnerPcAllow; 2],
                [G::Session; 2],
                [D::None; 2],
            )
        },
    ];
    for (m, mode) in ["observe", "strict"].into_iter().enumerate() {
        for c in &cases {
            pair_state_case(mode, m, c);
        }
    }
}

fn pair_state_case(mode: &str, m: usize, c: &PairState) {
    let case = format!("{mode}, {}", c.what);
    let strict = mode == "strict";
    let vera = Signer::new();
    let card = Signer::new();
    let mut keys = vec![vera.record(1001, "owner")];
    let (request_card, holder) = match c.what {
        "another person's key" | "the owner's own owner key, listed" => (vera.key_reg(), &vera),
        w if w.starts_with("the person's own key, listed") => {
            let mut r = card.record(456, "guest");
            r["unconfirmed"] = json!(w.contains("unconfirmed"));
            keys.push(r);
            (card.key_reg(), &card)
        }
        _ => (card.key_reg(), &card),
    };
    let mut state = state_of(mode, keys);
    if c.what == "a full list" {
        with_petya(&mut state, crate::viewer_keys::MAX_KEYS_PER_PERSON, "guest");
    }
    let mut h = Harness::new("pair_state", &state, &[]);
    if c.what == "a damaged list" {
        damage_list(&mut h);
    }
    h.engine.pairing_panel(&h.trusted, true);
    h.engine.pair_request(&PairRequest {
        request_id: "r1",
        telegram_user_id: c.uid,
        first_name: Some("Петя"),
        username: None,
        viewer_key: Some(&request_card),
    });
    if c.dirty {
        h.trusted.session_began("session_request", "s9");
    }
    let role = h.trusted.pair_role(c.uid).unwrap_or(BindingRole::Guest);
    let plan = h
        .engine
        .pair_plan(&h.trusted, "r1", role, c.via)
        .expect("the request waits");
    assert_eq!(plan, c.plan[m], "{case}: the plan");
    let gives = plan.gives(strict);
    assert_eq!(gives, c.gives[m], "{case}: what the window says");
    assert_eq!(
        plan.device(strict, false),
        c.device[m],
        "{case}: the device line"
    );
    if !gives.connects() {
        // Not offered, so no press: the person's next session is what the window says — refused
        // in strict, admitted by the binding in observe.
        let d = next_session(&mut h, c, holder);
        assert_eq!(
            d.admitted(),
            !strict,
            "{case}: not offered, the next session ({:?})",
            d.verdict
        );
        return;
    }
    // The press the window offers.
    let d = h
        .engine
        .pair_allow(&h.trusted, "r1", Some(c.uid), role, c.via, false);
    assert!(
        !d.second_step_required && !d.role_refused && !d.not_waiting,
        "{case}: the press is answered"
    );
    let wrote = d.op.is_some();
    assert_eq!(
        wrote,
        matches!(plan, PairPlan::Writes { .. }),
        "{case}: a write only for a key the plan writes"
    );
    if let Some(op) = d.op {
        assert!(h.apply(op, 1_000).result.is_ok(), "{case}: the write lands");
    }
    if plan == PairPlan::OwnerPcAllow {
        // Not offered by the rule above; nothing more of it here.
        return;
    }
    let d = next_session(&mut h, c, holder);
    assert!(
        d.admitted(),
        "{case}: the window offered «Разрешить», so the next session is admitted ({:?})",
        d.verdict
    );
}

/// The person's next session, bound: signed by the request's device — the binding alone for
/// another person's key, which is not theirs to sign with.
fn next_session(h: &mut Harness, c: &PairState, holder: &Signer) -> OfferDecision {
    h.engine.insert_nonce_batch(0, vec![nonce(1)]);
    if c.what == "another person's key" {
        unsigned_request(h, "s1");
        unsigned_offer(h, "s1", true)
    } else {
        request_as(h, "s1", c.uid, &nonce(1));
        let p = holder.proof("s1", &nonce(1), true, vec![]);
        offer_as(h, "s1", &p, true)
    }
}

/// What the window says when the press would not connect, checked against the session: in strict
/// the person of a listed-but-not-working key, of another person's key, of a full or damaged list
/// is refused (the window offers nothing there).
#[test]
fn a_strict_press_the_window_does_not_offer_leaves_the_person_out() {
    let card = Signer::new();
    let vera = Signer::new();
    let mut r = card.record(456, "guest");
    r["unconfirmed"] = json!(true);
    let state = state_of("strict", vec![vera.record(1001, "owner"), r]);
    let mut h = Harness::new("strict_listed", &state, &[]);
    h.engine.insert_nonce_batch(0, vec![nonce(1)]);
    request_as(&mut h, "s1", 456, &nonce(1));
    let p = card.proof("s1", &nonce(1), true, vec![]);
    let d = offer_as(&mut h, "s1", &p, true);
    assert!(
        !d.admitted(),
        "listed unconfirmed: refused ({:?})",
        d.verdict
    );
}

/// §5: the role is the PERSON's, derived whenever the PC has an owner — a keyless request naming
/// the owner's role for someone who is not an owner here is refused `role`, as one with a key:
/// nothing written, nothing answered, the request still waits; the derived role goes.
#[test]
fn the_derived_role_holds_for_a_keyless_request() {
    for (what, with_key, via) in [
        ("a keyless request", false, false),
        ("a key", true, false),
        ("a keyless request via pc_allow", false, true),
        ("a key via pc_allow", true, true),
    ] {
        let vera = Signer::new();
        let mut h = Harness::new(
            "role_first",
            &state_of("observe", vec![vera.record(1001, "owner")]),
            &[],
        );
        h.engine.pairing_panel(&h.trusted, true);
        let card = Signer::new().key_reg();
        h.engine.pair_request(&PairRequest {
            request_id: "r1",
            telegram_user_id: 456,
            first_name: Some("Петя"),
            username: None,
            viewer_key: with_key.then_some(&card),
        });
        assert_eq!(
            h.engine
                .pair_plan(&h.trusted, "r1", BindingRole::Owner, via),
            Some(PairPlan::Role),
            "{what}: the plan"
        );
        let d = h
            .engine
            .pair_allow(&h.trusted, "r1", Some(456), BindingRole::Owner, via, false);
        assert!(d.role_refused && d.op.is_none(), "{what}: refused role");
        assert!(h.engine.pair_waiting("r1").is_some(), "{what}: still waits");
        let d = h
            .engine
            .pair_allow(&h.trusted, "r1", Some(456), BindingRole::Guest, via, false);
        assert!(!d.role_refused, "{what}: the derived role goes");
    }
}

/// §5, one rule for every press, `pc_allow` included: the owner by the bindings demoted while
/// his request is on screen (another owner's key stays, so the PC derives a guest's role for him
/// now) — a `pc_allow` press still naming the owner is refused `role`, nothing kept; on a PC with no
/// owner at all a `pc_allow` press names only a guest; a direct press there chooses the role as
/// before.
#[test]
fn a_pc_allow_press_names_the_derived_role_like_any_press() {
    let vera = Signer::new();
    let mut h = Harness::new(
        "pc_allow_role",
        &state_of("observe", vec![vera.record(1001, "owner")]),
        &[],
    );
    h.engine
        .note_binding(&mut h.trusted, 456, BindingRole::Owner);
    h.engine.pairing_panel(&h.trusted, true);
    let card = Signer::new().key_reg();
    h.engine.pair_request(&PairRequest {
        request_id: "r1",
        telegram_user_id: 456,
        first_name: Some("Петя"),
        username: None,
        viewer_key: Some(&card),
    });
    assert_eq!(press_role(&h.trusted, 456, true), Some(BindingRole::Owner));
    h.engine.owner_changed(&mut h.trusted, None);
    assert_eq!(press_role(&h.trusted, 456, true), Some(BindingRole::Guest));
    let d = h
        .engine
        .pair_allow(&h.trusted, "r1", Some(456), BindingRole::Owner, true, false);
    assert!(
        d.role_refused && d.op.is_none(),
        "the old owner's role: refused"
    );
    assert!(h.engine.pair_waiting("r1").is_some(), "still waits");
    let d = h.engine.binding_added(&h.trusted, 456);
    assert!(
        d.op.is_none() && d.key_id.is_none(),
        "nothing kept for BindingAdded"
    );

    // No owner at all: via `pc_allow` only a guest; a direct press chooses.
    let mut h = Harness::new("no_owner", &state_of("observe", vec![]), &[]);
    h.engine.pairing_panel(&h.trusted, true);
    h.engine.pair_request(&PairRequest {
        request_id: "r1",
        telegram_user_id: 456,
        first_name: Some("Петя"),
        username: None,
        viewer_key: None,
    });
    assert_eq!(press_role(&h.trusted, 456, true), Some(BindingRole::Guest));
    assert_eq!(press_role(&h.trusted, 456, false), None, "chosen at the PC");
    for (via, refused) in [(true, true), (false, false)] {
        let d = h
            .engine
            .pair_allow(&h.trusted, "r1", Some(456), BindingRole::Owner, via, false);
        assert_eq!(d.role_refused, refused, "via pc_allow {via}");
    }
}

/// §5: observe `pc_allow` promises a device only when `BindingAdded` would write it — the plan
/// reads the activation's own check. A full list, another person's key and the person's own key
/// listed already: the device line names it, `BindingAdded` writes nothing, and the person's next
/// session is admitted by the binding.
#[test]
fn an_observe_pc_allow_device_line_is_what_binding_added_does() {
    for what in [
        "a full list",
        "another person's key",
        "the person's own key, listed",
    ] {
        let vera = Signer::new();
        let card = Signer::new();
        let mut keys = vec![vera.record(1001, "owner")];
        if what == "the person's own key, listed" {
            keys.push(card.record(456, "guest"));
        }
        let mut state = state_of("observe", keys);
        if what == "a full list" {
            with_petya(&mut state, crate::viewer_keys::MAX_KEYS_PER_PERSON, "guest");
        }
        let mut h = Harness::new("pc_allow_lands", &state, &[]);
        h.engine.pairing_panel(&h.trusted, true);
        let reg = if what == "another person's key" {
            vera.key_reg()
        } else {
            card.key_reg()
        };
        h.engine.pair_request(&PairRequest {
            request_id: "r1",
            telegram_user_id: 456,
            first_name: Some("Петя"),
            username: None,
            viewer_key: Some(&reg),
        });
        let plan = h
            .engine
            .pair_plan(&h.trusted, "r1", BindingRole::Guest, true)
            .expect("waits");
        let (lands, device) = match what {
            "a full list" => (KeyLanding::Refused(KeyRefusal::Full), PairDevice::ListFull),
            "another person's key" => (
                KeyLanding::Refused(KeyRefusal::OtherPerson),
                PairDevice::OtherPerson,
            ),
            _ => (KeyLanding::Already { works: true }, PairDevice::Added),
        };
        assert_eq!(plan, PairPlan::PcAllow { lands }, "{what}");
        assert_eq!(plan.device(false, false), device, "{what}");
        assert_eq!(plan.gives(false), PairGives::Connects, "{what}");
        let d = h
            .engine
            .pair_allow(&h.trusted, "r1", Some(456), BindingRole::Guest, true, false);
        assert!(
            d.op.is_none() && !d.role_refused,
            "{what}: waits for BindingAdded"
        );
        h.engine
            .note_binding(&mut h.trusted, 456, BindingRole::Guest);
        let d = h.engine.binding_added(&h.trusted, 456);
        assert!(d.op.is_none(), "{what}: BindingAdded writes nothing");
        h.engine.insert_nonce_batch(0, vec![nonce(1)]);
        unsigned_request(&mut h, "s1");
        let d = unsigned_offer(&mut h, "s1", true);
        assert!(
            d.admitted(),
            "{what}: admitted by the binding ({:?})",
            d.verdict
        );
    }
}

/// §5: a `pc_allow` key activated by `BindingAdded` as a guest's waits for its stage behind
/// another write; `owner_changed` names that person the owner meanwhile — the stage reads the
/// role again and writes no guest key (`role_changed`). Control: an unchanged guest gets it.
#[test]
fn a_pc_allow_key_whose_person_became_the_owner_before_its_stage_is_not_written() {
    for promoted in [true, false] {
        let case = if promoted {
            "promoted"
        } else {
            "still a guest"
        };
        let mut h = pc_allow_waiting();
        h.engine
            .note_binding(&mut h.trusted, 456, BindingRole::Guest);
        let d = h.engine.binding_added(&h.trusted, 456);
        let kid = d.key_id.clone().expect("the key");
        let op = d.op.expect("queued: a guest's key, unconfirmed");
        if promoted {
            h.engine.owner_changed(&mut h.trusted, Some(456));
        }
        let landed = h.apply(op, 1_000);
        let written = matches!(
            h.store().lookup(&kid),
            crate::viewer_keys::Lookup::Active(_)
        );
        if promoted {
            assert!(
                matches!(landed.result, Err(StoreError::RoleChanged)),
                "{case}: {:?}",
                landed.result
            );
            assert!(!written, "{case}: no guest key for the owner");
        } else {
            assert!(
                landed.result.is_ok() && written,
                "{case}: the guest's key lands"
            );
        }
    }
}

// --- The owner's own device (§5): pairing at the PC derives the role -------------------

/// A pairing request of `uid` holding `signer`'s card, on a panel opened now.
fn paired_request(h: &mut Harness, uid: i64, signer: &Signer) {
    h.engine.pairing_panel(&h.trusted, true);
    let card = signer.key_reg();
    assert_eq!(
        h.engine.pair_request(&PairRequest {
            request_id: "r1",
            telegram_user_id: uid,
            first_name: Some("Вера"),
            username: None,
            viewer_key: Some(&card),
        }),
        ViewerKeyOutcome::Accepted
    );
}

/// A strict list with no key at all and the owner in the `first_use` snapshot and the bindings: the
/// owner shut out of his own PC.
fn locked_out_owner() -> Harness {
    let mut state = state_of("strict", vec![]);
    state["snapshot"] = json!([{"telegram_user_id": 1001, "role": "owner"}]);
    state["bindings"] = json!([{"telegram_user_id": 1001, "role": "owner"}]);
    let mut h = Harness::new("locked out", &state, &[]);
    h.trusted.set_bound_owners([1001]);
    h
}

/// The way out of a strict lockout: strict mode, the owner bound, no key. His pairing at the PC
/// with a valid key — offered (`connects`), the owner's role derived — waits for
/// «Это моё устройство», then writes an owner key, confirmed; the switch's reading turns ready and
/// his next session is admitted, signed by a confirmed owner key (it does not count against the
/// window).
#[test]
fn the_owners_pairing_with_the_step_ends_the_strict_lockout() {
    let mut h = locked_out_owner();
    assert_eq!(
        h.store().owner_device(),
        crate::viewer_keys::OwnerDevice::Missing
    );
    let me = Signer::new();
    paired_request(&mut h, 1001, &me);
    assert!(h.trusted.owner_on_pc(1001));
    assert_eq!(h.trusted.pair_role(1001), Some(BindingRole::Owner));
    let plan = h
        .engine
        .pair_plan(&h.trusted, "r1", BindingRole::Owner, false)
        .unwrap();
    assert_eq!(plan, PairPlan::Writes { unconfirmed: false });
    assert_eq!(plan.gives(true), PairGives::Connects, "offered");

    let d = h.engine.pair_allow(
        &h.trusted,
        "r1",
        Some(1001),
        BindingRole::Owner,
        false,
        false,
    );
    assert!(
        d.second_step_required && d.op.is_none() && d.refused.is_none(),
        "no «Это моё устройство»: nothing changes"
    );
    assert!(
        h.engine.pair_waiting("r1").is_some(),
        "the request still waits"
    );

    let d = h.engine.pair_allow(
        &h.trusted,
        "r1",
        Some(1001),
        BindingRole::Owner,
        false,
        true,
    );
    assert!(!d.unconfirmed && d.refused.is_none());
    let op = d.op.expect("the owner's key goes to the list");
    let landed = h.apply(op, 1000);
    h.engine.landed(&mut h.trusted, landed);
    match h.store().lookup(&me.kid) {
        crate::viewer_keys::Lookup::Active(r) => {
            assert_eq!((r.role, r.unconfirmed), (BindingRole::Owner, false));
        }
        other => panic!("the key is not active: {other:?}"),
    }
    assert_eq!(
        h.store().owner_device(),
        crate::viewer_keys::OwnerDevice::Ready
    );

    h.engine.insert_nonce_batch(0, vec![nonce(1)]);
    request_as(&mut h, "s-owner", 1001, &nonce(1));
    let d = offer_as(
        &mut h,
        "s-owner",
        &me.proof("s-owner", &nonce(1), false, vec![]),
        true,
    );
    assert!(
        d.admitted() && d.verdict == Verdict::SIGNED,
        "{:?}",
        d.verdict
    );
    assert_eq!(h.engine.counting(), 0, "a confirmed owner key's session");
}

/// §5: with an owner on the PC the press's role must be the derived one — the owner pressing a
/// guest's, a guest pressing the owner's: refused `role`, nothing written, the request still
/// waits (the right role then goes), the plan says so.
#[test]
fn a_pairing_role_other_than_the_derived_one_is_refused_role() {
    for (uid, pressed) in [(1001, BindingRole::Guest), (456, BindingRole::Owner)] {
        let mut h = locked_out_owner();
        let s = Signer::new();
        paired_request(&mut h, uid, &s);
        assert_eq!(
            h.engine.pair_plan(&h.trusted, "r1", pressed, false),
            Some(PairPlan::Role),
            "user {uid}"
        );
        let d = h
            .engine
            .pair_allow(&h.trusted, "r1", Some(uid), pressed, false, true);
        assert!(d.op.is_none(), "user {uid}: nothing written");
        assert!(d.role_refused && d.refused.is_none(), "user {uid}: {d:?}");
        assert!(matches!(
            h.store().lookup(&s.kid),
            crate::viewer_keys::Lookup::Unknown
        ));
        assert!(
            h.engine.pair_waiting("r1").is_some(),
            "user {uid}: the request still waits"
        );
    }
}

/// §5: `pc_allow` from an owner on this PC takes no key (`BindingAdded` would land a
/// guest's); the binding goes as today.
#[test]
fn pc_allow_from_an_owner_on_this_pc_takes_no_key() {
    let mut state = state_of("observe", vec![]);
    state["bindings"] = json!([{"telegram_user_id": 1001, "role": "owner"}]);
    let mut h = Harness::new("pc_allow owner", &state, &[]);
    h.trusted.set_bound_owners([1001]);
    let me = Signer::new();
    paired_request(&mut h, 1001, &me);
    let d = h.engine.pair_allow(
        &h.trusted,
        "r1",
        Some(1001),
        BindingRole::Owner,
        true,
        false,
    );
    assert!(d.op.is_none() && d.refused.is_none() && !d.second_step_required);
    let d = h.engine.binding_added(&h.trusted, 1001);
    assert!(d.op.is_none(), "no key waited for BindingAdded");
    assert!(matches!(
        h.store().lookup(&me.kid),
        crate::viewer_keys::Lookup::Unknown
    ));
}

/// §5: the owner's pairing of a key that is already his own guest-role record lifts that
/// record to the owner's role (confirmed with a clean window); in strict mode with a dirty window
/// it stays a guest's and nothing is written. Only a pairing at the PC lifts it: no other ground
/// takes a key that is in the list already.
#[test]
fn the_owners_pairing_lifts_his_own_guest_record_only_at_the_pc() {
    for (mode, dirty) in [("observe", false), ("strict", false), ("strict", true)] {
        let case = format!("{mode}, {}", if dirty { "tainted" } else { "clean" });
        let me = Signer::new();
        let mut state = state_of(mode, vec![me.record(1001, "guest")]);
        state["bindings"] = json!([{"telegram_user_id": 1001, "role": "owner"}]);
        let mut h = Harness::new("lift", &state, &[]);
        h.trusted.set_bound_owners([1001]);
        paired_request(&mut h, 1001, &me);
        if dirty {
            h.trusted.session_began("session_request", "s9");
        }
        let d = h.engine.pair_allow(
            &h.trusted,
            "r1",
            Some(1001),
            BindingRole::Owner,
            false,
            true,
        );
        let lookup = |h: &mut Harness| match h.store().lookup(&me.kid) {
            crate::viewer_keys::Lookup::Active(r) => (r.role, r.unconfirmed),
            other => panic!("{case}: the key is not active: {other:?}"),
        };
        if dirty {
            assert!(d.op.is_none(), "{case}: nothing written");
            assert_eq!(d.refused, Some(Verdict::KEY_UNCONFIRMED), "{case}");
            assert_eq!(lookup(&mut h), (BindingRole::Guest, false), "{case}: stays");
            continue;
        }
        let op = d.op.expect("the lift goes to the list");
        let landed = h.apply(op, 1000);
        h.engine.landed(&mut h.trusted, landed);
        assert_eq!(
            lookup(&mut h),
            (BindingRole::Owner, false),
            "{case}: lifted"
        );
        assert_eq!(
            h.store().person_keys(1001).unwrap().listed_guest.len(),
            0,
            "{case}: one record, not a second"
        );
    }
    // Not by any other ground: the snapshot's first use of the same key finds it listed.
    let me = Signer::new();
    let mut state = state_of("observe", vec![me.record(1001, "guest")]);
    state["snapshot"] = json!([{"telegram_user_id": 1001, "role": "owner"}]);
    let mut h = Harness::new("lift first_use", &state, &[]);
    let reg = KeyReg::parse_verify(&me.key_reg()).unwrap();
    let r = h.store().check_add(
        &reg.new_key(),
        &crate::viewer_keys::Ground::FirstUse {
            telegram_user_id: 1001,
        },
        0,
    );
    assert!(r.is_err(), "first_use never lifts a listed key: {r:?}");
    match h.store().lookup(&me.kid) {
        crate::viewer_keys::Lookup::Active(r) => assert_eq!(r.role, BindingRole::Guest),
        other => panic!("{other:?}"),
    }
}

/// §10.2: an unconfirmed owner key's session is no confirmed owner's: it counts against the trust
/// window.
#[test]
fn an_unconfirmed_owner_keys_session_counts_against_the_window() {
    let vera = Signer::new();
    let mut rec = vera.record(1001, "owner");
    rec["unconfirmed"] = true.into();
    let mut h = Harness::new("unconfirmed owner", &state_of("observe", vec![rec]), &[]);
    h.engine.insert_nonce_batch(0, vec![nonce(1)]);
    request_as(&mut h, "s-owner", 1001, &nonce(1));
    let d = offer_as(
        &mut h,
        "s-owner",
        &vera.proof("s-owner", &nonce(1), false, vec![]),
        true,
    );
    assert!(d.admitted(), "{:?}", d.verdict);
    assert_eq!(d.verdict, Verdict::KEY_UNCONFIRMED);
    assert_eq!(h.engine.counting(), 1, "it counts against the window");
}

// --- §10 «Одно правило возврата»: a new endorse returns a removed key ----------------------------

/// When [`with_removed`]'s tombstones were written (unix ms, the PC's clock): the harness's
/// clock at 0. [`endorse_entry`] signs at the real now, later.
const REMOVED_AT: i64 = 1_789_600_000_000;

/// A list of `keys` in `mode` with the tombstones `removed` (key, person, origin), written at
/// [`REMOVED_AT`], four nonces.
fn with_removed(mode: &str, keys: Vec<Value>, removed: &[(&Signer, i64, &str)]) -> Harness {
    with_removed_spent(mode, keys, removed, &[])
}

/// [`with_removed`] with the endorse ids `[n; 16]` of `spent` spent already (the endorses that
/// added the removed keys).
fn with_removed_spent(
    mode: &str,
    keys: Vec<Value>,
    removed: &[(&Signer, i64, &str)],
    spent: &[u8],
) -> Harness {
    let mut s = state_of(mode, keys);
    s["spent"] = spent
        .iter()
        .map(|n| Value::from(b64(&[*n; 16])))
        .collect::<Vec<_>>()
        .into();
    s["revoked"] = removed
        .iter()
        .map(|(k, uid, origin)| {
            json!({"key_id": k.kid.as_str(), "spki": b64(&k.spki), "telegram_user_id": uid,
                   "origin": origin, "removed_at": REMOVED_AT})
        })
        .collect::<Vec<_>>()
        .into();
    let mut h = Harness::new("endorse return", &s, &[]);
    h.engine
        .insert_nonce_batch(0, (1..=4).map(nonce).collect::<Vec<_>>());
    h
}

/// `key`'s first offer as `uid` (nonce `n`) with `admit`, its write landed if it has one: the
/// final verdict and whether the session goes on.
fn offer_landed(
    h: &mut Harness,
    uid: i64,
    key: &Signer,
    n: u8,
    admit: Vec<Value>,
) -> (Verdict, bool) {
    let sid = format!("s{n}");
    request_as(h, &sid, uid, &nonce(n));
    let d = offer_as(h, &sid, &key.proof(&sid, &nonce(n), true, admit), true);
    let admitted = d.admitted();
    match d.outcome {
        Outcome::AfterWrite(op) => {
            let landed = h.apply(*op, 1000);
            let (_, admitted, v) = h
                .engine
                .landed(&mut h.trusted, landed)
                .session
                .expect("the session's answer");
            (v, admitted)
        }
        Outcome::Admit | Outcome::Refuse => (d.verdict, admitted),
    }
}

/// §10 «Одно правило возврата»: a device removed alone at the PC comes back by a NEW endorse of its person's active trusted device — the owner's second device and a guest's
/// alike: active again, the person's role, confirmed (the signer is); the tombstone goes, the
/// new endorse is spent. A `server` removal the same.
#[test]
fn a_new_endorse_of_the_persons_own_device_returns_a_removed_key() {
    for (uid, role, origin) in [
        (1001, BindingRole::Owner, "pc"),
        (456, BindingRole::Guest, "pc"),
        (456, BindingRole::Guest, "server"),
    ] {
        let (vera, phone, laptop) = (Signer::new(), Signer::new(), Signer::new());
        let keys = vec![vera.record(1001, "owner"), phone.record(uid, role.as_str())];
        let mut h = with_removed("strict", keys, &[(&laptop, uid, origin)]);
        let got = offer_landed(
            &mut h,
            uid,
            &laptop,
            1,
            vec![endorse_entry(&phone, &laptop.kid, 7)],
        );
        let case = format!("{} {origin}", role.as_str());
        assert_eq!(got, (Verdict::SIGNED, true), "{case}");
        match h.store().lookup(&laptop.kid) {
            Lookup::Active(r) => {
                assert_eq!(r.person.telegram_user_id, uid, "{case}");
                assert_eq!(r.role, role, "{case}");
                assert!(!r.unconfirmed, "{case}");
            }
            other => panic!("{case}: {other:?}"),
        }
        let (_, revoked, spent) = list_state(&mut h);
        assert!(revoked.is_empty(), "{case}: the tombstone is lifted");
        assert_eq!(spent, set_of(&[&b64(&[7; 16])]), "{case}");
    }
}

/// Negative (§10: «только своему человеку»): an endorse signed by ANOTHER person's device — the
/// PC's owner's included — returns nothing: `key_revoked`, nothing written, nothing spent, the
/// tombstone stays (`pc` and `server`).
#[test]
fn a_new_endorse_by_another_persons_device_lifts_nothing() {
    for origin in ["pc", "server"] {
        let (vera, laptop) = (Signer::new(), Signer::new());
        let mut h = with_removed(
            "observe",
            vec![vera.record(1001, "owner")],
            &[(&laptop, 456, origin)],
        );
        let before = list_state(&mut h);
        let got = offer_landed(
            &mut h,
            456,
            &laptop,
            1,
            vec![endorse_entry(&vera, &laptop.kid, 7)],
        );
        // Observe and bound: the session itself goes on by the binding; the key is refused.
        assert_eq!(got.0, Verdict::KEY_REVOKED, "{origin}");
        assert_eq!(
            list_state(&mut h),
            before,
            "{origin}: nothing lifted or spent"
        );
    }
}

/// Negative: a removed signer's (its own removal at the PC) endorse on a removed key is no ground
/// there (§10 «Повтор основания для удалённого ключа»): `key_revoked`, not
/// `endorse_signer_revoked`; a `replaced` key is not lifted by any endorse (`key_revoked`).
/// Nothing changes either way.
#[test]
fn a_removed_signer_or_a_replaced_key_lifts_nothing() {
    let (vera, phone, laptop) = (Signer::new(), Signer::new(), Signer::new());
    let mut h = with_removed(
        "observe",
        vec![vera.record(1001, "owner")],
        &[(&laptop, 456, "pc"), (&phone, 456, "pc")],
    );
    let before = list_state(&mut h);
    let got = offer_landed(
        &mut h,
        456,
        &laptop,
        1,
        vec![endorse_entry(&phone, &laptop.kid, 7)],
    );
    assert_eq!(got.0, Verdict::KEY_REVOKED);
    assert_eq!(list_state(&mut h), before, "the signer removed: nothing");

    let (vera, phone, laptop) = (Signer::new(), Signer::new(), Signer::new());
    let mut h = with_removed(
        "observe",
        vec![vera.record(1001, "owner"), phone.record(456, "guest")],
        &[(&laptop, 456, "replaced")],
    );
    let before = list_state(&mut h);
    let got = offer_landed(
        &mut h,
        456,
        &laptop,
        1,
        vec![endorse_entry(&phone, &laptop.kid, 7)],
    );
    assert_eq!(got.0, Verdict::KEY_REVOKED);
    assert_eq!(list_state(&mut h), before, "replaced: nothing");
}

/// §10.1: the returning key inherits the signer's mark — an unconfirmed signer in strict mode
/// writes nothing (`key_unconfirmed`, the tombstone stays); in observe the key is back
/// unconfirmed.
#[test]
fn an_unconfirmed_signers_endorse_returns_a_key_only_unconfirmed_in_observe() {
    for mode in ["strict", "observe"] {
        let (vera, phone, laptop) = (Signer::new(), Signer::new(), Signer::new());
        let mut signer = phone.record(456, "guest");
        signer["unconfirmed"] = true.into();
        let mut h = with_removed(
            mode,
            vec![vera.record(1001, "owner"), signer],
            &[(&laptop, 456, "pc")],
        );
        let before = list_state(&mut h);
        let (verdict, _) = offer_landed(
            &mut h,
            456,
            &laptop,
            1,
            vec![endorse_entry(&phone, &laptop.kid, 7)],
        );
        assert_eq!(verdict, Verdict::KEY_UNCONFIRMED, "{mode}");
        if mode == "strict" {
            assert_eq!(list_state(&mut h), before, "strict: nothing written");
        } else {
            match h.store().lookup(&laptop.kid) {
                Lookup::Active(r) => assert!(r.unconfirmed, "observe: back unconfirmed"),
                other => panic!("observe: {other:?}"),
            }
        }
    }
}

/// §10 «Одно правило возврата», the time: a removed key comes back only by an endorse issued
/// AFTER its removal (`issued_at` > `removed_at`, strictly; the signing device's clock against the
/// PC's, both unix ms). Not later — at the removal's very millisecond included — `key_revoked`:
/// nothing lifted, nothing spent; one millisecond later it returns the key.
#[test]
fn an_endorse_returns_a_removed_key_only_when_issued_after_the_removal() {
    let at = u64::try_from(REMOVED_AT).unwrap();
    for (issued_at, lifts) in [(at - 1, false), (at, false), (at + 1, true)] {
        let (vera, phone, laptop) = (Signer::new(), Signer::new(), Signer::new());
        let mut h = with_removed(
            "strict",
            vec![vera.record(1001, "owner"), phone.record(456, "guest")],
            &[(&laptop, 456, "pc")],
        );
        let before = list_state(&mut h);
        let got = offer_landed(
            &mut h,
            456,
            &laptop,
            1,
            vec![endorse_entry_at(&phone, &laptop.kid, 7, issued_at)],
        );
        let case = format!(
            "issued_at = removed_at {:+}",
            i128::from(issued_at) - i128::from(at)
        );
        if lifts {
            assert_eq!(got, (Verdict::SIGNED, true), "{case}");
            assert!(
                matches!(h.store().lookup(&laptop.kid), Lookup::Active(_)),
                "{case}"
            );
        } else {
            assert_eq!(got, (Verdict::KEY_REVOKED, false), "{case}");
            assert_eq!(
                list_state(&mut h),
                before,
                "{case}: nothing lifted, nothing spent"
            );
        }
    }
}

/// The time refusal is this ground's own: the next ground in `admit` is still tried — an old
/// endorse first and a new one second, the new one returns the key (only it is spent); an old
/// endorse before the owner's new grant, the grant returns it.
#[test]
fn an_old_endorse_is_skipped_for_the_next_ground_in_admit() {
    let old = u64::try_from(REMOVED_AT).unwrap() - 1;
    let new = u64::try_from(REMOVED_AT).unwrap() + 1;
    let (vera, phone, laptop) = (Signer::new(), Signer::new(), Signer::new());
    let mut h = with_removed(
        "strict",
        vec![vera.record(1001, "owner"), phone.record(456, "guest")],
        &[(&laptop, 456, "pc")],
    );
    let got = offer_landed(
        &mut h,
        456,
        &laptop,
        1,
        vec![
            endorse_entry_at(&phone, &laptop.kid, 7, old),
            endorse_entry_at(&phone, &laptop.kid, 8, new),
        ],
    );
    assert_eq!(got, (Verdict::SIGNED, true), "two endorses");
    let (_, revoked, spent) = list_state(&mut h);
    assert!(revoked.is_empty());
    assert_eq!(
        spent,
        set_of(&[&b64(&[8; 16])]),
        "only the new endorse is spent"
    );

    let (vera, phone, laptop) = (Signer::new(), Signer::new(), Signer::new());
    let mut h = with_removed(
        "strict",
        vec![vera.record(1001, "owner"), phone.record(456, "guest")],
        &[(&laptop, 456, "pc")],
    );
    let token = h.grant_token().unwrap();
    let at = u64::try_from(h.wall(1)).unwrap();
    let got = offer_landed(
        &mut h,
        456,
        &laptop,
        1,
        vec![
            endorse_entry_at(&phone, &laptop.kid, 7, old),
            vera.grant_entry_at(&laptop.kid, 456, 9, at, token),
        ],
    );
    assert_eq!(got, (Verdict::SIGNED, true), "an old endorse, then a grant");
    match h.store().lookup(&laptop.kid) {
        Lookup::Active(r) => assert!(matches!(
            r.source,
            crate::viewer_keys::KeySource::Grant { .. }
        )),
        other => panic!("{other:?}"),
    }
}

// --- §10 «Повтор основания для удалённого ключа»: an endorse refused on a removed key is no ground

/// Negative: the endorse that first added a removed key (spent) and an old one (issued before the
/// removal) — in either order in `admit` — both refuse, and neither is the offer's reason: the
/// SAME `key_revoked`, nothing lifted, nothing spent, the tombstone stays (`pc` and `server`).
#[test]
fn endorse_refusals_on_a_removed_key_are_key_revoked_in_either_order() {
    let old = u64::try_from(REMOVED_AT).unwrap() - 1;
    for origin in ["pc", "server"] {
        for spent_first in [true, false] {
            let (vera, phone, laptop) = (Signer::new(), Signer::new(), Signer::new());
            let mut h = with_removed_spent(
                "strict",
                vec![vera.record(1001, "owner"), phone.record(456, "guest")],
                &[(&laptop, 456, origin)],
                &[1],
            );
            let before = list_state(&mut h);
            let spent = endorse_entry(&phone, &laptop.kid, 1);
            let stale = endorse_entry_at(&phone, &laptop.kid, 2, old);
            let admit = if spent_first {
                vec![spent, stale]
            } else {
                vec![stale, spent]
            };
            let got = offer_landed(&mut h, 456, &laptop, 1, admit);
            let case = format!("{origin}, spent first: {spent_first}");
            assert_eq!(got, (Verdict::KEY_REVOKED, false), "{case}");
            assert_eq!(
                list_state(&mut h),
                before,
                "{case}: nothing lifted, nothing spent"
            );
        }
    }
}

/// A grant's refusal keeps its reason beside a refused endorse on a removed key, in either order:
/// [stale grant, spent endorse] and [spent endorse, stale grant] are both `grant_stale`; nothing
/// changes.
#[test]
fn a_stale_grant_keeps_its_reason_beside_a_refused_endorse_on_a_removed_key() {
    for grant_first in [true, false] {
        let (vera, phone, laptop) = (Signer::new(), Signer::new(), Signer::new());
        let mut h = with_removed_spent(
            "strict",
            vec![vera.record(1001, "owner"), phone.record(456, "guest")],
            &[(&laptop, 456, "pc")],
            &[1],
        );
        let before = list_state(&mut h);
        let stale = GrantToken::fresh(h.grant_token().unwrap());
        let at = u64::try_from(h.wall(1)).unwrap();
        let grant = vera.grant_entry_at(&laptop.kid, 456, 9, at, stale);
        let spent = endorse_entry(&phone, &laptop.kid, 1);
        let admit = if grant_first {
            vec![grant, spent]
        } else {
            vec![spent, grant]
        };
        let got = offer_landed(&mut h, 456, &laptop, 1, admit);
        let case = format!("grant first: {grant_first}");
        assert_eq!(
            got,
            (Verdict::admit_refused("grant_stale"), false),
            "{case}"
        );
        assert_eq!(list_state(&mut h), before, "{case}: nothing changes");
    }
}

/// Unchanged for a NEW key (no record, no removed record): the same spent endorse is
/// `admit_refused:endorse_spent`.
#[test]
fn a_spent_endorse_for_a_key_with_no_removed_record_is_still_endorse_spent() {
    let (vera, phone, laptop) = (Signer::new(), Signer::new(), Signer::new());
    let mut h = with_removed_spent(
        "strict",
        vec![vera.record(1001, "owner"), phone.record(456, "guest")],
        &[],
        &[1],
    );
    let before = list_state(&mut h);
    let got = offer_landed(
        &mut h,
        456,
        &laptop,
        1,
        vec![endorse_entry(&phone, &laptop.kid, 1)],
    );
    assert_eq!(got, (Verdict::admit_refused("endorse_spent"), false));
    assert_eq!(list_state(&mut h), before);
}

/// An endorse that returns a removed key passes its check, and before its write lands its signer
/// is removed at the PC — or another offer spends its `endorse_id` (the signer may vouch for two
/// keys with one id; the first write spends it): the write decides again and refuses it, and on a
/// key with a removed record that refusal is `key_revoked` (not `endorse_signer_revoked` /
/// `endorse_spent`). The key stays removed, the endorse is not spent by it.
#[test]
fn an_endorse_refused_at_its_write_on_a_removed_key_is_key_revoked() {
    for case in ["signer removed", "spent by another key"] {
        let (vera, phone, laptop, other) =
            (Signer::new(), Signer::new(), Signer::new(), Signer::new());
        let mut h = with_removed(
            "strict",
            vec![vera.record(1001, "owner"), phone.record(456, "guest")],
            &[(&laptop, 456, "pc")],
        );
        request_as(&mut h, "s1", 456, &nonce(1));
        let p = laptop.proof(
            "s1",
            &nonce(1),
            true,
            vec![endorse_entry(&phone, &laptop.kid, 7)],
        );
        let d = offer_as(&mut h, "s1", &p, true);
        let Outcome::AfterWrite(op) = d.outcome else {
            panic!("{case}: the endorse passes its check: {:?}", d.verdict);
        };
        if case == "signer removed" {
            let at = h.wall(500);
            h.store().remove(&phone.kid, Removal::Pc, at).unwrap();
            h.keys_removed(std::slice::from_ref(&phone.kid));
        } else {
            request_as(&mut h, "s2", 456, &nonce(2));
            let p2 = other.proof(
                "s2",
                &nonce(2),
                true,
                vec![endorse_entry(&phone, &other.kid, 7)],
            );
            let d2 = offer_as(&mut h, "s2", &p2, true);
            let Outcome::AfterWrite(op2) = d2.outcome else {
                panic!("{case}: the other key's endorse passes: {:?}", d2.verdict);
            };
            let landed = h.apply(*op2, 600);
            let (_, admitted, v) = h.engine.landed(&mut h.trusted, landed).session.unwrap();
            assert_eq!(
                (v, admitted),
                (Verdict::SIGNED, true),
                "{case}: the other key"
            );
        }
        let landed = h.apply(*op, 1000);
        assert!(
            matches!(
                &landed.result,
                Err(StoreError::SignerRemoved(_) | StoreError::Spent(_))
            ),
            "{case}: the write refuses the endorse itself: {:?}",
            landed.result
        );
        let (_, admitted, v) = h
            .engine
            .landed(&mut h.trusted, landed)
            .session
            .expect("the session's answer");
        assert_eq!((v, admitted), (Verdict::KEY_REVOKED, false), "{case}");
        assert!(
            matches!(h.store().lookup(&laptop.kid), Lookup::Removed(_)),
            "{case}: the key stays removed"
        );
    }
}

/// Piece 1a, the time rule where only the write's re-read protects: K's tombstone is at T1; an
/// endorse eA issued at T2 > T1 passes the check and its write waits; another offer's endorse lifts
/// K first; «Удалить» on K at T3 > T2 lands; eA's write — the queue's stage, `stage_add` — reads
/// the new tombstone and refuses it by the time: K stays removed (at T3), eA is not spent, nothing
/// is written or journaled. (eA's offer ended `key_revoked` already, by the removal's sweep of
/// K's sessions; an offer that still waits at a write refusal on a removed key —
/// `an_endorse_refused_at_its_write_on_a_removed_key_is_key_revoked` — hears `key_revoked`.)
#[test]
fn an_endorse_issued_before_a_later_removal_is_refused_at_its_write() {
    let (t1, t2, t3) = (REMOVED_AT, REMOVED_AT + 10, REMOVED_AT + 1000);
    let (vera, phone, laptop) = (Signer::new(), Signer::new(), Signer::new());
    let mut h = with_removed(
        "strict",
        vec![vera.record(1001, "owner"), phone.record(456, "guest")],
        &[(&laptop, 456, "pc")],
    );
    let issued = |at: i64| u64::try_from(at).unwrap();
    let mut waiting = Vec::new();
    for (n, at) in [(1u8, t2), (2, t2 + 10)] {
        let sid = format!("s{n}");
        request_as(&mut h, &sid, 456, &nonce(n));
        let p = laptop.proof(
            &sid,
            &nonce(n),
            true,
            vec![endorse_entry_at(&phone, &laptop.kid, 10 + n, issued(at))],
        );
        let d = offer_as(&mut h, &sid, &p, true);
        let Outcome::AfterWrite(op) = d.outcome else {
            panic!(
                "{sid}: its endorse passes the check over T1 = {t1}: {:?}",
                d.verdict
            );
        };
        waiting.push(op);
    }
    let lift = waiting.pop().unwrap();
    let ea = waiting.pop().unwrap();
    // The other endorse lifts K first.
    let landed = h.apply(*lift, 100);
    let (_, admitted, v) = h.engine.landed(&mut h.trusted, landed).session.unwrap();
    assert_eq!((v, admitted), (Verdict::SIGNED, true), "the lift");
    // «Удалить» on K at T3: the removal's sweep ends every session of K — eA's waiting one too —
    // `key_revoked`.
    h.store().remove(&laptop.kid, Removal::Pc, t3).unwrap();
    let ended = h.keys_removed(std::slice::from_ref(&laptop.kid));
    assert!(
        ended
            .iter()
            .any(|e| e.session_id == "s1" && e.verdict == Verdict::KEY_REVOKED),
        "eA's session ends key_revoked: {ended:?}"
    );
    let before = list_state(&mut h);
    let landed = h.apply(*ea, 1000);
    assert!(
        matches!(&landed.result, Err(StoreError::Removed { .. })),
        "the time refuses eA at its write: {:?}",
        landed.result
    );
    let ld = h.engine.landed(&mut h.trusted, landed);
    assert!(
        ld.session.is_none(),
        "nothing left to answer: {:?}",
        ld.session
    );
    assert!(ld.journal.is_empty(), "nothing journaled: {:?}", ld.journal);
    assert_eq!(list_state(&mut h), before, "nothing written, eA not spent");
    match h.store().lookup(&laptop.kid) {
        Lookup::Removed(t) => assert_eq!((t.origin.as_str(), t.at), ("pc", t3)),
        other => panic!("K stays removed: {other:?}"),
    }
}

// --- §10 «Повтор основания для удалённого ключа»: a spent or orphaned grant on a removed key

/// Petya's (456) laptop comes in by Vera's grant on her invitation (ids from 1: grant and
/// invitation spent), then is removed at the PC: the harness (strict; nonces 2..=4 left), Vera,
/// the laptop and that grant, unchanged.
fn a_guest_by_grant_removed_at_the_pc() -> (Harness, Signer, Signer, Value) {
    let (vera, laptop) = (Signer::new(), Signer::new());
    let mut h = with_removed("strict", vec![vera.record(1001, "owner")], &[]);
    let token = h.grant_token().unwrap();
    let at = u64::try_from(h.wall(1)).unwrap();
    let first = vera.grant_entry_at(&laptop.kid, 456, 1, at, token);
    let got = offer_landed(&mut h, 456, &laptop, 1, vec![first.clone()]);
    assert_eq!(got, (Verdict::SIGNED, true), "added by the grant");
    let removed_at = h.wall(500);
    h.store()
        .remove(&laptop.kid, Removal::Pc, removed_at)
        .unwrap();
    h.keys_removed(std::slice::from_ref(&laptop.kid));
    (h, vera, laptop, first)
}

/// The owner's grant for `key` of 456 over the PC's token now, signed now, with its own ids.
fn grant_now(h: &Harness, by: &Signer, key: &KeyId, ids: ([u8; 16], [u8; 16])) -> Value {
    let token = h.grant_token().unwrap();
    let at = u64::try_from(h.wall(1000)).unwrap();
    by.grant_entry_ids(key, 456, ids, at, token)
}

/// Negative: the device knocks again with the grant and invitation it came in by (both spent):
/// on a removed key that is no ground and nothing else returns it — `key_revoked`, not
/// `grant_spent`; nothing lifted, nothing spent. A fresh grant id on the spent invitation
/// (`invite_spent`) alike.
#[test]
fn a_spent_grant_or_invitation_on_a_removed_key_is_key_revoked() {
    let (mut h, vera, laptop, first) = a_guest_by_grant_removed_at_the_pc();
    let before = list_state(&mut h);
    let got = offer_landed(&mut h, 456, &laptop, 2, vec![first]);
    assert_eq!(got, (Verdict::KEY_REVOKED, false), "the spent grant again");
    // A fresh grant id on the spent invitation (`invite_spent`).
    let on_spent_invite = grant_now(&h, &vera, &laptop.kid, ([1; 16], [50; 16]));
    let got = offer_landed(&mut h, 456, &laptop, 3, vec![on_spent_invite]);
    assert_eq!(got, (Verdict::KEY_REVOKED, false), "a spent invitation");
    assert_eq!(list_state(&mut h), before, "nothing lifted, nothing spent");
    assert!(matches!(h.store().lookup(&laptop.kid), Lookup::Removed(_)));
}

/// A stale grant (over a token other than the PC's current one) keeps its reason beside a spent one, in
/// either order: `grant_stale` both ways; nothing changes.
#[test]
fn a_spent_grant_and_a_stale_grant_on_a_removed_key_is_grant_stale_in_either_order() {
    let (mut h, vera, laptop, first) = a_guest_by_grant_removed_at_the_pc();
    let before = list_state(&mut h);
    let stale_token = GrantToken::fresh(h.grant_token().unwrap());
    let at = u64::try_from(h.wall(1000)).unwrap();
    let stale = vera.grant_entry_at(&laptop.kid, 456, 2, at, stale_token);
    for (n, spent_first) in [(2u8, true), (3, false)] {
        let admit = if spent_first {
            vec![first.clone(), stale.clone()]
        } else {
            vec![stale.clone(), first.clone()]
        };
        let got = offer_landed(&mut h, 456, &laptop, n, admit);
        assert_eq!(
            got,
            (Verdict::admit_refused("grant_stale"), false),
            "spent first: {spent_first}"
        );
        assert_eq!(list_state(&mut h), before, "spent first: {spent_first}");
    }
}

/// The spent grant is skipped for the next ground: the owner's new grant on a new invitation
/// returns the key to its person, confirmed; the tombstone goes, only the new ids are spent too.
#[test]
fn a_spent_grant_then_a_new_invited_grant_returns_a_removed_key() {
    let (mut h, vera, laptop, first) = a_guest_by_grant_removed_at_the_pc();
    let (_, _, spent_before) = list_state(&mut h);
    let new = grant_now(&h, &vera, &laptop.kid, ([3; 16], [103; 16]));
    let got = offer_landed(&mut h, 456, &laptop, 2, vec![first, new]);
    assert_eq!(got, (Verdict::SIGNED, true));
    match h.store().lookup(&laptop.kid) {
        Lookup::Active(r) => {
            assert_eq!(r.person.telegram_user_id, 456);
            assert!(!r.unconfirmed);
        }
        other => panic!("{other:?}"),
    }
    let (_, revoked, spent) = list_state(&mut h);
    assert!(revoked.is_empty(), "the tombstone is lifted");
    let mut want = spent_before;
    want.extend([b64(&[3; 16]), b64(&[103; 16])]);
    assert_eq!(spent, want);
}

/// `grant_role` has two causes, one code outside: a grant naming a role other than guest is a
/// form error and keeps `grant_role` on a removed key (no `why`); a guest grant for a person who
/// is an owner on this PC is `grant_role` (`why` [`OWNER_ON_PC`]) on a key with no removed record
/// and no ground on a removed one (`key_revoked`). Nothing changes in any case.
#[test]
fn grant_role_keeps_its_reason_on_a_removed_key_only_for_a_role_other_than_guest() {
    // A role other than guest, after the spent grant.
    let (mut h, vera, laptop, first) = a_guest_by_grant_removed_at_the_pc();
    let before = list_state(&mut h);
    let mut as_owner = grant_now(&h, &vera, &laptop.kid, ([2; 16], [102; 16]));
    as_owner["grant"]["role"] = "owner".into();
    request_as(&mut h, "s2", 456, &nonce(2));
    let p = laptop.proof("s2", &nonce(2), true, vec![first, as_owner]);
    let d = offer_as(&mut h, "s2", &p, true);
    assert_eq!(d.verdict, Verdict::admit_refused("grant_role"));
    assert_eq!(d.why, None, "a form error names no owner");
    assert_eq!(list_state(&mut h), before);

    // The person is an owner on this PC (an owner-role key of his).
    let (vera, phone, laptop, tablet) =
        (Signer::new(), Signer::new(), Signer::new(), Signer::new());
    let mut h = with_removed(
        "strict",
        vec![vera.record(1001, "owner"), phone.record(456, "owner")],
        &[(&laptop, 456, "pc")],
    );
    let before = list_state(&mut h);
    let to_removed = grant_now(&h, &vera, &laptop.kid, ([2; 16], [102; 16]));
    let got = offer_landed(&mut h, 456, &laptop, 1, vec![to_removed]);
    assert_eq!(got, (Verdict::KEY_REVOKED, false), "a removed key");
    let to_new = grant_now(&h, &vera, &tablet.kid, ([3; 16], [103; 16]));
    request_as(&mut h, "s2", 456, &nonce(2));
    let d = offer_as(
        &mut h,
        "s2",
        &tablet.proof("s2", &nonce(2), true, vec![to_new]),
        true,
    );
    assert_eq!(d.verdict, Verdict::admit_refused("grant_role"), "a new key");
    assert_eq!(d.why, Some(OWNER_ON_PC));
    assert_eq!(list_state(&mut h), before, "nothing changes");
}

/// Unchanged for a key with NO removed record: the same spent grant (its ids, for another key of
/// the guest) is `grant_spent`, a grant on the spent invitation `invite_spent`.
#[test]
fn a_spent_grant_for_a_key_with_no_removed_record_keeps_its_reason() {
    let (mut h, vera, _laptop, _) = a_guest_by_grant_removed_at_the_pc();
    let tablet = Signer::new();
    let before = list_state(&mut h);
    let same_ids = grant_now(&h, &vera, &tablet.kid, ([1; 16], [101; 16]));
    let got = offer_landed(&mut h, 456, &tablet, 2, vec![same_ids]);
    assert_eq!(got, (Verdict::admit_refused("grant_spent"), false));
    let spent_invite = grant_now(&h, &vera, &tablet.kid, ([1; 16], [60; 16]));
    let got = offer_landed(&mut h, 456, &tablet, 3, vec![spent_invite]);
    assert_eq!(got, (Verdict::admit_refused("invite_spent"), false));
    assert_eq!(list_state(&mut h), before);
}

/// A new grant that returns a removed key passes its check, and before its write lands another
/// offer spends its invitation — or its grant id — or its signer is removed at the PC: the write
/// decides again and refuses it for a reason from the «no ground» list while the key has a
/// removed record: `key_revoked` (not `invite_spent` / `grant_spent` / `grant_not_owner`). The
/// key stays removed; its grant is not spent by it.
#[test]
fn a_grant_refused_at_its_write_on_a_removed_key_is_key_revoked() {
    for case in ["invite spent", "grant spent", "signer removed"] {
        let (mut h, vera, laptop, _) = a_guest_by_grant_removed_at_the_pc();
        let ids = ([2; 16], [102; 16]);
        request_as(&mut h, "s2", 456, &nonce(2));
        let g = grant_now(&h, &vera, &laptop.kid, ids);
        let d = offer_as(
            &mut h,
            "s2",
            &laptop.proof("s2", &nonce(2), true, vec![g]),
            true,
        );
        let Outcome::AfterWrite(op) = d.outcome else {
            panic!("{case}: the new grant passes its check: {:?}", d.verdict);
        };
        if case == "signer removed" {
            let at = h.wall(600);
            h.store().remove(&vera.kid, Removal::Pc, at).unwrap();
            h.keys_removed(std::slice::from_ref(&vera.kid));
        } else {
            // Another device of Petya's on the same invitation (or grant id) lands first.
            let tablet = Signer::new();
            let other = if case == "invite spent" {
                (ids.0, [77; 16])
            } else {
                ([78; 16], ids.1)
            };
            request_as(&mut h, "s3", 456, &nonce(3));
            let g2 = grant_now(&h, &vera, &tablet.kid, other);
            let d2 = offer_as(
                &mut h,
                "s3",
                &tablet.proof("s3", &nonce(3), true, vec![g2]),
                true,
            );
            let Outcome::AfterWrite(op2) = d2.outcome else {
                panic!("{case}: the other device's grant passes: {:?}", d2.verdict);
            };
            let landed = h.apply(*op2, 600);
            let (_, admitted, v) = h.engine.landed(&mut h.trusted, landed).session.unwrap();
            assert_eq!(
                (v, admitted),
                (Verdict::SIGNED, true),
                "{case}: the other device"
            );
        }
        let (_, _, spent_before) = list_state(&mut h);
        let landed = h.apply(*op, 1000);
        assert!(
            matches!(
                &landed.result,
                Err(StoreError::InviteSpent(_) | StoreError::Spent(_) | StoreError::NotOwner)
            ),
            "{case}: the write refuses the grant itself: {:?}",
            landed.result
        );
        let (_, admitted, v) = h
            .engine
            .landed(&mut h.trusted, landed)
            .session
            .expect("the session's answer");
        assert_eq!((v, admitted), (Verdict::KEY_REVOKED, false), "{case}");
        assert!(
            matches!(h.store().lookup(&laptop.kid), Lookup::Removed(_)),
            "{case}: the key stays removed"
        );
        let (_, _, spent) = list_state(&mut h);
        assert_eq!(spent, spent_before, "{case}: nothing spent by it");
    }
}
