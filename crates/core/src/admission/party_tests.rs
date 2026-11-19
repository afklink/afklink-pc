#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines,
    reason = "tests"
)]
//! «Пати» at the PC: the contract's vectors (`vectors/party/join.json`, `grant.json`) byte for
//! byte and verdict for verdict, the nine steps of a join in their order, the grant token's
//! table (party spec §4.4), the file's format 3 → 4, the leave's walk, a reset and an owner key's
//! removal. The admission's whole offers are in the orchestrator's tests (`agent.rs`).

use std::path::{Path, PathBuf};
use std::sync::Arc;

use aws_lc_rs::signature::{EcdsaKeyPair, KeyPair as _, ECDSA_P256_SHA256_FIXED_SIGNING};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use serde_json::{json, Value};

use super::*;
use crate::trusted::TrustedDone;
use crate::viewer_keys::wire::{grant_message, party_grant_message, GrantFields};
use crate::viewer_keys::{DamageKind, GrantToken, FILE_NAME, MAX_DELEGATIONS};

const DEVICE: &str = "8d3b1f42-6c7a-4e09-b5d8-2a9e7c1f3b64";

fn vectors(name: &str) -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../contract/packages/protocol/vectors/party")
        .join(name);
    serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap()
}

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn spki_key(text: &str) -> ViewerKey {
    ViewerKey::from_spki(&URL_SAFE_NO_PAD.decode(text).unwrap()).unwrap()
}

struct Dir(PathBuf);

impl Dir {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!("afklink-party-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }

    fn file(&self) -> Value {
        serde_json::from_slice(&std::fs::read(self.0.join(FILE_NAME)).unwrap()).unwrap()
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A device key of the tests: its pair, SPKI and id.
struct Key {
    pair: EcdsaKeyPair,
    spki: Vec<u8>,
    kid: KeyId,
}

impl Key {
    fn new() -> Self {
        const PREFIX: [u8; 26] = [
            0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06,
            0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
        ];
        let pair = EcdsaKeyPair::generate(&ECDSA_P256_SHA256_FIXED_SIGNING).unwrap();
        let mut spki = PREFIX.to_vec();
        spki.extend_from_slice(pair.public_key().as_ref());
        let kid = ViewerKey::from_spki(&spki).unwrap().key_id().clone();
        Self { pair, spki, kid }
    }

    fn sign(&self, m: &[u8]) -> String {
        b64(self
            .pair
            .sign(&aws_lc_rs::rand::SystemRandom::new(), m)
            .unwrap()
            .as_ref())
    }

    fn spki_text(&self) -> String {
        b64(&self.spki)
    }

    /// A key record of the file: a pairing at the PC of `uid` with `role`.
    fn record(&self, uid: i64, role: &str, unconfirmed: bool) -> Value {
        record(
            &self.kid,
            &self.spki_text(),
            uid,
            role,
            unconfirmed,
            json!({"kind": "pair"}),
        )
    }
}

fn record(
    kid: &KeyId,
    spki: &str,
    uid: i64,
    role: &str,
    unconfirmed: bool,
    source: Value,
) -> Value {
    json!({
        "key_id": kid.as_str(), "spki": spki, "person": {"telegram_user_id": uid},
        "role": role, "kind": "telegram", "platform": "android", "source": source,
        "unconfirmed": unconfirmed, "added_at": 0,
    })
}

/// A list file in the store's format.
#[allow(clippy::needless_pass_by_value)]
fn list(version: u32, strict: bool, token: &str, keys: Vec<Value>, more: Value) -> Value {
    let mut f = json!({
        "version": version, "switches": {"trusted_devices_mode": strict},
        "keys": keys, "tombstones": [],
        "spent": {"endorse_ids": [], "grant_ids": [], "invite_ids": []},
        "grant_token": token,
    });
    for (k, v) in more.as_object().into_iter().flatten() {
        f[k] = v.clone();
    }
    f
}

fn write(dir: &Path, file: &Value) {
    std::fs::write(
        dir.join(FILE_NAME),
        serde_json::to_vec_pretty(file).unwrap(),
    )
    .unwrap();
}

/// The engine and a list whose writes land in place (no runtime: a job runs where it starts and
/// its result comes back on the channel, taken in by [`land`]).
struct Pc {
    trusted: Trusted,
    engine: Admission,
    done: std::sync::mpsc::Receiver<TrustedDone>,
}

fn pc(dir: &Path) -> Pc {
    let (tx, done) = std::sync::mpsc::channel();
    let tx = std::sync::Mutex::new(tx);
    let (mut trusted, _view) = Trusted::new(Arc::new(move |d: TrustedDone| {
        let _ = crate::sync::lock(&tx).send(d);
    }));
    trusted.attach(TrustStore::open_in(dir));
    Pc {
        trusted,
        engine: Admission::new(DEVICE.into(), TelegramVerifier::production()),
        done,
    }
}

impl Pc {
    /// Every write that started lands; the party answers that are due.
    fn land(&mut self) -> Vec<crate::trusted::PartyAck> {
        while let Ok(d) = self.done.try_recv() {
            self.trusted.on_done(d, 0, None);
        }
        self.trusted.take_party_acks()
    }

    fn store(&self) -> &TrustStore {
        self.trusted.store().unwrap()
    }

    /// A join's result as the server hears it: refused now, or `ok` once its write landed.
    fn join(&mut self, join: &Value, now: u64) -> String {
        match self.engine.party_join(&mut self.trusted, join, now) {
            PartyAnswer::Now(ack) => {
                assert_eq!(ack.op, PartyAckOp::Join);
                ack.result.as_str().to_string()
            }
            PartyAnswer::Queued => {
                let acks = self.land();
                assert_eq!(acks.len(), 1, "one answer once the write landed");
                acks[0].result.as_str().to_string()
            }
            PartyAnswer::Unaddressed => "unaddressed".into(),
        }
    }

    fn leave(&mut self, party_id: &str, now: u64) -> String {
        match self.engine.party_leave(&mut self.trusted, party_id, now) {
            PartyAnswer::Now(ack) => ack.result.as_str().to_string(),
            PartyAnswer::Queued => {
                let acks = self.land();
                assert_eq!(acks.len(), 1);
                acks[0].result.as_str().to_string()
            }
            PartyAnswer::Unaddressed => "unaddressed".into(),
        }
    }

    fn token(&self) -> GrantToken {
        self.store().grant_token().unwrap()
    }
}

/// «ПК в пати» for this PC, signed by `by`.
fn join_of(party_id: &[u8; 16], party: &str, leader: &Key, token: &GrantToken, by: &Key) -> Value {
    let mut v = json!({
        "v": 1, "device_id": DEVICE, "party_id": b64(party_id), "party": party,
        "leader": {"telegram_user_id": 456, "name": "Петя", "username": "petya",
                   "spki": leader.spki_text()},
        "grant_token": token.to_wire(), "issued_at": 1_789_600_000_000u64,
        "by": by.kid.as_str(), "sig": b64(&[0; 64]),
    });
    let message = PartyJoin::parse(&v).unwrap().message();
    v["sig"] = by.sign(&message).into();
    v
}

/// A PC with an owner key `owner` (user 1001, confirmed) and the token `token`.
fn owner_pc(dir: &Dir, owner: &Key, strict: bool, token: &str) -> Pc {
    write(
        &dir.0,
        &list(
            3,
            strict,
            token,
            vec![owner.record(1001, "owner", false)],
            json!({}),
        ),
    );
    pc(&dir.0)
}

// --- A. The vectors ----------------------------------------------------------------------------

/// join.json: every case's bytes (`j_hex`) and signature (`sig_valid`), and its answer (`expect`)
/// through the one function on a PC made of the case's state; a form fault's `why` as the
/// parser names it.
#[test]
fn join_vectors_byte_for_byte_and_answer_for_answer() {
    let v = vectors("join.json");
    let cases = v["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 34);
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let mut state = v["pc"].clone();
        for (k, x) in case["pc"].as_object().into_iter().flatten() {
            state[k] = x.clone();
        }
        let expect = case["expect"].as_str().unwrap();
        let join: Value = match case.get("join_text") {
            Some(text) => match serde_json::from_str(text.as_str().unwrap()) {
                Ok(j) => j,
                Err(_) => {
                    // The agent's frame parser refuses the frame: the server never relays it.
                    assert_eq!(expect, "malformed", "{name}");
                    continue;
                }
            },
            None => case["join"].clone(),
        };
        let parsed = PartyJoin::parse(&join);
        if expect == "malformed" {
            assert_eq!(
                parsed.as_ref().err().copied(),
                case["why"].as_str(),
                "{name}: why"
            );
        }
        // A case whose bytes the parser refuses (a name past its bound) still has its `j_hex`.
        if let (Some(j_hex), Ok(j)) = (case["j_hex"].as_str(), parsed.as_ref()) {
            assert_eq!(j.message(), hex(j_hex), "{name}: j");
            let by = state["keys"]
                .as_array()
                .unwrap()
                .iter()
                .find(|k| k["key_id"] == join["by"]);
            if let Some(by) = by {
                let key = spki_key(by["spki"].as_str().unwrap());
                assert_eq!(
                    j.verify(&key),
                    case["sig_valid"].as_bool().unwrap(),
                    "{name}: sig"
                );
            }
        }
        let dir = Dir::new();
        let keys: Vec<Value> = state["keys"]
            .as_array()
            .unwrap()
            .iter()
            .map(|k| {
                record(
                    &KeyId::parse(k["key_id"].as_str().unwrap()).unwrap(),
                    k["spki"].as_str().unwrap(),
                    k["person"].as_i64().unwrap(),
                    k["role"].as_str().unwrap(),
                    k["unconfirmed"].as_bool().unwrap(),
                    json!({"kind": "pair"}),
                )
            })
            .collect();
        let strict = state["mode"] == "strict";
        write(
            &dir.0,
            &list(
                3,
                strict,
                state["grant_token"].as_str().unwrap(),
                keys,
                json!({}),
            ),
        );
        let mut pc = pc(&dir.0);
        let got = pc.join(&join, 1_000);
        if case["why"] == "party_id" {
            // No answer can name a party_id the PC cannot read (the server never relays such a
            // join): not answered at all, which the server treats as unanswered.
            assert_eq!(
                (got.as_str(), expect),
                ("unaddressed", "malformed"),
                "{name}"
            );
            continue;
        }
        assert_eq!(got, expect, "{name}");
        let parties = pc.store().saved_delegations().unwrap().len();
        assert_eq!(
            parties,
            usize::from(expect == "ok"),
            "{name}: written only on ok"
        );
    }
}

/// grant.json: every case's bytes (`pg_hex`) and signature, its difference from the keys' V2
/// grant (fields 0, 7 and 11 only), the cross-domain pairs, and its `ended_detail` through the
/// `party` ground on a PC made of the case's state; a refusal's `why`.
#[test]
fn grant_vectors_byte_for_byte_and_detail_for_detail() {
    let v = vectors("grant.json");
    let cases = v["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 26);
    // The PC's owner (user 1001, an owner on this PC) signed the delegation: join.json's key A.
    let a = vectors("join.json")["pc"]["keys"][0].clone();
    let a_kid = KeyId::parse(a["key_id"].as_str().unwrap()).unwrap();
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let mut state = v["pc"].clone();
        for (k, x) in case["pc"].as_object().into_iter().flatten() {
            state[k] = x.clone();
        }
        let expect = case["expect"].as_str().unwrap();
        let admit: Value = match case.get("admit_text") {
            Some(text) => match serde_json::from_str(text.as_str().unwrap()) {
                Ok(j) => j,
                Err(_) => {
                    assert_eq!(expect, "grant_malformed", "{name}");
                    continue;
                }
            },
            None => case["admit"].clone(),
        };
        let grant = &admit["grant"];
        let parsed = PartyGrant::parse(grant);
        if expect == "grant_malformed" {
            assert_eq!(
                parsed.as_ref().err().copied(),
                case["why"].as_str(),
                "{name}: why"
            );
        }
        let leader = &state["delegations"][0]["leader"];
        if let (Some(pg), Ok(g)) = (case["pg_hex"].as_str(), parsed.as_ref()) {
            assert_eq!(g.message(), hex(pg), "{name}: pg");
            let key = spki_key(leader["spki"].as_str().unwrap());
            if g.by.as_str() == leader["key_id"] {
                assert_eq!(
                    g.verify(&key),
                    case["sig_valid"].as_bool().unwrap(),
                    "{name}: sig"
                );
            }
        }
        if let Some(v2) = case["owner_grant_v2_hex"].as_str() {
            let fields = |bytes: &[u8]| {
                let mut out = Vec::new();
                let mut at = 0;
                while at < bytes.len() {
                    let n = u32::from_be_bytes(bytes[at..at + 4].try_into().unwrap()) as usize;
                    out.push(bytes[at + 4..at + 4 + n].to_vec());
                    at += 4 + n;
                }
                out
            };
            let (party, v2) = (
                fields(&hex(case["pg_hex"].as_str().unwrap())),
                fields(&hex(v2)),
            );
            let differ: Vec<Value> = (0..party.len())
                .filter(|i| party[*i] != v2[*i])
                .map(|i| json!(i))
                .collect();
            assert_eq!(Value::Array(differ), case["differs_from_v2_at"], "{name}");
        }
        let dir = Dir::new();
        let d = &state["delegations"][0];
        let parties = json!([{
            "party_id": d["party_id"], "party": "Орлы",
            "leader": {"telegram_user_id": 456, "key_id": d["leader"]["key_id"],
                       "spki": d["leader"]["spki"]},
            "by": a_kid.as_str(), "at": 0,
        }]);
        let owner = record(
            &a_kid,
            a["spki"].as_str().unwrap(),
            1001,
            "owner",
            false,
            json!({"kind": "pair"}),
        );
        let mut file = list(
            4,
            true,
            state["grant_token"].as_str().unwrap(),
            vec![owner],
            json!({ "parties": parties }),
        );
        file["spent"]["grant_ids"] = state["spent_grant_ids"].clone();
        write(&dir.0, &file);
        let mut pc = pc(&dir.0);
        let kid = KeyId::parse(case["proof_key_id"].as_str().unwrap()).unwrap();
        let got = run_party_ground(&mut pc, &kid, grant);
        let want_why = (expect != "ok" && expect != "grant_malformed")
            .then(|| case["why"].as_str())
            .flatten()
            .filter(|w| *w == OWNER_ON_PC);
        assert_eq!(got, (expect.to_string(), want_why), "{name}");
    }
    for c in v["cross_domain"].as_array().unwrap() {
        let f = &c["fields"];
        let g = PartyGrant::parse(f).unwrap();
        let fields = GrantFields {
            device_id: &g.device_id,
            key_id: &g.key_id,
            telegram_user_id: g.telegram_user_id,
            name: g.name.as_deref(),
            username: g.username.as_deref(),
            inv_id: Some(&g.party_id),
            grant_id: &g.grant_id,
            grant_token: &g.grant_token,
            issued_at: g.issued_at,
            by: &g.by,
        };
        let (party, v2) = (
            party_grant_message(&fields, &g.party_id),
            grant_message(&fields),
        );
        let (own, other) = if c["signed_under"] == "party" {
            (party, v2)
        } else {
            (v2, party)
        };
        assert_eq!(own, hex(c["own_hex"].as_str().unwrap()));
        assert_eq!(other, hex(c["other_hex"].as_str().unwrap()));
        let key = spki_key(c["signer_spki"].as_str().unwrap());
        assert!(
            key.verify(&own, &g.sig).is_ok(),
            "valid under its own domain"
        );
        assert!(key.verify(&other, &g.sig).is_err(), "never under the other");
    }
}

/// The `party` ground alone, for key `kid`: `("ok", None)` for a candidate, else the
/// `ended_detail` and the `why` of an «owner on this PC».
fn run_party_ground(pc: &mut Pc, kid: &KeyId, grant: &Value) -> (String, Option<&'static str>) {
    run_party_ground_into(pc, kid, grant, &mut Vec::new())
}

/// [`run_party_ground`], with the journal events the ground pushes into `journal`.
fn run_party_ground_into(
    pc: &mut Pc,
    kid: &KeyId,
    grant: &Value,
    journal: &mut Vec<JournalEvent>,
) -> (String, Option<&'static str>) {
    let Pc {
        trusted, engine, ..
    } = pc;
    let proof = OfferProof {
        key_id: kid.clone(),
        nonce_pc: [0; 16],
        sig: [0; 64],
        key_reg: None,
        admit: Vec::new(),
    };
    let new = Key::new();
    let reg = KeyReg {
        key: ViewerKey::from_spki(&new.spki).unwrap(),
        kind: ClientKind::parse("telegram").unwrap(),
        platform: Platform::parse("iphone").unwrap(),
        rpk: None,
    };
    let ctx = GroundCtx {
        trusted,
        store: trusted.store().unwrap(),
        proof: &proof,
        reg: Some(&reg),
        session_id: "s",
        mode: Mode::Strict,
        now_ms: 0,
    };
    match engine.party(&ctx, &reg.new_key(), grant, journal) {
        Ok(_) => ("ok".into(), None),
        Err(Fail::Verdict(v) | Fail::Stop(v)) => (v.detail.unwrap_or(v.code).into(), None),
        Err(Fail::Why(v, why)) => (v.detail.unwrap_or(v.code).into(), Some(why)),
    }
}

// --- C. The one function: the nine steps in order -----------------------------------------------

/// Each step refuses before the next one is looked at: a damaged list before the form, the form
/// before the device, the device before the bucket, the bucket before the signer — and a join
/// without a readable `party_id` is not answered and takes no token from the bucket.
#[test]
fn a_join_answers_its_first_failed_step() {
    let (owner, leader, guest) = (Key::new(), Key::new(), Key::new());
    let dir = Dir::new();
    let mut pc = owner_pc(&dir, &owner, true, "");
    let good = join_of(&[1; 16], "Орлы", &leader, &GrantToken::default(), &owner);
    let mut bad_form = good.clone();
    bad_form["party"] = "".into();
    let mut other_pc = good.clone();
    other_pc["device_id"] = "c41e9a07-2f5b-4d83-9e16-7b0a5c3d8f21".into();
    let by_guest = join_of(&[1; 16], "Орлы", &leader, &GrantToken::default(), &guest);

    // No readable party_id: nothing to answer, nothing spent.
    let mut unaddressed = good.clone();
    unaddressed["party_id"] = "short".into();
    assert_eq!(pc.join(&unaddressed, 0), "unaddressed");
    let leave = pc.engine.party_leave(&mut pc.trusted, "not-an-id", 0);
    assert_eq!(leave, PartyAnswer::Unaddressed);

    // The bucket empty (20 a second): the form and the device still answer first …
    for _ in 0..20 {
        assert!(pc.engine.take_bucket(0));
    }
    assert_eq!(pc.join(&bad_form, 0), "malformed");
    assert_eq!(pc.join(&other_pc, 0), "device");
    // … then busy, before the signer and the signature are read.
    assert_eq!(pc.join(&by_guest, 0), "busy");
    assert_eq!(pc.join(&good, 0), "busy");
    assert_eq!(
        pc.leave(&b64(&[1; 16]), 0),
        "busy",
        "a leave takes a token too"
    );
    assert!(pc.store().saved_delegations().unwrap().is_empty());

    // A second later: the signer (an owner key of this PC), then the rest.
    assert_eq!(
        pc.join(&by_guest, 2_000),
        "signer",
        "a key the PC does not hold"
    );
    assert_eq!(pc.join(&good, 2_000), "ok");

    // A damaged list answers damaged before anything else, a bad form too.
    std::fs::write(dir.0.join(FILE_NAME), b"{").unwrap();
    let mut damaged = pc_after_reopen(&dir);
    assert_eq!(damaged.join(&bad_form, 4_000), "damaged");
    assert_eq!(damaged.leave(&b64(&[1; 16]), 4_000), "damaged");
}

fn pc_after_reopen(dir: &Dir) -> Pc {
    let pc = pc(&dir.0);
    assert!(pc.store().is_damaged());
    pc
}

/// Step 5: a guest's key, an unknown key, a removed owner key, and in strict mode an unconfirmed
/// owner key are `signer`; observe mode takes the unconfirmed owner. Step 6 under the signer's
/// SPKI; step 7 the token byte for byte.
#[test]
fn the_signer_the_signature_and_the_token() {
    let (owner, unconfirmed, guest, leader) = (Key::new(), Key::new(), Key::new(), Key::new());
    for strict in [true, false] {
        let dir = Dir::new();
        let token = GrantToken::fresh(GrantToken::default());
        write(
            &dir.0,
            &list(
                3,
                strict,
                &token.to_wire(),
                vec![
                    owner.record(1001, "owner", false),
                    unconfirmed.record(1001, "owner", true),
                    guest.record(7, "guest", false),
                ],
                json!({}),
            ),
        );
        let mut pc = pc(&dir.0);
        let join = |by: &Key, t: &GrantToken| join_of(&[2; 16], "Орлы", &leader, t, by);
        assert_eq!(pc.join(&join(&guest, &token), 0), "signer");
        assert_eq!(
            pc.join(&join(&unconfirmed, &token), 0),
            if strict { "signer" } else { "ok" },
            "strict {strict}"
        );
        let mut forged = join(&owner, &token);
        forged["party"] = "Орлы2".into();
        assert_eq!(
            pc.join(&forged, 0),
            "bad_sig",
            "a field altered after signing"
        );
        let mut signed_by_other = join(&owner, &token);
        signed_by_other["sig"] = join(&guest, &token)["sig"].clone();
        assert_eq!(pc.join(&signed_by_other, 0), "bad_sig");
        assert_eq!(pc.join(&join(&owner, &GrantToken::default()), 0), "stale");
        let older = GrantToken::fresh(token);
        assert_eq!(pc.join(&join(&owner, &older), 0), "stale");
        assert_eq!(pc.join(&join(&owner, &token), 0), "ok");
        // A removed owner key signs nothing.
        let store = pc.trusted.store_for_notes().unwrap();
        store.deny_tree_now(&owner.kid, 0).unwrap();
        let now = pc.token();
        assert_eq!(pc.join(&join(&owner, &now), 0), "signer");
    }
}

/// Step 8: a new party past 256 is `limit`; a party the PC is in is still taken at the limit.
#[test]
fn the_257th_party_is_limit() {
    let (owner, leader) = (Key::new(), Key::new());
    let dir = Dir::new();
    let mut pc = owner_pc(&dir, &owner, true, "");
    for i in 0..MAX_DELEGATIONS {
        let mut id = [0u8; 16];
        id[..8].copy_from_slice(&(i as u64).to_be_bytes());
        let j = join_of(&id, "P", &leader, &GrantToken::default(), &owner);
        assert_eq!(pc.join(&j, (i as u64) * 100), "ok");
    }
    let next = join_of(&[0xEE; 16], "P", &leader, &GrantToken::default(), &owner);
    assert_eq!(pc.join(&next, 1_000_000), "limit");
    let again = join_of(&[0; 16], "P", &leader, &GrantToken::default(), &owner);
    assert_eq!(pc.join(&again, 1_000_000), "ok", "a party already there");
    assert_eq!(
        pc.store().saved_delegations().unwrap().len(),
        MAX_DELEGATIONS
    );
}

// --- §4.4 The grant token ------------------------------------------------------------------------

/// The token changes when something is taken from the PC or a party's leader changes; never on
/// a new party, nor on the same leader signed again by another owner key, nor on a leave of a
/// party the PC is not in.
#[test]
fn the_grant_token_follows_the_table() {
    let (owner, owner2, leader, leader2) = (Key::new(), Key::new(), Key::new(), Key::new());
    let dir = Dir::new();
    write(
        &dir.0,
        &list(
            3,
            true,
            "",
            vec![
                owner.record(1001, "owner", false),
                owner2.record(1001, "owner", false),
            ],
            json!({}),
        ),
    );
    let mut pc = pc(&dir.0);
    let p = [3u8; 16];
    let t0 = pc.token();
    assert_eq!(pc.join(&join_of(&p, "Орлы", &leader, &t0, &owner), 0), "ok");
    assert_eq!(pc.token(), t0, "a new party: the token stays");
    assert_eq!(
        pc.join(&join_of(&[4; 16], "Б", &leader2, &t0, &owner), 0),
        "ok"
    );
    assert_eq!(pc.token(), t0, "another new party: the token stays");
    assert_eq!(
        pc.join(&join_of(&p, "Орлы", &leader, &t0, &owner2), 0),
        "ok"
    );
    assert_eq!(
        pc.token(),
        t0,
        "the same leader by another owner key: the token stays"
    );
    assert_eq!(
        pc.store().delegation(&ground_id(&p)).unwrap().0.by,
        owner2.kid
    );
    assert_eq!(pc.leave(&b64(&[9; 16]), 0), "ok");
    assert_eq!(
        pc.token(),
        t0,
        "a leave of a party the PC is not in changes nothing"
    );
    assert_eq!(
        pc.join(&join_of(&p, "Орлы", &leader2, &t0, &owner), 0),
        "ok"
    );
    let t1 = pc.token();
    assert_ne!(t1, t0, "another leader: the token changes");
    assert_eq!(
        pc.join(&join_of(&p, "Орлы", &leader, &t0, &owner), 0),
        "stale",
        "the earlier join over the earlier token"
    );
    assert_eq!(pc.leave(&b64(&p), 0), "ok");
    assert_ne!(pc.token(), t1, "a leave: the token changes");
    assert_eq!(
        pc.store().saved_grant_token(),
        Some(pc.token()),
        "written with it"
    );
}

// --- B. The file -------------------------------------------------------------------------------

/// A version 3 file loads; a list with no party content is written as version 3 without a
/// `parties` field (what the released build reads); party content writes version 4, which reads
/// back as written; a newer version is damage.
#[test]
fn the_file_is_3_without_parties_and_4_with_them() {
    let (owner, leader) = (Key::new(), Key::new());
    let dir = Dir::new();
    let mut pc = owner_pc(&dir, &owner, true, "");
    assert!(!pc.store().is_damaged(), "version 3 loads");
    let store = pc.trusted.store_for_notes().unwrap();
    store.deny_tree_now(&owner.kid, 1).unwrap();
    store.flush().unwrap();
    let f = dir.file();
    assert_eq!(f["version"], 3);
    assert!(f.get("parties").is_none());
    let keys: Vec<&String> = f.as_object().unwrap().keys().collect();
    assert_eq!(
        keys,
        [
            "grant_token",
            "keys",
            "spent",
            "switches",
            "tombstones",
            "version"
        ],
        "the released writer's fields"
    );

    let dir = Dir::new();
    let mut pc = owner_pc(&dir, &owner, true, "");
    assert_eq!(
        pc.join(
            &join_of(&[5; 16], "Орлы", &leader, &GrantToken::default(), &owner),
            0
        ),
        "ok"
    );
    let f = dir.file();
    assert_eq!(f["version"], 4);
    assert_eq!(f["parties"][0]["party"], "Орлы");
    assert_eq!(f["parties"][0]["leader"]["key_id"], leader.kid.as_str());
    let again = TrustStore::open_in(&dir.0);
    assert_eq!(
        again.delegations().unwrap(),
        pc.store().delegations().unwrap(),
        "round trip"
    );

    // A tombstone with a party source alone keeps version 4.
    let src = json!({"kind": "party", "party_id": b64(&[5; 16]), "by": leader.kid.as_str(),
                     "grant_id": b64(&[6; 16])});
    let member = Key::new();
    let mut f = list(
        4,
        true,
        "",
        vec![owner.record(1001, "owner", false)],
        json!({}),
    );
    f["tombstones"] = json!([{"key_id": member.kid.as_str(), "spki": member.spki_text(),
        "telegram_user_id": 9, "origin": {"kind": "server"}, "at": 1, "source": src}]);
    f["spent"]["grant_ids"] = json!([b64(&[6; 16])]);
    let dir = Dir::new();
    write(&dir.0, &f);
    let mut store = TrustStore::open_in(&dir.0);
    assert!(!store.is_damaged());
    store.deny_tree_now(&owner.kid, 2).unwrap();
    store.flush().unwrap();
    assert_eq!(dir.file()["version"], 4, "a removed party record counts");

    let damaged = |f: &Value| {
        let dir = Dir::new();
        write(&dir.0, f);
        TrustStore::open_in(&dir.0).damage().map(|d| d.kind)
    };
    let mut newer = f.clone();
    newer["version"] = 5.into();
    assert_eq!(damaged(&newer), Some(DamageKind::NewerVersion));
    let mut unspent = f.clone();
    unspent["spent"]["grant_ids"] = json!([]);
    assert_eq!(
        damaged(&unspent),
        Some(DamageKind::Invariant),
        "a party grant_id is spent"
    );
    let mut wrong_leader = list(
        4,
        true,
        "",
        vec![owner.record(1001, "owner", false)],
        json!({}),
    );
    wrong_leader["parties"] = json!([{"party_id": b64(&[5; 16]), "party": "Орлы",
        "leader": {"telegram_user_id": 456, "key_id": owner.kid.as_str(), "spki": leader.spki_text()},
        "by": owner.kid.as_str(), "at": 0}]);
    assert_eq!(
        damaged(&wrong_leader),
        Some(DamageKind::Invariant),
        "key_id is its SPKI's"
    );
}

// --- F. Leaving, a reset, an owner key removed -----------------------------------------------------

/// A party's keys as the leave walk finds them: K1 came through the party and was replaced by a
/// recovery K2, which endorsed K3; R is a pairing of another person. The leave takes K2 and K3
/// (forward through the recovery), `server`; R stays, so does the owner.
fn walk_pc(dir: &Dir, owner: &Key, leader: &Key) -> (Key, Key, Key, Key) {
    let (k1, k2, k3, r) = (Key::new(), Key::new(), Key::new(), Key::new());
    let party = b64(&[7; 16]);
    let k1_src = json!({"kind": "party", "party_id": party, "by": leader.kid.as_str(),
                        "grant_id": b64(&[8; 16])});
    let k2_src = json!({"kind": "recover", "replaced": [k1.kid.as_str()], "parents": []});
    let k3_src = json!({"kind": "endorse", "by": k2.kid.as_str(), "endorse_id": b64(&[9; 16])});
    let mut f = list(
        4,
        true,
        "",
        vec![
            owner.record(1001, "owner", false),
            record(&k2.kid, &k2.spki_text(), 50, "guest", false, k2_src),
            record(&k3.kid, &k3.spki_text(), 50, "guest", false, k3_src),
            r.record(60, "guest", false),
        ],
        json!({"parties": [{"party_id": party, "party": "Орлы",
            "leader": {"telegram_user_id": 456, "key_id": leader.kid.as_str(),
                       "spki": leader.spki_text()},
            "by": owner.kid.as_str(), "at": 0}]}),
    );
    f["tombstones"] = json!([{"key_id": k1.kid.as_str(), "spki": k1.spki_text(),
        "telegram_user_id": 50, "origin": {"kind": "replaced", "new_key_id": k2.kid.as_str()},
        "at": 1, "source": k1_src}]);
    f["spent"] = json!({"endorse_ids": [b64(&[9; 16])], "grant_ids": [b64(&[8; 16])],
                        "invite_ids": []});
    write(&dir.0, &f);
    (k1, k2, k3, r)
}

fn origin_of(dir: &Dir, k: &Key) -> Option<String> {
    dir.file()["tombstones"]
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["key_id"] == k.kid.as_str())
        .map(|t| t["origin"]["kind"].as_str().unwrap().to_string())
}

#[test]
fn a_leave_walks_forward_through_a_recovery() {
    let (owner, leader) = (Key::new(), Key::new());
    let dir = Dir::new();
    let (_, k2, k3, r) = walk_pc(&dir, &owner, &leader);
    let mut pc = pc(&dir.0);
    let t0 = pc.token();
    assert_eq!(pc.leave(&b64(&[7; 16]), 0), "ok");
    assert_eq!(origin_of(&dir, &k2).as_deref(), Some("server"));
    assert_eq!(origin_of(&dir, &k3).as_deref(), Some("server"));
    assert_eq!(origin_of(&dir, &r), None, "another person's pairing stays");
    assert_eq!(origin_of(&dir, &owner), None);
    assert!(pc.store().saved_delegations().unwrap().is_empty());
    assert_ne!(pc.token(), t0);
    assert_eq!(
        dir.file()["version"],
        4,
        "the party's removed records keep version 4"
    );
}

/// Party spec §6: only by the server's word (`party_leave`) does a person who holds a working
/// owner key here keep their keys of the party; a leave pressed at the PC and the removal of the
/// owner key that signed the delegation take them `server`. That person's owner-role key stays in
/// every path, though it is on the walk (a recovery replaced a key of the party with it).
#[test]
fn only_the_servers_leave_spares_an_owner_on_this_pc() {
    use crate::trusted::{TrustedAsk, TrustedRequest};
    let (owner, leader, extra) = (Key::new(), Key::new(), Key::new());
    for path in ["server", "pc", "signer"] {
        let dir = Dir::new();
        let (_, k2, k3, _) = walk_pc(&dir, &owner, &leader);
        // User 50's owner-role key sits on the walk: it replaced, by a recovery, an older key
        // of the party (the walk goes forward from that key to it).
        let k4 = Key::new();
        let mut f = dir.file();
        f["keys"].as_array_mut().unwrap().push(record(
            &extra.kid,
            &extra.spki_text(),
            50,
            "owner",
            false,
            json!({"kind": "recover", "replaced": [k4.kid.as_str()], "parents": []}),
        ));
        f["tombstones"].as_array_mut().unwrap().push(json!({
            "key_id": k4.kid.as_str(), "spki": k4.spki_text(), "telegram_user_id": 50,
            "origin": {"kind": "replaced", "new_key_id": extra.kid.as_str()}, "at": 1,
            "source": {"kind": "party", "party_id": b64(&[7; 16]), "by": leader.kid.as_str(),
                       "grant_id": b64(&[10; 16])}}));
        f["spent"]["grant_ids"]
            .as_array_mut()
            .unwrap()
            .push(b64(&[10; 16]).into());
        write(&dir.0, &f);
        let mut pc = pc(&dir.0);
        assert!(!pc.store().is_damaged());
        match path {
            "server" => assert_eq!(pc.leave(&b64(&[7; 16]), 0), "ok"),
            "pc" => {
                let (reply, mut answer) = tokio::sync::oneshot::channel();
                let ask = TrustedAsk::PartyLeave {
                    party_id: GroundId::parse(&b64(&[7; 16])).unwrap(),
                };
                pc.trusted.command(TrustedRequest { ask, reply }, 0);
                assert!(
                    pc.land().is_empty(),
                    "no server answer for a leave at the PC"
                );
                assert_eq!(answer.try_recv().ok(), Some(Ok(2)), "K2 and K3");
            }
            _ => {
                let store = pc.trusted.store_for_notes().unwrap();
                store.deny_tree_now(&owner.kid, 5).unwrap();
                store.flush().unwrap();
                assert_eq!(origin_of(&dir, &owner).as_deref(), Some("pc"));
            }
        }
        let taken = (path != "server").then(|| "server".to_string());
        assert_eq!(origin_of(&dir, &k2), taken, "{path}: user 50's guest key");
        assert_eq!(origin_of(&dir, &k3), taken, "{path}: its descendant");
        assert!(
            matches!(pc.store().lookup(&extra.kid), Lookup::Active(_)),
            "{path}: the owner-role key on the walk stays"
        );
        assert_eq!(origin_of(&dir, &extra), None, "{path}: and is written so");
        assert!(pc.store().saved_delegations().unwrap().is_empty(), "{path}");
    }
}

/// «Удалить» of the owner key that signed a delegation is a leave in the same change; «Сбросить»
/// leaves every party, its keys `server`, the rest `pc`.
#[test]
fn an_owner_keys_removal_and_a_reset_leave_the_parties() {
    let (owner, leader) = (Key::new(), Key::new());
    let dir = Dir::new();
    let (_, k2, k3, r) = walk_pc(&dir, &owner, &leader);
    let mut store = TrustStore::open_in(&dir.0);
    let tree = store.deny_tree_now(&owner.kid, 5).unwrap();
    assert!(tree.removed.contains(&k2.kid) && tree.removed.contains(&k3.kid));
    assert!(
        store.delegations().unwrap().is_empty(),
        "decided at the press"
    );
    store.flush().unwrap();
    assert_eq!(origin_of(&dir, &owner).as_deref(), Some("pc"));
    assert_eq!(origin_of(&dir, &k2).as_deref(), Some("server"));
    assert_eq!(origin_of(&dir, &r), None);
    assert!(dir.file().get("parties").is_none());

    let dir = Dir::new();
    let (_, k2, k3, r) = walk_pc(&dir, &owner, &leader);
    let mut store = TrustStore::open_in(&dir.0);
    store.reset_to_empty(5).unwrap();
    assert_eq!(origin_of(&dir, &k2).as_deref(), Some("server"));
    assert_eq!(origin_of(&dir, &k3).as_deref(), Some("server"));
    assert_eq!(origin_of(&dir, &r).as_deref(), Some("pc"));
    assert_eq!(origin_of(&dir, &owner).as_deref(), Some("pc"));
    assert!(store.delegations().unwrap().is_empty());
    assert!(dir.file().get("parties").is_none());
}

/// A recovery of the owner key that signed a delegation: the delegation stays, its signer the
/// replacing key; that key's «Удалить» is the leave then.
#[test]
fn a_recovered_signer_keeps_the_delegation() {
    let (old, new, leader) = (Key::new(), Key::new(), Key::new());
    let party = b64(&[7; 16]);
    let new_src = json!({"kind": "recover", "replaced": [old.kid.as_str()], "parents": []});
    let mut f = list(
        4,
        true,
        "",
        vec![record(
            &new.kid,
            &new.spki_text(),
            1001,
            "owner",
            false,
            new_src,
        )],
        json!({"parties": [{"party_id": party, "party": "Орлы",
            "leader": {"telegram_user_id": 456, "key_id": leader.kid.as_str(),
                       "spki": leader.spki_text()},
            "by": old.kid.as_str(), "at": 0}]}),
    );
    f["tombstones"] = json!([{"key_id": old.kid.as_str(), "spki": old.spki_text(),
        "telegram_user_id": 1001, "origin": {"kind": "replaced", "new_key_id": new.kid.as_str()},
        "at": 1, "source": {"kind": "pair"}}]);
    let dir = Dir::new();
    write(&dir.0, &f);
    let mut store = TrustStore::open_in(&dir.0);
    let id = GroundId::parse(&party).unwrap();
    assert_eq!(store.delegation(&id).unwrap().1.key_id(), &new.kid);
    store.deny_tree_now(&new.kid, 3).unwrap();
    assert!(store.delegation(&id).is_none());
    assert!(
        store.delegations().unwrap().is_empty(),
        "removing the signer now is the leave"
    );
}

// --- §4.3 The write of a decision ------------------------------------------------------------------

/// Another writer's change of the file: a pairing of user `uid`.
fn other_writer(dir: &Dir, uid: i64) {
    let k = Key::new();
    let mut other = TrustStore::open_in(&dir.0);
    other
        .add(
            NewKey {
                key: ViewerKey::from_spki(&k.spki).unwrap(),
                rpk: None,
                kind: ClientKind::parse("telegram").unwrap(),
                platform: Platform::parse("android").unwrap(),
            },
            Ground::Pair {
                person: Person {
                    telegram_user_id: uid,
                    first_name: None,
                    username: None,
                },
                role: BindingRole::Guest,
                unconfirmed: false,
            },
            1,
        )
        .unwrap();
}

/// The next file job's result taken in, as the main loop would (the job runs on the runtime's
/// blocking pool and reports through the channel).
async fn step(pc: &mut Pc) {
    let since = Instant::now();
    loop {
        if let Ok(d) = pc.done.try_recv() {
            pc.trusted.on_done(d, 0, None);
            return;
        }
        assert!(
            since.elapsed() < Duration::from_secs(60),
            "a job's result in time"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

/// A join decided in memory survives a reload of the file before its write lands (another writer
/// changed the file: the write is abandoned, the list read again, memory's delegations kept), and
/// its answer goes once, after the write that holds it. A write that cannot be saved is parked,
/// tried again on the timer, and answered once.
#[tokio::test]
async fn a_joins_write_survives_a_reload_and_is_answered_once() {
    let (owner, leader) = (Key::new(), Key::new());
    let dir = Dir::new();
    let mut pc = owner_pc(&dir, &owner, true, "");
    let (release, gate) = std::sync::mpsc::channel::<()>();
    pc.trusted.gate_jobs(gate);
    let join = |id: u8| join_of(&[id; 16], "Орлы", &leader, &GrantToken::default(), &owner);

    let answer = pc.engine.party_join(&mut pc.trusted, &join(5), 0);
    assert_eq!(answer, PartyAnswer::Queued);
    other_writer(&dir, 200);
    release.send(()).unwrap();
    step(&mut pc).await;
    assert!(pc.trusted.take_party_acks().is_empty(), "not written yet");
    assert_eq!(
        pc.store().delegations().unwrap().len(),
        1,
        "kept over the reload"
    );
    assert!(pc.store().saved_delegations().unwrap().is_empty());
    release.send(()).unwrap();
    step(&mut pc).await;
    let acks = pc.trusted.take_party_acks();
    assert_eq!(acks.len(), 1);
    assert_eq!(acks[0].result, PartyAckResult::Ok);
    assert_eq!(pc.store().saved_delegations().unwrap().len(), 1);
    let f = dir.file();
    assert_eq!(f["parties"].as_array().unwrap().len(), 1);
    assert_eq!(
        f["keys"].as_array().unwrap().len(),
        2,
        "the other writer's key kept"
    );

    // Out of attempts: parked, its delegation kept in memory, no answer.
    let answer = pc.engine.party_join(&mut pc.trusted, &join(6), 0);
    assert_eq!(answer, PartyAnswer::Queued);
    for n in 0..crate::trusted::MAX_ATTEMPTS {
        other_writer(&dir, 300 + i64::from(n));
        release.send(()).unwrap();
        step(&mut pc).await;
        assert!(pc.trusted.take_party_acks().is_empty(), "attempt {n}");
    }
    assert!(pc.trusted.settled(), "parked, nothing in flight");
    assert_eq!(pc.store().delegations().unwrap().len(), 2);
    assert_eq!(pc.store().saved_delegations().unwrap().len(), 1);
    // The timer tries it again: written, answered once.
    pc.trusted
        .tick(Instant::now() + crate::trusted::PARKED_RETRY + Duration::from_secs(1));
    release.send(()).unwrap();
    step(&mut pc).await;
    let acks = pc.trusted.take_party_acks();
    assert_eq!(acks.len(), 1);
    assert_eq!(acks[0].party_id, b64(&[6; 16]));
    assert_eq!(pc.store().saved_delegations().unwrap().len(), 2);
    drop(release);
    assert!(pc.trusted.settled());
    assert!(pc.land().is_empty(), "answered once");
}

/// Process §7: a member's device the full list refuses (the person's own limit here) is `limit`,
/// and the person at the PC is told — the person and the party ([`JournalEvent::PartyDeviceLimit`])
/// — once: the same refusal within the hour tells nothing more.
#[test]
fn a_full_list_refuses_a_members_device_and_tells_it_once_an_hour() {
    let v = vectors("grant.json");
    let case = v["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "main")
        .unwrap()
        .clone();
    let state = v["pc"].clone();
    let a = vectors("join.json")["pc"]["keys"][0].clone();
    let a_kid = KeyId::parse(a["key_id"].as_str().unwrap()).unwrap();
    let grant = &case["admit"]["grant"];
    let uid = grant["telegram_user_id"].as_i64().unwrap();
    let d = &state["delegations"][0];
    let parties = json!([{
        "party_id": d["party_id"], "party": "Орлы",
        "leader": {"telegram_user_id": 456, "key_id": d["leader"]["key_id"],
                   "spki": d["leader"]["spki"]},
        "by": a_kid.as_str(), "at": 0,
    }]);
    let mut keys = vec![record(
        &a_kid,
        a["spki"].as_str().unwrap(),
        1001,
        "owner",
        false,
        json!({"kind": "pair"}),
    )];
    keys.extend(
        (0..crate::viewer_keys::MAX_KEYS_PER_PERSON)
            .map(|_| Key::new().record(uid, "guest", false)),
    );
    let dir = Dir::new();
    let mut file = list(
        4,
        true,
        state["grant_token"].as_str().unwrap(),
        keys,
        json!({ "parties": parties }),
    );
    file["spent"]["grant_ids"] = state["spent_grant_ids"].clone();
    write(&dir.0, &file);
    let mut pc = pc(&dir.0);
    let kid = KeyId::parse(case["proof_key_id"].as_str().unwrap()).unwrap();
    let mut journal = Vec::new();
    assert_eq!(
        run_party_ground_into(&mut pc, &kid, grant, &mut journal),
        ("limit".to_string(), None)
    );
    let party_id = GroundId::parse(d["party_id"].as_str().unwrap()).unwrap();
    assert!(
        matches!(
            journal.as_slice(),
            [JournalEvent::PartyDeviceLimit { telegram_user_id, party_id: p }]
                if *telegram_user_id == uid && *p == party_id
        ),
        "{:?}",
        journal.iter().map(JournalEvent::name).collect::<Vec<_>>()
    );
    assert_eq!(
        run_party_ground_into(&mut pc, &kid, grant, &mut journal),
        ("limit".to_string(), None)
    );
    assert_eq!(journal.len(), 1, "told once within the hour");
}
