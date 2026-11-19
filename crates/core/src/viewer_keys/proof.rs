//! The viewer's signed material on the wire, parsed and checked over bytes (protocol spec §1.2,
//! §3, §4, §6.5, §7, §8.3, §9): `offer_proof` with its limits, the key card `key_reg`, and the
//! grounds of `proof.admit`. Nothing here reads the trust list or the clock: the admission
//! (`crate::admission`) decides with the list.
//!
//! Every parser is strict (spec §1.2: base64url exactly, lengths by the table) and answers why it
//! refused with a stable `why` (the vectors' names), logged at `debug` by the caller. Unknown
//! fields are ignored, and so are `admit` entries of an unknown `kind` (spec §1.2).

use std::io::Write as _;

use serde_json::{Map, Value};

use afklink_protocol::party::{
    check_party_statement_wire, is_party_name, PARTY_LEADER_NAME_MAX, PARTY_LEADER_USERNAME_MAX,
};
use afklink_protocol::viewer_keys::WireLimit;

use super::wire::{
    b64url_array, b64url_exact, endorse_message, first_use_message, grant_message, invite_message,
    key_reg_message, offer_message, party_grant_message, party_join_message, GrantFields,
    GrantToken, PartyJoinFields, FINGERPRINT_LEN, GROUND_ID_BYTES, NONCE_PC_LEN,
};
use super::{
    ClientKind, GroundId, KeyId, Platform, ViewerKey, MAX_INIT_DATA_LEN, MAX_USER_ID,
    SIGNATURE_LEN, SPKI_LEN,
};

/// The most bytes of `proof` in compact serialization (spec §1.2).
pub const MAX_PROOF_BYTES: usize = 16 * 1024;
/// The deepest `proof`: nested objects and arrays, the proof object itself is level 1.
pub const MAX_PROOF_DEPTH: usize = 8;
/// The most grounds in `proof.admit`.
pub const MAX_ADMIT: usize = 4;
/// The most bytes of `pair_request.viewer_key` (spec §1.2).
pub const MAX_VIEWER_KEY_BYTES: usize = 1024;
/// The characters of a base64url ECDSA signature.
const SIG_CHARS: usize = 86;

/// A refusal's reason, for the log and the vectors' `why`.
pub type Why = &'static str;

/// `proof` of a first offer (spec §3.2), parsed: what the signature covers, the key card, and
/// the grounds (each parsed only when the admission reaches it, so its own code is the verdict).
#[derive(Debug, Clone)]
pub struct OfferProof {
    pub key_id: KeyId,
    pub nonce_pc: [u8; NONCE_PC_LEN],
    pub sig: [u8; SIGNATURE_LEN],
    /// The raw key card, checked by [`KeyReg::parse_verify`] when it is needed.
    pub key_reg: Option<Value>,
    pub admit: Vec<AdmitEntry>,
}

/// One ground of `proof.admit`, by its `kind`; unparsed beyond what the limits need.
#[derive(Debug, Clone)]
pub enum AdmitEntry {
    Endorse(Value),
    Grant {
        grant: Value,
        invite: Option<Value>,
    },
    Recover(Map<String, Value>),
    FirstUse(Map<String, Value>),
    /// A party leader's grant (party spec §2.3): the item's `grant`.
    Party(Value),
}

impl AdmitEntry {
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Endorse(_) => "endorse",
            Self::Grant { .. } => "grant",
            Self::Recover(_) => "recover",
            Self::FirstUse(_) => "first_use",
            Self::Party(_) => "party",
        }
    }
}

/// Counts bytes without keeping them.
struct Count(usize);

impl std::io::Write for Count {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0 = self.0.saturating_add(buf.len());
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// The compact serialization's length of `value` (spec §1.2: `serde_json::to_vec`).
pub fn compact_len(value: &Value) -> usize {
    let mut count = Count(0);
    if serde_json::to_writer(&mut count, value).is_err() {
        return usize::MAX;
    }
    let _ = count.flush();
    count.0
}

/// Whether `value` nests at most `max` levels of objects and arrays (a scalar is level 0, the
/// outer object level 1). Iterative: no recursion on the attacker's shape.
pub fn depth_within(value: &Value, max: usize) -> bool {
    let mut stack: Vec<(&Value, usize)> = vec![(value, 1)];
    while let Some((v, level)) = stack.pop() {
        let children: Box<dyn Iterator<Item = &Value>> = match v {
            Value::Object(m) => Box::new(m.values()),
            Value::Array(a) => Box::new(a.iter()),
            _ => continue,
        };
        if level > max {
            return false;
        }
        for child in children {
            if matches!(child, Value::Object(_) | Value::Array(_)) {
                stack.push((child, level + 1));
            }
        }
    }
    true
}

fn str_field<'a>(m: &'a Map<String, Value>, name: &str) -> Option<&'a str> {
    m.get(name).and_then(Value::as_str)
}

fn key_id_field(m: &Map<String, Value>, name: &str) -> Option<KeyId> {
    str_field(m, name).and_then(KeyId::parse)
}

fn sig_field(m: &Map<String, Value>, name: &str) -> Option<[u8; SIGNATURE_LEN]> {
    str_field(m, name)
        .filter(|s| s.len() == SIG_CHARS)
        .and_then(b64url_array::<SIGNATURE_LEN>)
}

fn ground_field(m: &Map<String, Value>, name: &str) -> Option<[u8; GROUND_ID_BYTES]> {
    str_field(m, name).and_then(b64url_array::<GROUND_ID_BYTES>)
}

/// `v` is exactly the integer 1.
fn v1(m: &Map<String, Value>) -> bool {
    m.get("v").and_then(Value::as_u64) == Some(1)
}

/// A JSON integer in `1..=2^53-1` (spec §1.1).
fn user_id(v: Option<&Value>) -> Option<i64> {
    v.and_then(Value::as_i64)
        .filter(|n| (1..=MAX_USER_ID).contains(n))
}

/// A JSON non-negative integer that fits `u64` (`issued_at`).
fn millis(v: Option<&Value>) -> Option<u64> {
    v.and_then(Value::as_u64)
}

impl OfferProof {
    /// Parse `proof` (spec §3.4 step 3): the limits first, before any decoding or cryptography
    /// (size, depth, `admit` count, `init_data` length), then `v`, `key_id`, `nonce_pc`, `sig`.
    /// Every failure is `proof_invalid:malformed`; `why` names the rule.
    pub fn parse(value: &Value) -> Result<Self, Why> {
        let Value::Object(m) = value else {
            return Err("not_object");
        };
        let size = compact_len(value);
        if size > MAX_PROOF_BYTES {
            tracing::debug!(size, max = MAX_PROOF_BYTES, "offer proof: too large");
            return Err("size");
        }
        if !depth_within(value, MAX_PROOF_DEPTH) {
            return Err("depth");
        }
        let admit_raw = match m.get("admit") {
            None | Some(Value::Null) => &[][..],
            Some(Value::Array(a)) => a.as_slice(),
            Some(_) => return Err("admit_not_array"),
        };
        if admit_raw.len() > MAX_ADMIT {
            tracing::debug!(
                count = admit_raw.len(),
                max = MAX_ADMIT,
                "offer proof: too many grounds"
            );
            return Err("admit_count");
        }
        let mut admit = Vec::with_capacity(admit_raw.len());
        for entry in admit_raw {
            let Value::Object(e) = entry else {
                return Err("admit_not_object");
            };
            let kind = str_field(e, "kind").unwrap_or("");
            match kind {
                "endorse" => admit.push(AdmitEntry::Endorse(
                    e.get("endorse").cloned().unwrap_or(Value::Null),
                )),
                "grant" => admit.push(AdmitEntry::Grant {
                    grant: e.get("grant").cloned().unwrap_or(Value::Null),
                    invite: e.get("invite").filter(|v| !v.is_null()).cloned(),
                }),
                "recover" => {
                    let init_len = e
                        .get("attest")
                        .and_then(|a| a.get("init_data"))
                        .and_then(Value::as_str)
                        .map_or(0, str::len);
                    if init_len > MAX_INIT_DATA_LEN {
                        tracing::debug!(
                            len = init_len,
                            max = MAX_INIT_DATA_LEN,
                            "offer proof: init_data too long"
                        );
                        return Err("init_data_size");
                    }
                    admit.push(AdmitEntry::Recover(e.clone()));
                }
                "first_use" => admit.push(AdmitEntry::FirstUse(e.clone())),
                "party" => admit.push(AdmitEntry::Party(
                    e.get("grant").cloned().unwrap_or(Value::Null),
                )),
                other => tracing::debug!(
                    kind_len = other.len(),
                    "offer proof: a ground of an unknown kind skipped"
                ),
            }
        }
        if !v1(m) {
            return Err("v");
        }
        let key_id = key_id_field(m, "key_id").ok_or("key_id")?;
        let nonce_pc = str_field(m, "nonce_pc")
            .and_then(b64url_array::<NONCE_PC_LEN>)
            .ok_or("nonce_pc")?;
        let sig = sig_field(m, "sig").ok_or("sig")?;
        let key_reg = m.get("key_reg").filter(|v| !v.is_null()).cloned();
        Ok(Self {
            key_id,
            nonce_pc,
            sig,
            key_reg,
            admit,
        })
    }

    /// Check the offer's signature (spec §3.1, §3.4 step 7) under `key`, with this PC's own
    /// `device_id` and the message's `session_id`.
    pub fn verify(
        &self,
        key: &ViewerKey,
        session_id: &str,
        device_id: &str,
        fp_viewer: &[u8; FINGERPRINT_LEN],
    ) -> bool {
        let m = offer_message(
            session_id,
            device_id,
            &self.key_id,
            &self.nonce_pc,
            fp_viewer,
        );
        key.verify(&m, &self.sig).is_ok()
    }
}

/// A key card (spec §4), checked: canonical SPKI, `kind`/`platform` well formed, `rpk` absent or
/// canonical, and the device key's signature over all of it.
#[derive(Debug, Clone)]
pub struct KeyReg {
    pub key: ViewerKey,
    pub kind: ClientKind,
    pub platform: Platform,
    pub rpk: Option<ViewerKey>,
}

impl KeyReg {
    /// Check a card. `why` (the vectors' order): `spki`, `kind`, `platform`, `rpk`, `sig`,
    /// `signature`.
    pub fn parse_verify(value: &Value) -> Result<Self, Why> {
        let Value::Object(m) = value else {
            return Err("not_object");
        };
        let key = str_field(m, "spki")
            .and_then(|s| b64url_exact(s, SPKI_LEN))
            .and_then(|b| ViewerKey::from_spki(&b).ok())
            .ok_or("spki")?;
        let kind = str_field(m, "kind")
            .and_then(ClientKind::parse)
            .ok_or("kind")?;
        let platform = str_field(m, "platform")
            .and_then(Platform::parse)
            .ok_or("platform")?;
        let rpk = match m.get("rpk") {
            None => None,
            Some(v) => Some(
                v.as_str()
                    .and_then(|s| b64url_exact(s, SPKI_LEN))
                    .and_then(|b| ViewerKey::from_spki(&b).ok())
                    .ok_or("rpk")?,
            ),
        };
        let sig = sig_field(m, "sig").ok_or("sig")?;
        let reg = key_reg_message(
            key.key_id(),
            kind.as_str(),
            platform.as_str(),
            rpk.as_ref().map(|r| &r.spki()[..]),
        );
        key.verify(&reg, &sig).map_err(|_| "signature")?;
        // not-a-key-name: a viewer device key's id, short (`kid`), never a keyboard key
        tracing::debug!(
            kid = %key.key_id().short(),
            kind = kind.as_str(),
            platform = platform.as_str(),
            rpk = rpk.is_some(),
            "key card: verified"
        );
        Ok(Self {
            key,
            kind,
            platform,
            rpk,
        })
    }

    /// The card's key, as the store adds it.
    pub fn new_key(&self) -> super::NewKey {
        super::NewKey {
            key: self.key.clone(),
            rpk: self.rpk.clone(),
            kind: self.kind.clone(),
            platform: self.platform.clone(),
        }
    }
}

/// `endorse` (spec §6.5), well formed (its signature is checked under the `by` record's key).
#[derive(Debug, Clone)]
pub struct Endorse {
    pub key_id: KeyId,
    pub by: KeyId,
    pub endorse_id: [u8; GROUND_ID_BYTES],
    pub issued_at: u64,
    pub sig: [u8; SIGNATURE_LEN],
}

impl Endorse {
    /// Form only (`endorse_malformed`).
    pub fn parse(value: &Value) -> Result<Self, Why> {
        let Value::Object(m) = value else {
            return Err("not_object");
        };
        if !v1(m) {
            return Err("v");
        }
        Ok(Self {
            key_id: key_id_field(m, "key_id").ok_or("key_id")?,
            by: key_id_field(m, "by").ok_or("by")?,
            endorse_id: ground_field(m, "endorse_id").ok_or("endorse_id")?,
            issued_at: millis(m.get("issued_at")).ok_or("issued_at")?,
            sig: sig_field(m, "sig").ok_or("sig")?,
        })
    }

    pub fn ground_id(&self) -> GroundId {
        ground_id(&self.endorse_id)
    }

    /// The signature under the endorsing key `by`.
    pub fn verify(&self, by: &ViewerKey) -> bool {
        let e = endorse_message(&self.key_id, &self.by, &self.endorse_id, self.issued_at);
        by.verify(&e, &self.sig).is_ok()
    }
}

/// An owner's invitation (spec §7), well formed.
#[derive(Debug, Clone)]
pub struct InviteSig {
    pub device_id: String,
    pub inv_id: [u8; GROUND_ID_BYTES],
    pub issued_at: u64,
    pub by: KeyId,
    pub sig: [u8; SIGNATURE_LEN],
}

impl InviteSig {
    /// Form only (a malformed invitation is `invite_missing`, spec §7 and grant.json).
    pub fn parse(value: &Value) -> Result<Self, Why> {
        let Value::Object(m) = value else {
            return Err("not_object");
        };
        if !v1(m) {
            return Err("v");
        }
        Ok(Self {
            device_id: str_field(m, "device_id").ok_or("device_id")?.to_string(),
            inv_id: ground_field(m, "inv_id").ok_or("inv_id")?,
            issued_at: millis(m.get("issued_at")).ok_or("issued_at")?,
            by: key_id_field(m, "by").ok_or("by")?,
            sig: sig_field(m, "sig").ok_or("sig")?,
        })
    }

    pub fn verify(&self, by: &ViewerKey) -> bool {
        let i = invite_message(&self.device_id, &self.inv_id, self.issued_at, &self.by);
        by.verify(&i, &self.sig).is_ok()
    }
}

/// `grant` (spec §7), well formed (`grant_malformed` otherwise); `role` is kept as sent and
/// checked by the admission (`grant_role`).
#[derive(Debug, Clone)]
pub struct Grant {
    pub device_id: String,
    pub key_id: KeyId,
    pub telegram_user_id: i64,
    pub name: Option<String>,
    pub username: Option<String>,
    pub role: String,
    pub inv_id: Option<[u8; GROUND_ID_BYTES]>,
    pub grant_id: [u8; GROUND_ID_BYTES],
    /// The PC's grant token the owner signed (required: `""` or 22 characters).
    pub grant_token: GrantToken,
    pub issued_at: u64,
    pub by: KeyId,
    pub sig: [u8; SIGNATURE_LEN],
}

/// A string-or-null field that must be present.
fn nullable_str(m: &Map<String, Value>, name: &str) -> Result<Option<String>, ()> {
    match m.get(name) {
        Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => Ok(Some(s.clone())),
        _ => Err(()),
    }
}

impl Grant {
    pub fn parse(value: &Value) -> Result<Self, Why> {
        let Value::Object(m) = value else {
            return Err("not_object");
        };
        if !v1(m) {
            return Err("v");
        }
        let inv_id = match m.get("inv_id") {
            Some(Value::Null) => None,
            Some(Value::String(s)) => Some(b64url_array::<GROUND_ID_BYTES>(s).ok_or("inv_id")?),
            _ => return Err("inv_id"),
        };
        Ok(Self {
            device_id: str_field(m, "device_id").ok_or("device_id")?.to_string(),
            key_id: key_id_field(m, "key_id").ok_or("key_id")?,
            telegram_user_id: user_id(m.get("telegram_user_id")).ok_or("telegram_user_id")?,
            name: nullable_str(m, "name").map_err(|()| "name")?,
            username: nullable_str(m, "username").map_err(|()| "username")?,
            role: str_field(m, "role").ok_or("role")?.to_string(),
            inv_id,
            grant_id: ground_field(m, "grant_id").ok_or("grant_id")?,
            grant_token: str_field(m, "grant_token")
                .and_then(GrantToken::parse)
                .ok_or("grant_token")?,
            issued_at: millis(m.get("issued_at")).ok_or("issued_at")?,
            by: key_id_field(m, "by").ok_or("by")?,
            sig: sig_field(m, "sig").ok_or("sig")?,
        })
    }

    pub fn verify(&self, by: &ViewerKey) -> bool {
        let g = grant_message(&GrantFields {
            device_id: &self.device_id,
            key_id: &self.key_id,
            telegram_user_id: self.telegram_user_id,
            name: self.name.as_deref(),
            username: self.username.as_deref(),
            inv_id: self.inv_id.as_ref(),
            grant_id: &self.grant_id,
            grant_token: &self.grant_token,
            issued_at: self.issued_at,
            by: &self.by,
        });
        by.verify(&g, &self.sig).is_ok()
    }
}

/// A party statement's limits first ([`check_party_statement_wire`]: an object, its depth, at
/// most 2048 bytes as compact JSON), then its fields.
fn party_statement(value: &Value) -> Result<&Map<String, Value>, Why> {
    check_party_statement_wire(value).map_err(|e| match e {
        WireLimit::TooLarge => "size",
        WireLimit::TooDeep => "depth",
        _ => "not_object",
    })?;
    match value {
        Value::Object(m) if v1(m) => Ok(m),
        Value::Object(_) => Err("v"),
        _ => Err("not_object"),
    }
}

/// [`nullable_str`] of at most `max` Unicode code points (party spec §2.1).
fn bounded_name(m: &Map<String, Value>, name: &str, max: usize) -> Result<Option<String>, ()> {
    nullable_str(m, name)?.map_or(Ok(None), |s| {
        (s.chars().count() <= max).then_some(Some(s)).ok_or(())
    })
}

/// A party leader's grant to a member (party spec §2.3), well formed (`grant_malformed`
/// otherwise): the keys' `grant` V2 with `party_id` in the invitation's place and the leader's key
/// as `by`. `role` is kept as sent and checked by the admission (`grant_role`).
#[derive(Debug, Clone)]
pub struct PartyGrant {
    pub device_id: String,
    pub key_id: KeyId,
    pub telegram_user_id: i64,
    pub name: Option<String>,
    pub username: Option<String>,
    pub role: String,
    pub party_id: [u8; GROUND_ID_BYTES],
    pub grant_id: [u8; GROUND_ID_BYTES],
    pub grant_token: GrantToken,
    pub issued_at: u64,
    pub by: KeyId,
    pub sig: [u8; SIGNATURE_LEN],
}

impl PartyGrant {
    /// `why` (grant.json): `size`, `depth`, `not_object`, `v`, then the field that failed.
    pub fn parse(value: &Value) -> Result<Self, Why> {
        let m = party_statement(value)?;
        Ok(Self {
            device_id: str_field(m, "device_id").ok_or("device_id")?.to_string(),
            key_id: key_id_field(m, "key_id").ok_or("key_id")?,
            telegram_user_id: user_id(m.get("telegram_user_id")).ok_or("telegram_user_id")?,
            name: bounded_name(m, "name", PARTY_LEADER_NAME_MAX).map_err(|()| "name")?,
            username: bounded_name(m, "username", PARTY_LEADER_USERNAME_MAX)
                .map_err(|()| "username")?,
            role: str_field(m, "role").ok_or("role")?.to_string(),
            party_id: ground_field(m, "party_id").ok_or("party_id")?,
            grant_id: ground_field(m, "grant_id").ok_or("grant_id")?,
            grant_token: str_field(m, "grant_token")
                .and_then(GrantToken::parse)
                .ok_or("grant_token")?,
            issued_at: millis(m.get("issued_at")).ok_or("issued_at")?,
            by: key_id_field(m, "by").ok_or("by")?,
            sig: sig_field(m, "sig").ok_or("sig")?,
        })
    }

    /// The signature under the leader's key (the delegation's SPKI).
    pub fn verify(&self, leader: &ViewerKey) -> bool {
        leader.verify(&self.message(), &self.sig).is_ok()
    }

    /// `pg` as this PC rebuilds it from the grant.
    pub fn message(&self) -> Vec<u8> {
        party_grant_message(
            &GrantFields {
                device_id: &self.device_id,
                key_id: &self.key_id,
                telegram_user_id: self.telegram_user_id,
                name: self.name.as_deref(),
                username: self.username.as_deref(),
                inv_id: None,
                grant_id: &self.grant_id,
                grant_token: &self.grant_token,
                issued_at: self.issued_at,
                by: &self.by,
            },
            &self.party_id,
        )
    }
}

/// The leader as «ПК в пати» names him (party spec §2.1): the SPKI checked canonical, its
/// `key_id` derived here.
#[derive(Debug, Clone)]
pub struct PartyLeaderRef {
    pub telegram_user_id: i64,
    pub name: Option<String>,
    pub username: Option<String>,
    pub key: ViewerKey,
}

/// «ПК в пати» (party spec §2.2), well formed (`party_ack` `malformed` otherwise).
#[derive(Debug, Clone)]
pub struct PartyJoin {
    pub device_id: String,
    pub party_id: [u8; GROUND_ID_BYTES],
    pub party: String,
    pub leader: PartyLeaderRef,
    pub grant_token: GrantToken,
    pub issued_at: u64,
    pub by: KeyId,
    pub sig: [u8; SIGNATURE_LEN],
}

impl PartyJoin {
    /// `why` (join.json): `size`, `depth`, `not_object`, `v`, then the field that failed
    /// (`leader_spki` for a SPKI that is not canonical).
    pub fn parse(value: &Value) -> Result<Self, Why> {
        let m = party_statement(value)?;
        let device_id = str_field(m, "device_id").ok_or("device_id")?.to_string();
        let party_id = ground_field(m, "party_id").ok_or("party_id")?;
        let party = str_field(m, "party")
            .filter(|p| is_party_name(p))
            .ok_or("party")?
            .to_string();
        let l = m.get("leader").and_then(Value::as_object).ok_or("leader")?;
        let leader = PartyLeaderRef {
            telegram_user_id: user_id(l.get("telegram_user_id"))
                .ok_or("leader.telegram_user_id")?,
            name: bounded_name(l, "name", PARTY_LEADER_NAME_MAX).map_err(|()| "leader.name")?,
            username: bounded_name(l, "username", PARTY_LEADER_USERNAME_MAX)
                .map_err(|()| "leader.username")?,
            key: str_field(l, "spki")
                .and_then(|s| b64url_exact(s, SPKI_LEN))
                .and_then(|b| ViewerKey::from_spki(&b).ok())
                .ok_or("leader_spki")?,
        };
        Ok(Self {
            device_id,
            party_id,
            party,
            leader,
            grant_token: str_field(m, "grant_token")
                .and_then(GrantToken::parse)
                .ok_or("grant_token")?,
            issued_at: millis(m.get("issued_at")).ok_or("issued_at")?,
            by: key_id_field(m, "by").ok_or("by")?,
            sig: sig_field(m, "sig").ok_or("sig")?,
        })
    }

    /// `j` as this PC rebuilds it from the statement.
    pub fn message(&self) -> Vec<u8> {
        party_join_message(&PartyJoinFields {
            device_id: &self.device_id,
            party_id: &self.party_id,
            party: &self.party,
            leader_telegram_user_id: self.leader.telegram_user_id,
            leader_name: self.leader.name.as_deref(),
            leader_username: self.leader.username.as_deref(),
            leader_key_id: self.leader.key.key_id(),
            grant_token: &self.grant_token,
            issued_at: self.issued_at,
            by: &self.by,
        })
    }

    /// The signature under the owner's key `by`.
    pub fn verify(&self, by: &ViewerKey) -> bool {
        by.verify(&self.message(), &self.sig).is_ok()
    }
}

/// A recovery ground (spec §8.3), well formed (`recover_malformed` otherwise).
#[derive(Debug, Clone)]
pub struct RecoverGround {
    pub init_data: String,
    pub rsig: [u8; SIGNATURE_LEN],
}

impl RecoverGround {
    pub fn parse(m: &Map<String, Value>) -> Result<Self, Why> {
        let init_data = m
            .get("attest")
            .and_then(Value::as_object)
            .and_then(|a| str_field(a, "init_data"))
            .ok_or("attest")?
            .to_string();
        Ok(Self {
            init_data,
            rsig: sig_field(m, "rsig").ok_or("rsig")?,
        })
    }
}

/// `first_use` (spec §9): its signature is checked first, and a ground that does not decode is
/// `first_use_bad_sig` too.
pub fn verify_first_use(
    m: &Map<String, Value>,
    device_id: &str,
    key: &ViewerKey,
) -> Result<i64, Why> {
    let uid = user_id(m.get("uid")).ok_or("uid")?;
    let sig = sig_field(m, "sig").ok_or("sig")?;
    let f = first_use_message(device_id, key.key_id(), uid);
    key.verify(&f, &sig).map_err(|_| "signature")?;
    Ok(uid)
}

/// A ground id as the store keeps it.
pub fn ground_id(bytes: &[u8; GROUND_ID_BYTES]) -> GroundId {
    use base64::Engine as _;
    let text = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
    #[allow(
        clippy::expect_used,
        reason = "16 bytes always encode to a valid ground id"
    )]
    GroundId::parse(&text).expect("16 bytes encode to 22 base64url characters")
}
