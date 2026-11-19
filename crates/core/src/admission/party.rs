//! «Пати» at the PC (party spec §4, §5): the one function for a join or a leave outside a
//! session, and the `party` ground of a first offer. The decisions only; the delegations are the
//! list's notes ([`TrustStore::put_delegation`], [`TrustStore::leave_party_now`]) and a decision's
//! write is a write of memory ([`Trusted::party_write`]), its answer sent once that write landed.
//!
//! # Threads
//!
//! On the orchestrator's main loop, synchronously, with no lock and no wait: one parse of a
//! statement of at most 2 KB, one ECDSA verify behind the shared signature bucket, memory changes.
//! The file is written on the blocking pool by the trusted list's queue.

use afklink_protocol::party::is_party_id;
use afklink_protocol::{PartyAckOp, PartyAckResult};

use super::*;
use crate::trusted::PartyAck;
use crate::viewer_keys::proof::{PartyGrant, PartyJoin};
use crate::viewer_keys::{Delegation, GroundId};

/// What the orchestrator does with a join or a leave ([`Admission::party_join`],
/// [`Admission::party_leave`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PartyAnswer {
    /// No readable `party_id`, so no answer can name it: nothing is sent (`warn`).
    Unaddressed,
    /// Refused: send this answer now.
    Now(PartyAck),
    /// Decided in memory: the answer goes once the write that holds it landed
    /// ([`Trusted::take_party_acks`]).
    Queued,
}

/// A statement's `party_id` as an answer can echo it (strict base64url of 16 bytes), or `None`.
fn party_id_of(text: Option<&str>, op: PartyAckOp) -> Option<(String, GroundId)> {
    let found = text
        .filter(|t| is_party_id(t))
        .and_then(|t| GroundId::parse(t).map(|id| (t.to_string(), id)));
    if found.is_none() {
        tracing::warn!(
            op = op.as_str(),
            present = text.is_some(),
            "party: a statement without a readable party_id (the server's schema forbids it); \
             nothing to answer"
        );
    }
    found
}

fn answer(party_id: &str, op: PartyAckOp, result: PartyAckResult) -> PartyAck {
    PartyAck {
        party_id: party_id.to_string(),
        op,
        result,
    }
}

impl Admission {
    /// «ПК в пати» (party spec §4.2): the nine steps in order, the first failure the answer —
    /// 1 `damaged`, 2 `malformed`, 3 `device`, 4 `busy` (the signature bucket shared with the
    /// offers), 5 `signer` (an active owner-role key; in strict mode a confirmed one), 6
    /// `bad_sig`, 7 `stale` (the current grant token, byte for byte), 8 `limit`, 9 the delegation
    /// written or replaced in memory (`ok` once its write landed). `now_ms`: the bucket's clock.
    pub fn party_join(&mut self, trusted: &mut Trusted, join: &Value, now_ms: u64) -> PartyAnswer {
        let op = PartyAckOp::Join;
        let Some((id_text, party_id)) =
            party_id_of(join.get("party_id").and_then(Value::as_str), op)
        else {
            return PartyAnswer::Unaddressed;
        };
        let refuse = |result: PartyAckResult, step: u8, why: &str| {
            tracing::debug!(
                party = %id_text,
                step,
                why,
                result = result.as_str(),
                "party: join refused"
            );
            PartyAnswer::Now(answer(&id_text, op, result))
        };
        let Some(store) = trusted.store().filter(|s| !s.is_damaged()) else {
            return refuse(PartyAckResult::Damaged, 1, "the key list cannot be read");
        };
        let j = match PartyJoin::parse(join) {
            Ok(j) => j,
            Err(why) => return refuse(PartyAckResult::Malformed, 2, why),
        };
        if j.device_id != self.device_id {
            return refuse(PartyAckResult::Device, 3, "another PC's device_id");
        }
        if !self.take_bucket(now_ms) {
            return refuse(PartyAckResult::Busy, 4, "the signature bucket is empty");
        }
        let strict = store.switches().is_ok_and(|s| s.trusted_devices_mode);
        let signer = match store.lookup(&j.by) {
            Lookup::Active(r) if r.role == BindingRole::Owner && !(strict && r.unconfirmed) => {
                r.key.clone()
            }
            Lookup::Active(r) if r.role == BindingRole::Owner => {
                return refuse(
                    PartyAckResult::Signer,
                    5,
                    "an unconfirmed owner key, strict mode",
                );
            }
            _ => {
                return refuse(PartyAckResult::Signer, 5, "not an active owner key here");
            }
        };
        if !j.verify(&signer) {
            return refuse(PartyAckResult::BadSig, 6, "the signature does not check");
        }
        if store.grant_token_current(&j.grant_token).is_err() {
            return refuse(PartyAckResult::Stale, 7, "signed over another grant token");
        }
        let delegation = Delegation {
            party_id,
            party: j.party,
            leader: Person {
                telegram_user_id: j.leader.telegram_user_id,
                first_name: j.leader.name,
                username: j.leader.username,
            },
            leader_key: j.leader.key,
            by: j.by,
            at: crate::journal::now_ms(),
        };
        let Some(store) = trusted.store_for_notes() else {
            return refuse(PartyAckResult::Damaged, 9, "no key list");
        };
        match store.put_delegation(delegation) {
            Ok(joined) => {
                tracing::info!(
                    party = %id_text,
                    joined = joined.as_str(),
                    strict,
                    "party: join taken in memory; its answer goes once its write lands"
                );
                trusted.party_write(Some(answer(&id_text, op, PartyAckResult::Ok)), Vec::new());
                PartyAnswer::Queued
            }
            Err(StoreError::PartyLimit) => {
                refuse(PartyAckResult::Limit, 8, "a new party past the limit")
            }
            Err(e) => refuse(PartyAckResult::Damaged, 9, e.as_str()),
        }
    }

    /// `party_leave` (party spec §4.2): steps 1 (`damaged`), 2 (the id is all of its form) and 4
    /// (`busy`); then the PC leaves the party in memory ([`TrustStore::leave_party_now`]) — not
    /// in it: nothing changes — and `ok` goes once the write of memory landed. The leave's keys
    /// are denied at once; their sessions end at the orchestrator's sweep (`key_revoked`).
    pub fn party_leave(
        &mut self,
        trusted: &mut Trusted,
        party_id: &str,
        now_ms: u64,
    ) -> PartyAnswer {
        let op = PartyAckOp::Leave;
        let Some((id_text, id)) = party_id_of(Some(party_id), op) else {
            return PartyAnswer::Unaddressed;
        };
        let refuse = |result: PartyAckResult, step: u8, why: &str| {
            tracing::debug!(party = %id_text, step, why, result = result.as_str(), "party: leave refused");
            PartyAnswer::Now(answer(&id_text, op, result))
        };
        if trusted.store().is_none_or(TrustStore::is_damaged) {
            return refuse(PartyAckResult::Damaged, 1, "the key list cannot be read");
        }
        if !self.take_bucket(now_ms) {
            return refuse(PartyAckResult::Busy, 4, "the signature bucket is empty");
        }
        let Some(store) = trusted.store_for_notes() else {
            return refuse(PartyAckResult::Damaged, 1, "no key list");
        };
        let why = "party_leave from the server";
        match store.leave_party_now(
            &id,
            crate::viewer_keys::PartyLeaveBy::Server,
            why,
            crate::journal::now_ms(),
        ) {
            Ok(left) => {
                let denied = left.unwrap_or_default();
                trusted.party_write(Some(answer(&id_text, op, PartyAckResult::Ok)), denied);
                PartyAnswer::Queued
            }
            Err(e) => refuse(PartyAckResult::Damaged, 1, e.as_str()),
        }
    }

    /// The `party` ground (party spec §5.1), in the order of grant.json: as `grant`, but the
    /// signer must be the leader of this PC's delegation of the party (its SPKI checks the
    /// signature; `party_leader` otherwise) and there is no invitation. The list's rules then,
    /// and again at the write. A list that is full for this key (`limit`, process §7) is told to
    /// the person at the PC ([`JournalEvent::PartyDeviceLimit`], at most once an hour per person).
    pub(super) fn party(
        &mut self,
        ctx: &GroundCtx<'_>,
        new: &NewKey,
        grant: &Value,
        journal: &mut Vec<JournalEvent>,
    ) -> Result<Candidate, Fail> {
        let refused = |d| Fail::Verdict(Verdict::admit_refused(d));
        let g = PartyGrant::parse(grant).map_err(|why| {
            tracing::debug!(why, "admission: party grant malformed");
            refused("grant_malformed")
        })?;
        if g.device_id != self.device_id {
            return Err(refused("grant_device"));
        }
        if g.key_id != ctx.proof.key_id {
            return Err(refused("grant_key_mismatch"));
        }
        let party_id = ground_id(&g.party_id);
        let delegation = ctx.store.delegation(&party_id);
        let Some((d, _)) = delegation.filter(|(d, _)| *d.leader_key.key_id() == g.by) else {
            tracing::debug!(
                party = %party_id,
                by = %g.by.short(),
                delegation = delegation.is_some(),
                "admission: no delegation of the party names this signer its leader: party_leader"
            );
            return Err(refused("party_leader"));
        };
        if g.role != "guest" {
            tracing::debug!(
                role_len = g.role.len(),
                "admission: the party grant names a role other than guest: grant_role"
            );
            return Err(refused("grant_role"));
        }
        let grant_id = ground_id(&g.grant_id);
        if ctx
            .store
            .spent()
            .is_ok_and(|(_, grants, _)| grants.contains(&grant_id))
        {
            return Err(refused("grant_spent"));
        }
        let grantee_owner = ctx
            .store
            .person_keys(g.telegram_user_id)
            .is_ok_and(|k| !k.listed_owner.is_empty())
            || ctx.trusted.owner_on_pc(g.telegram_user_id);
        if grantee_owner {
            tracing::debug!(
                user_id = g.telegram_user_id,
                "admission: the party grant's person is an owner on this PC: grant_role \
                 ({OWNER_ON_PC})"
            );
            return Err(Fail::Why(Verdict::admit_refused("grant_role"), OWNER_ON_PC));
        }
        if !g.verify(&d.leader_key) {
            return Err(refused("grant_bad_sig"));
        }
        if ctx.store.grant_token_current(&g.grant_token).is_err() {
            tracing::debug!(
                kid = %ctx.proof.key_id.short(),
                by = %g.by.short(),
                "admission: the party grant carries another grant token than the PC's: grant_stale"
            );
            return Err(refused("grant_stale"));
        }
        let ground = Ground::Party {
            party_id: party_id.clone(),
            by: g.by.clone(),
            grant_id,
            person: Person {
                telegram_user_id: g.telegram_user_id,
                first_name: g.name.clone(),
                username: g.username.clone(),
            },
            token: g.grant_token,
        };
        let out = match ctx.store.check_add(new, &ground, 0) {
            Ok(out) => out,
            Err(e) => {
                tracing::debug!(
                    user_id = g.telegram_user_id,
                    reason = e.as_str(),
                    error = %e,
                    "admission: the list refuses the party grant's key"
                );
                if matches!(e, StoreError::Full(_)) {
                    self.note_party_limit(g.telegram_user_id, party_id, ctx.now_ms, journal);
                }
                return Err(store_fail(&e, "party"));
            }
        };
        tracing::debug!(
            user_id = out.telegram_user_id,
            known_guest = out.known_person,
            unconfirmed = out.unconfirmed,
            lifted = out.lifted.unwrap_or("-"),
            "admission: the party grant gives a candidate ({})",
            if out.known_person {
                "a new device of a guest this PC has"
            } else {
                "a new guest"
            }
        );
        Ok(Candidate {
            op: StoreOp::add(new.clone(), ground),
            ground: "party",
            uid: out.telegram_user_id,
            role: out.role,
            unconfirmed: out.unconfirmed,
            by: Some(g.by),
        })
    }
}

impl Admission {
    /// A member's device the full list refused (process §7): told at most once an hour per person
    /// ([`PARTY_LIMIT_MS`]), so a device that keeps trying does not repeat the toast.
    fn note_party_limit(
        &mut self,
        telegram_user_id: i64,
        party_id: GroundId,
        now_ms: u64,
        journal: &mut Vec<JournalEvent>,
    ) {
        let due = self
            .party_limit_told
            .get(&telegram_user_id)
            .is_none_or(|at| now_ms.saturating_sub(*at) >= PARTY_LIMIT_MS);
        tracing::debug!(
            user_id = telegram_user_id,
            party = %party_id,
            told = due,
            "admission: a party member's device past the list's limit: {}",
            if due { "told" } else { "told within the hour already" }
        );
        if due {
            self.party_limit_told.insert(telegram_user_id, now_ms);
            journal.push(JournalEvent::PartyDeviceLimit {
                telegram_user_id,
                party_id,
            });
        }
    }
}

#[cfg(test)]
#[path = "party_tests.rs"]
mod tests;
