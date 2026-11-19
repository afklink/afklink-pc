//! «Пати» on the wire, the part the PC speaks: the agent's side of the contract's `party.ts` (limits,
//! closed lists) and `party-wire.ts` (the shapes of the agent's socket). Spec:
//! `docs/design/party-protocol.md` in the umbrella.
//!
//! A party's leader hands out guest grants on the owner's behalf. The PC hears two signed statements:
//! «ПК в пати» (`party_join`, signed by the PC owner's device key), which names the leader the PC takes
//! grants from, and the leader's grant to a member (`party` in `proof.admit`, beside the keys' `grant`).
//! It answers a join or a leave with `party_ack` and tells the server the whole of what it holds with
//! `party_state`.
//!
//! What is here is form only, as in [`crate::viewer_keys`]: the messages are in [`crate::agent_ws`],
//! the admit's word is [`crate::viewer_keys::KeyAdmit::Party`], the binding's is
//! [`crate::invites::BindingVia::Party`]. The statements arrive opaque (`serde_json::Value`) and are
//! held to their size here ([`check_party_statement_wire`]) before anything parses their fields; the
//! fields, the bytes they sign, the signatures and every decision belong to `afklink_core`.
//!
//! Held to the contract by `tests/viewer_keys.rs` (constants, lists, the schema's enums, every party
//! fixture against these checks) and by the golden fixtures (`tests/fixtures.rs`).

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::metrics::InvalidField;
use crate::viewer_keys::{bytes, check_opaque, is_b64url, WireLimit};

/* --- limits (§2.1, §3.1) -------------------------------------------------------------------------- */

/// `party_id`: 16 random bytes from the leader client's CSPRNG, 22 characters of strict base64url.
pub const PARTY_ID_BYTES: usize = 16;
/// A party's name at most, in Unicode code points ([`is_party_name`]).
pub const PARTY_NAME_MAX: usize = 64;
/// `leader.name` and a party grant's `name` at most, in Unicode code points.
pub const PARTY_LEADER_NAME_MAX: usize = 128;
/// `leader.username` and a party grant's `username` at most, in Unicode code points.
pub const PARTY_LEADER_USERNAME_MAX: usize = 64;
/// A join or a party grant at most, as compact JSON in UTF-8 (the contract's `GRANT_MAX_BYTES`).
pub const PARTY_STATEMENT_MAX_BYTES: usize = 2_048;
/// `join.v` and the party grant's `v`.
pub const PARTY_STATEMENT_VERSION: u32 = 1;
/// Delegations one PC keeps at most: the key list's bound, and `party_state.parties` at most. Past it
/// a join of a new party is `limit`.
pub const PARTY_DELEGATIONS_MAX: usize = 256;

/* --- closed lists (§4.1, §9) --------------------------------------------------------------------- */

/// `party_ack.op`: which statement the PC answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PartyAckOp {
    Join,
    Leave,
}

impl PartyAckOp {
    /// Every op, in the contract's order (`PARTY_ACK_OPS`).
    pub const ALL: [Self; 2] = [Self::Join, Self::Leave];

    /// The wire word.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Join => "join",
            Self::Leave => "leave",
        }
    }
}

/// `party_ack.result` (§4.2, `PARTY_ACK_RESULTS`): the first check that failed, or `ok`. A leave has
/// no signature: it answers `ok`, `malformed`, `busy` or `damaged`. The server stops repeating on any
/// answer but `busy` and `damaged`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PartyAckResult {
    /// A join: the delegation was written or replaced. A leave: the party left, or was never there.
    Ok,
    /// The form (§2), the size, a non-canonical `leader.spki`.
    Malformed,
    /// `device_id` is not this PC's.
    Device,
    /// `by` is not an active owner key of this PC (in strict mode: or it is unconfirmed).
    Signer,
    /// The signature under `by`'s SPKI did not check.
    BadSig,
    /// `grant_token` is not the PC's current one.
    Stale,
    /// A new party past [`PARTY_DELEGATIONS_MAX`].
    Limit,
    /// The PC's signature bucket was empty; the server repeats.
    Busy,
    /// The PC's key list cannot be read; the server repeats.
    Damaged,
}

impl PartyAckResult {
    /// Every result, in the contract's order.
    pub const ALL: [Self; 9] = [
        Self::Ok,
        Self::Malformed,
        Self::Device,
        Self::Signer,
        Self::BadSig,
        Self::Stale,
        Self::Limit,
        Self::Busy,
        Self::Damaged,
    ];

    /// The wire word.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Malformed => "malformed",
            Self::Device => "device",
            Self::Signer => "signer",
            Self::BadSig => "bad_sig",
            Self::Stale => "stale",
            Self::Limit => "limit",
            Self::Busy => "busy",
            Self::Damaged => "damaged",
        }
    }
}

/* --- `party_state` (§4.1) ------------------------------------------------------------------------ */

/// One delegation as the PC reports it in `party_state`: the party and its leader's `key_id`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PartyDelegation {
    /// 22 characters of strict base64url ([`PARTY_ID_BYTES`]).
    pub party_id: String,
    /// The leader's `key_id`: 43 characters of strict base64url.
    pub leader: String,
}

/// `party_state.parties` as the contract takes it (`partyDelegationsSchema`): at most
/// [`PARTY_DELEGATIONS_MAX`], each `party_id` and `leader` of its form. The server refuses a
/// `party_state` that fails (`bad_message`); the agent's delegations hold to it by their checks
/// when a join is parsed and when the key list is read. The first field that fails is named.
pub fn check_party_state(parties: &[PartyDelegation]) -> Result<(), InvalidField> {
    if parties.len() > PARTY_DELEGATIONS_MAX {
        return Err(InvalidField {
            field: "party_state.parties",
        });
    }
    for d in parties {
        if !is_party_id(&d.party_id) {
            return Err(InvalidField {
                field: "party_state.parties.party_id",
            });
        }
        if !is_b64url(&d.leader, bytes::KEY_ID) {
            return Err(InvalidField {
                field: "party_state.parties.leader",
            });
        }
    }
    Ok(())
}

/* --- form ---------------------------------------------------------------------------------------- */

/// A `party_id`'s form: strict base64url of [`PARTY_ID_BYTES`].
pub fn is_party_id(s: &str) -> bool {
    is_b64url(s, PARTY_ID_BYTES)
}

/// A party's name (§2.1, `isPartyName`): 1 to [`PARTY_NAME_MAX`] code points and no control character
/// (Unicode `Cc`). A Rust string is always well-formed, which the contract checks separately.
pub fn is_party_name(name: &str) -> bool {
    (1..=PARTY_NAME_MAX).contains(&name.chars().count()) && !name.chars().any(char::is_control)
}

/// A party statement within its limits (`partyJoinWireSchema`, `partyGrantWireSchema`): an object,
/// at most [`crate::viewer_keys::PROOF_MAX_DEPTH`] deep and [`PARTY_STATEMENT_MAX_BYTES`] as compact
/// JSON. Nothing else is looked at. A failure is a join's `party_ack` `malformed`, a party grant's
/// `admit_refused:grant_malformed` — the caller's decision, before any parsing or cryptography.
pub fn check_party_statement_wire(statement: &Value) -> Result<(), WireLimit> {
    check_opaque(statement, PARTY_STATEMENT_MAX_BYTES)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const PARTY: &str = "Rk9vZEJ1ZGR5UGFydHkxMg";
    const KEY: &str = "_w5-l8TmVUMzpALq6Y78jIWOvDaXdhE4IjPJU3Tk3RI";

    #[test]
    fn the_lists_are_written_as_the_contract_spells_them() {
        for op in PartyAckOp::ALL {
            assert_eq!(
                serde_json::to_value(op).expect("serializes"),
                json!(op.as_str())
            );
        }
        for r in PartyAckResult::ALL {
            let word = serde_json::to_value(r).expect("serializes");
            assert_eq!(word, json!(r.as_str()));
            assert_eq!(
                serde_json::from_value::<PartyAckResult>(word).expect("reads"),
                r
            );
        }
        assert!(serde_json::from_value::<PartyAckResult>(json!("unconfirmed")).is_err());
        assert!(serde_json::from_value::<PartyAckOp>(json!("lead")).is_err());
    }

    #[test]
    fn a_party_state_is_checked_before_it_goes() {
        let one = PartyDelegation {
            party_id: PARTY.into(),
            leader: KEY.into(),
        };
        assert_eq!(check_party_state(&[]), Ok(()));
        assert_eq!(check_party_state(std::slice::from_ref(&one)), Ok(()));
        assert_eq!(
            check_party_state(&vec![one.clone(); PARTY_DELEGATIONS_MAX]),
            Ok(())
        );
        assert_eq!(
            check_party_state(&vec![one.clone(); PARTY_DELEGATIONS_MAX + 1]),
            Err(InvalidField {
                field: "party_state.parties"
            })
        );
        let bad_party = PartyDelegation {
            party_id: KEY.into(),
            ..one.clone()
        };
        assert_eq!(
            check_party_state(&[bad_party]),
            Err(InvalidField {
                field: "party_state.parties.party_id"
            })
        );
        let bad_leader = PartyDelegation {
            leader: PARTY.into(),
            ..one
        };
        assert_eq!(
            check_party_state(&[bad_leader]),
            Err(InvalidField {
                field: "party_state.parties.leader"
            })
        );
    }

    #[test]
    fn a_party_name_is_one_to_sixty_four_characters_without_controls() {
        assert!(is_party_name("Орлы"));
        assert!(is_party_name(&"ж".repeat(PARTY_NAME_MAX)));
        assert!(is_party_name("🦅 ночь"));
        assert!(!is_party_name(""));
        assert!(!is_party_name(&"ж".repeat(PARTY_NAME_MAX + 1)));
        for control in ["\u{0}", "\n", "\u{1f}", "\u{7f}", "\u{85}", "\u{9f}"] {
            assert!(!is_party_name(&format!("Орлы{control}")), "{control:?}");
        }
        // Format characters are not controls (`Cc`): the contract takes them too.
        assert!(is_party_name("Ор\u{200d}лы"));
    }

    #[test]
    fn a_statement_is_an_object_within_two_kilobytes() {
        // `{"p":"…"}`: 8 bytes around the string.
        let pad = |len: usize| json!({ "p": "a".repeat(len - 8) });
        assert_eq!(
            check_party_statement_wire(&pad(PARTY_STATEMENT_MAX_BYTES)),
            Ok(())
        );
        assert_eq!(
            check_party_statement_wire(&pad(PARTY_STATEMENT_MAX_BYTES + 1)),
            Err(WireLimit::TooLarge)
        );
        assert_eq!(
            check_party_statement_wire(&json!([])),
            Err(WireLimit::NotObject)
        );
        // Eight arrays under the object: depth 9, one past PROOF_MAX_DEPTH (the object is level 1).
        let mut deep = json!(1);
        for _ in 0..8 {
            deep = json!([deep]);
        }
        assert_eq!(
            check_party_statement_wire(&json!({ "x": deep })),
            Err(WireLimit::TooDeep)
        );
    }
}
