//! Owner and guest roles: the vocabularies `owner_request`, `owner_request_state`, `owner_changed`
//! and the role fields carry. Mirrors
//! `packages/protocol/src/roles.ts`; the shapes that carry them are in [`crate::agent_ws`] and
//! [`crate::common`], held to the contract's fixtures by `tests/fixtures.rs`.
//!
//! Every set is closed, as the contract's `z.enum`s are: a third role would change what the PC lets
//! through, and a state or reason this build does not know is a message it cannot act on rightly —
//! better unparsed (and logged) than taken for another.
//!
//! The model in four lines, as the contract says it:
//!
//!   - every binding (a PC and a Telegram account) is `owner` or `guest`; a PC has one owner or none;
//!   - the server keeps the roles; the PC only asks, and the server applies or asks the owner;
//!   - what the PC asks about the owner (make a guest the owner, unbind the owner) waits for the
//!     current owner's answer in Telegram;
//!   - pairing on a PC with no owner asks «Кто это?» on the PC; on a PC with an owner every new
//!     person is a guest; while someone other than the owner has a session on that PC, the PC's
//!     «Разрешить» waits for the owner too ([`OwnerStateKind::PcAllow`]).

use serde::{Deserialize, Serialize};

/// A binding's role. At most one [`BindingRole::Owner`] per PC; the server's database holds it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BindingRole {
    Owner,
    Guest,
}

impl BindingRole {
    /// The wire spelling, for log lines.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Owner => "owner",
            Self::Guest => "guest",
        }
    }
}

/// What the PC asks the owner to confirm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OwnerRequestKind {
    /// The guest named becomes the owner, and the owner a guest (a transfer).
    MakeOwner,
    /// The owner's binding is removed.
    UnbindOwner,
}

impl OwnerRequestKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MakeOwner => "make_owner",
            Self::UnbindOwner => "unbind_owner",
        }
    }
}

/// What a request from the PC can be as `owner_request_state` names it (`OWNER_STATE_KINDS`): the
/// PC's own two ([`OwnerRequestKind`]), and [`OwnerStateKind::PcAllow`], which the server opens and
/// the PC never asks — `owner_request` keeps [`OwnerRequestKind`], so this build cannot send it.
///
/// An agent older than `pc_allow` (0.6.0) read the state's kind as an [`OwnerRequestKind`] and
/// drops the whole message over it: its prompt closed on the press, and `binding_added` or
/// `pair_cancelled` tell it how the pairing ended, as before.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OwnerStateKind {
    /// The PC's `make_owner`.
    MakeOwner,
    /// The PC's `unbind_owner`.
    UnbindOwner,
    /// «Разрешить» in the PC's pairing prompt, on a PC that has an owner, while someone other than
    /// that owner had a session there (connecting, live, or ended moments before the press): the
    /// server binds nobody yet, holds the pairing and asks the owner in Telegram; his «Разрешить»
    /// binds the newcomer as a guest. The request's id is the pairing's, the person named is the
    /// newcomer (not in the PC's list yet: the state names them), the deadline
    /// [`OWNER_REQUEST_TTL_MS`] from the press.
    PcAllow,
}

impl OwnerStateKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MakeOwner => "make_owner",
            Self::UnbindOwner => "unbind_owner",
            Self::PcAllow => "pc_allow",
        }
    }

    /// The kind as the PC asks it, for the two it can ask; `None` for `pc_allow`.
    pub const fn request_kind(self) -> Option<OwnerRequestKind> {
        match self {
            Self::MakeOwner => Some(OwnerRequestKind::MakeOwner),
            Self::UnbindOwner => Some(OwnerRequestKind::UnbindOwner),
            Self::PcAllow => None,
        }
    }
}

impl From<OwnerRequestKind> for OwnerStateKind {
    fn from(kind: OwnerRequestKind) -> Self {
        match kind {
            OwnerRequestKind::MakeOwner => Self::MakeOwner,
            OwnerRequestKind::UnbindOwner => Self::UnbindOwner,
        }
    }
}

/// Where a request from the PC stands, as `owner_request_state` says it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OwnerRequestState {
    /// Waiting for the owner, until `expires_at`.
    Pending,
    /// The owner confirmed and the change is applied (`pc_allow`: the newcomer is bound as a guest,
    /// and `binding_added` comes for them).
    Confirmed,
    /// Done without asking: the PC had no owner to ask (`make_owner` only).
    Applied,
    /// The owner declined; nothing changed.
    Declined,
    /// Nobody answered within [`OWNER_REQUEST_TTL_MS`]; nothing changed.
    Expired,
    /// Withdrawn before an answer — `reason` says why; nothing changed.
    Cancelled,
    /// Not opened at all — `reason` says why; there is no request.
    Refused,
}

impl OwnerRequestState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Confirmed => "confirmed",
            Self::Applied => "applied",
            Self::Declined => "declined",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
            Self::Refused => "refused",
        }
    }
}

/// Why a request was refused or cancelled (`owner_request_state.reason`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OwnerRequestReason {
    /// Refused: the person named has no binding on this PC.
    NotBound,
    /// Refused: `make_owner` named the owner.
    AlreadyOwner,
    /// Refused: `unbind_owner` named a guest (the PC unbinds a guest with `unbind`).
    NotOwner,
    /// Refused: another request is pending on this PC (at most one); the server sends that one's
    /// `pending` again right after.
    Busy,
    /// Refused: too many requests from this PC lately.
    RateLimited,
    /// Refused: the server could not open it (its database); try again.
    Failed,
    /// Cancelled: the PC withdrew it (`owner_request_cancel`).
    ByPc,
    /// Cancelled: the guest `make_owner` named is no longer bound.
    TargetLeft,
    /// Cancelled: the owner is no longer the owner (unbound themselves).
    OwnerLeft,
    /// Cancelled: the newcomer withdrew their pairing while the owner was asked (`pair_cancel`:
    /// «Отмена» or Back on the pairing screen). [`OwnerStateKind::PcAllow`] only — an agent older
    /// than the reason would drop a state of a kind it knows over it.
    ByRequester,
}

impl OwnerRequestReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotBound => "not_bound",
            Self::AlreadyOwner => "already_owner",
            Self::NotOwner => "not_owner",
            Self::Busy => "busy",
            Self::RateLimited => "rate_limited",
            Self::Failed => "failed",
            Self::ByPc => "by_pc",
            Self::TargetLeft => "target_left",
            Self::OwnerLeft => "owner_left",
            Self::ByRequester => "by_requester",
        }
    }
}

/// How long the owner has to answer a request from the PC. Mirrors `OWNER_REQUEST_TTL_MS`.
pub const OWNER_REQUEST_TTL_MS: u64 = 10 * 60_000;

#[cfg(test)]
mod tests {
    use super::*;

    /// `as_str` is what the log calls a value; serde's spelling is what the wire calls it.
    #[test]
    fn the_log_spelling_is_the_wire_spelling() {
        fn wire<T: Serialize>(v: T) -> String {
            serde_json::to_value(v)
                .expect("serialises")
                .as_str()
                .expect("a string")
                .to_string()
        }
        for r in [BindingRole::Owner, BindingRole::Guest] {
            assert_eq!(wire(r), r.as_str());
        }
        for k in [OwnerRequestKind::MakeOwner, OwnerRequestKind::UnbindOwner] {
            assert_eq!(wire(k), k.as_str());
            // The same word for the same kind in the state.
            assert_eq!(wire(OwnerStateKind::from(k)), k.as_str());
            assert_eq!(OwnerStateKind::from(k).request_kind(), Some(k));
        }
        for k in [
            OwnerStateKind::MakeOwner,
            OwnerStateKind::UnbindOwner,
            OwnerStateKind::PcAllow,
        ] {
            assert_eq!(wire(k), k.as_str());
        }
        assert_eq!(OwnerStateKind::PcAllow.request_kind(), None);
        for s in [
            OwnerRequestState::Pending,
            OwnerRequestState::Confirmed,
            OwnerRequestState::Applied,
            OwnerRequestState::Declined,
            OwnerRequestState::Expired,
            OwnerRequestState::Cancelled,
            OwnerRequestState::Refused,
        ] {
            assert_eq!(wire(s), s.as_str());
        }
        for r in [
            OwnerRequestReason::NotBound,
            OwnerRequestReason::AlreadyOwner,
            OwnerRequestReason::NotOwner,
            OwnerRequestReason::Busy,
            OwnerRequestReason::RateLimited,
            OwnerRequestReason::Failed,
            OwnerRequestReason::ByPc,
            OwnerRequestReason::TargetLeft,
            OwnerRequestReason::OwnerLeft,
            OwnerRequestReason::ByRequester,
        ] {
            assert_eq!(wire(r), r.as_str());
        }
    }

    /// Closed sets, as the contract's: a role this build does not know is not read as another.
    #[test]
    fn the_sets_are_closed() {
        assert!(serde_json::from_str::<BindingRole>(r#""admin""#).is_err());
        assert!(serde_json::from_str::<OwnerRequestKind>(r#""make_admin""#).is_err());
        assert!(serde_json::from_str::<OwnerStateKind>(r#""make_admin""#).is_err());
        assert!(serde_json::from_str::<OwnerRequestState>(r#""lost""#).is_err());
        assert!(serde_json::from_str::<OwnerRequestReason>(r#""because""#).is_err());
    }

    /// `pc_allow` is a state's kind, never a request's: the PC cannot ask it, and an agent that reads
    /// the state's kind as a request's (as 0.6.0 does) refuses the word, so it drops the message
    /// rather than take it for `make_owner`.
    #[test]
    fn pc_allow_is_a_states_kind_only() {
        assert!(serde_json::from_str::<OwnerRequestKind>(r#""pc_allow""#).is_err());
        assert_eq!(
            serde_json::from_str::<OwnerStateKind>(r#""pc_allow""#).expect("parses"),
            OwnerStateKind::PcAllow
        );
    }

    #[test]
    fn the_request_lives_ten_minutes() {
        assert_eq!(OWNER_REQUEST_TTL_MS, 600_000);
    }
}
