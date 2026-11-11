//! Guest invites, the part the PC hears of: how a binding came about, `binding_added.via`. Mirrors
//! `BINDING_VIAS` in `packages/protocol/src/invites.ts`; the rest of that file — the invite's token,
//! its limits, the REST shapes — is the server's and the Mini App's, never the PC's.
//!
//! The owner, away from the PC, invites a friend from Telegram and allows him there; the server binds
//! the friend as a guest and tells the PC `binding_added{role: guest, via: invite}`. Nobody at the PC
//! was asked, so the PC tells the person at it at once.
//!
//! Unlike the roles' sets ([`crate::roles`]), this one is open on the way in, as the contract asks: a
//! word this build does not know reads as no `via` at all — the binding counts whatever its origin,
//! and a later server's word must not cost the PC the whole message. The word is kept
//! ([`BindingVia::Other`]) only so the agent can log what it did not act on.

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// The most characters of a word this build does not know that are kept, for the log.
pub const VIA_OTHER_MAX_CHARS: usize = 32;

/// How a binding came about (`binding_added.via`), as this build reads it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum BindingVia {
    /// `invite`: the owner allowed, in Telegram, a friend who accepted his invite; nobody at the PC
    /// was asked. Always with `role: guest`.
    Invite,
    /// A word this build does not know — a later server's — or a value that is not a word at all,
    /// kept as given (at most [`VIA_OTHER_MAX_CHARS`] characters) for the log. Means what an absent
    /// `via` means: nothing.
    Other(String),
}

impl BindingVia {
    /// The contract's spelling; anything else is [`Self::Other`], kept as given.
    pub fn from_wire(word: &str) -> Self {
        match word {
            "invite" => Self::Invite,
            other => Self::Other(other.chars().take(VIA_OTHER_MAX_CHARS).collect()),
        }
    }

    /// The wire spelling, for log lines: `invite`, or the unknown word as it came.
    pub fn as_str(&self) -> &str {
        match self {
            Self::Invite => "invite",
            Self::Other(word) => word,
        }
    }
}

impl Serialize for BindingVia {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for BindingVia {
    /// Any value: a word is read by [`BindingVia::from_wire`], anything else is kept as its JSON
    /// text. Never an error — that would cost the PC the whole `binding_added`.
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Ok(match serde_json::Value::deserialize(deserializer)? {
            serde_json::Value::String(word) => Self::from_wire(&word),
            other => Self::from_wire(&other.to_string()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BindingRole, ServerToAgent};

    fn added(via: &str) -> String {
        format!(
            r#"{{"type":"binding_added","telegram_user_id":7,"username":"friend",
                "first_name":"Друг","role":"guest"{via}}}"#
        )
    }

    fn via_of(json: &str) -> Option<BindingVia> {
        match serde_json::from_str::<ServerToAgent>(json) {
            Ok(ServerToAgent::BindingAdded { via, .. }) => via,
            other => panic!("not a binding_added: {other:?}"),
        }
    }

    #[test]
    fn invite_is_read_and_written_as_the_contract_spells_it() {
        assert_eq!(BindingVia::from_wire("invite"), BindingVia::Invite);
        assert_eq!(BindingVia::Invite.as_str(), "invite");
        assert_eq!(
            serde_json::to_value(BindingVia::Invite).expect("serialises"),
            serde_json::json!("invite")
        );
        assert_eq!(
            via_of(&added(r#","via":"invite""#)),
            Some(BindingVia::Invite)
        );
    }

    /// The contract: a value the agent does not know reads as no `via` at all, and never costs it the
    /// message. The binding itself — who, which role — comes through whole.
    #[test]
    fn a_word_this_build_does_not_know_keeps_the_message() {
        for (via, kept) in [
            (r#","via":"Invite""#, "Invite"),
            (r#","via":"pairing""#, "pairing"),
            (r#","via":"""#, ""),
            (r#","via":1"#, "1"),
            (r#","via":{"kind":"invite"}"#, r#"{"kind":"invite"}"#),
            (r#","via":["invite"]"#, r#"["invite"]"#),
        ] {
            let json = added(via);
            let msg: ServerToAgent = serde_json::from_str(&json)
                .unwrap_or_else(|e| panic!("{via}: the message was refused: {e}"));
            let ServerToAgent::BindingAdded {
                telegram_user_id,
                role,
                via,
                ..
            } = msg
            else {
                panic!("{json}: not a binding_added");
            };
            assert_eq!(telegram_user_id, 7);
            assert_eq!(role, Some(BindingRole::Guest));
            assert_eq!(via, Some(BindingVia::Other(kept.to_string())), "{json}");
        }
    }

    #[test]
    fn null_and_absent_are_no_via() {
        assert_eq!(via_of(&added(r#","via":null"#)), None);
        assert_eq!(via_of(&added("")), None);
    }

    #[test]
    fn an_unknown_word_is_kept_short() {
        let long = "x".repeat(10_000);
        let BindingVia::Other(kept) = BindingVia::from_wire(&long) else {
            panic!("not an unknown word");
        };
        assert_eq!(kept.chars().count(), VIA_OTHER_MAX_CHARS);
        // Characters, not bytes: a word in Cyrillic is cut on a character.
        let BindingVia::Other(kept) = BindingVia::from_wire(&"ж".repeat(100)) else {
            panic!("not an unknown word");
        };
        assert_eq!(kept, "ж".repeat(VIA_OTHER_MAX_CHARS));
    }
}
