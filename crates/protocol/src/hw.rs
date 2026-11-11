//! `agent_hello.hw` (`agentHwSchema` in `packages/protocol/src/agent-ws.ts`): the PC's hardware
//! fingerprint, for the invite-only beta.
//!
//! The agent sends a SHA-256 of what it could read of the PC — MachineGuid, the SMBIOS system UUID,
//! the serial of the disk the system is on (`afklink_core::hw` reads and hashes them) — as base64url
//! without padding, with how many of the three went in and whether the SMBIOS maker says a virtual
//! machine. The server never keeps the hash as it comes: it stores an HMAC of it with a secret of its
//! own, and logs neither. A fact, not a key: nothing is let in or refused by it.
//!
//! The hash is never logged here either: [`AgentHw`]'s `Debug` prints its length only, so a hello
//! that reaches a `{:?}` somewhere says nothing about the PC.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::metrics::InvalidField;

/// The parts a fingerprint is made of (`AGENT_HW_PARTS`): MachineGuid, the SMBIOS UUID, the system
/// disk's serial.
pub const AGENT_HW_PARTS: u8 = 3;

/// A SHA-256 (32 bytes) as base64url without padding: 43 characters (`AGENT_HW_HASH_PATTERN`,
/// `^[A-Za-z0-9_-]{43}$`).
pub const AGENT_HW_HASH_LEN: usize = 43;

/// `hash` as the contract's pattern has it: exactly [`AGENT_HW_HASH_LEN`] characters of the base64url
/// alphabet. A hand-written mirror of the zod regex (the crate has no regex engine); `tests/metrics.rs`
/// pins the pattern it was written against.
pub fn is_hw_hash(s: &str) -> bool {
    s.len() == AGENT_HW_HASH_LEN
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// The PC's hardware fingerprint as `agent_hello` carries it.
///
/// An agent that could read no part of the PC sends no `hw` at all, so `parts` is 1 to
/// [`AGENT_HW_PARTS`] whenever there is one.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentHw {
    /// SHA-256 of the parts read, base64url without padding ([`is_hw_hash`]).
    pub hash: String,
    /// The SMBIOS maker or product says a virtual machine: the PC goes to an admin's review.
    pub vm: bool,
    /// How many of the [`AGENT_HW_PARTS`] went into `hash`: fewer is a weaker fingerprint.
    pub parts: u8,
}

impl AgentHw {
    /// Every field against the contract's rules; the first that fails is named. A hello the server's
    /// schema refuses would be refused on every attempt, so the agent sends no `hw` rather than one
    /// that fails this.
    pub fn check(&self) -> Result<(), InvalidField> {
        if !is_hw_hash(&self.hash) {
            return Err(InvalidField { field: "hw.hash" });
        }
        if !(1..=AGENT_HW_PARTS).contains(&self.parts) {
            return Err(InvalidField { field: "hw.parts" });
        }
        Ok(())
    }
}

/// The hash's length only: the hash is a fact about this PC and never goes into a log.
impl fmt::Debug for AgentHw {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AgentHw")
            .field("hash", &format_args!("<{} chars>", self.hash.len()))
            .field("vm", &self.vm)
            .field("parts", &self.parts)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HASH: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";

    #[test]
    fn the_hash_is_43_characters_of_base64url() {
        assert!(is_hw_hash(HASH));
        assert!(is_hw_hash(
            &"-_".repeat(21).chars().chain(['z']).collect::<String>()
        ));
        assert!(!is_hw_hash(&HASH[..42]), "too short");
        assert!(!is_hw_hash(&format!("{HASH}A")), "too long");
        assert!(
            !is_hw_hash(&format!("{}=", &HASH[..42])),
            "padding is not base64url without padding"
        );
        assert!(!is_hw_hash(&format!("{}+", &HASH[..42])), "standard base64");
        assert!(!is_hw_hash(&format!("{}/", &HASH[..42])), "standard base64");
        assert!(!is_hw_hash(""));
    }

    #[test]
    fn check_names_the_field_the_contract_would_refuse() {
        let ok = AgentHw {
            hash: HASH.into(),
            vm: false,
            parts: 3,
        };
        assert_eq!(ok.check(), Ok(()));
        for parts in [1, 2, 3] {
            assert_eq!(
                AgentHw {
                    parts,
                    ..ok.clone()
                }
                .check(),
                Ok(()),
                "{parts}"
            );
        }
        for parts in [0, 4, u8::MAX] {
            assert_eq!(
                AgentHw {
                    parts,
                    ..ok.clone()
                }
                .check(),
                Err(InvalidField { field: "hw.parts" }),
                "{parts}"
            );
        }
        assert_eq!(
            AgentHw {
                hash: "short".into(),
                ..ok
            }
            .check(),
            Err(InvalidField { field: "hw.hash" })
        );
    }

    #[test]
    fn debug_never_prints_the_hash() {
        let hw = AgentHw {
            hash: HASH.into(),
            vm: true,
            parts: 2,
        };
        let shown = format!("{hw:?}");
        assert!(!shown.contains(HASH), "{shown}");
        assert_eq!(shown, "AgentHw { hash: <43 chars>, vm: true, parts: 2 }");
    }
}
