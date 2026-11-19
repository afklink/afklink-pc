//! Shapes shared by more than one message.

use serde::{Deserialize, Serialize};

use crate::invites::BindingVia;
use crate::roles::BindingRole;

/// Direction of an SDP blob. Narrowed to the two values the contract allows, so an
/// unknown string fails to deserialize instead of being silently ignored.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SdpType {
    Offer,
    Answer,
}

/// One binding as advertised to the agent. Drives the "who has access" list in the
/// agent UI, which is why `username` and `first_name` are carried rather than just
/// the numeric id — the owner should see a person, not a number.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BindingInfo {
    pub telegram_user_id: i64,
    /// Telegram users may have no username; fall back to `first_name`, then the id.
    pub username: Option<String>,
    pub first_name: Option<String>,
    /// The binding's role. Absent from a server older than roles, which
    /// reads as "this server has no roles" — not as "guest"; absent on the wire again when it is.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<BindingRole>,
    /// How the binding stands now: [`BindingVia::Party`] — it lives only through parties, with no
    /// personal reason (the person is a guest only while one of `parties` holds this PC). Absent: a
    /// personal binding, or a server older than the field. A word this build does not know is
    /// [`BindingVia::Other`], read as no `via` at all.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub via: Option<BindingVia>,
    /// The parties through which this person is a guest of this PC now (`party_id`s), for the
    /// window to say which. Empty (or absent on the wire): none, or a server older than the field.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub parties: Vec<String>,
}

impl BindingInfo {
    /// A binding with no `via` and no parties: the shape of a personal one.
    pub fn personal(
        telegram_user_id: i64,
        username: Option<String>,
        first_name: Option<String>,
        role: Option<BindingRole>,
    ) -> Self {
        Self {
            telegram_user_id,
            username,
            first_name,
            role,
            via: None,
            parties: Vec::new(),
        }
    }

    /// The binding lives only through parties (`via: party`).
    pub fn party_only(&self) -> bool {
        matches!(self.via, Some(BindingVia::Party))
    }

    /// Best available human label for this user.
    pub fn display_name(&self) -> String {
        match (&self.username, &self.first_name) {
            (Some(u), _) if !u.is_empty() => format!("@{u}"),
            (_, Some(f)) if !f.is_empty() => f.clone(),
            _ => format!("id {}", self.telegram_user_id),
        }
    }
}

/// Ephemeral ICE credentials minted per session.
///
/// `Debug` is written by hand, and prints the URLs only: a `session_request` formatted with `{:?}`
/// anywhere — an error message, a log line — would otherwise put a live TURN credential in a log
/// file that is meant to be sent to whoever diagnoses a session.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TurnCreds {
    pub urls: Vec<String>,
    pub username: String,
    pub credential: String,
}

impl std::fmt::Debug for TurnCreds {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TurnCreds")
            .field("urls", &self.urls)
            .field("username", &"<redacted>")
            .field("credential", &"<redacted>")
            .finish()
    }
}

/// `RTCIceCandidateInit` as it travels over the wire.
///
/// Strict on the server side: no extra properties, so this is a bounded shape and
/// not a free-form tunnel between two clients.
/// Field names are camelCase on the wire because they come straight from the
/// browser's `RTCIceCandidateInit`; renaming them here rather than in JS keeps the
/// viewer able to pass the object through untouched.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IceCandidate {
    /// An empty string is the end-of-candidates marker.
    pub candidate: String,
    #[serde(rename = "sdpMid", default, skip_serializing_if = "Option::is_none")]
    pub sdp_mid: Option<String>,
    #[serde(
        rename = "sdpMLineIndex",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub sdp_mline_index: Option<u16>,
    #[serde(
        rename = "usernameFragment",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub username_fragment: Option<String>,
}

/// Why a pairing request ended without creating a binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PairDeclineReason {
    /// The owner pressed Decline.
    Declined,
    /// The owner did not answer in time.
    Timeout,
    /// The viewer withdrew the request.
    Cancelled,
    /// The agent went offline while the request was pending.
    AgentDisconnected,
}

/// Format a six-digit pairing code for display: `123456` -> `123 456`.
pub fn format_pairing_code(code: &str) -> String {
    if code.len() == 6 {
        format!("{} {}", &code[..3], &code[3..])
    } else {
        code.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_name_prefers_username_then_first_name_then_id() {
        let with_username = BindingInfo {
            telegram_user_id: 1,
            username: Some("owner".into()),
            first_name: Some("Owner".into()),
            role: None,
            via: None,
            parties: Vec::new(),
        };
        assert_eq!(with_username.display_name(), "@owner");

        let no_username = BindingInfo {
            telegram_user_id: 2,
            username: None,
            first_name: Some("Owner".into()),
            role: None,
            via: None,
            parties: Vec::new(),
        };
        assert_eq!(no_username.display_name(), "Owner");

        let nothing = BindingInfo {
            telegram_user_id: 3,
            username: None,
            first_name: None,
            role: None,
            via: None,
            parties: Vec::new(),
        };
        assert_eq!(nothing.display_name(), "id 3");
    }

    #[test]
    fn empty_username_is_not_rendered_as_a_bare_at_sign() {
        let empty = BindingInfo {
            telegram_user_id: 4,
            username: Some(String::new()),
            first_name: Some("Owner".into()),
            role: None,
            via: None,
            parties: Vec::new(),
        };
        assert_eq!(empty.display_name(), "Owner");
    }

    /// A binding from a server older than roles has no `role`, and goes back out without one: an
    /// absent role is "no roles here", never written as `null` or made up as a guest.
    #[test]
    fn a_binding_without_a_role_stays_without_one() {
        let old = r#"{"telegram_user_id":5,"username":null,"first_name":"Аня"}"#;
        let b: BindingInfo = serde_json::from_str(old).expect("the old shape parses");
        assert_eq!(b.role, None);
        let back = serde_json::to_value(&b).expect("serialises");
        assert!(back.get("role").is_none(), "{back}");
        let owner = r#"{"telegram_user_id":5,"username":null,"first_name":"Аня","role":"owner"}"#;
        let b: BindingInfo = serde_json::from_str(owner).expect("parses");
        assert_eq!(b.role, Some(BindingRole::Owner));
    }

    #[test]
    fn turn_credentials_never_reach_a_debug_string() {
        let creds = TurnCreds {
            urls: vec!["turn:turn.example:3478?transport=udp".into()],
            username: "1727190000:viewer".into(),
            credential: "s3cr3t-hmac".into(),
        };
        let shown = format!("{creds:?}");
        assert!(shown.contains("turn:turn.example:3478"), "{shown}");
        assert!(!shown.contains("s3cr3t-hmac"), "{shown}");
        assert!(!shown.contains("1727190000:viewer"), "{shown}");
    }

    #[test]
    fn pairing_code_is_grouped_in_threes() {
        assert_eq!(format_pairing_code("123456"), "123 456");
        // Leading zeros survive: the code is a string, never a number.
        assert_eq!(format_pairing_code("000123"), "000 123");
        // Anything unexpected is passed through rather than mangled.
        assert_eq!(format_pairing_code("12345"), "12345");
    }
}
