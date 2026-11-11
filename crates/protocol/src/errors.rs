//! Wire error codes, and whether retrying can ever help.
//!
//! Mirrors `ERROR_CODES` in `packages/protocol/src/errors.ts`, the source of truth: every code the
//! backend may put in an `error` frame, each `transient` (retrying later may succeed) or `fatal`
//! (retrying cannot help). The agent's reconnect loop reads this table to decide whether to back
//! off and retry, retry slowly, or stop (`afklink_core::reconnect`).
//!
//! Held to the contract by `tests/vocabulary.rs`, which compares [`ERROR_CODES`] with
//! `packages/protocol/fixtures/error-codes.json` (emitted from `ERROR_CODES` by
//! `packages/protocol/scripts/emit.ts`) in both directions: a code whose severity differs, a code
//! the contract gained that this table lacks, and a code this table has that the contract dropped
//! all fail the Rust suite in the commit that changed the contract.
//!
//! A code this build does not know is transient, exactly as the TypeScript side treats it
//! (`asErrorCode`): a newer backend may legitimately send one, and refusing to reconnect over it
//! would strand an agent that nothing is wrong with.

/// Whether retrying can help. Mirrors `ErrorSeverity` in the contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ErrorSeverity {
    /// Retrying later may succeed.
    Transient,
    /// Stop: retrying cannot help.
    Fatal,
}

impl ErrorSeverity {
    /// The contract's spelling: `"transient"` or `"fatal"`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Transient => "transient",
            Self::Fatal => "fatal",
        }
    }
}

/// Another connection for this device took over: the backend keeps only the latest one.
///
/// Named because the agent treats it apart from every other fatal code: it means a second process
/// with the same device identity is running, and two such processes would otherwise take the
/// connection from each other forever.
pub const REPLACED: &str = "replaced";

/// An admin blocked this PC (the invite-only beta):
/// sent on the agent's socket once its signature proves it, and on a live connection when the block
/// comes, then the close. Named because the agent shows it apart from every other fatal code
/// («ПК заблокирован», with no Retry): only an admin lifting the block helps, and the agent's slow
/// retry finds that by itself (`afklink_core::reconnect`).
pub const DEVICE_BLOCKED: &str = "device_blocked";

/// Every code in the contract with its severity, in the contract's order.
pub const ERROR_CODES: &[(&str, ErrorSeverity)] = {
    use ErrorSeverity::{Fatal, Transient};
    &[
        // Framing / schema, either channel.
        ("bad_json", Transient),
        ("bad_message", Transient),
        ("message_too_large", Transient),
        // Handshake, both channels.
        ("protocol_unsupported", Fatal),
        ("not_authenticated", Fatal),
        ("auth_timeout", Transient),
        ("rate_limited", Transient),
        // Agent handshake.
        ("already_hello", Fatal),
        ("invalid_pubkey", Fatal),
        ("pubkey_mismatch", Fatal),
        ("no_challenge", Fatal),
        ("bad_signature", Fatal),
        (REPLACED, Fatal),
        // Viewer handshake.
        ("unauthorized", Fatal),
        ("not_bound", Fatal),
        ("device_offline", Transient),
        // The website's one-time ticket in `viewer_hello`: unknown, used or past its minute. The
        // viewer asks for a new one; an agent never meets it.
        ("ticket_invalid", Transient),
        // Sessions.
        ("unknown_session", Transient),
        ("too_many_sessions", Transient),
        // REST.
        ("invalid_code", Transient),
        ("expired_code", Transient),
        ("code_used", Transient),
        ("not_found", Fatal),
        ("invalid_name", Transient),
        // A request signed in with the website's cookie came from another site's page (its Origin
        // says so): the same request from the same page never passes. An agent never meets it.
        ("origin_refused", Fatal),
        // Diagnostic reports: the desktop app's «Отправить логи» meets these, never the
        // reconnect loop (`crate::diagnostics`).
        ("payload_too_large", Fatal),
        ("clock_skew", Transient),
        ("nonce_reused", Transient),
        ("digest_mismatch", Transient),
        ("request_timeout", Transient),
        ("service_unavailable", Transient),
        // The invite-only beta: all three fatal — only an admin can
        // help. The agent signs in as a device, so of the three only `device_blocked` is ever sent
        // on its socket; the other two answer a viewer (`afklink_core::reconnect` says what each
        // would do here all the same).
        ("beta_required", Fatal),
        ("account_blocked", Fatal),
        (DEVICE_BLOCKED, Fatal),
        // Catch-all.
        ("internal", Transient),
    ]
};

/// The severity of a code this build knows; `None` for one it does not.
pub fn error_severity(code: &str) -> Option<ErrorSeverity> {
    ERROR_CODES
        .iter()
        .find(|(known, _)| *known == code)
        .map(|&(_, severity)| severity)
}

/// True only for a known fatal code. An unknown code is transient; see the module docs.
pub fn is_fatal(code: &str) -> bool {
    error_severity(code) == Some(ErrorSeverity::Fatal)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_code_appears_once() {
        let mut seen = std::collections::BTreeSet::new();
        for (code, _) in ERROR_CODES {
            assert!(seen.insert(*code), "{code} is listed twice");
        }
    }

    #[test]
    fn an_unknown_code_is_transient() {
        assert_eq!(error_severity("a_code_from_a_newer_backend"), None);
        assert!(!is_fatal("a_code_from_a_newer_backend"));
        assert!(!is_fatal(""));
    }

    #[test]
    fn the_codes_the_agent_decides_on_have_the_contract_severity() {
        assert!(is_fatal(REPLACED));
        assert!(is_fatal("protocol_unsupported"));
        assert!(is_fatal("bad_signature"));
        assert!(!is_fatal("auth_timeout"));
        assert!(!is_fatal("bad_message"));
        // The report upload's: the same body never fits; a skewed clock can be corrected.
        assert!(is_fatal("payload_too_large"));
        assert!(!is_fatal("clock_skew"));
        // The website's: a new ticket can help, a foreign page never.
        assert_eq!(
            error_severity("ticket_invalid"),
            Some(ErrorSeverity::Transient)
        );
        assert!(is_fatal("origin_refused"));
        // The beta's: retrying cannot help, only an admin.
        assert!(is_fatal(DEVICE_BLOCKED));
        assert!(is_fatal("account_blocked"));
        assert!(is_fatal("beta_required"));
        assert_eq!(ErrorSeverity::Fatal.as_str(), "fatal");
        assert_eq!(ErrorSeverity::Transient.as_str(), "transient");
    }
}
