//! The machine-readable stdout lines the bench harness reads.
//!
//! One event per line, `BENCH <WHAT>[ key=value ...]`, written with the stdout lock held and flushed
//! at once, so a line is never split by a log line and never waits in a buffer:
//!
//! ```text
//! BENCH DEVICE_ID=<uuid>                        once, when first authenticated
//! BENCH READY                                   each time signaling is up and sessions can start
//! BENCH PAIRING_CODE=<digits>                   whenever the backend issues a pairing code
//! BENCH SESSION_START id=<session>              a session's capture, encoder and peer run
//! BENCH SESSION_END id=<session> reason=<why>   it ended (or its setup failed: no START before it)
//! ```
//!
//! Values are single tokens: whitespace inside one becomes `_`, an empty one is `-`. The log lines
//! share stdout but never start with `BENCH` (they start with a timestamp).

use std::io::Write as _;

/// What every line starts with.
pub const PREFIX: &str = "BENCH";

#[must_use]
pub fn device_id(id: &str) -> String {
    format!("{PREFIX} DEVICE_ID={}", token(id))
}

#[must_use]
pub fn ready() -> String {
    format!("{PREFIX} READY")
}

/// The code as bare digits, whatever grouping it arrived with.
#[must_use]
pub fn pairing_code(code: &str) -> String {
    let digits: String = code.chars().filter(char::is_ascii_digit).collect();
    format!("{PREFIX} PAIRING_CODE={}", token(&digits))
}

#[must_use]
pub fn session_start(session_id: &str) -> String {
    format!("{PREFIX} SESSION_START id={}", token(session_id))
}

#[must_use]
pub fn session_end(session_id: &str, reason: &str) -> String {
    format!(
        "{PREFIX} SESSION_END id={} reason={}",
        token(session_id),
        token(reason)
    )
}

/// One whitespace-free token.
fn token(value: &str) -> String {
    let t: String = value
        .trim()
        .chars()
        .map(|c| if c.is_whitespace() { '_' } else { c })
        .collect();
    if t.is_empty() {
        "-".to_string()
    } else {
        t
    }
}

/// Write one line to stdout and flush it now. `what` names it for the log, which does not repeat
/// the line itself (a pairing code is a live credential; it goes to stdout only because the harness
/// needs it).
pub fn emit(line: &str, what: &str) {
    let mut out = std::io::stdout().lock();
    match writeln!(out, "{line}").and_then(|()| out.flush()) {
        Ok(()) => tracing::debug!(what, "bench line written to stdout"),
        Err(e) => tracing::warn!(what, "bench line could not be written to stdout: {e}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lines_match_the_contract() {
        assert_eq!(
            device_id("843eda6a-41d7-47cf-b279-50adc4c3c45c"),
            "BENCH DEVICE_ID=843eda6a-41d7-47cf-b279-50adc4c3c45c"
        );
        assert_eq!(ready(), "BENCH READY");
        assert_eq!(pairing_code("123456"), "BENCH PAIRING_CODE=123456");
        assert_eq!(pairing_code("012 345"), "BENCH PAIRING_CODE=012345");
        assert_eq!(
            session_start("5f0c7e0a-aaaa"),
            "BENCH SESSION_START id=5f0c7e0a-aaaa"
        );
        assert_eq!(
            session_end("5f0c7e0a-aaaa", "ice_timeout"),
            "BENCH SESSION_END id=5f0c7e0a-aaaa reason=ice_timeout"
        );
    }

    #[test]
    fn values_stay_single_tokens() {
        assert_eq!(
            session_end("a b", "two words\there"),
            "BENCH SESSION_END id=a_b reason=two_words_here"
        );
        assert_eq!(session_end("", " "), "BENCH SESSION_END id=- reason=-");
        assert_eq!(pairing_code("no digits"), "BENCH PAIRING_CODE=-");
        for line in [device_id("x"), ready(), session_start("s")] {
            assert!(line.starts_with("BENCH "), "{line}");
            assert!(!line.contains('\n'));
        }
    }
}
