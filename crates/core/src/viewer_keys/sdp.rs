//! The viewer's DTLS fingerprint in its SDP offer (protocol spec §3.3): the value the offer's
//! signature covers (`fp_viewer`) and the one a re-offer must repeat (§3.5).

use super::wire::FINGERPRINT_LEN;

/// Why an SDP has no single usable fingerprint (`proof_invalid:fp_bad`; the vectors' `why`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FpError {
    /// A bare CR (a `\r` not followed by `\n`) anywhere: str0m would split the lines otherwise.
    LineEnd,
    /// No `a=fingerprint:` line at all.
    None,
    /// A candidate line not exactly lowercase `a=fingerprint:` from its first character (another
    /// case, or leading spaces or tabs): str0m would not read it, so it is refused, not skipped.
    Name,
    /// A line not of the form `sha-256 <32 hex pairs joined by ':'>`.
    Form,
    /// A line with another algorithm than exactly lowercase `sha-256`.
    Alg,
    /// Lines with different values.
    Mismatch,
}

impl FpError {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LineEnd => "line_end",
            Self::None => "none",
            Self::Name => "name",
            Self::Form => "form",
            Self::Alg => "alg",
            Self::Mismatch => "mismatch",
        }
    }
}

const PREFIX: &str = "a=fingerprint:";

/// `fp_viewer` of `sdp` (§3.3), checked in this order (the vectors' `why`): a bare CR anywhere →
/// `line_end`; the candidates are the lines (split on `\r\n` or `\n`) that, after leading spaces
/// and tabs, start with `a=fingerprint:` in any case, at session level and in every `m=` — none →
/// `none`; then each candidate top to bottom: not exactly lowercase `a=fingerprint:` from its
/// first character → `name`; `<alg> <value>` split at the first space with a non-empty algorithm,
/// else `form`; the algorithm exactly lowercase `sha-256`, else `alg`; the value 32 bytes as
/// two-digit hex pairs (any case) joined by `:` and nothing more, else `form`; every value equal
/// to the first, else `mismatch`. An accepted value is the only fingerprint str0m can read from
/// that SDP (it reads the first session line, else the first media line, exactly lowercase), so
/// what str0m checks is what was signed.
pub fn viewer_fingerprint(sdp: &str) -> Result<[u8; FINGERPRINT_LEN], FpError> {
    let result = fingerprint_of(sdp);
    match &result {
        Ok(_) => tracing::trace!("sdp fingerprint: one value"),
        Err(e) => tracing::debug!(why = e.as_str(), "sdp fingerprint: refused"),
    }
    result
}

fn fingerprint_of(sdp: &str) -> Result<[u8; FINGERPRINT_LEN], FpError> {
    let bytes = sdp.as_bytes();
    let bare_cr = bytes
        .iter()
        .enumerate()
        .any(|(i, &b)| b == b'\r' && bytes.get(i + 1) != Some(&b'\n'));
    if bare_cr {
        return Err(FpError::LineEnd);
    }
    // No bare CR: every `\r` ends a `\r\n`, so dropping one at a line's end splits on both.
    let candidates: Vec<&str> = sdp
        .split('\n')
        .map(|raw| raw.strip_suffix('\r').unwrap_or(raw))
        .filter(|line| {
            line.trim_start_matches([' ', '\t'])
                .get(..PREFIX.len())
                .is_some_and(|head| head.eq_ignore_ascii_case(PREFIX))
        })
        .collect();
    if candidates.is_empty() {
        return Err(FpError::None);
    }
    let mut found: Option<[u8; FINGERPRINT_LEN]> = None;
    for line in candidates {
        let Some(rest) = line.strip_prefix(PREFIX) else {
            return Err(FpError::Name);
        };
        let Some((alg, value)) = rest.split_once(' ').filter(|(alg, _)| !alg.is_empty()) else {
            return Err(FpError::Form);
        };
        if alg != "sha-256" {
            return Err(FpError::Alg);
        }
        let fp = parse_hex_pairs(value).ok_or(FpError::Form)?;
        match &found {
            None => found = Some(fp),
            Some(prev) if *prev == fp => {}
            Some(_) => return Err(FpError::Mismatch),
        }
    }
    found.ok_or(FpError::None)
}

fn parse_hex_pairs(value: &str) -> Option<[u8; FINGERPRINT_LEN]> {
    let mut out = [0u8; FINGERPRINT_LEN];
    let mut n = 0usize;
    for pair in value.split(':') {
        let b = pair.as_bytes();
        if b.len() != 2 || n >= FINGERPRINT_LEN {
            return None;
        }
        let hi = (b[0] as char).to_digit(16)?;
        let lo = (b[1] as char).to_digit(16)?;
        out[n] = u8::try_from(hi * 16 + lo).ok()?;
        n += 1;
    }
    (n == FINGERPRINT_LEN).then_some(out)
}
