//! The device name: what the owner calls this PC, and what the Mini App's device list shows.
//!
//! One rule on both ends, mirrored from `deviceNameSchema` in `packages/protocol/src/common.ts`:
//! surrounding whitespace is not part of the name; what is left is 1 to [`DEVICE_NAME_MAX`]
//! characters and holds no control character. A character is a Unicode code point — a Rust
//! `char`, and what zod counts too (not UTF-16 units). `tests/device_name.rs` holds this module to
//! the cases the TypeScript side is tested with (`packages/protocol/vectors/device-names.json`)
//! and [`DEVICE_NAME_MAX`] to the emitted JSON Schema.
//!
//! The agent checks the owner's name with [`validate_device_name`] before it keeps it, and again
//! before it sends it with an approval (`pair_response.name`): a name the backend refuses leaves
//! the device under the backend's placeholder, which is the bug this rule exists for.

use std::fmt;

/// Longest device name, in characters. Mirrors `LIMITS.deviceName`.
pub const DEVICE_NAME_MAX: usize = 64;

/// Why a string is not a device name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceNameError {
    /// Nothing is left once surrounding whitespace is trimmed.
    Empty,
    /// More than [`DEVICE_NAME_MAX`] characters after trimming.
    TooLong { chars: usize },
    /// A control character (Unicode `Cc`: a tab, a newline, NUL, DEL, a C1 code).
    ControlChar,
}

impl DeviceNameError {
    /// The short name of the reason, as the shared cases spell it — and for log fields.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Empty => "empty",
            Self::TooLong { .. } => "too_long",
            Self::ControlChar => "control_char",
        }
    }
}

impl fmt::Display for DeviceNameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("a device name cannot be empty"),
            Self::TooLong { chars } => write!(
                f,
                "a device name is at most {DEVICE_NAME_MAX} characters, this one is {chars}"
            ),
            Self::ControlChar => f.write_str("a device name cannot hold control characters"),
        }
    }
}

impl std::error::Error for DeviceNameError {}

/// Whitespace as JavaScript's `String.prototype.trim` sees it, which is what the backend trims
/// with: Unicode `White_Space` without U+0085 (NEL, a control character JavaScript keeps), plus
/// U+FEFF (which JavaScript trims and Unicode does not call whitespace). Rust's own `trim` differs
/// on exactly those two.
fn is_js_whitespace(c: char) -> bool {
    (c.is_whitespace() && c != '\u{85}') || c == '\u{feff}'
}

fn trim_js(s: &str) -> &str {
    s.trim_matches(is_js_whitespace)
}

/// The name as it would be stored, or why it cannot be one.
///
/// Trimmed first, exactly as the backend's schema trims it, so a name that passes here is stored
/// as returned.
pub fn validate_device_name(raw: &str) -> Result<String, DeviceNameError> {
    let name = trim_js(raw);
    if name.is_empty() {
        return Err(DeviceNameError::Empty);
    }
    let chars = name.chars().count();
    if chars > DEVICE_NAME_MAX {
        return Err(DeviceNameError::TooLong { chars });
    }
    if name.chars().any(char::is_control) {
        return Err(DeviceNameError::ControlChar);
    }
    Ok(name.to_string())
}

/// The nearest valid name to `raw`, or `None` when nothing of it survives.
///
/// For a stored name that predates the rule (a `config.json` written before the desktop app
/// capped the field, or edited by hand): control characters dropped, whitespace trimmed, cut to
/// [`DEVICE_NAME_MAX`] characters. Owner input is not repaired this way — it is refused, so the
/// field says what was kept.
pub fn sanitize_device_name(raw: &str) -> Option<String> {
    let cleaned: String = raw.chars().filter(|c| !c.is_control()).collect();
    let cut: String = trim_js(&cleaned).chars().take(DEVICE_NAME_MAX).collect();
    validate_device_name(&cut).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_valid_name_comes_back_trimmed() {
        assert_eq!(
            validate_device_name("  Рабочий ПК \u{feff}"),
            Ok("Рабочий ПК".into())
        );
    }

    #[test]
    fn the_reasons_are_told_apart() {
        assert_eq!(validate_device_name(" \t "), Err(DeviceNameError::Empty));
        assert_eq!(
            validate_device_name(&"я".repeat(DEVICE_NAME_MAX + 1)),
            Err(DeviceNameError::TooLong {
                chars: DEVICE_NAME_MAX + 1
            })
        );
        assert_eq!(
            validate_device_name("a\u{85}b"),
            Err(DeviceNameError::ControlChar)
        );
    }

    #[test]
    fn a_stored_name_outside_the_rule_is_repaired_to_the_nearest_valid_one() {
        assert_eq!(
            sanitize_device_name("  Office\tPC\n"),
            Some("OfficePC".into())
        );
        let long = format!("{} tail", "b".repeat(DEVICE_NAME_MAX - 1));
        let repaired = sanitize_device_name(&long).expect("something survives");
        // Cut at the limit, and the space the cut left at the end trimmed away.
        assert_eq!(repaired, "b".repeat(DEVICE_NAME_MAX - 1));
        assert_eq!(sanitize_device_name("\u{0}\u{7f} "), None);
        assert_eq!(sanitize_device_name("HVN2MMZR"), Some("HVN2MMZR".into()));
    }
}
