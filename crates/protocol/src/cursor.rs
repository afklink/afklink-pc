//! The PC's cursor position, agent -> viewer (`cp`).
//!
//! Mirrors `cursorPosSchema` in `packages/protocol/src/datachannel.ts`, held to it by the
//! `agent-to-viewer` fixtures in `tests/fixtures.rs`.
//!
//! ## Why it exists
//!
//! The trackpad mode moves the PC cursor with relative moves only (`r`), and the only picture of
//! the cursor the phone has is the one in the video: a few pixels tall on a phone and a round trip
//! late. The viewer draws its own marker instead, at the last position the agent reported plus the
//! relative moves it has sent since. `ack` says which moves a report already includes — the
//! highest `r.s` the agent had applied when it sampled — so the marker never counts a move twice.
//!
//! ## Why the `cursor` channel
//!
//! Like the heartbeat, a report is a sample the next one supersedes: unordered and never
//! retransmitted is exactly right. `seq` rises by one per report so the viewer can drop one that
//! the unordered channel delivered late; the agent refreshes an unchanged report once per
//! [`crate::CURSOR_REPORT_REFRESH_MS`] because a lost last report would otherwise stand.

use serde::{Deserialize, Serialize};

/// One cursor report. Field names are the wire names.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct CursorPos {
    /// Rises by one per report, from 0 at session start.
    pub seq: u64,
    /// Position on the captured screen, normalized like `m` and clamped to `[0..1]`.
    pub x: f64,
    pub y: f64,
    /// The highest relative-move number (`r.s`) applied before this sample; absent until the
    /// first numbered move of the session.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ack: Option<u32>,
    /// The cursor cannot be seen on the captured screen: an application hid it, or it is on
    /// another monitor. Absent (false) otherwise.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub hidden: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AgentDataMessage;

    fn report() -> CursorPos {
        CursorPos {
            seq: 3,
            x: 0.25,
            y: 0.75,
            ack: None,
            hidden: false,
        }
    }

    /// The optional fields are absent while they say nothing, so the smallest report is the
    /// common one: a position and its number.
    #[test]
    fn a_plain_report_carries_only_its_number_and_position() {
        let json = AgentDataMessage::Cursor(report()).to_json().unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["t"], "cp");
        assert_eq!(v["seq"], 3);
        assert!(v.get("ack").is_none(), "{json}");
        assert!(v.get("hidden").is_none(), "{json}");
    }

    #[test]
    fn ack_and_hidden_round_trip_when_they_are_there() {
        let full = CursorPos {
            ack: Some(u32::MAX),
            hidden: true,
            ..report()
        };
        let json = AgentDataMessage::Cursor(full).to_json().unwrap();
        assert!(json.contains(r#""ack":4294967295"#), "{json}");
        assert!(json.contains(r#""hidden":true"#), "{json}");
        let back: AgentDataMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(back, AgentDataMessage::Cursor(full));
    }
}
