//! Rust side of the AFKLink wire contract.
//!
//! The authoritative definition lives in `packages/protocol` as zod schemas. This
//! crate mirrors the parts the agent actually speaks — the `/ws/agent` channel and
//! the input DataChannels — and is held to that definition by
//! `tests/fixtures.rs`, which walks the shared golden fixtures, parses every one of
//! them into these types, and re-serializes to check the result is byte-equivalent.
//!
//! That round-trip is the guarantee. A field renamed in the zod schema produces a
//! fixture this crate cannot parse; a field silently dropped here produces a
//! fixture that parses but does not round-trip. Either way the Rust test suite goes
//! red in the same commit that changed the contract, which is exactly what the
//! three hand-maintained copies failed to do.
//!
//! The two vocabularies that are not message shapes — the error codes with their severity
//! ([`errors`]) and the `session_end` reasons the agent sends ([`end_reason`]) — are held to the
//! contract the same way by `tests/vocabulary.rs`, against the fixtures emitted from
//! `ERROR_CODES` and `SESSION_END_REASONS`.
//!
//! The REST calls the agent makes itself: the signed diagnostics upload, «Отправить логи» — its
//! constants, shapes and signed string in [`diagnostics`], held to the contract's fixtures and
//! signature vectors by `tests/diagnostics.rs` — and the desktop app's start failure beacon, sent
//! when it cannot start ([`start_failure`], held to its fixture and schema by
//! `tests/start_failure.rs`).
//!
//! Contract v2 of the telemetry — the build, boot and last exit in `agent_hello`, the final report,
//! `session_end.detail`, the session summary and `agent_event` — is in [`metrics`], held to the
//! contract by the golden fixtures and by `tests/metrics.rs`.
//!
//! The invite-only beta's part of `agent_hello` — the PC's hardware fingerprint — is in [`hw`], held
//! to the contract by the golden fixture `agent_hello_hw.json` and by `tests/metrics.rs`.
//!
//! Types are written by hand rather than generated. Generating from JSON Schema was
//! the original plan, but zod's discriminated unions become `anyOf` plus `const`
//! discriminators, which produce non-idiomatic Rust whose variant names would not
//! match the agent's existing match arms. The fixtures give the same protection
//! without that cost; codegen remains an option if the contract grows large enough
//! to make hand-mirroring tedious.

#![forbid(unsafe_code)]

pub mod agent_ws;
pub mod clipboard;
pub mod common;
pub mod cursor;
pub mod device_name;
pub mod diagnostics;
pub mod end_reason;
pub mod errors;
pub mod heartbeat;
pub mod hw;
pub mod input;
pub mod invites;
pub mod metrics;
pub mod roles;
pub mod start_failure;

pub use agent_ws::{
    agent_challenge_message, AgentSessionStats, AgentToServer, GoodbyeReason, ServerToAgent,
    AGENT_CHALLENGE_MESSAGE_BYTES, AGENT_CHALLENGE_NONCE_BYTES, AGENT_CHALLENGE_PREFIX,
};
pub use clipboard::{
    ClipboardAck, ClipboardChunk, ClipboardPc, ClipboardRefusal, ClipboardState,
    CLIPBOARD_MAX_BYTES,
};
pub use common::{
    format_pairing_code, BindingInfo, IceCandidate, PairDeclineReason, SdpType, TurnCreds,
};
pub use cursor::CursorPos;
pub use device_name::{
    sanitize_device_name, validate_device_name, DeviceNameError, DEVICE_NAME_MAX,
};
pub use errors::{error_severity, is_fatal, ErrorSeverity, ERROR_CODES};
pub use heartbeat::{
    AgentDataMessage, GameHeartbeat, GameWindowState, Heartbeat, PipelineCause, PipelineState,
};
pub use hw::{AgentHw, AGENT_HW_PARTS};
pub use input::{
    InputChannel, InputMessage, KeySource, Mods, MouseButton, ViewerEngine, ViewerVideo, WheelMode,
    CHANNEL_CURSOR, CHANNEL_INPUT, KEY_FIELD_MAX_UNITS, VIS_WHY_MAX_CHARS,
};
pub use invites::{BindingVia, VIA_OTHER_MAX_CHARS};
pub use metrics::{
    AgentBuildInfo, AgentExitKind, AgentLastExit, PeerStage, SessionEndDetail,
    SESSION_TOMBSTONE_MS, TELEMETRY_FIRST_REPORT_MS,
};
pub use roles::{
    BindingRole, OwnerRequestKind, OwnerRequestReason, OwnerRequestState, OwnerStateKind,
    OWNER_REQUEST_TTL_MS,
};

/// Protocol version this build speaks. Mirrors `PROTOCOL_VERSION` in the contract.
pub const PROTOCOL_VERSION: u32 = 1;

/// Oldest version this build still accepts.
pub const MIN_SUPPORTED_PROTOCOL: u32 = 1;

/// Largest accepted signaling frame, in bytes.
pub const WS_FRAME_MAX_BYTES: usize = 64 * 1024;

/// Largest accepted DataChannel payload, in bytes.
pub const INPUT_MAX_BYTES: usize = 4 * 1024;

/// Silence on the input channel after which the agent releases everything held.
pub const INPUT_SILENCE_RELEASE_MS: u64 = 2_000;

/// How often each end reports cumulative session telemetry.
///
/// Mirrors `TELEMETRY_INTERVAL_MS` in `packages/protocol/src/telemetry.ts`. Fifteen seconds:
/// frequent enough that an abandoned session loses at most that much history, infrequent enough
/// to be nothing on a socket that already exists for signaling.
pub const TELEMETRY_INTERVAL_MS: u64 = 15_000;

/// How often the agent sends its pipeline heartbeat on the `cursor` channel.
///
/// Mirrors `HEARTBEAT_INTERVAL_MS` in `packages/protocol/src/channels.ts`. A state change goes out
/// at once rather than on this clock; this bounds how stale an "ok" can be.
pub const HEARTBEAT_INTERVAL_MS: u64 = 1_000;

/// The cursor report (`cp`) goes out at most this often, and only when something in it changed.
///
/// Mirrors `CURSOR_REPORT_MIN_INTERVAL_MS` in `packages/protocol/src/channels.ts`: about thirty a
/// second, a few hundred bytes a second while the pointer moves.
pub const CURSOR_REPORT_MIN_INTERVAL_MS: u64 = 33;

/// An unchanged cursor is reported again this often: the `cursor` channel never retransmits, so a
/// lost last report would otherwise stand until the pointer next moves. Mirrors
/// `CURSOR_REPORT_REFRESH_MS`.
pub const CURSOR_REPORT_REFRESH_MS: u64 = 1_000;

/// How long the owner has to answer a pairing prompt.
pub const PAIR_CONFIRM_TIMEOUT_MS: u64 = 120_000;
