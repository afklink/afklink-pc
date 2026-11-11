//! Core of the AFKLink Windows agent: identity, config, the platform-abstraction
//! traits, and the `Agent` orchestrator (connect + auth + session pipeline).
//!
//! Concrete platform backends live in the sibling crates (`capture`, `encode`,
//! `input`) and are injected via [`agent::Backends`], so this crate carries no
//! Windows-only dependencies and can be checked/run in isolation.

pub mod agent;
pub mod agent_events;
pub mod bg_hold;
pub mod build_info;
pub mod clipboard;
pub mod config;
pub mod cursor_report;
pub mod entry;
pub mod frame_dropper;
pub mod game;
pub mod game_access;
pub mod game_input;
pub mod goodbye;
pub mod identity;
mod input_reach;
mod input_rhythm;
mod input_session;
pub mod journal;
pub mod keyframe_window;
pub mod logging;
mod offload;
mod own_windows;
pub mod owner_request;
pub mod pairing;
pub mod paths;
pub mod person_name;
pub mod pipeline;
pub mod qr;
pub mod quality;
pub mod quality_policy;
pub mod reconnect;
mod relay;
pub mod run_state;
pub mod scale;
pub mod session_log;
pub mod step_watch;
pub mod summary;
pub mod sync;
pub mod traits;
pub mod types;
pub mod viewer_report;

pub use agent::{
    Agent, AgentCommand, AgentControl, AgentEvent, AgentState, Backends, ExitEnding, HwReader,
    PauseKept, SessionInfo, EXIT_END_BUDGET, START_STEP_BUDGET,
};
pub use config::Config;
pub use goodbye::{GoodbyeOutcome, GoodbyeReason, GOODBYE_BUDGET};
pub use identity::Identity;
pub use journal::Journal;
pub use pairing::PairingPanel;
pub use person_name::{person_name, NameSource, PersonName};
pub use reconnect::{OnReplaced, Refusal};
pub use session_log::SessionLog;
pub use sync::lock;

/// The log target of what the shared crates' extension points do for a host that embeds them (the
/// external frame sink, direct HID access): such a host can keep these lines while it turns the
/// agent's own modules off. The agent itself never takes these paths.
pub const EMBED_LOG_TARGET: &str = "afklink_embed";
pub use traits::{Capturer, Encoder, InputInjector};
pub use types::{EncodedFrame, Frame};

// Re-export the transport binding type so the UI can read `AgentState.bindings`
// without depending on the transport crate directly.
pub use afklink_transport::BindingInfo;

// The input event model is contract, not agent code: it lives in the protocol crate,
// which is generated from the same schemas the server and the Mini App parse. Backends
// get it from here so they need no direct dependency on it.
pub use afklink_protocol::{InputMessage, Mods, WheelMode};

// The roles' vocabulary, for the window and the CLI: the role on each
// binding, and what a request to the owner is.
pub use afklink_protocol::{BindingRole, OwnerRequestKind, OwnerStateKind};
