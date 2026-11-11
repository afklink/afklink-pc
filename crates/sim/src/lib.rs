//! An offline, virtual-time simulator of a remote-desktop session.
//!
//! Real frames (synthetic for now, recorded later) go through the real capture pacing, the real
//! OpenH264 encoder, the real encode-loop decisions and the real `QualityController`, into the real
//! str0m configured as the agent configures it, across a modelled network, into a second str0m
//! standing in for the viewer's Chrome — whose feedback, receiver reports, NACKs and PLIs come back
//! the same way. Everything runs on one virtual clock, so a minute of session takes a fraction of
//! that in wall time and a scenario with a seed produces the same session every time.
//!
//! The point is counterfactuals. The `ladder_replay` example feeds recorded per-second numbers to
//! the controller, and those numbers were produced by whatever the controller did at the time; a
//! different rung or budget would have produced different bytes and a different estimate, which a
//! replay cannot show and this can.
//!
//! ## Layout
//!
//! | module | what |
//! |---|---|
//! | [`clock`] | virtual time, the str0m wall-clock audit, the log timer |
//! | [`rng`] | the simulator's own seeded generator |
//! | [`link`] | one direction of the path: capacity schedule, drop-tail queue, loss, delay, jitter |
//! | [`source`] | the [`source::FrameSource`] trait (the corpus adapter point) and a scripted desktop |
//! | [`encode_loop`] | capture pacing and the encode loop, restated with time injected |
//! | [`transport`] | the agent's str0m peer and run-loop accounting |
//! | [`viewer`] | the viewer's str0m peer, with Chrome's keyframe-request behaviour |
//! | [`datachannel`] | the viewer's `vv` report of the frames it received, over an SCTP-like window |
//! | [`control`] | the control task: `Feedback`, the controller, the `pipeline` line |
//! | [`metrics`] | delivery timing, freezes, latency, the summary |
//! | [`scenario`] | scenario files |
//! | [`sim`] | the event loop |
//! | [`report`] | the summary table |
//!
//! Every place that restates production code names its source lines; the module docs of
//! [`encode_loop`], [`transport`] and [`control`] list them for the deduplication that should
//! follow once `agent.rs` and `webrtc.rs` are free.

pub mod clock;
pub mod control;
pub mod datachannel;
pub mod encode_loop;
pub mod link;
pub mod metrics;
pub mod report;
pub mod rng;
pub mod scenario;
pub mod sim;
pub mod source;
pub mod transport;
pub mod viewer;

pub use afklink_core::quality::QualityPolicy;
pub use scenario::Scenario;
pub use sim::{RunOutput, Simulation};
pub use source::{FrameSource, TimedFrame};

/// Load, build and run one scenario file, on the reference profile ([`reference_policy`]).
pub fn run_file(path: &std::path::Path) -> anyhow::Result<RunOutput> {
    run_file_with(path, reference_policy()?)
}

/// [`run_file`] on `policy`.
pub fn run_file_with(path: &std::path::Path, policy: QualityPolicy) -> anyhow::Result<RunOutput> {
    let scenario = Scenario::load(path)?;
    Simulation::with_policy(scenario, policy)?.run()
}

/// The profile a simulation runs on unless told otherwise: the contract's reference vector (the
/// tuning the server sends as `default`), read from the repository at run time — the agent's
/// binary carries only its conservative fallback.
pub fn reference_policy() -> anyhow::Result<QualityPolicy> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(afklink_core::quality_policy::REFERENCE_VECTOR);
    afklink_core::quality_policy::load_profile_file(&path)
        .map(|p| p.policy)
        .map_err(|e| {
            anyhow::anyhow!("the reference profile: {e} (the contract submodule checked out?)")
        })
}

/// A profile named on a command line: `builtin` for the agent's compiled fallback
/// ([`QualityPolicy::fallback`]), `reference` for [`reference_policy`], else a profile file
/// (`{id, v, values}`), checked as the agent checks a server's.
pub fn profile_from_arg(arg: &str) -> anyhow::Result<(String, QualityPolicy)> {
    match arg {
        "builtin" => Ok((
            afklink_core::quality_policy::FALLBACK_LABEL.to_string(),
            QualityPolicy::fallback(),
        )),
        "reference" => Ok((
            "default.v1 (reference vector)".to_string(),
            reference_policy()?,
        )),
        path => afklink_core::quality_policy::load_profile_file(std::path::Path::new(path))
            .map(|p| (p.label(), p.policy))
            .map_err(|e| anyhow::anyhow!(e)),
    }
}
