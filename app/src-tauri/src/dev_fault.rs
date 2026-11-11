//! A development build's fault on demand, so the orchestrator's end can be tried by hand (what
//! `crate::supervise` does about it): with
//!
//! ```text
//! AFKLINK_DEV_FAIL_ORCHESTRATOR_AFTER_S=<n>         the orchestrator returns an error n s after it starts
//! AFKLINK_DEV_FAIL_ORCHESTRATOR_AFTER_S=<n>:panic   it panics instead (`=panic` is read the same)
//! ```
//!
//! in the app's environment. A panic drops the orchestrator — the agent with its live sessions —
//! while unwinding, as a real panic on its worker does.
//!
//! Compiled into an app build only with the cargo feature `dev-fault` (`bun run portable
//! --dev-fault`), which no release build turns on: a release has no such path at all. A test build
//! compiles the module for its unit tests, without [`from_env`]. A `dev-fault` build still honours
//! the variable only on the development channel ([`Channel::Dev`]) and ignores it otherwise, saying
//! so at `warn`.

use std::future::Future;
use std::time::Duration;

use afklink_core::build_info::Channel;

/// The environment variable read ([`from_env`]).
pub(crate) const ENV: &str = "AFKLINK_DEV_FAIL_ORCHESTRATOR_AFTER_S";

/// How the orchestrator fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum How {
    /// `run` returns an error.
    Error,
    /// `run` panics.
    Panic,
}

/// The fault asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Fault {
    /// After how long from the orchestrator's start.
    pub(crate) after: Duration,
    pub(crate) how: How,
}

/// The fault [`ENV`] asks for, on a build of `channel`. Said either way, once (at the start).
#[cfg(feature = "dev-fault")]
pub(crate) fn from_env(channel: Channel) -> Option<Fault> {
    match std::env::var(ENV) {
        Ok(value) => armed(channel, Some(&value)),
        Err(std::env::VarError::NotPresent) => armed(channel, None),
        Err(std::env::VarError::NotUnicode(_)) => armed(channel, Some("<not unicode>")),
    }
}

/// The fault `value` (the variable's value, if set) asks for, on a build of `channel`.
pub(crate) fn armed(channel: Channel, value: Option<&str>) -> Option<Fault> {
    let Some(value) = value else {
        tracing::trace!(env = ENV, "dev fault: not asked for");
        return None;
    };
    if channel != Channel::Dev {
        tracing::warn!(
            env = ENV,
            value,
            %channel,
            "dev fault: ignored — only a development build fails its orchestrator on purpose"
        );
        return None;
    }
    let value = value.trim();
    let (secs, how) = match value.split_once([':', '=', ',']) {
        Some((secs, how)) => (secs.trim(), how.trim()),
        None => (value, "error"),
    };
    let how = match how.to_ascii_lowercase().as_str() {
        "error" => How::Error,
        "panic" => How::Panic,
        other => {
            tracing::warn!(
                env = ENV,
                value,
                "dev fault: not armed — {other:?} is neither `error` nor `panic`"
            );
            return None;
        }
    };
    let after = match secs.parse::<u64>() {
        Ok(secs) => Duration::from_secs(secs),
        Err(e) => {
            tracing::warn!(
                env = ENV,
                value,
                "dev fault: not armed — {secs:?} is no number of seconds ({e})"
            );
            return None;
        }
    };
    let fault = Fault { after, how };
    tracing::warn!(
        env = ENV,
        after_s = after.as_secs(),
        how = ?fault.how,
        "dev fault: ARMED — the orchestrator will fail on purpose after {} s (a development \
         build's test of its supervision)",
        after.as_secs()
    );
    Some(fault)
}

/// `run`, failing as `fault` says once its time is up (nothing changes without one). Its error,
/// when it returns one of its own, is kept with its chain (`{:#}`).
#[allow(
    clippy::panic,
    reason = "the panic is the fault asked for by hand, in a development build only"
)]
pub(crate) async fn run_with<F, E>(run: F, fault: Option<Fault>) -> Result<(), String>
where
    F: Future<Output = Result<(), E>>,
    E: std::fmt::Display,
{
    let Some(fault) = fault else {
        return run.await.map_err(|e| format!("{e:#}"));
    };
    let mut run = std::pin::pin!(run);
    tokio::select! {
        ended = &mut run => {
            tracing::info!(
                env = ENV,
                "dev fault: the orchestrator ended before its fault was due; not fired"
            );
            return ended.map_err(|e| format!("{e:#}"));
        }
        () = tokio::time::sleep(fault.after) => {}
    }
    match fault.how {
        How::Panic => {
            tracing::warn!(
                env = ENV,
                after_s = fault.after.as_secs(),
                "dev fault: FIRED — the orchestrator panics now (its future dropped while unwinding)"
            );
            // `run`, still alive here, is dropped while this panic unwinds.
            panic!("{ENV}: the orchestrator panics on purpose (a development build's fault)");
        }
        How::Error => {
            tracing::warn!(
                env = ENV,
                after_s = fault.after.as_secs(),
                "dev fault: FIRED — the orchestrator returns an error now"
            );
            Err(format!(
                "{ENV}: the orchestrator fails on purpose (a development build's fault)"
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    /// Compiled into the app only behind the feature: `lib.rs` declares the module under
    /// `cfg(any(test, feature = "dev-fault"))`, and each line of its that calls into it is in a
    /// block under `cfg(feature = "dev-fault")`, so a build without the feature has no such path.
    #[test]
    fn the_fault_is_compiled_in_only_behind_the_feature() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let lib = std::fs::read_to_string(root.join("src/lib.rs")).expect("lib.rs");
        let lines: Vec<&str> = lib.lines().collect();
        let mut declared = 0;
        let mut calls = 0;
        for (n, line) in lines.iter().enumerate() {
            let code = line.split("//").next().unwrap_or_default().trim();
            // The nearest attribute above, past doc comments, comments and the block's opening.
            let attribute = || {
                lines[..n]
                    .iter()
                    .rev()
                    .map(|l| l.trim())
                    .find(|l| l.starts_with("#["))
                    .unwrap_or_default()
            };
            if code == "mod dev_fault;" {
                declared += 1;
                assert_eq!(
                    attribute(),
                    "#[cfg(any(test, feature = \"dev-fault\"))]",
                    "lib.rs:{}",
                    n + 1
                );
            } else if code.contains("dev_fault::") {
                calls += 1;
                assert_eq!(
                    attribute(),
                    "#[cfg(feature = \"dev-fault\")]",
                    "lib.rs:{}: {line}",
                    n + 1
                );
            }
        }
        assert_eq!(
            (declared, calls),
            (1, 2),
            "the module, from_env and run_with"
        );
    }

    /// A release build ignores the variable, whatever it says; a development build reads it.
    #[test]
    fn a_release_build_ignores_the_fault() {
        for value in ["5", "5:panic", "0=panic"] {
            assert_eq!(armed(Channel::Release, Some(value)), None, "{value}");
        }
        assert_eq!(armed(Channel::Dev, None), None);
        assert_eq!(
            armed(Channel::Dev, Some(" 5 ")),
            Some(Fault {
                after: Duration::from_secs(5),
                how: How::Error
            })
        );
        for value in ["5:panic", "5=PANIC", "5, panic"] {
            assert_eq!(
                armed(Channel::Dev, Some(value)),
                Some(Fault {
                    after: Duration::from_secs(5),
                    how: How::Panic
                }),
                "{value}"
            );
        }
        for bad in ["", "soon", "5:explode", "-1", "<not unicode>"] {
            assert_eq!(armed(Channel::Dev, Some(bad)), None, "{bad:?}");
        }
    }

    /// Never ends; notes its drop.
    struct Forever(Arc<AtomicBool>);
    impl Future for Forever {
        type Output = Result<(), String>;
        fn poll(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Self::Output> {
            std::task::Poll::Pending
        }
    }
    impl Drop for Forever {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    /// Fired: an error returned, or a panic during which the orchestrator's future is dropped; no
    /// fault: the run's own end. Every wait bounded.
    /// `f` spawned on `rt` and awaited, within 10 s.
    fn within<F>(
        rt: &tokio::runtime::Runtime,
        f: F,
    ) -> Result<Result<(), String>, tokio::task::JoinError>
    where
        F: Future<Output = Result<(), String>> + Send + 'static,
    {
        rt.block_on(async { tokio::time::timeout(Duration::from_secs(10), tokio::spawn(f)).await })
            .expect("in time")
    }

    #[test]
    fn a_fault_fires_after_its_time_as_an_error_or_a_panic() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let error = Fault {
            after: Duration::from_millis(10),
            how: How::Error,
        };
        let dropped = Arc::new(AtomicBool::new(false));
        let ended = within(&rt, run_with(Forever(Arc::clone(&dropped)), Some(error)));
        assert!(ended.expect("no panic").is_err());
        assert!(dropped.load(Ordering::SeqCst));

        let panic = Fault {
            how: How::Panic,
            ..error
        };
        let dropped = Arc::new(AtomicBool::new(false));
        let ended = within(&rt, run_with(Forever(Arc::clone(&dropped)), Some(panic)));
        assert!(ended.expect_err("it panicked").is_panic());
        assert!(dropped.load(Ordering::SeqCst), "dropped while unwinding");

        let ended = within(
            &rt,
            run_with(std::future::ready(Err::<(), _>("its own")), Some(error)),
        );
        assert_eq!(ended.expect("no panic"), Err("its own".to_string()));
        let ended = within(
            &rt,
            run_with(std::future::ready(Ok::<(), String>(())), None),
        );
        assert_eq!(ended.expect("no panic"), Ok(()));
    }
}
