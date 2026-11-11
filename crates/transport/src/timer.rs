//! The Windows timer resolution: raised to 1 ms while a WebRTC peer is live.
//!
//! ## Why the peer loop needs it
//!
//! The peer's run loop sleeps on tokio's timer (`PeerLoop::serve` in `webrtc.rs`). On Windows that
//! sleep wakes only on a clock interrupt — every 15.625 ms unless this process asks for more
//! (since Windows 10 2004 another process asking does not count) — so a 2 ms sleep lasts ~16 ms.
//!
//! Media does not mind: str0m's pacer lets a late wake catch up. **Probing does.** str0m sends a
//! probe cluster as bursts at most one per wake and at least 2 ms apart
//! (`str0m-0.23.1/src/bwe/probe/cluster.rs:244-292`) and measures it by its own spacing; released
//! once per 16 ms wake, a cluster meant to test 6 Mbps leaves at about 2/16 of that and measures
//! what it was sent at. Without a probe result the estimate only crawls up (goog-cc's increase
//! rule, bounded by 1.5x what was acknowledged), and the quality ladder waits at a lower rung.
//!
//! Measured on the bench (relayed through Cloudflare TURN, RTT ~150 ms, three runs each):
//!
//! | link | timer | best probe, first 10 s | time at 1080p@30 |
//! |---|---|---|---|
//! | clean | 15.6 ms tick | 3.6-4.8 Mbps | 10, 11, 40 s |
//! | clean | 1 ms | 10.9-16.7 Mbps | 7, 8, 10 s |
//! | 8 Mbps, 0.5% loss | 15.6 ms tick | 2.2-5.4 Mbps | 10, 17, 88 s |
//! | 8 Mbps, 0.5% loss | 1 ms | 6.9-7.1 Mbps | 7, 7, 9 s |
//!
//! CPU at 1080p@60 was the same either way (111% vs 110% of a core): at 60 fps the loop is woken
//! by media and the socket far more often than by its timer.
//!
//! ## Why a process-wide request, scoped to live peers
//!
//! `timeBeginPeriod(1)` rather than a high-resolution waitable timer: the loop's timer is tokio's,
//! and replacing it would add a cross-thread wake to every sleep of a loop that turns over a
//! thousand times a second. Scoped to live peers because a 1 kHz clock interrupt keeps an idle CPU
//! out of its deeper sleep states, and the desktop app sits in the tray all day. Each peer holds a
//! [`HighResolution`]; Windows reference-counts the requests. Windows 11 ignores the request from a
//! process whose windows are all hidden unless it opts out of that throttling; [`init_process`]
//! does, once at startup.
//!
//! `AFKLINK_TIMER_RESOLUTION=off` leaves the system default (for comparing on the bench);
//! `AFKLINK_TIMER_RESOLUTION=<n>` asks for `n` ms (1-15). Unset: 1 ms. Read once per process.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::OnceLock;

/// The environment variable that overrides the policy. See the module docs.
pub const ENV_VAR: &str = "AFKLINK_TIMER_RESOLUTION";

/// The period asked for while a peer is live, in milliseconds.
pub const DEFAULT_PERIOD_MS: u32 = 1;

/// The coarsest period the override accepts: the default tick is 15.625 ms, so anything above it
/// asks for nothing.
const MAX_PERIOD_MS: u32 = 15;

/// What this process does about the timer resolution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Policy {
    /// Leave the system default.
    Off,
    /// Ask for this many milliseconds while a peer is live.
    Raise(u32),
}

impl Policy {
    /// The policy an override value asks for, and a warning when the value was not understood.
    ///
    /// Blank counts as unset, like `RUST_LOG`: `set VAR=` in cmd leaves an empty variable behind.
    fn parse(value: Option<&str>) -> (Policy, Option<String>) {
        let Some(raw) = value.map(str::trim).filter(|v| !v.is_empty()) else {
            return (Policy::Raise(DEFAULT_PERIOD_MS), None);
        };
        let lower = raw.to_ascii_lowercase();
        if matches!(lower.as_str(), "off" | "default" | "system" | "0") {
            return (Policy::Off, None);
        }
        match lower.trim_end_matches("ms").trim().parse::<u32>() {
            Ok(ms) if (1..=MAX_PERIOD_MS).contains(&ms) => (Policy::Raise(ms), None),
            _ => (
                Policy::Raise(DEFAULT_PERIOD_MS),
                Some(format!(
                    "{ENV_VAR}={raw:?} is not off or a period of 1-{MAX_PERIOD_MS} ms; using \
                     {DEFAULT_PERIOD_MS} ms"
                )),
            ),
        }
    }
}

/// The policy, where it came from, and a warning about the override if it had to be ignored.
#[derive(Debug)]
struct Resolved {
    policy: Policy,
    source: String,
    warning: Option<String>,
}

fn resolved() -> &'static Resolved {
    static RESOLVED: OnceLock<Resolved> = OnceLock::new();
    RESOLVED.get_or_init(|| {
        let value = std::env::var(ENV_VAR).ok();
        let (policy, warning) = Policy::parse(value.as_deref());
        let source = match value.as_deref().map(str::trim).filter(|v| !v.is_empty()) {
            Some(v) => format!("{ENV_VAR}={v}"),
            None => "default".to_string(),
        };
        Resolved {
            policy,
            source,
            warning,
        }
    })
}

/// The policy in force for this process.
pub fn policy() -> Policy {
    resolved().policy
}

/// Live peers holding a [`HighResolution`] request, for the log's transitions.
static HOLDERS: AtomicU32 = AtomicU32::new(0);

/// Once, at startup, in both binaries: settle the policy, opt out of Windows 11's throttling of
/// timer requests from hidden windows when the policy raises the resolution, and log what is in
/// effect.
///
/// The `system` figure is the machine-wide one (`NtQueryTimerResolution`), often already 1 ms
/// because a browser asked for it. Since Windows 10 2004 that does not reach a process that did
/// not ask itself: on the bench the system read 1 ms while this process, not asking, still woke on
/// the 15.6 ms tick. What this process actually gets is the `timer_late` field of each session's
/// `egress` line.
pub fn init_process() {
    let r = resolved();
    if let Some(w) = &r.warning {
        tracing::warn!("{w}");
    }
    let system = sys::resolution();
    match r.policy {
        Policy::Off => tracing::info!(
            source = %r.source,
            system = %describe(system),
            "timer resolution: left at the system default; WebRTC peers do not raise it"
        ),
        Policy::Raise(ms) => {
            let throttling = match sys::honour_requests_when_hidden() {
                Ok(()) => "opted_out".to_string(),
                Err(e) => {
                    // Not fatal: the request still works while a window is visible, and always for
                    // a process without windows (the CLI). The session's `egress` line shows
                    // whether the wakes actually got finer.
                    tracing::warn!(
                        "timer resolution: could not opt out of Windows 11's throttling of timer \
                         requests from hidden windows ({e}); with every window hidden the request \
                         may be ignored"
                    );
                    format!("error: {e}")
                }
            };
            tracing::info!(
                period_ms = ms,
                source = %r.source,
                system = %describe(system),
                hidden_window_throttling = %throttling,
                "timer resolution: raised to period_ms while a WebRTC peer is live, system default \
                 otherwise"
            );
        }
    }
}

/// A live peer's request for the raised resolution. Dropping it withdraws the request.
#[derive(Debug)]
#[must_use = "the resolution is lowered again as soon as this is dropped"]
pub struct HighResolution {
    /// The period this request holds, or `None` when it holds nothing (policy off, or the request
    /// failed).
    period_ms: Option<u32>,
    who: &'static str,
}

impl HighResolution {
    /// The period this request holds, if any.
    pub fn period_ms(&self) -> Option<u32> {
        self.period_ms
    }
}

/// Ask for the raised resolution for as long as the returned value lives. `who` names the holder
/// in the log.
pub fn acquire(who: &'static str) -> HighResolution {
    let ms = match policy() {
        Policy::Off => {
            tracing::debug!(who, "timer resolution not raised: the policy is off");
            return HighResolution {
                period_ms: None,
                who,
            };
        }
        Policy::Raise(ms) => ms,
    };
    if let Err(e) = sys::begin(ms) {
        tracing::warn!(
            who,
            period_ms = ms,
            "timer resolution not raised ({e}): this peer's timer wakes stay at the system tick, \
             and its bandwidth probes measure low"
        );
        return HighResolution {
            period_ms: None,
            who,
        };
    }
    let holders = HOLDERS.fetch_add(1, Ordering::Relaxed) + 1;
    if holders == 1 {
        tracing::info!(
            who,
            period_ms = ms,
            system = %describe(sys::resolution()),
            "timer resolution raised for the first live peer"
        );
    } else {
        tracing::debug!(
            who,
            period_ms = ms,
            holders,
            "timer resolution request added"
        );
    }
    HighResolution {
        period_ms: Some(ms),
        who,
    }
}

impl Drop for HighResolution {
    fn drop(&mut self) {
        let Some(ms) = self.period_ms.take() else {
            return;
        };
        if let Err(e) = sys::end(ms) {
            // Windows keeps the request, so the resolution stays raised until the process exits:
            // a power cost, not a correctness problem.
            tracing::warn!(
                who = self.who,
                period_ms = ms,
                "timer resolution request not withdrawn ({e}); it stays raised until exit"
            );
        }
        let left = HOLDERS.fetch_sub(1, Ordering::Relaxed).saturating_sub(1);
        if left == 0 {
            tracing::info!(
                who = self.who,
                period_ms = ms,
                system = %describe(sys::resolution()),
                "timer resolution released: no live peer holds it"
            );
        } else {
            tracing::debug!(
                who = self.who,
                period_ms = ms,
                holders = left,
                "timer resolution request withdrawn; others still hold it"
            );
        }
    }
}

/// The system's timer resolution, in milliseconds: the coarsest and finest the hardware allows, and
/// the one in effect right now (the finest any process is asking for).
#[derive(Debug, Clone, Copy, PartialEq)]
struct Resolution {
    coarsest_ms: f64,
    finest_ms: f64,
    current_ms: f64,
}

fn describe(r: Option<Resolution>) -> String {
    match r {
        Some(r) => format!(
            "current={:.3}ms finest={:.3}ms coarsest={:.3}ms",
            r.current_ms, r.finest_ms, r.coarsest_ms
        ),
        None => "unknown".to_string(),
    }
}

#[cfg(windows)]
mod sys {
    use super::Resolution;
    use windows::Wdk::System::SystemInformation::NtQueryTimerResolution;
    use windows::Win32::Media::{timeBeginPeriod, timeEndPeriod};
    use windows::Win32::System::Threading::{
        GetCurrentProcess, ProcessPowerThrottling, SetProcessInformation,
        PROCESS_POWER_THROTTLING_CURRENT_VERSION, PROCESS_POWER_THROTTLING_IGNORE_TIMER_RESOLUTION,
        PROCESS_POWER_THROTTLING_STATE,
    };

    /// `TIMERR_NOERROR`.
    const TIMERR_NOERROR: u32 = 0;

    pub(super) fn begin(ms: u32) -> Result<(), String> {
        // SAFETY: plain value argument; no memory is shared with the callee.
        let r = unsafe { timeBeginPeriod(ms) };
        if r == TIMERR_NOERROR {
            Ok(())
        } else {
            Err(format!("timeBeginPeriod({ms}) returned {r}"))
        }
    }

    pub(super) fn end(ms: u32) -> Result<(), String> {
        // SAFETY: plain value argument; no memory is shared with the callee.
        let r = unsafe { timeEndPeriod(ms) };
        if r == TIMERR_NOERROR {
            Ok(())
        } else {
            Err(format!("timeEndPeriod({ms}) returned {r}"))
        }
    }

    pub(super) fn resolution() -> Option<Resolution> {
        let (mut coarsest, mut finest, mut current) = (0u32, 0u32, 0u32);
        // SAFETY: three valid, writable u32 locals, as the function expects.
        let status = unsafe { NtQueryTimerResolution(&mut coarsest, &mut finest, &mut current) };
        if !status.is_ok() {
            tracing::debug!(status = status.0, "NtQueryTimerResolution failed");
            return None;
        }
        // Units of 100 ns.
        let ms = |v: u32| f64::from(v) / 10_000.0;
        Some(Resolution {
            coarsest_ms: ms(coarsest),
            finest_ms: ms(finest),
            current_ms: ms(current),
        })
    }

    /// Opt out of the Windows 11 policy that ignores a hidden window-owner's timer requests: the
    /// control bit set with the state bit clear means "always honour them".
    pub(super) fn honour_requests_when_hidden() -> Result<(), String> {
        let state = PROCESS_POWER_THROTTLING_STATE {
            Version: PROCESS_POWER_THROTTLING_CURRENT_VERSION,
            ControlMask: PROCESS_POWER_THROTTLING_IGNORE_TIMER_RESOLUTION,
            StateMask: 0,
        };
        // SAFETY: `state` outlives the call and the size passed is its own; the pseudo-handle from
        // GetCurrentProcess needs no closing.
        unsafe {
            SetProcessInformation(
                GetCurrentProcess(),
                ProcessPowerThrottling,
                std::ptr::from_ref(&state).cast(),
                std::mem::size_of::<PROCESS_POWER_THROTTLING_STATE>() as u32,
            )
        }
        .map_err(|e| e.to_string())
    }
}

#[cfg(not(windows))]
mod sys {
    //! Elsewhere the scheduler's timers are already fine-grained; nothing to ask for.
    use super::Resolution;

    pub(super) fn begin(_ms: u32) -> Result<(), String> {
        Ok(())
    }

    pub(super) fn end(_ms: u32) -> Result<(), String> {
        Ok(())
    }

    pub(super) fn resolution() -> Option<Resolution> {
        None
    }

    pub(super) fn honour_requests_when_hidden() -> Result<(), String> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{Policy, DEFAULT_PERIOD_MS};

    #[test]
    fn unset_or_blank_raises_to_the_default_period() {
        assert_eq!(
            Policy::parse(None),
            (Policy::Raise(DEFAULT_PERIOD_MS), None)
        );
        assert_eq!(
            Policy::parse(Some("  ")),
            (Policy::Raise(DEFAULT_PERIOD_MS), None)
        );
    }

    #[test]
    fn off_and_its_spellings_leave_the_system_default() {
        for v in ["off", "OFF", "default", "system", "0", " off "] {
            assert_eq!(Policy::parse(Some(v)), (Policy::Off, None), "{v:?}");
        }
    }

    #[test]
    fn a_period_in_range_is_taken_as_asked() {
        assert_eq!(Policy::parse(Some("1")), (Policy::Raise(1), None));
        assert_eq!(Policy::parse(Some("4ms")), (Policy::Raise(4), None));
        assert_eq!(Policy::parse(Some("15")), (Policy::Raise(15), None));
    }

    #[test]
    fn nonsense_falls_back_to_the_default_with_a_warning() {
        for v in ["16", "fast", "-1", "1.5"] {
            let (p, w) = Policy::parse(Some(v));
            assert_eq!(p, Policy::Raise(DEFAULT_PERIOD_MS), "{v:?}");
            assert!(w.is_some_and(|w| w.contains(v)), "{v:?}");
        }
    }

    #[test]
    fn a_request_holds_the_period_the_policy_asks_for() {
        // On Windows this really calls timeBeginPeriod, and timeEndPeriod on the drop. The holder
        // count is not asserted: peers spawned by other tests in this binary hold it concurrently.
        let held = super::acquire("test");
        match super::policy() {
            Policy::Raise(ms) => assert_eq!(held.period_ms(), Some(ms)),
            Policy::Off => assert_eq!(held.period_ms(), None),
        }
        drop(held);
    }
}
