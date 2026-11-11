//! Scenario files (TOML): what is on screen, what the network does, for how long, with what seed.
//!
//! ```toml
//! name = "wifi-0924"        # optional, defaults to the file name
//! duration_s = 90
//! seed = 1
//!
//! [content]                 # see `crate::source::ContentSpec`
//! kind = "desktop"
//! [[content.phases]]
//! kind = "typing"
//! secs = 3.0
//! cps = 6.0
//!
//! [link]
//! rtt_ms = 136              # split evenly between directions unless a direction sets delay_ms
//! [link.up]                 # agent -> viewer
//! kbps = 10000              # or: schedule = [[0, 10000], [30, 700]]  (seconds, kbps)
//!                           # or: trace = "traces/x.up" (Mahimahi, relative to this file)
//! queue_ms = 300            # or queue_bytes; neither is an unlimited queue
//! loss = 0.0                # Bernoulli; or gilbert = { p_good_to_bad, p_bad_to_good, loss_good, loss_bad }
//! jitter_ms = 0
//! delay_schedule = [[30, 230]]  # (seconds into the session, one-way ms): the path's delay steps
//!                               # there, as a VPN or a relay changing route does
//! [link.down]               # viewer -> agent; defaults to an uncongested 10 Mbps
//!
//! [viewer]                  # see `crate::viewer::ViewerConfig`
//! rr_interval_ms = 1000
//! keyframe_at_s = [20, 40]  # the Mini App's `kf` requests, seconds into the session
//! pin_height = 1080         # the viewer's resolution pin (1080, 720, 540 or 360), from the start
//! hidden = [[20, 620]]      # the viewer's page hidden from 20 s to 620 s (its `vis`): the
//!                           # agent's background hold, its 10 s grace included
//! asleep_when_hidden = true # the page sleeps while hidden, as an iPhone's WebView does: see
//!                           # `AsleepViewer`
//! wake_before_visible_ms = 800  # it wakes this long before its `vis hidden: false` arrives
//! asleep_backlog = "buffer" # what reaches it asleep waits for it (a relay over TCP), or "drop"
//! stale_rtt_ms = 11000      # the round trip its first report after waking carries; 0 for none
//! str0m = "0.23.1"          # the viewer's str0m, "0.23.1" or "0.24.1"; without it
//!                           # AFKLINK_SIM_VIEWER_STR0M, then the default (`crate::viewer::ViewerStr0m`)
//!
//! [sender]
//! timer_resolution_ms = 1     # the run loop's timer granularity; 15.625 is the Windows tick
//! reanchor = "capped"         # ResetBwe as the agent applies it (`webrtc::reanchor_bwe`), or
//!                             # "reset": a bare str0m reset, with its 3x/6x opening probes
//! keyframe_window = true      # the viewer's PLIs held against the keyframe already on its way,
//!                             # as the agent does (`afklink_core::keyframe_window`); false: every
//!                             # PLI forces a keyframe
//!
//! [encoder]
//! threads = 0               # 0: the production choice (half the cores, at most 4)
//! ```

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result};
use serde::Deserialize;

use crate::encode_loop::EncodeCost;
use crate::link::{parse_mahimahi, Capacity, LinkConfig, Loss, LossAt, QueueLimit};
use crate::source::ContentSpec;
use crate::transport::{ReanchorMode, SenderConfig};
use crate::viewer::{ViewerConfig, ViewerStr0m};

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawScenario {
    name: Option<String>,
    duration_s: f64,
    #[serde(default = "one")]
    seed: u64,
    content: ContentSpec,
    #[serde(default)]
    link: RawLink,
    #[serde(default)]
    viewer: RawViewer,
    #[serde(default)]
    sender: RawSender,
    #[serde(default)]
    encoder: RawEncoder,
}

fn one() -> u64 {
    1
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawLink {
    rtt_ms: Option<f64>,
    #[serde(default)]
    up: RawDirection,
    #[serde(default)]
    down: RawDirection,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawDirection {
    kbps: Option<f64>,
    schedule: Option<Vec<(f64, f64)>>,
    trace: Option<String>,
    trace_bytes: Option<u32>,
    delay_ms: Option<f64>,
    queue_ms: Option<f64>,
    queue_bytes: Option<u64>,
    loss: Option<f64>,
    gilbert: Option<RawGilbert>,
    jitter_ms: Option<f64>,
    reorder: Option<bool>,
    overhead_bytes: Option<u32>,
    delay_schedule: Option<Vec<(f64, f64)>>,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawGilbert {
    p_good_to_bad: f64,
    p_bad_to_good: f64,
    #[serde(default)]
    loss_good: f64,
    #[serde(default = "full")]
    loss_bad: f64,
}

fn full() -> f64 {
    1.0
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawViewer {
    rr_interval_ms: Option<f64>,
    nack: Option<bool>,
    pli_on_gap: Option<bool>,
    pli_repeat_ms: Option<f64>,
    keyframe_at_s: Option<Vec<f64>>,
    pin_height: Option<u32>,
    hidden: Option<Vec<(f64, f64)>>,
    asleep_when_hidden: Option<bool>,
    wake_before_visible_ms: Option<f64>,
    asleep_backlog: Option<String>,
    stale_rtt_ms: Option<f64>,
    str0m: Option<String>,
}

/// What reaches a sleeping viewer. See [`AsleepViewer`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backlog {
    /// Held and delivered all at once when it wakes: a TURN relay over TCP (an iPhone viewer on
    /// `relay/tcp`) keeps what it could not hand over.
    Buffer,
    /// Lost: a UDP path to a suspended socket.
    Drop,
}

/// A viewer whose page sleeps while it is hidden — the iPhone's WebView, as recorded:
/// from the moment the page is hidden it sends nothing at all, no receiver report, no
/// transport-wide feedback, no answer to ICE consent; it takes nothing in either. It wakes a little
/// before its `vis hidden: false` reaches the agent (ICE first: 0.8 and 1.5 s in the recording),
/// takes in what waited for it, and its first receiver report reads the time it slept as round trip
/// — its clock did not run while it was suspended (10993 and 19668 ms in the recording).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AsleepViewer {
    pub wake_before_visible: Duration,
    pub backlog: Backlog,
    /// The round trip of the first receiver report after waking, in ms; `None` for none.
    pub stale_rtt_ms: Option<u32>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSender {
    timer_resolution_ms: Option<f64>,
    reanchor: Option<String>,
    keyframe_window: Option<bool>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawEncoder {
    threads: Option<u16>,
    base_ms: Option<f64>,
    per_mpx_ms: Option<f64>,
    keyframe_factor: Option<f64>,
}

/// A validated scenario, ready to run.
#[derive(Debug, Clone)]
pub struct Scenario {
    pub name: String,
    pub duration: Duration,
    pub seed: u64,
    pub content: ContentSpec,
    pub up: LinkConfig,
    pub down: LinkConfig,
    /// Where each direction's one-way delay steps, in order: `(when, from the start of the session;
    /// the new delay)`. Applied with `Link::reconfigure`, so packets already on the path keep their
    /// timing, as they do when a route changes under them.
    pub up_delay_steps: Vec<(Duration, Duration)>,
    pub down_delay_steps: Vec<(Duration, Duration)>,
    pub viewer: ViewerConfig,
    /// When the viewer asks for a keyframe over the data channel, measured from the start of the
    /// session, in order: the Mini App's `kf` request, which its render watchdog sends when a frame
    /// is decoded but not shown, and which WebKit sends where Chrome would send a PLI
    /// (`core/src/viewer_report.rs`, `keyframe_request`). Not part of [`ViewerConfig`], which is a
    /// `Copy` of per-packet behaviour; these are one-off events a scenario scripts.
    pub keyframe_requests: Vec<Duration>,
    /// The resolution the viewer pinned from the start of the session, as an encoded height, or
    /// `None` for the automatic ladder: the ladder is then that height at falling frame rates
    /// (`QualityController::set_pinned_height`), which never pays a keyframe to give way.
    pub pin_height: Option<u32>,
    /// When the viewer's page is hidden, as `(from, to)` seconds into the session, in order and not
    /// overlapping: the viewer's `vis hidden: true` at `from` and `hidden: false` at `to`, fed to the
    /// agent's own hold cell (`afklink_core::bg_hold`) — its grace, its hold, its resume. See
    /// `crate::sim`, the background hold.
    pub hidden: Vec<(Duration, Duration)>,
    /// Whether the page sleeps while hidden, and how. See [`AsleepViewer`].
    pub asleep: Option<AsleepViewer>,
    pub sender: SenderConfig,
    /// `0` is the production encoder (`OpenH264Encoder::with_defaults`).
    pub encoder_threads: u16,
    pub encode_cost: EncodeCost,
}

fn ms(v: f64, what: &str) -> Result<Duration> {
    anyhow::ensure!(
        v.is_finite() && v >= 0.0,
        "{what} must be a non-negative number, got {v}"
    );
    Ok(Duration::from_secs_f64(v / 1e3))
}

fn probability(v: f64, what: &str) -> Result<f64> {
    anyhow::ensure!(
        (0.0..=1.0).contains(&v),
        "{what} must be in [0, 1], got {v}"
    );
    Ok(v)
}

impl RawDirection {
    /// The direction's `delay_schedule`, validated: non-negative, finite, in time order.
    fn delay_steps(&self, which: &str) -> Result<Vec<(Duration, Duration)>> {
        let mut out = Vec::new();
        for (t, d) in self.delay_schedule.as_deref().unwrap_or_default() {
            anyhow::ensure!(
                t.is_finite() && *t >= 0.0,
                "link.{which}.delay_schedule: bad time {t}"
            );
            out.push((
                Duration::from_secs_f64(*t),
                ms(*d, &format!("link.{which}.delay_schedule delay"))?,
            ));
        }
        anyhow::ensure!(
            out.windows(2).all(|w| w[0].0 <= w[1].0),
            "link.{which}.delay_schedule must be in time order"
        );
        Ok(out)
    }

    fn build(&self, default_delay: Duration, base: &Path, which: &str) -> Result<LinkConfig> {
        let given = [
            self.kbps.is_some(),
            self.schedule.is_some(),
            self.trace.is_some(),
        ]
        .iter()
        .filter(|g| **g)
        .count();
        anyhow::ensure!(
            given <= 1,
            "link.{which}: give at most one of kbps, schedule, trace"
        );
        let capacity = if let Some(steps) = &self.schedule {
            anyhow::ensure!(!steps.is_empty(), "link.{which}.schedule is empty");
            let mut out = Vec::with_capacity(steps.len());
            for (t, kbps) in steps {
                anyhow::ensure!(
                    t.is_finite() && *t >= 0.0 && kbps.is_finite() && *kbps >= 0.0,
                    "link.{which}.schedule: bad step [{t}, {kbps}]"
                );
                out.push((Duration::from_secs_f64(*t), *kbps));
            }
            anyhow::ensure!(
                out.windows(2).all(|w| w[0].0 <= w[1].0),
                "link.{which}.schedule must be in time order"
            );
            Capacity::Piecewise { steps: out }
        } else if let Some(trace) = &self.trace {
            let path = base.join(trace);
            let text = std::fs::read_to_string(&path)
                .with_context(|| format!("link.{which}.trace: read {}", path.display()))?;
            Capacity::Trace {
                opportunities_ms: parse_mahimahi(&text)
                    .with_context(|| format!("link.{which}.trace {}", path.display()))?,
                bytes_per_opportunity: self.trace_bytes.unwrap_or(1500),
            }
        } else {
            let kbps = self.kbps.unwrap_or(10_000.0);
            anyhow::ensure!(
                kbps.is_finite() && kbps > 0.0,
                "link.{which}.kbps must be positive, got {kbps}"
            );
            Capacity::Constant { kbps }
        };
        anyhow::ensure!(
            !(self.queue_ms.is_some() && self.queue_bytes.is_some()),
            "link.{which}: give queue_ms or queue_bytes, not both"
        );
        let queue = match (self.queue_ms, self.queue_bytes) {
            (Some(q), _) => QueueLimit::Delay(ms(q, "queue_ms")?),
            (_, Some(b)) => QueueLimit::Bytes(b),
            _ => QueueLimit::Unlimited,
        };
        anyhow::ensure!(
            !(self.loss.is_some() && self.gilbert.is_some()),
            "link.{which}: give loss or gilbert, not both"
        );
        let loss = match (self.loss, self.gilbert) {
            (_, Some(g)) => Loss::GilbertElliott {
                p_good_to_bad: probability(g.p_good_to_bad, "p_good_to_bad")?,
                p_bad_to_good: probability(g.p_bad_to_good, "p_bad_to_good")?,
                loss_good: probability(g.loss_good, "loss_good")?,
                loss_bad: probability(g.loss_bad, "loss_bad")?,
            },
            (Some(p), _) => {
                let p = probability(p, "loss")?;
                if p > 0.0 {
                    Loss::Bernoulli { p }
                } else {
                    Loss::None
                }
            }
            _ => Loss::None,
        };
        Ok(LinkConfig {
            capacity,
            delay: match self.delay_ms {
                Some(d) => ms(d, "delay_ms")?,
                None => default_delay,
            },
            queue,
            loss,
            // `mm-loss` in front of `mm-link`, as the simulator has always modelled it.
            loss_at: LossAt::Arrival,
            jitter: ms(self.jitter_ms.unwrap_or(0.0), "jitter_ms")?,
            reorder: self.reorder.unwrap_or(false),
            overhead_bytes: self.overhead_bytes.unwrap_or(28),
        })
    }
}

impl Scenario {
    /// Parse a scenario. `base` resolves relative trace paths; `fallback_name` names it when the
    /// file does not.
    pub fn parse(text: &str, base: &Path, fallback_name: &str) -> Result<Self> {
        let raw: RawScenario = toml::from_str(text).context("scenario TOML")?;
        anyhow::ensure!(
            raw.duration_s.is_finite() && raw.duration_s > 0.0,
            "duration_s must be positive"
        );
        let rtt = ms(raw.link.rtt_ms.unwrap_or(40.0), "link.rtt_ms")?;
        let half = rtt / 2;
        let up = raw.link.up.build(half, base, "up")?;
        let down = raw.link.down.build(half, base, "down")?;
        let up_delay_steps = raw.link.up.delay_steps("up")?;
        let down_delay_steps = raw.link.down.delay_steps("down")?;
        let d = ViewerConfig::default();
        let viewer = ViewerConfig {
            rr_interval: match raw.viewer.rr_interval_ms {
                Some(v) => ms(v, "viewer.rr_interval_ms")?,
                None => d.rr_interval,
            },
            nack: raw.viewer.nack.unwrap_or(d.nack),
            pli_on_gap: raw.viewer.pli_on_gap.unwrap_or(d.pli_on_gap),
            pli_repeat: match raw.viewer.pli_repeat_ms {
                Some(v) => ms(v, "viewer.pli_repeat_ms")?,
                None => d.pli_repeat,
            },
            str0m: ViewerStr0m::resolve(raw.viewer.str0m.as_deref()).context("viewer.str0m")?,
        };
        anyhow::ensure!(
            viewer.rr_interval >= Duration::from_millis(10),
            "viewer.rr_interval_ms must be at least 10"
        );
        let mut keyframe_requests = Vec::new();
        for s in raw.viewer.keyframe_at_s.as_deref().unwrap_or_default() {
            keyframe_requests.push(ms(s * 1e3, "viewer.keyframe_at_s")?);
        }
        anyhow::ensure!(
            keyframe_requests.windows(2).all(|w| w[0] <= w[1]),
            "viewer.keyframe_at_s must be in time order"
        );
        if let Some(h) = raw.viewer.pin_height {
            anyhow::ensure!(
                afklink_core::quality::PINNABLE_HEIGHTS.contains(&h),
                "viewer.pin_height must be one of {:?}, got {h}",
                afklink_core::quality::PINNABLE_HEIGHTS
            );
        }
        let mut hidden = Vec::new();
        for (from, to) in raw.viewer.hidden.as_deref().unwrap_or_default() {
            let (from, to) = (
                ms(from * 1e3, "viewer.hidden start")?,
                ms(to * 1e3, "viewer.hidden end")?,
            );
            anyhow::ensure!(
                from < to,
                "viewer.hidden: each window ends after it starts, got [{}, {}]",
                from.as_secs_f64(),
                to.as_secs_f64()
            );
            hidden.push((from, to));
        }
        anyhow::ensure!(
            hidden.windows(2).all(|w| w[0].1 <= w[1].0),
            "viewer.hidden windows must be in time order and not overlap"
        );
        let asleep = if raw.viewer.asleep_when_hidden.unwrap_or(false) {
            Some(AsleepViewer {
                wake_before_visible: ms(
                    raw.viewer.wake_before_visible_ms.unwrap_or(800.0),
                    "viewer.wake_before_visible_ms",
                )?,
                backlog: match raw.viewer.asleep_backlog.as_deref() {
                    None | Some("buffer") => Backlog::Buffer,
                    Some("drop") => Backlog::Drop,
                    Some(other) => anyhow::bail!(
                        "viewer.asleep_backlog must be \"buffer\" or \"drop\", not {other:?}"
                    ),
                },
                stale_rtt_ms: {
                    let v = raw.viewer.stale_rtt_ms.unwrap_or(11_000.0);
                    anyhow::ensure!(
                        v.is_finite() && v >= 0.0,
                        "viewer.stale_rtt_ms must be a non-negative number, got {v}"
                    );
                    (v >= 1.0).then_some(v as u32)
                },
            })
        } else {
            anyhow::ensure!(
                raw.viewer.wake_before_visible_ms.is_none()
                    && raw.viewer.asleep_backlog.is_none()
                    && raw.viewer.stale_rtt_ms.is_none(),
                "viewer: wake_before_visible_ms, asleep_backlog and stale_rtt_ms need \
                 asleep_when_hidden = true"
            );
            None
        };
        let sender = SenderConfig {
            timer_resolution: match raw.sender.timer_resolution_ms {
                Some(v) => ms(v, "sender.timer_resolution_ms")?,
                None => SenderConfig::default().timer_resolution,
            },
            reanchor: match raw.sender.reanchor.as_deref() {
                None => SenderConfig::default().reanchor,
                Some("capped") => ReanchorMode::Capped,
                Some("reset") => ReanchorMode::BareReset,
                Some(other) => {
                    anyhow::bail!("sender.reanchor must be \"capped\" or \"reset\", not {other:?}")
                }
            },
            keyframe_window: raw
                .sender
                .keyframe_window
                .unwrap_or(SenderConfig::default().keyframe_window),
        };
        let c = EncodeCost::default();
        let encode_cost = EncodeCost {
            base: match raw.encoder.base_ms {
                Some(v) => ms(v, "encoder.base_ms")?,
                None => c.base,
            },
            per_mpx: match raw.encoder.per_mpx_ms {
                Some(v) => ms(v, "encoder.per_mpx_ms")?,
                None => c.per_mpx,
            },
            keyframe_factor: raw.encoder.keyframe_factor.unwrap_or(c.keyframe_factor),
        };
        Ok(Self {
            name: raw.name.unwrap_or_else(|| fallback_name.to_string()),
            duration: Duration::from_secs_f64(raw.duration_s),
            seed: raw.seed,
            content: raw.content,
            up,
            down,
            up_delay_steps,
            down_delay_steps,
            viewer,
            keyframe_requests,
            pin_height: raw.viewer.pin_height,
            hidden,
            asleep,
            sender,
            encoder_threads: raw.encoder.threads.unwrap_or(0),
            encode_cost,
        })
    }

    /// Load a scenario file.
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("read scenario {}", path.display()))?;
        let base = path.parent().map_or_else(PathBuf::new, Path::to_path_buf);
        let stem = path.file_stem().map_or_else(
            || "scenario".to_string(),
            |s| s.to_string_lossy().into_owned(),
        );
        Self::parse(&text, &base, &stem).with_context(|| format!("scenario {}", path.display()))
    }
}

/// Every `*.toml` under `path` (not recursive), sorted, or `path` itself if it is a file.
pub fn collect(path: &Path) -> Result<Vec<PathBuf>> {
    if path.is_dir() {
        let mut out: Vec<PathBuf> = std::fs::read_dir(path)
            .with_context(|| format!("read directory {}", path.display()))?
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.extension().is_some_and(|x| x == "toml"))
            .collect();
        out.sort();
        anyhow::ensure!(!out.is_empty(), "no .toml scenarios in {}", path.display());
        Ok(out)
    } else {
        Ok(vec![path.to_path_buf()])
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::Scenario;
    use crate::link::{Capacity, Loss, QueueLimit};
    use std::path::Path;
    use std::time::Duration;

    #[test]
    fn a_full_scenario_parses() {
        let s = Scenario::parse(
            r#"
            duration_s = 30
            seed = 7
            [content]
            kind = "desktop"
            [[content.phases]]
            kind = "typing"
            secs = 2
            cps = 5
            [[content.phases]]
            kind = "scroll"
            secs = 0.5
            px_per_frame = 120
            [link]
            rtt_ms = 136
            [link.up]
            kbps = 700
            queue_ms = 80
            gilbert = { p_good_to_bad = 0.01, p_bad_to_good = 0.3 }
            delay_schedule = [[12.5, 150]]
            [link.down]
            schedule = [[0, 1000], [10, 500]]
            delay_ms = 20
            [viewer]
            nack = false
            keyframe_at_s = [2.5, 10]
            pin_height = 720
            hidden = [[3, 14.5], [20, 25]]
            asleep_when_hidden = true
            wake_before_visible_ms = 500
            asleep_backlog = "drop"
            stale_rtt_ms = 0
            str0m = "0.24.1"
            [sender]
            timer_resolution_ms = 0
            reanchor = "reset"
            keyframe_window = false
            "#,
            Path::new("."),
            "x",
        )
        .unwrap();
        assert_eq!(s.name, "x");
        assert_eq!(s.seed, 7);
        assert_eq!(s.up.delay, Duration::from_millis(68));
        assert_eq!(s.down.delay, Duration::from_millis(20));
        assert!(
            matches!(s.up.capacity, Capacity::Constant { kbps } if (kbps - 700.0).abs() < 1e-9)
        );
        assert_eq!(s.up.queue, QueueLimit::Delay(Duration::from_millis(80)));
        assert!(
            matches!(s.up.loss, Loss::GilbertElliott { loss_bad, .. } if (loss_bad - 1.0).abs() < 1e-9)
        );
        assert!(matches!(s.down.capacity, Capacity::Piecewise { ref steps } if steps.len() == 2));
        assert!(!s.viewer.nack);
        assert_eq!(s.viewer.str0m, crate::viewer::ViewerStr0m::V0_24);
        assert_eq!(
            s.keyframe_requests,
            vec![Duration::from_millis(2_500), Duration::from_secs(10)]
        );
        assert_eq!(s.pin_height, Some(720));
        assert_eq!(
            s.hidden,
            vec![
                (Duration::from_secs(3), Duration::from_millis(14_500)),
                (Duration::from_secs(20), Duration::from_secs(25))
            ]
        );
        assert_eq!(
            s.asleep,
            Some(super::AsleepViewer {
                wake_before_visible: Duration::from_millis(500),
                backlog: super::Backlog::Drop,
                stale_rtt_ms: None,
            })
        );
        assert_eq!(
            s.up_delay_steps,
            vec![(Duration::from_millis(12_500), Duration::from_millis(150))]
        );
        assert!(s.down_delay_steps.is_empty());
        assert_eq!(s.sender.timer_resolution, Duration::ZERO);
        assert_eq!(s.sender.reanchor, crate::transport::ReanchorMode::BareReset);
        assert!(!s.sender.keyframe_window);
        // And on unless a scenario turns it off, as the agent has it.
        let base = "duration_s = 5\n[content]\nkind = \"static\"\n";
        assert!(
            Scenario::parse(base, Path::new("."), "x")
                .unwrap()
                .sender
                .keyframe_window
        );
    }

    #[test]
    fn mistakes_are_refused() {
        let base = "duration_s = 5\n[content]\nkind = \"static\"\n";
        assert!(Scenario::parse(base, Path::new("."), "x").is_ok());
        for bad in [
            "[link.up]\nkbps = 1\nschedule = [[0, 1]]\n",
            "[link.up]\nqueue_ms = 1\nqueue_bytes = 1\n",
            "[link.up]\nloss = 2\n",
            "[link.up]\nkpbs = 1\n",
            "[sender]\nreanchor = \"sometimes\"\n",
            "[viewer]\nkeyframe_at_s = [10, 5]\n",
            "[viewer]\nkeyframe_at_s = [-1]\n",
            "[viewer]\npin_height = 900\n",
            "[link.up]\ndelay_schedule = [[5, 10], [1, 10]]\n",
            "[link.down]\ndelay_schedule = [[5, -1]]\n",
            "[viewer]\nhidden = [[10, 5]]\n",
            "[viewer]\nhidden = [[1, 10], [5, 20]]\n",
            "[viewer]\nhidden = [[-1, 10]]\n",
            "[viewer]\nstale_rtt_ms = 5000\n",
            "[viewer]\nasleep_when_hidden = true\nasleep_backlog = \"later\"\n",
            "[viewer]\nstr0m = \"0.22\"\n",
        ] {
            assert!(
                Scenario::parse(&format!("{base}{bad}"), Path::new("."), "x").is_err(),
                "{bad}"
            );
        }
    }
}
