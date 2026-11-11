//! What a run measured, and the summary it is reduced to.
//!
//! ## Freezes, defined for a screen that is allowed to be still
//!
//! A remote desktop sends nothing while nothing changes, so a gap between displayed frames is not a
//! freeze by itself. What the viewer experiences as a freeze is the display updating *later than
//! the source's own cadence says it should have*. For consecutive displayed frames `i-1`, `i`
//! (captured at `c`, displayed at `d`), with `n` the first frame the capturer admitted after
//! `c[i-1]`:
//!
//! ```text
//! expected[i] = d[i-1] + (n - c[i-1])          the next change, at the latency frame i-1 had
//! stall[i]    = d[i] - expected[i]             how much later than that the display moved
//! ```
//!
//! Steady motion gives ~0; a still stretch gives ~0 (n is the first frame after it); frames
//! withheld, discarded, lost or undecodable give their span; a queue that builds gives the latency
//! it added. A freeze is a stall over 100, 250 or 500 ms. A source that keeps changing after the
//! last displayed frame contributes an open stall up to the end of the run.
//!
//! ## Where a picture-quality metric plugs in
//!
//! Decoding is out of scope for the skeleton: a displayed frame is one str0m reassembled completely
//! and whose reference chain is intact. The place for a decoder is [`Metrics::note_displayed`]'s
//! caller in `crate::sim`, with the `ViewerFrame`'s bytes and the source frame kept by RTP
//! timestamp in [`SentFrame`] (the source pixels would have to be retained there): decode with
//! OpenH264's decoder, compare against the scaled source frame (PSNR/SSIM, or VMAF offline), and
//! report it per rung and per second next to QP.

use std::collections::{BTreeMap, HashMap};
use std::time::Duration;

use afklink_core::quality::{BrakeEvent, Reanchor, Rung};

use crate::control::Second;
use crate::link::{LinkStats, LinkWindow};
use crate::viewer::ViewerFrame;

/// A frame the agent handed to the transport.
#[derive(Debug, Clone, Copy)]
pub struct SentFrame {
    pub captured_at: Duration,
    pub encode_start: Duration,
    pub bytes: usize,
    pub keyframe: bool,
    pub qp: Option<u32>,
}

/// Everything recorded during a run, in virtual time.
#[derive(Debug, Default)]
pub struct Metrics {
    /// The ladder of the profile the run is on, best first: the order the summary reads rungs in.
    pub ladder: Vec<Rung>,
    /// The rung the run opened on: the top of [`Self::ladder`], or of the pinned ladder when the
    /// scenario pins a height (a 1080 pin opens at 1080p30 whatever the profile's top). `None` reads
    /// as the top of `ladder`.
    pub opening: Option<Rung>,
    pub pipeline_start: Duration,
    /// Frames the capturer admitted (paced), in order.
    pub captures: Vec<Duration>,
    /// By RTP timestamp (`encode-start ms x 90`).
    pub sent: HashMap<u32, SentFrame>,
    pub rung_time: BTreeMap<(u32, u32), Duration>,
    pub rung_changes: Vec<(Duration, Rung, &'static str)>,
    pub reanchors: Vec<(Duration, u32, Option<Reanchor>, u32)>,
    pub brakes: Vec<(Duration, BrakeEvent)>,
    pub seconds: Vec<(Duration, Second)>,
    pub link_up_seconds: Vec<(Duration, LinkWindow)>,
    pub collapse_seconds: BTreeMap<&'static str, u32>,
    pub discarded_writes: u64,
    pub resyncs: u64,
    pub broken_reference_frames: u64,
    /// Bytes the sender put on the wire, per 100 ms bin since the pipeline started.
    pub egress_bins: Vec<u64>,
    /// The viewer's hidden windows as the session lived them. See [`HoldMark`].
    pub hold_marks: Vec<HoldMark>,
}

/// One hidden window of the viewer's page, as the session lived it (virtual times).
#[derive(Debug, Clone, Copy, Default)]
pub struct HoldMark {
    /// The viewer's `vis hidden: true` reached the agent.
    pub hidden_at: Duration,
    /// The grace ran out and the hold began (the controller frozen); `None` for a grace the page
    /// came back within.
    pub held_from: Option<Duration>,
    /// The rung as the hold began.
    pub rung_before: Option<Rung>,
    /// The viewer's `vis hidden: false` reached the agent.
    pub visible_at: Option<Duration>,
    /// The control task resumed the controller, with str0m's estimate and the controller's capacity
    /// evidence as they stood then.
    pub resumed_tick: Option<Duration>,
    pub estimate_at_resume: u32,
    pub capacity_at_resume: u32,
    /// The capture started again, its first frame the screen as it is.
    pub capture_at: Option<Duration>,
    /// The largest egress the controller was fed in one tick in the two seconds after it resumed:
    /// the hold's padding handed over in one window would read as megabits.
    pub max_feedback_egress_after_kbps: u32,
    /// Over the ten seconds after the controller resumed: the least estimate it was fed (str0m's,
    /// as the agent sees it), the oldest our send queue got, and the frames the queue guard
    /// withheld (the encode loop's count at the resume, and as of the window's last tick).
    pub estimate_min_after_kbps: Option<u32>,
    pub queue_max_after_ms: u32,
    pub skipped_queue_at_resume: u64,
    pub skipped_queue_after: u64,
    /// The encoder's budget as the page was hidden, and from one second to ten after the controller
    /// resumed: the least of it and its sum over that many ticks (the resume's own keyframe second
    /// left out). And the brake as the controller resumed.
    pub budget_at_hide_kbps: u32,
    pub budget_min_after_kbps: Option<u32>,
    pub budget_sum_after: u64,
    pub budget_ticks_after: u32,
    pub brake_at_resume: &'static str,
}

/// What one background hold came to.
#[derive(Debug, Clone)]
pub struct HoldSummary {
    /// Seconds into the session: the page hidden, the hold begun, the page visible again.
    pub hidden_s: f64,
    pub held_s: f64,
    pub visible_s: f64,
    /// What went on the wire while held, from a second after it began (frames in flight) to its
    /// end: str0m's padding and RTCP, and nothing else, in kbps.
    pub egress_held_kbps: u32,
    /// Encoded frames handed to the transport in that stretch: none, if nothing is captured.
    pub media_frames_held: usize,
    /// From the page visible again to the first frame of the screen as it is displayed, ms.
    pub first_frame_ms: Option<f64>,
    pub rung_before: Option<Rung>,
    /// The rung ten seconds after the page came back (or at the run's end, if sooner).
    pub rung_after: Option<Rung>,
    /// str0m's estimate and the capacity evidence as the controller resumed.
    pub estimate_at_resume: u32,
    pub capacity_at_resume: u32,
    /// The re-anchors decided within three seconds of the resume: (trigger, estimate, value).
    pub reanchors: Vec<(&'static str, u32, u32)>,
    /// Brake episodes engaged within ten seconds of the resume.
    pub brakes_after: usize,
    /// Rung changes within ten seconds of the resume, and how many of them went down the ladder.
    pub moves_after: usize,
    pub downs_after: usize,
    /// See [`HoldMark::max_feedback_egress_after_kbps`].
    pub max_feedback_egress_after_kbps: u32,
    /// The ten seconds after the resume (see [`HoldMark`]): the least estimate, the oldest queue,
    /// the frames the queue guard withheld, and the longest stall the viewer saw after the first
    /// resumed frame and from one second after the page was visible again — the stutter a collapsed
    /// estimate causes; the hold's own stall, which that first frame ends, is not one.
    pub estimate_min_after_kbps: Option<u32>,
    pub queue_max_after_ms: u32,
    pub skipped_queue_after: u64,
    pub stall_max_after_ms: f64,
    /// The budget: as the page was hidden, and the least and the mean from one second to ten after
    /// the resume. See [`HoldMark`].
    pub budget_at_hide_kbps: u32,
    pub budget_min_after_kbps: Option<u32>,
    pub budget_mean_after_kbps: u32,
    /// Brake episodes engaged from the hide to the hold's start — the grace, when the page is hidden
    /// but the controller still runs — and the brake as the controller resumed (`-` for none).
    pub brakes_in_grace: usize,
    pub brake_at_resume: &'static str,
    /// Everything the sender put on the wire while the page was hidden — the grace and the hold —
    /// in bytes.
    pub egress_hidden_bytes: u64,
}

const BIN: Duration = Duration::from_millis(100);

impl Metrics {
    pub fn note_capture(&mut self, at: Duration) {
        self.captures.push(at);
    }

    pub fn note_sent(&mut self, rtp: u32, f: SentFrame) {
        self.sent.insert(rtp, f);
    }

    pub fn note_tick(&mut self, rung: Rung, dt: Duration) {
        *self.rung_time.entry((rung.max_h, rung.fps)).or_default() += dt;
    }

    pub fn note_egress(&mut self, at: Duration, bytes: u64) {
        let Some(since) = at.checked_sub(self.pipeline_start) else {
            return;
        };
        let bin = (since.as_nanos() / BIN.as_nanos()) as usize;
        if self.egress_bins.len() <= bin {
            self.egress_bins.resize(bin + 1, 0);
        }
        self.egress_bins[bin] += bytes;
    }

    /// Sender bytes over `[from, to)`, to the 100 ms bin.
    #[must_use]
    pub fn egress_bytes_between(&self, from: Duration, to: Duration) -> u64 {
        let bin = |t: Duration| {
            (t.saturating_sub(self.pipeline_start).as_nanos() / BIN.as_nanos()) as usize
        };
        let (a, b) = (bin(from), bin(to).min(self.egress_bins.len()));
        self.egress_bins.get(a..b).map_or(0, |s| s.iter().sum())
    }

    /// Sender bytes per second over `[at - window, at)`, in kbps.
    #[must_use]
    pub fn egress_kbps_before(&self, at: Duration, window: Duration) -> u32 {
        let Some(end) = at.checked_sub(self.pipeline_start) else {
            return 0;
        };
        let end_bin = (end.as_nanos() / BIN.as_nanos()) as usize;
        let n = (window.as_nanos() / BIN.as_nanos()).max(1) as usize;
        let start_bin = end_bin.saturating_sub(n);
        let bytes: u64 = self
            .egress_bins
            .get(start_bin..end_bin.min(self.egress_bins.len()))
            .map_or(0, |s| s.iter().sum());
        (bytes as f64 * 8.0 / window.as_secs_f64() / 1000.0) as u32
    }
}

/// A frame the viewer displayed, joined to when it was captured.
#[derive(Debug, Clone, Copy)]
pub struct Displayed {
    pub captured_at: Duration,
    pub at: Duration,
}

/// One estimate collapse: the estimate fell under half its 3-second peak.
#[derive(Debug, Clone, Copy)]
pub struct Collapse {
    pub at: Duration,
    pub from_kbps: u32,
    pub to_kbps: u32,
    /// What the sender put on the wire in the 500 ms before, kbps: str0m's delay-based cut goes to
    /// `0.85 x` its acknowledged rate, and this is the nearest outside view of that rate.
    pub egress_before_kbps: u32,
}

/// The reduction of one run. See the module documentation for the freeze definition.
#[derive(Debug, Clone)]
pub struct Summary {
    pub name: String,
    /// The viewer's str0m version (`crate::viewer::ViewerStr0m`); set by the simulation.
    pub viewer_str0m: &'static str,
    pub sim_secs: f64,
    pub wall_secs: f64,
    pub connect_ms: f64,
    /// The rung the run opened on ([`Metrics::opening`]): the top of its profile's ladder, or of the
    /// pinned ladder. `top%` is the share of it and `lowest` starts from it.
    pub ladder_top: Rung,
    pub rung_time: Vec<(Rung, f64)>,
    pub rung_changes: Vec<(f64, Rung, &'static str)>,
    pub lowest: Rung,
    pub reanchors: Vec<(f64, &'static str, u32, u32)>,
    pub brake_engaged: usize,
    pub brake_events: usize,
    pub freezes: [usize; 3],
    pub stall_max_ms: f64,
    pub stall_total_s: f64,
    pub first_frame_ms: Option<f64>,
    pub latency_ms: Option<[f64; 3]>,
    pub frames_captured: u64,
    pub frames_encoded: u64,
    pub frames_received: usize,
    pub frames_displayed: usize,
    pub frames_lost: usize,
    pub mean_qp: Option<f64>,
    pub encoded_bytes: u64,
    pub egress_bytes: u64,
    pub estimate: Option<[u32; 3]>,
    pub estimate_trajectory: Vec<(f64, u32)>,
    pub collapses: Vec<Collapse>,
    pub collapse_seconds: BTreeMap<&'static str, u32>,
    pub keyframes: u64,
    /// Every keyframe byte encoded.
    pub keyframe_bytes: u64,
    pub plis_viewer: u64,
    /// The viewer's PLIs the encode loop's window held: a keyframe already on its way
    /// answered them (`afklink_core::keyframe_window`).
    pub kf_suppressed: u64,
    /// The viewer's recoveries and what each cost; set by the simulation. See [`recoveries`].
    pub recoveries: Vec<Recovery>,
    pub nacks: u64,
    pub discarded: u64,
    pub resyncs: u64,
    pub broken_reference_frames: u64,
    pub dropped_rate: u64,
    pub skipped_queue: u64,
    pub link_up: LinkStats,
    pub link_down: LinkStats,
    pub wall_encode_secs: f64,
    /// The background holds, in order. See [`HoldSummary`].
    pub holds: Vec<HoldSummary>,
}

/// The rung in force at `t`: the last change at or before it, or the opening rung.
fn rung_at(m: &Metrics, t: Duration, opening: Rung) -> Rung {
    m.rung_changes
        .iter()
        .take_while(|(at, _, _)| *at <= t)
        .last()
        .map_or(opening, |(_, r, _)| *r)
}

/// Where `r` sits on `ladder`: 0 at the top, larger further down.
fn ladder_index(ladder: &[Rung], r: Rung) -> usize {
    ladder.iter().position(|l| *l == r).unwrap_or(ladder.len())
}

/// The run's opening rung: [`Metrics::opening`] when the simulation set it (a pin opens on the
/// pinned ladder's top, which need not be on the profile's ladder), else the top of the profile's
/// ladder (a profile's ladder is never empty; an empty one reads as a rung of nothing, so a summary
/// of a broken run still prints).
fn ladder_top(m: &Metrics) -> Rung {
    m.opening.unwrap_or_else(|| {
        m.ladder
            .first()
            .copied()
            .unwrap_or(Rung { max_h: 0, fps: 0 })
    })
}

/// Reduce the hold marks. See [`HoldSummary`].
fn hold_summaries(m: &Metrics, shown: &[Displayed], end: Duration) -> Vec<HoldSummary> {
    let start = m.pipeline_start;
    let secs = |t: Duration| t.saturating_sub(start).as_secs_f64();
    let all_stalls = stalls(&m.captures, shown, end);
    m.hold_marks
        .iter()
        .filter_map(|h| {
            let held_from = h.held_from?;
            let visible = h.visible_at.unwrap_or(end);
            let quiet_from = held_from + Duration::from_secs(1);
            let window = visible.saturating_sub(quiet_from);
            let egress_held_kbps = if window.is_zero() {
                0
            } else {
                m.egress_kbps_before(visible, window)
            };
            let media_frames_held = m
                .sent
                .values()
                .filter(|f| f.encode_start >= held_from + Duration::from_millis(500))
                .filter(|f| f.encode_start < visible)
                .count();
            let first_shown = h
                .capture_at
                .and_then(|c| shown.iter().find(|d| d.captured_at >= c).map(|d| d.at));
            let first_frame_ms =
                first_shown.map(|at| at.saturating_sub(visible).as_secs_f64() * 1e3);
            let after = visible + Duration::from_secs(10);
            let opening = h.rung_before.unwrap_or_else(|| ladder_top(m));
            let mut was = rung_at(m, visible.saturating_sub(Duration::from_nanos(1)), opening);
            let downs_after = m
                .rung_changes
                .iter()
                .filter(|(t, ..)| *t >= visible && *t <= after)
                .filter(|(_, r, _)| {
                    let down = ladder_index(&m.ladder, *r) > ladder_index(&m.ladder, was);
                    was = *r;
                    down
                })
                .count();
            Some(HoldSummary {
                hidden_s: secs(h.hidden_at),
                held_s: secs(held_from),
                visible_s: secs(visible),
                egress_held_kbps,
                media_frames_held,
                first_frame_ms,
                rung_before: h.rung_before,
                rung_after: h.visible_at.map(|_| rung_at(m, after.min(end), opening)),
                estimate_at_resume: h.estimate_at_resume,
                capacity_at_resume: h.capacity_at_resume,
                reanchors: m
                    .reanchors
                    .iter()
                    .filter(|(t, ..)| *t >= visible && *t <= visible + Duration::from_secs(3))
                    .map(|(_, kbps, r, est)| (r.map_or("-", |r| r.trigger.as_str()), *est, *kbps))
                    .collect(),
                brakes_after: m
                    .brakes
                    .iter()
                    .filter(|(t, e)| {
                        *t >= visible && *t <= after && matches!(e, BrakeEvent::Engaged(_))
                    })
                    .count(),
                moves_after: m
                    .rung_changes
                    .iter()
                    .filter(|(t, ..)| *t >= visible && *t <= after)
                    .count(),
                downs_after,
                budget_at_hide_kbps: h.budget_at_hide_kbps,
                budget_min_after_kbps: h.budget_min_after_kbps,
                budget_mean_after_kbps: u32::try_from(
                    h.budget_sum_after / u64::from(h.budget_ticks_after.max(1)),
                )
                .unwrap_or(u32::MAX),
                brakes_in_grace: m
                    .brakes
                    .iter()
                    .filter(|(t, e)| {
                        *t >= h.hidden_at && *t < held_from && matches!(e, BrakeEvent::Engaged(_))
                    })
                    .count(),
                brake_at_resume: h.brake_at_resume,
                egress_hidden_bytes: m.egress_bytes_between(h.hidden_at, visible),
                max_feedback_egress_after_kbps: h.max_feedback_egress_after_kbps,
                estimate_min_after_kbps: h.estimate_min_after_kbps,
                queue_max_after_ms: h.queue_max_after_ms,
                skipped_queue_after: h
                    .skipped_queue_after
                    .saturating_sub(h.skipped_queue_at_resume),
                // The hold's own stall ends with the first resumed frame: only those after it count.
                stall_max_after_ms: first_shown.map_or(0.0, |first| {
                    all_stalls
                        .iter()
                        .filter(|(t, _)| {
                            *t > first && *t >= visible + Duration::from_secs(1) && *t <= after
                        })
                        .map(|(_, s)| s.as_secs_f64() * 1e3)
                        .fold(0.0, f64::max)
                }),
            })
        })
        .collect()
}

impl Summary {
    #[must_use]
    pub fn speed(&self) -> f64 {
        if self.wall_secs > 0.0 {
            self.sim_secs / self.wall_secs
        } else {
            0.0
        }
    }
}

/// Percentile of a sorted slice, nearest-rank.
fn pct(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let rank = ((p / 100.0) * sorted.len() as f64).ceil() as usize;
    sorted[rank.clamp(1, sorted.len()) - 1]
}

/// Join the viewer's frames to what was sent. `None` for a frame the sender has no record of.
#[must_use]
pub fn displayed_frames(m: &Metrics, frames: &[ViewerFrame]) -> Vec<Displayed> {
    frames
        .iter()
        .filter(|f| f.displayed)
        .filter_map(|f| {
            m.sent.get(&f.rtp).map(|s| Displayed {
                captured_at: s.captured_at,
                at: f.at,
            })
        })
        .collect()
}

/// Stalls between consecutive displayed frames (see the module documentation), plus the open one
/// at the end if the source kept changing. `(when the display finally moved, stall)`.
#[must_use]
pub fn stalls(
    captures: &[Duration],
    shown: &[Displayed],
    end: Duration,
) -> Vec<(Duration, Duration)> {
    let mut out = Vec::new();
    for w in shown.windows(2) {
        let (prev, cur) = (w[0], w[1]);
        let i = captures.partition_point(|c| *c <= prev.captured_at);
        let Some(&next) = captures.get(i) else {
            continue;
        };
        let expected = prev.at + (next - prev.captured_at);
        if cur.at > expected {
            out.push((cur.at, cur.at - expected));
        }
    }
    if let Some(last) = shown.last() {
        let i = captures.partition_point(|c| *c <= last.captured_at);
        if let Some(&next) = captures.get(i) {
            let expected = last.at + (next - last.captured_at);
            if end > expected {
                out.push((end, end - expected));
            }
        }
    }
    out
}

/// One of the viewer's recoveries: a run of its PLIs none more than [`RECOVERY_GAP`] after the one
/// before, and the keyframes the agent handed to the transport from its first PLI to
/// [`RECOVERY_TAIL`] after its last.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Recovery {
    /// Seconds into the session of its first PLI.
    pub at_s: f64,
    pub plis: usize,
    pub keyframes: usize,
}

/// The grouping from the analysis of a recorded long-RTT session (PLIs closer than 1.5 s are one
/// recovery, keyframes counted to 0.8 s after its last), so a simulated run reads as that
/// session's numbers did — 294 of its 380 recoveries cost two keyframes, 67 three.
pub const RECOVERY_GAP: Duration = Duration::from_millis(1_500);
/// See [`RECOVERY_GAP`].
pub const RECOVERY_TAIL: Duration = Duration::from_millis(800);

/// The viewer's recoveries, from when it sent its PLIs (in order) and the keyframes in `m.sent`.
#[must_use]
pub fn recoveries(m: &Metrics, pli_times: &[Duration]) -> Vec<Recovery> {
    let mut keyframes: Vec<Duration> = m
        .sent
        .values()
        .filter(|f| f.keyframe)
        .map(|f| f.encode_start)
        .collect();
    keyframes.sort_unstable();
    let mut out = Vec::new();
    let mut i = 0;
    while let Some(&first) = pli_times.get(i) {
        let mut last = first;
        let mut n = 1;
        while let Some(&next) = pli_times.get(i + n) {
            if next.saturating_sub(last) > RECOVERY_GAP {
                break;
            }
            last = next;
            n += 1;
        }
        let until = last + RECOVERY_TAIL;
        out.push(Recovery {
            at_s: first.saturating_sub(m.pipeline_start).as_secs_f64(),
            plis: n,
            keyframes: keyframes
                .iter()
                .filter(|t| **t >= first && **t <= until)
                .count(),
        });
        i += n;
    }
    out
}

/// Estimate collapses from str0m's estimate events. See [`Collapse`].
#[must_use]
pub fn collapses(m: &Metrics, estimates: &[(Duration, u32)]) -> Vec<Collapse> {
    let mut out = Vec::new();
    let mut in_collapse = false;
    for (i, &(t, e)) in estimates.iter().enumerate() {
        let from = t.saturating_sub(Duration::from_secs(3));
        let peak = estimates[..i]
            .iter()
            .rev()
            .take_while(|(u, _)| *u >= from)
            .map(|(_, v)| *v)
            .max()
            .unwrap_or(0);
        let collapsed = peak >= 300 && e * 2 < peak;
        if collapsed && !in_collapse && t >= m.pipeline_start {
            out.push(Collapse {
                at: t,
                from_kbps: peak,
                to_kbps: e,
                egress_before_kbps: m.egress_kbps_before(t, Duration::from_millis(500)),
            });
        }
        in_collapse = collapsed;
    }
    out
}

/// Reduce a run. `rung_order` puts the ladder's rungs first, best first.
#[allow(clippy::too_many_arguments)]
#[must_use]
pub fn summarize(
    name: &str,
    m: &Metrics,
    viewer_frames: &[ViewerFrame],
    estimates: &[(Duration, u32)],
    counters: &crate::encode_loop::Counters,
    egress_bytes: u64,
    nacks: u64,
    plis_viewer: u64,
    link_up: &LinkStats,
    link_down: &LinkStats,
    end: Duration,
    wall_secs: f64,
) -> Summary {
    let start = m.pipeline_start;
    let shown = displayed_frames(m, viewer_frames);
    let st = stalls(&m.captures, &shown, end);
    let freezes = [100u64, 250, 500].map(|ms| {
        st.iter()
            .filter(|(_, s)| *s > Duration::from_millis(ms))
            .count()
    });
    let stall_max_ms = st
        .iter()
        .map(|(_, s)| s.as_secs_f64() * 1e3)
        .fold(0.0, f64::max);
    let stall_total_s = st
        .iter()
        .filter(|(_, s)| *s > Duration::from_millis(100))
        .map(|(_, s)| s.as_secs_f64())
        .sum();

    let mut lat: Vec<f64> = shown
        .iter()
        .map(|d| d.at.saturating_sub(d.captured_at).as_secs_f64() * 1e3)
        .collect();
    lat.sort_by(f64::total_cmp);
    let latency_ms =
        (!lat.is_empty()).then(|| [pct(&lat, 50.0), pct(&lat, 95.0), pct(&lat, 100.0)]);

    let received = viewer_frames.len();
    let received_rtps: std::collections::HashSet<u32> =
        viewer_frames.iter().map(|f| f.rtp).collect();
    // Frames still in flight when the run ended are not lost; a second is well past any delivery
    // that is still going to happen.
    let settled = end.saturating_sub(Duration::from_secs(1));
    let frames_lost = m
        .sent
        .iter()
        .filter(|(rtp, s)| s.encode_start < settled && !received_rtps.contains(rtp))
        .count();

    let mut rung_time: Vec<(Rung, f64)> = m
        .ladder
        .iter()
        .filter_map(|r| {
            m.rung_time
                .get(&(r.max_h, r.fps))
                .map(|t| (*r, t.as_secs_f64()))
        })
        .collect();
    for ((h, fps), t) in &m.rung_time {
        if !m.ladder.iter().any(|r| r.max_h == *h && r.fps == *fps) {
            rung_time.push((
                Rung {
                    max_h: *h,
                    fps: *fps,
                },
                t.as_secs_f64(),
            ));
        }
    }
    let lowest = m
        .rung_changes
        .iter()
        .map(|(_, r, _)| *r)
        .fold(ladder_top(m), |lo, r| {
            if (r.max_h, r.fps) < (lo.max_h, lo.fps) {
                r
            } else {
                lo
            }
        });

    let mut est: Vec<u32> = m.seconds.iter().map(|(_, s)| s.estimate_kbps).collect();
    let estimate_trajectory = m
        .seconds
        .iter()
        .step_by(5)
        .map(|(t, s)| (t.saturating_sub(start).as_secs_f64(), s.estimate_kbps))
        .collect();
    est.sort_unstable();
    let estimate = (!est.is_empty()).then(|| [est[0], est[est.len() / 2], est[est.len() - 1]]);

    Summary {
        name: name.to_string(),
        viewer_str0m: "",
        sim_secs: end.saturating_sub(start).as_secs_f64(),
        wall_secs,
        connect_ms: start.as_secs_f64() * 1e3,
        ladder_top: ladder_top(m),
        rung_time,
        rung_changes: m
            .rung_changes
            .iter()
            .map(|(t, r, why)| (t.saturating_sub(start).as_secs_f64(), *r, *why))
            .collect(),
        lowest,
        reanchors: m
            .reanchors
            .iter()
            .map(|(t, kbps, r, est)| {
                (
                    t.saturating_sub(start).as_secs_f64(),
                    r.map_or("-", |r| r.trigger.as_str()),
                    *est,
                    *kbps,
                )
            })
            .collect(),
        brake_engaged: m
            .brakes
            .iter()
            .filter(|(_, e)| matches!(e, BrakeEvent::Engaged(_)))
            .count(),
        brake_events: m.brakes.len(),
        freezes,
        stall_max_ms,
        stall_total_s,
        first_frame_ms: shown
            .first()
            .map(|d| d.at.saturating_sub(start).as_secs_f64() * 1e3),
        latency_ms,
        frames_captured: counters.frames_captured,
        frames_encoded: counters.frames_encoded,
        frames_received: received,
        frames_displayed: shown.len(),
        frames_lost,
        mean_qp: (counters.qp_samples > 0)
            .then(|| counters.qp_sum as f64 / counters.qp_samples as f64),
        encoded_bytes: counters.bytes_sent,
        egress_bytes,
        estimate,
        estimate_trajectory,
        collapses: collapses(m, estimates),
        collapse_seconds: m.collapse_seconds.clone(),
        keyframes: counters.keyframes,
        keyframe_bytes: counters.keyframe_bytes_total,
        plis_viewer,
        kf_suppressed: counters.keyframe_requests_suppressed,
        recoveries: Vec::new(),
        nacks,
        discarded: m.discarded_writes,
        resyncs: m.resyncs,
        broken_reference_frames: m.broken_reference_frames,
        dropped_rate: counters.frames_dropped_rate,
        skipped_queue: counters.frames_skipped_queue,
        link_up: link_up.clone(),
        link_down: link_down.clone(),
        wall_encode_secs: counters.wall_encode_us_total as f64 / 1e6,
        holds: hold_summaries(m, &shown, end),
    }
}

/// The per-second viewer line, beside the agent's `pipeline` line in the session log: what the
/// far end got, which the agent's own line cannot say.
#[must_use]
pub fn viewer_seconds(
    m: &Metrics,
    viewer_frames: &[ViewerFrame],
    end: Duration,
) -> Vec<(Duration, String)> {
    let start = m.pipeline_start;
    let shown = displayed_frames(m, viewer_frames);
    let st = stalls(&m.captures, &shown, end);
    let link: HashMap<u64, LinkWindow> = m
        .link_up_seconds
        .iter()
        .map(|(t, w)| (t.saturating_sub(start).as_secs(), *w))
        .collect();
    let secs = end.saturating_sub(start).as_secs();
    let mut out = Vec::new();
    // The picture's age at each second's end: since the capture of the newest frame on screen by
    // then. A freeze grows it, as the bench's frame age does; a still source grows it too, so it is
    // read on moving content.
    let mut newest: Option<Duration> = None;
    let mut next_shown = 0usize;
    for k in 1..=secs {
        let lo = start + Duration::from_secs(k - 1);
        let hi = start + Duration::from_secs(k);
        while shown.get(next_shown).is_some_and(|d| d.at < hi) {
            let c = shown[next_shown].captured_at;
            newest = Some(newest.map_or(c, |n| n.max(c)));
            next_shown += 1;
        }
        let age_ms = newest.map(|c| hi.saturating_sub(c).as_secs_f64() * 1e3);
        let in_sec: Vec<&Displayed> = shown.iter().filter(|d| d.at >= lo && d.at < hi).collect();
        let mut lat: Vec<f64> = in_sec
            .iter()
            .map(|d| d.at.saturating_sub(d.captured_at).as_secs_f64() * 1e3)
            .collect();
        lat.sort_by(f64::total_cmp);
        let received = viewer_frames
            .iter()
            .filter(|f| f.at >= lo && f.at < hi)
            .count();
        let stall = st
            .iter()
            .filter(|(t, _)| *t >= lo && *t < hi)
            .map(|(_, s)| s.as_secs_f64() * 1e3)
            .fold(0.0, f64::max);
        let w = link.get(&k).copied().unwrap_or_default();
        let fmt = |v: Option<f64>| v.map_or_else(|| "-".to_string(), |v| format!("{v:.0}"));
        out.push((
            hi,
            format!(
                "viewer displayed_fps={} received_fps={received} lat_p50_ms=\"{}\" \
                 lat_max_ms=\"{}\" stall_ms=\"{stall:.0}\" link_sojourn_max_ms=\"{:.1}\" \
                 link_drop_queue={} link_drop_loss={} link_kbps={} age_ms=\"{}\"",
                in_sec.len(),
                fmt((!lat.is_empty()).then(|| pct(&lat, 50.0))),
                fmt(lat.last().copied()),
                w.max_sojourn.as_secs_f64() * 1e3,
                w.dropped_queue,
                w.dropped_loss,
                w.delivered_bytes * 8 / 1000,
                fmt(age_ms),
            ),
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{pct, stalls, Displayed};
    use std::time::Duration;

    fn ms(v: u64) -> Duration {
        Duration::from_millis(v)
    }

    fn shown(pairs: &[(u64, u64)]) -> Vec<Displayed> {
        pairs
            .iter()
            .map(|&(c, d)| Displayed {
                captured_at: ms(c),
                at: ms(d),
            })
            .collect()
    }

    #[test]
    fn steady_motion_and_still_stretches_are_not_freezes() {
        // 30 fps at a constant 150 ms latency, then five seconds of nothing, then more motion at
        // the same latency.
        let mut caps: Vec<Duration> = (0..30).map(|k| ms(k * 33)).collect();
        caps.extend((0..30).map(|k| ms(6_000 + k * 33)));
        let mut pairs: Vec<(u64, u64)> = (0..30).map(|k| (k * 33, k * 33 + 150)).collect();
        pairs.extend((0..30).map(|k| (6_000 + k * 33, 6_000 + k * 33 + 150)));
        let st = stalls(&caps, &shown(&pairs), ms(7_500));
        assert!(st.iter().all(|(_, s)| *s < ms(1)), "{st:?}");
    }

    #[test]
    fn withheld_frames_and_a_growing_queue_are() {
        let caps: Vec<Duration> = (0..30).map(|k| ms(k * 33)).collect();
        // Frames 10..=19 never shown: a 330 ms hole.
        let pairs: Vec<(u64, u64)> = (0..30)
            .filter(|k| !(10..20).contains(k))
            .map(|k| (k * 33, k * 33 + 150))
            .collect();
        let st = stalls(&caps, &shown(&pairs), ms(1_200));
        let worst = st.iter().map(|(_, s)| *s).max().unwrap_or_default();
        assert_eq!(worst, ms(330));
        // All frames shown, but latency jumps from 150 to 450 ms at frame 10.
        let pairs: Vec<(u64, u64)> = (0..30)
            .map(|k| (k * 33, k * 33 + if k < 10 { 150 } else { 450 }))
            .collect();
        let st = stalls(&caps, &shown(&pairs), ms(1_500));
        let worst = st.iter().map(|(_, s)| *s).max().unwrap_or_default();
        assert_eq!(worst, ms(300));
    }

    #[test]
    fn nearest_rank_percentiles() {
        let v = [1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0];
        assert!((pct(&v, 50.0) - 5.0).abs() < 1e-9);
        assert!((pct(&v, 95.0) - 10.0).abs() < 1e-9);
        assert!((pct(&v, 100.0) - 10.0).abs() < 1e-9);
        assert!(pct(&[], 50.0).abs() < 1e-9);
    }
}
