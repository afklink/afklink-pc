//! Human motion, sampled on the display's refresh grid: scroll gestures, typing, window drags.
//!
//! Every planner here is a pure function of its parameters and seed, and returns one state per
//! vsync. A scenario delivers a frame at a vsync exactly when the state (and therefore the picture)
//! changed since the last delivery, which is how WGC behaves: a frame per composition that changed
//! something, none while the screen is still.
//!
//! The gesture shapes, and where their numbers come from:
//!
//! * **Wheel notch** — Chromium scrolls 100 CSS px per notch (200 physical at 200%) and animates it
//!   with an ease-out over roughly 150 ms; a notch arriving mid-animation retargets from where the
//!   page is.
//! * **Phone two-finger drag** — the Mini App sends finger travel as pixel wheel deltas every
//!   animation frame (`miniapp/src/input.ts`), and the agent turns them into sub-notch wheel units
//!   (`crates/input`), so the page follows the finger 1:1 in CSS px with no momentum: a
//!   minimum-jerk stroke of a few hundred pixels in 100-300 ms, a gap while the fingers reset, the
//!   next stroke.
//! * **Page Down** — a step of 87.5% of the viewport (Chromium's paging fraction), either instant or
//!   eased over 100-200 ms.
//! * **Scrollbar drag** — the mouse moves the thumb in whole pixels and the page moves by the
//!   document/track ratio (about 10x here), so content jumps in coarse, irregular steps.
//! * **Fling** — touchpad kinetic scroll: exponential decay of an initial velocity.

use serde::{Deserialize, Serialize};

use crate::rng::Rng;

/// The display refresh grid.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Vsync {
    pub hz: f64,
}

impl Vsync {
    #[must_use]
    pub fn period_us(self) -> f64 {
        1e6 / self.hz
    }

    /// Number of vsyncs in `seconds` (the grid covers `[0, seconds)`).
    #[must_use]
    pub fn count(self, seconds: f64) -> u64 {
        (seconds * self.hz).floor().max(0.0) as u64
    }

    #[must_use]
    pub fn t_s(self, k: u64) -> f64 {
        k as f64 / self.hz
    }
}

/// Delivery timestamps: the vsync instant plus bounded, seeded jitter, strictly increasing.
///
/// WGC hands frames over within about a millisecond of the composition that produced them; the
/// capturer's pacing has to cope with that (`crates/capture/src/pace.rs`), so the corpus keeps it.
#[derive(Debug, Clone)]
pub struct Stamper {
    vsync: Vsync,
    jitter_us: u32,
    rng: Rng,
    last: Option<u64>,
}

impl Stamper {
    #[must_use]
    pub fn new(vsync: Vsync, jitter_us: u32, rng: Rng) -> Self {
        Self {
            vsync,
            jitter_us,
            rng,
            last: None,
        }
    }

    /// Timestamp for a delivery at vsync `k`. Call in increasing `k`.
    pub fn stamp(&mut self, k: u64) -> u64 {
        let base = k as f64 * self.vsync.period_us();
        let j = if self.jitter_us == 0 {
            0.0
        } else {
            self.rng
                .range(-f64::from(self.jitter_us), f64::from(self.jitter_us))
        };
        let t = (base + j).round().max(0.0) as u64;
        let t = match self.last {
            Some(prev) if t <= prev => prev + 1,
            _ => t,
        };
        self.last = Some(t);
        t
    }
}

/// Which scroll behaviour to plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScrollProfile {
    /// Constant velocity with a slow wobble: a touchpad or autoscroll at reading pace.
    Steady,
    /// Mouse-wheel notches in small bursts with reading pauses between them.
    Wheel,
    /// Phone swipes, Page Down, scrollbar drags and flings, with stops in between.
    Jerky,
}

impl std::str::FromStr for ScrollProfile {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> anyhow::Result<Self> {
        match s {
            "steady" => Ok(Self::Steady),
            "wheel" => Ok(Self::Wheel),
            "jerky" => Ok(Self::Jerky),
            other => anyhow::bail!("unknown scroll profile {other:?} (steady, wheel, jerky)"),
        }
    }
}

/// Scroll planner parameters. All distances in physical pixels, times in seconds.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScrollParams {
    pub profile: ScrollProfile,
    pub seconds: f64,
    pub vsync: Vsync,
    pub seed: u64,
    /// Largest scroll offset (document height minus viewport height).
    pub max_scroll: f64,
    /// Viewport height, for Page Down steps.
    pub viewport_h: f64,
    /// Document pixels per scrollbar pixel, for thumb drags.
    pub track_ratio: f64,
    /// Where the page starts.
    pub start: f64,
    // Steady.
    pub speed_px_s: f64,
    /// Relative velocity wobble amplitude and its period.
    pub wobble: f64,
    pub wobble_period_s: f64,
    /// Mean running time between short holds (0 = never hold).
    pub hold_every_s: f64,
    pub hold_s: (f64, f64),
    // Wheel.
    pub notch_px: f64,
    pub notch_anim_s: f64,
    pub notches_per_burst: (u64, u64),
    pub notch_gap_s: (f64, f64),
    pub reading_pause_s: (f64, f64),
    // Jerky.
    /// Relative weights of swipe bursts, page jumps, scrollbar drags and flings.
    pub weights: [f64; 4],
    pub swipe_px: (f64, f64),
    pub swipe_s: (f64, f64),
    pub swipes_per_burst: (u64, u64),
    pub swipe_gap_s: (f64, f64),
    pub pages_per_burst: (u64, u64),
    pub page_gap_s: (f64, f64),
    /// Share of Page Down steps that jump in one frame instead of animating.
    pub page_instant: f64,
    pub page_anim_s: (f64, f64),
    pub drag_s: (f64, f64),
    pub fling_v0: (f64, f64),
    pub fling_tau_s: (f64, f64),
    /// Probability that a gesture group goes up rather than down (away from the ends).
    pub up_share: f64,
    pub pause_s: (f64, f64),
}

impl ScrollParams {
    /// Defaults for a profile on a page of the given geometry.
    #[must_use]
    pub fn new(profile: ScrollProfile, max_scroll: f64, viewport_h: f64, track_ratio: f64) -> Self {
        Self {
            profile,
            seconds: 60.0,
            vsync: Vsync { hz: 60.0 },
            seed: 1,
            max_scroll,
            viewport_h,
            track_ratio,
            start: 0.0,
            speed_px_s: 180.0,
            wobble: 0.25,
            wobble_period_s: 5.0,
            hold_every_s: 0.0,
            hold_s: (0.4, 1.2),
            notch_px: 200.0,
            notch_anim_s: 0.15,
            notches_per_burst: (1, 3),
            notch_gap_s: (0.06, 0.14),
            reading_pause_s: (0.5, 2.2),
            weights: [0.45, 0.2, 0.15, 0.2],
            swipe_px: (300.0, 1400.0),
            swipe_s: (0.10, 0.30),
            swipes_per_burst: (2, 5),
            swipe_gap_s: (0.10, 0.35),
            pages_per_burst: (1, 4),
            page_gap_s: (0.25, 1.0),
            page_instant: 0.5,
            page_anim_s: (0.10, 0.20),
            drag_s: (0.6, 1.8),
            fling_v0: (2500.0, 9000.0),
            fling_tau_s: (0.25, 0.45),
            up_share: 0.2,
            pause_s: (0.6, 3.0),
        }
    }
}

/// One stretch of scrolling, as a displacement from where it started.
#[derive(Debug, Clone)]
enum Segment {
    Hold {
        d: f64,
    },
    Steady {
        v: f64,
        d: f64,
        amp: f64,
        period: f64,
        phase: f64,
    },
    /// `dist * curve(t / d)`.
    Ease {
        dist: f64,
        d: f64,
        curve: Curve,
    },
    Fling {
        v0: f64,
        tau: f64,
        d: f64,
    },
    /// Wheel notches at the given offsets from the segment start, each retargeting an ease-out.
    Wheel {
        notches: Vec<(f64, f64)>,
        anim: f64,
        d: f64,
    },
    /// Precomputed displacement per vsync from the segment start.
    Sampled {
        samples: Vec<f64>,
        hz: f64,
    },
}

#[derive(Debug, Clone, Copy)]
enum Curve {
    MinJerk,
    EaseOut,
}

impl Curve {
    fn at(self, x: f64) -> f64 {
        let x = x.clamp(0.0, 1.0);
        match self {
            Self::MinJerk => x * x * x * (10.0 - 15.0 * x + 6.0 * x * x),
            Self::EaseOut => 1.0 - (1.0 - x).powi(3),
        }
    }
}

impl Segment {
    fn duration(&self) -> f64 {
        match self {
            Self::Hold { d }
            | Self::Steady { d, .. }
            | Self::Ease { d, .. }
            | Self::Fling { d, .. }
            | Self::Wheel { d, .. } => *d,
            Self::Sampled { samples, hz } => samples.len() as f64 / hz,
        }
    }

    fn offset(&self, t: f64) -> f64 {
        match self {
            Self::Hold { .. } => 0.0,
            Self::Steady {
                v,
                amp,
                period,
                phase,
                ..
            } => {
                let w = std::f64::consts::TAU / period;
                v * (t + amp / w * ((w * t + phase).sin() - phase.sin()))
            }
            Self::Ease { dist, d, curve } => {
                if *d <= 0.0 {
                    *dist
                } else {
                    dist * curve.at(t / d)
                }
            }
            Self::Fling { v0, tau, .. } => v0 * tau * (1.0 - (-t / tau).exp()),
            Self::Wheel { notches, anim, .. } => {
                // Replay the notches up to `t`: each one retargets an ease-out from wherever the
                // animation had got to.
                let (mut from, mut to, mut start) = (0.0, 0.0, 0.0);
                for &(at, delta) in notches {
                    if at > t {
                        break;
                    }
                    let now = if *anim > 0.0 {
                        from + (to - from) * Curve::EaseOut.at((at - start) / anim)
                    } else {
                        to
                    };
                    from = now;
                    to += delta;
                    start = at;
                }
                if *anim > 0.0 {
                    from + (to - from) * Curve::EaseOut.at((t - start) / anim)
                } else {
                    to
                }
            }
            Self::Sampled { samples, hz } => {
                let i = (t * hz).floor().max(0.0) as usize;
                samples.get(i).or(samples.last()).copied().unwrap_or(0.0)
            }
        }
    }
}

/// Plan a scroll: the page offset (whole physical pixels) at every vsync of the scenario.
#[must_use]
pub fn plan_scroll(p: &ScrollParams) -> Vec<i64> {
    let n = p.vsync.count(p.seconds);
    let mut rng = Rng::new(p.seed);
    let mut out = Vec::with_capacity(n as usize);

    let mut seg_start_t = 0.0;
    let mut seg_start_pos = p.start.clamp(0.0, p.max_scroll.max(0.0));
    let mut queue: std::collections::VecDeque<Segment> = std::collections::VecDeque::new();
    let mut seg: Option<Segment> = None;

    for k in 0..n {
        let t = p.vsync.t_s(k);
        loop {
            let cur_end = seg
                .as_ref()
                .map_or(seg_start_t, |s| seg_start_t + s.duration());
            if seg.is_some() && t < cur_end {
                break;
            }
            // Advance: close the current segment at its end position.
            if let Some(s) = seg.take() {
                seg_start_pos =
                    (seg_start_pos + s.offset(s.duration())).clamp(0.0, p.max_scroll.max(0.0));
                seg_start_t = cur_end;
            }
            if queue.is_empty() {
                plan_group(p, &mut rng, seg_start_pos, &mut queue);
            }
            seg = queue.pop_front();
            if seg.is_none() {
                break;
            }
        }
        let pos = seg
            .as_ref()
            .map_or(seg_start_pos, |s| seg_start_pos + s.offset(t - seg_start_t));
        out.push(pos.clamp(0.0, p.max_scroll.max(0.0)).round() as i64);
    }
    out
}

/// Which way the next gesture group goes: away from an end that is close, otherwise mostly down.
fn direction(p: &ScrollParams, rng: &mut Rng, pos: f64) -> f64 {
    let margin = (p.viewport_h * 3.0).min(p.max_scroll / 3.0);
    if pos >= p.max_scroll - margin {
        -1.0
    } else if pos <= margin {
        1.0
    } else if rng.chance(p.up_share) {
        -1.0
    } else {
        1.0
    }
}

/// Append the next group of segments for the profile.
fn plan_group(
    p: &ScrollParams,
    rng: &mut Rng,
    pos: f64,
    queue: &mut std::collections::VecDeque<Segment>,
) {
    match p.profile {
        ScrollProfile::Steady => {
            // Reading pace until the page ends, then back up at the same pace.
            let dir = if pos >= p.max_scroll - 1.0 { -1.0 } else { 1.0 };
            let run = if p.hold_every_s > 0.0 {
                rng.range(0.5, 1.5) * p.hold_every_s
            } else {
                p.seconds + 1.0
            };
            // Do not run past the end of the page: stop there and turn round.
            let room = if dir > 0.0 { p.max_scroll - pos } else { pos };
            let run = run.min((room / p.speed_px_s.max(1.0)).max(0.5));
            queue.push_back(Segment::Steady {
                v: dir * p.speed_px_s,
                d: run,
                amp: p.wobble,
                period: p.wobble_period_s,
                phase: rng.range(0.0, std::f64::consts::TAU),
            });
            if p.hold_every_s > 0.0 {
                queue.push_back(Segment::Hold {
                    d: rng.range(p.hold_s.0, p.hold_s.1),
                });
            }
        }
        ScrollProfile::Wheel => {
            let dir = direction(p, rng, pos);
            let count = rng.int(p.notches_per_burst.0, p.notches_per_burst.1);
            let mut notches = Vec::new();
            let mut at = 0.0;
            for i in 0..count {
                if i > 0 {
                    at += rng.range(p.notch_gap_s.0, p.notch_gap_s.1);
                }
                notches.push((at, dir * p.notch_px));
            }
            queue.push_back(Segment::Wheel {
                notches,
                anim: p.notch_anim_s,
                d: at + p.notch_anim_s,
            });
            queue.push_back(Segment::Hold {
                d: rng.range(p.reading_pause_s.0, p.reading_pause_s.1),
            });
        }
        ScrollProfile::Jerky => {
            let dir = direction(p, rng, pos);
            let total: f64 = p.weights.iter().sum::<f64>().max(1e-9);
            let mut pick = rng.unit() * total;
            let mut kind = 0;
            for (i, w) in p.weights.iter().enumerate() {
                if pick < *w {
                    kind = i;
                    break;
                }
                pick -= w;
            }
            match kind {
                0 => {
                    let n = rng.int(p.swipes_per_burst.0, p.swipes_per_burst.1);
                    for i in 0..n {
                        if i > 0 {
                            queue.push_back(Segment::Hold {
                                d: rng.range(p.swipe_gap_s.0, p.swipe_gap_s.1),
                            });
                        }
                        queue.push_back(Segment::Ease {
                            dist: dir * rng.range(p.swipe_px.0, p.swipe_px.1),
                            d: rng.range(p.swipe_s.0, p.swipe_s.1),
                            curve: Curve::MinJerk,
                        });
                    }
                }
                1 => {
                    let n = rng.int(p.pages_per_burst.0, p.pages_per_burst.1);
                    for i in 0..n {
                        if i > 0 {
                            queue.push_back(Segment::Hold {
                                d: rng.range(p.page_gap_s.0, p.page_gap_s.1),
                            });
                        }
                        let d = if rng.chance(p.page_instant) {
                            0.0
                        } else {
                            rng.range(p.page_anim_s.0, p.page_anim_s.1)
                        };
                        queue.push_back(Segment::Ease {
                            dist: dir * p.viewport_h * 0.875,
                            d,
                            curve: Curve::EaseOut,
                        });
                    }
                }
                2 => queue.push_back(scrollbar_drag(p, rng, dir)),
                _ => {
                    let v0 = dir * rng.range(p.fling_v0.0, p.fling_v0.1);
                    let tau = rng.range(p.fling_tau_s.0, p.fling_tau_s.1);
                    // Stops when the page moves less than half a pixel a frame.
                    let v_stop = 0.5 * p.vsync.hz;
                    let d = (tau * (v0.abs() / v_stop).ln()).max(0.05);
                    queue.push_back(Segment::Fling { v0, tau, d });
                }
            }
            queue.push_back(Segment::Hold {
                d: rng.range(p.pause_s.0, p.pause_s.1),
            });
        }
    }
}

/// A thumb drag: the mouse makes a handful of quick sub-moves in whole pixels, and the page moves
/// by the track ratio times the mouse.
fn scrollbar_drag(p: &ScrollParams, rng: &mut Rng, dir: f64) -> Segment {
    let hz = p.vsync.hz;
    let total = rng.range(p.drag_s.0, p.drag_s.1);
    let frames = (total * hz).ceil().max(1.0) as usize;
    let mut samples = Vec::with_capacity(frames);
    let mut mouse = 0.0f64;
    let mut k = 0usize;
    while k < frames {
        // A sub-move: mostly in `dir`, sometimes a small correction back.
        let back = rng.chance(0.15);
        let dist = if back { -dir } else { dir } * rng.range(8.0, 90.0);
        let len = ((rng.range(0.06, 0.25) * hz).ceil() as usize).max(1);
        let from = mouse;
        for i in 0..len {
            if k >= frames {
                break;
            }
            mouse = from + dist * Curve::MinJerk.at((i + 1) as f64 / len as f64);
            samples.push(mouse.round() * p.track_ratio);
            k += 1;
        }
        let hold = (rng.range(0.0, 0.1) * hz) as usize;
        for _ in 0..hold {
            if k >= frames {
                break;
            }
            samples.push(mouse.round() * p.track_ratio);
            k += 1;
        }
    }
    Segment::Sampled { samples, hz }
}

/// Typing parameters. Times in seconds.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypingParams {
    pub seconds: f64,
    pub vsync: Vsync,
    pub seed: u64,
    /// Median gap between keystrokes (0.2 s is about 5 characters a second, a steady typist
    /// writing code).
    pub key_median_s: f64,
    pub key_sigma: f64,
    /// Pause after Enter.
    pub line_pause_s: (f64, f64),
    /// Chance per keystroke of stopping to think, and for how long.
    pub think_prob: f64,
    pub think_s: (f64, f64),
    /// Chance per keystroke of deleting the last one to three characters and retyping them.
    pub backspace_prob: f64,
    /// Caret half-period (Windows' default blink rate).
    pub blink_s: f64,
    /// Seconds before the first keystroke.
    pub lead_in_s: f64,
}

impl Default for TypingParams {
    fn default() -> Self {
        Self {
            seconds: 60.0,
            vsync: Vsync { hz: 60.0 },
            seed: 1,
            key_median_s: 0.2,
            key_sigma: 0.45,
            line_pause_s: (0.35, 1.4),
            think_prob: 0.015,
            think_s: (1.5, 4.5),
            backspace_prob: 0.03,
            blink_s: 0.53,
            lead_in_s: 1.2,
        }
    }
}

/// The editor state after a keystroke: `line` (index into the typed lines) and `col` characters of
/// it revealed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Caret {
    pub line: usize,
    pub col: usize,
}

/// Plan keystrokes over `lines` (the text to be typed, one entry per line). Returns
/// `(time, caret)` after every keystroke, starting with the caret at the start of the first line.
#[must_use]
pub fn plan_typing(lines: &[String], p: &TypingParams) -> Vec<(f64, Caret)> {
    let mut rng = Rng::new(p.seed);
    let indent = |l: usize| {
        lines
            .get(l)
            .map_or(0, |s| s.chars().take_while(|c| *c == ' ').count())
    };
    let len = |l: usize| lines.get(l).map_or(0, |s| s.chars().count());
    let mut t = p.lead_in_s;
    let mut caret = Caret {
        line: 0,
        col: indent(0),
    };
    let mut out = vec![(0.0, caret)];
    while t < p.seconds && caret.line < lines.len() {
        let mut gap = rng.lognormal(p.key_median_s, p.key_sigma).clamp(0.04, 1.5);
        if rng.chance(p.think_prob) {
            gap += rng.range(p.think_s.0, p.think_s.1);
        }
        t += gap;
        if caret.col >= len(caret.line) {
            // Enter: a new line, auto-indented, and a pause to think about it.
            if caret.line + 1 >= lines.len() {
                break;
            }
            caret = Caret {
                line: caret.line + 1,
                col: indent(caret.line + 1),
            };
            out.push((t, caret));
            t += rng.range(p.line_pause_s.0, p.line_pause_s.1);
            continue;
        }
        if caret.col > indent(caret.line) + 2 && rng.chance(p.backspace_prob) {
            // A slip: delete a few characters (one keystroke each) and carry on retyping them.
            let n = rng.int(1, 3) as usize;
            for _ in 0..n {
                caret.col -= 1;
                out.push((t, caret));
                t += rng.lognormal(p.key_median_s * 0.6, 0.3).clamp(0.04, 0.6);
            }
            continue;
        }
        caret.col += 1;
        out.push((t, caret));
    }
    out.retain(|(tt, _)| *tt < p.seconds);
    out
}

/// Whether the caret is drawn at `t`, given the time of the last keystroke at or before `t`: solid
/// after a keystroke, then toggling every `blink_s`.
#[must_use]
pub fn caret_visible(t: f64, last_key: f64, blink_s: f64) -> bool {
    let since = (t - last_key).max(0.0);
    ((since / blink_s).floor() as u64).is_multiple_of(2)
}

/// Window drag/resize parameters, in physical pixels and seconds.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DragParams {
    pub seconds: f64,
    pub vsync: Vsync,
    pub seed: u64,
    /// Area the window may occupy (the screen above the taskbar).
    pub area_w: i64,
    pub area_h: i64,
    pub start: WindowRect,
    pub min_size: (i64, i64),
    pub max_size: (i64, i64),
    pub move_s: (f64, f64),
    pub pause_s: (f64, f64),
    /// Share of gestures that resize from the bottom-right corner instead of moving.
    pub resize_share: f64,
    /// Hand tremor amplitude added along a drag, pixels.
    pub tremor_px: f64,
}

/// Where the window is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowRect {
    pub x: i64,
    pub y: i64,
    pub w: i64,
    pub h: i64,
}

/// Plan a sequence of moves and resizes: the window rectangle at every vsync.
#[must_use]
pub fn plan_drag(p: &DragParams) -> Vec<WindowRect> {
    let mut rng = Rng::new(p.seed);
    let n = p.vsync.count(p.seconds) as usize;
    let hz = p.vsync.hz;
    let mut out = Vec::with_capacity(n);
    let mut cur = p.start;
    // Open with a still moment, as a person reaches for the title bar.
    let lead = (0.8 * hz) as usize;
    out.extend(std::iter::repeat_n(cur, lead.min(n)));
    while out.len() < n {
        let resize = rng.chance(p.resize_share);
        let target = if resize {
            let w = rng.int(p.min_size.0 as u64, p.max_size.0 as u64) as i64;
            let h = rng.int(p.min_size.1 as u64, p.max_size.1 as u64) as i64;
            WindowRect {
                x: cur.x,
                y: cur.y,
                w: w.min(p.area_w - cur.x),
                h: h.min(p.area_h - cur.y),
            }
        } else {
            let x = rng.int(0, (p.area_w - cur.w).max(0) as u64) as i64;
            let y = rng.int(0, (p.area_h - cur.h).max(0) as u64) as i64;
            WindowRect { x, y, ..cur }
        };
        let frames = ((rng.range(p.move_s.0, p.move_s.1) * hz).ceil() as usize).max(2);
        let phase = rng.range(0.0, std::f64::consts::TAU);
        for i in 1..=frames {
            if out.len() >= n {
                break;
            }
            let s = Curve::MinJerk.at(i as f64 / frames as f64);
            // Tremor fades in and out with the movement so the end point is exact.
            let env = (std::f64::consts::PI * i as f64 / frames as f64).sin();
            let wob = p.tremor_px * env * (phase + i as f64 * 0.9).sin();
            let lerp = |a: i64, b: i64| a as f64 + (b - a) as f64 * s;
            let mut r = WindowRect {
                x: lerp(cur.x, target.x).round() as i64,
                y: (lerp(cur.y, target.y) + wob).round() as i64,
                w: lerp(cur.w, target.w).round() as i64,
                h: lerp(cur.h, target.h).round() as i64,
            };
            if resize {
                r.y = cur.y;
                r.w = (lerp(cur.w, target.w) + wob).round() as i64;
            }
            r.x = r.x.clamp(0, (p.area_w - r.w).max(0));
            r.y = r.y.clamp(0, (p.area_h - r.h).max(0));
            out.push(r);
        }
        cur = *out.last().unwrap_or(&cur);
        let hold = (rng.range(p.pause_s.0, p.pause_s.1) * hz) as usize;
        for _ in 0..hold {
            if out.len() >= n {
                break;
            }
            out.push(cur);
        }
    }
    out.truncate(n);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params(profile: ScrollProfile, seed: u64) -> ScrollParams {
        let mut p = ScrollParams::new(profile, 20_000.0, 2076.0, 10.0);
        p.seed = seed;
        p.seconds = 30.0;
        p
    }

    #[test]
    fn scroll_plans_are_deterministic_per_seed() {
        for profile in [
            ScrollProfile::Steady,
            ScrollProfile::Wheel,
            ScrollProfile::Jerky,
        ] {
            let a = plan_scroll(&params(profile, 7));
            let b = plan_scroll(&params(profile, 7));
            assert_eq!(a, b, "{profile:?}");
            assert_eq!(a.len(), 1800);
            if profile != ScrollProfile::Steady {
                let c = plan_scroll(&params(profile, 8));
                assert_ne!(a, c, "{profile:?}: another seed, another plan");
            }
            assert!(a.iter().all(|p| (0..=20_000).contains(p)));
        }
    }

    #[test]
    fn steady_scrolls_at_about_the_asked_speed_and_never_stops() {
        let p = params(ScrollProfile::Steady, 3);
        let pos = plan_scroll(&p);
        let travelled = pos[pos.len() - 1] - pos[0];
        let expected = p.speed_px_s * p.seconds;
        assert!(
            (travelled as f64 - expected).abs() < expected * 0.1,
            "{travelled} vs {expected}"
        );
        // 3 px a frame on average: every vsync changes the picture.
        let still = pos.windows(2).filter(|w| w[0] == w[1]).count();
        assert!(still < pos.len() / 10, "{still} still frames");
    }

    #[test]
    fn jerky_has_big_jumps_and_long_stops() {
        let pos = plan_scroll(&params(ScrollProfile::Jerky, 11));
        let steps: Vec<i64> = pos.windows(2).map(|w| (w[1] - w[0]).abs()).collect();
        let big = steps.iter().filter(|s| **s >= 100).count();
        let still = steps.iter().filter(|s| **s == 0).count();
        assert!(big >= 10, "{big} frames jumped 100 px or more");
        assert!(
            still >= steps.len() / 4,
            "{still} still frames of {}",
            steps.len()
        );
    }

    #[test]
    fn wheel_notches_land_on_whole_notches() {
        let mut p = params(ScrollProfile::Wheel, 5);
        p.up_share = 0.0;
        let pos = plan_scroll(&p);
        // At rest between bursts the offset is a whole number of notches from the start.
        let rests: Vec<i64> = pos
            .windows(3)
            .filter(|w| w[0] == w[1] && w[1] == w[2])
            .map(|w| w[0])
            .collect();
        assert!(!rests.is_empty());
        for r in rests {
            assert_eq!(r % 200, 0, "rest at {r}");
        }
    }

    #[test]
    fn typing_is_deterministic_and_moves_forward() {
        let lines: Vec<String> = ["fn main() {", "    let x = 1;", "}"]
            .iter()
            .map(|s| (*s).to_string())
            .collect();
        let p = TypingParams {
            seconds: 20.0,
            ..TypingParams::default()
        };
        let a = plan_typing(&lines, &p);
        assert_eq!(a, plan_typing(&lines, &p));
        assert!(a.windows(2).all(|w| w[1].0 >= w[0].0));
        let last = a.last().expect("keystrokes").1;
        assert_eq!(last.line, 2, "three short lines fit in twenty seconds");
        // The indent of line 1 appears at once with the Enter.
        assert!(a.iter().any(|(_, c)| *c == Caret { line: 1, col: 4 }));
        assert!(caret_visible(1.0, 1.0, 0.53));
        assert!(!caret_visible(1.6, 1.0, 0.53));
        assert!(caret_visible(2.1, 1.0, 0.53));
    }

    #[test]
    fn drags_stay_on_screen_and_are_deterministic() {
        let p = DragParams {
            seconds: 20.0,
            vsync: Vsync { hz: 60.0 },
            seed: 4,
            area_w: 3600,
            area_h: 2304,
            start: WindowRect {
                x: 400,
                y: 300,
                w: 2000,
                h: 1300,
            },
            min_size: (1200, 800),
            max_size: (2600, 1700),
            move_s: (0.4, 1.1),
            pause_s: (0.3, 1.5),
            resize_share: 0.3,
            tremor_px: 3.0,
        };
        let a = plan_drag(&p);
        assert_eq!(a, plan_drag(&p));
        assert_eq!(a.len(), 1200);
        for r in &a {
            assert!(
                r.x >= 0 && r.y >= 0 && r.x + r.w <= 3600 && r.y + r.h <= 2304,
                "{r:?}"
            );
        }
        let moved = a.windows(2).filter(|w| w[0] != w[1]).count();
        assert!(moved > 200 && moved < 1100, "{moved}");
    }

    #[test]
    fn stamps_increase_and_stay_near_the_grid() {
        let mut s = Stamper::new(Vsync { hz: 60.0 }, 700, Rng::new(9));
        let mut last = None;
        for k in 0..600u64 {
            let t = s.stamp(k);
            if let Some(l) = last {
                assert!(t > l);
            }
            let grid = k as f64 * 1e6 / 60.0;
            assert!((t as f64 - grid).abs() <= 701.0, "k={k} t={t}");
            last = Some(t);
        }
    }
}
