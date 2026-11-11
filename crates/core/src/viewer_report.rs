//! The viewer's own account of its decoder and screen, in the agent's log.
//!
//! An iPhone viewer can freeze solid for minutes while input keeps working, its stats saying it
//! decoded every frame. From the jitter buffer alone the agent's log cannot tell whether the frames
//! reached the screen: a stalled `<video>` element and a broken reference chain look the same.
//!
//! This module turns the viewer's once-a-second `vv` report (`InputMessage::ViewerVideo`) into:
//!
//!   * a `viewer` debug line per report, with what moved since the previous report — frames
//!     received, decoded, presented, dropped, keyframes, freezes, PLIs — and the element's and the
//!     page's state;
//!   * a warn/info line whenever the viewer's render watchdog changes step, and once when reports
//!     start arriving;
//!   * five compact fields on the `pipeline` line (`v_dec`, `v_pres`, `v_drop`, `v_kf`, `v_frz`)
//!     plus the watchdog's step (`v_wd`), so a freeze is visible at `info` next to what the agent
//!     sent in the same second.
//!
//! It also bounds the viewer's own keyframe requests (`InputMessage::KeyframeRequest`): the viewer
//! rate-limits them, but they arrive from the network and each one costs an IDR.
//!
//! And it names the viewer's browser engine, once per session: the viewer's own word (`engine`),
//! or, for a viewer that predates the field, what its Telegram platform implies (`ios` and `macos`
//! render in WebKit, `android` in Chromium).
//!
//! Three things here steer the pipeline, all through the peer's playout policy
//! (`afklink_transport::ViewerPlayout`, whose `playout` module bounds the numbers itself): the
//! engine decides how a playout hold is released — fast for Chromium, carefully for anyone else —
//! the viewer's jitter-buffer target is what a careful release follows down and what a Chromium
//! viewer's cushion is sized from, and its freeze counters are what engages that cushion. Everything
//! else is a peer's numbers, evidence for the log.

use std::fmt::Display;
use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::time::{Duration, Instant};

use afklink_protocol::{ViewerEngine, ViewerVideo};
use afklink_transport::ViewerPlayout;

/// A gauge the viewer has not reported, or reported without this field. Distinct from zero: a
/// counter that did not move and a counter this browser does not expose must not print alike.
const ABSENT: u64 = u64::MAX;

/// The render watchdog's steps, in the contract's spelling (`RENDER_WATCH_STATES`).
const WATCHDOG_STATES: [&str; 8] = [
    "ok",
    "hidden",
    "blocked",
    "keyframe",
    "reattach",
    "stalled",
    "replace",
    "reconnect",
];

/// Where the session's engine came from, for the log.
const ENGINE_REPORTED: &str = "reported";
const ENGINE_FROM_PLATFORM: &str = "platform";

/// The viewer's engine by its own word, or by what its Telegram platform implies when it predates
/// the field; `None` when the report carries neither.
///
/// Telegram for iOS and for macOS render Mini Apps in `WKWebView`, and Telegram for Android in the
/// system WebView (Chromium). Every other platform string — `tdesktop` (WebView2 on Windows, but
/// WebKit on macOS and Linux), `weba`/`webk` (any browser), `browser` — says nothing about the
/// engine, and is `unknown`.
pub fn viewer_engine(r: &ViewerVideo) -> Option<(ViewerEngine, &'static str)> {
    if let Some(e) = r.engine.as_deref() {
        return Some((ViewerEngine::from_wire(e), ENGINE_REPORTED));
    }
    let engine = match r.platform.as_deref()? {
        "ios" | "macos" => ViewerEngine::WebKit,
        "android" | "android_x" => ViewerEngine::Chromium,
        _ => ViewerEngine::Unknown,
    };
    Some((engine, ENGINE_FROM_PLATFORM))
}

/// No report yet, or a report without a watchdog.
const WATCHDOG_NONE: u8 = 0;
/// A watchdog state this build does not know (a newer viewer).
const WATCHDOG_UNKNOWN: u8 = u8::MAX;

/// The least time between two viewer keyframe requests the agent honours.
///
/// The viewer asks at most once every two seconds and backs off from there; this is the agent's
/// own bound on a buggy or hostile peer, loose enough never to refuse a well-behaved one. The
/// browser's RTCP PLIs are not affected: they take their own path.
pub const KEYFRAME_REQUEST_MIN_SPACING: Duration = Duration::from_secs(1);

fn watchdog_code(s: Option<&str>) -> u8 {
    match s {
        None => WATCHDOG_NONE,
        Some(s) => WATCHDOG_STATES
            .iter()
            .position(|k| *k == s)
            .and_then(|i| u8::try_from(i + 1).ok())
            .unwrap_or(WATCHDOG_UNKNOWN),
    }
}

fn watchdog_label(code: u8) -> &'static str {
    match code {
        WATCHDOG_NONE => "-",
        WATCHDOG_UNKNOWN => "?",
        c => WATCHDOG_STATES
            .get(usize::from(c) - 1)
            .copied()
            .unwrap_or("?"),
    }
}

/// The frame count the viewer's watchdog trusts as "reached the screen", if it has one.
///
/// `presented_by` names it. A report without one (the field is optional) falls back to
/// `requestVideoFrameCallback`, then to `getVideoPlaybackQuality`. `time` and `none` have no frame
/// count: `currentTime` advancing is not a number of frames.
fn presented(r: &ViewerVideo) -> Option<u64> {
    match r.presented_by.as_deref() {
        Some("rvfc") => r.rvfc_frames,
        Some("vpq") => r.vpq_frames,
        Some(_) => None,
        None => r.rvfc_frames.or(r.vpq_frames),
    }
}

/// The latest viewer video report, as the pipeline line reads it.
///
/// Written by the session's event task on every report, read by the control task once a second.
/// Cumulative values, not rates: the pipeline line differences them on its own clock, so a report
/// that arrives late or not at all costs one second's resolution and never a frame of the total.
#[derive(Debug)]
pub struct ViewerGauges {
    /// Reports received. The pipeline line prints `-` for a second in which this did not move.
    reports: AtomicU64,
    frames_decoded: AtomicU64,
    presented: AtomicU64,
    frames_dropped: AtomicU64,
    key_frames: AtomicU64,
    freezes: AtomicU64,
    watchdog: AtomicU8,
}

impl Default for ViewerGauges {
    fn default() -> Self {
        Self {
            reports: AtomicU64::new(0),
            frames_decoded: AtomicU64::new(ABSENT),
            presented: AtomicU64::new(ABSENT),
            frames_dropped: AtomicU64::new(ABSENT),
            key_frames: AtomicU64::new(ABSENT),
            freezes: AtomicU64::new(ABSENT),
            watchdog: AtomicU8::new(WATCHDOG_NONE),
        }
    }
}

impl ViewerGauges {
    /// Record one report. The report count goes last, with release ordering, so a reader that sees
    /// it move also sees the values stored before it.
    pub fn store(&self, r: &ViewerVideo) {
        let put =
            |slot: &AtomicU64, v: Option<u64>| slot.store(v.unwrap_or(ABSENT), Ordering::Relaxed);
        put(&self.frames_decoded, r.frames_decoded);
        put(&self.presented, presented(r));
        put(&self.frames_dropped, r.frames_dropped);
        put(&self.key_frames, r.key_frames_decoded);
        put(&self.freezes, r.freeze_count);
        self.watchdog
            .store(watchdog_code(r.watchdog.as_deref()), Ordering::Relaxed);
        self.reports.fetch_add(1, Ordering::Release);
    }
}

/// The viewer's fields on one `pipeline` line. Each is `-` when no report arrived since the
/// previous line, when the viewer does not expose it, or on the first line with a report (there
/// is nothing to difference against yet).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ViewerLine {
    /// Frames decoded since the previous line.
    pub dec: String,
    /// Frames presented (reached the screen) since the previous line.
    pub pres: String,
    /// Frames the viewer's decoder dropped since the previous line.
    pub drop: String,
    /// Keyframes decoded since the previous line.
    pub kf: String,
    /// Freezes the browser itself counted since the previous line.
    pub frz: String,
    /// The viewer's render watchdog step.
    pub wd: String,
    /// [`Self::pres`] as a number, `None` where it prints `-`: what the session summary's freeze
    /// rule reads (`crate::summary`), so the summary and the line cannot disagree.
    pub presented: Option<u64>,
}

/// What the previous `pipeline` line printed from, so the next one can difference against it.
#[derive(Debug)]
pub struct ViewerLineState {
    reports: u64,
    dec: u64,
    pres: u64,
    drop: u64,
    kf: u64,
    frz: u64,
}

impl Default for ViewerLineState {
    fn default() -> Self {
        Self {
            reports: 0,
            dec: ABSENT,
            pres: ABSENT,
            drop: ABSENT,
            kf: ABSENT,
            frz: ABSENT,
        }
    }
}

impl ViewerLineState {
    /// The fields for this second's line, and this second remembered for the next.
    pub fn take(&mut self, g: &ViewerGauges) -> ViewerLine {
        let reports = g.reports.load(Ordering::Acquire);
        let fresh = reports != self.reports;
        self.reports = reports;
        let delta = |slot: &AtomicU64, prev: &mut u64| {
            let now = slot.load(Ordering::Relaxed);
            let out = if !fresh || now == ABSENT || *prev == ABSENT {
                None
            } else {
                // Saturating: `getVideoPlaybackQuality` restarts when the viewer re-attaches its
                // stream, and a counter that went backwards moved by nothing we can count.
                Some(now.saturating_sub(*prev))
            };
            *prev = now;
            out
        };
        let field = |v: Option<u64>| v.map_or_else(|| "-".to_string(), |v| v.to_string());
        let dec = field(delta(&g.frames_decoded, &mut self.dec));
        let presented = delta(&g.presented, &mut self.pres);
        let drop = field(delta(&g.frames_dropped, &mut self.drop));
        let kf = field(delta(&g.key_frames, &mut self.kf));
        let frz = field(delta(&g.freezes, &mut self.frz));
        let wd = if fresh {
            watchdog_label(g.watchdog.load(Ordering::Relaxed))
        } else {
            "-"
        };
        ViewerLine {
            dec,
            pres: field(presented),
            drop,
            kf,
            frz,
            wd: wd.to_string(),
            presented,
        }
    }
}

/// `-` for a value the viewer did not send.
fn opt<T: Display>(v: Option<T>) -> String {
    v.map_or_else(|| "-".to_string(), |v| v.to_string())
}

/// What a counter moved between two reports: `-` when either lacks it.
fn moved(prev: Option<u64>, now: Option<u64>) -> String {
    match (prev, now) {
        (Some(p), Some(n)) => n.saturating_sub(p).to_string(),
        _ => "-".to_string(),
    }
}

/// A float from a peer, printed only when it is a number in a range that means something.
fn ms_field(v: Option<f64>) -> String {
    match v {
        Some(v) if v.is_finite() && (0.0..=600_000.0).contains(&v) => format!("{v:.1}"),
        Some(_) => "?".to_string(),
        None => "-".to_string(),
    }
}

/// A string from a peer, bounded for the log. The transport already caps the message at 4 KiB;
/// this keeps one field from being most of a log line.
fn text(v: Option<&str>) -> String {
    match v {
        Some(s) => s.chars().take(64).collect(),
        None => "-".to_string(),
    }
}

/// The session's viewer reports and keyframe requests, as the event task sees them.
#[derive(Debug, Default)]
pub struct ViewerReportLog {
    /// The previous report and when it arrived, to difference against.
    prev: Option<(Instant, ViewerVideo)>,
    reports: u64,
    /// When a viewer keyframe request was last honoured, and how many were refused since.
    kf_honoured_at: Option<Instant>,
    kf_honoured: u64,
    kf_refused: u64,
    /// The session's engine, from the first report that named one, and where it came from.
    engine: Option<(ViewerEngine, &'static str)>,
    engine_conflict_noted: bool,
}

impl ViewerReportLog {
    /// One `vv` report: stored for the pipeline line, logged with what moved since the last one,
    /// and a line of its own whenever the viewer's watchdog changes step or a freeze recovers.
    ///
    /// Returns what the playout policy reads of it, for the caller to hand to the peer.
    pub fn observe(
        &mut self,
        now: Instant,
        r: ViewerVideo,
        sid: &str,
        gauges: &ViewerGauges,
    ) -> ViewerPlayout {
        gauges.store(&r);
        self.reports += 1;
        self.note_engine(&r, sid);
        let prev = self.prev.as_ref().map(|(_, p)| p);
        let interval_ms = self
            .prev
            .as_ref()
            .map(|(at, _)| now.saturating_duration_since(*at).as_millis());
        if prev.is_none() {
            // Once per session: which browser APIs this viewer has is the first thing to know
            // when reading what follows.
            tracing::info!(
                session = sid,
                platform = %text(r.platform.as_deref()),
                engine = self.engine.map_or("-", |(e, _)| e.as_str()),
                engine_source = self.engine.map_or("-", |(_, s)| s),
                decoder = %text(r.decoder.as_deref()),
                presented_by = %text(r.presented_by.as_deref()),
                rvfc = r.rvfc_frames.is_some(),
                vpq = r.vpq_frames.is_some(),
                auto_reconnects = %opt(r.auto_reconnects),
                "viewer video reports arriving"
            );
            if let Some(n) = r.auto_reconnects.filter(|&n| n > 0) {
                tracing::info!(
                    session = sid,
                    auto_reconnects = n,
                    "this session was started by the viewer itself, after a frozen picture that a \
                     keyframe, a re-attach and a new video element did not bring back \
                     (auto_reconnects in a row)"
                );
            }
        }
        let d = |f: fn(&ViewerVideo) -> Option<u64>| moved(prev.and_then(f), f(&r));
        tracing::debug!(
            session = sid,
            interval_ms = %opt(interval_ms),
            d_recv = %d(|v| v.frames_received),
            d_dec = %d(|v| v.frames_decoded),
            d_pres = %moved(prev.and_then(presented), presented(&r)),
            d_rvfc = %d(|v| v.rvfc_frames),
            d_vpq = %d(|v| v.vpq_frames),
            d_vpq_drop = %d(|v| v.vpq_dropped),
            d_drop = %d(|v| v.frames_dropped),
            d_kf = %d(|v| v.key_frames_decoded),
            d_frz = %d(|v| v.freeze_count),
            d_frz_ms = %d(|v| v.freeze_ms),
            d_pli = %d(|v| v.pli_count),
            d_ct_ms = %d(|v| v.current_ms),
            dec = %opt(r.frames_decoded),
            pres = %opt(presented(&r)),
            res = %format!("{}x{}", opt(r.width), opt(r.height)),
            fps = %ms_field(r.fps),
            jbuf_target_ms = %ms_field(r.jbuf_target_ms),
            jbuf_min_ms = %ms_field(r.jbuf_min_ms),
            paused = %opt(r.paused),
            ready_state = %opt(r.ready_state),
            visibility = ?text(r.visibility.as_deref()),
            presented_by = ?text(r.presented_by.as_deref()),
            watchdog = ?text(r.watchdog.as_deref()),
            kf_asked = %opt(r.kf_asked),
            reattaches = %opt(r.reattaches),
            replacements = %opt(r.replacements),
            recoveries = %opt(r.recoveries),
            d_recov = %d(|v| v.recoveries),
            recovered_at = ?text(r.recovered_at.as_deref()),
            recovered_ms = %opt(r.recovered_ms),
            auto_reconnects = %opt(r.auto_reconnects),
            ev_pause = %opt(r.ev_pause),
            ev_waiting = %opt(r.ev_waiting),
            ev_stalled = %opt(r.ev_stalled),
            decoder = ?text(r.decoder.as_deref()),
            engine = ?text(r.engine.as_deref()),
            "viewer"
        );
        self.note_transitions(prev, &r, sid);
        let playout = ViewerPlayout {
            engine: self.engine.map(|(e, _)| e),
            jbuf_target_ms: r.jbuf_target_ms,
            freezes: r.freeze_count,
            freeze_ms: r.freeze_ms,
        };
        self.prev = Some((now, r));
        playout
    }

    /// The session's engine: fixed by the first report that names one (see [`viewer_engine`]),
    /// logged once; a later report that contradicts it is logged once and ignored.
    fn note_engine(&mut self, r: &ViewerVideo, sid: &str) {
        let Some((engine, source)) = viewer_engine(r) else {
            return;
        };
        match self.engine {
            None => {
                self.engine = Some((engine, source));
                tracing::info!(
                    session = sid,
                    engine = engine.as_str(),
                    source,
                    reported = %text(r.engine.as_deref()),
                    platform = %text(r.platform.as_deref()),
                    "viewer engine: {}",
                    if source == ENGINE_REPORTED {
                        "as the viewer reports it"
                    } else {
                        "implied by its Telegram platform (a viewer that predates the engine field)"
                    }
                );
            }
            Some((known, ENGINE_FROM_PLATFORM)) if known == engine && source == ENGINE_REPORTED => {
                tracing::debug!(
                    session = sid,
                    engine = engine.as_str(),
                    "viewer engine confirmed by the viewer's own report"
                );
                self.engine = Some((engine, source));
            }
            Some((known, known_source)) if known != engine => {
                // A viewer that predates the field never sends one; a newer one always does. So a
                // reported engine after a platform guess is a correction worth taking.
                if known_source == ENGINE_FROM_PLATFORM && source == ENGINE_REPORTED {
                    tracing::info!(
                        session = sid,
                        engine = engine.as_str(),
                        was = known.as_str(),
                        "viewer engine corrected by the viewer's own report"
                    );
                    self.engine = Some((engine, source));
                } else if !self.engine_conflict_noted {
                    self.engine_conflict_noted = true;
                    tracing::warn!(
                        session = sid,
                        engine = known.as_str(),
                        reported = engine.as_str(),
                        "viewer reported a different engine mid-session; the first one stands"
                    );
                }
            }
            Some(_) => {}
        }
    }

    /// A line for each change the viewer reports in its watchdog, visibility or playback.
    fn note_transitions(&self, prev: Option<&ViewerVideo>, r: &ViewerVideo, sid: &str) {
        let was = prev.and_then(|p| p.watchdog.as_deref());
        let is = r.watchdog.as_deref();
        if was != is && is.is_some() {
            let from = text(was);
            let to = text(is);
            let decoded = moved(prev.and_then(|p| p.frames_decoded), r.frames_decoded);
            let shown = moved(prev.and_then(presented), presented(r));
            match is {
                // The viewer saw its picture stop, or autoplay refused: a degradation.
                Some("keyframe" | "reattach" | "replace" | "reconnect" | "stalled" | "blocked") => {
                    tracing::warn!(
                        session = sid,
                        from = %from,
                        to = %to,
                        d_dec = %decoded,
                        d_pres = %shown,
                        kf_asked = %opt(r.kf_asked),
                        reattaches = %opt(r.reattaches),
                        replacements = %opt(r.replacements),
                        "viewer render watchdog: the viewer's picture is not reaching its screen"
                    )
                }
                _ => tracing::info!(
                    session = sid,
                    from = %from,
                    to = %to,
                    d_dec = %decoded,
                    d_pres = %shown,
                    recovered_at = %text(r.recovered_at.as_deref()),
                    "viewer render watchdog changed step"
                ),
            }
        }
        // Which step brought a frozen picture back: the question the next live session has to
        // answer. The viewer counts recoveries, so one missed report does not lose one.
        let recoveries_was = prev.and_then(|p| p.recoveries).unwrap_or(0);
        if let Some(n) = r.recoveries.filter(|&n| n > recoveries_was) {
            tracing::info!(
                session = sid,
                recovered_at = %text(r.recovered_at.as_deref()),
                recovered_ms = %opt(r.recovered_ms),
                recoveries = n,
                kf_asked = %opt(r.kf_asked),
                reattaches = %opt(r.reattaches),
                replacements = %opt(r.replacements),
                "viewer render watchdog: the frozen picture came back (recovered_at is the step it \
                 was at: keyframe, reattach, replace or stalled)"
            );
        }
        let vis_was = prev.and_then(|p| p.visibility.as_deref());
        let vis = r.visibility.as_deref();
        if prev.is_some() && vis_was != vis {
            tracing::debug!(
                session = sid,
                from = %text(vis_was),
                to = %text(vis),
                "viewer page visibility changed"
            );
        }
        let paused_was = prev.and_then(|p| p.paused);
        if prev.is_some() && paused_was != r.paused {
            tracing::debug!(
                session = sid,
                from = %opt(paused_was),
                to = %opt(r.paused),
                visibility = %text(vis),
                "viewer video element paused state changed"
            );
        }
    }

    /// A keyframe request from the viewer over the data channel: true when it should be honoured.
    ///
    /// Refused only when it follows an honoured one by less than
    /// [`KEYFRAME_REQUEST_MIN_SPACING`]; the pending-keyframe flag coalesces anyway, so a refusal
    /// costs nothing a well-behaved viewer would notice.
    pub fn keyframe_request(&mut self, now: Instant, reason: Option<&str>, sid: &str) -> bool {
        let since = self
            .kf_honoured_at
            .map(|t| now.saturating_duration_since(t));
        if since.is_some_and(|s| s < KEYFRAME_REQUEST_MIN_SPACING) {
            self.kf_refused += 1;
            tracing::debug!(
                session = sid,
                reason = %text(reason),
                since_last_ms = %opt(since.map(|s| s.as_millis())),
                min_spacing_ms = KEYFRAME_REQUEST_MIN_SPACING.as_millis() as u64,
                "viewer keyframe request refused: too soon after the last one honoured"
            );
            return false;
        }
        tracing::debug!(
            session = sid,
            reason = %text(reason),
            since_last_ms = %opt(since.map(|s| s.as_millis())),
            refused_since = self.kf_refused,
            "viewer asked for a keyframe over the data channel; forcing one"
        );
        self.kf_honoured_at = Some(now);
        self.kf_honoured += 1;
        self.kf_refused = 0;
        true
    }

    /// The session's totals, once, when it ends.
    pub fn finish(&self, sid: &str) {
        let last = self.prev.as_ref().map(|(_, r)| r);
        tracing::debug!(
            session = sid,
            reports = self.reports,
            keyframe_requests_honoured = self.kf_honoured,
            last_watchdog = %text(last.and_then(|r| r.watchdog.as_deref())),
            recoveries = %opt(last.and_then(|r| r.recoveries)),
            last_recovered_at = %text(last.and_then(|r| r.recovered_at.as_deref())),
            replacements = %opt(last.and_then(|r| r.replacements)),
            engine = self.engine.map_or("-", |(e, _)| e.as_str()),
            "viewer reports: session totals"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report(dec: u64, pres: u64) -> ViewerVideo {
        ViewerVideo {
            frames_decoded: Some(dec),
            rvfc_frames: Some(pres),
            presented_by: Some("rvfc".into()),
            frames_dropped: Some(0),
            key_frames_decoded: Some(1),
            freeze_count: Some(0),
            watchdog: Some("ok".into()),
            ..ViewerVideo::default()
        }
    }

    fn all_dash(l: &ViewerLine) -> bool {
        [&l.dec, &l.pres, &l.drop, &l.kf, &l.frz, &l.wd]
            .iter()
            .all(|f| f.as_str() == "-")
    }

    /// An older viewer never reports: the line must say "nothing reported", not "nothing moved".
    #[test]
    fn the_pipeline_fields_are_dashes_until_the_viewer_reports() {
        let g = ViewerGauges::default();
        let mut s = ViewerLineState::default();
        assert!(all_dash(&s.take(&g)));
        assert!(all_dash(&s.take(&g)));
    }

    /// A frozen `<video>`, as the pipeline line prints it: frames decoded every
    /// second, none presented.
    #[test]
    fn a_frozen_picture_reads_as_decoded_but_not_presented() {
        let g = ViewerGauges::default();
        let mut s = ViewerLineState::default();
        g.store(&report(100, 100));
        // First line with a report: nothing to difference against yet.
        let first = s.take(&g);
        assert_eq!(first.dec, "-");
        assert_eq!(first.wd, "ok");
        g.store(&ViewerVideo {
            watchdog: Some("keyframe".into()),
            ..report(160, 100)
        });
        let frozen = s.take(&g);
        assert_eq!(frozen.dec, "60");
        assert_eq!(frozen.pres, "0");
        assert_eq!(frozen.kf, "0");
        assert_eq!(frozen.wd, "keyframe");
        // The number the summary's freeze rule reads is the field's own.
        assert_eq!(first.presented, None);
        assert_eq!(frozen.presented, Some(0));
    }

    /// A second without a report prints dashes, not zeros: zero presented would read as a freeze.
    #[test]
    fn a_second_without_a_report_is_not_a_second_of_nothing() {
        let g = ViewerGauges::default();
        let mut s = ViewerLineState::default();
        g.store(&report(100, 100));
        s.take(&g);
        g.store(&report(160, 160));
        assert_eq!(s.take(&g).pres, "60");
        // No report this second.
        assert!(all_dash(&s.take(&g)));
        // The next one covers both seconds.
        g.store(&report(280, 280));
        let l = s.take(&g);
        assert_eq!(l.dec, "120");
        assert_eq!(l.pres, "120");
    }

    /// A browser without a presentation counter, and a report without a watchdog, print dashes for
    /// exactly those fields.
    #[test]
    fn a_field_the_viewer_does_not_expose_is_a_dash() {
        let g = ViewerGauges::default();
        let mut s = ViewerLineState::default();
        let bare = ViewerVideo {
            frames_decoded: Some(10),
            ..ViewerVideo::default()
        };
        g.store(&bare);
        s.take(&g);
        g.store(&ViewerVideo {
            frames_decoded: Some(40),
            ..ViewerVideo::default()
        });
        let l = s.take(&g);
        assert_eq!(l.dec, "30");
        assert_eq!(l.pres, "-");
        assert_eq!(l.drop, "-");
        assert_eq!(l.wd, "-");
    }

    #[test]
    fn the_presentation_count_follows_what_the_viewer_trusts() {
        let mut r = ViewerVideo {
            rvfc_frames: Some(5),
            vpq_frames: Some(9),
            ..ViewerVideo::default()
        };
        assert_eq!(presented(&r), Some(5), "no presented_by: rVFC first");
        r.presented_by = Some("vpq".into());
        assert_eq!(presented(&r), Some(9));
        r.presented_by = Some("time".into());
        assert_eq!(presented(&r), None, "currentTime is not a frame count");
        r.presented_by = None;
        r.rvfc_frames = None;
        assert_eq!(presented(&r), Some(9));
    }

    #[test]
    fn watchdog_states_round_trip_and_unknown_ones_are_marked() {
        for s in WATCHDOG_STATES {
            assert_eq!(watchdog_label(watchdog_code(Some(s))), s);
        }
        assert_eq!(watchdog_label(watchdog_code(None)), "-");
        assert_eq!(watchdog_label(watchdog_code(Some("meditating"))), "?");
    }

    /// A re-attached stream restarts `getVideoPlaybackQuality`; that second moved by nothing
    /// countable, not by eighteen quintillion frames.
    #[test]
    fn a_counter_that_restarts_prints_zero_not_a_wraparound() {
        let g = ViewerGauges::default();
        let mut s = ViewerLineState::default();
        let vpq = |n: u64| ViewerVideo {
            vpq_frames: Some(n),
            presented_by: Some("vpq".into()),
            ..ViewerVideo::default()
        };
        g.store(&vpq(5000));
        s.take(&g);
        g.store(&vpq(12));
        assert_eq!(s.take(&g).pres, "0");
        g.store(&vpq(70));
        assert_eq!(s.take(&g).pres, "58");
    }

    #[test]
    fn keyframe_requests_are_bounded_by_the_agent_too() {
        let mut log = ViewerReportLog::default();
        let t0 = Instant::now();
        assert!(log.keyframe_request(t0, Some("render_stall"), "s"));
        // A buggy viewer asking again at once is refused...
        assert!(!log.keyframe_request(t0 + Duration::from_millis(200), Some("render_stall"), "s"));
        assert!(!log.keyframe_request(t0 + Duration::from_millis(900), None, "s"));
        // ...and one that waits its turn is not.
        assert!(log.keyframe_request(t0 + KEYFRAME_REQUEST_MIN_SPACING, Some("decode_stall"), "s"));
        assert_eq!(log.kf_honoured, 2);
        assert_eq!(log.kf_refused, 0, "reset by the honoured one");
    }

    #[test]
    fn observing_reports_feeds_the_gauges_and_remembers_the_previous_one() {
        let mut log = ViewerReportLog::default();
        let g = ViewerGauges::default();
        let t0 = Instant::now();
        log.observe(t0, report(10, 10), "s", &g);
        log.observe(
            t0 + Duration::from_secs(1),
            ViewerVideo {
                watchdog: Some("stalled".into()),
                ..report(70, 10)
            },
            "s",
            &g,
        );
        assert_eq!(log.reports, 2);
        assert_eq!(g.reports.load(Ordering::Relaxed), 2);
        assert_eq!(g.frames_decoded.load(Ordering::Relaxed), 70);
        assert_eq!(
            watchdog_label(g.watchdog.load(Ordering::Relaxed)),
            "stalled"
        );
        assert_eq!(
            log.prev.as_ref().and_then(|(_, r)| r.watchdog.as_deref()),
            Some("stalled")
        );
    }

    #[test]
    fn the_engine_is_the_viewers_word_or_what_its_platform_implies() {
        let with = |engine: Option<&str>, platform: Option<&str>| {
            viewer_engine(&ViewerVideo {
                engine: engine.map(str::to_string),
                platform: platform.map(str::to_string),
                ..ViewerVideo::default()
            })
        };
        // The viewer's own word wins, whatever the platform says.
        assert_eq!(
            with(Some("chromium"), Some("ios")),
            Some((ViewerEngine::Chromium, ENGINE_REPORTED))
        );
        assert_eq!(
            with(Some("webkit"), None),
            Some((ViewerEngine::WebKit, ENGINE_REPORTED))
        );
        assert_eq!(
            with(Some("netscape"), Some("android")),
            Some((ViewerEngine::Unknown, ENGINE_REPORTED))
        );
        // A viewer that predates the field: Telegram's platform.
        for (platform, engine) in [
            ("ios", ViewerEngine::WebKit),
            ("macos", ViewerEngine::WebKit),
            ("android", ViewerEngine::Chromium),
            ("android_x", ViewerEngine::Chromium),
            // WebView2 on Windows, but WebKit on macOS and Linux: not an engine.
            ("tdesktop", ViewerEngine::Unknown),
            ("weba", ViewerEngine::Unknown),
            ("browser", ViewerEngine::Unknown),
        ] {
            assert_eq!(
                with(None, Some(platform)),
                Some((engine, ENGINE_FROM_PLATFORM)),
                "{platform}"
            );
        }
        assert_eq!(with(None, None), None);
    }

    /// Each report hands the playout policy the viewer's jitter-buffer target, and the session's
    /// engine once known; a platform guess gives way to the viewer's own word, and a contradiction
    /// after that is ignored.
    #[test]
    fn observing_a_report_hands_the_playout_its_buffer_and_engine() {
        let mut log = ViewerReportLog::default();
        let g = ViewerGauges::default();
        let t0 = Instant::now();
        let first = log.observe(
            t0,
            ViewerVideo {
                platform: Some("ios".into()),
                jbuf_target_ms: Some(222.5),
                ..report(10, 10)
            },
            "s",
            &g,
        );
        assert_eq!(first.engine, Some(ViewerEngine::WebKit));
        assert_eq!(first.jbuf_target_ms, Some(222.5));
        let second = log.observe(
            t0 + Duration::from_secs(1),
            ViewerVideo {
                platform: Some("ios".into()),
                engine: Some("webkit".into()),
                ..report(70, 70)
            },
            "s",
            &g,
        );
        assert_eq!(second.engine, Some(ViewerEngine::WebKit));
        assert_eq!(
            second.jbuf_target_ms, None,
            "absent in this report: not carried over"
        );
        assert_eq!(log.engine, Some((ViewerEngine::WebKit, ENGINE_REPORTED)));
        let third = log.observe(
            t0 + Duration::from_secs(2),
            ViewerVideo {
                engine: Some("chromium".into()),
                jbuf_target_ms: Some(40.0),
                freeze_count: Some(3),
                freeze_ms: Some(840),
                ..report(130, 130)
            },
            "s",
            &g,
        );
        assert_eq!(
            third.engine,
            Some(ViewerEngine::WebKit),
            "the first report stands"
        );
        assert!(log.engine_conflict_noted);
        assert_eq!(third.jbuf_target_ms, Some(40.0));
        // The freeze counters go on as the viewer sent them, cumulative: the policy differences
        // them itself, so a report the peer's queue refused loses no freeze.
        assert_eq!((third.freezes, third.freeze_ms), (Some(3), Some(840)));
        assert_eq!(
            (first.freezes, first.freeze_ms),
            (Some(0), None),
            "absent stays absent"
        );
    }

    /// The step a freeze recovered at, and the new steps, reach the pipeline line and the log.
    #[test]
    fn the_new_watchdog_steps_and_recoveries_are_read() {
        let g = ViewerGauges::default();
        let mut s = ViewerLineState::default();
        g.store(&ViewerVideo {
            watchdog: Some("replace".into()),
            ..report(100, 100)
        });
        assert_eq!(s.take(&g).wd, "replace");
        g.store(&ViewerVideo {
            watchdog: Some("reconnect".into()),
            ..report(160, 100)
        });
        assert_eq!(s.take(&g).wd, "reconnect");

        let mut log = ViewerReportLog::default();
        let t0 = Instant::now();
        log.observe(
            t0,
            ViewerVideo {
                watchdog: Some("replace".into()),
                replacements: Some(1),
                recoveries: Some(0),
                ..report(100, 40)
            },
            "s",
            &g,
        );
        log.observe(
            t0 + Duration::from_secs(1),
            ViewerVideo {
                watchdog: Some("ok".into()),
                replacements: Some(1),
                recoveries: Some(1),
                recovered_at: Some("replace".into()),
                recovered_ms: Some(6100),
                ..report(160, 100)
            },
            "s",
            &g,
        );
        let last = log.prev.as_ref().map(|(_, r)| r);
        assert_eq!(
            last.and_then(|r| r.recovered_at.as_deref()),
            Some("replace")
        );
        assert_eq!(last.and_then(|r| r.recoveries), Some(1));
    }

    #[test]
    fn peer_values_are_bounded_for_the_log() {
        assert_eq!(ms_field(Some(42.5)), "42.5");
        assert_eq!(ms_field(Some(f64::NAN)), "?");
        assert_eq!(ms_field(Some(-1.0)), "?");
        assert_eq!(ms_field(None), "-");
        assert_eq!(text(Some("x".repeat(500).as_str())).len(), 64);
        assert_eq!(text(None), "-");
    }
}
