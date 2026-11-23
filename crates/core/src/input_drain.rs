//! Input that the network held back and then released all at once is not injected.
//!
//! The viewer's `input` data channel is ordered and reliable. When the viewer's path drops for a
//! while, its SCTP keeps everything it was given and sends it once the path is back. If its
//! retransmission timer backed off during the outage, that can be half a minute later, and every
//! click, key and move of that half minute arrives within one second. A game reads that as a chord
//! or as a key held for the length of the outage (`crate::input_rhythm` shows it as a gap and then a
//! burst). Messages carry no send time, so their age cannot be read from them.
//!
//! The channel has its own clock: the viewer's `vv` report, sent once a second for as long as the
//! session lives, on the same ordered `input` channel as presses and keys. So:
//!
//! - **Stall.** The `input` channel (every message the contract routes to it: everything but `m`,
//!   `r` and `w`) is silent for [`STALL_SILENCE`] or more. The silence must have begun while the
//!   viewer said it was visible: a hidden page sends little or nothing and its silence is not a
//!   stall. The `vv` clock must have been running when it began: a `vv` arrived at most
//!   [`CLOCK_FRESH`] before. A viewer that sends no `vv` has no clock, and its pauses are the
//!   person's.
//! - **Draining** begins with the first message after such a silence. Until it ends, presses
//!   (`d`), key downs, text, combos, the wheel and pointer moves (`m`, `r`) are counted and not
//!   injected. Button releases (`u`), key ups and `ra` always pass, so nothing can be left held, and
//!   messages that are not input (`vv`, `vis`, `q`, `kf`, the clipboard) keep reaching their handlers.
//! - **Draining ends** on the first of:
//!   - a `vv` that arrives [`CADENCE_GAP`] or more after the previous one (or after the start of the
//!     drain). The queue is empty and reports arrive at their normal rate again. That `vv` and
//!     everything after it pass;
//!   - no `vv` for [`NO_REPORT_EXIT`] while draining;
//!   - [`DRAIN_CAP`] since it began.
//!
//! The cost: fresh input in the first second or so after the path comes back is lost too. Without
//! this, input from up to half a minute earlier would be injected all at once.
//!
//! Logging: the start and the end of each drain at info, with the silence, why it ended and what
//! was dropped by kind. Nothing per message: this is the input hot path. The session's 10-second
//! `input` line counts the dropped messages as `drained`.
//!
//! State is local to the session's event task. Times come in as arguments so tests can replay a
//! timeline.

use std::time::{Duration, Instant};

use afklink_protocol::{InputChannel, InputMessage};

/// A silence of the `input` channel this long, while the viewer is visible and its `vv` clock is
/// running, is a stall. The viewer reports once a second, so this is two and a half missed
/// reports. It is above [`afklink_protocol::INPUT_SILENCE_RELEASE_MS`] (2 s). When both channels
/// stall, as a lost path does, the agent's silence release has let go of whatever was held before
/// the backlog arrives. That release counts any data-channel message, so while moves keep coming on
/// the `cursor` channel and only the `input` channel stalls, a held key or button stays down until
/// its release arrives in the backlog. A release always passes a drain.
pub(crate) const STALL_SILENCE: Duration = Duration::from_millis(2_500);

/// The `vv` clock counts as running at the start of a silence if a `vv` arrived at most this long
/// before.
pub(crate) const CLOCK_FRESH: Duration = Duration::from_millis(2_500);

/// While draining, a `vv` this long or longer after the previous one means the queue is empty.
/// Reports that were queued arrive a few milliseconds apart (about 30 in one second in the
/// recorded incident), and reports at the normal rate arrive about a second apart.
pub(crate) const CADENCE_GAP: Duration = Duration::from_millis(600);

/// While draining, this long without a `vv` ends the drain. The queue is not draining any more,
/// and the viewer may have stopped reporting.
pub(crate) const NO_REPORT_EXIT: Duration = Duration::from_millis(1_500);

/// A drain never lasts longer than this.
pub(crate) const DRAIN_CAP: Duration = Duration::from_secs(5);

/// Why a drain ended, for its log line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DrainEnd {
    /// A `vv` arrived at the normal rate again.
    Cadence,
    /// No `vv` for [`NO_REPORT_EXIT`].
    NoReport,
    /// [`DRAIN_CAP`] reached.
    Cap,
    /// The session ended while draining.
    SessionEnd,
}

impl DrainEnd {
    fn as_str(self) -> &'static str {
        match self {
            Self::Cadence => "reports back on cadence",
            Self::NoReport => "no report",
            Self::Cap => "cap",
            Self::SessionEnd => "session ended",
        }
    }
}

/// What was not injected during one drain, by kind. Counts only, never content.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Dropped {
    /// `d`.
    pub(crate) presses: u64,
    /// `k` with `d` other than 0.
    pub(crate) key_downs: u64,
    /// `text`.
    pub(crate) text: u64,
    /// `combo`.
    pub(crate) combos: u64,
    /// `w`.
    pub(crate) wheel: u64,
    /// `m`.
    pub(crate) abs: u64,
    /// `r`.
    pub(crate) rel: u64,
}

impl Dropped {
    pub(crate) fn total(&self) -> u64 {
        self.presses + self.key_downs + self.text + self.combos + self.wheel + self.abs + self.rel
    }
}

/// One drain in progress.
#[derive(Debug)]
struct Draining {
    since: Instant,
    /// The last `vv` received during this drain.
    last_report: Option<Instant>,
    dropped: Dropped,
    /// Releases (`u`, key ups, `ra`) that passed during this drain.
    releases: u64,
    /// `vv` reports received during this drain.
    reports: u64,
}

impl Draining {
    /// What the next `vv` is measured from, and the [`NO_REPORT_EXIT`] deadline too.
    fn report_mark(&self) -> Instant {
        self.last_report.unwrap_or(self.since)
    }

    /// The time-based end due at `now`, and when it fell due.
    fn due(&self, now: Instant) -> Option<(DrainEnd, Instant)> {
        let cap = self.since + DRAIN_CAP;
        let quiet = self.report_mark() + NO_REPORT_EXIT;
        if now >= cap.min(quiet) {
            Some(if cap <= quiet {
                (DrainEnd::Cap, cap)
            } else {
                (DrainEnd::NoReport, quiet)
            })
        } else {
            None
        }
    }
}

/// The session's drain state. See the module documentation.
#[derive(Debug)]
pub(crate) struct InputDrain {
    /// The last message on the `input` channel.
    last_input_lane: Option<Instant>,
    /// The last `vv`.
    last_report: Option<Instant>,
    /// What the viewer said about its page: by `vis`, or by the `visibility` of a `vv`. A session
    /// starts visible, as the viewer and the background hold assume.
    visible: bool,
    /// When the page became visible, as told, for the drain's start line.
    visible_since: Instant,
    draining: Option<Draining>,
    /// The last drain's end: why, how long, what was dropped, releases passed.
    #[cfg(test)]
    last_end: Option<(DrainEnd, u64, Dropped, u64)>,
}

/// Whether a message may go on to its handler.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Admit {
    Pass,
    /// Part of a backlog: not injected, counted.
    Drop,
}

impl InputDrain {
    pub(crate) fn new(now: Instant) -> Self {
        Self {
            last_input_lane: None,
            last_report: None,
            visible: true,
            visible_since: now,
            draining: None,
            #[cfg(test)]
            last_end: None,
        }
    }

    /// Whether a drain is in progress.
    #[cfg(test)]
    pub(crate) fn is_draining(&self) -> bool {
        self.draining.is_some()
    }

    /// End a drain whose time is up at `now`. Called on every turn of the event loop, so the end
    /// line comes on time even if nothing arrives.
    pub(crate) fn expire(&mut self, now: Instant, sid: &str) {
        if let Some((why, at)) = self.draining.as_ref().and_then(|d| d.due(now)) {
            self.end(why, at, sid);
        }
    }

    /// The session is over: a drain still in progress ends here.
    pub(crate) fn finish(&mut self, now: Instant, sid: &str) {
        self.expire(now, sid);
        if self.draining.is_some() {
            self.end(DrainEnd::SessionEnd, now, sid);
        }
    }

    /// A parsed message from the viewer arrived at `now`. Says whether it may go on.
    pub(crate) fn admit(&mut self, now: Instant, m: &InputMessage, sid: &str) -> Admit {
        self.expire(now, sid);
        let report = matches!(m, InputMessage::ViewerVideo(_));
        if m.channel() == InputChannel::Input {
            self.note_input_lane(now, m, sid);
        }
        // What the viewer says about its page takes effect after the stall check above, which asks
        // what the page was when the silence began.
        match m {
            InputMessage::Visibility { hidden, .. } => self.told_visible(!*hidden, now),
            InputMessage::ViewerVideo(v) => match v.visibility.as_deref() {
                Some("visible") => self.told_visible(true, now),
                Some("hidden") => self.told_visible(false, now),
                _ => {}
            },
            _ => {}
        }
        if report {
            self.last_report = Some(now);
        }
        let Some(d) = self.draining.as_mut() else {
            return Admit::Pass;
        };
        match m {
            InputMessage::ViewerVideo(_) => {
                d.reports += 1;
                if now.saturating_duration_since(d.report_mark()) >= CADENCE_GAP {
                    self.end(DrainEnd::Cadence, now, sid);
                } else {
                    d.last_report = Some(now);
                }
                Admit::Pass
            }
            InputMessage::Down { .. } => count_drop(&mut d.dropped.presses),
            InputMessage::Key { d: down, .. } if *down != 0 => count_drop(&mut d.dropped.key_downs),
            InputMessage::Text { .. } => count_drop(&mut d.dropped.text),
            InputMessage::Combo { .. } => count_drop(&mut d.dropped.combos),
            InputMessage::Wheel { .. } => count_drop(&mut d.dropped.wheel),
            InputMessage::Move { .. } => count_drop(&mut d.dropped.abs),
            InputMessage::Rel { .. } => count_drop(&mut d.dropped.rel),
            InputMessage::Up { .. } | InputMessage::Key { .. } | InputMessage::ReleaseAll => {
                d.releases += 1;
                Admit::Pass
            }
            // Not input: its handler decides.
            _ => Admit::Pass,
        }
    }

    /// A message on the `input` channel arrived: the stall check, then the channel's clock.
    fn note_input_lane(&mut self, now: Instant, m: &InputMessage, sid: &str) {
        let last = self.last_input_lane.replace(now);
        if self.draining.is_some() {
            return;
        }
        let Some(last) = last else { return };
        let silence = now.saturating_duration_since(last);
        if silence < STALL_SILENCE {
            return;
        }
        // Once per pause of 2.5 s or more: not the hot path.
        if !self.visible {
            tracing::debug!(
                session = sid,
                silence_ms = silence.as_millis() as u64,
                "input channel silent while the viewer said it was hidden: not a stall, \
                 nothing dropped"
            );
            return;
        }
        let clock = self.last_report.map(|r| last.saturating_duration_since(r));
        if !clock.is_some_and(|age| age <= CLOCK_FRESH) {
            tracing::debug!(
                session = sid,
                silence_ms = silence.as_millis() as u64,
                report_age_at_silence_ms = clock.map(|a| a.as_millis() as u64),
                "input channel silent, but the viewer's once-a-second report was not arriving \
                 when the silence began: taken as a pause, nothing dropped"
            );
            return;
        }
        tracing::info!(
            session = sid,
            silence_ms = silence.as_millis() as u64,
            report_age_at_silence_ms = clock.map(|a| a.as_millis() as u64),
            visible_for_ms = last
                .saturating_duration_since(self.visible_since)
                .as_millis() as u64,
            first = kind(m),
            "input backlog: the viewer's input channel was stalled while its page was visible; \
             presses, keys, text, wheel and moves are not injected until its reports arrive at \
             their normal rate again (releases pass)"
        );
        self.draining = Some(Draining {
            since: now,
            last_report: None,
            dropped: Dropped::default(),
            releases: 0,
            reports: 0,
        });
    }

    fn told_visible(&mut self, visible: bool, now: Instant) {
        if visible && !self.visible {
            self.visible_since = now;
        }
        self.visible = visible;
    }

    fn end(&mut self, why: DrainEnd, at: Instant, sid: &str) {
        let Some(d) = self.draining.take() else {
            return;
        };
        let x = d.dropped;
        let lasted_ms = at.saturating_duration_since(d.since).as_millis() as u64;
        #[cfg(test)]
        {
            self.last_end = Some((why, lasted_ms, x, d.releases));
        }
        tracing::info!(
            session = sid,
            why = why.as_str(),
            lasted_ms,
            dropped = x.total(),
            presses = x.presses,
            key_downs = x.key_downs,
            text = x.text,
            combos = x.combos,
            wheel = x.wheel,
            abs = x.abs,
            rel = x.rel,
            releases_passed = d.releases,
            reports = d.reports,
            "input backlog over: input is injected again"
        );
    }
}

fn count_drop(count: &mut u64) -> Admit {
    *count += 1;
    Admit::Drop
}

/// The message's wire tag, for the drain's start line: the kind only, never its content.
fn kind(m: &InputMessage) -> &'static str {
    match m {
        InputMessage::Move { .. } => "m",
        InputMessage::Rel { .. } => "r",
        InputMessage::Wheel { .. } => "w",
        InputMessage::Down { .. } => "d",
        InputMessage::Up { .. } => "u",
        InputMessage::Key { .. } => "k",
        InputMessage::Combo { .. } => "combo",
        InputMessage::Text { .. } => "text",
        InputMessage::ReleaseAll => "ra",
        InputMessage::Quality { .. } => "q",
        InputMessage::ViewerLatency { .. } => "vl",
        InputMessage::ViewerVideo(_) => "vv",
        InputMessage::KeyframeRequest { .. } => "kf",
        InputMessage::Visibility { .. } => "vis",
        InputMessage::ClipboardSync { .. } => "cb_sync",
        InputMessage::ClipboardSet(_) => "cb_set",
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use std::sync::{Arc, Mutex};

    use afklink_transport::PeerEvent;

    use crate::input_session::{InputSession, InputSilence};
    use crate::traits::InputInjector;

    const VV: &str = r#"{"t":"vv","visibility":"visible"}"#;
    const D: &str = r#"{"t":"d","b":0}"#;
    const U: &str = r#"{"t":"u","b":0}"#;
    const VIS_HIDDEN: &str = r#"{"t":"vis","hidden":true}"#;
    const VIS_VISIBLE: &str = r#"{"t":"vis","hidden":false}"#;

    fn msg(s: &str) -> InputMessage {
        InputMessage::parse(s).unwrap()
    }

    fn rel(s: u32) -> InputMessage {
        msg(&format!(r#"{{"t":"r","dx":0.001,"dy":0,"s":{s}}}"#))
    }

    /// Replays messages on a millisecond timeline.
    struct Replay {
        t0: Instant,
        drain: InputDrain,
    }

    impl Replay {
        fn new() -> Self {
            let t0 = Instant::now();
            Self {
                t0,
                drain: InputDrain::new(t0),
            }
        }

        fn at(&mut self, ms: u64, m: &InputMessage) -> Admit {
            self.drain
                .admit(self.t0 + Duration::from_millis(ms), m, "s")
        }

        fn at_s(&mut self, ms: u64, s: &str) -> Admit {
            self.at(ms, &msg(s))
        }

        /// A `vv` each second over `[from, to)`, all passing.
        fn reports(&mut self, from: u64, to: u64) {
            for ms in (from..to).step_by(1_000) {
                assert_eq!(self.at_s(ms, VV), Admit::Pass, "vv at {ms}");
            }
        }

        fn ended(&self) -> Option<(DrainEnd, u64, Dropped, u64)> {
            self.drain.last_end
        }
    }

    /// The recorded incident (viewer on WebKit, 0.11.1): reports at 1 Hz, then 34 s of nothing,
    /// then about 30 reports, 36 clicks and 1437 relative moves within one second, then reports at
    /// 1 Hz again.
    #[test]
    fn the_incident_replayed_drops_presses_and_moves_passes_releases_and_ends_on_cadence() {
        let mut r = Replay::new();
        r.reports(0, 25_001);
        assert_eq!(r.at_s(25_100, D), Admit::Pass);
        assert_eq!(r.at_s(25_200, U), Admit::Pass);
        r.at_s(25_800, VV);
        // The burst: 59 980 .. 60 950, reports every 33 ms, a click pair and moves between them.
        let (mut presses, mut releases, mut moves) = (0, 0, 0);
        let mut seq = 0u32;
        for i in 0..30u64 {
            let t = 59_980 + i * 33;
            assert_eq!(
                r.at_s(t, VV),
                Admit::Pass,
                "a report always reaches its handler"
            );
            assert!(r.drain.is_draining(), "draining at {t}");
            if i < 18 {
                assert_eq!(r.at_s(t + 5, D), Admit::Drop);
                presses += 1;
                assert_eq!(r.at_s(t + 10, U), Admit::Pass, "a release always passes");
                releases += 1;
            }
            for k in 0..48u64 {
                if moves == 1437 {
                    break;
                }
                assert_eq!(r.at(t + 12 + k / 3, &rel(seq)), Admit::Drop);
                seq += 1;
                moves += 1;
            }
        }
        assert_eq!(moves, 1437);
        assert!(r.ended().is_none(), "still draining after the burst");
        // Back on cadence: 940 ms after the burst's last report.
        assert_eq!(r.at_s(61_890, VV), Admit::Pass);
        assert!(!r.drain.is_draining());
        let (why, lasted, dropped, passed) = r.ended().unwrap();
        assert_eq!(why, DrainEnd::Cadence);
        assert_eq!(lasted, 61_890 - 59_980);
        assert_eq!(dropped.presses, presses);
        assert_eq!(dropped.rel, 1437);
        assert_eq!(dropped.total(), presses + 1437);
        assert_eq!(passed, releases);
        // And what the person does now goes through.
        assert_eq!(r.at_s(62_000, D), Admit::Pass);
        assert_eq!(r.at(62_010, &rel(seq)), Admit::Pass);
        assert_eq!(r.at_s(62_100, U), Admit::Pass);
    }

    #[test]
    fn the_first_click_right_after_the_backlog_ends_passes() {
        let mut r = Replay::new();
        r.reports(0, 10_001);
        // 20 s stalled; the backlog is three reports and a press.
        assert_eq!(r.at_s(30_000, VV), Admit::Pass);
        assert!(r.drain.is_draining());
        assert_eq!(r.at_s(30_010, D), Admit::Drop);
        r.at_s(30_020, VV);
        r.at_s(30_030, VV);
        // The viewer's next report on its own timer, then the person's click 10 ms after it.
        assert_eq!(r.at_s(30_900, VV), Admit::Pass);
        assert_eq!(r.ended().unwrap().0, DrainEnd::Cadence);
        assert_eq!(r.at_s(30_910, D), Admit::Pass);
        assert_eq!(r.at_s(30_990, U), Admit::Pass);
    }

    #[test]
    fn a_silence_while_hidden_is_not_a_stall() {
        let mut r = Replay::new();
        r.reports(0, 5_001);
        assert_eq!(r.at_s(5_200, VIS_HIDDEN), Admit::Pass);
        // 200 s hidden: a suspended page sends nothing at all.
        assert_eq!(r.at_s(205_200, VIS_VISIBLE), Admit::Pass);
        assert_eq!(r.at_s(205_300, VV), Admit::Pass);
        assert_eq!(r.at_s(205_400, D), Admit::Pass);
        assert_eq!(r.at_s(205_450, U), Admit::Pass);
        assert!(!r.drain.is_draining());
        assert!(r.ended().is_none());
    }

    /// A page that is hidden keeps reporting `hidden` in its `vv` until its timers stop.
    #[test]
    fn a_report_that_says_hidden_counts_as_told_hidden() {
        let mut r = Replay::new();
        r.reports(0, 3_001);
        r.at_s(4_000, r#"{"t":"vv","visibility":"hidden"}"#);
        assert_eq!(r.at_s(60_000, VV), Admit::Pass);
        assert_eq!(r.at_s(60_050, D), Admit::Pass);
        assert!(r.ended().is_none());
    }

    #[test]
    fn an_idle_viewer_whose_reports_keep_flowing_clicks_after_ten_seconds_unhindered() {
        let mut r = Replay::new();
        r.reports(0, 500);
        assert_eq!(r.at_s(500, D), Admit::Pass);
        assert_eq!(r.at_s(560, U), Admit::Pass);
        r.reports(1_000, 10_001);
        assert_eq!(r.at_s(10_500, D), Admit::Pass);
        assert_eq!(r.at(10_510, &rel(0)), Admit::Pass);
        assert_eq!(r.at_s(10_560, U), Admit::Pass);
        assert!(r.ended().is_none());
    }

    /// A viewer that sends no `vv` has no clock: its pauses are the person's.
    #[test]
    fn a_viewer_without_reports_never_drains() {
        let mut r = Replay::new();
        assert_eq!(r.at_s(0, D), Admit::Pass);
        assert_eq!(r.at_s(50, U), Admit::Pass);
        assert_eq!(r.at_s(10_000, D), Admit::Pass);
        assert_eq!(r.at_s(10_050, U), Admit::Pass);
        assert!(r.ended().is_none());
    }

    /// Reports that stopped long before the silence are no running clock either.
    #[test]
    fn reports_that_stopped_before_the_silence_do_not_start_a_drain() {
        let mut r = Replay::new();
        r.reports(0, 2_001);
        // Typing goes on for a while after the last report, then a pause.
        for ms in (2_100..8_000).step_by(200) {
            assert_eq!(r.at_s(ms, D), Admit::Pass);
        }
        assert_eq!(r.at_s(20_000, D), Admit::Pass);
        assert!(r.ended().is_none());
    }

    #[test]
    fn a_long_backlog_is_cut_off_at_the_cap() {
        let mut r = Replay::new();
        r.reports(0, 10_001);
        // Reports keep arriving 100 ms apart for 7 s: never back on cadence.
        for i in 0..70u64 {
            let t = 40_000 + i * 100;
            r.at_s(t, VV);
            let verdict = r.at_s(t + 50, D);
            if t + 50 < 45_000 {
                assert_eq!(verdict, Admit::Drop, "at {}", t + 50);
            } else {
                assert_eq!(verdict, Admit::Pass, "at {}", t + 50);
            }
        }
        let (why, lasted, _, _) = r.ended().unwrap();
        assert_eq!(why, DrainEnd::Cap);
        assert_eq!(lasted, 5_000);
    }

    #[test]
    fn no_report_while_draining_ends_it() {
        let mut r = Replay::new();
        r.reports(0, 10_001);
        assert_eq!(r.at_s(20_000, D), Admit::Drop);
        assert_eq!(r.at_s(21_400, D), Admit::Drop);
        assert_eq!(r.at_s(21_600, D), Admit::Pass);
        let (why, lasted, dropped, _) = r.ended().unwrap();
        assert_eq!(why, DrainEnd::NoReport);
        assert_eq!(lasted, 1_500);
        assert_eq!(dropped.presses, 2);
    }

    #[test]
    fn the_event_loop_turn_ends_a_drain_whose_time_is_up() {
        let mut r = Replay::new();
        r.reports(0, 3_001);
        r.at_s(10_000, D);
        r.drain.expire(r.t0 + Duration::from_millis(11_400), "s");
        assert!(r.drain.is_draining());
        r.drain.expire(r.t0 + Duration::from_millis(11_600), "s");
        assert!(!r.drain.is_draining());
        assert_eq!(r.ended().unwrap().0, DrainEnd::NoReport);
    }

    #[test]
    fn a_session_ending_mid_drain_says_so() {
        let mut r = Replay::new();
        r.reports(0, 3_001);
        r.at_s(10_000, VV);
        r.drain.finish(r.t0 + Duration::from_millis(10_200), "s");
        assert_eq!(r.ended().unwrap().0, DrainEnd::SessionEnd);
    }

    #[test]
    fn every_kind_of_input_but_releases_is_dropped_while_draining() {
        let mut r = Replay::new();
        r.reports(0, 3_001);
        r.at_s(10_000, VV);
        for (s, want) in [
            (D, Admit::Drop),
            (U, Admit::Pass),
            (r#"{"t":"k","d":1,"code":"KeyW"}"#, Admit::Drop),
            (r#"{"t":"k","d":0,"code":"KeyW"}"#, Admit::Pass),
            (r#"{"t":"text","text":"hi"}"#, Admit::Drop),
            (r#"{"t":"combo","name":"alt_tab"}"#, Admit::Drop),
            (r#"{"t":"w","dx":0,"dy":120}"#, Admit::Drop),
            (r#"{"t":"m","x":0.5,"y":0.5}"#, Admit::Drop),
            (r#"{"t":"r","dx":0.01,"dy":0}"#, Admit::Drop),
            (r#"{"t":"ra"}"#, Admit::Pass),
            (r#"{"t":"q","q":"auto"}"#, Admit::Pass),
            (r#"{"t":"kf","reason":"render_stall"}"#, Admit::Pass),
            (
                r#"{"t":"vl","jbuf_ms":10,"frames":60,"jitter_ms":1}"#,
                Admit::Pass,
            ),
            (r#"{"t":"cb_sync","on":true}"#, Admit::Pass),
            (VIS_VISIBLE, Admit::Pass),
        ] {
            assert_eq!(r.at_s(10_010, s), want, "{s}");
        }
        r.drain.finish(r.t0 + Duration::from_millis(10_100), "s");
        let (_, _, d, passed) = r.ended().unwrap();
        assert_eq!(
            d,
            Dropped {
                presses: 1,
                key_downs: 1,
                text: 1,
                combos: 1,
                wheel: 1,
                abs: 1,
                rel: 1
            }
        );
        assert_eq!(passed, 3);
    }

    #[test]
    fn a_silence_just_under_the_threshold_passes_and_one_at_it_drains() {
        let mut r = Replay::new();
        r.reports(0, 3_001);
        assert_eq!(r.at_s(5_400, D), Admit::Pass, "2.4 s of silence");
        assert!(!r.drain.is_draining());
        r.reports(6_000, 8_001);
        assert_eq!(r.at_s(10_500, D), Admit::Drop, "2.5 s of silence");
        assert!(r.drain.is_draining());
    }

    /// Moves on the `cursor` channel say nothing about the `input` channel's queue.
    #[test]
    fn moves_on_the_cursor_channel_do_not_keep_the_input_channel_clock() {
        let mut r = Replay::new();
        r.reports(0, 5_001);
        for i in 0..1_000u32 {
            let ms = 5_016 + u64::from(i) * 16;
            assert_eq!(r.at(ms, &rel(i)), Admit::Pass, "move at {ms}");
        }
        assert_eq!(r.at_s(30_000, D), Admit::Drop);
        assert!(r.drain.is_draining());
    }

    #[test]
    fn a_return_opened_by_a_report_saying_visible_after_one_saying_hidden_does_not_drain() {
        let mut r = Replay::new();
        r.reports(0, 3_001);
        r.at_s(3_500, r#"{"t":"vv","visibility":"hidden"}"#);
        assert_eq!(r.at_s(90_000, VV), Admit::Pass);
        assert!(!r.drain.is_draining());
        assert_eq!(r.at_s(90_050, D), Admit::Pass);
        assert!(r.ended().is_none());
    }

    #[derive(Default)]
    struct Keys {
        held: Mutex<Vec<String>>,
        injected: Mutex<Vec<InputMessage>>,
        releases: Mutex<usize>,
    }

    impl InputInjector for Keys {
        fn inject(&self, event: &InputMessage) -> anyhow::Result<()> {
            if let InputMessage::Key { d, code, .. } = event {
                let mut held = self.held.lock().unwrap();
                held.retain(|c| c != code);
                if *d != 0 {
                    held.push(code.clone());
                }
            }
            self.injected.lock().unwrap().push(event.clone());
            Ok(())
        }

        fn release_all(&self) {
            self.held.lock().unwrap().clear();
            *self.releases.lock().unwrap() += 1;
        }
    }

    /// The silence release still does its part: a key held when the channel stalled goes up after
    /// 2 s, the backlog's key-up for it later passes and changes nothing, and the backlog's next
    /// press of it is not injected.
    #[test]
    fn a_key_held_into_the_stall_is_released_by_the_silence_and_its_late_key_up_is_harmless() {
        let keys = Arc::new(Keys::default());
        let session = InputSession::new(keys.clone());
        let mut silence = InputSilence::new();
        let mut r = Replay::new();
        let t0 = r.t0;
        let t = |ms: u64| t0 + Duration::from_millis(ms);
        let data = |s: &str| PeerEvent::InputData(s.as_bytes().to_vec());
        let down = r#"{"t":"k","d":1,"code":"KeyW"}"#;
        let up = r#"{"t":"k","d":0,"code":"KeyW"}"#;

        for ms in (0..5_001).step_by(1_000) {
            silence.note_peer_event(t(ms), &data(VV));
            r.at_s(ms, VV);
        }
        silence.note_peer_event(t(5_100), &data(down));
        assert_eq!(r.at_s(5_100, down), Admit::Pass);
        session.inject(&msg(down)).unwrap();
        assert_eq!(*keys.held.lock().unwrap(), ["KeyW"]);

        // The stall: nothing arrives; the event loop turns on its timeout.
        assert!(!silence.release_due(t(7_099)));
        assert!(silence.release_due(t(7_100)));
        session.release_all();
        assert!(keys.held.lock().unwrap().is_empty());
        assert_eq!(*keys.releases.lock().unwrap(), 1);

        // The backlog, 30 s later: the key-up, then the person pressing it again.
        let mut injected = 0;
        for (ms, s) in [(40_000, VV), (40_005, up), (40_010, down), (40_020, VV)] {
            silence.note_peer_event(t(ms), &data(s));
            if r.at_s(ms, s) == Admit::Pass && !matches!(msg(s), InputMessage::ViewerVideo(_)) {
                assert!(session.inject(&msg(s)).unwrap());
                injected += 1;
            }
        }
        assert_eq!(injected, 1, "only the key-up went to the injector");
        assert!(keys.held.lock().unwrap().is_empty(), "nothing is held");
        assert!(session.is_active());
        let last = keys.injected.lock().unwrap().last().cloned().unwrap();
        assert_eq!(last, msg(up));
    }
}
