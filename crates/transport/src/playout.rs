//! The viewer's playout delay, decided from this end. Pure (the caller supplies the clock):
//! [`PlayoutPolicy`] picks the `playout-delay` pair (min, max) for each frame — the sender's only
//! lever on the viewer's jitter buffer — and [`RtxTrace`] traces retransmissions for diagnostics.
//!
//! **What Chrome does with the pair** (`modules/video_coding/timing/timing.cc`): `min == 0 && max
//! <= 500 ms` is the low-latency renderer, which shows each frame the moment it is decodable;
//! anything else renders at `expected arrival + clamp(current_delay, min, max)`. On the low-latency
//! path a lost packet is a freeze of about a round trip, however large `max` is. Bench (relayed,
//! 8 Mbps, RTT ~190 ms; freezes, presented fps and p50 frame age):
//!
//! ```text
//! loss   (0, 50) on every frame          (rtt+30, rtt+30) while losing
//! 0.1%   41 freezes/min  43 fps  209 ms   3 freezes/min  55 fps  430 ms
//! 0.5%   57 freezes/min  32 fps  239 ms   7 freezes/min  48 fps  454 ms
//! 1%     44 freezes/min  31 fps  345 ms   4 freezes/min  46 fps  446 ms
//! 2%     14 freezes/min  39 fps  348 ms   3 freezes/min  53 fps  347 ms
//! ```
//! A full round trip costs that much latency per frame, so it is held only while loss recurs.
//!
//! **Letting go without freezing WebKit.** WebKit (Telegram on iOS) honours the header but freezes
//! for good, while still decoding, when the pair arrives back at `(0, 50)` from a hold (three times
//! out of three); raising the `min`, or `(0, 50)` from the start, never froze it. So for every
//! engine but Chromium the release ([`PlayoutPolicy`], "Releasing") brings the `min` down at
//! [`RELEASE_RAMP_MS_PER_S`] to one tick above zero and parks it there for the rest of the session,
//! the `max` following the viewer's jitter-buffer target plus [`RELEASE_MAX_MARGIN_MS`] (not below
//! [`RELEASE_MAX_FLOOR_MS`]). Do not "simplify" this back to zero. Chromium releases straight to
//! `(0, 50)`: the careful release cost it latency and bought nothing. The engine comes from the
//! viewer's `vv` report ([`PlayoutPolicy::note_viewer`]).
//!
//! **A cushion for a path that freezes without losing anything (Chromium only).** A jittery path (a
//! VPN over Wi-Fi, round trip 290 ms) can freeze several times a minute with no loss: at 60 fps a
//! 150 ms spike is a freeze by Chrome's rule (`video/video_quality_observer2.cc`), and the frames
//! bunched behind it can overflow the hardware decoder. On evidence only —
//! [`CUSHION_STALLS_TO_ENGAGE`] coverable stalls with no loss within [`CUSHION_LOSS_GUARD`], inside
//! [`CUSHION_WINDOW`], not in the first [`CUSHION_WARMUP`] — the `min` rises to a cushion
//! ([`PlayoutPhase::Cushion`]) sized from the viewer's jitter within [`CUSHION_MIN_MS`] and
//! [`CUSHION_MAX_MS`]. It grows by [`CUSHION_GROW_MS`], releases after [`CUSHION_CALM`] or
//! [`CUSHION_UNCOVERABLE_TO_RELEASE`] freezes it cannot cover, re-arms within [`CUSHION_REARM`], and
//! drops for an outage until [`OUTAGE_SETTLE`] has passed. The larger of hold and cushion wins.
//! Bench: freezes 3.14 -> 1.94 a minute for 61 ms more median frame age.

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use afklink_protocol::ViewerEngine;

/// The unit the `playout-delay` extension is carried in, in milliseconds.
///
/// Hundredths of a second on the wire, and str0m rebases into it by integer division
/// (`rtp/ext.rs:686`, `rtp/mtime.rs:263-269`), so anything that is not a whole tick is silently
/// truncated downwards on the way out. Every pair this module hands out is in whole ticks, so the
/// number in a log line is the number the browser was told.
pub(crate) const PLAYOUT_DELAY_TICK_MS: u64 = 10;

/// The largest playout delay the viewer may grow to on a clean link, in milliseconds.
///
/// With `min` at zero this keeps Chrome on its low-latency renderer (see the module docs), so on a
/// clean link it is a cap on what the compositor queues rather than a delay anyone waits out.
/// Measured on a clean relayed path under this pair: jitter buffer p50 5 ms, receive-to-display
/// p50 28 ms.
pub(crate) const PLAYOUT_DELAY_MAX_MS: u64 = 50;

/// The largest playout delay this end will ever ask for, in milliseconds.
///
/// A statement about the product rather than the network: a quarter of a second of buffer is
/// already at the edge of what a desktop driven by hand tolerates, and a path whose round trip
/// needs more is one where buffering cannot make the pointer feel attached to the hand. Past here,
/// stalling on a retransmission is the honest failure.
pub(crate) const PLAYOUT_DELAY_MAX_LOSSY_MS: u64 = 250;

/// Added to the round trip when sizing the hold on a lossy link, in milliseconds.
///
/// A retransmission lands one round trip after the loss is *detected*, and detection waits for the
/// next packet — up to a frame interval (17 ms at 60 fps) when the lost packet ended its frame —
/// plus the jitter around both legs.
pub(crate) const LOSS_HEADROOM_MS: u64 = 30;

/// The hold to size for when loss has recurred but no round trip has been measured yet, in
/// milliseconds. A guess, used only before the first receiver report carries an RTT.
pub(crate) const PLAYOUT_DELAY_UNKNOWN_RTT_MS: u64 = 150;

/// The window loss is counted over, and how long after the last loss the hold is kept.
///
/// Loss on these paths comes in stretches and the receiver reports once a second, so reacting to
/// a single clean report would drop the hold in the middle of a lossy stretch and put the freezes
/// straight back. Ten seconds covers the gaps inside a bad stretch — a real session had NACKs in
/// 57% of its seconds — and is short enough that a link which genuinely recovers is back at the
/// low-latency pair while the user is still in the same piece of work.
pub(crate) const LOSS_MEMORY: Duration = Duration::from_secs(10);

/// How many receiver reports within [`LOSS_MEMORY`] must show loss before frames are held.
///
/// The hold costs a round trip of latency on every frame for at least [`LOSS_MEMORY`], so a single
/// lost packet — one freeze — does not buy it: that would trade one freeze for ten seconds of lag,
/// plus the hitches of ramping in and out. Loss that recurs does: at 0.1% and 7 Mbps a report shows
/// loss almost every second, and that link froze 41 times a minute without the hold.
pub(crate) const LOSS_REPORTS_TO_HOLD: usize = 2;

/// How fast the written `min` rises towards its target, in milliseconds per second.
///
/// Raising `min` at once makes Chrome hold the next frame for the whole difference — itself a
/// freeze of a round trip, on entering the hold. At 100 ms a second the picture plays 10% slow for
/// two seconds on the way in instead, the same rate Chrome's own timing allows itself
/// (`kDelayMaxChangeMsPerS` in `timing.cc`). WebKit took this rise three times out of three without
/// a hitch.
pub(crate) const MIN_RAMP_MS_PER_S: f64 = 100.0;

/// How fast the written `min` and `max` may come down, in milliseconds per second.
///
/// A quarter of [`MIN_RAMP_MS_PER_S`], which is also libwebrtc's own limit on how fast its render
/// delay may move (`kDelayMaxChangeMsPerS`): coming down at the full rate had the renderer's delay
/// move at its limit the whole way, and WebKit's reported target followed it almost one for one
/// (232 -> 154 -> 73 ms over the two seconds of the ramp) right up to the freeze. At 25 ms a
/// second a frame at 60 fps is rendered 0.4 ms earlier relative to its arrival than the one before
/// (1.7 ms at 100), the picture plays 2.5% fast instead of 10%, and the way down from a 250 ms hold
/// takes ten seconds instead of two and a half — seconds that cost a little latency and nothing else,
/// since a hold only ends after a whole [`LOSS_MEMORY`] without loss. Chromium, whose release stays
/// fast (see the module docs), comes down at [`MIN_RAMP_MS_PER_S`] instead.
pub(crate) const RELEASE_RAMP_MS_PER_S: f64 = 25.0;

/// The `min` a careful release ramps to and then keeps for the rest of the session, in
/// milliseconds: one tick.
///
/// libwebrtc takes a `min` of zero with a `max` up to 500 ms as its low-latency renderer (render
/// each frame the moment it is decodable) and anything else as timed rendering. Both WebKit freezes
/// with per-second presentation data began within a second of the ramp reaching a `min` of zero, and
/// frames kept reaching the screen at every positive `min` on the way down; one tick keeps the
/// renderer timed, and the release never takes it to zero (see the module docs). What it costs: the
/// viewer renders on its own jitter estimate instead of the moment a frame is decodable.
pub(crate) const RELEASE_MIN_FLOOR_MS: u64 = PLAYOUT_DELAY_TICK_MS;

/// The lowest `max` a careful release comes down to, in milliseconds: the clean pair's.
///
/// 50 ms is the bound WebKit ran under for whole sessions without a hitch (forty seconds under
/// `(0, 50)` with its own target at 65-250 ms; sixteen seconds at 146-160 ms), so a parked pair never asks less of the renderer than the clean one did; below it,
/// with the `min` at one tick, the `max` would start to clamp decode and render time itself (17-31 ms
/// on the iPhone). The viewer's target plus [`RELEASE_MAX_MARGIN_MS`] is at least this anyway; the
/// floor states it, for a target of zero.
pub(crate) const RELEASE_MAX_FLOOR_MS: u64 = PLAYOUT_DELAY_MAX_MS;

/// How far above the viewer's reported jitter-buffer target the `max` must stay while releasing,
/// in milliseconds.
///
/// The target the viewer reports (`jitterBufferTargetDelay` per emitted frame, `jbuf_target_ms` in
/// its `vv` report) leaves out decode and render time, which the `max` bounds too: a hold pinned at
/// 250 ms read as 219-233 ms on the iPhone, so up to 31 ms of the delay is not in the
/// number. On top of that, one report is a second old by the time the next arrives, and WebKit's
/// buffer estimate grew by up to 9 ms from one second to the next outside the ramps (68 -> 77 ms);
/// twice that, for a report that went missing, is the other 20.
pub(crate) const RELEASE_MAX_MARGIN_MS: u64 = 50;

/// How old the viewer's last jitter-buffer report may be for a release to lower the `max` on it.
///
/// The viewer reports once a second; two and a half seconds is one report missed plus its jitter.
/// Past it the `max` holds where it is: lowering it on a number from a buffer that may have grown
/// since is the one thing the release must not do.
pub(crate) const VIEWER_REPORT_MAX_AGE: Duration = Duration::from_millis(2_500);

/// The largest jitter-buffer target from a viewer that is taken as a number, in milliseconds. The
/// contract's own bound; anything outside it is a buggy or hostile peer, and is ignored.
const VIEWER_TARGET_MAX_MS: f64 = 60_000.0;

/// How fast the round-trip envelope forgets a peak, in milliseconds per second.
///
/// The hold is sized from the round trip, which the receiver reports once a second and which moves
/// by tens of milliseconds as the bottleneck queue breathes. The envelope takes a new peak at once —
/// a retransmission sized for a round trip that has just grown is the case that matters — and lets
/// it go at this rate.
const RTT_ENVELOPE_DECAY_MS_PER_S: f64 = 20.0;

/// The smallest cushion, in milliseconds (the product's range is 50-120 ms).
///
/// A cushion `c` turns a delay spike `s` into a gap of `s - c`, and Chrome's freeze is a gap 150 ms
/// past the average frame interval, so nothing under 150 ms of spike is a freeze to begin with: a
/// smaller cushion would remove only the freezes of 167-217 ms at 60 fps, and on a measured jittery
/// VPN path the shortest tenth were already 192 ms. It is also the clean pair's `max`, what the compositor may already
/// queue.
pub(crate) const CUSHION_MIN_MS: u64 = 50;

/// The largest cushion, in milliseconds: a product limit, well under the 250 ms loss hold.
///
/// It costs this much latency on every frame while it is on, so it is a statement about the product
/// rather than the network: on a 290 ms round trip it adds 40% of the round trip, and it covers the
/// freezes up to 287 ms long at 60 fps, 45% of them on the measured jittery VPN path.
pub(crate) const CUSHION_MAX_MS: u64 = 120;

/// How many stalls within [`CUSHION_WINDOW`] engage the cushion.
///
/// One freeze is noise — a busy viewer CPU, a garbage collection — and the cushion costs its size in
/// latency for at least [`CUSHION_CALM`]. Three in thirty seconds is six a minute; the measured
/// jittery VPN path froze at least that often in nine of its ten clean minutes (p10 6, p50 10 a
/// minute), and a healthy path does not come near it (a relayed iPhone: 14 freezes in seven
/// minutes, holds included).
pub(crate) const CUSHION_STALLS_TO_ENGAGE: usize = 3;

/// The window stalls are counted over, and the one the viewer's jitter-buffer target is taken
/// over when sizing the cushion.
pub(crate) const CUSHION_WINDOW: Duration = Duration::from_secs(30);

/// How long without a stall before the cushion is released, and so the least time it is on.
///
/// Twice [`CUSHION_WINDOW`]: release means "not one stall in a minute" where engaging took three in
/// half of one, a gap wide enough that a path freezing at the engaging rate is not cycled in and out.
/// On the replay of a 3.7-hour jittery VPN session a 30 s calm released and re-engaged it 25
/// times (75 under the replay's freeze model, which covered 31% of the freezes instead of 45%), every
/// relapse costing three freezes; 60 s, once (twice under the model), and 120 s changed nothing
/// more. A path that really is smooth again is back at the clean pair a minute after its last freeze.
pub(crate) const CUSHION_CALM: Duration = Duration::from_secs(60);

/// How close to a lossy receiver report a stall may be and still be the path's jitter rather than
/// the loss, either side of it.
///
/// A lost packet freezes the picture for a retransmission's round trip; the viewer's report of
/// that freeze arrives within a second of its end, and the receiver report showing the loss within
/// a second of the loss, in either order. Three seconds covers both and their jitter, and is the
/// window the jittery VPN session's PLIs were attributed over (242 of 380 episodes with no NACK in
/// the three seconds before). The loss hold answers loss; a cushion of at most [`CUSHION_MAX_MS`] cannot cover a
/// retransmission's round trip anyway.
pub(crate) const CUSHION_LOSS_GUARD: Duration = Duration::from_secs(3);

/// The gap after which a keyframe request opens a new episode, rather than repeating the last one.
///
/// Chrome repeats its PLI every couple of hundred milliseconds until a keyframe arrives, and on a
/// 290 ms path with a 111 kB keyframe that is two or three requests for one broken picture
/// (`since_last_line` up to 4). One and a half seconds is the gap the jittery VPN session's
/// recovery episodes were split on.
pub(crate) const KEYFRAME_EPISODE_GAP: Duration = Duration::from_millis(1_500);

/// Added to the viewer's peak jitter-buffer target when sizing the cushion, in milliseconds.
///
/// The target the viewer reports leaves out libwebrtc's 10 ms render delay (a hold pinned at 250 ms
/// read as 240 on Chromium), and libwebrtc's own estimate takes 2.33 standard
/// deviations of the frame-delay noise less a 30 ms offset (`jitter_estimator.cc`), which its
/// renderer can afford because it moves its delay within the second; a pinned cushion does not move,
/// so the offset is put back.
pub(crate) const CUSHION_HEADROOM_MS: u64 = 40;

/// How much a stall the cushion did not cover grows it, in milliseconds, up to [`CUSHION_MAX_MS`].
///
/// The jitter-buffer target sizes the cushion from the spread the viewer measures; the freezes that
/// still come under it are the spikes that spread left out. Only a freeze a cushion within the
/// ceiling could have covered grows it, so it stops growing once what still freezes is past the
/// ceiling. Two ticks a stall: from a 70-90 ms start, the ceiling in two or three. Zero leaves the
/// cushion where it was sized: on the replay of the jittery VPN session, 110 ms instead of 120 for
/// the whole session, and 42% of the freezes covered under the replay's model instead of 45%.
///
/// "Could have covered" is asked of the freeze as it was measured: under the `min` then in force,
/// `c`, which already shortened its spike by `c`. A cushion at the ceiling would have shortened it
/// by `CUSHION_MAX_MS - c` more, so it grows only when `freeze - (CUSHION_MAX_MS - c)` is under
/// [`CHROMIUM_FREEZE_GAP_MS`] — and not when the size the ramp is still heading for leaves it under
/// that already. Comparing the freeze itself with the ceiling plus 150 ms, as though measured
/// without a cushion, grew it on the bench for freezes that even 120 ms could not cover (7 growths
/// of 8), each 20 ms of latency on every frame for nothing.
pub(crate) const CUSHION_GROW_MS: u64 = 20;

/// Chrome's freeze: a gap between rendered frames this much longer than the average one, in
/// milliseconds (`kMinIncreaseForFreezeMs`, `video/video_quality_observer2.cc`). What a cushion
/// must leave of a spike for the viewer not to count it.
pub(crate) const CHROMIUM_FREEZE_EXCESS_MS: u64 = 150;

/// Chrome's freeze as a gap at 60 fps, in milliseconds: [`CHROMIUM_FREEZE_EXCESS_MS`] past the
/// average frame interval, 17 ms (three times the interval, the rule's other half, is less). A gap
/// shorter than this is not a freeze to the viewer. The bench found the rule under the cushion as
/// written: a spike `s` under a cushion `c` showed as a gap of `s - c` plus 0-30 ms, and
/// Chrome counted it from 167 ms.
pub(crate) const CHROMIUM_FREEZE_GAP_MS: u64 = CHROMIUM_FREEZE_EXCESS_MS + 17;

/// How many freezes under the cushion in force that no cushion within the ceiling could have
/// covered, within [`CUSHION_WINDOW`] and with none since that one could have, release it — at once,
/// down the ramp its calm takes, and with no relapse: the next one takes
/// [`CUSHION_STALLS_TO_ENGAGE`] stalls it could cover, as the first did.
///
/// Under a cushion at the ceiling every freeze the viewer still reports is one the ceiling cannot
/// cover — the ones it covers the viewer never sees — so that a stall under it is uncoverable says
/// nothing; how many keep coming does. On the bench, slow TCP-TURN relays (round trip about a
/// second) engaged it in 7 of 9 runs and every one of the 107 stalls under it was uncoverable,
/// receive-to-display 40-75 ms longer for nothing to see; on the direct runs, where it took freezes
/// from 2.9 to 1.6 a minute, at most 4 uncoverable freezes fell under it in any 30 s. Seven,
/// replayed, released it in 5 of the 7 relayed runs and in none of the direct ones; through a
/// 3.7-hour jittery session (`replay_a_sessions_stalls_through_the_cushion`) it released once and
/// stayed on 99.0% of the time outside the holds, freezes 7.9 -> 4.3 a minute.
pub(crate) const CUSHION_UNCOVERABLE_TO_RELEASE: usize = 7;

/// How long after its calm released it a cushion comes back on the first stall, at the size it
/// had, rather than after [`CUSHION_STALLS_TO_ENGAGE`] new ones.
///
/// The calm passes because the cushion is absorbing the spikes, not because they stopped: on the
/// bench all five releases in mid-run came back 16-60 s later, each after three new stalls — one to
/// three freezes and the PLIs with them. Five minutes is five times the longest of
/// those relapses; a path smooth for that long after the release is taken as a different one, and
/// earns its cushion again the way the first one did.
pub(crate) const CUSHION_REARM: Duration = Duration::from_secs(300);

/// Stats intervals in a row without a receiver report, while frames were written, that make an
/// outage for the cushion: the no-feedback brake's own count (`afklink_core::quality`,
/// `BRAKE_STALE_REPORTS`). On the bench two in a row came only in vpn-wifi-1011's 2.3 s stall,
/// 2.8-2.9 s after it began; rtt-290-clean had 24-28 single empty intervals in three minutes.
pub(crate) const OUTAGE_SILENT_REPORTS: u32 = 2;

/// A receiver report's round trip at or past which the path is holding a backlog of ours, in
/// milliseconds: an outage for the cushion. The controller's own line for drain mode
/// (`afklink_core::quality`, `DRAIN_ENTER_RTT_MS`), which the transport is not told of; drain mode
/// enters on two pieces of evidence, each of them this or [`OUTAGE_SILENT_REPORTS`], so either shows
/// here as soon as it does there.
pub(crate) const OUTAGE_RTT_MS: u64 = 2_000;

/// How long after the last sign of an outage the cushion is re-armed — once media flows and the
/// receiver and the viewer report again, too.
///
/// Chrome's timed renderer is what held the fresh frames after the bench's 2.3 s stall
/// (vpn-wifi-1011, all four cushioned runs): 0.4-1.3 s from receipt to display 5.1-5.9 s after
/// the stall began, and in f50-r1 nothing decoded from 4.8 s to 6.9 s; with `min` at zero (f0) the
/// picture was back under a second old at 5.0 s. The first sign comes about three seconds in (the
/// second silent interval 2.8-2.9 s in, the viewer's report of its freeze at 3.3), so five seconds
/// after the last one is past everything the bench showed.
pub(crate) const OUTAGE_SETTLE: Duration = Duration::from_secs(5);

/// How recently a frame must have been written for media to count as flowing again.
const MEDIA_FLOWING_WITHIN: Duration = Duration::from_millis(500);

/// How long after the first frame written the viewer's stalls are not counted for the cushion: the
/// connection's ramp — the estimate climbing, the start-up keyframes, the viewer's buffer settling —
/// not the path's jitter.
///
/// On the bench (slow relayed paths) 5 of the 8 engagements outside connect-x10 came
/// within 10 s of the first frame (4.7-9.2 s), each at 120 ms and none released before its run
/// ended: frame age p50 +75-87 ms where it engaged (wifi-relay 180 -> 267, hide-30 205 -> 280).
/// Fifteen seconds is those ten and a half again; a path that keeps freezing past it still engages
/// three stalls later.
pub(crate) const CUSHION_WARMUP: Duration = Duration::from_secs(15);

/// Slack when deciding that a gap in our own writes explains a freeze the viewer reports, in
/// milliseconds: two frame intervals at 60 fps, the bench's own reading of a "source" gap
/// (its `SAME_GAP_SLACK_MS`).
pub(crate) const SOURCE_GAP_SLACK_MS: u64 = 34;

/// How long ago a gap in our writes may have ended and still explain a freeze the viewer reports
/// now: its report covers about a second, the frames in it left one way before it, and the report
/// takes one way back — two and a half seconds is that on a 500 ms round trip, with a second's
/// margin.
const SOURCE_GAP_LOOKBACK: Duration = Duration::from_millis(2_500);

/// The longest freeze, on average over one viewer report, that counts as a stall, in milliseconds.
///
/// Past a second the picture did not jitter, it stopped: an outage, the receiver going silent, the
/// send queue's breaker or the controller's drain. No cushion within the ceiling covers that, and
/// it says nothing about how jittery the path is. The jittery VPN session's longest smooth-path
/// freezes were 793 ms at p99; one outage in it froze for 3.1 s. Such a freeze is a sign of an outage
/// instead ([`OUTAGE_SETTLE`]).
pub(crate) const CUSHION_STALL_MAX_MS: u64 = 1_000;

/// How long the pair on the wire must have been the clean one before a viewer report's
/// jitter-buffer target counts as a measure of the path's jitter.
///
/// The report covers the second before it, and under any raised `min` the target only repeats the
/// pair (a pinned 250 read as 240). Two seconds is the interval and its jitter.
const CUSHION_SAMPLE_CLEAN_FOR: Duration = Duration::from_secs(2);

/// One frame's `playout-delay` pair, in milliseconds, whole [`PLAYOUT_DELAY_TICK_MS`] ticks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PlayoutDelay {
    pub min_ms: u64,
    pub max_ms: u64,
}

impl PlayoutDelay {
    /// The clean-link pair: render the moment a frame is decodable.
    pub(crate) const CLEAN: PlayoutDelay = PlayoutDelay {
        min_ms: 0,
        max_ms: PLAYOUT_DELAY_MAX_MS,
    };

    /// The pair for a written `min`: [`Self::CLEAN`] at zero, otherwise `min` pinned, so Chrome
    /// holds exactly that long — neither less (the retransmission would not make it) nor more (its
    /// own estimate of a round trip it cannot measure).
    pub(crate) fn holding(min_ms: u64) -> PlayoutDelay {
        if min_ms == 0 {
            PlayoutDelay::CLEAN
        } else {
            PlayoutDelay {
                min_ms,
                max_ms: min_ms,
            }
        }
    }
}

fn whole_ticks(ms: u64) -> u64 {
    ms - ms % PLAYOUT_DELAY_TICK_MS
}

/// A written `min` in whole ticks: rounded to the millisecond, then down to the tick.
fn min_ticks(ms: f64) -> u64 {
    if ms.is_nan() || ms <= 0.0 {
        return 0;
    }
    whole_ticks(ms.round() as u64)
}

/// A written `max` in whole ticks, rounded *up*: a `max` never falls below the bound it was
/// computed from on its way to the wire.
fn max_ticks(ms: f64) -> u64 {
    if ms.is_nan() || ms <= 0.0 {
        return 0;
    }
    (ms.ceil() as u64).div_ceil(PLAYOUT_DELAY_TICK_MS) * PLAYOUT_DELAY_TICK_MS
}

/// How long to hold frames on a lossy link: one retransmission's round trip, `rtt +
/// LOSS_HEADROOM_MS`, at most [`PLAYOUT_DELAY_MAX_LOSSY_MS`], in whole ticks.
pub(crate) fn lossy_hold_ms(rtt_ms: Option<u64>) -> u64 {
    let wait = rtt_ms
        .map_or(PLAYOUT_DELAY_UNKNOWN_RTT_MS, |r| {
            r.saturating_add(LOSS_HEADROOM_MS)
        })
        .min(PLAYOUT_DELAY_MAX_LOSSY_MS);
    whole_ticks(wait)
}

/// `current` moved towards `target` over `dt`: up by at most [`MIN_RAMP_MS_PER_S`], down by at
/// most `down_ms_per_s`; exactly `target` once within reach.
fn ramp(current: f64, target: f64, dt: Duration, down_ms_per_s: f64) -> f64 {
    let secs = dt.as_secs_f64();
    if target > current {
        (current + MIN_RAMP_MS_PER_S * secs).min(target)
    } else {
        (current - down_ms_per_s * secs).max(target)
    }
}

/// A peak of the reported round trip that decays at [`RTT_ENVELOPE_DECAY_MS_PER_S`].
#[derive(Debug, Default)]
struct RttEnvelope {
    value_ms: Option<f64>,
    at: Option<Instant>,
}

impl RttEnvelope {
    fn note(&mut self, now: Instant, rtt_ms: u64) {
        let rtt = rtt_ms as f64;
        let decayed = match (self.value_ms, self.at) {
            (Some(v), Some(at)) => {
                v - RTT_ENVELOPE_DECAY_MS_PER_S * now.saturating_duration_since(at).as_secs_f64()
            }
            _ => rtt,
        };
        self.value_ms = Some(decayed.max(rtt));
        self.at = Some(now);
    }

    fn get(&self) -> Option<u64> {
        self.value_ms.map(|v| v.round().max(0.0) as u64)
    }
}

/// Where the policy is in its cycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PlayoutPhase {
    /// [`PlayoutDelay::CLEAN`] on every frame — after a Chromium viewer's release, once its fast
    /// ramp has come down to it.
    Clean,
    /// Loss keeps recurring: the `min` is at, or ramping to, one retransmission's round trip — or the
    /// cushion, when that is on and larger — and the `max` is pinned to it.
    Holding,
    /// No loss for a whole [`LOSS_MEMORY`]: coming down carefully (see the module docs) to one tick
    /// of `min`, and parked there for the rest of the session unless loss holds again. Never back to
    /// [`PlayoutDelay::CLEAN`].
    Releasing,
    /// A Chromium viewer only. No recurring loss, but the viewer keeps freezing on the smooth path:
    /// the `min` is at, or ramping to, the cushion, and the `max` is pinned to it. Released, after
    /// [`CUSHION_CALM`] without a stall or [`CUSHION_UNCOVERABLE_TO_RELEASE`] freezes past what it
    /// covers, as Chromium's hold is: down at [`MIN_RAMP_MS_PER_S`] to the clean pair. Left at once
    /// for [`PlayoutPhase::Clean`] when an outage begins, and come back to when it ends.
    Cushion,
}

impl PlayoutPhase {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            PlayoutPhase::Clean => "clean",
            PlayoutPhase::Holding => "holding",
            PlayoutPhase::Releasing => "releasing",
            PlayoutPhase::Cushion => "cushion",
        }
    }
}

/// One sign that the viewer's picture stalled, as the cushion counts them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stall {
    /// A viewer report whose freeze counter moved: `n` freezes by Chrome's own rule in its interval,
    /// `mean_ms` long on average. One stall however many: two freezes in one second are one bad
    /// second.
    Freeze { n: u64, mean_ms: u64 },
    /// The first PLI or FIR of an episode ([`KEYFRAME_EPISODE_GAP`]): the decoder lost the picture.
    KeyframeRequest,
}

impl Stall {
    fn as_str(self) -> &'static str {
        match self {
            Stall::Freeze { .. } => "freeze",
            Stall::KeyframeRequest => "keyframe_request",
        }
    }

    fn freeze_ms(self) -> Option<u64> {
        match self {
            Stall::Freeze { mean_ms, .. } => Some(mean_ms),
            Stall::KeyframeRequest => None,
        }
    }
}

/// The cushion while it is on.
#[derive(Debug, Clone, Copy)]
struct CushionOn {
    /// The `min` it asks for, in whole ticks within [`CUSHION_MIN_MS`]..=[`CUSHION_MAX_MS`].
    size_ms: u64,
    /// When it engaged, for the log.
    since: Instant,
    /// The last stall counted: [`CUSHION_CALM`] after it, the cushion is released.
    last_stall: Instant,
    /// Stalls counted while it was on, for the log.
    stalls: u64,
}

/// The cushion as its calm released it, for [`CUSHION_REARM`].
#[derive(Debug, Clone, Copy)]
struct CushionReleased {
    at: Instant,
    size_ms: u64,
}

/// What the cushion knows: the stalls it counted, the viewer's jitter, and whether it is on.
#[derive(Debug, Default)]
struct Cushion {
    /// Stalls counted within [`CUSHION_WINDOW`]: when, and which.
    stalls: VecDeque<(Instant, Stall)>,
    /// The viewer's jitter-buffer targets from reports taken on the smooth clean pair (see
    /// [`CUSHION_SAMPLE_CLEAN_FOR`]), within [`CUSHION_WINDOW`].
    samples: VecDeque<(Instant, f64)>,
    /// The viewer's cumulative freeze count and frozen time, as last reported.
    freezes_seen: Option<(u64, u64)>,
    /// The last keyframe request, for [`KEYFRAME_EPISODE_GAP`].
    last_keyframe_request: Option<Instant>,
    on: Option<CushionOn>,
    /// While it is on: the freezes under it in force that no cushion within the ceiling could have
    /// covered, within [`CUSHION_WINDOW`] and since the last one that could
    /// ([`CUSHION_UNCOVERABLE_TO_RELEASE`]).
    uncoverable: VecDeque<Instant>,
    /// The last release by the calm, until a stall within [`CUSHION_REARM`] re-engages it.
    released: Option<CushionReleased>,
    /// Stalls recur but the viewer is not Chromium: said once.
    refused_noted: bool,
}

/// A sign that the path stopped carrying the picture rather than jittering it ("The cushion",
/// outages).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OutageSign {
    /// [`OUTAGE_SILENT_REPORTS`] or more stats intervals in a row without a receiver report, while
    /// frames were written: the no-feedback brake's evidence.
    Silence { reports: u32 },
    /// A receiver report's round trip at or past [`OUTAGE_RTT_MS`]: the path holds a backlog.
    Backlog { rtt_ms: u64 },
    /// A viewer freeze longer than [`CUSHION_STALL_MAX_MS`].
    Freeze { freeze_ms: u64 },
}

impl OutageSign {
    fn as_str(self) -> &'static str {
        match self {
            OutageSign::Silence { .. } => "silence",
            OutageSign::Backlog { .. } => "backlog",
            OutageSign::Freeze { .. } => "freeze",
        }
    }
}

/// An outage under way, from its first sign until the cushion may be re-armed.
#[derive(Debug, Clone, Copy)]
struct Outage {
    since: Instant,
    first: OutageSign,
    last: OutageSign,
    last_at: Instant,
    signs: u32,
    /// Since the last sign: a receiver report, not silent and under [`OUTAGE_RTT_MS`].
    reported: bool,
    /// Since the last sign: a viewer report with frames emitted in its interval.
    viewer_shows: bool,
    /// The cushion was the pair in force, at this size, and was dropped to the clean pair.
    dropped_ms: Option<u64>,
}

/// What a release is waiting on, for the log: a line each time it changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReleaseStage {
    /// The viewer's report is fresh: the `max` follows it down, or already sits on its floor.
    Following,
    /// No fresh report from the viewer: the `max` holds where it is.
    NoReport,
    /// The `min` is at its floor and the `max` on the viewer's target plus the margin: the pair it
    /// keeps, the `max` still following the buffer, for the rest of the session.
    Parked,
}

impl ReleaseStage {
    fn as_str(self) -> &'static str {
        match self {
            ReleaseStage::Following => "following the viewer's buffer",
            ReleaseStage::NoReport => "max held: no fresh viewer report",
            ReleaseStage::Parked => "parked at the min floor",
        }
    }
}

/// The viewer's last report of its jitter-buffer target.
#[derive(Debug, Clone, Copy)]
struct ViewerBuffer {
    target_ms: f64,
    at: Instant,
}

/// Decides the pair, frame by frame, from what the receiver reports once a second and what the
/// viewer says about its own jitter buffer and engine.
///
/// Clean link: [`PlayoutDelay::CLEAN`]. Once [`LOSS_REPORTS_TO_HOLD`] reports within
/// [`LOSS_MEMORY`] have shown loss: hold every frame for [`lossy_hold_ms`] of the round-trip
/// envelope, the `min` rising at [`MIN_RAMP_MS_PER_S`] and the `max` pinned to it. Once a whole
/// [`LOSS_MEMORY`] passes without a lossy report, release.
///
/// A Chromium viewer's release is the one it always had: `min` and `max` down together at
/// [`MIN_RAMP_MS_PER_S`] to [`PlayoutDelay::CLEAN`]. Every other viewer's — WebKit, Gecko, unknown,
/// or not reported yet — is careful, step by step:
///
///   1. the `min` comes down at [`RELEASE_RAMP_MS_PER_S`] to [`RELEASE_MIN_FLOOR_MS`], never zero;
///   2. the `max` comes down no faster, never below the viewer's fresh jitter-buffer target plus
///      [`RELEASE_MAX_MARGIN_MS`] nor below [`RELEASE_MAX_FLOOR_MS`] (rising back to that if the
///      buffer grows, up to [`PLAYOUT_DELAY_MAX_LOSSY_MS`]), and holds while no report is younger
///      than [`VIEWER_REPORT_MAX_AGE`];
///   3. there it stays, by design, for the rest of the session: the `min` at one tick, the `max`
///      following the viewer's buffer down and up, the viewer rendering on its own estimate. It
///      never returns to [`PlayoutDelay::CLEAN`] — the min>0 -> min=0 switch is what froze WebKit.
///
/// Recurring loss, during a release or after it parked, holds again as usual, and the next
/// release parks at the same tick. For those viewers a hold that shrinks with the
/// round trip comes down at [`RELEASE_RAMP_MS_PER_S`] too, and the `max` never falls faster than
/// that except on entering a hold from the clean pair, which is the one direction WebKit was seen to
/// take without a hitch.
///
/// ## The cushion
///
/// For a Chromium viewer only (module docs, "A cushion..."), and on its own inputs, beside the hold:
///
///   * **Stalls** are the viewer's reports whose freeze counter moved ([`Self::note_freezes`]) and
///     the first PLI or FIR of each episode ([`Self::note_keyframe_request`]). One that comes within
///     [`CUSHION_LOSS_GUARD`] after a lossy receiver report is the loss's and is not counted, and a
///     lossy report takes back those counted within that guard before it; a freeze longer than
///     [`CUSHION_STALL_MAX_MS`] is an outage and is not counted either. Nor is a stall in the first
///     [`CUSHION_WARMUP`] after the first frame written, nor a freeze a gap in our own writes
///     explains — one at least as long, less [`SOURCE_GAP_SLACK_MS`], that ended within
///     [`SOURCE_GAP_LOOKBACK`]: a still screen or a paused encoder is not the path's jitter.
///   * **Counted towards engaging** — and a relapse — only a keyframe request or a freeze a cushion
///     within the ceiling could have covered: what it measured under the `min` then written, less
///     the rest of the way to [`CUSHION_MAX_MS`], under [`CHROMIUM_FREEZE_GAP_MS`]. A path whose
///     freezes are past the ceiling does not engage one.
///   * **Engaged** by the [`CUSHION_STALLS_TO_ENGAGE`]-th stall within [`CUSHION_WINDOW`]. Sized
///     from the largest jitter-buffer target the viewer reported over that window on the smooth
///     clean pair — at least [`CUSHION_SAMPLE_CLEAN_FOR`] on [`PlayoutDelay::CLEAN`] and a whole
///     [`LOSS_MEMORY`] after the last loss, when it measures the path and not the pair or the
///     retransmissions — plus [`CUSHION_HEADROOM_MS`], in whole ticks, within [`CUSHION_MIN_MS`] and
///     [`CUSHION_MAX_MS`]; [`CUSHION_MIN_MS`] with no such report. The `min` ramps to it at
///     [`MIN_RAMP_MS_PER_S`] with the `max` pinned, exactly as a hold begins.
///   * **Grown** by [`CUSHION_GROW_MS`] for each freeze under it that a cushion within the ceiling
///     could have covered — what the freeze measured under the `min` in force, less the rest of the
///     way to [`CUSHION_MAX_MS`], under [`CHROMIUM_FREEZE_GAP_MS`]; never shrunk while on.
///   * **Released** [`CUSHION_CALM`] after the last stall: down to the clean pair at
///     [`MIN_RAMP_MS_PER_S`], pinned, as Chromium's hold comes down.
///   * **Re-engaged** by the first stall within [`CUSHION_REARM`] of that release, at the larger of
///     the size it was released at and a fresh sizing; past it, three stalls engage it as at first.
///   * **Released early** by [`CUSHION_UNCOVERABLE_TO_RELEASE`] freezes under it in force
///     within [`CUSHION_WINDOW`] that no cushion within the ceiling could have covered, with none
///     since that one could have: the same way down, and no relapse — three stalls it could cover
///     engage the next one, counted from then.
///   * **Out of the pair for an outage**: [`OUTAGE_SILENT_REPORTS`] stats intervals in a row without
///     a receiver report while frames were written, a report whose round trip is past
///     [`OUTAGE_RTT_MS`], or a viewer freeze longer than [`CUSHION_STALL_MAX_MS`]. A cushion in force
///     drops at once to [`PlayoutDelay::CLEAN`]; one on under a hold stays out of its target. The
///     stalls meanwhile are the outage's, not counted, and no jitter sample is taken until
///     [`LOSS_MEMORY`] after its last sign. It ends — the cushion re-armed at its size, ramping in as
///     it first did — once, since the last sign, a receiver report under the line and a viewer
///     report with frames in it have arrived, a frame has been written within
///     [`MEDIA_FLOWING_WITHIN`], and [`OUTAGE_SETTLE`] has passed. The cushion's calm runs on
///     meanwhile, and may release it.
///
/// With the hold, the larger `min` wins: a hold's target is the larger of its round trip and the
/// cushion, a hold that ends with the cushion on comes down to the cushion rather than to the clean
/// pair, and recurring loss under the cushion holds as it always did. Stalls go on being counted
/// under a hold (the guard leaves out the loss's own), so the cushion can engage, stay or be released
/// meanwhile and takes over, or not, when the hold ends; it grows only while it is the pair in force.
#[derive(Debug)]
pub(crate) struct PlayoutPolicy {
    /// When each report that showed loss arrived, within the last [`LOSS_MEMORY`].
    losing: VecDeque<Instant>,
    /// When the last report that showed loss arrived, however long ago: the cushion's guard and
    /// its jitter samples read it.
    last_lossy_at: Option<Instant>,
    phase: PlayoutPhase,
    /// The last lossy report's fraction lost and new NACKs, for the log.
    last_loss: Option<(f32, u64)>,
    rtt: Option<Duration>,
    envelope: RttEnvelope,
    /// Where the written `min` is heading, in milliseconds: the hold, the release floor, or zero.
    target_ms: u64,
    /// The written `min` and `max` before rounding to ticks, and when they last moved.
    min_ms: f64,
    max_ms: f64,
    moved_at: Option<Instant>,
    /// A switch's ramp is under way; its arrival is logged. The ramps that follow the round trip
    /// while holding are not: they are a tick or three, once a second.
    switching: bool,
    /// The pair last written.
    last: PlayoutDelay,
    /// The viewer's latest jitter-buffer target, from its `vv` report.
    viewer: Option<ViewerBuffer>,
    /// The viewer's browser engine, once reported: Chromium's release is fast, anyone else's careful.
    engine: Option<ViewerEngine>,
    engine_conflict_noted: bool,
    /// When the release under way began, for the log.
    release_began: Option<Instant>,
    /// What the release under way last said it was waiting on.
    release_stage: Option<ReleaseStage>,
    /// The release under way has said, once, that it parked.
    release_parked: bool,
    /// The cushion against a smooth path's freezes (see "The cushion").
    cushion: Cushion,
    /// Since when the pair written has been [`PlayoutDelay::CLEAN`], frame after frame; `None`
    /// while it is not.
    clean_since: Option<Instant>,
    /// Frames written since the last receiver report: an interval without a report is silence only
    /// while frames went out.
    frames_since_report: u32,
    /// Stats intervals in a row without a receiver report while frames went out.
    silent_reports: u32,
    /// The outage under way ("The cushion", outages): while set, the cushion is out of the pair.
    outage: Option<Outage>,
    /// The last sign of an outage, however long ago: the cushion's jitter samples read it.
    last_outage_at: Option<Instant>,
    /// The first frame written: the cushion's [`CUSHION_WARMUP`] runs from it.
    first_frame_at: Option<Instant>,
    /// Gaps between frames written long enough to explain a freeze, within
    /// [`SOURCE_GAP_LOOKBACK`]: when each ended, and how long it was in milliseconds.
    write_gaps: VecDeque<(Instant, u64)>,
}

impl Default for PlayoutPolicy {
    fn default() -> Self {
        Self {
            losing: VecDeque::new(),
            last_lossy_at: None,
            phase: PlayoutPhase::Clean,
            last_loss: None,
            rtt: None,
            envelope: RttEnvelope::default(),
            target_ms: 0,
            min_ms: 0.0,
            max_ms: PLAYOUT_DELAY_MAX_MS as f64,
            moved_at: None,
            switching: false,
            last: PlayoutDelay::CLEAN,
            viewer: None,
            engine: None,
            engine_conflict_noted: false,
            release_began: None,
            release_stage: None,
            release_parked: false,
            cushion: Cushion::default(),
            clean_since: None,
            frames_since_report: 0,
            silent_reports: 0,
            outage: None,
            last_outage_at: None,
            first_frame_at: None,
            write_gaps: VecDeque::new(),
        }
    }
}

impl PlayoutPolicy {
    /// One receiver report: the round trip, if it carried one, and whether it showed loss.
    ///
    /// `loss` is the report's fraction lost, which rounds to zero for a single packet at these
    /// bitrates; `new_nacks` is the increase of str0m's NACK counter since the previous report,
    /// which catches exactly that case.
    pub(crate) fn note_report(
        &mut self,
        now: Instant,
        rtt: Option<Duration>,
        loss: Option<f32>,
        new_nacks: u64,
    ) {
        if let Some(rtt) = rtt {
            self.rtt = Some(rtt);
            self.envelope.note(now, rtt.as_millis() as u64);
        }
        let fraction = loss.unwrap_or(0.0);
        let losing = fraction > 0.0 || new_nacks > 0;
        if losing {
            self.losing.push_back(now);
            self.last_loss = Some((fraction, new_nacks));
            self.last_lossy_at = Some(now);
            self.cushion_takes_back_the_loss_stalls(now);
        }
        while self
            .losing
            .front()
            .is_some_and(|&t| now.saturating_duration_since(t) >= LOSS_MEMORY)
        {
            self.losing.pop_front();
        }
        // The outage watch ("The cushion", outages): a receiver silent while frames go out, or one
        // whose round trip says the path holds a backlog of ours. str0m's `loss` is `None` exactly
        // when the interval carried no receiver report.
        let wrote = std::mem::take(&mut self.frames_since_report);
        if loss.is_none() {
            // As the brake counts it: an empty interval with nothing sent in it is a still screen's.
            self.silent_reports = if wrote > 0 {
                self.silent_reports.saturating_add(1)
            } else {
                0
            };
            if self.silent_reports >= OUTAGE_SILENT_REPORTS {
                self.outage_sign(
                    now,
                    OutageSign::Silence {
                        reports: self.silent_reports,
                    },
                );
            } else {
                // Trace: one empty interval is Chrome's report timing, several a minute.
                tracing::trace!(
                    silent_reports = self.silent_reports,
                    needed = OUTAGE_SILENT_REPORTS,
                    frames_written = wrote,
                    "playout: a stats interval without a receiver report"
                );
            }
        } else {
            self.silent_reports = 0;
            match rtt.map(|d| d.as_millis() as u64) {
                Some(rtt_ms) if rtt_ms >= OUTAGE_RTT_MS => {
                    self.outage_sign(now, OutageSign::Backlog { rtt_ms });
                }
                _ => {
                    if let Some(o) = self.outage.as_mut() {
                        if !o.reported {
                            o.reported = true;
                            let since_sign = now.saturating_duration_since(o.last_at);
                            tracing::debug!(
                                rtt_ms = ?rtt.map(|d| d.as_millis() as u64),
                                since_sign_ms = since_sign.as_millis() as u64,
                                first = o.first.as_str(),
                                "playout: the receiver reports again after the outage's last sign"
                            );
                        }
                    }
                }
            }
        }
        // The cushion's calm runs out on the receiver's clock as well as on the viewer's.
        self.cushion_calm_check(now);

        let was = self.phase;
        let lossy = self.losing.len();
        match self.phase {
            PlayoutPhase::Clean | PlayoutPhase::Releasing | PlayoutPhase::Cushion
                if lossy >= LOSS_REPORTS_TO_HOLD =>
            {
                self.phase = PlayoutPhase::Holding;
            }
            PlayoutPhase::Holding if lossy == 0 => {
                self.phase = if self.careful() {
                    PlayoutPhase::Releasing
                } else if self.cushion_ms() > 0 {
                    // Chromium, still freezing on the smooth path: down to the cushion.
                    PlayoutPhase::Cushion
                } else {
                    // Chromium: the fast ramp to the clean pair, as it always was (see `delay`).
                    PlayoutPhase::Clean
                };
            }
            _ => {}
        }
        let target = self.phase_target();
        let previous_target = std::mem::replace(&mut self.target_ms, target);

        let rtt_ms = self.rtt.map(|d| d.as_millis() as u64);
        if self.phase != was {
            self.switching = true;
            let (reason, what) = match (was, self.phase) {
                (PlayoutPhase::Releasing, _) => {
                    // The max may sit above the new hold; it comes down to it no faster than a
                    // release would (see `delay`).
                    self.release_began = None;
                    self.release_stage = None;
                    self.release_parked = false;
                    (
                        "loss_during_release",
                        "loss is back during the release or its parking, so frames are held again \
                         (min ramps up to target_min_ms; a max above it comes down to it at \
                         release_ramp_ms_per_s)",
                    )
                }
                (_, PlayoutPhase::Holding) => {
                    // Pinned from the first tick, exactly as a hold has always begun.
                    self.max_ms = 0.0;
                    (
                        "loss",
                        "loss keeps recurring, so frames are held for one retransmission's round \
                         trip (min ramps to target_min_ms; the larger of that and a cushion that is \
                         on)",
                    )
                }
                (_, PlayoutPhase::Cushion) => (
                    "clean_cushioned",
                    "no loss for the whole window, but the viewer still freezes on the smooth path, \
                     so the hold comes down to the cushion rather than to the clean pair (a Chromium \
                     viewer: min and max down together at 100 ms a second to cushion_ms)",
                ),
                (_, PlayoutPhase::Clean) => (
                    "clean",
                    "no loss for the whole window, so frames are rendered as soon as they are \
                     decodable again (a Chromium viewer: min and max ramp down together to (0, 50))",
                ),
                _ => {
                    self.release_began = Some(now);
                    self.release_stage = None;
                    self.release_parked = false;
                    (
                        "clean",
                        "no loss for the whole window, so the hold is released carefully: min ramps \
                         down at release_ramp_ms_per_s to target_min_ms and parks there for the rest \
                         of the session by design (a WebKit viewer froze each time the min returned \
                         to zero after a hold; this is the path for every engine but Chromium), max \
                         follows the viewer's jitter-buffer target + margin_ms, no faster down, not \
                         below max_floor_ms",
                    )
                }
            };
            self.log_switch(now, was, reason, what);
        } else if self.phase == PlayoutPhase::Holding && target != previous_target {
            tracing::debug!(
                target_min_ms = target,
                from_target_ms = previous_target,
                rtt_ms,
                rtt_envelope_ms = self.envelope.get(),
                cushion_ms = self.cushion_ms(),
                "playout hold follows the round trip (or the cushion under it)"
            );
        } else if losing && self.phase != PlayoutPhase::Holding {
            tracing::debug!(
                phase = self.phase.as_str(),
                lossy_reports = lossy,
                needed = LOSS_REPORTS_TO_HOLD,
                window_s = LOSS_MEMORY.as_secs(),
                loss_fraction = fraction,
                new_nacks,
                "a lossy report, not yet recurring loss: frames are not held (a release carries on)"
            );
        }
        self.outage_check(now);
    }

    /// What the viewer says about itself, once a second (its `vv` report): its jitter-buffer
    /// target (`jbuf_target_ms`), which a release follows down and the cushion is sized from, and
    /// its browser engine, which is logged. The numbers are a peer's: a target that is not a finite
    /// number within the contract's bound is ignored, and so is an engine that contradicts the first
    /// one reported.
    pub(crate) fn note_viewer(
        &mut self,
        now: Instant,
        engine: Option<ViewerEngine>,
        jbuf_target_ms: Option<f64>,
    ) {
        if let Some(engine) = engine {
            self.note_engine(engine);
        }
        match jbuf_target_ms {
            Some(t) if t.is_finite() && (0.0..=VIEWER_TARGET_MAX_MS).contains(&t) => {
                // A measure of the path only on the smooth clean pair: under a raised min the
                // target repeats the pair, and for a while after loss it carries the
                // retransmissions it absorbed (module docs, `loss-onset`) — and after an outage,
                // the backlog it absorbed, likewise.
                let clean_for = self.clean_since.map(|at| now.saturating_duration_since(at));
                let sample = clean_for.is_some_and(|d| d >= CUSHION_SAMPLE_CLEAN_FOR)
                    && self
                        .last_lossy_at
                        .is_none_or(|at| now.saturating_duration_since(at) >= LOSS_MEMORY)
                    && self.outage.is_none()
                    && self
                        .last_outage_at
                        .is_none_or(|at| now.saturating_duration_since(at) >= LOSS_MEMORY);
                if sample {
                    self.cushion.samples.push_back((now, t));
                }
                self.prune_cushion_samples(now);
                // The viewer emitted frames in this report's interval: one of the things an
                // outage waits for before the cushion is re-armed (a freeze in the same report,
                // read next, is a new sign and takes it back).
                if let Some(o) = self.outage.as_mut() {
                    if !o.viewer_shows {
                        o.viewer_shows = true;
                        let since_sign = now.saturating_duration_since(o.last_at);
                        tracing::debug!(
                            target_ms = t,
                            since_sign_ms = since_sign.as_millis() as u64,
                            first = o.first.as_str(),
                            "playout: the viewer reports frames again after the outage's last sign"
                        );
                    }
                }
                // Trace: once a second, and the release and the cushion log what they do with it.
                tracing::trace!(
                    target_ms = t,
                    phase = self.phase.as_str(),
                    jitter_sample = sample,
                    clean_for_ms = ?clean_for.map(|d| d.as_millis()),
                    "viewer jitter-buffer target"
                );
                self.viewer = Some(ViewerBuffer {
                    target_ms: t,
                    at: now,
                });
            }
            Some(t) => tracing::debug!(
                value = t,
                "viewer jitter-buffer target out of range: ignored (the last good one ages out)"
            ),
            None => tracing::trace!(
                "viewer report without a jitter-buffer target (no frames emitted in its interval, \
                 or the browser does not expose it)"
            ),
        }
    }

    fn note_engine(&mut self, engine: ViewerEngine) {
        match self.engine {
            None => {
                self.engine = Some(engine);
                tracing::info!(
                    engine = engine.as_str(),
                    phase = self.phase.as_str(),
                    release = self.release_kind(),
                    "playout: the viewer's engine is known; a hold is released {}",
                    if self.careful() {
                        "carefully and parks at min 10 ms for the rest of the session by design \
                         (min down slowly to one tick and never to zero, max never below the \
                         viewer's buffer + margin)"
                    } else {
                        "fast, as Chromium always was (min and max down together at 100 ms a \
                         second to (0, 50))"
                    }
                );
                if self.phase == PlayoutPhase::Releasing && !self.careful() {
                    // A careful release begun before the engine was known: Chromium's own takes over
                    // from where the min is.
                    tracing::debug!(
                        min_ms = self.last.min_ms,
                        max_ms = self.last.max_ms,
                        "playout: a careful release under way hands over to Chromium's fast one"
                    );
                    self.phase = PlayoutPhase::Clean;
                    self.target_ms = 0;
                    self.max_ms = self.min_ms;
                    self.switching = true;
                    self.release_began = None;
                    self.release_stage = None;
                    self.release_parked = false;
                }
            }
            Some(known) if known != engine => {
                if !self.engine_conflict_noted {
                    self.engine_conflict_noted = true;
                    tracing::warn!(
                        engine = known.as_str(),
                        reported = engine.as_str(),
                        "playout: the viewer reported a different engine; the first one stands"
                    );
                }
            }
            Some(_) => {}
        }
    }

    /// The viewer's own freeze count and frozen time this session, cumulative, from its `vv` report
    /// (`freeze_count`, `freeze_ms`: Chrome's freeze rule). A report whose count moved is a stall for
    /// the cushion ("The cushion"), or an outage's sign when its freezes were longer than
    /// [`CUSHION_STALL_MAX_MS`]. Peer numbers: a counter that went backwards (a viewer that
    /// restarted its stats) is taken as the new base and counts nothing. Read after
    /// [`Self::note_viewer`] for the same report; the cushion's calm and an outage's end are
    /// looked at after it, whatever it held.
    pub(crate) fn note_freezes(&mut self, now: Instant, count: Option<u64>, ms: Option<u64>) {
        self.read_freezes(now, count, ms);
        self.cushion_calm_check(now);
        self.outage_check(now);
    }

    fn read_freezes(&mut self, now: Instant, count: Option<u64>, ms: Option<u64>) {
        let (Some(count), Some(ms)) = (count, ms) else {
            tracing::trace!(
                has_count = count.is_some(),
                has_ms = ms.is_some(),
                "viewer report without its freeze counters: no stall evidence in it"
            );
            return;
        };
        let Some((count_was, ms_was)) = self.cushion.freezes_seen.replace((count, ms)) else {
            tracing::debug!(
                freezes = count,
                freeze_ms = ms,
                "playout cushion: the viewer's freeze counters, first seen, taken as the base"
            );
            return;
        };
        if count < count_was || ms < ms_was {
            tracing::debug!(
                freezes = count,
                freezes_was = count_was,
                freeze_ms = ms,
                freeze_ms_was = ms_was,
                "playout cushion: the viewer's freeze counters went backwards, so they are the new \
                 base and count nothing"
            );
            return;
        }
        let n = count - count_was;
        // `None` when the count did not move: no freeze in this report's interval.
        if let Some(mean_ms) = (ms - ms_was).checked_div(n) {
            self.note_stall(now, Stall::Freeze { n, mean_ms });
        }
    }

    /// A PLI or FIR from the viewer: the first of an episode ([`KEYFRAME_EPISODE_GAP`]) is a stall
    /// for the cushion; the repeats while the keyframe is on its way are not.
    pub(crate) fn note_keyframe_request(&mut self, now: Instant) {
        let since = self
            .cushion
            .last_keyframe_request
            .replace(now)
            .map(|at| now.saturating_duration_since(at));
        if since.is_some_and(|s| s < KEYFRAME_EPISODE_GAP) {
            // Trace: Chrome repeats these every couple of hundred milliseconds while it waits.
            tracing::trace!(
                since_ms = ?since.map(|s| s.as_millis()),
                "keyframe request repeating an episode: not another stall"
            );
            return;
        }
        self.note_stall(now, Stall::KeyframeRequest);
    }

    /// One stall: counted unless it is the loss's or an outage's — or, while no cushion is on, a
    /// freeze none within the ceiling would have covered — and engaging, keeping, growing or
    /// releasing the cushion for a Chromium viewer ("The cushion").
    fn note_stall(&mut self, now: Instant, stall: Stall) {
        let freeze_ms = stall.freeze_ms();
        let n = match stall {
            Stall::Freeze { n, .. } => n,
            Stall::KeyframeRequest => 1,
        };
        if let Some(long_ms) = freeze_ms.filter(|&ms| ms > CUSHION_STALL_MAX_MS) {
            tracing::debug!(
                stall = stall.as_str(),
                freezes = n,
                freeze_ms = ?freeze_ms,
                max_ms = CUSHION_STALL_MAX_MS,
                phase = self.phase.as_str(),
                "playout cushion: a freeze too long to be jitter (an outage or a stalled sender), \
                 not counted as a stall"
            );
            self.outage_sign(now, OutageSign::Freeze { freeze_ms: long_ms });
            return;
        }
        let since_loss = self
            .last_lossy_at
            .map(|at| now.saturating_duration_since(at));
        if since_loss.is_some_and(|s| s < CUSHION_LOSS_GUARD) {
            tracing::debug!(
                stall = stall.as_str(),
                freezes = n,
                freeze_ms = ?freeze_ms,
                since_loss_ms = ?since_loss.map(|s| s.as_millis()),
                guard_ms = CUSHION_LOSS_GUARD.as_millis() as u64,
                phase = self.phase.as_str(),
                "playout cushion: a stall right after a lossy report is the loss's, not counted (the \
                 hold answers loss)"
            );
            return;
        }
        match self.engine {
            Some(ViewerEngine::Chromium) => {}
            Some(engine) => {
                if !self.cushion.refused_noted {
                    self.cushion.refused_noted = true;
                    tracing::debug!(
                        engine = engine.as_str(),
                        stall = stall.as_str(),
                        freeze_ms = ?freeze_ms,
                        phase = self.phase.as_str(),
                        "playout cushion: the viewer stalls on a smooth path, but its engine is not \
                         Chromium, so it gets no cushion (a raised min must never come back to zero \
                         there: WebKit froze each time it did after a hold); said once a session"
                    );
                }
                return;
            }
            None => {
                tracing::trace!(
                    stall = stall.as_str(),
                    "playout cushion: a stall before the viewer's engine is known, not counted"
                );
                return;
            }
        }
        if let Some(o) = self.outage {
            tracing::debug!(
                stall = stall.as_str(),
                freezes = n,
                freeze_ms = ?freeze_ms,
                outage = o.first.as_str(),
                outage_ms = now.saturating_duration_since(o.since).as_millis() as u64,
                since_sign_ms = now.saturating_duration_since(o.last_at).as_millis() as u64,
                settle_ms = OUTAGE_SETTLE.as_millis() as u64,
                phase = self.phase.as_str(),
                "playout cushion: a stall during an outage, or before it has settled, is the \
                 outage's, not counted"
            );
            return;
        }
        let media_for = self
            .first_frame_at
            .map(|at| now.saturating_duration_since(at));
        if media_for.is_none_or(|d| d < CUSHION_WARMUP) {
            tracing::debug!(
                stall = stall.as_str(),
                freezes = n,
                freeze_ms = ?freeze_ms,
                media_ms = ?media_for.map(|d| d.as_millis() as u64),
                warmup_ms = CUSHION_WARMUP.as_millis() as u64,
                phase = self.phase.as_str(),
                "playout cushion: a stall in the first seconds of media is the connection's ramp, \
                 not the path's jitter: not counted"
            );
            return;
        }
        if let Some(mean_ms) = freeze_ms {
            let gap_ms = self.recent_write_gap_ms(now);
            if gap_ms.is_some_and(|gap| gap + SOURCE_GAP_SLACK_MS >= mean_ms) {
                tracing::debug!(
                    stall = stall.as_str(),
                    freezes = n,
                    freeze_ms = mean_ms,
                    write_gap_ms = ?gap_ms,
                    slack_ms = SOURCE_GAP_SLACK_MS,
                    lookback_ms = SOURCE_GAP_LOOKBACK.as_millis() as u64,
                    phase = self.phase.as_str(),
                    "playout cushion: a freeze our own sender explains — no frame was written for as \
                     long (a still screen, an encoder pause, frames withheld), not the path's \
                     jitter: not counted"
                );
                return;
            }
        }
        // Whether a cushion within the ceiling could have covered it (see `CUSHION_GROW_MS`): what
        // it measured under the min then written — at most the cushion's size while one is on, the
        // ceiling while none is — less the rest of the way to the ceiling, under Chrome's freeze
        // gap. `None` for a keyframe request, which has no length to judge.
        let under_ms = self
            .last
            .min_ms
            .min(self.cushion.on.map_or(CUSHION_MAX_MS, |on| on.size_ms));
        let left_at_ceiling = freeze_ms.map(|ms| ms.saturating_sub(CUSHION_MAX_MS - under_ms));
        let coverable = left_at_ceiling.map(|ms| ms < CHROMIUM_FREEZE_GAP_MS);
        if self.cushion.on.is_none() && coverable == Some(false) {
            // Not towards engaging one, nor a relapse: no cushion within the ceiling would have
            // spared the viewer this freeze (`CUSHION_UNCOVERABLE_TO_RELEASE`).
            tracing::debug!(
                stall = stall.as_str(),
                freezes = n,
                freeze_ms = ?freeze_ms,
                under_ms,
                left_at_ceiling_ms = ?left_at_ceiling,
                freeze_gap_ms = CHROMIUM_FREEZE_GAP_MS,
                ceiling_ms = CUSHION_MAX_MS,
                stalls = self.cushion_stalls(now),
                phase = self.phase.as_str(),
                "playout cushion: a freeze no cushion within the ceiling would have covered (what \
                 it measured, less the rest of the way to the ceiling, is still a freeze): not \
                 counted towards one"
            );
            return;
        }
        self.cushion.stalls.push_back((now, stall));
        self.prune_cushion_stalls(now);
        let count = self.cushion.stalls.len();
        let Some(mut on) = self.cushion.on else {
            // Released by its calm not long ago: the calm passed because it was absorbing the
            // spikes, so the first stall puts it back ([`CUSHION_REARM`]).
            if let Some(released) = self.cushion.released {
                let since = now.saturating_duration_since(released.at);
                if since < CUSHION_REARM {
                    self.engage_cushion(now, stall, Some(released));
                    return;
                }
                self.cushion.released = None;
                tracing::debug!(
                    stall = stall.as_str(),
                    since_release_s = since.as_secs(),
                    rearm_s = CUSHION_REARM.as_secs(),
                    released_size_ms = released.size_ms,
                    "playout cushion: its last release is older than the rearm window, so this \
                     stall starts a new count"
                );
            }
            if count < CUSHION_STALLS_TO_ENGAGE {
                tracing::debug!(
                    stall = stall.as_str(),
                    freezes = n,
                    freeze_ms = ?freeze_ms,
                    stalls = count,
                    needed = CUSHION_STALLS_TO_ENGAGE,
                    window_s = CUSHION_WINDOW.as_secs(),
                    phase = self.phase.as_str(),
                    "playout cushion: a stall on a smooth path, not yet recurring: no cushion"
                );
                return;
            }
            self.engage_cushion(now, stall, None);
            return;
        };
        on.last_stall = now;
        on.stalls += 1;
        // Grows only while it is the pair in force, and only on a freeze a cushion within the
        // ceiling would have covered: measured under the min then written, which had already
        // shortened its spike by that much, so the ceiling would have taken off only the rest
        // (see `CUSHION_GROW_MS`). Not when the size the ramp is heading for covers it already.
        let in_force = self.phase == PlayoutPhase::Cushion;
        let left_at_size = freeze_ms.map(|ms| ms.saturating_sub(on.size_ms - under_ms));
        let covered_by_size = left_at_size.is_some_and(|ms| ms < CHROMIUM_FREEZE_GAP_MS);
        let grown = (coverable == Some(true)
            && !covered_by_size
            && in_force
            && CUSHION_GROW_MS > 0
            && on.size_ms < CUSHION_MAX_MS)
            .then(|| (on.size_ms + CUSHION_GROW_MS).min(CUSHION_MAX_MS));
        let from_ms = on.size_ms;
        if let Some(size) = grown {
            on.size_ms = size;
            self.target_ms = size;
            self.switching = true;
        }
        self.cushion.on = Some(on);
        // The freezes under it in force that it cannot cover, since the last one it could
        // (`CUSHION_UNCOVERABLE_TO_RELEASE`); a keyframe request, or a stall under a hold, says
        // nothing either way.
        match coverable {
            Some(false) if in_force => {
                self.cushion.uncoverable.push_back(now);
                while self
                    .cushion
                    .uncoverable
                    .front()
                    .is_some_and(|&at| now.saturating_duration_since(at) >= CUSHION_WINDOW)
                {
                    self.cushion.uncoverable.pop_front();
                }
            }
            Some(true) if in_force => self.cushion.uncoverable.clear(),
            _ => {}
        }
        let uncoverable = self.cushion.uncoverable.len();
        tracing::debug!(
            stall = stall.as_str(),
            freezes = n,
            freeze_ms = ?freeze_ms,
            stalls = count,
            stalls_since_on = on.stalls,
            cushion_ms = on.size_ms,
            from_ms,
            under_ms,
            left_at_ceiling_ms = ?left_at_ceiling,
            freeze_gap_ms = CHROMIUM_FREEZE_GAP_MS,
            grow_ms = CUSHION_GROW_MS,
            uncoverable,
            release_at = CUSHION_UNCOVERABLE_TO_RELEASE,
            window_s = CUSHION_WINDOW.as_secs(),
            phase = self.phase.as_str(),
            calm_s = CUSHION_CALM.as_secs(),
            "playout cushion: {}",
            if grown.is_some() {
                "a stall under the cushion that a larger one would have covered: it grows (and the \
                 calm starts again)"
            } else if !in_force {
                "a stall while a hold is the pair in force: the cushion stays on, unchanged (the \
                 calm starts again)"
            } else if uncoverable >= CUSHION_UNCOVERABLE_TO_RELEASE {
                "one more stall under the cushion that no cushion within the ceiling would have \
                 covered, and enough of them within the window with none it could have since: it \
                 is released"
            } else if on.size_ms >= CUSHION_MAX_MS {
                "a stall under the cushion, already at its ceiling: kept (the calm starts again)"
            } else if covered_by_size {
                "a stall under the cushion while it ramps, which the size it is heading for covers: \
                 kept, not grown (the calm starts again)"
            } else if freeze_ms.is_none() {
                "a stall under the cushion (a keyframe request, no length to judge): kept, not \
                 grown (the calm starts again)"
            } else {
                "a stall under the cushion that no cushion within the ceiling would have covered: \
                 kept, not grown (the calm starts again)"
            }
        );
        if in_force && uncoverable >= CUSHION_UNCOVERABLE_TO_RELEASE {
            self.release_cushion_uncoverable(now, uncoverable);
        }
    }

    /// [`CUSHION_UNCOVERABLE_TO_RELEASE`] freezes under the cushion in force that no cushion within
    /// the ceiling could have covered: released down the ramp its calm takes, to the clean pair,
    /// with no relapse — the next cushion takes [`CUSHION_STALLS_TO_ENGAGE`] stalls it could cover,
    /// counted from now.
    fn release_cushion_uncoverable(&mut self, now: Instant, uncoverable: usize) {
        let Some(on) = self.cushion.on.take() else {
            return;
        };
        let window_ms = self
            .cushion
            .uncoverable
            .front()
            .map(|&at| now.saturating_duration_since(at).as_millis() as u64);
        self.cushion.uncoverable.clear();
        self.cushion.stalls.clear();
        self.cushion.released = None;
        let was = self.phase;
        self.phase = PlayoutPhase::Clean;
        self.target_ms = 0;
        self.switching = true;
        tracing::debug!(
            cushion_ms = on.size_ms,
            on_for_s = now.saturating_duration_since(on.since).as_secs(),
            stalls_while_on = on.stalls,
            uncoverable,
            over_ms = ?window_ms,
            window_s = CUSHION_WINDOW.as_secs(),
            needed = CUSHION_STALLS_TO_ENGAGE,
            "playout cushion released: the path keeps freezing under it past what any cushion \
             within the ceiling covers, so it only adds latency; no relapse — the next one takes \
             `needed` stalls it could cover, counted afresh"
        );
        self.log_switch(
            now,
            was,
            "uncoverable",
            "the viewer keeps freezing under the cushion for longer than any cushion within the \
             ceiling would cover, so the cushion is released: frames are rendered as soon as they \
             are decodable again (a Chromium viewer: min and max ramp down together to (0, 50))",
        );
    }

    /// The stall that makes [`CUSHION_STALLS_TO_ENGAGE`]: on, sized from the viewer's jitter. Or,
    /// with `relapse`, the first stall within [`CUSHION_REARM`] of the calm's release: on at once,
    /// at the larger of the size it was released at and a fresh sizing.
    fn engage_cushion(&mut self, now: Instant, stall: Stall, relapse: Option<CushionReleased>) {
        self.prune_cushion_samples(now);
        let peak = self
            .cushion
            .samples
            .iter()
            .map(|&(_, t)| t)
            .reduce(f64::max);
        let sized = peak.map_or(CUSHION_MIN_MS, |p| {
            max_ticks(p + CUSHION_HEADROOM_MS as f64).clamp(CUSHION_MIN_MS, CUSHION_MAX_MS)
        });
        let size = relapse.map_or(sized, |r| r.size_ms.max(sized));
        let stalls = self.cushion.stalls.len();
        let freezes = self
            .cushion
            .stalls
            .iter()
            .filter(|(_, s)| matches!(s, Stall::Freeze { .. }))
            .count();
        self.cushion.released = None;
        self.cushion.uncoverable.clear();
        tracing::debug!(
            stall = stall.as_str(),
            stalls,
            freezes,
            keyframe_requests = stalls - freezes,
            window_s = CUSHION_WINDOW.as_secs(),
            peak_viewer_target_ms = ?peak,
            jitter_samples = self.cushion.samples.len(),
            headroom_ms = CUSHION_HEADROOM_MS,
            min_ms = CUSHION_MIN_MS,
            max_ms = CUSHION_MAX_MS,
            sized_ms = sized,
            size_ms = size,
            relapse = relapse.is_some(),
            released_size_ms = ?relapse.map(|r| r.size_ms),
            since_release_s = ?relapse.map(|r| now.saturating_duration_since(r.at).as_secs()),
            rearm_s = CUSHION_REARM.as_secs(),
            phase = self.phase.as_str(),
            "playout cushion sized: {}{}",
            if relapse.is_some() {
                "re-engaged on the first stall since its calm released it, within the rearm \
                 window (the calm passed because it was absorbing the spikes), at the larger of \
                 the size it was released at and the viewer's peak jitter-buffer target over the \
                 window on the smooth clean pair, plus the headroom, within the bounds"
            } else {
                "the viewer's peak jitter-buffer target over the window on the smooth clean pair, \
                 plus the headroom, within the bounds"
            },
            if peak.is_none() {
                " (no such report in the window: the smallest)"
            } else {
                ""
            }
        );
        self.cushion.on = Some(CushionOn {
            size_ms: size,
            since: now,
            last_stall: now,
            stalls: stalls as u64,
        });
        match self.phase {
            PlayoutPhase::Clean => {
                let was = self.phase;
                self.phase = PlayoutPhase::Cushion;
                self.target_ms = size;
                // Pinned from the first tick, exactly as a hold has always begun.
                self.max_ms = 0.0;
                self.switching = true;
                if relapse.is_some() {
                    self.log_switch(
                        now,
                        was,
                        "relapse",
                        "the viewer froze again soon after the cushion's calm released it, so the \
                         cushion is back at once: min ramps to target_min_ms (the size it was \
                         released at, or a fresh sizing if larger), max pinned to it (a Chromium \
                         viewer)",
                    );
                } else {
                    self.log_switch(
                        now,
                        was,
                        "stalls",
                        "the viewer keeps freezing on a smooth path, with no loss, so frames get a \
                         cushion: min ramps to target_min_ms (sized from the viewer's jitter), max \
                         pinned to it (a Chromium viewer; released after calm_s without a stall)",
                    );
                }
            }
            PlayoutPhase::Holding => {
                let target = self.phase_target();
                let from = std::mem::replace(&mut self.target_ms, target);
                tracing::debug!(
                    cushion_ms = size,
                    target_min_ms = target,
                    from_target_ms = from,
                    "playout cushion on under a hold: the hold stays the pair (the larger min wins), \
                     and the cushion takes over when it ends"
                );
            }
            // A cushion is only ever on for Chromium, whose release is never the careful one, and
            // it was off: neither is reachable, and neither needs anything but the line.
            PlayoutPhase::Releasing | PlayoutPhase::Cushion => tracing::debug!(
                phase = self.phase.as_str(),
                cushion_ms = size,
                "playout cushion on in a phase that does not take it: the pair is unchanged"
            ),
        }
    }

    /// A lossy report: stalls counted within [`CUSHION_LOSS_GUARD`] before it were the loss's.
    fn cushion_takes_back_the_loss_stalls(&mut self, now: Instant) {
        let before = self.cushion.stalls.len();
        while self
            .cushion
            .stalls
            .back()
            .is_some_and(|&(at, _)| now.saturating_duration_since(at) < CUSHION_LOSS_GUARD)
        {
            self.cushion.stalls.pop_back();
        }
        let taken = before - self.cushion.stalls.len();
        if taken > 0 {
            tracing::debug!(
                taken,
                stalls = self.cushion.stalls.len(),
                guard_ms = CUSHION_LOSS_GUARD.as_millis() as u64,
                cushion_on = self.cushion.on.is_some(),
                "playout cushion: a lossy report, so the stalls counted just before it were the \
                 loss's and are taken back (a cushion already on stays)"
            );
        }
    }

    /// Release the cushion once [`CUSHION_CALM`] has passed since its last stall.
    fn cushion_calm_check(&mut self, now: Instant) {
        let Some(on) = self.cushion.on else {
            return;
        };
        let calm = now.saturating_duration_since(on.last_stall);
        if calm < CUSHION_CALM {
            return;
        }
        self.cushion.on = None;
        self.cushion.uncoverable.clear();
        // Kept for a relapse: the first stall within the rearm window puts it back at this size.
        self.cushion.released = Some(CushionReleased {
            at: now,
            size_ms: on.size_ms,
        });
        let on_for_s = now.saturating_duration_since(on.since).as_secs();
        match self.phase {
            // Out of the pair for an outage (`Self::outage_sign` dropped it): nothing to ramp, and
            // nothing to re-arm when the outage is over.
            PlayoutPhase::Clean | PlayoutPhase::Releasing => {
                tracing::debug!(
                    cushion_ms = on.size_ms,
                    on_for_s,
                    stalls_while_on = on.stalls,
                    calm_ms = calm.as_millis() as u64,
                    phase = self.phase.as_str(),
                    outage = self.outage.map_or("-", |o| o.first.as_str()),
                    rearm_s = CUSHION_REARM.as_secs(),
                    "playout cushion released: no stall for the whole calm, while an outage had it \
                     out of the pair (nothing to re-arm when the outage is over)"
                );
            }
            PlayoutPhase::Cushion => {
                let was = self.phase;
                self.phase = PlayoutPhase::Clean;
                self.target_ms = 0;
                self.switching = true;
                tracing::debug!(
                    cushion_ms = on.size_ms,
                    on_for_s,
                    stalls_while_on = on.stalls,
                    calm_ms = calm.as_millis() as u64,
                    rearm_s = CUSHION_REARM.as_secs(),
                    "playout cushion released: no stall for the whole calm (the first stall within \
                     rearm_s puts it back at this size)"
                );
                self.log_switch(
                    now,
                    was,
                    "calm",
                    "no stall on the smooth path for the whole calm, so the cushion is released: \
                     frames are rendered as soon as they are decodable again (a Chromium viewer: min \
                     and max ramp down together to (0, 50))",
                );
            }
            PlayoutPhase::Holding => {
                let target = self.phase_target();
                let from = std::mem::replace(&mut self.target_ms, target);
                tracing::debug!(
                    cushion_ms = on.size_ms,
                    on_for_s,
                    stalls_while_on = on.stalls,
                    calm_ms = calm.as_millis() as u64,
                    phase = self.phase.as_str(),
                    target_min_ms = target,
                    from_target_ms = from,
                    "playout cushion released under a hold: no stall for the whole calm, so the hold \
                     ends at the clean pair"
                );
            }
        }
    }

    /// A sign that the path stopped carrying the picture ("The cushion", outages). The first opens
    /// an outage: a cushion that is the pair in force drops at once to the clean pair, and one on
    /// under a hold stays out of it; every sign after that starts the wait for the end again.
    fn outage_sign(&mut self, now: Instant, sign: OutageSign) {
        self.last_outage_at = Some(now);
        let (silent_reports, rtt_ms, freeze_ms) = match sign {
            OutageSign::Silence { reports } => (Some(reports), None, None),
            OutageSign::Backlog { rtt_ms } => (None, Some(rtt_ms), None),
            OutageSign::Freeze { freeze_ms } => (None, None, Some(freeze_ms)),
        };
        if let Some(o) = self.outage.as_mut() {
            o.last = sign;
            o.last_at = now;
            o.signs = o.signs.saturating_add(1);
            o.reported = false;
            o.viewer_shows = false;
            // Trace: a silence signs once a second for as long as it lasts.
            tracing::trace!(
                sign = sign.as_str(),
                silent_reports = ?silent_reports,
                rtt_ms = ?rtt_ms,
                freeze_ms = ?freeze_ms,
                signs = o.signs,
                outage_ms = now.saturating_duration_since(o.since).as_millis() as u64,
                "playout: the outage goes on (the wait for its end starts again)"
            );
            return;
        }
        // The cushion only ever exists for a Chromium viewer, so the pair this drops is never one a
        // careful release would have to bring back (module docs, WebKit).
        let in_force = self.phase == PlayoutPhase::Cushion && self.cushion.on.is_some();
        let size = self.cushion.on.map(|on| on.size_ms);
        self.outage = Some(Outage {
            since: now,
            first: sign,
            last: sign,
            last_at: now,
            signs: 1,
            reported: false,
            viewer_shows: false,
            dropped_ms: size.filter(|_| in_force),
        });
        tracing::debug!(
            sign = sign.as_str(),
            silent_reports = ?silent_reports,
            rtt_ms = ?rtt_ms,
            freeze_ms = ?freeze_ms,
            phase = self.phase.as_str(),
            cushion_ms = ?size,
            min_ms = self.last.min_ms,
            max_ms = self.last.max_ms,
            settle_s = OUTAGE_SETTLE.as_secs(),
            "playout: an outage — the path stopped carrying the picture rather than jittering it; {}",
            if in_force {
                "the cushion in force drops at once to the clean pair, so what comes through after \
                 it is rendered the moment it is decodable"
            } else if size.is_some() {
                "the cushion, on under a hold, stays out of the pair until the outage is over"
            } else {
                "no cushion is on, so the pair is unchanged; the stalls of the outage are not \
                 counted towards one"
            }
        );
        if in_force {
            let was = self.phase;
            self.phase = PlayoutPhase::Clean;
            self.target_ms = 0;
            // At once, not down the release ramp: on the bench's 2.3 s stall (vpn-wifi-1011)
            // Chrome's timed renderer held the frames after it 0.4-1.6 s on every cushioned run,
            // and none on the low-latency pair. Chromium only: the min > 0 -> 0 switch that froze
            // WebKit is the one Chromium's own release has always made (module docs); what an
            // instant one costs is the frames queued for the timed render coming out at once, the
            // newest shown.
            self.min_ms = 0.0;
            self.max_ms = PLAYOUT_DELAY_MAX_MS as f64;
            self.switching = false;
            self.log_switch(
                now,
                was,
                "outage",
                "the path stopped carrying the picture (a silent receiver, a backlog, or a freeze \
                 of over a second), so the cushion drops at once to the clean pair: frames are \
                 rendered as soon as they are decodable while the stall comes through (a Chromium \
                 viewer; re-armed at its size once media flows, the receiver and the viewer report \
                 again and settle_s has passed since the last sign)",
            );
        }
    }

    /// The end of an outage: since its last sign, a receiver report (not silent, under the
    /// backlog line), a viewer report with frames in it, media written within
    /// [`MEDIA_FLOWING_WITHIN`], and [`OUTAGE_SETTLE`]. A cushion still on is re-armed at its size,
    /// ramping in as it first did.
    fn outage_check(&mut self, now: Instant) {
        let Some(o) = self.outage else {
            return;
        };
        let since_sign = now.saturating_duration_since(o.last_at);
        let flowing = self
            .moved_at
            .is_some_and(|at| now.saturating_duration_since(at) <= MEDIA_FLOWING_WITHIN);
        if !(o.reported && o.viewer_shows && flowing && since_sign >= OUTAGE_SETTLE) {
            // Trace: looked at once a second per report, receiver's and viewer's.
            tracing::trace!(
                reported = o.reported,
                viewer_shows = o.viewer_shows,
                flowing,
                since_sign_ms = since_sign.as_millis() as u64,
                settle_ms = OUTAGE_SETTLE.as_millis() as u64,
                "playout: the outage is not over yet"
            );
            return;
        }
        self.outage = None;
        let lasted_ms = now.saturating_duration_since(o.since).as_millis() as u64;
        let Some(on) = self.cushion.on else {
            tracing::debug!(
                first = o.first.as_str(),
                last = o.last.as_str(),
                signs = o.signs,
                lasted_ms,
                dropped_ms = ?o.dropped_ms,
                phase = self.phase.as_str(),
                "playout: the outage is over (no cushion on to re-arm{})",
                if o.dropped_ms.is_some() {
                    ": its calm released it meanwhile"
                } else {
                    ""
                }
            );
            return;
        };
        match self.phase {
            PlayoutPhase::Clean => {
                let was = self.phase;
                self.phase = PlayoutPhase::Cushion;
                self.target_ms = on.size_ms;
                // Pinned from the first tick, exactly as it first engaged.
                self.max_ms = 0.0;
                self.switching = true;
                tracing::debug!(
                    first = o.first.as_str(),
                    last = o.last.as_str(),
                    signs = o.signs,
                    lasted_ms,
                    cushion_ms = on.size_ms,
                    dropped_ms = ?o.dropped_ms,
                    "playout cushion re-armed: the outage is over (media flows, the receiver and the \
                     viewer report again, and the settle has passed since its last sign)"
                );
                self.log_switch(
                    now,
                    was,
                    "outage_over",
                    "the outage is over, so the cushion is back at the size it had: min ramps to \
                     target_min_ms, max pinned to it (a Chromium viewer)",
                );
            }
            PlayoutPhase::Holding => {
                let target = self.phase_target();
                let from = std::mem::replace(&mut self.target_ms, target);
                tracing::debug!(
                    first = o.first.as_str(),
                    signs = o.signs,
                    lasted_ms,
                    cushion_ms = on.size_ms,
                    target_min_ms = target,
                    from_target_ms = from,
                    "playout cushion re-armed under a hold: the outage is over, so the hold is again \
                     the larger of its round trip and the cushion"
                );
            }
            // A cushion is only on for Chromium, whose release is never the careful one, and the
            // outage took it out of the pair: neither is reachable.
            PlayoutPhase::Releasing | PlayoutPhase::Cushion => tracing::debug!(
                phase = self.phase.as_str(),
                cushion_ms = on.size_ms,
                lasted_ms,
                "playout: the outage is over in a phase that does not take the cushion back: the \
                 pair is unchanged"
            ),
        }
    }

    fn prune_write_gaps(&mut self, now: Instant) {
        while self
            .write_gaps
            .front()
            .is_some_and(|&(at, _)| now.saturating_duration_since(at) > SOURCE_GAP_LOOKBACK)
        {
            self.write_gaps.pop_front();
        }
    }

    /// The longest gap in our writes that ended within [`SOURCE_GAP_LOOKBACK`] of `now`, in
    /// milliseconds.
    fn recent_write_gap_ms(&mut self, now: Instant) -> Option<u64> {
        self.prune_write_gaps(now);
        self.write_gaps
            .iter()
            .filter(|&&(at, _)| at <= now)
            .map(|&(_, ms)| ms)
            .max()
    }

    fn prune_cushion_stalls(&mut self, now: Instant) {
        while self
            .cushion
            .stalls
            .front()
            .is_some_and(|&(at, _)| now.saturating_duration_since(at) >= CUSHION_WINDOW)
        {
            self.cushion.stalls.pop_front();
        }
    }

    fn prune_cushion_samples(&mut self, now: Instant) {
        while self
            .cushion
            .samples
            .front()
            .is_some_and(|&(at, _)| now.saturating_duration_since(at) >= CUSHION_WINDOW)
        {
            self.cushion.samples.pop_front();
        }
    }

    /// Where the written `min` heads in the phase the policy is in.
    fn phase_target(&self) -> u64 {
        match self.phase {
            PlayoutPhase::Holding => lossy_hold_ms(self.envelope.get()).max(self.cushion_ms()),
            PlayoutPhase::Cushion => self.cushion_ms(),
            PlayoutPhase::Releasing => RELEASE_MIN_FLOOR_MS,
            PlayoutPhase::Clean => 0,
        }
    }

    /// The line every switch of the pair writes, at info: one per hold, release and cushion.
    fn log_switch(&self, now: Instant, was: PlayoutPhase, reason: &'static str, what: &str) {
        let (last_fraction, last_nacks) = self.last_loss.unwrap_or((0.0, 0));
        tracing::info!(
            phase = self.phase.as_str(),
            holding = self.phase == PlayoutPhase::Holding,
            target_min_ms = self.target_ms,
            from_min_ms = self.last.min_ms,
            from_max_ms = self.last.max_ms,
            rtt_ms = self.rtt.map(|d| d.as_millis() as u64),
            rtt_envelope_ms = self.envelope.get(),
            lossy_reports = self.losing.len(),
            window_s = LOSS_MEMORY.as_secs(),
            last_loss_fraction = last_fraction,
            last_new_nacks = last_nacks,
            viewer_target_ms = ?self.viewer.map(|v| v.target_ms),
            viewer_report_age_ms = ?self.viewer.map(|v| now.saturating_duration_since(v.at).as_millis()),
            engine = self.engine.map_or("-", ViewerEngine::as_str),
            release = self.release_kind(),
            release_ramp_ms_per_s = RELEASE_RAMP_MS_PER_S,
            margin_ms = RELEASE_MAX_MARGIN_MS,
            max_floor_ms = RELEASE_MAX_FLOOR_MS,
            from_phase = was.as_str(),
            cushion_ms = self.cushion_ms(),
            cushion_size_ms = self.cushion_size_ms(),
            outage = self.outage.map_or("-", |o| o.first.as_str()),
            stalls = self.cushion_stalls(now),
            stall_window_s = CUSHION_WINDOW.as_secs(),
            calm_s = CUSHION_CALM.as_secs(),
            reason,
            "playout-delay changed: {what}"
        );
    }

    /// The cushion's `min` while it is on and not out of the pair for an outage, in milliseconds;
    /// zero otherwise.
    pub(crate) fn cushion_ms(&self) -> u64 {
        if self.outage.is_some() {
            return 0;
        }
        self.cushion_size_ms()
    }

    /// The cushion's size while it is on, outage or not, in milliseconds; zero while it is off.
    pub(crate) fn cushion_size_ms(&self) -> u64 {
        self.cushion.on.map_or(0, |on| on.size_ms)
    }

    /// Whether an outage has the cushion out of the pair ("The cushion", outages).
    pub(crate) fn outage(&self) -> bool {
        self.outage.is_some()
    }

    /// Stalls the cushion counted within [`CUSHION_WINDOW`] of `now`.
    pub(crate) fn cushion_stalls(&self, now: Instant) -> usize {
        self.cushion
            .stalls
            .iter()
            .filter(|&&(at, _)| now.saturating_duration_since(at) < CUSHION_WINDOW)
            .count()
    }

    /// Whether a hold is released carefully: for every viewer but a Chromium one (module docs).
    fn careful(&self) -> bool {
        self.engine != Some(ViewerEngine::Chromium)
    }

    fn release_kind(&self) -> &'static str {
        if self.careful() {
            "careful"
        } else {
            "fast"
        }
    }

    /// How fast `min` and `max` may come down: at the release rate, except for Chromium.
    fn down_ms_per_s(&self) -> f64 {
        if self.careful() {
            RELEASE_RAMP_MS_PER_S
        } else {
            MIN_RAMP_MS_PER_S
        }
    }

    /// The viewer's jitter-buffer target, if its report is young enough to lower the `max` on.
    fn fresh_viewer_target(&self, now: Instant) -> Option<f64> {
        self.viewer
            .filter(|v| now.saturating_duration_since(v.at) <= VIEWER_REPORT_MAX_AGE)
            .map(|v| v.target_ms)
    }

    /// The media path changed under the session: the round trip this policy knows, and the peak its
    /// envelope holds, describe a path the packets have left. Forgotten, so a hold on the new
    /// path is sized from the new path's first report — not from a peak the old one left behind,
    /// which decays at only [`RTT_ENVELOPE_DECAY_MS_PER_S`] (measured: 1758 ms from a dying WiFi
    /// link was still 1598 in the envelope eight seconds into LTE).
    pub(crate) fn forget_rtt(&mut self, why: &'static str) {
        if self.rtt.is_some() || self.envelope.get().is_some() {
            tracing::debug!(
                why,
                rtt_ms = self.rtt.map(|d| d.as_millis() as u64),
                rtt_envelope_ms = self.envelope.get(),
                phase = self.phase.as_str(),
                "playout: the path changed, so its round trip is forgotten; the next receiver \
                 report sizes the hold"
            );
        }
        self.rtt = None;
        self.envelope = RttEnvelope::default();
    }

    /// Whether frames are being held for retransmissions.
    pub(crate) fn holding(&self) -> bool {
        self.phase == PlayoutPhase::Holding
    }

    /// Where the policy is in its cycle.
    pub(crate) fn phase(&self) -> PlayoutPhase {
        self.phase
    }

    /// The viewer's last jitter-buffer target and how old it is at `now`, for the log.
    pub(crate) fn viewer_target(&self, now: Instant) -> Option<(f64, Duration)> {
        self.viewer
            .map(|v| (v.target_ms, now.saturating_duration_since(v.at)))
    }

    /// The viewer's engine, once reported.
    pub(crate) fn engine(&self) -> Option<ViewerEngine> {
        self.engine
    }

    /// Where the written `min` is heading, in milliseconds.
    pub(crate) fn target_ms(&self) -> u64 {
        self.target_ms
    }

    /// The round-trip envelope the hold is sized from, in milliseconds.
    pub(crate) fn rtt_envelope_ms(&self) -> Option<u64> {
        self.envelope.get()
    }

    /// The pair for the frame being written at `now`.
    ///
    /// Runs on every frame; the ramps are advanced by the time since the previous one. The switches
    /// are logged where they are decided ([`Self::note_report`], and the cushion's stalls and calm);
    /// here only what happens between reports is: a switch's
    /// ramp arriving at its target, each change in what a release is waiting on, and the release
    /// ending — never a line per frame, because the ramps move a tick every 100-400 ms and the
    /// per-second `playout` line carries the pair anyway.
    pub(crate) fn delay(&mut self, now: Instant) -> PlayoutDelay {
        let dt = self
            .moved_at
            .map_or(Duration::ZERO, |t| now.saturating_duration_since(t));
        self.moved_at = Some(now);
        self.frames_since_report = self.frames_since_report.saturating_add(1);
        self.first_frame_at.get_or_insert(now);
        // A gap in our own writes long enough to explain a freeze: kept for the cushion, which does
        // not count a freeze its own sender explains ("The cushion", stalls). A comparison a frame;
        // a push only after a pause.
        let gap_ms = dt.as_millis() as u64;
        if gap_ms + SOURCE_GAP_SLACK_MS >= CHROMIUM_FREEZE_GAP_MS {
            self.write_gaps.push_back((now, gap_ms));
            self.prune_write_gaps(now);
            // Trace: up to a few a second on a screen that changes in bursts.
            tracing::trace!(gap_ms, "playout: a gap in the frames written");
        }
        let target = self.target_ms as f64;
        let down = self.down_ms_per_s();
        let pair = match self.phase {
            PlayoutPhase::Clean if self.min_ms > 0.0 => {
                // Chromium's release, exactly as it always was: min and max pinned together,
                // down at the engage rate, to the clean pair.
                self.min_ms = ramp(self.min_ms, 0.0, dt, MIN_RAMP_MS_PER_S);
                self.max_ms = self.min_ms;
                PlayoutDelay::holding(min_ticks(self.min_ms))
            }
            PlayoutPhase::Clean => {
                self.min_ms = 0.0;
                self.max_ms = PLAYOUT_DELAY_MAX_MS as f64;
                PlayoutDelay::CLEAN
            }
            // The cushion is held exactly as loss is, only to its own target (and only for
            // Chromium, so `down` is the fast rate).
            PlayoutPhase::Holding | PlayoutPhase::Cushion => {
                self.min_ms = ramp(self.min_ms, target, dt, down);
                // A max an interrupted release left above the hold comes down to it no faster than
                // a release would; a pinned max follows the min, which falls no faster either.
                self.max_ms = (self.max_ms - down * dt.as_secs_f64()).max(self.min_ms);
                if self.max_ms <= self.min_ms + 1e-9 {
                    // Pinned: exactly the hold, neither less nor more.
                    self.max_ms = self.min_ms;
                    PlayoutDelay::holding(min_ticks(self.min_ms))
                } else {
                    // Not pinned yet: the min stays off zero meanwhile.
                    let min = min_ticks(self.min_ms).max(RELEASE_MIN_FLOOR_MS);
                    PlayoutDelay {
                        min_ms: min,
                        max_ms: max_ticks(self.max_ms).max(min),
                    }
                }
            }
            PlayoutPhase::Releasing => self.release_step(now, dt),
        };
        if self.switching && (self.min_ms - self.target_ms as f64).abs() < 1e-9 {
            self.switching = false;
            tracing::debug!(
                min_ms = pair.min_ms,
                max_ms = pair.max_ms,
                phase = self.phase.as_str(),
                "playout-delay ramp reached its target"
            );
        }
        if pair == PlayoutDelay::CLEAN {
            self.clean_since.get_or_insert(now);
        } else {
            self.clean_since = None;
        }
        self.last = pair;
        pair
    }

    /// One frame of a careful release: see [`PlayoutPolicy`] for the steps and the module docs for
    /// why. It never returns to [`PlayoutDelay::CLEAN`]: once the min is at its floor the pair stays
    /// parked there, the max following the viewer's buffer, until loss holds again or the session
    /// ends.
    fn release_step(&mut self, now: Instant, dt: Duration) -> PlayoutDelay {
        let secs = dt.as_secs_f64();
        let floor_ms = RELEASE_MIN_FLOOR_MS as f64;
        self.min_ms = ramp(self.min_ms, floor_ms, dt, RELEASE_RAMP_MS_PER_S);
        let margin = RELEASE_MAX_MARGIN_MS as f64;
        let viewer = self.fresh_viewer_target(now);
        let mut stage = match viewer {
            Some(t) => {
                let floor = (t + margin).max(RELEASE_MAX_FLOOR_MS as f64);
                self.max_ms = if floor > self.max_ms {
                    // The viewer's buffer is above what the max now clears: give it room again,
                    // up to the most this end ever asks for.
                    floor
                        .min(PLAYOUT_DELAY_MAX_LOSSY_MS as f64)
                        .max(self.max_ms)
                } else {
                    (self.max_ms - RELEASE_RAMP_MS_PER_S * secs).max(floor)
                };
                ReleaseStage::Following
            }
            // No fresh report: the max holds. The min still comes down to its floor, which only
            // hands the viewer's own estimate more of the range; it never takes any away.
            None => ReleaseStage::NoReport,
        };
        self.max_ms = self.max_ms.max(self.min_ms);
        let min = min_ticks(self.min_ms).max(RELEASE_MIN_FLOOR_MS);
        let max = max_ticks(self.max_ms).max(min);

        if let Some(t) = viewer {
            let floor = (t + margin).max(RELEASE_MAX_FLOOR_MS as f64);
            if self.min_ms <= floor_ms + 1e-9 && self.max_ms <= floor + 1e-9 {
                stage = ReleaseStage::Parked;
            }
        }
        if self.release_stage != Some(stage) {
            let from = self.release_stage.map_or("start", ReleaseStage::as_str);
            let first_park = stage == ReleaseStage::Parked && !self.release_parked;
            self.release_stage = Some(stage);
            let age_ms = self
                .viewer
                .map(|v| now.saturating_duration_since(v.at).as_millis());
            if first_park {
                // Once per release: the pair it will keep for the rest of the session.
                self.release_parked = true;
                tracing::info!(
                    min_ms = min,
                    max_ms = max,
                    viewer_target_ms = ?self.viewer.map(|v| v.target_ms),
                    took_ms = ?self.release_began.map(|at| now.saturating_duration_since(at).as_millis()),
                    engine = self.engine.map_or("-", ViewerEngine::as_str),
                    "playout-delay release parked: min stays at min_ms for the rest of the session \
                     by design (this engine froze when the min returned to zero after a hold); the \
                     max keeps following the viewer's jitter-buffer target + margin"
                );
            } else {
                tracing::debug!(
                    stage = stage.as_str(),
                    from,
                    min_ms = min,
                    max_ms = max,
                    viewer_target_ms = ?self.viewer.map(|v| v.target_ms),
                    viewer_report_age_ms = ?age_ms,
                    max_floor_ms = ?viewer.map(|t| (t + margin).max(RELEASE_MAX_FLOOR_MS as f64)),
                    "playout-delay release: {}",
                    match stage {
                        ReleaseStage::Following => {
                            "the max follows the viewer's fresh report, never below its target + \
                             margin"
                        }
                        ReleaseStage::NoReport => {
                            "no viewer report younger than the limit, so the max holds where it is"
                        }
                        ReleaseStage::Parked => {
                            "min at its floor and max on the viewer's target + margin: parked"
                        }
                    }
                );
            }
        }
        PlayoutDelay {
            min_ms: min,
            max_ms: max,
        }
    }
}

// ------------------------------------------------------------------------------------------------
// Retransmission trace
// ------------------------------------------------------------------------------------------------

/// How long a NACK waits for its retransmission before it counts as unanswered.
///
/// str0m answers from its RTX cache (2000 packets over 3 s, `streams/send.rs:326`) on the next
/// pacer turn, so an answer is a few milliseconds away or never: the sequence number had left the
/// cache, or the retransmission budget (`rtx_ratio_cap`, 15% of the bytes of the last second,
/// `streams/send.rs:769-777`) cleared the queue. Two seconds is far past either.
const NACK_TTL: Duration = Duration::from_secs(2);

/// At most this many retransmitted frames are listed per report line.
const RTX_RTP_LISTED: usize = 64;

/// NACKs outstanding for one sequence number.
#[derive(Debug, Default)]
struct Pending {
    /// Arrival of every NACK not yet answered, oldest first. str0m queues one retransmission per
    /// NACK entry (`streams/send.rs:953-979`), so the n-th retransmission of a sequence number
    /// answers its n-th NACK — unless str0m dropped a queued one, and then the time measured is
    /// how long the viewer really waited.
    waiting: VecDeque<Instant>,
    /// When a NACK for it last arrived; the entry expires [`NACK_TTL`] after.
    last_nack: Option<Instant>,
}

/// One report window of [`RtxTrace`].
#[derive(Debug, Default, Clone, PartialEq)]
pub(crate) struct RtxWindow {
    /// Sequence numbers NACKed for the first time.
    pub nacked: u32,
    /// NACKs for a sequence number already NACKed: the viewer asking again, because the
    /// retransmission was lost or has not arrived within its retry interval.
    pub renacked: u32,
    /// Retransmissions that answered a NACK, and how long after its arrival each went out, in
    /// microseconds.
    pub rtx: u32,
    pub rtx_after_us: Vec<u64>,
    /// Retransmissions nobody asked for: str0m's padding for probes ("spurious resends").
    pub spurious: u32,
    /// NACKs that got no retransmission within [`NACK_TTL`].
    pub unanswered: u32,
    /// RTP timestamps of the frames whose packets were retransmitted, distinct, in send order.
    pub rtx_rtp: Vec<u32>,
    /// RTP timestamps of keyframes written.
    pub keyframes_rtp: Vec<u32>,
    /// Frames written in the window.
    pub frames: u32,
    /// The smallest `wall clock at write − frame timestamp` in the window, in Unix milliseconds:
    /// the wall-clock time of RTP timestamp zero, as seen from the transport. A frame's age at
    /// display on the viewer is its presentation time minus `anchor + rtp / 90`.
    pub rtp_anchor_ms: Option<i64>,
}

impl RtxWindow {
    /// `p50/max` of the NACK-to-retransmission times, in milliseconds, or `-`.
    pub(crate) fn rtx_after_summary(&self) -> String {
        if self.rtx_after_us.is_empty() {
            return "-".to_string();
        }
        let mut v = self.rtx_after_us.clone();
        v.sort_unstable();
        let p50 = v[(v.len() - 1) / 2];
        let max = v[v.len() - 1];
        format!("{:.1}/{:.1}", p50 as f64 / 1000.0, max as f64 / 1000.0)
    }

    pub(crate) fn is_quiet(&self) -> bool {
        self.frames == 0 && self.nacked == 0 && self.renacked == 0 && self.rtx == 0
    }
}

/// Every NACK the viewer sent and every retransmission str0m answered it with.
///
/// str0m handles NACKs internally (`streams/send.rs:953-979`) and exposes neither side of it, so
/// this reads its debug mirror: `RtcConfig::enable_raw_packets` hands every incoming RTCP packet
/// and every outgoing RTP packet to the application as `Event::RawPacket`. A retransmission is an
/// RTP packet on the RTX SSRC whose payload starts with the original sequence number (RFC 4588).
/// The clone per packet is why this is only switched on when its debug line would be written
/// (measured at about 0.2 µs a packet sent, 0.02% of a core at 10 Mbit/s: see `spawn_peer_on`).
#[derive(Debug, Default)]
pub(crate) struct RtxTrace {
    pending: HashMap<u16, Pending>,
    window: RtxWindow,
}

impl RtxTrace {
    /// A NACK for these sequence numbers arrived at `now`.
    pub(crate) fn on_nack(&mut self, now: Instant, seqs: impl IntoIterator<Item = u16>) {
        for seq in seqs {
            let p = self.pending.entry(seq).or_default();
            if p.last_nack.is_some() {
                self.window.renacked += 1;
            } else {
                self.window.nacked += 1;
            }
            p.waiting.push_back(now);
            p.last_nack = Some(now);
        }
    }

    /// A retransmission of `orig_seq`, from the frame at `rtp`, went out at `now`.
    pub(crate) fn on_rtx(&mut self, now: Instant, orig_seq: u16, rtp: u32) {
        let asked = self
            .pending
            .get_mut(&orig_seq)
            .and_then(|p| p.waiting.pop_front());
        let Some(asked) = asked else {
            self.window.spurious += 1;
            return;
        };
        self.window.rtx += 1;
        self.window.rtx_after_us.push(
            u64::try_from(now.saturating_duration_since(asked).as_micros()).unwrap_or(u64::MAX),
        );
        if !self.window.rtx_rtp.contains(&rtp) && self.window.rtx_rtp.len() < RTX_RTP_LISTED {
            self.window.rtx_rtp.push(rtp);
        }
    }

    /// A frame was written: its RTP timestamp, whether it is a keyframe, and the wall-clock anchor
    /// of its timestamp (see [`RtxWindow::rtp_anchor_ms`]).
    pub(crate) fn on_frame(&mut self, rtp: u32, keyframe: bool, anchor_ms: i64) {
        self.window.frames += 1;
        if keyframe {
            self.window.keyframes_rtp.push(rtp);
        }
        self.window.rtp_anchor_ms = Some(match self.window.rtp_anchor_ms {
            Some(a) => a.min(anchor_ms),
            None => anchor_ms,
        });
    }

    /// Close the window: expire NACKs past [`NACK_TTL`] and hand back what the window saw.
    pub(crate) fn take_window(&mut self, now: Instant) -> RtxWindow {
        let mut unanswered = 0u32;
        self.pending.retain(|_, p| {
            let alive = p
                .last_nack
                .is_some_and(|t| now.saturating_duration_since(t) < NACK_TTL);
            if !alive {
                unanswered += u32::try_from(p.waiting.len()).unwrap_or(u32::MAX);
            }
            alive
        });
        self.window.unanswered += unanswered;
        std::mem::take(&mut self.window)
    }
}

/// The sequence numbers a NACK entry names: `pid`, and `pid + i + 1` for every bit `i` of `blp`
/// (RFC 4585 §6.2.1).
pub(crate) fn nack_seqs(pid: u16, blp: u16) -> impl Iterator<Item = u16> {
    std::iter::once(pid).chain(
        (0..16u16)
            .filter(move |i| blp & (1 << i) != 0)
            .map(move |i| pid.wrapping_add(i + 1)),
    )
}

/// The original sequence number an RTX packet carries (RFC 4588 §4), or `None` for a packet that
/// is not a retransmission: str0m's blank padding sets the RTP padding bit and has no payload
/// worth reading.
pub(crate) fn rtx_original_seq(packet: &[u8], header_len: usize) -> Option<u16> {
    let first = *packet.first()?;
    if first & 0x20 != 0 {
        return None;
    }
    let b = packet.get(header_len..header_len + 2)?;
    Some(u16::from_be_bytes([b[0], b[1]]))
}

/// Unix milliseconds of `SystemTime::now()`, or `None` if the clock is before 1970.
pub(crate) fn unix_ms_now() -> Option<i64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_millis()).ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    const RTT_180: Option<Duration> = Some(Duration::from_millis(180));

    fn secs(s: f64) -> Duration {
        Duration::from_secs_f64(s)
    }

    /// Frames at 60 fps from `from` to `to` seconds after `t0`; the pair on the last one.
    fn frames(p: &mut PlayoutPolicy, t0: Instant, from: f64, to: f64) -> PlayoutDelay {
        let mut last = p.delay(t0 + secs(from));
        let mut t = from;
        while t < to {
            t = (t + 1.0 / 60.0).min(to);
            last = p.delay(t0 + secs(t));
        }
        last
    }

    #[test]
    fn the_hold_is_one_retransmission_round_trip() {
        // The bench's LTE path: 180 ms round trip. 180 + 30 = 210, a whole tick.
        assert_eq!(lossy_hold_ms(Some(180)), 210);
        // The owner's relayed path: 137-141 ms.
        assert_eq!(lossy_hold_ms(Some(137)), 160);
        // A LAN pays only what a retransmission takes there.
        assert_eq!(lossy_hold_ms(Some(8)), 30);
        // A path whose round trip no buffer covers is not turned into a recording.
        assert_eq!(lossy_hold_ms(Some(400)), PLAYOUT_DELAY_MAX_LOSSY_MS);
        assert_eq!(lossy_hold_ms(Some(u64::MAX)), PLAYOUT_DELAY_MAX_LOSSY_MS);
        // Loss before any round trip was measured: the documented guess.
        assert_eq!(lossy_hold_ms(None), PLAYOUT_DELAY_UNKNOWN_RTT_MS);
    }

    #[test]
    fn every_pair_is_whole_ticks_and_pinned_while_holding() {
        assert_eq!(PlayoutDelay::holding(0), PlayoutDelay::CLEAN);
        assert_eq!(
            PlayoutDelay::holding(210),
            PlayoutDelay {
                min_ms: 210,
                max_ms: 210
            }
        );
        for rtt in [0, 1, 9, 20, 45, 137, 141, 199, 221, 1_000] {
            let hold = lossy_hold_ms(Some(rtt));
            assert_eq!(hold % PLAYOUT_DELAY_TICK_MS, 0, "rtt {rtt}");
            assert!(hold <= PLAYOUT_DELAY_MAX_LOSSY_MS, "rtt {rtt}");
        }
        // And the ramp in between writes whole ticks too.
        let t0 = Instant::now();
        let mut p = PlayoutPolicy::default();
        p.note_report(t0, RTT_180, Some(0.01), 3);
        p.note_report(t0 + secs(1.0), RTT_180, Some(0.01), 3);
        let mut t = 1.0;
        while t < 4.0 {
            t += 0.007;
            let d = p.delay(t0 + secs(t));
            assert_eq!(d.min_ms % PLAYOUT_DELAY_TICK_MS, 0, "at {t}: {d:?}");
            assert_eq!(d.max_ms % PLAYOUT_DELAY_TICK_MS, 0, "at {t}: {d:?}");
        }
    }

    #[test]
    fn a_clean_link_renders_as_soon_as_decodable_whatever_the_round_trip() {
        let t0 = Instant::now();
        let mut p = PlayoutPolicy::default();
        for (i, rtt) in [5u64, 180, 400].into_iter().enumerate() {
            let at = t0 + secs(i as f64);
            p.note_report(at, Some(Duration::from_millis(rtt)), Some(0.0), 0);
            assert_eq!(p.delay(at), PlayoutDelay::CLEAN, "rtt {rtt}");
        }
        assert!(!p.holding());
    }

    #[test]
    fn one_lost_packet_is_not_worth_a_round_trip_of_latency() {
        let t0 = Instant::now();
        let mut p = PlayoutPolicy::default();
        p.note_report(t0, RTT_180, Some(0.0), 1);
        assert!(!p.holding(), "a single lossy report does not hold frames");
        // A second one, but eleven seconds later: the first has left the window.
        p.note_report(t0 + secs(11.0), RTT_180, Some(0.0), 1);
        assert!(!p.holding());
        assert_eq!(frames(&mut p, t0, 11.0, 15.0), PlayoutDelay::CLEAN);
    }

    /// A policy for a Chromium viewer, whose release is the fast one it always had.
    fn chromium(t0: Instant) -> PlayoutPolicy {
        let mut p = PlayoutPolicy::default();
        p.note_viewer(t0, Some(ViewerEngine::Chromium), None);
        p
    }

    /// Chromium, unchanged: the hold ramps in at 100 ms a second, and out the same way to the
    /// clean pair.
    #[test]
    fn recurring_loss_holds_frames_and_ramps_in_and_out() {
        let t0 = Instant::now();
        let mut p = chromium(t0);
        assert_eq!(frames(&mut p, t0, 0.0, 1.0), PlayoutDelay::CLEAN);
        p.note_report(t0 + secs(1.0), RTT_180, Some(0.004), 2);
        assert_eq!(frames(&mut p, t0, 1.0, 2.0), PlayoutDelay::CLEAN);
        p.note_report(t0 + secs(2.0), RTT_180, Some(0.0), 1);
        assert!(p.holding());
        assert_eq!(p.target_ms(), 210);
        // 100 ms a second: a second into the ramp the pair is (100, 100), not the full 210.
        assert_eq!(
            frames(&mut p, t0, 2.0, 3.0),
            PlayoutDelay {
                min_ms: 100,
                max_ms: 100
            }
        );
        assert_eq!(
            frames(&mut p, t0, 3.0, 5.0),
            PlayoutDelay {
                min_ms: 210,
                max_ms: 210
            }
        );
        // Loss keeps coming: the hold stays, clean seconds in between notwithstanding.
        p.note_report(t0 + secs(8.0), RTT_180, Some(0.0), 0);
        p.note_report(t0 + secs(9.0), RTT_180, Some(0.0), 4);
        assert!(p.holding());
        // Ten seconds without a lossy report ends it, and the ramp takes the min back to zero.
        for s in 10..=18 {
            p.note_report(t0 + secs(f64::from(s)), RTT_180, Some(0.0), 0);
            assert!(p.holding(), "still inside the window at {s} s");
        }
        assert_eq!(
            frames(&mut p, t0, 5.0, 19.0),
            PlayoutDelay {
                min_ms: 210,
                max_ms: 210
            }
        );
        p.note_report(t0 + secs(19.0), RTT_180, Some(0.0), 0);
        assert!(!p.holding());
        assert_eq!(p.target_ms(), 0);
        assert_eq!(
            frames(&mut p, t0, 19.0, 20.0),
            PlayoutDelay {
                min_ms: 110,
                max_ms: 110
            }
        );
        assert_eq!(frames(&mut p, t0, 20.0, 22.5), PlayoutDelay::CLEAN);
    }

    /// Any other viewer — here one whose engine is not known — releases the same hold carefully:
    /// the min comes down at a quarter of the rate it went up, and with no word from the viewer
    /// about its buffer the max holds.
    #[test]
    fn a_viewer_that_is_not_chromium_releases_carefully() {
        let t0 = Instant::now();
        let mut p = PlayoutPolicy::default();
        p.note_report(t0 + secs(1.0), RTT_180, Some(0.004), 2);
        p.note_report(t0 + secs(2.0), RTT_180, Some(0.0), 1);
        assert_eq!(frames(&mut p, t0, 2.0, 12.0), PlayoutDelay::holding(210));
        p.note_report(t0 + secs(12.0), RTT_180, Some(0.0), 0);
        assert_eq!(p.phase(), PlayoutPhase::Releasing);
        assert_eq!(p.target_ms(), RELEASE_MIN_FLOOR_MS);
        assert_eq!(
            frames(&mut p, t0, 12.0, 13.0),
            PlayoutDelay {
                min_ms: 180,
                max_ms: 210
            }
        );
        assert_eq!(
            frames(&mut p, t0, 13.0, 40.0),
            PlayoutDelay {
                min_ms: RELEASE_MIN_FLOOR_MS,
                max_ms: 210
            },
            "never back to the clean pair without the viewer's buffer to go by"
        );
    }

    /// The viewer's jitter-buffer target as WebKit reports it: the delay the
    /// pair forces (or its own estimate, when that is larger and the max allows it) less the decode
    /// and render time it leaves out — a hold pinned at 250 read as ~222 — and, on the low-latency
    /// pair, its bare estimate.
    fn webkit_target(pair: PlayoutDelay, estimate_ms: f64) -> f64 {
        const DECODE_AND_RENDER_MS: f64 = 28.0;
        if pair.min_ms == 0 {
            return estimate_ms;
        }
        (estimate_ms + DECODE_AND_RENDER_MS).clamp(pair.min_ms as f64, pair.max_ms as f64)
            - DECODE_AND_RENDER_MS
    }

    /// Frames at 60 fps from `from` to `to` seconds after `t0`, with a clean receiver report and a
    /// viewer report (from `viewer`, given the pair on the wire) at every whole second. Every pair.
    fn run(
        p: &mut PlayoutPolicy,
        t0: Instant,
        from: f64,
        to: f64,
        viewer: &mut dyn FnMut(f64, PlayoutDelay) -> Option<f64>,
    ) -> Vec<(f64, PlayoutDelay)> {
        let mut out = Vec::new();
        let mut t = from;
        let mut next_report = from.floor() + 1.0;
        while t < to {
            t = (t + 1.0 / 60.0).min(to);
            if t >= next_report {
                let at = t0 + secs(next_report);
                // The round trip of `held_at_250`, so the hold stays where it was put.
                p.note_report(at, Some(Duration::from_millis(220)), Some(0.0), 0);
                let last = out.last().map_or(p.last, |(_, d)| *d);
                p.note_viewer(at, None, viewer(next_report, last));
                next_report += 1.0;
            }
            out.push((t, p.delay(t0 + secs(t))));
        }
        out
    }

    /// A hold of 250 ms, reached and settled, at `t0 + 5 s`.
    fn held_at_250(t0: Instant) -> PlayoutPolicy {
        let mut p = PlayoutPolicy::default();
        let rtt = Some(Duration::from_millis(220));
        p.note_report(t0, rtt, Some(0.01), 3);
        p.note_report(t0 + secs(1.0), rtt, Some(0.01), 3);
        assert_eq!(frames(&mut p, t0, 1.0, 5.0), PlayoutDelay::holding(250));
        p
    }

    /// Everything a release must never do, frame by frame: take the min to zero before the end,
    /// let the max below the min, or bring either down faster than the release rate (one tick of
    /// rounding allowed over each second).
    fn assert_careful(pairs: &[(f64, PlayoutDelay)]) {
        for (i, (t, d)) in pairs.iter().enumerate() {
            assert!(d.max_ms >= d.min_ms, "at {t}: {d:?}");
            if *d != PlayoutDelay::CLEAN {
                assert!(d.min_ms >= RELEASE_MIN_FLOOR_MS, "at {t}: {d:?}");
            }
            let Some((t1, d1)) = pairs[..i].iter().rev().find(|(t1, _)| t - t1 >= 1.0) else {
                continue;
            };
            if *d == PlayoutDelay::CLEAN {
                continue;
            }
            let allowed = (RELEASE_RAMP_MS_PER_S * (t - t1)) as u64 + PLAYOUT_DELAY_TICK_MS;
            assert!(
                d1.max_ms.saturating_sub(d.max_ms) <= allowed,
                "max fell too fast: {d1:?} at {t1} -> {d:?} at {t}"
            );
            assert!(
                d1.min_ms.saturating_sub(d.min_ms) <= allowed,
                "min fell too fast: {d1:?} at {t1} -> {d:?} at {t}"
            );
        }
    }

    /// A 250 ms hold released on an LTE path whose WebKit buffer estimate sat near 70 ms. A plain
    /// ramp takes the pair from (250, 250) to (0, 50) in 2.5 s and the picture freezes as it
    /// arrives. Here the max never drops under the viewer's buffer plus the margin, and
    /// the release parks at min 10 for good.
    #[test]
    fn a_release_follows_the_viewers_buffer_down_and_parks_above_it() {
        let t0 = Instant::now();
        let mut p = held_at_250(t0);
        let mut reports: Vec<(f64, f64)> = Vec::new();
        let mut webkit = |t: f64, pair: PlayoutDelay| {
            let target = webkit_target(pair, 70.0);
            reports.push((t, target));
            Some(target)
        };
        // The loss stopped at 1 s; the window runs out at 11 s.
        let hold = run(&mut p, t0, 5.0, 11.5, &mut webkit);
        assert!(hold
            .iter()
            .filter(|(t, _)| *t < 11.0)
            .all(|(_, d)| *d == PlayoutDelay::holding(250)));
        assert_eq!(p.phase(), PlayoutPhase::Releasing);
        // Five minutes on a clean link after the release began.
        let release = run(&mut p, t0, 11.5, 311.0, &mut webkit);
        assert_careful(&release);
        // The max stays clear of what the viewer buffers: on every frame, at least the target it
        // last reported plus the margin — or the most this end asks for, when that is lower.
        for (t, d) in &release {
            let Some((_, target)) = reports.iter().rev().find(|(at, _)| at <= t) else {
                continue;
            };
            let bound = (target + RELEASE_MAX_MARGIN_MS as f64).min(250.0);
            assert!(
                d.max_ms as f64 + 1e-9 >= bound,
                "at {t}: {d:?}, viewer {target}"
            );
        }
        // Where it settled, and stayed for the rest of those five minutes: the min on its floor,
        // the max at the buffer (70) plus the margin, never the clean pair.
        let parked = PlayoutDelay {
            min_ms: RELEASE_MIN_FLOOR_MS,
            max_ms: 120,
        };
        assert!(release
            .iter()
            .filter(|(t, _)| *t >= 30.0)
            .all(|(_, d)| *d == parked));
        assert!(release.iter().all(|(_, d)| *d != PlayoutDelay::CLEAN));
        assert_eq!(reports.last().map(|(_, t)| *t), Some(70.0));
        assert_eq!(p.phase(), PlayoutPhase::Releasing);
        assert_eq!(p.target_ms(), RELEASE_MIN_FLOOR_MS);
        // The way down took the ten seconds the rate implies, not two and a half.
        let reached_floor = release
            .iter()
            .find(|(_, d)| d.min_ms == RELEASE_MIN_FLOOR_MS)
            .map(|(t, _)| t - 11.0);
        assert!(
            reached_floor.is_some_and(|s| (9.0..=10.5).contains(&s)),
            "{reached_floor:?}"
        );
    }

    /// However small the viewer's buffer gets, a careful release does not take the last step: the
    /// max follows it down to its floor (the clean pair's 50 ms) and the min stays at one tick.
    #[test]
    fn a_small_buffer_brings_the_max_to_its_floor_but_never_back_to_the_clean_pair() {
        let t0 = Instant::now();
        let mut p = held_at_250(t0);
        let mut estimate = 70.0;
        let mut viewer = |t: f64, pair: PlayoutDelay| {
            estimate = if t >= 60.0 {
                0.0
            } else if t >= 30.0 {
                30.0
            } else {
                70.0
            };
            Some(webkit_target(pair, estimate))
        };
        run(&mut p, t0, 5.0, 11.5, &mut viewer);
        let release = run(&mut p, t0, 11.5, 120.0, &mut viewer);
        assert_careful(&release);
        assert!(release.iter().all(|(_, d)| *d != PlayoutDelay::CLEAN));
        let pair_at = |at: f64| {
            release
                .iter()
                .find(|(t, _)| *t >= at)
                .map(|(_, d)| *d)
                .unwrap_or(PlayoutDelay::CLEAN)
        };
        let floor = RELEASE_MIN_FLOOR_MS;
        assert_eq!(
            pair_at(29.0),
            PlayoutDelay {
                min_ms: floor,
                max_ms: 120
            }
        );
        // 30 + 50, reached at the release rate.
        assert_eq!(
            pair_at(59.0),
            PlayoutDelay {
                min_ms: floor,
                max_ms: 80
            }
        );
        // Nothing to buffer: the max floor, and the min still one tick above zero.
        assert_eq!(
            pair_at(119.0),
            PlayoutDelay {
                min_ms: floor,
                max_ms: RELEASE_MAX_FLOOR_MS
            }
        );
        assert_eq!(p.phase(), PlayoutPhase::Releasing);
        assert_eq!(p.target_ms(), RELEASE_MIN_FLOOR_MS);
    }

    /// A new hold after the release parked engages as usual and releases back to the same parking.
    #[test]
    fn a_new_hold_after_parking_engages_as_usual_and_parks_again() {
        let t0 = Instant::now();
        let mut p = held_at_250(t0);
        let mut viewer = |_t: f64, pair: PlayoutDelay| Some(webkit_target(pair, 30.0));
        run(&mut p, t0, 5.0, 11.5, &mut viewer);
        let first = run(&mut p, t0, 11.5, 40.0, &mut viewer);
        let parked = PlayoutDelay {
            min_ms: RELEASE_MIN_FLOOR_MS,
            max_ms: 80,
        };
        assert_eq!(first.last().map(|(_, d)| *d), Some(parked));
        // Loss again: held as any hold is, the min climbing at the engage rate to a pinned 250.
        let rtt = Some(Duration::from_millis(220));
        p.note_report(t0 + secs(40.0), rtt, Some(0.01), 2);
        p.note_report(t0 + secs(41.0), rtt, Some(0.01), 2);
        assert_eq!(p.phase(), PlayoutPhase::Holding);
        let held = frames(&mut p, t0, 40.0, 45.0);
        assert_eq!(held, PlayoutDelay::holding(250));
        // Clean for the window again: the same careful release, to the same parking.
        let second = run(&mut p, t0, 45.0, 80.0, &mut viewer);
        assert_eq!(p.phase(), PlayoutPhase::Releasing);
        assert_careful(&second);
        assert!(second.iter().all(|(_, d)| *d != PlayoutDelay::CLEAN));
        assert_eq!(second.last().map(|(_, d)| *d), Some(parked));
    }

    /// No fresh report from the viewer: the max holds, wherever it is. A report lowers it again,
    /// and when reports stop, it holds again past the age limit.
    #[test]
    fn without_a_fresh_viewer_report_the_max_holds() {
        let t0 = Instant::now();
        let mut p = held_at_250(t0);
        let mut none = |_t: f64, _pair: PlayoutDelay| None;
        run(&mut p, t0, 5.0, 11.5, &mut none);
        let silent = run(&mut p, t0, 11.5, 30.0, &mut none);
        assert_careful(&silent);
        assert!(silent.iter().all(|(_, d)| d.max_ms == 250));
        assert_eq!(
            silent.last().map(|(_, d)| d.min_ms),
            Some(RELEASE_MIN_FLOOR_MS)
        );
        // Two reports of a small buffer, at 31 and 32 s: the max comes down at the release rate
        // while they are fresh (to 34.5 s)...
        let mut two = |t: f64, _pair: PlayoutDelay| (t <= 32.0).then_some(30.0);
        let told = run(&mut p, t0, 30.0, 45.0, &mut two);
        assert_careful(&told);
        let max_at = |at: f64| {
            told.iter()
                .find(|(t, _)| *t >= at)
                .map(|(_, d)| d.max_ms)
                .unwrap_or(0)
        };
        assert_eq!(max_at(31.0), 250);
        // 3.4 s at 25 ms a second: 165, to the tick above.
        assert_eq!(max_at(34.4), 170);
        // ...and not a millisecond after the last one went stale.
        assert_eq!(max_at(35.0), max_at(44.9));
        assert!(told.iter().all(|(_, d)| *d != PlayoutDelay::CLEAN));
    }

    /// A buffer that grows while parked gets its room back, up to the most this end ever asks for.
    #[test]
    fn a_growing_buffer_during_a_release_raises_the_max_again() {
        let t0 = Instant::now();
        let mut p = held_at_250(t0);
        let mut viewer = |t: f64, pair: PlayoutDelay| {
            Some(if t >= 35.0 {
                // Past anything the product will wait for.
                400.0
            } else if t >= 25.0 {
                // Its buffer jumps past what the parked max clears.
                180.0
            } else {
                webkit_target(pair, 45.0)
            })
        };
        run(&mut p, t0, 5.0, 11.5, &mut viewer);
        let release = run(&mut p, t0, 11.5, 45.0, &mut viewer);
        let max_before = |at: f64| {
            release
                .iter()
                .rfind(|(t, _)| *t < at)
                .map(|(_, d)| *d)
                .unwrap_or(PlayoutDelay::CLEAN)
        };
        assert_eq!(max_before(25.0).max_ms, 100, "45 + margin, to the tick");
        assert_eq!(max_before(35.0).max_ms, 230, "180 + margin");
        let later = release
            .last()
            .map(|(_, d)| *d)
            .unwrap_or(PlayoutDelay::CLEAN);
        assert_eq!(
            later.max_ms, PLAYOUT_DELAY_MAX_LOSSY_MS,
            "capped at the most ever asked for"
        );
        assert_eq!(later.min_ms, RELEASE_MIN_FLOOR_MS);
    }

    /// Loss coming back mid-release holds again: the min climbs at the engage rate, and the max,
    /// which sits above it, is never yanked down to meet it.
    #[test]
    fn loss_during_a_release_holds_again_without_dropping_the_max() {
        let t0 = Instant::now();
        let mut p = held_at_250(t0);
        let mut viewer = |_t: f64, pair: PlayoutDelay| Some(webkit_target(pair, 70.0));
        run(&mut p, t0, 5.0, 11.5, &mut viewer);
        let mid = run(&mut p, t0, 11.5, 16.0, &mut viewer);
        let (_, at_16) = mid.last().copied().unwrap_or((0.0, PlayoutDelay::CLEAN));
        assert!(
            at_16.min_ms < 250 && at_16.max_ms > at_16.min_ms,
            "{at_16:?}"
        );
        p.note_report(
            t0 + secs(16.0),
            Some(Duration::from_millis(220)),
            Some(0.01),
            2,
        );
        p.note_report(
            t0 + secs(17.0),
            Some(Duration::from_millis(220)),
            Some(0.01),
            2,
        );
        assert_eq!(p.phase(), PlayoutPhase::Holding);
        let again = run(&mut p, t0, 16.0, 22.0, &mut viewer);
        assert_careful(&again);
        for w in again.windows(2) {
            assert!(
                w[1].1.min_ms + PLAYOUT_DELAY_TICK_MS >= w[0].1.min_ms,
                "{w:?}"
            );
        }
        assert_eq!(
            again.last().map(|(_, d)| *d),
            Some(PlayoutDelay::holding(250))
        );
    }

    /// A hold that shrinks with the round trip (here, a path change) comes down no faster than a
    /// release, and stays pinned.
    #[test]
    fn a_shrinking_hold_comes_down_at_the_release_rate_and_stays_pinned() {
        let t0 = Instant::now();
        let mut p = held_at_250(t0);
        p.forget_rtt("test");
        p.note_report(t0 + secs(5.0), RTT_180, Some(0.01), 1);
        assert_eq!(p.target_ms(), 210);
        let pairs = {
            let mut out = Vec::new();
            let mut t = 5.0;
            while t < 8.0 {
                t += 1.0 / 60.0;
                out.push((t, p.delay(t0 + secs(t))));
            }
            out
        };
        assert_careful(&pairs);
        assert!(pairs.iter().all(|(_, d)| d.min_ms == d.max_ms), "pinned");
        let at = |s: f64| pairs.iter().find(|(t, _)| *t >= s).map(|(_, d)| d.min_ms);
        assert_eq!(
            at(6.0),
            Some(220),
            "250 - 25 in the first second, to the tick"
        );
        assert_eq!(at(7.9), Some(210));

        // Chromium's hold shrinks as it always did, at 100 ms a second.
        let mut c = chromium(t0);
        let rtt = Some(Duration::from_millis(220));
        c.note_report(t0, rtt, Some(0.01), 3);
        c.note_report(t0 + secs(1.0), rtt, Some(0.01), 3);
        assert_eq!(frames(&mut c, t0, 1.0, 5.0), PlayoutDelay::holding(250));
        c.forget_rtt("test");
        c.note_report(t0 + secs(5.0), RTT_180, Some(0.01), 1);
        assert_eq!(frames(&mut c, t0, 5.0, 5.3), PlayoutDelay::holding(220));
        assert_eq!(frames(&mut c, t0, 5.3, 6.0), PlayoutDelay::holding(210));
    }

    /// Chromium's release is the fast one; every other engine's, and an engine not reported yet,
    /// is careful. The engine that sets the rule is the first one reported.
    #[test]
    fn the_release_is_fast_for_chromium_and_careful_for_everyone_else() {
        let t0 = Instant::now();
        let script = |engine: Option<ViewerEngine>| {
            let mut p = held_at_250(t0);
            if engine.is_some() {
                p.note_viewer(t0, engine, None);
            }
            let mut viewer = |_t: f64, pair: PlayoutDelay| Some(webkit_target(pair, 30.0));
            run(&mut p, t0, 5.0, 11.0, &mut viewer);
            let pairs = run(&mut p, t0, 11.0, 40.0, &mut viewer);
            (p.engine(), pairs)
        };
        let clean_after = |pairs: &[(f64, PlayoutDelay)]| {
            pairs
                .iter()
                .find(|(_, d)| *d == PlayoutDelay::CLEAN)
                .map(|(t, _)| t - 11.0)
        };
        let (engine, fast) = script(Some(ViewerEngine::Chromium));
        assert_eq!(engine, Some(ViewerEngine::Chromium));
        // Pinned all the way down at 100 ms a second: 250 ms of hold in 2.5 s.
        assert!(fast
            .iter()
            .all(|(_, d)| *d == PlayoutDelay::CLEAN || d.min_ms == d.max_ms));
        assert!(
            clean_after(&fast).is_some_and(|s| (2.4..=2.6).contains(&s)),
            "{fast:?}"
        );
        for engine in [
            Some(ViewerEngine::WebKit),
            Some(ViewerEngine::Gecko),
            Some(ViewerEngine::Unknown),
            None,
        ] {
            let (_, careful) = script(engine);
            assert_careful(&careful);
            // Down at the release rate to one tick, and parked there: never the clean pair.
            assert_eq!(clean_after(&careful), None, "{engine:?}");
            assert_eq!(
                careful.last().map(|(_, d)| *d),
                Some(PlayoutDelay {
                    min_ms: RELEASE_MIN_FLOOR_MS,
                    max_ms: 80
                }),
                "{engine:?}"
            );
        }
        // A second, different engine changes nothing.
        let mut p = chromium(t0);
        p.note_viewer(t0, Some(ViewerEngine::WebKit), None);
        assert_eq!(p.engine(), Some(ViewerEngine::Chromium));
    }

    /// The engine can arrive after a careful release has begun; Chromium's fast one takes over
    /// from where the min is.
    #[test]
    fn a_chromium_engine_reported_mid_release_takes_the_fast_way_down() {
        let t0 = Instant::now();
        let mut p = held_at_250(t0);
        let mut none = |_t: f64, _pair: PlayoutDelay| None;
        run(&mut p, t0, 5.0, 11.0, &mut none);
        let careful = run(&mut p, t0, 11.0, 13.0, &mut none);
        assert_eq!(p.phase(), PlayoutPhase::Releasing);
        assert_eq!(careful.last().map(|(_, d)| d.min_ms), Some(200));
        p.note_viewer(t0 + secs(13.0), Some(ViewerEngine::Chromium), None);
        assert_eq!(p.phase(), PlayoutPhase::Clean);
        let fast = run(&mut p, t0, 13.0, 16.0, &mut none);
        assert!(fast
            .iter()
            .all(|(_, d)| *d == PlayoutDelay::CLEAN || d.min_ms == d.max_ms));
        assert_eq!(fast.last().map(|(_, d)| *d), Some(PlayoutDelay::CLEAN));
    }

    // --------------------------------------------------------------------------------------------
    // The cushion
    // --------------------------------------------------------------------------------------------

    /// What [`replay`] saw, frame by frame at 60 fps.
    #[derive(Debug, Default)]
    struct Replayed {
        seconds: f64,
        holding_s: f64,
        cushion_s: f64,
        /// Time-weighted sum of the `min` written, and of the one the session itself wrote.
        min_ms_s: f64,
        real_min_ms_s: f64,
        /// Time spent in [`PlayoutPhase::Cushion`] by cushion size.
        size_s: std::collections::BTreeMap<u64, f64>,
        /// When the cushion went on (and at what size) and off, in seconds.
        engaged: Vec<(f64, u64)>,
        released: Vec<f64>,
        /// Of `released`: those for freezes under it that no cushion within the ceiling covers
        /// ([`CUSHION_UNCOVERABLE_TO_RELEASE`]) rather than by its calm.
        released_uncoverable: u64,
        /// Outages that began ("The cushion", outages).
        outages: u64,
        /// Freezes the viewer reported on the session's own clean pair, with no lossy report in
        /// the guard before them; how many of those fell while the replayed cushion was on; and
        /// how many the freeze model takes as covered by the pair then in force.
        smooth_freezes: u64,
        smooth_freezes_cushioned: u64,
        covered: u64,
        /// Every pair written.
        pairs: Vec<(f64, PlayoutDelay)>,
        keep_pairs: bool,
    }

    /// A frame interval at 60 fps: what [`replay`] steps by, and what the freeze model adds to
    /// Chrome's 150 ms.
    const FRAME_S: f64 = 1.0 / 60.0;

    /// Replay a session's events through the policy for a viewer of `engine`, with frames at 60
    /// fps in between.
    ///
    /// One event per line, tab-separated, times in milliseconds (the format `extract.py` writes
    /// from a session log):
    ///
    /// ```text
    /// R <t> <rtt_ms|-> <loss_fraction|-> <new_nacks>                 a receiver report
    /// V <t> <freezes> <freeze_ms> <jbuf_target_ms|-> <session_min>   a `vv` report, cumulative
    /// P <t> <requests>                                               a logged PLI line
    /// ```
    ///
    /// `session_min` is the `min` the session itself had on the wire, for telling the freezes of its
    /// clean pair from those under its holds. With `model`, a freeze on the session's clean pair
    /// that the pair now in force would have covered by Chrome's rule (at most its `min` +
    /// [`CHROMIUM_FREEZE_EXCESS_MS`] + a frame) is taken as never having happened, and the policy
    /// does not hear of it; one it would not have is heard of shortened by that `min` (a spike `s`
    /// under `c` shows as `s - c`; the release on freezes past the ceiling reads their length) — a crude model of the timed renderer, which knows nothing of the
    /// decoder.
    fn replay(events: &str, engine: Option<ViewerEngine>, model: bool, keep: bool) -> Replayed {
        let t0 = Instant::now();
        let mut p = PlayoutPolicy::default();
        if engine.is_some() {
            p.note_viewer(t0, engine, None);
        }
        let mut out = Replayed {
            keep_pairs: keep,
            ..Replayed::default()
        };
        let mut t = 0.0f64;
        let mut last_lossy: Option<f64> = None;
        let mut seen = (0u64, 0u64);
        let mut hidden = (0u64, 0u64);
        let mut real_min = 0.0f64;
        let mut outage = false;
        let guard = CUSHION_LOSS_GUARD.as_secs_f64();
        for line in events.lines().map(str::trim).filter(|l| !l.is_empty()) {
            let f: Vec<&str> = line.split_whitespace().collect();
            let at = f[1].parse::<f64>().expect("time") / 1000.0;
            while t + FRAME_S <= at {
                t += FRAME_S;
                let d = p.delay(t0 + secs(t));
                out.seconds += FRAME_S;
                out.min_ms_s += d.min_ms as f64 * FRAME_S;
                out.real_min_ms_s += real_min * FRAME_S;
                match p.phase() {
                    PlayoutPhase::Cushion => {
                        out.cushion_s += FRAME_S;
                        *out.size_s.entry(p.cushion_ms()).or_default() += FRAME_S;
                    }
                    PlayoutPhase::Holding => out.holding_s += FRAME_S,
                    PlayoutPhase::Clean | PlayoutPhase::Releasing => {}
                }
                if out.keep_pairs {
                    out.pairs.push((t, d));
                }
            }
            let now = t0 + secs(at);
            // On and off by its size, not by the pair: an outage takes it out of the pair without
            // releasing it.
            let was = p.cushion_size_ms();
            match f[0] {
                "R" => {
                    let rtt = f[2].parse::<u64>().ok().map(Duration::from_millis);
                    let loss = f[3].parse::<f32>().ok();
                    let nacks = f[4].parse::<u64>().unwrap_or(0);
                    if loss.is_some_and(|l| l > 0.0) || nacks > 0 {
                        last_lossy = Some(at);
                    }
                    p.note_report(now, rtt, loss, nacks);
                }
                "V" => {
                    let count: u64 = f[2].parse().expect("freezes");
                    let ms: u64 = f[3].parse().expect("freeze_ms");
                    let target = f[4].parse::<f64>().ok();
                    real_min = f[5].parse().unwrap_or(0.0);
                    let (n, n_ms) = (count - seen.0, ms - seen.1);
                    seen = (count, ms);
                    let smooth = real_min == 0.0 && last_lossy.is_none_or(|l| at - l >= guard);
                    if n > 0 && smooth {
                        out.smooth_freezes += n;
                        if p.phase() == PlayoutPhase::Cushion {
                            out.smooth_freezes_cushioned += n;
                        }
                        let c = p.last.min_ms as f64;
                        let reach = c + CHROMIUM_FREEZE_EXCESS_MS as f64 + FRAME_S * 1000.0;
                        if model && c > 0.0 && (n_ms / n) as f64 <= reach {
                            out.covered += n;
                            hidden = (hidden.0 + n, hidden.1 + n_ms);
                        } else if model && c > 0.0 {
                            // Not covered: shown shortened by the pair, `s - c` (module docs).
                            hidden.1 += n * p.last.min_ms;
                        }
                    }
                    p.note_viewer(now, None, target);
                    p.note_freezes(now, Some(count - hidden.0), Some(ms - hidden.1));
                }
                "P" => p.note_keyframe_request(now),
                other => panic!("unknown event {other:?} in {line:?}"),
            }
            let is = p.cushion_size_ms();
            if was == 0 && is > 0 {
                out.engaged.push((at, is));
            } else if was > 0 && is == 0 {
                out.released.push(at);
                // The calm keeps it for a relapse; a release for uncoverable freezes does not.
                if p.cushion.released.is_none() {
                    out.released_uncoverable += 1;
                }
            }
            if !outage && p.outage() {
                out.outages += 1;
            }
            outage = p.outage();
        }
        out
    }

    /// The jittery VPN session's first 58 seconds ([`replay`]'s format, as `extract.py` wrote it
    /// from the session's log): Telegram Desktop over a VPN on Wi-Fi, 290 ms.
    /// A freeze at 2 s; a burst of loss at 28.7-29.7 s, with the freezes and the PLI it caused and a
    /// freeze of a second at 31 s, held at 250 ms until 39.7 s; then, on the clean pair with no
    /// loss, a PLI episode at 52 s and freezes of 815, 223 and 241 ms at 53, 54 and 55 s.
    const JITTERY_VPN_FIRST_MINUTE: &str = "
        V 0 0 0 - 0
        V 1000 0 0 88.8 0
        R 1688 294 0.0 0
        V 2005 1 192 99.5 0
        V 2999 1 192 93.1 0
        R 3688 291 0.0 0
        V 4000 1 192 93.4 0
        R 4688 288 0.0 0
        V 4998 1 192 97.9 0
        V 6001 1 192 95.7 0
        R 6688 293 0.0 0
        V 7000 1 192 88.8 0
        R 7689 294 0.0 0
        V 8002 1 192 80.7 0
        R 8688 292 0.0 0
        V 9002 1 192 77.7 0
        R 9689 291 0.0 0
        V 9999 1 192 71.5 0
        V 11002 1 192 67.6 0
        R 11689 292 0.0 0
        V 11999 1 192 67.6 0
        R 12688 290 0.0 0
        V 13000 1 192 67.0 0
        R 13688 294 0.0 0
        V 13999 1 192 65.9 0
        R 14689 298 0.0 0
        V 15001 1 192 64.1 0
        R 15689 293 0.0 0
        V 16013 1 192 62.6 0
        R 16689 313 0.0 0
        V 17001 1 192 62.6 0
        R 17689 308 0.0 0
        V 18003 1 192 62.0 0
        R 18689 298 0.0 0
        V 18999 1 192 61.5 0
        R 19689 302 0.0 0
        V 19999 1 192 59.9 0
        V 21000 1 192 59.2 0
        R 21689 401 0.0 0
        V 22037 1 192 58.2 0
        R 22688 294 0.0 0
        V 23000 1 192 59.3 0
        R 23688 291 0.0 0
        V 24001 1 192 59.0 0
        R 24689 293 0.0 0
        V 24998 1 192 58.3 0
        R 25688 293 0.0 0
        V 26000 1 192 58.0 0
        R 26688 296 0.0 0
        V 26998 1 192 56.7 0
        R 27688 298 0.0 0
        V 28004 1 192 53.1 0
        R 28688 294 0.0216 2
        V 29001 2 489 38.5 0
        P 29094 1
        R 29689 294 0.0268 4
        V 30004 2 489 32.2 0
        R 30688 291 0.0 0
        V 30999 3 1526 42.4 100
        R 31688 371 0.0 0
        V 32012 3 1526 118.7 200
        R 32688 300 0.0 0
        V 33002 3 1526 228.6 250
        R 33688 292 0.0 0
        V 34013 3 1526 240.0 250
        R 34689 294 0.0 0
        V 35003 3 1526 240.0 250
        V 36007 3 1526 240.0 250
        R 36688 301 0.0 0
        V 37001 3 1526 240.0 250
        R 37689 295 0.0 0
        V 38003 3 1526 240.0 250
        R 38688 296 0.0 0
        V 39003 3 1526 240.0 250
        R 39689 297 0.0 0
        V 40002 3 1526 240.0 250
        R 40689 353 0.0 0
        V 41068 3 1526 187.3 150
        R 41688 305 0.0 0
        V 42001 3 1526 85.0 50
        V 42996 3 1526 53.4 0
        R 43689 300 0.0 0
        V 44001 3 1526 48.8 0
        R 44688 299 0.0 0
        V 44999 3 1526 44.8 0
        R 45689 326 0.0 0
        V 46006 3 1526 46.0 0
        R 46688 300 0.0 0
        V 46999 3 1526 45.8 0
        R 47689 292 0.0 0
        V 48011 3 1526 45.3 0
        R 48688 291 0.0 0
        V 49008 3 1526 47.8 0
        R 49689 329 0.0 0
        V 50001 3 1526 52.4 0
        R 50689 294 0.0 0
        V 50998 3 1526 51.3 0
        R 51689 292 0.0 0
        P 51982 5
        V 52004 3 1526 49.1 0
        R 52688 295 0.0 0
        V 53001 4 2341 57.6 0
        R 53688 295 0.0 0
        V 53999 5 2564 63.5 0
        R 54688 293 0.0 0
        V 54999 6 2805 72.6 0
        R 55688 293 0.0 0
        V 55999 6 2805 70.9 0
        R 56688 312 0.0 0
        V 57006 6 2805 69.5 0
        R 57688 293 0.0 0
    ";

    /// The pair written at `at` seconds, from a replay that kept them.
    fn pair_at(r: &Replayed, at: f64) -> PlayoutDelay {
        r.pairs
            .iter()
            .find(|(t, _)| *t >= at)
            .map_or(PlayoutDelay::CLEAN, |(_, d)| *d)
    }

    /// The jittery VPN session's first minute, for its Chromium viewer: the loss is held, the
    /// stalls the loss caused are not counted (nor the freeze of over a second, an outage's sign),
    /// and three on the clean pair after it — a PLI episode at 52 s and the freezes of 223 and
    /// 241 ms at 54 and 55 s, none near loss — engage a cushion sized from the viewer's own
    /// jitter-buffer target. The 815 ms freeze at 53 s between them is not counted
    /// (`CUSHION_UNCOVERABLE_TO_RELEASE`): no cushion within the ceiling would have spared the viewer
    /// it, 695 ms left at 120.
    #[test]
    fn a_smooth_path_that_keeps_freezing_gets_a_cushion() {
        let r = replay(
            JITTERY_VPN_FIRST_MINUTE,
            Some(ViewerEngine::Chromium),
            false,
            true,
        );
        // Nothing before the third stall: the freeze at 2 s had left the window long before, the
        // ones at 29-31 s were the loss's (and one an outage-long second).
        assert_eq!(r.engaged.len(), 1, "{:?}", r.engaged);
        let (at, size) = r.engaged[0];
        assert!((54.9..55.1).contains(&at), "engaged at {at}");
        // The viewer's peak target on the smooth clean pair over the window, 72.6 ms at 55 s, plus
        // the headroom: 112.6, to the tick above.
        assert_eq!(size, CUSHION_MAX_MS);
        assert!(r.released.is_empty());
        // The freeze of a second at 31 s, under the hold: an outage's sign, with no cushion on.
        assert_eq!(r.outages, 1);
        // The hold, exactly as it always was: pinned at the 250 cap (294 + 30), then Chromium's
        // fast way down to the clean pair, which it keeps until the cushion.
        assert_eq!(pair_at(&r, 35.0), PlayoutDelay::holding(250));
        assert!(r
            .pairs
            .iter()
            .filter(|(t, _)| (44.0..54.99).contains(t))
            .all(|(_, d)| *d == PlayoutDelay::CLEAN));
        assert!(r
            .pairs
            .iter()
            .filter(|(t, _)| *t < 28.6)
            .all(|(_, d)| *d == PlayoutDelay::CLEAN));
        // In at the engage rate, pinned all the way (its first tenth of a second rounds to the
        // clean pair, as a hold's does): 120 a little over a second in, and there it stays.
        assert!(r
            .pairs
            .iter()
            .filter(|(t, _)| *t > 55.2)
            .all(|(_, d)| d.min_ms == d.max_ms && d.min_ms > 0));
        assert_eq!(pair_at(&r, 55.6).min_ms, 60);
        assert_eq!(pair_at(&r, 57.5), PlayoutDelay::holding(CUSHION_MAX_MS));
        assert_eq!(
            r.size_s.keys().copied().collect::<Vec<_>>(),
            vec![CUSHION_MAX_MS]
        );
    }

    /// The same minute for a WebKit viewer, or one whose engine is not known: no cushion, ever, and
    /// the hold's careful release parks at one tick as it always did — the min never returns to
    /// zero after a hold (module docs, "Letting go without freezing WebKit").
    #[test]
    fn webkit_and_unknown_engines_never_get_a_cushion_and_still_park() {
        for engine in [
            Some(ViewerEngine::WebKit),
            Some(ViewerEngine::Gecko),
            Some(ViewerEngine::Unknown),
            None,
        ] {
            let r = replay(JITTERY_VPN_FIRST_MINUTE, engine, false, true);
            assert!(r.engaged.is_empty(), "{engine:?}");
            // The freeze of a second at 31 s is an outage's sign for any engine; with no cushion it
            // changes nothing in the pair, which the parking below shows.
            assert_eq!(r.outages, 1, "{engine:?}");
            assert!(
                r.size_s.is_empty(),
                "never a frame in the cushion: {engine:?}"
            );
            assert!(r.pairs.iter().all(|(_, d)| d.min_ms <= 250), "{engine:?}");
            // After the hold, never the clean pair again; parked at one tick by the end.
            let after: Vec<_> = r.pairs.iter().filter(|(t, _)| *t > 30.0).collect();
            assert!(
                after.iter().all(|(_, d)| d.min_ms >= RELEASE_MIN_FLOOR_MS),
                "{engine:?}"
            );
            assert_eq!(pair_at(&r, 57.5).min_ms, RELEASE_MIN_FLOOR_MS, "{engine:?}");
            // And before the hold, the clean pair, as for everyone.
            assert!(r
                .pairs
                .iter()
                .filter(|(t, _)| *t < 28.6)
                .all(|(_, d)| *d == PlayoutDelay::CLEAN));
        }
    }

    /// A Chromium policy and a viewer that freezes: [`Self::freeze`] reports `n` more freezes of
    /// `ms` each at `at` seconds, cumulative as the viewer sends them.
    struct Freezing {
        p: PlayoutPolicy,
        t0: Instant,
        count: u64,
        ms: u64,
    }

    impl Freezing {
        /// Media written since [`CUSHION_WARMUP`] before `t0`, so the stalls from `t0` on count: one
        /// frame then, and the next frames wherever each test writes them.
        fn chromium() -> Self {
            let start = Instant::now();
            let mut f = Self::chromium_cold_at(start, start + CUSHION_WARMUP);
            f.p.delay(start);
            f
        }

        /// No frame written yet: the cushion's warm-up runs from the first frame a test writes.
        fn chromium_cold() -> Self {
            let t0 = Instant::now();
            Self::chromium_cold_at(t0, t0)
        }

        fn chromium_cold_at(start: Instant, t0: Instant) -> Self {
            let mut p = chromium(start);
            p.note_freezes(t0, Some(0), Some(0));
            Freezing {
                p,
                t0,
                count: 0,
                ms: 0,
            }
        }

        fn freeze(&mut self, at: f64, n: u64, ms: u64) {
            self.count += n;
            self.ms += n * ms;
            self.p
                .note_freezes(self.t0 + secs(at), Some(self.count), Some(self.ms));
        }

        fn quiet(&mut self, at: f64) {
            self.p
                .note_freezes(self.t0 + secs(at), Some(self.count), Some(self.ms));
        }

        fn report(&mut self, at: f64, loss: f32, nacks: u64) {
            self.p
                .note_report(self.t0 + secs(at), RTT_180, Some(loss), nacks);
        }

        fn frames(&mut self, from: f64, to: f64) -> PlayoutDelay {
            frames(&mut self.p, self.t0, from, to)
        }
    }

    /// Three stalls within the window engage; two do not, nor three spread wider than it.
    #[test]
    fn the_cushion_engages_on_the_third_stall_within_the_window() {
        let mut f = Freezing::chromium();
        f.freeze(1.0, 1, 250);
        f.freeze(20.0, 1, 250);
        assert_eq!(f.p.cushion_ms(), 0);
        // The first has left the window by 32 s.
        f.freeze(32.0, 1, 250);
        assert_eq!(f.p.cushion_ms(), 0);
        assert_eq!(f.frames(0.0, 51.0), PlayoutDelay::CLEAN);
        // Two freezes in one report are one stall (and the one at 20 s has left the window).
        f.freeze(51.0, 2, 250);
        assert_eq!(f.p.cushion_stalls(f.t0 + secs(51.0)), 2);
        assert_eq!(f.p.cushion_ms(), 0);
        // A PLI episode is one more: five repeats inside the episode gap count once.
        for i in 0..5 {
            f.p.note_keyframe_request(f.t0 + secs(52.0 + 0.25 * f64::from(i)));
        }
        assert_eq!(f.p.cushion_stalls(f.t0 + secs(53.0)), 3);
        assert_eq!(f.p.phase(), PlayoutPhase::Cushion);
        // No smooth clean report to size it from: the smallest.
        assert_eq!(f.p.cushion_ms(), CUSHION_MIN_MS);
        assert_eq!(f.p.target_ms(), CUSHION_MIN_MS);
        assert_eq!(f.frames(51.0, 54.0), PlayoutDelay::holding(CUSHION_MIN_MS));
        assert!(!f.p.holding(), "a cushion is not a loss hold");
    }

    /// Stalls next to loss are the loss's: not counted after a lossy report, and taken back when
    /// the lossy report arrives just after them. A freeze of over a second is an outage, and the
    /// stalls until it is over are the outage's.
    #[test]
    fn stalls_next_to_loss_or_longer_than_a_second_are_not_counted() {
        let mut f = Freezing::chromium();
        // Counted, then taken back by the loss a second later.
        f.freeze(10.0, 1, 250);
        assert_eq!(f.p.cushion_stalls(f.t0 + secs(10.0)), 1);
        f.report(11.0, 0.0, 3);
        assert_eq!(f.p.cushion_stalls(f.t0 + secs(11.0)), 0);
        // Within the guard after it: the loss's.
        f.freeze(12.0, 1, 250);
        f.p.note_keyframe_request(f.t0 + secs(13.5));
        assert_eq!(f.p.cushion_stalls(f.t0 + secs(13.5)), 0);
        // An outage, however clean the path, and the stalls right after it its own.
        f.freeze(20.0, 1, 1_600);
        assert!(f.p.outage());
        f.freeze(21.0, 1, 200);
        f.freeze(22.0, 1, 200);
        f.p.note_keyframe_request(f.t0 + secs(23.0));
        assert_eq!(f.p.cushion_stalls(f.t0 + secs(23.0)), 0);
        // Over once media flows, the receiver and the viewer report, and the settle has passed.
        f.frames(20.0, 25.5);
        f.report(25.5, 0.0, 0);
        assert!(f.p.outage(), "the viewer has not reported frames yet");
        f.p.note_viewer(f.t0 + secs(25.5), None, Some(40.0));
        f.quiet(25.5);
        assert!(!f.p.outage());
        // These are the path's.
        f.freeze(26.0, 1, 200);
        f.freeze(27.0, 1, 200);
        assert_eq!(f.p.cushion_ms(), 0);
        f.freeze(28.0, 1, 200);
        assert_eq!(f.p.phase(), PlayoutPhase::Cushion);
    }

    /// The first seconds of media are the connection's ramp: on the bench, slow relays engaged the
    /// cushion on stalls 4.7-9.2 s after the first frame in 5 of 8 runs (hide-30-f-r2: freezes at
    /// 2.8 and 4.7 s and a third at 7.8 s). Not counted until [`CUSHION_WARMUP`] after the first
    /// frame written, nor before any frame at all.
    #[test]
    fn stalls_in_the_first_seconds_of_media_are_not_counted() {
        let mut f = Freezing::chromium_cold();
        f.freeze(0.5, 1, 200);
        assert_eq!(
            f.p.cushion_stalls(f.t0 + secs(0.5)),
            0,
            "no frame written yet"
        );
        f.frames(1.0, 3.8);
        f.freeze(3.8, 1, 173);
        f.frames(3.8, 5.7);
        f.freeze(5.7, 1, 196);
        f.frames(5.7, 8.8);
        f.freeze(8.8, 1, 228);
        assert_eq!(f.p.cushion_stalls(f.t0 + secs(8.8)), 0);
        assert_eq!(f.p.phase(), PlayoutPhase::Clean);
        // Past the warm-up, from the first frame at 1 s: three engage it as ever.
        f.frames(8.8, 16.0);
        f.freeze(16.0, 1, 214);
        f.frames(16.0, 17.0);
        f.freeze(17.0, 1, 233);
        assert_eq!(f.p.cushion_ms(), 0);
        f.frames(17.0, 18.0);
        f.freeze(18.0, 1, 259);
        assert_eq!(f.p.phase(), PlayoutPhase::Cushion);
    }

    /// A freeze a gap in our own writes explains is not the path's jitter: the bench counted 13 such
    /// "source" gaps among the 32 stalls that engaged the cushion (3g-stall-100-f-r3: freezes of
    /// 393 and 486 ms, both where the sender had sent nothing). One our gap does not cover — longer
    /// than it by more than two frames — counts, and so does one with no gap near it. (Those two
    /// would not count anyway: past what a cushion within the ceiling covers.)
    #[test]
    fn a_freeze_our_own_sender_explains_is_not_counted() {
        let mut f = Freezing::chromium();
        f.frames(0.0, 30.0);
        // Nothing written for 250 ms, then frames again; the viewer reports a 240 ms freeze.
        f.frames(30.25, 31.0);
        f.freeze(31.0, 1, 240);
        assert_eq!(f.p.cushion_stalls(f.t0 + secs(31.0)), 0);
        // 250 + 34 is the most that gap explains.
        f.frames(31.0, 31.5);
        f.freeze(31.5, 1, 285);
        assert_eq!(f.p.cushion_stalls(f.t0 + secs(31.5)), 1);
        // Two and a half seconds on, the gap explains nothing any more.
        f.frames(31.5, 33.5);
        f.freeze(33.5, 1, 240);
        assert_eq!(f.p.cushion_stalls(f.t0 + secs(33.5)), 2);
        // A keyframe request is not a freeze to explain.
        f.frames(33.5, 34.0);
        f.frames(34.3, 34.5);
        f.p.note_keyframe_request(f.t0 + secs(34.5));
        assert_eq!(f.p.phase(), PlayoutPhase::Cushion);
    }

    /// The size: the viewer's peak jitter-buffer target over the window, from reports on the smooth
    /// clean pair only, plus the headroom, within the bounds.
    #[test]
    fn the_cushion_is_sized_from_the_viewers_jitter_on_the_clean_pair() {
        // Frames from `start` s (the pair is clean from its first frame), the viewer's targets, an
        // optional lossy report, and three freezes at 40-42 s (past the warm-up from `start`).
        let size_for = |start: f64, targets: &[(f64, f64)], loss_at: Option<f64>| {
            let mut f = Freezing::chromium_cold();
            if let Some(at) = loss_at {
                f.report(at, 0.01, 1);
            }
            let mut t = start;
            for &(at, target) in targets {
                f.frames(t, at);
                t = at;
                f.p.note_viewer(f.t0 + secs(at), None, Some(target));
            }
            f.frames(t, 40.0);
            f.freeze(40.0, 1, 200);
            f.freeze(41.0, 1, 200);
            f.freeze(42.0, 1, 200);
            assert_eq!(f.p.phase(), PlayoutPhase::Cushion);
            f.p.cushion_ms()
        };
        // 63.5 + 40 = 103.5, to the tick above.
        assert_eq!(
            size_for(0.0, &[(20.0, 40.0), (30.0, 63.5), (35.0, 50.0)], None),
            110
        );
        // Older than the window at 42 s: not a measure of the path now.
        assert_eq!(size_for(0.0, &[(5.0, 300.0), (30.0, 25.0)], None), 70);
        // Within the bounds either way.
        assert_eq!(size_for(0.0, &[(30.0, 2.0)], None), CUSHION_MIN_MS);
        assert_eq!(size_for(0.0, &[(30.0, 500.0)], None), CUSHION_MAX_MS);
        // A report from the first seconds of the clean pair (after a hold, or here the session's
        // first frame) carries the pair before it, and one within ten seconds of loss the
        // retransmissions: not samples.
        assert_eq!(size_for(14.0, &[(15.0, 90.0)], None), CUSHION_MIN_MS);
        assert_eq!(size_for(12.0, &[(15.0, 90.0)], None), CUSHION_MAX_MS);
        assert_eq!(size_for(0.0, &[(25.0, 90.0)], Some(20.0)), CUSHION_MIN_MS);
        assert_eq!(size_for(0.0, &[(31.0, 90.0)], Some(20.0)), CUSHION_MAX_MS);
    }

    /// A Chromium cushion engaged at 22 s from a viewer target of `target_ms` (taken at 10 s on the
    /// clean pair), frames written all along; returned at 22 s, its ramp not begun.
    fn cushioned(target_ms: f64) -> Freezing {
        let mut f = Freezing::chromium();
        f.frames(0.0, 10.0);
        f.p.note_viewer(f.t0 + secs(10.0), None, Some(target_ms));
        f.frames(10.0, 20.0);
        f.freeze(20.0, 1, 200);
        f.frames(20.0, 21.0);
        f.freeze(21.0, 1, 200);
        f.frames(21.0, 22.0);
        f.freeze(22.0, 1, 200);
        assert_eq!(f.p.phase(), PlayoutPhase::Cushion);
        f
    }

    /// Only a freeze that a cushion within the ceiling would have covered grows it — judged against
    /// the `min` it was measured under, not the freeze itself against 120 + 150 ms. The bench's
    /// growths: of the seven, only 186 ms under 90 (156 left
    /// at the ceiling) would still grow it; 225 under 80, 253 under 110, 234 under 100, 255 under 80
    /// and 237 under 90 leave 185-243 ms at the ceiling, a freeze still. A PLI has no length to
    /// judge; one the ramp under way will cover by itself does not grow it either.
    #[test]
    fn the_cushion_grows_only_on_freezes_a_cushion_within_the_ceiling_would_cover() {
        let settled = |target_ms: f64, size_ms: u64| {
            let mut f = cushioned(target_ms);
            assert_eq!(f.frames(22.0, 25.0), PlayoutDelay::holding(size_ms));
            f
        };
        // Two freezes from vpn-wifi-1011: 186 under 90 grows it, 253 under 110 not.
        let mut f = settled(50.0, 90);
        f.freeze(25.0, 1, 186);
        assert_eq!(f.p.cushion_ms(), 110);
        assert_eq!(f.frames(25.0, 26.0), PlayoutDelay::holding(110));
        f.freeze(26.0, 1, 253);
        assert_eq!(f.p.cushion_ms(), 110);
        // 120 - 110 = 10 left to take off: under 177 ms grows it to the ceiling.
        f.freeze(27.0, 1, 176);
        assert_eq!(f.p.cushion_ms(), CUSHION_MAX_MS);
        f.frames(26.0, 28.0);
        f.freeze(28.0, 1, 170);
        assert_eq!(
            f.p.cushion_ms(),
            CUSHION_MAX_MS,
            "at the ceiling, nothing grows it"
        );
        // The rest of the bench's growths: none now.
        for (target, size, freeze) in [
            (40.0, 80, 225),
            (60.0, 100, 234),
            (40.0, 80, 255),
            (50.0, 90, 237),
        ] {
            let mut f = settled(target, size);
            f.freeze(25.0, 1, freeze);
            f.p.note_keyframe_request(f.t0 + secs(26.0));
            assert_eq!(f.p.cushion_ms(), size, "{freeze} ms under {size}");
        }
        // Under 90 the edge is 197 ms: 196 grows it, 197 does not.
        let mut f = settled(50.0, 90);
        f.freeze(25.0, 1, 196);
        assert_eq!(f.p.cushion_ms(), 110);
        let mut f = settled(50.0, 90);
        f.freeze(25.0, 1, CHROMIUM_FREEZE_GAP_MS + (CUSHION_MAX_MS - 90));
        assert_eq!(f.p.cushion_ms(), 90);
        // Ramping to 110 and at 30 when a 230 ms freeze is reported: 110 leaves 150 of it, under
        // the gap, so the ramp covers it without growing; 260 at 30 leaves 180 at 110 and 170 at
        // the ceiling, a freeze either way.
        let mut f = cushioned(70.0);
        assert_eq!(f.frames(22.0, 22.3).min_ms, 30);
        f.freeze(22.3, 1, 230);
        assert_eq!(f.p.cushion_ms(), 110);
        f.freeze(22.35, 1, 260);
        assert_eq!(f.p.cushion_ms(), 110);
        // At 30 a 250 ms freeze leaves 170 at 110, a freeze still, and 160 at the ceiling: grown.
        f.freeze(22.4, 1, 250);
        assert_eq!(f.p.cushion_ms(), CUSHION_MAX_MS);
    }

    /// A minute without a stall releases it, Chromium's fast way, to the clean pair; the first
    /// stall within the rearm window puts it back at once at the size it had, and only past that
    /// window does it take three again.
    #[test]
    fn the_cushion_is_released_after_a_calm_minute() {
        let mut f = Freezing::chromium();
        for at in [1.0, 2.0, 3.0] {
            f.freeze(at, 1, 200);
        }
        assert_eq!(f.frames(0.0, 5.0), PlayoutDelay::holding(CUSHION_MIN_MS));
        // A stall at 30 s starts the calm again: still on at 89 s.
        f.p.note_keyframe_request(f.t0 + secs(30.0));
        f.quiet(89.0);
        assert_eq!(f.p.phase(), PlayoutPhase::Cushion);
        assert_eq!(f.frames(5.0, 90.0), PlayoutDelay::holding(CUSHION_MIN_MS));
        // A receiver report a minute after the last stall ends it.
        f.report(90.0, 0.0, 0);
        assert_eq!(f.p.phase(), PlayoutPhase::Clean);
        assert_eq!(f.p.cushion_ms(), 0);
        assert_eq!(f.p.target_ms(), 0);
        // 100 ms a second, min and max together: 50 ms is half a second.
        assert_eq!(f.frames(90.0, 90.2), PlayoutDelay::holding(30));
        assert_eq!(f.frames(90.2, 91.0), PlayoutDelay::CLEAN);
        // A relapse ten seconds later (the bench's came 16-60 s after): back on the first stall.
        f.freeze(100.0, 1, 200);
        assert_eq!(f.p.phase(), PlayoutPhase::Cushion);
        assert_eq!(f.p.cushion_ms(), CUSHION_MIN_MS);
        assert_eq!(
            f.frames(100.0, 102.0),
            PlayoutDelay::holding(CUSHION_MIN_MS)
        );
        // Released again a calm minute on; a stall more than the rearm window after that is a new
        // episode, and three engage it, as the first time.
        f.report(161.0, 0.0, 0);
        assert_eq!(f.p.phase(), PlayoutPhase::Clean);
        let later = 161.0 + CUSHION_REARM.as_secs_f64() + 1.0;
        for at in [later, later + 1.0] {
            f.freeze(at, 1, 200);
        }
        assert_eq!(f.p.cushion_ms(), 0);
        f.freeze(later + 2.0, 1, 200);
        assert_eq!(f.p.phase(), PlayoutPhase::Cushion);
    }

    /// Only a freeze a cushion within the ceiling could have covered counts towards engaging one, or
    /// a relapse: slow relays on the bench engaged it on freezes such as hide-30-f2-r1's 936, 428
    /// and 348 ms, which 120 ms would have left at 816, 308 and 228 — freezes still. Judged against
    /// the `min` then written. A keyframe request has no length to judge and always counts.
    #[test]
    fn a_freeze_past_what_the_ceiling_covers_does_not_count_towards_a_cushion() {
        let mut f = Freezing::chromium();
        let edge = CHROMIUM_FREEZE_GAP_MS + CUSHION_MAX_MS;
        for (at, ms) in [(1.0, 936), (2.0, 428), (3.0, 348), (4.0, edge)] {
            f.freeze(at, 1, ms);
        }
        assert_eq!(f.p.cushion_stalls(f.t0 + secs(4.0)), 0);
        assert_eq!(f.p.phase(), PlayoutPhase::Clean);
        // A millisecond under the edge leaves 166 at the ceiling: one. A PLI episode: two.
        f.freeze(5.0, 1, edge - 1);
        f.p.note_keyframe_request(f.t0 + secs(6.0));
        assert_eq!(f.p.cushion_stalls(f.t0 + secs(6.0)), 2);
        f.freeze(7.0, 1, 200);
        assert_eq!(f.p.phase(), PlayoutPhase::Cushion);
        // Released by its calm, it does not come back on a freeze it could not have covered; it
        // does on the first one it could.
        f.frames(0.0, 68.0);
        f.report(68.0, 0.0, 0);
        assert_eq!(f.p.phase(), PlayoutPhase::Clean);
        assert_eq!(f.frames(68.0, 70.0), PlayoutDelay::CLEAN);
        f.freeze(70.0, 1, 400);
        assert_eq!(f.p.phase(), PlayoutPhase::Clean);
        assert_eq!(f.p.cushion_stalls(f.t0 + secs(70.0)), 0);
        f.freeze(71.0, 1, 250);
        assert_eq!(f.p.phase(), PlayoutPhase::Cushion);
    }

    /// [`CUSHION_UNCOVERABLE_TO_RELEASE`] freezes under the cushion in force that no cushion within
    /// the ceiling could have covered, within the window and with none since that it could have,
    /// release it. The bench's hide-30-f2-r3 had 18 such freezes under it at 120 in 55 s (264, 203,
    /// 215, 235, 258, 203, 329 ms, …): it goes down Chromium's way, with no relapse — three stalls
    /// it could cover engage the next one, counted afresh.
    #[test]
    fn freezes_past_the_ceiling_under_the_cushion_release_it() {
        let q6 = [264, 203, 215, 235, 258, 203, 329];
        assert_eq!(q6.len(), CUSHION_UNCOVERABLE_TO_RELEASE);
        let mut f = cushioned(500.0);
        assert_eq!(f.frames(22.0, 24.0), PlayoutDelay::holding(CUSHION_MAX_MS));
        let mut t = 24.0;
        for &ms in &q6[..q6.len() - 1] {
            t += 1.5;
            f.frames(t - 1.5, t);
            f.freeze(t, 1, ms);
        }
        // A keyframe request says nothing either way.
        f.p.note_keyframe_request(f.t0 + secs(t + 0.5));
        assert_eq!(f.p.phase(), PlayoutPhase::Cushion);
        assert_eq!(f.p.cushion_ms(), CUSHION_MAX_MS);
        f.frames(t, t + 1.0);
        f.freeze(t + 1.0, 1, q6[q6.len() - 1]);
        assert_eq!(f.p.phase(), PlayoutPhase::Clean);
        assert_eq!((f.p.cushion_ms(), f.p.target_ms()), (0, 0));
        // Chromium's way down: min and max together at 100 ms a second.
        assert_eq!(
            f.frames(t + 1.0, t + 1.5),
            PlayoutDelay::holding(CUSHION_MAX_MS - 50)
        );
        assert_eq!(f.frames(t + 1.5, t + 3.0), PlayoutDelay::CLEAN);
        // No relapse: one freeze it could have covered is the first of a new count.
        f.freeze(t + 3.0, 1, 200);
        assert_eq!(f.p.phase(), PlayoutPhase::Clean);
        assert_eq!(f.p.cushion_stalls(f.t0 + secs(t + 3.0)), 1);
        f.freeze(t + 4.0, 1, 200);
        f.freeze(t + 5.0, 1, 200);
        assert_eq!(f.p.phase(), PlayoutPhase::Cushion);

        // One it could cover starts the count again (and grows it from 90).
        fn freeze_after(f: &mut Freezing, t: &mut f64, gap: f64, ms: u64) {
            f.frames(*t, *t + gap);
            *t += gap;
            f.freeze(*t, 1, ms);
        }
        let mut f = cushioned(50.0);
        assert_eq!(f.frames(22.0, 25.0), PlayoutDelay::holding(90));
        let mut t = 25.0;
        for _ in 1..CUSHION_UNCOVERABLE_TO_RELEASE {
            freeze_after(&mut f, &mut t, 1.0, 250);
        }
        // 190 under 90 leaves 160 at the ceiling: it grows, and the count starts again.
        freeze_after(&mut f, &mut t, 1.0, 190);
        assert_eq!(f.p.cushion_ms(), 110);
        for _ in 1..CUSHION_UNCOVERABLE_TO_RELEASE {
            freeze_after(&mut f, &mut t, 1.0, 250);
        }
        assert_eq!(f.p.phase(), PlayoutPhase::Cushion);

        // Seven seconds apart, no more than five fall within the window at a time.
        let mut f = cushioned(500.0);
        let mut t = 22.0;
        for _ in 0..=CUSHION_UNCOVERABLE_TO_RELEASE {
            freeze_after(&mut f, &mut t, 7.0, 250);
        }
        assert_eq!(f.p.phase(), PlayoutPhase::Cushion);

        // Under a hold the cushion is not the pair: its freezes are not judged.
        let mut f = cushioned(500.0);
        f.frames(22.0, 25.0);
        f.report(25.0, 0.01, 2);
        f.report(26.0, 0.01, 2);
        assert_eq!(f.p.phase(), PlayoutPhase::Holding);
        let mut t = 29.0;
        f.frames(25.0, t);
        for _ in 0..=CUSHION_UNCOVERABLE_TO_RELEASE {
            freeze_after(&mut f, &mut t, 0.8, 300);
        }
        assert!(t < 36.0, "{t}");
        assert_eq!(f.p.phase(), PlayoutPhase::Holding);
        assert_eq!(f.p.cushion_size_ms(), CUSHION_MAX_MS);
        f.report(36.0, 0.0, 0);
        assert_eq!(f.p.phase(), PlayoutPhase::Cushion);
    }

    /// A relapse comes back at the larger of the size it was released at and a fresh sizing from
    /// the smooth clean pair since.
    #[test]
    fn a_relapse_takes_the_larger_of_its_old_size_and_a_fresh_one() {
        // Released at 90 (engaged at 22 s, last stall there, released at 82 s).
        let mut f = cushioned(50.0);
        f.frames(22.0, 82.0);
        f.report(82.0, 0.0, 0);
        assert_eq!(f.p.phase(), PlayoutPhase::Clean);
        // The viewer's buffer, measured on the clean pair since, says 110.
        f.frames(82.0, 90.0);
        f.p.note_viewer(f.t0 + secs(90.0), None, Some(70.0));
        f.frames(90.0, 100.0);
        f.freeze(100.0, 1, 200);
        assert_eq!(f.p.cushion_ms(), 110);
        // And a smaller fresh one leaves it at the size it had.
        let mut f = cushioned(50.0);
        f.frames(22.0, 82.0);
        f.report(82.0, 0.0, 0);
        f.frames(82.0, 90.0);
        f.p.note_viewer(f.t0 + secs(90.0), None, Some(20.0));
        f.frames(90.0, 100.0);
        f.freeze(100.0, 1, 200);
        assert_eq!(f.p.cushion_ms(), 90);
    }

    /// Recurring loss under the cushion holds as it always did, at the larger of the two; when the
    /// hold ends, it comes down to the cushion if the cushion is still on and to the clean pair if
    /// its calm ran out meanwhile.
    #[test]
    fn the_loss_hold_wins_over_the_cushion_and_hands_back_to_it() {
        let rtt = Some(Duration::from_millis(220));
        let mut f = Freezing::chromium();
        for at in [1.0, 2.0, 3.0] {
            f.freeze(at, 1, 200);
        }
        assert_eq!(f.frames(0.0, 5.0), PlayoutDelay::holding(CUSHION_MIN_MS));
        f.p.note_report(f.t0 + secs(5.0), rtt, Some(0.01), 2);
        f.p.note_report(f.t0 + secs(6.0), rtt, Some(0.01), 2);
        assert_eq!(f.p.phase(), PlayoutPhase::Holding);
        assert_eq!(f.p.target_ms(), 250);
        assert_eq!(f.frames(5.0, 10.0), PlayoutDelay::holding(250));
        // The calm has not run out when the hold ends (a stall at 12 s, past the guard): down to
        // the cushion, not to the clean pair.
        f.freeze(12.0, 1, 200);
        for s in 7..=15 {
            f.p.note_report(f.t0 + secs(f64::from(s)), rtt, Some(0.0), 0);
        }
        assert_eq!(f.p.phase(), PlayoutPhase::Holding);
        assert_eq!(f.frames(10.0, 16.0), PlayoutDelay::holding(250));
        f.p.note_report(f.t0 + secs(16.0), rtt, Some(0.0), 0);
        assert_eq!(f.p.phase(), PlayoutPhase::Cushion);
        assert_eq!(f.p.target_ms(), CUSHION_MIN_MS);
        assert_eq!(f.frames(16.0, 17.0), PlayoutDelay::holding(150));
        assert_eq!(f.frames(17.0, 20.0), PlayoutDelay::holding(CUSHION_MIN_MS));
        // Loss again, every four seconds for longer than the calm: the cushion (last stall at
        // 12 s) is released under the hold, whose own pair stands...
        for s in (30..=78).step_by(4) {
            f.p.note_report(f.t0 + secs(f64::from(s)), rtt, Some(0.01), 1);
            assert_eq!(f.p.cushion_ms() > 0, s < 72, "{s}");
        }
        assert_eq!(f.p.phase(), PlayoutPhase::Holding);
        assert_eq!(f.p.target_ms(), 250);
        // ...and it ends at the clean pair.
        for s in 79..=88 {
            f.p.note_report(f.t0 + secs(f64::from(s)), rtt, Some(0.0), 0);
        }
        assert_eq!(f.p.phase(), PlayoutPhase::Clean);
        assert_eq!(f.p.target_ms(), 0);
    }

    /// On a short path the loss hold is smaller than the cushion: while both apply the larger,
    /// the cushion, is the floor.
    #[test]
    fn under_a_short_hold_the_cushion_is_the_floor() {
        let lan = Some(Duration::from_millis(8));
        let mut f = Freezing::chromium();
        for at in [1.0, 2.0, 3.0] {
            f.freeze(at, 1, 200);
        }
        f.frames(0.0, 5.0);
        f.p.note_report(f.t0 + secs(5.0), lan, Some(0.01), 2);
        f.p.note_report(f.t0 + secs(6.0), lan, Some(0.01), 2);
        assert_eq!(f.p.phase(), PlayoutPhase::Holding);
        assert_eq!(lossy_hold_ms(Some(8)), 30);
        assert_eq!(f.p.target_ms(), CUSHION_MIN_MS);
        assert_eq!(f.frames(5.0, 8.0), PlayoutDelay::holding(CUSHION_MIN_MS));
    }

    /// The bench's 2.3 s stall (vpn-wifi-1011) under a cushion of 90 ms:
    /// the second interval without a receiver report while frames go out drops it at once to the
    /// clean pair. The viewer's report of its 2.3 s freeze is one more sign; its PLI and the 271 ms
    /// freeze after it are the outage's, not counted; the first report back (842 ms) is under the
    /// backlog line. Media flowing, both reports back and five seconds past the last sign, the
    /// cushion is re-armed at its size and ramps in as it first did.
    #[test]
    fn an_outage_drops_the_cushion_at_once_and_re_arms_it_after() {
        let rtt = Some(Duration::from_millis(299));
        let mut f = cushioned(50.0);
        assert_eq!(f.frames(22.0, 30.0), PlayoutDelay::holding(90));
        f.p.note_report(f.t0 + secs(30.0), rtt, Some(0.0), 0);
        f.frames(30.0, 31.0);
        f.p.note_report(f.t0 + secs(31.0), None, None, 0);
        assert!(
            !f.p.outage(),
            "one empty interval is Chrome's report timing"
        );
        assert_eq!(f.frames(31.0, 32.0), PlayoutDelay::holding(90));
        f.p.note_report(f.t0 + secs(32.0), None, None, 0);
        assert!(f.p.outage());
        assert_eq!(f.p.phase(), PlayoutPhase::Clean);
        assert_eq!((f.p.cushion_ms(), f.p.cushion_size_ms()), (0, 90));
        // At once, not down a ramp: the very next frame.
        assert_eq!(f.p.delay(f.t0 + secs(32.0)), PlayoutDelay::CLEAN);
        f.frames(32.0, 33.3);
        f.p.note_viewer(f.t0 + secs(33.3), None, Some(40.0));
        f.freeze(33.3, 1, 2_297);
        f.frames(33.3, 34.0);
        f.p.note_keyframe_request(f.t0 + secs(34.0));
        f.frames(34.0, 34.9);
        f.p.note_report(
            f.t0 + secs(34.9),
            Some(Duration::from_millis(842)),
            Some(0.0),
            0,
        );
        f.frames(34.9, 35.7);
        f.freeze(35.7, 1, 271);
        // Only the three that engaged it, at 20-22 s.
        assert_eq!(f.p.cushion_stalls(f.t0 + secs(35.7)), 3);
        assert_eq!(f.frames(35.7, 37.0), PlayoutDelay::CLEAN);
        f.p.note_viewer(f.t0 + secs(37.0), None, Some(40.0));
        f.quiet(37.0);
        assert!(f.p.outage(), "3.7 s since the last sign");
        assert_eq!(f.frames(37.0, 38.4), PlayoutDelay::CLEAN);
        f.p.note_report(f.t0 + secs(38.4), rtt, Some(0.0), 0);
        assert!(!f.p.outage());
        assert_eq!(f.p.phase(), PlayoutPhase::Cushion);
        assert_eq!((f.p.target_ms(), f.p.cushion_ms()), (90, 90));
        assert_eq!(f.frames(38.4, 38.9), PlayoutDelay::holding(50));
        assert_eq!(f.frames(38.9, 40.0), PlayoutDelay::holding(90));
    }

    /// A report whose round trip says the path holds a backlog — drain mode's own line, 2 s — is an
    /// outage too; one just under it is not. Empty intervals with nothing sent in them are a still
    /// screen's, not silence.
    #[test]
    fn a_backlog_is_an_outage_and_a_still_screens_silence_is_not() {
        let mut f = cushioned(50.0);
        f.frames(22.0, 30.0);
        f.p.note_report(
            f.t0 + secs(30.0),
            Some(Duration::from_millis(1_999)),
            Some(0.0),
            0,
        );
        assert!(!f.p.outage());
        f.frames(30.0, 31.0);
        f.p.note_report(
            f.t0 + secs(31.0),
            Some(Duration::from_millis(OUTAGE_RTT_MS)),
            Some(0.0),
            0,
        );
        assert!(f.p.outage());
        assert_eq!(f.frames(31.0, 31.1), PlayoutDelay::CLEAN);

        let mut f = cushioned(50.0);
        f.frames(22.0, 30.0);
        f.p.note_report(f.t0 + secs(30.0), None, None, 0);
        f.p.note_report(f.t0 + secs(31.0), None, None, 0);
        f.p.note_report(f.t0 + secs(32.0), None, None, 0);
        assert!(!f.p.outage());
        assert_eq!(f.p.phase(), PlayoutPhase::Cushion);
        assert_eq!(f.frames(30.0, 33.0), PlayoutDelay::holding(90));
    }

    /// Under a hold an outage leaves the hold alone and takes the cushion out of its target; a hold
    /// that ends meanwhile ends at the clean pair, and the outage's end puts the cushion back.
    #[test]
    fn an_outage_under_a_hold_leaves_the_hold_and_takes_the_cushion_out() {
        // A LAN: the hold, 8 + 30 to the tick, is under the cushion, which is its floor.
        let lan = Some(Duration::from_millis(8));
        let mut f = cushioned(50.0);
        f.frames(22.0, 25.0);
        f.p.note_report(f.t0 + secs(25.0), lan, Some(0.01), 2);
        f.p.note_report(f.t0 + secs(26.0), lan, Some(0.01), 2);
        assert_eq!(f.p.phase(), PlayoutPhase::Holding);
        assert_eq!(f.p.target_ms(), 90);
        f.frames(25.0, 27.0);
        f.freeze(27.0, 1, 1_400);
        assert!(f.p.outage());
        assert_eq!(f.p.phase(), PlayoutPhase::Holding);
        f.frames(27.0, 28.0);
        f.p.note_report(f.t0 + secs(28.0), lan, Some(0.01), 1);
        assert_eq!(
            f.p.target_ms(),
            30,
            "the hold's own round trip, without the cushion"
        );
        // No loss from here; the viewer silent about its frames, so the outage goes on.
        for s in 29..=38 {
            f.frames(f64::from(s) - 1.0, f64::from(s));
            f.p.note_report(f.t0 + secs(f64::from(s)), lan, Some(0.0), 0);
        }
        assert_eq!(f.p.phase(), PlayoutPhase::Clean);
        assert!(f.p.outage());
        assert_eq!(f.p.cushion_size_ms(), 90);
        f.frames(38.0, 39.0);
        f.p.note_viewer(f.t0 + secs(39.0), None, Some(40.0));
        f.quiet(39.0);
        assert!(!f.p.outage());
        assert_eq!(f.p.phase(), PlayoutPhase::Cushion);
        assert_eq!(f.p.target_ms(), 90);
    }

    /// A viewer that is not Chromium never has a cushion, and an outage changes nothing in its
    /// pair: parked at one tick after its hold, it stays parked through the silence and the freeze
    /// and after them — the min never returns to zero (module docs, WebKit).
    #[test]
    fn an_outage_never_touches_a_careful_release() {
        let t0 = Instant::now();
        let mut p = held_at_250(t0);
        p.note_viewer(t0, Some(ViewerEngine::WebKit), None);
        let mut viewer = |_t: f64, pair: PlayoutDelay| Some(webkit_target(pair, 30.0));
        run(&mut p, t0, 5.0, 11.5, &mut viewer);
        let parked = run(&mut p, t0, 11.5, 40.0, &mut viewer);
        let park = PlayoutDelay {
            min_ms: RELEASE_MIN_FLOOR_MS,
            max_ms: 80,
        };
        assert_eq!(parked.last().map(|(_, d)| *d), Some(park));
        frames(&mut p, t0, 40.0, 41.0);
        p.note_report(t0 + secs(41.0), None, None, 0);
        frames(&mut p, t0, 41.0, 42.0);
        p.note_report(t0 + secs(42.0), None, None, 0);
        p.note_freezes(t0 + secs(42.5), Some(0), Some(0));
        p.note_freezes(t0 + secs(43.0), Some(1), Some(2_300));
        assert!(p.outage());
        let mut t = 42.0;
        while t < 50.0 {
            t += 1.0 / 60.0;
            assert_eq!(p.delay(t0 + secs(t)), park, "at {t}");
        }
        assert_eq!(p.phase(), PlayoutPhase::Releasing);
        assert_eq!(p.cushion_size_ms(), 0);
    }

    /// The whole of a session, from the file `AFKLINK_PLAYOUT_REPLAY` names (see [`replay`]), for a
    /// Chromium viewer: what the cushion would have done, printed. With
    /// `AFKLINK_PLAYOUT_REPLAY_MODEL=1`, freezes the pair in force would have covered are not
    /// heard of (see [`replay`]). `cargo test -p afklink-transport --release -- --ignored
    /// --nocapture replay_a_sessions`.
    #[test]
    #[ignore = "needs a session's events in AFKLINK_PLAYOUT_REPLAY"]
    fn replay_a_sessions_stalls_through_the_cushion() {
        let Ok(path) = std::env::var("AFKLINK_PLAYOUT_REPLAY") else {
            println!("AFKLINK_PLAYOUT_REPLAY is not set: nothing to replay");
            return;
        };
        let model = std::env::var("AFKLINK_PLAYOUT_REPLAY_MODEL").is_ok_and(|v| v == "1");
        let events = std::fs::read_to_string(&path).expect("the events file");
        let r = replay(&events, Some(ViewerEngine::Chromium), model, false);
        let pct = |a: f64, b: f64| 100.0 * a / b.max(1e-9);
        let outside = r.seconds - r.holding_s;
        println!(
            "{path} (model {model}): {:.0} s; holding {:.1}%; cushion {:.1}% of the session, {:.1}% \
             outside the holds",
            r.seconds,
            pct(r.holding_s, r.seconds),
            pct(r.cushion_s, r.seconds),
            pct(r.cushion_s, outside)
        );
        println!(
            "mean min written {:.1} ms (the session's own {:.1} ms); added per second outside the \
             holds {:.1} ms",
            r.min_ms_s / r.seconds,
            r.real_min_ms_s / r.seconds,
            (r.min_ms_s - r.real_min_ms_s.min(r.min_ms_s)) / outside.max(1e-9)
        );
        let sizes: Vec<String> = r
            .size_s
            .iter()
            .map(|(ms, s)| format!("{ms}: {:.1}%", pct(*s, r.cushion_s)))
            .collect();
        println!("cushion by size, share of its time: {}", sizes.join(", "));
        println!(
            "engaged {} times at {:?} ms; released {} times ({} for freezes past the ceiling); \
             outages {}",
            r.engaged.len(),
            r.engaged.iter().map(|(_, s)| *s).collect::<Vec<_>>(),
            r.released.len(),
            r.released_uncoverable,
            r.outages
        );
        println!(
            "first engagements at {:?} s",
            r.engaged
                .iter()
                .take(5)
                .map(|(t, _)| *t)
                .collect::<Vec<_>>()
        );
        println!(
            "first releases at {:?} s",
            r.released.iter().take(5).collect::<Vec<_>>()
        );
        let per_min = |n: u64| n as f64 * 60.0 / outside.max(1e-9);
        println!(
            "smooth-path freezes {} ({:.2}/min outside the holds), {} of them while the cushion was \
             on ({:.0}%); covered by the model {} ({:.0}%): {:.2} -> {:.2} a minute",
            r.smooth_freezes,
            per_min(r.smooth_freezes),
            r.smooth_freezes_cushioned,
            pct(r.smooth_freezes_cushioned as f64, r.smooth_freezes as f64),
            r.covered,
            pct(r.covered as f64, r.smooth_freezes as f64),
            per_min(r.smooth_freezes),
            per_min(r.smooth_freezes - r.covered)
        );
        assert!(r
            .size_s
            .keys()
            .all(|ms| (CUSHION_MIN_MS..=CUSHION_MAX_MS).contains(ms)));
    }

    #[test]
    fn viewer_reports_are_bounded_for_the_cushion_too() {
        let start = Instant::now();
        let t0 = start + CUSHION_WARMUP;
        let mut p = chromium(start);
        p.delay(start);
        p.note_freezes(t0, Some(5), Some(900));
        // Backwards: a new base, nothing counted.
        p.note_freezes(t0 + secs(1.0), Some(2), Some(400));
        p.note_freezes(t0 + secs(2.0), Some(2), Some(400));
        assert_eq!(p.cushion_stalls(t0 + secs(2.0)), 0);
        // Half a report is no report.
        p.note_freezes(t0 + secs(3.0), Some(9), None);
        assert_eq!(p.cushion_stalls(t0 + secs(3.0)), 0);
        p.note_freezes(t0 + secs(4.0), Some(3), Some(650));
        assert_eq!(p.cushion_stalls(t0 + secs(4.0)), 1);
    }

    /// The viewer's numbers are a peer's: nonsense is ignored.
    #[test]
    fn viewer_reports_are_bounded() {
        let t0 = Instant::now();
        let mut p = PlayoutPolicy::default();
        p.note_viewer(t0, Some(ViewerEngine::WebKit), Some(f64::NAN));
        p.note_viewer(t0, Some(ViewerEngine::Chromium), Some(-5.0));
        p.note_viewer(t0, None, Some(1e9));
        assert_eq!(p.viewer_target(t0), None);
        assert_eq!(
            p.engine(),
            Some(ViewerEngine::WebKit),
            "the first engine stands"
        );
        p.note_viewer(t0, None, Some(42.5));
        assert_eq!(p.viewer_target(t0 + secs(1.0)).map(|(t, _)| t), Some(42.5));
    }

    #[test]
    fn the_min_rises_at_the_engage_rate_and_falls_at_the_rate_asked() {
        let r = RELEASE_RAMP_MS_PER_S;
        assert!((ramp(0.0, 250.0, secs(1.0), r) - 100.0).abs() < 1e-9);
        assert!((ramp(250.0, 0.0, secs(1.0), r) - 225.0).abs() < 1e-9);
        assert!((ramp(250.0, 0.0, secs(1.0), MIN_RAMP_MS_PER_S) - 150.0).abs() < 1e-9);
        assert!((ramp(20.0, 10.0, secs(1.0), r) - 10.0).abs() < 1e-9);
        assert!((ramp(95.0, 100.0, secs(1.0), r) - 100.0).abs() < 1e-9);
        assert_eq!(max_ticks(0.0), 0);
        assert_eq!(max_ticks(110.0), 110);
        assert_eq!(max_ticks(110.2), 120);
        assert_eq!(min_ticks(119.6), 120);
        assert_eq!(min_ticks(114.9), 110);
    }

    #[test]
    fn the_hold_follows_a_growing_round_trip_at_once_and_a_shrinking_one_slowly() {
        let t0 = Instant::now();
        let mut p = PlayoutPolicy::default();
        p.note_report(t0, RTT_180, Some(0.01), 1);
        p.note_report(t0 + secs(1.0), RTT_180, Some(0.01), 1);
        assert_eq!(p.target_ms(), 210);
        p.note_report(
            t0 + secs(2.0),
            Some(Duration::from_millis(200)),
            Some(0.01),
            1,
        );
        assert_eq!(p.target_ms(), 230);
        p.note_report(t0 + secs(3.0), RTT_180, Some(0.01), 1);
        // 200 decayed by 20 ms over the second: 180 + 30.
        assert_eq!(p.rtt_envelope_ms(), Some(180));
        assert_eq!(p.target_ms(), 210);
    }

    /// A dying WiFi link's 1758 ms round trip sat in the envelope and was still
    /// 1598 eight seconds into the next path. Had that path been a 130 ms one, a hold sized from the
    /// envelope would have sat at the 250 ms cap for over a minute instead of 160. A path change
    /// forgets it.
    #[test]
    fn a_path_change_forgets_the_old_paths_round_trip() {
        let t0 = Instant::now();
        let mut p = PlayoutPolicy::default();
        p.note_report(t0, Some(Duration::from_millis(1_758)), Some(0.01), 1);
        p.note_report(
            t0 + secs(1.0),
            Some(Duration::from_millis(1_758)),
            Some(0.01),
            1,
        );
        assert!(p.holding());
        assert_eq!(p.target_ms(), PLAYOUT_DELAY_MAX_LOSSY_MS);
        p.forget_rtt("test");
        assert_eq!(p.rtt_envelope_ms(), None);
        p.note_report(
            t0 + secs(9.0),
            Some(Duration::from_millis(130)),
            Some(0.01),
            1,
        );
        assert_eq!(
            p.rtt_envelope_ms(),
            Some(130),
            "the new path's own round trip"
        );
        assert_eq!(p.target_ms(), 160, "130 + 30 ms of headroom");
    }

    #[test]
    fn the_round_trip_envelope_takes_peaks_at_once_and_lets_them_go_slowly() {
        let t0 = Instant::now();
        let mut e = RttEnvelope::default();
        e.note(t0, 180);
        assert_eq!(e.get(), Some(180));
        e.note(t0 + secs(1.0), 300);
        assert_eq!(e.get(), Some(300), "a peak is taken at once");
        e.note(t0 + secs(2.0), 170);
        assert_eq!(e.get(), Some(280), "and forgotten at 20 ms a second");
        e.note(t0 + secs(12.0), 170);
        assert_eq!(
            e.get(),
            Some(170),
            "down to what is being measured, never below it"
        );
    }

    #[test]
    fn nack_entries_expand_to_their_sequence_numbers() {
        assert_eq!(nack_seqs(100, 0).collect::<Vec<_>>(), vec![100]);
        assert_eq!(
            nack_seqs(65_534, 0b1000_0000_0000_0101).collect::<Vec<_>>(),
            vec![65_534, 65_535, 1, 14]
        );
    }

    #[test]
    fn an_rtx_packet_is_read_for_its_original_sequence_number() {
        // 12-byte header, then OSN 0x1234.
        let mut p = vec![0x80u8; 12];
        p.extend_from_slice(&[0x12, 0x34, 0xde, 0xad]);
        assert_eq!(rtx_original_seq(&p, 12), Some(0x1234));
        // Blank padding: the P bit.
        p[0] = 0xa0;
        assert_eq!(rtx_original_seq(&p, 12), None);
        // Too short to carry one.
        assert_eq!(rtx_original_seq(&[0x80; 13], 12), None);
    }

    #[test]
    fn the_trace_pairs_each_retransmission_with_its_nack() {
        let t0 = Instant::now();
        let ms = Duration::from_millis;
        let mut t = RtxTrace::default();
        t.on_nack(t0, [10, 11]);
        t.on_rtx(t0 + ms(2), 10, 9_000);
        t.on_rtx(t0 + ms(3), 11, 9_000);
        // Asked again (the first retransmission was lost), answered again.
        t.on_nack(t0 + ms(200), [10]);
        t.on_rtx(t0 + ms(201), 10, 9_000);
        // Padding str0m sent on its own.
        t.on_rtx(t0 + ms(300), 99, 8_000);
        // Never answered.
        t.on_nack(t0 + ms(400), [12]);
        t.on_frame(9_000, false, 1_000);
        t.on_frame(10_500, true, 990);

        let w = t.take_window(t0 + ms(500));
        assert_eq!(w.nacked, 3);
        assert_eq!(w.renacked, 1);
        assert_eq!(w.rtx, 3);
        assert_eq!(w.rtx_after_us, vec![2_000, 3_000, 1_000]);
        assert_eq!(w.spurious, 1);
        assert_eq!(w.unanswered, 0, "not yet past its time to live");
        assert_eq!(w.rtx_rtp, vec![9_000]);
        assert_eq!(w.keyframes_rtp, vec![10_500]);
        assert_eq!(w.frames, 2);
        assert_eq!(w.rtp_anchor_ms, Some(990));
        assert_eq!(w.rtx_after_summary(), "2.0/3.0");

        let w = t.take_window(t0 + ms(3_000));
        assert_eq!(w.unanswered, 1, "sequence 12 expired unanswered");
        assert!(w.is_quiet());
    }
}
