//! The deadline scheduler's decision, with no capture API attached to it.
//!
//! Extracted from `wgc::Handler::on_frame_arrived` so it can be tested on a machine that has no
//! screen — the failure it exists to prevent is a beat between two clocks, and a beat is a thing
//! you reproduce with arithmetic rather than with a monitor. See [`admit`] for the rule and
//! [`early_tolerance`] for the one number in it.

use std::time::{Duration, Instant};

/// The most a frame may arrive before its slot and still be taken, in absolute terms.
///
/// See [`early_tolerance`], which also bounds it relatively.
pub const MAX_EARLY: Duration = Duration::from_millis(4);

/// What the scheduler decided about one arrival.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admission {
    /// Take this frame and fill the slot.
    Admit,
    /// It arrived too far before its slot; the slot is still open.
    Early,
}

/// How early a frame may be and still count as being on time.
///
/// `min(interval / 4, 4 ms)`, and both halves are load-bearing.
///
/// The **absolute** bound is what stops a low rung from admitting a frame a whole source period
/// early, which would quietly raise its rate. On a 60 Hz source the nearest unwanted frame sits
/// 16.67 ms before a 30 fps deadline, 16.67 ms before a 15 fps one, and — the tightest case on the
/// ladder — 8.33 ms before an 8 fps one, because 125 ms is seven and a half source periods rather
/// than a whole number of them. Four milliseconds clears that worst case by a factor of two. At
/// eight and a half it would take every seventh frame instead of alternating seven and eight, and
/// the 8 fps rung would deliver 8.6.
///
/// The **relative** bound is the same guarantee expressed as a fraction, for rungs that do not
/// exist yet: a quarter of an interval can never be half of one, so a tolerance can never reach
/// the midpoint between two deadlines however fast the rung is. On today's ladder it never binds —
/// a quarter drops below 4 ms only above 62.5 fps — so the absolute bound is the operative one
/// everywhere from 1080p60 down. A 120 fps rung would get 2.08 ms from it.
#[must_use]
pub fn early_tolerance(interval: Duration) -> Duration {
    (interval / 4).min(MAX_EARLY)
}

/// Decide one arrival against the deadline, and return the deadline to carry forward.
///
/// `next_due` is `None` before the first frame. The returned instant is always the new deadline,
/// including on [`Admission::Early`], where it is the old one unchanged.
///
/// Three arms, in the order they matter:
///
///   *on time or a little late*  fill the slot and advance the deadline by exactly one interval
///                               **from the old deadline**. That is what keeps the average honest
///                               when arrivals are uneven.
///   *slightly early*            same thing. A frame inside [`early_tolerance`] is this slot's
///                               frame that happened to arrive first; advancing from the old
///                               deadline rather than from `now` is what stops the tolerance from
///                               becoming a rate increase — the schedule keeps its phase, and the
///                               next frame is due at the same wall-clock instant it always was.
///   *a full interval late*      resync from `now`. This is the still screen: a minute of no
///                               frames must not leave a minute of deadlines in the past for the
///                               next burst to walk through.
#[must_use]
pub fn admit(now: Instant, next_due: Option<Instant>, interval: Duration) -> (Admission, Instant) {
    let Some(due) = next_due else {
        return (Admission::Admit, now + interval);
    };

    if now >= due {
        if now.duration_since(due) < interval {
            (Admission::Admit, due + interval)
        } else {
            (Admission::Admit, now + interval)
        }
    } else if due.duration_since(now) <= early_tolerance(interval) {
        (Admission::Admit, due + interval)
    } else {
        (Admission::Early, due)
    }
}

#[cfg(test)]
mod tests {
    use super::{admit, early_tolerance, Admission, MAX_EARLY};
    use std::time::{Duration, Instant};

    /// A 60 Hz panel's period, to the microsecond. The whole defect lives in the gap between this
    /// and the 16 666 µs that `1_000_000 / 60` truncates to.
    const SOURCE_60HZ_US: u64 = 16_667;

    fn interval_for(fps: u64) -> Duration {
        Duration::from_micros(1_000_000 / fps)
    }

    /// Run a sequence of arrival offsets (µs from a common base) through the scheduler.
    fn run(fps: u64, offsets_us: impl IntoIterator<Item = u64>) -> Vec<bool> {
        let base = Instant::now();
        let interval = interval_for(fps);
        let mut next_due = None;
        let mut out = Vec::new();
        for us in offsets_us {
            let (decision, due) = admit(base + Duration::from_micros(us), next_due, interval);
            next_due = Some(due);
            out.push(decision == Admission::Admit);
        }
        out
    }

    /// Indices of the admitted frames.
    fn admitted(flags: &[bool]) -> Vec<usize> {
        flags
            .iter()
            .enumerate()
            .filter_map(|(i, ok)| ok.then_some(i))
            .collect()
    }

    /// Deterministic delivery jitter in [-1000, 1000] µs. An LCG rather than a random source so a
    /// failure is the same failure on every machine and in every run.
    fn jitter(seed: &mut u64) -> i64 {
        *seed = seed
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        ((*seed >> 33) % 2_001) as i64 - 1_000
    }

    #[test]
    fn the_tolerance_is_bounded_both_ways() {
        // Every rung on today's ladder is bounded by the absolute four milliseconds: a quarter of
        // the interval only falls below it above 62.5 fps.
        assert_eq!(early_tolerance(interval_for(60)), MAX_EARLY);
        assert_eq!(early_tolerance(interval_for(30)), MAX_EARLY);
        assert_eq!(early_tolerance(interval_for(15)), MAX_EARLY);
        assert_eq!(early_tolerance(interval_for(8)), MAX_EARLY);
        // And the relative bound takes over for a rung faster than any that exists.
        assert_eq!(
            early_tolerance(interval_for(120)),
            Duration::from_nanos(2_083_250)
        );
        // Whatever the rate, it can never reach the midpoint between two deadlines.
        for fps in [8_u64, 15, 30, 60, 120, 240, 1_000] {
            assert!(early_tolerance(interval_for(fps)) * 2 < interval_for(fps));
        }
    }

    #[test]
    fn a_frame_early_by_more_than_the_tolerance_is_still_rejected() {
        let base = Instant::now();
        let interval = interval_for(60);
        let due = base + Duration::from_micros(100_000);

        let just_inside = due - MAX_EARLY;
        assert_eq!(
            admit(just_inside, Some(due), interval),
            (Admission::Admit, due + interval),
            "a frame exactly at the tolerance fills the slot, and the deadline keeps its phase"
        );

        let just_outside = due - MAX_EARLY - Duration::from_micros(1);
        assert_eq!(
            admit(just_outside, Some(due), interval),
            (Admission::Early, due),
            "one microsecond further out is held back, and the slot stays open"
        );
    }

    #[test]
    fn sixty_fps_on_a_sixty_hertz_source_keeps_every_frame_through_jitter() {
        // The defect, in one test. The interval is 16 666 µs and the source period 16 667, so
        // without a tolerance any frame delivered even half a millisecond early is discarded and
        // the next does not arrive for a full period — roughly half the frames lost, and a 60 fps
        // rung delivering 30.
        let mut seed = 0x5eed_1234_9abc_def0;
        let offsets = (0..600_u64).map(|k| {
            let t = 2_000 + k * SOURCE_60HZ_US;
            t.wrapping_add_signed(jitter(&mut seed))
        });
        let flags = run(60, offsets.collect::<Vec<_>>());
        let taken = flags.iter().filter(|ok| **ok).count();
        assert!(
            taken * 100 >= flags.len() * 99,
            "±1 ms of delivery jitter must not cost frames: {taken} of {} admitted",
            flags.len()
        );
    }

    #[test]
    fn thirty_fps_on_a_sixty_hertz_source_takes_every_second_frame() {
        // The in-between frame is 16.67 ms early, four times outside the tolerance, so the
        // tolerance buys it nothing — which is the point of bounding it absolutely.
        let flags = run(
            30,
            (0..200_u64).map(|k| k * SOURCE_60HZ_US).collect::<Vec<_>>(),
        );
        for (k, ok) in flags.iter().enumerate() {
            assert_eq!(*ok, k % 2 == 0, "frame {k}");
        }
    }

    #[test]
    fn fifteen_fps_on_a_sixty_hertz_source_takes_one_frame_in_four() {
        // Here the interval is 66.7 ms, so a quarter of it is 16.7 ms — exactly the earliness of
        // the frame that must be rejected. The absolute bound of 4 ms is what rejects it.
        let flags = run(
            15,
            (0..200_u64).map(|k| k * SOURCE_60HZ_US).collect::<Vec<_>>(),
        );
        for (k, ok) in flags.iter().enumerate() {
            assert_eq!(*ok, k % 4 == 0, "frame {k}");
        }
    }

    #[test]
    fn eight_fps_alternates_seven_and_eight_frame_gaps() {
        // 125 ms is 7.4999 source periods, so no whole number of frames fits a slot and the
        // scheduler has to alternate. What must not happen is a run of rejections longer than
        // that — which is what a tolerance above 8.33 ms would turn into its opposite, taking
        // every seventh frame and delivering 8.6 fps.
        let flags = run(
            8,
            (0..300_u64).map(|k| k * SOURCE_60HZ_US).collect::<Vec<_>>(),
        );
        let idx = admitted(&flags);
        let gaps: Vec<usize> = idx.windows(2).map(|w| w[1] - w[0]).collect();
        assert!(!gaps.is_empty());
        for g in &gaps {
            assert!(*g == 7 || *g == 8, "gap of {g} frames between admissions");
        }
        assert!(gaps.contains(&7) && gaps.contains(&8), "{gaps:?}");
        // 300 source frames at 16.667 ms is 5.0 s, so an 8 fps rung owes about 40 frames.
        let taken = idx.len();
        assert!((39..=41).contains(&taken), "{taken} frames in 5 s at 8 fps");
    }

    #[test]
    fn a_still_screen_resyncs_the_deadline_from_now() {
        let base = Instant::now();
        let interval = interval_for(60);

        let (first, due) = admit(base, None, interval);
        assert_eq!(first, Admission::Admit);
        assert_eq!(due, base + interval);

        // Nothing changes on screen for five seconds: 300 deadlines pass unfilled. The next frame
        // must be taken, and the schedule must restart from it rather than from a pile of expired
        // slots the following burst would walk straight through.
        let woken = base + Duration::from_secs(5);
        let (second, due) = admit(woken, Some(due), interval);
        assert_eq!(second, Admission::Admit);
        assert_eq!(due, woken + interval);
    }

    #[test]
    fn phase_drift_at_sixty_fps_never_drops_a_frame() {
        // A 16 666 µs interval against a 16 667 µs source period drifts by one microsecond a
        // frame, always in the direction of lateness, so frames are admitted by the "slightly
        // late" arm rather than by the tolerance. After 16 666 frames — four and a half minutes —
        // the drift reaches a whole interval and the resync arm takes over. Neither transition
        // costs a frame.
        //
        // 60 s first, as the stated requirement, then far past the resync point.
        for frames in [3_600_u64, 60_000] {
            let flags = run(
                60,
                (0..frames).map(|k| k * SOURCE_60HZ_US).collect::<Vec<_>>(),
            );
            let taken = flags.iter().filter(|ok| **ok).count();
            assert_eq!(
                taken,
                flags.len(),
                "slow drift must not cost a frame over {frames} frames"
            );
        }
    }
}
