use std::collections::VecDeque;
use std::time::{Duration, Instant};

use super::super::macros::{log_bitrate_estimate, log_delay_variation};
use super::super::{AckedPacket, BandwidthUsage};
use super::arrival_group::ArrivalGroupAccumulator;
use super::rate_control::RateControl;
use super::trendline::TrendlineEstimator;
use crate::rtp_::Bitrate;
use crate::util::{MovingAverage, already_happened};

const MAX_RTT_HISTORY_WINDOW: usize = 32;
const UPDATE_INTERVAL: Duration = Duration::from_millis(25);
/// The maximum time we keep updating our estimate without receiving a TWCC report.
const MAX_TWCC_GAP: Duration = Duration::from_millis(500);
/// RFC 6298: Exponentially Weighted Moving Average smoothing factor for RTT (alpha = 1/8)
const RTT_SMOOTHING_FACTOR: f64 = 0.125;

/// Delay controller for googcc inspired BWE.
///
/// This controller attempts to estimate the available send bandwidth by looking at the variations
/// in packet arrival times for groups of packets sent together. Broadly, if the delay variation is
/// increasing this indicates overuse.
pub struct DelayController {
    arrival_group_accumulator: ArrivalGroupAccumulator,
    trendline_estimator: TrendlineEstimator,
    rate_control: RateControl,
    /// Last estimate produced, unlike [`next_estimate`] this will always have a value after the
    /// first estimate.
    last_estimate: Option<Bitrate>,
    /// Smoothed RTT using EWMA (RFC 6298, alpha = 1/8).
    smoothed_rtt: MovingAverage,
    /// History of the max RTT derived for each TWCC report (kept for fallback).
    max_rtt_history: VecDeque<Duration>,

    /// The next time we should poll.
    next_timeout: Instant,
    /// The last time we ingested a TWCC report.
    last_twcc_report: Instant,
}

impl DelayController {
    pub fn new(initial_bitrate: Bitrate) -> Self {
        Self {
            arrival_group_accumulator: ArrivalGroupAccumulator::default(),
            trendline_estimator: TrendlineEstimator::new(20),
            rate_control: RateControl::new(initial_bitrate, Bitrate::kbps(40), Bitrate::gbps(10)),
            last_estimate: Some(initial_bitrate),
            smoothed_rtt: MovingAverage::new(RTT_SMOOTHING_FACTOR),
            max_rtt_history: VecDeque::default(),
            next_timeout: already_happened(),
            last_twcc_report: already_happened(),
        }
    }

    /// Record a packet from a TWCC report.
    pub fn update(
        &mut self,
        acked: &[AckedPacket],
        acked_bitrate: Option<Bitrate>,
        probe_bitrate: Option<Bitrate>,
        now: Instant,
    ) -> Option<Bitrate> {
        let mut max_rtt = None;

        for acked_packet in acked {
            max_rtt = max_rtt.max(Some(acked_packet.rtt()));
            if let Some(delay_variation) = self
                .arrival_group_accumulator
                .accumulate_packet(acked_packet)
            {
                log_delay_variation!(delay_variation.arrival_delta);

                // Got a new delay variation, add it to the trendline.
                //
                // IMPORTANT: Match WebRTC's TrendlineEstimator time base.
                // WebRTC calls Detect/UpdateThreshold with `arrival_time_ms` (remote receive time),
                // not the local "time we processed this feedback". Using the remote receive time
                // avoids threshold adaptation artifacts when many deltas are processed in one
                // feedback batch (e.g. TWCC reports).
                //
                // Note: We use remote timestamps for relative timing only (computing time deltas
                // between packets). Clock skew doesn't matter since we're measuring trends in
                // delay variations, not absolute times.
                self.trendline_estimator
                    .add_delay_observation(delay_variation, delay_variation.last_remote_recv_time);
            }
        }

        if let Some(rtt) = max_rtt {
            self.update_rtt(rtt);
        }

        let new_hypothesis = self.trendline_estimator.hypothesis();

        self.update_estimate(
            new_hypothesis,
            acked_bitrate,
            probe_bitrate,
            self.get_smoothed_rtt(),
            now,
        );
        self.last_twcc_report = now;

        self.last_estimate
    }

    pub fn poll_timeout(&self) -> Instant {
        self.next_timeout
    }

    pub fn handle_timeout(&mut self, acked_bitrate: Option<Bitrate>, now: Instant) {
        if !self.trendline_hypothesis_valid(now) {
            // We haven't received a TWCC report in a while. The trendline hypothesis can
            // no longer be considered valid. We need another TWCC report before we can update
            // estimates.
            let next_timeout_in = self
                .get_smoothed_rtt()
                .unwrap_or(MAX_TWCC_GAP)
                .min(UPDATE_INTERVAL);

            // Set this even if we didn't update, otherwise we get stuck in a poll -> handle loop
            // that starves the run loop.
            self.next_timeout = now + next_timeout_in;
            return;
        }

        self.update_estimate(
            self.trendline_estimator.hypothesis(),
            acked_bitrate,
            None,
            self.get_smoothed_rtt(),
            now,
        );
    }

    /// Get the latest estimate.
    pub fn last_estimate(&self) -> Option<Bitrate> {
        self.last_estimate
    }

    /// Whether the delay-based detector currently signals overuse.
    ///
    /// This is useful for gating behaviors (like probing) that would otherwise
    /// re-excite the system while we're already congested.
    pub fn is_overusing(&self) -> bool {
        self.trendline_estimator.hypothesis() == BandwidthUsage::Overuse
    }

    /// Update smoothed RTT using EWMA (RFC 6298, alpha = 1/8).
    fn update_rtt(&mut self, rtt: Duration) {
        // Keep history as fallback in case smoothed RTT is not yet available
        while self.max_rtt_history.len() >= MAX_RTT_HISTORY_WINDOW {
            self.max_rtt_history.pop_front();
        }
        self.max_rtt_history.push_back(rtt);

        // Update smoothed RTT using EWMA: smoothed = (7/8) * smoothed + (1/8) * sample
        self.smoothed_rtt.update(rtt.as_secs_f64());
    }

    /// Get the current smoothed RTT, with fallback to mean of history if not yet available.
    fn get_smoothed_rtt(&self) -> Option<Duration> {
        // Try smoothed RTT first (EWMA)
        if let Some(avg_secs) = self.smoothed_rtt.get() {
            return Some(Duration::from_secs_f64(avg_secs));
        }

        // Fallback to mean of history during initialization
        if self.max_rtt_history.is_empty() {
            return None;
        }

        let sum = self
            .max_rtt_history
            .iter()
            .fold(Duration::ZERO, |acc, rtt| acc + *rtt);
        Some(sum / self.max_rtt_history.len() as u32)
    }

    fn update_estimate(
        &mut self,
        hypothesis: BandwidthUsage,
        observed_bitrate: Option<Bitrate>,
        probe_bitrate: Option<Bitrate>,
        mean_max_rtt: Option<Duration>,
        now: Instant,
    ) {
        // WebRTC's logic from delay_based_bwe.cc MaybeUpdateEstimate():
        // - If we have a probe result, apply it directly and skip delay-based updates
        // - Otherwise, apply normal delay-based rate control
        //
        // This prevents probe results from being immediately overridden by delay-based
        // decreases caused by the probe itself (probes cause temporary queuing delay).

        if let Some(probe_rate) = probe_bitrate {
            // Apply probe result directly, bypassing delay-based updates
            self.rate_control.set_probe_result(probe_rate, now);
            let estimated_rate = self.rate_control.estimated_bitrate();
            log_bitrate_estimate!(estimated_rate.as_f64());
            self.last_estimate = Some(estimated_rate);
        } else if let Some(observed_bitrate) = observed_bitrate {
            // No probe result, apply normal delay-based rate control
            self.rate_control
                .update(hypothesis.into(), observed_bitrate, mean_max_rtt, now);
            let estimated_rate = self.rate_control.estimated_bitrate();

            log_bitrate_estimate!(estimated_rate.as_f64());
            self.last_estimate = Some(estimated_rate);
        }

        // Set this even if we didn't update, otherwise we get stuck in a poll -> handle loop
        // that starves the run loop.
        self.next_timeout = now + UPDATE_INTERVAL;
    }

    /// Whether the current trendline hypothesis is valid i.e. not too old.
    fn trendline_hypothesis_valid(&self, now: Instant) -> bool {
        now.duration_since(self.last_twcc_report)
            <= self
                .get_smoothed_rtt()
                .map(|rtt| rtt * 2)
                .unwrap_or(MAX_TWCC_GAP)
                .min(UPDATE_INTERVAL * 2)
    }
}

/// AFKLink patch: the delay controller as the session drives it, fed TWCC-like reports, so the
/// trendline patch is checked where it matters: the estimate the pacer and encoder get.
#[cfg(test)]
mod afklink_test {
    use std::time::{Duration, Instant};

    use super::super::super::AckedPacket;
    use super::DelayController;
    use crate::rtp_::{Bitrate, DataSize};

    const PACKET_BYTES: i64 = 1_200;
    const ONE_WAY_MS: f64 = 20.0;
    const REPORT_EVERY_MS: f64 = 100.0;

    /// The path a packet sent at a time (ms) meets: (link time per packet in ms, buffer in ms of
    /// queueing before tail drop, extra one-way delay in ms).
    type Path<'a> = dyn Fn(f64) -> (f64, f64, f64) + 'a;

    /// Drive a delay controller (5 Mbps to start) until `until_ms`: `per_frame` packets of
    /// `PACKET_BYTES` sent back to back every `frame_ms` (a frame's packets, 0.3 ms apart) over
    /// `path`, a TWCC report every `REPORT_EVERY_MS`. Returns (report time ms, estimate kbps).
    fn drive(
        upstream_only: bool,
        frame_ms: f64,
        per_frame: usize,
        until_ms: f64,
        path: &Path<'_>,
    ) -> Vec<(f64, u64)> {
        let base = Instant::now();
        let at = |ms: f64| base + Duration::from_micros((ms * 1000.0) as u64);
        let mut c = DelayController::new(Bitrate::kbps(5_000));
        c.trendline_estimator.upstream_only = upstream_only;

        let mut seq = 0u64;
        let mut link_free_ms = 0.0f64;
        let mut pending: Vec<(f64, f64, u64)> = Vec::new(); // (send, arrival, seq)
        let mut next_report = REPORT_EVERY_MS;
        let mut out = Vec::new();
        let mut frame = 0.0;
        while frame < until_ms {
            frame += frame_ms;
            for i in 0..per_frame {
                let send = frame + 0.3 * i as f64;
                let (service, buffer_ms, extra_ms) = path(send);
                let unqueued = send + ONE_WAY_MS + extra_ms;
                let arrival = unqueued.max(link_free_ms + service);
                seq += 1;
                if arrival - unqueued > buffer_ms {
                    continue; // tail drop: never reported
                }
                link_free_ms = arrival;
                pending.push((send, arrival, seq));
            }
            while frame >= next_report {
                let report_at = next_report;
                next_report += REPORT_EVERY_MS;
                // What arrived by when the report left the far end (it takes ONE_WAY_MS back).
                let cutoff = report_at - ONE_WAY_MS;
                let (acked, rest): (Vec<_>, Vec<_>) =
                    pending.drain(..).partition(|(_, a, _)| *a <= cutoff);
                pending = rest;
                if acked.is_empty() {
                    continue;
                }
                let packets: Vec<AckedPacket> = acked
                    .iter()
                    .map(|&(s, a, q)| AckedPacket {
                        seq_no: q.into(),
                        size: DataSize::bytes(PACKET_BYTES),
                        local_send_time: at(s),
                        remote_recv_time: at(a),
                        local_recv_time: at(report_at),
                    })
                    .collect();
                let bits = (acked.len() as i64 * PACKET_BYTES * 8) as f64;
                let observed = Bitrate::bps((bits * 1000.0 / REPORT_EVERY_MS) as u64);
                let estimate = c
                    .update(&packets, Some(observed), None, at(report_at))
                    .map_or(0, |b| b.as_u64() / 1000);
                out.push((report_at, estimate));
            }
        }
        out
    }

    /// The estimate at the last report before `from_ms`, and its lowest from then to the end.
    fn before_and_lowest(estimates: &[(f64, u64)], from_ms: f64) -> (u64, u64) {
        let before = estimates
            .iter()
            .filter(|(t, _)| *t < from_ms)
            .map(|(_, e)| *e)
            .next_back()
            .unwrap_or(0);
        let lowest = estimates
            .iter()
            .filter(|(t, _)| *t >= from_ms)
            .map(|(_, e)| *e)
            .min()
            .unwrap_or(u64::MAX);
        (before, lowest)
    }

    #[test]
    fn afklink_the_estimate_drops_on_a_queue_that_soon_stops_growing() {
        // We send 4.8 Mbps (a packet every 2 ms); at 2 s the link narrows to 1/`ratio` of that
        // behind a buffer, or the path gets 100 ms longer for good.
        for (label, ratio, buffer, extra) in [
            ("2x, 40 ms buffer", 2.0, 40.0, 0.0),
            ("2x, 80 ms buffer", 2.0, 80.0, 0.0),
            ("3x, 60 ms buffer", 3.0, 60.0, 0.0),
            ("path +100 ms for good", 1.0, f64::INFINITY, 100.0),
        ] {
            let path = move |s: f64| {
                if s < 2_000.0 {
                    (0.1, f64::INFINITY, 0.0)
                } else if ratio > 1.0 {
                    (2.0 * ratio, buffer, 0.0)
                } else {
                    (0.1, buffer, extra)
                }
            };
            let (up_before, up_low) =
                before_and_lowest(&drive(true, 2.0, 1, 3_500.0, &path), 2_000.0);
            let (before, low) = before_and_lowest(&drive(false, 2.0, 1, 3_500.0, &path), 2_000.0);
            println!(
                "{label}: estimate {up_before} -> {up_low} kbps upstream, {before} -> {low} kbps patched"
            );
            assert!(up_low < up_before * 9 / 10, "{label}: upstream cuts");
            assert!(
                low < before * 9 / 10,
                "{label}: patched cuts too ({before} -> {low})"
            );
            if extra > 0.0 {
                // A longer path is no queue: the latch's cap keeps the patched build from
                // cutting it much deeper than upstream's one cut.
                assert!(
                    low * 10 >= up_low * 9,
                    "{label}: patched {low} kbps against upstream's {up_low}"
                );
            }
        }
    }

    #[test]
    fn afklink_repeated_stalls_leave_the_estimate_uncut() {
        // 30 s of the 25 Oct viewer at frame-sized groups: a stall every 3-5 s, step (+100 ms
        // for 150 ms) and ramp (to +130 ms over 120 ms) taking turns, room to spare on the link.
        let starts = [
            3_000.0, 7_000.0, 10_500.0, 15_000.0, 18_000.0, 23_000.0, 26_500.0,
        ];
        let stall = |s: f64| -> f64 {
            for (n, at) in starts.iter().enumerate() {
                let into = s - at;
                if n % 2 == 0 && (0.0..150.0).contains(&into) {
                    return 100.0;
                }
                if n % 2 == 1 && (0.0..120.0).contains(&into) {
                    return 130.0 * into / 120.0;
                }
            }
            0.0
        };
        let path = |s: f64| (0.1, f64::INFINITY, stall(s));
        for (frame_ms, per_frame) in [(16.7, 8), (33.0, 16)] {
            let (up_before, up_low) =
                before_and_lowest(&drive(true, frame_ms, per_frame, 30_000.0, &path), 3_000.0);
            let (before, low) =
                before_and_lowest(&drive(false, frame_ms, per_frame, 30_000.0, &path), 3_000.0);
            println!(
                "{frame_ms} ms frames: estimate {up_before} -> lowest {up_low} kbps upstream, \
                 {before} -> lowest {low} kbps patched"
            );
            assert!(
                up_low < up_before * 9 / 10,
                "{frame_ms} ms: upstream cuts on stalls"
            );
            assert!(
                low * 100 >= before * 95,
                "{frame_ms} ms: patched {before} -> {low} kbps"
            );
        }
    }

    /// From `from_ms` on, a train of big frames: every `k`-th frame's packets take `beta` frame
    /// intervals of link time between them, the other frames share the rest of `rho` intervals
    /// each, so the link carries 1/rho of what we send.
    fn burst_train_path(
        frame_ms: f64,
        per_frame: usize,
        k: i64,
        beta: f64,
        rho: f64,
        from_ms: f64,
    ) -> impl Fn(f64) -> (f64, f64, f64) {
        let packets = per_frame as f64;
        let big = beta * frame_ms / packets;
        let small = (k as f64 * rho - beta) * frame_ms / ((k - 1) as f64 * packets);
        move |s: f64| {
            if s < from_ms {
                return (0.1, f64::INFINITY, 0.0);
            }
            let frame = (s / frame_ms).floor() as i64;
            let service = if frame % k == 0 { big } else { small };
            (service, f64::INFINITY, 0.0)
        }
    }

    /// When (ms after `from_ms`) the estimate first fell below 95% of what it was before.
    fn first_cut(estimates: &[(f64, u64)], from_ms: f64) -> Option<f64> {
        let (before, _) = before_and_lowest(estimates, from_ms);
        estimates
            .iter()
            .find(|(t, e)| *t >= from_ms && *e * 100 < before * 95)
            .map(|(t, _)| *t - from_ms)
    }

    #[test]
    fn afklink_the_estimate_drops_on_a_burst_train_over_a_growing_queue() {
        // The review's escape at the controller: a big frame every 6 or 12 frames into a link we
        // overrun by 2-10%. Upstream cuts within 200-700 ms; round 4 never cut 16 of these 45.
        // The patched estimate is cut too, at most a burst cycle, a hold (250 ms) and two reports
        // later.
        let mut worst = (f64::NEG_INFINITY, String::new());
        for (frame_ms, per_frame) in [(16.7, 8), (20.8, 10), (33.0, 16)] {
            for k in [6i64, 12] {
                for beta in [3.0, 5.0, 8.0] {
                    for rho in [1.02, 1.05, 1.1] {
                        if k as f64 * rho - beta < 0.1 * (k - 1) as f64 {
                            continue;
                        }
                        let case =
                            format!("{frame_ms} ms, a big frame of {beta} every {k}, {rho}x");
                        let path = burst_train_path(frame_ms, per_frame, k, beta, rho, 3_000.0);
                        let up =
                            first_cut(&drive(true, frame_ms, per_frame, 13_000.0, &path), 3_000.0)
                                .unwrap_or_else(|| panic!("{case}: upstream cuts"));
                        let patched =
                            first_cut(&drive(false, frame_ms, per_frame, 13_000.0, &path), 3_000.0)
                                .unwrap_or_else(|| panic!("{case}: patched never cuts"));
                        assert!(
                            patched <= up + k as f64 * frame_ms + 250.0 + 2.0 * REPORT_EVERY_MS,
                            "{case}: upstream cuts after {up:.0} ms, patched after {patched:.0}"
                        );
                        if patched - up > worst.0 {
                            worst = (patched - up, case);
                        }
                    }
                }
            }
        }
        println!(
            "burst trains at the controller: cut at most {:.0} ms after upstream ({})",
            worst.0, worst.1
        );
    }
}
