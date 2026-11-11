//! One direction of the network path: a bottleneck with a capacity schedule, a drop-tail queue in
//! front of it, random loss, propagation delay and jitter.
//!
//! ## The model
//!
//! A single FIFO server. A datagram arriving at `now`:
//!
//!   1. may be lost at random (Bernoulli, or Gilbert-Elliott for bursts) before it reaches the
//!      queue, so a lost packet costs no capacity — the shape of `mm-loss` in front of `mm-link`
//!      ([`LossAt::Arrival`], the default). With [`LossAt::Departure`] the draw happens after the
//!      bottleneck instead, so a lost packet has already spent its queue slot and its capacity —
//!      loss on a hop downstream of the bottleneck, such as a radio link behind a base station's
//!      queue;
//!   2. is dropped at the tail if the queue is full, by bytes waiting or by the milliseconds it
//!      would wait before its first bit is served;
//!   3. is serialised at the bottleneck: fluid at the current rate for a constant or piecewise
//!      capacity, instantly for [`Capacity::Unlimited`], or byte credit of 1500 per delivery
//!      opportunity for a Mahimahi trace (several small packets can share one opportunity, a large
//!      one spans several, credit left over when the queue empties is wasted —
//!      `mahimahi/src/packet/link_queue.cc`);
//!   4. arrives `delay` + a uniform `[0, jitter]` after it leaves the bottleneck, never overtaking
//!      an earlier packet unless `reorder` is set.
//!
//! Because the server is FIFO and the capacity schedule is known in advance, a packet's departure
//! is fixed at the moment it is accepted, so the whole link is a function of its arrivals and its
//! seed: no timer of its own beyond "the next delivery is due at".
//!
//! Sizes on the wire are the datagram plus `overhead_bytes` (IPv4 + UDP is 28; add 4 for a TURN
//! ChannelData header, 36 for a TURN Send indication).
//!
//! ## Clocks
//!
//! Time is a `Duration` from an origin the caller chooses. The simulator passes its virtual clock;
//! the agent's bench shaper passes `Instant::now() - start`. Readings handed to one link must not go
//! backwards.
//!
//! ## Ideal mode
//!
//! Until [`Link::set_ideal`]`(false)` the link is a fixed delay and nothing else. The simulation
//! runs the ICE/DTLS handshake that way, because DTLS handshake sizes vary with the OS-random keys
//! str0m cannot be told to seed (see `afklink_sim::clock`), and a capacity or a loss draw that
//! depended on them would make every later event depend on them too. The real-time shaper leaves
//! ideal mode at once: on the wire the handshake is shaped like everything else.

use std::cmp::Ordering;
use std::collections::{BinaryHeap, VecDeque};
use std::net::SocketAddr;
use std::time::Duration;

use crate::rng::SimRng;

/// A UDP datagram in flight between the two peers.
#[derive(Debug, Clone)]
pub struct Datagram {
    pub source: SocketAddr,
    pub destination: SocketAddr,
    pub contents: Vec<u8>,
}

/// How much the bottleneck can serve, over time.
#[derive(Debug, Clone, PartialEq)]
pub enum Capacity {
    /// No bottleneck at all: a packet leaves the moment it arrives, and a queue never forms. The
    /// shape of a direction that only has delay, jitter and loss.
    Unlimited,
    /// A fixed rate, in kbps.
    Constant { kbps: f64 },
    /// Piecewise-constant: each `(from, kbps)` holds until the next. The first step should start at
    /// zero (earlier time is served at the first step's rate). A 0 kbps step is an outage; a final
    /// 0 kbps step means packets queued behind it are never delivered.
    Piecewise { steps: Vec<(Duration, f64)> },
    /// A Mahimahi packet-delivery trace: each value is a millisecond (from the trace start) at which
    /// `bytes_per_opportunity` bytes may leave. The trace repeats with a period of its last value,
    /// as `mm-link` does with `--repeat` (its default).
    Trace {
        opportunities_ms: Vec<u64>,
        bytes_per_opportunity: u32,
    },
}

/// When the queue in front of the bottleneck is full.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum QueueLimit {
    Unlimited,
    /// Bytes accepted and not yet fully serialised, the packet in service included.
    Bytes(u64),
    /// How long an arriving packet would wait before its first bit is served.
    Delay(Duration),
}

/// Random loss.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Loss {
    None,
    Bernoulli {
        p: f64,
    },
    /// Two-state Markov chain, stepped once per packet: move between good and bad with the given
    /// probabilities, then lose with the state's loss probability. `loss_bad = 1`, `loss_good = 0`
    /// is the classic Gilbert model; mean burst length is `1 / p_bad_to_good` packets.
    GilbertElliott {
        p_good_to_bad: f64,
        p_bad_to_good: f64,
        loss_good: f64,
        loss_bad: f64,
    },
}

/// Where on the path the random loss is drawn. See the module documentation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LossAt {
    /// Before the queue: a lost packet costs no capacity (`mm-loss` in front of `mm-link`).
    #[default]
    Arrival,
    /// After the bottleneck: a lost packet has used its queue slot and its serialisation time.
    Departure,
}

#[derive(Debug, Clone, PartialEq)]
pub struct LinkConfig {
    pub capacity: Capacity,
    /// One-way propagation delay, after the bottleneck.
    pub delay: Duration,
    pub queue: QueueLimit,
    pub loss: Loss,
    /// Where `loss` is drawn.
    pub loss_at: LossAt,
    /// Upper bound of a uniform extra delay per packet, after the bottleneck.
    pub jitter: Duration,
    /// Whether jitter may reorder packets. Off, a packet never arrives before one sent earlier.
    pub reorder: bool,
    /// Bytes added to every datagram on the wire (IP/UDP, a TURN header).
    pub overhead_bytes: u32,
}

impl Default for LinkConfig {
    fn default() -> Self {
        Self {
            capacity: Capacity::Constant { kbps: 10_000.0 },
            delay: Duration::from_millis(20),
            queue: QueueLimit::Unlimited,
            loss: Loss::None,
            loss_at: LossAt::Arrival,
            jitter: Duration::ZERO,
            reorder: false,
            overhead_bytes: 28,
        }
    }
}

/// What happened on the link, cumulatively.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct LinkStats {
    pub sent_packets: u64,
    pub sent_bytes: u64,
    pub delivered_packets: u64,
    pub delivered_bytes: u64,
    pub dropped_queue: u64,
    pub dropped_loss: u64,
    /// Accepted behind an outage that never ends; never delivered.
    pub dropped_outage: u64,
    /// Longest time a packet spent from arrival to leaving the bottleneck (queue + serialisation).
    pub max_sojourn: Duration,
    pub sojourn_total: Duration,
    pub sojourn_samples: u64,
}

/// The same, over the window since [`Link::take_window`] was last called.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct LinkWindow {
    pub max_sojourn: Duration,
    pub dropped_queue: u64,
    pub dropped_loss: u64,
    pub delivered_bytes: u64,
}

#[derive(Debug)]
struct InFlight {
    at: Duration,
    seq: u64,
    counted: bool,
    dgram: Datagram,
}

impl PartialEq for InFlight {
    fn eq(&self, other: &Self) -> bool {
        self.at == other.at && self.seq == other.seq
    }
}
impl Eq for InFlight {}
impl PartialOrd for InFlight {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for InFlight {
    /// Reversed, so `BinaryHeap` pops the earliest delivery; the sequence number breaks ties in
    /// send order, which keeps delivery deterministic when two packets are due at once.
    fn cmp(&self, other: &Self) -> Ordering {
        (other.at, other.seq).cmp(&(self.at, self.seq))
    }
}

/// One direction of the path. See the module documentation.
#[derive(Debug)]
pub struct Link {
    name: &'static str,
    cfg: LinkConfig,
    rng: SimRng,
    ideal: bool,
    ge_bad: bool,
    /// Fluid capacity: when the last accepted packet finishes serialisation.
    server_free_at: Duration,
    /// Trace capacity: the opportunity used by the last accepted packet, and its credit left.
    cursor: Option<(u64, u32)>,
    /// Accepted and not yet departed, for the byte limit.
    backlog: VecDeque<(Duration, u32)>,
    backlog_bytes: u64,
    in_flight: BinaryHeap<InFlight>,
    seq: u64,
    last_delivery: Duration,
    stats: LinkStats,
    window: LinkWindow,
}

impl Link {
    /// A link that starts in ideal mode; see the module documentation.
    #[must_use]
    pub fn new(name: &'static str, cfg: LinkConfig, rng: SimRng) -> Self {
        tracing::debug!(
            link = name,
            capacity = %describe_capacity(&cfg.capacity),
            delay_ms = cfg.delay.as_secs_f64() * 1e3,
            queue = ?cfg.queue,
            loss = ?cfg.loss,
            loss_at = ?cfg.loss_at,
            jitter_ms = cfg.jitter.as_secs_f64() * 1e3,
            reorder = cfg.reorder,
            overhead_bytes = cfg.overhead_bytes,
            "link configured"
        );
        Self {
            name,
            cfg,
            rng,
            ideal: true,
            ge_bad: false,
            server_free_at: Duration::ZERO,
            cursor: None,
            backlog: VecDeque::new(),
            backlog_bytes: 0,
            in_flight: BinaryHeap::new(),
            seq: 0,
            last_delivery: Duration::ZERO,
            stats: LinkStats::default(),
            window: LinkWindow::default(),
        }
    }

    /// Leave (or re-enter) ideal mode.
    ///
    /// Leaving it also restarts the statistics: what the handshake sent depends on OS-random DTLS
    /// sizes, and a counter that included it would make two runs of one seed differ by a few bytes.
    pub fn set_ideal(&mut self, ideal: bool, now: Duration) {
        if self.ideal != ideal {
            tracing::debug!(
                link = self.name,
                ideal,
                at_ms = now.as_secs_f64() * 1e3,
                handshake_packets = self.stats.sent_packets,
                "link mode changed"
            );
            if !ideal {
                self.stats = LinkStats::default();
                self.window = LinkWindow::default();
            }
        }
        self.ideal = ideal;
        self.server_free_at = self.server_free_at.max(now);
    }

    /// Replace the configuration mid-run, keeping everything already in flight.
    ///
    /// A packet's departure and arrival are committed when it is accepted (see the module docs), so
    /// a new rate, delay or jitter applies from the next arrival on; packets accepted before keep the
    /// timing they were given, and FIFO order still holds across the change. A queue already longer
    /// than a new, shorter limit drains on its old schedule while new arrivals are refused against
    /// it — what a router does the moment its buffer is shrunk. The Gilbert-Elliott chain keeps its
    /// state while the loss stays Gilbert-Elliott; a trace cursor restarts when the capacity changes,
    /// since the opportunities of one schedule mean nothing in another.
    pub fn reconfigure(&mut self, cfg: LinkConfig, now: Duration) {
        if cfg == self.cfg {
            tracing::debug!(link = self.name, "link reconfigure: unchanged");
            return;
        }
        if cfg.capacity != self.cfg.capacity {
            self.cursor = None;
        }
        if !matches!(cfg.loss, Loss::GilbertElliott { .. }) {
            self.ge_bad = false;
        }
        tracing::debug!(
            link = self.name,
            at_ms = now.as_secs_f64() * 1e3,
            capacity = %describe_capacity(&cfg.capacity),
            was_capacity = %describe_capacity(&self.cfg.capacity),
            delay_ms = cfg.delay.as_secs_f64() * 1e3,
            queue = ?cfg.queue,
            loss = ?cfg.loss,
            loss_at = ?cfg.loss_at,
            jitter_ms = cfg.jitter.as_secs_f64() * 1e3,
            in_flight = self.in_flight.len(),
            queued_bytes = self.queued_bytes(now),
            "link reconfigured; packets already accepted keep their timing"
        );
        self.cfg = cfg;
    }

    #[must_use]
    pub fn name(&self) -> &'static str {
        self.name
    }

    #[must_use]
    pub fn config(&self) -> &LinkConfig {
        &self.cfg
    }

    #[must_use]
    pub fn stats(&self) -> &LinkStats {
        &self.stats
    }

    /// Take the per-window counters and start a new window.
    pub fn take_window(&mut self) -> LinkWindow {
        std::mem::take(&mut self.window)
    }

    /// Datagrams accepted and not yet delivered at the far end.
    #[must_use]
    pub fn in_flight_len(&self) -> usize {
        self.in_flight.len()
    }

    /// Bytes accepted and still waiting for (or in) the bottleneck at `now`: the queue.
    #[must_use]
    pub fn queued_bytes(&self, now: Duration) -> u64 {
        self.backlog
            .iter()
            .filter(|(depart, _)| *depart > now)
            .map(|(_, bytes)| u64::from(*bytes))
            .sum()
    }

    /// How long a packet arriving now would wait before its first bit is served.
    #[must_use]
    pub fn queue_delay(&self, now: Duration) -> Duration {
        if self.ideal {
            return Duration::ZERO;
        }
        match &self.cfg.capacity {
            Capacity::Trace { .. } => self
                .first_opportunity(now)
                .map_or(Duration::ZERO, |(k, _)| {
                    self.opportunity_at(k).saturating_sub(now)
                }),
            _ => self.server_free_at.saturating_sub(now),
        }
    }

    /// Hand the link a datagram at `now`.
    pub fn send(&mut self, now: Duration, dgram: Datagram) {
        let wire = u32::try_from(dgram.contents.len())
            .unwrap_or(u32::MAX)
            .saturating_add(self.cfg.overhead_bytes);
        self.stats.sent_packets += 1;
        self.stats.sent_bytes += u64::from(wire);

        if self.ideal {
            let at = (now + self.cfg.delay).max(self.last_delivery);
            self.enqueue_delivery(at, dgram, false);
            return;
        }

        if self.cfg.loss_at == LossAt::Arrival && self.lose() {
            self.count_loss(wire, "random loss before the queue");
            return;
        }

        while let Some(&(depart, bytes)) = self.backlog.front() {
            if depart > now {
                break;
            }
            self.backlog.pop_front();
            self.backlog_bytes -= u64::from(bytes);
        }

        let depart = match &self.cfg.capacity {
            Capacity::Trace { .. } => self.serve_trace(now, wire),
            _ => self.serve_fluid(now, wire),
        };
        let Some(depart) = depart else {
            return;
        };

        let sojourn = depart - now;
        self.stats.max_sojourn = self.stats.max_sojourn.max(sojourn);
        self.stats.sojourn_total += sojourn;
        self.stats.sojourn_samples += 1;
        self.window.max_sojourn = self.window.max_sojourn.max(sojourn);
        self.backlog.push_back((depart, wire));
        self.backlog_bytes += u64::from(wire);

        // After the bottleneck: the packet has already spent its place in the queue.
        if self.cfg.loss_at == LossAt::Departure && self.lose() {
            self.count_loss(wire, "random loss after the bottleneck");
            return;
        }

        let jitter = if self.cfg.jitter.is_zero() {
            Duration::ZERO
        } else {
            Duration::from_secs_f64(self.rng.next_f64() * self.cfg.jitter.as_secs_f64())
        };
        let mut at = depart + self.cfg.delay + jitter;
        if !self.cfg.reorder {
            at = at.max(self.last_delivery);
        }
        self.enqueue_delivery(at, dgram, true);
    }

    /// When the next datagram is due at the far end, if any is in flight.
    #[must_use]
    pub fn next_delivery(&self) -> Option<Duration> {
        self.in_flight.peek().map(|f| f.at)
    }

    /// The next datagram due at or before `now`.
    pub fn pop_due(&mut self, now: Duration) -> Option<Datagram> {
        if self.in_flight.peek().is_some_and(|f| f.at <= now) {
            let f = self.in_flight.pop()?;
            if f.counted {
                let wire = u64::try_from(f.dgram.contents.len()).unwrap_or(0)
                    + u64::from(self.cfg.overhead_bytes);
                self.stats.delivered_packets += 1;
                self.stats.delivered_bytes += wire;
                self.window.delivered_bytes += wire;
            }
            Some(f.dgram)
        } else {
            None
        }
    }

    fn count_loss(&mut self, wire: u32, what: &'static str) {
        self.stats.dropped_loss += 1;
        self.window.dropped_loss += 1;
        tracing::trace!(link = self.name, bytes = wire, "{what}");
    }

    /// `counted`: whether the delivery belongs to the statistics (not a handshake packet).
    fn enqueue_delivery(&mut self, at: Duration, dgram: Datagram, counted: bool) {
        self.last_delivery = self.last_delivery.max(at);
        self.seq += 1;
        self.in_flight.push(InFlight {
            at,
            seq: self.seq,
            counted,
            dgram,
        });
    }

    fn lose(&mut self) -> bool {
        match self.cfg.loss {
            Loss::None => false,
            Loss::Bernoulli { p } => self.rng.chance(p),
            Loss::GilbertElliott {
                p_good_to_bad,
                p_bad_to_good,
                loss_good,
                loss_bad,
            } => {
                if self.ge_bad {
                    if self.rng.chance(p_bad_to_good) {
                        self.ge_bad = false;
                    }
                } else if self.rng.chance(p_good_to_bad) {
                    self.ge_bad = true;
                }
                let p = if self.ge_bad { loss_bad } else { loss_good };
                self.rng.chance(p)
            }
        }
    }

    fn drop_tail(&mut self, wire: u32, wait: Duration) -> bool {
        let full = match self.cfg.queue {
            QueueLimit::Unlimited => false,
            QueueLimit::Bytes(limit) => self.backlog_bytes + u64::from(wire) > limit,
            QueueLimit::Delay(limit) => wait > limit,
        };
        if full {
            self.stats.dropped_queue += 1;
            self.window.dropped_queue += 1;
            tracing::trace!(
                link = self.name,
                bytes = wire,
                backlog_bytes = self.backlog_bytes,
                wait_ms = wait.as_secs_f64() * 1e3,
                "queue full: dropped at the tail"
            );
        }
        full
    }

    /// Fluid service: the departure of a packet of `wire` bytes arriving at `now`, or `None` when
    /// it is dropped or would never be served.
    fn serve_fluid(&mut self, now: Duration, wire: u32) -> Option<Duration> {
        let start = now.max(self.server_free_at);
        if self.drop_tail(wire, start - now) {
            return None;
        }
        let bits = f64::from(wire) * 8.0;
        let Some(finish) = fluid_finish(&self.cfg.capacity, start, bits) else {
            self.stats.dropped_outage += 1;
            tracing::debug!(
                link = self.name,
                at_ms = now.as_secs_f64() * 1e3,
                "packet behind an outage that never ends: never delivered"
            );
            return None;
        };
        self.server_free_at = finish;
        Some(finish)
    }

    /// Trace service: byte credit per delivery opportunity, as `mm-link`.
    fn serve_trace(&mut self, now: Duration, wire: u32) -> Option<Duration> {
        let Capacity::Trace {
            bytes_per_opportunity,
            ..
        } = self.cfg.capacity
        else {
            return None;
        };
        let per = bytes_per_opportunity.max(1);
        let (mut k, mut left) = self.first_opportunity(now)?;
        let wait = self.opportunity_at(k).saturating_sub(now);
        if self.drop_tail(wire, wait) {
            return None;
        }
        let mut need = wire;
        loop {
            let take = need.min(left);
            need -= take;
            left -= take;
            if need == 0 {
                break;
            }
            k += 1;
            left = per;
        }
        self.cursor = Some((k, left));
        Some(self.opportunity_at(k))
    }

    /// The opportunity a packet arriving at `now` starts on, and the credit left in it.
    fn first_opportunity(&self, now: Duration) -> Option<(u64, u32)> {
        let Capacity::Trace {
            opportunities_ms,
            bytes_per_opportunity,
        } = &self.cfg.capacity
        else {
            return None;
        };
        let n = opportunities_ms.len() as u64;
        let period_ms = *opportunities_ms.last()?;
        if n == 0 || period_ms == 0 {
            return None;
        }
        // The first opportunity at or after `now`, in integer nanoseconds so an arrival exactly on
        // an opportunity's millisecond takes it.
        let now_ns = now.as_nanos();
        let period_ns = u128::from(period_ms) * 1_000_000;
        let cycle = now_ns / period_ns;
        let within = now_ns - cycle * period_ns;
        let i = opportunities_ms.partition_point(|&t| u128::from(t) * 1_000_000 < within) as u64;
        let by_time = u64::try_from(cycle).unwrap_or(u64::MAX / 2) * n + i;
        match self.cursor {
            // The previous packet left credit in an opportunity that has not happened yet: share it.
            Some((k, left)) if left > 0 && self.opportunity_at(k) >= now => Some((k, left)),
            // Otherwise the next unused one, never one an earlier packet already consumed (FIFO).
            Some((k, left)) => {
                let floor = if left > 0 { k } else { k + 1 };
                Some((by_time.max(floor), *bytes_per_opportunity))
            }
            None => Some((by_time, *bytes_per_opportunity)),
        }
    }

    /// The time of global opportunity `k`.
    fn opportunity_at(&self, k: u64) -> Duration {
        let Capacity::Trace {
            opportunities_ms, ..
        } = &self.cfg.capacity
        else {
            return Duration::ZERO;
        };
        let n = opportunities_ms.len() as u64;
        let Some(&period) = opportunities_ms.last() else {
            return Duration::ZERO;
        };
        if n == 0 {
            return Duration::ZERO;
        }
        let idx = usize::try_from(k % n).unwrap_or(0);
        Duration::from_millis((k / n) * period + opportunities_ms[idx])
    }
}

/// When `bits` starting at `start` finish serialising under a fluid capacity, or `None` if never.
fn fluid_finish(capacity: &Capacity, start: Duration, bits: f64) -> Option<Duration> {
    match capacity {
        Capacity::Unlimited => Some(start),
        Capacity::Constant { kbps } => {
            if *kbps <= 0.0 {
                return None;
            }
            Some(start + Duration::from_secs_f64(bits / (kbps * 1000.0)))
        }
        Capacity::Piecewise { steps } => {
            if steps.is_empty() {
                return None;
            }
            let mut t = start;
            let mut remaining = bits;
            // The step in force at `t`: the last one starting at or before it (the first before any).
            let mut i = steps
                .partition_point(|(from, _)| *from <= t)
                .saturating_sub(1);
            loop {
                let rate = steps[i].1.max(0.0) * 1000.0;
                let end = steps.get(i + 1).map(|(from, _)| *from);
                match end {
                    Some(end) => {
                        let span = end.saturating_sub(t).as_secs_f64();
                        let can = rate * span;
                        if rate > 0.0 && can >= remaining {
                            return Some(t + Duration::from_secs_f64(remaining / rate));
                        }
                        remaining -= can;
                        t = t.max(end);
                        i += 1;
                    }
                    None => {
                        if rate <= 0.0 {
                            return None;
                        }
                        return Some(t + Duration::from_secs_f64(remaining / rate));
                    }
                }
            }
        }
        Capacity::Trace { .. } => None,
    }
}

/// A short human description of a capacity, for logs and the summary.
#[must_use]
pub fn describe_capacity(c: &Capacity) -> String {
    match c {
        Capacity::Unlimited => "unlimited".to_string(),
        Capacity::Constant { kbps } => format!("{kbps:.0} kbps"),
        Capacity::Piecewise { steps } => {
            let parts: Vec<String> = steps
                .iter()
                .map(|(t, k)| format!("{:.1}s:{k:.0}", t.as_secs_f64()))
                .collect();
            format!("piecewise[{}]", parts.join(","))
        }
        Capacity::Trace {
            opportunities_ms,
            bytes_per_opportunity,
        } => {
            let period = opportunities_ms.last().copied().unwrap_or(0);
            let kbps = if period > 0 {
                opportunities_ms.len() as f64 * f64::from(*bytes_per_opportunity) * 8.0
                    / period as f64
            } else {
                0.0
            };
            format!(
                "trace[{} opp / {period} ms, mean {kbps:.0} kbps]",
                opportunities_ms.len()
            )
        }
    }
}

/// Parse a Mahimahi trace: one millisecond timestamp per line, blank lines and `#` comments
/// ignored. Timestamps must be non-decreasing and the last must be positive (it is the period).
pub fn parse_mahimahi(text: &str) -> anyhow::Result<Vec<u64>> {
    let mut out = Vec::new();
    for (n, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let v: u64 = line
            .parse()
            .map_err(|e| anyhow::anyhow!("trace line {}: {line:?}: {e}", n + 1))?;
        if out.last().is_some_and(|&last| v < last) {
            anyhow::bail!("trace line {}: {v} goes backwards", n + 1);
        }
        out.push(v);
    }
    if out.last().is_none_or(|&last| last == 0) {
        anyhow::bail!("trace is empty or its period (the last timestamp) is zero");
    }
    Ok(out)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::{parse_mahimahi, Capacity, Datagram, Link, LinkConfig, Loss, LossAt, QueueLimit};
    use crate::rng::SimRng;
    use std::net::SocketAddr;
    use std::time::Duration;

    fn dgram(len: usize) -> Datagram {
        let a: SocketAddr = "10.0.0.1:5000".parse().unwrap();
        let b: SocketAddr = "10.0.0.2:6000".parse().unwrap();
        Datagram {
            source: a,
            destination: b,
            contents: vec![0u8; len],
        }
    }

    fn link(cfg: LinkConfig, seed: u64) -> Link {
        let mut l = Link::new("test", cfg, SimRng::new(seed));
        l.set_ideal(false, Duration::ZERO);
        l
    }

    fn cfg(capacity: Capacity) -> LinkConfig {
        LinkConfig {
            capacity,
            delay: Duration::ZERO,
            queue: QueueLimit::Unlimited,
            loss: Loss::None,
            loss_at: LossAt::Arrival,
            jitter: Duration::ZERO,
            reorder: false,
            overhead_bytes: 0,
        }
    }

    fn drain(l: &mut Link) -> Vec<Duration> {
        let mut out = Vec::new();
        while let Some(t) = l.next_delivery() {
            let _ = l.pop_due(t).unwrap();
            out.push(t);
        }
        out
    }

    fn ms(v: f64) -> Duration {
        Duration::from_secs_f64(v / 1e3)
    }

    fn close(a: Duration, b: Duration) -> bool {
        a.abs_diff(b) < Duration::from_micros(1)
    }

    #[test]
    fn a_constant_capacity_serialises_packets_back_to_back() {
        // 1250 bytes at 1 Mbps is 10 ms each.
        let mut l = link(cfg(Capacity::Constant { kbps: 1_000.0 }), 1);
        for _ in 0..3 {
            l.send(Duration::ZERO, dgram(1250));
        }
        let got = drain(&mut l);
        assert_eq!(got.len(), 3);
        for (t, want) in got.iter().zip([10.0, 20.0, 30.0]) {
            assert!(close(*t, ms(want)), "{t:?} vs {want}");
        }
        // An idle link serves a late arrival at once.
        l.send(ms(100.0), dgram(1250));
        assert!(close(drain(&mut l)[0], ms(110.0)));
    }

    #[test]
    fn propagation_delay_is_added_after_the_bottleneck_and_overhead_counts() {
        let mut c = cfg(Capacity::Constant { kbps: 1_000.0 });
        c.delay = ms(50.0);
        c.overhead_bytes = 250; // 1000 + 250 = 1250 bytes on the wire
        let mut l = link(c, 1);
        l.send(Duration::ZERO, dgram(1000));
        l.send(Duration::ZERO, dgram(1000));
        let got = drain(&mut l);
        assert!(
            close(got[0], ms(60.0)) && close(got[1], ms(70.0)),
            "{got:?}"
        );
        assert_eq!(l.stats().delivered_bytes, 2500);
    }

    #[test]
    fn a_byte_limited_queue_drops_at_the_tail() {
        let mut c = cfg(Capacity::Constant { kbps: 1_000.0 });
        c.queue = QueueLimit::Bytes(3_000);
        let mut l = link(c, 1);
        for _ in 0..5 {
            l.send(Duration::ZERO, dgram(1250));
        }
        // 1250 and 2500 fit, 3750 does not; the rest are refused too.
        assert_eq!(l.stats().dropped_queue, 3);
        assert_eq!(drain(&mut l).len(), 2);
        // Once the first has left there is room again.
        let mut c = cfg(Capacity::Constant { kbps: 1_000.0 });
        c.queue = QueueLimit::Bytes(3_000);
        let mut l = link(c, 1);
        l.send(Duration::ZERO, dgram(1250));
        l.send(Duration::ZERO, dgram(1250));
        l.send(ms(10.0), dgram(1250));
        assert_eq!(l.stats().dropped_queue, 0);
    }

    #[test]
    fn a_delay_limited_queue_drops_what_would_wait_too_long() {
        let mut c = cfg(Capacity::Constant { kbps: 1_000.0 });
        c.queue = QueueLimit::Delay(ms(15.0));
        let mut l = link(c, 1);
        for _ in 0..3 {
            l.send(Duration::ZERO, dgram(1250));
        }
        // Waits of 0 and 10 ms are accepted; 20 ms is not.
        assert_eq!(l.stats().dropped_queue, 1);
        assert!(close(l.queue_delay(Duration::ZERO), ms(20.0)));
        assert_eq!(l.queued_bytes(Duration::ZERO), 2_500);
        assert_eq!(l.queued_bytes(ms(15.0)), 1_250);
    }

    #[test]
    fn loss_is_a_function_of_the_seed() {
        let run = |seed: u64| {
            let mut c = cfg(Capacity::Constant { kbps: 100_000.0 });
            c.loss = Loss::Bernoulli { p: 0.2 };
            let mut l = link(c, seed);
            let mut kept = Vec::new();
            for i in 0..2_000usize {
                let mut d = dgram(100);
                d.contents[0] = (i % 251) as u8;
                d.contents[1] = (i / 251) as u8;
                l.send(Duration::from_micros(i as u64 * 100), d);
            }
            while let Some(t) = l.next_delivery() {
                let d = l.pop_due(t).unwrap();
                kept.push(usize::from(d.contents[0]) + 251 * usize::from(d.contents[1]));
            }
            (kept, l.stats().dropped_loss)
        };
        let (a, lost_a) = run(9);
        let (b, lost_b) = run(9);
        assert_eq!(a, b, "same seed, same survivors");
        assert_eq!(lost_a, lost_b);
        assert!((300..500).contains(&lost_a), "{lost_a} of 2000 at p=0.2");
        let (c, _) = run(10);
        assert_ne!(a, c, "another seed, another pattern");
    }

    #[test]
    fn gilbert_elliott_loses_in_bursts_at_its_stationary_rate() {
        let mut c = cfg(Capacity::Constant { kbps: 100_000.0 });
        c.loss = Loss::GilbertElliott {
            p_good_to_bad: 0.01,
            p_bad_to_good: 0.25,
            loss_good: 0.0,
            loss_bad: 1.0,
        };
        let mut l = link(c, 3);
        let n = 200_000u64;
        let mut lost_run = 0u32;
        let mut runs = Vec::new();
        for i in 0..n {
            let before = l.stats().dropped_loss;
            l.send(Duration::from_micros(i * 10), dgram(50));
            if l.stats().dropped_loss > before {
                lost_run += 1;
            } else if lost_run > 0 {
                runs.push(lost_run);
                lost_run = 0;
            }
        }
        // Stationary P(bad) = 0.01 / (0.01 + 0.25) ≈ 3.85%; mean burst 1 / 0.25 = 4 packets.
        let rate = l.stats().dropped_loss as f64 / n as f64;
        assert!((0.03..0.047).contains(&rate), "loss rate {rate}");
        let mean_run = runs.iter().map(|&r| f64::from(r)).sum::<f64>() / runs.len() as f64;
        assert!((3.4..4.6).contains(&mean_run), "mean burst {mean_run}");
    }

    #[test]
    fn a_trace_serves_byte_credit_per_opportunity_and_repeats() {
        let c = cfg(Capacity::Trace {
            opportunities_ms: vec![1, 2, 3],
            bytes_per_opportunity: 1500,
        });
        let mut l = link(c, 1);
        l.send(Duration::ZERO, dgram(3000)); // opportunities at 1 and 2
        l.send(Duration::ZERO, dgram(100)); // shares opportunity 3 ...
        l.send(Duration::ZERO, dgram(100)); // ... with this one
        l.send(Duration::ZERO, dgram(1500)); // opportunity 3 has 1300 left: spills into 4
        let got = drain(&mut l);
        assert_eq!(got, vec![ms(2.0), ms(3.0), ms(3.0), ms(4.0)]);
        // Credit left over when the queue empties is wasted; a late arrival takes the next one.
        l.send(ms(4.5), dgram(100));
        assert_eq!(drain(&mut l), vec![ms(5.0)]);
        // The trace repeats with its last timestamp as the period: 7, 8, 9, 10, ...
        l.send(ms(6.2), dgram(100));
        assert_eq!(drain(&mut l), vec![ms(7.0)]);
    }

    #[test]
    fn a_piecewise_capacity_changes_rate_mid_packet() {
        let c = cfg(Capacity::Piecewise {
            steps: vec![(Duration::ZERO, 1_000.0), (ms(5.0), 2_000.0)],
        });
        let mut l = link(c, 1);
        // 10 000 bits: 5 000 in the first 5 ms at 1 Mbps, the rest in 2.5 ms at 2 Mbps.
        l.send(Duration::ZERO, dgram(1250));
        assert!(close(drain(&mut l)[0], ms(7.5)));
        // An outage holds packets until the rate comes back.
        let c = cfg(Capacity::Piecewise {
            steps: vec![
                (Duration::ZERO, 1_000.0),
                (ms(10.0), 0.0),
                (ms(100.0), 1_000.0),
            ],
        });
        let mut l = link(c, 1);
        l.send(ms(20.0), dgram(1250));
        assert!(close(drain(&mut l)[0], ms(110.0)));
    }

    #[test]
    fn jitter_without_reordering_keeps_send_order() {
        let mut c = cfg(Capacity::Constant { kbps: 100_000.0 });
        c.jitter = ms(30.0);
        let mut l = link(c, 5);
        for i in 0..500u64 {
            let mut d = dgram(200);
            d.contents[..8].copy_from_slice(&i.to_le_bytes());
            l.send(Duration::from_micros(i * 500), d);
        }
        let mut last = 0u64;
        let mut first = true;
        while let Some(t) = l.next_delivery() {
            let d = l.pop_due(t).unwrap();
            let mut b = [0u8; 8];
            b.copy_from_slice(&d.contents[..8]);
            let i = u64::from_le_bytes(b);
            assert!(first || i > last, "{i} after {last}");
            first = false;
            last = i;
        }
    }

    #[test]
    fn ideal_mode_is_a_fixed_delay_and_nothing_else() {
        let mut c = cfg(Capacity::Constant { kbps: 1.0 });
        c.delay = ms(40.0);
        c.loss = Loss::Bernoulli { p: 1.0 };
        let mut l = Link::new("ideal", c, SimRng::new(1));
        l.send(Duration::ZERO, dgram(1200));
        l.send(Duration::ZERO, dgram(1200));
        assert_eq!(drain(&mut l), vec![ms(40.0), ms(40.0)]);
        assert_eq!(l.stats().dropped_loss, 0);
    }

    #[test]
    fn mahimahi_traces_parse_and_bad_ones_are_refused() {
        assert_eq!(parse_mahimahi("1\n1\n# x\n\n5\n").unwrap(), vec![1, 1, 5]);
        assert!(parse_mahimahi("3\n2\n").is_err());
        assert!(parse_mahimahi("").is_err());
        assert!(parse_mahimahi("0\n0\n").is_err());
        assert!(parse_mahimahi("1\nx\n").is_err());
    }

    #[test]
    fn an_unlimited_capacity_is_delay_only_and_never_queues() {
        let mut c = cfg(Capacity::Unlimited);
        c.delay = ms(30.0);
        c.queue = QueueLimit::Delay(Duration::ZERO);
        let mut l = link(c, 1);
        for _ in 0..100 {
            l.send(ms(5.0), dgram(1200));
        }
        assert_eq!(l.stats().dropped_queue, 0, "nothing ever waits");
        let got = drain(&mut l);
        assert_eq!(got.len(), 100);
        assert!(got.iter().all(|t| close(*t, ms(35.0))), "{:?}", &got[..3]);
    }

    #[test]
    fn loss_after_the_bottleneck_still_spends_capacity() {
        // 1250 bytes at 1 Mbps is 10 ms each. Every packet is lost, but at the departure: each one
        // still occupies the bottleneck, so a survivor sent after them waits behind all of them.
        let mut c = cfg(Capacity::Constant { kbps: 1_000.0 });
        c.loss = Loss::Bernoulli { p: 1.0 };
        c.loss_at = LossAt::Departure;
        let mut l = link(c.clone(), 1);
        for _ in 0..3 {
            l.send(Duration::ZERO, dgram(1250));
        }
        assert_eq!(l.stats().dropped_loss, 3);
        assert!(close(l.queue_delay(Duration::ZERO), ms(30.0)));
        c.loss = Loss::None;
        l.reconfigure(c, Duration::ZERO);
        l.send(Duration::ZERO, dgram(1250));
        assert_eq!(drain(&mut l), vec![ms(40.0)]);

        // The same losses before the queue cost nothing.
        let mut c = cfg(Capacity::Constant { kbps: 1_000.0 });
        c.loss = Loss::Bernoulli { p: 1.0 };
        let mut l = link(c, 1);
        for _ in 0..3 {
            l.send(Duration::ZERO, dgram(1250));
        }
        assert_eq!(l.queue_delay(Duration::ZERO), Duration::ZERO);
    }

    #[test]
    fn a_reconfigured_rate_applies_from_the_next_arrival_and_keeps_fifo() {
        let mut l = link(cfg(Capacity::Constant { kbps: 1_000.0 }), 1);
        l.send(Duration::ZERO, dgram(1250)); // departs at 10 ms under the old rate
        let mut faster = cfg(Capacity::Constant { kbps: 10_000.0 });
        faster.delay = Duration::ZERO;
        l.reconfigure(faster, ms(1.0));
        l.send(ms(1.0), dgram(1250)); // waits for the server until 10 ms, then 1 ms at the new rate
        assert_eq!(drain(&mut l), vec![ms(10.0), ms(11.0)]);

        // A shorter delay never lets a later packet overtake an earlier one.
        let mut slow = cfg(Capacity::Unlimited);
        slow.delay = ms(100.0);
        let mut l = link(slow, 1);
        l.send(Duration::ZERO, dgram(100));
        let mut quick = cfg(Capacity::Unlimited);
        quick.delay = ms(10.0);
        l.reconfigure(quick, ms(1.0));
        l.send(ms(1.0), dgram(100));
        assert_eq!(drain(&mut l), vec![ms(100.0), ms(100.0)]);
        assert_eq!(l.in_flight_len(), 0);
    }
}
