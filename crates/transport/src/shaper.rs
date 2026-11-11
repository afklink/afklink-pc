//! In-process link shaper for the bench: the peer's own UDP socket, impaired on purpose.
//!
//! Active only when the CLI agent is started with `--link-profile` or `--link-control`; otherwise no
//! [`LinkShaper`] exists and the peer's socket is used directly (see `crate::socket`), so the product
//! pays one `match` per datagram for this module existing.
//!
//! It sits on the one UDP socket a peer owns, so everything str0m sends and receives and the srflx
//! STUN transaction (`crate::stun`) go through it: a blackout silences the STUN servers too. The
//! signaling WebSocket (TCP, another host) is not shaped.
//!
//! * **egress** (agent -> viewer, the media): a bottleneck of `rate_kbps` with a drop-tail queue of
//!   `queue_ms` of that rate or `queue_bytes`, then `delay_ms` + uniform `[0, jitter_ms]`, then
//!   random loss (`loss`, or a Gilbert-Elliott chain from `burst_loss`). Sizes count the IPv4 + UDP
//!   header (28 bytes), as a router's rate limit does.
//! * **ingress** (viewer -> agent: RTCP feedback, the data channels): delay, jitter and loss.
//! * **blackout**: every datagram dropped both ways, including those already in flight.
//!
//! The model is `afklink_netem::link::Link`, the simulator's, driven here by real time, so a
//! profile means the same in a simulated session and on the wire and the model's tests cover it.
//!
//! ## Real time
//!
//! The model fixes each datagram's delivery instant when it is accepted. Two plain threads per
//! shaped socket, one per direction, hand datagrams on at that instant — not tokio timers, which on
//! Windows can wake on the 15.6 ms system tick and would add jitter and burst the output. A std
//! `thread::sleep` uses a high-resolution waitable timer on Windows 10 1803+ and wakes within about
//! a millisecond without changing the process's timer resolution. Long waits park (a parked thread
//! can be woken early) and only the last stretch is slept. Egress: `send_to` feeds the model and the
//! thread hands the datagram to a tokio task for the real send. Ingress: a tokio task feeds the model
//! from the socket and the thread hands each datagram to the channel `recv_from` reads.
//!
//! Each direction is FIFO, so a thread only needs waking (`unpark`) when its direction goes from
//! empty to non-empty.
//!
//! One [`LinkShaper`] per process holds the profile in force and a generation counter. Every shaped
//! socket checks the generation on each datagram and reconfigures its model when it moved, so a
//! change written to the `--link-control` file reaches a live session within one poll (200 ms) plus
//! one datagram. Datagrams already accepted keep the timing they were given (see
//! `Link::reconfigure`); a blackout also drops those still in flight.

use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError};
use std::thread::{self, Thread};
use std::time::{Duration, Instant, SystemTime};

use afklink_netem::{Capacity, Datagram, Link, LinkConfig, Loss, LossAt, QueueLimit, SimRng};
use anyhow::{ensure, Context, Result};
use serde::{Deserialize, Serialize};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

/// How often the `--link-control` file's modification time is looked at.
pub const CONTROL_POLL: Duration = Duration::from_millis(200);

/// IPv4 + UDP header bytes, counted against the egress rate with every datagram.
const IP_UDP_OVERHEAD: u32 = 28;

/// The seed a profile gets when it names none. Fixed, so two runs with the same profile and the
/// same packet sequence drop the same packets.
pub const DEFAULT_SEED: u64 = 0x6265_6e63_685f_6c6e; // "bench_ln"

/// Stream constants, so egress and ingress draw independent sequences from one seed.
const EGRESS_STREAM: u64 = 0x4547_5245_5353_0001;
const INGRESS_STREAM: u64 = 0x494e_4752_4553_0002;

/// Sanity bounds: a profile beyond these is a typo, not a network.
const MAX_DELAY_MS: u64 = 60_000;
const MAX_QUEUE_MS: u64 = 60_000;

/// A thread whose direction is empty parks for at most this long, to notice a stop it was not
/// woken for (it always is; this is the belt).
const IDLE_PARK: Duration = Duration::from_millis(100);

/// Waits longer than this park (interruptibly, but on the coarse system tick) until
/// [`COARSE_MARGIN`] before the deadline; the rest is slept precisely.
const COARSE_WAIT: Duration = Duration::from_millis(20);
/// More than one 15.6 ms Windows tick, so a coarse park never oversleeps the deadline.
const COARSE_MARGIN: Duration = Duration::from_millis(17);

/// Receive buffer of the ingress reader: the largest UDP datagram, so nothing is truncated there.
const RECV_BUF: usize = 65_536;

// --------------------------------------------------------------------------------------------
// Profile
// --------------------------------------------------------------------------------------------

/// What the link does, as written in a `--link-profile` / `--link-control` JSON file.
///
/// ```json
/// {"egress":{"rate_kbps":800,"queue_ms":200,"queue_bytes":null,"delay_ms":40,"jitter_ms":5,
///            "loss":0.01,"burst_loss":{"p_good_to_bad":0.01,"p_bad_to_good":0.3,"loss_in_bad":0.5}},
///  "ingress":{"delay_ms":40,"jitter_ms":5,"loss":0.0},
///  "blackout":false}
/// ```
///
/// Every field may be omitted and means "no impairment"; an unknown field makes the file invalid
/// (a typo must not silently mean an unshaped link). `seed` is an optional extension to the bench
/// contract: the loss and jitter draws of every socket shaped while this profile is in force start
/// from it ([`DEFAULT_SEED`] when absent).
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LinkProfile {
    #[serde(default)]
    pub egress: EgressProfile,
    #[serde(default)]
    pub ingress: IngressProfile,
    #[serde(default)]
    pub blackout: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seed: Option<u64>,
}

/// Agent -> viewer.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EgressProfile {
    /// Bottleneck rate; `null` is no bottleneck.
    #[serde(default)]
    pub rate_kbps: Option<u64>,
    /// Drop-tail limit as the wait before service, in ms of the rate. Exclusive with `queue_bytes`.
    #[serde(default)]
    pub queue_ms: Option<u64>,
    /// Drop-tail limit in bytes waiting (headers included). Exclusive with `queue_ms`.
    #[serde(default)]
    pub queue_bytes: Option<u64>,
    #[serde(default)]
    pub delay_ms: u64,
    #[serde(default)]
    pub jitter_ms: u64,
    /// Bernoulli loss; with `burst_loss`, the loss probability in the chain's good state.
    #[serde(default)]
    pub loss: f64,
    #[serde(default)]
    pub burst_loss: Option<BurstLoss>,
}

/// A Gilbert-Elliott chain: stepped per datagram, lose with `loss_in_bad` in the bad state and with
/// the direction's `loss` in the good one. Mean burst length is `1 / p_bad_to_good` datagrams.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BurstLoss {
    pub p_good_to_bad: f64,
    pub p_bad_to_good: f64,
    pub loss_in_bad: f64,
}

/// Viewer -> agent.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IngressProfile {
    #[serde(default)]
    pub delay_ms: u64,
    #[serde(default)]
    pub jitter_ms: u64,
    #[serde(default)]
    pub loss: f64,
}

fn probability(v: f64, what: &str) -> Result<()> {
    ensure!(
        v.is_finite() && (0.0..=1.0).contains(&v),
        "{what} must be in [0, 1], got {v}"
    );
    Ok(())
}

fn ms(v: u64) -> Duration {
    Duration::from_millis(v)
}

impl LinkProfile {
    /// Parse and validate a profile from JSON text. A leading UTF-8 byte-order mark is ignored:
    /// PowerShell's `Out-File` writes one, and the harness runs on Windows.
    pub fn parse(text: &str) -> Result<Self> {
        let text = text.trim_start_matches('\u{feff}');
        let profile: Self = serde_json::from_str(text).context("not a valid link profile")?;
        profile.validate()?;
        Ok(profile)
    }

    /// Read, parse and validate a profile file.
    pub fn load(path: &Path) -> Result<Self> {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
        Self::parse(&text).with_context(|| format!("link profile {}", path.display()))
    }

    /// The limits a profile has to respect to mean a network rather than a typo.
    pub fn validate(&self) -> Result<()> {
        let e = &self.egress;
        ensure!(
            !(e.queue_ms.is_some() && e.queue_bytes.is_some()),
            "egress: give queue_ms or queue_bytes, not both"
        );
        if let Some(rate) = e.rate_kbps {
            ensure!(
                rate > 0,
                "egress.rate_kbps must be positive (null is no bottleneck, blackout is an outage)"
            );
        }
        if let Some(q) = e.queue_ms {
            ensure!(
                q <= MAX_QUEUE_MS,
                "egress.queue_ms {q} exceeds {MAX_QUEUE_MS}"
            );
        }
        for (v, what) in [
            (e.delay_ms, "egress.delay_ms"),
            (e.jitter_ms, "egress.jitter_ms"),
            (self.ingress.delay_ms, "ingress.delay_ms"),
            (self.ingress.jitter_ms, "ingress.jitter_ms"),
        ] {
            ensure!(v <= MAX_DELAY_MS, "{what} {v} exceeds {MAX_DELAY_MS}");
        }
        probability(e.loss, "egress.loss")?;
        if let Some(b) = e.burst_loss {
            probability(b.p_good_to_bad, "egress.burst_loss.p_good_to_bad")?;
            probability(b.p_bad_to_good, "egress.burst_loss.p_bad_to_good")?;
            probability(b.loss_in_bad, "egress.burst_loss.loss_in_bad")?;
        }
        probability(self.ingress.loss, "ingress.loss")?;
        Ok(())
    }

    /// Nothing is impaired: what a missing or invalid profile falls back to at start.
    #[must_use]
    pub fn is_passthrough(&self) -> bool {
        let clean = LinkProfile {
            seed: self.seed,
            ..LinkProfile::default()
        };
        *self == clean
    }

    /// The model configuration of the agent -> viewer direction.
    #[must_use]
    pub fn egress_config(&self) -> LinkConfig {
        let e = &self.egress;
        LinkConfig {
            capacity: e
                .rate_kbps
                .map_or(Capacity::Unlimited, |kbps| Capacity::Constant {
                    kbps: kbps as f64,
                }),
            delay: ms(e.delay_ms),
            queue: match (e.queue_ms, e.queue_bytes) {
                (Some(q), _) => QueueLimit::Delay(ms(q)),
                (_, Some(b)) => QueueLimit::Bytes(b),
                _ => QueueLimit::Unlimited,
            },
            loss: match e.burst_loss {
                Some(b) => Loss::GilbertElliott {
                    p_good_to_bad: b.p_good_to_bad,
                    p_bad_to_good: b.p_bad_to_good,
                    loss_good: e.loss,
                    loss_bad: b.loss_in_bad,
                },
                None if e.loss > 0.0 => Loss::Bernoulli { p: e.loss },
                None => Loss::None,
            },
            // "a bottleneck ... then delay/jitter/loss": a lost datagram has used the bottleneck.
            loss_at: LossAt::Departure,
            jitter: ms(e.jitter_ms),
            reorder: false,
            overhead_bytes: IP_UDP_OVERHEAD,
        }
    }

    /// The model configuration of the viewer -> agent direction: no bottleneck.
    #[must_use]
    pub fn ingress_config(&self) -> LinkConfig {
        let i = &self.ingress;
        LinkConfig {
            capacity: Capacity::Unlimited,
            delay: ms(i.delay_ms),
            queue: QueueLimit::Unlimited,
            loss: if i.loss > 0.0 {
                Loss::Bernoulli { p: i.loss }
            } else {
                Loss::None
            },
            loss_at: LossAt::Departure,
            jitter: ms(i.jitter_ms),
            reorder: false,
            overhead_bytes: IP_UDP_OVERHEAD,
        }
    }
}

impl fmt::Display for LinkProfile {
    /// One line, every value, for the log: `egress[rate=800kbps queue=200ms delay=40ms jitter=5ms
    /// loss=0.0100 burst=-] ingress[delay=40ms jitter=5ms loss=0.0000] blackout=false seed=-`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let e = &self.egress;
        let rate = e
            .rate_kbps
            .map_or_else(|| "unlimited".to_string(), |r| format!("{r}kbps"));
        let queue = match (e.queue_ms, e.queue_bytes) {
            (Some(q), _) => format!("{q}ms"),
            (_, Some(b)) => format!("{b}B"),
            _ => "unlimited".to_string(),
        };
        let burst = e.burst_loss.map_or_else(
            || "-".to_string(),
            |b| {
                format!(
                    "(g2b={:.4},b2g={:.4},bad={:.4})",
                    b.p_good_to_bad, b.p_bad_to_good, b.loss_in_bad
                )
            },
        );
        let seed = self.seed.map_or_else(|| "-".to_string(), |s| s.to_string());
        write!(
            f,
            "egress[rate={rate} queue={queue} delay={}ms jitter={}ms loss={:.4} burst={burst}] \
             ingress[delay={}ms jitter={}ms loss={:.4}] blackout={} seed={seed}",
            e.delay_ms,
            e.jitter_ms,
            e.loss,
            self.ingress.delay_ms,
            self.ingress.jitter_ms,
            self.ingress.loss,
            self.blackout
        )
    }
}

// --------------------------------------------------------------------------------------------
// The shared handle
// --------------------------------------------------------------------------------------------

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    // No invariant here that a panic mid-update could break: a profile is replaced whole, and the
    // model's state is valid between any two of its calls.
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The profile in force for the whole process, shared by every shaped socket.
///
/// Created by the CLI when a link flag is given; handed to the orchestrator, which passes it to
/// every peer it spawns (`crate::spawn_peer_with`).
#[derive(Debug)]
pub struct LinkShaper {
    profile: Mutex<LinkProfile>,
    /// Bumped on every change; sockets compare it per datagram.
    generation: AtomicU64,
    /// Sockets wrapped so far, for their log names.
    sockets: AtomicU64,
}

impl LinkShaper {
    /// A shaper starting at `initial`.
    #[must_use]
    pub fn new(initial: LinkProfile) -> Arc<Self> {
        tracing::info!(profile = %initial, "link shaper active on every peer socket");
        Arc::new(Self {
            profile: Mutex::new(initial),
            generation: AtomicU64::new(0),
            sockets: AtomicU64::new(0),
        })
    }

    /// The profile in force.
    #[must_use]
    pub fn profile(&self) -> LinkProfile {
        lock(&self.profile).clone()
    }

    /// How many times the profile has changed.
    #[must_use]
    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }

    /// Replace the profile. One info line with the old and the new values when it changed; a debug
    /// line when it did not. Returns whether it changed.
    pub fn set_profile(&self, new: LinkProfile, source: &str) -> bool {
        let old = {
            let mut p = lock(&self.profile);
            if *p == new {
                tracing::debug!(source, profile = %new, "link profile re-read: unchanged");
                return false;
            }
            std::mem::replace(&mut *p, new.clone())
        };
        let generation = self.generation.fetch_add(1, Ordering::AcqRel) + 1;
        tracing::info!(
            source,
            generation,
            old = %old,
            new = %new,
            "link profile changed"
        );
        true
    }

    /// Read `path` and make it the profile. A file that is missing or invalid is a warning, and the
    /// profile in force stays. Returns whether the profile changed.
    pub fn apply_file(&self, path: &Path, source: &str) -> bool {
        match LinkProfile::load(path) {
            Ok(p) => self.set_profile(p, source),
            Err(e) => {
                tracing::warn!(
                    source,
                    path = %path.display(),
                    keeping = %self.profile(),
                    "link profile not applied: {e:#}"
                );
                false
            }
        }
    }

    /// Watch `path` for changes (modification time and size, every [`CONTROL_POLL`]) and apply each
    /// one. The first look applies the file if it exists. Runs until the runtime stops.
    pub fn watch_control_file(self: &Arc<Self>, path: PathBuf) -> tokio::task::JoinHandle<()> {
        let shaper = self.clone();
        tokio::spawn(async move { watch(shaper, path).await })
    }
}

/// What identifies one version of the control file on disk.
type Stamp = (Option<SystemTime>, u64);

fn stamp(path: &Path) -> io::Result<Stamp> {
    let meta = std::fs::metadata(path)?;
    Ok((meta.modified().ok(), meta.len()))
}

async fn watch(shaper: Arc<LinkShaper>, path: PathBuf) {
    tracing::info!(
        path = %path.display(),
        poll_ms = CONTROL_POLL.as_millis() as u64,
        "watching the link control file"
    );
    let mut tick = tokio::time::interval(CONTROL_POLL);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut seen: Option<Stamp> = None;
    // Said once per episode rather than every 200 ms.
    let mut unreadable_said = false;
    // A file caught half-written parses as garbage and may not change again afterwards; one
    // retry on the next poll catches the finished version.
    let mut retry = false;
    loop {
        tick.tick().await;
        match stamp(&path) {
            Ok(st) => {
                if unreadable_said {
                    tracing::info!(path = %path.display(), "link control file is readable again");
                    unreadable_said = false;
                }
                let changed = seen != Some(st);
                if changed || retry {
                    tracing::debug!(
                        path = %path.display(),
                        changed,
                        retry,
                        bytes = st.1,
                        "link control file: reading"
                    );
                    seen = Some(st);
                    retry = match LinkProfile::load(&path) {
                        Ok(p) => {
                            shaper.set_profile(p, "link-control");
                            false
                        }
                        // The first failure of a change is retried quietly once; a second one is
                        // the file's real content and is said.
                        Err(e) if changed => {
                            tracing::debug!(
                                path = %path.display(),
                                "link control file did not parse; retrying once in case it was \
                                 caught mid-write: {e:#}"
                            );
                            true
                        }
                        Err(e) => {
                            tracing::warn!(
                                path = %path.display(),
                                keeping = %shaper.profile(),
                                "link control file is invalid; the profile in force stays: {e:#}"
                            );
                            false
                        }
                    };
                }
            }
            Err(e) => {
                if !unreadable_said {
                    tracing::warn!(
                        path = %path.display(),
                        keeping = %shaper.profile(),
                        "link control file cannot be read ({e}); the profile in force stays until \
                         it can"
                    );
                    unreadable_said = true;
                }
                // Reappearing with the same stamp still counts as a change.
                seen = None;
                retry = false;
            }
        }
    }
}

// --------------------------------------------------------------------------------------------
// The shaped socket
// --------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Dir {
    Egress,
    Ingress,
}

impl Dir {
    fn as_str(self) -> &'static str {
        match self {
            Dir::Egress => "egress",
            Dir::Ingress => "ingress",
        }
    }
}

/// Counters beyond the model's own, for the once-a-second line.
#[derive(Debug, Default)]
struct Window {
    eg_in_packets: u64,
    eg_in_bytes: u64,
    eg_out_packets: u64,
    eg_out_bytes: u64,
    eg_blackout: u64,
    in_in_packets: u64,
    in_in_bytes: u64,
    in_out_packets: u64,
    in_out_bytes: u64,
    in_blackout: u64,
    send_errors: u64,
    last_send_error: Option<String>,
    recv_errors: u64,
    last_recv_error: Option<String>,
}

impl Window {
    fn is_quiet(&self) -> bool {
        self.eg_in_packets
            + self.eg_out_packets
            + self.eg_blackout
            + self.in_in_packets
            + self.in_out_packets
            + self.in_blackout
            + self.send_errors
            + self.recv_errors
            == 0
    }
}

/// Totals for the socket's life, for its last line.
#[derive(Debug, Default, Clone, Copy)]
struct Totals {
    eg_blackout: u64,
    in_blackout: u64,
    send_errors: u64,
    recv_errors: u64,
}

struct State {
    generation: u64,
    blackout: bool,
    egress: Link,
    ingress: Link,
    window: Window,
    window_start: Instant,
    totals: Totals,
}

struct Inner {
    name: String,
    local: SocketAddr,
    shared: Arc<LinkShaper>,
    epoch: Instant,
    state: Mutex<State>,
    stop: AtomicBool,
    egress_thread: OnceLock<Thread>,
    ingress_thread: OnceLock<Thread>,
}

impl Inner {
    /// The model's clock: time since this socket was wrapped.
    fn now(&self) -> Duration {
        self.epoch.elapsed()
    }

    /// Adopt the process's profile if it changed since this socket last looked.
    fn refresh(&self, st: &mut State) {
        let generation = self.shared.generation();
        if generation == st.generation {
            return;
        }
        let profile = self.shared.profile();
        let now = self.now();
        st.egress.reconfigure(profile.egress_config(), now);
        st.ingress.reconfigure(profile.ingress_config(), now);
        if st.blackout != profile.blackout {
            tracing::debug!(
                socket = %self.name,
                blackout = profile.blackout,
                in_flight_egress = st.egress.in_flight_len(),
                in_flight_ingress = st.ingress.in_flight_len(),
                "link shaper: blackout {}",
                if profile.blackout {
                    "begins; everything in flight is dropped as it comes due"
                } else {
                    "ends"
                }
            );
        }
        st.blackout = profile.blackout;
        st.generation = generation;
        tracing::debug!(
            socket = %self.name,
            generation,
            profile = %profile,
            "link profile applied to this socket"
        );
    }

    fn unpark(&self, dir: Dir) {
        let slot = match dir {
            Dir::Egress => &self.egress_thread,
            Dir::Ingress => &self.ingress_thread,
        };
        match slot.get() {
            Some(t) => t.unpark(),
            None => {
                tracing::trace!(socket = %self.name, dir = dir.as_str(), "no thread to wake yet")
            }
        }
    }

    /// The once-a-second line. Quiet seconds are not logged. The counters are taken under the lock
    /// and logged after it is released, so a slow log sink never holds up the datagrams.
    fn report(&self) {
        let (w, eg, ing, queued, queue_delay, blackout, secs) = {
            let mut guard = lock(&self.state);
            let st = &mut *guard;
            let now = self.now();
            let secs = st.window_start.elapsed().as_secs_f64().max(1e-3);
            st.window_start = Instant::now();
            (
                std::mem::take(&mut st.window),
                st.egress.take_window(),
                st.ingress.take_window(),
                st.egress.queued_bytes(now),
                st.egress.queue_delay(now),
                st.blackout,
                secs,
            )
        };
        if w.is_quiet() && eg == Default::default() && ing == Default::default() && queued == 0 {
            return;
        }
        let kbps = |bytes: u64| format!("{:.0}", bytes as f64 * 8.0 / secs / 1000.0);
        tracing::debug!(
            socket = %self.name,
            blackout,
            eg_in = w.eg_in_packets,
            eg_in_kbps = %kbps(w.eg_in_bytes),
            eg_out = w.eg_out_packets,
            eg_out_kbps = %kbps(w.eg_out_bytes),
            eg_queued_bytes = queued,
            eg_queue_ms = queue_delay.as_millis() as u64,
            eg_max_sojourn_ms = eg.max_sojourn.as_millis() as u64,
            eg_drop_queue = eg.dropped_queue,
            eg_drop_loss = eg.dropped_loss,
            eg_drop_blackout = w.eg_blackout,
            in_in = w.in_in_packets,
            in_in_kbps = %kbps(w.in_in_bytes),
            in_out = w.in_out_packets,
            in_drop_loss = ing.dropped_loss,
            in_drop_blackout = w.in_blackout,
            send_errors = w.send_errors,
            last_send_error = w.last_send_error.as_deref().unwrap_or("-"),
            recv_errors = w.recv_errors,
            last_recv_error = w.last_recv_error.as_deref().unwrap_or("-"),
            "link shaper"
        );
    }
}

/// A peer socket behind the link shaper. See the module documentation.
pub(crate) struct ShapedSocket {
    inner: Arc<Inner>,
    ingress_rx: mpsc::UnboundedReceiver<io::Result<(Vec<u8>, SocketAddr)>>,
    reader: tokio::task::JoinHandle<()>,
    /// Said once: a closed ingress channel means the shaper's machinery died, which is a bug.
    dead_said: bool,
}

impl ShapedSocket {
    /// Wrap `socket`, starting at the process's current profile. Must be called inside a tokio
    /// runtime (it spawns the reader and writer tasks).
    pub(crate) fn new(socket: UdpSocket, shaper: Arc<LinkShaper>) -> io::Result<Self> {
        let local = socket.local_addr()?;
        let index = shaper.sockets.fetch_add(1, Ordering::Relaxed);
        let generation = shaper.generation();
        let profile = shaper.profile();
        let seed = profile.seed.unwrap_or(DEFAULT_SEED);
        let epoch = Instant::now();
        let mut egress = Link::new(
            "egress",
            profile.egress_config(),
            SimRng::derive(seed, EGRESS_STREAM),
        );
        egress.set_ideal(false, Duration::ZERO);
        let mut ingress = Link::new(
            "ingress",
            profile.ingress_config(),
            SimRng::derive(seed, INGRESS_STREAM),
        );
        ingress.set_ideal(false, Duration::ZERO);
        let name = format!("udp:{}#{index}", local.port());
        let inner = Arc::new(Inner {
            name: name.clone(),
            local,
            shared: shaper,
            epoch,
            state: Mutex::new(State {
                generation,
                blackout: profile.blackout,
                egress,
                ingress,
                window: Window::default(),
                window_start: Instant::now(),
                totals: Totals::default(),
            }),
            stop: AtomicBool::new(false),
            egress_thread: OnceLock::new(),
            ingress_thread: OnceLock::new(),
        });
        let socket = Arc::new(socket);

        let (out_tx, out_rx) = mpsc::unbounded_channel::<(Vec<u8>, SocketAddr)>();
        let (in_tx, ingress_rx) = mpsc::unbounded_channel();

        let egress = {
            let inner = inner.clone();
            thread::Builder::new()
                .name(format!("shaper-egress-{}", local.port()))
                .spawn(move || {
                    pump(&inner, Dir::Egress, |d| {
                        out_tx.send((d.contents, d.destination)).is_ok()
                    })
                })?
        };
        // Set exactly once, here, before anything can send: a second set cannot happen.
        if inner.egress_thread.set(egress.thread().clone()).is_err() {
            tracing::debug!(socket = %name, "egress thread handle was already set");
        }
        let ingress = {
            let inner = inner.clone();
            let in_tx = in_tx.clone();
            thread::Builder::new()
                .name(format!("shaper-ingress-{}", local.port()))
                .spawn(move || {
                    pump(&inner, Dir::Ingress, |d| {
                        in_tx.send(Ok((d.contents, d.source))).is_ok()
                    })
                })?
        };
        if inner.ingress_thread.set(ingress.thread().clone()).is_err() {
            tracing::debug!(socket = %name, "ingress thread handle was already set");
        }

        tokio::spawn(writer(socket.clone(), out_rx, inner.clone()));
        let reader = tokio::spawn(reader(socket, inner.clone(), in_tx));

        tracing::info!(
            socket = %name,
            %local,
            seed,
            generation,
            profile = %profile,
            "link shaper wraps this peer's socket"
        );
        Ok(Self {
            inner,
            ingress_rx,
            reader,
            dead_said: false,
        })
    }

    /// Hand a datagram to the egress model. It leaves the real socket when the model says; a
    /// datagram dropped by the queue, by loss or by a blackout is reported sent, as a network
    /// would have it.
    pub(crate) fn send_to(&self, buf: &[u8], to: SocketAddr) -> io::Result<usize> {
        let inner = &self.inner;
        let wake = {
            let mut guard = lock(&inner.state);
            let st = &mut *guard;
            inner.refresh(st);
            st.window.eg_in_packets += 1;
            st.window.eg_in_bytes += buf.len() as u64;
            if st.blackout {
                st.window.eg_blackout += 1;
                st.totals.eg_blackout += 1;
                tracing::trace!(socket = %inner.name, bytes = buf.len(), %to, "egress: blackout drop");
                return Ok(buf.len());
            }
            let was_idle = st.egress.next_delivery().is_none();
            st.egress.send(
                inner.now(),
                Datagram {
                    source: inner.local,
                    destination: to,
                    contents: buf.to_vec(),
                },
            );
            was_idle && st.egress.next_delivery().is_some()
        };
        if wake {
            inner.unpark(Dir::Egress);
        }
        Ok(buf.len())
    }

    /// The next datagram the ingress model has delivered.
    pub(crate) async fn recv_from(&mut self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        match self.ingress_rx.recv().await {
            Some(Ok((data, from))) => {
                let n = data.len().min(buf.len());
                buf[..n].copy_from_slice(&data[..n]);
                if data.len() > buf.len() {
                    tracing::debug!(
                        socket = %self.inner.name,
                        bytes = data.len(),
                        kept = n,
                        %from,
                        "ingress datagram larger than the caller's buffer; truncated"
                    );
                }
                Ok((n, from))
            }
            Some(Err(e)) => Err(e),
            None => {
                if !self.dead_said {
                    self.dead_said = true;
                    tracing::error!(
                        socket = %self.inner.name,
                        "link shaper's ingress machinery stopped while the peer still runs; nothing \
                         more will be received on this socket"
                    );
                }
                // Returning an error here would spin the caller's receive loop; this socket is
                // deaf now, as a socket whose network vanished is.
                std::future::pending().await
            }
        }
    }
}

impl Drop for ShapedSocket {
    fn drop(&mut self) {
        let inner = &self.inner;
        inner.stop.store(true, Ordering::Release);
        inner.unpark(Dir::Egress);
        inner.unpark(Dir::Ingress);
        self.reader.abort();
        let (eg, ing, totals, in_flight) = {
            let st = lock(&inner.state);
            (
                st.egress.stats().clone(),
                st.ingress.stats().clone(),
                st.totals,
                st.egress.in_flight_len(),
            )
        };
        tracing::debug!(
            socket = %inner.name,
            lived_s = format!("{:.1}", inner.epoch.elapsed().as_secs_f64()),
            eg_sent = eg.sent_packets,
            eg_delivered = eg.delivered_packets,
            eg_drop_queue = eg.dropped_queue,
            eg_drop_loss = eg.dropped_loss,
            eg_drop_blackout = totals.eg_blackout,
            eg_max_sojourn_ms = eg.max_sojourn.as_millis() as u64,
            eg_in_flight = in_flight,
            in_received = ing.sent_packets,
            in_delivered = ing.delivered_packets,
            in_drop_loss = ing.dropped_loss,
            in_drop_blackout = totals.in_blackout,
            send_errors = totals.send_errors,
            recv_errors = totals.recv_errors,
            "link shaper released this socket: totals"
        );
    }
}

/// One direction's thread: hand on every datagram the model says is due, then wait for the next.
fn pump(inner: &Inner, dir: Dir, mut deliver: impl FnMut(Datagram) -> bool) {
    tracing::debug!(socket = %inner.name, dir = dir.as_str(), "link shaper thread started");
    let mut due: Vec<Datagram> = Vec::new();
    loop {
        if inner.stop.load(Ordering::Acquire) {
            break;
        }
        let next = {
            let mut guard = lock(&inner.state);
            let st = &mut *guard;
            inner.refresh(st);
            let now = inner.now();
            let link = match dir {
                Dir::Egress => &mut st.egress,
                Dir::Ingress => &mut st.ingress,
            };
            while let Some(d) = link.pop_due(now) {
                due.push(d);
            }
            let next = link.next_delivery().map(|t| t.saturating_sub(now));
            let packets = due.len() as u64;
            let bytes: u64 = due.iter().map(|d| d.contents.len() as u64).sum();
            match (dir, st.blackout) {
                (_, true) if packets > 0 => {
                    tracing::trace!(
                        socket = %inner.name,
                        dir = dir.as_str(),
                        packets,
                        "blackout: in-flight datagrams dropped as they came due"
                    );
                    match dir {
                        Dir::Egress => {
                            st.window.eg_blackout += packets;
                            st.totals.eg_blackout += packets;
                        }
                        Dir::Ingress => {
                            st.window.in_blackout += packets;
                            st.totals.in_blackout += packets;
                        }
                    }
                    due.clear();
                }
                (_, true) => {}
                (Dir::Egress, false) => {
                    st.window.eg_out_packets += packets;
                    st.window.eg_out_bytes += bytes;
                }
                (Dir::Ingress, false) => {
                    st.window.in_out_packets += packets;
                    st.window.in_out_bytes += bytes;
                }
            }
            next
        };
        for d in due.drain(..) {
            if !deliver(d) {
                tracing::debug!(
                    socket = %inner.name,
                    dir = dir.as_str(),
                    "link shaper thread: its consumer is gone; stopping"
                );
                return;
            }
        }
        wait(next);
    }
    tracing::debug!(socket = %inner.name, dir = dir.as_str(), "link shaper thread stopped");
}

/// Wait until the next delivery (see [`COARSE_WAIT`]), or until woken when there is none.
fn wait(next: Option<Duration>) {
    match next {
        None => thread::park_timeout(IDLE_PARK),
        Some(d) if d > COARSE_WAIT => thread::park_timeout(d - COARSE_MARGIN),
        Some(d) if !d.is_zero() => thread::sleep(d),
        Some(_) => {}
    }
}

/// Egress, last step: the real `send_to`, when the model released the datagram.
async fn writer(
    socket: Arc<UdpSocket>,
    mut rx: mpsc::UnboundedReceiver<(Vec<u8>, SocketAddr)>,
    inner: Arc<Inner>,
) {
    while let Some((bytes, to)) = rx.recv().await {
        if let Err(e) = socket.send_to(&bytes, to).await {
            tracing::trace!(socket = %inner.name, %to, "shaped udp send failed: {e}");
            let mut st = lock(&inner.state);
            st.window.send_errors += 1;
            st.window.last_send_error = Some(format!("{e} (to {to})"));
            st.totals.send_errors += 1;
        }
    }
    tracing::debug!(socket = %inner.name, "link shaper writer stopped");
}

/// Ingress, first step: the real socket into the model. Also writes the once-a-second line.
async fn reader(
    socket: Arc<UdpSocket>,
    inner: Arc<Inner>,
    tx: mpsc::UnboundedSender<io::Result<(Vec<u8>, SocketAddr)>>,
) {
    let mut buf = vec![0u8; RECV_BUF];
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    tick.tick().await;
    loop {
        tokio::select! {
            res = socket.recv_from(&mut buf) => match res {
                Ok((n, from)) => {
                    let wake = {
                        let mut guard = lock(&inner.state);
                        let st = &mut *guard;
                        inner.refresh(st);
                        st.window.in_in_packets += 1;
                        st.window.in_in_bytes += n as u64;
                        if st.blackout {
                            st.window.in_blackout += 1;
                            st.totals.in_blackout += 1;
                            tracing::trace!(socket = %inner.name, bytes = n, %from, "ingress: blackout drop");
                            false
                        } else {
                            let was_idle = st.ingress.next_delivery().is_none();
                            st.ingress.send(
                                inner.now(),
                                Datagram { source: from, destination: inner.local, contents: buf[..n].to_vec() },
                            );
                            was_idle && st.ingress.next_delivery().is_some()
                        }
                    };
                    if wake {
                        inner.unpark(Dir::Ingress);
                    }
                }
                Err(e) => {
                    let blackout = {
                        let mut st = lock(&inner.state);
                        st.window.recv_errors += 1;
                        st.window.last_recv_error = Some(e.to_string());
                        st.totals.recv_errors += 1;
                        st.blackout
                    };
                    if blackout {
                        // An ICMP error is a message from the network too.
                        tracing::trace!(socket = %inner.name, "receive error during a blackout; dropped: {e}");
                    } else {
                        // Passed on as it is, as the socket itself would have: the peer loop and the
                        // STUN transaction each know what a reset means to them.
                        tracing::trace!(socket = %inner.name, "receive error passed on: {e}");
                        if tx.send(Err(e)).is_err() {
                            tracing::debug!(socket = %inner.name, "link shaper reader: the peer is gone; stopping");
                            return;
                        }
                    }
                    // A persistent error must not turn this into a busy loop.
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
            },
            _ = tick.tick() => inner.report(),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;

    const CONTRACT_EXAMPLE: &str = r#"{"egress":{"rate_kbps":800,"queue_ms":200,"queue_bytes":null,
        "delay_ms":40,"jitter_ms":5,"loss":0.01,
        "burst_loss":{"p_good_to_bad":0.01,"p_bad_to_good":0.3,"loss_in_bad":0.5}},
        "ingress":{"delay_ms":30,"jitter_ms":2,"loss":0.02},"blackout":false}"#;

    #[test]
    fn the_contract_schema_parses_and_maps_onto_the_model() {
        let p = LinkProfile::parse(CONTRACT_EXAMPLE).unwrap();
        assert_eq!(p.egress.rate_kbps, Some(800));
        let eg = p.egress_config();
        assert_eq!(eg.capacity, Capacity::Constant { kbps: 800.0 });
        assert_eq!(eg.queue, QueueLimit::Delay(Duration::from_millis(200)));
        assert_eq!(eg.delay, Duration::from_millis(40));
        assert_eq!(eg.jitter, Duration::from_millis(5));
        assert_eq!(eg.loss_at, LossAt::Departure);
        assert_eq!(eg.overhead_bytes, 28);
        assert_eq!(
            eg.loss,
            Loss::GilbertElliott {
                p_good_to_bad: 0.01,
                p_bad_to_good: 0.3,
                loss_good: 0.01,
                loss_bad: 0.5
            }
        );
        let ing = p.ingress_config();
        assert_eq!(ing.capacity, Capacity::Unlimited);
        assert_eq!(ing.queue, QueueLimit::Unlimited);
        assert_eq!(ing.loss, Loss::Bernoulli { p: 0.02 });
        assert_eq!(ing.delay, Duration::from_millis(30));
        assert!(!p.is_passthrough());
        let shown = p.to_string();
        assert!(
            shown.contains("rate=800kbps") && shown.contains("queue=200ms"),
            "{shown}"
        );

        // Nulls and omissions are no impairment; a BOM is ignored.
        let p = LinkProfile::parse(
            "\u{feff}{\"egress\":{\"rate_kbps\":null,\"queue_ms\":null,\"queue_bytes\":null,\
             \"delay_ms\":0,\"jitter_ms\":0,\"loss\":0,\"burst_loss\":null},\
             \"ingress\":{\"delay_ms\":0,\"jitter_ms\":0,\"loss\":0},\"blackout\":false}",
        )
        .unwrap();
        assert!(p.is_passthrough());
        assert_eq!(p.egress_config().capacity, Capacity::Unlimited);
        assert_eq!(p.egress_config().loss, Loss::None);
        assert!(LinkProfile::parse("{}").unwrap().is_passthrough());
        let bytes =
            LinkProfile::parse(r#"{"egress":{"rate_kbps":500,"queue_bytes":30000}}"#).unwrap();
        assert_eq!(bytes.egress_config().queue, QueueLimit::Bytes(30_000));
    }

    #[test]
    fn bad_profiles_are_refused() {
        for bad in [
            r#"{"egress":{"rate_kbps":800,"queue_ms":100,"queue_bytes":1000}}"#,
            r#"{"egress":{"loss":1.5}}"#,
            r#"{"ingress":{"loss":-0.1}}"#,
            r#"{"egress":{"delay_ms":-5}}"#,
            r#"{"egress":{"rate_kbps":0}}"#,
            r#"{"egress":{"rat_kbps":800}}"#,
            r#"{"blackout":false,"extra":1}"#,
            r#"{"egress":{"burst_loss":{"p_good_to_bad":0.1,"p_bad_to_good":2,"loss_in_bad":1}}}"#,
            r#"{"egress":{"delay_ms":600000}}"#,
            "not json",
        ] {
            assert!(LinkProfile::parse(bad).is_err(), "{bad} should be refused");
        }
    }

    fn temp_file(name: &str) -> PathBuf {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let nanos = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let dir = std::env::temp_dir().join(format!(
            "afklink-shaper-{}-{nanos}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir.join(name)
    }

    #[test]
    fn a_change_bumps_the_generation_and_a_bad_file_keeps_the_profile() {
        let shaper = LinkShaper::new(LinkProfile::default());
        assert_eq!(shaper.generation(), 0);
        let blackout = LinkProfile {
            blackout: true,
            ..LinkProfile::default()
        };
        assert!(shaper.set_profile(blackout.clone(), "test"));
        assert_eq!(shaper.generation(), 1);
        assert!(!shaper.set_profile(blackout.clone(), "test"), "unchanged");
        assert_eq!(shaper.generation(), 1);

        let path = temp_file("bad.json");
        std::fs::write(&path, r#"{"egress":{"loss":7}}"#).unwrap();
        assert!(!shaper.apply_file(&path, "test"));
        assert!(!shaper.apply_file(&path.with_file_name("missing.json"), "test"));
        assert_eq!(shaper.profile(), blackout, "the profile in force stays");
        std::fs::write(&path, r#"{"egress":{"delay_ms":25}}"#).unwrap();
        assert!(shaper.apply_file(&path, "test"));
        assert_eq!(shaper.profile().egress.delay_ms, 25);
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    async fn wait_for(what: &str, mut cond: impl FnMut() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while !cond() {
            assert!(Instant::now() < deadline, "timed out waiting for {what}");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    #[tokio::test]
    async fn the_control_file_is_watched_and_each_change_applied() {
        let path = temp_file("control.json");
        std::fs::write(&path, r#"{"egress":{"delay_ms":10}}"#).unwrap();
        let shaper = LinkShaper::new(LinkProfile::default());
        let task = shaper.watch_control_file(path.clone());
        wait_for("the first read", || shaper.profile().egress.delay_ms == 10).await;
        // Changed content with a different size, so the stamp moves even on a coarse clock.
        std::fs::write(&path, r#"{"egress":{"delay_ms":200}, "blackout": true}"#).unwrap();
        wait_for("the change", || shaper.profile().blackout).await;
        assert_eq!(shaper.profile().egress.delay_ms, 200);
        let generation = shaper.generation();
        // Invalid, then missing: both keep the profile.
        std::fs::write(&path, r#"{"egress":{"delay_ms":"soon"}}"#).unwrap();
        tokio::time::sleep(CONTROL_POLL * 4).await;
        std::fs::remove_file(&path).unwrap();
        tokio::time::sleep(CONTROL_POLL * 3).await;
        assert_eq!(shaper.generation(), generation);
        assert!(shaper.profile().blackout);
        // And it comes back.
        std::fs::write(&path, "{}").unwrap();
        wait_for("the file coming back", || !shaper.profile().blackout).await;
        task.abort();
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    /// A shaped socket on loopback and a plain one to talk to.
    async fn pair(profile: LinkProfile) -> (Arc<LinkShaper>, ShapedSocket, UdpSocket, SocketAddr) {
        let shaper = LinkShaper::new(profile);
        let a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let a_addr = a.local_addr().unwrap();
        let shaped = ShapedSocket::new(a, shaper.clone()).unwrap();
        let b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        (shaper, shaped, b, a_addr)
    }

    /// Everything `sock` receives within `window`, with arrival times from `t0`.
    async fn collect(sock: &UdpSocket, t0: Instant, window: Duration) -> Vec<(Duration, Vec<u8>)> {
        let mut out = Vec::new();
        let mut buf = [0u8; 2048];
        let end = tokio::time::Instant::now() + window;
        while let Ok(Ok((n, _))) = tokio::time::timeout_at(end, sock.recv_from(&mut buf)).await {
            out.push((t0.elapsed(), buf[..n].to_vec()));
        }
        out
    }

    #[tokio::test]
    async fn egress_delay_is_applied_in_real_time() {
        let (_s, shaped, b, _) = pair(LinkProfile {
            egress: EgressProfile {
                delay_ms: 60,
                ..EgressProfile::default()
            },
            ..LinkProfile::default()
        })
        .await;
        let to = b.local_addr().unwrap();
        let t0 = Instant::now();
        shaped.send_to(b"hello", to).unwrap();
        let got = collect(&b, t0, Duration::from_millis(400)).await;
        assert_eq!(got.len(), 1);
        let at = got[0].0;
        assert!(
            at >= Duration::from_millis(59) && at < Duration::from_millis(120),
            "arrived after {at:?}"
        );
    }

    #[tokio::test]
    async fn ingress_delay_is_applied_in_real_time() {
        let (_s, mut shaped, b, a_addr) = pair(LinkProfile {
            ingress: IngressProfile {
                delay_ms: 50,
                ..IngressProfile::default()
            },
            ..LinkProfile::default()
        })
        .await;
        let t0 = Instant::now();
        b.send_to(b"feedback", a_addr).await.unwrap();
        let mut buf = [0u8; 64];
        let (n, from) = tokio::time::timeout(Duration::from_secs(1), shaped.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        let at = t0.elapsed();
        assert_eq!(&buf[..n], b"feedback");
        assert_eq!(from, b.local_addr().unwrap());
        assert!(
            at >= Duration::from_millis(49) && at < Duration::from_millis(120),
            "delivered after {at:?}"
        );
    }

    #[tokio::test]
    async fn the_rate_serialises_a_burst() {
        // 1000 + 28 bytes at 2000 kbps is 4.112 ms each: 50 of them leave over ~206 ms.
        let (_s, shaped, b, _) = pair(LinkProfile {
            egress: EgressProfile {
                rate_kbps: Some(2_000),
                ..EgressProfile::default()
            },
            ..LinkProfile::default()
        })
        .await;
        let to = b.local_addr().unwrap();
        let t0 = Instant::now();
        for i in 0..50u8 {
            let mut p = vec![0u8; 1000];
            p[0] = i;
            shaped.send_to(&p, to).unwrap();
        }
        let got = collect(&b, t0, Duration::from_millis(600)).await;
        assert_eq!(got.len(), 50, "an unlimited queue drops nothing");
        let order: Vec<u8> = got.iter().map(|(_, p)| p[0]).collect();
        assert_eq!(order, (0..50).collect::<Vec<_>>(), "FIFO");
        let last = got[49].0;
        assert!(
            last >= Duration::from_millis(195) && last < Duration::from_millis(320),
            "the burst took {last:?}"
        );
        let first = got[0].0;
        assert!(
            first < Duration::from_millis(40),
            "the first left at {first:?}"
        );
    }

    #[tokio::test]
    async fn a_short_queue_drops_the_tail_of_a_burst() {
        // 1028 bytes at 1000 kbps is 8.224 ms each; a 50 ms queue admits the waits 0, 8.2 .. 49.3:
        // seven datagrams, the other 93 dropped at the tail.
        let (_s, shaped, b, _) = pair(LinkProfile {
            egress: EgressProfile {
                rate_kbps: Some(1_000),
                queue_ms: Some(50),
                ..EgressProfile::default()
            },
            ..LinkProfile::default()
        })
        .await;
        let to = b.local_addr().unwrap();
        let t0 = Instant::now();
        for _ in 0..100 {
            shaped.send_to(&[0u8; 1000], to).unwrap();
        }
        let got = collect(&b, t0, Duration::from_millis(400)).await;
        assert_eq!(got.len(), 7, "{got:?}");
        let st = lock(&shaped.inner.state);
        assert_eq!(st.egress.stats().dropped_queue, 93);
    }

    #[tokio::test]
    async fn loss_is_the_same_for_the_same_seed() {
        async fn survivors(seed: u64) -> Vec<u8> {
            let (_s, shaped, b, _) = pair(LinkProfile {
                egress: EgressProfile {
                    loss: 0.3,
                    ..EgressProfile::default()
                },
                seed: Some(seed),
                ..LinkProfile::default()
            })
            .await;
            let to = b.local_addr().unwrap();
            for i in 0..200u8 {
                shaped.send_to(&[i], to).unwrap();
            }
            let got = collect(&b, Instant::now(), Duration::from_millis(300)).await;
            got.into_iter().map(|(_, p)| p[0]).collect()
        }
        let a = survivors(7).await;
        let b = survivors(7).await;
        assert_eq!(a, b, "same seed, same survivors");
        assert!(
            (110..170).contains(&a.len()),
            "{} of 200 at 30% loss",
            a.len()
        );
        let c = survivors(8).await;
        assert_ne!(a, c, "another seed, another pattern");
    }

    #[tokio::test]
    async fn a_blackout_drops_both_ways_and_a_reload_ends_it() {
        let (shaper, mut shaped, b, a_addr) = pair(LinkProfile {
            egress: EgressProfile {
                delay_ms: 100,
                ..EgressProfile::default()
            },
            ..LinkProfile::default()
        })
        .await;
        let to = b.local_addr().unwrap();
        // In flight when the blackout begins: dropped as it comes due.
        shaped.send_to(b"in flight", to).unwrap();
        assert!(shaper.set_profile(
            LinkProfile {
                egress: EgressProfile {
                    delay_ms: 100,
                    ..EgressProfile::default()
                },
                blackout: true,
                ..LinkProfile::default()
            },
            "test"
        ));
        shaped.send_to(b"during", to).unwrap();
        b.send_to(b"inbound during", a_addr).await.unwrap();
        let got = collect(&b, Instant::now(), Duration::from_millis(300)).await;
        assert!(got.is_empty(), "{got:?}");
        let mut buf = [0u8; 64];
        assert!(
            tokio::time::timeout(Duration::from_millis(200), shaped.recv_from(&mut buf))
                .await
                .is_err(),
            "nothing comes in during a blackout"
        );
        {
            let st = lock(&shaped.inner.state);
            assert_eq!(
                st.totals.eg_blackout, 2,
                "the one in flight and the one sent during"
            );
            assert_eq!(st.totals.in_blackout, 1);
        }

        // The reload that ends it takes effect on the next datagram.
        assert!(shaper.set_profile(LinkProfile::default(), "test"));
        let t0 = Instant::now();
        shaped.send_to(b"after", to).unwrap();
        let got = collect(&b, t0, Duration::from_millis(200)).await;
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].1, b"after");
        assert!(
            got[0].0 < Duration::from_millis(50),
            "no delay any more: {:?}",
            got[0].0
        );
        b.send_to(b"inbound after", a_addr).await.unwrap();
        let (n, _) = tokio::time::timeout(Duration::from_secs(1), shaped.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf[..n], b"inbound after");
    }
}
