//! What crossed the peer's socket, path by path, and how far the DTLS handshake got.
//!
//! ## Why this exists
//!
//! A viewer behind a VPN can see ICE `Connected` within a second and then nothing: frames "arriving
//! before the connection is up", egress at 1-30 kbit/s, and after 30 s a connect timeout or a DTLS
//! handshake timeout. Without counters the log cannot say which pair ICE chose, where DTLS went, how
//! big it was, or whether a single DTLS datagram arrived from the viewer.
//!
//! So every datagram str0m hands the run loop to send, and every one the loop hands str0m, is
//! counted here: by remote address, by direction, and by what its first byte says it is (RFC 7983
//! §7: 0-3 STUN, 20-63 DTLS, 128-191 RTP/RTCP, anything else "other") — packets, bytes, the
//! largest datagram, and when the first and the last went by. DTLS datagrams are read as far as
//! their record headers, enough to name the handshake messages: a viewer that keeps resending its
//! ClientHello has not heard our reply. The srflx discovery's own STUN (`crate::stun`) never reaches
//! str0m and logs itself.
//!
//! ## str0m sends to a pair the viewer never answers on
//!
//! str0m's controlled ICE agent sends DTLS and media on the highest-priority pair the viewer ever
//! sent a check with USE-CANDIDATE on (`is-0.11.0/src/agent.rs:1910-1916`, `evaluate_nomination`),
//! without asking whether one of *its* checks on that pair was ever answered (RFC 8445 §7.3.1.5
//! nominates a pair only once it is valid). libwebrtc, controlling, puts USE-CANDIDATE on every
//! check while it has no writable selected pair and afterwards on every pair ranked above the one
//! selected (`SEMI_AGGRESSIVE`, `BasicIceController::GetUseCandidateAttr` in
//! `p2p/base/basic_ice_controller.cc`). So a viewer whose VPN carries its srflx checks to us and
//! nothing of ours back nominates that pair, with none of our checks on it answered, while it
//! selects a relay (only a writable pair, `BasicIceController::CompareConnectionStates`) and sends
//! every ClientHello there. str0m keeps the srflx pair: the relays rank lower, and a pair the remote
//! checked within 15 s is never pruned (`is-0.11.0/src/pair.rs:445-455`,
//! `RECENT_BINDING_REQUEST`). Our flight goes to the dead pair for as long as the viewer checks it.
//!
//! The STUN in each direction is therefore classified too ([`peek_stun`]): our checks, the
//! viewer's checks and how many of them nominated, and the replies each way — per ICE generation
//! as well, which is what [`judge_send_path`] reads to take str0m off such a pair.
//!
//! Nothing here logs. It is sans-IO and has no clock of its own — the loop passes `now` — so the
//! rules are tested without a network; `crate::webrtc` writes the aggregated lines.

use std::fmt::{self, Write as _};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

/// How many remote addresses are counted one by one. A session sees the viewer's candidates (six
/// to eight), their restarts' candidates, and a STUN server's late reply or two; anything past this
/// is counted without an address, in [`PathBook`]'s overflow.
pub(crate) const MAX_PATHS: usize = 32;

/// How many local source addresses are listed per path: str0m names the base of whichever local
/// candidate a datagram belongs to, and a PC offers two or three.
const MAX_LOCALS: usize = 4;

/// How long ICE may be connected without DTLS before the run loop says so at warn.
///
/// A healthy handshake takes one round trip after ICE — tens to a few hundred milliseconds, even
/// through a TCP relay. Three seconds is past every handshake that was going to finish, and early
/// enough that the line lands well inside the viewer's 30 s connect deadline, while there is still
/// time for it to try another path.
pub(crate) const DTLS_STALL_WARN_AFTER: Duration = Duration::from_secs(3);

/// How often a stalled handshake is reported again, at debug, after that warning.
pub(crate) const DTLS_STALL_REPORT_EVERY: Duration = Duration::from_secs(5);

/// How long the viewer may go without a word on the pair our DTLS goes to before the stall's
/// verdict calls that pair silent (see [`Verdict::NominatedPathSilent`]).
///
/// Its checks come every 50-500 ms while its ICE is still settling, and a round trip even through
/// a TCP relay is under half a second (180-450 ms measured): a second and a half without one is
/// not jitter. On a one-way VPN path the srflx pair had been quiet 2.3 s when the warning came.
pub(crate) const SILENT_AFTER: Duration = Duration::from_millis(1_500);

/// How many of our checks on a pair must go unanswered — all of them sent after the viewer was
/// first heard on that pair, and none answered since — before the pair can be called dead. str0m
/// sends them 250, 500 and 1000 ms apart on a pair that has not answered
/// (`is-0.11.0/src/stun.rs:37-48`), once per local candidate; three is one short round of them.
pub(crate) const FOLLOW_MIN_UNANSWERED: u32 = 3;

/// How long the oldest of those checks must have gone unanswered before the handshake gives up
/// on the pair str0m sends on (DTLS not up yet). The same reasoning as [`SILENT_AFTER`]; and the
/// clock only starts once the viewer has been heard on the pair, so checks that left before its
/// NAT had a hole for them do not count.
pub(crate) const FOLLOW_DEAD_AFTER_HANDSHAKE: Duration = Duration::from_millis(1_500);

/// The same, once DTLS is up and media flows. Longer: str0m checks a working pair every 3 s and
/// only then speeds up (`is-0.11.0/src/pair.rs:405-440`), so three unanswered checks already span
/// three and a half seconds, and a live session should not leave its pair over a Wi-Fi hiccup. It
/// also has to be the viewer that moved first (see [`judge_send_path`]), which libwebrtc does once
/// our packets stop arriving on its selected pair for 2.5 s.
pub(crate) const FOLLOW_DEAD_AFTER_CONNECTED: Duration = Duration::from_secs(3);

/// How recently the viewer's pair must have answered one of our checks to be a pair to move to.
/// str0m checks a pair it is not sending on every 3 s at the slowest; five leaves room for a round
/// trip and a lost reply.
pub(crate) const FOLLOW_ALIVE_WITHIN: Duration = Duration::from_secs(5);

/// How often the run loop asks [`judge_send_path`] whether to move.
pub(crate) const FOLLOW_EVERY: Duration = Duration::from_millis(250);

/// What a datagram is, by its first byte (RFC 7983 §7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    Stun,
    Dtls,
    /// RTP or RTCP (SRTP/SRTCP on the wire).
    Rtp,
    /// Anything else: TURN channel data, ZRTP, junk, an empty datagram.
    Other,
}

impl Kind {
    const ALL: [Kind; 4] = [Kind::Stun, Kind::Dtls, Kind::Rtp, Kind::Other];

    pub(crate) fn of(datagram: &[u8]) -> Self {
        match datagram.first() {
            Some(0..=3) => Kind::Stun,
            Some(20..=63) => Kind::Dtls,
            Some(128..=191) => Kind::Rtp,
            _ => Kind::Other,
        }
    }

    fn index(self) -> usize {
        match self {
            Kind::Stun => 0,
            Kind::Dtls => 1,
            Kind::Rtp => 2,
            Kind::Other => 3,
        }
    }

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Kind::Stun => "stun",
            Kind::Dtls => "dtls",
            Kind::Rtp => "rtp",
            Kind::Other => "other",
        }
    }
}

/// Which way a datagram went.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Dir {
    /// From this PC to the viewer (str0m's `Output::Transmit`).
    Out,
    /// From the viewer to this PC (what the loop feeds str0m as `Input::Receive`).
    In,
}

impl Dir {
    fn index(self) -> usize {
        match self {
            Dir::Out => 0,
            Dir::In => 1,
        }
    }

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Dir::Out => "out",
            Dir::In => "in",
        }
    }
}

/// Datagrams of one kind, one way, on one path.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Tally {
    pub(crate) packets: u64,
    pub(crate) bytes: u64,
    /// The largest datagram, in bytes.
    pub(crate) max: usize,
    pub(crate) first: Option<Instant>,
    pub(crate) last: Option<Instant>,
}

impl Tally {
    /// Count one datagram of `len` bytes. `true` when it is the first.
    fn add(&mut self, len: usize, now: Instant) -> bool {
        self.packets += 1;
        self.bytes = self.bytes.saturating_add(len as u64);
        self.max = self.max.max(len);
        self.last = Some(now);
        if self.first.is_some() {
            return false;
        }
        self.first = Some(now);
        true
    }

    fn merge(&mut self, other: &Tally) {
        self.packets += other.packets;
        self.bytes = self.bytes.saturating_add(other.bytes);
        self.max = self.max.max(other.max);
        self.first = match (self.first, other.first) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
        self.last = self.last.max(other.last);
    }

    /// `12p/1104B<=96 @0.21-27.31s`: packets, bytes, the largest datagram, and the first and last
    /// of them in seconds from `base` (the peer's start).
    fn write(&self, out: &mut String, base: Instant) {
        let _ = write!(out, "{}p/{}B<={}", self.packets, self.bytes, self.max);
        if let (Some(first), Some(last)) = (self.first, self.last) {
            let s = |t: Instant| t.saturating_duration_since(base).as_secs_f64();
            let _ = write!(out, " @{:.2}-{:.2}s", s(first), s(last));
        }
    }
}

/// Bits of [`DtlsSeen::seen`]: handshake message types 0 to 24 by number, and these.
const BIT_CCS: u32 = 1 << 25;
const BIT_ALERT: u32 = 1 << 26;
/// A handshake record past epoch 0: encrypted, so its type cannot be read (the Finished).
const BIT_ENCRYPTED: u32 = 1 << 27;
/// Application data: SCTP, once the handshake is done.
const BIT_APP: u32 = 1 << 28;
/// A DTLS 1.3 record with the unified header: encrypted, nothing more to read.
const BIT_DTLS13: u32 = 1 << 29;
/// A record header or handshake header cut short, or a content type DTLS does not have.
const BIT_MALFORMED: u32 = 1 << 30;
/// A handshake type above 24.
const BIT_OTHER_HS: u32 = 1 << 31;

const HS_CLIENT_HELLO: u8 = 1;
const HS_SERVER_HELLO: u8 = 2;
const HS_SERVER_HELLO_DONE: u8 = 14;
const HS_CLIENT_KEY_EXCHANGE: u8 = 16;

/// What one DTLS datagram carries, read from its record and handshake headers.
///
/// Only headers: the handshake bodies are str0m's business, and past epoch 0 they are encrypted
/// anyway. The first fragment of a ClientHello or ServerHello marks a flight being sent or resent,
/// which is what tells a viewer that never heard us from one we never heard.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct DtlsPeek {
    seen: u32,
    /// A ClientHello starts in this datagram: the client's first flight, sent or resent.
    client_hello: bool,
    /// A ServerHello starts in this datagram: the server's flight, sent or resent.
    server_hello: bool,
    /// The description of a plaintext alert in it (RFC 5246 §7.2), if there is one.
    alert: Option<u8>,
}

/// Read a DTLS datagram's records (RFC 6347 §4.1: 13-byte header, length in the last two) and the
/// handshake messages in the plaintext ones (§4.2.2: 12-byte header, type first, fragment offset
/// at 6..9, fragment length at 9..12).
pub(crate) fn peek_dtls(d: &[u8]) -> DtlsPeek {
    const RECORD_HEADER: usize = 13;
    const HANDSHAKE_HEADER: usize = 12;
    let mut p = DtlsPeek::default();
    let mut at = 0;
    while at < d.len() {
        let content_type = d[at];
        if (32..=63).contains(&content_type) {
            // DTLS 1.3's unified header (RFC 9147 §4): encrypted, and its length field optional.
            p.seen |= BIT_DTLS13;
            break;
        }
        let Some(header) = d.get(at..at + RECORD_HEADER) else {
            p.seen |= BIT_MALFORMED;
            break;
        };
        let epoch = u16::from_be_bytes([header[3], header[4]]);
        let len = usize::from(u16::from_be_bytes([header[11], header[12]]));
        let body_at = at + RECORD_HEADER;
        let Some(body) = d.get(body_at..body_at + len) else {
            p.seen |= BIT_MALFORMED;
            break;
        };
        match (content_type, epoch) {
            (20, _) => p.seen |= BIT_CCS,
            (21, 0) => {
                p.seen |= BIT_ALERT;
                p.alert = body.get(1).copied();
            }
            (21, _) => p.seen |= BIT_ALERT,
            (22, 0) => {
                let mut hs = body;
                while !hs.is_empty() {
                    let Some(h) = hs.get(..HANDSHAKE_HEADER) else {
                        p.seen |= BIT_MALFORMED;
                        break;
                    };
                    let msg_type = h[0];
                    let fragment_offset = u32::from_be_bytes([0, h[6], h[7], h[8]]);
                    let fragment_len = u32::from_be_bytes([0, h[9], h[10], h[11]]) as usize;
                    p.seen |= if msg_type <= 24 {
                        1 << msg_type
                    } else {
                        BIT_OTHER_HS
                    };
                    if fragment_offset == 0 {
                        p.client_hello |= msg_type == HS_CLIENT_HELLO;
                        p.server_hello |= msg_type == HS_SERVER_HELLO;
                    }
                    match hs.get(HANDSHAKE_HEADER + fragment_len..) {
                        Some(rest) => hs = rest,
                        None => {
                            p.seen |= BIT_MALFORMED;
                            break;
                        }
                    }
                }
            }
            (22, _) => p.seen |= BIT_ENCRYPTED,
            (23, _) => p.seen |= BIT_APP,
            _ => {
                p.seen |= BIT_MALFORMED;
                break;
            }
        }
        at = body_at + len;
    }
    p
}

/// A STUN message's class (RFC 5389 §6), for the Binding method; any other method is `Other`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StunClass {
    /// A connectivity check: a Binding request.
    Request,
    /// The answer to a check: a Binding success response.
    Success,
    /// A Binding error response: a role conflict (487), a bad request, a wrong password.
    Error,
    /// A Binding indication: a keepalive nobody answers.
    Indication,
    /// Not a Binding message (TURN methods), or not STUN at all (no magic cookie).
    Other,
}

/// What a STUN datagram is, from its header and the two attributes ICE decides by.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct StunPeek<'a> {
    pub(crate) class: StunClass,
    /// USE-CANDIDATE (RFC 8445 §7.1.2): the controlling side nominates the pair this check is on.
    pub(crate) use_candidate: bool,
    /// USERNAME's first half: the recipient's ufrag (RFC 8445 §7.2.2). On a check sent to us it is
    /// our own, of the ICE generation the viewer is checking in.
    pub(crate) recipient_ufrag: Option<&'a [u8]>,
}

/// RFC 5389 §6: the fixed value in every STUN header.
const STUN_MAGIC: [u8; 4] = [0x21, 0x12, 0xa4, 0x42];
const STUN_HEADER: usize = 20;
const ATTR_USERNAME: u16 = 0x0006;
const ATTR_USE_CANDIDATE: u16 = 0x0025;

/// Read a STUN datagram's type and walk its attributes (type, length, value padded to four bytes)
/// for USERNAME and USE-CANDIDATE. Nothing is verified — str0m checks the integrity of what it
/// takes; this only classifies what crossed the socket. Never a panic: a short or malformed message
/// reads as far as it goes.
pub(crate) fn peek_stun(d: &[u8]) -> StunPeek<'_> {
    let mut p = StunPeek {
        class: StunClass::Other,
        use_candidate: false,
        recipient_ufrag: None,
    };
    let Some(header) = d.get(..STUN_HEADER) else {
        return p;
    };
    if header[4..8] != STUN_MAGIC {
        return p;
    }
    p.class = match u16::from_be_bytes([header[0], header[1]]) {
        0x0001 => StunClass::Request,
        0x0101 => StunClass::Success,
        0x0111 => StunClass::Error,
        0x0011 => StunClass::Indication,
        _ => return p,
    };
    let len = usize::from(u16::from_be_bytes([header[2], header[3]]));
    let body = &d[STUN_HEADER..];
    let mut attrs = &body[..len.min(body.len())];
    while let Some(h) = attrs.get(..4) {
        let attr = u16::from_be_bytes([h[0], h[1]]);
        let attr_len = usize::from(u16::from_be_bytes([h[2], h[3]]));
        let Some(value) = attrs.get(4..4 + attr_len) else {
            break;
        };
        match attr {
            ATTR_USE_CANDIDATE => p.use_candidate = true,
            ATTR_USERNAME => p.recipient_ufrag = value.split(|b| *b == b':').next(),
            _ => {}
        }
        attrs = attrs.get(4 + attr_len.next_multiple_of(4)..).unwrap_or(&[]);
    }
    p
}

/// The STUN one way on a path, by what it was: counted for the path lines, over the whole session.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct StunSeen {
    /// Binding requests: connectivity checks.
    pub(crate) checks: u32,
    /// Of those, the ones carrying USE-CANDIDATE: the controlling side (the viewer) nominating.
    pub(crate) nominating: u32,
    /// Binding success responses: checks answered.
    pub(crate) replies: u32,
    /// Binding error responses.
    pub(crate) errors: u32,
    /// Checks addressed to another ICE generation's ufrag than ours: the viewer still checking a
    /// pair of the generation a restart replaced. Not in `checks`; str0m drops them.
    pub(crate) stale: u32,
}

impl StunSeen {
    fn is_empty(&self) -> bool {
        *self == StunSeen::default()
    }
}

/// `checks 3, nominating 3, replies 0`: checks and replies always, the rest when there were any.
impl fmt::Display for StunSeen {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "checks {}", self.checks)?;
        if self.nominating > 0 {
            write!(f, ", nominating {}", self.nominating)?;
        }
        write!(f, ", replies {}", self.replies)?;
        if self.errors > 0 {
            write!(f, ", errors {}", self.errors)?;
        }
        if self.stale > 0 {
            write!(f, ", stale {}", self.stale)?;
        }
        Ok(())
    }
}

/// What this ICE generation's STUN says about one path: whether the viewer nominated it, and
/// whether it answers our checks. Reset by an ICE restart ([`PathBook::new_generation`]): str0m
/// flushes every pair then, and nothing learned about the old ones holds for the new.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Evidence {
    /// When the viewer was first heard here: a check naming our ufrag, or a reply to ours. From
    /// then on its NAT has a hole for us, and a check of ours that goes unanswered means something.
    pub(crate) first_heard: Option<Instant>,
    /// Checks with USE-CANDIDATE from here, and the last of them.
    pub(crate) nominations: u32,
    pub(crate) last_nomination: Option<Instant>,
    /// Our checks answered from here, and the last answer.
    pub(crate) replies: u32,
    pub(crate) last_reply: Option<Instant>,
    /// Our checks sent here since the last answer (and after `first_heard`), and when the first
    /// of them left.
    pub(crate) unanswered: u32,
    pub(crate) unanswered_since: Option<Instant>,
}

impl Evidence {
    /// How long our oldest unanswered check here has waited, if any is waiting.
    pub(crate) fn unanswered_for(&self, now: Instant) -> Option<Duration> {
        self.unanswered_since
            .map(|t| now.saturating_duration_since(t))
    }

    /// Whether this path has stopped answering us: [`FOLLOW_MIN_UNANSWERED`] checks or more,
    /// the oldest of them waiting `after` or longer.
    pub(crate) fn dead(&self, now: Instant, after: Duration) -> bool {
        self.unanswered >= FOLLOW_MIN_UNANSWERED
            && self
                .unanswered_for(now)
                .is_some_and(|waited| waited >= after)
    }

    /// Whether this path answered one of our checks within `within`.
    fn answered_within(&self, now: Instant, within: Duration) -> bool {
        self.last_reply
            .is_some_and(|t| now.saturating_duration_since(t) <= within)
    }
}

/// Everything DTLS carried one way on a path: which handshake messages, how many times a flight
/// started, the last plaintext alert.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct DtlsSeen {
    seen: u32,
    /// Datagrams that started a ClientHello: the client's first flight and each resend of it.
    pub(crate) client_hellos: u32,
    /// Datagrams that started a ServerHello: the server's flight and each resend of it.
    pub(crate) server_hellos: u32,
    alert: Option<u8>,
}

impl DtlsSeen {
    fn add(&mut self, p: DtlsPeek) {
        self.seen |= p.seen;
        self.client_hellos += u32::from(p.client_hello);
        self.server_hellos += u32::from(p.server_hello);
        if p.alert.is_some() {
            self.alert = p.alert;
        }
    }

    fn merge(&mut self, other: &DtlsSeen) {
        self.seen |= other.seen;
        self.client_hellos += other.client_hellos;
        self.server_hellos += other.server_hellos;
        if other.alert.is_some() {
            self.alert = other.alert;
        }
    }

    fn has(&self, msg_type: u8) -> bool {
        msg_type <= 24 && self.seen & (1 << msg_type) != 0
    }
}

impl From<DtlsPeek> for DtlsSeen {
    fn from(p: DtlsPeek) -> Self {
        let mut s = DtlsSeen::default();
        s.add(p);
        s
    }
}

/// `CHx3 SH Cert SKE CR SHD CCS Enc`: the handshake messages by their usual abbreviations (with
/// how many datagrams started a ClientHello or a ServerHello), then what else the records were.
impl fmt::Display for DtlsSeen {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut parts: Vec<String> = Vec::new();
        for t in 0..=24u8 {
            if !self.has(t) {
                continue;
            }
            let name = match t {
                0 => "HelloRequest",
                HS_CLIENT_HELLO => "CH",
                HS_SERVER_HELLO => "SH",
                3 => "HVR",
                4 => "NST",
                8 => "EE",
                11 => "Cert",
                12 => "SKE",
                13 => "CR",
                HS_SERVER_HELLO_DONE => "SHD",
                15 => "CV",
                HS_CLIENT_KEY_EXCHANGE => "CKE",
                20 => "Fin",
                24 => "KU",
                _ => "",
            };
            let count = match t {
                HS_CLIENT_HELLO => self.client_hellos,
                HS_SERVER_HELLO => self.server_hellos,
                _ => 1,
            };
            parts.push(match (name, count) {
                ("", _) => format!("hs{t}"),
                (name, 0 | 1) => name.to_string(),
                (name, n) => format!("{name}x{n}"),
            });
        }
        for (bit, name) in [
            (BIT_OTHER_HS, "hs>24"),
            (BIT_CCS, "CCS"),
            (BIT_ENCRYPTED, "Enc"),
            (BIT_APP, "App"),
            (BIT_DTLS13, "D13"),
            (BIT_MALFORMED, "Malformed"),
        ] {
            if self.seen & bit != 0 {
                parts.push(name.to_string());
            }
        }
        if self.seen & BIT_ALERT != 0 {
            parts.push(match self.alert {
                Some(desc) => format!("Alert({desc})"),
                None => "Alert".to_string(),
            });
        }
        if parts.is_empty() {
            return f.write_str("-");
        }
        f.write_str(&parts.join(" "))
    }
}

/// Everything seen to or from one remote address.
#[derive(Debug, Clone)]
pub(crate) struct Path {
    pub(crate) remote: SocketAddr,
    /// The local addresses str0m named as the source of what it sent here (its candidates' bases),
    /// at most [`MAX_LOCALS`]; all of them leave through the same socket.
    locals: Vec<SocketAddr>,
    tally: [[Tally; 4]; 2],
    dtls: [DtlsSeen; 2],
    /// What the STUN each way was, over the session.
    stun: [StunSeen; 2],
    /// What this ICE generation's STUN says about the path. See [`Evidence`].
    ev: Evidence,
    /// Datagrams from here that str0m could not parse, so never handed to it.
    unparsed: u64,
}

impl Path {
    fn new(remote: SocketAddr) -> Self {
        Self {
            remote,
            locals: Vec::new(),
            tally: [[Tally::default(); 4]; 2],
            dtls: [DtlsSeen::default(); 2],
            stun: [StunSeen::default(); 2],
            ev: Evidence::default(),
            unparsed: 0,
        }
    }

    pub(crate) fn tally(&self, dir: Dir, kind: Kind) -> &Tally {
        &self.tally[dir.index()][kind.index()]
    }

    pub(crate) fn stun_seen(&self, dir: Dir) -> &StunSeen {
        &self.stun[dir.index()]
    }

    pub(crate) fn evidence(&self) -> &Evidence {
        &self.ev
    }

    /// One STUN datagram: counted by class, and read for evidence. `current` is whether a check
    /// from the viewer names our ufrag of this generation (always `true` otherwise).
    fn note_stun(&mut self, dir: Dir, s: StunPeek<'_>, current: bool, now: Instant) {
        let seen = &mut self.stun[dir.index()];
        let ev = &mut self.ev;
        match (dir, s.class) {
            (Dir::Out, StunClass::Request) => {
                seen.checks += 1;
                // Before the viewer has been heard here its NAT may have no hole for us yet; a
                // check lost to that says nothing about the path.
                if ev.first_heard.is_some() {
                    if ev.unanswered == 0 {
                        ev.unanswered_since = Some(now);
                    }
                    ev.unanswered += 1;
                }
            }
            (Dir::In, StunClass::Request) if !current => seen.stale += 1,
            (Dir::In, StunClass::Request) => {
                seen.checks += 1;
                ev.first_heard.get_or_insert(now);
                if s.use_candidate {
                    seen.nominating += 1;
                    ev.nominations += 1;
                    ev.last_nomination = Some(now);
                }
            }
            (Dir::In, StunClass::Success) => {
                seen.replies += 1;
                ev.first_heard.get_or_insert(now);
                ev.replies += 1;
                ev.last_reply = Some(now);
                ev.unanswered = 0;
                ev.unanswered_since = None;
            }
            (Dir::Out, StunClass::Success) => seen.replies += 1,
            (_, StunClass::Error) => seen.errors += 1,
            (_, StunClass::Indication | StunClass::Other) => {}
        }
    }

    fn write_dir(&self, out: &mut String, dir: Dir, base: Instant) {
        out.push_str(dir.as_str());
        let mut any = false;
        for kind in Kind::ALL {
            let t = self.tally(dir, kind);
            if t.packets == 0 {
                continue;
            }
            out.push_str(if any { ", " } else { " " });
            any = true;
            let _ = write!(out, "{} ", kind.as_str());
            t.write(out, base);
            if kind == Kind::Dtls {
                let _ = write!(out, " {{{}}}", self.dtls[dir.index()]);
            }
            let stun = self.stun_seen(dir);
            if kind == Kind::Stun && !stun.is_empty() {
                let _ = write!(out, " [{stun}]");
            }
        }
        if !any {
            out.push_str(" -");
        }
        if dir == Dir::Out && !self.locals.is_empty() {
            let locals: Vec<String> = self.locals.iter().map(ToString::to_string).collect();
            let _ = write!(out, " via {}", locals.join(","));
        }
        if dir == Dir::In && self.unparsed > 0 {
            let _ = write!(out, " unparsed {}", self.unparsed);
        }
    }
}

/// What [`PathBook::note`] made of one datagram.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Noted {
    pub(crate) kind: Kind,
    /// The first datagram of its kind this way on this path.
    pub(crate) first_on_path: bool,
    /// The first datagram of its kind this way on any path.
    pub(crate) first_anywhere: bool,
    /// For DTLS: what its record headers say.
    pub(crate) dtls: Option<DtlsPeek>,
}

/// Every datagram in and out of a peer's socket that went through str0m, by remote address, way
/// and kind.
///
/// One linear lookup per datagram over a handful of addresses, with the last one tried first
/// because media goes to a single address at a time; no allocation after an address's first
/// datagram, and no logging.
#[derive(Debug, Default)]
pub(crate) struct PathBook {
    paths: Vec<Path>,
    /// Datagrams to or from addresses past [`MAX_PATHS`], counted without an address.
    overflow: [[Tally; 4]; 2],
    overflow_unparsed: u64,
    /// Whether a datagram of each way and kind has been seen on any path.
    seen_any: [[bool; 4]; 2],
    /// Where the last datagram went or came from.
    last: usize,
    /// Our ICE ufrag of this generation: a viewer's check naming another one belongs to a
    /// generation an ICE restart replaced. `None` counts every check as current.
    local_ufrag: Option<String>,
    /// Where the viewer's latest DTLS or RTP/RTCP datagram came from, and when: the pair the
    /// viewer itself is using (libwebrtc sends everything on its selected pair).
    last_data: Option<(SocketAddr, Instant)>,
}

impl PathBook {
    /// A new ICE generation, with `ufrag` as our ufrag in it: the session's first, or an ICE
    /// restart's. Every path's [`Evidence`] starts over; the session's counts stay.
    pub(crate) fn new_generation(&mut self, ufrag: Option<String>) {
        for p in &mut self.paths {
            p.ev = Evidence::default();
        }
        self.local_ufrag = ufrag;
    }

    /// Whether a check the viewer sent names our ufrag of this generation. Only checks carry a
    /// USERNAME; everything else counts as current.
    fn is_current(&self, s: &StunPeek<'_>) -> bool {
        match (s.class, s.recipient_ufrag, &self.local_ufrag) {
            (StunClass::Request, Some(ufrag), Some(ours)) => ufrag == ours.as_bytes(),
            _ => true,
        }
    }

    /// Count one datagram. `local` is the source str0m named for one it sent; `None` for one
    /// received, which arrives on the one socket.
    pub(crate) fn note(
        &mut self,
        dir: Dir,
        local: Option<SocketAddr>,
        remote: SocketAddr,
        datagram: &[u8],
        now: Instant,
    ) -> Noted {
        let kind = Kind::of(datagram);
        let (d, k) = (dir.index(), kind.index());
        let first_anywhere = !std::mem::replace(&mut self.seen_any[d][k], true);
        let dtls = (kind == Kind::Dtls).then(|| peek_dtls(datagram));
        if dir == Dir::In && matches!(kind, Kind::Dtls | Kind::Rtp) {
            self.last_data = Some((remote, now));
        }
        let stun = (kind == Kind::Stun).then(|| peek_stun(datagram));
        let current = match (dir, &stun) {
            (Dir::In, Some(s)) => self.is_current(s),
            _ => true,
        };
        let Some(i) = self.index_of(remote) else {
            self.overflow[d][k].add(datagram.len(), now);
            return Noted {
                kind,
                first_on_path: false,
                first_anywhere,
                dtls,
            };
        };
        let path = &mut self.paths[i];
        let first_on_path = path.tally[d][k].add(datagram.len(), now);
        if let Some(peek) = dtls {
            path.dtls[d].add(peek);
        }
        if let Some(s) = stun {
            path.note_stun(dir, s, current, now);
        }
        if let Some(local) = local {
            if path.locals.len() < MAX_LOCALS && !path.locals.contains(&local) {
                path.locals.push(local);
            }
        }
        Noted {
            kind,
            first_on_path,
            first_anywhere,
            dtls,
        }
    }

    /// A datagram from `remote` that str0m could not parse. Already counted by [`Self::note`].
    pub(crate) fn unparsed(&mut self, remote: SocketAddr) {
        match self.index_of(remote) {
            Some(i) => self.paths[i].unparsed += 1,
            None => self.overflow_unparsed += 1,
        }
    }

    fn index_of(&mut self, remote: SocketAddr) -> Option<usize> {
        if self
            .paths
            .get(self.last)
            .is_some_and(|p| p.remote == remote)
        {
            return Some(self.last);
        }
        let i = match self.paths.iter().position(|p| p.remote == remote) {
            Some(i) => i,
            None if self.paths.len() >= MAX_PATHS => return None,
            None => {
                self.paths.push(Path::new(remote));
                self.paths.len() - 1
            }
        };
        self.last = i;
        Some(i)
    }

    #[cfg(test)]
    pub(crate) fn paths(&self) -> &[Path] {
        &self.paths
    }

    /// The path to or from `remote`, if it is counted one by one.
    pub(crate) fn path(&self, remote: SocketAddr) -> Option<&Path> {
        self.paths.iter().find(|p| p.remote == remote)
    }

    /// Where the viewer's latest DTLS or RTP/RTCP datagram came from, and when.
    pub(crate) fn last_data(&self) -> Option<(SocketAddr, Instant)> {
        self.last_data
    }

    /// Whether the viewer has gone silent on `send`, the pair our DTLS goes to: not one DTLS
    /// datagram from it, and either no STUN from it for [`SILENT_AFTER`] while another path had
    /// some within that time, or our checks on it unanswered that long (see [`Evidence::dead`]).
    pub(crate) fn send_path_silent(&self, send: SocketAddr, now: Instant) -> bool {
        let Some(p) = self.path(send) else {
            return false;
        };
        if p.tally(Dir::In, Kind::Dtls).packets > 0 {
            return false;
        }
        let recent =
            |t: Option<Instant>| t.is_some_and(|t| now.saturating_duration_since(t) < SILENT_AFTER);
        let quiet = !recent(p.tally(Dir::In, Kind::Stun).last)
            && self
                .paths
                .iter()
                .any(|o| o.remote != send && recent(o.tally(Dir::In, Kind::Stun).last));
        quiet || p.ev.dead(now, SILENT_AFTER)
    }

    /// One way and kind over every path, the overflow included.
    pub(crate) fn total(&self, dir: Dir, kind: Kind) -> Tally {
        let mut t = self.overflow[dir.index()][kind.index()];
        for p in &self.paths {
            t.merge(p.tally(dir, kind));
        }
        t
    }

    /// What DTLS carried one way, over every path.
    pub(crate) fn dtls_seen(&self, dir: Dir) -> DtlsSeen {
        let mut s = DtlsSeen::default();
        for p in &self.paths {
            s.merge(&p.dtls[dir.index()]);
        }
        s
    }

    /// How many remote addresses have sent this kind.
    pub(crate) fn sources_of(&self, kind: Kind) -> usize {
        self.paths
            .iter()
            .filter(|p| p.tally(Dir::In, kind).packets > 0)
            .count()
    }

    /// DTLS one way over every path, for a log line: `3p/2436B<=812 @0.68-3.21s {SHx3 Cert SKE
    /// CR SHD}`, or `-` when there was none.
    pub(crate) fn dtls_summary(&self, dir: Dir, base: Instant) -> String {
        let t = self.total(dir, Kind::Dtls);
        if t.packets == 0 {
            return "-".to_string();
        }
        let mut out = String::new();
        t.write(&mut out, base);
        let _ = write!(out, " {{{}}}", self.dtls_seen(dir));
        out
    }

    /// Every path, for a log line: the remote address, what `name` calls it (with `*` for the one
    /// str0m sends on), then each way's kinds — STUN with what it was, `[checks 3, nominating 3,
    /// replies 0]` (see [`StunSeen`]). Paths are ` | `-separated, in the order their first
    /// datagram arrived or left.
    pub(crate) fn describe(
        &self,
        base: Instant,
        name: impl Fn(SocketAddr) -> String,
        nominated: Option<SocketAddr>,
    ) -> String {
        let mut out = String::new();
        for p in &self.paths {
            if !out.is_empty() {
                out.push_str(" | ");
            }
            let star = if nominated == Some(p.remote) { "*" } else { "" };
            let _ = write!(out, "{} {}{}: ", p.remote, name(p.remote), star);
            p.write_dir(&mut out, Dir::Out, base);
            out.push_str("; ");
            p.write_dir(&mut out, Dir::In, base);
        }
        let overflow: u64 = self.overflow.iter().flatten().map(|t| t.packets).sum();
        if overflow > 0 || self.overflow_unparsed > 0 {
            if !out.is_empty() {
                out.push_str(" | ");
            }
            let _ = write!(
                out,
                "{overflow} datagrams on addresses past the first {MAX_PATHS} ({} unparsed)",
                self.overflow_unparsed
            );
        }
        if out.is_empty() {
            out.push('-');
        }
        out
    }
}

/// The agent's side of the DTLS handshake, from the `a=setup` of the answer it sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DtlsRole {
    /// `a=setup:passive`: the agent waits for the viewer's ClientHello and answers it. What str0m
    /// answers to a browser's `actpass` offer, so every session so far.
    Server,
    /// `a=setup:active`: the agent sends the ClientHello.
    Client,
    /// No `a=setup` line, or one this does not know.
    Unknown,
}

impl DtlsRole {
    pub(crate) fn from_answer(answer_sdp: &str) -> Self {
        let setup = answer_sdp
            .lines()
            .find_map(|l| l.trim_end().strip_prefix("a=setup:"));
        match setup {
            Some("passive") => DtlsRole::Server,
            Some("active") => DtlsRole::Client,
            _ => DtlsRole::Unknown,
        }
    }

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            DtlsRole::Server => "server",
            DtlsRole::Client => "client",
            DtlsRole::Unknown => "unknown",
        }
    }
}

/// Where the DTLS handshake stands against ICE, for the stall warning. Sans-IO: the loop supplies
/// the clock.
///
/// The rules:
///   * the clock starts at ICE's first `Connected` (or `Completed`) and is never restarted — a
///     path lost and found again before DTLS is up has not given the handshake a fresh start;
///   * [`DTLS_STALL_WARN_AFTER`] later, if DTLS is still not up, one warning;
///   * then a report every [`DTLS_STALL_REPORT_EVERY`] until DTLS comes up or the peer ends;
///   * nothing at all once DTLS is up.
#[derive(Debug, Default)]
pub(crate) struct DtlsWatch {
    ice_connected_at: Option<Instant>,
    up_at: Option<Instant>,
    /// When the warning, or the last report after it, was due and given.
    reported_at: Option<Instant>,
}

/// What [`DtlsWatch::poll`] says the loop owes the log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Stall {
    Quiet,
    /// The first time: ICE has been up this long with no DTLS.
    Warn {
        waited: Duration,
    },
    /// Again, later.
    Report {
        waited: Duration,
    },
}

impl DtlsWatch {
    /// ICE reached `Connected` or `Completed`. `true` the first time.
    pub(crate) fn ice_connected(&mut self, now: Instant) -> bool {
        if self.ice_connected_at.is_some() {
            return false;
        }
        self.ice_connected_at = Some(now);
        true
    }

    /// str0m said `Connected`: DTLS is up. How long after ICE first connected, if it had.
    pub(crate) fn dtls_up(&mut self, now: Instant) -> Option<Duration> {
        self.up_at.get_or_insert(now);
        self.ice_connected_at
            .map(|at| now.saturating_duration_since(at))
    }

    pub(crate) fn ice_connected_at(&self) -> Option<Instant> {
        self.ice_connected_at
    }

    /// How long DTLS took after ICE first connected, once both happened: `session_end.detail`'s
    /// `dtls_after_ice_ms`.
    pub(crate) fn dtls_after_ice(&self) -> Option<Duration> {
        match (self.ice_connected_at, self.up_at) {
            (Some(ice), Some(up)) => Some(up.saturating_duration_since(ice)),
            _ => None,
        }
    }

    /// How long ICE has been up while DTLS has not, if that is the situation.
    pub(crate) fn stalled_for(&self, now: Instant) -> Option<Duration> {
        match (self.ice_connected_at, self.up_at) {
            (Some(at), None) => Some(now.saturating_duration_since(at)),
            _ => None,
        }
    }

    pub(crate) fn poll(&mut self, now: Instant) -> Stall {
        let Some(waited) = self.stalled_for(now) else {
            return Stall::Quiet;
        };
        match self.reported_at {
            None if waited >= DTLS_STALL_WARN_AFTER => {
                self.reported_at = Some(now);
                Stall::Warn { waited }
            }
            Some(at) if now.saturating_duration_since(at) >= DTLS_STALL_REPORT_EVERY => {
                self.reported_at = Some(now);
                Stall::Report { waited }
            }
            _ => Stall::Quiet,
        }
    }

    /// When [`Self::poll`] next has something to say, if it can have.
    pub(crate) fn next_due(&self) -> Option<Instant> {
        let (Some(ice), None) = (self.ice_connected_at, self.up_at) else {
            return None;
        };
        Some(match self.reported_at {
            None => ice + DTLS_STALL_WARN_AFTER,
            Some(at) => at + DTLS_STALL_REPORT_EVERY,
        })
    }
}

/// Which side of a stalled handshake is not being heard, as far as the counters can tell.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Verdict {
    /// Not one DTLS datagram from the viewer.
    NothingFromViewer,
    /// We are the server, the viewer's ClientHello arrived, and nothing went back.
    NoReplySent,
    /// The viewer keeps resending its ClientHello and never its next flight: our reply is not
    /// reaching it.
    ViewerResendsHello,
    /// The viewer sent its ClientHello once and nothing since, while we sent our flight: its
    /// answer (the flight with its certificate) is not arriving.
    ViewerSilentAfterHello,
    /// The viewer's second flight arrived (its ClientKeyExchange), and still no DTLS.
    SecondFlightStuck,
    /// Our DTLS goes to a pair the viewer has gone silent on, while its ClientHello comes over
    /// another: str0m holds on to a dead nominated pair. See the module docs.
    NominatedPathSilent,
    /// We are the client and sent no ClientHello.
    NoHelloSent,
    /// The counters do not point at either side.
    Unclear,
}

impl Verdict {
    /// Every verdict, in the contract's order (`DTLS_VERDICTS`): what `session_end.detail.verdict`
    /// may say.
    #[cfg(test)]
    pub(crate) const ALL: [Self; 8] = [
        Verdict::NothingFromViewer,
        Verdict::NoReplySent,
        Verdict::ViewerResendsHello,
        Verdict::ViewerSilentAfterHello,
        Verdict::SecondFlightStuck,
        Verdict::NominatedPathSilent,
        Verdict::NoHelloSent,
        Verdict::Unclear,
    ];

    /// `send` is where str0m sends DTLS: the destination of its last DTLS or media datagram, or
    /// the pair its stats named. `now` dates the silence on it.
    pub(crate) fn of(
        role: DtlsRole,
        book: &PathBook,
        send: Option<SocketAddr>,
        now: Instant,
    ) -> Self {
        let out = book.total(Dir::Out, Kind::Dtls);
        let inn = book.total(Dir::In, Kind::Dtls);
        let seen_in = book.dtls_seen(Dir::In);
        let send_silent = send.is_some_and(|s| book.send_path_silent(s, now));
        match role {
            DtlsRole::Server | DtlsRole::Unknown if inn.packets == 0 => Verdict::NothingFromViewer,
            DtlsRole::Server if out.packets == 0 => Verdict::NoReplySent,
            DtlsRole::Server if seen_in.has(HS_CLIENT_KEY_EXCHANGE) => Verdict::SecondFlightStuck,
            DtlsRole::Server if send_silent => Verdict::NominatedPathSilent,
            DtlsRole::Server if seen_in.client_hellos >= 2 => Verdict::ViewerResendsHello,
            DtlsRole::Server if seen_in.client_hellos == 1 => Verdict::ViewerSilentAfterHello,
            DtlsRole::Client if out.packets == 0 => Verdict::NoHelloSent,
            DtlsRole::Client if inn.packets == 0 => Verdict::NothingFromViewer,
            _ => Verdict::Unclear,
        }
    }

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Verdict::NothingFromViewer => "nothing_from_viewer",
            Verdict::NoReplySent => "no_reply_sent",
            Verdict::ViewerResendsHello => "viewer_resends_hello",
            Verdict::ViewerSilentAfterHello => "viewer_silent_after_hello",
            Verdict::SecondFlightStuck => "second_flight_stuck",
            Verdict::NominatedPathSilent => "nominated_path_silent",
            Verdict::NoHelloSent => "no_hello_sent",
            Verdict::Unclear => "unclear",
        }
    }

    /// What it means, for the log.
    pub(crate) fn hint(self) -> &'static str {
        match self {
            Verdict::NothingFromViewer => {
                "not one DTLS datagram has arrived from the viewer while its STUN does: its \
                 ClientHello is lost on the way here, or it never sent one"
            }
            Verdict::NoReplySent => {
                "the viewer's ClientHello arrived and nothing went back: a fault on this side"
            }
            Verdict::ViewerResendsHello => {
                "the viewer keeps resending its ClientHello and never its next flight, so our reply \
                 is not reaching it, although the pair it goes to is alive: STUN and its \
                 ClientHello get through, our larger flight (dtls_out max) does not"
            }
            Verdict::NominatedPathSilent => {
                "our DTLS goes to the pair str0m nominated (pair), and the viewer is silent on it — \
                 no STUN from it lately, or none of our checks on it answered — while its \
                 ClientHello and STUN come over other paths: str0m holds on to the \
                 highest-priority pair the viewer ever nominated, dead or not; not a size problem \
                 (paths: where the viewer talks)"
            }
            Verdict::ViewerSilentAfterHello => {
                "the viewer sent its ClientHello once and nothing since, although our flight went \
                 out: its answer (the flight with its certificate) is not arriving, or it gave up"
            }
            Verdict::SecondFlightStuck => {
                "the viewer's second flight arrived and DTLS is still not up: part of it lost \
                 (dtls_in max), or rejected"
            }
            Verdict::NoHelloSent => "as the DTLS client this side has not sent its ClientHello",
            Verdict::Unclear => "the counters point at neither side; see paths",
        }
    }
}

/// What [`judge_send_path`] makes of the pair str0m sends on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Follow {
    /// Stay: str0m's choice stands, for this reason.
    Hold(Hold),
    /// Take str0m off the pair it sends on. See [`Leave`].
    Leave(Leave),
}

/// Why str0m's send pair stands. Compared from one look to the next, so the run loop logs a
/// change of reason rather than every look.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Hold {
    /// Our checks on the send pair are answered, or have not gone unanswered long enough to call
    /// it dead. Every healthy session, all the time.
    SendPathAnswers,
    /// The send pair is one this loop already took str0m off; its next DTLS or media datagram
    /// will show where it went.
    Moving,
    /// The send pair is past [`MAX_PATHS`]: nothing is known about it.
    SendPathUncounted,
    /// The send pair is dead, and not one DTLS or RTP/RTCP datagram has come from the viewer: no
    /// sign of where it is.
    NoViewerData,
    /// The send pair is dead, and the viewer's latest datagram came from it all the same.
    ViewerOnSendPath,
    /// The viewer talks on a pair this loop took str0m off earlier in this ICE generation.
    ViewerOnWithdrawnPath,
    /// The viewer talks on an address past [`MAX_PATHS`].
    ViewerPathUncounted,
    /// The viewer talks on a pair it has not nominated in this ICE generation: str0m would have
    /// nothing to move to.
    ViewerPathNotNominated,
    /// The viewer talks on a pair that has not answered one of our checks lately.
    ViewerPathNotAnswering,
}

impl Hold {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Hold::SendPathAnswers => "send_path_answers",
            Hold::Moving => "moving",
            Hold::SendPathUncounted => "send_path_uncounted",
            Hold::NoViewerData => "no_viewer_data",
            Hold::ViewerOnSendPath => "viewer_on_send_path",
            Hold::ViewerOnWithdrawnPath => "viewer_on_withdrawn_path",
            Hold::ViewerPathUncounted => "viewer_path_uncounted",
            Hold::ViewerPathNotNominated => "viewer_path_not_nominated",
            Hold::ViewerPathNotAnswering => "viewer_path_not_answering",
        }
    }

    pub(crate) fn hint(self) -> &'static str {
        match self {
            Hold::SendPathAnswers => {
                "the pair str0m sends on answers our checks (or has not gone unanswered long \
                 enough to call it dead)"
            }
            Hold::Moving => {
                "str0m was just taken off this pair; its next DTLS or media datagram shows where \
                 it went"
            }
            Hold::SendPathUncounted => "the send pair is past the path book's limit; nothing known",
            Hold::NoViewerData => {
                "the send pair does not answer, but no DTLS or media has come from the viewer on \
                 any pair to say where it is; str0m's own timeouts decide"
            }
            Hold::ViewerOnSendPath => {
                "the send pair does not answer our checks, but the viewer's latest datagram came \
                 from it: the path works one way at least, and there is nowhere better to go"
            }
            Hold::ViewerOnWithdrawnPath => {
                "the viewer talks on a pair str0m was taken off earlier in this ICE generation; \
                 only a restart brings it back"
            }
            Hold::ViewerPathUncounted => "the viewer's pair is past the path book's limit",
            Hold::ViewerPathNotNominated => {
                "the send pair does not answer and the viewer talks on another, which it has not \
                 nominated: str0m would have no pair to move to"
            }
            Hold::ViewerPathNotAnswering => {
                "the send pair does not answer and the viewer talks on another, which has not \
                 answered our checks lately either"
            }
        }
    }
}

/// Take str0m off `dead` (the send pair first, then every other pair the viewer nominated that
/// has stopped answering), so the pair it sends on next is one the viewer nominated and answers
/// on — `to` itself, unless the viewer nominated a live pair that outranks it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Leave {
    pub(crate) dead: Vec<SocketAddr>,
    pub(crate) to: SocketAddr,
}

/// Whether to take str0m off `send`, the pair it sends DTLS and media on. `dtls_up` picks the
/// threshold ([`FOLLOW_DEAD_AFTER_HANDSHAKE`] or [`FOLLOW_DEAD_AFTER_CONNECTED`]); `left` is what
/// this ICE generation already took str0m off.
///
/// Leave only when all of this holds:
///   * our checks on `send` go unanswered ([`Evidence::dead`]): our datagrams do not reach the
///     viewer there, or its answers do not reach us;
///   * the viewer's latest DTLS or RTP/RTCP datagram came from another pair, `to`: libwebrtc
///     sends everything on its selected pair, so that is where the viewer is;
///   * the viewer nominated `to` in this ICE generation, so str0m has it as a nominated pair to
///     move to (it only ever sends on one);
///   * `to` answered one of our checks within [`FOLLOW_ALIVE_WITHIN`] and is not dead itself.
///
/// Every one of these is about the viewer's own choice, not ours, so a session whose pairs both
/// work never moves; and a pair left is withdrawn from str0m for the rest of the ICE generation,
/// so a move is never undone and the pairs cannot take turns.
pub(crate) fn judge_send_path(
    book: &PathBook,
    send: SocketAddr,
    dtls_up: bool,
    left: &[SocketAddr],
    now: Instant,
) -> Follow {
    let dead_after = if dtls_up {
        FOLLOW_DEAD_AFTER_CONNECTED
    } else {
        FOLLOW_DEAD_AFTER_HANDSHAKE
    };
    if left.contains(&send) {
        return Follow::Hold(Hold::Moving);
    }
    let Some(s) = book.path(send) else {
        return Follow::Hold(Hold::SendPathUncounted);
    };
    if !s.ev.dead(now, dead_after) {
        return Follow::Hold(Hold::SendPathAnswers);
    }
    let Some((to, _)) = book.last_data() else {
        return Follow::Hold(Hold::NoViewerData);
    };
    if to == send {
        return Follow::Hold(Hold::ViewerOnSendPath);
    }
    if left.contains(&to) {
        return Follow::Hold(Hold::ViewerOnWithdrawnPath);
    }
    let Some(a) = book.path(to) else {
        return Follow::Hold(Hold::ViewerPathUncounted);
    };
    if a.ev.nominations == 0 {
        return Follow::Hold(Hold::ViewerPathNotNominated);
    }
    if !a.ev.answered_within(now, FOLLOW_ALIVE_WITHIN) || a.ev.dead(now, dead_after) {
        return Follow::Hold(Hold::ViewerPathNotAnswering);
    }
    let mut dead = vec![send];
    dead.extend(
        book.paths
            .iter()
            .filter(|p| p.remote != send && p.remote != to && !left.contains(&p.remote))
            .filter(|p| p.ev.nominations > 0 && p.ev.dead(now, dead_after))
            .map(|p| p.remote),
    );
    Follow::Leave(Leave { dead, to })
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::time::{Duration, Instant};

    use super::{
        judge_send_path, peek_dtls, peek_stun, Dir, DtlsRole, DtlsSeen, DtlsWatch, Follow, Hold,
        Kind, Leave, PathBook, Stall, StunClass, Verdict, DTLS_STALL_REPORT_EVERY,
        DTLS_STALL_WARN_AFTER, FOLLOW_DEAD_AFTER_CONNECTED, FOLLOW_DEAD_AFTER_HANDSHAKE, MAX_PATHS,
        STUN_MAGIC,
    };

    fn addr(s: &str) -> SocketAddr {
        s.parse().expect("addr")
    }

    const MS: fn(u64) -> Duration = Duration::from_millis;

    /// A DTLS 1.2 record: content type, version 1.2, epoch, sequence number 0, then `body`.
    fn record(content_type: u8, epoch: u16, body: &[u8]) -> Vec<u8> {
        let mut r = vec![content_type, 0xfe, 0xfd];
        r.extend_from_slice(&epoch.to_be_bytes());
        r.extend_from_slice(&[0; 6]);
        r.extend_from_slice(&u16::try_from(body.len()).expect("small").to_be_bytes());
        r.extend_from_slice(body);
        r
    }

    /// A handshake message fragment: type, total length, sequence, offset, then `body_len` bytes.
    fn handshake(msg_type: u8, offset: u32, body_len: usize) -> Vec<u8> {
        let len = u32::try_from(body_len).expect("small").to_be_bytes();
        let off = offset.to_be_bytes();
        let mut h = vec![msg_type, len[1], len[2], len[3], 0, 0];
        h.extend_from_slice(&off[1..]);
        h.extend_from_slice(&len[1..]);
        h.extend(std::iter::repeat_n(0xab, body_len));
        h
    }

    /// What the viewer's ClientHello looks like on the wire.
    fn client_hello() -> Vec<u8> {
        record(22, 0, &handshake(1, 0, 180))
    }

    /// The server's flight in one datagram, as dimpl packs it: ServerHello, Certificate,
    /// ServerKeyExchange, CertificateRequest, ServerHelloDone, a record each.
    fn server_flight() -> Vec<u8> {
        let mut d = Vec::new();
        for (t, len) in [(2, 70), (11, 390), (12, 150), (13, 30), (14, 0)] {
            d.extend(record(22, 0, &handshake(t, 0, len)));
        }
        d
    }

    #[test]
    fn kinds_follow_rfc_7983() {
        for (first, kind) in [
            (0x00, Kind::Stun),
            (0x01, Kind::Stun),
            (0x03, Kind::Stun),
            (0x04, Kind::Other),
            (0x13, Kind::Other),
            (0x14, Kind::Dtls),
            (0x16, Kind::Dtls),
            (0x3f, Kind::Dtls),
            (0x40, Kind::Other),
            (0x7f, Kind::Other),
            (0x80, Kind::Rtp),
            (0xbf, Kind::Rtp),
            (0xc0, Kind::Other),
        ] {
            assert_eq!(Kind::of(&[first, 0, 0]), kind, "{first:#x}");
        }
        assert_eq!(Kind::of(&[]), Kind::Other, "an empty datagram");
    }

    #[test]
    fn dtls_records_are_named_from_their_headers() {
        let ch = peek_dtls(&client_hello());
        assert!(ch.client_hello && !ch.server_hello);
        assert_eq!(DtlsSeen::from(ch).to_string(), "CH");

        let flight = peek_dtls(&server_flight());
        assert!(flight.server_hello && !flight.client_hello);
        assert_eq!(
            DtlsSeen::from(flight).to_string(),
            "SH Cert SKE CR SHD",
            "every record of the datagram is read"
        );

        // A message fragmented across datagrams starts once: the second fragment is not a resend.
        let second_fragment = peek_dtls(&record(22, 0, &handshake(1, 600, 100)));
        assert!(!second_fragment.client_hello);
        assert_eq!(DtlsSeen::from(second_fragment).to_string(), "CH");

        // The client's second flight: Certificate, ClientKeyExchange, CertificateVerify, then the
        // cipher change and its encrypted Finished.
        let mut d = Vec::new();
        for (t, len) in [(11, 380), (16, 66), (15, 72)] {
            d.extend(record(22, 0, &handshake(t, 0, len)));
        }
        d.extend(record(20, 0, &[1]));
        d.extend(record(22, 1, &[0x55; 40]));
        assert_eq!(
            DtlsSeen::from(peek_dtls(&d)).to_string(),
            "Cert CV CKE CCS Enc"
        );

        // After the handshake: SCTP in application data. And a plaintext fatal alert names itself.
        assert_eq!(
            DtlsSeen::from(peek_dtls(&record(23, 1, &[0; 60]))).to_string(),
            "App"
        );
        assert_eq!(
            DtlsSeen::from(peek_dtls(&record(21, 0, &[2, 40]))).to_string(),
            "Alert(40)"
        );
        // DTLS 1.3's unified header is encrypted: named, not parsed.
        assert_eq!(
            DtlsSeen::from(peek_dtls(&[0x2c, 1, 2, 3, 4])).to_string(),
            "D13"
        );
        // Cut short, or a content type DTLS 1.2 does not have: said so, never a panic.
        let mut cut = client_hello();
        cut.truncate(20);
        assert_eq!(DtlsSeen::from(peek_dtls(&cut)).to_string(), "Malformed");
        assert_eq!(
            DtlsSeen::from(peek_dtls(&[0x1f; 20])).to_string(),
            "Malformed"
        );
        assert_eq!(
            DtlsSeen::from(peek_dtls(&[22, 0xfe])).to_string(),
            "Malformed"
        );
    }

    #[test]
    fn a_book_counts_each_path_each_way_by_kind() {
        let t0 = Instant::now();
        let local = addr("172.18.0.1:63604");
        let lan = addr("192.168.0.24:63604");
        let srflx = addr("203.0.113.158:43410");
        let relay = addr("198.51.100.62:28535");
        let stun = [0u8; 96];
        let mut book = PathBook::default();

        let n = book.note(Dir::Out, Some(local), srflx, &stun, t0);
        assert_eq!(n.kind, Kind::Stun);
        assert!(n.first_on_path && n.first_anywhere);
        let n = book.note(Dir::Out, Some(lan), relay, &stun[..80], t0 + MS(6));
        assert!(
            n.first_on_path && !n.first_anywhere,
            "STUN already went elsewhere"
        );
        let n = book.note(Dir::In, None, srflx, &stun[..84], t0 + MS(40));
        assert!(n.first_on_path && n.first_anywhere, "the first way in");
        assert!(
            !book
                .note(Dir::Out, Some(lan), srflx, &stun, t0 + MS(50))
                .first_on_path
        );

        let n = book.note(Dir::In, None, srflx, &client_hello(), t0 + MS(600));
        assert_eq!(n.kind, Kind::Dtls);
        assert!(n.first_anywhere);
        assert_eq!(n.dtls.map(|p| p.client_hello), Some(true));
        let flight = server_flight();
        for ms in [610, 1_600, 3_700] {
            book.note(Dir::Out, Some(local), srflx, &flight, t0 + MS(ms));
        }
        book.note(Dir::In, None, srflx, &client_hello(), t0 + MS(1_590));
        book.note(Dir::In, None, relay, &[0xff, 1, 2], t0 + MS(2_000));
        book.unparsed(relay);

        let p = &book.paths()[0];
        assert_eq!(p.remote, srflx);
        let out = p.tally(Dir::Out, Kind::Dtls);
        assert_eq!(
            (out.packets, out.bytes, out.max),
            (3, 3 * flight.len() as u64, flight.len())
        );
        assert_eq!(
            (out.first, out.last),
            (Some(t0 + MS(610)), Some(t0 + MS(3_700)))
        );
        assert_eq!(p.tally(Dir::In, Kind::Dtls).packets, 2);
        assert_eq!(p.tally(Dir::Out, Kind::Stun).packets, 2);
        assert_eq!(book.total(Dir::Out, Kind::Stun).packets, 3);
        assert_eq!(book.total(Dir::Out, Kind::Stun).max, 96);
        assert_eq!(book.sources_of(Kind::Stun), 1);
        assert_eq!(book.dtls_seen(Dir::In).client_hellos, 2);
        assert_eq!(book.dtls_seen(Dir::Out).server_hellos, 3);
        assert_eq!(book.paths()[1].tally(Dir::In, Kind::Other).packets, 1);

        let line = book.describe(
            t0,
            |a| if a == srflx { "srflx" } else { "relay/tcp" }.to_string(),
            Some(srflx),
        );
        let fl = flight.len();
        assert_eq!(
            line,
            format!(
                "203.0.113.158:43410 srflx*: out stun 2p/192B<=96 @0.00-0.05s, dtls 3p/{}B<={fl} \
                 @0.61-3.70s {{SHx3 Cert SKE CR SHD}} via 172.18.0.1:63604,192.168.0.24:63604; in \
                 stun 1p/84B<=84 @0.04-0.04s, dtls 2p/{}B<={} @0.60-1.59s {{CHx2}} | \
                 198.51.100.62:28535 relay/tcp: out stun 1p/80B<=80 @0.01-0.01s via \
                 192.168.0.24:63604; in other 1p/3B<=3 @2.00-2.00s unparsed 1",
                3 * fl,
                2 * client_hello().len(),
                client_hello().len()
            )
        );
        assert_eq!(
            book.dtls_summary(Dir::In, t0),
            format!(
                "2p/{}B<={} @0.60-1.59s {{CHx2}}",
                2 * client_hello().len(),
                client_hello().len()
            )
        );
        assert_eq!(PathBook::default().dtls_summary(Dir::Out, t0), "-");
        assert_eq!(
            PathBook::default().describe(t0, |_| String::new(), None),
            "-"
        );
    }

    #[test]
    fn a_book_past_its_limit_counts_without_an_address() {
        let t0 = Instant::now();
        let mut book = PathBook::default();
        for port in 0..MAX_PATHS as u16 + 3 {
            let remote = SocketAddr::from(([198, 51, 100, 1], 1000 + port));
            book.note(Dir::In, None, remote, &[1; 20], t0);
        }
        book.unparsed(addr("198.51.100.2:1"));
        assert_eq!(book.paths().len(), MAX_PATHS);
        assert_eq!(
            book.total(Dir::In, Kind::Stun).packets,
            MAX_PATHS as u64 + 3
        );
        let line = book.describe(t0, |_| "x".to_string(), None);
        assert!(
            line.ends_with(&format!(
                "| 3 datagrams on addresses past the first {MAX_PATHS} (1 unparsed)"
            )),
            "{line}"
        );
    }

    #[test]
    fn the_role_is_read_from_the_answers_setup() {
        assert_eq!(
            DtlsRole::from_answer("v=0\r\na=setup:passive\r\n"),
            DtlsRole::Server
        );
        assert_eq!(
            DtlsRole::from_answer("v=0\r\na=setup:active\r\n"),
            DtlsRole::Client
        );
        assert_eq!(DtlsRole::from_answer("v=0\r\n"), DtlsRole::Unknown);
    }

    #[test]
    fn a_stalled_handshake_is_warned_once_then_reported_every_five_seconds() {
        let t0 = Instant::now();
        let mut w = DtlsWatch::default();
        assert_eq!(
            w.poll(t0 + Duration::from_secs(60)),
            Stall::Quiet,
            "no ICE yet"
        );
        assert_eq!(w.next_due(), None);

        assert!(w.ice_connected(t0));
        assert!(!w.ice_connected(t0 + MS(900)), "the clock starts once");
        assert_eq!(w.next_due(), Some(t0 + DTLS_STALL_WARN_AFTER));
        assert_eq!(w.poll(t0 + DTLS_STALL_WARN_AFTER - MS(1)), Stall::Quiet);
        let warned = t0 + DTLS_STALL_WARN_AFTER + MS(4);
        assert_eq!(
            w.poll(warned),
            Stall::Warn {
                waited: DTLS_STALL_WARN_AFTER + MS(4)
            }
        );
        assert_eq!(w.poll(warned + MS(10)), Stall::Quiet, "once");
        assert_eq!(w.next_due(), Some(warned + DTLS_STALL_REPORT_EVERY));
        assert_eq!(
            w.poll(warned + DTLS_STALL_REPORT_EVERY - MS(1)),
            Stall::Quiet
        );
        let reported = warned + DTLS_STALL_REPORT_EVERY;
        assert_eq!(
            w.poll(reported),
            Stall::Report {
                waited: DTLS_STALL_WARN_AFTER + MS(4) + DTLS_STALL_REPORT_EVERY
            }
        );
        assert_eq!(w.stalled_for(reported), Some(reported - t0));

        // DTLS comes up: silence, and how long it took is the answer.
        assert_eq!(
            w.dtls_up(t0 + Duration::from_secs(9)),
            Some(Duration::from_secs(9))
        );
        assert_eq!(w.poll(t0 + Duration::from_secs(60)), Stall::Quiet);
        assert_eq!(w.next_due(), None);
        assert_eq!(w.stalled_for(t0 + Duration::from_secs(60)), None);
    }

    #[test]
    fn a_handshake_that_finishes_in_time_is_never_reported() {
        let t0 = Instant::now();
        let mut w = DtlsWatch::default();
        w.ice_connected(t0);
        assert_eq!(w.dtls_up(t0 + MS(180)), Some(MS(180)));
        assert_eq!(w.poll(t0 + Duration::from_secs(30)), Stall::Quiet);
        // What `session_end.detail` says: how long DTLS took after ICE, kept from the first up.
        assert_eq!(w.dtls_after_ice(), Some(MS(180)));
        w.dtls_up(t0 + Duration::from_secs(5));
        assert_eq!(w.dtls_after_ice(), Some(MS(180)), "the first up stands");
        // And DTLS without ICE having been seen (it cannot happen, but it must not panic).
        let mut no_ice = DtlsWatch::default();
        assert_eq!(no_ice.dtls_up(t0), None);
        assert_eq!(no_ice.dtls_after_ice(), None);
        let mut ice_only = DtlsWatch::default();
        ice_only.ice_connected(t0);
        assert_eq!(ice_only.dtls_after_ice(), None, "DTLS never came");
    }

    /// `session_end.detail.verdict` is `Verdict::as_str`: every word is the contract's
    /// (`DTLS_VERDICTS`, mirrored in `afklink_protocol::metrics`), in its order.
    #[test]
    fn the_verdicts_are_the_contracts_words() {
        let words: Vec<&str> = Verdict::ALL.iter().map(|v| v.as_str()).collect();
        assert_eq!(words, afklink_protocol::metrics::DTLS_VERDICTS);
    }

    /// Each verdict from the counters it is read from, the first one being the one-way VPN path's.
    #[test]
    fn a_verdict_names_the_side_that_is_not_heard() {
        let t0 = Instant::now();
        let viewer = addr("203.0.113.158:43410");
        let local = Some(addr("172.18.0.1:63604"));
        let verdict = |dtls_in: &[&[u8]], dtls_out: &[&[u8]], role: DtlsRole| {
            let mut book = PathBook::default();
            book.note(Dir::In, None, viewer, &[1; 96], t0);
            for d in dtls_in {
                book.note(Dir::In, None, viewer, d, t0);
            }
            for d in dtls_out {
                book.note(Dir::Out, local, viewer, d, t0);
            }
            Verdict::of(role, &book, Some(viewer), t0)
        };
        let (ch, flight) = (client_hello(), server_flight());
        let (ch, flight) = (ch.as_slice(), flight.as_slice());
        let second: Vec<u8> = [(11u8, 380usize), (16, 66), (15, 72)]
            .into_iter()
            .flat_map(|(t, len)| record(22, 0, &handshake(t, 0, len)))
            .collect();
        let server = DtlsRole::Server;

        assert_eq!(verdict(&[], &[], server), Verdict::NothingFromViewer);
        assert_eq!(verdict(&[ch], &[], server), Verdict::NoReplySent);
        assert_eq!(
            verdict(&[ch, ch, ch], &[flight, flight], server),
            Verdict::ViewerResendsHello
        );
        assert_eq!(
            verdict(&[ch], &[flight, flight], server),
            Verdict::ViewerSilentAfterHello
        );
        assert_eq!(
            verdict(&[ch, &second], &[flight], server),
            Verdict::SecondFlightStuck
        );
        assert_eq!(verdict(&[], &[], DtlsRole::Client), Verdict::NoHelloSent);
        assert_eq!(
            verdict(&[], &[ch], DtlsRole::Client),
            Verdict::NothingFromViewer
        );
        assert_eq!(
            verdict(&[flight], &[ch], DtlsRole::Client),
            Verdict::Unclear
        );
        assert_eq!(
            verdict(&[], &[], DtlsRole::Unknown),
            Verdict::NothingFromViewer
        );
    }

    /// A STUN message: header (type, length, magic cookie, transaction id), then `attrs`, each
    /// padded to four bytes as RFC 5389 §15 has it.
    fn stun_message(typ: u16, attrs: &[(u16, &[u8])]) -> Vec<u8> {
        let mut body = Vec::new();
        for (t, v) in attrs {
            body.extend_from_slice(&t.to_be_bytes());
            body.extend_from_slice(&u16::try_from(v.len()).expect("small").to_be_bytes());
            body.extend_from_slice(v);
            body.resize(body.len().next_multiple_of(4), 0);
        }
        let mut m = typ.to_be_bytes().to_vec();
        m.extend_from_slice(&u16::try_from(body.len()).expect("small").to_be_bytes());
        m.extend_from_slice(&STUN_MAGIC);
        m.extend_from_slice(&[7; 12]);
        m.extend_from_slice(&body);
        m
    }

    /// A check the viewer sends us, shaped like libwebrtc's: USERNAME `<our ufrag>:<its ufrag>`
    /// (an odd length, so the padding is exercised), PRIORITY, ICE-CONTROLLING, USE-CANDIDATE when
    /// it nominates, then MESSAGE-INTEGRITY and FINGERPRINT.
    fn check_to(our_ufrag: &str, nominate: bool) -> Vec<u8> {
        let username = format!("{our_ufrag}:6YR1");
        let mut attrs: Vec<(u16, &[u8])> = vec![
            (0x0006, username.as_bytes()),
            (0x0024, &[0x6e, 0x00, 0x1e, 0xff]),
            (0x802a, &[1, 2, 3, 4, 5, 6, 7, 8]),
        ];
        if nominate {
            attrs.push((0x0025, &[]));
        }
        attrs.push((0x0008, &[0x5a; 20]));
        attrs.push((0x8028, &[1, 2, 3, 4]));
        stun_message(0x0001, &attrs)
    }

    /// Our check to the viewer: USERNAME `<its ufrag>:<ours>`, ICE-CONTROLLED, no USE-CANDIDATE.
    fn our_check() -> Vec<u8> {
        stun_message(
            0x0001,
            &[
                (0x0006, b"6YR1:gkHAtTVfTVbd6kBa"),
                (0x0024, &[0x6e, 0x00, 0x1e, 0xff]),
                (0x8029, &[8; 8]),
                (0x0008, &[0x5a; 20]),
            ],
        )
    }

    /// A Binding success response: XOR-MAPPED-ADDRESS, MESSAGE-INTEGRITY, FINGERPRINT.
    fn reply() -> Vec<u8> {
        stun_message(
            0x0101,
            &[
                (0x0020, &[0, 1, 0xe6, 0x7d, 1, 2, 3, 4]),
                (0x0008, &[0x5a; 20]),
                (0x8028, &[1, 2, 3, 4]),
            ],
        )
    }

    #[test]
    fn stun_is_read_for_its_class_nomination_and_recipient() {
        let c = check_to("gkHAtTVfTVbd6kBa", true);
        let p = peek_stun(&c);
        assert_eq!(p.class, StunClass::Request);
        assert!(p.use_candidate);
        assert_eq!(p.recipient_ufrag, Some(b"gkHAtTVfTVbd6kBa".as_slice()));
        let plain = check_to("gkHAtTVfTVbd6kBa", false);
        assert!(!peek_stun(&plain).use_candidate, "no USE-CANDIDATE");
        assert_eq!(peek_stun(&reply()).class, StunClass::Success);
        assert_eq!(
            peek_stun(&stun_message(0x0111, &[(0x0009, &[0, 0, 4, 87])])).class,
            StunClass::Error
        );
        assert_eq!(
            peek_stun(&stun_message(0x0011, &[])).class,
            StunClass::Indication
        );
        // A TURN method, no magic cookie, cut short: `Other`, or as far as it goes; never a panic.
        assert_eq!(
            peek_stun(&stun_message(0x0003, &[])).class,
            StunClass::Other
        );
        assert_eq!(peek_stun(&[0; 96]).class, StunClass::Other);
        assert_eq!(peek_stun(&[1; 10]).class, StunClass::Other);
        let mut cut = check_to("gkHAtTVfTVbd6kBa", true);
        cut.truncate(30);
        let p = peek_stun(&cut);
        assert_eq!(p.class, StunClass::Request);
        assert!(!p.use_candidate, "the attribute was cut off");
        // A length field that claims more than there is reads what there is.
        let mut long = check_to("x", true);
        long[3] = 0xff;
        assert!(peek_stun(&long).use_candidate);
    }

    #[test]
    fn the_path_lines_count_checks_nominations_and_replies_each_way() {
        let t0 = Instant::now();
        let local = Some(addr("172.18.0.1:59080"));
        let srflx = addr("203.0.113.158:56111");
        let mut book = PathBook::default();
        book.new_generation(Some("gkHAtTVfTVbd6kBa".into()));
        let nominating = check_to("gkHAtTVfTVbd6kBa", true);
        book.note(Dir::Out, local, srflx, &our_check(), t0 + MS(110));
        book.note(Dir::Out, local, srflx, &our_check(), t0 + MS(360));
        book.note(Dir::In, None, srflx, &nominating, t0 + MS(390));
        book.note(Dir::Out, local, srflx, &reply(), t0 + MS(391));
        book.note(
            Dir::In,
            None,
            srflx,
            &check_to("old-ufrag", true),
            t0 + MS(500),
        );
        book.note(Dir::Out, local, srflx, &our_check(), t0 + MS(860));
        let line = book.describe(t0, |_| "srflx".to_string(), Some(srflx));
        assert!(
            line.contains("out stun 4p/") && line.contains("[checks 3, replies 1]"),
            "{line}"
        );
        assert!(
            line.contains("in stun 2p/")
                && line.contains("[checks 1, nominating 1, replies 0, stale 1]"),
            "{line}"
        );
        let ev = book.path(srflx).expect("counted").evidence();
        assert_eq!(
            ev.nominations, 1,
            "a check to a replaced ufrag nominates nothing"
        );
        assert_eq!(ev.first_heard, Some(t0 + MS(390)));
        assert_eq!(
            (ev.unanswered, ev.unanswered_since),
            (1, Some(t0 + MS(860))),
            "checks sent before the viewer was heard on the pair do not count against it"
        );
        // A restart: the evidence starts over, the session's counts do not.
        book.new_generation(Some("8vjXtUmnsznTrlJU".into()));
        let p = book.path(srflx).expect("counted");
        assert_eq!(*p.evidence(), super::Evidence::default());
        assert_eq!(p.stun_seen(Dir::Out).checks, 3);
    }

    /// Datagrams to note, played in the order of their times — the evidence is a sequence (a check
    /// counts against a pair only after the viewer was heard there, a reply clears what came
    /// before), so the order the test writes them in must not matter.
    #[derive(Default)]
    struct Script(Vec<(Duration, Dir, SocketAddr, Vec<u8>)>);

    impl Script {
        /// `n` datagrams evenly from `first` to `last` seconds.
        fn spread(
            &mut self,
            dir: Dir,
            remote: SocketAddr,
            datagram: &[u8],
            n: u32,
            (first, last): (f64, f64),
        ) {
            for i in 0..n {
                let s = if n == 1 {
                    first
                } else {
                    first + (last - first) * f64::from(i) / f64::from(n - 1)
                };
                self.0
                    .push((Duration::from_secs_f64(s), dir, remote, datagram.to_vec()));
            }
        }

        /// Note everything, earliest first; datagrams at the same time in the order written.
        fn play(mut self, book: &mut PathBook, t0: Instant) {
            self.0.sort_by_key(|e| e.0);
            let local = Some(addr("172.18.0.1:59080"));
            for (at, dir, remote, d) in self.0 {
                let local = (dir == Dir::Out).then_some(local).flatten();
                book.note(dir, local, remote, &d, t0 + at);
            }
        }
    }

    const SRFLX: &str = "203.0.113.158:56111";
    const RELAY_TCP_1: &str = "198.51.100.144:51917";
    const RELAY_TCP_2: &str = "198.51.100.67:53242";
    const RELAY_TLS_1: &str = "198.51.100.58:42675";
    const RELAY_UDP: &str = "198.51.100.143:23002";
    const RELAY_TLS_2: &str = "198.51.100.65:27468";

    /// A recorded session over a one-way VPN path, as its stall warning counted it three seconds
    /// after ICE connected: every path's STUN and DTLS, each way, with the times of the first and
    /// the last datagram. What the STUN was, that log did not say; `stun` is what to write for it.
    fn one_way_vpn_stall(stun: &[u8]) -> Script {
        let mut s = Script::default();
        let (ch, flight) = (client_hello(), server_flight());
        let srflx = addr(SRFLX);
        s.spread(Dir::Out, srflx, stun, 15, (0.11, 2.01));
        s.spread(Dir::Out, srflx, &flight, 5, (0.60, 2.70));
        s.spread(Dir::In, srflx, stun, 3, (0.39, 1.14));
        for (relay, out, out_at, inn, in_at) in [
            (RELAY_TCP_1, 14, (0.19, 2.09), 12, (0.40, 2.26)),
            (RELAY_TCP_2, 15, (0.27, 2.17), 15, (0.43, 2.32)),
            (RELAY_TLS_1, 13, (0.35, 2.24), 13, (0.50, 2.39)),
            (RELAY_UDP, 17, (0.40, 3.26), 14, (0.55, 3.26)),
            (RELAY_TLS_2, 12, (0.44, 2.32), 12, (0.60, 2.48)),
        ] {
            s.spread(Dir::Out, addr(relay), stun, out, out_at);
            s.spread(Dir::In, addr(relay), stun, inn, in_at);
        }
        // The viewer's ClientHellos, each over the relay it had selected by then.
        s.spread(Dir::In, addr(RELAY_TCP_1), &ch, 1, (0.59, 0.59));
        s.spread(Dir::In, addr(RELAY_TCP_2), &ch, 1, (0.90, 0.90));
        s.spread(Dir::In, addr(RELAY_UDP), &ch, 2, (1.49, 2.70));
        s
    }

    fn played(s: Script) -> (PathBook, Instant) {
        let t0 = Instant::now();
        let mut b = PathBook::default();
        s.play(&mut b, t0);
        (b, t0)
    }

    /// The stall warning came 3.0 s after ICE connected at 0.39 s: our flight had
    /// gone five times to the srflx pair, not one DTLS datagram had come from it, and the viewer
    /// had last been heard there at 1.14 s while its STUN kept coming over the relays and its
    /// ClientHellos over three of them. That is a dead nominated pair, not a lost large datagram —
    /// and the verdict has to say so from those counters alone.
    #[test]
    fn a_one_way_vpn_stall_is_a_nominated_pair_gone_silent() {
        let (book, t0) = played(one_way_vpn_stall(&[0; 96]));
        let warned = t0 + MS(3_392);
        let srflx = addr(SRFLX);
        assert!(book.send_path_silent(srflx, warned));
        assert_eq!(
            Verdict::of(DtlsRole::Server, &book, Some(srflx), warned),
            Verdict::NominatedPathSilent
        );
        assert_eq!(
            Verdict::NominatedPathSilent.as_str(),
            "nominated_path_silent"
        );
        // Its hint says what the old one could not: a dead pair, not a size.
        assert!(Verdict::NominatedPathSilent
            .hint()
            .contains("not a size problem"));
        // With no send pair known the old verdict stands.
        assert_eq!(
            Verdict::of(DtlsRole::Server, &book, None, warned),
            Verdict::ViewerResendsHello
        );

        // Had the viewer still been talking on the srflx pair, the same resent ClientHellos would
        // have meant our flight is lost on a live pair: the size, as before.
        let mut s = one_way_vpn_stall(&[0; 96]);
        s.spread(Dir::In, srflx, &[0; 96], 4, (1.5, 3.3));
        let (alive, t0) = played(s);
        let warned = t0 + MS(3_392);
        assert!(!alive.send_path_silent(srflx, warned));
        assert_eq!(
            Verdict::of(DtlsRole::Server, &alive, Some(srflx), warned),
            Verdict::ViewerResendsHello
        );
        // A pair with DTLS from the viewer on it is not silent, however quiet its STUN.
        let mut s = one_way_vpn_stall(&[0; 96]);
        s.spread(Dir::In, srflx, &client_hello(), 1, (0.7, 0.7));
        let (talked, t0) = played(s);
        assert!(!talked.send_path_silent(srflx, t0 + MS(3_392)));
    }

    /// The same session with its STUN classified — the viewer's checks on the
    /// srflx pair nominating it and none of ours there answered, its checks and replies on the
    /// relays — at the moment the send-pair watch would have looked.
    fn one_way_vpn_stall_classified() -> (PathBook, Instant) {
        let ours = "gkHAtTVfTVbd6kBa";
        let mut s = Script::default();
        let (ch, flight) = (client_hello(), server_flight());
        let (check, nominating, answer) = (our_check(), check_to(ours, true), reply());
        let srflx = addr(SRFLX);
        s.spread(Dir::Out, srflx, &check, 15, (0.11, 2.01));
        s.spread(Dir::Out, srflx, &flight, 3, (0.60, 1.49));
        s.spread(Dir::In, srflx, &nominating, 3, (0.39, 1.14));
        for (relay, nominated, out_at, in_at) in [
            (RELAY_TCP_1, true, (0.19, 2.09), (0.40, 2.26)),
            (RELAY_TCP_2, true, (0.27, 2.17), (0.43, 2.32)),
            (RELAY_TLS_1, false, (0.35, 2.24), (0.50, 2.39)),
            (RELAY_UDP, true, (0.40, 2.10), (0.55, 2.10)),
            (RELAY_TLS_2, false, (0.44, 2.32), (0.60, 2.48)),
        ] {
            s.spread(Dir::Out, addr(relay), &check, 8, out_at);
            // Each check of ours answered, the viewer's own checks in between.
            s.spread(Dir::In, addr(relay), &answer, 8, in_at);
            s.spread(Dir::In, addr(relay), &check_to(ours, nominated), 6, in_at);
        }
        s.spread(Dir::In, addr(RELAY_TCP_1), &ch, 1, (0.59, 0.59));
        s.spread(Dir::In, addr(RELAY_TCP_2), &ch, 1, (0.90, 0.90));
        s.spread(Dir::In, addr(RELAY_UDP), &ch, 1, (1.49, 1.49));
        let t0 = Instant::now();
        let mut b = PathBook::default();
        b.new_generation(Some(ours.into()));
        s.play(&mut b, t0);
        (b, t0)
    }

    #[test]
    fn a_one_way_vpn_stall_leaves_the_srflx_pair_for_the_relay_the_viewer_uses() {
        let (book, t0) = one_way_vpn_stall_classified();
        let srflx = addr(SRFLX);
        let ev = book.path(srflx).expect("counted").evidence();
        assert_eq!((ev.nominations, ev.replies), (3, 0));
        // Our first check after the viewer was heard there (0.39 s) left at 0.49 s.
        let since = ev.unanswered_since.expect("unanswered") - t0;
        assert!(since > MS(390) && since < MS(600), "{since:?}");

        let judge = |at: u64| judge_send_path(&book, srflx, false, &[], t0 + MS(at));
        // A second and a half after that first unanswered check, and not before.
        assert_eq!(judge(1_900), Follow::Hold(Hold::SendPathAnswers));
        assert_eq!(
            judge(2_100),
            Follow::Leave(Leave {
                dead: vec![srflx],
                to: addr(RELAY_UDP)
            }),
            "the relay/udp pair: the viewer's last ClientHello came over it, it nominated it and \
             answers there; the TCP relays answer too, so only the srflx pair is dead"
        );
        // The move is made once: the pair left is not judged again, whatever str0m does next.
        assert_eq!(
            judge_send_path(&book, srflx, false, &[srflx], t0 + MS(2_100)),
            Follow::Hold(Hold::Moving)
        );
        // Once DTLS is up the bar is higher: three seconds of silence, not one and a half.
        assert_eq!(
            judge_send_path(&book, srflx, true, &[], t0 + MS(2_100)),
            Follow::Hold(Hold::SendPathAnswers)
        );
        assert!(FOLLOW_DEAD_AFTER_CONNECTED > FOLLOW_DEAD_AFTER_HANDSHAKE);
        assert!(matches!(
            judge_send_path(&book, srflx, true, &[], t0 + MS(3_600)),
            Follow::Leave(_)
        ));
    }

    #[test]
    fn a_dead_send_pair_stays_without_somewhere_better_to_go() {
        let ours = "gkHAtTVfTVbd6kBa";
        let (send, viewer) = (addr(SRFLX), addr(RELAY_UDP));
        let t0 = Instant::now();
        let at = t0 + MS(3_000);
        // A send pair whose three checks after the viewer's nomination went unanswered.
        let mut b = PathBook::default();
        b.new_generation(Some(ours.into()));
        b.note(Dir::In, None, send, &check_to(ours, true), t0);
        for ms in [100, 550, 1_000] {
            b.note(Dir::Out, None, send, &our_check(), t0 + MS(ms));
        }
        assert_eq!(
            judge_send_path(&b, send, false, &[], at),
            Follow::Hold(Hold::NoViewerData),
            "no DTLS or media from the viewer anywhere: no sign where it is"
        );

        b.note(Dir::In, None, send, &client_hello(), t0 + MS(500));
        assert_eq!(
            judge_send_path(&b, send, false, &[], at),
            Follow::Hold(Hold::ViewerOnSendPath)
        );

        // The viewer moves to a pair it has not nominated.
        b.note(Dir::In, None, viewer, &check_to(ours, false), t0 + MS(600));
        b.note(Dir::In, None, viewer, &reply(), t0 + MS(2_500));
        b.note(Dir::In, None, viewer, &client_hello(), t0 + MS(2_600));
        assert_eq!(
            judge_send_path(&b, send, false, &[], at),
            Follow::Hold(Hold::ViewerPathNotNominated)
        );
        // It nominates it, but in a generation a restart replaced: still nothing.
        b.note(
            Dir::In,
            None,
            viewer,
            &check_to("old", true),
            t0 + MS(2_700),
        );
        assert_eq!(
            judge_send_path(&b, send, false, &[], at),
            Follow::Hold(Hold::ViewerPathNotNominated)
        );
        // In ours: now it goes.
        b.note(Dir::In, None, viewer, &check_to(ours, true), t0 + MS(2_800));
        assert_eq!(
            judge_send_path(&b, send, false, &[], at),
            Follow::Leave(Leave {
                dead: vec![send],
                to: viewer
            })
        );
        // Unless that pair was left earlier in the generation.
        assert_eq!(
            judge_send_path(&b, send, false, &[viewer], at),
            Follow::Hold(Hold::ViewerOnWithdrawnPath)
        );
        // Or its last answer is too old.
        assert_eq!(
            judge_send_path(&b, send, false, &[], t0 + MS(8_000)),
            Follow::Hold(Hold::ViewerPathNotAnswering)
        );
        // A send pair that answers again is kept, whatever the viewer does.
        b.note(Dir::In, None, send, &reply(), t0 + MS(2_900));
        assert_eq!(
            judge_send_path(&b, send, false, &[], at),
            Follow::Hold(Hold::SendPathAnswers)
        );
    }

    /// Every other pair the viewer nominated that has stopped answering is left in the same move,
    /// so str0m does not fall onto the next dead one — but a pair nobody nominated is not touched.
    #[test]
    fn a_move_takes_every_dead_nominated_pair_with_it() {
        let ours = "u";
        let t0 = Instant::now();
        let (send, other_dead, unnominated_dead, viewer) = (
            addr("198.51.100.1:1000"),
            addr("198.51.100.2:1000"),
            addr("198.51.100.3:1000"),
            addr("198.51.100.4:1000"),
        );
        let mut b = PathBook::default();
        b.new_generation(Some(ours.into()));
        for (path, nominate) in [(send, true), (other_dead, true), (unnominated_dead, false)] {
            b.note(Dir::In, None, path, &check_to(ours, nominate), t0);
            for ms in [100, 350, 850, 1_200] {
                b.note(Dir::Out, None, path, &our_check(), t0 + MS(ms));
            }
        }
        b.note(Dir::In, None, viewer, &check_to(ours, true), t0);
        b.note(Dir::In, None, viewer, &reply(), t0 + MS(1_500));
        b.note(Dir::In, None, viewer, &client_hello(), t0 + MS(1_600));
        assert_eq!(
            judge_send_path(&b, send, false, &[], t0 + MS(2_000)),
            Follow::Leave(Leave {
                dead: vec![send, other_dead],
                to: viewer
            })
        );
    }
}
