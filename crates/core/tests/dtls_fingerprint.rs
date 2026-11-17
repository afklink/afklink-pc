//! The viewer's signed DTLS fingerprint is the one str0m holds the handshake to (device keys
//! protocol §3.3, §3.6).
//!
//! The viewer's device key signs `fp_viewer`, which the agent reads out of the offer with
//! [`viewer_fingerprint`]; str0m reads the offer itself and, in the DTLS handshake, refuses a
//! certificate whose SHA-256 is not the `a=fingerprint` it picked. The signature is only worth
//! something if those two agree: an offer where ours says "the genuine viewer's fingerprint" while
//! str0m picks another line would let whoever holds that other certificate in. So, against the
//! vendored str0m (through `afklink_transport::str0m`, the very copy the peers run on):
//!
//! * a peer built from the agent's own configuration ([`peer_rtc_config`]) completes a handshake
//!   with the certificate its offer names, and refuses one it does not name;
//! * over a set of offers with fingerprint lines placed, cased and spelled every way that matters,
//!   each handshaken by a genuine viewer and by one holding another certificate: whenever str0m
//!   lets a certificate in, ours yields exactly that certificate's fingerprint or refuses the offer;
//! * on the contract's vectors (`sdp-fingerprint.json`), whatever ours accepts is what str0m's own
//!   SDP parse picks, or str0m picks nothing.
//!
//! Everything runs in one process on a virtual clock: datagrams are handed between the two `Rtc`s,
//! no socket is opened.

use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use afklink_core::viewer_keys::sdp::{viewer_fingerprint, FpError};
use afklink_transport::str0m;
use afklink_transport::webrtc::peer_rtc_config;
use str0m::change::SdpOffer;
use str0m::config::{DtlsCert, Fingerprint};
use str0m::media::{Direction, MediaKind};
use str0m::net::{Protocol, Receive};
use str0m::{Candidate, Event, Input, Output, Rtc};

/// The error str0m's DTLS layer gives for a certificate the offer does not name
/// (`vendor/str0m/src/lib.rs`, `DtlsOutput::PeerCert`).
const NO_MATCH: &str = "remote fingerprint no match";

/// The longest a handshake may take on the virtual clock; an in-process one takes milliseconds.
const HANDSHAKE_LIMIT: Duration = Duration::from_secs(20);

fn agent_addr() -> SocketAddr {
    (Ipv4Addr::new(10, 0, 0, 1), 5000).into()
}

fn viewer_addr() -> SocketAddr {
    (Ipv4Addr::new(10, 0, 0, 2), 6000).into()
}

fn new_cert() -> DtlsCert {
    Arc::new(str0m::crypto::from_feature_flags())
        .dtls_provider
        .generate_certificate()
        .expect("a DTLS certificate")
}

/// A viewer with its own DTLS certificate, its SHA-256 the fingerprint an offer names it by.
struct Viewer {
    cert: DtlsCert,
    fp: Vec<u8>,
}

impl Viewer {
    fn new() -> Self {
        let cert = new_cert();
        let fp = Self::rtc_with(&cert)
            .direct_api()
            .local_dtls_fingerprint()
            .clone();
        assert_eq!(fp.hash_func, "sha-256");
        assert_eq!(fp.bytes.len(), 32);
        Self { cert, fp: fp.bytes }
    }

    /// A fresh `Rtc` on this viewer's certificate, shaped like the Mini App's: H.264 only.
    fn rtc_with(cert: &DtlsCert) -> Rtc {
        Rtc::builder()
            .set_crypto_provider(Arc::new(str0m::crypto::from_feature_flags()))
            .set_dtls_cert(cert.clone())
            .clear_codecs()
            .enable_h264(true)
            .build(Instant::now())
    }
}

/// One end of the in-process link.
struct End {
    rtc: Rtc,
    addr: SocketAddr,
    connected: bool,
    error: Option<String>,
    next: Instant,
}

impl End {
    fn new(rtc: Rtc, addr: SocketAddr, now: Instant) -> Self {
        Self {
            rtc,
            addr,
            connected: false,
            error: None,
            next: now,
        }
    }

    fn up(&self) -> bool {
        self.error.is_none() && self.rtc.is_alive()
    }

    fn input(&mut self, input: Input<'_>) {
        if !self.up() {
            return;
        }
        if let Err(e) = self.rtc.handle_input(input) {
            self.error = Some(e.to_string());
        }
    }

    /// Everything the `Rtc` has to send or say, up to its next timeout.
    fn drain(&mut self, wire: &mut Vec<Datagram>) {
        while self.up() {
            match self.rtc.poll_output() {
                Ok(Output::Timeout(t)) => {
                    self.next = t;
                    return;
                }
                Ok(Output::Transmit(t)) => wire.push(Datagram {
                    from: t.source,
                    to: t.destination,
                    bytes: t.contents.to_vec(),
                }),
                Ok(Output::Event(Event::Connected)) => self.connected = true,
                Ok(Output::Event(_)) => {}
                Err(e) => self.error = Some(e.to_string()),
            }
        }
    }
}

struct Datagram {
    from: SocketAddr,
    to: SocketAddr,
    bytes: Vec<u8>,
}

/// How a session on one offer went, from the agent's side.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Outcome {
    /// str0m's SDP parse refused the offer.
    NotParsed,
    /// str0m parsed it but would not answer it (no `a=fingerprint` it reads, among others).
    NotAnswered(String),
    /// The DTLS handshake completed: str0m let the viewer's certificate in.
    Connected,
    /// The agent's `Rtc` failed during the handshake.
    Failed(String),
    /// Neither, by [`HANDSHAKE_LIMIT`].
    Stalled,
}

/// The agent, from its own configuration, answers `offer` (a viewer's offer whose fingerprint
/// lines `edit` rewrote) and runs the handshake with the viewer that made it.
fn session(viewer: &Viewer, edit: impl Fn(&str) -> String) -> (String, Outcome, Option<End>) {
    let start = Instant::now();
    let mut v = Viewer::rtc_with(&viewer.cert);
    v.add_local_candidate(Candidate::host(viewer_addr(), "udp").expect("viewer candidate"));
    let mut api = v.sdp_api();
    api.add_media(MediaKind::Video, Direction::RecvOnly, None, None, None);
    api.add_channel("input".to_string());
    let (offer, pending) = api.apply().expect("an offer");
    let sdp = edit(&offer.to_sdp_string());

    let mut agent = peer_rtc_config(None).build(start);
    agent.add_local_candidate(Candidate::host(agent_addr(), "udp").expect("agent candidate"));
    let Ok(offer) = SdpOffer::from_sdp_string(&sdp) else {
        return (sdp, Outcome::NotParsed, None);
    };
    let answer = match agent.sdp_api().accept_offer(offer) {
        Ok(answer) => answer,
        Err(e) => return (sdp, Outcome::NotAnswered(e.to_string()), None),
    };
    v.sdp_api()
        .accept_answer(pending, answer)
        .expect("the viewer takes the agent's answer");

    let mut agent = End::new(agent, agent_addr(), start);
    let mut viewer = End::new(v, viewer_addr(), start);
    let mut now = start;
    while now < start + HANDSHAKE_LIMIT {
        let mut wire = Vec::new();
        agent.input(Input::Timeout(now));
        viewer.input(Input::Timeout(now));
        agent.drain(&mut wire);
        viewer.drain(&mut wire);
        // Hand every datagram over at once (a zero-latency link), and what it makes in turn.
        while !wire.is_empty() {
            for d in std::mem::take(&mut wire) {
                let to = if d.to == agent.addr {
                    &mut agent
                } else if d.to == viewer.addr {
                    &mut viewer
                } else {
                    continue;
                };
                let Ok(contents) = d.bytes.as_slice().try_into() else {
                    continue;
                };
                to.input(Input::Receive(
                    now,
                    Receive {
                        proto: Protocol::Udp,
                        source: d.from,
                        destination: d.to,
                        contents,
                    },
                ));
                to.drain(&mut wire);
            }
        }
        if !agent.up() || (agent.connected && viewer.connected) {
            break;
        }
        now = agent
            .next
            .min(viewer.next)
            .max(now + Duration::from_millis(1));
    }
    let outcome = if agent.connected {
        Outcome::Connected
    } else if let Some(e) = &agent.error {
        Outcome::Failed(e.clone())
    } else if !agent.rtc.is_alive() {
        Outcome::Failed("the agent's Rtc closed".to_string())
    } else {
        Outcome::Stalled
    };
    (sdp, outcome, Some(agent))
}

/// `sdp` (str0m writes `\r\n`) without its `a=fingerprint` lines, then `session` at the end of
/// the session part and `media[i]` at the end of the i-th `m=` section; joined by `\n` alone when
/// `lf_only`.
fn place(sdp: &str, session: &[String], media: &[Vec<String>], lf_only: bool) -> String {
    let lines: Vec<&str> = sdp
        .split("\r\n")
        .filter(|l| !l.is_empty() && !l.starts_with("a=fingerprint:"))
        .collect();
    let mut sections: Vec<Vec<String>> = vec![Vec::new()];
    for line in lines {
        if line.starts_with("m=") {
            sections.push(Vec::new());
        }
        sections
            .last_mut()
            .expect("a section")
            .push(line.to_string());
    }
    assert_eq!(sections.len(), 3, "the offer has two m= sections: {sdp}");
    sections[0].extend(session.iter().cloned());
    for (i, extra) in media.iter().enumerate() {
        sections[i + 1].extend(extra.iter().cloned());
    }
    let eol = if lf_only { "\n" } else { "\r\n" };
    let mut out = sections.concat().join(eol);
    out.push_str(eol);
    out
}

fn hex(bytes: &[u8], upper: bool) -> String {
    bytes
        .iter()
        .map(|b| {
            if upper {
                format!("{b:02X}")
            } else {
                format!("{b:02x}")
            }
        })
        .collect::<Vec<_>>()
        .join(":")
}

fn sha256(bytes: &[u8]) -> Fingerprint {
    Fingerprint {
        hash_func: "sha-256".to_string(),
        bytes: bytes.to_vec(),
    }
}

/// What str0m's own SDP parse picks as the offer's fingerprint: the first session-level line,
/// else the first one in any `m=` section. `Sdp::fingerprint` (`vendor/str0m/src/sdp/data.rs`)
/// is crate-private, so this repeats its two lines over the parse's public fields;
/// [`whenever_str0m_lets_a_certificate_in_ours_names_it_or_refuses`] checks it against the
/// handshake itself, where a wrong copy here would show.
fn str0m_pick(sdp: &str) -> Option<Fingerprint> {
    let offer = SdpOffer::from_sdp_string(sdp).ok()?;
    offer
        .session
        .fingerprint()
        .or_else(|| offer.media_lines.iter().find_map(|m| m.fingerprint()))
}

/// The genuine viewer — the one whose fingerprint its device key signed — and another
/// certificate's holder: whoever sits between the two and wants in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Who {
    Genuine,
    Other,
}

/// A peer built from the agent's configuration completes the handshake with the certificate the
/// offer names, and refuses one it does not: the offer names the genuine viewer's fingerprint
/// (as signed), the certificate presented is another's.
#[test]
fn a_certificate_the_offer_does_not_name_is_refused() {
    let genuine = Viewer::new();
    let other = Viewer::new();
    assert_ne!(genuine.fp, other.fp);
    let names_genuine = |sdp: &str| {
        let line = format!("a=fingerprint:sha-256 {}", hex(&genuine.fp, true));
        place(sdp, &[], &[vec![line.clone()], vec![line]], false)
    };

    // The control: the genuine viewer's own certificate is let in, and str0m saw exactly it.
    let (sdp, outcome, agent) = session(&genuine, names_genuine);
    assert_eq!(outcome, Outcome::Connected, "the genuine viewer: {sdp}");
    assert_eq!(
        viewer_fingerprint(&sdp).map(Vec::from),
        Ok(genuine.fp.clone())
    );
    let mut agent = agent.expect("the agent's end");
    assert_eq!(
        agent.rtc.direct_api().remote_dtls_fingerprint(),
        Some(&sha256(&genuine.fp)),
        "the certificate the agent saw"
    );

    // The same offer, signed for the genuine viewer, from another certificate's holder.
    let (sdp, outcome, agent) = session(&other, names_genuine);
    assert_eq!(
        viewer_fingerprint(&sdp).map(Vec::from),
        Ok(genuine.fp.clone())
    );
    assert_eq!(
        outcome,
        Outcome::Failed(format!("remote sdp: {NO_MATCH}")),
        "another certificate under the genuine viewer's fingerprint: {sdp}"
    );
    let agent = agent.expect("the agent's end");
    assert!(!agent.connected, "never connected");
    assert!(!agent.rtc.is_alive(), "the agent's Rtc is closed");
}

/// One offer shape: the fingerprint lines at session level and in the two `m=` sections, with
/// `{R}` / `{r}` the genuine viewer's fingerprint in upper / lower case hex, `{D}` the other
/// certificate's, `{R31}` the genuine one less its last byte, `{X20}` / `{X48}` / `{X64}` that
/// many filler bytes.
struct Shape {
    name: &'static str,
    session: &'static [&'static str],
    m0: &'static [&'static str],
    m1: &'static [&'static str],
    lf_only: bool,
    /// What ours makes of it.
    ours: Result<Who, FpError>,
    /// Whose certificate str0m lets in, if anyone's.
    str0m: Option<Who>,
}

macro_rules! shape {
    ($name:literal, [$($s:expr),*], [$($m0:expr),*], [$($m1:expr),*], $ours:expr, $str0m:expr) => {
        Shape {
            name: $name,
            session: &[$($s),*],
            m0: &[$($m0),*],
            m1: &[$($m1),*],
            lf_only: false,
            ours: $ours,
            str0m: $str0m,
        }
    };
}

// A table: one shape a line reads better than rustfmt's seven.
#[rustfmt::skip]
fn shapes() -> Vec<Shape> {
    use Who::{Genuine as G, Other as O};
    const R: &str = "a=fingerprint:sha-256 {R}";
    const D: &str = "a=fingerprint:sha-256 {D}";
    vec![
        // Accepted by both, and the same certificate.
        shape!("chrome_every_m_section", [], [R], [R], Ok(G), Some(G)),
        shape!("firefox_session_level", [R], [], [], Ok(G), Some(G)),
        shape!("session_and_every_m_section", [R], [R], [R], Ok(G), Some(G)),
        shape!("lower_case_hex", ["a=fingerprint:sha-256 {r}"], [R], [], Ok(G), Some(G)),
        Shape {
            lf_only: true,
            ..shape!("lf_line_ends", [], [R], [R], Ok(G), Some(G))
        },
        // Ours says the other certificate: so does str0m.
        shape!("every_line_the_other", [], [D], [D], Ok(O), Some(O)),
        // Two values: ours refuses whichever str0m would pick.
        shape!("session_genuine_media_other", [R], [D], [], Err(FpError::Mismatch), Some(G)),
        shape!("session_other_media_genuine", [D], [R], [R], Err(FpError::Mismatch), Some(O)),
        shape!("first_m_genuine_second_other", [], [R], [D], Err(FpError::Mismatch), Some(G)),
        shape!("first_m_other_second_genuine", [], [D], [R], Err(FpError::Mismatch), Some(O)),
        shape!("two_in_one_m_section", [], [R, D], [], Err(FpError::Mismatch), Some(G)),
        shape!("two_at_session_level", [D, R], [], [], Err(FpError::Mismatch), Some(O)),
        // Other hash algorithms, alone or beside sha-256.
        shape!("upper_case_algorithm", ["a=fingerprint:SHA-256 {R}"], [], [], Err(FpError::Alg), None),
        shape!("sha1_first", [], ["a=fingerprint:sha-1 {X20}"], [R], Err(FpError::Alg), None),
        shape!("sha512_at_session_level", ["a=fingerprint:sha-512 {X64}"], [R], [R], Err(FpError::Alg), None),
        shape!("sha384_after_the_genuine", [], [R], ["a=fingerprint:sha-384 {X48}"], Err(FpError::Alg), Some(G)),
        // The attribute name in another case, or after leading blanks: str0m does not read the
        // line, ours refuses it (§3.3 `name`) rather than skip it.
        shape!("name_case_other_at_session", ["a=Fingerprint:sha-256 {D}"], [R], [R], Err(FpError::Name), Some(G)),
        shape!("name_case_only", ["a=FINGERPRINT:sha-256 {R}"], [], [], Err(FpError::Name), None),
        shape!("line_type_case_other", ["A=fingerprint:sha-256 {D}"], [R], [R], Err(FpError::Name), None),
        shape!("leading_space_other", [" a=fingerprint:sha-256 {D}"], [R], [R], Err(FpError::Name), None),
        shape!("leading_tab_other", ["\ta=fingerprint:sha-256 {D}"], [R], [R], Err(FpError::Name), None),
        shape!("genuine_then_mixed_case_other", [R], [], ["a=fingerprint:sha-256 {R}", "a=FingerPrint:sha-256 {D}"], Err(FpError::Name), Some(G)),
        // Not of the form: ours refuses, str0m reads the line as nothing and goes on.
        shape!("trailing_space_then_other", ["a=fingerprint:sha-256 {R} "], [D], [], Err(FpError::Form), Some(O)),
        shape!("trailing_space_then_genuine", ["a=fingerprint:sha-256 {R} "], [R], [], Err(FpError::Form), Some(G)),
        shape!("double_space_then_other", ["a=fingerprint:sha-256  {R}"], [D], [], Err(FpError::Form), Some(O)),
        shape!("31_bytes", ["a=fingerprint:sha-256 {R31}"], [], [], Err(FpError::Form), None),
        shape!("33_bytes", ["a=fingerprint:sha-256 {R}:00"], [], [], Err(FpError::Form), None),
        shape!("no_value", ["a=fingerprint:"], [R], [], Err(FpError::Form), Some(G)),
        shape!("none_at_all", [], [], [], Err(FpError::None), None),
        shape!("empty_algorithm", ["a=fingerprint: sha-256 {R}"], [R], [], Err(FpError::Form), Some(G)),
        // A bare CR anywhere: ours refuses (§3.3 `line_end`); str0m splits lines otherwise.
        shape!("bare_cr_hides_other_at_session", ["a=ice-options:trickle\ra=fingerprint:sha-256 {D}"], [R], [R], Err(FpError::LineEnd), None),
        shape!("bare_cr_hides_other_in_m", [], ["a=x-afk:1\ra=fingerprint:sha-256 {D}"], [R], Err(FpError::LineEnd), None),
        // Not a candidate: a BOM before `a=` (only spaces and tabs are skipped).
        shape!("bom_before_other", ["\u{feff}a=fingerprint:sha-256 {D}"], [R], [R], Ok(G), None),
    ]
}

fn fill(line: &str, genuine: &[u8], other: &[u8]) -> String {
    let filler = |n: usize| hex(&vec![0xab; n], true);
    line.replace("{R31}", &hex(&genuine[..31], true))
        .replace("{R}", &hex(genuine, true))
        .replace("{r}", &hex(genuine, false))
        .replace("{D}", &hex(other, true))
        .replace("{X20}", &filler(20))
        .replace("{X48}", &filler(48))
        .replace("{X64}", &filler(64))
}

/// Every [`shapes`] offer, handshaken by the genuine viewer and by the other certificate's
/// holder, against a peer from the agent's configuration. The rule (§3.3): whenever str0m lets a
/// certificate in, ours yielded exactly that certificate's fingerprint or refused the offer — so a
/// signature over what ours yields admits no one else. Then each shape's expected outcomes, so a
/// str0m that reads offers differently (a version bump) shows here by name.
#[test]
fn whenever_str0m_lets_a_certificate_in_ours_names_it_or_refuses() {
    let genuine = Viewer::new();
    let other = Viewer::new();
    let fp_of = |who: Who| match who {
        Who::Genuine => &genuine.fp,
        Who::Other => &other.fp,
    };
    let mut failures = Vec::new();
    for shape in shapes() {
        let lines = |ls: &[&str]| -> Vec<String> {
            ls.iter().map(|l| fill(l, &genuine.fp, &other.fp)).collect()
        };
        let edit = |sdp: &str| {
            place(
                sdp,
                &lines(shape.session),
                &[lines(shape.m0), lines(shape.m1)],
                shape.lf_only,
            )
        };
        let mut let_in = None;
        let mut ours_said = None;
        for who in [Who::Genuine, Who::Other] {
            let viewer = if who == Who::Genuine {
                &genuine
            } else {
                &other
            };
            let (sdp, outcome, _) = session(viewer, edit);
            let ours = viewer_fingerprint(&sdp);
            ours_said = Some(ours.map(|fp| {
                if fp.as_slice() == genuine.fp.as_slice() {
                    Who::Genuine
                } else {
                    assert_eq!(fp.as_slice(), other.fp.as_slice(), "{}", shape.name);
                    Who::Other
                }
            }));
            if outcome == Outcome::Connected {
                // The rule itself.
                if let Ok(fp) = ours {
                    if fp.as_slice() != fp_of(who).as_slice() {
                        failures.push(format!(
                            "{}: str0m let the {who:?} certificate in, ours yielded another \
                             fingerprint",
                            shape.name
                        ));
                    }
                }
                // The parse oracle the vectors test uses agrees with the handshake.
                if str0m_pick(&sdp) != Some(sha256(fp_of(who))) {
                    failures.push(format!(
                        "{}: str0m let the {who:?} certificate in, str0m_pick says {:?}",
                        shape.name,
                        str0m_pick(&sdp)
                    ));
                }
                let_in = Some(who);
            } else if matches!(outcome, Outcome::Failed(ref e) if !e.contains(NO_MATCH)) {
                failures.push(format!(
                    "{}: {who:?}: the handshake failed, not on the fingerprint: {outcome:?}",
                    shape.name
                ));
            } else if outcome == Outcome::Stalled {
                failures.push(format!("{}: {who:?}: stalled", shape.name));
            }
        }
        // This shape's expected outcomes (ours reads the same lines from either viewer's offer).
        let ours = ours_said.expect("two sessions");
        if ours != shape.ours {
            failures.push(format!(
                "{}: ours {ours:?}, expected {:?}",
                shape.name, shape.ours
            ));
        }
        if let_in != shape.str0m {
            failures.push(format!(
                "{}: str0m let in {let_in:?}, expected {:?}",
                shape.name, shape.str0m
            ));
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../contract/packages/protocol/vectors/viewer-keys")
}

/// The contract's vectors against str0m's own parse ([`str0m_pick`]): when ours accepts an offer,
/// str0m picks the same sha-256 value or nothing (it then answers no session); when str0m picks a
/// sha-256 value, ours yields it or refuses.
#[test]
fn on_the_contract_vectors_ours_accepts_only_what_str0m_picks() {
    let path = vectors_dir().join("sdp-fingerprint.json");
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let vectors: serde_json::Value = serde_json::from_str(&text).expect("JSON");
    let cases = vectors["cases"].as_array().expect("cases");
    assert!(cases.len() >= 10, "{} cases", cases.len());
    let mut picked = 0;
    for case in cases {
        let name = case["name"].as_str().expect("name");
        let sdp = case["sdp"].as_str().expect("sdp");
        let ours = viewer_fingerprint(sdp);
        let pick = str0m_pick(sdp);
        picked += usize::from(pick.is_some());
        if let Ok(fp) = ours {
            assert!(
                pick.is_none() || pick == Some(sha256(&fp)),
                "{name}: ours accepted {fp:02x?}, str0m picks {pick:?}"
            );
        }
        if let Some(p) = &pick {
            if p.hash_func == "sha-256" {
                assert!(
                    ours.is_err() || ours.map(Vec::from) == Ok(p.bytes.clone()),
                    "{name}: str0m picks {p:?}, ours yields {ours:02x?}"
                );
            }
        }
    }
    // Most vectors are whole offers str0m reads; the check above is not vacuous.
    assert!(
        picked * 2 > cases.len(),
        "str0m picked a fingerprint in only {picked} of {} vectors",
        cases.len()
    );
}
