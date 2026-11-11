//! Resolving the `.local` name a browser puts in its host ICE candidate.
//!
//! ## Why this exists
//!
//! Browsers do not put your LAN address in a host candidate any more. Since roughly 2019 they
//! replace it with a random `<uuid>.local` name, registered over multicast DNS, unless the page
//! holds a camera or microphone permission — otherwise any web page could enumerate the local
//! network by reading its own candidates. A native peer that parses candidates into a `SocketAddr`
//! rejects the name, and the LAN address is simply never learned.
//!
//! Measured here, every session: the phone offers exactly one host candidate and it is an mDNS
//! name, plus a server-reflexive one and six Cloudflare relay addresses. The one pairing that
//! could be direct is discarded before ICE considers it, so every session in this product's
//! history has gone through the TURN relay — at 133 to 159 ms round trip, and at a bandwidth that
//! does not fit 1080p60. A phone sitting on the same Wi-Fi as the PC took the long way round the
//! internet to reach a machine two metres away.
//!
//! ## Why this is hand-rolled
//!
//! One question, one answer, one record type, on a name we already have. That is about eighty
//! lines, against a dependency that would bring a service browser, a responder, a cache and its
//! own threads — none of which this needs. The STUN binding request next door was written the same
//! way and for the same reason.
//!
//! ## Why the reply comes back unicast
//!
//! The query sets the QU bit (RFC 6762 §5.4), which asks the responder to reply directly to the
//! source port instead of to the multicast group. That is not only faster: it means the answer
//! arrives as a reply to something we sent, so a stateful firewall passes it without an inbound
//! rule. Requiring the user to open a port would put a Windows Firewall prompt in the middle of
//! the first session, on a product whose whole premise is that it asks before it does anything.
//!
//! When there is no answer — AP isolation, a guest network, a phone on mobile data — the candidate
//! is simply dropped as before and ICE falls back to the relay. This can only add a path.

use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use tokio::net::UdpSocket;

/// The IPv4 multicast group and port every mDNS responder listens on (RFC 6762 §3).
const MDNS_GROUP: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(224, 0, 0, 251), 5353);

/// How long to wait for an answer.
///
/// mDNS is a link-local protocol, so a responder that exists answers in single-digit milliseconds.
/// A second is generous enough to survive a busy phone and short enough to be invisible: ICE is
/// still checking the relay candidates meanwhile, so nothing is delayed by waiting.
const TIMEOUT: Duration = Duration::from_millis(1_000);

/// `QCLASS` IN with the QU bit set — "answer me directly, not to the group".
const CLASS_IN_UNICAST: u16 = 0x8001;
const TYPE_A: u16 = 1;

/// Resolve a single `<name>.local` to an IPv4 address.
///
/// `from` is the interface to ask from; using the real LAN address rather than `0.0.0.0` keeps the
/// query on the network the phone is actually on, which matters on a machine with a VPN adapter —
/// and a machine running this product very often has one.
pub async fn resolve(name: &str, from: Ipv4Addr) -> Result<Ipv4Addr> {
    let socket = UdpSocket::bind(SocketAddr::new(IpAddr::V4(from), 0))
        .await
        .context("bind mdns socket")?;

    let query = build_query(name)?;
    socket
        .send_to(&query, MDNS_GROUP)
        .await
        .context("send mdns query")?;

    let mut buf = vec![0u8; 1500];
    loop {
        let (n, _) = tokio::time::timeout(TIMEOUT, socket.recv_from(&mut buf))
            .await
            .context("mdns query timed out")?
            .context("mdns recv")?;
        // Other responders share this group and will answer questions that are not ours. An
        // unrelated announcement is not an error, it is just not the answer, so keep listening
        // until the timeout rather than giving up on the first packet that arrives.
        if let Some(addr) = parse_answer(&buf[..n], name) {
            return Ok(addr);
        }
    }
}

/// A DNS query for one A record, with the QU bit set.
fn build_query(name: &str) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(64);
    // Header: mDNS uses a zero transaction id (RFC 6762 §18.1) and a plain query opcode.
    out.extend_from_slice(&0u16.to_be_bytes()); // id
    out.extend_from_slice(&0u16.to_be_bytes()); // flags
    out.extend_from_slice(&1u16.to_be_bytes()); // qdcount
    out.extend_from_slice(&[0; 6]); // an/ns/ar counts

    for label in name.split('.') {
        // 63 is the protocol's limit on one label; a longer one cannot be encoded at all, and a
        // zero-length one would terminate the name early and turn this into a query for the root.
        if label.is_empty() || label.len() > 63 {
            bail!("bad mdns label in {name:?}");
        }
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0); // root label

    out.extend_from_slice(&TYPE_A.to_be_bytes());
    out.extend_from_slice(&CLASS_IN_UNICAST.to_be_bytes());
    Ok(out)
}

/// Pull the first A record for `name` out of a response, if it is there.
///
/// Returns `None` rather than an error for anything unexpected: this is a shared multicast group,
/// so "not the packet I wanted" is the ordinary case and not a failure.
fn parse_answer(buf: &[u8], name: &str) -> Option<Ipv4Addr> {
    if buf.len() < 12 {
        return None;
    }
    let qdcount = u16::from_be_bytes([buf[4], buf[5]]);
    let ancount = u16::from_be_bytes([buf[6], buf[7]]);
    if ancount == 0 {
        return None;
    }

    let mut pos = 12;
    for _ in 0..qdcount {
        pos = skip_name(buf, pos)?;
        pos = pos.checked_add(4)?; // qtype + qclass
    }

    for _ in 0..ancount {
        let (rname, next) = read_name(buf, pos)?;
        pos = next;
        let rtype = u16::from_be_bytes([*buf.get(pos)?, *buf.get(pos + 1)?]);
        // Skip class and TTL; the cache-flush bit lives in the top of the class field and is
        // irrelevant to a one-shot query.
        let rdlen = u16::from_be_bytes([*buf.get(pos + 8)?, *buf.get(pos + 9)?]) as usize;
        pos += 10;
        let rdata = buf.get(pos..pos.checked_add(rdlen)?)?;
        pos += rdlen;

        if rtype == TYPE_A && rdlen == 4 && rname.eq_ignore_ascii_case(name) {
            return Some(Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3]));
        }
    }
    None
}

/// Read a (possibly compressed) DNS name, returning it and the offset just past it.
fn read_name(buf: &[u8], start: usize) -> Option<(String, usize)> {
    let mut labels = Vec::new();
    let mut pos = start;
    let mut after: Option<usize> = None;
    // A compression pointer can only ever point backwards, so bounding the walk by the buffer
    // length is enough to make a malicious or corrupt packet terminate rather than loop.
    let mut budget = buf.len();

    loop {
        budget = budget.checked_sub(1)?;
        let len = *buf.get(pos)?;
        match len & 0xC0 {
            0 => {
                if len == 0 {
                    pos += 1;
                    break;
                }
                let end = pos.checked_add(1 + len as usize)?;
                labels.push(String::from_utf8_lossy(buf.get(pos + 1..end)?).into_owned());
                pos = end;
            }
            0xC0 => {
                let ptr = ((u16::from(len & 0x3F) << 8) | u16::from(*buf.get(pos + 1)?)) as usize;
                after.get_or_insert(pos + 2);
                if ptr >= pos {
                    return None; // forward or self reference
                }
                pos = ptr;
            }
            _ => return None, // reserved label type
        }
    }
    Some((labels.join("."), after.unwrap_or(pos)))
}

/// As [`read_name`], when the name itself is not wanted.
fn skip_name(buf: &[u8], start: usize) -> Option<usize> {
    read_name(buf, start).map(|(_, pos)| pos)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal response: the question echoed back, then one A record.
    fn response(qname: &str, aname: &str, addr: [u8; 4]) -> Vec<u8> {
        let mut out = build_query(qname).expect("query");
        out[6] = 0;
        out[7] = 1; // ancount = 1
        for label in aname.split('.') {
            out.push(label.len() as u8);
            out.extend_from_slice(label.as_bytes());
        }
        out.push(0);
        out.extend_from_slice(&TYPE_A.to_be_bytes());
        out.extend_from_slice(&1u16.to_be_bytes()); // class IN
        out.extend_from_slice(&120u32.to_be_bytes()); // ttl
        out.extend_from_slice(&4u16.to_be_bytes()); // rdlength
        out.extend_from_slice(&addr);
        out
    }

    #[test]
    fn reads_the_address_out_of_an_answer() {
        let name = "2d1bab66-20b5-4b47-bbd8-3ace2d76f6b4.local";
        let pkt = response(name, name, [192, 168, 1, 42]);
        assert_eq!(
            parse_answer(&pkt, name),
            Some(Ipv4Addr::new(192, 168, 1, 42))
        );
    }

    #[test]
    fn ignores_answers_about_other_names() {
        // The group is shared. A printer announcing itself must not be mistaken for the phone,
        // because the address would be wrong and ICE would spend its checks on a stranger.
        let pkt = response("wanted.local", "someone-else.local", [10, 0, 0, 9]);
        assert_eq!(parse_answer(&pkt, "wanted.local"), None);
    }

    #[test]
    fn a_query_round_trips_its_name() {
        let q = build_query("abc.local").expect("query");
        let (name, _) = read_name(&q, 12).expect("name");
        assert_eq!(name, "abc.local");
        // And the QU bit is set, which is what makes the reply arrive as a reply rather than as
        // unsolicited inbound multicast a firewall would drop.
        let class = u16::from_be_bytes([q[q.len() - 2], q[q.len() - 1]]);
        assert_eq!(class & 0x8000, 0x8000);
    }

    #[test]
    fn a_name_that_cannot_be_encoded_is_refused() {
        assert!(build_query("").is_err());
        assert!(build_query(&format!("{}.local", "x".repeat(64))).is_err());
    }

    #[test]
    fn a_compression_loop_terminates() {
        // A pointer to itself, which a naive reader follows forever. Malformed packets arrive on a
        // multicast group by definition — anything on the LAN can send one.
        let mut pkt = vec![0u8; 14];
        pkt[12] = 0xC0;
        pkt[13] = 12;
        assert_eq!(read_name(&pkt, 12), None);
    }

    #[test]
    fn a_truncated_packet_is_not_an_answer() {
        let name = "abc.local";
        let pkt = response(name, name, [1, 2, 3, 4]);
        for cut in 0..pkt.len() {
            let _ = parse_answer(&pkt[..cut], name);
        }
    }
}
