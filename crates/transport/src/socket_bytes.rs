//! What a peer actually put on its socket, and how much of it went to a TURN relay: the session
//! summary's `bytes_socket` and `bytes_relay`.
//!
//! Not the encoder's output (`bytes_sent` in the report) and not what str0m handed the loop to send
//! (`Peer::egress_bytes_total`, which counts a datagram whose `send_to` then failed): only datagrams
//! the socket took. `relay` is the part addressed to a viewer's relay candidate — what the TURN
//! provider bills. The agent itself never relays; the viewer is the TURN client, so "through a
//! relay" is "to the viewer's relayed address".
//!
//! Counted by the peer loop, one `fetch_add` (two for a relayed datagram) per datagram; read by the
//! session's reports. Never reset.

use std::sync::atomic::{AtomicU64, Ordering};

/// The peer's socket totals. Shared: the peer loop counts, the session's summary reads.
#[derive(Debug, Default)]
pub struct SocketBytes {
    total: AtomicU64,
    relay: AtomicU64,
}

impl SocketBytes {
    /// A datagram of `len` bytes the socket took; `relay` when it went to a relay candidate.
    pub fn note(&self, len: usize, relay: bool) {
        let len = len as u64;
        self.total.fetch_add(len, Ordering::Relaxed);
        if relay {
            self.relay.fetch_add(len, Ordering::Relaxed);
        }
    }

    /// Every byte the socket took.
    pub fn total(&self) -> u64 {
        self.total.load(Ordering::Relaxed)
    }

    /// Of those, the bytes to a relay candidate.
    pub fn relay(&self) -> u64 {
        self.relay.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relayed_bytes_are_a_part_of_the_total() {
        let b = SocketBytes::default();
        assert_eq!((b.total(), b.relay()), (0, 0));
        b.note(1200, false);
        b.note(300, true);
        b.note(0, true);
        assert_eq!(b.total(), 1500);
        assert_eq!(b.relay(), 300);
    }
}
