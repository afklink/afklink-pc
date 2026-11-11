//! The peer's UDP socket: used directly, or behind the bench link shaper.
//!
//! Every datagram a peer sends or receives — str0m's, and the srflx STUN transaction's
//! (`crate::stun`) — goes through [`PeerSocket`], so shaping cannot miss a path. Without a
//! `LinkShaper` it is the plain tokio socket and the cost is one `match` per call.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::UdpSocket;

use crate::shaper::{LinkShaper, ShapedSocket};

pub(crate) enum PeerSocket {
    /// Production: the socket itself.
    Direct(UdpSocket),
    /// Bench: through the link shaper's model. See `crate::shaper`.
    Shaped(ShapedSocket),
    /// A host-driven peer: the socket its host supplied. See `crate::host_peer`.
    Host(Box<dyn crate::host_peer::HostSocket>),
}

impl PeerSocket {
    /// `socket` as it is, or behind `shaper` when one is given.
    pub(crate) fn new(socket: UdpSocket, shaper: Option<Arc<LinkShaper>>) -> io::Result<Self> {
        match shaper {
            None => Ok(Self::Direct(socket)),
            Some(shaper) => Ok(Self::Shaped(ShapedSocket::new(socket, shaper)?)),
        }
    }

    pub(crate) async fn send_to(&self, buf: &[u8], to: SocketAddr) -> io::Result<usize> {
        match self {
            Self::Direct(s) => s.send_to(buf, to).await,
            Self::Shaped(s) => s.send_to(buf, to),
            Self::Host(s) => s.send_to(buf, to).await,
        }
    }

    /// Separate socket path for the binding transaction, never used for ICE/DTLS/RTP.
    ///
    /// A host's socket never carries it: `spawn_host_peer` asks no STUN server, so this refusal is
    /// only a guard that a host's relay never sends a binding request on the peer's behalf.
    pub(crate) async fn send_stun_to(&self, buf: &[u8], to: SocketAddr) -> io::Result<usize> {
        if let Self::Host(_) = self {
            tracing::debug!(%to, "a host's socket carries no binding transaction; refused");
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        self.send_to(buf, to).await
    }

    /// Cancel-safe, like the socket's own: nothing is lost if the future is dropped unfinished.
    pub(crate) async fn recv_from(&mut self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        match self {
            Self::Direct(s) => s.recv_from(buf).await,
            Self::Shaped(s) => s.recv_from(buf).await,
            Self::Host(s) => s.recv_from(buf).await,
        }
    }

    /// The host socket's own address, which the peer uses as its local one.
    pub(crate) fn host_address(&self) -> Option<SocketAddr> {
        match self {
            Self::Host(s) => Some(s.address()),
            _ => None,
        }
    }

    /// Release a host socket; the peer's own sockets close when dropped.
    pub(crate) async fn close_host(&mut self) {
        if let Self::Host(s) = self {
            s.close().await;
        }
    }
}

impl From<UdpSocket> for PeerSocket {
    fn from(socket: UdpSocket) -> Self {
        Self::Direct(socket)
    }
}
