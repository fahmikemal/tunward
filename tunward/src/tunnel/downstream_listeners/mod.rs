mod tcp;
#[cfg(target_os = "linux")]
mod tproxy;

mod http_proxy;
mod socks5;
mod stdio;
mod udp;
#[cfg(unix)]
mod unix_sock;

#[cfg(target_os = "linux")]
pub use tproxy::TProxyTcpDownstreamListener;
#[cfg(target_os = "linux")]
pub use tproxy::new_tproxy_udp;

pub use http_proxy::HttpProxyDownstreamListener;
pub use socks5::Socks5DownstreamListener;
pub use stdio::new_stdio_listener;
pub use tcp::TcpDownstreamListener;
pub use udp::UdpDownstreamListener;

#[cfg(unix)]
pub use unix_sock::UnixDownstreamListener;

use crate::tunnel::RemoteAddr;
use std::future::Future;
use std::io;
use std::pin::Pin;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_stream::Stream;

/// Read half of a local duplex stream that can be forwarded through a tunnel.
pub trait DownstreamRead: AsyncRead + Send + 'static {
    /// A fatal local error must interrupt a tunnel write blocked by remote backpressure.
    /// A directional EOF is not cancellation: the response may still be in flight.
    fn cancelled(self: Pin<&mut Self>) -> impl Future<Output = io::Error> + Send {
        std::future::pending()
    }
}

impl DownstreamRead for tokio::net::tcp::OwnedReadHalf {
    async fn cancelled(self: Pin<&mut Self>) -> io::Error {
        let reader = self.get_mut();
        let socket: &tokio::net::TcpStream = reader.as_ref();
        match socket.ready(tokio::io::Interest::ERROR).await {
            Err(error) => error,
            Ok(_) => socket
                .take_error()
                .unwrap_or_else(Some)
                .unwrap_or_else(|| io::Error::new(io::ErrorKind::ConnectionAborted, "local TCP socket failed")),
        }
    }
}
#[cfg(unix)]
impl DownstreamRead for tokio::net::unix::OwnedReadHalf {}
impl DownstreamRead for udp::UdpPeerReader {}
impl DownstreamRead for crate::protocols::udp::UdpStream {}
impl DownstreamRead for crate::protocols::udp::WsUdpStream {}
impl DownstreamRead for tokio::io::DuplexStream {}
impl<T: AsyncRead + Send + 'static> DownstreamRead for tokio::io::ReadHalf<T> {}

/// Write half of a local duplex stream that can be forwarded through a tunnel. On top of being
/// writable, it must acknowledge the end-to-end tunnel outcome to the local client once it is known.
///
/// Most local protocols (plain TCP, UDP, unix, stdio, ...) have nothing to acknowledge and rely on
/// the no-op default. SOCKS5 overrides [`DownstreamWrite::on_tunnel_ready`] to defer its
/// `reply_success` / `reply_error` until the tunnel to the remote endpoint (and onward to the
/// target) is confirmed up or has failed.
pub trait DownstreamWrite: AsyncWrite + Send + 'static {
    /// Called exactly once per connection, after the tunnel connection attempt completes and before
    /// any data is forwarded.
    fn on_tunnel_ready(
        &mut self,
        result: Result<(), &anyhow::Error>,
    ) -> impl Future<Output = std::io::Result<()>> + Send {
        let _ = result;
        async { Ok(()) }
    }
}

// Forward local protocols without a post-connect handshake: nothing to acknowledge.
// A blanket `impl<T: AsyncWrite>` is impossible here because it would overlap the SOCKS5 impl, so the
// concrete writer types are enumerated explicitly (tcp/tproxy/http_proxy share `OwnedWriteHalf`,
// udp/tproxy-udp share `UdpStreamWriter`).
impl DownstreamWrite for tokio::net::tcp::OwnedWriteHalf {}
#[cfg(unix)]
impl DownstreamWrite for tokio::net::unix::OwnedWriteHalf {}
impl DownstreamWrite for crate::protocols::udp::UdpStreamWriter {}

pub trait DownstreamListener: Stream<Item = anyhow::Result<((Self::Reader, Self::Writer), RemoteAddr)>> {
    type Reader: DownstreamRead;
    type Writer: DownstreamWrite;
}

impl<T, R, W> DownstreamListener for T
where
    T: Stream<Item = anyhow::Result<((R, W), RemoteAddr)>>,
    R: DownstreamRead,
    W: DownstreamWrite,
{
    type Reader = R;
    type Writer = W;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddr};
    use std::time::Duration;
    use tokio_stream::StreamExt;
    use url::Host;

    #[tokio::test]
    async fn a_port_zero_listener_reports_the_port_it_is_bound_to() {
        let any = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
        let mut udp = UdpDownstreamListener::new(any, (Host::Ipv4(Ipv4Addr::LOCALHOST), 0), None)
            .await
            .unwrap();
        let socks = Socks5DownstreamListener::new(any, None, None, false).await.unwrap();
        let http = HttpProxyDownstreamListener::new(any, None, None, false).await.unwrap();

        let udp_bound = udp.bound_addr();
        assert_ne!(udp_bound.port(), 0, "UDP reported the requested port");
        assert!(std::net::UdpSocket::bind(udp_bound).is_err(), "UDP is not bound to {udp_bound}");
        for bound in [socks.bound_addr(), http.bound_addr()] {
            assert_ne!(bound.port(), 0, "a proxy reported the requested port");
            assert!(std::net::TcpListener::bind(bound).is_err(), "no proxy is bound to {bound}");
        }

        // A peer's destination port 0 stands for the listener's own port, as for TCP.
        let peer = tokio::net::UdpSocket::bind(any).await.unwrap();
        peer.send_to(b"ping", udp_bound).await.unwrap();
        let (_, remote) = tokio::time::timeout(Duration::from_secs(5), udp.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(remote.port, udp_bound.port());
    }
}
