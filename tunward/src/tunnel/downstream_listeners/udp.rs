use crate::protocols::udp;
use crate::protocols::udp::{UdpStream, UdpStreamWriter};
use crate::tunnel::{LocalProtocol, RemoteAddr};
use anyhow::{Context, anyhow};
use pin_project::pin_project;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Poll, ready};
use std::time::Duration;
use tokio::io::{AsyncRead, ReadBuf};
use tokio_stream::Stream;
use url::Host;

pub struct UdpDownstreamListener {
    listener: Pin<Box<dyn Stream<Item = io::Result<UdpStream>> + Send>>,
    dest: (Host, u16),
    timeout: Option<Duration>,
    /// Cloned into every reader handed out, so its count tells whether a peer is still served.
    readers: Arc<()>,
}

impl UdpDownstreamListener {
    pub async fn new(
        bind_addr: SocketAddr,
        dest: (Host, u16),
        timeout: Option<Duration>,
    ) -> anyhow::Result<UdpDownstreamListener> {
        let listener = udp::run_server(bind_addr, timeout, |_| Ok(()), |s| Ok(s.clone()))
            .await
            .with_context(|| anyhow!("Cannot start UDP server on {bind_addr}"))?;

        Ok(UdpDownstreamListener {
            listener: Box::pin(listener),
            dest,
            timeout,
            readers: Arc::new(()),
        })
    }

    /// Whether a reader handed out by this listener is still in use.
    ///
    /// Unlike a TCP connection, a UDP peer has no socket of its own: polling this listener is what
    /// sorts incoming datagrams to their peer's reader, so it must keep running while any is served.
    pub fn serves_peers(&self) -> bool {
        Arc::strong_count(&self.readers) > 1
    }
}

/// Reads the datagrams of one peer, and marks its listener as still serving while it lives.
#[pin_project]
pub struct UdpPeerReader {
    #[pin]
    stream: UdpStream,
    _listener: Arc<()>,
}

impl AsyncRead for UdpPeerReader {
    fn poll_read(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        self.project().stream.poll_read(cx, buf)
    }
}

impl Stream for UdpDownstreamListener {
    type Item = anyhow::Result<((UdpPeerReader, UdpStreamWriter), RemoteAddr)>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Option<Self::Item>> {
        let this = unsafe { self.get_unchecked_mut() };
        let ret = ready!(unsafe { Pin::new_unchecked(&mut this.listener) }.poll_next(cx));
        let ret = match ret {
            Some(Ok(stream)) => {
                let (host, port) = this.dest.clone();
                let stream_writer = stream.writer();
                let reader = UdpPeerReader {
                    stream,
                    _listener: this.readers.clone(),
                };
                Some(anyhow::Ok((
                    (reader, stream_writer),
                    RemoteAddr {
                        protocol: LocalProtocol::Udp { timeout: this.timeout },
                        host,
                        port,
                    },
                )))
            }
            Some(Err(err)) => Some(Err(anyhow::Error::new(err))),
            None => None,
        };
        Poll::Ready(ret)
    }
}
