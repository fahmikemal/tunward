use crate::protocols;
use crate::protocols::tcp::configure_socket;
use crate::somark::SoMark;
use crate::tunnel::{LocalProtocol, RemoteAddr};
use anyhow::{Context, anyhow};
use socket2::SockRef;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Poll, ready};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio_stream::Stream;
use tokio_stream::wrappers::TcpListenerStream;
use url::Host;

pub struct TcpDownstreamListener {
    listener: TcpListenerStream,
    dest: (Host, u16),
    proxy_protocol: bool,
    bound_addr: SocketAddr,
}

impl TcpDownstreamListener {
    pub async fn new(bind_addr: SocketAddr, dest: (Host, u16), proxy_protocol: bool) -> anyhow::Result<Self> {
        let (listener, bound_addr) = protocols::tcp::run_server_with_addr(bind_addr, false)
            .await
            .with_context(|| anyhow!("Cannot start TCP server on {bind_addr}"))?;

        Ok(Self {
            listener,
            dest,
            proxy_protocol,
            bound_addr,
        })
    }

    pub fn bound_addr(&self) -> SocketAddr {
        self.bound_addr
    }
}

impl Stream for TcpDownstreamListener {
    type Item = anyhow::Result<((OwnedReadHalf, OwnedWriteHalf), RemoteAddr)>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        let ret = ready!(Pin::new(&mut this.listener).poll_next(cx));
        let ret = match ret {
            Some(Ok(stream)) => {
                let _ = configure_socket(SockRef::from(&stream), SoMark::new(None))
                    .inspect_err(|e| log::error!("TCP Downstream listener error: {e}"));
                let (host, mut port) = this.dest.clone();
                if port == 0 {
                    port = this.bound_addr.port();
                }
                Some(anyhow::Ok((
                    stream.into_split(),
                    RemoteAddr {
                        protocol: LocalProtocol::Tcp {
                            proxy_protocol: this.proxy_protocol,
                        },
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
