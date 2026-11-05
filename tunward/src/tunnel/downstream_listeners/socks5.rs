use crate::protocols::socks5;
use crate::protocols::socks5::{Socks5Listener, Socks5ReadHalf, Socks5WriteHalf};
use crate::tunnel::RemoteAddr;
use anyhow::{Context, anyhow};
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Poll, ready};
use std::time::Duration;
use tokio_stream::Stream;

pub struct Socks5DownstreamListener {
    listener: Socks5Listener,
}

impl Socks5DownstreamListener {
    pub async fn new(
        bind_addr: SocketAddr,
        timeout: Option<Duration>,
        credentials: Option<(String, String)>,
        proxy_protocol: bool,
    ) -> anyhow::Result<Self> {
        let listener = socks5::run_server(bind_addr, timeout, credentials, proxy_protocol)
            .await
            .with_context(|| anyhow!("Cannot start Socks5 server on {bind_addr}"))?;

        Ok(Self { listener })
    }

    pub fn bound_addr(&self) -> SocketAddr {
        self.listener.local_addr()
    }
}

impl Stream for Socks5DownstreamListener {
    type Item = anyhow::Result<((Socks5ReadHalf, Socks5WriteHalf), RemoteAddr)>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        let ret = ready!(Pin::new(&mut this.listener).poll_next(cx));
        let ret = match ret {
            Some(Ok((stream, (host, port)))) => {
                let protocol = stream.local_protocol();
                Some(anyhow::Ok((stream.into_split(), RemoteAddr { protocol, host, port })))
            }
            Some(Err(err)) => Some(Err(err)),
            None => None,
        };
        Poll::Ready(ret)
    }
}
