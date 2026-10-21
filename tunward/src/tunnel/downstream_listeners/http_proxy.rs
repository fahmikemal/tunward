use crate::protocols::http_proxy;
use crate::protocols::http_proxy::{HttpProxyListener, HttpProxyRead, HttpProxyWrite};
use crate::tunnel::{LocalProtocol, RemoteAddr};
use anyhow::{Context, anyhow};
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Poll, ready};
use std::time::Duration;
use tokio_stream::Stream;

pub struct HttpProxyDownstreamListener {
    listener: HttpProxyListener,
    proxy_protocol: bool,
}

impl HttpProxyDownstreamListener {
    pub async fn new(
        bind_addr: SocketAddr,
        timeout: Option<Duration>,
        credentials: Option<(String, String)>,
        proxy_protocol: bool,
    ) -> anyhow::Result<Self> {
        let listener = http_proxy::run_server(bind_addr, timeout, credentials)
            .await
            .with_context(|| anyhow!("Cannot start http proxy server on {bind_addr}"))?;

        Ok(Self {
            listener,
            proxy_protocol,
        })
    }
}

impl Stream for HttpProxyDownstreamListener {
    type Item = anyhow::Result<((HttpProxyRead, HttpProxyWrite), RemoteAddr)>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        let ret = ready!(Pin::new(&mut this.listener).poll_next(cx));
        let ret = match ret {
            Some(Ok((halves, (host, port)))) => {
                let protocol = LocalProtocol::Tcp {
                    proxy_protocol: this.proxy_protocol,
                };
                Some(anyhow::Ok((halves, RemoteAddr { protocol, host, port })))
            }
            Some(Err(err)) => Some(Err(err)),
            None => None,
        };
        Poll::Ready(ret)
    }
}
