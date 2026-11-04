use std::io::{Error, IoSlice};
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use anyhow::anyhow;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use url::Url;

use crate::protocols;
use crate::protocols::dns::DnsResolver;
use crate::protocols::udp;
use crate::protocols::udp::WsUdpStream;
use crate::somark::SoMark;
use crate::tunnel::allowlist::DestinationAllowlist;
use crate::tunnel::upstream_connectors::UpstreamConnector;
use crate::tunnel::{LocalProtocol, RemoteAddr};

pub struct Socks5UpstreamConnector {
    so_mark: SoMark,
    connect_timeout: Duration,
    dns_resolver: DnsResolver,
    allow: Option<Arc<DestinationAllowlist>>,
}

impl Socks5UpstreamConnector {
    pub fn new(so_mark: SoMark, connect_timeout: Duration, dns_resolver: DnsResolver) -> Socks5UpstreamConnector {
        Socks5UpstreamConnector {
            so_mark,
            connect_timeout,
            dns_resolver,
            allow: None,
        }
    }

    /// Connect only to destinations this list allows, at their allowed addresses.
    pub fn with_allowlist(mut self, allow: Option<Arc<DestinationAllowlist>>) -> Self {
        self.allow = allow;
        self
    }

    /// The addresses `remote` may be dialed at, or `None` to dial it as requested.
    async fn permitted(&self, remote: &RemoteAddr) -> anyhow::Result<Option<Vec<IpAddr>>> {
        match &self.allow {
            Some(allow) => Ok(Some(
                allow
                    .permitted(&remote.host, remote.port, &self.dns_resolver, self.connect_timeout)
                    .await?,
            )),
            None => Ok(None),
        }
    }
}

impl UpstreamConnector for Socks5UpstreamConnector {
    type Reader = Socks5UpstreamReader;
    type Writer = Socks5UpstreamWriter;

    async fn connect(&self, remote: &Option<RemoteAddr>) -> anyhow::Result<(Self::Reader, Self::Writer)> {
        let Some(remote) = remote else {
            return Err(anyhow!("Missing remote destination for reverse socks5"));
        };

        let (host, port) = (&remote.host, remote.port);
        match remote.protocol {
            LocalProtocol::Tcp { proxy_protocol: _ } => {
                let stream = match self.permitted(remote).await? {
                    Some(addresses) => {
                        protocols::tcp::connect_to_addresses(host, port, &addresses, self.so_mark, self.connect_timeout)
                            .await?
                    }
                    None => {
                        protocols::tcp::connect(host, port, self.so_mark, self.connect_timeout, &self.dns_resolver)
                            .await?
                    }
                };
                let (reader, writer) = stream.into_split();
                Ok((Socks5UpstreamReader::Tcp(reader), Socks5UpstreamWriter::Tcp(writer)))
            }
            LocalProtocol::Udp { .. } => {
                let stream = match self.permitted(remote).await? {
                    Some(addresses) => {
                        udp::connect_to_addresses(host, port, &addresses, self.connect_timeout, self.so_mark).await?
                    }
                    None => udp::connect(host, port, self.connect_timeout, self.so_mark, &self.dns_resolver).await?,
                };
                Ok((Socks5UpstreamReader::Udp(stream.clone()), Socks5UpstreamWriter::Udp(stream)))
            }
            _ => Err(anyhow!("Invalid protocol for reverse socks5 {:?}", remote.protocol)),
        }
    }

    async fn connect_with_http_proxy(
        &self,
        proxy: &Url,
        remote: &Option<RemoteAddr>,
    ) -> anyhow::Result<(Self::Reader, Self::Writer)> {
        let Some(remote) = remote else {
            return Err(anyhow!("Missing remote destination for reverse socks5"));
        };

        match remote.protocol {
            LocalProtocol::Tcp { proxy_protocol: _ } => {
                // The proxy only takes one target, so an allowed destination goes as its first allowed address.
                let pinned = self.permitted(remote).await?.map(|addresses| match addresses[0] {
                    IpAddr::V4(ip) => url::Host::Ipv4(ip),
                    IpAddr::V6(ip) => url::Host::Ipv6(ip),
                });
                let stream = protocols::tcp::connect_with_http_proxy(
                    proxy,
                    pinned.as_ref().unwrap_or(&remote.host),
                    remote.port,
                    self.so_mark,
                    self.connect_timeout,
                    &self.dns_resolver,
                )
                .await?;
                let (reader, writer) = stream.into_split();
                Ok((Socks5UpstreamReader::Tcp(reader), Socks5UpstreamWriter::Tcp(writer)))
            }
            _ => Err(anyhow!("Socks5 UDP cannot use http proxy to connect to destination")),
        }
    }
}

pub enum Socks5UpstreamReader {
    Tcp(OwnedReadHalf),
    Udp(WsUdpStream),
}

impl AsyncRead for Socks5UpstreamReader {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Socks5UpstreamReader::Tcp(reader) => Pin::new(reader).poll_read(cx, buf),
            Socks5UpstreamReader::Udp(reader) => Pin::new(reader).poll_read(cx, buf),
        }
    }
}

pub enum Socks5UpstreamWriter {
    Tcp(OwnedWriteHalf),
    Udp(WsUdpStream),
}

impl AsyncWrite for Socks5UpstreamWriter {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<Result<usize, Error>> {
        match self.get_mut() {
            Socks5UpstreamWriter::Tcp(writer) => Pin::new(writer).poll_write(cx, buf),
            Socks5UpstreamWriter::Udp(wrtier) => Pin::new(wrtier).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        match self.get_mut() {
            Socks5UpstreamWriter::Tcp(writer) => Pin::new(writer).poll_flush(cx),
            Socks5UpstreamWriter::Udp(wrtier) => Pin::new(wrtier).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        match self.get_mut() {
            Socks5UpstreamWriter::Tcp(writer) => Pin::new(writer).poll_shutdown(cx),
            Socks5UpstreamWriter::Udp(wrtier) => Pin::new(wrtier).poll_shutdown(cx),
        }
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<Result<usize, Error>> {
        match self.get_mut() {
            Socks5UpstreamWriter::Tcp(writer) => Pin::new(writer).poll_write_vectored(cx, bufs),
            Socks5UpstreamWriter::Udp(wrtier) => Pin::new(wrtier).poll_write_vectored(cx, bufs),
        }
    }

    fn is_write_vectored(&self) -> bool {
        match self {
            Socks5UpstreamWriter::Tcp(v) => v.is_write_vectored(),
            Socks5UpstreamWriter::Udp(v) => v.is_write_vectored(),
        }
    }
}
