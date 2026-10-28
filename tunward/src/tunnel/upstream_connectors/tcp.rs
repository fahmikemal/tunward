use std::net::IpAddr;
use std::time::Duration;

use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use url::{Host, Url};

use crate::protocols;
use crate::protocols::dns::DnsResolver;
use crate::somark::SoMark;
use crate::tunnel::RemoteAddr;
use crate::tunnel::upstream_connectors::UpstreamConnector;

pub struct TcpUpstreamConnector {
    host: Host,
    port: u16,
    so_mark: SoMark,
    connect_timeout: Duration,
    dns_resolver: DnsResolver,
    addresses: Option<Vec<IpAddr>>,
}

impl TcpUpstreamConnector {
    pub fn new(
        host: Host,
        port: u16,
        so_mark: SoMark,
        connect_timeout: Duration,
        dns_resolver: DnsResolver,
    ) -> TcpUpstreamConnector {
        TcpUpstreamConnector {
            host,
            port,
            so_mark,
            connect_timeout,
            dns_resolver,
            addresses: None,
        }
    }

    /// Dial only these addresses, already checked against the restriction rules, instead of
    /// resolving the configured host again.
    pub fn with_addresses(mut self, addresses: Option<Vec<IpAddr>>) -> Self {
        self.addresses = addresses;
        self
    }
}

impl UpstreamConnector for TcpUpstreamConnector {
    type Reader = OwnedReadHalf;
    type Writer = OwnedWriteHalf;

    async fn connect(&self, remote: &Option<RemoteAddr>) -> anyhow::Result<(Self::Reader, Self::Writer)> {
        let stream = match (remote, &self.addresses) {
            (None, Some(addresses)) => {
                protocols::tcp::connect_to_addresses(
                    &self.host,
                    self.port,
                    addresses,
                    self.so_mark,
                    self.connect_timeout,
                )
                .await?
            }
            _ => {
                let (host, port) = match remote {
                    Some(remote) => (&remote.host, remote.port),
                    None => (&self.host, self.port),
                };
                protocols::tcp::connect(host, port, self.so_mark, self.connect_timeout, &self.dns_resolver).await?
            }
        };
        Ok(stream.into_split())
    }

    async fn connect_with_http_proxy(
        &self,
        proxy: &Url,
        remote: &Option<RemoteAddr>,
    ) -> anyhow::Result<(Self::Reader, Self::Writer)> {
        // The proxy only takes one target, so a pinned destination is sent as its preferred address.
        let pinned = match (remote, self.addresses.as_deref()) {
            (None, Some([address, ..])) => Some(match address {
                IpAddr::V4(ip) => Host::Ipv4(*ip),
                IpAddr::V6(ip) => Host::Ipv6(*ip),
            }),
            _ => None,
        };
        let (host, port) = match (remote, &pinned) {
            (Some(remote), _) => (&remote.host, remote.port),
            (None, Some(pinned)) => (pinned, self.port),
            (None, None) => (&self.host, self.port),
        };

        let stream = protocols::tcp::connect_with_http_proxy(
            proxy,
            host,
            port,
            self.so_mark,
            self.connect_timeout,
            &self.dns_resolver,
        )
        .await?;
        Ok(stream.into_split())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn pinned_addresses_are_dialed_without_resolving_the_host() {
        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        // `.invalid` never resolves (RFC 6761), so success proves the lookup was skipped.
        let connector = TcpUpstreamConnector::new(
            Host::Domain("pinned.invalid".into()),
            port,
            SoMark::new(None),
            Duration::from_secs(2),
            DnsResolver::System,
        )
        .with_addresses(Some(vec![Ipv4Addr::LOCALHOST.into()]));

        let (mut rx, mut tx) = connector.connect(&None).await.unwrap();
        let (mut accepted, _) = listener.accept().await.unwrap();
        tx.write_all(b"pinned").await.unwrap();
        let mut buf = [0; 6];
        accepted.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"pinned");
        accepted.write_all(b"ok").await.unwrap();
        let mut buf = [0; 2];
        rx.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ok");
    }

    #[tokio::test]
    async fn unpinned_connector_still_resolves_the_host() {
        let connector = TcpUpstreamConnector::new(
            Host::Domain("unpinned.invalid.".into()),
            9,
            SoMark::new(None),
            Duration::from_secs(2),
            DnsResolver::System,
        );
        let error = connector.connect(&None).await.unwrap_err();
        assert!(format!("{error:#}").contains("cannot resolve domain"), "{error:#}");
    }
}
