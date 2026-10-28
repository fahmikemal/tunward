use std::net::IpAddr;
use std::time::Duration;

use url::Host;

use crate::protocols;
use crate::protocols::dns::DnsResolver;
use crate::protocols::udp::WsUdpStream;
use crate::somark::SoMark;
use crate::tunnel::RemoteAddr;
use crate::tunnel::upstream_connectors::UpstreamConnector;

pub struct UdpUpstreamConnector {
    host: Host,
    port: u16,
    so_mark: SoMark,
    connect_timeout: Duration,
    dns_resolver: DnsResolver,
    addresses: Option<Vec<IpAddr>>,
}

impl UdpUpstreamConnector {
    pub fn new(
        host: Host,
        port: u16,
        so_mark: SoMark,
        connect_timeout: Duration,
        dns_resolver: DnsResolver,
    ) -> UdpUpstreamConnector {
        UdpUpstreamConnector {
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

impl UpstreamConnector for UdpUpstreamConnector {
    type Reader = WsUdpStream;
    type Writer = WsUdpStream;

    async fn connect(&self, _: &Option<RemoteAddr>) -> anyhow::Result<(Self::Reader, Self::Writer)> {
        let stream = match &self.addresses {
            Some(addresses) => {
                protocols::udp::connect_to_addresses(
                    &self.host,
                    self.port,
                    addresses,
                    self.connect_timeout,
                    self.so_mark,
                )
                .await?
            }
            None => {
                protocols::udp::connect(&self.host, self.port, self.connect_timeout, self.so_mark, &self.dns_resolver)
                    .await?
            }
        };

        Ok((stream.clone(), stream))
    }
}
