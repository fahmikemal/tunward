//! The destinations a client lets a dynamic reverse tunnel open on its side of the network.
//!
//! The peers of a reverse SOCKS5 or HTTP proxy tunnel are on the server's side, and they choose
//! where this client connects. `?allow=` limits that choice to address ranges and ports.

use crate::protocols::dns::DnsResolver;
use anyhow::{Context, anyhow, bail, ensure};
use ipnet::{IpNet, Ipv4Net};
use std::fmt;
use std::net::IpAddr;
use std::ops::RangeInclusive;
use std::time::Duration;
use url::Host;

/// An address range and the ports allowed in it; `None` allows every port.
#[derive(Debug, Clone, PartialEq, Eq)]
struct AllowedDestination {
    net: IpNet,
    ports: Option<RangeInclusive<u16>>,
}

/// Destinations a dynamic reverse tunnel may connect to, from its `?allow=` option.
///
/// A destination is allowed when one entry covers its address and port. A domain is resolved once
/// and only its allowed addresses are dialed, so a later DNS answer cannot lead elsewhere.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DestinationAllowlist(Vec<AllowedDestination>);

impl DestinationAllowlist {
    /// Parses `allow=` values, each a comma-separated list of `NET[:PORTS]` entries. NET is an IPv4
    /// address, an IPv6 address in brackets, or either with a `/prefix`; PORTS is a port or an
    /// inclusive `first..last` range, as in restriction files.
    pub fn parse<'a>(values: impl IntoIterator<Item = &'a str>) -> anyhow::Result<Self> {
        let entries = values
            .into_iter()
            .flat_map(|value| value.split(','))
            .map(|entry| parse_entry(entry.trim()).with_context(|| format!("invalid allow entry '{entry}'")))
            .collect::<anyhow::Result<Vec<_>>>()?;
        ensure!(!entries.is_empty(), "allow= needs at least one entry");
        Ok(Self(entries))
    }

    pub fn allows(&self, ip: IpAddr, port: u16) -> bool {
        let ip = ip.to_canonical();
        self.0.iter().any(|allowed| {
            allowed.net.contains(&ip) && allowed.ports.as_ref().is_none_or(|ports| ports.contains(&port))
        })
    }

    /// The addresses of `host` this tunnel may dial at `port`. Fails when there are none, so the
    /// caller connects to nothing rather than to the requested host.
    pub async fn permitted(
        &self,
        host: &Host,
        port: u16,
        dns_resolver: &DnsResolver,
        timeout: Duration,
    ) -> anyhow::Result<Vec<IpAddr>> {
        let candidates = match host {
            Host::Ipv4(ip) => vec![IpAddr::V4(*ip)],
            Host::Ipv6(ip) => vec![IpAddr::V6(*ip)],
            Host::Domain(domain) => tokio::time::timeout(timeout, dns_resolver.lookup_host(domain, port))
                .await
                .map_err(|_| anyhow!("timed out resolving {domain} to check it against the allow list"))?
                .with_context(|| format!("cannot resolve {domain} to check it against the allow list"))?
                .into_iter()
                .map(|address| address.ip())
                .collect(),
        };
        let mut permitted = Vec::with_capacity(candidates.len());
        for ip in candidates.iter().map(|ip| ip.to_canonical()) {
            if self.allows(ip, port) && !permitted.contains(&ip) {
                permitted.push(ip);
            }
        }
        if permitted.is_empty() {
            match host {
                Host::Domain(_) => bail!("{host}:{port} resolves to {candidates:?}, outside the allow list {self}"),
                _ => bail!("{host}:{port} is outside the allow list {self}"),
            }
        }
        Ok(permitted)
    }
}

impl fmt::Display for DestinationAllowlist {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, allowed) in self.0.iter().enumerate() {
            if index > 0 {
                f.write_str(",")?;
            }
            match allowed.net {
                IpNet::V6(net) => write!(f, "[{}]/{}", net.addr(), net.prefix_len())?,
                IpNet::V4(net) => write!(f, "{net}")?,
            }
            match &allowed.ports {
                Some(ports) if ports.start() == ports.end() => write!(f, ":{}", ports.start())?,
                Some(ports) => write!(f, ":{}..{}", ports.start(), ports.end())?,
                None => {}
            }
        }
        Ok(())
    }
}

/// An IPv4-mapped IPv6 range as the IPv4 range it covers, the form addresses are compared in.
pub(crate) fn canonical_net(net: IpNet) -> IpNet {
    match net {
        IpNet::V6(v6) if v6.prefix_len() >= 96 => match v6.network().to_ipv4_mapped() {
            Some(v4) => IpNet::V4(Ipv4Net::new(v4, v6.prefix_len() - 96).expect("prefix of at most 32")),
            None => net,
        },
        net => net,
    }
}

fn parse_entry(entry: &str) -> anyhow::Result<AllowedDestination> {
    // Split the address from what follows it: nothing, `/prefix`, `/prefix:ports` or `:ports`.
    let (address, rest) = if let Some(bracketed) = entry.strip_prefix('[') {
        bracketed
            .split_once(']')
            .context("an IPv6 address opened with [ needs a closing ]")?
    } else if let Some(slash) = entry.find('/') {
        entry.split_at(slash)
    } else if entry.matches(':').count() > 1 {
        bail!("write an IPv6 address as [address] or with a /prefix");
    } else {
        entry.find(':').map_or((entry, ""), |colon| entry.split_at(colon))
    };
    let (prefix, ports) = if let Some(rest) = rest.strip_prefix('/') {
        rest.split_once(':')
            .map_or((Some(rest), None), |(prefix, ports)| (Some(prefix), Some(ports)))
    } else if let Some(ports) = rest.strip_prefix(':') {
        (None, Some(ports))
    } else {
        ensure!(rest.is_empty(), "unexpected '{rest}' after the address");
        (None, None)
    };

    let ip: IpAddr = address
        .parse()
        .with_context(|| format!("'{address}' is not an IP address"))?;
    let net = match prefix {
        Some(prefix) => {
            let prefix = prefix
                .parse()
                .with_context(|| format!("'{prefix}' is not a prefix length"))?;
            IpNet::new(ip, prefix)?
        }
        None => IpNet::from(ip),
    };
    let ports = ports.map(parse_ports).transpose()?;
    Ok(AllowedDestination {
        net: canonical_net(net.trunc()),
        ports,
    })
}

fn parse_ports(ports: &str) -> anyhow::Result<RangeInclusive<u16>> {
    let port = |port: &str| {
        port.parse::<u16>()
            .with_context(|| format!("'{port}' is not a port number"))
    };
    let (first, last) = match ports.split_once("..") {
        Some((first, last)) => (port(first)?, port(last)?),
        None => (port(ports)?, port(ports)?),
    };
    ensure!(first <= last, "port range {first}..{last} starts after it ends");
    Ok(first..=last)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn allow(value: &str) -> DestinationAllowlist {
        DestinationAllowlist::parse([value]).unwrap()
    }

    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    #[test]
    fn entries_name_ranges_and_ports() {
        let list = DestinationAllowlist::parse(["10.0.0.0/8:443,192.168.1.10", "[2001:db8::]/32:8000..8100"]).unwrap();
        assert_eq!(list.to_string(), "10.0.0.0/8:443,192.168.1.10/32,[2001:db8::]/32:8000..8100");
        assert!(list.allows(v4(10, 1, 2, 3), 443));
        assert!(!list.allows(v4(10, 1, 2, 3), 80), "the port is outside the entry");
        assert!(list.allows(v4(192, 168, 1, 10), 22), "an entry without ports allows every port");
        assert!(!list.allows(v4(192, 168, 1, 11), 22));
        let doc = IpAddr::V6("2001:db8::5".parse().unwrap());
        assert!(list.allows(doc, 8050));
        assert!(!list.allows(doc, 8101));
        assert!(!list.allows(IpAddr::V6(Ipv6Addr::LOCALHOST), 443));
    }

    #[test]
    fn unbracketed_ipv6_needs_a_prefix_and_hosts_bits_are_dropped() {
        assert_eq!(allow("2001:db8::1/32:443").to_string(), "[2001:db8::]/32:443");
        assert_eq!(allow("[::1]").to_string(), "[::1]/128");
        assert_eq!(allow("10.9.8.7/8").to_string(), "10.0.0.0/8");
    }

    #[test]
    fn ipv4_mapped_addresses_are_matched_as_ipv4() {
        // A mapped destination reaches the IPv4 host, so IPv4 rules apply to it and IPv6 ones do not.
        let mapped = IpAddr::V6(Ipv4Addr::LOCALHOST.to_ipv6_mapped());
        assert!(!allow("[::]/0").allows(mapped, 80));
        assert!(allow("127.0.0.0/8").allows(mapped, 80));
        // A mapped range is the IPv4 range it covers.
        let list = allow("[::ffff:10.0.0.0]/104:443");
        assert_eq!(list.to_string(), "10.0.0.0/8:443");
        assert!(list.allows(v4(10, 0, 0, 1), 443));
    }

    #[test]
    fn malformed_entries_are_rejected() {
        for bad in [
            "",
            "10.0.0.0/33",
            "2001:db8::1",
            "[2001:db8::1",
            "[2001:db8::1]x",
            "example.com",
            "10.0.0.1:",
            "10.0.0.1:70000",
            "10.0.0.1:9..8",
            "10.0.0.1:1..",
            "10.0.0.0/x",
            "10.0.0.1,",
        ] {
            assert!(DestinationAllowlist::parse([bad]).is_err(), "{bad:?} was accepted");
        }
        assert!(
            DestinationAllowlist::parse([]).is_err(),
            "an empty list would refuse everything"
        );
    }

    #[tokio::test]
    async fn only_allowed_addresses_of_a_destination_are_dialed() {
        let list = allow("127.0.0.0/8:22");
        let resolver = DnsResolver::System;
        let timeout = Duration::from_secs(5);
        let loopback = Host::Ipv4(Ipv4Addr::LOCALHOST);
        assert_eq!(
            list.permitted(&loopback, 22, &resolver, timeout).await.unwrap(),
            [IpAddr::V4(Ipv4Addr::LOCALHOST)]
        );
        let refused = list.permitted(&loopback, 23, &resolver, timeout).await.unwrap_err();
        assert!(
            refused.to_string().contains("outside the allow list 127.0.0.0/8:22"),
            "{refused}"
        );

        // `localhost` may also resolve to ::1, which is outside the list and must not be dialed.
        let domain = Host::Domain("localhost".to_string());
        assert_eq!(
            list.permitted(&domain, 22, &resolver, timeout).await.unwrap(),
            [IpAddr::V4(Ipv4Addr::LOCALHOST)]
        );
        let elsewhere = allow("192.0.2.0/24");
        let refused = elsewhere.permitted(&domain, 22, &resolver, timeout).await.unwrap_err();
        assert!(refused.to_string().contains("resolves to"), "{refused}");
        // A mapped destination is dialed as the IPv4 address it reaches.
        let mapped = Host::Ipv6(Ipv4Addr::LOCALHOST.to_ipv6_mapped());
        assert_eq!(
            list.permitted(&mapped, 22, &resolver, timeout).await.unwrap(),
            [IpAddr::V4(Ipv4Addr::LOCALHOST)]
        );
    }
}
