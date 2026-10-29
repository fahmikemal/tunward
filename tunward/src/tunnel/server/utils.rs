use crate::LocalProtocol;
use crate::restrictions::types::{
    AllowConfig, AllowReverseTunnelConfig, AllowTunnelConfig, MatchConfig, RestrictionConfig, RestrictionsRules,
    ReverseTunnelProtocol, TunnelProtocol,
};
use crate::tunnel::RemoteAddr;
use crate::tunnel::transport::TunnelMetadata;
use crate::tunnel::transport::{JWT_HEADER_PREFIX, JwtTunnelConfig, jwt_token_to_tunnel, tunnel_to_jwt_token};
use anyhow::Context;
use bytes::Bytes;
use derive_more::{Display, Error};
use http_body_util::Either;
use http_body_util::combinators::BoxBody;
use hyper::body::Body;
use hyper::header::{AUTHORIZATION, COOKIE, HeaderMap, HeaderName, HeaderValue, SEC_WEBSOCKET_PROTOCOL};
use hyper::{Request, Response, StatusCode, http};
use ipnet::IpNet;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use tracing::{error, info};
use url::Host;
use uuid::Uuid;

pub type HttpResponse = Response<Either<String, BoxBody<Bytes, anyhow::Error>>>;

pub(super) fn bad_request() -> HttpResponse {
    http::Response::builder()
        .status(StatusCode::BAD_REQUEST)
        .body(Either::Left("Invalid request".to_string()))
        .unwrap()
}

pub(super) fn quota_rejection(error: crate::quotas::QuotaError) -> Box<HttpResponse> {
    let mut response = http::Response::builder()
        .status(StatusCode::TOO_MANY_REQUESTS)
        .header(hyper::header::CACHE_CONTROL, "no-store");
    if let Some(delay) = error.retry_after {
        let seconds = delay
            .as_secs()
            .saturating_add(u64::from(delay.subsec_nanos() != 0))
            .max(1);
        response = response.header(hyper::header::RETRY_AFTER, seconds.to_string());
    }
    Box::new(
        response
            .body(Either::Left(format!("Device quota exceeded: {}", error.kind)))
            .unwrap(),
    )
}

/// Checks if the requested (remote) port has been mapped in the configuration to another port.
/// If it is not mapped the original port number is returned.
#[inline]
pub(super) fn find_mapped_port(req_port: u16, restriction: &RestrictionConfig) -> u16 {
    // Determine if the requested port is to be mapped to a different port.
    let remote_port = restriction
        .allow
        .iter()
        .find_map(|allow| {
            if let AllowConfig::ReverseTunnel(allow) = allow {
                return allow.port_mapping.get(&req_port).cloned();
            }
            None
        })
        .unwrap_or(req_port);

    if req_port != remote_port {
        info!("Client requested port {} was mapped to {}", req_port, remote_port);
    }

    remote_port
}

#[inline]
pub(super) fn extract_authorization<B>(req: &Request<B>) -> Option<&str> {
    req.headers().get(AUTHORIZATION)?.to_str().ok()
}

const X_FORWARDED_FOR: HeaderName = HeaderName::from_static("x-forwarded-for");

/// Most hops read from one X-Forwarded-For list; a longer list is treated as malformed.
const MAX_FORWARDED_HOPS: usize = 32;

/// What a request's X-Forwarded-For header establishes about its client.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum ForwardedFor {
    /// The request has no X-Forwarded-For header.
    Absent,
    /// The connection's peer is not a trusted proxy, so the header proves nothing about the client.
    Untrusted,
    /// A trusted proxy relayed a list that holds something other than an address, or too many hops.
    Malformed,
    /// The rightmost address in the list that is not a trusted proxy.
    Client(IpAddr),
}

/// Resolves the client of a request that the connection's `peer` relayed.
///
/// Only a trusted proxy can vouch for the address before it, so the header counts only when `peer`
/// is one. The list, joined across every X-Forwarded-For header in order, is then read from the
/// right past each trusted proxy, and the first other address is the client. Entries to its left
/// were written by the client itself and are never used.
pub(super) fn forwarded_client(peer: IpAddr, headers: &HeaderMap, trusted: &[IpNet]) -> ForwardedFor {
    let mut values = headers.get_all(X_FORWARDED_FOR).iter().peekable();
    if values.peek().is_none() {
        return ForwardedFor::Absent;
    }
    if !cidr_contains(trusted, peer) {
        return ForwardedFor::Untrusted;
    }
    let mut hops = Vec::new();
    for value in values {
        let Ok(value) = value.to_str() else {
            return ForwardedFor::Malformed;
        };
        hops.extend(value.split(','));
    }
    if hops.len() > MAX_FORWARDED_HOPS {
        return ForwardedFor::Malformed;
    }
    let mut earliest = None;
    for hop in hops.iter().rev() {
        let Some(ip) = parse_forwarded_hop(hop) else {
            return ForwardedFor::Malformed;
        };
        if !cidr_contains(trusted, ip) {
            return ForwardedFor::Client(ip);
        }
        earliest = Some(ip);
    }
    // Every hop is a trusted proxy, so the leftmost one is the earliest address on record.
    earliest.map_or(ForwardedFor::Malformed, ForwardedFor::Client)
}

/// One X-Forwarded-For entry: an IP address, bare, bracketed (`[::1]`), or with the port some
/// proxies append (`192.0.2.1:443`, `[2001:db8::1]:443`).
fn parse_forwarded_hop(hop: &str) -> Option<IpAddr> {
    let hop = hop.trim();
    let ip = hop
        .parse::<IpAddr>()
        .ok()
        .or_else(|| hop.parse::<SocketAddr>().ok().map(|addr| addr.ip()))
        .or_else(|| {
            hop.strip_prefix('[')?
                .strip_suffix(']')?
                .parse::<Ipv6Addr>()
                .ok()
                .map(IpAddr::V6)
        })?;
    Some(canonical_ip(ip))
}

#[inline]
pub(super) fn extract_path_prefix(path: &str) -> Result<&str, PathPrefixErr> {
    if !path.starts_with('/') {
        return Err(PathPrefixErr::BadPathPrefix);
    }

    let without_leading_slash = &path[1..];
    let prefix = without_leading_slash
        .strip_suffix("/events")
        .ok_or(PathPrefixErr::BadUpgradeRequest)?;

    if prefix.is_empty() {
        return Err(PathPrefixErr::BadPathPrefix);
    }

    Ok(prefix)
}

#[derive(Debug, Display, Error)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub(super) enum PathPrefixErr {
    #[display("bad path prefix in upgrade request")]
    BadPathPrefix,
    #[display("bad upgrade request")]
    BadUpgradeRequest,
}

#[inline]
pub(super) fn extract_tunnel_info<B>(req: &Request<B>) -> anyhow::Result<TunnelMetadata<JwtTunnelConfig>> {
    let jwt = req
        .headers()
        .get(SEC_WEBSOCKET_PROTOCOL)
        .and_then(|header| header.to_str().ok())
        .and_then(|header| header.split_once(JWT_HEADER_PREFIX))
        .map(|(_prefix, jwt)| jwt)
        .or_else(|| req.headers().get(COOKIE).and_then(|header| header.to_str().ok()))
        .unwrap_or_default();

    jwt_token_to_tunnel(jwt).with_context(|| "invalid or unsupported tunnel metadata")
}

impl RestrictionConfig {
    /// Returns true if the parameters match the restriction config
    #[inline]
    fn filter(self: &RestrictionConfig, path_prefix: &str, authorization_header_val: Option<&str>) -> bool {
        self.r#match.iter().all(|m| match m {
            MatchConfig::Any => true,
            MatchConfig::PathPrefix(path) => path.is_match(path_prefix),
            MatchConfig::Authorization(auth) => authorization_header_val.is_some_and(|val| auth.is_match(val)),
        })
    }
}

/// Where a forward destination allowed by a restriction may be connected to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum DestinationGrant {
    /// The destination is allowed as requested; a domain is resolved when connecting.
    AsRequested,
    /// The domain is only allowed at these resolved addresses, in resolver order. Connecting to them,
    /// instead of resolving again, keeps a changed DNS answer from escaping the CIDR rules.
    Addresses(Vec<IpAddr>),
}

impl DestinationGrant {
    pub(super) fn into_addresses(self) -> Option<Vec<IpAddr>> {
        match self {
            Self::AsRequested => None,
            Self::Addresses(addresses) => Some(addresses),
        }
    }
}

/// Match IPv4-mapped IPv6 addresses as the IPv4 address they reach, so `::ffff:10.0.0.1` is subject
/// to IPv4 CIDR rules instead of IPv6 ones.
#[inline]
fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(ip) => ip.to_ipv4_mapped().map_or(IpAddr::V6(ip), IpAddr::V4),
        ip => ip,
    }
}

#[inline]
fn cidr_contains(cidr: &[IpNet], ip: IpAddr) -> bool {
    let ip = canonical_ip(ip);
    cidr.iter().any(|net| net.contains(&ip))
}

impl AllowReverseTunnelConfig {
    #[inline]
    fn is_allowed(&self, remote: &RemoteAddr) -> bool {
        if !remote.protocol.is_reverse_tunnel() {
            return false;
        }

        if !self.protocol.is_empty() && !self.protocol.contains(&ReverseTunnelProtocol::from(&remote.protocol)) {
            return false;
        }

        // Unix listeners have a filesystem identity, rather than a network port or CIDR.
        if let LocalProtocol::ReverseUnix { path } = &remote.protocol {
            return self
                .unix_path
                .is_match(path.to_str().unwrap_or("####INVALID_UNIX_PATH####"));
        }

        if !self.port.is_empty() && !self.port.iter().any(|range| range.contains(&remote.port)) {
            return false;
        }

        match &remote.host {
            Host::Domain(_) => false,
            Host::Ipv4(ip) => cidr_contains(&self.cidr, IpAddr::V4(*ip)),
            Host::Ipv6(ip) => cidr_contains(&self.cidr, IpAddr::V6(*ip)),
        }
    }
}

impl AllowTunnelConfig {
    /// Protocol and port checks, which hold whatever address the destination resolves to.
    #[inline]
    fn admits(&self, remote: &RemoteAddr) -> bool {
        !remote.protocol.is_reverse_tunnel()
            && (self.port.is_empty() || self.port.iter().any(|range| range.contains(&remote.port)))
            && (self.protocol.is_empty() || self.protocol.contains(&TunnelProtocol::from(&remote.protocol)))
    }

    /// Whether a domain must also resolve inside `cidr`. An empty list authorizes names on their own,
    /// as `--restrict-to HOST:PORT` does, and a list covering both address families checks nothing.
    #[inline]
    fn constrains_domains(&self) -> bool {
        let covers = |v4: bool| {
            self.cidr
                .iter()
                .any(|net| net.prefix_len() == 0 && matches!(net, IpNet::V4(_)) == v4)
        };
        !self.cidr.is_empty() && !(covers(true) && covers(false))
    }

    #[inline]
    fn needs_resolution(&self, remote: &RemoteAddr) -> bool {
        matches!(&remote.host, Host::Domain(host) if self.host.is_match(host))
            && self.admits(remote)
            && self.constrains_domains()
    }

    fn grant(&self, remote: &RemoteAddr, resolved: Option<&[IpAddr]>) -> Option<DestinationGrant> {
        if !self.admits(remote) {
            return None;
        }

        match &remote.host {
            Host::Domain(host) if !self.host.is_match(host) => None,
            Host::Domain(_) if !self.constrains_domains() => Some(DestinationGrant::AsRequested),
            // An unresolved domain cannot be shown to stay inside the CIDRs.
            Host::Domain(_) => {
                let addresses: Vec<IpAddr> = resolved?
                    .iter()
                    .map(|ip| canonical_ip(*ip))
                    .filter(|ip| cidr_contains(&self.cidr, *ip))
                    .collect();
                (!addresses.is_empty()).then_some(DestinationGrant::Addresses(addresses))
            }
            Host::Ipv4(ip) => cidr_contains(&self.cidr, IpAddr::V4(*ip)).then_some(DestinationGrant::AsRequested),
            Host::Ipv6(ip) => cidr_contains(&self.cidr, IpAddr::V6(*ip)).then_some(DestinationGrant::AsRequested),
        }
    }
}

impl AllowConfig {
    #[inline]
    fn needs_resolution(&self, remote: &RemoteAddr) -> bool {
        matches!(self, AllowConfig::Tunnel(config) if config.needs_resolution(remote))
    }

    #[inline]
    fn grant(&self, remote: &RemoteAddr, resolved: Option<&[IpAddr]>) -> Option<DestinationGrant> {
        match self {
            AllowConfig::ReverseTunnel(config) => config.is_allowed(remote).then_some(DestinationGrant::AsRequested),
            AllowConfig::Tunnel(config) => config.grant(remote, resolved),
        }
    }
}

impl RestrictionConfig {
    /// Merge what each allow rule grants: any rule allowing the destination as requested wins,
    /// otherwise the union of the addresses the rules allow, kept in resolver order.
    fn grant(&self, remote: &RemoteAddr, resolved: Option<&[IpAddr]>) -> Option<DestinationGrant> {
        let mut allowed = Vec::new();
        for grant in self.allow.iter().filter_map(|allow| allow.grant(remote, resolved)) {
            match grant {
                DestinationGrant::AsRequested => return Some(DestinationGrant::AsRequested),
                DestinationGrant::Addresses(addresses) => allowed.extend(addresses),
            }
        }

        let mut addresses: Vec<IpAddr> = Vec::with_capacity(allowed.len());
        for ip in resolved.unwrap_or_default().iter().map(|ip| canonical_ip(*ip)) {
            if allowed.contains(&ip) && !addresses.contains(&ip) {
                addresses.push(ip);
            }
        }
        (!addresses.is_empty()).then_some(DestinationGrant::Addresses(addresses))
    }
}

/// Validate if the requested tunnel is allowed by the restrictions.
///
/// Restrictions are checked one by one. If one matches the tunnel, the tunnel will be allowed.
/// If no restriction matches, the tunnel will be rejected.
///
/// # Return value:
/// * `Some((restriction, grant))` - Tunnel is allowed by `restriction`, at the addresses in `grant`.
/// * `None` - Tunnel is not allowed.
#[cfg(test)]
pub(super) fn validate_tunnel<'a>(
    remote: &RemoteAddr,
    path_prefix: &str,
    authorization: Option<&str>,
    restrictions: &'a RestrictionsRules,
    resolved: Option<&[IpAddr]>,
) -> Option<(&'a RestrictionConfig, DestinationGrant)> {
    validate_tunnel_with_scope(remote, path_prefix, authorization, restrictions, resolved, |_| true)
}

/// Validate if the requested tunnel is allowed by the restrictions in `scope`, checked in order.
///
/// Returns the first restriction that allows the tunnel, with the addresses it may be dialed at.
/// `resolved` holds the addresses a domain destination resolves to, when [`needs_resolution`] asked
/// for them. Rules that only allow the domain inside their CIDRs do not match without them.
pub(super) fn validate_tunnel_with_scope<'a>(
    remote: &RemoteAddr,
    path_prefix: &str,
    authorization: Option<&str>,
    restrictions: &'a RestrictionsRules,
    resolved: Option<&[IpAddr]>,
    scope: impl Fn(&RestrictionConfig) -> bool,
) -> Option<(&'a RestrictionConfig, DestinationGrant)> {
    restrictions
        .restrictions
        .iter()
        .filter(|restriction| scope(restriction))
        .filter(|restriction| restriction.filter(path_prefix, authorization))
        .find_map(|restriction| restriction.grant(remote, resolved).map(|grant| (restriction, grant)))
}

/// Whether a candidate restriction allows the requested domain only inside its CIDRs, so the
/// addresses the domain resolves to must be passed to [`validate_tunnel_with_scope`].
pub(super) fn needs_resolution(
    remote: &RemoteAddr,
    path_prefix: &str,
    authorization: Option<&str>,
    restrictions: &RestrictionsRules,
    scope: impl Fn(&RestrictionConfig) -> bool,
) -> bool {
    matches!(remote.host, Host::Domain(_))
        && restrictions
            .restrictions
            .iter()
            .filter(|restriction| scope(restriction))
            .filter(|restriction| restriction.filter(path_prefix, authorization))
            .any(|restriction| restriction.allow.iter().any(|allow| allow.needs_resolution(remote)))
}

/// Whether any restriction could allow a tunnel for this path prefix and authorization.
///
/// This is the destination-independent half of [`validate_tunnel_with_scope`]: it answers "may this client
/// talk to us at all", without knowing where it wants to go. Webtransport checks it when accepting
/// a session, since one session is shared by every tunnel the client opens on it and the
/// destination only arrives per stream. Streams are still validated in full afterwards.
pub(super) fn matches_any_restriction(
    path_prefix: &str,
    authorization: Option<&str>,
    restrictions: &RestrictionsRules,
) -> bool {
    restrictions
        .restrictions
        .iter()
        .filter(|restriction| !restriction.allow.is_empty())
        .any(|restriction| restriction.filter(path_prefix, authorization))
}

pub(super) fn inject_cookie(response: &mut http::Response<impl Body>, remote_addr: &RemoteAddr) -> Result<(), ()> {
    let Ok(header_val) = HeaderValue::from_str(&tunnel_to_jwt_token(Uuid::from_u128(0), remote_addr)) else {
        error!("Bad header value for reverse socks5: {} {}", remote_addr.host, remote_addr.port);
        return Err(());
    };
    response.headers_mut().insert(COOKIE, header_val);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::restrictions::types::{AllowReverseTunnelConfig, AllowTunnelConfig, default_cidr, default_host};
    use crate::tunnel::LocalProtocol;
    use ipnet::{IpNet, Ipv4Net, Ipv6Net};
    use regex::Regex;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::path::PathBuf;

    fn allows(config: impl Into<AllowConfig>, remote: &RemoteAddr) -> bool {
        config.into().grant(remote, None).is_some()
    }

    fn forwarded(peer: &str, values: &[&str], trusted: &[&str]) -> ForwardedFor {
        let mut headers = HeaderMap::new();
        for value in values {
            headers.append(X_FORWARDED_FOR, HeaderValue::from_str(value).unwrap());
        }
        let trusted: Vec<IpNet> = trusted.iter().map(|net| net.parse().unwrap()).collect();
        forwarded_client(peer.parse().unwrap(), &headers, &trusted)
    }

    fn client(ip: &str) -> ForwardedFor {
        ForwardedFor::Client(ip.parse().unwrap())
    }

    #[test]
    fn x_forwarded_for_is_ignored_unless_the_peer_is_a_trusted_proxy() {
        assert_eq!(forwarded("198.51.100.7", &[], &[]), ForwardedFor::Absent);
        // The default: no proxy is trusted, so any client could otherwise pick its own address.
        assert_eq!(forwarded("198.51.100.7", &["203.0.113.9"], &[]), ForwardedFor::Untrusted);
        assert_eq!(
            forwarded("198.51.100.7", &["203.0.113.9"], &["10.0.0.0/8"]),
            ForwardedFor::Untrusted
        );
    }

    #[test]
    fn the_client_is_the_rightmost_address_that_is_not_a_trusted_proxy() {
        let trusted = ["10.0.0.0/8"];
        assert_eq!(forwarded("10.0.0.1", &["203.0.113.9"], &trusted), client("203.0.113.9"));
        // The client prepended a spoofed address; the trusted proxy appended the real one.
        assert_eq!(
            forwarded("10.0.0.1", &["192.0.2.66, 203.0.113.9"], &trusted),
            client("203.0.113.9")
        );
        // Two trusted hops are skipped.
        assert_eq!(
            forwarded("10.0.0.1", &["192.0.2.66, 203.0.113.9, 10.0.0.2"], &trusted),
            client("203.0.113.9")
        );
        // Only trusted hops: the earliest one is the best address on record.
        assert_eq!(forwarded("10.0.0.1", &["10.0.0.3, 10.0.0.2"], &trusted), client("10.0.0.3"));
    }

    #[test]
    fn every_x_forwarded_for_header_forms_one_list() {
        let trusted = ["10.0.0.0/8"];
        assert_eq!(
            forwarded("10.0.0.1", &["192.0.2.66", "203.0.113.9"], &trusted),
            client("203.0.113.9")
        );
        assert_eq!(
            forwarded("10.0.0.1", &["203.0.113.9", "10.0.0.2"], &trusted),
            client("203.0.113.9")
        );
    }

    #[test]
    fn hops_are_read_with_ports_brackets_and_ipv4_mapped_forms() {
        let trusted = ["10.0.0.0/8", "2001:db8:ffff::/48"];
        assert_eq!(forwarded("10.0.0.1", &["203.0.113.9:4711"], &trusted), client("203.0.113.9"));
        assert_eq!(forwarded("10.0.0.1", &["[2001:db8::7]"], &trusted), client("2001:db8::7"));
        assert_eq!(forwarded("10.0.0.1", &["[2001:db8::7]:443"], &trusted), client("2001:db8::7"));
        // A dual-stack listener reports IPv4 peers as IPv4-mapped IPv6; they still match IPv4 ranges.
        assert_eq!(
            forwarded("::ffff:10.0.0.1", &["::ffff:203.0.113.9"], &trusted),
            client("203.0.113.9")
        );
        assert_eq!(
            forwarded("::ffff:10.0.0.1", &["::ffff:10.0.0.2, 2001:db8::7"], &trusted),
            client("2001:db8::7")
        );
    }

    #[test]
    fn a_malformed_or_oversized_list_from_a_trusted_proxy_is_not_used() {
        let trusted = ["10.0.0.0/8"];
        for value in [
            "unknown",
            "",
            "203.0.113.9,",
            "_hidden",
            "fe80::1%eth0",
            "203.0.113.9 10.0.0.2",
        ] {
            assert_eq!(forwarded("10.0.0.1", &[value], &trusted), ForwardedFor::Malformed, "{value}");
        }
        let long = vec!["10.0.0.2"; MAX_FORWARDED_HOPS + 1].join(",");
        assert_eq!(forwarded("10.0.0.1", &[long.as_str()], &trusted), ForwardedFor::Malformed);
        // Garbage left of the client is never read.
        assert_eq!(
            forwarded("10.0.0.1", &["unknown, 203.0.113.9"], &trusted),
            client("203.0.113.9")
        );
    }

    fn net(value: &str) -> IpNet {
        value.parse().unwrap()
    }

    fn tcp_to(host: Host, port: u16) -> RemoteAddr {
        RemoteAddr {
            protocol: LocalProtocol::Tcp { proxy_protocol: false },
            host,
            port,
        }
    }

    fn forward_rule(name: &str, cidr: Vec<IpNet>) -> RestrictionConfig {
        RestrictionConfig {
            name: name.into(),
            r#match: vec![MatchConfig::Any],
            allow: vec![AllowConfig::Tunnel(AllowTunnelConfig {
                protocol: vec![],
                port: vec![],
                host: default_host(),
                cidr,
            })],
        }
    }

    #[test]
    fn test_domain_cannot_bypass_constraining_cidr() {
        // A rule that only names a CIDR keeps the default `^.*$` host regex. A domain must not reach
        // addresses outside that CIDR just because its name matches the regex.
        let restrictions = RestrictionsRules {
            restrictions: vec![forward_rule("only-10-net", vec![net("10.0.0.0/8")])],
        };
        let remote = tcp_to(Host::Domain("localhost".into()), 3000);
        let loopback: [IpAddr; 2] = [Ipv4Addr::LOCALHOST.into(), Ipv6Addr::LOCALHOST.into()];
        let mixed: [IpAddr; 3] = [Ipv4Addr::LOCALHOST.into(), [10, 1, 2, 3].into(), [10, 4, 5, 6].into()];

        assert!(needs_resolution(&remote, "p", None, &restrictions, |_| true));
        assert!(validate_tunnel(&remote, "p", None, &restrictions, None).is_none());
        assert!(validate_tunnel(&remote, "p", None, &restrictions, Some(&loopback)).is_none());
        assert!(validate_tunnel(&remote, "p", None, &restrictions, Some(&[])).is_none());
        let (_, grant) = validate_tunnel(&remote, "p", None, &restrictions, Some(&mixed)).unwrap();
        assert_eq!(
            grant,
            DestinationGrant::Addresses(vec![[10, 1, 2, 3].into(), [10, 4, 5, 6].into()]),
            "only the resolved addresses inside the CIDR may be dialed, in resolver order"
        );

        // The literal address keeps being denied, as before.
        assert!(
            validate_tunnel(&tcp_to(Host::Ipv4(Ipv4Addr::LOCALHOST), 3000), "p", None, &restrictions, None).is_none()
        );
    }

    #[test]
    fn test_unconstrained_cidr_authorizes_domain_by_name() {
        let remote = tcp_to(Host::Domain("example.com".into()), 443);
        for cidr in [vec![], default_cidr()] {
            let restrictions = RestrictionsRules {
                restrictions: vec![forward_rule("by-name", cidr)],
            };
            assert!(!needs_resolution(&remote, "p", None, &restrictions, |_| true));
            let (_, grant) = validate_tunnel(&remote, "p", None, &restrictions, None).unwrap();
            assert_eq!(grant, DestinationGrant::AsRequested);
        }

        // `--restrict-to HOST:PORT` authorizes that exact name, without constraining its addresses,
        // and still denies literal addresses and other names.
        let restrictions = RestrictionsRules::from_path_prefix(&[], &[("localhost".into(), 443)]).unwrap();
        let localhost = tcp_to(Host::Domain("localhost".into()), 443);
        assert!(!needs_resolution(&localhost, "p", None, &restrictions, |_| true));
        assert_eq!(
            validate_tunnel(&localhost, "p", None, &restrictions, None).unwrap().1,
            DestinationGrant::AsRequested
        );
        assert!(
            validate_tunnel(&tcp_to(Host::Ipv4(Ipv4Addr::LOCALHOST), 443), "p", None, &restrictions, None).is_none()
        );
        assert!(
            validate_tunnel(
                &tcp_to(Host::Domain("localhost.evil".into()), 443),
                "p",
                None,
                &restrictions,
                None
            )
            .is_none()
        );

        // `--restrict-to IP:PORT` never authorizes a name, whatever it resolves to.
        let restrictions = RestrictionsRules::from_path_prefix(&[], &[("127.0.0.1".into(), 443)]).unwrap();
        let resolved: [IpAddr; 1] = [Ipv4Addr::LOCALHOST.into()];
        assert!(validate_tunnel(&localhost, "p", None, &restrictions, Some(&resolved)).is_none());
    }

    #[test]
    fn test_single_family_cidr_constrains_domains() {
        // Covering all of IPv4 says nothing about where a domain's IPv6 addresses lead.
        let restrictions = RestrictionsRules {
            restrictions: vec![forward_rule("ipv4-only", vec![net("0.0.0.0/0")])],
        };
        let remote = tcp_to(Host::Domain("dual.example".into()), 80);
        let resolved: [IpAddr; 2] = [Ipv6Addr::LOCALHOST.into(), [192, 0, 2, 10].into()];
        assert!(needs_resolution(&remote, "p", None, &restrictions, |_| true));
        assert_eq!(
            validate_tunnel(&remote, "p", None, &restrictions, Some(&resolved))
                .unwrap()
                .1,
            DestinationGrant::Addresses(vec![[192, 0, 2, 10].into()])
        );
    }

    #[test]
    fn test_ipv4_mapped_addresses_follow_ipv4_rules() {
        let mapped = Ipv4Addr::LOCALHOST.to_ipv6_mapped();
        let remote = tcp_to(Host::Ipv6(mapped), 80);

        let ipv6_only = RestrictionsRules {
            restrictions: vec![forward_rule("ipv6-only", vec![IpNet::V6(Ipv6Net::default())])],
        };
        assert!(validate_tunnel(&remote, "p", None, &ipv6_only, None).is_none());

        let loopback_v4 = RestrictionsRules {
            restrictions: vec![forward_rule("loopback-v4", vec![net("127.0.0.1/32")])],
        };
        assert!(validate_tunnel(&remote, "p", None, &loopback_v4, None).is_some());

        // A resolver answering with a mapped address is dialed at the IPv4 address it reaches.
        let domain = tcp_to(Host::Domain("mapped.example".into()), 80);
        let resolved: [IpAddr; 1] = [mapped.into()];
        assert_eq!(
            validate_tunnel(&domain, "p", None, &loopback_v4, Some(&resolved))
                .unwrap()
                .1,
            DestinationGrant::Addresses(vec![Ipv4Addr::LOCALHOST.into()])
        );
        assert!(validate_tunnel(&domain, "p", None, &ipv6_only, Some(&resolved)).is_none());

        // Reverse listeners cannot bind an IPv4 address through its mapped form either.
        let reverse = AllowReverseTunnelConfig {
            protocol: vec![],
            port: vec![],
            port_mapping: Default::default(),
            cidr: vec![IpNet::V6(Ipv6Net::default())],
            unix_path: default_host(),
        };
        let bind = RemoteAddr {
            protocol: LocalProtocol::ReverseTcp,
            host: Host::Ipv6(mapped),
            port: 8080,
        };
        assert!(!reverse.is_allowed(&bind));
    }

    #[test]
    fn test_restriction_merges_allow_rules_in_resolver_order() {
        let mut restriction = forward_rule("merged", vec![net("10.0.0.0/8")]);
        restriction.allow.push(AllowConfig::Tunnel(AllowTunnelConfig {
            protocol: vec![],
            port: vec![],
            host: default_host(),
            cidr: vec![net("192.168.0.0/16")],
        }));
        let restrictions = RestrictionsRules {
            restrictions: vec![restriction],
        };
        let remote = tcp_to(Host::Domain("multi.example".into()), 80);
        let resolved: [IpAddr; 4] = [
            [192, 168, 1, 1].into(),
            [8, 8, 8, 8].into(),
            [10, 0, 0, 1].into(),
            [192, 168, 1, 1].into(),
        ];
        assert_eq!(
            validate_tunnel(&remote, "p", None, &restrictions, Some(&resolved))
                .unwrap()
                .1,
            DestinationGrant::Addresses(vec![[192, 168, 1, 1].into(), [10, 0, 0, 1].into()])
        );

        // An allow rule authorizing the name outright makes the addresses irrelevant.
        let mut restrictions = restrictions;
        restrictions.restrictions[0]
            .allow
            .push(AllowConfig::Tunnel(AllowTunnelConfig {
                protocol: vec![],
                port: vec![],
                host: Regex::new("^multi[.]example$").unwrap(),
                cidr: vec![],
            }));
        assert_eq!(
            validate_tunnel(&remote, "p", None, &restrictions, Some(&resolved))
                .unwrap()
                .1,
            DestinationGrant::AsRequested
        );
    }

    #[test]
    fn test_restriction_order_is_kept_with_resolution() {
        // The first matching restriction still wins: resolution decides whether the constrained one
        // matches instead of skipping it for a later, broader restriction.
        let restrictions = RestrictionsRules {
            restrictions: vec![
                forward_rule("constrained", vec![net("127.0.0.0/8")]),
                forward_rule("broad", default_cidr()),
            ],
        };
        let remote = tcp_to(Host::Domain("localhost".into()), 80);
        let inside: [IpAddr; 1] = [Ipv4Addr::LOCALHOST.into()];
        let outside: [IpAddr; 1] = [[203, 0, 113, 9].into()];
        assert_eq!(
            validate_tunnel(&remote, "p", None, &restrictions, Some(&inside))
                .unwrap()
                .0
                .name,
            "constrained"
        );
        let (restriction, grant) = validate_tunnel(&remote, "p", None, &restrictions, Some(&outside)).unwrap();
        assert_eq!((restriction.name.as_str(), grant), ("broad", DestinationGrant::AsRequested));

        // Rules out of scope (another tenant's) neither match nor trigger a lookup.
        let scope = |rule: &RestrictionConfig| rule.name == "broad";
        assert!(!needs_resolution(&remote, "p", None, &restrictions, scope));
    }

    #[test]
    fn test_validate_tunnel() {
        let restrictions = RestrictionsRules {
            restrictions: vec![
                // tunnel
                RestrictionConfig {
                    name: "restrict1".into(),
                    r#match: vec![MatchConfig::Any],
                    allow: vec![AllowConfig::Tunnel(AllowTunnelConfig {
                        protocol: vec![TunnelProtocol::Tcp],
                        port: std::iter::once(80..=80).collect(),
                        cidr: vec![IpNet::from(Ipv4Net::new([127, 0, 0, 1].into(), 24).unwrap())],
                        host: Regex::new("example.com").unwrap(),
                    })],
                },
                // reverse tunnel
                RestrictionConfig {
                    name: "restrict2".into(),
                    r#match: vec![MatchConfig::Any],
                    allow: vec![AllowConfig::ReverseTunnel(AllowReverseTunnelConfig {
                        protocol: vec![ReverseTunnelProtocol::Tcp],
                        port: std::iter::once(80..=80).collect(),
                        cidr: vec![IpNet::from(Ipv4Net::new([127, 0, 0, 1].into(), 24).unwrap())],
                        port_mapping: Default::default(),
                        unix_path: default_host(),
                    })],
                },
            ],
        };

        let remote = RemoteAddr {
            protocol: LocalProtocol::Tcp { proxy_protocol: false },
            host: Host::Ipv4([127, 0, 0, 1].into()),
            port: 80,
        };
        assert_eq!(
            validate_tunnel(&remote, "/doesnt/matter", None, &restrictions, None)
                .unwrap()
                .0
                .name,
            restrictions.restrictions[0].name
        );

        let remote = RemoteAddr {
            protocol: LocalProtocol::ReverseTcp,
            host: Host::Ipv4([127, 0, 0, 1].into()),
            port: 80,
        };
        assert_eq!(
            validate_tunnel(&remote, "/doesnt/matter", None, &restrictions, None)
                .unwrap()
                .0
                .name,
            restrictions.restrictions[1].name
        );

        let remote = RemoteAddr {
            protocol: LocalProtocol::Tcp { proxy_protocol: false },
            host: Host::Ipv4([127, 0, 0, 1].into()),
            port: 81,
        };
        assert!(validate_tunnel(&remote, "/doesnt/matter", None, &restrictions, None).is_none());

        let remote = RemoteAddr {
            protocol: LocalProtocol::Tcp { proxy_protocol: false },
            host: Host::Ipv4([127, 0, 1, 1].into()),
            port: 80,
        };
        assert!(validate_tunnel(&remote, "/doesnt/matter", None, &restrictions, None).is_none());

        // The rule constrains its CIDR, so the domain is allowed only where it resolves inside it.
        let remote = RemoteAddr {
            protocol: LocalProtocol::Tcp { proxy_protocol: false },
            host: Host::Domain("example.com".into()),
            port: 80,
        };
        assert!(needs_resolution(&remote, "/doesnt/matter", None, &restrictions, |_| true));
        let inside: [IpAddr; 2] = [[8, 8, 8, 8].into(), [127, 0, 0, 7].into()];
        let (restriction, grant) =
            validate_tunnel(&remote, "/doesnt/matter", None, &restrictions, Some(&inside)).unwrap();
        assert_eq!(restriction.name, restrictions.restrictions[0].name);
        assert_eq!(grant, DestinationGrant::Addresses(vec![[127, 0, 0, 7].into()]));
        let outside: [IpAddr; 1] = [[8, 8, 8, 8].into()];
        assert!(validate_tunnel(&remote, "/doesnt/matter", None, &restrictions, Some(&outside)).is_none());
        assert!(validate_tunnel(&remote, "/doesnt/matter", None, &restrictions, None).is_none());

        let remote = RemoteAddr {
            protocol: LocalProtocol::Tcp { proxy_protocol: false },
            host: Host::Domain("not.com".into()),
            port: 80,
        };
        assert!(!needs_resolution(&remote, "/doesnt/matter", None, &restrictions, |_| true));
        assert!(validate_tunnel(&remote, "/doesnt/matter", None, &restrictions, Some(&inside)).is_none());

        let remote = RemoteAddr {
            protocol: LocalProtocol::Tcp { proxy_protocol: false },
            host: Host::Ipv6(Ipv6Addr::LOCALHOST),
            port: 80,
        };
        assert!(validate_tunnel(&remote, "/doesnt/matter", None, &restrictions, None).is_none());
    }

    #[test]
    fn test_validate_tunnel_with_auth() {
        let restrictions = RestrictionsRules {
            restrictions: vec![RestrictionConfig {
                name: "restrict1".into(),
                r#match: vec![MatchConfig::Authorization(
                    Regex::new("^[Bb]earer +the-bearer-token$").unwrap(),
                )],
                allow: vec![AllowConfig::Tunnel(AllowTunnelConfig {
                    protocol: vec![],
                    port: vec![],
                    cidr: default_cidr(),
                    host: default_host(),
                })],
            }],
        };

        let remote = RemoteAddr {
            protocol: LocalProtocol::Tcp { proxy_protocol: false },
            host: Host::Ipv4([127, 0, 0, 1].into()),
            port: 80,
        };
        assert_eq!(
            validate_tunnel(&remote, "/doesnt/matter", Some("Bearer the-bearer-token"), &restrictions, None)
                .unwrap()
                .0
                .name,
            restrictions.restrictions[0].name
        );
        assert!(
            validate_tunnel(
                &remote,
                "/doesnt/matter",
                Some("Bearer other-bearer-token"),
                &restrictions,
                None
            )
            .is_none()
        );
        assert!(validate_tunnel(&remote, "/doesnt/matter", None, &restrictions, None).is_none());
    }

    #[test]
    fn test_reverse_tunnel_is_allowed() {
        let config = AllowReverseTunnelConfig {
            protocol: vec![ReverseTunnelProtocol::Tcp],
            port: std::iter::once(80..=80).collect(),
            cidr: vec![IpNet::from(Ipv4Net::new([127, 0, 0, 1].into(), 8).unwrap())],
            port_mapping: Default::default(),
            unix_path: default_host(),
        };

        let remote = RemoteAddr {
            protocol: LocalProtocol::ReverseTcp,
            host: Host::Ipv4([127, 0, 0, 1].into()),
            port: 80,
        };
        assert!(config.is_allowed(&remote));
        assert!(allows(config.clone(), &remote));

        // another ip on the same subnet
        let remote = RemoteAddr {
            protocol: LocalProtocol::ReverseTcp,
            host: Host::Ipv4([127, 0, 1, 1].into()),
            port: 80,
        };
        assert!(config.is_allowed(&remote));
        assert!(allows(config.clone(), &remote));
    }

    #[test]
    fn test_reverse_tunnel_is_not_allowed() {
        let config = AllowReverseTunnelConfig {
            protocol: vec![ReverseTunnelProtocol::Tcp],
            port: std::iter::once(80..=80).collect(),
            cidr: vec![IpNet::from(Ipv4Net::new([127, 0, 0, 1].into(), 24).unwrap())],
            port_mapping: Default::default(),
            unix_path: default_host(),
        };

        // wrong IP
        let remote = RemoteAddr {
            protocol: LocalProtocol::ReverseTcp,
            host: Host::Ipv4([127, 0, 1, 1].into()),
            port: 80,
        };
        assert!(!config.is_allowed(&remote));
        assert!(!allows(config.clone(), &remote));

        // ipv6
        let remote = RemoteAddr {
            protocol: LocalProtocol::ReverseTcp,
            host: Host::Ipv6(Ipv6Addr::LOCALHOST),
            port: 80,
        };
        assert!(!config.is_allowed(&remote));
        assert!(!allows(config.clone(), &remote));

        // wrong port
        let remote = RemoteAddr {
            protocol: LocalProtocol::ReverseTcp,
            host: Host::Ipv4([127, 0, 0, 1].into()),
            port: 81,
        };
        assert!(!config.is_allowed(&remote));
        assert!(!allows(config.clone(), &remote));

        // wrong protocol - remote
        let remote = RemoteAddr {
            protocol: LocalProtocol::ReverseUdp { timeout: None },
            host: Host::Ipv4([127, 0, 0, 1].into()),
            port: 80,
        };
        assert!(!config.is_allowed(&remote));
        assert!(!allows(config.clone(), &remote));

        // wrong protocol - local
        let remote = RemoteAddr {
            protocol: LocalProtocol::Tcp { proxy_protocol: false },
            host: Host::Ipv4([127, 0, 0, 1].into()),
            port: 80,
        };
        assert!(!config.is_allowed(&remote));
        assert!(!allows(config.clone(), &remote));

        // host is domain
        let remote = RemoteAddr {
            protocol: LocalProtocol::ReverseTcp,
            host: Host::Domain("example.com".into()),
            port: 80,
        };
        assert!(!config.is_allowed(&remote));
        assert!(!allows(config.clone(), &remote));
    }

    #[test]
    fn test_reverse_unix_tunnel_is_allowed() {
        let config = AllowReverseTunnelConfig {
            protocol: vec![ReverseTunnelProtocol::Unix],
            port: vec![],
            cidr: vec![],
            port_mapping: Default::default(),
            unix_path: Regex::new("^/tmp/tutu$").unwrap(),
        };

        // wrong protocol
        let remote = RemoteAddr {
            protocol: LocalProtocol::ReverseTcp,
            host: Host::Ipv4([127, 0, 1, 1].into()),
            port: 80,
        };
        assert!(!config.is_allowed(&remote));

        // ReverseUnix is not allowed because wrong path
        let remote = RemoteAddr {
            protocol: LocalProtocol::ReverseUnix {
                path: PathBuf::from("/tmp/toto"),
            },
            host: Host::Domain("test.com".to_string()),
            port: 12,
        };
        assert!(!config.is_allowed(&remote));

        // ReverseUnix is allowed
        let remote = RemoteAddr {
            protocol: LocalProtocol::ReverseUnix {
                path: PathBuf::from("/tmp/tutu"),
            },
            host: Host::Domain("test.com".to_string()),
            port: 12,
        };
        assert!(config.is_allowed(&remote));
    }

    #[test]
    fn test_tunnel_is_allowed() {
        let config = AllowTunnelConfig {
            protocol: vec![TunnelProtocol::Tcp],
            port: std::iter::once(80..=80).collect(),
            cidr: vec![IpNet::from(Ipv4Net::new([127, 0, 0, 1].into(), 8).unwrap())],
            host: Regex::new(".*").unwrap(),
        };

        let remote = RemoteAddr {
            protocol: LocalProtocol::Tcp { proxy_protocol: false },
            host: Host::Ipv4([127, 0, 0, 1].into()),
            port: 80,
        };
        assert!(config.grant(&remote, None).is_some());
        assert!(allows(config.clone(), &remote));

        // another ip on the same subnet
        let remote = RemoteAddr {
            protocol: LocalProtocol::Tcp { proxy_protocol: false },
            host: Host::Ipv4([127, 0, 1, 1].into()),
            port: 80,
        };
        assert!(config.grant(&remote, None).is_some());
        assert!(allows(config.clone(), &remote));

        // host is domain: the CIDR constrains it, so it is allowed at its resolved addresses inside
        let remote = RemoteAddr {
            protocol: LocalProtocol::Tcp { proxy_protocol: false },
            host: Host::Domain("example.com".into()),
            port: 80,
        };
        let resolved: [IpAddr; 2] = [[93, 184, 215, 14].into(), [127, 0, 0, 9].into()];
        assert_eq!(
            config.grant(&remote, Some(&resolved)),
            Some(DestinationGrant::Addresses(vec![[127, 0, 0, 9].into()]))
        );
        assert!(config.grant(&remote, None).is_none());
        assert!(!allows(config.clone(), &remote));
    }

    #[test]
    fn test_tunnel_is_not_allowed() {
        let config = AllowTunnelConfig {
            protocol: vec![TunnelProtocol::Tcp],
            port: std::iter::once(80..=80).collect(),
            cidr: vec![IpNet::from(Ipv4Net::new([127, 0, 0, 1].into(), 24).unwrap())],
            host: Regex::new("example.com").unwrap(),
        };

        // wrong IP
        let remote = RemoteAddr {
            protocol: LocalProtocol::Tcp { proxy_protocol: false },
            host: Host::Ipv4([127, 0, 1, 1].into()),
            port: 80,
        };
        assert!(config.grant(&remote, None).is_none());
        assert!(!allows(config.clone(), &remote));

        // ipv6
        let remote = RemoteAddr {
            protocol: LocalProtocol::Tcp { proxy_protocol: false },
            host: Host::Ipv6(Ipv6Addr::LOCALHOST),
            port: 80,
        };
        assert!(config.grant(&remote, None).is_none());
        assert!(!allows(config.clone(), &remote));

        // wrong port
        let remote = RemoteAddr {
            protocol: LocalProtocol::Tcp { proxy_protocol: false },
            host: Host::Ipv4([127, 0, 0, 1].into()),
            port: 81,
        };
        assert!(config.grant(&remote, None).is_none());
        assert!(!allows(config.clone(), &remote));

        // wrong protocol - remote
        let remote = RemoteAddr {
            protocol: LocalProtocol::ReverseTcp,
            host: Host::Ipv4([127, 0, 0, 1].into()),
            port: 80,
        };
        assert!(config.grant(&remote, None).is_none());
        assert!(!allows(config.clone(), &remote));

        // wrong protocol - local
        let remote = RemoteAddr {
            protocol: LocalProtocol::Udp { timeout: None },
            host: Host::Ipv4([127, 0, 0, 1].into()),
            port: 80,
        };
        assert!(config.grant(&remote, None).is_none());
        assert!(!allows(config.clone(), &remote));

        // wrong host
        let remote = RemoteAddr {
            protocol: LocalProtocol::Tcp { proxy_protocol: false },
            host: Host::Domain("not.com".into()),
            port: 80,
        };
        assert!(config.grant(&remote, None).is_none());
        assert!(!allows(config.clone(), &remote));
    }

    #[test]
    fn test_extract_path_prefix_happy_path() {
        assert_eq!(extract_path_prefix("/prefix/events"), Ok("prefix"));
        assert_eq!(extract_path_prefix("/prefix/a/events"), Ok("prefix/a"));
        assert_eq!(extract_path_prefix("/prefix/a/b/events"), Ok("prefix/a/b"));
        assert_eq!(
            extract_path_prefix("/spiffe://example.org/ns/prod/sa/device-1/events"),
            Ok("spiffe://example.org/ns/prod/sa/device-1")
        );
        assert_eq!(
            extract_path_prefix("/device-01.corp.internal/events"),
            Ok("device-01.corp.internal")
        );
    }

    #[test]
    fn test_extract_path_prefix_no_events_suffix() {
        assert_eq!(extract_path_prefix("/prefix/events/"), Err(PathPrefixErr::BadUpgradeRequest));
        assert_eq!(extract_path_prefix("/prefix"), Err(PathPrefixErr::BadUpgradeRequest));
        assert_eq!(extract_path_prefix("/prefixevents"), Err(PathPrefixErr::BadUpgradeRequest));
        assert_eq!(extract_path_prefix("/prefix/event"), Err(PathPrefixErr::BadUpgradeRequest));
        assert_eq!(extract_path_prefix("/prefix/a"), Err(PathPrefixErr::BadUpgradeRequest));
        assert_eq!(extract_path_prefix("/prefix/a/b"), Err(PathPrefixErr::BadUpgradeRequest));
    }

    #[test]
    fn test_extract_path_prefix_no_slash_prefix() {
        assert_eq!(extract_path_prefix(""), Err(PathPrefixErr::BadPathPrefix));
        assert_eq!(extract_path_prefix("p"), Err(PathPrefixErr::BadPathPrefix));
        assert_eq!(extract_path_prefix("\\"), Err(PathPrefixErr::BadPathPrefix));
        assert_eq!(extract_path_prefix("prefix/events"), Err(PathPrefixErr::BadPathPrefix));
        assert_eq!(extract_path_prefix("prefix/a/events"), Err(PathPrefixErr::BadPathPrefix));
        assert_eq!(extract_path_prefix("prefix/a/b/events"), Err(PathPrefixErr::BadPathPrefix));
    }

    #[test]
    fn test_empty_restrictions_deny_tunnel_and_session() {
        let empty_rules = RestrictionsRules {
            restrictions: vec![RestrictionConfig {
                name: "empty".into(),
                r#match: vec![MatchConfig::Any],
                allow: vec![],
            }],
        };
        let remote = RemoteAddr {
            protocol: LocalProtocol::Tcp { proxy_protocol: false },
            host: Host::Ipv4([127, 0, 0, 1].into()),
            port: 80,
        };
        assert!(validate_tunnel(&remote, "events", None, &empty_rules, None).is_none());
        assert!(!matches_any_restriction("events", None, &empty_rules));
    }
}
