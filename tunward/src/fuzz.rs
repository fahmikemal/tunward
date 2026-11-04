//! What the targets in `fuzz/` check for one input.
//!
//! The checks live in the crate, where they can reach private parsers, so `cargo test` also replays
//! `fuzz/seeds` through them on the pinned toolchain, without a fuzzer.

use crate::protocols::http_proxy::destination;
use crate::protocols::socks5::udp_server::reply_header;
use crate::protocols::udp::idle_watchdog;
use crate::tunnel::allowlist::DestinationAllowlist;
use crate::tunnel::server::utils::{ForwardedFor, forwarded_client};
use crate::tunnel::transport::io::decode_records;
use crate::tunnel::transport::{jwt_token_to_tunnel, reply_to_jwt_token, tunnel_to_jwt_token};
use crate::tunnel::{LocalProtocol, RemoteAddr};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hyper::Uri;
use hyper::header::{HeaderMap, HeaderValue};
use ipnet::IpNet;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::LazyLock;
use tokio::runtime::{Builder, Runtime};
use uuid::Uuid;

static RUNTIME: LazyLock<Runtime> = LazyLock::new(|| {
    Builder::new_current_thread()
        .enable_time()
        .build()
        .expect("a test runtime")
});

/// The routing envelope a client names on every request and a server returns in its reply.
pub fn tunnel_envelope(data: &[u8]) {
    // As written on the wire, and past the base64 layer so that mutations reach the JSON inside.
    if let Ok(token) = std::str::from_utf8(data) {
        check_envelope(token);
    }
    check_envelope(&format!("v2.{}", URL_SAFE_NO_PAD.encode(data)));
}

fn check_envelope(token: &str) {
    let Ok(metadata) = jwt_token_to_tunnel(token) else {
        return;
    };
    let claims = metadata.claims;
    assert_eq!(claims.v, 2);
    assert!(Uuid::parse_str(&claims.id).is_ok());
    let listener_port = claims.lp;
    let Ok(remote) = RemoteAddr::try_from(claims) else {
        return;
    };
    // A UDP flow on a reverse tunnel arms a timer from the timeout its client chose.
    if let LocalProtocol::ReverseUdp { timeout } | LocalProtocol::ReverseSocks5 { timeout, .. } = remote.protocol {
        let _runtime = RUNTIME.enter();
        drop(idle_watchdog(timeout));
    }
    // `exec_tunnel` refuses every other protocol before a reply is built.
    if !matches!(remote.protocol, LocalProtocol::Tcp { .. } | LocalProtocol::Udp { .. })
        && !remote.protocol.is_reverse_tunnel()
    {
        return;
    }
    let reply = reply_to_jwt_token(&remote, listener_port);
    let Ok(decoded) = jwt_token_to_tunnel(&reply) else {
        assert!(reply.len() > 8192, "a server reply did not decode: {reply}");
        return;
    };
    assert!(decoded.claims.p == remote.protocol);
    assert_eq!(decoded.claims.lp, listener_port);
    let echoed = RemoteAddr::try_from(decoded.claims).expect("a server reply names a valid destination");
    assert_eq!((echoed.host, echoed.port), (remote.host, remote.port));
}

/// The header a reverse proxy relays. The first byte picks the connection's peer, and the rest holds
/// one header value per line.
pub fn forwarded_for(data: &[u8]) {
    let Some((&flags, lists)) = data.split_first() else {
        return;
    };
    let trusted = ["10.0.0.0/8", "2001:db8::/32"].map(|net| net.parse::<IpNet>().expect("a valid range"));
    let is_trusted = |ip: IpAddr| trusted.iter().any(|net| net.contains(&ip));
    let peer = IpAddr::V4(if flags & 1 == 0 {
        Ipv4Addr::new(10, 0, 0, 1)
    } else {
        Ipv4Addr::new(192, 0, 2, 1)
    });
    let values: Vec<_> = lists
        .split(|&byte| byte == b'\n')
        .filter_map(|v| HeaderValue::from_bytes(v).ok())
        .collect();
    let read = |extra_before: Option<&str>, extra_after: Option<&str>| {
        let mut headers = HeaderMap::new();
        let extra = |value: Option<&str>| value.map(|value| HeaderValue::from_str(value).expect("a valid value"));
        for value in extra(extra_before).iter().chain(&values).chain(&extra(extra_after)) {
            headers.append("x-forwarded-for", value.clone());
        }
        forwarded_client(peer, &headers, &trusted)
    };

    let result = read(None, None);
    if values.is_empty() {
        assert_eq!(result, ForwardedFor::Absent);
    } else if !is_trusted(peer) {
        assert_eq!(result, ForwardedFor::Untrusted);
    }
    let ForwardedFor::Client(client) = result else {
        return;
    };
    assert_eq!(client, client.to_canonical());
    // A list that grows past the hop limit is refused, which keeps the peer's own address.
    let same_or_refused = |other: ForwardedFor| {
        assert!(
            other == ForwardedFor::Client(client) || other == ForwardedFor::Malformed,
            "{other:?} after {client}"
        );
    };
    // A further trusted proxy changes nothing, wherever the client was found.
    same_or_refused(read(None, Some("10.0.0.2")));
    // Whatever the client wrote before reaching the proxies cannot change who it is.
    if !is_trusted(client) {
        same_or_refused(read(Some("203.0.113.66, not an address"), None));
    }
}

/// The target of a request to the HTTP proxy listener. The first byte tells CONNECT from a plain
/// proxied request, and the rest is the request target.
pub fn http_proxy_target(data: &[u8]) {
    let Some((&flags, target)) = data.split_first() else {
        return;
    };
    let Ok(uri) = Uri::try_from(target) else {
        return;
    };
    let Some((host, port)) = destination(&uri, flags & 1 == 0) else {
        return;
    };
    assert_ne!(port, 0);
    // The client names this destination to its server, which must read back the same one.
    let remote = RemoteAddr {
        protocol: LocalProtocol::Tcp { proxy_protocol: false },
        host,
        port,
    };
    let token = tunnel_to_jwt_token(Uuid::from_u128(0), &remote);
    let Ok(metadata) = jwt_token_to_tunnel(&token) else {
        assert!(token.len() > 8192, "an envelope did not decode: {token}");
        return;
    };
    let named = RemoteAddr::try_from(metadata.claims).expect("a proxied destination is a valid one");
    assert_eq!((named.host, named.port), (remote.host, remote.port));
}

/// A datagram to the SOCKS5 UDP relay, whose header comes back on every reply to the peer.
pub fn socks5_udp_datagram(data: &[u8]) {
    let parsed = RUNTIME.block_on(fast_socks5::parse_udp_request(data));
    let Ok((_, destination, _)) = parsed else {
        return;
    };
    let header = reply_header(&destination);
    let reparsed = RUNTIME.block_on(fast_socks5::parse_udp_request(&header));
    let (fragment, _, payload) = reparsed.expect("a reply header is a valid request header");
    assert_eq!(fragment, 0);
    assert!(payload.is_empty());
}

/// The records of a tunnel stream. The first byte sets how the bytes arrive, which must not matter.
pub fn tunnel_records(data: &[u8]) {
    let Some((&chunk, wire)) = data.split_first() else {
        return;
    };
    RUNTIME.block_on(async {
        let (payload, valid, finished) = decode_records(wire, usize::from(chunk) + 1).await;
        assert!(payload.len() <= wire.len());
        assert!(!finished || payload.len() + 5 <= wire.len());
        let (whole_payload, whole_valid, whole_finished) = decode_records(wire, wire.len().max(1)).await;
        let (split_payload, split_valid, split_finished) = decode_records(wire, 1).await;
        assert_eq!((&payload, valid, finished), (&split_payload, split_valid, split_finished));
        assert_eq!((&payload, valid, finished), (&whole_payload, whole_valid, whole_finished));
    });
}

/// An `allow=` option, one value per line. What it prints must parse back to the same list.
pub fn allow_list(data: &[u8]) {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(list) = DestinationAllowlist::parse(text.split('\n')) else {
        return;
    };
    let printed = list.to_string();
    let reparsed = DestinationAllowlist::parse([printed.as_str()]).expect("a printed allow list parses");
    assert_eq!(reparsed, list);
    assert_eq!(reparsed.to_string(), printed);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    type Check = fn(&[u8]);

    #[test]
    fn every_seed_passes_the_check_of_its_target() {
        let targets: [(&str, Check); 6] = [
            ("tunnel_envelope", tunnel_envelope),
            ("forwarded_for", forwarded_for),
            ("http_proxy_target", http_proxy_target),
            ("socks5_udp_datagram", socks5_udp_datagram),
            ("tunnel_records", tunnel_records),
            ("allow_list", allow_list),
        ];
        let seeds = Path::new(env!("CARGO_MANIFEST_DIR")).join("../fuzz/seeds");
        for (target, check) in targets {
            let mut replayed = 0;
            for seed in std::fs::read_dir(seeds.join(target)).unwrap() {
                check(&std::fs::read(seed.unwrap().path()).unwrap());
                replayed += 1;
            }
            assert!(replayed > 0, "{target} has no seeds");
        }
    }
}
