use crate::config::ClientIdentityField;
use crate::embedded_certificate;
use crate::executor::DefaultTokioExecutor;
use crate::protocols;
use crate::protocols::dns::DnsResolver;
use crate::restrictions::types;
use crate::restrictions::types::{AllowConfig, MatchConfig, RestrictionConfig, RestrictionsRules};
use crate::somark::SoMark;
use crate::tunnel::client::{Client, ClientConfig, TlsClientConfig};
use crate::tunnel::downstream_listeners::{Socks5DownstreamListener, TcpDownstreamListener, UdpDownstreamListener};
use crate::tunnel::server::{Server, ServerConfig, TlsServerConfig};
use crate::tunnel::transport::{TransportAddr, TransportScheme};
use crate::tunnel::upstream_connectors::TcpUpstreamConnector;
use crate::tunnel::{LocalProtocol, RemoteAddr};
use bytes::BytesMut;
use futures_util::{Stream, StreamExt};
use hyper::http::HeaderValue;
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use regex::Regex;
use rstest::{fixture, rstest};
use scopeguard::defer;
use serial_test::serial;
use std::collections::{BTreeSet, HashMap};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::pin;
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use url::Host;
use web_transport_quinn::quinn;

/// Ports already handed out by [`free_port`] in this process. A port becomes free again as soon
/// as the probe socket is dropped, so without this two calls could hand out the same one.
static HANDED_OUT_PORTS: Mutex<BTreeSet<u16>> = Mutex::new(BTreeSet::new());

/// Reserve a loopback port that is free for both TCP and UDP.
///
/// Webtransport serves QUIC/UDP on the same port as the TCP listener, so a port free for only
/// one of the two would make its tests flaky. Both probe sockets are dropped before returning:
/// the port is picked, not held, and the caller binds it right after.
fn free_port() -> u16 {
    loop {
        let tcp = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("Cannot bind a free TCP port");
        let port = tcp.local_addr().expect("Cannot read the bound TCP port").port();
        drop(tcp);

        if HANDED_OUT_PORTS.lock().unwrap().insert(port)
            && std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, port)).is_ok()
        {
            return port;
        }
    }
}

/// A loopback address on a free port, with its host apart, as tunnel listeners take both.
fn free_addr() -> (SocketAddr, Host) {
    (
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, free_port())),
        Host::Ipv4(Ipv4Addr::LOCALHOST),
    )
}

#[fixture]
fn dns_resolver() -> DnsResolver {
    // Whichever provider the crate was built with, as only one of the two is compiled in.
    // Installing twice is expected across fixtures, hence the ignored result.
    #[cfg(feature = "aws-lc-rs")]
    let _ = tokio_rustls::rustls::crypto::aws_lc_rs::default_provider().install_default();
    #[cfg(all(feature = "ring", not(feature = "aws-lc-rs")))]
    let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();

    DnsResolver::new_from_urls(&[], None, SoMark::new(None), true).expect("Cannot create DNS resolver")
}

/// Cleartext server configuration on a free loopback port, for tests to adjust before `Server::new`.
fn server_config(dns_resolver: DnsResolver) -> ServerConfig {
    ServerConfig {
        socket_so_mark: SoMark::new(None),
        bind: free_addr().0,
        websocket_ping_frequency: Some(Duration::from_secs(10)),
        timeout_connect: Duration::from_secs(10),
        websocket_mask_frame: false,
        tls: None,
        dns_resolver,
        restriction_config: None,
        http_proxy: None,
        remote_server_idle_timeout: Duration::from_secs(30),
        enable_webtransport: false,
        management_api: None,
        device_quotas: None,
        device_revocation_config: None,
        fleet_inventory: None,
        tenant_config: None,
        fleet_inventory_max_devices: std::num::NonZeroU32::new(10000).unwrap(),
        tls_client_identity_field: ClientIdentityField::default(),
        tls_handshake_timeout: Duration::from_secs(10),
        max_pending_tls_handshakes: std::num::NonZeroU32::new(1024).unwrap(),
    }
}

/// The embedded self-signed certificate, without client authentication.
fn embedded_tls() -> TlsServerConfig {
    TlsServerConfig {
        tls_certificate: parking_lot::Mutex::new(embedded_certificate::TLS_CERTIFICATE.0.clone()),
        tls_key: parking_lot::Mutex::new(embedded_certificate::TLS_CERTIFICATE.1.clone_key()),
        tls_client_ca_certificates: None,
        tls_certificate_path: None,
        tls_key_path: None,
        tls_client_ca_certs_path: None,
    }
}

#[fixture]
fn server_no_tls(dns_resolver: DnsResolver) -> Server {
    Server::new(server_config(dns_resolver), DefaultTokioExecutor::default())
}

/// Server serving webtransport over UDP, alongside websocket/http2 over TCP.
#[fixture]
fn server_webtransport(dns_resolver: DnsResolver) -> Server {
    let server_config = ServerConfig {
        tls: Some(embedded_tls()),
        enable_webtransport: true,
        ..server_config(dns_resolver)
    };
    Server::new(server_config, DefaultTokioExecutor::default())
}

/// Not a fixture, as the port to dial is only known once the server fixture has picked one.
async fn client_webtransport(server_port: u16, dns_resolver: DnsResolver) -> Client {
    // The embedded certificate is self-signed with no SAN, so verification must be off.
    let tls_connector =
        crate::protocols::tls::tls_connector(false, TransportScheme::Wts.alpn_protocols(), true, None, None, None)
            .unwrap();
    let tls = TlsClientConfig {
        tls_sni_disabled: false,
        tls_sni_override: None,
        tls_verify_certificate: false,
        tls_connector: Arc::new(parking_lot::RwLock::new(tls_connector)),
        tls_certificate_path: None,
        tls_key_path: None,
    };

    let client_config = ClientConfig {
        remote_addr: TransportAddr::new(TransportScheme::Wts, Host::Ipv4(Ipv4Addr::LOCALHOST), server_port, Some(tls))
            .unwrap(),
        socket_so_mark: SoMark::new(None),
        http_upgrade_path_prefix: "tunward".to_string(),
        http_upgrade_credentials: None,
        http_headers: HashMap::new(),
        http_headers_file: None,
        http_header_host: HeaderValue::from_str(&format!("127.0.0.1:{server_port}")).unwrap(),
        timeout_connect: Duration::from_secs(10),
        websocket_ping_frequency: Some(Duration::from_secs(10)),
        websocket_mask_frame: false,
        dns_resolver,
        http_proxy: None,
        webtransport: Some(Arc::new(
            crate::tunnel::transport::webtransport::WebTransportEndpoint::new(
                crate::protocols::tls::quic_client_config(false, None, None).unwrap(),
                SoMark::new(None),
                Some(Duration::from_secs(10)),
            )
            .unwrap(),
        )),
        client_id: None,
    };

    Client::new(
        client_config,
        1,
        Duration::from_secs(1),
        Duration::from_secs(1),
        DefaultTokioExecutor::default(),
    )
    .await
    .unwrap()
}

/// Not a fixture, as the port to dial is only known once the server fixture has picked one.
async fn client_ws(server_port: u16, dns_resolver: DnsResolver) -> Client {
    let client_config = ClientConfig {
        remote_addr: TransportAddr::new(TransportScheme::Ws, Host::Ipv4(Ipv4Addr::LOCALHOST), server_port, None)
            .unwrap(),
        socket_so_mark: SoMark::new(None),
        http_upgrade_path_prefix: "tunward".to_string(),
        http_upgrade_credentials: None,
        http_headers: HashMap::new(),
        http_headers_file: None,
        http_header_host: HeaderValue::from_str(&format!("127.0.0.1:{server_port}")).unwrap(),
        timeout_connect: Duration::from_secs(10),
        websocket_ping_frequency: Some(Duration::from_secs(10)),
        websocket_mask_frame: false,
        dns_resolver,
        http_proxy: None,
        webtransport: None,
        client_id: None,
    };

    Client::new(
        client_config,
        1,
        Duration::from_secs(1),
        Duration::from_secs(1),
        DefaultTokioExecutor::default(),
    )
    .await
    .unwrap()
}

#[fixture]
fn no_restrictions() -> RestrictionsRules {
    pub fn default_host() -> Regex {
        Regex::new("^.*$").unwrap()
    }

    pub fn default_cidr() -> Vec<IpNet> {
        vec![IpNet::V4(Ipv4Net::default()), IpNet::V6(Ipv6Net::default())]
    }

    let tunnels = types::AllowConfig::Tunnel(types::AllowTunnelConfig {
        protocol: vec![],
        port: vec![],
        host: default_host(),
        cidr: default_cidr(),
    });
    let reverse_tunnel = AllowConfig::ReverseTunnel(types::AllowReverseTunnelConfig {
        protocol: vec![],
        port: vec![],
        port_mapping: Default::default(),
        cidr: default_cidr(),
        unix_path: default_host(),
    });

    RestrictionsRules {
        restrictions: vec![RestrictionConfig {
            name: "".to_string(),
            r#match: vec![MatchConfig::Any],
            allow: vec![tunnels, reverse_tunnel],
        }],
    }
}

#[rstest]
#[timeout(Duration::from_secs(10))]
#[tokio::test]
#[serial]
async fn test_tcp_tunnel(server_no_tls: Server, no_restrictions: RestrictionsRules, dns_resolver: DnsResolver) {
    let (tunnel_listen, tunnel_host) = free_addr();
    let (endpoint_listen, endpoint_host) = free_addr();

    let server_port = server_no_tls.config.bind.port();
    let server_h = tokio::spawn(server_no_tls.serve(no_restrictions));
    defer! { server_h.abort(); };

    let client_ws = client_ws(server_port, dns_resolver.clone()).await;

    let server = TcpDownstreamListener::new(tunnel_listen, (endpoint_host, endpoint_listen.port()), false)
        .await
        .unwrap();
    tokio::spawn(async move {
        client_ws.run_tunnel(server).await.unwrap();
    });

    let mut tcp_listener = protocols::tcp::run_server(endpoint_listen, false).await.unwrap();
    let mut client = protocols::tcp::connect(
        &tunnel_host,
        tunnel_listen.port(),
        SoMark::new(None),
        Duration::from_secs(10),
        &dns_resolver,
    )
    .await
    .unwrap();

    client.write_all(b"Hello").await.unwrap();
    let mut dd = tcp_listener.next().await.unwrap().unwrap();
    let mut buf = BytesMut::new();
    dd.read_buf(&mut buf).await.unwrap();
    assert_eq!(&buf[..5], b"Hello");
    buf.clear();

    dd.write_all(b"world!").await.unwrap();
    client.read_buf(&mut buf).await.unwrap();
    assert_eq!(&buf[..6], b"world!");
}

#[rstest]
#[case(TransportScheme::Ws)]
#[timeout(Duration::from_secs(15))]
#[tokio::test]
#[serial]
async fn test_reverse_tunnel_timeout_recovers(
    server_no_tls: Server,
    no_restrictions: RestrictionsRules,
    dns_resolver: DnsResolver,
    #[case] scheme: TransportScheme,
) {
    let server_addr = server_no_tls.config.bind;
    let server_h = tokio::spawn(server_no_tls.serve(no_restrictions));
    defer! { server_h.abort(); };

    let proxy = TcpListener::bind(free_addr().0).await.unwrap();
    let proxy_port = proxy.local_addr().unwrap().port();
    let (events_tx, mut events_rx) = mpsc::unbounded_channel();
    let proxy_h = tokio::spawn(async move {
        let attempts = Arc::new(AtomicUsize::new(0));
        let mut connections = JoinSet::new();
        loop {
            let (mut downstream, _) = proxy.accept().await.unwrap();
            let attempts = attempts.clone();
            let events = events_tx.clone();
            connections.spawn(async move {
                let mut buf = [0; 4096];
                let len = downstream.read(&mut buf).await.unwrap();
                if len == 0 {
                    return; // Ignore unused connections from the client's pool.
                }
                let attempt = attempts.fetch_add(1, Ordering::SeqCst) + 1;
                let mut upstream = TcpStream::connect(server_addr).await.unwrap();
                upstream.write_all(&buf[..len]).await.unwrap();
                events.send((attempt, "opened")).unwrap();
                if attempt == 2 {
                    // Silently stall the next pending request while keeping TCP open.
                    // Established sessions and later attempts still pass through normally.
                    while let Ok(len) = downstream.read(&mut buf).await {
                        if len == 0 {
                            break;
                        }
                    }
                } else {
                    let _ = tokio::io::copy_bidirectional(&mut downstream, &mut upstream).await;
                }
                drop(upstream);
                drop(downstream);
                let _ = events.send((attempt, "closed"));
            });
        }
    });
    defer! { proxy_h.abort(); };

    let client = client_ws(proxy_port, dns_resolver.clone()).await;
    let mut config = (*client.config).clone();
    drop(client);
    config.remote_addr = TransportAddr::new(scheme, Host::Ipv4(Ipv4Addr::LOCALHOST), proxy_port, None).unwrap();
    // Avoid unused pooled connections so every connection belongs to one attempt.
    let client = Client::new(
        config,
        0,
        Duration::from_secs(1),
        Duration::from_secs(1),
        DefaultTokioExecutor::default(),
    )
    .await
    .unwrap();
    let endpoint = TcpListener::bind(free_addr().0).await.unwrap();
    let (reverse_addr, reverse_host) = free_addr();
    let connector = TcpUpstreamConnector::new(
        Host::Ipv4(Ipv4Addr::LOCALHOST),
        endpoint.local_addr().unwrap().port(),
        SoMark::new(None),
        Duration::from_secs(1),
        dns_resolver,
    );
    let client_h = tokio::spawn(client.run_reverse_tunnel(
        RemoteAddr {
            protocol: LocalProtocol::ReverseTcp,
            host: reverse_host,
            port: reverse_addr.port(),
        },
        connector,
    ));
    defer! { client_h.abort(); };

    assert_eq!(events_rx.recv().await, Some((1, "opened")));
    // The proxy observes the request just before the server binds the reverse listener.
    let mut first = loop {
        match TcpStream::connect(reverse_addr).await {
            Ok(stream) => break stream,
            Err(err) if err.kind() == std::io::ErrorKind::ConnectionRefused => {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            Err(err) => panic!("Cannot connect to reverse listener: {err}"),
        }
    };
    let (mut first_endpoint, _) = endpoint.accept().await.unwrap();

    assert_eq!(events_rx.recv().await, Some((2, "opened")));
    // Expiry must close the old TCP connection, not just abandon the handshake future.
    assert_eq!(events_rx.recv().await, Some((2, "closed")));
    assert_eq!(events_rx.recv().await, Some((3, "opened")));
    // Also expire a healthy idle request, to exercise cleanup of the server's waiter.
    assert_eq!(events_rx.recv().await, Some((3, "closed")));
    assert_eq!(events_rx.recv().await, Some((4, "opened")));

    first.write_all(b"still alive").await.unwrap();
    let mut buf = [0; 11];
    first_endpoint.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"still alive");
    first_endpoint.write_all(b"still alive").await.unwrap();
    first.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"still alive");

    // An expired waiter must not consume the new application connection.
    let mut second = TcpStream::connect(reverse_addr).await.unwrap();
    let (mut second_endpoint, _) = endpoint.accept().await.unwrap();
    second.write_all(b"new session").await.unwrap();
    second_endpoint.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"new session");
}

#[rstest]
#[timeout(Duration::from_secs(5))]
#[tokio::test]
async fn test_reverse_tunnel_timeout_disabled(dns_resolver: DnsResolver) {
    let server = TcpListener::bind(free_addr().0).await.unwrap();
    let client = client_ws(server.local_addr().unwrap().port(), dns_resolver.clone()).await;
    let (reverse_addr, reverse_host) = free_addr();
    let connector = TcpUpstreamConnector::new(
        Host::Ipv4(Ipv4Addr::LOCALHOST),
        free_port(),
        SoMark::new(None),
        Duration::from_secs(1),
        dns_resolver,
    );
    let client_h = tokio::spawn(client.run_reverse_tunnel(
        RemoteAddr {
            protocol: LocalProtocol::ReverseTcp,
            host: reverse_host,
            port: reverse_addr.port(),
        },
        connector,
    ));
    defer! { client_h.abort(); };

    let (mut pending, _) = server.accept().await.unwrap();
    let mut request = Vec::new();
    while !request.ends_with(b"\r\n\r\n") {
        request.push(pending.read_u8().await.unwrap());
    }
    assert!(request.starts_with(b"GET "));
    // Zero means unlimited waiting, rather than an immediately expired attempt.
    assert!(
        tokio::time::timeout(Duration::from_millis(100), pending.read_u8())
            .await
            .is_err()
    );
}

#[rstest]
#[timeout(Duration::from_secs(10))]
#[tokio::test]
#[serial]
async fn test_udp_tunnel(server_no_tls: Server, no_restrictions: RestrictionsRules, dns_resolver: DnsResolver) {
    let (tunnel_listen, tunnel_host) = free_addr();
    let (endpoint_listen, endpoint_host) = free_addr();

    let server_port = server_no_tls.config.bind.port();
    let server_h = tokio::spawn(server_no_tls.serve(no_restrictions));
    defer! { server_h.abort(); };

    let client_ws = client_ws(server_port, dns_resolver.clone()).await;

    let server = UdpDownstreamListener::new(tunnel_listen, (endpoint_host, endpoint_listen.port()), None)
        .await
        .unwrap();
    tokio::spawn(async move {
        client_ws.run_tunnel(server).await.unwrap();
    });

    let udp_listener = protocols::udp::run_server(endpoint_listen, None, |_| Ok(()), |s| Ok(s.clone()))
        .await
        .unwrap();
    let mut client = protocols::udp::connect(
        &tunnel_host,
        tunnel_listen.port(),
        Duration::from_secs(10),
        SoMark::new(None),
        &dns_resolver,
    )
    .await
    .unwrap();

    client.write_all(b"Hello").await.unwrap();
    pin!(udp_listener);
    let dd = udp_listener.next().await.unwrap().unwrap();
    pin!(dd);
    let mut buf = BytesMut::new();
    dd.read_buf(&mut buf).await.unwrap();
    assert_eq!(&buf[..5], b"Hello");
    buf.clear();

    dd.writer().write_all(b"world!").await.unwrap();
    client.read_buf(&mut buf).await.unwrap();
    assert_eq!(&buf[..6], b"world!");
}

#[rstest]
#[timeout(Duration::from_secs(15))]
#[tokio::test]
#[serial]
async fn test_tcp_tunnel_webtransport(
    server_webtransport: Server,
    no_restrictions: RestrictionsRules,
    dns_resolver: DnsResolver,
) {
    let (tunnel_listen, tunnel_host) = free_addr();
    let (endpoint_listen, endpoint_host) = free_addr();

    let server_port = server_webtransport.config.bind.port();
    let server_h = tokio::spawn(server_webtransport.serve(no_restrictions));
    defer! { server_h.abort(); };

    let client = client_webtransport(server_port, dns_resolver.clone()).await;

    let server = TcpDownstreamListener::new(tunnel_listen, (endpoint_host, endpoint_listen.port()), false)
        .await
        .unwrap();
    tokio::spawn(async move {
        client.run_tunnel(server).await.unwrap();
    });

    let mut tcp_listener = protocols::tcp::run_server(endpoint_listen, false).await.unwrap();
    let mut client = protocols::tcp::connect(
        &tunnel_host,
        tunnel_listen.port(),
        SoMark::new(None),
        Duration::from_secs(10),
        &dns_resolver,
    )
    .await
    .unwrap();

    client.write_all(b"Hello").await.unwrap();
    let mut dd = tcp_listener.next().await.unwrap().unwrap();
    let mut buf = BytesMut::new();
    dd.read_buf(&mut buf).await.unwrap();
    assert_eq!(&buf[..5], b"Hello");
    buf.clear();

    dd.write_all(b"world!").await.unwrap();
    client.read_buf(&mut buf).await.unwrap();
    assert_eq!(&buf[..6], b"world!");
}

/// Read exactly one datagram from `reader`, while keeping `listener` polled.
///
/// The UDP server stream is what dispatches incoming datagrams to the streams it already handed
/// out (it peeks the sender, then notifies that peer), so a read that is not raced with a poll of
/// the listener would block forever on the second datagram. In production the listener is polled
/// by its own accept loop; a test that holds a single stream has to drive it by hand.
async fn read_one_datagram(
    listener: &mut (impl Stream<Item = std::io::Result<protocols::udp::UdpStream>> + Unpin),
    reader: &mut (impl AsyncReadExt + Unpin),
    buf: &mut BytesMut,
) {
    // Reserved up front: `read_buf` only grows a `BytesMut` by a small increment, and a UDP recv
    // truncates whatever does not fit, which would read as a boundary bug rather than a short buffer.
    buf.reserve(64 * 1024);
    tokio::select! {
        biased;
        res = reader.read_buf(buf) => { res.unwrap(); }
        next = listener.next() => panic!("unexpected second UDP connection: {:?}", next.map(|r| r.map(|_| ()))),
    }
}

#[rstest]
#[timeout(Duration::from_secs(15))]
#[tokio::test]
#[serial]
async fn test_udp_tunnel_webtransport(
    server_webtransport: Server,
    no_restrictions: RestrictionsRules,
    dns_resolver: DnsResolver,
) {
    let (tunnel_listen, tunnel_host) = free_addr();
    let (endpoint_listen, endpoint_host) = free_addr();

    let server_port = server_webtransport.config.bind.port();
    let server_h = tokio::spawn(server_webtransport.serve(no_restrictions));
    defer! { server_h.abort(); };

    let client = client_webtransport(server_port, dns_resolver.clone()).await;

    let server = UdpDownstreamListener::new(tunnel_listen, (endpoint_host, endpoint_listen.port()), None)
        .await
        .unwrap();
    tokio::spawn(async move {
        client.run_tunnel(server).await.unwrap();
    });

    let udp_listener = protocols::udp::run_server(endpoint_listen, None, |_| Ok(()), |s| Ok(s.clone()))
        .await
        .unwrap();
    let mut client = protocols::udp::connect(
        &tunnel_host,
        tunnel_listen.port(),
        Duration::from_secs(10),
        SoMark::new(None),
        &dns_resolver,
    )
    .await
    .unwrap();

    client.write_all(b"Hello").await.unwrap();
    client.write_all(b"John").await.unwrap();
    client.flush().await.unwrap();
    pin!(udp_listener);
    let dd = udp_listener.next().await.unwrap().unwrap();
    pin!(dd);
    let mut buf = BytesMut::new();
    // Compared on the whole buffer, not a prefix: the two datagrams were sent back to back, so a
    // transport that lost their boundaries would hand over "HelloJohn" in one read, and a prefix
    // comparison would accept it here and only hang on the read that follows.
    read_one_datagram(&mut udp_listener, &mut dd, &mut buf).await;
    assert_eq!(&buf[..], b"Hello");
    buf.clear();
    read_one_datagram(&mut udp_listener, &mut dd, &mut buf).await;
    assert_eq!(&buf[..], b"John");
    buf.clear();

    dd.writer().write_all(b"world!").await.unwrap();
    client.read_buf(&mut buf).await.unwrap();
    assert_eq!(&buf[..], b"world!");
}

/// Perform a SOCKS5 no-auth greeting + CONNECT to `dst`, and return the reply code byte (0x00 =
/// success, non-zero = failure per RFC 1928). Drains the full reply, including the bound address.
async fn socks5_handshake_connect(
    stream: &mut (impl AsyncReadExt + AsyncWriteExt + Unpin),
    dst_ip: Ipv4Addr,
    dst_port: u16,
) -> u8 {
    // Greeting: version 5, one method offered: no-auth (0x00).
    stream.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut method = [0u8; 2];
    stream.read_exact(&mut method).await.unwrap();
    assert_eq!(method, [0x05, 0x00], "server must select no-auth");

    // CONNECT (0x01) to an IPv4 destination.
    let mut req = vec![0x05, 0x01, 0x00, 0x01];
    req.extend_from_slice(&dst_ip.octets());
    req.extend_from_slice(&dst_port.to_be_bytes());
    stream.write_all(&req).await.unwrap();

    // Reply: VER REP RSV ATYP BND.ADDR BND.PORT.
    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await.unwrap();
    assert_eq!(head[0], 0x05, "reply must be SOCKS5");
    let addr_len = match head[3] {
        0x01 => 4,
        0x04 => 16,
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await.unwrap();
            len[0] as usize
        }
        other => panic!("unexpected ATYP in reply: {other}"),
    };
    let mut rest = vec![0u8; addr_len + 2];
    stream.read_exact(&mut rest).await.unwrap();
    head[1]
}

#[rstest]
#[timeout(Duration::from_secs(10))]
#[tokio::test]
#[serial]
async fn test_socks5_tunnel(server_no_tls: Server, no_restrictions: RestrictionsRules, dns_resolver: DnsResolver) {
    let (tunnel_listen, tunnel_host) = free_addr();
    let (endpoint_listen, _endpoint_host) = free_addr();

    let server_port = server_no_tls.config.bind.port();
    let server_h = tokio::spawn(server_no_tls.serve(no_restrictions));
    defer! { server_h.abort(); };

    let client_ws = client_ws(server_port, dns_resolver.clone()).await;

    let server = Socks5DownstreamListener::new(tunnel_listen, None, None).await.unwrap();
    tokio::spawn(async move {
        client_ws.run_tunnel(server).await.unwrap();
    });

    // Reachable endpoint: the tunward server must connect to it before the SOCKS5 reply is sent.
    let mut tcp_listener = protocols::tcp::run_server(endpoint_listen, false).await.unwrap();
    let mut client = protocols::tcp::connect(
        &tunnel_host,
        tunnel_listen.port(),
        SoMark::new(None),
        Duration::from_secs(10),
        &dns_resolver,
    )
    .await
    .unwrap();

    let rep = socks5_handshake_connect(&mut client, Ipv4Addr::LOCALHOST, endpoint_listen.port()).await;
    assert_eq!(rep, 0x00, "reply must be success once the tunnel is established");

    client.write_all(b"Hello").await.unwrap();
    let mut dd = tcp_listener.next().await.unwrap().unwrap();
    let mut buf = BytesMut::new();
    dd.read_buf(&mut buf).await.unwrap();
    assert_eq!(&buf[..5], b"Hello");
    buf.clear();

    dd.write_all(b"world!").await.unwrap();
    client.read_buf(&mut buf).await.unwrap();
    assert_eq!(&buf[..6], b"world!");
}

#[rstest]
#[timeout(Duration::from_secs(10))]
#[tokio::test]
#[serial]
async fn test_socks5_tunnel_unreachable_target_replies_error(
    server_no_tls: Server,
    no_restrictions: RestrictionsRules,
    dns_resolver: DnsResolver,
) {
    let (tunnel_listen, tunnel_host) = free_addr();
    // A reserved-but-unbound port: the tunward server's connect to it is refused.
    let (dead_endpoint, _) = free_addr();

    let server_port = server_no_tls.config.bind.port();
    let server_h = tokio::spawn(server_no_tls.serve(no_restrictions));
    defer! { server_h.abort(); };

    let client_ws = client_ws(server_port, dns_resolver.clone()).await;

    let server = Socks5DownstreamListener::new(tunnel_listen, None, None).await.unwrap();
    tokio::spawn(async move {
        client_ws.run_tunnel(server).await.unwrap();
    });

    let mut client = protocols::tcp::connect(
        &tunnel_host,
        tunnel_listen.port(),
        SoMark::new(None),
        Duration::from_secs(10),
        &dns_resolver,
    )
    .await
    .unwrap();

    // The target is unreachable, so the reply must report failure (not a premature success).
    let rep = socks5_handshake_connect(&mut client, Ipv4Addr::LOCALHOST, dead_endpoint.port()).await;
    assert_ne!(rep, 0x00, "reply must report failure when the target is unreachable");
    assert_eq!(rep, 0x01, "expected GeneralFailure reply code");
}

#[rstest]
#[timeout(Duration::from_secs(10))]
#[tokio::test]
#[serial]
async fn test_fleet_management_and_ephemeral_reverse_tunnel(
    no_restrictions: RestrictionsRules,
    dns_resolver: DnsResolver,
) {
    let mgmt_addr = free_addr().0;
    let server_bind = free_addr().0;
    let server_config = ServerConfig {
        socket_so_mark: SoMark::new(None),
        bind: server_bind,
        websocket_ping_frequency: Some(Duration::from_secs(10)),
        timeout_connect: Duration::from_secs(10),
        websocket_mask_frame: false,
        tls: None,
        dns_resolver: dns_resolver.clone(),
        restriction_config: None,
        http_proxy: None,
        remote_server_idle_timeout: Duration::from_secs(30),
        enable_webtransport: false,
        management_api: Some(mgmt_addr),
        device_quotas: None,
        device_revocation_config: None,
        fleet_inventory: None,
        tenant_config: None,
        fleet_inventory_max_devices: std::num::NonZeroU32::new(10000).unwrap(),
        tls_client_identity_field: ClientIdentityField::default(),
        tls_handshake_timeout: Duration::from_secs(10),
        max_pending_tls_handshakes: std::num::NonZeroU32::new(1024).unwrap(),
    };
    let server = Server::new(server_config, DefaultTokioExecutor::default());
    let server_port = server.config.bind.port();
    let server_h = tokio::spawn(server.serve(no_restrictions));
    defer! { server_h.abort(); };

    // Wait for management API to be reachable
    let mut ready = false;
    for _ in 0..20 {
        if let Ok(mut stream) = TcpStream::connect(mgmt_addr).await {
            let _ = stream
                .write_all(b"GET /healthz HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
                .await;
            let mut resp = String::new();
            if stream.read_to_string(&mut resp).await.is_ok() && resp.contains("200 OK") {
                ready = true;
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(ready, "Management API /healthz failed to respond");

    // Start mock upstream echo service
    let echo_addr = free_addr().0;
    let echo_listener = TcpListener::bind(echo_addr).await.unwrap();
    let echo_h = tokio::spawn(async move {
        while let Ok((mut socket, _)) = echo_listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                while let Ok(n) = socket.read(&mut buf).await {
                    if n == 0 {
                        break;
                    }
                    let _ = socket.write_all(&buf[..n]).await;
                }
            });
        }
    });
    defer! { echo_h.abort(); };

    // Start client with client_id
    let client_config = ClientConfig {
        remote_addr: TransportAddr::new(TransportScheme::Ws, Host::Ipv4(Ipv4Addr::LOCALHOST), server_port, None)
            .unwrap(),
        socket_so_mark: SoMark::new(None),
        http_upgrade_path_prefix: "tunward".to_string(),
        http_upgrade_credentials: None,
        http_headers: HashMap::new(),
        http_headers_file: None,
        http_header_host: HeaderValue::from_str(&format!("127.0.0.1:{server_port}")).unwrap(),
        timeout_connect: Duration::from_secs(10),
        websocket_ping_frequency: Some(Duration::from_secs(10)),
        websocket_mask_frame: false,
        dns_resolver: dns_resolver.clone(),
        http_proxy: None,
        webtransport: None,
        client_id: Some("kiosk-padang-01".to_string()),
    };
    let client = Client::new(
        client_config,
        1,
        Duration::from_secs(1),
        Duration::from_secs(1),
        DefaultTokioExecutor::default(),
    )
    .await
    .unwrap();

    let connector = TcpUpstreamConnector::new(
        Host::Ipv4(Ipv4Addr::LOCALHOST),
        echo_addr.port(),
        SoMark::new(None),
        Duration::from_secs(1),
        dns_resolver,
    );
    let client_h = tokio::spawn(client.run_reverse_tunnel(
        RemoteAddr {
            protocol: LocalProtocol::ReverseTcp,
            host: Host::Ipv4(Ipv4Addr::LOCALHOST),
            port: 0,
        },
        connector,
    ));
    defer! { client_h.abort(); };

    // Verify client appears in /api/v1/clients
    let mut client_found = false;
    for _ in 0..40 {
        if let Ok(mut stream) = TcpStream::connect(mgmt_addr).await {
            let _ = stream
                .write_all(b"GET /api/v1/clients HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
                .await;
            let mut resp = String::new();
            if stream.read_to_string(&mut resp).await.is_ok() && resp.contains("kiosk-padang-01") {
                client_found = true;
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(client_found, "Client kiosk-padang-01 must appear in /api/v1/clients");

    // Verify GET /api/v1/clients/kiosk-padang-01
    let mut stream = TcpStream::connect(mgmt_addr).await.unwrap();
    stream
        .write_all(b"GET /api/v1/clients/kiosk-padang-01 HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut resp = String::new();
    stream.read_to_string(&mut resp).await.unwrap();
    assert!(resp.contains("200 OK"));
    assert!(resp.contains("kiosk-padang-01"));

    // Verify GET /healthz reflects active client count
    let mut stream = TcpStream::connect(mgmt_addr).await.unwrap();
    stream
        .write_all(b"GET /healthz HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut resp = String::new();
    stream.read_to_string(&mut resp).await.unwrap();
    assert!(resp.contains("\"active_clients\":1"));
}

/// Wss client with no idle pooled connection, so every tunnel opens and authenticates its own.
async fn client_wss(server_port: u16, dns_resolver: DnsResolver) -> Client {
    // The embedded certificate is self-signed with no SAN, so verification must be off.
    let tls_connector =
        crate::protocols::tls::tls_connector(false, TransportScheme::Wss.alpn_protocols(), true, None, None, None)
            .unwrap();
    let tls = TlsClientConfig {
        tls_sni_disabled: false,
        tls_sni_override: None,
        tls_verify_certificate: false,
        tls_connector: Arc::new(parking_lot::RwLock::new(tls_connector)),
        tls_certificate_path: None,
        tls_key_path: None,
    };
    let client = client_ws(server_port, dns_resolver).await;
    let mut config = (*client.config).clone();
    drop(client);
    config.remote_addr =
        TransportAddr::new(TransportScheme::Wss, Host::Ipv4(Ipv4Addr::LOCALHOST), server_port, Some(tls)).unwrap();
    Client::new(
        config,
        0,
        Duration::from_secs(5),
        Duration::from_secs(1),
        DefaultTokioExecutor::default(),
    )
    .await
    .unwrap()
}

/// One allow rule per port: `cidr` constrains every destination on `port`.
fn cidr_by_port(rules: &[(u16, &str)]) -> RestrictionsRules {
    RestrictionsRules {
        restrictions: vec![RestrictionConfig {
            name: "cidr-by-port".into(),
            r#match: vec![MatchConfig::Any],
            allow: rules
                .iter()
                .map(|(port, cidr)| {
                    AllowConfig::Tunnel(types::AllowTunnelConfig {
                        protocol: vec![],
                        port: std::iter::once(*port..=*port).collect(),
                        host: types::default_host(),
                        cidr: vec![cidr.parse().unwrap()],
                    })
                })
                .collect(),
        }],
    }
}

/// Open a TCP tunnel to `destination` and report whether it reached `endpoint`, carrying data both
/// ways. A rejected tunnel must close the local connection without the endpoint seeing a connection.
async fn tcp_tunnel_reaches(client: &Client, destination: (Host, u16), endpoint: &TcpListener) -> bool {
    let (tunnel_listen, _) = free_addr();
    let listener = TcpDownstreamListener::new(tunnel_listen, destination, false)
        .await
        .unwrap();
    let tunnel_client = client.clone();
    let tunnel_h = tokio::spawn(async move {
        let _ = tunnel_client.run_tunnel(listener).await;
    });
    defer! { tunnel_h.abort(); };

    let mut local = TcpStream::connect(tunnel_listen).await.unwrap();
    local.write_all(b"ping").await.unwrap();
    let mut probe = [0; 4];
    let reached = tokio::time::timeout(Duration::from_secs(10), async {
        tokio::select! {
            accepted = endpoint.accept() => {
                let (mut accepted, _) = accepted.unwrap();
                accepted.read_exact(&mut probe).await.unwrap();
                assert_eq!(&probe, b"ping");
                accepted.write_all(b"pong").await.unwrap();
                local.read_exact(&mut probe).await.unwrap();
                assert_eq!(&probe, b"pong");
                true
            }
            read = local.read(&mut probe) => {
                assert_eq!(read.unwrap_or(0), 0, "a rejected tunnel must not deliver data");
                false
            }
        }
    })
    .await
    .expect("the tunnel neither reached the endpoint nor was closed");
    if !reached {
        assert!(
            tokio::time::timeout(Duration::from_millis(300), endpoint.accept())
                .await
                .is_err(),
            "a rejected tunnel reached the endpoint late"
        );
    }
    reached
}

/// UDP counterpart of [`tcp_tunnel_reaches`]: a rejected tunnel delivers no datagram.
async fn udp_tunnel_reaches(client: &Client, destination: (Host, u16), endpoint: &tokio::net::UdpSocket) -> bool {
    let (tunnel_listen, _) = free_addr();
    let listener = UdpDownstreamListener::new(tunnel_listen, destination, None)
        .await
        .unwrap();
    let tunnel_client = client.clone();
    let tunnel_h = tokio::spawn(async move {
        let _ = tunnel_client.run_tunnel(listener).await;
    });
    defer! { tunnel_h.abort(); };

    let local = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    local.connect(tunnel_listen).await.unwrap();
    local.send(b"ping").await.unwrap();
    let mut buf = [0; 16];
    match tokio::time::timeout(Duration::from_secs(2), endpoint.recv_from(&mut buf)).await {
        Ok(Ok((len, peer))) => {
            assert_eq!(&buf[..len], b"ping");
            endpoint.send_to(b"pong", peer).await.unwrap();
            let len = tokio::time::timeout(Duration::from_secs(5), local.recv(&mut buf))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(&buf[..len], b"pong");
            true
        }
        _ => false,
    }
}

#[rstest]
#[case::websocket(TransportScheme::Ws)]
#[case::http2(TransportScheme::Http)]
#[case::webtransport(TransportScheme::Wts)]
#[timeout(Duration::from_secs(60))]
#[tokio::test]
#[serial]
async fn test_domain_destination_is_confined_to_restriction_cidr(
    server_no_tls: Server,
    server_webtransport: Server,
    dns_resolver: DnsResolver,
    #[case] scheme: TransportScheme,
) {
    // Endpoints listen on IPv4 loopback only. `localhost` also resolves to ::1, so the allowed case
    // proves the tunnel dials the address its rule admitted.
    let allowed_tcp = TcpListener::bind(free_addr().0).await.unwrap();
    let decoy_tcp = TcpListener::bind(free_addr().0).await.unwrap();
    let allowed_udp = tokio::net::UdpSocket::bind(free_addr().0).await.unwrap();
    let decoy_udp = tokio::net::UdpSocket::bind(free_addr().0).await.unwrap();
    let mapped_decoy = TcpListener::bind(free_addr().0).await.unwrap();
    let [
        allowed_tcp_port,
        decoy_tcp_port,
        allowed_udp_port,
        decoy_udp_port,
        mapped_decoy_port,
    ] = [
        allowed_tcp.local_addr().unwrap().port(),
        decoy_tcp.local_addr().unwrap().port(),
        allowed_udp.local_addr().unwrap().port(),
        decoy_udp.local_addr().unwrap().port(),
        mapped_decoy.local_addr().unwrap().port(),
    ];
    let restrictions = cidr_by_port(&[
        (allowed_tcp_port, "127.0.0.1/32"),
        (allowed_udp_port, "127.0.0.1/32"),
        (decoy_tcp_port, "10.0.0.0/8"),
        (decoy_udp_port, "10.0.0.0/8"),
        (mapped_decoy_port, "::/0"),
    ]);

    let server = match scheme {
        TransportScheme::Wts => server_webtransport,
        _ => server_no_tls,
    };
    let port = server.config.bind.port();
    let server_h = tokio::spawn(server.serve(restrictions));
    defer! { server_h.abort(); };
    let client = match scheme {
        TransportScheme::Wts => client_webtransport(port, dns_resolver.clone()).await,
        _ => {
            let client = client_ws(port, dns_resolver.clone()).await;
            let mut config = (*client.config).clone();
            drop(client);
            config.remote_addr = TransportAddr::new(scheme, Host::Ipv4(Ipv4Addr::LOCALHOST), port, None).unwrap();
            Client::new(
                config,
                1,
                Duration::from_secs(5),
                Duration::from_secs(1),
                DefaultTokioExecutor::default(),
            )
            .await
            .unwrap()
        }
    };

    let localhost = |port| (Host::Domain("localhost".to_string()), port);
    assert!(
        tcp_tunnel_reaches(&client, localhost(allowed_tcp_port), &allowed_tcp).await,
        "{scheme:?}: a domain resolving inside the CIDR must be allowed"
    );
    assert!(
        !tcp_tunnel_reaches(&client, localhost(decoy_tcp_port), &decoy_tcp).await,
        "{scheme:?}: a domain resolving outside the CIDR must not bypass it"
    );
    assert!(
        !tcp_tunnel_reaches(&client, (Host::Ipv4(Ipv4Addr::LOCALHOST), decoy_tcp_port), &decoy_tcp).await,
        "{scheme:?}: an address outside the CIDR stays denied"
    );
    assert!(
        !tcp_tunnel_reaches(
            &client,
            (Host::Ipv6(Ipv4Addr::LOCALHOST.to_ipv6_mapped()), mapped_decoy_port),
            &mapped_decoy
        )
        .await,
        "{scheme:?}: an IPv4-mapped address must follow IPv4 rules, not ::/0"
    );
    assert!(
        udp_tunnel_reaches(&client, localhost(allowed_udp_port), &allowed_udp).await,
        "{scheme:?}: UDP to a domain resolving inside the CIDR must be allowed"
    );
    assert!(
        !udp_tunnel_reaches(&client, localhost(decoy_udp_port), &decoy_udp).await,
        "{scheme:?}: UDP to a domain resolving outside the CIDR must not bypass it"
    );
}

/// Minimal loopback DNS responder. The n-th A query is answered with `answers[n]` (the last one
/// repeats) and a zero TTL; other query types get an empty NOERROR answer.
async fn rebinding_dns(answers: Vec<Ipv4Addr>) -> (u16, Arc<AtomicUsize>, tokio::task::JoinHandle<()>) {
    let socket = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let port = socket.local_addr().unwrap().port();
    let a_queries = Arc::new(AtomicUsize::new(0));
    let counter = a_queries.clone();
    let task = tokio::spawn(async move {
        let mut buf = [0u8; 512];
        while let Ok((len, peer)) = socket.recv_from(&mut buf).await {
            let query = &buf[..len];
            // Skip the QNAME labels to the QTYPE and QCLASS of the single question.
            let mut end = 12;
            while end < len && query[end] != 0 {
                end += 1 + query[end] as usize;
            }
            if end + 5 > len {
                continue;
            }
            let qtype = u16::from_be_bytes([query[end + 1], query[end + 2]]);
            let answer = (qtype == 1).then(|| answers[counter.fetch_add(1, Ordering::SeqCst).min(answers.len() - 1)]);
            let mut response = Vec::with_capacity(64);
            response.extend_from_slice(&query[..2]);
            response.extend_from_slice(&[0x81, 0x80, 0, 1, 0, u8::from(answer.is_some()), 0, 0, 0, 0]);
            response.extend_from_slice(&query[12..end + 5]);
            if let Some(ip) = answer {
                // Name pointer to the question, type A, class IN, TTL 0, four bytes of address.
                response.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 0, 0, 4]);
                response.extend_from_slice(&ip.octets());
            }
            let _ = socket.send_to(&response, peer).await;
        }
    });
    (port, a_queries, task)
}

/// A domain admitted by its CIDR is dialed at the address that was checked. Resolving it again for
/// the connection would let a DNS answer that changed in between (rebinding) reach another address.
#[cfg(target_os = "linux")]
#[rstest]
#[timeout(Duration::from_secs(30))]
#[tokio::test]
#[serial]
async fn test_domain_destination_is_pinned_against_dns_rebinding(dns_resolver: DnsResolver) {
    let allowed = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let port = allowed.local_addr().unwrap().port();
    // Linux routes all of 127.0.0.0/8 to loopback, so this second address is reachable too.
    let forbidden = TcpListener::bind((Ipv4Addr::new(127, 0, 0, 2), port)).await.unwrap();

    let (dns_port, a_queries, dns_h) = rebinding_dns(vec![Ipv4Addr::LOCALHOST, Ipv4Addr::new(127, 0, 0, 2)]).await;
    defer! { dns_h.abort(); };
    let server_resolver = DnsResolver::new_from_urls(
        &[url::Url::parse(&format!("dns://127.0.0.1:{dns_port}")).unwrap()],
        None,
        SoMark::new(None),
        false,
    )
    .unwrap();
    let server = Server::new(server_config(server_resolver.clone()), DefaultTokioExecutor::default());
    let server_port = server.config.bind.port();
    let server_h = tokio::spawn(server.serve(cidr_by_port(&[(port, "127.0.0.1/32")])));
    defer! { server_h.abort(); };
    let client = client_ws(server_port, dns_resolver).await;

    let rebinding = (Host::Domain("rebind.tunward.test".to_string()), port);
    assert!(tcp_tunnel_reaches(&client, rebinding.clone(), &allowed).await);
    assert_eq!(
        a_queries.load(Ordering::SeqCst),
        1,
        "the connection must reuse the checked answer instead of resolving again"
    );

    // Self-check that the resolver does not cache this zero-TTL answer: had the server resolved
    // again, it would have been handed the forbidden address.
    let next = server_resolver.lookup_host("rebind.tunward.test", port).await.unwrap();
    assert_eq!(next, vec![SocketAddr::from((Ipv4Addr::new(127, 0, 0, 2), port))]);

    // Once the name only resolves outside the CIDR, the tunnel is rejected.
    assert!(!tcp_tunnel_reaches(&client, rebinding, &forbidden).await);
    assert!(
        tokio::time::timeout(Duration::from_millis(300), forbidden.accept())
            .await
            .is_err(),
        "the forbidden address must never be dialed"
    );
}

#[rstest]
#[timeout(Duration::from_secs(30))]
#[tokio::test]
#[serial]
async fn test_pending_tls_handshakes_are_bounded_without_affecting_sessions(
    no_restrictions: RestrictionsRules,
    dns_resolver: DnsResolver,
) {
    const HANDSHAKE_TIMEOUT: Duration = Duration::from_millis(1500);
    let server = Server::new(
        ServerConfig {
            tls: Some(embedded_tls()),
            tls_handshake_timeout: HANDSHAKE_TIMEOUT,
            max_pending_tls_handshakes: std::num::NonZeroU32::new(2).unwrap(),
            ..server_config(dns_resolver.clone())
        },
        DefaultTokioExecutor::default(),
    );
    let server_addr = server.config.bind;
    let server_h = tokio::spawn(server.serve(no_restrictions));
    defer! { server_h.abort(); };
    let client = client_wss(server_addr.port(), dns_resolver).await;

    let endpoint = TcpListener::bind(free_addr().0).await.unwrap();
    let endpoint_port = endpoint.local_addr().unwrap().port();
    let destination = (Host::Ipv4(Ipv4Addr::LOCALHOST), endpoint_port);

    // An authenticated session established before the flood.
    let (tunnel_listen, _) = free_addr();
    let listener = TcpDownstreamListener::new(tunnel_listen, destination.clone(), false)
        .await
        .unwrap();
    let tunnel_client = client.clone();
    let tunnel_h = tokio::spawn(async move {
        let _ = tunnel_client.run_tunnel(listener).await;
    });
    defer! { tunnel_h.abort(); };
    let mut session = TcpStream::connect(tunnel_listen).await.unwrap();
    session.write_all(b"before").await.unwrap();
    let (mut session_endpoint, _) = endpoint.accept().await.unwrap();
    let mut buf = [0; 6];
    session_endpoint.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"before");

    // Peers that connect but never send a ClientHello fill every handshake slot...
    let mut idle = Vec::new();
    for _ in 0..2 {
        idle.push(TcpStream::connect(server_addr).await.unwrap());
    }
    tokio::time::sleep(Duration::from_millis(200)).await;

    // ...so the next connection is closed as soon as it is accepted, instead of holding a descriptor.
    let started = tokio::time::Instant::now();
    let mut shed = TcpStream::connect(server_addr).await.unwrap();
    let mut probe = [0; 1];
    let read = tokio::time::timeout(Duration::from_secs(1), shed.read(&mut probe))
        .await
        .expect("an excess handshake must be closed right away");
    assert_eq!(read.unwrap_or(0), 0);
    assert!(started.elapsed() < HANDSHAKE_TIMEOUT, "closed by the limit, not the timeout");

    // The established session keeps forwarding during the flood.
    session_endpoint.write_all(b"during").await.unwrap();
    session.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"during");

    // Pending handshakes are closed once the timeout elapses, which frees their slots.
    for mut stream in idle {
        let read = tokio::time::timeout(HANDSHAKE_TIMEOUT * 3, stream.read(&mut probe))
            .await
            .expect("an idle handshake must be closed by --tls-handshake-timeout");
        assert_eq!(read.unwrap_or(0), 0);
    }
    assert!(started.elapsed() >= HANDSHAKE_TIMEOUT - Duration::from_millis(400));

    // New authenticated sessions are accepted again.
    let fresh = TcpListener::bind(free_addr().0).await.unwrap();
    let fresh_port = fresh.local_addr().unwrap().port();
    assert!(tcp_tunnel_reaches(&client, (Host::Ipv4(Ipv4Addr::LOCALHOST), fresh_port), &fresh).await);
}

/// A QUIC connection that completes its handshake, then never sends the HTTP/3 request that would
/// open a WebTransport session.
async fn quic_without_connect(server: SocketAddr) -> Result<quinn::Connection, quinn::ConnectionError> {
    // The embedded certificate is self-signed with no SAN, so verification must be off.
    let tls = crate::protocols::tls::quic_client_config(false, None, None).unwrap();
    let quic_tls = quinn::crypto::rustls::QuicClientConfig::try_from(tls).unwrap();
    let mut endpoint = quinn::Endpoint::client(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
    endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(quic_tls)));
    endpoint.connect(server, "localhost").unwrap().await
}

#[rstest]
#[timeout(Duration::from_secs(30))]
#[tokio::test]
#[serial]
async fn test_webtransport_handshakes_are_bounded_without_affecting_sessions(
    no_restrictions: RestrictionsRules,
    dns_resolver: DnsResolver,
) {
    const HANDSHAKE_TIMEOUT: Duration = Duration::from_millis(1500);
    let server = Server::new(
        ServerConfig {
            tls: Some(embedded_tls()),
            enable_webtransport: true,
            // No pings means no QUIC idle timeout either, so only the handshake bounds can apply.
            websocket_ping_frequency: None,
            tls_handshake_timeout: HANDSHAKE_TIMEOUT,
            max_pending_tls_handshakes: std::num::NonZeroU32::new(2).unwrap(),
            ..server_config(dns_resolver.clone())
        },
        DefaultTokioExecutor::default(),
    );
    let server_addr = server.config.bind;
    let server_h = tokio::spawn(server.serve(no_restrictions));
    defer! { server_h.abort(); };

    let reachable = |listener: &TcpListener| (Host::Ipv4(Ipv4Addr::LOCALHOST), listener.local_addr().unwrap().port());
    let endpoint = TcpListener::bind(free_addr().0).await.unwrap();
    let client = client_webtransport(server_addr.port(), dns_resolver.clone()).await;
    assert!(tcp_tunnel_reaches(&client, reachable(&endpoint), &endpoint).await);

    // Peers that complete QUIC but never send their CONNECT fill every handshake slot...
    let mut idle = Vec::new();
    for _ in 0..2 {
        idle.push(
            quic_without_connect(server_addr)
                .await
                .expect("the QUIC handshake itself must succeed"),
        );
    }
    tokio::time::sleep(Duration::from_millis(200)).await;

    // ...so the next connection is refused instead of being kept pending.
    let started = tokio::time::Instant::now();
    assert!(
        quic_without_connect(server_addr).await.is_err(),
        "a connection beyond --max-pending-tls-handshakes must be refused"
    );
    assert!(started.elapsed() < HANDSHAKE_TIMEOUT, "refused by the limit, not the timeout");

    // The established session keeps opening tunnels during the flood.
    let during = TcpListener::bind(free_addr().0).await.unwrap();
    assert!(tcp_tunnel_reaches(&client, reachable(&during), &during).await);

    // Pending connections are closed once the timeout elapses, even without a QUIC idle timeout.
    for connection in idle {
        tokio::time::timeout(HANDSHAKE_TIMEOUT * 3, connection.closed())
            .await
            .expect("a connection without CONNECT must be closed by --tls-handshake-timeout");
    }
    assert!(started.elapsed() >= HANDSHAKE_TIMEOUT - Duration::from_millis(400));

    // New sessions are accepted again.
    let fresh_client = client_webtransport(server_addr.port(), dns_resolver).await;
    let fresh = TcpListener::bind(free_addr().0).await.unwrap();
    assert!(tcp_tunnel_reaches(&fresh_client, reachable(&fresh), &fresh).await);
}
