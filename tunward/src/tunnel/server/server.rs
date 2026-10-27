use crate::config::ClientIdentityField;
use crate::executor::DefaultTokioExecutor;
use crate::management::registry::{ConnectionLease, TunnelLease};
use crate::protocols;
use crate::protocols::dns::DnsResolver;
use crate::protocols::tls;
use crate::quotas::{DeviceQuotaConfig, QuotaError, QuotaManager, QuotaSession, TunnelPermit};
use crate::reload::{ReloadState, ServerReload};
use crate::restrictions::config_reloader::RestrictionsRulesReloader;
use crate::restrictions::types::{RestrictionConfig, RestrictionsRules};
use crate::revocation::{RevocationGuard, RevocationManager};
use crate::somark::SoMark;
use crate::tenants::{TenantAccess, TenantPolicy};
use crate::tunnel::downstream_listeners::{
    HttpProxyDownstreamListener, Socks5DownstreamListener, TcpDownstreamListener, UdpDownstreamListener,
};
use crate::tunnel::server::handler_http2::http_server_upgrade;
use crate::tunnel::server::handler_websocket::ws_server_upgrade;
use crate::tunnel::server::handler_webtransport;
use crate::tunnel::server::reverse_tunnel::{ListenerOwner, ReverseTunnelServer};
use crate::tunnel::server::utils::{
    HttpResponse, bad_request, extract_authorization, extract_path_prefix, extract_tunnel_info,
    extract_x_forwarded_for, find_mapped_port, quota_rejection, validate_tunnel, validate_tunnel_with_scope,
};
use crate::tunnel::tls_reloader::TlsReloader;
use crate::tunnel::upstream_connectors::{TcpUpstreamConnector, UdpUpstreamConnector, UpstreamConnector};
use crate::tunnel::{LocalProtocol, RemoteAddr, try_to_sock_addr};
use ahash::AHasher;
use anyhow::{Context, anyhow};
use arc_swap::ArcSwap;
use futures_util::FutureExt;
use http_body_util::Either;
use hyper::body::Incoming;
use hyper::server::conn::{http1, http2};
use hyper::service::service_fn;
use hyper::{Request, StatusCode, Version, http};
use hyper_util::rt::{TokioExecutor, TokioTimer};
use parking_lot::Mutex;
use socket2::SockRef;
use std::fmt;
use std::fmt::{Debug, Formatter};
use std::hash::{Hash, Hasher};
use std::net::{Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::{Arc, LazyLock};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tracing::{Instrument, Level, Span, error, info, span, warn};
use url::{Host, Url};

#[derive(Debug)]
pub struct TlsServerConfig {
    pub tls_certificate: Mutex<Vec<CertificateDer<'static>>>,
    pub tls_key: Mutex<PrivateKeyDer<'static>>,
    pub tls_client_ca_certificates: Option<Mutex<Vec<CertificateDer<'static>>>>,
    pub tls_certificate_path: Option<PathBuf>,
    pub tls_key_path: Option<PathBuf>,
    pub tls_client_ca_certs_path: Option<PathBuf>,
}

pub struct ServerConfig {
    pub socket_so_mark: SoMark,
    pub bind: SocketAddr,
    pub websocket_ping_frequency: Option<Duration>,
    pub timeout_connect: Duration,
    pub websocket_mask_frame: bool,
    pub tls: Option<TlsServerConfig>,
    pub dns_resolver: DnsResolver,
    pub restriction_config: Option<PathBuf>,
    pub http_proxy: Option<Url>,
    pub remote_server_idle_timeout: Duration,
    /// Additionally serve WebTransport over UDP on the same port as the TCP listener.
    /// Requires TLS, since QUIC mandates TLS 1.3.
    pub enable_webtransport: bool,
    /// [Optional] Enable local REST management API on the specified socket address.
    pub management_api: Option<SocketAddr>,
    pub device_quotas: Option<DeviceQuotaConfig>,
    pub device_revocation_config: Option<PathBuf>,
    pub fleet_inventory: Option<PathBuf>,
    pub fleet_inventory_max_devices: std::num::NonZeroU32,
    pub tenant_config: Option<PathBuf>,
    pub tls_client_identity_field: ClientIdentityField,
}

#[derive(Clone, Default)]
pub(super) struct ConnectionContext {
    pub path: Option<String>,
    pub quota: Option<QuotaSession>,
    pub revocation: RevocationGuard,
    pub fleet: Option<ConnectionLease>,
    pub tenant: Option<TenantAccess>,
}

impl ConnectionContext {
    pub fn admit_tunnel(&self) -> Result<Option<TunnelPermit>, QuotaError> {
        self.quota
            .as_ref()
            .map(|quota| {
                quota.check_request()?;
                quota.open_tunnel()
            })
            .transpose()
    }
}

pub(super) struct EstablishedTunnel {
    pub remote_addr: RemoteAddr,
    pub local_rx: Pin<Box<dyn AsyncRead + Send>>,
    pub local_tx: Pin<Box<dyn AsyncWrite + Send>>,
    pub need_cookie: bool,
    pub quota: Option<TunnelPermit>,
    pub fleet: Option<TunnelLease>,
}

#[derive(Clone)]
pub struct Server<E: crate::TokioExecutorRef = DefaultTokioExecutor> {
    pub config: Arc<ServerConfig>,
    pub fleet_registry: Option<crate::management::FleetRegistry>,
    pub executor: E,
    quotas: Option<QuotaManager>,
    revocations: Option<RevocationManager>,
    tenants: Option<Arc<TenantPolicy>>,
    pub(crate) managed: Option<Arc<ReloadState>>,
    reload: Option<ServerReload>,
    instance: uuid::Uuid,
}

impl<E: crate::TokioExecutorRef> Server<E> {
    pub fn new(config: ServerConfig, executor: E) -> Self {
        let fleet_registry = (config.management_api.is_some() || config.fleet_inventory.is_some())
            .then(crate::management::FleetRegistry::new);
        let quotas = config.device_quotas.clone().map(QuotaManager::new);
        Self {
            config: Arc::new(config),
            fleet_registry,
            executor,
            quotas,
            revocations: None,
            tenants: None,
            managed: None,
            reload: None,
            instance: uuid::Uuid::now_v7(),
        }
    }

    pub(crate) fn with_reload(mut self, state: Arc<ReloadState>, reload: ServerReload) -> Self {
        self.quotas = self
            .config
            .device_quotas
            .as_ref()
            .map(|_| QuotaManager::live(state.live.clone()));
        self.managed = Some(state);
        self.reload = Some(reload);
        self
    }

    pub(super) async fn connection_context(
        &self,
        path: Option<String>,
        certificates: Option<&[CertificateDer<'_>]>,
        peer_addr: SocketAddr,
        transport: &str,
    ) -> anyhow::Result<ConnectionContext> {
        let snapshot = self.managed.as_ref().map(|state| state.snapshot());
        let tenant_policy = snapshot
            .as_ref()
            .map(|snapshot| &snapshot.tenants)
            .unwrap_or(&self.tenants);
        let tenant = match tenant_policy {
            None => None,
            Some(policy) => Some(
                policy.access(
                    path.as_deref()
                        .ok_or_else(|| anyhow!("verified tenant identity required"))?,
                )?,
            ),
        };
        let revocation = match &self.revocations {
            None => RevocationGuard::default(),
            Some(manager) => manager.register(
                path.as_deref()
                    .ok_or_else(|| anyhow!("verified device identity required"))?,
                certificates
                    .and_then(|certs| certs.first())
                    .ok_or_else(|| anyhow!("verified client certificate required"))?,
            )?,
        };
        let quota = match &self.quotas {
            None => None,
            Some(manager) => Some(
                manager.open_session(
                    path.as_deref()
                        .ok_or_else(|| anyhow!("verified device identity required"))?,
                )?,
            ),
        };
        let fleet = match &self.fleet_registry {
            None => None,
            Some(registry) => {
                let fingerprint = certificates
                    .and_then(|certs| certs.first())
                    .map(crate::revocation::certificate_fingerprint)
                    .transpose()?;
                let connection = registry
                    .connection(path.clone(), fingerprint, peer_addr, transport)
                    .await?;
                connection.set_tenant(
                    tenant.as_ref().map(TenantAccess::tenant_id),
                    tenant.as_ref().map(TenantAccess::roles).unwrap_or(&[]),
                );
                Some(connection)
            }
        };
        if let Some(state) = &self.managed {
            state.register(path.as_deref(), &revocation, tenant.as_ref(), fleet.as_ref())?;
        }
        Ok(ConnectionContext {
            path,
            quota,
            revocation,
            fleet,
            tenant,
        })
    }

    /// Validate an incoming tunnel request and open the tunnel to its destination.
    ///
    /// Generic over the body type because only the headers and uri are read: the websocket and
    /// http2 handlers pass a `Request<Incoming>`, while the webtransport handler rebuilds a
    /// `Request<()>` from the HTTP/3 CONNECT request, which has no hyper body.
    pub(super) async fn handle_tunnel_request<B>(
        &self,
        restrictions: Arc<RestrictionsRules>,
        mut restrict_path_prefix: ConnectionContext,
        mut client_addr: SocketAddr,
        req: &Request<B>,
        pre_admitted: Option<TunnelPermit>,
    ) -> Result<EstablishedTunnel, Box<HttpResponse>> {
        let snapshot = self.managed.as_ref().map(|state| state.snapshot());
        let restrictions = snapshot
            .as_ref()
            .map(|snapshot| snapshot.restrictions.clone())
            .unwrap_or(restrictions);
        if let Some(snapshot) = &snapshot {
            restrict_path_prefix.tenant = snapshot
                .tenants
                .as_ref()
                .map(|policy| {
                    let identity = restrict_path_prefix
                        .path
                        .as_deref()
                        .ok_or_else(|| anyhow!("Verified tenant identity required"))?;
                    policy.access(identity)
                })
                .transpose()
                .map_err(|_| Box::new(bad_request()))?;
        }
        let revocation = restrict_path_prefix.revocation.clone();
        if revocation.is_revoked() {
            return Err(Box::new(bad_request()));
        }
        let quota = match pre_admitted {
            Some(permit) => Some(permit),
            None => restrict_path_prefix.admit_tunnel().map_err(quota_rejection)?,
        };
        if let Some((x_forward_for, x_forward_for_str)) = extract_x_forwarded_for(req) {
            info!("Request X-Forwarded-For: {x_forward_for:?}");
            Span::current().record("forwarded_for", x_forward_for_str);
            client_addr.set_ip(x_forward_for);
        };

        let path_prefix = extract_path_prefix(req.uri().path()).map_err(|err| {
            warn!("Rejecting connection with {err}: {}", req.uri());
            bad_request()
        })?;

        if let Some(restrict_path) = restrict_path_prefix.path.as_deref()
            && path_prefix != restrict_path
        {
            warn!(
                "Client requested upgrade path '{path_prefix}' does not match upgrade path restriction '{restrict_path}' (mTLS, etc.)"
            );
            return Err(Box::new(bad_request()));
        }

        let jwt = extract_tunnel_info(req).map_err(|err| {
            warn!("{}", err);
            bad_request()
        })?;

        Span::current().record("id", &jwt.claims.id);
        Span::current().record("remote", format!("{}:{}", jwt.claims.r, jwt.claims.rp));
        let remote = RemoteAddr::try_from(jwt.claims).map_err(|err| {
            warn!("Rejecting connection with bad tunnel info: {err} {}", req.uri());
            bad_request()
        })?;

        let authorization = extract_authorization(req);
        let restriction = match &restrict_path_prefix.tenant {
            Some(tenant) => validate_tunnel_with_scope(&remote, path_prefix, authorization, &restrictions, |rule| {
                tenant.allows(&remote.protocol, &rule.name)
            }),
            None => validate_tunnel(&remote, path_prefix, authorization, &restrictions),
        }
        .ok_or_else(|| {
            warn!("Rejecting connection with not allowed destination: {remote:?}");
            bad_request()
        })?;
        if let Some(tenant) = &restrict_path_prefix.tenant {
            if !remote.protocol.is_reverse_tunnel()
                && self
                    .config
                    .management_api
                    .is_some_and(|address| address.port() == remote.port)
            {
                warn!(
                    tenant = tenant.tenant_id(),
                    "Rejecting tenant forwarding to reserved management port"
                );
                return Err(Box::new(bad_request()));
            }
            tenant
                .authorize_reverse(&remote, find_mapped_port(remote.port, restriction))
                .map_err(|err| {
                    warn!(
                        tenant = tenant.tenant_id(),
                        device = restrict_path_prefix.path.as_deref(),
                        "Rejecting tenant reverse resource: {err}"
                    );
                    bad_request()
                })?;
        }
        let owner = ListenerOwner {
            instance: self.instance,
            tenant: restrict_path_prefix
                .tenant
                .as_ref()
                .map(|tenant| Arc::from(tenant.tenant_id())),
            device: revocation
                .identity()
                .or_else(|| quota.as_ref().map(TunnelPermit::identity))
                .or_else(|| restrict_path_prefix.path.as_deref().map(Arc::from)),
        };
        info!("Tunnel accepted due to matched restriction: {}", restriction.name);

        let client_id = req
            .headers()
            .get("x-client-id")
            .or_else(|| req.headers().get("x-device-id"))
            .and_then(|h| h.to_str().ok())
            .filter(|s| !s.is_empty() && s.len() <= 256)
            .map(|s| s.to_string());

        if let Some(connection) = &restrict_path_prefix.fleet {
            connection.set_tcp_transport(if req.version() == Version::HTTP_2 { "http" } else { "ws" });
        }
        let fleet = self
            .fleet_registry
            .as_ref()
            .map(|registry| registry.tunnel(restrict_path_prefix.fleet.as_ref(), client_id, client_addr, remote.port));

        let req_protocol = remote.protocol.clone();
        let tunnel = revocation
            .run(self.exec_tunnel(
                restriction,
                remote,
                client_addr,
                (quota.as_ref(), &revocation, fleet.as_ref()),
                &owner,
                restrict_path_prefix.tenant.as_ref(),
            ))
            .await
            .map_err(|err| {
                warn!("Rejecting connection with bad upgrade request: {err} {}", req.uri());
                bad_request()
            })?;

        let (remote_addr, local_rx, local_tx) = tunnel;
        if let Some(fleet) = &fleet {
            fleet.ready(remote_addr.port);
        }
        let inject_cookie = req_protocol.is_dynamic_reverse_tunnel();
        info!("connected to {:?} {}:{}", req_protocol, remote_addr.host, remote_addr.port);
        Ok(EstablishedTunnel {
            remote_addr,
            local_rx,
            local_tx,
            need_cookie: inject_cookie,
            quota,
            fleet,
        })
    }

    async fn exec_tunnel(
        &self,
        restriction: &RestrictionConfig,
        remote: RemoteAddr,
        client_address: SocketAddr,
        resources: (Option<&TunnelPermit>, &RevocationGuard, Option<&TunnelLease>),
        owner: &ListenerOwner,
        tenant: Option<&TenantAccess>,
    ) -> anyhow::Result<(RemoteAddr, Pin<Box<dyn AsyncRead + Send>>, Pin<Box<dyn AsyncWrite + Send>>)> {
        let (quota, revocation, fleet) = resources;
        match remote.protocol {
            LocalProtocol::Udp { timeout, .. } => {
                let connector = UdpUpstreamConnector::new(
                    remote.host.clone(),
                    remote.port,
                    self.config.socket_so_mark,
                    timeout.unwrap_or(Duration::from_secs(10)),
                    self.config.dns_resolver.clone(),
                );
                let (rx, tx) = match &self.config.http_proxy {
                    None => connector.connect(&None).await?,
                    Some(_) => Err(anyhow!("UDP tunneling is not supported with HTTP proxy"))?,
                };

                Ok((remote, Box::pin(rx), Box::pin(tx)))
            }
            LocalProtocol::Tcp { proxy_protocol } => {
                let connector = TcpUpstreamConnector::new(
                    remote.host.clone(),
                    remote.port,
                    self.config.socket_so_mark,
                    Duration::from_secs(10),
                    self.config.dns_resolver.clone(),
                );
                let (rx, mut tx) = match &self.config.http_proxy {
                    None => connector.connect(&None).await?,
                    Some(proxy_url) => connector.connect_with_http_proxy(proxy_url, &None).await?,
                };

                if proxy_protocol {
                    let mut dest_addr = tx.local_addr()?;

                    // Fix address family mismatches to satisfy PROXY protocol v2 rules
                    if client_address.is_ipv6() && dest_addr.is_ipv4() {
                        dest_addr = std::net::SocketAddr::new(
                            std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
                            dest_addr.port(),
                        );
                    } else if client_address.is_ipv4() && dest_addr.is_ipv6() {
                        dest_addr = std::net::SocketAddr::new(
                            std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
                            dest_addr.port(),
                        );
                    }

                    let header = ppp::v2::Builder::with_addresses(
                        ppp::v2::Version::Two | ppp::v2::Command::Proxy,
                        ppp::v2::Protocol::Stream,
                        (client_address, dest_addr),
                    )
                    .build()?;
                    let _ = tx.write_all(&header).await;
                }

                Ok((remote, Box::pin(rx), Box::pin(tx)))
            }
            LocalProtocol::ReverseTcp => {
                static SERVERS: LazyLock<ReverseTunnelServer<TcpDownstreamListener>> =
                    LazyLock::new(ReverseTunnelServer::new);

                let remote_port = find_mapped_port(remote.port, restriction);
                let local_srv = (remote.host, remote_port);
                let bind = try_to_sock_addr(local_srv.clone())?;
                let listening_server = bind_reverse(bind, tenant, |candidate| {
                    let destination = (local_srv.0.clone(), candidate.port());
                    async move {
                        let listener = TcpDownstreamListener::new(candidate, destination, false).await?;
                        let bound = listener.bound_addr();
                        Ok((listener, bound))
                    }
                });
                let ((local_rx, local_tx), remote) = SERVERS
                    .run_listening_server(
                        &self.executor,
                        super::reverse_tunnel::ReverseListenerKey::Socket(owner.clone(), bind),
                        self.config.remote_server_idle_timeout,
                        listening_server,
                        fleet.cloned(),
                        (quota.cloned(), revocation.clone()),
                    )
                    .await?;

                Ok((remote, Box::pin(local_rx), Box::pin(local_tx)))
            }
            LocalProtocol::ReverseUdp { timeout } => {
                static SERVERS: LazyLock<ReverseTunnelServer<UdpDownstreamListener>> =
                    LazyLock::new(ReverseTunnelServer::new);

                let remote_port = find_mapped_port(remote.port, restriction);
                let local_srv = (remote.host, remote_port);
                let bind = try_to_sock_addr(local_srv.clone())?;
                let listening_server = bind_reverse(bind, tenant, |candidate| {
                    let destination = (local_srv.0.clone(), candidate.port());
                    async move {
                        let listener = UdpDownstreamListener::new(candidate, destination, timeout).await?;
                        Ok((listener, candidate))
                    }
                });
                let ((local_rx, local_tx), remote) = SERVERS
                    .run_listening_server(
                        &self.executor,
                        super::reverse_tunnel::ReverseListenerKey::Socket(owner.clone(), bind),
                        self.config.remote_server_idle_timeout,
                        listening_server,
                        fleet.cloned(),
                        (quota.cloned(), revocation.clone()),
                    )
                    .await?;
                Ok((remote, Box::pin(local_rx), Box::pin(local_tx)))
            }
            LocalProtocol::ReverseSocks5 { timeout, credentials } => {
                static SERVERS: LazyLock<ReverseTunnelServer<Socks5DownstreamListener>> =
                    LazyLock::new(ReverseTunnelServer::new);

                let remote_port = find_mapped_port(remote.port, restriction);
                let local_srv = (remote.host, remote_port);
                let bind = try_to_sock_addr(local_srv.clone())?;
                let listening_server = bind_reverse(bind, tenant, |candidate| {
                    let credentials = credentials.clone();
                    async move {
                        let listener = Socks5DownstreamListener::new(candidate, timeout, credentials).await?;
                        Ok((listener, candidate))
                    }
                });
                let ((local_rx, mut local_tx), remote) = SERVERS
                    .run_listening_server(
                        &self.executor,
                        super::reverse_tunnel::ReverseListenerKey::Socket(owner.clone(), bind),
                        self.config.remote_server_idle_timeout,
                        listening_server,
                        fleet.cloned(),
                        (quota.cloned(), revocation.clone()),
                    )
                    .await?;

                // Send the deferred SOCKS5 reply now that a reverse-tunnel client has picked up the
                // connection. On the reverse path the actual target connection happens on the far
                // tunward client side, so the server cannot know whether the target was reached;
                // acknowledging success here is the best achievable (and mandatory, otherwise the
                // write half stays pending forever).
                use crate::tunnel::downstream_listeners::DownstreamWrite;
                let _ = local_tx.on_tunnel_ready(Ok(())).await;

                Ok((remote, Box::pin(local_rx), Box::pin(local_tx)))
            }
            LocalProtocol::ReverseHttpProxy { timeout, credentials } => {
                static SERVERS: LazyLock<ReverseTunnelServer<HttpProxyDownstreamListener>> =
                    LazyLock::new(ReverseTunnelServer::new);

                let remote_port = find_mapped_port(remote.port, restriction);
                let local_srv = (remote.host, remote_port);
                let bind = try_to_sock_addr(local_srv.clone())?;
                let listening_server = bind_reverse(bind, tenant, |candidate| {
                    let credentials = credentials.clone();
                    async move {
                        let listener = HttpProxyDownstreamListener::new(candidate, timeout, credentials, false).await?;
                        Ok((listener, candidate))
                    }
                });
                let ((local_rx, local_tx), remote) = SERVERS
                    .run_listening_server(
                        &self.executor,
                        super::reverse_tunnel::ReverseListenerKey::Socket(owner.clone(), bind),
                        self.config.remote_server_idle_timeout,
                        listening_server,
                        fleet.cloned(),
                        (quota.cloned(), revocation.clone()),
                    )
                    .await?;

                Ok((remote, Box::pin(local_rx), Box::pin(local_tx)))
            }
            #[cfg(unix)]
            LocalProtocol::ReverseUnix { ref path } => {
                use crate::tunnel::downstream_listeners::UnixDownstreamListener;
                static SERVERS: LazyLock<ReverseTunnelServer<UnixDownstreamListener>> =
                    LazyLock::new(ReverseTunnelServer::new);

                // we hash the unix socket path to generate a unique host
                let host = {
                    let mut hasher = AHasher::default();
                    path.hash(&mut hasher);
                    Host::Ipv6(Ipv6Addr::from(hasher.finish() as u128))
                };

                let local_srv = (host, 0);
                let bind = try_to_sock_addr(local_srv.clone())?;
                let listening_server = async {
                    let l = UnixDownstreamListener::new(path, local_srv, false).await?;
                    Ok((l, bind))
                };
                let ((local_rx, local_tx), remote) = SERVERS
                    .run_listening_server(
                        &self.executor,
                        super::reverse_tunnel::ReverseListenerKey::Unix(owner.clone(), path.clone()),
                        self.config.remote_server_idle_timeout,
                        listening_server,
                        fleet.cloned(),
                        (quota.cloned(), revocation.clone()),
                    )
                    .await?;

                Ok((remote, Box::pin(local_rx), Box::pin(local_tx)))
            }
            #[cfg(not(unix))]
            LocalProtocol::ReverseUnix { .. } => {
                error!("Received an unsupported target protocol {:?}", remote);
                Err(anyhow::anyhow!("Invalid upgrade request"))
            }
            LocalProtocol::Stdio { .. }
            | LocalProtocol::Socks5 { .. }
            | LocalProtocol::TProxyTcp
            | LocalProtocol::TProxyUdp { .. }
            | LocalProtocol::HttpProxy { .. }
            | LocalProtocol::Unix { .. } => {
                error!("Received an unsupported target protocol {:?}", remote);
                Err(anyhow::anyhow!("Invalid upgrade request"))
            }
        }
    }

    pub async fn serve(mut self, restrictions: RestrictionsRules) -> anyhow::Result<()> {
        if let Some(path) = &self.config.tenant_config {
            anyhow::ensure!(
                self.config
                    .tls
                    .as_ref()
                    .is_some_and(|tls| tls.tls_client_ca_certificates.is_some())
                    && self.config.restriction_config.is_some(),
                "tenant isolation requires verified mTLS and --restrict-config"
            );
            self.tenants = match &self.managed {
                Some(state) => state.snapshot().tenants.clone(),
                None => Some(TenantPolicy::from_path(path, &restrictions)?),
            };
        }
        if let Some(path) = &self.config.fleet_inventory {
            anyhow::ensure!(
                self.config
                    .tls
                    .as_ref()
                    .is_some_and(|tls| tls.tls_client_ca_certificates.is_some()),
                "fleet inventory requires TLS and --tls-client-ca-certs (verified mTLS identity)"
            );
            self.fleet_registry
                .as_ref()
                .expect("inventory registry")
                .attach_inventory(path.clone(), self.config.fleet_inventory_max_devices)
                .await?;
        }
        if let Some(config) = &self.config.device_quotas {
            config.validate()?;
            anyhow::ensure!(
                self.config
                    .tls
                    .as_ref()
                    .is_some_and(|tls| tls.tls_client_ca_certificates.is_some()),
                "device quotas require TLS and --tls-client-ca-certs (verified mTLS identity)"
            );
        }
        let _revocation_reload = if let Some(path) = &self.config.device_revocation_config {
            anyhow::ensure!(
                self.config
                    .tls
                    .as_ref()
                    .is_some_and(|tls| tls.tls_client_ca_certificates.is_some()),
                "device revocation requires TLS and --tls-client-ca-certs (verified mTLS identity)"
            );
            let manager = RevocationManager::from_path(path)?;
            self.revocations = Some(manager.clone());
            Some(scopeguard::guard(self.executor.spawn(manager.reload(path.clone())), |task| {
                task.abort()
            }))
        } else {
            if self.managed.is_some()
                && self
                    .config
                    .tls
                    .as_ref()
                    .is_some_and(|tls| tls.tls_client_ca_certificates.is_some())
            {
                self.revocations = Some(RevocationManager::empty());
            }
            None
        };
        info!("Starting tunward server listening on {}", self.config.bind);

        // setup upgrade request handler
        let mk_websocket_upgrade_fn = |server: Server<_>,
                                       restrictions: Arc<ArcSwap<RestrictionsRules>>,
                                       restrict_path: ConnectionContext,
                                       client_addr: SocketAddr| {
            move |req: Request<Incoming>| {
                ws_server_upgrade(
                    server.clone(),
                    restrictions.load().clone(),
                    restrict_path.clone(),
                    client_addr,
                    req,
                )
                .map::<anyhow::Result<_>, _>(Ok)
                .instrument(mk_span())
            }
        };

        let mk_http_upgrade_fn = |server: Server<_>,
                                  restrictions: Arc<ArcSwap<RestrictionsRules>>,
                                  restrict_path: ConnectionContext,
                                  client_addr: SocketAddr| {
            move |req: Request<Incoming>| {
                http_server_upgrade(
                    server.clone(),
                    restrictions.load().clone(),
                    restrict_path.clone(),
                    client_addr,
                    req,
                )
                .map::<anyhow::Result<_>, _>(Ok)
                .instrument(mk_span())
            }
        };

        let mk_auto_upgrade_fn = |server: Server<_>,
                                  restrictions: Arc<ArcSwap<RestrictionsRules>>,
                                  restrict_path: ConnectionContext,
                                  client_addr: SocketAddr| {
            move |req: Request<Incoming>| {
                let server = server.clone();
                let restrictions = restrictions.clone();
                let restrict_path = restrict_path.clone();
                async move {
                    if fastwebsockets::upgrade::is_upgrade_request(&req) {
                        ws_server_upgrade(server.clone(), restrictions.load().clone(), restrict_path, client_addr, req)
                            .map::<anyhow::Result<_>, _>(Ok)
                            .await
                    } else if req.version() == Version::HTTP_2 {
                        http_server_upgrade(
                            server.clone(),
                            restrictions.load().clone(),
                            restrict_path.clone(),
                            client_addr,
                            req,
                        )
                        .map::<anyhow::Result<_>, _>(Ok)
                        .await
                    } else {
                        error!("Invalid protocol version request, got {:?} while expecting either websocket http1 upgrade or http2", req.version());
                        Ok(http::Response::builder()
                            .status(StatusCode::BAD_REQUEST)
                            .body(Either::Left("Invalid protocol request".to_string()))
                            .unwrap())
                    }
                }
                    .instrument(mk_span())
            }
        };

        // Init TLS if needed
        let mut tls_context = if let Some(tls_config) = &self.config.tls {
            let tls_context = TlsContext {
                tls_acceptor: Arc::new(tls::tls_acceptor(
                    tls_config,
                    Some(vec![b"h2".to_vec(), b"http/1.1".to_vec()]),
                )?),
                tls_reloader: if self.managed.is_some() {
                    None
                } else {
                    Some(TlsReloader::new_for_server(self.config.clone())?)
                },
                tls_config,
            };
            Some(tls_context)
        } else {
            None
        };

        // Bind server and run forever to serve incoming connections.
        let restrictions = RestrictionsRulesReloader::new(
            restrictions,
            if self.managed.is_some() {
                None
            } else {
                self.config.restriction_config.clone()
            },
        )?;
        let listener = TcpListener::bind(&self.config.bind)
            .await
            .with_context(|| format!("Failed to bind to socket on {}", self.config.bind))?;

        let _reload_task = if let (Some(state), Some(reload)) = (&self.managed, &self.reload) {
            let requests = reload.take_receiver().await?;
            let task = self.executor.spawn(state.clone().run(requests));
            Some(scopeguard::guard(task, |task| task.abort()))
        } else {
            None
        };

        // WebTransport needs its own UDP socket, so it runs as a sibling of the TCP accept loop
        // below. One server process then answers websocket, http2 and webtransport clients.
        if self.config.enable_webtransport {
            if self.config.tls.is_none() {
                return Err(anyhow!(
                    "--enable-webtransport requires TLS: QUIC mandates TLS 1.3, so it cannot be served on a cleartext ws:// or http:// endpoint. Use wss:// or wts://."
                ));
            }

            let server = self.clone();
            let restrictions = restrictions.restrictions_rules().clone();
            self.executor.spawn(async move {
                if let Err(err) = handler_webtransport::run_webtransport_server(server, restrictions).await {
                    error!("Webtransport server stopped: {err:?}");
                }
            });
        }

        if let (Some(mgmt_addr), Some(reg)) = (self.config.management_api, &self.fleet_registry) {
            let reg = reg.clone();
            self.executor.spawn(async move {
                if let Err(err) = crate::management::run_management_server(mgmt_addr, reg).await {
                    error!("Management REST API stopped: {err:?}");
                }
            });
        }

        loop {
            let (stream, peer_addr) = match listener.accept().await {
                Ok(ret) => ret,
                Err(err) => {
                    warn!("Error while accepting connection {:?}", err);
                    continue;
                }
            };

            let span = span!(Level::INFO, "cnx", peer = peer_addr.to_string());
            info!(parent: &span, "Accepting connection");
            if let Err(err) = protocols::tcp::configure_socket(SockRef::from(&stream), SoMark::new(None)) {
                warn!("Error while configuring server socket {:?}", err);
            }

            let server = self.clone();
            let restrictions = restrictions.restrictions_rules().clone();

            // Check if we need to enable TLS or not
            match tls_context.as_mut() {
                Some(tls) => {
                    // Reload TLS certificate if needed
                    let tls_acceptor = match &server.managed {
                        Some(state) => state.snapshot().tcp_tls.clone().expect("TLS mode is fixed at startup"),
                        None => tls.tls_acceptor().clone(),
                    };
                    let fut = async move {
                        info!("Doing TLS handshake");
                        let tls_stream = match tls_acceptor.accept(stream).await {
                            Ok(tls_stream) => hyper_util::rt::TokioIo::new(tls_stream),
                            Err(err) => {
                                error!("error while accepting TLS connection {}", err);
                                return;
                            }
                        };

                        let tls_ctx = tls_stream.inner().get_ref().1;
                        let identity_required = server
                            .config
                            .tls
                            .as_ref()
                            .is_some_and(|tls| tls.tls_client_ca_certificates.is_some());
                        let restrict_path = match tls::client_path_from_certificate(
                            tls_ctx.peer_certificates(),
                            identity_required,
                            server.config.tls_client_identity_field,
                        ) {
                            Ok(identity) => identity,
                            Err(err) => {
                                warn!("Rejecting mTLS connection without a supported client identity: {err}");
                                return;
                            }
                        };
                        let is_http2 = tls_ctx.alpn_protocol() == Some(b"h2");
                        let restrict_path = match server
                            .connection_context(
                                restrict_path,
                                tls_ctx.peer_certificates(),
                                peer_addr,
                                if is_http2 { "https" } else { "wss" },
                            )
                            .await
                        {
                            Ok(context) => context,
                            Err(err) => {
                                warn!("Rejecting authenticated session due to access policy: {err}");
                                return;
                            }
                        };
                        let revocation = restrict_path.revocation.clone();
                        let serve_connection = async move {
                            match is_http2 {
                                // http2
                                true => {
                                    let mut conn_builder = http2::Builder::new(TokioExecutor::new());
                                    conn_builder.timer(TokioTimer::new());
                                    if let Some(ping) = server.config.websocket_ping_frequency {
                                        conn_builder.keep_alive_interval(ping);
                                    }

                                    let http_upgrade_fn =
                                        mk_http_upgrade_fn(server, restrictions, restrict_path, peer_addr);
                                    let con_fut =
                                        conn_builder.serve_connection(tls_stream, service_fn(http_upgrade_fn));
                                    if let Err(e) = con_fut.await {
                                        error!("Error while upgrading cnx to http: {:?}", e);
                                    }
                                }
                                // websocket
                                false => {
                                    let websocket_upgrade_fn =
                                        mk_websocket_upgrade_fn(server, restrictions, restrict_path, peer_addr);
                                    let conn_fut = http1::Builder::new()
                                        .timer(TokioTimer::new())
                                        // https://github.com/fahmikemal/tunward/issues/358
                                        // disabled, to avoid conflict with --connection-min-idle flag, that open idle connections
                                        .header_read_timeout(None)
                                        .serve_connection(tls_stream, service_fn(websocket_upgrade_fn))
                                        .with_upgrades();

                                    if let Err(e) = conn_fut.await {
                                        error!("Error while upgrading cnx: {:?}", e);
                                    }
                                }
                            };
                            Ok(())
                        };
                        if let Err(err) = revocation.run(serve_connection).await {
                            info!("Closing authenticated connection: {err}");
                        }
                    }
                    .instrument(span);

                    self.executor.spawn(fut);
                }
                // HTTP without TLS
                None => {
                    let fut = async move {
                        let context = match server.connection_context(None, None, peer_addr, "tcp").await {
                            Ok(context) => context,
                            Err(err) => {
                                warn!("Cannot register connection: {err}");
                                return;
                            }
                        };
                        let stream = hyper_util::rt::TokioIo::new(stream);
                        let mut conn_fut = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new());
                        conn_fut.http1().timer(TokioTimer::new());
                        conn_fut.http2().timer(TokioTimer::new());
                        if let Some(ping) = server.config.websocket_ping_frequency {
                            conn_fut.http2().keep_alive_interval(ping);
                        }

                        let websocket_upgrade_fn = mk_auto_upgrade_fn(server, restrictions, context, peer_addr);
                        let upgradable =
                            conn_fut.serve_connection_with_upgrades(stream, service_fn(websocket_upgrade_fn));

                        if let Err(e) = upgradable.await {
                            error!("Error while upgrading cnx to websocket: {:?}", e);
                        }
                    }
                    .instrument(span);

                    self.executor.spawn(fut);
                }
            }
        }
    }
}

fn mk_span() -> Span {
    span!(
        Level::INFO,
        "tunnel",
        id = tracing::field::Empty,
        remote = tracing::field::Empty,
        forwarded_for = tracing::field::Empty
    )
}

impl Debug for ServerConfig {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServerConfig")
            .field("socket_so_mark", &self.socket_so_mark)
            .field("bind", &self.bind)
            .field("websocket_ping_frequency", &self.websocket_ping_frequency)
            .field("timeout_connect", &self.timeout_connect)
            .field("websocket_mask_frame", &self.websocket_mask_frame)
            .field("restriction_config", &self.restriction_config)
            .field("tls", &self.tls.is_some())
            .field("remote_server_idle_timeout", &self.remote_server_idle_timeout)
            .field("enable_webtransport", &self.enable_webtransport)
            .field("device_quotas", &self.device_quotas)
            .field("tls_client_identity_field", &self.tls_client_identity_field)
            .field(
                "mTLS",
                &self
                    .tls
                    .as_ref()
                    .map(|x| x.tls_client_ca_certificates.is_some())
                    .unwrap_or(false),
            )
            .finish()
    }
}

async fn bind_reverse<T, F, Fut>(
    bind: SocketAddr,
    tenant: Option<&TenantAccess>,
    mut create: F,
) -> anyhow::Result<(T, SocketAddr)>
where
    F: FnMut(SocketAddr) -> Fut,
    Fut: std::future::Future<Output = anyhow::Result<(T, SocketAddr)>>,
{
    let candidates = tenant
        .map(|tenant| tenant.bind_candidates(bind))
        .unwrap_or_else(|| vec![bind]);
    let mut last_error = anyhow!("no tenant reverse ports available");
    for candidate in candidates {
        match create(candidate).await {
            Ok(listener) => return Ok(listener),
            Err(error) => {
                if !error.chain().any(|source| {
                    source
                        .downcast_ref::<std::io::Error>()
                        .is_some_and(|error| error.kind() == std::io::ErrorKind::AddrInUse)
                }) {
                    return Err(error);
                }
                last_error = error;
            }
        }
    }
    Err(last_error)
}

struct TlsContext<'a> {
    tls_acceptor: Arc<TlsAcceptor>,
    tls_reloader: Option<TlsReloader>,
    tls_config: &'a TlsServerConfig,
}
impl TlsContext<'_> {
    #[inline]
    pub fn tls_acceptor(&mut self) -> &Arc<TlsAcceptor> {
        if self
            .tls_reloader
            .as_ref()
            .is_some_and(TlsReloader::should_reload_certificate)
        {
            match tls::tls_acceptor(self.tls_config, Some(vec![b"h2".to_vec(), b"http/1.1".to_vec()])) {
                Ok(acceptor) => self.tls_acceptor = Arc::new(acceptor),
                Err(err) => error!("Cannot reload TLS certificate {:?}", err),
            };
        }

        &self.tls_acceptor
    }
}
