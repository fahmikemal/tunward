use super::server::{ConnectionContext, EstablishedTunnel};
use crate::executor::TokioExecutorRef;
use crate::protocols::tcp::LogLimiter;
use crate::protocols::tls;
use crate::restrictions::types::RestrictionsRules;
use crate::tunnel::server::Server;
use crate::tunnel::server::utils::{extract_path_prefix, matches_any_restriction};
use crate::tunnel::tls_reloader::TlsReloader;
use crate::tunnel::transport;
use crate::tunnel::transport::tunnel_to_jwt_token;
use crate::tunnel::transport::webtransport::{
    WebTransportRead, WebTransportWrite, bind_udp_socket, mk_transport_config, read_jwt_preamble, write_jwt_preamble,
};
use anyhow::{Context, anyhow};
use arc_swap::ArcSwap;
use hyper::header::{AUTHORIZATION, COOKIE, HeaderValue};
use hyper::{Request, StatusCode};
use std::any::Any;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;
use tokio_rustls::rustls::pki_types::CertificateDer;
use tracing::{Instrument, Level, Span, debug, error, info, span, warn};
use uuid::Uuid;
use web_transport_quinn::quinn;
use web_transport_quinn::quinn::crypto::rustls::QuicServerConfig;

/// Serve WebTransport (HTTP/3 over QUIC) on the same port as the TCP listener, over UDP.
///
/// This runs alongside [`Server::serve`]'s TCP accept loop rather than replacing it, so one
/// server process answers websocket, http2 and webtransport clients.
pub(super) async fn run_webtransport_server(
    server: Server<impl TokioExecutorRef>,
    restrictions: Arc<ArcSwap<RestrictionsRules>>,
) -> anyhow::Result<()> {
    let Some(tls_config) = server.config.tls.as_ref() else {
        return Err(anyhow!(
            "webtransport requires TLS: QUIC mandates TLS 1.3, so it cannot be served on a cleartext ws:// or http:// endpoint"
        ));
    };

    let bind = server.config.bind;
    let endpoint = mk_quic_endpoint(&server, tls_config)?;
    if let Some(state) = &server.managed {
        state.register_endpoint(endpoint.clone());
    }
    let tls_reloader = if server.managed.is_some() {
        None
    } else {
        Some(
            TlsReloader::new_for_server(server.config.clone())
                .with_context(|| "Cannot create the tls reloader for webtransport")?,
        )
    };

    info!("Starting tunward webtransport server listening on udp://{bind}");
    let mut reload_tick = tokio::time::interval(std::time::Duration::from_secs(1));
    reload_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    // The QUIC and HTTP/3 handshakes are driven here instead of by web_transport_quinn::Server, which
    // keeps every one pending with neither a deadline nor a bound: server keep-alives would hold a peer
    // that completes QUIC but never sends its CONNECT forever. A connection stays pending, and counts
    // against the same limits as the TCP listener, until that CONNECT request arrives.
    let pending_handshakes = Arc::new(Semaphore::new(server.config.max_pending_tls_handshakes.get() as usize));
    let refused_log = LogLimiter::new(Duration::from_secs(10));
    let timeout_log = Arc::new(LogLimiter::new(Duration::from_secs(10)));
    loop {
        let incoming = tokio::select! {
            _ = reload_tick.tick() => {
                // Handshakes may all fail with the old certificate, so do not wait for one to
                // succeed before installing a new trust anchor.
                if tls_reloader.as_ref().is_some_and(TlsReloader::should_reload_certificate) {
                    match mk_quic_server_config(&server, tls_config) {
                        Ok(config) => endpoint.set_server_config(Some(config)),
                        Err(err) => error!("Cannot reload the webtransport TLS certificate {err:?}"),
                    }
                }
                continue;
            }
            incoming = endpoint.accept() => incoming,
        };
        let Some(incoming) = incoming else {
            warn!("webtransport endpoint closed, stopping to accept connections");
            return Ok(());
        };

        let peer_addr = incoming.remote_address();
        let Ok(handshake_permit) = pending_handshakes.clone().try_acquire_owned() else {
            if let Some(suppressed) = refused_log.check() {
                warn!(
                    suppressed,
                    "Refusing webtransport connection from {peer_addr}: {} handshakes already pending (--max-pending-tls-handshakes)",
                    server.config.max_pending_tls_handshakes
                );
            }
            incoming.refuse();
            continue;
        };
        let span = span!(Level::INFO, "cnx", peer = peer_addr.to_string());
        info!(parent: &span, "Accepting webtransport connection");

        let session_handler = {
            let server = server.clone();
            let restrictions = restrictions.clone();
            let timeout_log = timeout_log.clone();
            async move {
                let handshake_timeout = server.config.tls_handshake_timeout;
                let handshake = async {
                    let connection = incoming.accept()?.await?;
                    anyhow::Ok(web_transport_quinn::Request::accept(connection).await?)
                };
                // On a timeout, dropping the handshake drops the connection, which closes it.
                let request = match tokio::time::timeout(handshake_timeout, handshake).await {
                    Ok(Ok(request)) => request,
                    Ok(Err(err)) => {
                        debug!("Webtransport handshake failed: {err:#}");
                        return;
                    }
                    Err(_) => {
                        if let Some(suppressed) = timeout_log.check() {
                            warn!(
                                suppressed,
                                "Closing webtransport connection whose QUIC/HTTP3 handshake did not complete within {handshake_timeout:?} (--tls-handshake-timeout)"
                            );
                        }
                        return;
                    }
                };
                drop(handshake_permit);
                if let Err(err) = handle_session(server, restrictions, request).await {
                    warn!("{err:?}");
                }
            }
            .instrument(span)
        };
        server.executor.spawn(session_handler);
    }
}

fn mk_quic_server_config(
    server: &Server<impl TokioExecutorRef>,
    tls_config: &crate::tunnel::server::TlsServerConfig,
) -> anyhow::Result<quinn::ServerConfig> {
    if let Some(state) = &server.managed {
        return state
            .snapshot()
            .quic_tls
            .clone()
            .context("Missing managed QUIC configuration");
    }
    let tls = tls::quic_server_config(tls_config).with_context(|| "Cannot create the TLS config for webtransport")?;
    let tls = QuicServerConfig::try_from(tls)
        .with_context(|| "Cannot use the TLS config for QUIC, TLS 1.3 with a supported cipher suite is required")?;

    let mut config = quinn::ServerConfig::with_crypto(Arc::new(tls));
    config.transport_config(Arc::new(mk_transport_config(server.config.websocket_ping_frequency)?));

    Ok(config)
}

fn mk_quic_endpoint(
    server: &Server<impl TokioExecutorRef>,
    tls_config: &crate::tunnel::server::TlsServerConfig,
) -> anyhow::Result<quinn::Endpoint> {
    let socket = bind_udp_socket(Some(server.config.bind), server.config.socket_so_mark)
        .with_context(|| format!("Failed to bind to udp socket on {}", server.config.bind))?;

    quinn::Endpoint::new(
        quinn::EndpointConfig::default(),
        Some(mk_quic_server_config(server, tls_config)?),
        socket,
        Arc::new(quinn::TokioRuntime),
    )
    .with_context(|| format!("Failed to create the QUIC endpoint on {}", server.config.bind))
}

async fn handle_session(
    server: Server<impl TokioExecutorRef>,
    restrictions: Arc<ArcSwap<RestrictionsRules>>,
    request: web_transport_quinn::Request,
) -> anyhow::Result<()> {
    if transport::check_version(&request.headers).is_err() {
        let _ = request.reject(StatusCode::BAD_REQUEST).await;
        return Ok(());
    }
    // Unlike the TCP path, the client certificate is readable before we answer the CONNECT.
    let peer_certificates = request
        .conn()
        .peer_identity()
        .and_then(|identity: Box<dyn Any>| identity.downcast::<Vec<CertificateDer<'static>>>().ok());
    let identity_required = server
        .config
        .tls
        .as_ref()
        .is_some_and(|tls| tls.tls_client_ca_certificates.is_some());
    let restrict_path = match tls::client_path_from_certificate(
        peer_certificates.as_deref().map(|certs| certs.as_slice()),
        identity_required,
        server.config.tls_client_identity_field,
    ) {
        Ok(identity) => identity,
        Err(err) => {
            warn!("Rejecting mTLS connection without a supported client identity: {err}");
            let _ = request.reject(StatusCode::BAD_REQUEST).await;
            return Ok(());
        }
    };

    // Rebuild an http request so the whole validation path is shared with the other transports.
    // Only the uri and headers are read, so the unit body is fine. The destination is *not* in
    // here: the session is shared by every tunnel the client opens on it, so each stream announces
    // its own destination with a JWT preamble and gets this request with that JWT filled in.
    let session_path = request.url.path().to_string();
    let session_headers = request.headers.clone();

    // The destination only arrives per stream, but the path prefix and the authorization header are
    // known now. Checking them here turns a client that could never open any tunnel away with a
    // real status, instead of accepting its session and resetting every stream it opens.
    //
    // Every rejection answers 400, like `utils::bad_request` does on the TCP path, so a prober
    // cannot tell a bad path from a forbidden one.
    let client_addr = request.conn().remote_address();
    let path_prefix = match extract_path_prefix(&session_path) {
        Ok(path_prefix) => path_prefix,
        Err(err) => {
            warn!("Rejecting webtransport session from {client_addr} with {err}: {session_path}");
            let _ = request.reject(StatusCode::BAD_REQUEST).await;
            return Ok(());
        }
    };

    if let Some(restrict_path) = &restrict_path
        && path_prefix != restrict_path
    {
        warn!(
            "Client requested upgrade path '{path_prefix}' does not match upgrade path restriction '{restrict_path}' (mTLS, etc.)"
        );
        let _ = request.reject(StatusCode::BAD_REQUEST).await;
        return Ok(());
    }

    let policy = server.managed.as_ref().map(|state| state.snapshot());
    let session_restrictions = policy
        .as_ref()
        .map(|snapshot| snapshot.restrictions.clone())
        .unwrap_or_else(|| restrictions.load_full());
    let allowed = matches_any_restriction(
        path_prefix,
        session_headers.get(AUTHORIZATION).and_then(|auth| auth.to_str().ok()),
        &session_restrictions,
    );
    if !allowed {
        warn!("Rejecting webtransport session from {client_addr}: no restriction matches path prefix '{path_prefix}'");
        let _ = request.reject(StatusCode::BAD_REQUEST).await;
        return Ok(());
    }

    let restrict_path = match server
        .connection_context(
            restrict_path,
            peer_certificates.as_deref().map(|certs| certs.as_slice()),
            client_addr,
            "wts",
        )
        .await
    {
        Ok(context) => context,
        Err(err) => {
            warn!("Rejecting authenticated WebTransport session due to access policy: {err}");
            let status = if err.downcast_ref::<crate::quotas::QuotaError>().is_some() {
                StatusCode::TOO_MANY_REQUESTS
            } else {
                StatusCode::FORBIDDEN
            };
            let _ = request.reject(status).await;
            return Ok(());
        }
    };

    let revocation = restrict_path.revocation.clone();
    let session = revocation
        .run(async {
            request
                .ok()
                .await
                .with_context(|| format!("Cannot accept the webtransport session from {client_addr}"))
        })
        .await?;

    // One tunnel per stream. Accepting the session commits nothing upstream, so there is no need to
    // bound how long the client takes to open the first one; an idle session costs a QUIC
    // connection, which the keep-alive/idle timeout already reaps.
    loop {
        let accepted = tokio::select! {
            biased;
            _ = revocation.cancelled() => {
                session.close(StatusCode::FORBIDDEN.as_u16() as u32, b"device access revoked");
                return Ok(());
            }
            stream = session.accept_bi() => stream,
        };
        let (send, recv) = match accepted {
            Ok(stream) => stream,
            Err(err) => {
                debug!("webtransport session with {client_addr} ended: {err}");
                return Ok(());
            }
        };

        let restrictions: Arc<RestrictionsRules> = restrictions.load().clone();
        let server = server.clone();
        let session = session.clone();
        let session_path = session_path.clone();
        let session_headers = session_headers.clone();
        let restrict_path = restrict_path.clone();
        let revocation = revocation.clone();
        let span = span!(Level::INFO, "tunnel", peer = client_addr.to_string());
        server.executor.clone().spawn(
            async move {
                if let Err(err) = revocation
                    .run(wt_server_connect(
                        server,
                        restrictions,
                        session,
                        client_addr,
                        restrict_path,
                        &session_path,
                        session_headers,
                        (send, recv),
                    ))
                    .await
                {
                    warn!("{err:?}");
                }
            }
            .instrument(span),
        );
    }
}

/// Serve one tunnel, carried by one bidirectional stream of a webtransport session.
#[allow(clippy::too_many_arguments)]
async fn wt_server_connect(
    server: Server<impl TokioExecutorRef>,
    restrictions: Arc<RestrictionsRules>,
    session: web_transport_quinn::Session,
    client_addr: SocketAddr,
    restrict_path: ConnectionContext,
    session_path: &str,
    session_headers: hyper::HeaderMap,
    (mut send, mut recv): (web_transport_quinn::SendStream, web_transport_quinn::RecvStream),
) -> anyhow::Result<()> {
    let revocation = restrict_path.revocation.clone();
    let quota = match restrict_path.admit_tunnel() {
        Ok(permit) => permit,
        Err(err) => {
            warn!("Rejecting WebTransport stream due to device quota: {err}");
            let _ = send.reset(StatusCode::TOO_MANY_REQUESTS.as_u16() as u32);
            return Ok(());
        }
    };
    // The client announces the destination for this stream before anything else, since the
    // session-level CONNECT is shared and cannot carry it.
    let jwt = tokio::time::timeout(server.config.timeout_connect, read_jwt_preamble(&mut recv))
        .await
        .map_err(|_| {
            let timeout = server.config.timeout_connect;
            anyhow!("Client {client_addr} opened a webtransport stream but sent no tunnel jwt within {timeout:?}")
        })?
        .with_context(|| format!("Cannot read the tunnel jwt from {client_addr}"))?;

    let mut http_request = Request::builder()
        .method("CONNECT")
        .uri(session_path)
        .body(())
        .with_context(|| format!("webtransport request has an invalid path: {session_path}"))?;
    *http_request.headers_mut() = session_headers;
    http_request.headers_mut().insert(
        COOKIE,
        HeaderValue::from_str(&jwt).with_context(|| "client sent an invalid tunnel jwt")?,
    );

    let tunnel = tokio::select! {
        tunnel = server.handle_tunnel_request(restrictions, restrict_path, client_addr, &http_request, quota) => tunnel,
        _ = send.stopped() => return Ok(()),
    };

    let EstablishedTunnel {
        remote_addr,
        local_rx,
        local_tx,
        quota,
        fleet,
        ..
    } = match tunnel {
        Ok(tunnel) => tunnel,
        Err(response) => {
            // The session stays up for the client's other tunnels, so only this stream is
            // refused. There is no per-stream status code, so the http status goes out as the
            // stream reset code.
            let status = response.status();
            warn!("Rejecting webtransport stream from {client_addr} with {status}");
            let _ = send.reset(status.as_u16() as u32);
            return Ok(());
        }
    };

    // A stream is ready only after destination validation and the upstream/visitor accept.
    // The same acknowledgement carries dynamic reverse destinations.
    let jwt = tunnel_to_jwt_token(Uuid::from_u128(0), &remote_addr);
    write_jwt_preamble(&mut send, &jwt).await?;
    server.executor.spawn(
        async move {
            let _fleet = fleet;
            revocation
                .run(transport::io::forward_with_quota(
                    local_rx,
                    local_tx,
                    WebTransportRead::new(recv, session.clone()),
                    WebTransportWrite::new(send, session),
                    None,
                    quota,
                ))
                .await
        }
        .instrument(Span::current()),
    );

    Ok(())
}
