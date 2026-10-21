//! The client half of the webtransport transport: building the session-level CONNECT request,
//! and opening one tunnel as a stream on an already-established session.

use super::utils::{read_jwt_preamble, write_jwt_preamble};
use super::{WebTransportRead, WebTransportWrite};
use crate::tunnel::RemoteAddr;
use crate::tunnel::client::{Client, ClientConfig};
use crate::tunnel::transport::headers_from_file;
use crate::tunnel::transport::jwt::tunnel_to_jwt_token;
use anyhow::{Context, anyhow};
use hyper::Response;
use hyper::header::{AUTHORIZATION, COOKIE, HeaderValue};
use hyper::http::response::Parts;
use log::debug;
use url::{Host, Url};
use uuid::Uuid;
use web_transport_quinn::proto::ConnectRequest;

/// Build the session-level CONNECT request for a `wts://` server.
///
/// This carries only what every tunnel on the session shares — url, custom headers, upgrade
/// credentials. The per-tunnel destination travels as a stream preamble instead (see
/// [`write_jwt_preamble`]), because one session serves many tunnels.
pub(crate) fn mk_connect_request(client_cfg: &ClientConfig) -> anyhow::Result<ConnectRequest> {
    let host = client_cfg.remote_addr.host();
    let port = client_cfg.remote_addr.port();

    let authority = match host {
        Host::Ipv6(ip) => format!("[{ip}]:{port}"),
        Host::Ipv4(ip) => format!("{ip}:{port}"),
        Host::Domain(domain) => format!("{domain}:{port}"),
    };
    let url = Url::parse(&format!("https://{authority}/{}/events", client_cfg.http_upgrade_path_prefix)).with_context(
        || {
            format!(
                "cannot build the webtransport url, most likely path_prefix `{}` is not valid",
                client_cfg.http_upgrade_path_prefix
            )
        },
    )?;

    let mut request = ConnectRequest::new(url);

    for (k, v) in &client_cfg.http_headers {
        request.headers.remove(k);
        request.headers.append(k, v.clone());
    }

    if let Some(auth) = &client_cfg.http_upgrade_credentials {
        request.headers.remove(AUTHORIZATION);
        request.headers.append(AUTHORIZATION, auth.clone());
    }

    super::super::insert_client_label(&mut request.headers, client_cfg.client_id.as_deref());

    if let Some(headers_file_path) = &client_cfg.http_headers_file {
        let (host_header, headers_file) = headers_from_file(headers_file_path);
        for (k, v) in headers_file {
            request.headers.remove(&k);
            request.headers.append(k, v);
        }
        // Unlike http1, there is no Host header: the authority lives in the request url.
        if let Some((_, val)) = host_header {
            debug!("ignoring Host header from the headers file, webtransport uses the url authority: {val:?}");
        }
    }

    request.headers.insert(
        super::super::VERSION_HEADER,
        HeaderValue::from_static(super::super::PROTOCOL_VERSION),
    );
    debug!("opening WebTransport session");
    Ok(request)
}

pub async fn connect(
    request_id: Uuid,
    client: &Client<impl crate::TokioExecutorRef>,
    dest_addr: &RemoteAddr,
) -> anyhow::Result<(WebTransportRead, WebTransportWrite, Parts)> {
    let client_cfg = &client.config;

    // The pool hands out an established webtransport session: QUIC handshake, HTTP/3 SETTINGS and
    // CONNECT are all already done, and with --connection-min-idle they happened before this tunnel
    // was even requested. The session is cloned rather than taken, so it stays in the pool and
    // every later tunnel multiplexes another stream over the same one.
    let session = {
        let pooled_cnx = match client.cnx_pool.get().await {
            Ok(cnx) => Ok(cnx),
            Err(err) => Err(anyhow!("failed to get a connection to the server from the pool: {err:?}")),
        }?;
        pooled_cnx
            .as_ref()
            .and_then(|cnx| cnx.as_ref().right())
            .cloned()
            .ok_or_else(|| anyhow!("the connection pool did not return a webtransport session for a wts:// server"))?
    };

    let (mut send, mut recv) = session
        .open_bi()
        .await
        .with_context(|| format!("failed to open a webtransport stream with {:?}", client_cfg.remote_addr))?;

    // The session-level CONNECT is shared by every tunnel on this session, so it cannot carry the
    // destination. Each stream announces its own with a JWT preamble instead, which the server
    // reads before it opens anything upstream.
    let jwt = tunnel_to_jwt_token(request_id, dest_addr);
    write_jwt_preamble(&mut send, &jwt)
        .await
        .with_context(|| format!("failed to send the tunnel jwt to {:?}", client_cfg.remote_addr))?;

    let acknowledgement = read_jwt_preamble(&mut recv);
    let jwt = if dest_addr.protocol.is_reverse_tunnel() {
        acknowledgement.await?
    } else {
        match tokio::time::timeout(client_cfg.timeout_connect, acknowledgement).await {
            Ok(result) => result?,
            Err(err) => {
                session.close(504, b"tunnel acknowledgement timed out");
                return Err(err).with_context(|| "timed out waiting for the v2 server acknowledgement");
            }
        }
    };
    let remote = crate::tunnel::transport::jwt_token_to_tunnel(&jwt)?;
    RemoteAddr::try_from(remote.claims)?;
    let mut response = Response::new(());
    if dest_addr.protocol.is_dynamic_reverse_tunnel() {
        response.headers_mut().insert(COOKIE, HeaderValue::from_str(&jwt)?);
    }
    let response = response.into_parts().0;

    Ok((
        WebTransportRead::new(recv, session.clone()),
        WebTransportWrite::new(send, session),
        response,
    ))
}
