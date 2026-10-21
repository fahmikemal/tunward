use super::server::{ConnectionContext, EstablishedTunnel};
use crate::executor::TokioExecutorRef;
use crate::restrictions::types::RestrictionsRules;
use crate::tunnel::server::Server;
use crate::tunnel::server::utils::{HttpResponse, bad_request, inject_cookie};
use crate::tunnel::transport;
use crate::tunnel::transport::websocket::mk_websocket_tunnel;
use fastwebsockets::Role;
use http_body_util::Either;
use http_body_util::combinators::BoxBody;
use hyper::body::Incoming;
use hyper::header::{HeaderName, HeaderValue, SEC_WEBSOCKET_PROTOCOL};
use hyper::{Request, Response};
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::{Instrument, Span, error, warn};

pub(super) async fn ws_server_upgrade(
    server: Server<impl TokioExecutorRef>,
    restrictions: Arc<RestrictionsRules>,
    restrict_path_prefix: ConnectionContext,
    client_addr: SocketAddr,
    mut req: Request<Incoming>,
) -> HttpResponse {
    let revocation = restrict_path_prefix.revocation.clone();
    let quota = match restrict_path_prefix.admit_tunnel() {
        Ok(permit) => permit,
        Err(err) => return *super::utils::quota_rejection(err),
    };
    if !fastwebsockets::upgrade::is_upgrade_request(&req) {
        warn!("Rejecting connection with bad upgrade request: {}", req.uri());
        return bad_request();
    }

    let mask_frame = server.config.websocket_mask_frame;
    let EstablishedTunnel {
        remote_addr,
        local_rx,
        local_tx,
        need_cookie,
        quota,
        fleet,
    } = match server
        .handle_tunnel_request(restrictions, restrict_path_prefix, client_addr, &req, quota)
        .await
    {
        Ok(ret) => ret,
        Err(err) => {
            return *err;
        }
    };

    let (response, fut) = match fastwebsockets::upgrade::upgrade(&mut req) {
        Ok(ret) => ret,
        Err(err) => {
            warn!("Rejecting connection with bad upgrade request: {} {}", err, req.uri());
            return bad_request();
        }
    };

    server.executor.spawn(
        async move {
            let _fleet = fleet;
            revocation
                .run(async move {
                    let (ws_rx, ws_tx) = match fut.await {
                        Ok(ws) => match mk_websocket_tunnel(ws, Role::Server, mask_frame) {
                            Ok(ws) => ws,
                            Err(err) => {
                                error!("Error during http upgrade request: {:?}", err);
                                return Err(err);
                            }
                        },
                        Err(err) => {
                            error!("Error during http upgrade request: {:?}", err);
                            return Err(anyhow::Error::from(err));
                        }
                    };
                    let _ = transport::io::forward_with_quota(
                        local_rx,
                        local_tx,
                        ws_rx,
                        ws_tx,
                        server.config.websocket_ping_frequency,
                        quota,
                    )
                    .await;
                    Ok(())
                })
                .await
        }
        .instrument(Span::current()),
    );

    let mut response = Response::from_parts(response.into_parts().0, Either::Right(BoxBody::default()));
    if need_cookie && inject_cookie(&mut response, &remote_addr).is_err() {
        return bad_request();
    }

    if remote_addr.port != 0 {
        response
            .headers_mut()
            .insert(HeaderName::from_static("x-assigned-port"), HeaderValue::from(remote_addr.port));
    }

    response
        .headers_mut()
        .insert(SEC_WEBSOCKET_PROTOCOL, HeaderValue::from_static("v2"));
    response
        .headers_mut()
        .insert(transport::VERSION_HEADER, HeaderValue::from_static(transport::PROTOCOL_VERSION));

    response
}
