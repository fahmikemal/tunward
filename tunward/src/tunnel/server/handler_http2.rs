use super::server::{ConnectionContext, EstablishedTunnel};
use crate::executor::TokioExecutorRef;
use crate::restrictions::types::RestrictionsRules;
use crate::tunnel::server::Server;
use crate::tunnel::server::utils::{HttpResponse, bad_request, inject_cookie};
use crate::tunnel::transport;
use crate::tunnel::transport::http2::{Http2TransportRead, Http2TransportWrite};
use bytes::Bytes;
use futures_util::StreamExt;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyStream, Either, StreamBody};
use hyper::body::{Frame, Incoming};
use hyper::header::CONTENT_TYPE;
use hyper::{Request, Response, StatusCode};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tracing::{Instrument, Span};

pub(super) async fn http_server_upgrade(
    server: Server<impl TokioExecutorRef>,
    restrictions: Arc<RestrictionsRules>,
    restrict_path_prefix: ConnectionContext,
    client_addr: SocketAddr,
    mut req: Request<Incoming>,
) -> HttpResponse {
    let revocation = restrict_path_prefix.revocation.clone();
    let EstablishedTunnel {
        remote_addr,
        local_rx,
        local_tx,
        need_cookie,
        quota,
        fleet,
    } = match server
        .handle_tunnel_request(restrictions, restrict_path_prefix, client_addr, &req, None)
        .await
    {
        Ok(ret) => ret,
        Err(err) => return *err,
    };

    let req_content_type = req.headers_mut().remove(CONTENT_TYPE);
    let ws_rx = BodyStream::new(req.into_body());
    let (ws_tx, rx) = mpsc::channel::<Bytes>(8);
    let body = BoxBody::new(StreamBody::new(
        ReceiverStream::new(rx).map(|s| -> anyhow::Result<Frame<Bytes>> { Ok(Frame::data(s)) }),
    ));

    let mut response = Response::builder()
        .status(StatusCode::OK)
        .body(Either::Right(body))
        .expect("bug: failed to build response");

    server.executor.spawn(
        async move {
            let _fleet = fleet;
            revocation
                .run(transport::io::forward_with_quota(
                    local_rx,
                    local_tx,
                    Http2TransportRead::new(ws_rx, None),
                    Http2TransportWrite::new(ws_tx),
                    None,
                    quota,
                ))
                .await
        }
        .instrument(Span::current()),
    );

    if need_cookie && inject_cookie(&mut response, &remote_addr).is_err() {
        return bad_request();
    }

    if let Some(content_type) = req_content_type {
        response.headers_mut().insert(CONTENT_TYPE, content_type);
    }

    response.headers_mut().insert(
        transport::VERSION_HEADER,
        hyper::header::HeaderValue::from_static(transport::PROTOCOL_VERSION),
    );
    response
}
