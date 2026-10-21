use anyhow::{Context, anyhow};
use base64::Engine;
use bytes::Bytes;
use futures_util::{Stream, stream};
use http_body_util::{BodyExt, Empty, combinators::BoxBody};
use hyper::body::Incoming;
use hyper::header::{CONNECTION, HOST, PROXY_AUTHENTICATE, PROXY_AUTHORIZATION};
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode, Uri};
use hyper_util::rt::{TokioIo, TokioTimer};
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;
use tokio::io::{AsyncWrite, DuplexStream, ReadHalf, WriteHalf};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinSet;
use tracing::{info, warn};
use url::Host;

pub type HttpProxyRead = ReadHalf<DuplexStream>;
pub struct HttpProxyWrite {
    inner: WriteHalf<DuplexStream>,
    ready: Option<oneshot::Sender<bool>>,
}

impl crate::tunnel::downstream_listeners::DownstreamWrite for HttpProxyWrite {
    async fn on_tunnel_ready(&mut self, result: Result<(), &anyhow::Error>) -> io::Result<()> {
        if let Some(tx) = self.ready.take() {
            let _ = tx.send(result.is_ok());
        }
        Ok(())
    }
}

impl AsyncWrite for HttpProxyWrite {
    fn poll_write(self: Pin<&mut Self>, cx: &mut TaskContext<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

type Connection = ((HttpProxyRead, HttpProxyWrite), (Host, u16));
type Accepted = anyhow::Result<Connection>;
type ProxyBody = BoxBody<Bytes, hyper::Error>;

pub struct HttpProxyListener {
    listener: Pin<Box<dyn Stream<Item = Accepted> + Send>>,
}
impl Stream for HttpProxyListener {
    type Item = Accepted;
    fn poll_next(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<Option<Self::Item>> {
        self.get_mut().listener.as_mut().poll_next(cx)
    }
}

fn response(status: StatusCode) -> Response<ProxyBody> {
    let mut response = Response::new(Empty::<Bytes>::new().map_err(|never| match never {}).boxed());
    *response.status_mut() = status;
    if status == StatusCode::PROXY_AUTHENTICATION_REQUIRED {
        response.headers_mut().insert(
            PROXY_AUTHENTICATE,
            hyper::header::HeaderValue::from_static("Basic realm=\"tunward\""),
        );
    }
    response
}

fn strip_hop_headers(headers: &mut hyper::HeaderMap) {
    let named: Vec<_> = headers
        .get_all(CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .filter_map(|name| hyper::header::HeaderName::from_bytes(name.trim().as_bytes()).ok())
        .collect();
    for name in named {
        headers.remove(name);
    }
    for name in [
        "connection",
        "proxy-connection",
        "proxy-authorization",
        "proxy-authenticate",
        "keep-alive",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    ] {
        headers.remove(name);
    }
}

async fn handle_request(
    mut req: Request<Incoming>,
    auth: Option<String>,
    tx: mpsc::Sender<Accepted>,
    tasks: Arc<tokio::sync::Semaphore>,
) -> Result<Response<ProxyBody>, anyhow::Error> {
    let permit = match tasks.try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => return Ok(response(StatusCode::SERVICE_UNAVAILABLE)),
    };
    if let Some(expected) = auth {
        let supplied = req.headers().get(PROXY_AUTHORIZATION).and_then(|v| v.to_str().ok());
        if supplied != Some(expected.as_str()) {
            return Ok(response(StatusCode::PROXY_AUTHENTICATION_REQUIRED));
        }
    }
    let is_connect = req.method() == Method::CONNECT;
    if !is_connect && req.uri().scheme_str() != Some("http") {
        return Ok(response(StatusCode::BAD_REQUEST));
    }
    let Some(host) = req
        .uri()
        .host()
        .and_then(|h| Host::parse(h.trim_matches(['[', ']'])).ok())
    else {
        return Ok(response(StatusCode::BAD_REQUEST));
    };
    let port = req.uri().port_u16().unwrap_or(if is_connect { 443 } else { 80 });
    if port == 0 {
        return Ok(response(StatusCode::BAD_REQUEST));
    }
    let authority = req
        .uri()
        .authority()
        .ok_or_else(|| anyhow!("missing proxy authority"))?
        .clone();
    let (upstream, bridge) = tokio::io::duplex(64 * 1024);
    let (reader, writer) = tokio::io::split(bridge);
    let (ready_tx, ready_rx) = oneshot::channel();
    tx.send(Ok((
        (
            reader,
            HttpProxyWrite {
                inner: writer,
                ready: Some(ready_tx),
            },
        ),
        (host, port),
    )))
    .await
    .map_err(|_| anyhow!("proxy listener closed"))?;
    if !tokio::time::timeout(Duration::from_secs(30), ready_rx)
        .await
        .ok()
        .and_then(Result::ok)
        .unwrap_or(false)
    {
        return Ok(response(StatusCode::BAD_GATEWAY));
    }
    if is_connect {
        let upgrade = hyper::upgrade::on(&mut req);
        tokio::spawn(async move {
            let _permit = permit;
            if let Ok(upgraded) = upgrade.await {
                let mut downstream = TokioIo::new(upgraded);
                let mut upstream = upstream;
                let _ = tokio::io::copy_bidirectional(&mut downstream, &mut upstream).await;
            }
        });
        return Ok(response(StatusCode::OK));
    }
    strip_hop_headers(req.headers_mut());
    req.headers_mut()
        .insert(HOST, hyper::header::HeaderValue::from_str(authority.as_str())?);
    req.headers_mut()
        .insert(CONNECTION, hyper::header::HeaderValue::from_static("close"));
    *req.uri_mut() = Uri::builder()
        .path_and_query(req.uri().path_and_query().map_or("/", |p| p.as_str()))
        .build()?;
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(upstream)).await?;
    tokio::spawn(async move {
        let _permit = permit;
        let _ = connection.await;
    });
    let mut result = sender.send_request(req).await?;
    strip_hop_headers(result.headers_mut());
    Ok(result.map(BodyExt::boxed))
}

pub async fn run_server(
    bind: SocketAddr,
    timeout: Option<Duration>,
    credentials: Option<(String, String)>,
) -> anyhow::Result<HttpProxyListener> {
    let listener = TcpListener::bind(bind)
        .await
        .with_context(|| format!("Cannot create HTTP proxy {bind}"))?;
    info!(
        "Starting HTTP proxy on {} (authentication: {})",
        listener.local_addr()?,
        credentials.is_some()
    );
    let auth = credentials.map(|(user, pass)| {
        format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(format!("{user}:{pass}"))
        )
    });
    let (tx, rx) = mpsc::channel(64);
    let permits = Arc::new(tokio::sync::Semaphore::new(256));
    let stream = stream::unfold(
        (listener, JoinSet::new(), tx, rx, auth, permits),
        move |(listener, mut tasks, tx, mut rx, auth, permits)| async move {
            loop {
                tokio::select! {
                    item = rx.recv() => return item.map(|item| (item, (listener, tasks, tx, rx, auth, permits))),
                    _ = tasks.join_next(), if !tasks.is_empty() => {},
                    accepted = listener.accept(), if tasks.len() < 256 => {
                        match accepted {
                            Ok((socket, _)) => {
                                let auth = auth.clone(); let tx = tx.clone(); let permits = permits.clone();
                                tasks.spawn(async move {
                                    let mut builder = hyper::server::conn::http1::Builder::new();
                                    builder.timer(TokioTimer::new()).header_read_timeout(Some(timeout.unwrap_or(Duration::from_secs(10)).min(Duration::from_secs(10))))
                                        .max_buf_size(32 * 1024).half_close(true);
                                    let service = service_fn(move |req| handle_request(req, auth.clone(), tx.clone(), permits.clone()));
                                    if let Err(err) = builder.serve_connection(TokioIo::new(socket), service).with_upgrades().await {
                                        warn!("HTTP proxy connection ended: {err}");
                                    }
                                });
                            },
                            Err(err) => return Some((Err(err.into()), (listener, tasks, tx, rx, auth, permits))),
                        }
                    },
                }
            }
        },
    );
    Ok(HttpProxyListener {
        listener: Box::pin(stream),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn consumes_proxy_credentials_and_connection_named_headers() {
        let mut headers = hyper::HeaderMap::new();
        headers.insert(PROXY_AUTHORIZATION, "Basic synthetic".parse().unwrap());
        headers.insert(CONNECTION, "keep-alive, x-private".parse().unwrap());
        headers.insert("x-private", "private".parse().unwrap());
        headers.insert("content-length", "100".parse().unwrap());
        headers.insert("authorization", "Bearer origin".parse().unwrap());
        strip_hop_headers(&mut headers);
        assert!(!headers.contains_key(PROXY_AUTHORIZATION));
        assert!(!headers.contains_key(CONNECTION));
        assert!(!headers.contains_key("x-private"));
        assert_eq!(headers["content-length"], "100");
        assert_eq!(headers["authorization"], "Bearer origin");
    }

    #[test]
    fn authentication_challenge_is_a_proxy_challenge() {
        let response = response(StatusCode::PROXY_AUTHENTICATION_REQUIRED);
        assert_eq!(response.status(), StatusCode::PROXY_AUTHENTICATION_REQUIRED);
        assert_eq!(response.headers()[PROXY_AUTHENTICATE], "Basic realm=\"tunward\"");
    }
}
