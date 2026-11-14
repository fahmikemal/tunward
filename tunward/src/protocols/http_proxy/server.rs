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
use std::io::{self, IoSlice};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll, ready};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf, ReadHalf, WriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::JoinSet;
use tracing::{info, warn};
use url::Host;

pub struct HttpProxyRead {
    inner: ReadHalf<DuplexStream>,
    cancelled: watch::Receiver<bool>,
}

impl AsyncRead for HttpProxyRead {
    fn poll_read(self: Pin<&mut Self>, cx: &mut TaskContext<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl crate::tunnel::downstream_listeners::DownstreamRead for HttpProxyRead {
    async fn cancelled(self: Pin<&mut Self>) -> io::Error {
        let signal = &mut self.get_mut().cancelled;
        loop {
            if *signal.borrow_and_update() {
                return io::Error::new(io::ErrorKind::ConnectionAborted, "HTTP proxy connection failed");
            }
            if signal.changed().await.is_err() {
                // A normally completed HTTP connection is not an abort. Buffered reply
                // data must still drain through the bridge after directional EOF.
                return std::future::pending().await;
            }
        }
    }
}

// Share readiness without duplicating the descriptor or spawning a monitor task.
// Hyper owns the I/O handle; its connection/upgrade task watches ERROR independently
// of HTTP body flow control and a full duplex bridge.
struct ProxySocket(Arc<TcpStream>);

impl AsyncRead for ProxySocket {
    fn poll_read(self: Pin<&mut Self>, cx: &mut TaskContext<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        loop {
            ready!(self.0.poll_read_ready(cx))?;
            match self.0.try_read(buf.initialize_unfilled()) {
                Ok(count) => {
                    buf.advance(count);
                    return Poll::Ready(Ok(()));
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
                Err(error) => return Poll::Ready(Err(error)),
            }
        }
    }
}

impl AsyncWrite for ProxySocket {
    fn poll_write(self: Pin<&mut Self>, cx: &mut TaskContext<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        loop {
            ready!(self.0.poll_write_ready(cx))?;
            match self.0.try_write(buf) {
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
                result => return Poll::Ready(result),
            }
        }
    }
    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        loop {
            ready!(self.0.poll_write_ready(cx))?;
            match self.0.try_write_vectored(bufs) {
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
                result => return Poll::Ready(result),
            }
        }
    }
    fn is_write_vectored(&self) -> bool {
        true
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(socket2::SockRef::from(self.0.as_ref()).shutdown(std::net::Shutdown::Write))
    }
}

async fn socket_failure(socket: &TcpStream) -> io::Error {
    match socket.ready(tokio::io::Interest::ERROR).await {
        Err(error) => error,
        Ok(_) => socket
            .take_error()
            .unwrap_or_else(Some)
            .unwrap_or_else(|| io::Error::new(io::ErrorKind::ConnectionAborted, "HTTP proxy socket failed")),
    }
}

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
    local_addr: SocketAddr,
}
impl HttpProxyListener {
    /// The address the proxy is bound to, with the port the OS picked for a port-0 bind.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }
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
    socket: Arc<TcpStream>,
    cancellation: watch::Sender<bool>,
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
    let Some((host, port)) = destination(req.uri(), is_connect) else {
        return Ok(response(StatusCode::BAD_REQUEST));
    };
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
            HttpProxyRead {
                inner: reader,
                cancelled: cancellation.subscribe(),
            },
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
                let result = tokio::select! {
                    result = tokio::io::copy_bidirectional(&mut downstream, &mut upstream) => result.map(|_| ()),
                    error = socket_failure(&socket) => Err(error),
                };
                if result.is_err() {
                    cancellation.send_replace(true);
                }
            } else {
                cancellation.send_replace(true);
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
    let driver_cancellation = cancellation.clone();
    tokio::spawn(async move {
        let _permit = permit;
        if connection.await.is_err() {
            driver_cancellation.send_replace(true);
        }
    });
    let mut result = match sender.send_request(req).await {
        Ok(response) => response,
        Err(error) => {
            cancellation.send_replace(true);
            return Err(error.into());
        }
    };
    strip_hop_headers(result.headers_mut());
    Ok(result.map(BodyExt::boxed))
}

/// The host and port a proxy request names, or `None` when it names no reachable destination.
pub(crate) fn destination(uri: &Uri, is_connect: bool) -> Option<(Host, u16)> {
    // `Uri::host` keeps the brackets of an IPv6 literal, which is the form `Host::parse` expects.
    let host = Host::parse(uri.host()?).ok()?;
    let port = uri.port_u16().unwrap_or(if is_connect { 443 } else { 80 });
    (port != 0).then_some((host, port))
}

pub async fn run_server(
    bind: SocketAddr,
    timeout: Option<Duration>,
    credentials: Option<(String, String)>,
) -> anyhow::Result<HttpProxyListener> {
    let listener = TcpListener::bind(bind)
        .await
        .with_context(|| format!("Cannot create HTTP proxy {bind}"))?;
    let local_addr = listener.local_addr()?;
    info!(
        "Starting HTTP proxy on {} (authentication: {})",
        local_addr,
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
                                    let socket = Arc::new(socket);
                                    let (cancellation, _) = watch::channel(false);
                                    let request_cancellation = cancellation.clone();
                                    let request_socket = socket.clone();
                                    let mut builder = hyper::server::conn::http1::Builder::new();
                                    builder.timer(TokioTimer::new()).header_read_timeout(Some(timeout.unwrap_or(Duration::from_secs(10)).min(Duration::from_secs(10))))
                                        .max_buf_size(32 * 1024).half_close(true);
                                    let service = service_fn(move |req| handle_request(req, auth.clone(), tx.clone(), permits.clone(), request_socket.clone(), request_cancellation.clone()));
                                    let result = tokio::select! {
                                        result = builder.serve_connection(TokioIo::new(ProxySocket(socket.clone())), service).with_upgrades() => result.map_err(anyhow::Error::from),
                                        error = socket_failure(&socket) => Err(error.into()),
                                    };
                                    if let Err(err) = result {
                                        cancellation.send_replace(true);
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
        local_addr,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tunnel::downstream_listeners::{DownstreamRead, DownstreamWrite};
    use futures_util::StreamExt;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn connect_reply(application: &mut tokio::net::TcpStream) {
        let mut header = Vec::new();
        while !header.ends_with(b"\r\n\r\n") {
            assert!(header.len() < 4096);
            header.push(application.read_u8().await.unwrap());
        }
        assert!(header.starts_with(b"HTTP/1.1 200 "));
    }

    #[tokio::test]
    async fn connect_reset_cancels_a_full_proxy_bridge() {
        let mut proxy = run_server("127.0.0.1:0".parse().unwrap(), None, None).await.unwrap();
        let mut application = tokio::net::TcpStream::connect(proxy.local_addr()).await.unwrap();
        application
            .write_all(b"CONNECT 127.0.0.1:80 HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();
        let ((mut reader, mut writer), _) = tokio::time::timeout(Duration::from_secs(2), proxy.listener.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        writer.on_tunnel_ready(Ok(())).await.unwrap();
        tokio::time::timeout(Duration::from_secs(2), connect_reply(&mut application))
            .await
            .unwrap();
        socket2::SockRef::from(&application)
            .set_send_buffer_size(65536)
            .unwrap();
        let payload = vec![42; 32 * 1024 * 1024];
        let mut uploading = Box::pin(application.write_all(&payload));
        let mut first = [0];
        tokio::select! {
            result = &mut uploading => panic!("upload unexpectedly completed before the bridge was drained: {result:?}"),
            result = reader.read_exact(&mut first) => { result.unwrap(); },
            _ = tokio::time::sleep(Duration::from_secs(2)) => panic!("CONNECT payload did not reach the bridge"),
        }
        assert_eq!(first, [42]);
        assert!(
            tokio::time::timeout(Duration::from_millis(200), &mut uploading)
                .await
                .is_err()
        );
        drop(uploading);
        socket2::SockRef::from(&application)
            .set_linger(Some(Duration::ZERO))
            .unwrap();
        drop(application);
        let error = tokio::time::timeout(Duration::from_secs(2), Pin::new(&mut reader).cancelled())
            .await
            .expect("a local TCP reset must cancel a backpressured HTTP bridge");
        assert_eq!(error.kind(), io::ErrorKind::ConnectionAborted);
    }

    #[tokio::test]
    async fn connect_preserves_buffered_payload_and_half_close_reply() {
        let mut proxy = run_server("127.0.0.1:0".parse().unwrap(), None, None).await.unwrap();
        let mut application = tokio::net::TcpStream::connect(proxy.local_addr()).await.unwrap();
        application
            .write_all(b"CONNECT 127.0.0.1:80 HTTP/1.1\r\nHost: localhost\r\n\r\nearly payload")
            .await
            .unwrap();
        let ((mut reader, mut writer), _) = tokio::time::timeout(Duration::from_secs(2), proxy.listener.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        writer.on_tunnel_ready(Ok(())).await.unwrap();
        tokio::time::timeout(Duration::from_secs(2), connect_reply(&mut application))
            .await
            .unwrap();
        application.shutdown().await.unwrap();
        let mut received = Vec::new();
        tokio::time::timeout(Duration::from_secs(2), reader.read_to_end(&mut received))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(received, b"early payload");
        writer.write_all(b"late reply").await.unwrap();
        writer.shutdown().await.unwrap();
        let mut reply = Vec::new();
        tokio::time::timeout(Duration::from_secs(2), application.read_to_end(&mut reply))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(reply, b"late reply");
    }

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
    fn requests_name_ip_literals_and_domains() {
        let named = |uri: &str, is_connect| destination(&uri.parse().unwrap(), is_connect);
        assert_eq!(
            named("127.0.0.1:22", true),
            Some((Host::Ipv4(std::net::Ipv4Addr::LOCALHOST), 22))
        );
        assert_eq!(named("[::1]:22", true), Some((Host::Ipv6(std::net::Ipv6Addr::LOCALHOST), 22)));
        let mapped = std::net::Ipv4Addr::LOCALHOST.to_ipv6_mapped();
        assert_eq!(named("[::ffff:127.0.0.1]:22", true), Some((Host::Ipv6(mapped), 22)));
        assert_eq!(
            named("http://[2001:db8::1]/index.html", false),
            Some((Host::Ipv6("2001:db8::1".parse().unwrap()), 80))
        );
        assert_eq!(
            named("example.com", true),
            Some((Host::Domain("example.com".to_string()), 443)),
            "CONNECT defaults to 443"
        );
        assert_eq!(named("/index.html", false), None, "a request must name its destination");
        assert_eq!(
            named("http://example.com/", false),
            Some((Host::Domain("example.com".to_string()), 80))
        );
        assert_eq!(named("127.0.0.1:0", true), None, "port 0 is no destination");
    }

    #[test]
    fn authentication_challenge_is_a_proxy_challenge() {
        let response = response(StatusCode::PROXY_AUTHENTICATION_REQUIRED);
        assert_eq!(response.status(), StatusCode::PROXY_AUTHENTICATION_REQUIRED);
        assert_eq!(response.headers()[PROXY_AUTHENTICATE], "Basic realm=\"tunward\"");
    }
}
