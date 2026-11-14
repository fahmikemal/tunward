use super::io::{MAX_RECORD_LENGTH, TransportRead, TransportWrite};
use crate::tunnel::RemoteAddr;
use crate::tunnel::client::Client;
use crate::tunnel::client::connection_pool::{L4ReadHalf, L4Stream, L4WriteHalf};
use crate::tunnel::transport::headers_from_file;
use crate::tunnel::transport::jwt::{JWT_HEADER_PREFIX, TunnelRequest, tunnel_to_jwt_token};
use anyhow::{Context, anyhow};
use bytes::{Bytes, BytesMut};
use either::Either;
use fastwebsockets::{CloseCode, Frame, OpCode, Payload, Role, WebSocket, WebSocketRead, WebSocketWrite};
use http_body_util::Empty;
use hyper::Request;
use hyper::header::{AUTHORIZATION, SEC_WEBSOCKET_PROTOCOL, SEC_WEBSOCKET_VERSION, UPGRADE};
use hyper::header::{CONNECTION, HOST, SEC_WEBSOCKET_KEY};
use hyper::http::response::Parts;
use hyper::upgrade::Upgraded;
use hyper_util::rt::TokioExecutor;
use hyper_util::rt::TokioIo;
use log::debug;
use std::io;
use std::io::ErrorKind;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering::Relaxed;
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Notify;
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio_rustls::server::TlsStream;
use tracing::trace;

pub struct WebsocketTransportWrite {
    inner: WebSocketWrite<L4WriteHalf>,
    buf: BytesMut,
    pending_operations: Receiver<Frame<'static>>,
    pending_ops_notify: Arc<Notify>,
    in_flight_ping: Arc<AtomicUsize>,
}

impl WebsocketTransportWrite {
    pub fn new(
        ws: WebSocketWrite<L4WriteHalf>,
        (pending_operations, notify): (Receiver<Frame<'static>>, Arc<Notify>),
        in_flight_ping: Arc<AtomicUsize>,
    ) -> Self {
        Self {
            inner: ws,
            buf: BytesMut::with_capacity(MAX_RECORD_LENGTH),
            pending_operations,
            pending_ops_notify: notify,
            in_flight_ping,
        }
    }
}

impl TransportWrite for WebsocketTransportWrite {
    fn buf_mut(&mut self) -> &mut BytesMut {
        &mut self.buf
    }

    async fn write(&mut self) -> Result<(), io::Error> {
        let read_len = self.buf.len();
        let buf = &mut self.buf;

        let ret = self
            .inner
            .write_frame(Frame::binary(Payload::BorrowedMut(&mut buf[..read_len])))
            .await;

        if let Err(err) = ret {
            return Err(io::Error::new(ErrorKind::ConnectionAborted, err));
        }

        // It is needed to call poll_flush to ensure that the data is written to the underlying stream.
        // In case of a TLS stream, it may still be buffered in the TLS layer if not flushed.
        // https://docs.rs/tokio-rustls/latest/tokio_rustls/#why-do-i-need-to-call-poll_flush
        if let Err(err) = self.inner.flush().await {
            return Err(io::Error::new(ErrorKind::ConnectionAborted, err));
        }

        // Each write carries one bounded v2 record. Keep room for its header as well as the
        // maximum payload, and reuse it instead of growing an adaptive stream-sized buffer.
        buf.clear();

        Ok(())
    }

    async fn ping(&mut self) -> Result<(), io::Error> {
        if self.in_flight_ping.fetch_add(1, Relaxed) >= 3 {
            return Err(io::Error::new(
                ErrorKind::ConnectionAborted,
                "too many in flight/un-answered pings",
            ));
        }

        if let Err(err) = self
            .inner
            .write_frame(Frame::new(true, OpCode::Ping, None, Payload::BorrowedMut(&mut [])))
            .await
        {
            return Err(io::Error::new(ErrorKind::BrokenPipe, err));
        }

        self.inner.flush().await.map_err(io::Error::other)
    }

    async fn close(&mut self) -> Result<(), io::Error> {
        if let Err(err) = self.inner.write_frame(Frame::close(1000, &[])).await {
            return Err(io::Error::new(ErrorKind::BrokenPipe, err));
        }

        self.inner.flush().await.map_err(io::Error::other)
    }

    fn pending_operations_notify(&mut self) -> Arc<Notify> {
        self.pending_ops_notify.clone()
    }

    async fn handle_pending_operations(&mut self) -> Result<(), io::Error> {
        while let Ok(frame) = self.pending_operations.try_recv() {
            debug!("received frame {:?}", frame.opcode);
            match frame.opcode {
                OpCode::Close => {
                    if self.inner.write_frame(frame).await.is_err() {
                        return Err(io::Error::new(ErrorKind::ConnectionAborted, "cannot send close frame"));
                    }
                }
                OpCode::Ping => {
                    debug!("sending pong frame");
                    if self.inner.write_frame(Frame::pong(frame.payload)).await.is_err() {
                        return Err(io::Error::new(ErrorKind::ConnectionAborted, "cannot send pong frame"));
                    }
                }
                OpCode::Pong => {
                    debug!("received pong frame");
                    self.in_flight_ping.store(0, Relaxed);
                }
                OpCode::Continuation | OpCode::Text | OpCode::Binary => unreachable!(),
            }
        }

        self.inner.flush().await.map_err(io::Error::other)
    }
}

pub struct WebsocketTransportRead {
    inner: WebSocketRead<L4ReadHalf>,
    pending_operations: Sender<Frame<'static>>,
    notify_pending_ops: Arc<Notify>,
    in_flight_ping: Arc<AtomicUsize>,
}

impl WebsocketTransportRead {
    pub fn new(
        ws: WebSocketRead<L4ReadHalf>,
        in_flight_ping: Arc<AtomicUsize>,
    ) -> (Self, (Receiver<Frame<'static>>, Arc<Notify>)) {
        let (tx, rx) = tokio::sync::mpsc::channel(10);
        let notify = Arc::new(Notify::new());
        (
            Self {
                inner: ws,
                pending_operations: tx,
                notify_pending_ops: notify.clone(),
                in_flight_ping,
            },
            (rx, notify),
        )
    }
}

fn frame_reader(_: Frame<'_>) -> futures_util::future::Ready<anyhow::Result<()>> {
    //error!("frame {:?} {:?}", x.opcode, x.payload);
    futures_util::future::ready(anyhow::Ok(()))
}

impl TransportRead for WebsocketTransportRead {
    async fn copy(&mut self, mut writer: impl AsyncWrite + Unpin + Send) -> Result<(), io::Error> {
        loop {
            let msg = match self.inner.read_frame(&mut frame_reader).await {
                Ok(msg) => msg,
                Err(err) => return Err(io::Error::new(ErrorKind::ConnectionAborted, err)),
            };

            trace!("received WebSocket {:?} frame ({} bytes)", msg.opcode, msg.payload.len());
            self.in_flight_ping.store(0, Relaxed);
            match msg.opcode {
                OpCode::Continuation | OpCode::Text | OpCode::Binary => {
                    return match writer.write_all(msg.payload.as_ref()).await {
                        Ok(_) => Ok(()),
                        Err(err) => Err(io::Error::new(ErrorKind::ConnectionAborted, err)),
                    };
                }
                OpCode::Close => {
                    // A congested writer may have filled the control queue. The close reply is
                    // best effort: waiting for room here would stop RX from cancelling forwarding.
                    let _ = self
                        .pending_operations
                        .try_send(Frame::close(CloseCode::Normal.into(), &[]));
                    self.notify_pending_ops.notify_one();
                    return Err(io::Error::new(ErrorKind::NotConnected, "websocket close"));
                }
                OpCode::Ping => {
                    match self.pending_operations.try_send(Frame::new(
                        true,
                        msg.opcode,
                        None,
                        Payload::Owned(msg.payload.to_owned()),
                    )) {
                        Ok(()) => {
                            self.notify_pending_ops.notify_one();
                        }
                        Err(TrySendError::Full(_)) => {
                            // Queue full due to TX write congestion; drop pong to avoid blocking RX
                        }
                        Err(TrySendError::Closed(_)) => {
                            return Err(io::Error::new(ErrorKind::ConnectionAborted, "cannot send ping"));
                        }
                    }
                }
                OpCode::Pong => {
                    match self.pending_operations.try_send(Frame::pong(Payload::Borrowed(&[]))) {
                        Ok(()) => {
                            self.notify_pending_ops.notify_one();
                        }
                        Err(TrySendError::Full(_)) => {
                            // Queue full; in_flight_ping is already reset by RX
                        }
                        Err(TrySendError::Closed(_)) => {
                            return Err(io::Error::new(ErrorKind::ConnectionAborted, "cannot send pong"));
                        }
                    }
                }
            };
        }
    }
}

pub async fn connect(
    request: TunnelRequest,
    client: &Client<impl crate::TokioExecutorRef>,
    dest_addr: &RemoteAddr,
) -> anyhow::Result<(WebsocketTransportRead, WebsocketTransportWrite, Parts)> {
    let client_cfg = &client.config;
    let mut pooled_cnx = match client.cnx_pool.get().await {
        Ok(cnx) => Ok(cnx),
        Err(err) => Err(anyhow!("failed to get a connection to the server from the pool: {err:?}")),
    }?;

    let mut req = Request::builder()
        .method("GET")
        .uri(format!("/{}/events", client_cfg.http_upgrade_path_prefix))
        .header(HOST, &client_cfg.http_header_host)
        .header(UPGRADE, "websocket")
        .header(CONNECTION, "upgrade")
        .header(SEC_WEBSOCKET_KEY, fastwebsockets::handshake::generate_key())
        .header(SEC_WEBSOCKET_VERSION, "13")
        .header(
            SEC_WEBSOCKET_PROTOCOL,
            format!("v2, {}{}", JWT_HEADER_PREFIX, tunnel_to_jwt_token(request, dest_addr)),
        )
        .version(hyper::Version::HTTP_11);

    let headers = match req.headers_mut() {
        Some(h) => h,
        None => {
            return Err(anyhow!(
                "failed to build HTTP request to contact the server {:?}. Most likely path_prefix `{}` or http headers is not valid",
                req.body(Empty::<Bytes>::new()),
                client_cfg.http_upgrade_path_prefix
            ));
        }
    };
    for (k, v) in &client_cfg.http_headers {
        let _ = headers.remove(k);
        headers.append(k, v.clone());
    }

    if let Some(auth) = &client_cfg.http_upgrade_credentials {
        let _ = headers.remove(AUTHORIZATION);
        headers.append(AUTHORIZATION, auth.clone());
    }

    super::insert_client_label(headers, client_cfg.client_id.as_deref());

    if let Some(headers_file_path) = &client_cfg.http_headers_file {
        let (host, headers_file) = headers_from_file(headers_file_path);
        for (k, v) in headers_file {
            let _ = headers.remove(&k);
            headers.append(k, v);
        }
        if let Some((host, val)) = host {
            let _ = headers.remove(&host);
            headers.append(host, val);
        }
    }

    let req = req.body(Empty::<Bytes>::new()).with_context(|| {
        format!(
            "failed to build HTTP request to contact the server {:?}",
            client_cfg.remote_addr
        )
    })?;
    debug!("opening WebSocket tunnel");
    let transport = pooled_cnx
        .take()
        .and_then(Either::left)
        .ok_or_else(|| anyhow!("the connection pool did not return a TCP stream"))?;

    let (ws, response) = fastwebsockets::handshake::client(&TokioExecutor::new(), req, transport)
        .await
        .with_context(|| format!("failed to do websocket handshake with the server {:?}", client_cfg.remote_addr))?;

    super::check_version(response.headers())?;
    let (ws_rx, ws_tx) = mk_websocket_tunnel(ws, Role::Client, client_cfg.websocket_mask_frame)?;
    Ok((ws_rx, ws_tx, response.into_parts().0))
}

pub fn mk_websocket_tunnel(
    ws: WebSocket<TokioIo<Upgraded>>,
    role: Role,
    mask_frame: bool,
) -> anyhow::Result<(WebsocketTransportRead, WebsocketTransportWrite)> {
    let mut ws = match role {
        Role::Client => {
            let stream = ws
                .into_inner()
                .into_inner()
                .downcast::<TokioIo<L4Stream>>()
                .map_err(|_| anyhow!("cannot downcast websocket client stream"))?;
            let transport = L4Stream::from(stream.io.into_inner(), stream.read_buf);
            WebSocket::after_handshake(transport, role)
        }
        Role::Server => {
            let upgraded = ws.into_inner().into_inner();
            match upgraded.downcast::<TokioIo<TlsStream<TcpStream>>>() {
                Ok(stream) => {
                    let transport = L4Stream::from_server_tls(stream.io.into_inner(), stream.read_buf);
                    WebSocket::after_handshake(transport, role)
                }
                Err(upgraded) => {
                    let stream = hyper_util::server::conn::auto::upgrade::downcast::<TokioIo<TcpStream>>(upgraded)
                        .map_err(|_| anyhow!("cannot downcast websocket server stream"))?;
                    let transport = L4Stream::from_tcp(stream.io.into_inner(), stream.read_buf);
                    WebSocket::after_handshake(transport, role)
                }
            }
        }
    };

    ws.set_auto_pong(false);
    ws.set_auto_close(false);
    ws.set_auto_apply_mask(mask_frame);
    let (ws_rx, ws_tx) = ws.split(|x| x.into_split());

    let in_flight_ping = Arc::new(AtomicUsize::new(0));
    let (ws_rx, pending_ops) = WebsocketTransportRead::new(ws_rx, in_flight_ping.clone());
    Ok((ws_rx, WebsocketTransportWrite::new(ws_tx, pending_ops, in_flight_ping)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tunnel::transport::io::MAX_PACKET_LENGTH;
    use std::time::Duration;
    use tokio::net::TcpListener;

    async fn connected_websockets() -> (WebSocket<TcpStream>, WebSocket<L4Stream>) {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let (client, (server, _)) =
            tokio::try_join!(TcpStream::connect(listener.local_addr().unwrap()), listener.accept(),).unwrap();
        let client = WebSocket::after_handshake(client, Role::Client);
        let mut server = WebSocket::after_handshake(L4Stream::from_tcp(server, Bytes::new()), Role::Server);
        server.set_auto_pong(false);
        server.set_auto_close(false);
        (client, server)
    }

    #[tokio::test]
    async fn peer_close_does_not_wait_for_a_saturated_control_queue() {
        let (mut peer, server) = connected_websockets().await;
        let (read, _) = server.split(|stream| stream.into_split());
        let (mut read, (pending, _)) = WebsocketTransportRead::new(read, Arc::new(AtomicUsize::new(0)));
        for _ in 0..pending.max_capacity() {
            peer.write_frame(Frame::new(true, OpCode::Ping, None, Payload::Borrowed(&[])))
                .await
                .unwrap();
        }
        peer.write_frame(Frame::close(1000, &[])).await.unwrap();
        peer.flush().await.unwrap();

        // Keep both the peer and the congested control receiver alive: neither EOF nor a dropped
        // queue may rescue a Close that incorrectly waits for the blocked sender to make room.
        let result = tokio::time::timeout(Duration::from_secs(1), read.copy(tokio::io::sink()))
            .await
            .expect("peer Close must stop receiving even while the control queue is full");
        assert_eq!(result.unwrap_err().kind(), ErrorKind::NotConnected);
        assert_eq!(pending.len(), pending.max_capacity());
    }

    #[tokio::test]
    async fn maximum_records_reuse_the_websocket_write_buffer() {
        use bytes::BufMut;
        let (mut peer, server) = connected_websockets().await;
        let (_, write) = server.split(|stream| stream.into_split());
        let (_control_tx, control_rx) = tokio::sync::mpsc::channel(10);
        let mut write =
            WebsocketTransportWrite::new(write, (control_rx, Arc::new(Notify::new())), Arc::new(AtomicUsize::new(0)));
        let initial_capacity = write.buf.capacity();
        let sending = async {
            for value in [17, 34] {
                let buf = write.buf_mut();
                buf.put_u8(0);
                buf.put_u32(MAX_PACKET_LENGTH as u32);
                buf.resize(MAX_PACKET_LENGTH + 5, value);
                write.write().await.unwrap();
                assert_eq!(
                    write.buf.capacity(),
                    initial_capacity,
                    "a full legal record must not grow the per-tunnel write buffer"
                );
            }
            write.buf_mut().extend_from_slice(&[1, 0, 0, 0, 0]);
            write.write().await.unwrap();
        };
        let receiving = async {
            for value in [17, 34] {
                let frame = peer.read_frame().await.unwrap();
                assert_eq!(frame.opcode, OpCode::Binary);
                assert_eq!(frame.payload.len(), MAX_PACKET_LENGTH + 5);
                assert_eq!(&frame.payload[..5], &[0, 0, 1, 0, 0]);
                assert!(frame.payload[5..].iter().all(|byte| *byte == value));
            }
            let fin = peer.read_frame().await.unwrap();
            assert_eq!(fin.payload.as_ref(), &[1, 0, 0, 0, 0]);
        };
        tokio::time::timeout(Duration::from_secs(2), async {
            tokio::join!(sending, receiving);
        })
        .await
        .unwrap();
    }
}
