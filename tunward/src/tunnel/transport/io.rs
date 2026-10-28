use crate::quotas::{BandwidthWait, RateLimiter, TunnelPermit};
use crate::tunnel::transport::http2::{Http2TransportRead, Http2TransportWrite};
use crate::tunnel::transport::websocket::{WebsocketTransportRead, WebsocketTransportWrite};
use crate::tunnel::transport::webtransport::{
    WebTransportRead, WebTransportUdpRead, WebTransportUdpWrite, WebTransportWrite,
};
use bytes::{BufMut, BytesMut};
use futures_util::pin_mut;
use std::future::Future;
use std::io::{self, ErrorKind};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, ready};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::select;
use tokio::sync::{Notify, oneshot};
use tokio::time::Instant;

pub(super) static MAX_PACKET_LENGTH: usize = 64 * 1024;

pub trait TransportWrite: Send + 'static {
    fn buf_mut(&mut self) -> &mut BytesMut;
    fn write(&mut self) -> impl Future<Output = Result<(), std::io::Error>> + Send;
    fn ping(&mut self) -> impl Future<Output = Result<(), std::io::Error>> + Send;
    fn close(&mut self) -> impl Future<Output = Result<(), std::io::Error>> + Send;
    fn pending_operations_notify(&mut self) -> Arc<Notify>;
    fn handle_pending_operations(&mut self) -> impl Future<Output = Result<(), std::io::Error>> + Send;
}

pub trait TransportRead: Send + 'static {
    fn copy(
        &mut self,
        writer: impl AsyncWrite + Unpin + Send,
    ) -> impl Future<Output = Result<(), std::io::Error>> + Send;

    fn finish(&mut self) -> impl Future<Output = Result<(), std::io::Error>> + Send {
        std::future::ready(Ok(()))
    }
}

pub enum TransportReader {
    Websocket(WebsocketTransportRead),
    Http2(Http2TransportRead),
    // Boxed: a quinn RecvStream plus the session handle is several times the size of the other
    // variants, and would otherwise inflate the enum for every tunnel.
    WebTransport(Box<WebTransportRead>),
    WebTransportUdp(Box<WebTransportUdpRead>),
}

impl TransportRead for TransportReader {
    async fn copy(&mut self, writer: impl AsyncWrite + Unpin + Send) -> Result<(), std::io::Error> {
        match self {
            Self::Websocket(s) => s.copy(writer).await,
            Self::Http2(s) => s.copy(writer).await,
            Self::WebTransport(s) => s.copy(writer).await,
            Self::WebTransportUdp(s) => s.copy(writer).await,
        }
    }

    async fn finish(&mut self) -> io::Result<()> {
        match self {
            Self::Websocket(s) => s.finish().await,
            Self::Http2(s) => s.finish().await,
            Self::WebTransport(s) => s.finish().await,
            Self::WebTransportUdp(s) => s.finish().await,
        }
    }
}

pub enum TransportWriter {
    Websocket(WebsocketTransportWrite),
    Http2(Http2TransportWrite),
    // Boxed for the same reason as `TunnelReader::WebTransport`.
    WebTransport(Box<WebTransportWrite>),
    WebTransportUdp(Box<WebTransportUdpWrite>),
}

impl TransportWrite for TransportWriter {
    fn buf_mut(&mut self) -> &mut BytesMut {
        match self {
            Self::Websocket(s) => s.buf_mut(),
            Self::Http2(s) => s.buf_mut(),
            Self::WebTransport(s) => s.buf_mut(),
            Self::WebTransportUdp(s) => s.buf_mut(),
        }
    }

    async fn write(&mut self) -> Result<(), std::io::Error> {
        match self {
            Self::Websocket(s) => s.write().await,
            Self::Http2(s) => s.write().await,
            Self::WebTransport(s) => s.write().await,
            Self::WebTransportUdp(s) => s.write().await,
        }
    }

    async fn ping(&mut self) -> Result<(), std::io::Error> {
        match self {
            Self::Websocket(s) => s.ping().await,
            Self::Http2(s) => s.ping().await,
            Self::WebTransport(s) => s.ping().await,
            Self::WebTransportUdp(s) => s.ping().await,
        }
    }

    async fn close(&mut self) -> Result<(), std::io::Error> {
        match self {
            Self::Websocket(s) => s.close().await,
            Self::Http2(s) => s.close().await,
            Self::WebTransport(s) => s.close().await,
            Self::WebTransportUdp(s) => s.close().await,
        }
    }

    fn pending_operations_notify(&mut self) -> Arc<Notify> {
        match self {
            Self::Websocket(s) => s.pending_operations_notify(),
            Self::Http2(s) => s.pending_operations_notify(),
            Self::WebTransport(s) => s.pending_operations_notify(),
            Self::WebTransportUdp(s) => s.pending_operations_notify(),
        }
    }

    async fn handle_pending_operations(&mut self) -> Result<(), std::io::Error> {
        match self {
            Self::Websocket(s) => s.handle_pending_operations().await,
            Self::Http2(s) => s.handle_pending_operations().await,
            Self::WebTransport(s) => s.handle_pending_operations().await,
            Self::WebTransportUdp(s) => s.handle_pending_operations().await,
        }
    }
}

// Protocol v2 records are independent of WebSocket, HTTP/2 DATA, and QUIC chunk boundaries.
const RECORD_HEADER_LEN: usize = 5;
const DATA: u8 = 0;
const FIN: u8 = 1;

struct RecordDecoder<W> {
    writer: W,
    header: [u8; RECORD_HEADER_LEN],
    header_used: usize,
    payload: BytesMut,
    payload_len: usize,
    written: usize,
    finished: bool,
    bandwidth: BandwidthWait,
    charged: bool,
}

impl<W: AsyncWrite + Unpin> RecordDecoder<W> {
    fn new(writer: W) -> Self {
        Self {
            writer,
            header: [0; RECORD_HEADER_LEN],
            header_used: 0,
            payload: BytesMut::new(),
            payload_len: 0,
            written: 0,
            finished: false,
            bandwidth: BandwidthWait::default(),
            charged: false,
        }
    }

    fn with_bandwidth(writer: W, limiter: Option<RateLimiter>) -> Self {
        let mut decoder = Self::new(writer);
        decoder.bandwidth = BandwidthWait::new(limiter);
        decoder
    }

    fn poll_payload(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.header_used == RECORD_HEADER_LEN && self.payload.len() == self.payload_len {
            if !self.charged && self.payload_len != 0 {
                ready!(self.bandwidth.poll_acquire(cx, self.payload_len));
                self.charged = true;
            }
            while self.written < self.payload.len() {
                let n = ready!(Pin::new(&mut self.writer).poll_write(cx, &self.payload[self.written..]))?;
                if n == 0 {
                    return Poll::Ready(Err(ErrorKind::WriteZero.into()));
                }
                self.written += n;
            }
            self.payload.clear();
            self.header_used = 0;
            self.written = 0;
            self.charged = false;
        }
        Poll::Ready(Ok(()))
    }
}

impl<W: AsyncWrite + Unpin> AsyncWrite for RecordDecoder<W> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, input: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        ready!(this.poll_payload(cx))?;
        if input.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if this.finished {
            return Poll::Ready(Err(io::Error::new(ErrorKind::InvalidData, "data after tunnel FIN")));
        }
        if this.header_used < RECORD_HEADER_LEN {
            let n = (RECORD_HEADER_LEN - this.header_used).min(input.len());
            this.header[this.header_used..this.header_used + n].copy_from_slice(&input[..n]);
            this.header_used += n;
            if this.header_used == RECORD_HEADER_LEN {
                this.payload_len = u32::from_be_bytes(this.header[1..].try_into().unwrap()) as usize;
                match this.header[0] {
                    DATA if this.payload_len > 0 && this.payload_len <= MAX_PACKET_LENGTH => {}
                    FIN if this.payload_len == 0 => {
                        this.finished = true;
                    }
                    _ => return Poll::Ready(Err(io::Error::new(ErrorKind::InvalidData, "invalid tunnel record"))),
                }
            }
            return Poll::Ready(Ok(n));
        }
        let n = (this.payload_len - this.payload.len()).min(input.len());
        this.payload.extend_from_slice(&input[..n]);
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_payload(cx))?;
        Pin::new(&mut this.writer).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_payload(cx))?;
        Pin::new(&mut this.writer).poll_shutdown(cx)
    }
}

async fn send_records(
    local_rx: impl AsyncRead,
    tx: &mut impl TransportWrite,
    mut receive_done: oneshot::Receiver<()>,
    ping_frequency: Option<Duration>,
    download: Option<RateLimiter>,
) -> io::Result<()> {
    let frequency = ping_frequency
        .filter(|d| !d.is_zero())
        .unwrap_or(Duration::from_secs(86400));
    let mut timer = tokio::time::interval_at(Instant::now() + frequency, frequency);
    let notify = tx.pending_operations_notify();
    let mut payload = vec![0u8; MAX_PACKET_LENGTH];
    let mut sent_fin = false;
    let mut pending_len = None;
    let mut bandwidth = BandwidthWait::new(download);
    pin_mut!(local_rx);
    loop {
        select! {
            biased;
            _ = notify.notified() => tx.handle_pending_operations().await?,
            _ = &mut receive_done, if sent_fin => return Ok(()),
            read = local_rx.read(&mut payload), if !sent_fin && pending_len.is_none() => {
                let n = read?;
                pending_len = Some(n);
            },
            _ = std::future::poll_fn(|cx| bandwidth.poll_acquire(cx, pending_len.unwrap_or(0))), if pending_len.is_some() => {
                let n = pending_len.take().unwrap();
                let buf = tx.buf_mut();
                buf.clear();
                buf.put_u8(if n == 0 { FIN } else { DATA });
                buf.put_u32(n as u32);
                buf.extend_from_slice(&payload[..n]);
                tx.write().await?;
                sent_fin = n == 0;
            },
            _ = timer.tick(), if ping_frequency.is_some() => tx.ping().await?,
        }
    }
}

async fn receive_records(
    local_tx: impl AsyncWrite + Send,
    rx: &mut impl TransportRead,
    received_fin: oneshot::Sender<()>,
    mut send_done: oneshot::Receiver<()>,
    upload: Option<RateLimiter>,
) -> io::Result<()> {
    pin_mut!(local_tx);
    let mut decoder = RecordDecoder::with_bandwidth(local_tx, upload);
    let mut received_fin = Some(received_fin);
    loop {
        select! {
            biased;
            _ = &mut send_done, if received_fin.is_none() => return Ok(()),
            result = rx.copy(&mut decoder) => result?,
        }
        if decoder.finished && received_fin.is_some() {
            decoder.shutdown().await?;
            let _ = received_fin.take().unwrap().send(());
            // WebSocket Ping/Pong and protocol violations still need to be read after FIN.
            // Only the local writer is shut down; the transport lives until our own FIN.
        } else if !decoder.finished {
            decoder.flush().await?;
        }
    }
}

/// Keep each direction alive until its own FIN. A fatal error cancels both directions.
pub async fn forward(
    local_rx: impl AsyncRead + Send,
    local_tx: impl AsyncWrite + Send,
    rx: impl TransportRead,
    tx: impl TransportWrite,
    ping_frequency: Option<Duration>,
) -> anyhow::Result<()> {
    forward_with_quota(local_rx, local_tx, rx, tx, ping_frequency, None).await
}

pub(crate) async fn forward_with_quota(
    local_rx: impl AsyncRead + Send,
    local_tx: impl AsyncWrite + Send,
    mut rx: impl TransportRead,
    mut tx: impl TransportWrite,
    ping_frequency: Option<Duration>,
    quota: Option<TunnelPermit>,
) -> anyhow::Result<()> {
    let upload = quota.as_ref().and_then(TunnelPermit::upload);
    let download = quota.as_ref().and_then(TunnelPermit::download);
    let (received_fin_tx, received_fin_rx) = oneshot::channel();
    let (send_done_tx, send_done_rx) = oneshot::channel();
    let send = async {
        let result = send_records(local_rx, &mut tx, received_fin_rx, ping_frequency, download).await;
        let _ = send_done_tx.send(());
        result
    };
    tokio::try_join!(send, receive_records(local_tx, &mut rx, received_fin_tx, send_done_rx, upload))?;
    tx.close().await?;
    rx.finish().await?;
    drop(quota);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct Packets(Vec<Vec<u8>>);
    impl AsyncWrite for Packets {
        fn poll_write(mut self: Pin<&mut Self>, _: &mut Context<'_>, bytes: &[u8]) -> Poll<io::Result<usize>> {
            self.0.push(bytes.to_vec());
            Poll::Ready(Ok(bytes.len()))
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn records_preserve_datagrams_across_arbitrary_transport_chunks() {
        let packets = [vec![17; 40000], vec![34; 1200]];
        let mut wire = Vec::new();
        for packet in &packets {
            wire.push(DATA);
            wire.extend_from_slice(&(packet.len() as u32).to_be_bytes());
            wire.extend_from_slice(packet);
        }
        wire.extend_from_slice(&[FIN, 0, 0, 0, 0]);
        for chunk_size in [1, 3, 16384, 65536] {
            let mut decoder = RecordDecoder::new(Packets::default());
            for chunk in wire.chunks(chunk_size) {
                decoder.write_all(chunk).await.unwrap();
                decoder.flush().await.unwrap();
            }
            assert!(decoder.finished);
            assert_eq!(decoder.writer.0, packets);
        }
    }

    #[tokio::test]
    async fn records_reject_oversized_unknown_and_post_fin_data() {
        for wire in [vec![DATA, 0, 1, 0, 1], vec![9, 0, 0, 0, 0], vec![FIN, 0, 0, 0, 0, DATA]] {
            let mut decoder = RecordDecoder::new(Packets::default());
            assert_eq!(decoder.write_all(&wire).await.unwrap_err().kind(), ErrorKind::InvalidData);
            assert!(decoder.writer.0.is_empty());
        }
    }

    #[tokio::test(start_paused = true)]
    async fn bandwidth_wait_preserves_full_datagram_writes() {
        let config = crate::yaml::from_slice(b"version: 1\ndefault: {upload_bytes_per_second: 65536}").unwrap();
        let manager = crate::quotas::QuotaManager::new(config);
        let permit = manager.open_session("device").unwrap().open_tunnel().unwrap();
        let mut decoder = RecordDecoder::with_bandwidth(Packets::default(), permit.upload());
        let packets = [vec![11; 40000], vec![22; 40000]];
        let before = Instant::now();
        for packet in &packets {
            let mut record = vec![DATA];
            record.extend_from_slice(&(packet.len() as u32).to_be_bytes());
            record.extend_from_slice(packet);
            decoder.write_all(&record).await.unwrap();
            decoder.flush().await.unwrap();
        }
        assert!(before.elapsed() >= Duration::from_millis(220));
        assert_eq!(decoder.writer.0, packets);
    }

    #[tokio::test(start_paused = true)]
    async fn pending_upstream_write_does_not_double_charge_payload() {
        struct PendingOnce {
            pending: bool,
            written: usize,
        }
        impl AsyncWrite for PendingOnce {
            fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, bytes: &[u8]) -> Poll<io::Result<usize>> {
                if self.pending {
                    self.pending = false;
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
                self.written += bytes.len();
                Poll::Ready(Ok(bytes.len()))
            }
            fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
                Poll::Ready(Ok(()))
            }
            fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
                Poll::Ready(Ok(()))
            }
        }
        let config = crate::yaml::from_slice(b"version: 1\ndefault: {upload_bytes_per_second: 65536}").unwrap();
        let manager = crate::quotas::QuotaManager::new(config);
        let permit = manager.open_session("a").unwrap().open_tunnel().unwrap();
        let mut decoder = RecordDecoder::with_bandwidth(
            PendingOnce {
                pending: true,
                written: 0,
            },
            permit.upload(),
        );
        let mut record = vec![DATA];
        record.extend_from_slice(&65536u32.to_be_bytes());
        record.extend_from_slice(&vec![5; 65536]);
        let before = Instant::now();
        decoder.write_all(&record).await.unwrap();
        decoder.flush().await.unwrap();
        assert_eq!(decoder.writer.written, 65536);
        assert_eq!(before.elapsed(), Duration::ZERO);
    }
}
