use super::udp_server::{Socks5UdpStream, Socks5UdpStreamWriter};
use crate::protocols::tcp::configure_socket;
use crate::somark::SoMark;
use crate::tunnel::LocalProtocol;
use crate::tunnel::downstream_listeners::DownstreamWrite;
use anyhow::Context;
use fast_socks5::server::Socks5ServerProtocol;
use fast_socks5::server::states::CommandRead;
use fast_socks5::util::target_addr::TargetAddr;
use fast_socks5::{ReplyError, Socks5Command};
use futures_util::{Stream, StreamExt, stream};
use socket2::SockRef;
use std::future::Future;
use std::io::{Error, ErrorKind, IoSlice};
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::Poll;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::select;
use tokio::sync::oneshot;
use tokio::task::JoinSet;
use tracing::{info, warn};
use url::Host;

/// Max time a client has to send its SOCKS5 greeting and command once connected.
/// Negotiations run concurrently with a bounded number of pending clients.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

#[allow(clippy::type_complexity)]
pub struct Socks5Listener {
    socks_server: Pin<Box<dyn Stream<Item = anyhow::Result<(Socks5Stream, (Host, u16))>> + Send>>,
}

pub enum Socks5ReadHalf {
    Tcp(OwnedReadHalf),
    /// Before the tunnel is confirmed we don't yet own the read half; it arrives over the oneshot
    /// once the write half has replied success and split the socket. A closed/`None` receiver means
    /// the write half replied an error (or was dropped) => treat as EOF.
    TcpPending(Option<oneshot::Receiver<OwnedReadHalf>>),
    Udp(Socks5UdpStream),
}

pub enum Socks5WriteHalf {
    Tcp(OwnedWriteHalf),
    /// Carries the whole client socket (via the `CommandRead` proto) plus the reply address until
    /// the tunnel outcome is known. [`Socks5WriteHalf::on_tunnel_ready`] consumes the proto to send
    /// the SOCKS5 reply, then splits the socket and hands the read half to
    /// [`Socks5ReadHalf::TcpPending`].
    TcpPending {
        proto: Option<Socks5ServerProtocol<TcpStream, CommandRead>>,
        reply_addr: SocketAddr,
        read_half_tx: Option<oneshot::Sender<OwnedReadHalf>>,
    },
    Udp(Socks5UdpStreamWriter),
}

pub enum Socks5Stream {
    /// The SOCKS5 command has been read but not yet replied to: `proto` still owns the whole client
    /// socket. The reply (`reply_addr`) is deferred until the tunnel is known to be up or down.
    Tcp {
        proto: Socks5ServerProtocol<TcpStream, CommandRead>,
        reply_addr: SocketAddr,
    },
    Udp((Socks5UdpStream, Socks5UdpStreamWriter)),
}

impl Socks5Stream {
    pub fn local_protocol(&self) -> LocalProtocol {
        match self {
            Self::Tcp { .. } => LocalProtocol::Tcp { proxy_protocol: false }, // TODO: Implement proxy protocol
            Self::Udp(s) => LocalProtocol::Udp {
                timeout: s.0.watchdog_deadline.as_ref().map(|x| x.period()),
            },
        }
    }

    pub fn into_split(self) -> (Socks5ReadHalf, Socks5WriteHalf) {
        match self {
            Self::Tcp { proto, reply_addr } => {
                let (read_half_tx, rx) = oneshot::channel();
                (
                    Socks5ReadHalf::TcpPending(Some(rx)),
                    Socks5WriteHalf::TcpPending {
                        proto: Some(proto),
                        reply_addr,
                        read_half_tx: Some(read_half_tx),
                    },
                )
            }
            Self::Udp((r, w)) => (Socks5ReadHalf::Udp(r), Socks5WriteHalf::Udp(w)),
        }
    }
}

impl DownstreamWrite for Socks5WriteHalf {
    /// Send the deferred SOCKS5 reply now that the end-to-end tunnel outcome is known, then split the
    /// client socket for data forwarding. Called exactly once per connection.
    async fn on_tunnel_ready(&mut self, result: Result<(), &anyhow::Error>) -> std::io::Result<()> {
        let Self::TcpPending {
            proto,
            reply_addr,
            read_half_tx,
        } = self
        else {
            // UDP, or an already-finalized TCP write half: nothing to acknowledge.
            return Ok(());
        };

        let Some(proto) = proto.take() else {
            panic!("on_tunnel_ready called twice on a TcpPending half");
        };

        match result {
            Ok(()) => {
                let stream = proto.reply_success(*reply_addr).await.map_err(Error::other)?;
                let _ = configure_socket(SockRef::from(&stream), SoMark::new(None));
                let (read_half, write_half) = stream.into_split();
                // Hand the read half to the paired `Socks5ReadHalf::TcpPending`. If the receiver is
                // gone (read half dropped) there is nothing to read anyway, so ignore the error.
                if let Some(tx) = read_half_tx.take() {
                    let _ = tx.send(read_half);
                }
                *self = Self::Tcp(write_half);
                Ok(())
            }
            Err(_) => {
                // Tell the local SOCKS5 client the connection failed. The upstream error is opaque
                // (any target failure collapses to a rejected tunnel request), so report the generic
                // failure code. Dropping `read_half_tx` signals EOF to the read half.
                let _ = proto.reply_error(&ReplyError::GeneralFailure).await;
                *read_half_tx = None;
                Err(Error::new(ErrorKind::ConnectionRefused, "socks5: upstream tunnel failed"))
            }
        }
    }
}

impl Stream for Socks5Listener {
    type Item = anyhow::Result<(Socks5Stream, (Host, u16))>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Option<Self::Item>> {
        unsafe { self.map_unchecked_mut(|x| &mut x.socks_server) }.poll_next(cx)
    }
}

pub async fn run_server(
    bind: SocketAddr,
    timeout: Option<Duration>,
    credentials: Option<(String, String)>,
) -> Result<Socks5Listener, anyhow::Error> {
    let listener = TcpListener::bind(bind)
        .await
        .with_context(|| format!("Cannot create socks5 server {bind:?}"))?;
    info!(
        "Starting SOCKS5 server on {} (authentication: {})",
        listener.local_addr()?,
        credentials.is_some()
    );
    let (tx, rx) = tokio::sync::mpsc::channel(64);
    let stream = stream::unfold(
        (listener, JoinSet::new(), tx, rx, credentials),
        move |(listener, mut tasks, tx, mut rx, credentials)| async move {
            loop {
                select! {
                    item = rx.recv() => return item.map(|item| (item, (listener, tasks, tx, rx, credentials))),
                    _ = tasks.join_next(), if !tasks.is_empty() => {},
                    accepted = listener.accept(), if tasks.len() < 256 => {
                        match accepted {
                            Ok((socket, _)) => {
                                let tx = tx.clone();
                                let credentials = credentials.clone();
                                tasks.spawn(async move {
                                    if let Err(err) = accept_client(socket, timeout, credentials, tx).await {
                                        warn!("SOCKS5 connection rejected: {err}");
                                    }
                                });
                            },
                            Err(err) => return Some((Err(err.into()), (listener, tasks, tx, rx, credentials))),
                        }
                    },
                }
            }
        },
    );
    Ok(Socks5Listener {
        socks_server: Box::pin(stream),
    })
}

type AcceptedSocks = anyhow::Result<(Socks5Stream, (Host, u16))>;

async fn accept_client(
    socket: TcpStream,
    timeout: Option<Duration>,
    credentials: Option<(String, String)>,
    tx: tokio::sync::mpsc::Sender<AcceptedSocks>,
) -> anyhow::Result<()> {
    let peer = socket.peer_addr()?;
    let local_ip = socket.local_addr()?.ip();
    let negotiation = async {
        let proto = if let Some((username, password)) = credentials {
            Socks5ServerProtocol::accept_password_auth(socket, move |user, pass| user == username && pass == password)
                .await?
                .0
        } else {
            Socks5ServerProtocol::accept_no_auth(socket).await?
        };
        proto.read_command().await
    };
    let (proto, cmd, target) = tokio::time::timeout(HANDSHAKE_TIMEOUT, negotiation).await??;
    if cmd == Socks5Command::UDPAssociate {
        let expected_port = match &target {
            TargetAddr::Ip(addr) => addr.port(),
            TargetAddr::Domain(_, port) => *port,
        };
        let (relay_addr, udp) = super::udp_server::run_server(
            SocketAddr::new(local_ip, 0),
            timeout,
            SocketAddr::new(peer.ip(), expected_port),
        )
        .await?;
        let mut control = proto.reply_success(relay_addr).await?;
        tokio::pin!(udp);
        let relay = async {
            while let Some(stream) = udp.next().await {
                let stream = stream?;
                let dest = stream.destination();
                let writer = stream.writer();
                tx.send(Ok((Socks5Stream::Udp((stream, writer)), dest)))
                    .await
                    .map_err(|_| Error::from(ErrorKind::BrokenPipe))?;
            }
            anyhow::Ok(())
        };
        let closed = async {
            let mut buf = [0; 8];
            loop {
                if control.read(&mut buf).await? == 0 {
                    return anyhow::Ok(());
                }
            }
        };
        select! { result = relay => result, result = closed => result }
    } else if cmd == Socks5Command::TCPConnect {
        let dest = match target {
            TargetAddr::Ip(addr) => (Host::parse(&addr.ip().to_string())?, addr.port()),
            TargetAddr::Domain(host, port) => (Host::Domain(host), port),
        };
        tx.send(Ok((
            Socks5Stream::Tcp {
                proto,
                reply_addr: SocketAddr::new(local_ip, 0),
            },
            dest,
        )))
        .await
        .map_err(|_| Error::from(ErrorKind::BrokenPipe))?;
        Ok(())
    } else {
        let _ = proto.reply_error(&ReplyError::CommandNotSupported).await;
        Ok(())
    }
}

impl Unpin for Socks5Stream {}
impl AsyncRead for Socks5ReadHalf {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        loop {
            match self.as_mut().get_mut() {
                Self::Tcp(s) => return Pin::new(s).poll_read(cx, buf),
                Self::Udp(s) => return Pin::new(s).poll_read(cx, buf),
                Self::TcpPending(rx_opt) => {
                    let Some(rx) = rx_opt.as_mut() else {
                        // The write half already replied an error (or was dropped): stable EOF.
                        return Poll::Ready(Ok(()));
                    };
                    // A compliant SOCKS5 client sends no payload until it receives our reply, which
                    // is exactly when the read half is delivered over this channel, so parking here
                    // cannot drop client bytes.
                    match Pin::new(rx).poll(cx) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Ok(read_half)) => {
                            *self.as_mut().get_mut() = Self::Tcp(read_half);
                            // Loop around to read from the now-available half.
                        }
                        Poll::Ready(Err(_)) => {
                            *rx_opt = None;
                            return Poll::Ready(Ok(()));
                        }
                    }
                }
            }
        }
    }
}

impl AsyncWrite for Socks5WriteHalf {
    fn poll_write(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>, buf: &[u8]) -> Poll<Result<usize, Error>> {
        match self.get_mut() {
            Self::Tcp(s) => Pin::new(s).poll_write(cx, buf),
            Self::Udp(s) => Pin::new(s).poll_write(cx, buf),
            // Unreachable by design: the client waits for our reply before sending, and forwarding
            // only starts after `on_tunnel_ready` has finalized this half.
            Self::TcpPending { .. } => {
                Poll::Ready(Err(Error::other("socks5: write before tunnel handshake completed")))
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Result<(), Error>> {
        match self.get_mut() {
            Self::Tcp(s) => Pin::new(s).poll_flush(cx),
            Self::Udp(s) => Pin::new(s).poll_flush(cx),
            Self::TcpPending { .. } => Poll::Ready(Ok(())),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Result<(), Error>> {
        match self.get_mut() {
            Self::Tcp(s) => Pin::new(s).poll_shutdown(cx),
            Self::Udp(s) => Pin::new(s).poll_shutdown(cx),
            Self::TcpPending { .. } => Poll::Ready(Ok(())),
        }
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<Result<usize, Error>> {
        match self.get_mut() {
            Self::Tcp(s) => Pin::new(s).poll_write_vectored(cx, bufs),
            Self::Udp(s) => Pin::new(s).poll_write_vectored(cx, bufs),
            Self::TcpPending { .. } => {
                Poll::Ready(Err(Error::other("socks5: write before tunnel handshake completed")))
            }
        }
    }

    fn is_write_vectored(&self) -> bool {
        match self {
            Self::Tcp(s) => s.is_write_vectored(),
            Self::Udp(s) => s.is_write_vectored(),
            Self::TcpPending { .. } => false,
        }
    }
}
