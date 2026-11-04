use crate::executor::TokioExecutorRef;
use crate::management::registry::TunnelLease;
use crate::protocols::tcp::AcceptBackoff;
use crate::quotas::TunnelPermit;
use crate::revocation::RevocationGuard;
use crate::tunnel::RemoteAddr;
use crate::tunnel::downstream_listeners::{DownstreamListener, DownstreamWrite};
use ahash::AHashMap;
use anyhow::anyhow;
use futures_util::{StreamExt, pin_mut};
use log::warn;
use parking_lot::Mutex;
use std::future::Future;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::task::AbortHandle;
use tokio::{select, time};
use tracing::{Instrument, Span, info};

struct ReverseTunnelItem<T: DownstreamListener> {
    #[allow(clippy::type_complexity)]
    receiver: async_channel::Receiver<(
        (<T as DownstreamListener>::Reader, <T as DownstreamListener>::Writer),
        RemoteAddr,
    )>,
    nb_seen_clients: Arc<AtomicUsize>,
    server_task: AbortHandle,
    bound: SocketAddr,
}

impl<T: DownstreamListener> ReverseTunnelItem<T> {
    #[allow(clippy::type_complexity)]
    pub fn get_cnx_awaiter(
        &self,
    ) -> async_channel::Receiver<(
        (<T as DownstreamListener>::Reader, <T as DownstreamListener>::Writer),
        RemoteAddr,
    )> {
        self.nb_seen_clients.fetch_add(1, Ordering::Relaxed);
        self.receiver.clone()
    }
}

impl<T: DownstreamListener> Drop for ReverseTunnelItem<T> {
    fn drop(&mut self) {
        self.server_task.abort();
    }
}

#[derive(Clone, Hash, PartialEq, Eq)]
pub(super) struct ListenerOwner {
    pub instance: uuid::Uuid,
    pub tenant: Option<Arc<str>>,
    pub device: Option<Arc<str>>,
}

#[derive(Clone, Hash, PartialEq, Eq)]
pub(super) enum ReverseListenerKey {
    Socket(ListenerOwner, SocketAddr),
    /// A port-0 listener allocated for one client reverse tunnel. Every request of that tunnel names
    /// the same identity, so they all find this listener instead of each allocating a new port.
    Allocated(ListenerOwner, SocketAddr, uuid::Uuid),
    Unix(ListenerOwner, PathBuf),
}

impl ListenerOwner {
    /// The key of a socket listener bound at `bind`. A port-0 bind is allocated to the client tunnel
    /// a request names, and otherwise opens a single-use ephemeral listener.
    pub(super) fn socket_key(&self, bind: SocketAddr, tunnel: Option<uuid::Uuid>) -> ReverseListenerKey {
        match tunnel {
            Some(tunnel) if bind.port() == 0 => ReverseListenerKey::Allocated(self.clone(), bind, tunnel),
            _ => ReverseListenerKey::Socket(self.clone(), bind),
        }
    }
}

/// A connection a reverse listener accepted, with what it was accepted for.
#[allow(clippy::type_complexity)]
pub(super) type ReverseConnection<T> = (
    (<T as DownstreamListener>::Reader, <T as DownstreamListener>::Writer),
    RemoteAddr,
);

/// When an idle check closes a reverse listener.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClosePolicy {
    /// At the first check no request waits on it: an ephemeral listener, or one that holds quota.
    FirstIdleCheck,
    /// At a check no request waits on it and none arrived since the previous one: a fixed port.
    NoNewRequest,
    /// Once a whole interval passed with no request waiting and none arriving. Its tunnel asks again
    /// as soon as a request is served, so a check that falls between two requests must not close it
    /// and give the tunnel another port.
    Allocated,
}

struct IdleCheck {
    policy: ClosePolicy,
    /// Whether a request waited at the previous check. The first check comes right away.
    waited: bool,
}

impl IdleCheck {
    fn new(policy: ClosePolicy) -> Self {
        Self { policy, waited: true }
    }

    /// Whether the listener is unused at this check. `seen_clients` counts the requests that came for
    /// it, and `serves_peers` whether connections it handed out still depend on it.
    fn unused(&mut self, waiting: bool, serves_peers: impl FnOnce() -> bool, seen_clients: &AtomicUsize) -> bool {
        match self.policy {
            ClosePolicy::Allocated => {
                let arrived = seen_clients.swap(0, Ordering::Relaxed) != 0;
                let gone = !waiting && !self.waited && !arrived;
                self.waited = waiting;
                gone && !serves_peers()
            }
            ClosePolicy::FirstIdleCheck => !waiting && !serves_peers(),
            ClosePolicy::NoNewRequest => !waiting && !serves_peers() && seen_clients.swap(0, Ordering::Relaxed) == 0,
        }
    }
}

pub struct ReverseTunnelServer<T: DownstreamListener> {
    servers: Arc<Mutex<AHashMap<ReverseListenerKey, ReverseTunnelItem<T>>>>,
}

impl<T: DownstreamListener> ReverseTunnelServer<T> {
    pub fn new() -> Self {
        Self {
            servers: Arc::new(Mutex::new(AHashMap::with_capacity(1))),
        }
    }

    /// `serves_peers` tells whether connections already handed out still depend on the listener, as
    /// UDP peers do: such a listener stays open past its idle checks until they are gone.
    ///
    /// Returns the connection and the address the listener is bound to.
    #[allow(clippy::too_many_arguments)]
    pub async fn run_listening_server(
        &self,
        executor: &impl TokioExecutorRef,
        key: ReverseListenerKey,
        idle_timeout: Duration,
        gen_listening_server: impl Future<Output = anyhow::Result<(T, SocketAddr)>>,
        fleet: Option<TunnelLease>,
        ownership: (Option<TunnelPermit>, RevocationGuard),
        serves_peers: fn(&T) -> bool,
    ) -> anyhow::Result<(ReverseConnection<T>, SocketAddr)>
    where
        T: DownstreamListener + Send + 'static,
    {
        let (quota, revocation) = ownership;
        let is_ephemeral = matches!(&key, ReverseListenerKey::Socket(_, bind) if bind.port() == 0);
        let allocated = matches!(&key, ReverseListenerKey::Allocated(..));
        let listening_server = if is_ephemeral {
            None
        } else {
            self.servers
                .lock()
                .get(&key)
                .map(|server| (server.get_cnx_awaiter(), server.bound))
        };
        let (cnx, bound) = if let Some(listening_server) = listening_server {
            listening_server
        } else {
            let (listening_server, actual_bind_addr) = gen_listening_server.await?;
            if let ReverseListenerKey::Allocated(_, _, tunnel) = &key {
                info!("Allocated reverse listener {actual_bind_addr} to client tunnel {tunnel}");
            }
            let actual_key = match key {
                ReverseListenerKey::Socket(owner, _) => ReverseListenerKey::Socket(owner, actual_bind_addr),
                // An allocated listener is found by its tunnel, and a Unix one by its path.
                other => other,
            };
            let cleanup_key = actual_key.clone();
            let (tx, rx) = async_channel::bounded(10);
            let nb_seen_clients = Arc::new(AtomicUsize::new(0));
            let seen_clients = nb_seen_clients.clone();
            let server = self.servers.clone();
            let listener_lease = fleet.map(|fleet| fleet.listener(actual_bind_addr));

            let fut = async move {
                // Retained listeners remain charged even after their original request is cancelled.
                let retained_quota = quota;
                let _listener_lease = listener_lease;
                scopeguard::defer!({
                    server.lock().remove(&cleanup_key);
                });

                let check_interval = if retained_quota.is_some() {
                    Duration::from_secs(1).min(idle_timeout)
                } else if is_ephemeral {
                    Duration::from_secs(5).min(idle_timeout)
                } else {
                    idle_timeout
                };
                let mut timer = time::interval(check_interval);
                let mut idle_check = IdleCheck::new(if allocated {
                    ClosePolicy::Allocated
                } else if retained_quota.is_some() || is_ephemeral {
                    ClosePolicy::FirstIdleCheck
                } else {
                    ClosePolicy::NoNewRequest
                });
                let mut accept_backoff = AcceptBackoff::new("Error while listening for incoming connections");
                pin_mut!(listening_server);
                loop {
                    select! {
                        biased;
                        cnx = listening_server.next() => {
                           match cnx {
                                None => {
                                    warn!("Error while listening for incoming connections. Server stopped");
                                    break
                                },
                                Some(Err(err)) => {
                                    accept_backoff.wait(err.as_ref()).await;
                                    continue;
                                }
                                Some(Ok(cnx)) => {
                                    accept_backoff.reset();
                                    // Only the request that opened an ephemeral listener takes its connections. Once it
                                    // has, a later one would wait for nobody, and a UDP one would also hold up the
                                    // listener, and with it the datagrams of the peer already served.
                                    if is_ephemeral && tx.receiver_count() <= 1 {
                                        info!("Dropping a new connection to ephemeral reverse listener {actual_bind_addr}, whose request was already served");
                                        continue;
                                    }
                                    if time::timeout(idle_timeout, tx.send(cnx)).await.is_err() {
                                        info!("New reverse connection failed to be picked by client after {}s. Closing reverse tunnel server", idle_timeout.as_secs());
                                        break;
                                    }
                                }
                            }
                        },
                        _ = timer.tick() => {
                            // <= 1 because the server itself has a receiver
                            let waiting = tx.receiver_count() > 1;
                            if idle_check.unused(waiting, || serves_peers(&listening_server), &seen_clients) {
                                info!("No active client connected to reverse tunnel server on {}. Closing reverse listener.", actual_bind_addr);
                                break;
                            }
                        },
                    }
                }
                info!("Stopping listening reverse server");
                Ok(())
            };
            let fut = async move {
                let _ = revocation.run(fut).await;
            }
            .instrument(Span::current());

            let item = ReverseTunnelItem {
                receiver: rx,
                nb_seen_clients,
                server_task: executor.spawn(fut),
                bound: actual_bind_addr,
            };
            let cnx_awaiter = item.get_cnx_awaiter();
            self.servers.lock().insert(actual_key, item);
            (cnx_awaiter, actual_bind_addr)
        };

        let mut cnx = cnx
            .recv()
            .await
            .map_err(|_| anyhow!("listening reverse server stopped"))?;
        let _ = cnx.0.1.on_tunnel_ready(Ok(())).await;
        Ok((cnx, bound))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::executor::DefaultTokioExecutor;
    use crate::tunnel::downstream_listeners::{TcpDownstreamListener, UdpDownstreamListener};
    use std::net::Ipv4Addr;
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpStream, UdpSocket};
    use tokio::task::JoinHandle;
    use url::Host;

    async fn read(reader: &mut (impl AsyncRead + Unpin), expected: &[u8]) {
        let mut buf = [0; 64];
        let len = time::timeout(Duration::from_secs(2), reader.read(&mut buf))
            .await
            .expect("the datagram was not delivered")
            .unwrap();
        assert_eq!(&buf[..len], expected);
    }

    #[tokio::test]
    async fn ephemeral_udp_listener_serves_its_peer_past_idle_checks_and_drops_strangers() {
        let bind = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .unwrap()
            .local_addr()
            .unwrap();
        let listener = UdpDownstreamListener::new(bind, (Host::Ipv4(Ipv4Addr::LOCALHOST), 9), None)
            .await
            .unwrap();
        let servers = Arc::new(ReverseTunnelServer::new());
        let owner = ListenerOwner {
            instance: uuid::Uuid::now_v7(),
            tenant: None,
            device: None,
        };
        // Port 0 makes the listener ephemeral; the tenant pool picked `bind` for it.
        let key = ReverseListenerKey::Socket(owner, SocketAddr::new(bind.ip(), 0));
        let request = tokio::spawn({
            let servers = servers.clone();
            async move {
                servers
                    .run_listening_server(
                        &DefaultTokioExecutor::default(),
                        key,
                        Duration::from_millis(100),
                        async move { Ok((listener, bind)) },
                        None,
                        (None, RevocationGuard::default()),
                        UdpDownstreamListener::serves_peers,
                    )
                    .await
            }
        });

        let peer = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        peer.connect(bind).await.unwrap();
        peer.send(b"one").await.unwrap();
        let (((reader, mut writer), _), _) = request.await.unwrap().unwrap();
        let mut reader = Box::pin(reader);
        read(&mut reader, b"one").await;

        // Several idle checks pass while the peer is quiet: its datagrams must still arrive.
        time::sleep(Duration::from_millis(500)).await;
        peer.send(b"two").await.unwrap();
        read(&mut reader, b"two").await;
        writer.write_all(b"reply").await.unwrap();
        let mut buf = [0; 64];
        let len = time::timeout(Duration::from_secs(2), peer.recv(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf[..len], b"reply");

        // No request will ever take a connection from another sender, so it must not hold up the peer.
        let stranger = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        stranger.send_to(b"stranger", bind).await.unwrap();
        peer.send(b"three").await.unwrap();
        read(&mut reader, b"three").await;

        // Once the peer is gone, the next idle check closes the listener and frees its port.
        drop((reader, writer));
        time::timeout(Duration::from_secs(2), async {
            while !servers.servers.lock().is_empty() {
                time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("the listener stayed open after its peer was gone");
        assert!(std::net::UdpSocket::bind(bind).is_ok());
    }

    #[test]
    fn an_allocated_listener_survives_a_check_between_two_requests_of_its_tunnel() {
        let seen = AtomicUsize::new(0);
        let idle = || false;

        // A single-use listener closes at the first check nobody waits on it.
        let mut single = IdleCheck::new(ClosePolicy::FirstIdleCheck);
        assert!(!single.unused(true, idle, &seen));
        assert!(single.unused(false, idle, &seen));
        assert!(
            !single.unused(false, || true, &seen),
            "a UDP listener still serving its peer stays"
        );

        // A fixed one closes when no request waits and none arrived since the previous check.
        let mut fixed = IdleCheck::new(ClosePolicy::NoNewRequest);
        seen.store(1, Ordering::Relaxed);
        assert!(!fixed.unused(false, idle, &seen));
        assert!(fixed.unused(false, idle, &seen));

        let mut allocated = IdleCheck::new(ClosePolicy::Allocated);
        // The first check comes right away, possibly before the opening request waits.
        assert!(!allocated.unused(false, idle, &seen));
        assert!(!allocated.unused(true, idle, &seen));
        // A check between a served request and the next one keeps it, though nobody waits on it now.
        assert!(!allocated.unused(false, idle, &seen));
        // A request arrived since, served before this check: the tunnel is still there.
        seen.store(1, Ordering::Relaxed);
        assert!(!allocated.unused(false, idle, &seen));
        assert!(
            !allocated.unused(false, || true, &seen),
            "a UDP listener still serving its peer stays"
        );
        // A whole interval with no request waiting and none arriving: the tunnel is gone.
        assert!(allocated.unused(false, idle, &seen));
    }

    type TcpRequest = JoinHandle<anyhow::Result<(ReverseConnection<TcpDownstreamListener>, SocketAddr)>>;

    /// One reverse request on `key`, counting the listeners it had to bind.
    fn tcp_request(
        servers: &Arc<ReverseTunnelServer<TcpDownstreamListener>>,
        key: ReverseListenerKey,
        allocations: &Arc<AtomicUsize>,
    ) -> TcpRequest {
        tcp_request_checked_every(servers, key, allocations, Duration::from_millis(200))
    }

    /// [`tcp_request`] on a listener whose idle checks come every `interval`.
    fn tcp_request_checked_every(
        servers: &Arc<ReverseTunnelServer<TcpDownstreamListener>>,
        key: ReverseListenerKey,
        allocations: &Arc<AtomicUsize>,
        interval: Duration,
    ) -> TcpRequest {
        let servers = servers.clone();
        let allocations = allocations.clone();
        tokio::spawn(async move {
            servers
                .run_listening_server(
                    &DefaultTokioExecutor::default(),
                    key,
                    interval,
                    async move {
                        allocations.fetch_add(1, Ordering::Relaxed);
                        let destination = (Host::Ipv4(Ipv4Addr::LOCALHOST), 9);
                        let listener =
                            TcpDownstreamListener::new((Ipv4Addr::LOCALHOST, 0).into(), destination, false).await?;
                        let bound = listener.bound_addr();
                        Ok((listener, bound))
                    },
                    None,
                    (None, RevocationGuard::default()),
                    |_| false,
                )
                .await
        })
    }

    async fn bound(servers: &ReverseTunnelServer<TcpDownstreamListener>, key: &ReverseListenerKey) -> SocketAddr {
        time::timeout(Duration::from_secs(2), async {
            loop {
                if let Some(item) = servers.servers.lock().get(key) {
                    return item.bound;
                }
                time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the listener was not opened")
    }

    async fn visit(listener: SocketAddr, payload: &[u8]) -> TcpStream {
        let mut visitor = TcpStream::connect(listener).await.unwrap();
        visitor.write_all(payload).await.unwrap();
        visitor
    }

    async fn served(request: TcpRequest, listener: SocketAddr, expected: &[u8]) {
        let (((reader, _writer), _), bound) = time::timeout(Duration::from_secs(2), request)
            .await
            .expect("the request was not served")
            .unwrap()
            .unwrap();
        assert_eq!(bound, listener, "the reply must name the listener port");
        read(&mut Box::pin(reader), expected).await;
    }

    #[tokio::test]
    async fn an_allocated_tcp_listener_serves_every_request_of_its_tunnel() {
        let servers = Arc::new(ReverseTunnelServer::new());
        let allocations = Arc::new(AtomicUsize::new(0));
        let owner = ListenerOwner {
            instance: uuid::Uuid::now_v7(),
            tenant: None,
            device: None,
        };
        let any_port = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
        let key = owner.socket_key(any_port, Some(uuid::Uuid::new_v4()));
        assert!(matches!(key, ReverseListenerKey::Allocated(..)));

        let first = tcp_request(&servers, key.clone(), &allocations);
        let listener = bound(&servers, &key).await;
        let _one = visit(listener, b"one").await;
        served(first, listener, b"one").await;

        // A visitor arriving before the tunnel's next request waits for it instead of being dropped.
        let _two = visit(listener, b"two").await;
        time::sleep(Duration::from_millis(50)).await;
        served(tcp_request(&servers, key.clone(), &allocations), listener, b"two").await;

        let third = tcp_request(&servers, key.clone(), &allocations);
        let _three = visit(listener, b"three").await;
        served(third, listener, b"three").await;
        assert_eq!(allocations.load(Ordering::Relaxed), 1, "later requests must reuse the listener");

        // Another tunnel of the same owner gets a listener of its own.
        let other_key = owner.socket_key(any_port, Some(uuid::Uuid::new_v4()));
        let other = tcp_request(&servers, other_key.clone(), &allocations);
        let other_listener = bound(&servers, &other_key).await;
        assert_ne!(other_listener, listener);
        assert_eq!(allocations.load(Ordering::Relaxed), 2);
        other.abort();

        // Once the tunnel stops asking, the listener closes and frees its port.
        time::timeout(Duration::from_secs(3), async {
            while servers.servers.lock().contains_key(&key) {
                time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("the listener stayed open after its tunnel stopped asking");
        assert!(std::net::TcpListener::bind(listener).is_ok());
    }

    #[tokio::test]
    async fn an_allocated_listener_keeps_its_port_when_a_check_falls_between_two_requests() {
        // Without quotas an allocated listener is checked every idle timeout, first when it opens.
        let interval = Duration::from_millis(400);
        let servers = Arc::new(ReverseTunnelServer::new());
        let allocations = Arc::new(AtomicUsize::new(0));
        let owner = ListenerOwner {
            instance: uuid::Uuid::now_v7(),
            tenant: None,
            device: None,
        };
        let key = owner.socket_key(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), Some(uuid::Uuid::new_v4()));
        let request =
            |key: &ReverseListenerKey| tcp_request_checked_every(&servers, key.clone(), &allocations, interval);

        let first = request(&key);
        let listener = bound(&servers, &key).await;
        // Checks come at `opened + n * interval`, give or take the polling of `bound`.
        let opened = time::Instant::now();
        let _one = visit(listener, b"one").await;
        served(first, listener, b"one").await;

        // The second request waits through a check, then is served a quarter interval after it.
        let second = request(&key);
        let checks_passed = (opened.elapsed().as_millis() / interval.as_millis()) as u32 + 1;
        let check = opened + interval * checks_passed;
        time::sleep_until(check + interval / 4).await;
        let _two = visit(listener, b"two").await;
        served(second, listener, b"two").await;

        // No request waits through the next check; the tunnel asks again half an interval after it.
        time::sleep_until(check + interval * 3 / 2).await;
        let third = request(&key);
        let _three = visit(listener, b"three").await;
        served(third, listener, b"three").await;
        assert_eq!(
            allocations.load(Ordering::Relaxed),
            1,
            "a check between two requests of the tunnel closed its listener"
        );
    }

    #[test]
    fn only_a_port_zero_bind_is_allocated_to_a_tunnel() {
        let owner = ListenerOwner {
            instance: uuid::Uuid::from_u128(1),
            tenant: None,
            device: None,
        };
        let tunnel = Some(uuid::Uuid::from_u128(2));
        let fixed = SocketAddr::from((Ipv4Addr::LOCALHOST, 8080));
        let any = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
        assert!(matches!(owner.socket_key(fixed, tunnel), ReverseListenerKey::Socket(_, bind) if bind == fixed));
        assert!(matches!(owner.socket_key(any, None), ReverseListenerKey::Socket(_, bind) if bind == any));
        assert!(matches!(owner.socket_key(any, tunnel), ReverseListenerKey::Allocated(_, bind, _) if bind == any));
    }
}
