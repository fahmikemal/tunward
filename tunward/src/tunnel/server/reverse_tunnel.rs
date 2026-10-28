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
    Unix(ListenerOwner, PathBuf),
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

    pub async fn run_listening_server(
        &self,
        executor: &impl TokioExecutorRef,
        key: ReverseListenerKey,
        idle_timeout: Duration,
        gen_listening_server: impl Future<Output = anyhow::Result<(T, SocketAddr)>>,
        fleet: Option<TunnelLease>,
        ownership: (Option<TunnelPermit>, RevocationGuard),
    ) -> anyhow::Result<(
        (<T as DownstreamListener>::Reader, <T as DownstreamListener>::Writer),
        RemoteAddr,
    )>
    where
        T: DownstreamListener + Send + 'static,
    {
        let (quota, revocation) = ownership;
        let is_ephemeral = matches!(&key, ReverseListenerKey::Socket(_, bind) if bind.port() == 0);
        let listening_server = if is_ephemeral {
            None
        } else {
            self.servers.lock().get(&key).map(|server| server.get_cnx_awaiter())
        };
        let cnx = if let Some(listening_server) = listening_server {
            listening_server
        } else {
            let (listening_server, actual_bind_addr) = gen_listening_server.await?;
            let actual_key = match key {
                ReverseListenerKey::Socket(owner, _) => ReverseListenerKey::Socket(owner, actual_bind_addr),
                unix => unix,
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
                                    if time::timeout(idle_timeout, tx.send(cnx)).await.is_err() {
                                        info!("New reverse connection failed to be picked by client after {}s. Closing reverse tunnel server", idle_timeout.as_secs());
                                        break;
                                    }
                                }
                            }
                        },
                        _ = timer.tick() => {
                            // if no client connected to the reverse tunnel server, close it
                            // <= 1 because the server itself has a receiver
                            if tx.receiver_count() <= 1 && (retained_quota.is_some() || is_ephemeral || seen_clients.swap(0, Ordering::Relaxed) == 0) {
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
            };
            let cnx_awaiter = item.get_cnx_awaiter();
            self.servers.lock().insert(actual_key, item);
            cnx_awaiter
        };

        let mut cnx = cnx
            .recv()
            .await
            .map_err(|_| anyhow!("listening reverse server stopped"))?;
        let _ = cnx.0.1.on_tunnel_ready(Ok(())).await;
        Ok(cnx)
    }
}
