use crate::executor::{DefaultTokioExecutor, TokioExecutorRef};
use crate::tunnel;
use crate::tunnel::RemoteAddr;
use crate::tunnel::client::ClientConfig;
use crate::tunnel::client::connection_pool::L4StreamManager;
use crate::tunnel::downstream_listeners::{DownstreamListener, DownstreamRead, DownstreamWrite};
use crate::tunnel::tls_reloader::TlsReloader;
use crate::tunnel::transport::io::{TransportReader, TransportWriter};
use crate::tunnel::transport::{TransportScheme, jwt_token_to_tunnel};
use crate::tunnel::upstream_connectors::UpstreamConnector;
use anyhow::Context;
use futures_util::pin_mut;
use hyper::header::COOKIE;
use log::debug;
use std::sync::Arc;
use std::time::Duration;
use tokio_stream::StreamExt;
use tracing::{Instrument, Level, error, event, span};
use url::Host;
use uuid::Uuid;

#[derive(Clone)]
pub struct Client<E: TokioExecutorRef = DefaultTokioExecutor> {
    pub config: Arc<ClientConfig>,
    pub cnx_pool: bb8::Pool<L4StreamManager>,
    reverse_tunnel_connection_retry_max_backoff: Duration,
    _tls_reloader: Arc<TlsReloader>,
    pub(crate) executor: E,
}

impl<E: TokioExecutorRef> Client<E> {
    pub async fn new(
        config: ClientConfig,
        connection_min_idle: u32,
        connection_retry_max_backoff: Duration,
        reverse_tunnel_connection_retry_max_backoff: Duration,
        executor: E,
    ) -> anyhow::Result<Self> {
        anyhow::ensure!(
            !connection_retry_max_backoff.is_zero(),
            "connection-retry-max-backoff must be greater than zero"
        );
        anyhow::ensure!(connection_min_idle <= 1000, "connection-min-idle must not exceed 1000");
        let config = Arc::new(config);

        let cnx = L4StreamManager::new(config.clone());
        let tls_reloader = TlsReloader::new_for_client(config.clone()).with_context(|| "Cannot create tls reloader")?;
        // QUIC sessions multiplex streams. A TCP-sized pool retains many independently stale
        // sessions after a server restart, costing one acknowledgement deadline per checkout.
        let multiplexed = config.remote_addr.scheme().is_webtransport();
        let cnx_pool = bb8::Pool::builder()
            .max_size(if multiplexed { 1 } else { 1000 })
            .min_idle(Some(if multiplexed {
                connection_min_idle.min(1)
            } else {
                connection_min_idle
            }))
            .max_lifetime(Some(Duration::from_secs(30)))
            .connection_timeout(connection_retry_max_backoff)
            .retry_connection(true)
            .build(cnx)
            .await?;

        Ok(Self {
            config,
            cnx_pool,
            reverse_tunnel_connection_retry_max_backoff,
            _tls_reloader: Arc::new(tls_reloader),
            executor,
        })
    }

    pub async fn connect_to_server<R, W>(
        &self,
        request_id: Uuid,
        remote_cfg: &RemoteAddr,
        duplex_stream: (R, W),
    ) -> anyhow::Result<()>
    where
        R: DownstreamRead,
        W: DownstreamWrite,
    {
        // Connect to server with the correct protocol. Capture the result instead of `?`-ing it: on
        // failure we must still acknowledge the local handshake (e.g. send a SOCKS5 error reply)
        // before bubbling the error up.
        let connect_result = match self.config.remote_addr.scheme() {
            TransportScheme::Ws | TransportScheme::Wss => {
                tunnel::transport::websocket::connect(request_id, self, remote_cfg)
                    .await
                    .map(|(r, w, response)| (TransportReader::Websocket(r), TransportWriter::Websocket(w), response))
            }
            TransportScheme::Http | TransportScheme::Https => {
                tunnel::transport::http2::connect(request_id, self, remote_cfg)
                    .await
                    .map(|(r, w, response)| (TransportReader::Http2(r), TransportWriter::Http2(w), response))
            }
            TransportScheme::Wts => tunnel::transport::webtransport::connect(request_id, self, remote_cfg)
                .await
                .map(|(r, w, response)| {
                    (
                        TransportReader::WebTransport(Box::new(r)),
                        TransportWriter::WebTransport(Box::new(w)),
                        response,
                    )
                }),
        };

        let (local_rx, mut local_tx) = duplex_stream;

        // Acknowledge the tunnel outcome to the local client (no-op for protocols without a
        // handshake). A successful transport connect means the server accepted the request and
        // reached the target, so this is the moment to reply success; otherwise reply failure.
        let (ws_rx, ws_tx, response) = match connect_result {
            Ok(tunnel) => {
                if let Err(err) = local_tx.on_tunnel_ready(Ok(())).await {
                    return Err(anyhow::Error::new(err).context("failed to acknowledge local tunnel handshake"));
                }
                tunnel
            }
            Err(err) => {
                let _ = local_tx.on_tunnel_ready(Err(&err)).await;
                return Err(err);
            }
        };

        debug!("Server response: {response:?}");
        tunnel::transport::io::forward(local_rx, local_tx, ws_rx, ws_tx, self.config.websocket_ping_frequency).await
    }

    pub async fn run_tunnel(self, tunnel_listener: impl DownstreamListener) -> anyhow::Result<()> {
        pin_mut!(tunnel_listener);
        // everybody who connects to the local socket gets their own tunnel
        while let Some(cnx) = tunnel_listener.next().await {
            let (cnx_stream, remote_addr) = match cnx {
                Ok((cnx_stream, remote_addr)) => (cnx_stream, remote_addr),
                Err(err) => {
                    error!("Error accepting connection: {:?}", err);
                    continue;
                }
            };

            let request_id = Uuid::now_v7();
            let span = span!(
                Level::INFO,
                "tunnel",
                id = request_id.to_string(),
                remote = format!("{}:{}", remote_addr.host, remote_addr.port)
            );
            let client = self.clone();
            let tunnel = async move {
                let _ = client
                    .connect_to_server(request_id, &remote_addr, cnx_stream)
                    .await
                    .map_err(|err| error!("{:?}", err));
            }
            .instrument(span);

            self.executor.spawn(tunnel);
        }

        Ok(())
    }

    pub async fn run_reverse_tunnel(
        self,
        remote_addr: RemoteAddr,
        connector: impl UpstreamConnector,
    ) -> anyhow::Result<()> {
        const REVERSE_TUNNEL_REPLY_TIMEOUT: Duration = Duration::from_secs(if cfg!(test) { 5 } else { 30 });
        fn new_reconnect_delay(max_delay: Duration) -> impl FnMut() -> Duration {
            let mut attempt: u32 = 0;
            let base_secs = 1.0_f64;
            let max_secs = max_delay.as_secs_f64();

            move || -> Duration {
                let exp_secs = base_secs * 2.0_f64.powi(attempt as i32);
                attempt = attempt.saturating_add(1);
                let ceiling = exp_secs.min(max_secs);
                let jittered = if ceiling > 0.5 {
                    use rand::Rng;
                    rand::thread_rng().gen_range(0.5..=ceiling)
                } else {
                    ceiling
                };
                Duration::from_secs_f64(jittered)
            }
        }

        let connector = Arc::new(connector);
        let mut reconnect_delay = new_reconnect_delay(self.reverse_tunnel_connection_retry_max_backoff);
        loop {
            let client = self.clone();
            let request_id = Uuid::now_v7();
            let span = span!(
                Level::INFO,
                "tunnel",
                id = request_id.to_string(),
                remote = format!("{}:{}", remote_addr.host, remote_addr.port)
            );
            // A reverse request waits for an incoming connection before the server replies.
            // WebSocket pings have not started yet, so a silently lost request needs a deadline.
            let connect = async {
                match client.config.remote_addr.scheme() {
                    TransportScheme::Ws | TransportScheme::Wss => {
                        tunnel::transport::websocket::connect(request_id, &client, &remote_addr)
                            .await
                            .map(|(r, w, response)| {
                                (TransportReader::Websocket(r), TransportWriter::Websocket(w), response)
                            })
                    }
                    TransportScheme::Http | TransportScheme::Https => {
                        tunnel::transport::http2::connect(request_id, &client, &remote_addr)
                            .await
                            .map(|(r, w, response)| (TransportReader::Http2(r), TransportWriter::Http2(w), response))
                    }
                    TransportScheme::Wts => tunnel::transport::webtransport::connect(request_id, &client, &remote_addr)
                        .await
                        .map(|(r, w, response)| {
                            (
                                TransportReader::WebTransport(Box::new(r)),
                                TransportWriter::WebTransport(Box::new(w)),
                                response,
                            )
                        }),
                }
            }
            .instrument(span.clone());

            let (ws_rx, ws_tx, response) = match tokio::time::timeout(REVERSE_TUNNEL_REPLY_TIMEOUT, connect).await {
                Ok(Ok(tunnel)) => tunnel,
                Ok(Err(err)) => {
                    let delay = reconnect_delay();
                    event!(parent: &span, Level::ERROR, "Retrying in {:?}, cannot connect to remote server: {:?}", delay, err);
                    tokio::time::sleep(delay).await;
                    continue;
                }
                Err(_) => {
                    // Timeout waiting for new reverse tunnel, retrying immediately
                    continue;
                }
            };
            reconnect_delay = new_reconnect_delay(self.reverse_tunnel_connection_retry_max_backoff);

            // Connect to endpoint
            event!(parent: &span, Level::DEBUG, "Server response: {:?}", response);
            if let Some(port_hdr) = response.headers.get("x-assigned-port").and_then(|v| v.to_str().ok()) {
                tracing::info!("Reverse tunnel active on assigned remote port: {port_hdr}");
            }
            let task = {
                let connector = connector.clone();
                async move {
                    let remote = response
                        .headers
                        .get(COOKIE)
                        .and_then(|h| h.to_str().ok())
                        .and_then(|h| jwt_token_to_tunnel(h).ok())
                        .map(|jwt| RemoteAddr {
                            protocol: jwt.claims.p,
                            host: Host::parse(&jwt.claims.r).unwrap_or_else(|_| Host::Domain(String::new())),
                            port: jwt.claims.rp,
                        });

                    let (local_rx, local_tx) = match connector.connect(&remote).instrument(span.clone()).await {
                        Ok(s) => s,
                        Err(err) => {
                            event!(parent: &span, Level::ERROR, "Cannot connect to {remote:?}: {err:?}");
                            return;
                        }
                    };

                    let _ = super::super::transport::io::forward(
                        local_rx,
                        local_tx,
                        ws_rx,
                        ws_tx,
                        client.config.websocket_ping_frequency,
                    )
                    .instrument(span.clone())
                    .await;
                }
            };

            self.executor.spawn(task);
        }
    }
}
