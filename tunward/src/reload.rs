//! Validated configuration generations and acknowledged, process-local reload requests.
use crate::config::ServerCreationRequest;
use crate::management::registry::{ConnectionLease, WeakConnectionLease};
use crate::protocols::tls;
use crate::quotas::DeviceQuotaConfig;
use crate::restrictions::types::RestrictionsRules;
use crate::revocation::{RevocationGuard, WeakRevocationGuard};
use crate::server_config::{ServerConfigFiles, load_server_files};
use crate::tenants::{TenantAccess, TenantPolicy};
use crate::tunnel::transport::webtransport::mk_transport_config;
use anyhow::{Context, anyhow, ensure};
use arc_swap::ArcSwap;
use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};
use tokio_rustls::TlsAcceptor;
use tracing::{info, warn};
use web_transport_quinn::quinn;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ReloadStatus {
    pub generation: u64,
    pub disconnected_sessions: usize,
}

type Reply = oneshot::Sender<Result<ReloadStatus, String>>;

/// One consumer belongs to the running server. Clones may request a serialized reload.
#[derive(Clone)]
pub struct ServerReload {
    sender: mpsc::Sender<Reply>,
    receiver: Arc<tokio::sync::Mutex<Option<mpsc::Receiver<Reply>>>>,
}

impl Default for ServerReload {
    fn default() -> Self {
        let (sender, receiver) = mpsc::channel(1);
        Self {
            sender,
            receiver: Arc::new(tokio::sync::Mutex::new(Some(receiver))),
        }
    }
}

impl ServerReload {
    /// Wait for validation and activation; an error leaves the active generation unchanged.
    pub async fn reload(&self) -> anyhow::Result<ReloadStatus> {
        tokio::time::timeout(Duration::from_secs(30), async {
            let (reply, result) = oneshot::channel();
            self.sender.send(reply).await.context("Reload server is unavailable")?;
            result
                .await
                .context("Reload server stopped before acknowledgment")?
                .map_err(|message| anyhow!(message))
        })
        .await
        .context("Reload acknowledgment timed out; outcome is unconfirmed")?
    }

    pub(crate) async fn take_receiver(&self) -> anyhow::Result<mpsc::Receiver<Reply>> {
        self.receiver
            .lock()
            .await
            .take()
            .context("Reload handle already belongs to a server")
    }
}

#[derive(Clone)]
pub(crate) struct ReloadSnapshot {
    pub generation: u64,
    pub restrictions: Arc<RestrictionsRules>,
    pub tenants: Option<Arc<TenantPolicy>>,
    pub device_quotas: Option<Arc<DeviceQuotaConfig>>,
    pub tcp_tls: Option<Arc<TlsAcceptor>>,
    pub quic_tls: Option<quinn::ServerConfig>,
}

impl ReloadSnapshot {
    pub fn prepare(args: &ServerCreationRequest, files: &ServerConfigFiles, generation: u64) -> anyhow::Result<Self> {
        let tcp_tls = files
            .tls
            .as_ref()
            .map(|config| tls::tls_acceptor(config, Some(vec![b"h2".to_vec(), b"http/1.1".to_vec()])).map(Arc::new))
            .transpose()?;
        let quic_tls = if args.enable_webtransport || args.remote_addr.scheme() == "wts" {
            let config = files.tls.as_ref().context("WebTransport requires TLS")?;
            let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls::quic_server_config(config)?)?;
            let mut config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
            let heartbeat = args
                .websocket_ping_frequency
                .or(Some(Duration::from_secs(30)))
                .filter(|duration| duration.as_secs() > 0);
            config.transport_config(Arc::new(mk_transport_config(heartbeat)?));
            Some(config)
        } else {
            None
        };
        Ok(Self {
            generation,
            restrictions: Arc::new(files.restrictions.clone()),
            tenants: files.tenants.clone(),
            device_quotas: files.device_quotas.clone().map(Arc::new),
            tcp_tls,
            quic_tls,
        })
    }
}

struct ReloadSession {
    identity: String,
    revocation: WeakRevocationGuard,
    tenant: Mutex<Option<TenantAccess>>,
    fleet: Option<WeakConnectionLease>,
}

pub(crate) struct ReloadState {
    pub live: Arc<ArcSwap<ReloadSnapshot>>,
    source: ServerCreationRequest,
    sessions: Mutex<Vec<ReloadSession>>,
    endpoint: Mutex<Option<quinn::Endpoint>>,
    gate: RwLock<()>,
}

impl ReloadState {
    pub fn new(source: ServerCreationRequest, snapshot: ReloadSnapshot) -> Self {
        Self {
            source,
            live: Arc::new(ArcSwap::from_pointee(snapshot)),
            sessions: Mutex::new(Vec::new()),
            endpoint: Mutex::new(None),
            gate: RwLock::new(()),
        }
    }

    pub fn snapshot(&self) -> Arc<ReloadSnapshot> {
        let _gate = self.gate.read();
        self.live.load_full()
    }

    pub fn register_endpoint(&self, endpoint: quinn::Endpoint) {
        *self.endpoint.lock() = Some(endpoint);
    }

    pub fn register(
        &self,
        identity: Option<&str>,
        revocation: &RevocationGuard,
        tenant: Option<&TenantAccess>,
        fleet: Option<&ConnectionLease>,
    ) -> anyhow::Result<()> {
        let Some(weak_guard) = revocation.downgrade() else {
            return Ok(());
        };
        let mut sessions = self.sessions.lock();
        let snapshot = self.snapshot();
        let access = snapshot
            .tenants
            .as_ref()
            .map(|policy| policy.access(identity.context("Verified tenant identity required")?))
            .transpose()?;
        ensure!(
            match (&access, tenant) {
                (Some(new), Some(old)) => new.retains(old),
                (None, None) => true,
                _ => false,
            },
            "Tenant access changed while the connection was being registered"
        );
        let session = ReloadSession {
            identity: identity.unwrap_or_default().to_owned(),
            revocation: weak_guard,
            tenant: Mutex::new(access),
            fleet: fleet.map(ConnectionLease::downgrade),
        };
        sessions.retain(|session| session.revocation.upgrade().is_some());
        sessions.push(session);
        Ok(())
    }

    pub async fn run(self: Arc<Self>, mut requests: mpsc::Receiver<Reply>) {
        while let Some(reply) = requests.recv().await {
            if reply.is_closed() {
                continue;
            }
            let source = self.source.clone();
            let generation = match self.snapshot().generation.checked_add(1) {
                Some(value) => value,
                None => {
                    let _ = reply.send(Err("Configuration generation exhausted".into()));
                    continue;
                }
            };
            let candidate = tokio::task::spawn_blocking(move || {
                let files = load_server_files(&source)?;
                ReloadSnapshot::prepare(&source, &files, generation)
            })
            .await
            .context("Configuration preparation task failed")
            .and_then(|result| result);
            let result = candidate.and_then(|candidate| {
                ensure!(!reply.is_closed(), "Reload requester disconnected before activation");
                self.commit(candidate)
            });
            match &result {
                Ok(status) => info!(
                    generation = status.generation,
                    disconnected_sessions = status.disconnected_sessions,
                    "Configuration reload applied"
                ),
                Err(error) => warn!("Configuration reload rejected; active generation retained: {error:#}"),
            }
            let _ = reply.send(result.map_err(|error| format!("{error:#}")));
        }
    }

    fn commit(&self, candidate: ReloadSnapshot) -> anyhow::Result<ReloadStatus> {
        let mut sessions = self.sessions.lock();
        let _gate = self.gate.write();
        let endpoint = self.endpoint.lock();
        if let Some(config) = &candidate.quic_tls {
            endpoint
                .as_ref()
                .context("WebTransport endpoint is not ready for reload")?
                .set_server_config(Some(config.clone()));
        }
        let mut disconnected_sessions = 0;
        self.live.store(Arc::new(candidate));
        let active = self.live.load();
        sessions.retain(|session| {
            let Some(guard) = session.revocation.upgrade() else {
                return false;
            };
            let new = active
                .tenants
                .as_ref()
                .map(|policy| policy.access(&session.identity))
                .transpose();
            let mut previous = session.tenant.lock();
            let keep = match (&new, previous.as_ref()) {
                (Ok(Some(new)), Some(old)) => new.retains(old),
                (Ok(None), None) => true,
                _ => false,
            };
            if keep {
                let access = new.expect("checked above");
                if let Some(fleet) = session.fleet.as_ref().and_then(WeakConnectionLease::upgrade) {
                    fleet.set_tenant(
                        access.as_ref().map(TenantAccess::tenant_id),
                        access.as_ref().map(TenantAccess::roles).unwrap_or(&[]),
                    );
                }
                *previous = access;
            } else if !guard.is_revoked() {
                guard.revoke();
                disconnected_sessions += 1;
            }
            true
        });
        Ok(ReloadStatus {
            generation: active.generation,
            disconnected_sessions,
        })
    }
}
