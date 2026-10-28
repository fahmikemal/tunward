use super::devices::{DevicePage, DeviceRecord, Observation};
use super::inventory::Inventory;
use ahash::AHashMap;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::net::SocketAddr;
use std::num::NonZeroU32;
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};
use std::time::SystemTime;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClientRecord {
    pub id: String,
    pub peer_addr: SocketAddr,
    pub connected_at: u64,
    pub last_seen_at: u64,
    pub active_tunnels: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub assigned_port: Option<u16>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SessionRecord {
    pub session_id: String,
    pub client_id: String,
    pub assigned_port: u16,
    pub bind_addr: SocketAddr,
    pub target_port: u16,
    pub created_at: u64,
    #[serde(default)]
    pub kind: String,
    #[serde(default)]
    pub state: String,
    #[serde(default)]
    pub connection_id: Option<String>,
    #[serde(default)]
    pub verified_device_id: Option<String>,
    #[serde(default)]
    pub transport: Option<String>,
    #[serde(default)]
    pub tenant_id: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConnectionRecord {
    pub connection_id: String,
    pub verified_device_id: Option<String>,
    pub certificate_sha256: Option<String>,
    pub peer_addr: SocketAddr,
    pub transport: String,
    pub connected_at: u64,
    pub last_seen_at: u64,
    pub last_client_label: Option<String>,
    #[serde(default)]
    pub tenant_id: Option<String>,
    #[serde(default)]
    pub roles: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HealthStats {
    pub status: &'static str,
    pub version: &'static str,
    pub uptime_seconds: u64,
    pub active_clients: usize,
    pub active_sessions: usize,
    pub active_connections: usize,
    pub active_tunnels: usize,
    pub active_devices: usize,
    pub inventory_enabled: bool,
    pub inventory_healthy: Option<bool>,
}

#[derive(Clone)]
pub struct FleetRegistry {
    clients: Arc<RwLock<AHashMap<String, ClientRecord>>>,
    sessions: Arc<RwLock<AHashMap<String, SessionRecord>>>,
    connections: Arc<RwLock<AHashMap<String, ConnectionRecord>>>,
    inventory: Arc<OnceLock<Inventory>>,
    start_time: SystemTime,
}

impl Default for FleetRegistry {
    fn default() -> Self {
        Self {
            clients: Arc::new(RwLock::new(AHashMap::new())),
            sessions: Arc::new(RwLock::new(AHashMap::new())),
            connections: Arc::default(),
            inventory: Arc::default(),
            start_time: SystemTime::now(),
        }
    }
}

impl FleetRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register_client(&self, id: String, peer_addr: SocketAddr) {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let mut clients = self.clients.write();
        clients
            .entry(id.clone())
            .and_modify(|c| {
                c.peer_addr = peer_addr;
                c.last_seen_at = now;
                c.active_tunnels += 1;
            })
            .or_insert_with(|| ClientRecord {
                id,
                peer_addr,
                connected_at: now,
                last_seen_at: now,
                active_tunnels: 1,
                assigned_port: None,
            });
    }

    pub fn set_client_assigned_port(&self, id: &str, port: u16) {
        let mut clients = self.clients.write();
        if let Some(entry) = clients.get_mut(id) {
            entry.assigned_port = Some(port);
        }
    }

    pub fn unregister_client(&self, id: &str) {
        let mut clients = self.clients.write();
        if let Some(entry) = clients.get_mut(id) {
            entry.active_tunnels = entry.active_tunnels.saturating_sub(1);
            if entry.active_tunnels == 0 {
                clients.remove(id);
            }
        }
    }

    pub fn list_clients(&self) -> Vec<ClientRecord> {
        self.clients.read().values().cloned().collect()
    }

    pub fn get_client(&self, id: &str) -> Option<ClientRecord> {
        self.clients.read().get(id).cloned()
    }

    pub fn add_session(&self, session: SessionRecord) {
        self.sessions.write().insert(session.session_id.clone(), session);
    }

    pub fn register_session(
        &self,
        session_id: String,
        client_id: String,
        assigned_port: u16,
        bind_addr: SocketAddr,
        target_port: u16,
    ) {
        let created_at = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        self.set_client_assigned_port(&client_id, assigned_port);
        self.add_session(SessionRecord {
            session_id,
            client_id,
            assigned_port,
            bind_addr,
            target_port,
            created_at,
            kind: "legacy".into(),
            state: "active".into(),
            connection_id: None,
            verified_device_id: None,
            transport: None,
            tenant_id: None,
        });
    }

    pub fn remove_session(&self, session_id: &str) -> Option<SessionRecord> {
        self.sessions.write().remove(session_id)
    }

    pub fn unregister_session(&self, session_id: &str) -> Option<SessionRecord> {
        self.remove_session(session_id)
    }

    pub fn list_sessions(&self) -> Vec<SessionRecord> {
        self.sessions.read().values().cloned().collect()
    }

    pub fn health(&self) -> HealthStats {
        let uptime = self.start_time.elapsed().map(|d| d.as_secs()).unwrap_or(0);
        let active_clients = self.clients.read().len();
        let active_sessions = self.sessions.read().len();
        let inventory_healthy = self.inventory.get().map(Inventory::healthy);
        HealthStats {
            status: if inventory_healthy == Some(false) {
                "degraded"
            } else {
                "healthy"
            },
            version: env!("CARGO_PKG_VERSION"),
            uptime_seconds: uptime,
            active_clients,
            active_sessions,
            active_connections: self.connections.read().len(),
            active_tunnels: self.sessions.read().values().filter(|s| s.kind == "tunnel").count(),
            active_devices: self
                .connections
                .read()
                .values()
                .filter_map(|c| c.verified_device_id.as_ref())
                .collect::<HashSet<_>>()
                .len(),
            inventory_enabled: self.inventory.get().is_some(),
            inventory_healthy,
        }
    }

    pub fn list_connections(&self) -> Vec<ConnectionRecord> {
        self.connections.read().values().cloned().collect()
    }

    pub(crate) async fn attach_inventory(&self, path: PathBuf, capacity: NonZeroU32) -> anyhow::Result<()> {
        let inventory = Inventory::open(path, capacity).await?;
        self.inventory
            .set(inventory)
            .map_err(|_| anyhow::anyhow!("inventory already configured"))
    }

    pub(crate) async fn connection(
        &self,
        identity: Option<String>,
        fingerprint: Option<String>,
        peer_addr: SocketAddr,
        transport: &str,
    ) -> anyhow::Result<ConnectionLease> {
        if let (Some(inventory), Some(identity), Some(fingerprint)) = (self.inventory.get(), &identity, &fingerprint) {
            inventory
                .observe(Observation {
                    identity: identity.clone(),
                    fingerprint: fingerprint.clone(),
                    transport: transport.into(),
                    timestamp: now(),
                })
                .await?;
        }
        let id = uuid::Uuid::now_v7().to_string();
        self.connections.write().insert(
            id.clone(),
            ConnectionRecord {
                connection_id: id.clone(),
                verified_device_id: identity,
                certificate_sha256: fingerprint,
                peer_addr,
                transport: transport.into(),
                connected_at: now(),
                last_seen_at: now(),
                last_client_label: None,
                tenant_id: None,
                roles: Vec::new(),
            },
        );
        Ok(ConnectionLease(Arc::new(ConnectionState {
            registry: self.clone(),
            id,
        })))
    }

    pub(crate) fn tunnel(
        &self,
        connection: Option<&ConnectionLease>,
        label: Option<String>,
        peer: SocketAddr,
        target_port: u16,
    ) -> TunnelLease {
        let record = connection.and_then(|lease| {
            self.connections.write().get_mut(&lease.0.id).map(|record| {
                record.last_seen_at = now();
                record.last_client_label = label.clone();
                record.clone()
            })
        });
        let peer = record.as_ref().map(|r| r.peer_addr).unwrap_or(peer);
        if let Some(label) = &label {
            self.register_client(label.clone(), peer);
        }
        let id = uuid::Uuid::now_v7().to_string();
        self.add_session(SessionRecord {
            session_id: id.clone(),
            client_id: label.clone().unwrap_or_else(|| "anonymous".into()),
            assigned_port: 0,
            bind_addr: peer,
            target_port,
            created_at: now(),
            kind: "tunnel".into(),
            state: "pending".into(),
            connection_id: record.as_ref().map(|r| r.connection_id.clone()),
            verified_device_id: record.as_ref().and_then(|r| r.verified_device_id.clone()),
            tenant_id: record.as_ref().and_then(|r| r.tenant_id.clone()),
            transport: record.map(|r| r.transport),
        });
        TunnelLease(Arc::new(TunnelState {
            registry: self.clone(),
            id,
            label,
            _connection: connection.cloned(),
        }))
    }

    pub async fn list_devices(&self, limit: usize, after: String) -> anyhow::Result<DevicePage> {
        let mut page = self
            .inventory
            .get()
            .ok_or_else(|| anyhow::anyhow!("persistent inventory is not configured"))?
            .list(limit, after)
            .await?;
        for device in &mut page.devices {
            self.decorate_device(device);
        }
        Ok(page)
    }

    pub async fn get_device(&self, id: String) -> anyhow::Result<Option<DeviceRecord>> {
        let mut device = self
            .inventory
            .get()
            .ok_or_else(|| anyhow::anyhow!("persistent inventory is not configured"))?
            .get(id)
            .await?;
        if let Some(device) = &mut device {
            self.decorate_device(device);
        }
        Ok(device)
    }

    fn decorate_device(&self, device: &mut DeviceRecord) {
        device.active_connections = self
            .connections
            .read()
            .values()
            .filter(|c| c.verified_device_id.as_ref() == Some(&device.id))
            .count();
        device.active_tunnels = self
            .sessions
            .read()
            .values()
            .filter(|s| s.kind == "tunnel" && s.verified_device_id.as_ref() == Some(&device.id))
            .count();
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

struct ConnectionState {
    registry: FleetRegistry,
    id: String,
}
impl Drop for ConnectionState {
    fn drop(&mut self) {
        self.registry.connections.write().remove(&self.id);
    }
}
#[derive(Clone)]
pub(crate) struct ConnectionLease(Arc<ConnectionState>);
pub(crate) struct WeakConnectionLease(std::sync::Weak<ConnectionState>);

impl WeakConnectionLease {
    pub fn upgrade(&self) -> Option<ConnectionLease> {
        self.0.upgrade().map(ConnectionLease)
    }
}

impl ConnectionLease {
    pub fn downgrade(&self) -> WeakConnectionLease {
        WeakConnectionLease(Arc::downgrade(&self.0))
    }
    pub fn set_tenant(&self, tenant: Option<&str>, roles: &[String]) {
        if let Some(record) = self.0.registry.connections.write().get_mut(&self.0.id) {
            record.tenant_id = tenant.map(str::to_string);
            record.roles = roles.to_vec();
        }
    }
    pub fn set_tcp_transport(&self, transport: &str) {
        if let Some(record) = self.0.registry.connections.write().get_mut(&self.0.id)
            && matches!(record.transport.as_str(), "tcp" | "ws" | "http")
        {
            record.transport = transport.into();
        }
    }
}

struct TunnelState {
    registry: FleetRegistry,
    id: String,
    label: Option<String>,
    _connection: Option<ConnectionLease>,
}
impl Drop for TunnelState {
    fn drop(&mut self) {
        self.registry.remove_session(&self.id);
        if let Some(label) = &self.label {
            self.registry.unregister_client(label);
        }
    }
}
#[derive(Clone)]
pub(crate) struct TunnelLease(Arc<TunnelState>);
impl TunnelLease {
    pub fn ready(&self, assigned_port: u16) {
        if let Some(record) = self.0.registry.sessions.write().get_mut(&self.0.id) {
            record.state = "forwarding".into();
            record.assigned_port = assigned_port;
        }
        if let Some(label) = &self.0.label {
            self.0.registry.set_client_assigned_port(label, assigned_port);
        }
    }
    pub fn listener(&self, bind: SocketAddr) -> ListenerLease {
        let id = uuid::Uuid::now_v7().to_string();
        let record = self.0.registry.sessions.read().get(&self.0.id).cloned();
        if let Some(mut record) = record {
            record.session_id = id.clone();
            record.kind = "reverse_listener".into();
            record.state = "listening".into();
            record.bind_addr = bind;
            record.assigned_port = bind.port();
            self.0.registry.add_session(record);
        }
        if let Some(label) = &self.0.label {
            self.0.registry.set_client_assigned_port(label, bind.port());
        }
        ListenerLease {
            registry: self.0.registry.clone(),
            id,
        }
    }
}
pub(crate) struct ListenerLease {
    registry: FleetRegistry,
    id: String,
}
impl Drop for ListenerLease {
    fn drop(&mut self) {
        self.registry.remove_session(&self.id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn leases_separate_verified_identity_from_shared_labels_and_drop_once() {
        let registry = FleetRegistry::new();
        let peer = "127.0.0.1:1234".parse().unwrap();
        let a = registry
            .connection(Some("a".into()), Some("key-a".into()), peer, "wss")
            .await
            .unwrap();
        let b = registry
            .connection(Some("b".into()), Some("key-b".into()), peer, "wts")
            .await
            .unwrap();
        let first = registry.tunnel(Some(&a), Some("same-label".into()), peer, 80);
        let clone = first.clone();
        let second = registry.tunnel(Some(&b), Some("same-label".into()), peer, 80);
        assert_eq!(registry.health().active_devices, 2);
        assert_eq!(registry.get_client("same-label").unwrap().active_tunnels, 2);
        let listener = first.listener("127.0.0.1:8444".parse().unwrap());
        drop(a);
        drop(first);
        assert_eq!(registry.health().active_tunnels, 2);
        drop(clone);
        assert_eq!(registry.health().active_connections, 1);
        assert_eq!(registry.health().active_tunnels, 1);
        assert_eq!(
            registry
                .list_sessions()
                .iter()
                .filter(|s| s.kind == "reverse_listener")
                .count(),
            1
        );
        drop(second);
        drop(b);
        drop(listener);
        assert_eq!(registry.health().active_connections, 0);
        assert!(registry.list_sessions().is_empty());
        assert!(registry.list_clients().is_empty());
    }

    #[test]
    fn test_fleet_registry_client_lifecycle() {
        let registry = FleetRegistry::new();
        let peer: SocketAddr = "10.0.0.1:12345".parse().unwrap();

        assert_eq!(registry.list_clients().len(), 0);

        // Register client
        registry.register_client("kiosk-01".to_string(), peer);
        let clients = registry.list_clients();
        assert_eq!(clients.len(), 1);
        assert_eq!(clients[0].id, "kiosk-01");
        assert_eq!(clients[0].peer_addr, peer);
        assert_eq!(clients[0].active_tunnels, 1);

        // Second tunnel from same client
        registry.register_client("kiosk-01".to_string(), peer);
        let client = registry.get_client("kiosk-01").unwrap();
        assert_eq!(client.active_tunnels, 2);

        // Unregister one tunnel -> client still active
        registry.unregister_client("kiosk-01");
        let client = registry.get_client("kiosk-01").unwrap();
        assert_eq!(client.active_tunnels, 1);

        // Unregister second tunnel -> client removed
        registry.unregister_client("kiosk-01");
        assert!(registry.get_client("kiosk-01").is_none());
    }

    #[test]
    fn test_fleet_registry_sessions_and_health() {
        let registry = FleetRegistry::new();
        let session = SessionRecord {
            session_id: "sess_01".to_string(),
            client_id: "kiosk-01".to_string(),
            assigned_port: 24892,
            bind_addr: "127.0.0.1:24892".parse().unwrap(),
            target_port: 15555,
            created_at: 100,
            kind: "legacy".into(),
            state: "active".into(),
            connection_id: None,
            verified_device_id: None,
            transport: None,
            tenant_id: None,
        };

        registry.add_session(session);
        assert_eq!(registry.list_sessions().len(), 1);

        let health = registry.health();
        assert_eq!(health.status, "healthy");
        assert_eq!(health.active_sessions, 1);

        let removed = registry.remove_session("sess_01");
        assert!(removed.is_some());
        assert_eq!(registry.list_sessions().len(), 0);
    }
}
