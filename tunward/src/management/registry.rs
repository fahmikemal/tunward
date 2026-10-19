use ahash::AHashMap;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::SystemTime;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClientRecord {
    pub id: String,
    pub peer_addr: SocketAddr,
    pub connected_at: u64,
    pub last_seen_at: u64,
    pub active_tunnels: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SessionRecord {
    pub session_id: String,
    pub client_id: String,
    pub assigned_port: u16,
    pub bind_addr: SocketAddr,
    pub target_port: u16,
    pub created_at: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HealthStats {
    pub status: &'static str,
    pub version: &'static str,
    pub uptime_seconds: u64,
    pub active_clients: usize,
    pub active_sessions: usize,
}

#[derive(Clone)]
pub struct FleetRegistry {
    clients: Arc<RwLock<AHashMap<String, ClientRecord>>>,
    sessions: Arc<RwLock<AHashMap<String, SessionRecord>>>,
    start_time: SystemTime,
}

impl Default for FleetRegistry {
    fn default() -> Self {
        Self {
            clients: Arc::new(RwLock::new(AHashMap::new())),
            sessions: Arc::new(RwLock::new(AHashMap::new())),
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
            });
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
        self.add_session(SessionRecord {
            session_id,
            client_id,
            assigned_port,
            bind_addr,
            target_port,
            created_at,
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
        HealthStats {
            status: "healthy",
            version: env!("CARGO_PKG_VERSION"),
            uptime_seconds: uptime,
            active_clients,
            active_sessions,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
