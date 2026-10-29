//! Device records reported by the management API, whichever inventory backend stores them.

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DeviceRecord {
    pub id: String,
    pub first_seen_at: u64,
    pub last_seen_at: u64,
    pub last_certificate_sha256: String,
    pub last_transport: String,
    pub observed_connections: u64,
    pub active_connections: usize,
    pub active_tunnels: usize,
}

#[derive(Debug, Serialize)]
pub struct DevicePage {
    pub devices: Vec<DeviceRecord>,
    pub next_cursor: Option<String>,
}

// Only the SQLite inventory reads an observation; builds without it record none.
#[cfg_attr(not(feature = "fleet-inventory"), allow(dead_code))]
pub(crate) struct Observation {
    pub identity: String,
    pub fingerprint: String,
    pub transport: String,
    pub timestamp: u64,
}
