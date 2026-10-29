pub mod api;
mod devices;
// The SQLite inventory; builds without it get a stand-in that refuses --fleet-inventory.
#[cfg(feature = "fleet-inventory")]
mod inventory;
#[cfg(not(feature = "fleet-inventory"))]
#[path = "inventory_disabled.rs"]
mod inventory;
pub mod registry;

pub use api::run_management_server;
pub use devices::{DevicePage, DeviceRecord};
pub use registry::{ClientRecord, ConnectionRecord, FleetRegistry, HealthStats, SessionRecord};
