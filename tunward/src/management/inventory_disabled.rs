//! Stands in for the persistent fleet inventory in builds without the `fleet-inventory` feature.

use super::devices::{DevicePage, DeviceRecord, Observation};
use std::num::NonZeroU32;
use std::path::PathBuf;

/// Never constructed: opening always fails, so its other methods cannot be reached.
#[derive(Clone)]
pub(crate) struct Inventory(Unbuildable);

#[derive(Clone, Copy)]
enum Unbuildable {}

impl Inventory {
    pub async fn open(path: PathBuf, _capacity: NonZeroU32) -> anyhow::Result<Self> {
        anyhow::bail!(
            "cannot open fleet inventory {}: this build has no fleet-inventory feature (it is on by default)",
            path.display()
        )
    }

    fn unreachable(&self) -> ! {
        let never = self.0;
        match never {}
    }

    pub fn healthy(&self) -> bool {
        self.unreachable()
    }

    pub async fn observe(&self, _observation: Observation) -> anyhow::Result<()> {
        self.unreachable()
    }

    pub async fn list(&self, _limit: usize, _after: String) -> anyhow::Result<DevicePage> {
        self.unreachable()
    }

    pub async fn get(&self, _identity: String) -> anyhow::Result<Option<DeviceRecord>> {
        self.unreachable()
    }
}
