//! Every policy example in the repository loads with the server's own loaders, so an example
//! cannot drift from the schema unnoticed.

use crate::quotas::DeviceQuotaConfig;
use crate::restrictions::types::RestrictionsRules;
use crate::revocation::RevocationManager;
use crate::tenants::TenantPolicy;
use std::path::{Path, PathBuf};

fn repository(path: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join(path)
}

fn restrictions(path: &Path) -> RestrictionsRules {
    RestrictionsRules::from_config_file(path).unwrap_or_else(|err| panic!("{}: {err:#}", path.display()))
}

#[test]
fn restriction_examples_load() {
    let mut examples: Vec<_> = std::fs::read_dir(repository("examples/restrictions"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|extension| extension == "yaml"))
        .collect();
    examples.sort();
    assert!(!examples.is_empty(), "examples/restrictions holds no example");
    for path in [
        repository("restrictions.yaml"),
        repository("tenant-restrictions.example.yaml"),
    ]
    .into_iter()
    .chain(examples)
    {
        assert!(!restrictions(&path).restrictions.is_empty(), "{} has no rule", path.display());
    }
}

#[test]
fn quota_revocation_and_tenant_examples_load() {
    DeviceQuotaConfig::from_path(&repository("device-quotas.example.yaml")).unwrap();
    RevocationManager::from_path(&repository("device-revocations.example.yaml")).unwrap();
    let rules = restrictions(&repository("tenant-restrictions.example.yaml"));
    TenantPolicy::from_path(&repository("tenant-policy.example.yaml"), &rules).unwrap();
}
