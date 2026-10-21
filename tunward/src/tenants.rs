//! Startup-loaded tenant scope and role permissions for verified mTLS identities.

use crate::restrictions::types::RestrictionsRules;
use crate::tunnel::{LocalProtocol, RemoteAddr};
use anyhow::{Context, ensure};
use rand::seq::SliceRandom;
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::io::Read;
use std::net::{IpAddr, SocketAddr};
use std::ops::RangeInclusive;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Hash)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Permission {
    ForwardTcp,
    ForwardUdp,
    ReverseTcp,
    ReverseUdp,
    ReverseSocks5,
    ReverseHttpProxy,
    ReverseUnix,
}

impl Permission {
    fn for_protocol(protocol: &LocalProtocol) -> Option<Self> {
        Some(match protocol {
            LocalProtocol::Tcp { .. } => Self::ForwardTcp,
            LocalProtocol::Udp { .. } => Self::ForwardUdp,
            LocalProtocol::ReverseTcp => Self::ReverseTcp,
            LocalProtocol::ReverseUdp { .. } => Self::ReverseUdp,
            LocalProtocol::ReverseSocks5 { .. } => Self::ReverseSocks5,
            LocalProtocol::ReverseHttpProxy { .. } => Self::ReverseHttpProxy,
            LocalProtocol::ReverseUnix { .. } => Self::ReverseUnix,
            _ => return None,
        })
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyFile {
    version: u32,
    roles: HashMap<String, Vec<Permission>>,
    tenants: HashMap<String, TenantFile>,
    devices: HashMap<String, Membership>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TenantFile {
    restrictions: Vec<String>,
    #[serde(default)]
    reverse_bindings: Vec<BindingFile>,
    #[serde(default)]
    reverse_unix_paths: Vec<PathBuf>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BindingFile {
    address: IpAddr,
    ports: Vec<String>,
    #[serde(default)]
    allow_ephemeral: bool,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Membership {
    tenant: String,
    roles: Vec<String>,
}

struct Binding {
    address: IpAddr,
    ports: Vec<RangeInclusive<u16>>,
    allow_ephemeral: bool,
}

struct Tenant {
    restrictions: HashSet<String>,
    bindings: Vec<Binding>,
    unix_paths: HashSet<PathBuf>,
}

pub(crate) struct TenantPolicy {
    tenants: HashMap<String, Tenant>,
    roles: HashMap<String, HashSet<Permission>>,
    devices: HashMap<String, Membership>,
}

fn port_range(value: &str) -> anyhow::Result<RangeInclusive<u16>> {
    let (start, end) = value.split_once("..").unwrap_or((value, value));
    let (start, end) = (start.parse::<u16>()?, end.parse::<u16>()?);
    ensure!(
        start > 0 && start <= end,
        "invalid tenant port range {value}; use positive ascending ports"
    );
    Ok(start..=end)
}

fn validate_unix_path(path: &Path) -> anyhow::Result<()> {
    ensure!(
        !path
            .as_os_str()
            .as_encoded_bytes()
            .split(|byte| *byte == b'/')
            .any(|part| part == b"." || part == b".."),
        "tenant Unix paths must not contain dot or parent components"
    );
    ensure!(
        path.is_absolute() && path.file_name().is_some(),
        "tenant Unix paths must be absolute file paths"
    );
    ensure!(
        path.components()
            .all(|c| matches!(c, Component::RootDir | Component::Normal(_))),
        "tenant Unix paths must not contain dot or parent components"
    );
    let parent = path.parent().expect("absolute file parent");
    ensure!(
        parent.canonicalize()? == parent,
        "tenant Unix parent must exist and be canonical (no symlink aliases)"
    );
    Ok(())
}

impl TenantPolicy {
    pub fn from_path(path: &Path, restrictions: &RestrictionsRules) -> anyhow::Result<Arc<Self>> {
        ensure!(std::fs::metadata(path)?.is_file(), "tenant policy must be a regular file");
        let mut bytes = Vec::new();
        std::fs::File::open(path)?.take(1_048_577).read_to_end(&mut bytes)?;
        ensure!(bytes.len() <= 1_048_576, "tenant policy exceeds 1 MiB");
        Self::parse(&bytes, restrictions)
            .map(Arc::new)
            .with_context(|| format!("Invalid tenant policy {}", path.display()))
    }

    fn parse(bytes: &[u8], restrictions: &RestrictionsRules) -> anyhow::Result<Self> {
        let file: PolicyFile = serde_yaml::from_slice(bytes)?;
        ensure!(file.version == 1, "unsupported tenant policy version; expected 1");
        ensure!(
            file.devices.len() <= 10000 && file.roles.len() <= 1000 && file.tenants.len() <= 1000,
            "tenant policy exceeds identity/role/tenant capacity"
        );
        let mut names = HashSet::new();
        for rule in &restrictions.restrictions {
            ensure!(
                !rule.name.is_empty() && names.insert(rule.name.clone()),
                "tenant mode requires unique nonempty restriction names"
            );
        }
        let mut roles = HashMap::new();
        for (name, permissions) in file.roles {
            ensure!(
                !name.is_empty() && !permissions.is_empty(),
                "roles need a nonempty name and permissions"
            );
            roles.insert(name, permissions.into_iter().collect());
        }
        let mut tenants = HashMap::new();
        let mut reserved: Vec<(IpAddr, RangeInclusive<u16>)> = Vec::new();
        let mut unix_paths = HashSet::new();
        for (name, tenant) in file.tenants {
            ensure!(
                !name.is_empty() && !tenant.restrictions.is_empty(),
                "tenants need a nonempty name and restriction scope"
            );
            for rule in &tenant.restrictions {
                ensure!(names.contains(rule), "tenant {name} references unknown restriction {rule}");
            }
            let mut bindings = Vec::new();
            for binding in tenant.reverse_bindings {
                ensure!(
                    !binding.address.is_unspecified() && !binding.address.is_multicast(),
                    "tenant reverse bindings require a concrete unicast address"
                );
                ensure!(
                    !matches!(binding.address, IpAddr::V6(ip) if ip.to_ipv4_mapped().is_some()),
                    "IPv4-mapped IPv6 bind aliases are not allowed in tenant policy"
                );
                ensure!(!binding.ports.is_empty(), "tenant reverse binding needs reserved ports");
                let ports = binding
                    .ports
                    .iter()
                    .map(|value| port_range(value))
                    .collect::<anyhow::Result<Vec<_>>>()?;
                for range in &ports {
                    ensure!(
                        !reserved.iter().any(|(address, other)| *address == binding.address
                            && range.start() <= other.end()
                            && other.start() <= range.end()),
                        "overlapping tenant reverse port reservations on {}",
                        binding.address
                    );
                    reserved.push((binding.address, range.clone()));
                }
                bindings.push(Binding {
                    address: binding.address,
                    ports,
                    allow_ephemeral: binding.allow_ephemeral,
                });
            }
            for path in &tenant.reverse_unix_paths {
                validate_unix_path(path)?;
                ensure!(
                    unix_paths.insert(path.clone()),
                    "Unix listener path is reserved more than once: {}",
                    path.display()
                );
            }
            tenants.insert(
                name,
                Tenant {
                    restrictions: tenant.restrictions.into_iter().collect(),
                    bindings,
                    unix_paths: tenant.reverse_unix_paths.into_iter().collect(),
                },
            );
        }
        for (identity, membership) in &file.devices {
            ensure!(
                !identity.is_empty() && tenants.contains_key(&membership.tenant),
                "device {identity} has an unknown tenant"
            );
            ensure!(
                !membership.roles.is_empty() && membership.roles.iter().all(|role| roles.contains_key(role)),
                "device {identity} has missing or unknown roles"
            );
        }
        Ok(Self {
            tenants,
            roles,
            devices: file.devices,
        })
    }

    pub fn access(self: &Arc<Self>, identity: &str) -> anyhow::Result<TenantAccess> {
        let membership = self
            .devices
            .get(identity)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("verified device has no tenant membership"))?;
        Ok(TenantAccess {
            policy: self.clone(),
            membership,
        })
    }
}

#[derive(Clone)]
pub(crate) struct TenantAccess {
    policy: Arc<TenantPolicy>,
    membership: Membership,
}

impl TenantAccess {
    /// A restrictive grant change invalidates the device's retained listeners and transport sessions.
    pub(crate) fn retains(&self, previous: &Self) -> bool {
        if self.tenant_id() != previous.tenant_id() {
            return false;
        }
        let current = &self.policy.tenants[self.tenant_id()];
        let old = &previous.policy.tenants[previous.tenant_id()];
        let permissions = self
            .membership
            .roles
            .iter()
            .flat_map(|role| &self.policy.roles[role])
            .collect::<HashSet<_>>();
        old.restrictions.is_subset(&current.restrictions)
            && old.unix_paths.is_subset(&current.unix_paths)
            && previous
                .membership
                .roles
                .iter()
                .flat_map(|role| &previous.policy.roles[role])
                .all(|permission| permissions.contains(permission))
            && old.bindings.iter().all(|binding| {
                let mut granted = current
                    .bindings
                    .iter()
                    .filter(|new| binding.address == new.address && (!binding.allow_ephemeral || new.allow_ephemeral))
                    .flat_map(|new| &new.ports)
                    .collect::<Vec<_>>();
                granted.sort_unstable_by_key(|range| *range.start());
                binding.ports.iter().all(|range| {
                    let mut next = u32::from(*range.start());
                    for grant in &granted {
                        if u32::from(*grant.start()) > next {
                            break;
                        }
                        next = next.max(u32::from(*grant.end()) + 1);
                        if next > u32::from(*range.end()) {
                            return true;
                        }
                    }
                    false
                })
            })
    }
    pub fn tenant_id(&self) -> &str {
        &self.membership.tenant
    }
    pub fn roles(&self) -> &[String] {
        &self.membership.roles
    }

    pub fn allows(&self, protocol: &LocalProtocol, restriction_name: &str) -> bool {
        let Some(permission) = Permission::for_protocol(protocol) else {
            return false;
        };
        self.policy.tenants[&self.membership.tenant]
            .restrictions
            .contains(restriction_name)
            && self
                .membership
                .roles
                .iter()
                .any(|role| self.policy.roles[role].contains(&permission))
    }

    pub fn authorize_reverse(&self, remote: &RemoteAddr, mapped_port: u16) -> anyhow::Result<()> {
        if !remote.protocol.is_reverse_tunnel() {
            return Ok(());
        }
        let tenant = &self.policy.tenants[&self.membership.tenant];
        if let LocalProtocol::ReverseUnix { path } = &remote.protocol {
            ensure!(tenant.unix_paths.contains(path), "Unix path is outside tenant ownership");
            validate_unix_path(path)?;
            return Ok(());
        }
        let ip = match remote.host {
            url::Host::Ipv4(ip) => IpAddr::V4(ip),
            url::Host::Ipv6(ip) => IpAddr::V6(ip),
            _ => anyhow::bail!("tenant reverse bindings require a literal IP"),
        };
        ensure!(
            tenant.bindings.iter().any(|binding| binding.address == ip
                && if mapped_port == 0 {
                    binding.allow_ephemeral
                } else {
                    binding.ports.iter().any(|range| range.contains(&mapped_port))
                }),
            "reverse bind is outside tenant ownership"
        );
        Ok(())
    }

    pub fn bind_candidates(&self, bind: SocketAddr) -> Vec<SocketAddr> {
        if bind.port() != 0 {
            return vec![bind];
        }
        let candidates = self.policy.tenants[&self.membership.tenant]
            .bindings
            .iter()
            .filter(|binding| binding.address == bind.ip() && binding.allow_ephemeral)
            .flat_map(|binding| binding.ports.iter().flat_map(|range| range.clone()))
            .map(|port| SocketAddr::new(bind.ip(), port))
            .collect::<Vec<_>>();
        candidates
            .choose_multiple(&mut rand::thread_rng(), 32)
            .copied()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn restrictions() -> RestrictionsRules {
        serde_yaml::from_str("restrictions:\n - name: alpha\n   match: [Any]\n   allow: []\n - name: beta\n   match: [Any]\n   allow: []").unwrap()
    }
    const POLICY: &str = "version: 1\nroles: {reader: [forward_tcp], agent: [reverse_tcp]}\ntenants:\n alpha:\n  restrictions: [alpha]\n  reverse_bindings: [{address: 127.0.0.1, ports: ['20000..20031'], allow_ephemeral: true}]\n beta:\n  restrictions: [beta]\n  reverse_bindings: [{address: 127.0.0.1, ports: ['21000..21031']}]\ndevices:\n a: {tenant: alpha, roles: [reader]}\n b: {tenant: beta, roles: [agent]}\n";

    #[test]
    fn reload_retains_equivalent_or_expanded_grants_and_rejects_reductions() {
        let access = |text: &str| {
            Arc::new(TenantPolicy::parse(text.as_bytes(), &restrictions()).unwrap())
                .access("a")
                .unwrap()
        };
        let original = access(POLICY);
        let renamed = access(&POLICY.replace("reader", "renamed"));
        assert!(renamed.retains(&original));
        let expanded = access(&POLICY.replace("roles: [reader]", "roles: [reader, agent]"));
        assert!(expanded.retains(&original));
        assert!(!original.retains(&expanded));
        assert!(!access(&POLICY.replace("reader: [forward_tcp]", "reader: [forward_udp]")).retains(&original));
        assert!(!access(&POLICY.replace("20000..20031", "20000..20015")).retains(&original));
        assert!(access(&POLICY.replace("20000..20031", "20000..20063")).retains(&original));
        assert!(access(&POLICY.replace("'20000..20031'", "'20000..20015','20016..20031'")).retains(&original));
        assert!(!access(&POLICY.replace("'20000..20031'", "'20000..20014','20016..20031'")).retains(&original));
        assert!(!access(&POLICY.replace("allow_ephemeral: true", "allow_ephemeral: false")).retains(&original));
        assert!(!access(&POLICY.replace("a: {tenant: alpha", "a: {tenant: beta")).retains(&original));
    }

    #[test]
    fn role_action_and_tenant_scope_are_both_required() {
        let policy = Arc::new(TenantPolicy::parse(POLICY.as_bytes(), &restrictions()).unwrap());
        let a = policy.access("a").unwrap();
        assert!(a.allows(&LocalProtocol::Tcp { proxy_protocol: false }, "alpha"));
        assert!(!a.allows(&LocalProtocol::ReverseTcp, "alpha"));
        assert!(!a.allows(&LocalProtocol::Tcp { proxy_protocol: false }, "beta"));
        assert!(policy.access("unknown").is_err());
        assert!(policy.access("A").is_err());
    }

    #[test]
    fn validates_references_typos_and_overlapping_resources() {
        for invalid in [
            POLICY.replace("version: 1", "version: 2"),
            POLICY.replace("reader: [forward_tcp]", "reader: [admin]"),
            POLICY.replace("roles: [reader]", "roles: [missing]"),
            POLICY.replace("tenant: alpha", "tenant: missing"),
            POLICY.replace("21000..21031", "20031..21000"),
            POLICY.replace("21000..21031", "0..20"),
            POLICY.replace("127.0.0.1", "0.0.0.0"),
            POLICY.replace("restrictions: [alpha]", "restrictions: [missing]"),
            POLICY.replace("allow_ephemeral: true", "allow_ephemerl: true"),
        ] {
            assert!(TenantPolicy::parse(invalid.as_bytes(), &restrictions()).is_err(), "{invalid}");
        }
    }

    #[test]
    fn mapped_ports_and_ephemeral_pool_stay_in_tenant_scope() {
        let policy = Arc::new(TenantPolicy::parse(POLICY.as_bytes(), &restrictions()).unwrap());
        let a = policy.access("a").unwrap();
        let remote = RemoteAddr {
            protocol: LocalProtocol::ReverseTcp,
            host: url::Host::Ipv4(std::net::Ipv4Addr::LOCALHOST),
            port: 123,
        };
        assert!(a.authorize_reverse(&remote, 20000).is_ok());
        assert!(a.authorize_reverse(&remote, 21000).is_err());
        assert!(a.authorize_reverse(&remote, 0).is_ok());
        let candidates = a.bind_candidates("127.0.0.1:0".parse().unwrap());
        assert_eq!(candidates.len(), 32);
        assert!(
            candidates
                .iter()
                .all(|candidate| (20000..=20031).contains(&candidate.port()))
        );
        assert!(
            policy
                .access("b")
                .unwrap()
                .bind_candidates("127.0.0.1:0".parse().unwrap())
                .is_empty()
        );
    }

    #[cfg(unix)]
    #[test]
    fn unix_ownership_rejects_aliases_traversal_and_shared_reservations() {
        let directory = std::env::temp_dir().join(format!("tunward-tenant-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(directory.join("real")).unwrap();
        let _cleanup = scopeguard::guard(directory.clone(), |path| {
            let _ = std::fs::remove_dir_all(path);
        });
        let path = directory.join("real/agent.sock");
        assert!(validate_unix_path(&path).is_ok());
        assert!(validate_unix_path(&directory.join("real/../agent.sock")).is_err());
        assert!(validate_unix_path(&directory.join("real/./agent.sock")).is_err());
        std::os::unix::fs::symlink(directory.join("real"), directory.join("alias")).unwrap();
        assert!(validate_unix_path(&directory.join("alias/agent.sock")).is_err());
        let yaml = POLICY.replace(
            "restrictions: [alpha]",
            &format!("restrictions: [alpha]\n  reverse_unix_paths: ['{}']", path.display()),
        );
        let policy = Arc::new(TenantPolicy::parse(yaml.as_bytes(), &restrictions()).unwrap());
        let remote = RemoteAddr {
            protocol: LocalProtocol::ReverseUnix { path: path.clone() },
            host: url::Host::Ipv4(std::net::Ipv4Addr::LOCALHOST),
            port: 0,
        };
        assert!(policy.access("a").unwrap().authorize_reverse(&remote, 0).is_ok());
        assert!(policy.access("b").unwrap().authorize_reverse(&remote, 0).is_err());
        let duplicate = yaml.replace(
            "restrictions: [beta]",
            &format!("restrictions: [beta]\n  reverse_unix_paths: ['{}']", path.display()),
        );
        assert!(TenantPolicy::parse(duplicate.as_bytes(), &restrictions()).is_err());
    }
}
