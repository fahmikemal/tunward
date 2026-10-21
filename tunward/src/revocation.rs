//! Live, process-local denial of verified device identities and certificate fingerprints.

use anyhow::{Context, anyhow, ensure};
use parking_lot::Mutex;
use serde::Deserialize;
use std::collections::HashSet;
use std::future::Future;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Weak};
use std::time::Duration;
use tokio::sync::watch;
use tokio_rustls::rustls::{
    crypto::{CryptoProvider, hash::HashAlgorithm},
    pki_types::CertificateDer,
};
use tracing::{info, warn};

const MAX_POLICY_BYTES: u64 = 1_048_576;
const MAX_ENTRIES: usize = 10000;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyFile {
    version: u32,
    #[serde(default)]
    blocked_devices: Vec<String>,
    #[serde(default)]
    blocked_cert_sha256: Vec<String>,
}

#[derive(Default)]
struct Policy {
    devices: HashSet<String>,
    certificates: HashSet<String>,
}

impl Policy {
    fn parse(bytes: &[u8]) -> anyhow::Result<Self> {
        ensure!(bytes.len() <= MAX_POLICY_BYTES as usize, "revocation policy exceeds 1 MiB");
        let file: PolicyFile = serde_yaml::from_slice(bytes).context("Invalid revocation YAML")?;
        ensure!(file.version == 1, "unsupported revocation version; expected 1");
        ensure!(
            file.blocked_devices
                .len()
                .saturating_add(file.blocked_cert_sha256.len())
                <= MAX_ENTRIES,
            "revocation policy exceeds 10000 entries"
        );
        ensure!(
            file.blocked_devices.iter().all(|identity| !identity.is_empty()),
            "blocked device CN must not be empty"
        );
        let certificates = file
            .blocked_cert_sha256
            .iter()
            .map(|value| {
                let value = value.replace(':', "").to_ascii_lowercase();
                ensure!(
                    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()),
                    "certificate fingerprint must contain exactly 64 SHA-256 hex digits"
                );
                Ok(value)
            })
            .collect::<anyhow::Result<_>>()?;
        Ok(Self {
            devices: file.blocked_devices.into_iter().collect(),
            certificates,
        })
    }

    fn denies(&self, identity: &str, fingerprint: &str) -> bool {
        self.devices.contains(identity) || self.certificates.contains(fingerprint)
    }
}

fn read_policy(path: &Path) -> anyhow::Result<Vec<u8>> {
    ensure!(std::fs::metadata(path)?.is_file(), "revocation policy must be a regular file");
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take(MAX_POLICY_BYTES + 1)
        .read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= MAX_POLICY_BYTES as usize, "revocation policy exceeds 1 MiB");
    Ok(bytes)
}

pub(crate) fn certificate_fingerprint(certificate: &CertificateDer<'_>) -> anyhow::Result<String> {
    let provider = CryptoProvider::get_default().ok_or_else(|| anyhow!("No TLS crypto provider installed"))?;
    let hash = provider
        .cipher_suites
        .iter()
        .filter_map(|suite| suite.tls13().map(|suite| suite.common.hash_provider))
        .find(|hash| hash.algorithm() == HashAlgorithm::SHA256)
        .ok_or_else(|| anyhow!("TLS crypto provider does not expose SHA-256"))?;
    Ok(hash
        .hash(certificate.as_ref())
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

struct Session {
    identity: Arc<str>,
    fingerprint: String,
    revoked: watch::Sender<bool>,
}

/// Cancellation is sticky even if a later policy update restores access.
#[derive(Clone, Default)]
pub(crate) struct RevocationGuard(Option<Arc<Session>>);

impl RevocationGuard {
    pub fn identity(&self) -> Option<Arc<str>> {
        self.0.as_ref().map(|session| session.identity.clone())
    }

    pub fn is_revoked(&self) -> bool {
        self.0.as_ref().is_some_and(|session| *session.revoked.borrow())
    }

    pub async fn cancelled(&self) {
        match &self.0 {
            None => std::future::pending().await,
            Some(session) => {
                let mut receiver = session.revoked.subscribe();
                let _ = receiver.wait_for(|revoked| *revoked).await;
            }
        }
    }

    pub async fn run<T>(&self, work: impl Future<Output = anyhow::Result<T>>) -> anyhow::Result<T> {
        tokio::select! {
            biased;
            _ = self.cancelled() => Err(anyhow!("authenticated device access revoked")),
            result = work => result,
        }
    }
}

struct State {
    policy: Policy,
    healthy: bool,
    sessions: Vec<Weak<Session>>,
}

#[derive(Clone)]
pub(crate) struct RevocationManager(Arc<Mutex<State>>);

impl RevocationManager {
    pub fn from_path(path: &Path) -> anyhow::Result<Self> {
        let policy = Policy::parse(&read_policy(path)?)
            .with_context(|| format!("Cannot load revocation policy {}", path.display()))?;
        Ok(Self(Arc::new(Mutex::new(State {
            policy,
            healthy: true,
            sessions: Vec::new(),
        }))))
    }

    pub fn register(&self, identity: &str, certificate: &CertificateDer<'_>) -> anyhow::Result<RevocationGuard> {
        self.register_identity(identity, certificate_fingerprint(certificate)?)
    }

    fn register_identity(&self, identity: &str, fingerprint: String) -> anyhow::Result<RevocationGuard> {
        let mut state = self.0.lock();
        ensure!(state.healthy, "revocation policy unavailable; authenticated access denied");
        ensure!(
            !state.policy.denies(identity, &fingerprint),
            "device or certificate access revoked"
        );
        let session = Arc::new(Session {
            identity: Arc::from(identity),
            fingerprint,
            revoked: watch::Sender::new(false),
        });
        if state.sessions.len().is_multiple_of(1024) {
            state.sessions.retain(|session| session.strong_count() > 0);
        }
        state.sessions.push(Arc::downgrade(&session));
        Ok(RevocationGuard(Some(session)))
    }

    fn apply(&self, policy: Option<Policy>) {
        let mut state = self.0.lock();
        let healthy = policy.is_some();
        if let Some(policy) = policy {
            state.policy = policy;
        }
        state.healthy = healthy;
        let State { policy, sessions, .. } = &mut *state;
        let mut cancelled = 0;
        sessions.retain(|session| {
            let Some(session) = session.upgrade() else {
                return false;
            };
            if (!healthy || policy.denies(&session.identity, &session.fingerprint))
                && !session.revoked.send_replace(true)
            {
                cancelled += 1;
            }
            true
        });
        info!(healthy, cancelled_sessions = cancelled, "Applied device revocation policy");
    }

    pub async fn reload(self, path: PathBuf) {
        let mut previous = None;
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tick.tick().await;
            let path = path.clone();
            let loaded = tokio::task::spawn_blocking(move || read_policy(&path)).await;
            let loaded = loaded.map_err(anyhow::Error::from).and_then(|result| result);
            let result = loaded.and_then(|bytes| {
                if previous.as_ref() == Some(&bytes) {
                    return Ok(None);
                }
                let policy = Policy::parse(&bytes)?;
                previous = Some(bytes);
                Ok(Some(policy))
            });
            match result {
                Ok(Some(policy)) => self.apply(Some(policy)),
                Ok(None) => {}
                Err(err) => {
                    previous = None;
                    if self.0.lock().healthy {
                        warn!("Revocation policy unavailable; closing authenticated sessions: {err:#}");
                        self.apply(None);
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(devices: &[&str], certificates: &[&str]) -> Policy {
        Policy {
            devices: devices.iter().map(|value| value.to_string()).collect(),
            certificates: certificates.iter().map(|value| value.to_string()).collect(),
        }
    }

    fn manager() -> RevocationManager {
        RevocationManager(Arc::new(Mutex::new(State {
            policy: Policy::default(),
            healthy: true,
            sessions: Vec::new(),
        })))
    }

    #[tokio::test]
    async fn certificate_revocation_preserves_rotated_key_and_other_device() {
        let manager = manager();
        let a = manager.register_identity("a", "old".into()).unwrap();
        let rotated = manager.register_identity("a", "new".into()).unwrap();
        let b = manager.register_identity("b", "other".into()).unwrap();
        manager.apply(Some(policy(&[], &["old"])));
        a.cancelled().await;
        assert!(!rotated.is_revoked());
        assert!(!b.is_revoked());
        assert!(manager.register_identity("a", "old".into()).is_err());
        manager.apply(Some(policy(&["a"], &[])));
        rotated.cancelled().await;
        assert!(!b.is_revoked());
        assert!(manager.register_identity("a", "newer".into()).is_err());
    }

    #[tokio::test]
    async fn cancellation_is_sticky_across_restore_and_late_subscriptions() {
        let manager = manager();
        let old = manager.register_identity("a", "key".into()).unwrap();
        manager.apply(Some(policy(&["a"], &[])));
        manager.apply(Some(Policy::default()));
        old.cancelled().await;
        assert!(old.clone().run(async { Ok(()) }).await.is_err());
        assert!(!manager.register_identity("a", "key".into()).unwrap().is_revoked());
    }

    #[tokio::test]
    async fn broken_policy_closes_all_and_recovery_only_admits_new_sessions() {
        let manager = manager();
        let old = manager.register_identity("a", "key".into()).unwrap();
        manager.apply(None);
        old.cancelled().await;
        assert!(manager.register_identity("b", "key".into()).is_err());
        manager.apply(Some(Policy::default()));
        assert!(old.is_revoked());
        assert!(manager.register_identity("a", "key".into()).is_ok());
    }

    #[test]
    fn validates_and_normalizes_policy() {
        let fingerprint = "AA:".repeat(31) + "AA";
        let parsed = Policy::parse(format!("version: 1\nblocked_cert_sha256: ['{fingerprint}']").as_bytes()).unwrap();
        assert!(parsed.denies("a", &"aa".repeat(32)));
        for invalid in [
            "version: 2",
            "version: 1\nblocked_devices: ['']",
            "version: 1\nblocked_cert_sha256: [abc]",
            "version: 1\nblocked_device: []",
        ] {
            assert!(Policy::parse(invalid.as_bytes()).is_err(), "{invalid}");
        }
        assert!(Policy::parse(&vec![b' '; MAX_POLICY_BYTES as usize + 1]).is_err());
        assert!(
            Policy::parse(b"version: 1\nblocked_devices: [a,A]")
                .unwrap()
                .devices
                .contains("A")
        );
    }

    #[test]
    fn expired_weak_sessions_are_reclaimed() {
        let manager = manager();
        for _ in 0..2050 {
            manager.register_identity("a", "key".into()).unwrap();
        }
        assert!(manager.0.lock().sessions.len() <= 1024);
        manager.apply(Some(Policy::default()));
        assert!(manager.0.lock().sessions.is_empty());
    }
}
