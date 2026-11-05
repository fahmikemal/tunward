//! Live, process-local denial of verified device identities and certificate fingerprints.

use crate::config::ClientCrlScope;
use crate::protocols::tls::{ClientCrls, RevocationKeys};
use anyhow::{Context, anyhow, ensure};
use parking_lot::Mutex;
use serde::Deserialize;
use std::collections::HashSet;
use std::future::Future;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Weak};
use std::time::{Duration, SystemTime};
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
    #[serde(default, deserialize_with = "crate::yaml::required")]
    blocked_devices: Vec<String>,
    #[serde(default, deserialize_with = "crate::yaml::required")]
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
        let file: PolicyFile = crate::yaml::from_slice(bytes).context("Invalid revocation YAML")?;
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
    /// What a client CRL is checked against; empty without `--tls-client-crl`.
    crl_keys: RevocationKeys,
    revoked: watch::Sender<bool>,
}

/// Cancellation is sticky even if a later policy update restores access.
#[derive(Clone, Default)]
pub(crate) struct RevocationGuard(Option<Arc<Session>>);

pub(crate) struct WeakRevocationGuard(Weak<Session>);

impl WeakRevocationGuard {
    pub(crate) fn upgrade(&self) -> Option<RevocationGuard> {
        self.0.upgrade().map(|session| RevocationGuard(Some(session)))
    }
}

impl RevocationGuard {
    pub(crate) fn downgrade(&self) -> Option<WeakRevocationGuard> {
        self.0
            .as_ref()
            .map(|session| WeakRevocationGuard(Arc::downgrade(session)))
    }
    pub(crate) fn revoke(&self) {
        if let Some(session) = &self.0 {
            session.revoked.send_replace(true);
        }
    }
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
    crl: Option<CrlState>,
}

/// The client CRLs in force, as the TLS verifier was last given them.
struct CrlState {
    scope: ClientCrlScope,
    enforce_expiry: bool,
    crls: Arc<ClientCrls>,
}

/// What `/healthz` reports about the client CRLs.
pub(crate) struct CrlHealth {
    pub next_update: Option<SystemTime>,
    /// Past its next update, a CRL fails the handshakes that need it.
    pub enforced_expiry: bool,
}

#[derive(Clone)]
pub(crate) struct RevocationManager(Arc<Mutex<State>>);

impl RevocationManager {
    pub fn empty() -> Self {
        Self(Arc::new(Mutex::new(State {
            policy: Policy::default(),
            healthy: true,
            sessions: Vec::new(),
            crl: None,
        })))
    }
    pub fn from_path(path: &Path) -> anyhow::Result<Self> {
        let policy = Policy::parse(&read_policy(path)?)
            .with_context(|| format!("Cannot load revocation policy {}", path.display()))?;
        Ok(Self(Arc::new(Mutex::new(State {
            policy,
            healthy: true,
            sessions: Vec::new(),
            crl: None,
        }))))
    }

    /// Check sessions against client CRLs from now on, starting with `crls`.
    pub fn enable_crls(&self, scope: ClientCrlScope, enforce_expiry: bool, crls: Arc<ClientCrls>) {
        self.0.lock().crl = Some(CrlState {
            scope,
            enforce_expiry,
            crls,
        });
    }

    /// `chain` is the verified client certificate followed by the CA certificates it presented.
    pub fn register(&self, identity: &str, chain: &[CertificateDer<'_>]) -> anyhow::Result<RevocationGuard> {
        let certificate = chain.first().context("verified client certificate required")?;
        let fingerprint = certificate_fingerprint(certificate)?;
        let scope = self.0.lock().crl.as_ref().map(|crl| crl.scope);
        let crl_keys = scope.map(|scope| RevocationKeys::of(chain, scope)).unwrap_or_default();
        self.register_identity(identity, fingerprint, crl_keys)
    }

    fn register_identity(
        &self,
        identity: &str,
        fingerprint: String,
        crl_keys: RevocationKeys,
    ) -> anyhow::Result<RevocationGuard> {
        let mut state = self.0.lock();
        ensure!(state.healthy, "revocation policy unavailable; authenticated access denied");
        ensure!(
            !state.policy.denies(identity, &fingerprint),
            "device or certificate access revoked"
        );
        // The handshake was verified against the CRLs of its time, which a newer one may revoke.
        ensure!(
            !state.crl.as_ref().is_some_and(|crl| crl.crls.revokes(&crl_keys)),
            "client certificate revoked by --tls-client-crl"
        );
        let session = Arc::new(Session {
            identity: Arc::from(identity),
            fingerprint,
            crl_keys,
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

    /// Install client CRLs and close the sessions whose certificates they revoke. Returns how
    /// many were closed.
    pub fn apply_crls(&self, crls: Arc<ClientCrls>) -> usize {
        let mut state = self.0.lock();
        let State { sessions, crl, .. } = &mut *state;
        let Some(crl) = crl else {
            return 0;
        };
        if Arc::ptr_eq(&crl.crls, &crls) {
            return 0;
        }
        crl.crls = crls;
        let mut cancelled = 0;
        sessions.retain(|session| {
            let Some(session) = session.upgrade() else {
                return false;
            };
            if crl.crls.revokes(&session.crl_keys) && !session.revoked.send_replace(true) {
                cancelled += 1;
            }
            true
        });
        info!(cancelled_sessions = cancelled, "Applied client CRLs");
        cancelled
    }

    /// The client CRLs in force, if `--tls-client-crl` is set.
    pub fn crls(&self) -> Option<Arc<ClientCrls>> {
        self.0.lock().crl.as_ref().map(|crl| crl.crls.clone())
    }

    pub fn crl_health(&self) -> Option<CrlHealth> {
        self.0.lock().crl.as_ref().map(|crl| CrlHealth {
            next_update: crl.crls.next_update(),
            enforced_expiry: crl.enforce_expiry,
        })
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
        RevocationManager::empty()
    }

    #[tokio::test]
    async fn certificate_revocation_preserves_rotated_key_and_other_device() {
        let manager = manager();
        let a = manager
            .register_identity("a", "old".into(), RevocationKeys::default())
            .unwrap();
        let rotated = manager
            .register_identity("a", "new".into(), RevocationKeys::default())
            .unwrap();
        let b = manager
            .register_identity("b", "other".into(), RevocationKeys::default())
            .unwrap();
        manager.apply(Some(policy(&[], &["old"])));
        a.cancelled().await;
        assert!(!rotated.is_revoked());
        assert!(!b.is_revoked());
        assert!(
            manager
                .register_identity("a", "old".into(), RevocationKeys::default())
                .is_err()
        );
        manager.apply(Some(policy(&["a"], &[])));
        rotated.cancelled().await;
        assert!(!b.is_revoked());
        assert!(
            manager
                .register_identity("a", "newer".into(), RevocationKeys::default())
                .is_err()
        );
    }

    #[tokio::test]
    async fn cancellation_is_sticky_across_restore_and_late_subscriptions() {
        let manager = manager();
        let old = manager
            .register_identity("a", "key".into(), RevocationKeys::default())
            .unwrap();
        manager.apply(Some(policy(&["a"], &[])));
        manager.apply(Some(Policy::default()));
        old.cancelled().await;
        assert!(old.clone().run(async { Ok(()) }).await.is_err());
        assert!(
            !manager
                .register_identity("a", "key".into(), RevocationKeys::default())
                .unwrap()
                .is_revoked()
        );
    }

    #[tokio::test]
    async fn broken_policy_closes_all_and_recovery_only_admits_new_sessions() {
        let manager = manager();
        let old = manager
            .register_identity("a", "key".into(), RevocationKeys::default())
            .unwrap();
        manager.apply(None);
        old.cancelled().await;
        assert!(
            manager
                .register_identity("b", "key".into(), RevocationKeys::default())
                .is_err()
        );
        manager.apply(Some(Policy::default()));
        assert!(old.is_revoked());
        assert!(
            manager
                .register_identity("a", "key".into(), RevocationKeys::default())
                .is_ok()
        );
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
            // Left blank, a list would read as empty and silently lift every revocation.
            "version: 1\nblocked_devices:",
            "version: 1\nblocked_cert_sha256: ~",
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

    #[tokio::test]
    async fn a_new_crl_closes_the_sessions_it_revokes_and_refuses_them_afterwards() {
        crate::tunnel::ca_reloader::SystemCaReloader::init_crypto_provider();
        let ca = crate::protocols::tls::TestCa::new("CA");
        let crls = |serials: &[u64]| {
            Arc::new(ClientCrls::parse(ca.crl(serials, time::Duration::days(1)).as_ref(), &[ca.der()]).unwrap())
        };
        let manager = manager();
        manager.enable_crls(ClientCrlScope::Chain, true, crls(&[]));
        let (a, b) = (ca.client("device-a", 11), ca.client("device-b", 12));
        let session_a = manager.register("device-a", std::slice::from_ref(&a)).unwrap();
        let session_b = manager.register("device-b", std::slice::from_ref(&b)).unwrap();

        // Reapplying the CRLs in force changes nothing.
        let current = manager.crls().unwrap();
        assert_eq!(manager.apply_crls(current), 0);

        assert_eq!(manager.apply_crls(crls(&[11])), 1);
        session_a.cancelled().await;
        assert!(!session_b.is_revoked());
        let refused = manager.register("device-a", std::slice::from_ref(&a)).err().unwrap();
        assert_eq!(refused.to_string(), "client certificate revoked by --tls-client-crl");
        // A new certificate for the same device is not revoked by the old one's serial.
        assert!(manager.register("device-a", &[ca.client("device-a", 13)]).is_ok());

        // Cancellation is sticky, as for the revocation policy.
        assert_eq!(manager.apply_crls(crls(&[])), 0);
        assert!(session_a.is_revoked());
        assert!(manager.register("device-a", std::slice::from_ref(&a)).is_ok());
    }

    #[test]
    fn sessions_are_not_checked_against_crls_unless_enabled() {
        crate::tunnel::ca_reloader::SystemCaReloader::init_crypto_provider();
        let ca = crate::protocols::tls::TestCa::new("CA");
        let manager = manager();
        let session = manager.register("device", &[ca.client("device", 1)]).unwrap();
        let crls = ClientCrls::parse(ca.crl(&[1], time::Duration::days(1)).as_ref(), &[ca.der()]).unwrap();
        assert_eq!(manager.apply_crls(Arc::new(crls)), 0);
        assert!(!session.is_revoked());
        assert!(manager.crl_health().is_none());
    }

    #[test]
    fn expired_weak_sessions_are_reclaimed() {
        let manager = manager();
        for _ in 0..2050 {
            manager
                .register_identity("a", "key".into(), RevocationKeys::default())
                .unwrap();
        }
        assert!(manager.0.lock().sessions.len() <= 1024);
        manager.apply(Some(Policy::default()));
        assert!(manager.0.lock().sessions.is_empty());
    }
}
