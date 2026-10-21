//! Process-local quotas keyed by the verified mTLS Common Name.

use anyhow::{Context, ensure};
use arc_swap::ArcSwap;
use parking_lot::Mutex;
use serde::Deserialize;
use std::collections::HashMap;
use std::fmt;
use std::future::Future;
use std::num::{NonZeroU32, NonZeroU64};
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;
use tokio::time::{Instant, Sleep};

const TOKEN_SCALE: u128 = 1_000_000_000;
const RECORD_BYTES: u64 = 65536;

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceQuotaConfig {
    pub version: u32,
    #[serde(default = "default_tracked_devices")]
    pub max_tracked_devices: NonZeroU32,
    pub default: DeviceQuotaLimits,
    #[serde(default)]
    pub devices: HashMap<String, DeviceQuotaLimits>,
}

fn default_tracked_devices() -> NonZeroU32 {
    NonZeroU32::new(10000).unwrap()
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceQuotaLimits {
    pub max_sessions: Option<NonZeroU32>,
    pub max_tunnels: Option<NonZeroU32>,
    pub requests_per_second: Option<NonZeroU32>,
    pub request_burst: Option<NonZeroU32>,
    pub upload_bytes_per_second: Option<NonZeroU64>,
    pub download_bytes_per_second: Option<NonZeroU64>,
    pub bandwidth_burst_bytes: Option<NonZeroU64>,
}

impl DeviceQuotaLimits {
    fn has_limit(&self) -> bool {
        self.max_sessions.is_some()
            || self.max_tunnels.is_some()
            || self.requests_per_second.is_some()
            || self.upload_bytes_per_second.is_some()
            || self.download_bytes_per_second.is_some()
    }

    fn inherit(&self, defaults: &Self) -> Self {
        Self {
            max_sessions: self.max_sessions.or(defaults.max_sessions),
            max_tunnels: self.max_tunnels.or(defaults.max_tunnels),
            requests_per_second: self.requests_per_second.or(defaults.requests_per_second),
            request_burst: self.request_burst.or(defaults.request_burst),
            upload_bytes_per_second: self.upload_bytes_per_second.or(defaults.upload_bytes_per_second),
            download_bytes_per_second: self.download_bytes_per_second.or(defaults.download_bytes_per_second),
            bandwidth_burst_bytes: self.bandwidth_burst_bytes.or(defaults.bandwidth_burst_bytes),
        }
    }

    fn validate(&self) -> anyhow::Result<()> {
        ensure!(
            self.request_burst.is_none() || self.requests_per_second.is_some(),
            "request_burst requires requests_per_second"
        );
        ensure!(
            self.bandwidth_burst_bytes.is_none()
                || self.upload_bytes_per_second.is_some()
                || self.download_bytes_per_second.is_some(),
            "bandwidth_burst_bytes requires an upload or download rate"
        );
        ensure!(
            self.bandwidth_burst_bytes.is_none_or(|n| n.get() >= RECORD_BYTES),
            "bandwidth_burst_bytes must be at least 65536 to preserve full UDP records"
        );
        Ok(())
    }
}

impl DeviceQuotaConfig {
    pub fn from_path(path: &Path) -> anyhow::Result<Self> {
        let file =
            std::fs::File::open(path).with_context(|| format!("Cannot open device quota config {}", path.display()))?;
        let config: Self = serde_yaml::from_reader(file).context("Invalid device quota YAML")?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        ensure!(self.version == 1, "unsupported device quota version; expected 1");
        self.default.validate().context("Invalid default device quota")?;
        ensure!(
            self.default.has_limit() || self.devices.values().any(DeviceQuotaLimits::has_limit),
            "device quota config must set at least one limit"
        );
        ensure!(
            self.devices.len() <= self.max_tracked_devices.get() as usize,
            "device overrides exceed max_tracked_devices"
        );
        for (identity, limits) in &self.devices {
            ensure!(!identity.is_empty(), "device quota identity must not be empty");
            limits
                .inherit(&self.default)
                .validate()
                .with_context(|| format!("Invalid quota override for {identity}"))?;
        }
        Ok(())
    }
}

#[derive(Debug)]
pub(crate) struct QuotaError {
    pub kind: &'static str,
    pub retry_after: Option<Duration>,
}

impl QuotaError {
    fn limit(kind: &'static str) -> Self {
        Self {
            kind,
            retry_after: None,
        }
    }
}

impl fmt::Display for QuotaError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.kind)
    }
}

impl std::error::Error for QuotaError {}

#[derive(Clone)]
enum QuotaSource {
    Static(Arc<DeviceQuotaConfig>),
    Live(Arc<ArcSwap<crate::reload::ReloadSnapshot>>),
}

impl QuotaSource {
    fn config(&self) -> Arc<DeviceQuotaConfig> {
        match self {
            Self::Static(config) => config.clone(),
            Self::Live(config) => config
                .load()
                .device_quotas
                .as_ref()
                .expect("quota source is fixed at startup")
                .clone(),
        }
    }

    fn limits(&self, identity: &str) -> DeviceQuotaLimits {
        let config = self.config();
        config
            .devices
            .get(identity)
            .map(|limits| limits.inherit(&config.default))
            .unwrap_or_else(|| config.default.clone())
    }
}

#[derive(Clone)]
pub(crate) struct QuotaManager {
    config: QuotaSource,
    devices: Arc<Mutex<HashMap<String, Arc<DeviceState>>>>,
}

impl QuotaManager {
    pub fn new(config: DeviceQuotaConfig) -> Self {
        Self {
            config: QuotaSource::Static(Arc::new(config)),
            devices: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn live(config: Arc<ArcSwap<crate::reload::ReloadSnapshot>>) -> Self {
        Self {
            config: QuotaSource::Live(config),
            devices: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn open_session(&self, identity: &str) -> Result<QuotaSession, QuotaError> {
        let config = self.config.config();
        let limits = config
            .devices
            .get(identity)
            .map(|limits| limits.inherit(&config.default))
            .unwrap_or_else(|| config.default.clone());
        let device = {
            let mut devices = self.devices.lock();
            if let Some(device) = devices.get(identity) {
                device.clone()
            } else {
                if devices.len() >= config.max_tracked_devices.get() as usize {
                    // Retain depleted buckets across reconnects; evict only inactive, refilled entries.
                    devices.retain(|_, device| Arc::strong_count(device) != 1 || !device.can_evict());
                }
                if devices.len() >= config.max_tracked_devices.get() as usize {
                    return Err(QuotaError::limit("tracked_device_limit"));
                }
                let device = Arc::new(DeviceState::new(self.config.clone(), Arc::from(identity)));
                devices.insert(identity.to_owned(), device.clone());
                device
            }
        };
        {
            let mut counts = device.counts.lock();
            if limits.max_sessions.is_some_and(|max| counts.sessions >= max.get()) {
                return Err(QuotaError::limit("session_limit"));
            }
            counts.sessions = counts
                .sessions
                .checked_add(1)
                .ok_or_else(|| QuotaError::limit("session_limit"))?;
        }
        Ok(QuotaSession(Arc::new(SessionLease { device })))
    }
}

#[derive(Default)]
struct Counts {
    sessions: u32,
    tunnels: u32,
}

struct DeviceState {
    identity: Arc<str>,
    source: QuotaSource,
    counts: Mutex<Counts>,
    requests: Option<RateLimiter>,
    upload: Option<RateLimiter>,
    download: Option<RateLimiter>,
}

impl DeviceState {
    fn new(source: QuotaSource, identity: Arc<str>) -> Self {
        let limits = source.limits(&identity);
        let mut requests = limits
            .requests_per_second
            .map(|rate| RateLimiter::new(u64::from(rate.get()), u64::from(limits.request_burst.unwrap_or(rate).get())));
        let burst = limits.bandwidth_burst_bytes.map_or(RECORD_BYTES, NonZeroU64::get);
        let mut upload = limits
            .upload_bytes_per_second
            .map(|rate| RateLimiter::new(rate.get(), burst));
        let mut download = limits
            .download_bytes_per_second
            .map(|rate| RateLimiter::new(rate.get(), burst));
        if matches!(source, QuotaSource::Live(_)) {
            requests = Some(RateLimiter::live(source.clone(), identity.clone(), Direction::Requests));
            upload = Some(RateLimiter::live(source.clone(), identity.clone(), Direction::Upload));
            download = Some(RateLimiter::live(source.clone(), identity.clone(), Direction::Download));
        }
        Self {
            identity,
            source,
            counts: Mutex::new(Counts::default()),
            requests,
            upload,
            download,
        }
    }

    fn can_evict(&self) -> bool {
        let counts = self.counts.lock();
        counts.sessions == 0
            && counts.tunnels == 0
            && [&self.requests, &self.upload, &self.download]
                .into_iter()
                .all(|bucket| bucket.as_ref().is_none_or(RateLimiter::is_full))
    }
}

struct SessionLease {
    device: Arc<DeviceState>,
}

impl Drop for SessionLease {
    fn drop(&mut self) {
        self.device.counts.lock().sessions -= 1;
    }
}

/// Clones retain one authenticated transport session, rather than incrementing its count.
#[derive(Clone)]
pub(crate) struct QuotaSession(Arc<SessionLease>);

impl QuotaSession {
    pub fn check_request(&self) -> Result<(), QuotaError> {
        if let Some(limiter) = &self.0.device.requests
            && let Some(delay) = limiter.try_take(1)
        {
            return Err(QuotaError {
                kind: "request_rate",
                retry_after: Some(delay),
            });
        }
        Ok(())
    }

    pub fn open_tunnel(&self) -> Result<TunnelPermit, QuotaError> {
        let device = &self.0.device;
        let mut counts = device.counts.lock();
        if device
            .source
            .limits(&device.identity)
            .max_tunnels
            .is_some_and(|max| counts.tunnels >= max.get())
        {
            return Err(QuotaError::limit("tunnel_limit"));
        }
        counts.tunnels = counts
            .tunnels
            .checked_add(1)
            .ok_or_else(|| QuotaError::limit("tunnel_limit"))?;
        Ok(TunnelPermit(Arc::new(TunnelLease { session: self.clone() })))
    }
}

struct TunnelLease {
    session: QuotaSession,
}

#[derive(Clone)]
pub(crate) struct TunnelPermit(Arc<TunnelLease>);

impl TunnelPermit {
    pub fn identity(&self) -> Arc<str> {
        self.0.session.0.device.identity.clone()
    }

    pub fn upload(&self) -> Option<RateLimiter> {
        self.0.session.0.device.upload.clone()
    }

    pub fn download(&self) -> Option<RateLimiter> {
        self.0.session.0.device.download.clone()
    }
}

impl Drop for TunnelLease {
    fn drop(&mut self) {
        self.session.0.device.counts.lock().tunnels -= 1;
    }
}

struct Bucket {
    rate: u64,
    capacity: u128,
    credit: u128,
    updated: Instant,
}

impl Bucket {
    fn refill(&mut self) {
        let now = Instant::now();
        let added = now
            .duration_since(self.updated)
            .as_nanos()
            .saturating_mul(u128::from(self.rate));
        self.credit = self.credit.saturating_add(added).min(self.capacity);
        self.updated = now;
    }
}

#[derive(Clone)]
pub(crate) struct RateLimiter(Arc<Mutex<Bucket>>, Option<(QuotaSource, Arc<str>, Direction)>);

#[derive(Clone, Copy)]
enum Direction {
    Requests,
    Upload,
    Download,
}

impl RateLimiter {
    fn new(rate: u64, burst: u64) -> Self {
        let capacity = u128::from(burst) * TOKEN_SCALE;
        Self(
            Arc::new(Mutex::new(Bucket {
                rate,
                capacity,
                credit: capacity,
                updated: Instant::now(),
            })),
            None,
        )
    }

    fn live(source: QuotaSource, identity: Arc<str>, direction: Direction) -> Self {
        let mut limiter = Self::new(0, 0);
        limiter.1 = Some((source, identity, direction));
        limiter.refresh(&mut limiter.0.lock());
        limiter
    }

    fn refresh(&self, bucket: &mut Bucket) {
        let Some((source, identity, direction)) = &self.1 else {
            return;
        };
        let limits = source.limits(identity);
        let (rate, burst) = match direction {
            Direction::Requests => (
                limits.requests_per_second.map(|n| u64::from(n.get())),
                limits
                    .request_burst
                    .or(limits.requests_per_second)
                    .map(|n| u64::from(n.get())),
            ),
            Direction::Upload => (
                limits.upload_bytes_per_second.map(NonZeroU64::get),
                limits.bandwidth_burst_bytes.map(NonZeroU64::get),
            ),
            Direction::Download => (
                limits.download_bytes_per_second.map(NonZeroU64::get),
                limits.bandwidth_burst_bytes.map(NonZeroU64::get),
            ),
        };
        let rate = rate.unwrap_or(0);
        let capacity = if rate == 0 {
            0
        } else {
            u128::from(burst.unwrap_or(RECORD_BYTES)) * TOKEN_SCALE
        };
        if bucket.rate != rate || bucket.capacity != capacity {
            bucket.refill();
            bucket.credit = if bucket.rate == 0 {
                capacity
            } else {
                bucket.credit.min(capacity)
            };
            bucket.rate = rate;
            bucket.capacity = capacity;
        }
    }

    // A failed attempt reserves no future credit, so cancellation cannot strand a reservation.
    fn try_take(&self, amount: u64) -> Option<Duration> {
        let mut bucket = self.0.lock();
        self.refresh(&mut bucket);
        if bucket.rate == 0 {
            return None;
        }
        bucket.refill();
        let requested = u128::from(amount) * TOKEN_SCALE;
        if requested <= bucket.credit {
            bucket.credit -= requested;
            None
        } else {
            let nanos = (requested - bucket.credit).div_ceil(u128::from(bucket.rate));
            Some(Duration::from_nanos(u64::try_from(nanos).unwrap_or(u64::MAX)))
        }
    }

    fn is_full(&self) -> bool {
        let mut bucket = self.0.lock();
        self.refresh(&mut bucket);
        bucket.refill();
        bucket.credit == bucket.capacity
    }
}

#[derive(Default)]
pub(crate) struct BandwidthWait {
    limiter: Option<RateLimiter>,
    sleep: Option<Pin<Box<Sleep>>>,
}

impl BandwidthWait {
    pub fn new(limiter: Option<RateLimiter>) -> Self {
        Self { limiter, sleep: None }
    }

    pub fn poll_acquire(&mut self, cx: &mut TaskContext<'_>, bytes: usize) -> Poll<()> {
        let Some(limiter) = &self.limiter else {
            return Poll::Ready(());
        };
        loop {
            if let Some(timer) = self.sleep.as_mut() {
                std::task::ready!(timer.as_mut().poll(cx));
                self.sleep = None;
            }
            match limiter.try_take(bytes as u64) {
                None => return Poll::Ready(()),
                Some(delay) => {
                    let delay = if limiter.1.is_some() {
                        delay.min(Duration::from_millis(100))
                    } else {
                        delay
                    };
                    self.sleep = Some(Box::pin(tokio::time::sleep(delay)));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::poll_fn;

    fn config(yaml: &str) -> DeviceQuotaConfig {
        let config: DeviceQuotaConfig = serde_yaml::from_str(yaml).unwrap();
        config.validate().unwrap();
        config
    }

    fn live_config(config: DeviceQuotaConfig) -> (QuotaManager, Arc<ArcSwap<crate::reload::ReloadSnapshot>>) {
        let snapshot = crate::reload::ReloadSnapshot {
            generation: 1,
            restrictions: Arc::new(crate::restrictions::types::RestrictionsRules::from_path_prefix(&[], &[]).unwrap()),
            tenants: None,
            device_quotas: Some(Arc::new(config)),
            tcp_tls: None,
            quic_tls: None,
        };
        let source = Arc::new(ArcSwap::from_pointee(snapshot));
        (QuotaManager::live(source.clone()), source)
    }

    fn replace_live(source: &ArcSwap<crate::reload::ReloadSnapshot>, config: DeviceQuotaConfig) {
        let mut snapshot = (*source.load_full()).clone();
        snapshot.generation += 1;
        snapshot.device_quotas = Some(Arc::new(config));
        source.store(Arc::new(snapshot));
    }

    #[tokio::test(start_paused = true)]
    async fn reload_preserves_counts_and_depleted_request_credit() {
        let initial =
            config("version: 1\ndefault: {max_sessions: 2, max_tunnels: 2, requests_per_second: 1, request_burst: 1}");
        let (manager, source) = live_config(initial.clone());
        let first = manager.open_session("a").unwrap();
        let second = manager.open_session("a").unwrap();
        let one = first.open_tunnel().unwrap();
        let two = second.open_tunnel().unwrap();
        first.check_request().unwrap();
        replace_live(&source, initial);
        assert!(first.check_request().is_err(), "no-op reload must not refill request tokens");
        assert!(manager.open_session("a").is_err());
        assert!(first.open_tunnel().is_err());
        replace_live(
            &source,
            config(
                "version: 1\ndefault: {max_sessions: 1, max_tunnels: 1, requests_per_second: 10, request_burst: 10}",
            ),
        );
        assert!(first.check_request().is_err(), "larger capacity must not grant a fresh burst");
        assert!(manager.open_session("a").is_err());
        assert!(first.open_tunnel().is_err());
        drop(two);
        drop(second);
        assert!(
            first.open_tunnel().is_err(),
            "existing tunnel remains counted at the lower limit"
        );
        tokio::time::advance(Duration::from_millis(100)).await;
        first.check_request().unwrap();
        drop(one);
        first.open_tunnel().unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn reload_changes_bandwidth_for_existing_permits_without_resetting_credit() {
        let (manager, source) = live_config(config("version: 1\ndefault: {max_tunnels: 4}"));
        let session = manager.open_session("a").unwrap();
        let permit = session.open_tunnel().unwrap();
        let upload = permit.upload().unwrap();
        assert!(upload.try_take(65536).is_none());
        let limited = config(
            "version: 1\ndefault: {max_tunnels: 4, upload_bytes_per_second: 65536, bandwidth_burst_bytes: 65536}",
        );
        replace_live(&source, limited.clone());
        assert!(upload.try_take(65536).is_none());
        assert!(upload.try_take(1).is_some());
        replace_live(&source, limited);
        assert!(
            upload.try_take(1).is_some(),
            "no-op reload must retain depleted bandwidth credit"
        );
        tokio::time::advance(Duration::from_secs(1)).await;
        assert!(upload.try_take(65536).is_none());
        replace_live(&source, config("version: 1\ndefault: {max_tunnels: 4}"));
        assert!(
            upload.try_take(65536).is_none(),
            "removing shaping reaches the already-cloned limiter"
        );
    }

    #[tokio::test]
    async fn admission_is_atomic_and_clones_do_not_add_sessions() {
        let manager = QuotaManager::new(config("version: 1\ndefault: {max_sessions: 1, max_tunnels: 2}"));
        let session = manager.open_session("a").unwrap();
        let clone = session.clone();
        assert_eq!(manager.open_session("a").err().unwrap().kind, "session_limit");
        let one = session.open_tunnel().unwrap();
        let two = clone.open_tunnel().unwrap();
        assert_eq!(session.open_tunnel().err().unwrap().kind, "tunnel_limit");
        assert!(manager.open_session("b").is_ok());
        drop(session);
        drop(clone);
        assert!(manager.open_session("a").is_err());
        drop(one);
        drop(two);
        assert!(manager.open_session("a").is_ok());
    }

    #[tokio::test]
    async fn concurrent_tunnel_admission_and_cancel_release() {
        let manager = QuotaManager::new(config("version: 1\ndefault: {max_tunnels: 3}"));
        let session = manager.open_session("a").unwrap();
        let barrier = Arc::new(tokio::sync::Barrier::new(33));
        let mut tasks = Vec::new();
        for _ in 0..32 {
            let session = session.clone();
            let barrier = barrier.clone();
            tasks.push(tokio::spawn(async move {
                let permit = session.open_tunnel();
                barrier.wait().await;
                permit
            }));
        }
        barrier.wait().await;
        let mut permits = Vec::new();
        for task in tasks {
            if let Ok(permit) = task.await.unwrap() {
                permits.push(permit);
            }
        }
        assert_eq!(permits.len(), 3);
        drop(permits);
        let (tx, rx) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            let _permit = session.open_tunnel().unwrap();
            tx.send(()).unwrap();
            std::future::pending::<()>().await;
        });
        rx.await.unwrap();
        task.abort();
        let _ = task.await;
        let session = manager.open_session("a").unwrap();
        let _permits = (0..3).map(|_| session.open_tunnel().unwrap()).collect::<Vec<_>>();
    }

    #[tokio::test(start_paused = true)]
    async fn reconnect_does_not_reset_rate_and_inactive_entries_are_bounded() {
        let manager = QuotaManager::new(config(
            "version: 1\nmax_tracked_devices: 1\ndefault: {requests_per_second: 1, request_burst: 1}",
        ));
        let session = manager.open_session("a").unwrap();
        session.check_request().unwrap();
        drop(session);
        let session = manager.open_session("a").unwrap();
        assert_eq!(session.check_request().unwrap_err().kind, "request_rate");
        drop(session);
        assert_eq!(manager.open_session("b").err().unwrap().kind, "tracked_device_limit");
        tokio::time::advance(Duration::from_secs(1)).await;
        assert!(manager.open_session("b").is_ok());
    }

    #[tokio::test(start_paused = true)]
    async fn bandwidth_is_shared_directional_and_waits_without_reservation() {
        let manager = QuotaManager::new(config(
            "version: 1\ndefault: {upload_bytes_per_second: 65536, download_bytes_per_second: 65536}",
        ));
        let a = manager.open_session("a").unwrap();
        let one = a.open_tunnel().unwrap();
        let two = manager.open_session("a").unwrap().open_tunnel().unwrap();
        assert!(one.upload().unwrap().try_take(65536).is_none());
        assert_eq!(two.upload().unwrap().try_take(65536), Some(Duration::from_secs(1)));
        assert!(two.download().unwrap().try_take(65536).is_none());
        let mut wait = BandwidthWait::new(two.upload());
        let before = Instant::now();
        poll_fn(|cx| wait.poll_acquire(cx, 65536)).await;
        assert!(before.elapsed() >= Duration::from_secs(1));
        assert!(one.upload().unwrap().try_take(1).is_some());
        let other = manager.open_session("b").unwrap().open_tunnel().unwrap();
        assert!(other.upload().unwrap().try_take(65536).is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn cancelled_bandwidth_wait_does_not_reserve_future_tokens() {
        let limiter = RateLimiter::new(65536, 65536);
        assert!(limiter.try_take(65536).is_none());
        let mut wait = BandwidthWait::new(Some(limiter.clone()));
        let mut context = TaskContext::from_waker(std::task::Waker::noop());
        assert!(wait.poll_acquire(&mut context, 65536).is_pending());
        drop(wait);
        tokio::time::advance(Duration::from_secs(1)).await;
        assert!(limiter.try_take(65536).is_none());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_authenticated_sessions_cannot_exceed_cap() {
        let manager = QuotaManager::new(config("version: 1\ndefault: {max_sessions: 3}"));
        let barrier = Arc::new(tokio::sync::Barrier::new(33));
        let mut tasks = Vec::new();
        for _ in 0..32 {
            let manager = manager.clone();
            let barrier = barrier.clone();
            tasks.push(tokio::spawn(async move {
                let session = manager.open_session("a");
                barrier.wait().await;
                session
            }));
        }
        barrier.wait().await;
        let mut sessions = Vec::new();
        for task in tasks {
            if let Ok(session) = task.await.unwrap() {
                sessions.push(session);
            }
        }
        assert_eq!(sessions.len(), 3);
        drop(sessions);
        assert!(manager.open_session("a").is_ok());
    }

    #[test]
    fn configuration_rejects_typos_zero_and_invalid_bursts() {
        for yaml in [
            "version: 1\ndefault: {max_tunels: 1}",
            "version: 1\ndefault: {max_sessions: 0}",
            "version: 1\ndefault: {upload_bytes_per_second: 0}",
        ] {
            assert!(serde_yaml::from_str::<DeviceQuotaConfig>(yaml).is_err());
        }
        for yaml in [
            "version: 2\ndefault: {}",
            "version: 1\ndefault: {}",
            "version: 1\ndefault: {request_burst: 1}",
            "version: 1\ndefault: {bandwidth_burst_bytes: 65536}",
            "version: 1\ndefault: {upload_bytes_per_second: 1, bandwidth_burst_bytes: 65535}",
        ] {
            assert!(
                serde_yaml::from_str::<DeviceQuotaConfig>(yaml)
                    .unwrap()
                    .validate()
                    .is_err()
            );
        }
    }

    #[tokio::test]
    async fn per_device_override_inherits_default_limits() {
        let manager = QuotaManager::new(config(
            "version: 1\ndefault: {max_sessions: 1, max_tunnels: 1}\ndevices:\n  a: {max_tunnels: 2}",
        ));
        let a = manager.open_session("a").unwrap();
        let _one = a.open_tunnel().unwrap();
        let _two = a.open_tunnel().unwrap();
        assert!(a.open_tunnel().is_err());
        assert!(manager.open_session("a").is_err());
        let b = manager.open_session("b").unwrap();
        let _one = b.open_tunnel().unwrap();
        assert!(b.open_tunnel().is_err());
    }

    #[tokio::test]
    async fn retained_reverse_resource_counts_once_until_last_owner_drops() {
        let manager = QuotaManager::new(config("version: 1\ndefault: {max_tunnels: 1}"));
        let session = manager.open_session("a").unwrap();
        let request = session.open_tunnel().unwrap();
        let listener = request.clone();
        drop(request);
        assert!(session.open_tunnel().is_err());
        drop(listener);
        assert!(session.open_tunnel().is_ok());
    }
}
