use super::devices::{DevicePage, DeviceRecord, Observation};
use anyhow::{Context, anyhow, ensure};
use rusqlite::{Connection, OpenFlags, OptionalExtension, TransactionBehavior, params};
use std::fs::{File, OpenOptions};
use std::num::NonZeroU32;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};
use tokio::time::{Instant, timeout_at};

const APPLICATION_ID: i32 = 0x54554e57;
const SCHEMA_VERSION: i32 = 1;
/// Requests waiting for the worker. A caller that finds it full waits for room within its deadline.
const QUEUE_CAPACITY: usize = 256;
/// The most observations one transaction commits. A burst of connections then costs one sync per
/// batch instead of one per connection, while a batch still holds the write lock only briefly.
const MAX_BATCH: usize = QUEUE_CAPACITY;
/// How long a caller waits, from the moment it asks, for room in the queue and the answer together.
const RESPONSE_DEADLINE: Duration = Duration::from_secs(5);

type Reply<T> = oneshot::Sender<anyhow::Result<T>>;

enum Command {
    Observe(Observation, Reply<()>),
    List(usize, String, Reply<DevicePage>),
    Get(String, Reply<Option<DeviceRecord>>),
}

#[derive(Clone)]
pub(crate) struct Inventory {
    tx: mpsc::Sender<Command>,
    healthy: Arc<AtomicBool>,
}

impl Inventory {
    pub async fn open(path: PathBuf, capacity: NonZeroU32) -> anyhow::Result<Self> {
        let (connection, lock) = tokio::task::spawn_blocking(move || open_database(&path)).await??;
        let (tx, rx) = mpsc::channel(QUEUE_CAPACITY);
        let healthy = Arc::new(AtomicBool::new(true));
        let health = healthy.clone();
        std::thread::Builder::new()
            .name("tunward-inventory".into())
            .spawn(move || {
                let _lock = lock;
                serve(connection, rx, capacity.get(), &health);
                health.store(false, Ordering::Relaxed);
            })?;
        Ok(Self { tx, healthy })
    }

    pub fn healthy(&self) -> bool {
        self.healthy.load(Ordering::Relaxed) && !self.tx.is_closed()
    }

    async fn request<T>(&self, make: impl FnOnce(Reply<T>) -> Command) -> anyhow::Result<T> {
        let deadline = Instant::now() + RESPONSE_DEADLINE;
        let (tx, rx) = oneshot::channel();
        timeout_at(deadline, self.tx.send(make(tx)))
            .await
            .map_err(|_| anyhow!("inventory queue stayed full past the response deadline"))?
            .map_err(|_| anyhow!("inventory worker stopped"))?;
        timeout_at(deadline, rx)
            .await
            .context("inventory response deadline exceeded")?
            .context("inventory worker stopped")?
    }

    pub async fn observe(&self, observation: Observation) -> anyhow::Result<()> {
        self.request(|reply| Command::Observe(observation, reply)).await
    }

    pub async fn list(&self, limit: usize, after: String) -> anyhow::Result<DevicePage> {
        ensure!((1..=1000).contains(&limit), "inventory page limit must be between 1 and 1000");
        self.request(|reply| Command::List(limit, after, reply)).await
    }

    pub async fn get(&self, identity: String) -> anyhow::Result<Option<DeviceRecord>> {
        self.request(|reply| Command::Get(identity, reply)).await
    }
}

/// Answers requests in arrival order until every sender is gone.
///
/// Observations queued back to back are committed together. `health` follows storage only: a write
/// that commits sets it, a storage error clears it, and a refused observation leaves it alone, since a
/// full inventory is a policy outcome that operators see in the logs, not a broken database.
fn serve(mut connection: Connection, mut rx: mpsc::Receiver<Command>, capacity: u32, health: &AtomicBool) {
    let mut next = None;
    while let Some(command) = next.take().or_else(|| rx.blocking_recv()) {
        match command {
            Command::Observe(observation, reply) => {
                let mut observations = vec![observation];
                let mut replies = vec![reply];
                while observations.len() < MAX_BATCH {
                    match rx.try_recv() {
                        Ok(Command::Observe(observation, reply)) => {
                            observations.push(observation);
                            replies.push(reply);
                        }
                        Ok(other) => {
                            next = Some(other);
                            break;
                        }
                        Err(_) => break,
                    }
                }
                match record(&mut connection, &observations, capacity) {
                    Ok(outcomes) => {
                        if outcomes.iter().any(Result::is_ok) {
                            health.store(true, Ordering::Relaxed);
                        }
                        for (reply, outcome) in replies.into_iter().zip(outcomes) {
                            let _ = reply.send(outcome);
                        }
                    }
                    Err(err) => {
                        health.store(false, Ordering::Relaxed);
                        for reply in replies {
                            let _ = reply.send(Err(anyhow!("inventory write failed: {err}")));
                        }
                    }
                }
            }
            Command::List(limit, after, reply) => {
                let result = list(&connection, limit, &after);
                if result.is_err() {
                    health.store(false, Ordering::Relaxed);
                }
                let _ = reply.send(result);
            }
            Command::Get(identity, reply) => {
                let result = connection
                    .query_row(
                        "SELECT identity, first_seen, last_seen, certificate_sha256, transport, observations
                         FROM devices WHERE identity = ?1",
                        [&identity],
                        device,
                    )
                    .optional()
                    .map_err(anyhow::Error::from);
                if result.is_err() {
                    health.store(false, Ordering::Relaxed);
                }
                let _ = reply.send(result);
            }
        }
    }
}

fn open_private(path: &Path) -> anyhow::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(nix::libc::O_NOFOLLOW);
    }
    let file = options.open(path)?;
    ensure!(file.metadata()?.is_file(), "inventory path must be a regular file");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        ensure!(
            file.metadata()?.permissions().mode() & 0o077 == 0,
            "inventory files require owner-only permissions (0600)"
        );
    }
    Ok(file)
}

fn open_database(path: &Path) -> anyhow::Result<(Connection, File)> {
    ensure!(path != Path::new(":memory:"), "inventory requires a persistent file path");
    let mut lock_path = path.as_os_str().to_os_string();
    lock_path.push(".lock");
    let lock = open_private(Path::new(&lock_path))?;
    lock.try_lock()
        .map_err(|err| anyhow!("inventory already in use or cannot lock: {err}"))?;
    open_private(path)?;
    let mut connection =
        Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX)?;
    connection.busy_timeout(Duration::from_secs(1))?;
    let app: i32 = connection.pragma_query_value(None, "application_id", |row| row.get(0))?;
    let version: i32 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    let tables: u32 =
        connection.query_row("SELECT count(*) FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'", [], |row| {
            row.get(0)
        })?;
    ensure!(
        (app == APPLICATION_ID && version == SCHEMA_VERSION) || (app == 0 && version == 0 && tables == 0),
        "unsupported or foreign inventory database schema"
    );
    let mode: String = connection.pragma_update_and_check(None, "journal_mode", "WAL", |row| row.get(0))?;
    ensure!(mode == "wal", "inventory requires SQLite WAL support on a local filesystem");
    connection.pragma_update(None, "synchronous", "FULL")?;
    let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    tx.execute_batch(
        "CREATE TABLE IF NOT EXISTS devices (
        identity TEXT PRIMARY KEY NOT NULL,
        first_seen INTEGER NOT NULL,
        last_seen INTEGER NOT NULL,
        certificate_sha256 TEXT NOT NULL,
        transport TEXT NOT NULL,
        observations INTEGER NOT NULL CHECK(observations > 0)
    ) WITHOUT ROWID;",
    )?;
    tx.pragma_update(None, "application_id", APPLICATION_ID)?;
    tx.pragma_update(None, "user_version", SCHEMA_VERSION)?;
    tx.commit()?;
    // Reject a version-tagged but incompatible schema before accepting traffic.
    connection.prepare(
        "SELECT identity, first_seen, last_seen, certificate_sha256, transport, observations FROM devices LIMIT 0",
    )?;
    Ok((connection, lock))
}

/// Commits `observations` in one transaction and returns one outcome for each, in order.
///
/// A new identity beyond `capacity` is refused on its own and writes nothing, so the rest of the
/// batch still lands. A storage error fails the whole batch instead: SQLite may roll a transaction
/// back by itself on such errors (a full disk, an I/O error, a lock it cannot get), so no
/// observation in it can be reported as recorded.
fn record(
    connection: &mut Connection,
    observations: &[Observation],
    capacity: u32,
) -> rusqlite::Result<Vec<anyhow::Result<()>>> {
    let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let mut stored: u32 = tx.query_row("SELECT count(*) FROM devices", [], |row| row.get(0))?;
    let mut outcomes = Vec::with_capacity(observations.len());
    {
        let mut known = tx.prepare_cached("SELECT EXISTS(SELECT 1 FROM devices WHERE identity=?1)")?;
        let mut upsert = tx.prepare_cached(
            "INSERT INTO devices(identity,first_seen,last_seen,certificate_sha256,transport,observations)
            VALUES (?1,?2,?2,?3,?4,1)
            ON CONFLICT(identity) DO UPDATE SET
            last_seen=max(devices.last_seen,excluded.last_seen),
            certificate_sha256=excluded.certificate_sha256, transport=excluded.transport,
            observations=min(devices.observations,9223372036854775806)+1",
        )?;
        for observation in observations {
            let Ok(timestamp) = i64::try_from(observation.timestamp) else {
                outcomes.push(Err(anyhow!("inventory timestamp exceeds SQLite integer range")));
                continue;
            };
            let new = !known.query_row([&observation.identity], |row| row.get::<_, bool>(0))?;
            if new && stored >= capacity {
                outcomes.push(Err(anyhow!("inventory device capacity reached")));
                continue;
            }
            upsert.execute(params![
                observation.identity,
                timestamp,
                observation.fingerprint,
                observation.transport
            ])?;
            stored += u32::from(new);
            outcomes.push(Ok(()));
        }
    }
    tx.commit()?;
    Ok(outcomes)
}

fn device(row: &rusqlite::Row<'_>) -> rusqlite::Result<DeviceRecord> {
    Ok(DeviceRecord {
        id: row.get(0)?,
        first_seen_at: unsigned(row, 1)?,
        last_seen_at: unsigned(row, 2)?,
        last_certificate_sha256: row.get(3)?,
        last_transport: row.get(4)?,
        observed_connections: unsigned(row, 5)?,
        active_connections: 0,
        active_tunnels: 0,
    })
}

fn unsigned(row: &rusqlite::Row<'_>, index: usize) -> rusqlite::Result<u64> {
    let value = row.get::<_, i64>(index)?;
    value
        .try_into()
        .map_err(|_| rusqlite::Error::IntegralValueOutOfRange(index, value))
}

fn list(connection: &Connection, limit: usize, after: &str) -> anyhow::Result<DevicePage> {
    let mut statement = connection.prepare(
        "SELECT identity, first_seen, last_seen, certificate_sha256, transport, observations
        FROM devices WHERE identity > ?1 ORDER BY identity LIMIT ?2",
    )?;
    let mut devices = statement
        .query_map(params![after, i64::try_from(limit + 1)?], device)?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let next_cursor = if devices.len() > limit {
        devices.truncate(limit);
        devices.last().map(|device| device.id.clone())
    } else {
        None
    };
    Ok(DevicePage { devices, next_cursor })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temporary_path() -> (PathBuf, scopeguard::ScopeGuard<PathBuf, impl FnOnce(PathBuf)>) {
        let dir = std::env::temp_dir().join(format!("tunward-inventory-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("devices.sqlite3");
        (
            path,
            scopeguard::guard(dir, |dir| {
                let _ = std::fs::remove_dir_all(dir);
            }),
        )
    }

    fn observation(identity: &str, fingerprint: &str) -> Observation {
        Observation {
            identity: identity.into(),
            fingerprint: fingerprint.into(),
            transport: "wss".into(),
            timestamp: 100,
        }
    }

    fn outcomes(results: Vec<anyhow::Result<()>>) -> Vec<Result<(), String>> {
        results
            .into_iter()
            .map(|result| result.map_err(|err| err.to_string()))
            .collect()
    }

    #[tokio::test]
    async fn persistence_rotation_capacity_and_pagination() {
        let (path, _cleanup) = temporary_path();
        {
            let (mut db, _lock) = open_database(&path).unwrap();
            let batch = [
                observation("a", "old"),
                observation("a", "new"),
                observation("b", "other"),
                observation("c", "full"),
            ];
            assert_eq!(
                outcomes(record(&mut db, &batch, 2).unwrap()),
                [Ok(()), Ok(()), Ok(()), Err("inventory device capacity reached".into())]
            );
            let page = list(&db, 1, "").unwrap();
            assert_eq!(page.next_cursor.as_deref(), Some("a"));
            assert_eq!(page.devices[0].observed_connections, 2);
            assert_eq!(page.devices[0].last_certificate_sha256, "new");
        }
        let store = Inventory::open(path.clone(), NonZeroU32::new(2).unwrap())
            .await
            .unwrap();
        assert!(Inventory::open(path, NonZeroU32::new(2).unwrap()).await.is_err());
        assert_eq!(store.list(1, "a".into()).await.unwrap().devices[0].id, "b");
        assert_eq!(store.get("a".into()).await.unwrap().unwrap().first_seen_at, 100);
        assert!(store.get("c".into()).await.unwrap().is_none());
        assert!(store.list(1001, "".into()).await.is_err());
    }

    #[test]
    fn a_refused_observation_does_not_hold_back_the_rest_of_its_batch() {
        let (path, _cleanup) = temporary_path();
        let (mut db, _lock) = open_database(&path).unwrap();
        let mut late = observation("b", "key");
        late.timestamp = u64::MAX;
        let batch = [
            observation("a", "key"),
            late,
            observation("b", "key"),
            observation("c", "key"),
            observation("a", "key"),
        ];
        assert_eq!(
            outcomes(record(&mut db, &batch, 2).unwrap()),
            [
                Ok(()),
                Err("inventory timestamp exceeds SQLite integer range".into()),
                Ok(()),
                Err("inventory device capacity reached".into()),
                Ok(())
            ]
        );
        let page = list(&db, 10, "").unwrap();
        let rows: Vec<_> = page
            .devices
            .iter()
            .map(|device| (device.id.as_str(), device.observed_connections, device.last_seen_at))
            .collect();
        assert_eq!(rows, [("a", 2, 100), ("b", 1, 100)]);
    }

    #[tokio::test]
    async fn a_full_inventory_refuses_new_devices_without_reporting_itself_unhealthy() {
        let (path, _cleanup) = temporary_path();
        let store = Inventory::open(path, NonZeroU32::new(1).unwrap()).await.unwrap();
        store.observe(observation("a", "key")).await.unwrap();
        let refused = store.observe(observation("b", "key")).await.unwrap_err();
        assert_eq!(refused.to_string(), "inventory device capacity reached");
        assert!(store.healthy(), "a policy refusal is not a storage failure");
        store.observe(observation("a", "key")).await.unwrap();
        assert!(store.healthy());
    }

    #[tokio::test]
    async fn concurrent_observations_use_bound_parameters() {
        const OBSERVATIONS: u64 = 32;
        let (path, _cleanup) = temporary_path();
        let store = Inventory::open(path, NonZeroU32::new(2).unwrap()).await.unwrap();
        let mut tasks = tokio::task::JoinSet::new();
        for _ in 0..OBSERVATIONS {
            let store = store.clone();
            tasks.spawn(async move {
                store
                    .observe(observation("a'; DROP TABLE devices; --", "key"))
                    .await
                    .unwrap();
            });
        }
        while let Some(result) = tasks.join_next().await {
            result.unwrap();
        }
        let page = store.list(100, "".into()).await.unwrap();
        assert_eq!(page.devices.len(), 1);
        assert_eq!(page.devices[0].observed_connections, OBSERVATIONS);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_burst_larger_than_the_queue_is_recorded_in_full() {
        // Each connection with a verified identity waits for its observation before it is admitted.
        // Committing one at a time refused all but about 260 of these on an NVMe disk ("queue full"),
        // so a reconnect storm after a restart locked most devices out.
        const DEVICES: usize = 4 * QUEUE_CAPACITY;
        let (path, _cleanup) = temporary_path();
        let store = Inventory::open(path, NonZeroU32::new(DEVICES as u32).unwrap())
            .await
            .unwrap();
        let mut tasks = tokio::task::JoinSet::new();
        for index in 0..DEVICES {
            let store = store.clone();
            tasks.spawn(async move { store.observe(observation(&format!("device-{index:04}"), "key")).await });
        }
        while let Some(result) = tasks.join_next().await {
            result.unwrap().unwrap();
        }
        let mut seen = 0;
        let mut after = String::new();
        loop {
            let page = store.list(1000, after).await.unwrap();
            seen += page.devices.len();
            match page.next_cursor {
                Some(cursor) => after = cursor,
                None => break,
            }
        }
        assert_eq!(seen, DEVICES);
        assert!(store.healthy());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_storage_failure_fails_every_waiting_observation_and_recovers() {
        let (path, _cleanup) = temporary_path();
        let store = Inventory::open(path.clone(), NonZeroU32::new(100).unwrap())
            .await
            .unwrap();
        store.observe(observation("a", "key")).await.unwrap();
        // Another writer holding the database lock past the one-second busy timeout.
        let mut other = Connection::open(&path).unwrap();
        let held = other.transaction_with_behavior(TransactionBehavior::Immediate).unwrap();
        let mut tasks = tokio::task::JoinSet::new();
        for index in 0..8 {
            let store = store.clone();
            tasks.spawn(async move { store.observe(observation(&format!("waiting-{index}"), "key")).await });
        }
        while let Some(result) = tasks.join_next().await {
            let err = result.unwrap().unwrap_err().to_string();
            assert!(err.starts_with("inventory write failed: "), "{err}");
        }
        assert!(!store.healthy());
        held.rollback().unwrap();
        assert!(store.get("waiting-0".into()).await.unwrap().is_none());
        assert!(!store.healthy(), "a read does not clear a write failure");
        store.observe(observation("b", "key")).await.unwrap();
        assert!(store.healthy());
    }

    #[test]
    fn foreign_and_future_schemas_are_rejected_without_replacement() {
        let (path, _cleanup) = temporary_path();
        open_private(&path).unwrap();
        let db = Connection::open(&path).unwrap();
        db.execute_batch("CREATE TABLE private_data(value TEXT); INSERT INTO private_data VALUES ('keep');")
            .unwrap();
        drop(db);
        assert!(open_database(&path).is_err());
        let db = Connection::open(&path).unwrap();
        assert_eq!(
            db.query_row("SELECT value FROM private_data", [], |row| row.get::<_, String>(0))
                .unwrap(),
            "keep"
        );
        db.execute_batch("DROP TABLE private_data;").unwrap();
        db.pragma_update(None, "application_id", APPLICATION_ID).unwrap();
        db.pragma_update(None, "user_version", SCHEMA_VERSION + 1).unwrap();
        drop(db);
        assert!(open_database(&path).is_err());
    }
}
