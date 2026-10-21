use anyhow::{Context, anyhow, ensure};
use rusqlite::{Connection, OpenFlags, OptionalExtension, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::num::NonZeroU32;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};

const APPLICATION_ID: i32 = 0x54554e57;
const SCHEMA_VERSION: i32 = 1;

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

pub(crate) struct Observation {
    pub identity: String,
    pub fingerprint: String,
    pub transport: String,
    pub timestamp: u64,
}

enum Command {
    Observe(Observation, oneshot::Sender<anyhow::Result<()>>),
    List(usize, String, oneshot::Sender<anyhow::Result<DevicePage>>),
    Get(String, oneshot::Sender<anyhow::Result<Option<DeviceRecord>>>),
}

#[derive(Clone)]
pub(crate) struct Inventory {
    tx: mpsc::Sender<Command>,
    healthy: Arc<AtomicBool>,
}

impl Inventory {
    pub async fn open(path: PathBuf, capacity: NonZeroU32) -> anyhow::Result<Self> {
        let (connection, lock) = tokio::task::spawn_blocking(move || open_database(&path)).await??;
        let (tx, mut rx) = mpsc::channel(256);
        let healthy = Arc::new(AtomicBool::new(true));
        let health = healthy.clone();
        std::thread::Builder::new()
            .name("tunward-inventory".into())
            .spawn(move || {
                let _lock = lock;
                let mut connection = connection;
                while let Some(command) = rx.blocking_recv() {
                    match command {
                        Command::Observe(observation, reply) => {
                            let result = observe(&mut connection, observation, capacity.get());
                            health.store(result.is_ok(), Ordering::Relaxed);
                            let _ = reply.send(result);
                        }
                        Command::List(limit, after, reply) => {
                            let result = list(&connection, limit, &after);
                            if result.is_err() {
                                health.store(false, Ordering::Relaxed);
                            }
                            let _ = reply.send(result);
                        }
                        Command::Get(identity, reply) => {
                            let result = connection.query_row(
                            "SELECT identity, first_seen, last_seen, certificate_sha256, transport, observations
                             FROM devices WHERE identity = ?1", [&identity], device,
                        ).optional().map_err(anyhow::Error::from);
                            if result.is_err() {
                                health.store(false, Ordering::Relaxed);
                            }
                            let _ = reply.send(result);
                        }
                    }
                }
                health.store(false, Ordering::Relaxed);
            })?;
        Ok(Self { tx, healthy })
    }

    pub fn healthy(&self) -> bool {
        self.healthy.load(Ordering::Relaxed) && !self.tx.is_closed()
    }

    async fn request<T>(&self, make: impl FnOnce(oneshot::Sender<anyhow::Result<T>>) -> Command) -> anyhow::Result<T> {
        let (tx, rx) = oneshot::channel();
        self.tx
            .try_send(make(tx))
            .map_err(|_| anyhow!("inventory worker unavailable or queue full"))?;
        tokio::time::timeout(Duration::from_secs(5), rx)
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

fn observe(connection: &mut Connection, observation: Observation, capacity: u32) -> anyhow::Result<()> {
    let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let exists: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM devices WHERE identity=?1)",
        [&observation.identity],
        |row| row.get(0),
    )?;
    if !exists {
        let count: u32 = tx.query_row("SELECT count(*) FROM devices", [], |row| row.get(0))?;
        ensure!(count < capacity, "inventory device capacity reached");
    }
    tx.execute(
        "INSERT INTO devices(identity,first_seen,last_seen,certificate_sha256,transport,observations)
        VALUES (?1,?2,?2,?3,?4,1)
        ON CONFLICT(identity) DO UPDATE SET
        last_seen=max(devices.last_seen,excluded.last_seen),
        certificate_sha256=excluded.certificate_sha256, transport=excluded.transport,
        observations=min(devices.observations,9223372036854775806)+1",
        params![
            observation.identity,
            i64::try_from(observation.timestamp).context("inventory timestamp exceeds SQLite integer range")?,
            observation.fingerprint,
            observation.transport
        ],
    )?;
    tx.commit()?;
    Ok(())
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

    #[tokio::test]
    async fn persistence_rotation_capacity_and_pagination() {
        let (path, _cleanup) = temporary_path();
        {
            let (mut db, _lock) = open_database(&path).unwrap();
            observe(&mut db, observation("a", "old"), 2).unwrap();
            observe(&mut db, observation("a", "new"), 2).unwrap();
            observe(&mut db, observation("b", "other"), 2).unwrap();
            assert!(observe(&mut db, observation("c", "full"), 2).is_err());
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
        assert!(store.list(1001, "".into()).await.is_err());
    }

    #[tokio::test]
    async fn concurrent_observations_use_bound_parameters() {
        let (path, _cleanup) = temporary_path();
        let store = Inventory::open(path, NonZeroU32::new(2).unwrap()).await.unwrap();
        let mut tasks = tokio::task::JoinSet::new();
        for _ in 0..32 {
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
        assert_eq!(page.devices[0].observed_connections, 32);
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
