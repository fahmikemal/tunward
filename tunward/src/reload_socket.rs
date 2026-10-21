//! Local reload control is restricted by a private Unix directory and a mode-0600 socket.
use crate::reload::{ReloadStatus, ServerReload};
use anyhow::{Context, ensure};
use std::io::{Read, Write};
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixListener;
use tracing::warn;

pub fn validate_reload_socket_path(path: &Path) -> anyhow::Result<()> {
    ensure!(path.is_absolute(), "Reload socket path must be absolute");
    let parent = path.parent().context("Reload socket needs a parent directory")?;
    let metadata = std::fs::metadata(parent)
        .with_context(|| format!("Cannot read reload socket directory {}", parent.display()))?;
    ensure!(
        metadata.is_dir() && metadata.mode() & 0o077 == 0,
        "Reload socket requires a private parent directory (mode 0700 or stricter)"
    );
    Ok(())
}

struct SocketPath {
    path: PathBuf,
    device: u64,
    inode: u64,
}

impl Drop for SocketPath {
    fn drop(&mut self) {
        if let Ok(metadata) = std::fs::symlink_metadata(&self.path)
            && metadata.file_type().is_socket()
            && metadata.dev() == self.device
            && metadata.ino() == self.inode
        {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

pub struct ReloadSocket {
    listener: UnixListener,
    _path: SocketPath,
}

impl ReloadSocket {
    /// Bind before starting the tunnel server. Existing sockets are never removed implicitly.
    pub fn bind(path: &Path) -> anyhow::Result<Self> {
        validate_reload_socket_path(path)?;
        let listener =
            UnixListener::bind(path).with_context(|| format!("Cannot bind reload socket {}", path.display()))?;
        let metadata = std::fs::symlink_metadata(path)?;
        let guard = SocketPath {
            path: path.to_owned(),
            device: metadata.dev(),
            inode: metadata.ino(),
        };
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        Ok(Self { listener, _path: guard })
    }

    pub async fn serve(self, reload: ServerReload) {
        let clients = Arc::new(tokio::sync::Semaphore::new(32));
        loop {
            let (mut stream, _) = match self.listener.accept().await {
                Ok(connection) => connection,
                Err(error) => {
                    warn!("Reload control accept error: {error}");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            };
            let Ok(permit) = clients.clone().try_acquire_owned() else {
                continue;
            };
            let reload = reload.clone();
            tokio::spawn(async move {
                let _permit = permit;
                let request = async {
                    let mut command = [0; 7];
                    stream.read_exact(&mut command).await?;
                    ensure!(&command == b"reload\n", "Invalid reload control command");
                    anyhow::Ok(())
                };
                if !matches!(tokio::time::timeout(Duration::from_secs(5), request).await, Ok(Ok(()))) {
                    return;
                }
                let mut extra = [0; 1];
                let result = tokio::select! {
                    result = reload.reload() => result.map_err(|error| error.to_string().chars().take(2048).collect::<String>()),
                    _ = stream.read(&mut extra) => return,
                };
                let Ok(bytes) = serde_json::to_vec(&result) else {
                    return;
                };
                let response = async {
                    stream.write_all(&bytes).await?;
                    stream.shutdown().await
                };
                let _ = tokio::time::timeout(Duration::from_secs(5), response).await;
            });
        }
    }
}

/// Synchronous acknowledgment makes this suitable for systemd ExecReload.
pub fn request_reload(path: &Path) -> anyhow::Result<ReloadStatus> {
    let mut stream = std::os::unix::net::UnixStream::connect(path)
        .with_context(|| format!("Cannot connect to reload socket {}", path.display()))?;
    stream.set_read_timeout(Some(Duration::from_secs(35)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    stream.write_all(b"reload\n")?;
    let mut reply = Vec::new();
    (&mut stream).take(16385).read_to_end(&mut reply)?;
    ensure!(reply.len() <= 16384, "Reload response exceeds 16 KiB");
    let response: Result<ReloadStatus, String> =
        serde_json::from_slice(&reply).context("Invalid reload acknowledgment")?;
    response.map_err(anyhow::Error::msg)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn directory() -> (PathBuf, impl Drop) {
        let path = std::env::temp_dir().join(format!("tw-reload-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        let guard = scopeguard::guard(path.clone(), |path| {
            let _ = std::fs::remove_dir_all(path);
        });
        (path, guard)
    }

    #[tokio::test]
    async fn rejects_public_directories_and_preserves_existing_paths() {
        let (directory, _guard) = directory();
        let socket = directory.join("control.sock");
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(ReloadSocket::bind(&socket).is_err());
        assert!(!socket.exists());
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::write(&socket, b"existing file").unwrap();
        assert!(ReloadSocket::bind(&socket).is_err());
        assert_eq!(std::fs::read(&socket).unwrap(), b"existing file");
    }

    #[tokio::test]
    async fn acknowledges_completion_and_cleans_up_only_its_socket() {
        let (directory, _guard) = directory();
        let path = directory.join("control.sock");
        let socket = ReloadSocket::bind(&path).unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().mode() & 0o777, 0o600);
        let reload = ServerReload::default();
        let mut requests = reload.take_receiver().await.unwrap();
        let task = tokio::spawn(socket.serve(reload));
        let client_path = path.clone();
        let client = tokio::task::spawn_blocking(move || request_reload(&client_path));
        let reply = requests.recv().await.unwrap();
        assert!(!client.is_finished(), "client must wait for the server acknowledgment");
        reply
            .send(Ok(ReloadStatus {
                generation: 7,
                disconnected_sessions: 0,
            }))
            .unwrap();
        assert_eq!(client.await.unwrap().unwrap().generation, 7);
        task.abort();
        let _ = task.await;
        assert!(!path.exists());
        let socket = ReloadSocket::bind(&path).unwrap();
        std::fs::remove_file(&path).unwrap();
        std::fs::write(&path, b"replacement").unwrap();
        drop(socket);
        assert_eq!(std::fs::read(&path).unwrap(), b"replacement");
    }
}
