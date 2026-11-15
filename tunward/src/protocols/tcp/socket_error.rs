//! Windows reports an established TCP reset through read/write closure, not Mio's ERROR flag.

use futures_util::FutureExt;
use std::io::{self, ErrorKind};
use std::mem::MaybeUninit;
use std::time::Duration;
use tokio::io::Interest;
use tokio::net::TcpStream;

/// Keep Tokio's implicit write-half FIN from turning an abortive close into a
/// graceful close on Windows. Explicit AsyncWrite shutdown remains unchanged.
pub struct ResettableWriteHalf(Option<tokio::net::tcp::OwnedWriteHalf>);

impl ResettableWriteHalf {
    pub(crate) fn new(write: tokio::net::tcp::OwnedWriteHalf) -> Self {
        Self(Some(write))
    }
}

impl Drop for ResettableWriteHalf {
    fn drop(&mut self) {
        let write = self.0.take().expect("write half is present until drop");
        #[cfg(test)]
        eprintln!(
            "resettable write drop: linger={:?}",
            socket2::SockRef::from(write.as_ref()).linger()
        );
        if socket2::SockRef::from(write.as_ref()).linger().ok() == Some(Some(Duration::ZERO)) {
            write.forget();
        }
        // Otherwise the ordinary OwnedWriteHalf drop sends directional FIN.
    }
}

impl tokio::io::AsyncWrite for ResettableWriteHalf {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        bytes: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        std::pin::Pin::new(self.get_mut().0.as_mut().unwrap()).poll_write(cx, bytes)
    }

    fn poll_flush(self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(self.get_mut().0.as_mut().unwrap()).poll_flush(cx)
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(self.get_mut().0.as_mut().unwrap()).poll_shutdown(cx)
    }

    fn poll_write_vectored(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> std::task::Poll<io::Result<usize>> {
        std::pin::Pin::new(self.get_mut().0.as_mut().unwrap()).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        tokio::io::AsyncWrite::is_write_vectored(self.0.as_ref().unwrap())
    }
}

pub(crate) async fn wait(socket: &TcpStream) -> io::Error {
    loop {
        if let Err(error) = socket.ready(Interest::READABLE | Interest::ERROR).await {
            return error;
        }
        match socket.take_error() {
            Ok(Some(error)) | Err(error) => return error,
            Ok(None) => {}
        }
        // Mio marks AFD_POLL_ABORT as writable/readable-closed. A normal peer FIN only
        // closes local reads, so it must not discard buffered local delivery.
        if let Some(result) = socket.ready(Interest::WRITABLE).now_or_never() {
            match result {
                Err(error) => return error,
                Ok(ready) if ready.is_write_closed() => {
                    return io::Error::new(ErrorKind::ConnectionAborted, "TCP transport aborted");
                }
                Ok(_) => {}
            }
        }
        // MSG_PEEK never consumes application/TLS bytes. Clear cached readability only
        // when a real syscall says WouldBlock, as required by TcpStream::try_io.
        let mut byte = [MaybeUninit::<u8>::uninit(); 1];
        match socket.try_io(Interest::READABLE, || socket2::SockRef::from(socket).peek(&mut byte)) {
            Err(error) if error.kind() == ErrorKind::WouldBlock => continue,
            Err(error) => return error,
            Ok(_) => {
                // Data or normal EOF stays readable while another task drains its buffer.
                // Back off locally instead of spinning; this sends no heartbeat traffic.
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn write_half_drop_preserves_fin_and_abortive_close() {
        use tokio::io::AsyncReadExt;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        for (abort, duplicate) in [(false, false), (true, false), (true, true)] {
            let mut peer = TcpStream::connect(listener.local_addr().unwrap()).await.unwrap();
            let (socket, _) = listener.accept().await.unwrap();
            let monitor = duplicate.then(|| {
                let copy: std::net::TcpStream = socket2::SockRef::from(&socket).try_clone().unwrap().into();
                copy.set_nonblocking(true).unwrap();
                TcpStream::from_std(copy).unwrap()
            });
            let (read, write) = socket.into_split();
            let write = ResettableWriteHalf::new(write);
            if abort {
                socket2::SockRef::from(monitor.as_ref().unwrap_or(read.as_ref()))
                    .set_linger(Some(Duration::ZERO))
                    .unwrap();
            }
            drop(write);
            if abort {
                drop(read);
                drop(monitor);
                let result = tokio::time::timeout(Duration::from_secs(2), peer.read_u8())
                    .await
                    .unwrap();
                assert_eq!(result.unwrap_err().kind(), ErrorKind::ConnectionReset, "duplicate={duplicate}");
            } else {
                let mut byte = [0];
                assert_eq!(
                    tokio::time::timeout(Duration::from_secs(2), peer.read(&mut byte))
                        .await
                        .unwrap()
                        .unwrap(),
                    0
                );
                drop(read);
            }
        }
    }

    #[tokio::test]
    async fn probing_preserves_data_and_normal_fin_and_observes_reset() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut peer = TcpStream::connect(listener.local_addr().unwrap()).await.unwrap();
        let (socket, _) = listener.accept().await.unwrap();
        peer.write_all(b"abc").await.unwrap();
        peer.shutdown().await.unwrap();
        let mut failure = Box::pin(wait(&socket));
        assert!(
            tokio::time::timeout(Duration::from_millis(100), &mut failure)
                .await
                .is_err()
        );
        let mut bytes = [0; 3];
        let mut used = 0;
        while used < bytes.len() {
            socket.readable().await.unwrap();
            match socket.try_read(&mut bytes[used..]) {
                Ok(0) => panic!("error probing consumed payload"),
                Ok(count) => used += count,
                Err(error) if error.kind() == ErrorKind::WouldBlock => continue,
                Err(error) => panic!("cannot read the preserved payload: {error}"),
            }
        }
        assert_eq!(&bytes, b"abc");
        assert!(
            tokio::time::timeout(Duration::from_millis(100), &mut failure)
                .await
                .is_err()
        );
        // A socket that has already sent TCP FIN need not emit a later RST on
        // Windows. Use a separate, still-open connection for the reset assertion.
        drop(failure);
        drop(peer);
        let mut peer = TcpStream::connect(listener.local_addr().unwrap()).await.unwrap();
        let (socket, _) = listener.accept().await.unwrap();
        peer.write_all(b"buffered before reset").await.unwrap();
        let mut failure = Box::pin(wait(&socket));
        assert!(
            tokio::time::timeout(Duration::from_millis(100), &mut failure)
                .await
                .is_err()
        );
        socket2::SockRef::from(&peer).set_linger(Some(Duration::ZERO)).unwrap();
        drop(peer);
        let error = tokio::time::timeout(Duration::from_secs(2), &mut failure)
            .await
            .expect("a reset must be observed even while application bytes remain buffered");
        assert!(matches!(
            error.kind(),
            ErrorKind::ConnectionReset | ErrorKind::ConnectionAborted
        ));
    }
}
