//! Windows reports an established TCP reset through read/write closure, not Mio's ERROR flag.

use futures_util::FutureExt;
use std::io::{self, ErrorKind};
use std::mem::MaybeUninit;
use std::time::Duration;
use tokio::io::Interest;
use tokio::net::TcpStream;

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
