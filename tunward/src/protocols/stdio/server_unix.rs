use nix::fcntl::{FcntlArg, OFlag, fcntl};
use std::io;
use std::os::fd::{AsFd, OwnedFd};
use std::pin::Pin;
use std::task::{Context, Poll, ready};
use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::oneshot;
use tracing::info;

/// A standard stream registered with the runtime's reactor.
///
/// It owns a duplicate of the stream's descriptor, so the descriptor the reactor watches cannot be
/// closed or replaced elsewhere while it is registered, which `AsyncFd::register` requires.
pub struct StdioFd(AsyncFd<OwnedFd>);

impl StdioFd {
    fn new(stream: impl AsFd) -> io::Result<Self> {
        let fd = stream.as_fd().try_clone_to_owned()?;
        // The duplicate shares the open file description, so this also affects the original stream.
        let flags = OFlag::from_bits_retain(fcntl(&fd, FcntlArg::F_GETFL)?);
        fcntl(&fd, FcntlArg::F_SETFL(flags | OFlag::O_NONBLOCK))?;
        // SAFETY: `fd` is an `OwnedFd` moved into the `AsyncFd`, which owns it until it is dropped: it is
        // open, refers to the same file description, and `as_raw_fd` returns the same number throughout.
        let fd = unsafe { AsyncFd::register(fd) }.map_err(|error| error.into_parts().1)?;
        Ok(Self(fd))
    }
}

impl AsyncRead for StdioFd {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        loop {
            let mut guard = ready!(self.0.poll_read_ready(cx))?;
            let unfilled = buf.initialize_unfilled();
            match guard.try_io(|fd| Ok(nix::unistd::read(fd.get_ref(), unfilled)?)) {
                Ok(read) => {
                    buf.advance(read?);
                    return Poll::Ready(Ok(()));
                }
                // Not actually readable: readiness was cleared, so wait for the next event.
                Err(_would_block) => continue,
            }
        }
    }
}

impl AsyncWrite for StdioFd {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        loop {
            let mut guard = ready!(self.0.poll_write_ready(cx))?;
            match guard.try_io(|fd| Ok(nix::unistd::write(fd.get_ref(), buf)?)) {
                Ok(written) => return Poll::Ready(written),
                Err(_would_block) => continue,
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

pub struct StdinStream {
    stdin: StdioFd,
    _receiver: oneshot::Receiver<()>,
}

impl AsyncRead for StdinStream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().stdin).poll_read(cx, buf)
    }
}

pub async fn run_server() -> Result<((StdinStream, StdioFd), oneshot::Sender<()>), anyhow::Error> {
    info!("Starting STDIO server");

    let stdin = StdioFd::new(io::stdin())?;
    let stdout = StdioFd::new(io::stdout())?;
    let (tx, rx) = oneshot::channel::<()>();

    Ok(((StdinStream { stdin, _receiver: rx }, stdout), tx))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixStream;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn reads_and_writes_through_a_duplicated_descriptor() {
        let (local, mut peer) = UnixStream::pair().unwrap();
        let mut stream = StdioFd::new(&local).unwrap();
        // The original descriptor can be closed: the registered duplicate keeps the stream open.
        drop(local);

        stream.write_all(b"from stdout").await.unwrap();
        let mut buf = [0; 11];
        std::io::Read::read_exact(&mut peer, &mut buf).unwrap();
        assert_eq!(&buf, b"from stdout");

        std::io::Write::write_all(&mut peer, b"to stdin").unwrap();
        let mut buf = [0; 8];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"to stdin");

        // End of input is reported as a zero-length read.
        drop(peer);
        let mut rest = Vec::new();
        stream.read_to_end(&mut rest).await.unwrap();
        assert!(rest.is_empty());
    }

    #[tokio::test]
    async fn waits_for_input_without_spinning() {
        let (local, mut peer) = UnixStream::pair().unwrap();
        let mut stream = StdioFd::new(&local).unwrap();
        let reader = tokio::spawn(async move {
            let mut buf = [0; 5];
            stream.read_exact(&mut buf).await.map(|_| buf)
        });
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        assert!(!reader.is_finished(), "a read with no input must stay pending");
        std::io::Write::write_all(&mut peer, b"ready").unwrap();
        assert_eq!(&reader.await.unwrap().unwrap(), b"ready");
    }
}
