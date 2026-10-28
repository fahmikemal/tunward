use parking_lot::Mutex;
use std::error::Error;
use std::io;
use std::time::Duration;
use tokio::time::Instant;
use tracing::{debug, warn};

/// Emits at most one log line per interval and counts the events it held back in between.
pub(crate) struct LogLimiter {
    interval: Duration,
    state: Mutex<(Option<Instant>, u64)>,
}

impl LogLimiter {
    pub fn new(interval: Duration) -> Self {
        Self {
            interval,
            state: Mutex::new((None, 0)),
        }
    }

    /// Returns how many events were suppressed since the last emitted one, or `None` when this
    /// event must stay silent.
    pub fn check(&self) -> Option<u64> {
        let now = Instant::now();
        let mut state = self.state.lock();
        let (last, suppressed) = &mut *state;
        if last.is_some_and(|last| now.duration_since(last) < self.interval) {
            *suppressed += 1;
            return None;
        }
        *last = Some(now);
        Some(std::mem::take(suppressed))
    }
}

/// Paces an accept loop after errors. A persistent failure such as file descriptor exhaustion
/// returns immediately on every retry, so retrying without a pause spins a CPU and floods the log.
///
/// The pause stays short: a descriptor freed while the loop sleeps can be taken by another task
/// instead, such as the client pool, which keeps the connections it finishes after their requester
/// gave up idle until they expire. Retrying ten times a second costs nothing and wins those races.
pub(crate) struct AcceptBackoff {
    what: &'static str,
    delay: Duration,
    log: LogLimiter,
}

impl AcceptBackoff {
    const INITIAL_DELAY: Duration = Duration::from_millis(5);
    const MAX_DELAY: Duration = Duration::from_millis(100);

    pub fn new(what: &'static str) -> Self {
        Self {
            what,
            delay: Duration::ZERO,
            log: LogLimiter::new(Duration::from_secs(10)),
        }
    }

    /// Call after a successful accept, so a later failure starts from the shortest pause.
    pub fn reset(&mut self) {
        self.delay = Duration::ZERO;
    }

    /// Wait before the next accept. Errors about one peer, such as a connection reset while it
    /// waited in the backlog, do not affect the next connection and are retried right away.
    pub async fn wait(&mut self, error: &(dyn Error + Send + Sync + 'static)) {
        if is_peer_error(error) {
            debug!("{}: {error}", self.what);
            return;
        }

        self.delay = (self.delay * 2).clamp(Self::INITIAL_DELAY, Self::MAX_DELAY);
        if let Some(suppressed) = self.log.check() {
            warn!(
                suppressed,
                "{}: {error}; pausing accepts for {:?} before retrying", self.what, self.delay
            );
        }
        tokio::time::sleep(self.delay).await;
    }

    #[cfg(test)]
    fn delay(&self) -> Duration {
        self.delay
    }
}

fn is_peer_error(error: &(dyn Error + 'static)) -> bool {
    std::iter::successors(Some(error), |&error| error.source())
        .filter_map(|error| error.downcast_ref::<io::Error>())
        .any(|error| {
            matches!(
                error.kind(),
                io::ErrorKind::ConnectionAborted
                    | io::ErrorKind::ConnectionReset
                    | io::ErrorKind::ConnectionRefused
                    | io::ErrorKind::Interrupted
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn too_many_open_files() -> io::Error {
        io::Error::from_raw_os_error(24)
    }

    #[tokio::test(start_paused = true)]
    async fn resource_errors_back_off_exponentially_up_to_a_tenth_of_a_second() {
        let mut backoff = AcceptBackoff::new("test accept");
        let mut delays = Vec::new();
        for _ in 0..8 {
            let started = Instant::now();
            backoff.wait(&too_many_open_files()).await;
            assert_eq!(started.elapsed(), backoff.delay());
            delays.push(backoff.delay().as_millis());
        }
        assert_eq!(delays, [5, 10, 20, 40, 80, 100, 100, 100]);

        backoff.reset();
        backoff.wait(&too_many_open_files()).await;
        assert_eq!(backoff.delay(), Duration::from_millis(5));
    }

    #[tokio::test(start_paused = true)]
    async fn peer_errors_retry_immediately_and_keep_the_current_pause() {
        let mut backoff = AcceptBackoff::new("test accept");
        backoff.wait(&too_many_open_files()).await;
        for kind in [
            io::ErrorKind::ConnectionAborted,
            io::ErrorKind::ConnectionReset,
            io::ErrorKind::ConnectionRefused,
            io::ErrorKind::Interrupted,
        ] {
            let started = Instant::now();
            backoff.wait(&io::Error::from(kind)).await;
            assert_eq!(started.elapsed(), Duration::ZERO, "{kind:?}");
        }
        assert_eq!(backoff.delay(), Duration::from_millis(5));
    }

    #[tokio::test(start_paused = true)]
    async fn errors_wrapped_by_listeners_are_classified_by_their_io_source() {
        let mut backoff = AcceptBackoff::new("test accept");
        let wrapped = anyhow::Error::from(io::Error::from(io::ErrorKind::ConnectionReset)).context("listener");
        let started = Instant::now();
        backoff.wait(wrapped.as_ref()).await;
        assert_eq!(started.elapsed(), Duration::ZERO);

        // An error without an I/O cause is paced, since retrying it right away cannot be shown safe.
        let opaque = anyhow::anyhow!("listener failed");
        backoff.wait(opaque.as_ref()).await;
        assert_eq!(backoff.delay(), Duration::from_millis(5));
    }

    #[tokio::test(start_paused = true)]
    async fn log_limiter_emits_once_per_interval_and_counts_the_rest() {
        let limiter = LogLimiter::new(Duration::from_secs(10));
        assert_eq!(limiter.check(), Some(0));
        for _ in 0..5 {
            assert_eq!(limiter.check(), None);
        }
        tokio::time::advance(Duration::from_secs(10)).await;
        assert_eq!(limiter.check(), Some(5));
        assert_eq!(limiter.check(), None);
    }
}
