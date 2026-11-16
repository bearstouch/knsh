//! The tunnel: bytes copied unchanged both ways between client and destination, with idle and total timeouts.
//!
//! One thread per direction (the connection's own thread and one scoped helper), each a blocking loop of `read` and
//! `write_all`: no buffering beyond one 16 KiB chunk, no inspection, no rewriting (byte for byte). An end of stream
//! from one side is passed on as a half close (`shutdown(Write)`) to the other, so protocols that half-close keep
//! working.
//!
//! - **Idle timeout:** no byte in either direction for [`Timeouts::idle`]. Reads wake every [`tick`] to check it, and
//!   a write blocked for that long (a peer that stopped reading) counts as idle too.
//! - **Total timeout:** the tunnel is closed [`Timeouts::total`] after it opened, busy or not.
//!
//! Either timeout, a failed read or write, or a revocation (the proxy shuts the client socket down) closes both
//! sockets in both directions, which ends both loops.

use std::io::{ErrorKind, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use knsh_platform::{Clock, Monotonic};

/// Bytes moved per read.
const CHUNK: usize = 16 * 1024;

/// Longest pause between timeout checks.
const MAX_TICK: Duration = Duration::from_secs(1);
/// Shortest pause between timeout checks.
const MIN_TICK: Duration = Duration::from_millis(10);

/// A tunnel's time limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timeouts {
    /// Closed after this long without a byte in either direction.
    pub idle: Duration,
    /// Closed this long after it opened.
    pub total: Duration,
}

/// How often reads wake to check the timeouts: a quarter of the idle timeout, between 10 ms and 1 s. A timeout fires
/// at most one tick late.
#[must_use]
pub fn tick(timeouts: Timeouts) -> Duration {
    (timeouts.idle / 4).clamp(MIN_TICK, MAX_TICK)
}

/// What both directions share.
struct Tunnel<'a> {
    client: &'a TcpStream,
    upstream: &'a TcpStream,
    clock: &'a Arc<dyn Clock>,
    timeouts: Timeouts,
    opened: Monotonic,
    /// Nanoseconds from `opened` to the last byte moved, either way.
    last_activity: AtomicU64,
    closed: AtomicBool,
}

impl Tunnel<'_> {
    /// Notes that a byte moved now.
    fn touch(&self) {
        let since = self.clock.monotonic().saturating_duration_since(self.opened);
        self.last_activity
            .store(u64::try_from(since.as_nanos()).unwrap_or(u64::MAX), Ordering::Relaxed);
    }

    /// Whether either timeout has passed.
    fn expired(&self) -> bool {
        let now = self.clock.monotonic().saturating_duration_since(self.opened);
        let last = Duration::from_nanos(self.last_activity.load(Ordering::Relaxed));
        now >= self.timeouts.total || now.saturating_sub(last) >= self.timeouts.idle
    }

    /// Closes both sockets both ways, which ends the other direction's loop too.
    fn close(&self) {
        self.closed.store(true, Ordering::Relaxed);
        let _ = self.client.shutdown(Shutdown::Both);
        let _ = self.upstream.shutdown(Shutdown::Both);
    }

    /// Copies `from` to `to` until `from` ends (passed on as a half close) or the tunnel closes.
    fn pump(&self, mut from: &TcpStream, mut to: &TcpStream) {
        let tick = tick(self.timeouts);
        if from.set_read_timeout(Some(tick)).is_err() || to.set_write_timeout(Some(self.timeouts.idle)).is_err() {
            self.close();
            return;
        }
        let mut buf = vec![0; CHUNK];
        while !self.closed.load(Ordering::Relaxed) {
            match from.read(&mut buf) {
                Ok(0) => {
                    // The sender is done; the other direction carries on until it is done too.
                    let _ = to.shutdown(Shutdown::Write);
                    return;
                }
                Ok(read) => {
                    if to.write_all(&buf[..read]).is_err() {
                        self.close();
                        return;
                    }
                    self.touch();
                }
                // A tick with nothing to read, or a signal: only the timeout check below.
                Err(error)
                    if matches!(
                        error.kind(),
                        ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted
                    ) => {}
                Err(_) => {
                    self.close();
                    return;
                }
            }
            if self.expired() {
                self.close();
                return;
            }
        }
    }
}

/// Tunnels between `client` and `upstream` until both directions end or the tunnel is closed (module
/// documentation). Blocks the calling thread; one helper thread is scoped to the call.
pub fn relay(client: &TcpStream, upstream: &TcpStream, timeouts: Timeouts, clock: &Arc<dyn Clock>) {
    let tunnel = Tunnel {
        client,
        upstream,
        clock,
        timeouts,
        opened: clock.monotonic(),
        last_activity: AtomicU64::new(0),
        closed: AtomicBool::new(false),
    };
    std::thread::scope(|scope| {
        scope.spawn(|| tunnel.pump(client, upstream));
        tunnel.pump(upstream, client);
    });
}

#[cfg(test)]
mod tests {
    use std::net::TcpListener;
    use std::time::Instant;

    use knsh_platform::macos::SystemClock;

    use super::*;

    /// A connected pair of loopback sockets.
    fn pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let near = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (far, _) = listener.accept().unwrap();
        (near, far)
    }

    /// Runs a relay between two fresh pairs; returns the outer ends (client side, destination side) and the relay
    /// thread.
    fn tunnel(timeouts: Timeouts) -> (TcpStream, TcpStream, std::thread::JoinHandle<()>) {
        let (client, proxy_client) = pair();
        let (proxy_upstream, upstream) = pair();
        let clock: Arc<dyn Clock> = Arc::new(SystemClock::new());
        let handle = std::thread::spawn(move || relay(&proxy_client, &proxy_upstream, timeouts, &clock));
        (client, upstream, handle)
    }

    const LONG: Timeouts = Timeouts {
        idle: Duration::from_secs(10),
        total: Duration::from_secs(30),
    };

    // FR-NET-01: every byte value passes unchanged both ways, and a half close is passed on.
    #[test]
    fn tunnels_byte_for_byte_both_ways() {
        let (mut client, mut upstream, handle) = tunnel(LONG);
        let all: Vec<u8> = (0..=255).cycle().take(100_000).collect();
        client.write_all(&all).unwrap();
        client.shutdown(Shutdown::Write).unwrap();
        let mut received = Vec::new();
        upstream.read_to_end(&mut received).unwrap();
        assert_eq!(received, all);
        upstream.write_all(b"\x00\xff\r\nreply").unwrap();
        upstream.shutdown(Shutdown::Write).unwrap();
        let mut back = Vec::new();
        client.read_to_end(&mut back).unwrap();
        assert_eq!(back, b"\x00\xff\r\nreply");
        handle.join().unwrap();
    }

    // The idle timeout closes a quiet tunnel, both ways.
    #[test]
    fn closes_idle_tunnel() {
        let started = Instant::now();
        let (mut client, mut upstream, handle) = tunnel(Timeouts {
            idle: Duration::from_millis(150),
            total: Duration::from_secs(30),
        });
        let mut buf = [0; 1];
        assert_eq!(client.read(&mut buf).unwrap_or(0), 0);
        assert_eq!(upstream.read(&mut buf).unwrap_or(0), 0);
        handle.join().unwrap();
        let took = started.elapsed();
        assert!(
            took >= Duration::from_millis(150) && took < Duration::from_secs(5),
            "{took:?}"
        );
    }

    // The total timeout closes a busy tunnel.
    #[test]
    fn closes_tunnel_at_total_timeout() {
        let started = Instant::now();
        let (mut client, mut upstream, handle) = tunnel(Timeouts {
            idle: Duration::from_secs(10),
            total: Duration::from_millis(300),
        });
        let reader = std::thread::spawn(move || {
            let mut sink = Vec::new();
            let _ = upstream.read_to_end(&mut sink);
        });
        // Keep the tunnel busy until it is closed under us.
        while client.write_all(b"busy").is_ok() && started.elapsed() < Duration::from_secs(5) {
            std::thread::sleep(Duration::from_millis(20));
        }
        handle.join().unwrap();
        reader.join().unwrap();
        let took = started.elapsed();
        assert!(
            took >= Duration::from_millis(300) && took < Duration::from_secs(5),
            "{took:?}"
        );
    }

    #[test]
    fn tick_is_bounded() {
        let at = |idle| {
            tick(Timeouts {
                idle,
                total: Duration::MAX,
            })
        };
        assert_eq!(at(Duration::from_millis(1)), MIN_TICK);
        assert_eq!(at(Duration::from_secs(400)), MAX_TICK);
        assert_eq!(at(Duration::from_millis(400)), Duration::from_millis(100));
    }
}
