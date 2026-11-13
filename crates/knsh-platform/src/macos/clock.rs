//! System wall and monotonic clocks.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use knsh_core::Timestamp;

use crate::clock::{Clock, Monotonic};
use crate::error::PlatformError;

/// The system clocks: `gettimeofday` (through `SystemTime`) for wall time and `CLOCK_MONOTONIC` for elapsed time.
///
/// On macOS `CLOCK_MONOTONIC` keeps counting while the machine sleeps, so a timeout that spans a sleep expires on
/// wake instead of being extended by the sleep.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl SystemClock {
    /// The system clock.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl Clock for SystemClock {
    fn now(&self) -> Result<Timestamp, PlatformError> {
        let since_epoch = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| PlatformError::ClockOutOfRange)?;
        let micros = u64::try_from(since_epoch.as_micros()).map_err(|_| PlatformError::ClockOutOfRange)?;
        Timestamp::from_unix_micros(micros).map_err(|_| PlatformError::ClockOutOfRange)
    }

    fn monotonic(&self) -> Monotonic {
        let mut now = libc::timespec { tv_sec: 0, tv_nsec: 0 };
        // SAFETY: `now` is a valid, writable `timespec` for the duration of the call, and `CLOCK_MONOTONIC` is a
        // clock id macOS always supports, so the call cannot fail (it can only fail with EINVAL/EFAULT).
        let rc = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &raw mut now) };
        debug_assert_eq!(rc, 0, "clock_gettime(CLOCK_MONOTONIC) failed");
        // Both fields are non-negative for a monotonic clock; the fallbacks are unreachable in practice.
        let secs = u64::try_from(now.tv_sec).unwrap_or(0);
        let nanos = u32::try_from(now.tv_nsec).unwrap_or(0);
        Monotonic::from_elapsed(Duration::new(secs, nanos))
    }

    fn sleep(&self, duration: Duration) {
        std::thread::sleep(duration);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wall_clock_is_after_2026_and_monotonic_does_not_decrease() {
        let clock = SystemClock::new();
        // 2026-01-01T00:00:00Z.
        assert!(clock.now().unwrap().as_unix_micros() > 1_767_225_600_000_000);
        let first = clock.monotonic();
        let second = clock.monotonic();
        assert!(second >= first);
    }
}
