//! A clock that moves only when told.

use std::sync::Mutex;
use std::time::Duration;

use knsh_core::Timestamp;

use super::lock;
use crate::clock::{Clock, Monotonic};
use crate::error::PlatformError;

/// A controllable clock. Wall and monotonic time start where the test says and change only through
/// [`FakeClock::advance`] and [`FakeClock::set_wall`].
#[derive(Debug)]
pub struct FakeClock {
    state: Mutex<State>,
}

#[derive(Debug)]
struct State {
    /// Wall time in microseconds since the epoch; may be set out of range to test [`PlatformError::ClockOutOfRange`].
    wall_micros: u64,
    monotonic: Duration,
}

impl FakeClock {
    /// A clock whose wall time is `start` and whose monotonic reading is zero.
    #[must_use]
    pub fn new(start: Timestamp) -> Self {
        Self {
            state: Mutex::new(State {
                wall_micros: start.as_unix_micros(),
                monotonic: Duration::ZERO,
            }),
        }
    }

    /// Moves both clocks forward by `by` (wall time at microsecond precision). Saturates instead of overflowing.
    pub fn advance(&self, by: Duration) {
        let mut state = lock(&self.state);
        let micros = u64::try_from(by.as_micros()).unwrap_or(u64::MAX);
        state.wall_micros = state.wall_micros.saturating_add(micros);
        state.monotonic = state.monotonic.saturating_add(by);
    }

    /// Jumps the wall clock to `micros` since the epoch (backwards or forwards) without moving the monotonic clock,
    /// like an NTP correction. A value past 9999 makes [`Clock::now`] fail.
    pub fn set_wall(&self, micros: u64) {
        lock(&self.state).wall_micros = micros;
    }
}

impl Clock for FakeClock {
    fn now(&self) -> Result<Timestamp, PlatformError> {
        Timestamp::from_unix_micros(lock(&self.state).wall_micros).map_err(|_| PlatformError::ClockOutOfRange)
    }

    fn monotonic(&self) -> Monotonic {
        Monotonic::from_elapsed(lock(&self.state).monotonic)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Determinism: time never moves on its own.
    #[test]
    fn fake_clock_advances_only_when_told() {
        let start = Timestamp::from_unix_micros(1_700_000_000_000_000).unwrap();
        let clock = FakeClock::new(start);
        let m0 = clock.monotonic();
        std::thread::sleep(Duration::from_millis(5));
        assert_eq!(clock.now(), Ok(start));
        assert_eq!(clock.monotonic(), m0);

        clock.advance(Duration::from_millis(1500));
        assert_eq!(clock.now().unwrap().as_unix_micros(), 1_700_000_001_500_000);
        assert_eq!(
            clock.monotonic().saturating_duration_since(m0),
            Duration::from_millis(1500)
        );

        // A wall jump backwards leaves the monotonic clock alone.
        clock.set_wall(0);
        assert_eq!(clock.now(), Ok(Timestamp::UNIX_EPOCH));
        assert_eq!(
            clock.monotonic().saturating_duration_since(m0),
            Duration::from_millis(1500)
        );

        clock.set_wall(u64::MAX);
        assert_eq!(clock.now(), Err(PlatformError::ClockOutOfRange));
    }
}
