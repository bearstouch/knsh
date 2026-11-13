//! Wall and monotonic time.
//!
//! The wall clock stamps records and events; the monotonic clock measures timeouts and rate-limit windows, where a
//! wall-clock jump (NTP, the user changing the time) must not shorten or extend a deadline.

use std::time::Duration;

use knsh_core::Timestamp;

use crate::error::PlatformError;

/// A reading of a monotonic clock: time since an unspecified origin that never goes backwards.
///
/// Only differences between readings from the same [`Clock`] are meaningful; the origin is not related to the wall
/// clock and differs between implementations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Monotonic(Duration);

impl Monotonic {
    /// A reading at `elapsed` after the clock's origin.
    #[must_use]
    pub const fn from_elapsed(elapsed: Duration) -> Self {
        Self(elapsed)
    }

    /// Time since the clock's origin.
    #[must_use]
    pub const fn elapsed_since_origin(self) -> Duration {
        self.0
    }

    /// Time from `earlier` to `self`, or zero if `earlier` is later.
    #[must_use]
    pub fn saturating_duration_since(self, earlier: Self) -> Duration {
        self.0.saturating_sub(earlier.0)
    }

    /// The reading `duration` after `self`, or `None` on overflow.
    #[must_use]
    pub fn checked_add(self, duration: Duration) -> Option<Self> {
        self.0.checked_add(duration).map(Self)
    }
}

/// Wall and monotonic time. Object safe: hold it as `Arc<dyn Clock>`.
pub trait Clock: Send + Sync {
    /// The current UTC wall-clock time, with microsecond precision.
    ///
    /// # Errors
    ///
    /// [`PlatformError::ClockOutOfRange`] if the system clock is before 1970 or after 9999.
    fn now(&self) -> Result<Timestamp, PlatformError>;

    /// The current monotonic reading. Never fails and never decreases between calls on the same clock.
    fn monotonic(&self) -> Monotonic;

    /// Blocks the calling thread for `duration` of monotonic time. A fake clock advances itself instead of
    /// blocking, so code that polls with a deadline (the capability probe, KNSH-014) is tested without real waits.
    fn sleep(&self, duration: Duration);
}
