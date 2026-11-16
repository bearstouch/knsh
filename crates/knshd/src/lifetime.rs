//! How long `knshd` stays alive (KNSH-013, `specs/02-architecture/process-model.md`).
//!
//! `knshd` stays alive while any envelope or recording session exists or any connection is open, and exits after
//! [`IDLE_LIMIT`] with none of them. launchd starts it again on the next connection, so an idle machine pays nothing.
//!
//! The rule is a pure function of the injected monotonic clock ([`IdleTimer`]), so tests move time instead of waiting
//! ten minutes. What keeps `knshd` alive besides connections ([`Activity`]) and what must be saved before it exits
//! ([`PendingWrites`]) are traits, filled in by the session registry (`crate::sessions::Sessions`, KNSH-021) and
//! the record store (KNSH-016, `crate::records::Records`).

use std::fmt;
use std::time::Duration;

use knsh_platform::Monotonic;

/// How long `knshd` waits with nothing to do before it exits.
pub(crate) const IDLE_LIMIT: Duration = Duration::from_mins(10);

/// Sessions that keep `knshd` alive: any envelope, or any session with recording on. `Send + Sync`: the accept loop
/// asks while connection threads change sessions.
pub(crate) trait Activity: Send + Sync {
    /// Whether an envelope or a recording session exists now.
    fn keeps_alive(&self) -> bool;
}

/// Keeps `knshd` alive while any of its parts does: the session registry, and the control service's open
/// connections (KNSH-067).
pub(crate) struct AnyActivity(pub(crate) Vec<std::sync::Arc<dyn Activity>>);

impl Activity for AnyActivity {
    fn keeps_alive(&self) -> bool {
        self.0.iter().any(|activity| activity.keeps_alive())
    }
}

/// Writes that must reach disk before `knshd` exits, such as buffered records.
pub(crate) trait PendingWrites: Send + Sync {
    /// Commits everything pending and returns once it is durable.
    ///
    /// # Errors
    ///
    /// [`CommitFailed`] if something could not be committed; `knshd` then exits with a failure status.
    fn commit(&self) -> Result<(), CommitFailed>;
}

/// Pending writes could not be committed. Carries only a fixed name of what failed, so it can be logged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CommitFailed(pub(crate) &'static str);

impl fmt::Display for CommitFailed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "pending writes not committed: {}", self.0)
    }
}

impl std::error::Error for CommitFailed {}

/// Where the idle clock stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Idle {
    /// Something keeps `knshd` alive; the timer was reset.
    Busy,
    /// Idle, with this long left before exit.
    Remaining(Duration),
    /// Idle for the whole limit: time to exit.
    Expired,
}

/// Measures idle time on the monotonic clock, so a wall-clock jump neither kills `knshd` early nor keeps it forever.
#[derive(Debug, Clone, Copy)]
pub(crate) struct IdleTimer {
    limit: Duration,
    /// The last time anything kept `knshd` alive (or start-up).
    last_active: Monotonic,
}

impl IdleTimer {
    /// A timer that starts counting at `now`, as if `knshd` had just been busy.
    pub(crate) const fn new(limit: Duration, now: Monotonic) -> Self {
        Self {
            limit,
            last_active: now,
        }
    }

    /// Records whether anything keeps `knshd` alive at `now` and says where the idle clock stands. Busy resets it.
    pub(crate) fn observe(&mut self, now: Monotonic, busy: bool) -> Idle {
        if busy {
            // `max`: a reading from another thread may be slightly older than the last one seen here.
            self.last_active = self.last_active.max(now);
            return Idle::Busy;
        }
        let idle = now.saturating_duration_since(self.last_active);
        match self.limit.checked_sub(idle) {
            Some(remaining) if !remaining.is_zero() => Idle::Remaining(remaining),
            Some(_) | None => Idle::Expired,
        }
    }
}

#[cfg(test)]
mod tests {
    use knsh_core::Timestamp;
    use knsh_platform::Clock;
    use knsh_platform::testing::FakeClock;

    use super::*;

    fn clock() -> FakeClock {
        FakeClock::new(Timestamp::from_unix_micros(1_700_000_000_000_000).unwrap())
    }

    // KNSH-013: with no sessions and no connections, knshd exits after exactly 10 idle minutes (fake clock).
    #[test]
    fn exits_after_10_idle_minutes() {
        let clock = clock();
        let mut timer = IdleTimer::new(IDLE_LIMIT, clock.monotonic());
        clock.advance(Duration::from_secs(9 * 60 + 59));
        assert_eq!(
            timer.observe(clock.monotonic(), false),
            Idle::Remaining(Duration::from_secs(1))
        );
        clock.advance(Duration::from_secs(1));
        assert_eq!(timer.observe(clock.monotonic(), false), Idle::Expired);
    }

    // KNSH-013: any session, envelope or open connection resets the timer; the ten minutes count from the last time
    // something was active.
    #[test]
    fn activity_resets_the_idle_timer() {
        let clock = clock();
        let mut timer = IdleTimer::new(IDLE_LIMIT, clock.monotonic());
        clock.advance(Duration::from_mins(9));
        assert_eq!(timer.observe(clock.monotonic(), true), Idle::Busy);
        clock.advance(Duration::from_mins(9));
        assert_eq!(
            timer.observe(clock.monotonic(), false),
            Idle::Remaining(Duration::from_secs(60))
        );
        clock.advance(Duration::from_secs(60));
        assert_eq!(timer.observe(clock.monotonic(), false), Idle::Expired);
    }

    // A wall-clock jump does not move the idle clock.
    #[test]
    fn wall_clock_jump_does_not_expire_the_timer() {
        let clock = clock();
        let mut timer = IdleTimer::new(IDLE_LIMIT, clock.monotonic());
        clock.set_wall(u64::from(u32::MAX) * 1_000_000);
        assert_eq!(timer.observe(clock.monotonic(), false), Idle::Remaining(IDLE_LIMIT));
    }
}
