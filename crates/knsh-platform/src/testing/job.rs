//! A terminal and `time` clocks that record and replay (KNSH-100).

use std::collections::VecDeque;
use std::os::fd::OwnedFd;
use std::sync::Mutex;
use std::time::Duration;

use super::lock;
use crate::error::PlatformError;
use crate::job::{CpuTimes, JobTerminal, ShellTimes};
use crate::process::{ProcessGroupId, SharedFd};

/// A [`JobTerminal`] that records every foreground change: `Some(group)` for a job, `None` for the shell taking the
/// terminal back. Its descriptor is a real descriptor of `/dev/null`, so it can travel in
/// [`ChildOptions`](crate::ChildOptions).
#[derive(Debug)]
pub struct FakeTerminal {
    fd: SharedFd,
    changes: Mutex<Vec<Option<ProcessGroupId>>>,
}

impl FakeTerminal {
    /// A terminal the shell owns.
    ///
    /// # Panics
    ///
    /// If `/dev/null` cannot be opened.
    #[must_use]
    pub fn new() -> Self {
        #[allow(clippy::expect_used)]
        let file = std::fs::File::open("/dev/null").expect("/dev/null opens");
        Self {
            fd: SharedFd::new(OwnedFd::from(file)),
            changes: Mutex::new(Vec::new()),
        }
    }

    /// Every foreground change, in order.
    #[must_use]
    pub fn changes(&self) -> Vec<Option<ProcessGroupId>> {
        lock(&self.changes).clone()
    }
}

impl Default for FakeTerminal {
    fn default() -> Self {
        Self::new()
    }
}

impl JobTerminal for FakeTerminal {
    fn descriptor(&self) -> SharedFd {
        self.fd.clone()
    }

    fn set_foreground(&self, group: Option<ProcessGroupId>) -> Result<(), PlatformError> {
        lock(&self.changes).push(group);
        Ok(())
    }
}

/// [`ShellTimes`] that gives scripted readings in order, the last repeated (zero when none is scripted).
#[derive(Debug, Default)]
pub struct FakeShellTimes {
    readings: Mutex<VecDeque<(Duration, CpuTimes)>>,
}

impl FakeShellTimes {
    /// No readings: every clock reads zero.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Queues one reading of both clocks: [`ShellTimes::elapsed`] and then [`ShellTimes::cpu`] give it.
    #[must_use]
    pub fn then(self, elapsed: Duration, user: Duration, system: Duration) -> Self {
        lock(&self.readings).push_back((elapsed, CpuTimes { user, system }));
        self
    }

    /// The current reading; consumed by [`ShellTimes::cpu`] unless it is the last.
    fn current(&self, consume: bool) -> (Duration, CpuTimes) {
        let mut readings = lock(&self.readings);
        let reading = readings.front().copied().unwrap_or_default();
        if consume && readings.len() > 1 {
            readings.pop_front();
        }
        reading
    }
}

impl ShellTimes for FakeShellTimes {
    fn elapsed(&self) -> Duration {
        self.current(false).0
    }

    fn cpu(&self) -> CpuTimes {
        self.current(true).1
    }
}
