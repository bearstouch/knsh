//! A system probe whose answers are set by the test.

use std::sync::atomic::{AtomicUsize, Ordering};

use crate::error::{Operation, PlatformError};
use crate::probe::SystemProbe;

/// A [`SystemProbe`] that answers what it was built with and counts how often it was asked, so a test can check
/// that probing happens once per `knshd` lifetime.
#[derive(Debug)]
pub struct FakeSystemProbe {
    // Fixed at construction, so no lock is needed: only the call count changes.
    os_major: Result<u32, PlatformError>,
    file_events: Result<(), PlatformError>,
    calls: AtomicUsize,
}

impl FakeSystemProbe {
    /// A machine running OS major version `major` with working file events.
    #[must_use]
    pub fn working(major: u32) -> Self {
        Self {
            os_major: Ok(major),
            file_events: Ok(()),
            calls: AtomicUsize::new(0),
        }
    }

    /// A machine where every check fails.
    #[must_use]
    pub fn failing() -> Self {
        Self {
            os_major: Err(PlatformError::Os {
                operation: Operation::SystemInfo,
                errno: libc::ENOENT,
            }),
            file_events: Err(PlatformError::Os {
                operation: Operation::FileEvents,
                errno: libc::EIO,
            }),
            calls: AtomicUsize::new(0),
        }
    }

    /// How many checks have been run, of either kind.
    #[must_use]
    pub fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl SystemProbe for FakeSystemProbe {
    fn os_major_version(&self) -> Result<u32, PlatformError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.os_major
    }

    fn check_file_events(&self) -> Result<(), PlatformError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.file_events
    }
}
