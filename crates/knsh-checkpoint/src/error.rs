//! The crate's single error type.
//!
//! Like [`PlatformError`], messages never echo a path or file contents (NFR-PRIV-02).

use std::fmt;

use knsh_platform::PlatformError;

/// Every way a checkpoint operation can fail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckpointError {
    /// A platform call failed.
    Platform(PlatformError),
    /// A file kept changing while its post-image identity was read: its identity before and after hashing differed
    /// on every attempt, so no identity could be recorded that matches its contents (FR-CKP-09).
    IdentityUnstable,
    /// A thread could not be started (the file-event watcher's worker, KNSH-080).
    Threads,
}

impl fmt::Display for CheckpointError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Platform(error) => write!(f, "platform call failed: {error}"),
            Self::IdentityUnstable => f.write_str("file kept changing while its identity was read"),
            Self::Threads => f.write_str("a thread could not be started"),
        }
    }
}

impl std::error::Error for CheckpointError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Platform(error) => Some(error),
            Self::IdentityUnstable | Self::Threads => None,
        }
    }
}

impl From<PlatformError> for CheckpointError {
    fn from(error: PlatformError) -> Self {
        Self::Platform(error)
    }
}
