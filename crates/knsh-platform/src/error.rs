//! The crate's single error type.
//!
//! Messages never echo a path, a command line or any other input: errors are logged and sent over the wire, and
//! those values may be private (NFR-PRIV-02). Variants carry the failed operation and the `errno` instead.

use std::fmt;
use std::io;

use knsh_core::CoreError;

/// The platform operation that failed. Also names the step a test fake injects a fault into
/// ([`crate::testing::MemFs::inject_fault`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Operation {
    /// Opening a file for reading.
    Open,
    /// Reading file contents.
    Read,
    /// Creating or writing a file (including the temporary file of an atomic replace).
    Write,
    /// Flushing a file's contents to stable storage (`fsync`, `F_FULLFSYNC`).
    SyncFile,
    /// Renaming the temporary file over the target of an atomic replace.
    Rename,
    /// Flushing a directory entry to stable storage after a rename.
    SyncDirectory,
    /// Creating a directory.
    CreateDirectory,
    /// Reading file metadata.
    Metadata,
    /// Resolving a path to canonical form.
    Canonicalise,
    /// Starting a process.
    Spawn,
    /// Sending a signal to a process group.
    Signal,
    /// Waiting for a process to exit.
    Wait,
    /// Reading the clock.
    Clock,
    /// Reading random bytes.
    Random,
}

impl Operation {
    fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Read => "read",
            Self::Write => "write",
            Self::SyncFile => "sync file",
            Self::Rename => "rename",
            Self::SyncDirectory => "sync directory",
            Self::CreateDirectory => "create directory",
            Self::Metadata => "metadata",
            Self::Canonicalise => "canonicalise",
            Self::Spawn => "spawn",
            Self::Signal => "signal",
            Self::Wait => "wait",
            Self::Clock => "clock",
            Self::Random => "random",
        }
    }
}

/// Every way a platform call can fail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlatformError {
    /// The operating system refused an operation. Carries the `errno` value (`EIO` when the failure had none, for
    /// example a short write).
    Os {
        /// What was being done.
        operation: Operation,
        /// The `errno` value reported by the system.
        errno: i32,
    },
    /// A path argument was relative or otherwise unusable for the operation (for example a target with no parent
    /// directory or no file name). Engine paths are always absolute.
    InvalidPath,
    /// A resolved path did not satisfy the [`knsh_core::CanonicalPath`] invariants.
    NotCanonical(CoreError),
    /// A file was larger than the caller's limit; nothing was allocated for it.
    TooLarge {
        /// The caller's limit, in bytes.
        limit: u64,
    },
    /// The process group is not one this instance created, or it was already reaped. Its id may have been reused
    /// by an unrelated process, so it is never signalled (CLAUDE.md "Concurrency").
    UnknownProcessGroup,
    /// The wall clock is before 1970 or after 9999, outside what [`knsh_core::Timestamp`] can hold.
    ClockOutOfRange,
    /// A test fake was asked for something its script does not cover (only produced by [`crate::testing`]).
    NotScripted,
}

impl PlatformError {
    /// Builds [`PlatformError::Os`] from a standard I/O error, keeping only the `errno`.
    pub(crate) fn from_io(operation: Operation, error: &io::Error) -> Self {
        Self::Os {
            operation,
            errno: error.raw_os_error().unwrap_or(libc::EIO),
        }
    }

    /// The `errno` for an [`PlatformError::Os`] failure, otherwise `None`.
    #[must_use]
    pub fn errno(&self) -> Option<i32> {
        match self {
            Self::Os { errno, .. } => Some(*errno),
            Self::InvalidPath
            | Self::NotCanonical(_)
            | Self::TooLarge { .. }
            | Self::UnknownProcessGroup
            | Self::ClockOutOfRange
            | Self::NotScripted => None,
        }
    }

    /// Whether the failure means the path does not exist (`ENOENT`).
    #[must_use]
    pub fn is_not_found(&self) -> bool {
        self.errno() == Some(libc::ENOENT)
    }
}

impl fmt::Display for PlatformError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Os { operation, errno } => {
                // `io::Error` renders the system's text for the errno, without any path.
                write!(
                    f,
                    "{} failed: {}",
                    operation.as_str(),
                    io::Error::from_raw_os_error(*errno)
                )
            }
            Self::InvalidPath => f.write_str("path is not absolute or has no parent directory or file name"),
            Self::NotCanonical(error) => write!(f, "resolved path is not canonical: {error}"),
            Self::TooLarge { limit } => write!(f, "file is larger than the {limit}-byte limit"),
            Self::UnknownProcessGroup => f.write_str("process group was not created by this instance or was reaped"),
            Self::ClockOutOfRange => f.write_str("wall clock is outside 1970-01-01 to 9999-12-31 UTC"),
            Self::NotScripted => f.write_str("test fake has no script for this call"),
        }
    }
}

impl std::error::Error for PlatformError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::NotCanonical(error) => Some(error),
            Self::Os { .. }
            | Self::InvalidPath
            | Self::TooLarge { .. }
            | Self::UnknownProcessGroup
            | Self::ClockOutOfRange
            | Self::NotScripted => None,
        }
    }
}

impl From<CoreError> for PlatformError {
    fn from(error: CoreError) -> Self {
        Self::NotCanonical(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_never_echoes_input() {
        let error = PlatformError::Os {
            operation: Operation::Rename,
            errno: libc::ENOENT,
        };
        let text = error.to_string();
        assert!(text.starts_with("rename failed: "), "{text}");
        assert!(error.is_not_found());
        assert_eq!(PlatformError::InvalidPath.errno(), None);
    }

    #[test]
    fn io_error_without_errno_maps_to_eio() {
        let error = PlatformError::from_io(Operation::Write, &io::Error::from(io::ErrorKind::WriteZero));
        assert_eq!(error.errno(), Some(libc::EIO));
    }
}
