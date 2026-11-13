//! The crate's single error type.
//!
//! Messages never echo stored or supplied text: a command, a path or a cursor may carry private data, and these
//! errors are logged (NFR-PRIV-02).

use std::fmt;

use knsh_platform::PlatformError;

/// Every way the record store can refuse or fail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreError {
    /// A filesystem or SQLite call failed. Carries the operation and code, never SQLite's message text.
    Platform(PlatformError),
    /// The database was written by a newer engine. It is not opened for writing and is left exactly as it was
    /// (CLAUDE.md "Persistence": a newer file is never overwritten).
    NewerSchema {
        /// The schema version found in the file.
        found: i64,
        /// The newest version this build understands.
        supported: i64,
    },
    /// The file is a SQLite database, but not a record store: it has another application id, or it already has
    /// tables without being marked as ours. Never adopted or overwritten.
    ForeignDatabase,
    /// The database file is not a regular file owned by the engine's user with mode `0600` (CLAUDE.md "Secrets and
    /// privacy"). Refused rather than repaired: someone else may be able to read or replace it.
    UnsafeFile,
    /// A stored value could not be read back (for example a malformed ID): the file was changed outside the engine.
    Corrupt,
    /// A record field breaks a storage rule, such as a secret name with a line break. Names the field.
    InvalidRecord(&'static str),
    /// The query asked for a session outside the caller's scope (`-32003` on the API).
    OutOfScope,
    /// No record with this ID is visible in the caller's scope.
    RecordNotFound,
    /// The store thread has stopped, so nothing can be written or read.
    Closed,
    /// The store thread could not be started.
    ThreadStart,
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Platform(error) => write!(f, "record store: {error}"),
            Self::NewerSchema { found, supported } => write!(
                f,
                "record store schema version {found} is newer than this engine's {supported}; not opened"
            ),
            Self::ForeignDatabase => f.write_str("record store file belongs to another application; not opened"),
            Self::UnsafeFile => f.write_str("record store file is not an owner-only (0600) regular file"),
            Self::Corrupt => f.write_str("record store holds a value the engine cannot read"),
            Self::InvalidRecord(field) => write!(f, "record field {field} cannot be stored"),
            Self::OutOfScope => f.write_str("records outside the caller's session"),
            Self::RecordNotFound => f.write_str("record not found"),
            Self::Closed => f.write_str("record store is closed"),
            Self::ThreadStart => f.write_str("record store thread could not start"),
        }
    }
}

impl std::error::Error for StoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Platform(error) => Some(error),
            Self::NewerSchema { .. }
            | Self::ForeignDatabase
            | Self::UnsafeFile
            | Self::Corrupt
            | Self::InvalidRecord(_)
            | Self::OutOfScope
            | Self::RecordNotFound
            | Self::Closed
            | Self::ThreadStart => None,
        }
    }
}

impl From<PlatformError> for StoreError {
    fn from(error: PlatformError) -> Self {
        Self::Platform(error)
    }
}

impl StoreError {
    /// A fixed name for the failure, for the system log (which accepts only static text).
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Platform(_) => "platform",
            Self::NewerSchema { .. } => "newer_schema",
            Self::ForeignDatabase => "foreign_database",
            Self::UnsafeFile => "unsafe_file",
            Self::Corrupt => "corrupt",
            Self::InvalidRecord(_) => "invalid_record",
            Self::OutOfScope => "out_of_scope",
            Self::RecordNotFound => "record_not_found",
            Self::Closed => "closed",
            Self::ThreadStart => "thread_start",
        }
    }
}
