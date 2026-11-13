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
    /// Opening a SQLite database connection.
    DatabaseOpen,
    /// Configuring a SQLite connection (busy timeout, journal mode, synchronous mode).
    DatabaseConfigure,
    /// Compiling SQL text into a prepared statement.
    Prepare,
    /// Binding a parameter value to a prepared statement.
    Bind,
    /// Running a prepared statement one step.
    Step,
    /// Reading a column of the current result row.
    Column,
    /// Running SQL text without parameters (`sqlite3_exec`).
    Execute,
    /// Changing the permission bits of a path (`chmod`).
    SetMode,
    /// Reading an extended attribute (`getxattr`).
    ReadAttribute,
    /// Writing an extended attribute (`setxattr`).
    WriteAttribute,
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
            Self::DatabaseOpen => "database open",
            Self::DatabaseConfigure => "database configure",
            Self::Prepare => "prepare statement",
            Self::Bind => "bind parameter",
            Self::Step => "step statement",
            Self::Column => "read column",
            Self::Execute => "execute statement",
            Self::SetMode => "set mode",
            Self::ReadAttribute => "read extended attribute",
            Self::WriteAttribute => "write extended attribute",
        }
    }
}

/// A SQLite result code, extended form (for example `2067`, `SQLITE_CONSTRAINT_UNIQUE`), as returned by the system
/// library with extended result codes enabled (KNSH-010).
///
/// The text SQLite attaches to an error (`sqlite3_errmsg`) is deliberately not kept: it can quote SQL text, schema
/// names or values (`near "...": syntax error`), and errors are logged and sent over the wire (NFR-PRIV-02).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SqliteCode(i32);

impl SqliteCode {
    /// `SQLITE_ERROR`: generic error, for example an SQL syntax error.
    pub const ERROR: Self = Self(1);
    /// `SQLITE_BUSY`: the database is locked by another connection and the busy timeout ran out.
    pub const BUSY: Self = Self(5);
    /// `SQLITE_NOMEM`: an allocation failed.
    pub const NOMEM: Self = Self(7);
    /// `SQLITE_READONLY`: a write was attempted on a read-only connection.
    pub const READONLY: Self = Self(8);
    /// `SQLITE_CANTOPEN`: the database file could not be opened.
    pub const CANTOPEN: Self = Self(14);
    /// `SQLITE_TOOBIG`: a string or blob exceeds the size limit (also used for SQL text too long to pass).
    pub const TOOBIG: Self = Self(18);
    /// `SQLITE_CONSTRAINT`: a constraint (unique, not null, check, foreign key) was violated.
    pub const CONSTRAINT: Self = Self(19);
    /// `SQLITE_MISMATCH`: a column holds a different type than the reader asked for, or text is not UTF-8.
    pub const MISMATCH: Self = Self(20);
    /// `SQLITE_MISUSE`: the API was used incorrectly (for example a column read with no current row, several
    /// statements in one `prepare`, or a NUL byte inside SQL text). Raised by this wrapper before calling SQLite.
    pub const MISUSE: Self = Self(21);
    /// `SQLITE_RANGE`: a parameter or column index is out of range, or the wrong number of parameters was bound.
    pub const RANGE: Self = Self(25);
    /// `SQLITE_CONSTRAINT_UNIQUE`: a `UNIQUE` constraint was violated.
    pub const CONSTRAINT_UNIQUE: Self = Self(2067);
    /// `SQLITE_CONSTRAINT_PRIMARYKEY`: a `PRIMARY KEY` constraint was violated.
    pub const CONSTRAINT_PRIMARYKEY: Self = Self(1555);
    /// `SQLITE_CONSTRAINT_NOTNULL`: a `NOT NULL` constraint was violated.
    pub const CONSTRAINT_NOTNULL: Self = Self(1299);

    /// Wraps a raw result code as SQLite returned it.
    #[must_use]
    pub const fn from_raw(code: i32) -> Self {
        Self(code)
    }

    /// The extended result code, exactly as SQLite returned it.
    #[must_use]
    pub const fn extended(self) -> i32 {
        self.0
    }

    /// The primary result code: the low eight bits of the extended code (for example `19` for `2067`).
    #[must_use]
    pub const fn primary(self) -> Self {
        Self(self.0 & 0xff)
    }

    /// Whether this is any kind of constraint violation (`SQLITE_CONSTRAINT_*`).
    #[must_use]
    pub const fn is_constraint(self) -> bool {
        self.0 & 0xff == Self::CONSTRAINT.0
    }

    /// Whether the database was locked by another connection (`SQLITE_BUSY_*`).
    #[must_use]
    pub const fn is_busy(self) -> bool {
        self.0 & 0xff == Self::BUSY.0
    }

    /// The symbolic name of the primary code, for example `SQLITE_CONSTRAINT`. A fixed table rather than
    /// `sqlite3_errstr`, so formatting an error needs no foreign call.
    #[must_use]
    pub const fn primary_name(self) -> &'static str {
        match self.0 & 0xff {
            0 => "SQLITE_OK",
            1 => "SQLITE_ERROR",
            2 => "SQLITE_INTERNAL",
            3 => "SQLITE_PERM",
            4 => "SQLITE_ABORT",
            5 => "SQLITE_BUSY",
            6 => "SQLITE_LOCKED",
            7 => "SQLITE_NOMEM",
            8 => "SQLITE_READONLY",
            9 => "SQLITE_INTERRUPT",
            10 => "SQLITE_IOERR",
            11 => "SQLITE_CORRUPT",
            12 => "SQLITE_NOTFOUND",
            13 => "SQLITE_FULL",
            14 => "SQLITE_CANTOPEN",
            15 => "SQLITE_PROTOCOL",
            16 => "SQLITE_EMPTY",
            17 => "SQLITE_SCHEMA",
            18 => "SQLITE_TOOBIG",
            19 => "SQLITE_CONSTRAINT",
            20 => "SQLITE_MISMATCH",
            21 => "SQLITE_MISUSE",
            22 => "SQLITE_NOLFS",
            23 => "SQLITE_AUTH",
            24 => "SQLITE_FORMAT",
            25 => "SQLITE_RANGE",
            26 => "SQLITE_NOTADB",
            27 => "SQLITE_NOTICE",
            28 => "SQLITE_WARNING",
            100 => "SQLITE_ROW",
            101 => "SQLITE_DONE",
            _ => "SQLITE_UNKNOWN",
        }
    }
}

impl fmt::Display for SqliteCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} (code {})", self.primary_name(), self.0)
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
    /// A SQLite call failed, or the safe wrapper refused a call that SQLite would treat as misuse. Carries the
    /// result code, never SQLite's message text (see [`SqliteCode`]).
    Sqlite {
        /// What was being done.
        operation: Operation,
        /// The extended result code.
        code: SqliteCode,
    },
    /// An engine path is owned by another user, so it is never used: whoever owns it could read or replace engine
    /// data (KNSH-011, NFR-SEC-08). Fail closed rather than adopt or repair it.
    ForeignOwner,
    /// An engine path exists but is the wrong kind of entry (for example a symlink or a file where a directory must
    /// be). A symlink could redirect engine data elsewhere, so it is refused rather than followed (KNSH-011).
    UnexpectedKind,
    /// A backup or indexing exclusion was written but did not read back as written (KNSH-011, NFR-PRIV-04).
    ExclusionNotVerified,
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
            | Self::NotScripted
            | Self::Sqlite { .. }
            | Self::ForeignOwner
            | Self::UnexpectedKind
            | Self::ExclusionNotVerified => None,
        }
    }

    /// The SQLite result code for a [`PlatformError::Sqlite`] failure, otherwise `None`.
    #[must_use]
    pub fn sqlite_code(&self) -> Option<SqliteCode> {
        match self {
            Self::Sqlite { code, .. } => Some(*code),
            Self::Os { .. }
            | Self::InvalidPath
            | Self::NotCanonical(_)
            | Self::TooLarge { .. }
            | Self::UnknownProcessGroup
            | Self::ClockOutOfRange
            | Self::NotScripted
            | Self::ForeignOwner
            | Self::UnexpectedKind
            | Self::ExclusionNotVerified => None,
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
            Self::Sqlite { operation, code } => write!(f, "{} failed: {code}", operation.as_str()),
            Self::ForeignOwner => f.write_str("engine path is owned by another user"),
            Self::UnexpectedKind => f.write_str("engine path is not the expected kind of entry"),
            Self::ExclusionNotVerified => f.write_str("backup or indexing exclusion did not read back as written"),
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
            | Self::NotScripted
            | Self::Sqlite { .. }
            | Self::ForeignOwner
            | Self::UnexpectedKind
            | Self::ExclusionNotVerified => None,
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
    fn sqlite_error_shows_code_name_without_message_text() {
        let error = PlatformError::Sqlite {
            operation: Operation::Step,
            code: SqliteCode::CONSTRAINT_UNIQUE,
        };
        assert_eq!(
            error.to_string(),
            "step statement failed: SQLITE_CONSTRAINT (code 2067)"
        );
        assert_eq!(error.sqlite_code(), Some(SqliteCode::CONSTRAINT_UNIQUE));
        assert_eq!(error.errno(), None);
        assert!(SqliteCode::CONSTRAINT_UNIQUE.is_constraint());
        assert_eq!(SqliteCode::CONSTRAINT_UNIQUE.primary(), SqliteCode::CONSTRAINT);
        assert_eq!(SqliteCode::from_raw(517).primary_name(), "SQLITE_BUSY");
        assert!(SqliteCode::from_raw(517).is_busy());
    }

    #[test]
    fn io_error_without_errno_maps_to_eio() {
        let error = PlatformError::from_io(Operation::Write, &io::Error::from(io::ErrorKind::WriteZero));
        assert_eq!(error.errno(), Some(libc::EIO));
    }
}
