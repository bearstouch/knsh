//! Which processes hold files for writing (KNSH-085, FR-CKP-24, decision 17).
//!
//! A store through a live shared mapping moves neither a file's size nor its modification time, and file events
//! report nothing while the writer lives (KNSH-077, claim C3), so a change made that way cannot be found after the
//! fact. It is found by **observation at line end** instead: the supervisor lists the processes that could still be
//! writing (the line's process group and the processes of its envelope) and asks each which files it holds open for
//! writing or has mapped writable. Those files, inside a checkpoint root, are *possibly torn*.
//!
//! The trait only reports; deciding which processes to ask, and what a held file means, is `knsh-checkpoint`'s.

use std::path::PathBuf;

use crate::ancestry::ProcessKey;
use crate::error::PlatformError;

/// The most processes [`WriteHolders::processes`] returns: far above a Mac's process table (about a thousand).
pub const MAX_PROCESSES: usize = 16_384;

/// The most files [`WriteHolders::held_for_writing`] returns for one process; more are an error, never a silent
/// cut (a file left off the list would read as not held).
pub const MAX_HELD_FILES: usize = 4096;

/// One live process, as the process table lists it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcessEntry {
    /// The process, by pid and unique id (never a bare pid that may be reused).
    pub key: ProcessKey,
    /// Its parent's unique id; 0 for `launchd`'s parent (the kernel).
    pub parent_unique_id: u64,
    /// Its process group.
    pub group: i32,
}

/// How a process holds a file for writing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum HoldKind {
    /// A descriptor open for writing.
    OpenForWriting,
    /// A shared mapping that is writable: stores go to the file.
    MappedWritable,
}

/// A file a process holds for writing.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HeldFile {
    /// The file's path as the kernel names it (absolute; may differ from a canonical path only where a symlink
    /// leads to it).
    pub path: PathBuf,
    /// How it is held.
    pub how: HoldKind,
}

/// Lists processes and the files they hold for writing. Object safe: hold it as `Arc<dyn WriteHolders>`.
pub trait WriteHolders: Send + Sync {
    /// Every live process this user may read, at most [`MAX_PROCESSES`].
    ///
    /// A process that exits while the table is read is left out, never reported with a guessed group or parent.
    ///
    /// # Errors
    ///
    /// [`PlatformError::Os`] with [`Operation::ProcessInfo`](crate::Operation::ProcessInfo) if the table cannot be
    /// read, or holds more than [`MAX_PROCESSES`] processes (`EOVERFLOW`).
    fn processes(&self) -> Result<Vec<ProcessEntry>, PlatformError>;

    /// The files `process` holds open for writing or has mapped writable, at most [`MAX_HELD_FILES`], each once per
    /// [`HoldKind`]. Descriptors and mappings that are not files (sockets, pipes, anonymous memory) are left out.
    ///
    /// # Errors
    ///
    /// [`PlatformError::Os`] with [`Operation::ProcessInfo`](crate::Operation::ProcessInfo): `ESRCH` if `process`
    /// has exited (or its pid now names another process), `EPERM` if it may not be read, `EOVERFLOW` if it holds
    /// more than [`MAX_HELD_FILES`] files.
    fn held_for_writing(&self, process: ProcessKey) -> Result<Vec<HeldFile>, PlatformError>;
}
