//! The crate's single error type.
//!
//! Like [`PlatformError`], messages never echo a path or file contents (NFR-PRIV-02); conflicting paths are carried as
//! data ([`CheckpointError::Conflicts`]) for the caller to send where the caller may see them.

use std::fmt;

use knsh_core::{HistoryError, RestoreConflict, StateId};
use knsh_platform::PlatformError;

/// Every way a checkpoint operation can fail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckpointError {
    /// A platform call failed.
    Platform(PlatformError),
    /// A file kept changing while its post-image identity was read: its identity before and after hashing differed
    /// on every attempt, so no identity could be recorded that matches its contents (FR-CKP-09).
    IdentityUnstable,
    /// A thread could not be started (the file-event watcher's worker, KNSH-080).
    Threads,
    /// The history tree refused the undo or redo (KNSH-083): unknown change, not in effect, nothing to redo, redo
    /// blocked by a newer branch, or an older change overlapped by later ones (FR-CKP-30).
    History(HistoryError),
    /// Undo or redo would overwrite work the engine did not record, or cannot restore some path: `-32004` with these
    /// paths and reasons (FR-CKP-20). Nothing was changed.
    Conflicts(Vec<RestoreConflict>),
    /// `force` was asked by a caller that is neither the user nor the authority (FR-CKP-21).
    ForceNotAllowed,
    /// An agent asked to undo or redo a change that is not its own session's, or one no agent may undo (external
    /// edits). Answered as unknown on `agent.sock` (`-32003`, KNSH-088).
    NotOwnChange,
    /// `checkpoint.restore` was asked by a caller that is neither the user nor the authority (KNSH-086).
    RestoreNotAllowed,
    /// Returning to a state failed part-way, and undoing the steps already taken failed too (KNSH-086): the history
    /// is at this state, which the files match (each step is restored whole or not at all), except where a step's
    /// own rollback failed: its journal then puts its paths back at the next start ([`crate::recover_restores`]).
    RestoreStopped(StateId),
    /// The checkpoint has paths in a root whose store it does not know, so the current versions cannot be saved.
    NoStore,
    /// The restore journal could not be read: it is not in the form the engine writes, or is from a newer version. It
    /// is left as found.
    Journal,
    /// Restoring failed part-way; every file was put back to the version it had before (KNSH-084: never mixed).
    RolledBack(PlatformError),
    /// Restoring failed part-way and putting files back failed too: the journal is kept, so the next recovery
    /// ([`crate::recover_restores`]) finishes putting them back.
    RollbackFailed(PlatformError),
}

impl fmt::Display for CheckpointError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Platform(error) => write!(f, "platform call failed: {error}"),
            Self::IdentityUnstable => f.write_str("file kept changing while its identity was read"),
            Self::Threads => f.write_str("a thread could not be started"),
            Self::History(error) => write!(f, "history refused the operation: {error}"),
            Self::Conflicts(conflicts) => write!(f, "{} paths conflict; nothing was restored", conflicts.len()),
            Self::ForceNotAllowed => f.write_str("force is only for the user and the authority"),
            Self::NotOwnChange => f.write_str("the change does not belong to the caller's session"),
            Self::RestoreNotAllowed => f.write_str("restoring a state is only for the user and the authority"),
            Self::RestoreStopped(state) => write!(f, "restoring a state stopped part-way, at state {state}"),
            Self::NoStore => f.write_str("a checkpoint root has no known store"),
            Self::Journal => f.write_str("the restore journal is not in the engine's format"),
            Self::RolledBack(error) => write!(f, "restore failed and every file was put back: {error}"),
            Self::RollbackFailed(error) => {
                write!(
                    f,
                    "restore failed and putting files back failed; recovery will retry: {error}"
                )
            }
        }
    }
}

impl std::error::Error for CheckpointError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Platform(error) | Self::RolledBack(error) | Self::RollbackFailed(error) => Some(error),
            Self::History(error) => Some(error),
            Self::IdentityUnstable
            | Self::Threads
            | Self::Conflicts(_)
            | Self::ForceNotAllowed
            | Self::NotOwnChange
            | Self::RestoreNotAllowed
            | Self::RestoreStopped(_)
            | Self::NoStore
            | Self::Journal => None,
        }
    }
}

impl From<PlatformError> for CheckpointError {
    fn from(error: PlatformError) -> Self {
        Self::Platform(error)
    }
}

impl From<HistoryError> for CheckpointError {
    fn from(error: HistoryError) -> Self {
        Self::History(error)
    }
}
