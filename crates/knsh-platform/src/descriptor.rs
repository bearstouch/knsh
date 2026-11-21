//! The descriptors a shell opens for its redirections (KNSH-099).
//!
//! The native interpreter (`knsh-interp`) keeps the shell's descriptor table itself: which number holds which open
//! file, what a command inherits, what is restored after it. The files behind it are opened here, through
//! [`Descriptors`], so the interpreter never touches the system and its tests run against a fake. Every descriptor
//! returned is close-on-exec in this process: a command receives one only when the interpreter places it in the
//! command's table ([`CommandRequest::descriptors`](crate::CommandRequest::descriptors)), never by accident.
//!
//! The interpreter runs in a process that holds descriptors of its own (the connection to the supervisor, the
//! engine's files). On macOS, opening `/dev/fd/N` duplicates *this process's* descriptor `N`, so the real backend
//! refuses any path that reaches `/dev/fd` (directly, through `..`, or through a symlink such as `/dev/stdin`):
//! bash's `/dev/fd/N` and `/dev/std*` names are the shell's own table, which the interpreter resolves itself.

use std::path::Path;

use crate::error::PlatformError;
use crate::process::SharedFd;

/// How a redirection opens its file, by operator (bash's `redir_open` flags).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OpenMode {
    /// `<`: read only. The file must exist.
    Read,
    /// `>` without `noclobber`, and `>|`: write only, created (mode `0666` less the umask) or truncated.
    Truncate,
    /// `>` with `noclobber` (`set -C`): as bash's `noclobber_open`, an existing regular file is refused with
    /// `EEXIST`; a missing file is created exclusively (`O_EXCL`, so a file created meanwhile is refused too); an
    /// existing file that is not regular (`/dev/null`, a FIFO) is opened for writing without truncation.
    NoClobber,
    /// `>>`: write only, created or appended to.
    Append,
    /// `<>`: read and write, created if missing, never truncated.
    ReadWrite,
}

/// Opens the files behind a shell's redirections and writes the shell's own messages. Object safe: hold it as
/// `Arc<dyn Descriptors>`.
pub trait Descriptors: Send + Sync {
    /// Opens `path` (absolute) as `mode`, following symlinks as bash does. The descriptor is close-on-exec.
    ///
    /// # Errors
    ///
    /// [`PlatformError::InvalidPath`] for a relative path or one holding a NUL byte; [`PlatformError::Os`] with
    /// [`Operation::Open`](crate::Operation::Open) and the system's `errno` (`ENOENT`, `EACCES`, `EISDIR`, `EEXIST`
    /// for [`OpenMode::NoClobber`]), or `EPERM` for a path that reaches this process's own descriptors
    /// (`/dev/fd`).
    fn open(&self, path: &Path, mode: OpenMode) -> Result<SharedFd, PlatformError>;

    /// A read-only descriptor positioned at the start of exactly `text`, for a here-string (`<<<`): a pipe already
    /// holding it when it fits, otherwise an unlinked temporary file. Close-on-exec.
    ///
    /// # Errors
    ///
    /// [`PlatformError::Os`] if no pipe or temporary file could be made or written.
    fn here_string(&self, text: &[u8]) -> Result<SharedFd, PlatformError>;

    /// A new pipe, `(read end, write end)`, both close-on-exec: the connection between two commands of a pipeline
    /// (KNSH-100).
    ///
    /// # Errors
    ///
    /// [`PlatformError::Os`] with [`Operation::Pipe`](crate::Operation::Pipe) (`EMFILE`, `ENFILE`).
    fn pipe(&self) -> Result<(SharedFd, SharedFd), PlatformError>;

    /// Writes all of `bytes` to `fd`: the shell's own messages when its standard error is redirected
    /// (`let 1/0 2>err`).
    ///
    /// # Errors
    ///
    /// [`PlatformError::Os`] with [`Operation::Write`](crate::Operation::Write) (`EBADF` for a descriptor opened
    /// read-only, `EPIPE` for a pipe nobody reads).
    fn write_all(&self, fd: &SharedFd, bytes: &[u8]) -> Result<(), PlatformError>;
}

/// Whether `path` (absolute, read component by component without following symlinks) names `/dev/fd` or anything
/// below it: the descriptor table of the process that opens it.
#[must_use]
pub fn reaches_descriptor_table(path: &Path) -> bool {
    use std::path::Component;

    let mut parts: Vec<&std::ffi::OsStr> = Vec::new();
    for component in path.components() {
        match component {
            Component::RootDir | Component::Prefix(_) | Component::CurDir => {}
            Component::ParentDir => {
                parts.pop();
            }
            Component::Normal(part) => parts.push(part),
        }
    }
    matches!(parts.as_slice(), [dev, fd, ..] if *dev == "dev" && *fd == "fd")
}

#[cfg(test)]
mod tests {
    use super::*;

    // KNSH-099: every spelling of `/dev/fd` is caught before any symlink is looked at.
    #[test]
    fn descriptor_table_paths_are_recognised_in_every_spelling() {
        for path in [
            "/dev/fd",
            "/dev/fd/3",
            "/dev//fd/0",
            "/dev/./fd/1",
            "/tmp/../dev/fd/2",
            "/dev/fd/3/..",
        ] {
            assert!(reaches_descriptor_table(Path::new(path)), "{path}");
        }
        for path in ["/dev/null", "/dev/fdx", "/tmp/dev/fd/1", "/dev/fd/../null", "/"] {
            assert!(!reaches_descriptor_table(Path::new(path)), "{path}");
        }
    }
}
