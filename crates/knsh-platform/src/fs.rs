//! Filesystem access.
//!
//! Engine files are owner-only (files `0600`, directories `0700`) and every persistent file is written by
//! [`Fs::atomic_replace`], so a crash or error leaves either the old or the new contents, never a mix (CLAUDE.md
//! "Persistence"). Policy matches only canonical paths (FR-POL-11), which [`Fs::canonicalise`] produces.

use std::ffi::OsString;
use std::io::Read;
use std::path::Path;

use knsh_core::CanonicalPath;

use crate::error::PlatformError;

/// What a path names, without following a final symlink.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FileKind {
    /// A regular file.
    File,
    /// A directory.
    Directory,
    /// A symbolic link (the link itself, not its target).
    Symlink,
    /// A socket, FIFO, device or anything else.
    Other,
}

/// Metadata of one path, read without following a final symlink (`lstat`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Metadata {
    /// What the path names.
    pub kind: FileKind,
    /// Size in bytes (for a symlink, the length of its target text).
    pub len: u64,
    /// Permission bits (`0o7777` mask), for example `0o600`.
    pub mode: u32,
    /// User id of the owner. Engine paths owned by anyone but the engine's user are refused (KNSH-011).
    pub uid: u32,
}

/// Filesystem operations. Object safe: hold it as `Arc<dyn Fs>`.
///
/// All paths must be absolute; a relative path is refused with [`PlatformError::InvalidPath`] rather than resolved
/// against a working directory the engine does not control.
pub trait Fs: Send + Sync {
    /// Opens an existing regular file for streaming reads.
    ///
    /// # Errors
    ///
    /// [`PlatformError::InvalidPath`] for a relative path; [`PlatformError::Os`] with
    /// [`Operation::Open`](crate::Operation::Open) if the file cannot be opened.
    fn open_read(&self, path: &Path) -> Result<Box<dyn Read + Send>, PlatformError>;

    /// Reads a whole file, refusing it before allocating if it is larger than `limit` bytes (untrusted-input rule).
    ///
    /// # Errors
    ///
    /// [`PlatformError::InvalidPath`]; [`PlatformError::TooLarge`] if the file exceeds `limit`, including a file
    /// that grows past it while being read; [`PlatformError::Os`] with `Open`, `Metadata` or `Read`.
    fn read(&self, path: &Path, limit: u64) -> Result<Vec<u8>, PlatformError>;

    /// Creates or truncates a file and writes `data`, without fsync. A new file gets `mode` (further restricted by
    /// the umask); an existing file keeps its mode. A final symlink is not followed: the call fails with `ELOOP`.
    ///
    /// Not crash-safe: use [`Fs::atomic_replace`] for anything that must survive a crash.
    ///
    /// # Errors
    ///
    /// [`PlatformError::InvalidPath`]; [`PlatformError::Os`] with [`Operation::Write`](crate::Operation::Write).
    fn write(&self, path: &Path, data: &[u8], mode: u32) -> Result<(), PlatformError>;

    /// Creates a new, empty regular file with permission bits exactly `mode` (not reduced by the umask). Fails if
    /// anything already exists at `path`, including a symlink, so it never truncates or follows an existing entry
    /// (`O_CREAT | O_EXCL`). Used to create owner-only files that another component then opens, such as the
    /// record database (KNSH-010).
    ///
    /// # Errors
    ///
    /// [`PlatformError::InvalidPath`]; [`PlatformError::Os`] with [`Operation::Write`](crate::Operation::Write),
    /// including `EEXIST` if anything already exists at `path`.
    fn create_new(&self, path: &Path, mode: u32) -> Result<(), PlatformError>;

    /// Replaces the file at `path` with `data` and permission bits exactly `mode`, atomically and durably.
    ///
    /// Steps: create a new temporary file in the same directory (so the rename stays on one volume), write it,
    /// flush it to stable storage, rename it over `path`, then flush the directory so the rename itself survives a
    /// crash. If `path` is a symlink, the link is replaced, not its target.
    ///
    /// # Errors
    ///
    /// [`PlatformError::InvalidPath`] for a relative path or one without a parent or file name;
    /// [`PlatformError::Os`] naming the failed step (`Write`, `SyncFile`, `Rename` or `SyncDirectory`).
    ///
    /// On any error up to and including `Rename`, the previous file is untouched and the temporary file is
    /// removed. A `SyncDirectory` error comes after the rename: `path` already holds the new contents, but their
    /// durability across a crash is not confirmed, so callers must treat the write as failed.
    fn atomic_replace(&self, path: &Path, data: &[u8], mode: u32) -> Result<(), PlatformError>;

    /// Creates one directory (not its parents) with `mode`, further restricted by the umask.
    ///
    /// # Errors
    ///
    /// [`PlatformError::InvalidPath`]; [`PlatformError::Os`] with
    /// [`Operation::CreateDirectory`](crate::Operation::CreateDirectory), including `EEXIST` if anything already
    /// exists at `path`.
    fn create_dir(&self, path: &Path, mode: u32) -> Result<(), PlatformError>;

    /// Reads metadata of `path` itself, without following a final symlink.
    ///
    /// # Errors
    ///
    /// [`PlatformError::InvalidPath`]; [`PlatformError::Os`] with [`Operation::Metadata`](crate::Operation::Metadata)
    /// (`ENOENT` if nothing exists there).
    fn metadata(&self, path: &Path) -> Result<Metadata, PlatformError>;

    /// Resolves an existing path to canonical form: absolute, every symlink followed, no `.` or `..`
    /// (for example `/var/folders/x` becomes `/private/var/folders/x` on macOS). FR-POL-11.
    ///
    /// # Errors
    ///
    /// [`PlatformError::InvalidPath`]; [`PlatformError::Os`] with
    /// [`Operation::Canonicalise`](crate::Operation::Canonicalise) if a component does not exist or a symlink loop
    /// is found (`ELOOP`); [`PlatformError::NotCanonical`] if the system returned a path that breaks the
    /// [`CanonicalPath`] invariants.
    fn canonicalise(&self, path: &Path) -> Result<CanonicalPath, PlatformError>;

    /// Sets the permission bits of `path` to exactly `mode` (not reduced by the umask), without following a final
    /// symlink: if `path` is a symlink, the link itself is changed, never its target. Used to tighten engine paths
    /// to owner-only (KNSH-011, NFR-SEC-08).
    ///
    /// # Errors
    ///
    /// [`PlatformError::InvalidPath`]; [`PlatformError::Os`] with [`Operation::SetMode`](crate::Operation::SetMode)
    /// (`ENOENT` if nothing exists there, `EPERM` if the caller does not own it).
    fn set_mode(&self, path: &Path, mode: u32) -> Result<(), PlatformError>;

    /// Reads the extended attribute `name` of `path` itself, without following a final symlink. Returns `None` if
    /// the attribute is not set. Values longer than `limit` bytes are refused before allocating more than `limit`.
    ///
    /// # Errors
    ///
    /// [`PlatformError::InvalidPath`] for a relative path or a path or name containing a NUL byte;
    /// [`PlatformError::TooLarge`] if the value is longer than `limit`; [`PlatformError::Os`] with
    /// [`Operation::ReadAttribute`](crate::Operation::ReadAttribute).
    fn xattr(&self, path: &Path, name: &str, limit: usize) -> Result<Option<Vec<u8>>, PlatformError>;

    /// Creates or replaces the extended attribute `name` of `path` itself with `value`, without following a final
    /// symlink. Used for the Time Machine exclusion of engine directories (KNSH-011, NFR-PRIV-04).
    ///
    /// # Errors
    ///
    /// [`PlatformError::InvalidPath`] for a relative path or a path or name containing a NUL byte;
    /// [`PlatformError::Os`] with [`Operation::WriteAttribute`](crate::Operation::WriteAttribute) (`ENOTSUP` if the
    /// filesystem has no extended attributes).
    fn set_xattr(&self, path: &Path, name: &str, value: &[u8]) -> Result<(), PlatformError>;

    /// Removes the directory entry at `path` (`unlink`): a file, or a symlink itself, never its target. Used to remove
    /// the launch agent property list on uninstall (KNSH-012).
    ///
    /// # Errors
    ///
    /// [`PlatformError::InvalidPath`]; [`PlatformError::Os`] with [`Operation::RemoveFile`](crate::Operation::RemoveFile)
    /// (`ENOENT` if nothing exists there, `EPERM` for a directory).
    fn remove_file(&self, path: &Path) -> Result<(), PlatformError>;

    /// Removes the empty directory at `path` (`rmdir`). A final symlink is never followed: a symlink at `path` is
    /// refused, not its target removed. Used to keep checkpoint shadows in step with the live tree (KNSH-080).
    ///
    /// # Errors
    ///
    /// [`PlatformError::InvalidPath`]; [`PlatformError::Os`] with
    /// [`Operation::RemoveDirectory`](crate::Operation::RemoveDirectory) (`ENOENT` if nothing exists there,
    /// `ENOTDIR` for anything but a directory, `ENOTEMPTY` if it has entries).
    fn remove_dir(&self, path: &Path) -> Result<(), PlatformError>;

    /// Renames the entry at `from` to `to` in one step, and only if nothing exists at `to`: it never replaces an
    /// existing entry, a symlink included (`renamex_np` with `RENAME_EXCL` on macOS). Neither final component is
    /// followed: a symlink at `from` is moved itself, never its target. Both paths must be on one volume. Used to set
    /// an unreadable state file aside without overwriting it (KNSH-074).
    ///
    /// # Errors
    ///
    /// [`PlatformError::InvalidPath`]; [`PlatformError::Os`] with [`Operation::Rename`](crate::Operation::Rename)
    /// (`EEXIST` if anything exists at `to`, `ENOENT` if nothing exists at `from`). On error nothing has moved.
    fn rename_new(&self, from: &Path, to: &Path) -> Result<(), PlatformError>;

    /// The names of the entries of the directory `path` (not `.` or `..`), sorted bytewise, so callers see the same
    /// order on every backend. A final symlink is followed, as `opendir` does: callers that must not follow one
    /// check [`Fs::metadata`] first. At most `limit` names are returned; a larger directory is refused rather than
    /// read in part (untrusted-input rule). Used to sweep compiled profiles no line uses (KNSH-045).
    ///
    /// # Errors
    ///
    /// [`PlatformError::InvalidPath`]; [`PlatformError::TooLarge`] if the directory holds more than `limit`
    /// entries; [`PlatformError::Os`] with [`Operation::ReadDirectory`](crate::Operation::ReadDirectory)
    /// (`ENOENT`, `ENOTDIR`).
    fn list_dir(&self, path: &Path, limit: usize) -> Result<Vec<OsString>, PlatformError>;
}

/// Refuses relative paths, which every [`Fs`] method rejects.
pub(crate) fn require_absolute(path: &Path) -> Result<(), PlatformError> {
    if path.is_absolute() {
        Ok(())
    } else {
        Err(PlatformError::InvalidPath)
    }
}

/// Splits an atomic-replace target into its parent directory and file name.
///
/// The raw spelling is checked first because `Path::file_name` silently skips a trailing `/` or `/.`, which would
/// make `/a/b/.` replace `/a/b`.
pub(crate) fn split_target(path: &Path) -> Result<(&Path, &std::ffi::OsStr), PlatformError> {
    require_absolute(path)?;
    let raw = path.as_os_str().as_encoded_bytes();
    if raw.ends_with(b"/") || raw.ends_with(b"/.") || raw.ends_with(b"/..") {
        return Err(PlatformError::InvalidPath);
    }
    match (path.parent(), path.file_name()) {
        (Some(parent), Some(name)) => Ok((parent, name)),
        _ => Err(PlatformError::InvalidPath),
    }
}
