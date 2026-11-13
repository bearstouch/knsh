//! The real filesystem, through the standard library's safe wrappers over the POSIX calls.

use std::ffi::CString;
use std::fs::{self, DirBuilder, File, OpenOptions, Permissions};
use std::io::{self, Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use knsh_core::CanonicalPath;

use crate::error::{Operation, PlatformError};
use crate::fs::{FileKind, Fs, Metadata, require_absolute, split_target};

/// How many temporary names [`RealFs::atomic_replace`] tries before giving up. A collision needs a stale temporary
/// file from an earlier process with the same pid, so more than one retry is already rare.
const TEMP_ATTEMPTS: u32 = 16;

/// Distinguishes temporary files created by concurrent replaces within one process.
static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// The real filesystem.
///
/// File contents are flushed with `F_FULLFSYNC` (the standard library's `sync_all` on Apple platforms), because a
/// plain `fsync` on macOS only reaches the drive's cache, not stable storage.
#[derive(Debug, Clone, Copy, Default)]
pub struct RealFs;

impl RealFs {
    /// The real filesystem.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

/// Maps a standard I/O error to the crate error for `operation`.
fn os(operation: Operation) -> impl Fn(io::Error) -> PlatformError {
    move |error| PlatformError::from_io(operation, &error)
}

/// Creates a fresh temporary file next to the target. `create_new` (`O_EXCL`) guarantees it is a new file this
/// call owns, not a symlink or file planted by someone else.
fn create_temp(dir: &Path, mode: u32) -> Result<(File, PathBuf), PlatformError> {
    let pid = std::process::id();
    for _ in 0..TEMP_ATTEMPTS {
        let n = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let temp = dir.join(format!(".knsh.{pid}.{n}.tmp"));
        match OpenOptions::new().write(true).create_new(true).mode(mode).open(&temp) {
            Ok(file) => return Ok((file, temp)),
            // A stale temporary file holds this name: try the next one.
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(PlatformError::from_io(Operation::Write, &error)),
        }
    }
    Err(PlatformError::Os {
        operation: Operation::Write,
        errno: libc::EEXIST,
    })
}

/// Writes, sets the exact mode and flushes the temporary file. Separate from the rename so the caller can remove the
/// temporary file on any failure here.
fn fill_temp(file: &mut File, data: &[u8], mode: u32) -> Result<(), PlatformError> {
    // `open` applied the umask; `fchmod` sets the exact bits the caller asked for.
    file.set_permissions(Permissions::from_mode(mode))
        .map_err(os(Operation::Write))?;
    file.write_all(data).map_err(os(Operation::Write))?;
    file.sync_all().map_err(os(Operation::SyncFile))
}

/// The `errno` of the last failed system call, as the crate error for `operation`.
fn last_os_error(operation: Operation) -> PlatformError {
    PlatformError::from_io(operation, &io::Error::last_os_error())
}

/// An absolute path as a C string for the `libc` calls the standard library does not wrap. A path with an inner NUL
/// byte cannot be passed to the system and is refused.
fn c_path(path: &Path) -> Result<CString, PlatformError> {
    require_absolute(path)?;
    CString::new(path.as_os_str().as_bytes()).map_err(|_| PlatformError::InvalidPath)
}

/// An extended attribute name as a C string; an inner NUL byte is refused like one in a path.
fn c_name(name: &str) -> Result<CString, PlatformError> {
    CString::new(name).map_err(|_| PlatformError::InvalidPath)
}

impl Fs for RealFs {
    fn open_read(&self, path: &Path) -> Result<Box<dyn Read + Send>, PlatformError> {
        require_absolute(path)?;
        let file = File::open(path).map_err(os(Operation::Open))?;
        Ok(Box::new(file))
    }

    fn read(&self, path: &Path, limit: u64) -> Result<Vec<u8>, PlatformError> {
        require_absolute(path)?;
        let file = File::open(path).map_err(os(Operation::Open))?;
        let len = file.metadata().map_err(os(Operation::Metadata))?.len();
        if len > limit {
            return Err(PlatformError::TooLarge { limit });
        }
        // The size can change between `fstat` and the read, so the read itself is capped one byte past the limit:
        // reading that extra byte proves the file grew too large.
        let mut data = Vec::with_capacity(usize::try_from(len).unwrap_or(0));
        file.take(limit.saturating_add(1))
            .read_to_end(&mut data)
            .map_err(os(Operation::Read))?;
        if data.len() as u64 > limit {
            return Err(PlatformError::TooLarge { limit });
        }
        Ok(data)
    }

    fn write(&self, path: &Path, data: &[u8], mode: u32) -> Result<(), PlatformError> {
        require_absolute(path)?;
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(mode)
            // A symlink planted at an engine path must not redirect the write elsewhere.
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
            .map_err(os(Operation::Write))?;
        file.write_all(data).map_err(os(Operation::Write))
    }

    fn create_new(&self, path: &Path, mode: u32) -> Result<(), PlatformError> {
        require_absolute(path)?;
        // `create_new` is `O_CREAT | O_EXCL`: an existing file or a planted symlink fails with `EEXIST`.
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(path)
            .map_err(os(Operation::Write))?;
        // `open` applied the umask; `fchmod` sets the exact bits the caller asked for.
        file.set_permissions(Permissions::from_mode(mode))
            .map_err(os(Operation::Write))
    }

    fn atomic_replace(&self, path: &Path, data: &[u8], mode: u32) -> Result<(), PlatformError> {
        let (dir, _) = split_target(path)?;
        let (mut file, temp) = create_temp(dir, mode)?;
        let filled = fill_temp(&mut file, data, mode);
        drop(file);
        // Until the rename succeeds the target is untouched; on failure only the temporary file needs cleaning up.
        // A failed cleanup leaves a stray `.knsh.*.tmp` file but never touches the target, so it is ignored.
        if let Err(error) = filled.and_then(|()| fs::rename(&temp, path).map_err(os(Operation::Rename))) {
            let _ = fs::remove_file(&temp);
            return Err(error);
        }
        // Flush the directory so the new entry survives a crash. Past this point the target already holds the new
        // contents, so a failure is reported but cannot be rolled back (see the trait docs).
        File::open(dir)
            .and_then(|d| d.sync_all())
            .map_err(os(Operation::SyncDirectory))
    }

    fn create_dir(&self, path: &Path, mode: u32) -> Result<(), PlatformError> {
        require_absolute(path)?;
        DirBuilder::new()
            .mode(mode)
            .create(path)
            .map_err(os(Operation::CreateDirectory))
    }

    fn metadata(&self, path: &Path) -> Result<Metadata, PlatformError> {
        require_absolute(path)?;
        let meta = fs::symlink_metadata(path).map_err(os(Operation::Metadata))?;
        let file_type = meta.file_type();
        let kind = if file_type.is_symlink() {
            FileKind::Symlink
        } else if file_type.is_dir() {
            FileKind::Directory
        } else if file_type.is_file() {
            FileKind::File
        } else {
            // Sockets, FIFOs and devices are all "other" to the engine.
            debug_assert!(
                file_type.is_socket()
                    || file_type.is_fifo()
                    || file_type.is_block_device()
                    || file_type.is_char_device()
            );
            FileKind::Other
        };
        Ok(Metadata {
            kind,
            len: meta.len(),
            mode: meta.permissions().mode() & 0o7777,
            uid: meta.uid(),
        })
    }

    fn canonicalise(&self, path: &Path) -> Result<CanonicalPath, PlatformError> {
        require_absolute(path)?;
        // `fs::canonicalize` is `realpath(3)`: it follows every symlink, including `/var` -> `/private/var`.
        let resolved = fs::canonicalize(path).map_err(os(Operation::Canonicalise))?;
        Ok(CanonicalPath::new(resolved)?)
    }

    fn set_mode(&self, path: &Path, mode: u32) -> Result<(), PlatformError> {
        let c_path = c_path(path)?;
        // `mode_t` is 16 bits on macOS; the permission mask always fits.
        let mode = libc::mode_t::try_from(mode & 0o7777).map_err(|_| PlatformError::Os {
            operation: Operation::SetMode,
            errno: libc::EINVAL,
        })?;
        // `std::fs::set_permissions` follows a final symlink; `AT_SYMLINK_NOFOLLOW` makes a symlink swapped in at an
        // engine path change only the link, never whatever it points to.
        // SAFETY: `c_path` is a valid NUL-terminated string that outlives the call; `AT_FDCWD` is ignored because
        // the path is absolute. The call reads nothing else from our memory.
        let rc = unsafe { libc::fchmodat(libc::AT_FDCWD, c_path.as_ptr(), mode, libc::AT_SYMLINK_NOFOLLOW) };
        if rc == 0 {
            Ok(())
        } else {
            Err(last_os_error(Operation::SetMode))
        }
    }

    fn remove_file(&self, path: &Path) -> Result<(), PlatformError> {
        require_absolute(path)?;
        // `unlink(2)`: removes a final symlink itself, and refuses a directory.
        fs::remove_file(path).map_err(os(Operation::RemoveFile))
    }

    fn xattr(&self, path: &Path, name: &str, limit: usize) -> Result<Option<Vec<u8>>, PlatformError> {
        let c_path = c_path(path)?;
        let c_name = c_name(name)?;
        // A buffer of exactly `limit` bytes: a longer value fails with `ERANGE` instead of growing the allocation.
        let mut buf = vec![0u8; limit];
        // SAFETY: both strings are valid and NUL-terminated; `buf` is a writable region of exactly `buf.len()` bytes
        // that outlives the call, and `getxattr` writes at most that many bytes into it. Position 0 is required for
        // every attribute but resource forks.
        let read = unsafe {
            libc::getxattr(
                c_path.as_ptr(),
                c_name.as_ptr(),
                buf.as_mut_ptr().cast(),
                buf.len(),
                0,
                libc::XATTR_NOFOLLOW,
            )
        };
        // A negative result is a failure; otherwise it is the number of bytes written, at most `buf.len()`.
        let Ok(len) = usize::try_from(read) else {
            let error = io::Error::last_os_error();
            return match error.raw_os_error() {
                Some(libc::ENOATTR) => Ok(None),
                Some(libc::ERANGE) => Err(PlatformError::TooLarge { limit: limit as u64 }),
                _ => Err(PlatformError::from_io(Operation::ReadAttribute, &error)),
            };
        };
        // With an empty buffer `getxattr` reports the value's size instead of failing with `ERANGE`, so a length
        // past the buffer is a value too large for `limit`, never bytes that were read.
        if len > buf.len() {
            return Err(PlatformError::TooLarge { limit: limit as u64 });
        }
        buf.truncate(len);
        Ok(Some(buf))
    }

    fn set_xattr(&self, path: &Path, name: &str, value: &[u8]) -> Result<(), PlatformError> {
        let c_path = c_path(path)?;
        let c_name = c_name(name)?;
        // SAFETY: both strings are valid and NUL-terminated; `value` is a readable region of exactly `value.len()`
        // bytes that outlives the call. Options 0 | `XATTR_NOFOLLOW` create or replace the attribute on the path
        // itself, never on a symlink's target.
        let rc = unsafe {
            libc::setxattr(
                c_path.as_ptr(),
                c_name.as_ptr(),
                value.as_ptr().cast(),
                value.len(),
                0,
                libc::XATTR_NOFOLLOW,
            )
        };
        if rc == 0 {
            Ok(())
        } else {
            Err(last_os_error(Operation::WriteAttribute))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::symlink;

    use super::*;

    /// A fresh directory under the system temp dir, removed on drop. Tests never touch the user's real state.
    struct TempDir(PathBuf);

    impl TempDir {
        fn new(tag: &str) -> Self {
            let n = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!("knsh-platform-{tag}-{}-{n}", std::process::id()));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    // FR-POL-11: policy sees only resolved paths; `/var` is a symlink to `/private/var` on macOS.
    #[test]
    fn canonicalise_follows_symlinks() {
        let fs = RealFs::new();
        let tmp = TempDir::new("canon");
        let real = tmp.0.join("real");
        fs::create_dir(&real).unwrap();
        fs::write(real.join("f"), b"x").unwrap();
        symlink(&real, tmp.0.join("link")).unwrap();

        let via_link = fs.canonicalise(&tmp.0.join("link/./f")).unwrap();
        let direct = fs.canonicalise(&real.join("f")).unwrap();
        assert_eq!(via_link, direct);
        assert!(!via_link.as_path().starts_with(tmp.0.join("link")));

        let var = fs.canonicalise(Path::new("/var")).unwrap();
        assert_eq!(var.as_path(), Path::new("/private/var"));

        assert!(fs.canonicalise(&tmp.0.join("missing")).unwrap_err().is_not_found());
        assert_eq!(fs.canonicalise(Path::new("relative")), Err(PlatformError::InvalidPath));
    }

    #[test]
    fn atomic_replace_writes_exact_mode_and_leaves_no_temp_file() {
        let fs = RealFs::new();
        let tmp = TempDir::new("replace");
        let target = tmp.0.join("state.json");
        fs.atomic_replace(&target, b"one", 0o600).unwrap();
        fs.atomic_replace(&target, b"two", 0o640).unwrap();
        assert_eq!(fs.read(&target, 16).unwrap(), b"two");
        assert_eq!(fs.metadata(&target).unwrap().mode, 0o640);
        let entries: Vec<_> = fs::read_dir(&tmp.0).unwrap().collect();
        assert_eq!(entries.len(), 1, "temporary file left behind");
    }

    // Failure safety: a rename that cannot happen (target is a non-empty directory) keeps the target as it was and
    // removes the temporary file.
    #[test]
    fn atomic_replace_keeps_previous_target_when_rename_fails() {
        let fs = RealFs::new();
        let tmp = TempDir::new("rename-fail");
        let target = tmp.0.join("dir");
        fs::create_dir(&target).unwrap();
        fs::write(target.join("keep"), b"k").unwrap();
        let error = fs.atomic_replace(&target, b"new", 0o600).unwrap_err();
        assert!(matches!(
            error,
            PlatformError::Os {
                operation: Operation::Rename,
                ..
            }
        ));
        assert_eq!(fs::read(target.join("keep")).unwrap(), b"k");
        assert_eq!(fs::read_dir(&tmp.0).unwrap().count(), 1, "temporary file left behind");
    }

    #[test]
    fn atomic_replace_refuses_targets_without_a_file_name() {
        let fs = RealFs::new();
        for bad in ["/", "/tmp/.", "/tmp/..", "/tmp/x/", "relative"] {
            assert_eq!(
                fs.atomic_replace(Path::new(bad), b"", 0o600),
                Err(PlatformError::InvalidPath),
                "{bad}"
            );
        }
    }

    #[test]
    fn read_refuses_files_over_the_limit() {
        let fs = RealFs::new();
        let tmp = TempDir::new("limit");
        let file = tmp.0.join("f");
        fs.write(&file, b"12345", 0o600).unwrap();
        assert_eq!(fs.read(&file, 4), Err(PlatformError::TooLarge { limit: 4 }));
        assert_eq!(fs.read(&file, 5).unwrap(), b"12345");
        let mut text = String::new();
        fs.open_read(&file).unwrap().read_to_string(&mut text).unwrap();
        assert_eq!(text, "12345");
    }

    #[test]
    fn write_does_not_follow_a_final_symlink() {
        let fs = RealFs::new();
        let tmp = TempDir::new("nofollow");
        let victim = tmp.0.join("victim");
        fs::write(&victim, b"safe").unwrap();
        let link = tmp.0.join("link");
        symlink(&victim, &link).unwrap();
        assert_eq!(fs.write(&link, b"evil", 0o600).unwrap_err().errno(), Some(libc::ELOOP));
        assert_eq!(fs::read(&victim).unwrap(), b"safe");
        assert_eq!(fs.metadata(&link).unwrap().kind, FileKind::Symlink);
    }

    #[test]
    fn create_new_sets_exact_mode_and_refuses_existing_entries() {
        let fs = RealFs::new();
        let tmp = TempDir::new("create-new");
        let file = tmp.0.join("db");
        fs.create_new(&file, 0o600).unwrap();
        let meta = fs.metadata(&file).unwrap();
        assert_eq!((meta.kind, meta.len, meta.mode), (FileKind::File, 0, 0o600));
        fs::write(&file, b"keep").unwrap();
        assert_eq!(fs.create_new(&file, 0o600).unwrap_err().errno(), Some(libc::EEXIST));
        assert_eq!(
            fs::read(&file).unwrap(),
            b"keep",
            "an existing file must never be truncated"
        );
        let link = tmp.0.join("link");
        symlink(tmp.0.join("elsewhere"), &link).unwrap();
        assert_eq!(fs.create_new(&link, 0o600).unwrap_err().errno(), Some(libc::EEXIST));
        assert!(
            !tmp.0.join("elsewhere").exists(),
            "a dangling symlink must not be followed"
        );
    }

    #[test]
    fn create_dir_applies_mode_and_refuses_existing() {
        let fs = RealFs::new();
        let tmp = TempDir::new("mkdir");
        let dir = tmp.0.join("d");
        fs.create_dir(&dir, 0o700).unwrap();
        let meta = fs.metadata(&dir).unwrap();
        assert_eq!((meta.kind, meta.mode), (FileKind::Directory, 0o700));
        assert_eq!(fs.create_dir(&dir, 0o700).unwrap_err().errno(), Some(libc::EEXIST));
    }

    #[test]
    fn metadata_reports_the_owner() {
        let fs = RealFs::new();
        let tmp = TempDir::new("owner");
        // SAFETY: `geteuid` has no preconditions and cannot fail.
        let uid = unsafe { libc::geteuid() };
        assert_eq!(fs.metadata(&tmp.0).unwrap().uid, uid);
    }

    // NFR-SEC-08: tightening must never follow a symlink planted at an engine path to its target.
    #[test]
    fn set_mode_sets_exact_bits_and_does_not_follow_symlinks() {
        let fs = RealFs::new();
        let tmp = TempDir::new("chmod");
        let dir = tmp.0.join("d");
        fs::create_dir(&dir).unwrap();
        fs::set_permissions(&dir, Permissions::from_mode(0o755)).unwrap();
        fs.set_mode(&dir, 0o700).unwrap();
        assert_eq!(fs.metadata(&dir).unwrap().mode, 0o700);

        let victim = tmp.0.join("victim");
        fs::write(&victim, b"x").unwrap();
        fs::set_permissions(&victim, Permissions::from_mode(0o644)).unwrap();
        let link = tmp.0.join("link");
        symlink(&victim, &link).unwrap();
        fs.set_mode(&link, 0o600).unwrap();
        assert_eq!(fs.metadata(&victim).unwrap().mode, 0o644, "symlink target was changed");
        assert!(fs.set_mode(&tmp.0.join("missing"), 0o700).unwrap_err().is_not_found());
    }

    #[test]
    fn xattr_round_trips_and_respects_limit() {
        let fs = RealFs::new();
        let tmp = TempDir::new("xattr");
        let name = "com.knsh.test";
        assert_eq!(fs.xattr(&tmp.0, name, 16).unwrap(), None);
        fs.set_xattr(&tmp.0, name, b"value").unwrap();
        assert_eq!(fs.xattr(&tmp.0, name, 16).unwrap().as_deref(), Some(&b"value"[..]));
        assert_eq!(fs.xattr(&tmp.0, name, 5).unwrap().as_deref(), Some(&b"value"[..]));
        assert_eq!(fs.xattr(&tmp.0, name, 4), Err(PlatformError::TooLarge { limit: 4 }));
        assert_eq!(fs.xattr(&tmp.0, name, 0), Err(PlatformError::TooLarge { limit: 0 }));
        fs.set_xattr(&tmp.0, name, b"v2").unwrap();
        assert_eq!(fs.xattr(&tmp.0, name, 16).unwrap().as_deref(), Some(&b"v2"[..]));
        assert_eq!(fs.set_xattr(&tmp.0, "bad\0name", b""), Err(PlatformError::InvalidPath));
        assert_eq!(
            fs.xattr(Path::new("relative"), name, 1),
            Err(PlatformError::InvalidPath)
        );
    }

    // KNSH-012: removal unlinks a symlink itself, never its target, and refuses a directory.
    #[test]
    fn remove_file_does_not_follow_symlinks_or_remove_directories() {
        let dir = TempDir::new("remove");
        let file = dir.0.join("f");
        let link = dir.0.join("link");
        fs::write(&file, b"x").unwrap();
        symlink(&file, &link).unwrap();
        let real = RealFs::new();
        real.remove_file(&link).unwrap();
        assert!(file.exists());
        real.remove_file(&file).unwrap();
        assert!(real.remove_file(&file).unwrap_err().is_not_found());
        assert!(real.remove_file(&dir.0).is_err());
        assert!(dir.0.exists());
    }
}
