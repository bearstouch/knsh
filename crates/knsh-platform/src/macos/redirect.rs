//! [`Descriptors`] on the real system: the files behind a shell's redirections (KNSH-099).
//!
//! # Why the opens never reach `/dev/fd`
//!
//! Opening `/dev/fd/N` duplicates this process's descriptor `N`, which in the interpreter's process may be the
//! connection to the supervisor or an engine file. A path is therefore opened with `O_NOFOLLOW_ANY` (macOS 11 and
//! later: the open fails with `ELOOP` if any component is a symlink) after a check of its text: with no symlink
//! followed, the text says exactly which file is opened. A path that does hold a symlink (`/tmp` is one on macOS) is
//! resolved first (`realpath`, or `realpath` of its directory for a file still to be created), checked, and the
//! resolved path is opened with `O_NOFOLLOW_ANY` again, so a component swapped for a symlink in between makes the
//! open fail rather than reach somewhere unchecked.

use std::ffi::CString;
use std::io::Write;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use crate::descriptor::{Descriptors, OpenMode, reaches_descriptor_table};
use crate::error::{Operation, PlatformError};
use crate::process::SharedFd;

/// Here-strings up to this many bytes go through a pipe; longer ones through an unlinked temporary file. Well below
/// the 16 KiB a macOS pipe buffers, so the write never blocks (it is non-blocking anyway, and falls back to a file).
const PIPE_HERE_STRING_LIMIT: usize = 4096;

/// Opens redirection files with the system calls, as bash does.
#[derive(Debug, Default)]
pub struct SystemDescriptors {
    /// Numbers the names of temporary files, with the process id, so two here-strings never race for one name.
    temp_counter: AtomicU64,
}

impl SystemDescriptors {
    /// The real backend.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// An unlinked temporary file holding `text`, opened read-only at its start.
    fn temp_file(&self, text: &[u8]) -> Result<SharedFd, PlatformError> {
        let io = |error: &std::io::Error| PlatformError::from_io(Operation::Write, error);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_nanos());
        let count = self.temp_counter.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(".knsh-here-{}-{nanos}-{count}", std::process::id()));
        // Owner-only and never an existing entry (`create_new` is `O_EXCL`, which also refuses a symlink).
        let mut writer = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .map_err(|error| io(&error))?;
        let reader = std::fs::File::open(&path);
        // Unlinked at once: nothing else can open it, and it disappears with its last descriptor.
        let removed = std::fs::remove_file(&path);
        let reader = reader.map_err(|error| io(&error))?;
        removed.map_err(|error| io(&error))?;
        writer.write_all(text).map_err(|error| io(&error))?;
        Ok(SharedFd::new(OwnedFd::from(reader)))
    }
}

/// The `open` flags for `mode`, close-on-exec, and whether the file must not exist yet.
fn flags(mode: OpenMode) -> libc::c_int {
    let base = match mode {
        OpenMode::Read => libc::O_RDONLY,
        OpenMode::Truncate => libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC,
        OpenMode::NoClobber => libc::O_WRONLY,
        OpenMode::Append => libc::O_WRONLY | libc::O_CREAT | libc::O_APPEND,
        OpenMode::ReadWrite => libc::O_RDWR | libc::O_CREAT,
    };
    base | libc::O_CLOEXEC
}

/// The error of a refused open.
const fn open_error(errno: i32) -> PlatformError {
    PlatformError::Os {
        operation: Operation::Open,
        errno,
    }
}

/// `open(path, flags | O_NOFOLLOW_ANY, 0666)`, retried on `EINTR`.
fn open_nofollow(path: &Path, flags: libc::c_int) -> Result<OwnedFd, i32> {
    let text = CString::new(path.as_os_str().as_bytes()).map_err(|_| libc::EINVAL)?;
    loop {
        // SAFETY: `text` is a valid NUL-terminated string that outlives the call; the mode is a plain integer
        // (variadic, promoted to `c_uint` as `open` expects).
        let fd = unsafe { libc::open(text.as_ptr(), flags | libc::O_NOFOLLOW_ANY, 0o666 as libc::c_uint) };
        if fd >= 0 {
            // SAFETY: `open` just returned this descriptor; nothing else owns it.
            return Ok(unsafe { OwnedFd::from_raw_fd(fd) });
        }
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(libc::EIO);
        if errno != libc::EINTR {
            return Err(errno);
        }
    }
}

/// `path` with every symlink resolved: the whole path if it exists, otherwise its directory resolved and its last
/// component kept (a file a redirection is about to create).
fn resolve(path: &Path) -> Result<PathBuf, i32> {
    let errno = |error: std::io::Error| error.raw_os_error().unwrap_or(libc::EIO);
    match std::fs::canonicalize(path) {
        Ok(resolved) => Ok(resolved),
        Err(error) if error.raw_os_error() == Some(libc::ENOENT) => {
            let (Some(parent), Some(name)) = (path.parent(), path.file_name()) else {
                return Err(libc::ENOENT);
            };
            Ok(std::fs::canonicalize(parent).map_err(errno)?.join(name))
        }
        Err(error) => Err(errno(error)),
    }
}

/// Opens `path` with `flags`, never reaching this process's descriptor table (see the module docs).
fn open_checked(path: &Path, flags: libc::c_int) -> Result<OwnedFd, i32> {
    if reaches_descriptor_table(path) {
        return Err(libc::EPERM);
    }
    match open_nofollow(path, flags) {
        Err(libc::ELOOP) => {
            let resolved = resolve(path)?;
            if reaches_descriptor_table(&resolved) {
                return Err(libc::EPERM);
            }
            open_nofollow(&resolved, flags)
        }
        other => other,
    }
}

/// Whether `fd` is a regular file.
fn is_regular(fd: &OwnedFd) -> Result<bool, i32> {
    // SAFETY: an all-zero `stat` is a valid value (a plain C struct of integers).
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: `fd` is open for the duration of the call and `stat` is valid, writable memory of the right type.
    if unsafe { libc::fstat(fd.as_raw_fd(), &raw mut stat) } != 0 {
        return Err(std::io::Error::last_os_error().raw_os_error().unwrap_or(libc::EIO));
    }
    Ok(stat.st_mode & libc::S_IFMT == libc::S_IFREG)
}

/// Bash's `noclobber_open`: refuse an existing regular file, create a missing one exclusively, open anything else
/// (`/dev/null`) for writing without truncating it.
fn open_noclobber(path: &Path) -> Result<OwnedFd, i32> {
    let write = flags(OpenMode::NoClobber);
    match open_checked(path, write | libc::O_CREAT | libc::O_EXCL) {
        Err(libc::EEXIST) => {}
        other => return other,
    }
    let fd = open_checked(path, write)?;
    // Regular now (replaced since the exclusive open failed, or it always was): refused, as bash refuses it.
    if is_regular(&fd)? {
        return Err(libc::EEXIST);
    }
    Ok(fd)
}

impl Descriptors for SystemDescriptors {
    fn open(&self, path: &Path, mode: OpenMode) -> Result<SharedFd, PlatformError> {
        if !path.is_absolute() || path.as_os_str().as_bytes().contains(&0) {
            return Err(PlatformError::InvalidPath);
        }
        let opened = match mode {
            OpenMode::NoClobber => open_noclobber(path),
            OpenMode::Read | OpenMode::Truncate | OpenMode::Append | OpenMode::ReadWrite => {
                open_checked(path, flags(mode))
            }
        };
        opened.map(SharedFd::new).map_err(open_error)
    }

    fn here_string(&self, text: &[u8]) -> Result<SharedFd, PlatformError> {
        if text.len() > PIPE_HERE_STRING_LIMIT {
            return self.temp_file(text);
        }
        let (reader, writer) = std::io::pipe().map_err(|error| PlatformError::from_io(Operation::Write, &error))?;
        // Non-blocking, so a pipe that holds less than expected falls back to a file instead of blocking the shell.
        // SAFETY: `fcntl` on a descriptor this function owns; it touches no memory.
        let nonblocking = unsafe { libc::fcntl(writer.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK) } == 0;
        let mut writer = writer;
        if nonblocking && writer.write_all(text).is_ok() {
            return Ok(SharedFd::new(OwnedFd::from(reader)));
        }
        self.temp_file(text)
    }

    fn write_all(&self, fd: &SharedFd, bytes: &[u8]) -> Result<(), PlatformError> {
        let mut rest = bytes;
        while !rest.is_empty() {
            // SAFETY: `fd` is open for the duration of the call (the `SharedFd` holds it), and `rest` is valid for
            // `rest.len()` bytes.
            let written = unsafe { libc::write(fd.as_raw_fd(), rest.as_ptr().cast(), rest.len()) };
            match usize::try_from(written) {
                Ok(0) => {
                    return Err(PlatformError::Os {
                        operation: Operation::Write,
                        errno: libc::EIO,
                    });
                }
                Ok(count) => rest = rest.get(count..).unwrap_or_default(),
                Err(_) => {
                    let error = std::io::Error::last_os_error();
                    if error.raw_os_error() != Some(libc::EINTR) {
                        return Err(PlatformError::from_io(Operation::Write, &error));
                    }
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::io::Read;

    use super::*;

    /// A fresh directory under the (resolved) temporary directory.
    fn temp_dir(label: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("knsh-redirect-{label}-{}-{nanos}", std::process::id()));
        std::fs::create_dir(&dir).unwrap();
        dir
    }

    fn read_all(fd: &SharedFd) -> String {
        let mut file = std::fs::File::from(fd.try_clone_owned().unwrap());
        let mut text = String::new();
        file.read_to_string(&mut text).unwrap();
        text
    }

    fn errno(result: Result<SharedFd, PlatformError>) -> Option<i32> {
        result.err().and_then(|error| error.errno())
    }

    // KNSH-099: each mode opens as bash's operator does; the descriptors are close-on-exec.
    #[test]
    fn modes_open_like_bash() {
        let descriptors = SystemDescriptors::new();
        let dir = temp_dir("modes");
        let file = dir.join("f");
        let out = descriptors.open(&file, OpenMode::Truncate).unwrap();
        descriptors.write_all(&out, b"one\n").unwrap();
        let appended = descriptors.open(&file, OpenMode::Append).unwrap();
        descriptors.write_all(&appended, b"two\n").unwrap();
        assert_eq!(
            read_all(&descriptors.open(&file, OpenMode::Read).unwrap()),
            "one\ntwo\n"
        );
        // SAFETY: `fcntl` on a descriptor the test holds; it touches no memory.
        let flags = unsafe { libc::fcntl(out.as_raw_fd(), libc::F_GETFD) };
        assert_eq!(flags & libc::FD_CLOEXEC, libc::FD_CLOEXEC);
        let both = descriptors.open(&file, OpenMode::ReadWrite).unwrap();
        assert_eq!(read_all(&both), "one\ntwo\n");
        descriptors.open(&file, OpenMode::Truncate).unwrap();
        assert_eq!(std::fs::read(&file).unwrap(), b"");
        assert_eq!(
            errno(descriptors.open(&dir.join("missing"), OpenMode::Read)),
            Some(libc::ENOENT)
        );
        assert_eq!(errno(descriptors.open(&dir, OpenMode::Truncate)), Some(libc::EISDIR));
        assert_eq!(
            descriptors.open(Path::new("relative"), OpenMode::Read).err(),
            Some(PlatformError::InvalidPath)
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    // KNSH-099: `noclobber` refuses an existing regular file, creates a missing one, and still writes to devices.
    #[test]
    fn noclobber_refuses_existing_regular_files_only() {
        let descriptors = SystemDescriptors::new();
        let dir = temp_dir("noclobber");
        let file = dir.join("f");
        descriptors.open(&file, OpenMode::NoClobber).unwrap();
        assert_eq!(errno(descriptors.open(&file, OpenMode::NoClobber)), Some(libc::EEXIST));
        descriptors.open(Path::new("/dev/null"), OpenMode::NoClobber).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    // KNSH-099: no path reaches this process's own descriptors, whether written out or through a symlink; ordinary
    // symlinks (the temporary directory holds one on macOS) are still followed.
    #[test]
    fn never_opens_this_process_descriptor_table() {
        let descriptors = SystemDescriptors::new();
        let dir = temp_dir("fdesc");
        let link = dir.join("link");
        std::os::unix::fs::symlink("/dev/fd/0", &link).unwrap();
        for path in [
            Path::new("/dev/fd/0"),
            Path::new("/dev/stdout"),
            Path::new("/dev/./fd/1"),
            &link,
        ] {
            assert_eq!(
                errno(descriptors.open(path, OpenMode::Truncate)),
                Some(libc::EPERM),
                "{path:?}"
            );
        }
        let target = dir.join("target");
        std::fs::write(&target, "t").unwrap();
        let alias = dir.join("alias");
        std::os::unix::fs::symlink(&target, &alias).unwrap();
        assert_eq!(read_all(&descriptors.open(&alias, OpenMode::Read).unwrap()), "t");
        // Through `/tmp`, a symlink to `/private/tmp`, a file is still created.
        let through_tmp = Path::new("/tmp").join(format!("knsh-redirect-tmp-{}", std::process::id()));
        descriptors.open(&through_tmp, OpenMode::Truncate).unwrap();
        std::fs::remove_file(&through_tmp).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    // KNSH-099: a here-string reads back exactly, short ones through a pipe and long ones through a file that is
    // already unlinked.
    #[test]
    fn here_strings_read_back_exactly() {
        let descriptors = SystemDescriptors::new();
        assert_eq!(read_all(&descriptors.here_string(b"short\n").unwrap()), "short\n");
        let long = "x".repeat(PIPE_HERE_STRING_LIMIT * 4);
        let fd = descriptors.here_string(long.as_bytes()).unwrap();
        assert_eq!(read_all(&fd), long);
        assert_eq!(read_all(&descriptors.here_string(b"").unwrap()), "");
    }
}
