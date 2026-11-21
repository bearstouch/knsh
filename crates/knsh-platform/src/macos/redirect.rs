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
use std::time::Duration;

use crate::descriptor::{Descriptors, OpenMode, TerminalInput, TerminalSettings, reaches_descriptor_table};
use crate::error::{Operation, PlatformError};
use crate::fs::FileStatus;
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

/// `open(path, flags | O_NOFOLLOW_ANY, perms)`, retried on `EINTR`. A file created gets `perms` less the process's
/// umask.
fn open_nofollow(path: &Path, flags: libc::c_int, perms: u32) -> Result<OwnedFd, i32> {
    let text = CString::new(path.as_os_str().as_bytes()).map_err(|_| libc::EINVAL)?;
    loop {
        // SAFETY: `text` is a valid NUL-terminated string that outlives the call; the mode is a plain integer
        // (variadic, promoted to `c_uint` as `open` expects).
        let fd = unsafe { libc::open(text.as_ptr(), flags | libc::O_NOFOLLOW_ANY, perms as libc::c_uint) };
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

/// Opens `path` with `flags` (a file created gets `perms`), never reaching this process's descriptor table (see the
/// module docs).
fn open_checked(path: &Path, flags: libc::c_int, perms: u32) -> Result<OwnedFd, i32> {
    if reaches_descriptor_table(path) {
        return Err(libc::EPERM);
    }
    match open_nofollow(path, flags, perms) {
        Err(libc::ELOOP) => {
            let resolved = resolve(path)?;
            if reaches_descriptor_table(&resolved) {
                return Err(libc::EPERM);
            }
            open_nofollow(&resolved, flags, perms)
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
fn open_noclobber(path: &Path, perms: u32) -> Result<OwnedFd, i32> {
    let write = flags(OpenMode::NoClobber);
    match open_checked(path, write | libc::O_CREAT | libc::O_EXCL, perms) {
        Err(libc::EEXIST) => {}
        other => return other,
    }
    let fd = open_checked(path, write, perms)?;
    // Regular now (replaced since the exclusive open failed, or it always was): refused, as bash refuses it.
    if is_regular(&fd)? {
        return Err(libc::EEXIST);
    }
    Ok(fd)
}

impl SystemDescriptors {
    /// [`Descriptors::open`] with `perms` for a file it creates.
    fn open_with(path: &Path, mode: OpenMode, perms: u32) -> Result<SharedFd, PlatformError> {
        if !path.is_absolute() || path.as_os_str().as_bytes().contains(&0) {
            return Err(PlatformError::InvalidPath);
        }
        let opened = match mode {
            OpenMode::NoClobber => open_noclobber(path, perms),
            OpenMode::Read | OpenMode::Truncate | OpenMode::Append | OpenMode::ReadWrite => {
                open_checked(path, flags(mode), perms)
            }
        };
        opened.map(SharedFd::new).map_err(open_error)
    }
}

impl Descriptors for SystemDescriptors {
    fn open(&self, path: &Path, mode: OpenMode) -> Result<SharedFd, PlatformError> {
        Self::open_with(path, mode, 0o666)
    }

    fn open_masked(&self, path: &Path, mode: OpenMode, umask: u32) -> Result<SharedFd, PlatformError> {
        Self::open_with(path, mode, 0o666 & !umask & 0o777)
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

    fn pipe(&self) -> Result<(SharedFd, SharedFd), PlatformError> {
        // std's pipe is close-on-exec at both ends; a child gets an end only as a placement.
        let (reader, writer) = std::io::pipe().map_err(|error| PlatformError::from_io(Operation::Pipe, &error))?;
        Ok((
            SharedFd::new(OwnedFd::from(reader)),
            SharedFd::new(OwnedFd::from(writer)),
        ))
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

    fn read(&self, fd: &SharedFd, buffer: &mut [u8]) -> Result<usize, PlatformError> {
        loop {
            // SAFETY: `fd` is open for the duration of the call (the `SharedFd` holds it), and `buffer` is valid for
            // writes of `buffer.len()` bytes.
            let count = unsafe { libc::read(fd.as_raw_fd(), buffer.as_mut_ptr().cast(), buffer.len()) };
            if let Ok(count) = usize::try_from(count) {
                return Ok(count);
            }
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::EINTR) {
                return Err(PlatformError::from_io(Operation::Read, &error));
            }
        }
    }

    fn wait_readable(&self, fd: &SharedFd, timeout: Duration) -> Result<bool, PlatformError> {
        // A timeout too long to add to the clock never runs out: wait in `i32::MAX` millisecond rounds.
        let deadline = std::time::Instant::now().checked_add(timeout);
        loop {
            let left = deadline.map_or(Duration::MAX, |deadline| {
                deadline.saturating_duration_since(std::time::Instant::now())
            });
            // Rounded up, so a wait never ends before its time; `poll` takes at most `i32::MAX` milliseconds, and a
            // longer wait goes round again.
            let millis = i32::try_from(left.as_micros().div_ceil(1000)).unwrap_or(i32::MAX);
            let mut entry = libc::pollfd {
                fd: fd.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY: `entry` is one valid `pollfd` for the duration of the call; `fd` is held open by `SharedFd`.
            let ready = unsafe { libc::poll(&raw mut entry, 1, millis) };
            match ready {
                0 if left.is_zero() || deadline.is_some_and(|deadline| std::time::Instant::now() >= deadline) => {
                    return Ok(false);
                }
                0 => {}
                n if n > 0 => return Ok(true),
                _ => {
                    let error = std::io::Error::last_os_error();
                    if error.raw_os_error() != Some(libc::EINTR) {
                        return Err(PlatformError::from_io(Operation::Read, &error));
                    }
                }
            }
        }
    }

    fn is_terminal(&self, fd: &SharedFd) -> bool {
        // SAFETY: `isatty` reads nothing but the descriptor number, which `SharedFd` keeps open.
        unsafe { libc::isatty(fd.as_raw_fd()) == 1 }
    }

    fn status(&self, fd: &SharedFd) -> Result<FileStatus, PlatformError> {
        let file = std::fs::File::from(
            fd.try_clone_owned()
                .map_err(|error| PlatformError::from_io(Operation::Metadata, &error))?,
        );
        let meta = file
            .metadata()
            .map_err(|error| PlatformError::from_io(Operation::Metadata, &error))?;
        Ok(super::fs::status_of(&meta))
    }

    fn set_terminal_input(
        &self,
        fd: &SharedFd,
        input: TerminalInput,
    ) -> Result<Option<TerminalSettings>, PlatformError> {
        if !self.is_terminal(fd) {
            return Ok(None);
        }
        let terminal = |result: libc::c_int| {
            if result == 0 {
                Ok(())
            } else {
                Err(PlatformError::from_io(
                    Operation::Terminal,
                    &std::io::Error::last_os_error(),
                ))
            }
        };
        // SAFETY: an all-zero `termios` is a valid value of the plain C struct; `tcgetattr` overwrites it.
        let mut saved: libc::termios = unsafe { std::mem::zeroed() };
        // SAFETY: `saved` is a valid, writable `termios` for the duration of the call; `fd` is held open.
        terminal(unsafe { libc::tcgetattr(fd.as_raw_fd(), &raw mut saved) })?;
        let mut changed = saved;
        if !input.echo {
            // Bash's `ttfd_noecho`.
            changed.c_lflag &= !(libc::ECHO | libc::ECHOK | libc::ECHONL);
        }
        if !input.canonical {
            // Bash's `ttfd_cbreak`: characters arrive one at a time, signals still work.
            changed.c_lflag &= !libc::ICANON;
            changed.c_lflag |= libc::ISIG | libc::IEXTEN;
            changed.c_cc[libc::VMIN] = 1;
            changed.c_cc[libc::VTIME] = 0;
        }
        // SAFETY: `changed` is a valid `termios` read for the duration of the call; `fd` is held open.
        terminal(unsafe { libc::tcsetattr(fd.as_raw_fd(), libc::TCSADRAIN, &raw const changed) })?;
        Ok(Some(TerminalSettings { saved: Some(saved) }))
    }

    fn restore_terminal(&self, fd: &SharedFd, saved: &TerminalSettings) -> Result<(), PlatformError> {
        let Some(termios) = saved.saved else {
            return Ok(());
        };
        // SAFETY: `termios` is a valid `termios` read for the duration of the call; `fd` is held open.
        if unsafe { libc::tcsetattr(fd.as_raw_fd(), libc::TCSADRAIN, &raw const termios) } == 0 {
            Ok(())
        } else {
            Err(PlatformError::from_io(
                Operation::Terminal,
                &std::io::Error::last_os_error(),
            ))
        }
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

    // KNSH-101: a file a redirection creates gets the shell's umask (`umask 077` before `>secret`); an existing file
    // keeps its mode.
    #[test]
    fn masked_opens_create_files_with_the_shell_umask() {
        use std::os::unix::fs::PermissionsExt;

        let descriptors = SystemDescriptors::new();
        let dir = temp_dir("umask");
        let mode = |path: &Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
        for (name, open) in [
            ("t", OpenMode::Truncate),
            ("a", OpenMode::Append),
            ("rw", OpenMode::ReadWrite),
            ("n", OpenMode::NoClobber),
        ] {
            let path = dir.join(name);
            descriptors.open_masked(&path, open, 0o077).unwrap();
            assert_eq!(mode(&path), 0o600, "{name}");
        }
        let existing = dir.join("t");
        std::fs::set_permissions(&existing, std::fs::Permissions::from_mode(0o644)).unwrap();
        descriptors.open_masked(&existing, OpenMode::Truncate, 0o077).unwrap();
        assert_eq!(mode(&existing), 0o644);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    // KNSH-102: `read` reads a byte at a time, waits with a timeout, and stats and asks about its descriptor.
    #[test]
    fn reads_wait_and_stat_descriptors() {
        let descriptors = SystemDescriptors::new();
        let (reader, writer) = descriptors.pipe().unwrap();
        assert!(!descriptors.wait_readable(&reader, Duration::from_millis(20)).unwrap());
        descriptors.write_all(&writer, b"ab").unwrap();
        assert!(descriptors.wait_readable(&reader, Duration::ZERO).unwrap());
        // A timeout past what the clock can add (`read -t 18446744073709551615`) waits without end, never panics.
        assert!(descriptors.wait_readable(&reader, Duration::MAX).unwrap());
        let mut byte = [0_u8];
        assert_eq!(descriptors.read(&reader, &mut byte).unwrap(), 1);
        assert_eq!(&byte, b"a");
        assert_eq!(descriptors.read(&reader, &mut byte).unwrap(), 1);
        drop(writer);
        // End of file is readable, and reads 0.
        assert!(descriptors.wait_readable(&reader, Duration::from_secs(5)).unwrap());
        assert_eq!(descriptors.read(&reader, &mut byte).unwrap(), 0);
        assert_eq!(descriptors.status(&reader).unwrap().file_type, crate::FileType::Fifo);
        assert!(!descriptors.is_terminal(&reader));
        // Not a terminal: nothing to change or put back.
        let input = TerminalInput {
            echo: false,
            canonical: false,
        };
        assert!(descriptors.set_terminal_input(&reader, input).unwrap().is_none());
        let null = descriptors.open(Path::new("/dev/null"), OpenMode::Read).unwrap();
        assert_eq!(
            descriptors.status(&null).unwrap().file_type,
            crate::FileType::CharacterDevice
        );
        let written = descriptors.open(Path::new("/dev/null"), OpenMode::Truncate).unwrap();
        assert_eq!(
            descriptors.read(&written, &mut byte).unwrap_err().errno(),
            Some(libc::EBADF)
        );
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
