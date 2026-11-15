//! The system calls the trampoline makes, as hand-written `extern` declarations (NFR-SUP-01: no `libc` crate).
//!
//! macOS only: the declarations and constants below match `<unistd.h>`, `<fcntl.h>`, `<signal.h>` and
//! `<sys/proc_info.h>` on Darwin. Each wrapper returns `std::io::Error` built from `errno`.

use std::ffi::{CString, OsString, c_char, c_int, c_void};
use std::io;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::Path;

/// `F_GETFD` in `<sys/fcntl.h>`.
const F_GETFD: c_int = 1;
/// `F_SETFD` in `<sys/fcntl.h>`.
const F_SETFD: c_int = 2;
/// `FD_CLOEXEC` in `<sys/fcntl.h>`.
const FD_CLOEXEC: c_int = 1;
/// `SIGPIPE` in `<sys/signal.h>`.
const SIGPIPE: c_int = 13;
/// `SIG_DFL` in `<sys/signal.h>`.
const SIG_DFL: usize = 0;
/// `SIG_ERR` in `<sys/signal.h>`: `(void (*)(int))-1`.
const SIG_ERR: usize = usize::MAX;
/// `PROC_PIDLISTFDS` in `<sys/proc_info.h>`: the open descriptors, as `proc_fdinfo` entries.
const PROC_PIDLISTFDS: c_int = 1;
/// `PROC_PIDTASKINFO` in `<sys/proc_info.h>`: one `proc_taskinfo`.
const PROC_PIDTASKINFO: c_int = 4;
/// `EIO` in `<sys/errno.h>`, for a kernel answer that does not have the expected shape.
const EIO: i32 = 5;

/// `struct proc_fdinfo` in `<sys/proc_info.h>`.
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct ProcFdInfo {
    proc_fd: i32,
    proc_fdtype: u32,
}

/// `struct proc_taskinfo` in `<sys/proc_info.h>` (96 bytes). Only the thread count is read. Field names follow the
/// C header, prefix included, so the layout can be checked against it line by line.
#[repr(C)]
#[allow(clippy::struct_field_names)]
#[derive(Default)]
struct ProcTaskInfo {
    pti_virtual_size: u64,
    pti_resident_size: u64,
    pti_total_user: u64,
    pti_total_system: u64,
    pti_threads_user: u64,
    pti_threads_system: u64,
    pti_policy: i32,
    pti_faults: i32,
    pti_pageins: i32,
    pti_cow_faults: i32,
    pti_messages_sent: i32,
    pti_messages_received: i32,
    pti_syscalls_mach: i32,
    pti_syscalls_unix: i32,
    pti_csw: i32,
    pti_threadnum: i32,
    pti_numrunning: i32,
    pti_priority: i32,
}

// SAFETY (for the block): these are the libSystem signatures on Darwin. `fcntl` is variadic and is only called with
// the integer third argument `F_SETFD` takes, or none for `F_GETFD`.
unsafe extern "C" {
    fn getpid() -> c_int;
    fn geteuid() -> u32;
    fn setpgid(pid: c_int, pgid: c_int) -> c_int;
    fn fcntl(fd: c_int, cmd: c_int, ...) -> c_int;
    fn write(fd: c_int, buf: *const c_void, count: usize) -> isize;
    fn signal(signum: c_int, handler: usize) -> usize;
    fn execve(path: *const c_char, argv: *const *const c_char, envp: *const *const c_char) -> c_int;
    fn proc_pidinfo(pid: c_int, flavor: c_int, arg: u64, buffer: *mut c_void, buffersize: c_int) -> c_int;
}

/// The effective user id, the owner every profile file must have.
pub(crate) fn effective_uid() -> u32 {
    // SAFETY: `geteuid` takes no arguments, touches no memory and cannot fail.
    unsafe { geteuid() }
}

/// Makes this process the leader of its own process group (`setpgid(0, 0)`), so the supervisor can signal the
/// command and everything it forks together, and never signals a group it does not own (CLAUDE.md "Concurrency").
/// Already being the leader (the supervisor spawns with a new group) is fine.
///
/// # Errors
///
/// The `errno` of `setpgid`, for example `EPERM` for a session leader.
pub(crate) fn lead_own_process_group() -> io::Result<()> {
    // SAFETY: plain integers, no memory.
    if unsafe { setpgid(0, 0) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Restores the default `SIGPIPE` action. The Rust runtime ignores `SIGPIPE` at start-up, and an ignored signal
/// stays ignored across `execve`: without this, every sandboxed command would ignore it (`yes | head` would spin on
/// `EPIPE` instead of ending).
///
/// # Errors
///
/// The `errno` of `signal`.
pub(crate) fn default_sigpipe() -> io::Result<()> {
    // SAFETY: `SIG_DFL` is a valid disposition for `SIGPIPE`; no handler code is installed.
    if unsafe { signal(SIGPIPE, SIG_DFL) } == SIG_ERR {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// The number of threads in this process, from the kernel's task information.
///
/// # Errors
///
/// The `errno` of `proc_pidinfo`, or `EIO` if it returned fewer bytes than a `proc_taskinfo`.
pub(crate) fn thread_count() -> io::Result<usize> {
    let mut info = ProcTaskInfo::default();
    let size = c_int::try_from(size_of::<ProcTaskInfo>()).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    // SAFETY: `info` is a writable `proc_taskinfo` of exactly `size` bytes, alive for the call.
    let written = unsafe { proc_pidinfo(getpid(), PROC_PIDTASKINFO, 0, (&raw mut info).cast(), size) };
    if written < 0 {
        return Err(io::Error::last_os_error());
    }
    if written != size {
        return Err(io::Error::from_raw_os_error(EIO));
    }
    usize::try_from(info.pti_threadnum).map_err(|_| io::Error::from_raw_os_error(EIO))
}

/// Every descriptor open in this process, in ascending order.
///
/// # Errors
///
/// The `errno` of `proc_pidinfo`, or `EIO` if the list did not fit after a few retries.
pub(crate) fn open_descriptors() -> io::Result<Vec<i32>> {
    let entry = size_of::<ProcFdInfo>();
    // SAFETY: a null buffer of size 0 only asks for the size the list needs; nothing is written.
    let needed = unsafe { proc_pidinfo(getpid(), PROC_PIDLISTFDS, 0, std::ptr::null_mut(), 0) };
    if needed < 0 {
        return Err(io::Error::last_os_error());
    }
    // Room for the reported size plus slack. A list that fills the buffer exactly may have been cut short, so the
    // buffer grows and the call is repeated; the process is single-threaded, so nothing opens descriptors meanwhile.
    let mut capacity = usize::try_from(needed).unwrap_or(0) / entry + 32;
    for _ in 0..4 {
        let mut buffer = vec![ProcFdInfo::default(); capacity];
        let bytes = c_int::try_from(capacity * entry).map_err(|_| io::Error::from_raw_os_error(EIO))?;
        // SAFETY: `buffer` holds `capacity` writable entries, `bytes` bytes in all, alive for the call.
        let written = unsafe { proc_pidinfo(getpid(), PROC_PIDLISTFDS, 0, buffer.as_mut_ptr().cast(), bytes) };
        if written < 0 {
            return Err(io::Error::last_os_error());
        }
        let count = usize::try_from(written).unwrap_or(0) / entry;
        if count < capacity {
            let mut fds: Vec<i32> = buffer[..count].iter().map(|info| info.proc_fd).collect();
            fds.sort_unstable();
            return Ok(fds);
        }
        capacity *= 2;
    }
    Err(io::Error::from_raw_os_error(EIO))
}

/// Sets (`true`) or clears (`false`) `FD_CLOEXEC` on `fd`, keeping its other descriptor flags.
///
/// # Errors
///
/// The `errno` of `fcntl`.
pub(crate) fn set_close_on_exec(fd: i32, close: bool) -> io::Result<()> {
    // SAFETY: `F_GETFD` takes no third argument and touches no memory.
    let flags = unsafe { fcntl(fd, F_GETFD) };
    if flags == -1 {
        return Err(io::Error::last_os_error());
    }
    let wanted = if close { flags | FD_CLOEXEC } else { flags & !FD_CLOEXEC };
    // SAFETY: `F_SETFD` takes one `int` argument and touches no memory.
    if unsafe { fcntl(fd, F_SETFD, wanted) } == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Writes the single byte `code` to `fd`, the supervisor's status descriptor. Best effort: the exit code still says
/// what happened, so a failed write is ignored. No `EINTR` retry: the trampoline installs no signal handlers, so a
/// one-byte pipe write is never interrupted.
pub(crate) fn write_status(fd: i32, code: u8) {
    // SAFETY: `code` lives on this stack frame for the whole call, and `write` reads exactly one byte from it. An
    // invalid or closed `fd` makes `write` fail with `EBADF`, touching no memory.
    let _ = unsafe { write(fd, (&raw const code).cast::<c_void>(), 1) };
}

/// Replaces this process with `program`, `argv` and `env` (`execve`, no `PATH` search). Returns only on failure.
///
/// The returned error is the `errno` of `execve`, or an [`io::ErrorKind::InvalidInput`] error if an argument holds a
/// NUL byte (arguments and the environment of this process cannot, so that is unreachable in practice).
pub(crate) fn exec(program: &Path, argv: Vec<OsString>, env: Vec<OsString>) -> io::Error {
    let to_c = |items: Vec<OsString>| -> Option<Vec<CString>> {
        items
            .into_iter()
            .map(|item| CString::new(item.into_vec()).ok())
            .collect()
    };
    let (Some(path), Some(argv), Some(env)) =
        (CString::new(program.as_os_str().as_bytes()).ok(), to_c(argv), to_c(env))
    else {
        return io::Error::from(io::ErrorKind::InvalidInput);
    };
    let argv_ptrs: Vec<*const c_char> = argv.iter().map(|arg| arg.as_ptr()).chain([std::ptr::null()]).collect();
    let env_ptrs: Vec<*const c_char> = env.iter().map(|var| var.as_ptr()).chain([std::ptr::null()]).collect();
    // SAFETY: `path` is a NUL-terminated string; `argv_ptrs` and `env_ptrs` are NULL-terminated arrays of pointers to
    // NUL-terminated strings owned by `argv` and `env`, all alive until `execve` returns (it only returns on
    // failure).
    unsafe { execve(path.as_ptr(), argv_ptrs.as_ptr(), env_ptrs.as_ptr()) };
    io::Error::last_os_error()
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::os::fd::AsRawFd;
    use std::sync::mpsc;

    use super::*;

    // KNSH-046: the thread count the trampoline checks before exec is the real one.
    #[test]
    fn counts_this_processs_threads() {
        let before = thread_count().unwrap();
        assert!(before >= 1);
        let (release, blocked) = mpsc::channel::<()>();
        let (ready, started) = mpsc::channel();
        let worker = std::thread::spawn(move || {
            ready.send(()).unwrap();
            let _ = blocked.recv();
        });
        started.recv().unwrap();
        // Other test threads may come and go, so only "at least one more" is certain while the worker blocks.
        assert!(thread_count().unwrap() >= 2);
        drop(release);
        worker.join().unwrap();
    }

    #[test]
    fn lists_open_descriptors_and_sets_close_on_exec() {
        let file = File::open("/dev/null").unwrap();
        let fd = file.as_raw_fd();
        let open = open_descriptors().unwrap();
        assert!(open.contains(&fd));
        assert!(open.windows(2).all(|pair| pair[0] < pair[1]), "sorted, no duplicates");

        set_close_on_exec(fd, false).unwrap();
        // SAFETY: `F_GETFD` on an open descriptor, no memory.
        assert_eq!(unsafe { fcntl(fd, F_GETFD) } & FD_CLOEXEC, 0);
        set_close_on_exec(fd, true).unwrap();
        // SAFETY: as above.
        assert_eq!(unsafe { fcntl(fd, F_GETFD) } & FD_CLOEXEC, FD_CLOEXEC);
    }

    // KNSH-046: a sandbox-exec that cannot be executed is an error, never a fallback to running the line directly.
    #[test]
    fn failed_exec_returns_the_error() {
        let error = exec(
            Path::new("/nonexistent/knsh/sandbox-exec"),
            vec!["/nonexistent/knsh/sandbox-exec".into()],
            Vec::new(),
        );
        assert_eq!(error.raw_os_error(), Some(2), "ENOENT");
    }
}
