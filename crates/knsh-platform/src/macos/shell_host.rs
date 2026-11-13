//! Process plumbing for hosting a stock shell in integration mode (KNSH-019, FR-SES-20, FR-SES-22).
//!
//! `knsh` keeps the hosted shell's behaviour exactly as plain zsh: it never touches the terminal, and it only needs
//! three small system facilities that the standard library does not offer.
//!
//! - [`TelemetryPipe`]: a pipe whose write end the shell inherits (the standard library marks every pipe it creates
//!   close-on-exec) and which never blocks a writer, so a slow or absent reader can never delay a prompt.
//! - [`JobSignalsIgnored`]: while the shell runs as a child, terminal-generated `SIGINT`, `SIGQUIT` and `SIGTSTP` must
//!   reach the shell only, never kill or stop `knsh` (the same rule `system(3)` follows).
//! - [`reraise_default`]: when the shell was killed by a signal, `knsh` ends by the same signal, so its parent sees
//!   exactly what it would have seen from plain zsh.

use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::raw::c_int;

use crate::error::{Operation, PlatformError};

/// The signals a terminal sends to its foreground process group, which `knsh` must ignore while it hosts a shell.
const JOB_SIGNALS: [c_int; 3] = [libc::SIGINT, libc::SIGQUIT, libc::SIGTSTP];

/// One more than the highest signal number on macOS (`NSIG` in `<sys/signal.h>`; the `libc` crate does not export it
/// for Apple targets).
const NSIG: c_int = 32;

/// The last OS error as a [`PlatformError`] for `operation`.
fn last_os_error(operation: Operation) -> PlatformError {
    PlatformError::from_io(operation, &io::Error::last_os_error())
}

/// The pipe that carries integration-mode telemetry lines from the hosted shell's hooks to `knsh` (KNSH-019).
///
/// - The **read end** is close-on-exec: only `knsh` holds it.
/// - The **write end** is inheritable, so the next process started (the hosted shell) receives it under the number
///   [`TelemetryPipe::writer_fd`] reports, and non-blocking (`O_NONBLOCK`), so a write to a full pipe fails at once
///   instead of waiting. The hooks drop such a line silently (FR-SES-22: never delay or block a human).
///
/// Drop the write end (from [`TelemetryPipe::into_parts`]) right after starting the shell: while `knsh` holds it,
/// any other process it starts would inherit it too, and the reader would never see end of file.
#[derive(Debug)]
pub struct TelemetryPipe {
    reader: File,
    writer: OwnedFd,
}

impl TelemetryPipe {
    /// Creates the pipe.
    ///
    /// `pipe(2)` and the flag changes are separate calls (macOS has no `pipe2`), so another thread starting a process
    /// in between could inherit the read end. Call this while no other thread starts processes; `knsh` is
    /// single-threaded at that point.
    ///
    /// # Errors
    ///
    /// [`PlatformError::Os`] with [`Operation::Pipe`] if no pipe can be created (for example `EMFILE`), or with
    /// [`Operation::DescriptorFlags`] if its flags cannot be set. Nothing is leaked on error.
    pub fn new() -> Result<Self, PlatformError> {
        let mut fds: [c_int; 2] = [-1; 2];
        // SAFETY: `fds` is a writable array of two `c_int`, exactly what `pipe` fills in.
        if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
            return Err(last_os_error(Operation::Pipe));
        }
        // SAFETY: `pipe` succeeded, so both descriptors are open, fresh, and owned by nothing else in this process.
        let (reader, writer) = unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
        set_close_on_exec(&reader, true)?;
        set_close_on_exec(&writer, false)?;
        set_non_blocking(&writer)?;
        Ok(Self {
            reader: File::from(reader),
            writer,
        })
    }

    /// The descriptor number of the write end, as a child started now would inherit it.
    #[must_use]
    pub fn writer_fd(&self) -> RawFd {
        self.writer.as_raw_fd()
    }

    /// Splits the pipe into its read end and its write end.
    #[must_use]
    pub fn into_parts(self) -> (File, OwnedFd) {
        (self.reader, self.writer)
    }
}

/// Sets or clears `FD_CLOEXEC` on `fd`.
fn set_close_on_exec(fd: &OwnedFd, close_on_exec: bool) -> Result<(), PlatformError> {
    // SAFETY: `fd` is an open descriptor we own; `F_GETFD` reads its flags and touches no memory of ours.
    let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFD) };
    if flags < 0 {
        return Err(last_os_error(Operation::DescriptorFlags));
    }
    let wanted = if close_on_exec {
        flags | libc::FD_CLOEXEC
    } else {
        flags & !libc::FD_CLOEXEC
    };
    // SAFETY: as above; `F_SETFD` with an integer argument changes only this descriptor's flags.
    if unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, wanted) } < 0 {
        return Err(last_os_error(Operation::DescriptorFlags));
    }
    Ok(())
}

/// Sets `O_NONBLOCK` on the open file description behind `fd`.
fn set_non_blocking(fd: &OwnedFd) -> Result<(), PlatformError> {
    // SAFETY: `fd` is an open descriptor we own; `F_GETFL` reads its status flags and touches no memory of ours.
    let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
    if flags < 0 {
        return Err(last_os_error(Operation::DescriptorFlags));
    }
    // SAFETY: as above; `F_SETFL` with an integer argument changes only the status flags of this description.
    if unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(last_os_error(Operation::DescriptorFlags));
    }
    Ok(())
}

/// While alive, this process ignores `SIGINT`, `SIGQUIT` and `SIGTSTP`; dropping it restores what was there before.
///
/// Install it only **after** starting the hosted shell: ignored signals are inherited across `exec`, and the shell
/// and the commands it runs must start with the dispositions `knsh` itself was given.
#[derive(Debug)]
pub struct JobSignalsIgnored {
    /// Each signal changed so far and the action it had before.
    previous: Vec<(c_int, libc::sigaction)>,
}

impl JobSignalsIgnored {
    /// Ignores the job-control signals.
    ///
    /// # Errors
    ///
    /// [`PlatformError::Os`] with [`Operation::SignalDisposition`] if the system refuses. Signals already changed are
    /// restored first, so on error nothing has changed.
    pub fn install() -> Result<Self, PlatformError> {
        let mut guard = Self {
            previous: Vec::with_capacity(JOB_SIGNALS.len()),
        };
        for signal in JOB_SIGNALS {
            // SAFETY: an all-zero `sigaction` is a valid value (empty mask, no flags); the handler is set below.
            let mut ignore: libc::sigaction = unsafe { std::mem::zeroed() };
            ignore.sa_sigaction = libc::SIG_IGN;
            // SAFETY: as above; overwritten by `sigaction` on success.
            let mut old: libc::sigaction = unsafe { std::mem::zeroed() };
            // SAFETY: both pointers refer to live, properly initialised `sigaction` values for the whole call.
            if unsafe { libc::sigaction(signal, &raw const ignore, &raw mut old) } != 0 {
                let error = last_os_error(Operation::SignalDisposition);
                drop(guard); // Restores the signals changed before this one.
                return Err(error);
            }
            guard.previous.push((signal, old));
        }
        Ok(guard)
    }
}

impl Drop for JobSignalsIgnored {
    fn drop(&mut self) {
        for (signal, old) in self.previous.drain(..).rev() {
            // SAFETY: `old` is the action the system returned for `signal`, so it is valid to install again. A
            // failure leaves the signal ignored, which is harmless for a process about to exit; there is nothing
            // better to do with it.
            unsafe { libc::sigaction(signal, &raw const old, std::ptr::null_mut()) };
        }
    }
}

/// Ends this process by `signal` with its default action, as the hosted shell ended.
///
/// Returns only if the signal did not end the process: its default action is to ignore it or stop the process, or
/// the number is not a signal. The caller then exits with `128 + signal`, the shell convention.
pub fn reraise_default(signal: i32) {
    if !(1..NSIG).contains(&signal) {
        return;
    }
    // SAFETY: an all-zero `sigaction` is a valid value; `SIG_DFL` is a valid handler for every signal.
    let mut default: libc::sigaction = unsafe { std::mem::zeroed() };
    default.sa_sigaction = libc::SIG_DFL;
    // SAFETY: the pointer refers to a live, initialised `sigaction`; a refused signal number just fails. The result
    // is deliberately ignored: `SIGKILL` and `SIGSTOP` refuse any change (`EINVAL`) yet must still be raised, since
    // their action is always the default one.
    let _ = unsafe { libc::sigaction(signal, &raw const default, std::ptr::null_mut()) };
    // SAFETY: an all-zero `sigset_t` is valid storage; `sigemptyset` initialises it before use.
    let mut set: libc::sigset_t = unsafe { std::mem::zeroed() };
    // SAFETY: `set` is valid, writable storage for the whole sequence; the signal number was checked above. A blocked
    // signal would stay pending instead of ending the process, so it is unblocked before being raised.
    unsafe {
        libc::sigemptyset(&raw mut set);
        libc::sigaddset(&raw mut set, signal);
        libc::sigprocmask(libc::SIG_UNBLOCK, &raw const set, std::ptr::null_mut());
        libc::raise(signal);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    fn flags(fd: RawFd, command: c_int) -> c_int {
        // SAFETY: `fd` is open for the duration of the test; the call only reads flags.
        unsafe { libc::fcntl(fd, command) }
    }

    // KNSH-019: the shell inherits the write end (not close-on-exec) and never blocks on it; knsh alone reads.
    #[test]
    fn telemetry_pipe_write_end_is_inheritable_and_non_blocking() {
        let pipe = TelemetryPipe::new().expect("pipe");
        let (mut reader, writer) = pipe.into_parts();
        assert_eq!(flags(writer.as_raw_fd(), libc::F_GETFD) & libc::FD_CLOEXEC, 0);
        assert_ne!(flags(writer.as_raw_fd(), libc::F_GETFL) & libc::O_NONBLOCK, 0);
        assert_ne!(flags(reader.as_raw_fd(), libc::F_GETFD) & libc::FD_CLOEXEC, 0);

        let mut writer = File::from(writer);
        writer.write_all(b"line\n").expect("write");
        drop(writer);
        let mut text = String::new();
        reader.read_to_string(&mut text).expect("read");
        assert_eq!(text, "line\n");
    }

    // KNSH-019 / FR-SES-22: a full pipe fails the write at once (EAGAIN) instead of delaying the prompt.
    #[test]
    fn full_telemetry_pipe_fails_writes_instead_of_blocking() {
        let (_reader, writer) = TelemetryPipe::new().expect("pipe").into_parts();
        let mut writer = File::from(writer);
        let chunk = [b'x'; 4096];
        let error = loop {
            if let Err(error) = writer.write(&chunk) {
                break error;
            }
        };
        assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
    }

    fn current_handler(signal: c_int) -> libc::sighandler_t {
        // SAFETY: an all-zero `sigaction` is valid storage, filled in by the query below.
        let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
        // SAFETY: a null new action only queries; `action` is valid writable storage.
        unsafe { libc::sigaction(signal, std::ptr::null(), &raw mut action) };
        action.sa_sigaction
    }

    // KNSH-019: knsh ignores terminal job-control signals only while the guard lives, then restores them.
    #[test]
    fn job_signals_are_ignored_while_the_guard_lives() {
        let before: Vec<_> = JOB_SIGNALS.iter().map(|signal| current_handler(*signal)).collect();
        let guard = JobSignalsIgnored::install().expect("install");
        for signal in JOB_SIGNALS {
            assert_eq!(current_handler(signal), libc::SIG_IGN);
        }
        drop(guard);
        let after: Vec<_> = JOB_SIGNALS.iter().map(|signal| current_handler(*signal)).collect();
        assert_eq!(before, after);
    }

    /// Set in the re-executed test process to the signal it must end by.
    const RERAISE_CHILD: &str = "KNSH_TEST_RERAISE_SIGNAL";

    // KNSH-019: knsh ends by the signal that ended the hosted shell, including SIGKILL, whose disposition cannot
    // be changed. Runs in a re-executed copy of this test binary, since the signal ends the process.
    #[test]
    fn reraise_ends_the_process_by_the_signal() {
        use std::os::unix::process::ExitStatusExt;

        if let Some(signal) = std::env::var_os(RERAISE_CHILD) {
            let signal: c_int = signal.to_str().and_then(|text| text.parse().ok()).expect("signal");
            reraise_default(signal);
            std::process::exit(0);
        }
        for signal in [libc::SIGTERM, libc::SIGKILL, libc::SIGPIPE, libc::SIGINT] {
            let status = std::process::Command::new(std::env::current_exe().expect("test binary"))
                .args([
                    "--exact",
                    "macos::shell_host::tests::reraise_ends_the_process_by_the_signal",
                ])
                .env(RERAISE_CHILD, signal.to_string())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .expect("re-run");
            assert_eq!(status.signal(), Some(signal), "signal {signal}");
        }
    }

    #[test]
    fn reraise_returns_for_numbers_that_are_not_signals() {
        reraise_default(0);
        reraise_default(NSIG);
        reraise_default(-1);
    }
}
