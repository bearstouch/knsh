//! The controlling terminal of an interactive shell and the clocks of `time`, on the real system (KNSH-100).

use std::os::fd::AsRawFd;
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use crate::error::{Operation, PlatformError};
use crate::job::{CpuTimes, JobTerminal, ShellTimes};
use crate::process::{ProcessGroupId, SharedFd, SignalSet};

/// Signals an interactive shell with job control ignores itself, as bash does: the terminal's suspend character and
/// the stops for reading or writing the terminal from a background group (the shell hands the terminal over with
/// `tcsetpgrp`, which would otherwise stop it).
const IGNORED: [libc::c_int; 3] = [libc::SIGTSTP, libc::SIGTTIN, libc::SIGTTOU];

/// The terminal an interactive shell runs on, taken over for job control by [`SystemTerminal::take`].
///
/// Taking it changes the whole process: it ignores `SIGTSTP`, `SIGTTIN` and `SIGTTOU` and leads its own process
/// group, the terminal's foreground group. Dropping it restores the three signals' previous actions. Only a process
/// that is an interactive shell (the `knsh` front end with the native interpreter) takes its terminal.
pub struct SystemTerminal {
    /// The terminal.
    fd: SharedFd,
    /// The shell's terminal modes when it took the terminal, restored when it takes the terminal back.
    modes: Mutex<libc::termios>,
    /// The actions the ignored signals had before.
    previous: Vec<(libc::c_int, libc::sigaction)>,
}

impl std::fmt::Debug for SystemTerminal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SystemTerminal")
            .field("fd", &self.fd)
            .finish_non_exhaustive()
    }
}

fn terminal_error() -> PlatformError {
    PlatformError::from_io(Operation::Terminal, &std::io::Error::last_os_error())
}

impl SystemTerminal {
    /// Takes `fd`, a terminal, for job control: ignores the job-control signals, makes this process the leader of
    /// its own group (unless it already is, or leads its session) and that group the terminal's foreground group,
    /// and saves the terminal modes.
    ///
    /// # Errors
    ///
    /// [`PlatformError::Os`] with [`Operation::Terminal`]: `ENOTTY` if `fd` is not a terminal, or the system's
    /// refusal of `tcsetpgrp` or `tcgetattr`; [`Operation::SignalDisposition`] if a signal could not be ignored.
    /// Nothing is left changed on failure but what succeeded before it (signals already ignored are restored).
    pub fn take(fd: SharedFd) -> Result<Self, PlatformError> {
        let raw = fd.as_raw_fd();
        // SAFETY: `isatty` takes a plain integer and touches no memory.
        if unsafe { libc::isatty(raw) } != 1 {
            return Err(PlatformError::Os {
                operation: Operation::Terminal,
                errno: libc::ENOTTY,
            });
        }
        let mut terminal = Self {
            fd,
            // SAFETY: an all-zero `termios` is a valid value (integers and arrays of integers); filled in below.
            modes: Mutex::new(unsafe { std::mem::zeroed() }),
            previous: Vec::new(),
        };
        for signal in IGNORED {
            // SAFETY: an all-zero `sigaction` is a valid value (empty mask, no flags); the handler is set below.
            let mut ignore: libc::sigaction = unsafe { std::mem::zeroed() };
            ignore.sa_sigaction = libc::SIG_IGN;
            // SAFETY: as above; overwritten by `sigaction` on success.
            let mut old: libc::sigaction = unsafe { std::mem::zeroed() };
            // SAFETY: both pointers refer to live, initialised `sigaction` values for the whole call.
            if unsafe { libc::sigaction(signal, &raw const ignore, &raw mut old) } != 0 {
                return Err(PlatformError::from_io(
                    Operation::SignalDisposition,
                    &std::io::Error::last_os_error(),
                ));
            }
            terminal.previous.push((signal, old));
        }
        // SAFETY: `getpid`, `getpgrp`, `getsid` and `setpgid` take plain integers and touch no memory.
        unsafe {
            let pid = libc::getpid();
            if libc::getpgrp() != pid && libc::getsid(0) != pid {
                // A refusal leaves the shell in its group; `tcsetpgrp` below then still names a group it is in.
                libc::setpgid(0, 0);
            }
            if libc::tcsetpgrp(raw, libc::getpgrp()) != 0 {
                return Err(terminal_error());
            }
        }
        {
            let mut modes = terminal.modes.lock().unwrap_or_else(PoisonError::into_inner);
            // SAFETY: `modes` is a valid, writable `termios` for the whole call.
            if unsafe { libc::tcgetattr(raw, &raw mut *modes) } != 0 {
                return Err(terminal_error());
            }
        }
        Ok(terminal)
    }
}

impl JobTerminal for SystemTerminal {
    fn descriptor(&self) -> SharedFd {
        self.fd.clone()
    }

    fn set_foreground(&self, group: Option<ProcessGroupId>) -> Result<(), PlatformError> {
        let raw = self.fd.as_raw_fd();
        // SAFETY: `getpgrp` and `tcsetpgrp` take plain integers and touch no memory. This process ignores
        // `SIGTTOU` (`take`), so setting the foreground group from a background group does not stop it.
        let group = group.map_or_else(|| unsafe { libc::getpgrp() }, ProcessGroupId::as_raw);
        // SAFETY: as above.
        if unsafe { libc::tcsetpgrp(raw, group) } != 0 {
            return Err(terminal_error());
        }
        // SAFETY: `getpgrp` takes nothing and touches no memory.
        if group == unsafe { libc::getpgrp() } {
            let modes = self.modes.lock().unwrap_or_else(PoisonError::into_inner);
            // SAFETY: `modes` is a valid `termios` read by the call, which touches no other memory.
            if unsafe { libc::tcsetattr(raw, libc::TCSADRAIN, &raw const *modes) } != 0 {
                return Err(terminal_error());
            }
        }
        Ok(())
    }
}

impl Drop for SystemTerminal {
    fn drop(&mut self) {
        for (signal, old) in self.previous.drain(..).rev() {
            // SAFETY: `old` is a live, initialised `sigaction` that `sigaction` returned for this signal.
            unsafe { libc::sigaction(signal, &raw const old, std::ptr::null_mut()) };
        }
    }
}

/// The `time` keyword's clocks on the real system: a monotonic clock and `getrusage` of this process plus its
/// reaped children.
///
/// `getrusage` counts every thread of the process and every child it has reaped, whichever thread reaped it: inside
/// a process running more than one shell at once the figures include the others' work.
#[derive(Debug)]
pub struct SystemShellTimes {
    /// The origin of [`ShellTimes::elapsed`].
    origin: Instant,
}

impl Default for SystemShellTimes {
    fn default() -> Self {
        Self::new()
    }
}

impl SystemShellTimes {
    /// Clocks starting now.
    #[must_use]
    pub fn new() -> Self {
        Self { origin: Instant::now() }
    }
}

/// The CPU time `getrusage(who)` reports, or zero if the call fails (it only fails for a bad `who`).
fn usage(who: libc::c_int) -> CpuTimes {
    // SAFETY: an all-zero `rusage` is a valid value (integers and `timeval`s).
    let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
    // SAFETY: `usage` is a valid, writable `rusage` for the whole call.
    if unsafe { libc::getrusage(who, &raw mut usage) } != 0 {
        return CpuTimes::default();
    }
    let duration = |time: libc::timeval| {
        let seconds = u64::try_from(time.tv_sec).unwrap_or(0);
        let micros = u64::try_from(time.tv_usec).unwrap_or(0);
        Duration::from_secs(seconds) + Duration::from_micros(micros)
    };
    CpuTimes {
        user: duration(usage.ru_utime),
        system: duration(usage.ru_stime),
    }
}

impl ShellTimes for SystemShellTimes {
    fn elapsed(&self) -> Duration {
        self.origin.elapsed()
    }

    fn cpu(&self) -> CpuTimes {
        let own = usage(libc::RUSAGE_SELF);
        let children = usage(libc::RUSAGE_CHILDREN);
        CpuTimes {
            user: own.user + children.user,
            system: own.system + children.system,
        }
    }
}

/// The signals this process ignores now (`SIG_IGN`), among those [`signals::NAMES`](crate::signals::NAMES) lists.
/// Read at start-up, before anything changes them, they are the signals a shell was started ignoring, which bash keeps
/// ignored and never lets a non-interactive script trap (KNSH-104). A signal whose disposition cannot be read is left
/// out.
#[must_use]
pub fn ignored_signals() -> SignalSet {
    let mut set = SignalSet::new();
    for &(signal, _) in crate::signals::NAMES {
        // SAFETY: an all-zero `sigaction` is a valid value (a plain C struct); `sigaction` with a null new action
        // only reads the disposition into `old`, which lives for the call.
        let ignored = unsafe {
            let mut old: libc::sigaction = std::mem::zeroed();
            libc::sigaction(signal, std::ptr::null(), &raw mut old) == 0 && old.sa_sigaction == libc::SIG_IGN
        };
        if ignored {
            set.insert(signal);
        }
    }
    set
}

#[cfg(test)]
mod tests {
    use super::*;

    // KNSH-104: `SIGKILL` can never be ignored, so it is never reported.
    #[test]
    fn ignored_signals_never_include_kill() {
        assert!(!ignored_signals().contains(libc::SIGKILL));
    }

    #[test]
    fn take_refuses_what_is_not_a_terminal() {
        let file = SharedFd::new(std::fs::File::open("/dev/null").unwrap().into());
        let error = SystemTerminal::take(file).unwrap_err();
        assert_eq!(error.errno(), Some(libc::ENOTTY));
    }

    #[test]
    fn cpu_times_grow_and_elapsed_is_monotonic() {
        let times = SystemShellTimes::new();
        let before = (times.elapsed(), times.cpu());
        let mut x = 0u64;
        for i in 0..2_000_000u64 {
            x = x.wrapping_mul(31).wrapping_add(i);
        }
        std::hint::black_box(x);
        let after = (times.elapsed(), times.cpu());
        assert!(after.0 >= before.0);
        assert!(after.1.user + after.1.system >= before.1.user + before.1.system);
    }
}
