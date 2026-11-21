//! What a shell's job control and its `time` keyword need besides processes (KNSH-100): the controlling terminal
//! and the clocks `time` reads.
//!
//! An interactive shell owns its terminal: it gives the terminal to each foreground job's process group and takes it
//! back when the job ends or stops, so the terminal's Ctrl-Z and Ctrl-C reach the job and never the shell
//! ([`JobTerminal`]). The `time` keyword reports the real time a pipeline took and the CPU time the shell and its
//! children spent meanwhile ([`ShellTimes`]).

use std::time::Duration;

/// This platform's numbers of the signals job control names, for code that reports them (`Stopped(SIGTTIN)`,
/// `Terminated: 15`) without a `libc` dependency of its own, and the names bash gives every signal (`trap -l`,
/// KNSH-104).
pub mod signals {
    pub use libc::{
        SIGABRT, SIGALRM, SIGHUP, SIGINT, SIGKILL, SIGPIPE, SIGQUIT, SIGSEGV, SIGSTOP, SIGTERM, SIGTSTP, SIGTTIN,
        SIGTTOU,
    };

    /// Every signal of this platform with the name bash gives it (its `signal_names` table, as `trap -l` prints
    /// it), in increasing order of number: 1 to 31 on macOS.
    #[cfg(target_os = "macos")]
    pub const NAMES: &[(i32, &str)] = &[
        (libc::SIGHUP, "SIGHUP"),
        (libc::SIGINT, "SIGINT"),
        (libc::SIGQUIT, "SIGQUIT"),
        (libc::SIGILL, "SIGILL"),
        (libc::SIGTRAP, "SIGTRAP"),
        (libc::SIGABRT, "SIGABRT"),
        (libc::SIGEMT, "SIGEMT"),
        (libc::SIGFPE, "SIGFPE"),
        (libc::SIGKILL, "SIGKILL"),
        (libc::SIGBUS, "SIGBUS"),
        (libc::SIGSEGV, "SIGSEGV"),
        (libc::SIGSYS, "SIGSYS"),
        (libc::SIGPIPE, "SIGPIPE"),
        (libc::SIGALRM, "SIGALRM"),
        (libc::SIGTERM, "SIGTERM"),
        (libc::SIGURG, "SIGURG"),
        (libc::SIGSTOP, "SIGSTOP"),
        (libc::SIGTSTP, "SIGTSTP"),
        (libc::SIGCONT, "SIGCONT"),
        (libc::SIGCHLD, "SIGCHLD"),
        (libc::SIGTTIN, "SIGTTIN"),
        (libc::SIGTTOU, "SIGTTOU"),
        (libc::SIGIO, "SIGIO"),
        (libc::SIGXCPU, "SIGXCPU"),
        (libc::SIGXFSZ, "SIGXFSZ"),
        (libc::SIGVTALRM, "SIGVTALRM"),
        (libc::SIGPROF, "SIGPROF"),
        (libc::SIGWINCH, "SIGWINCH"),
        (libc::SIGINFO, "SIGINFO"),
        (libc::SIGUSR1, "SIGUSR1"),
        (libc::SIGUSR2, "SIGUSR2"),
    ];

    /// Every signal of this platform with the name bash gives it, in increasing order of number: the 31 standard
    /// signals of Linux (bash's real-time signal names are not listed).
    #[cfg(not(target_os = "macos"))]
    pub const NAMES: &[(i32, &str)] = &[
        (libc::SIGHUP, "SIGHUP"),
        (libc::SIGINT, "SIGINT"),
        (libc::SIGQUIT, "SIGQUIT"),
        (libc::SIGILL, "SIGILL"),
        (libc::SIGTRAP, "SIGTRAP"),
        (libc::SIGABRT, "SIGABRT"),
        (libc::SIGBUS, "SIGBUS"),
        (libc::SIGFPE, "SIGFPE"),
        (libc::SIGKILL, "SIGKILL"),
        (libc::SIGUSR1, "SIGUSR1"),
        (libc::SIGSEGV, "SIGSEGV"),
        (libc::SIGUSR2, "SIGUSR2"),
        (libc::SIGPIPE, "SIGPIPE"),
        (libc::SIGALRM, "SIGALRM"),
        (libc::SIGTERM, "SIGTERM"),
        (libc::SIGSTKFLT, "SIGSTKFLT"),
        (libc::SIGCHLD, "SIGCHLD"),
        (libc::SIGCONT, "SIGCONT"),
        (libc::SIGSTOP, "SIGSTOP"),
        (libc::SIGTSTP, "SIGTSTP"),
        (libc::SIGTTIN, "SIGTTIN"),
        (libc::SIGTTOU, "SIGTTOU"),
        (libc::SIGURG, "SIGURG"),
        (libc::SIGXCPU, "SIGXCPU"),
        (libc::SIGXFSZ, "SIGXFSZ"),
        (libc::SIGVTALRM, "SIGVTALRM"),
        (libc::SIGPROF, "SIGPROF"),
        (libc::SIGWINCH, "SIGWINCH"),
        (libc::SIGIO, "SIGIO"),
        (libc::SIGPWR, "SIGPWR"),
        (libc::SIGSYS, "SIGSYS"),
    ];

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::process::SignalSet;

        // KNSH-104: names follow numbers, as `trap -l` lists them.
        #[test]
        fn names_are_in_increasing_order_of_number() {
            assert!(NAMES.windows(2).all(|pair| pair[0].0 < pair[1].0));
            assert_eq!(NAMES.first(), Some(&(SIGHUP, "SIGHUP")));
            assert!(NAMES.iter().all(|(_, name)| name.starts_with("SIG")));
        }

        // KNSH-104: a set holds only signal numbers 1 to 63.
        #[test]
        fn signal_sets_hold_numbers_one_to_sixty_three() {
            let mut set: SignalSet = [SIGINT, SIGTERM, 0, 64, -1].into_iter().collect();
            assert!(set.contains(SIGINT) && set.contains(SIGTERM));
            assert_eq!(set.iter().collect::<Vec<_>>(), [SIGINT, SIGTERM]);
            set.remove(SIGINT);
            assert!(!set.contains(SIGINT) && !set.is_empty());
            assert!(SignalSet::new().is_empty());
        }
    }
}

use crate::error::PlatformError;
use crate::process::{ProcessGroupId, SharedFd};

/// The controlling terminal of an interactive shell with job control. Object safe: hold it as
/// `Arc<dyn JobTerminal>`.
pub trait JobTerminal: Send + Sync {
    /// The terminal itself, for [`ChildOptions::terminal`](crate::ChildOptions::terminal): the first process of a
    /// foreground job takes the terminal for its new group before it executes.
    fn descriptor(&self) -> SharedFd;

    /// Makes `group` the terminal's foreground process group, or with `None` the shell's own group again, restoring
    /// the terminal modes the shell had when it took the terminal (a job may leave them changed).
    ///
    /// The caller passes only the group of a job it still holds a member of unreaped, so the id cannot name a
    /// stranger's group.
    ///
    /// # Errors
    ///
    /// [`PlatformError::Os`] with [`Operation::Terminal`](crate::Operation::Terminal) if the system refuses (the
    /// group is gone, the terminal was revoked).
    fn set_foreground(&self, group: Option<ProcessGroupId>) -> Result<(), PlatformError>;
}

/// CPU time, split as `getrusage` splits it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CpuTimes {
    /// Time spent running the program's own code.
    pub user: Duration,
    /// Time the system spent on the program's behalf.
    pub system: Duration,
}

impl CpuTimes {
    /// `self - earlier`, field by field, never below zero.
    #[must_use]
    pub fn since(self, earlier: Self) -> Self {
        Self {
            user: self.user.saturating_sub(earlier.user),
            system: self.system.saturating_sub(earlier.system),
        }
    }
}

/// The clocks of the `time` keyword. Object safe: hold it as `Arc<dyn ShellTimes>`.
pub trait ShellTimes: Send + Sync {
    /// A monotonic reading: only differences between two readings mean anything.
    fn elapsed(&self) -> Duration;

    /// The CPU time of this process and of its children reaped so far, added together, as bash adds them for
    /// `time`.
    fn cpu(&self) -> CpuTimes;
}
