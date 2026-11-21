//! What a shell's job control and its `time` keyword need besides processes (KNSH-100): the controlling terminal
//! and the clocks `time` reads.
//!
//! An interactive shell owns its terminal: it gives the terminal to each foreground job's process group and takes it
//! back when the job ends or stops, so the terminal's Ctrl-Z and Ctrl-C reach the job and never the shell
//! ([`JobTerminal`]). The `time` keyword reports the real time a pipeline took and the CPU time the shell and its
//! children spent meanwhile ([`ShellTimes`]).

use std::time::Duration;

/// This platform's numbers of the signals job control names, for code that reports them (`Stopped(SIGTTIN)`,
/// `Terminated: 15`) without a `libc` dependency of its own.
pub mod signals {
    pub use libc::{
        SIGABRT, SIGALRM, SIGHUP, SIGINT, SIGKILL, SIGPIPE, SIGQUIT, SIGSEGV, SIGSTOP, SIGTERM, SIGTSTP, SIGTTIN,
        SIGTTOU,
    };
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
