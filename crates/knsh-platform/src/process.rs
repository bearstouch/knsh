//! Starting, signalling and waiting for processes.
//!
//! Every process starts as the leader of a new process group, so a command and everything it forks can be stopped
//! together. Signals go only to groups this instance created and still holds unreaped: while the leader is
//! unreaped (running or a zombie) its id, which is also the group id, cannot be reused by the system. Once reaped,
//! the group is forgotten and signalling it is refused, so a reused id is never signalled (CLAUDE.md
//! "Concurrency").

use std::ffi::OsString;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::path::PathBuf;
use std::sync::Arc;

use crate::error::PlatformError;

/// An open descriptor a spawn request hands to the child, shared so the request stays cheap to clone.
///
/// Two values are equal when they hold the same descriptor number; the descriptor is closed when the last clone is
/// dropped. The child receives its own copy, so dropping this after [`Processes::spawn`] returns never affects it.
#[derive(Clone)]
pub struct SharedFd(Arc<OwnedFd>);

impl SharedFd {
    /// Shares `fd`.
    #[must_use]
    pub fn new(fd: OwnedFd) -> Self {
        Self(Arc::new(fd))
    }

    /// A new descriptor for the same open file (`dup`, close-on-exec), owned by the caller.
    ///
    /// # Errors
    ///
    /// The `dup` failed (`EMFILE`).
    pub fn try_clone_owned(&self) -> std::io::Result<OwnedFd> {
        self.0.try_clone()
    }
}

impl AsRawFd for SharedFd {
    fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }
}

impl fmt::Debug for SharedFd {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SharedFd({})", self.as_raw_fd())
    }
}

impl PartialEq for SharedFd {
    fn eq(&self, other: &Self) -> bool {
        self.as_raw_fd() == other.as_raw_fd()
    }
}

impl Eq for SharedFd {}

impl Hash for SharedFd {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.as_raw_fd().hash(state);
    }
}

/// What a child's standard input, output and error are connected to.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub enum Stdio {
    /// `/dev/null` for all three. The default: nothing leaks to or from the engine's own descriptors.
    #[default]
    Null,
    /// The engine's own descriptors.
    Inherit,
    /// These three descriptors, in order, as the child's 0, 1 and 2: for example a caller's stdio received over a
    /// socket (KNSH-051).
    Passed(Box<[SharedFd; 3]>),
}

/// A request to start one program.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpawnRequest {
    /// Absolute path of the executable. Not searched in `PATH`: the engine always names what it runs.
    pub program: PathBuf,
    /// `argv[0]`, or `None` for `program` itself. A shell passes the command name as written (`ls`), as bash does
    /// (KNSH-096).
    pub argv0: Option<OsString>,
    /// Arguments after `argv[0]`.
    pub args: Vec<OsString>,
    /// The complete environment. Always explicit: the engine's own environment is never inherited by accident.
    pub env: Vec<(OsString, OsString)>,
    /// Working directory, or `None` for the caller's.
    pub cwd: Option<PathBuf>,
    /// Standard descriptors.
    pub stdio: Stdio,
    /// Descriptors above stdio the child keeps open under their own numbers (their `FD_CLOEXEC` is cleared in the
    /// child only), for example a status pipe whose number the child is told in an argument. Everything else the
    /// engine has open stays close-on-exec and never reaches the child.
    pub inherit: Vec<SharedFd>,
    /// Descriptors the child gets under numbers of the caller's choosing, after [`stdio`](Self::stdio) is set up: a
    /// shell's redirections (`3>file`, `2>&1`, `>&-`), KNSH-099. Each target number appears at most once and never
    /// as an [`inherit`](Self::inherit) descriptor's number; numbers 0 to 2 here replace what `stdio` put there.
    /// Every source is read before any target is written, so `1>&2 2>&1` swaps rather than collapses. Empty for
    /// every other caller.
    pub placements: Vec<Placement>,
}

/// Most descriptor numbers a [`Placement`] may target: 0 to `MAX_PLACED_FD`. Below macOS's default soft limit on open
/// descriptors (256), so a placement never fails in the child for a number its limit does not cover.
pub const MAX_PLACED_FD: i32 = 255;

/// One descriptor number of a child and what it holds ([`SpawnRequest::placements`]).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Placement {
    /// The number in the child, 0 to [`MAX_PLACED_FD`].
    pub target: i32,
    /// What the number holds, or `None` to close it.
    pub source: Option<PlacementSource>,
}

/// Where a [`Placement`]'s descriptor comes from.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum PlacementSource {
    /// A descriptor of this process. The child gets its own copy; this one stays as it is.
    Shared(SharedFd),
    /// The child's own standard descriptor 0, 1 or 2 as [`SpawnRequest::stdio`] set it up, before any placement
    /// (for `2>&1` when standard output is the caller's).
    Stdio(i32),
}

impl SpawnRequest {
    /// A request for `program` (also its `argv[0]`) with no arguments, an empty environment, the caller's working directory and
    /// [`Stdio::Null`].
    #[must_use]
    pub fn new(program: impl Into<PathBuf>) -> Self {
        Self {
            program: program.into(),
            argv0: None,
            args: Vec::new(),
            env: Vec::new(),
            cwd: None,
            stdio: Stdio::Null,
            inherit: Vec::new(),
            placements: Vec::new(),
        }
    }

    /// Appends one argument.
    #[must_use]
    pub fn arg(mut self, arg: impl Into<OsString>) -> Self {
        self.args.push(arg.into());
        self
    }

    /// Adds one environment variable.
    #[must_use]
    pub fn env(mut self, key: impl Into<OsString>, value: impl Into<OsString>) -> Self {
        self.env.push((key.into(), value.into()));
        self
    }
}

/// A process group created by [`Processes::spawn`]. Its value equals the leader's process id.
///
/// The id alone grants nothing: [`Processes`] checks it against the groups it holds before every signal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProcessGroupId(i32);

impl ProcessGroupId {
    /// Wraps a raw group id, for example one read back from a record. Using it with a [`Processes`] that did not
    /// create it fails with [`PlatformError::UnknownProcessGroup`].
    #[must_use]
    pub const fn from_raw(id: i32) -> Self {
        Self(id)
    }

    /// The raw group id.
    #[must_use]
    pub const fn as_raw(self) -> i32 {
        self.0
    }
}

/// Signals the engine sends to process groups.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Signal {
    /// `SIGINT`: interrupt, as from Ctrl-C.
    Interrupt,
    /// `SIGTERM`: polite termination.
    Terminate,
    /// `SIGKILL`: forced termination; cannot be caught.
    Kill,
    /// `SIGHUP`: the controlling terminal went away.
    Hangup,
    /// `SIGSTOP`: suspend; cannot be caught.
    Stop,
    /// `SIGCONT`: resume after a stop.
    Continue,
}

impl Signal {
    /// The signal number on this platform.
    #[must_use]
    pub fn number(self) -> i32 {
        match self {
            Self::Interrupt => libc::SIGINT,
            Self::Terminate => libc::SIGTERM,
            Self::Kill => libc::SIGKILL,
            Self::Hangup => libc::SIGHUP,
            Self::Stop => libc::SIGSTOP,
            Self::Continue => libc::SIGCONT,
        }
    }
}

/// How a process ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExitStatus {
    /// It called `exit` with this code (0 to 255).
    Exited(i32),
    /// A signal with this number ended it.
    Signalled(i32),
}

/// Starts and controls processes. Object safe: hold it as `Arc<dyn Processes>`.
pub trait Processes: Send + Sync {
    /// Starts `request.program` as the leader of a new process group and keeps a handle to it.
    ///
    /// # Errors
    ///
    /// [`PlatformError::InvalidPath`] if `program` is relative; [`PlatformError::Os`] with
    /// [`Operation::Spawn`](crate::Operation::Spawn) if the program cannot be started (for example `ENOENT`).
    fn spawn(&self, request: &SpawnRequest) -> Result<ProcessGroupId, PlatformError>;

    /// Sends `signal` to every process in `group`.
    ///
    /// # Errors
    ///
    /// [`PlatformError::UnknownProcessGroup`] unless `group` was created by this instance and not yet reaped by
    /// [`Processes::wait`] or [`Processes::try_wait`]; [`PlatformError::Os`] with
    /// [`Operation::Signal`](crate::Operation::Signal) if the system refuses.
    fn signal(&self, group: ProcessGroupId, signal: Signal) -> Result<(), PlatformError>;

    /// Blocks until the group leader exits, reaps it and forgets the group. Other threads may signal the group while
    /// this call waits.
    ///
    /// Other members of the group that outlive the leader are no longer reachable afterwards: signal the group
    /// before waiting if they must stop too.
    ///
    /// # Errors
    ///
    /// [`PlatformError::UnknownProcessGroup`] for a group this instance does not hold, including one another
    /// thread reaped first; [`PlatformError::Os`] with [`Operation::Wait`](crate::Operation::Wait).
    fn wait(&self, group: ProcessGroupId) -> Result<ExitStatus, PlatformError>;

    /// Whether the group leader has exited, without reaping it: the group stays held, so it can still be signalled
    /// (for example to stop members that outlive the leader) before [`Processes::wait`] reaps it. Never blocks.
    ///
    /// On macOS, signalling a group whose only member left is the unreaped leader fails with `EPERM`
    /// ([`PlatformError::Os`]): nothing is left to stop, so a caller stopping stragglers may ignore that error.
    ///
    /// # Errors
    ///
    /// As [`Processes::wait`].
    fn exited(&self, group: ProcessGroupId) -> Result<bool, PlatformError>;

    /// Like [`Processes::wait`] but returns `Ok(None)` at once if the leader is still running.
    ///
    /// # Errors
    ///
    /// As [`Processes::wait`].
    fn try_wait(&self, group: ProcessGroupId) -> Result<Option<ExitStatus>, PlatformError>;
}
