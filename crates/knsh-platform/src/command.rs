//! Running one external command for the shell interpreter and reporting how it ended (KNSH-096).
//!
//! The interpreter (`knsh-interp`) finds the program on `PATH` itself and hands over the absolute path, the argument
//! vector and the complete environment. [`CommandSpawner`] starts it, waits for it and reports a
//! [`CommandOutcome`], which the interpreter turns into bash's exit status: the program's own code, `128 + n` for
//! a program killed by signal `n`, 127 when the program vanished before `exec`, 126 when the system refused to run it
//! (NFR-COMPAT-09).
//!
//! Every external command of a script goes through this one trait. That is the seam KNSH-108 uses: a spawner that
//! wraps another one sees each resolved command before it starts, and can submit it for a decision (and refuse it)
//! before delegating. [`ProcessCommandSpawner`] is the plain implementation over [`Processes`].
//!
//! Pipelines, background jobs and job control (KNSH-100) need commands that run side by side: the interpreter
//! starts each with [`CommandSpawner::start`], placed in a process group as [`ChildOptions`] says, and waits for it
//! with [`CommandSpawner::wait`], which also reports stops (Ctrl-Z). [`CommandSpawner::run`] starts one command in
//! the caller's group and waits for it to end.

use std::ffi::OsString;
use std::path::PathBuf;
use std::sync::Arc;

use crate::error::{Operation, PlatformError};
use crate::process::{
    ChildEvent, ChildHandle, ChildOptions, ExitStatus, Placement, PlacementSource, ProcessGroupId, Processes, SharedFd,
    Signal, SpawnRequest, Stdio,
};

/// One external command, resolved by the interpreter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandRequest {
    /// Absolute path of the program, as found on `PATH` (or the name joined to the working directory when it holds a
    /// `/`). Not canonicalised: bash executes the path it found, symlinks included.
    pub program: PathBuf,
    /// `argv[0]`: the command name as written, as bash passes it.
    pub argv0: OsString,
    /// The arguments after `argv[0]`.
    pub args: Vec<OsString>,
    /// The complete environment: the shell's exported variables and the command's own assignments.
    pub env: Vec<(OsString, OsString)>,
    /// The shell's working directory, absolute.
    pub cwd: PathBuf,
    /// The command's whole descriptor table, by number in increasing order: what the shell's redirections left
    /// (KNSH-099). A number not listed is closed in the command, so nothing reaches it that the shell did not pass
    /// (bash passes every descriptor it holds open for the script and none of its own). [`standard_descriptors`]
    /// is the table of a command without redirections.
    ///
    /// [`standard_descriptors`]: CommandRequest::standard_descriptors
    pub descriptors: Vec<(i32, ChildDescriptor)>,
}

impl CommandRequest {
    /// Standard input, output and error as the spawner's own: the table of a command without redirections.
    #[must_use]
    pub fn standard_descriptors() -> Vec<(i32, ChildDescriptor)> {
        StandardStream::ALL
            .iter()
            .map(|&stream| (stream.number(), ChildDescriptor::Standard(stream)))
            .collect()
    }
}

/// One of the three standard descriptors a [`CommandSpawner`] gives every command it starts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum StandardStream {
    /// Standard input, descriptor 0.
    Input,
    /// Standard output, descriptor 1.
    Output,
    /// Standard error, descriptor 2.
    Error,
}

impl StandardStream {
    /// The three, in descriptor order.
    pub const ALL: [Self; 3] = [Self::Input, Self::Output, Self::Error];

    /// The descriptor number: 0, 1 or 2.
    #[must_use]
    pub const fn number(self) -> i32 {
        match self {
            Self::Input => 0,
            Self::Output => 1,
            Self::Error => 2,
        }
    }
}

/// What one descriptor of a command holds.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ChildDescriptor {
    /// One of the spawner's standard descriptors (what a command gets without redirections): `2>&1` while standard
    /// output is the shell's own makes descriptor 2 `Standard(Output)`.
    Standard(StandardStream),
    /// A file, pipe or other descriptor the shell opened (`>file`, `<<<text`, `exec 3>file`).
    Open(SharedFd),
}

/// How an external command ended, as far as the shell's exit status is concerned.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CommandOutcome {
    /// It ran and ended normally or by a signal.
    Finished(ExitStatus),
    /// `exec` reported that the program does not exist (`ENOENT`, for example a file removed after the lookup, or a
    /// missing `#!` interpreter): bash reports 127.
    NotFound,
    /// `exec` refused to run the program (`EACCES`, `EISDIR`, `ENOEXEC`, a bad binary format and the like): bash
    /// reports 126.
    NotExecutable,
}

/// What [`CommandSpawner::start`] did with a command.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Started {
    /// The command is running: wait for it with [`CommandSpawner::wait`].
    Running(ChildHandle),
    /// It never ran: [`CommandOutcome::NotFound`] or [`CommandOutcome::NotExecutable`], with the meaning those have
    /// for [`CommandSpawner::run`] (a refusal by a deciding wrapper included, KNSH-108).
    Refused(CommandOutcome),
}

/// Starts external commands and waits for them. Object safe: hold it as `Arc<dyn CommandSpawner>`.
///
/// Implementations may refuse a command before it starts (KNSH-108) by returning
/// [`Started::Refused`] with [`CommandOutcome::NotExecutable`] after reporting the reason themselves.
pub trait CommandSpawner: Send + Sync {
    /// Starts `request` placed as `options` says, without waiting for it.
    ///
    /// # Errors
    ///
    /// A failure that is not the program's fault and has no bash exit status, for example no process could be
    /// created (`EAGAIN`), or [`PlatformError::UnknownProcessGroup`] for a group to join that is gone. The
    /// interpreter stops the script on it.
    fn start(&self, request: &CommandRequest, options: &ChildOptions) -> Result<Started, PlatformError>;

    /// Blocks until `child` stops, continues or ends. After [`ChildEvent::Exited`] the handle is spent.
    ///
    /// # Errors
    ///
    /// Waiting failed, or the handle is not one this spawner gave out and still holds.
    fn wait(&self, child: ChildHandle) -> Result<ChildEvent, PlatformError>;

    /// Sends `signal` to the process group `group` of commands this spawner started, while it holds one of them
    /// unreaped (job control's `fg`, `bg`, and the supervisor's pause, FR-SES-10).
    ///
    /// # Errors
    ///
    /// [`PlatformError::UnknownProcessGroup`] when no member is held any more; the system's refusal otherwise.
    fn signal_job(&self, group: ProcessGroupId, signal: Signal) -> Result<(), PlatformError>;

    /// Runs `request` to completion in the caller's process group: [`CommandSpawner::start`] with default options,
    /// then [`CommandSpawner::wait`] until it ends (stops are waited through).
    ///
    /// # Errors
    ///
    /// As [`CommandSpawner::start`] and [`CommandSpawner::wait`].
    fn run(&self, request: &CommandRequest) -> Result<CommandOutcome, PlatformError> {
        match self.start(request, &ChildOptions::default())? {
            Started::Refused(outcome) => Ok(outcome),
            Started::Running(child) => loop {
                match self.wait(child)? {
                    ChildEvent::Exited(status) => return Ok(CommandOutcome::Finished(status)),
                    ChildEvent::Stopped(_) | ChildEvent::Continued => {}
                }
            },
        }
    }
}

/// [`CommandSpawner`] over [`Processes`]: each command starts with the given standard descriptors, in the process
/// group its [`ChildOptions`] name (the caller's own by default, as bash runs a script's commands).
#[derive(Clone)]
pub struct ProcessCommandSpawner {
    /// Starts and waits for the processes.
    processes: Arc<dyn Processes>,
    /// The standard descriptors every command gets.
    stdio: Stdio,
}

impl ProcessCommandSpawner {
    /// A spawner starting commands through `processes`, each with `stdio` as its standard descriptors.
    #[must_use]
    pub fn new(processes: Arc<dyn Processes>, stdio: Stdio) -> Self {
        Self { processes, stdio }
    }
}

impl std::fmt::Debug for ProcessCommandSpawner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProcessCommandSpawner")
            .field("stdio", &self.stdio)
            .finish_non_exhaustive()
    }
}

impl CommandSpawner for ProcessCommandSpawner {
    fn start(&self, request: &CommandRequest, options: &ChildOptions) -> Result<Started, PlatformError> {
        let spawn = SpawnRequest {
            program: request.program.clone(),
            argv0: Some(request.argv0.clone()),
            args: request.args.clone(),
            env: request.env.clone(),
            cwd: Some(request.cwd.clone()),
            stdio: self.stdio.clone(),
            inherit: Vec::new(),
            placements: placements(&request.descriptors),
        };
        match self.processes.spawn_child(&spawn, options) {
            Ok(child) => Ok(Started::Running(child)),
            Err(PlatformError::Os {
                operation: Operation::Spawn,
                errno,
            }) => exec_failure(errno).map(Started::Refused),
            Err(error) => Err(error),
        }
    }

    fn wait(&self, child: ChildHandle) -> Result<ChildEvent, PlatformError> {
        self.processes.wait_child(child)
    }

    fn signal_job(&self, group: ProcessGroupId, signal: Signal) -> Result<(), PlatformError> {
        self.processes.signal_job(group, signal)
    }
}

/// The placements that turn the spawner's standard descriptors into `descriptors`: every standard number the table
/// does not hold as the same stream is placed or closed, every number above them is placed. A table of the three
/// standard streams in place needs none, so a command without redirections spawns exactly as before KNSH-099.
fn placements(descriptors: &[(i32, ChildDescriptor)]) -> Vec<Placement> {
    let mut placements = Vec::new();
    for stream in StandardStream::ALL {
        let number = stream.number();
        if !descriptors.iter().any(|(target, _)| *target == number) {
            placements.push(Placement {
                target: number,
                source: None,
            });
        }
    }
    for (target, descriptor) in descriptors {
        let source = match descriptor {
            ChildDescriptor::Standard(held) if held.number() == *target => continue,
            ChildDescriptor::Standard(held) => PlacementSource::Stdio(held.number()),
            ChildDescriptor::Open(fd) => PlacementSource::Shared(fd.clone()),
        };
        placements.push(Placement {
            target: *target,
            source: Some(source),
        });
    }
    placements
}

/// The outcome of a spawn that failed with `errno`, as bash's `shell_execve` reports it: `ENOENT` is 127, every
/// other refusal by `exec` is 126. Running out of processes or descriptors is not an `exec` refusal and stays an
/// error, and so does a backend without [`Processes::spawn_child`] (`ENOTSUP`).
fn exec_failure(errno: i32) -> Result<CommandOutcome, PlatformError> {
    match errno {
        libc::ENOENT => Ok(CommandOutcome::NotFound),
        libc::EAGAIN | libc::EMFILE | libc::ENFILE | libc::ENOMEM | libc::ENOTSUP => Err(PlatformError::Os {
            operation: Operation::Spawn,
            errno,
        }),
        _ => Ok(CommandOutcome::NotExecutable),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{Script, ScriptedProcesses};

    fn request(program: &str) -> CommandRequest {
        CommandRequest {
            program: PathBuf::from(program),
            argv0: "tool".into(),
            args: vec!["a".into()],
            env: vec![("PATH".into(), "/bin".into())],
            cwd: PathBuf::from("/work"),
            descriptors: CommandRequest::standard_descriptors(),
        }
    }

    // NFR-COMPAT-09: the spawner hands over argv[0] as written, the environment and the working directory.
    #[test]
    fn passes_argv0_arguments_environment_and_directory() {
        let processes = Arc::new(ScriptedProcesses::new());
        processes.expect("/bin/tool", Script::Exits(3));
        let spawner = ProcessCommandSpawner::new(processes.clone(), Stdio::Null);
        let outcome = spawner.run(&request("/bin/tool")).unwrap();
        assert_eq!(outcome, CommandOutcome::Finished(ExitStatus::Exited(3)));
        let seen = &processes.spawned()[0];
        assert_eq!(seen.argv0.as_deref(), Some("tool".as_ref()));
        assert_eq!(seen.args, vec![OsString::from("a")]);
        assert_eq!(seen.cwd.as_deref(), Some("/work".as_ref()));
        assert_eq!(seen.env, vec![("PATH".into(), "/bin".into())]);
    }

    // NFR-COMPAT-09: ENOENT at exec is 127, any other exec refusal 126, as bash's shell_execve reports.
    #[test]
    fn maps_exec_failures_like_bash() {
        for (errno, outcome) in [
            (libc::ENOENT, CommandOutcome::NotFound),
            (libc::EACCES, CommandOutcome::NotExecutable),
            (libc::ENOEXEC, CommandOutcome::NotExecutable),
            (libc::EISDIR, CommandOutcome::NotExecutable),
        ] {
            let processes = Arc::new(ScriptedProcesses::new());
            processes.expect("/bin/tool", Script::FailsToSpawn(errno));
            let spawner = ProcessCommandSpawner::new(processes, Stdio::Null);
            assert_eq!(spawner.run(&request("/bin/tool")).unwrap(), outcome, "errno {errno}");
        }
    }

    // KNSH-099: a table of the standard streams in place spawns with no placements; any other table becomes the
    // placements that produce it, closing the standard numbers it leaves out.
    #[test]
    fn descriptor_table_becomes_placements() {
        let processes = Arc::new(ScriptedProcesses::new());
        processes.expect("/bin/tool", Script::Exits(0));
        processes.expect("/bin/tool", Script::Exits(0));
        let spawner = ProcessCommandSpawner::new(processes.clone(), Stdio::Null);
        spawner.run(&request("/bin/tool")).unwrap();
        let file = SharedFd::new(std::fs::File::open("/dev/null").unwrap().into());
        let mut redirected = request("/bin/tool");
        redirected.descriptors = vec![
            (1, ChildDescriptor::Open(file.clone())),
            (2, ChildDescriptor::Standard(StandardStream::Output)),
            (5, ChildDescriptor::Open(file.clone())),
        ];
        spawner.run(&redirected).unwrap();
        let requests = processes.spawned();
        assert_eq!(requests[0].placements, []);
        let placed = |target, source| Placement {
            target,
            source: Some(source),
        };
        assert_eq!(
            requests[1].placements,
            [
                Placement {
                    target: 0,
                    source: None
                },
                placed(1, PlacementSource::Shared(file.clone())),
                placed(2, PlacementSource::Stdio(1)),
                placed(5, PlacementSource::Shared(file)),
            ]
        );
    }

    // A resource shortage is not the program's fault: it stays an error instead of a made-up status.
    #[test]
    fn resource_shortage_is_an_error() {
        let processes = Arc::new(ScriptedProcesses::new());
        processes.expect("/bin/tool", Script::FailsToSpawn(libc::EAGAIN));
        let spawner = ProcessCommandSpawner::new(processes, Stdio::Null);
        assert!(spawner.run(&request("/bin/tool")).is_err());
    }
}
