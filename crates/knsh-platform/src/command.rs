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

use std::ffi::OsString;
use std::path::PathBuf;
use std::sync::Arc;

use crate::error::{Operation, PlatformError};
use crate::process::{ExitStatus, Processes, SpawnRequest, Stdio};

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

/// Starts one external command and waits for it. Object safe: hold it as `Arc<dyn CommandSpawner>`.
///
/// Implementations may refuse a command before it starts (KNSH-108) by returning
/// [`CommandOutcome::NotExecutable`] after reporting the reason themselves.
pub trait CommandSpawner: Send + Sync {
    /// Runs `request` to completion.
    ///
    /// # Errors
    ///
    /// A failure that is not the program's fault and has no bash exit status, for example no process could be
    /// created (`EAGAIN`) or waiting failed. The interpreter stops the script on it.
    fn run(&self, request: &CommandRequest) -> Result<CommandOutcome, PlatformError>;
}

/// [`CommandSpawner`] over [`Processes`]: each command starts in its own process group with the given standard
/// descriptors, and the call blocks until the group leader exits.
///
/// Job control (foreground process groups, `SIGINT` forwarding) belongs to KNSH-100 and is not done here.
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
    fn run(&self, request: &CommandRequest) -> Result<CommandOutcome, PlatformError> {
        let spawn = SpawnRequest {
            program: request.program.clone(),
            argv0: Some(request.argv0.clone()),
            args: request.args.clone(),
            env: request.env.clone(),
            cwd: Some(request.cwd.clone()),
            stdio: self.stdio.clone(),
            inherit: Vec::new(),
        };
        let group = match self.processes.spawn(&spawn) {
            Ok(group) => group,
            Err(PlatformError::Os {
                operation: Operation::Spawn,
                errno,
            }) => return exec_failure(errno),
            Err(error) => return Err(error),
        };
        self.processes.wait(group).map(CommandOutcome::Finished)
    }
}

/// The outcome of a spawn that failed with `errno`, as bash's `shell_execve` reports it: `ENOENT` is 127, every
/// other refusal by `exec` is 126. Running out of processes or descriptors is not an `exec` refusal and stays an
/// error.
fn exec_failure(errno: i32) -> Result<CommandOutcome, PlatformError> {
    match errno {
        libc::ENOENT => Ok(CommandOutcome::NotFound),
        libc::EAGAIN | libc::EMFILE | libc::ENFILE | libc::ENOMEM => Err(PlatformError::Os {
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

    // A resource shortage is not the program's fault: it stays an error instead of a made-up status.
    #[test]
    fn resource_shortage_is_an_error() {
        let processes = Arc::new(ScriptedProcesses::new());
        processes.expect("/bin/tool", Script::FailsToSpawn(libc::EAGAIN));
        let spawner = ProcessCommandSpawner::new(processes, Stdio::Null);
        assert!(spawner.run(&request("/bin/tool")).is_err());
    }
}
