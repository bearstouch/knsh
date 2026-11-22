//! Native mode for a human (KNSH-107, phase 4): `knsh`'s own interpreter with its line editor, chosen with
//! `[shell] hosted = "native"` (opt-in until the phase 4 gate, KNSH-109, is green; zsh users stay in integration mode,
//! NFR-COMPAT-06).
//!
//! The shell is built over the real system as bash builds an interactive shell: it takes the terminal for job
//! control, ignores `SIGINT`, `SIGQUIT` and `SIGTSTP` itself (its foreground jobs get them, with their default
//! actions), reads the start-up files bash would read ([`knsh_interp::interactive::startup`]), loads `HISTFILE`, then
//! runs the session. A human session is never decided or blocked (FR-SES-22): commands start through the
//! platform's spawner directly, with no supervisor in the way, and every error is reported and the shell goes on.
//!
//! Not yet: recording a native session's telemetry (integration mode's hooks have no equivalent here yet), and
//! bash's `--norc`, `--noprofile` and `--rcfile` options.

use std::ffi::OsString;
use std::os::fd::AsFd;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use knsh_interp::interactive::startup::{self, Startup};
use knsh_interp::interactive::{DescriptorTerminal, HostInfo, Session, SessionOptions};
use knsh_interp::{Interpreter, ShellState};
use knsh_platform::macos::{
    JobSignalsIgnored, RealFs, SystemCollation, SystemDescriptors, SystemLocalTime, SystemProcesses, SystemShellTimes,
    SystemTerminal, SystemUserHomes, effective_uid, host_name, ignored_signals, terminal_name, user_name,
};
use knsh_platform::{Descriptors, Fs, JobTerminal, ProcessCommandSpawner, SharedFd, Stdio};

/// How the native shell was started.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NativeStart {
    /// A login shell (`-l`, `--login`, `argv[0]` starting with `-`).
    pub login: bool,
    /// Write OSC 7 and OSC 133 marks (`knsh`'s standard output is a terminal, NFR-COMPAT-10).
    pub marks: bool,
}

/// How the native shell ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeExit {
    /// With this status.
    Status(u8),
    /// By this signal's default action: the caller ends itself by it, as bash does.
    Signal(i32),
}

/// Writes one of the front end's messages on standard error, ignoring failure.
fn report(message: &str) {
    use std::io::Write;
    let _ = std::io::stderr().write_all(message.as_bytes());
}

/// A duplicate of this process's descriptor `fd` (0, 1 or 2), or `None` if it is closed.
fn standard(fd: std::os::fd::BorrowedFd<'_>) -> Option<SharedFd> {
    fd.try_clone_to_owned().ok().map(SharedFd::new)
}

/// Runs the native interactive shell until it exits.
#[must_use]
pub fn run(start: NativeStart) -> NativeExit {
    // Read before anything changes them: what the shell was started ignoring stays ignored for its commands.
    let ignored = ignored_signals();
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("/"));
    let name = if start.login { "-knsh" } else { "knsh" };
    let environment: Vec<(OsString, OsString)> = std::env::vars_os().collect();
    let state = match ShellState::new(name, cwd) {
        Ok(state) => state,
        Err(error) => {
            report(&format!("knsh: {error}\n"));
            return NativeExit::Status(1);
        }
    };
    let state = state.with_environment(environment).with_ignored_signals(ignored);
    let (Some(input), Some(errors)) = (standard(std::io::stdin().as_fd()), standard(std::io::stderr().as_fd())) else {
        report("knsh: standard input or error is closed\n");
        return NativeExit::Status(1);
    };
    // Job control on the terminal, as an interactive bash; without a terminal the shell still runs.
    let terminal: Option<Arc<dyn JobTerminal>> = match SystemTerminal::take(input.clone()) {
        Ok(terminal) => Some(Arc::new(terminal)),
        Err(error) => {
            report(&format!(
                "knsh: cannot set terminal process group ({error}); no job control in this shell\n"
            ));
            None
        }
    };
    // The shell itself ignores the keyboard's signals; its foreground jobs get them (bash's interactive shell).
    let signals_ignored = JobSignalsIgnored::install()
        .map_err(|error| report(&format!("knsh: cannot ignore the job-control signals ({error})\n")))
        .ok();
    let descriptors: Arc<dyn Descriptors> = Arc::new(SystemDescriptors::new());
    let fs: Arc<dyn Fs> = Arc::new(RealFs::new());
    let shell = Interpreter::new(
        state,
        Arc::clone(&fs),
        Arc::new(ProcessCommandSpawner::new(
            Arc::new(SystemProcesses::new()),
            Stdio::Inherit,
        )),
        Arc::new(SystemUserHomes::new()),
        Arc::new(SystemCollation::new()),
        Arc::clone(&descriptors),
        Box::new(std::io::stderr()),
    )
    .with_output(Box::new(std::io::stdout()))
    .with_times(Arc::new(SystemShellTimes::new()));
    let local_time = Arc::new(SystemLocalTime::new());
    let shell = match shell.with_local_time(local_time.clone()) {
        Ok(shell) => shell,
        Err(error) => {
            report(&format!("knsh: {error}\n"));
            return NativeExit::Status(1);
        }
    };
    let shell = shell.with_job_control(terminal);
    let uid = effective_uid();
    let host = HostInfo {
        host: host_name().unwrap_or_default(),
        user: user_name(uid).unwrap_or_default(),
        terminal: terminal_name(&input)
            .and_then(|path| path.file_name().map(|name| name.to_string_lossy().into_owned()))
            .unwrap_or_else(|| "tty".to_owned()),
        superuser: uid == 0,
    };
    let home = std::env::var_os("HOME").map(PathBuf::from);
    let startup = Startup {
        login: start.login,
        interactive: true,
        ..Startup::default()
    };
    let readable = |path: &Path| std::fs::File::open(path).is_ok();
    let options = SessionOptions {
        marks: start.marks,
        logout_file: startup::logout_file(&startup, home.as_deref(), &readable),
    };
    let tty = DescriptorTerminal::new(Arc::clone(&descriptors), input, errors);
    let mut session = Session::new(shell, tty, host, options).with_local_time(local_time);
    for file in startup::startup_files(&startup, home.as_deref(), None, &readable) {
        if let Err(error) = session.shell_mut().source_startup_file(&file) {
            report(&format!("knsh: {}: {error}\n", file.display()));
        }
        if session.shell().has_exited() {
            break;
        }
    }
    session.load_history();
    let status = match session.run() {
        Ok(status) => status.code(),
        Err(error) => {
            report(&format!("knsh: {error}\n"));
            1
        }
    };
    let signal = session.shell().terminating_signal();
    drop(session);
    drop(signals_ignored);
    match signal {
        Some(signal) => NativeExit::Signal(signal),
        None => NativeExit::Status(status),
    }
}
