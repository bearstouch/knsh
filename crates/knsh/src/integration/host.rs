//! Installing the zsh startup directory and starting the hosted shell (KNSH-019, FR-SES-20, FR-SES-22).
//!
//! Two ways to start it, chosen by whether recording is on:
//!
//! - **Recording off** ([`exec`]): `knsh` replaces itself with zsh. No telemetry descriptor exists, no hook is
//!   installed, and `knshd` is never contacted (FR-SES-23). Exit status, signals, job control and terminal
//!   ownership are zsh's own, because no `knsh` process is left in between.
//! - **Recording on** ([`run_recorded`]): zsh runs as a child that inherits the write end of a
//!   [`TelemetryPipe`]; a forwarder thread decodes the lines and hands them to a [`TelemetrySink`] (KNSH-021
//!   provides the one that talks to `knshd`). `knsh` never touches the terminal: interactive zsh puts itself in its
//!   own process group and takes the terminal, as under any parent, and gives it back on exit. While it runs, `knsh`
//!   ignores the terminal's job-control signals ([`JobSignalsIgnored`]) so that only zsh receives them, then
//!   returns zsh's exit status for the caller to pass on.

use std::ffi::OsString;
use std::fs::File;
use std::io::{self, BufReader};
use std::os::fd::AsRawFd;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use knsh_platform::engine_dirs::{DIR_MODE, FILE_MODE};
use knsh_platform::{EnginePaths, FileKind, Fs, PlatformError, ensure_engine_dirs};

#[cfg(target_os = "macos")]
use knsh_platform::macos::{JobSignalsIgnored, TelemetryPipe, reraise_default};

use super::telemetry::{LineReader, TelemetryLine};
use super::zsh::{LaunchPlan, STARTUP_FILE, ZSHENV, ZshLaunch};

/// How long `knsh` waits, after zsh has exited, for the forwarder to deliver the lines still in the pipe.
const FORWARDER_DRAIN: Duration = Duration::from_millis(200);

/// How often the drain wait checks whether the forwarder has finished.
const DRAIN_POLL: Duration = Duration::from_millis(5);

/// The largest startup file read back for comparison; anything longer differs from [`ZSHENV`] anyway.
const STARTUP_FILE_READ_LIMIT: u64 = 64 * 1024;

/// Whether the forwarder keeps reading after a line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flow {
    /// Keep reading.
    Continue,
    /// Stop and close the read end. Later hook writes fail silently; the shell is unaffected (FR-SES-22).
    Stop,
}

/// Receives the telemetry lines of a recorded session, in order, on the forwarder thread.
///
/// Rejected lines are never delivered. A sink must not block for long: while it does, the pipe fills and the
/// hooks drop lines (they never wait).
pub trait TelemetrySink: Send {
    /// Handles one line.
    fn deliver(&mut self, line: TelemetryLine) -> Flow;
}

/// Why the hosted shell could not be run.
#[derive(Debug)]
pub enum HostError {
    /// The telemetry pipe could not be created.
    Telemetry(PlatformError),
    /// zsh could not be started (for example it does not exist).
    Start(io::Error),
    /// Waiting for zsh failed.
    Wait(io::Error),
}

impl std::fmt::Display for HostError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Telemetry(error) => write!(f, "cannot set up telemetry: {error}"),
            Self::Start(error) => write!(f, "cannot start zsh: {error}"),
            Self::Wait(error) => write!(f, "cannot wait for zsh: {error}"),
        }
    }
}

impl std::error::Error for HostError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Telemetry(error) => Some(error),
            Self::Start(error) | Self::Wait(error) => Some(error),
        }
    }
}

/// Makes sure `.zshenv` in [`EnginePaths::zsh_startup_dir`] holds this build's [`ZSHENV`] and returns
/// the directory, to be used as `ZDOTDIR`.
///
/// The usual case, where the file is already current, costs a few `lstat`s and one read. Otherwise the engine
/// directories are prepared ([`ensure_engine_dirs`]), the two owner-only directories created, and the file
/// written by atomic replace (CLAUDE.md "Persistence"), so a concurrent start never sees a partial file.
///
/// # Errors
///
/// Any [`PlatformError`] from preparing the directories or writing the file, including
/// [`PlatformError::UnexpectedKind`] or [`PlatformError::ForeignOwner`] when something other than this user's
/// directory sits where one belongs. The caller then starts plain zsh: a human shell is never refused.
pub fn install_zsh_startup_dir(fs: &dyn Fs, paths: &EnginePaths, uid: u32) -> Result<PathBuf, PlatformError> {
    let dir = paths.zsh_startup_dir();
    let file = dir.join(STARTUP_FILE);
    if private_dir_exists(fs, &dir, uid)?
        && fs
            .read(&file, STARTUP_FILE_READ_LIMIT)
            .is_ok_and(|text| text == ZSHENV.as_bytes())
    {
        return Ok(dir);
    }
    ensure_engine_dirs(fs, paths, uid)?;
    // `shell/` then `shell/zsh/`, both below the data directory just prepared.
    if let Some(parent) = dir.parent() {
        ensure_private_dir(fs, parent, uid)?;
    }
    ensure_private_dir(fs, &dir, uid)?;
    fs.atomic_replace(&file, ZSHENV.as_bytes(), FILE_MODE)?;
    Ok(dir)
}

/// Whether `dir` exists as this user's directory. Anything else in its place is refused rather than followed.
fn private_dir_exists(fs: &dyn Fs, dir: &Path, uid: u32) -> Result<bool, PlatformError> {
    match fs.metadata(dir) {
        Ok(metadata) if metadata.kind != FileKind::Directory => Err(PlatformError::UnexpectedKind),
        Ok(metadata) if metadata.uid != uid => Err(PlatformError::ForeignOwner),
        Ok(_) => Ok(true),
        Err(error) if error.is_not_found() => Ok(false),
        Err(error) => Err(error),
    }
}

/// Creates `dir` owner-only unless it already exists as this user's directory.
fn ensure_private_dir(fs: &dyn Fs, dir: &Path, uid: u32) -> Result<(), PlatformError> {
    if private_dir_exists(fs, dir, uid)? {
        return Ok(());
    }
    match fs.create_dir(dir, DIR_MODE) {
        Ok(()) => Ok(()),
        // Another shell starting at the same moment created it first: check what is there now.
        Err(error) if is_already_exists(&error) => private_dir_exists(fs, dir, uid).map(|_| ()),
        Err(error) => Err(error),
    }
}

/// Whether `error` is `EEXIST`.
fn is_already_exists(error: &PlatformError) -> bool {
    error
        .errno()
        .is_some_and(|errno| io::Error::from_raw_os_error(errno).kind() == io::ErrorKind::AlreadyExists)
}

/// A [`Command`] that carries out `plan`. Standard descriptors and the rest of the environment are inherited.
#[must_use]
pub fn command(plan: &LaunchPlan) -> Command {
    apply(plan, Command::new(&plan.program))
}

/// Applies `plan`'s `argv` and environment changes to `command`, which must run `plan.program`.
fn apply(plan: &LaunchPlan, mut command: Command) -> Command {
    command.arg0(&plan.arg0).args(&plan.args);
    for name in &plan.remove_env {
        command.env_remove(name);
    }
    for (name, value) in &plan.set_env {
        command.env(name, value);
    }
    command
}

/// Replaces this process with zsh as `plan` describes (recording off). Returns only on failure.
#[must_use]
pub fn exec(plan: &LaunchPlan) -> io::Error {
    command(plan).exec()
}

/// What the hosted shell starts with when it is not simply `knsh`'s own: tests use it to run zsh in isolation.
#[derive(Debug)]
pub struct Isolation {
    /// Standard input.
    pub stdin: Stdio,
    /// Standard output.
    pub stdout: Stdio,
    /// Standard error.
    pub stderr: Stdio,
    /// The environment that replaces `knsh`'s own before the launch plan's changes are applied.
    pub env: Vec<(OsString, OsString)>,
}

/// Runs zsh as a child with the telemetry descriptor (recording on), forwarding each decoded line to `sink`, and
/// returns zsh's exit status. `launch.telemetry_fd` is ignored: the descriptor is created here. `isolation` is `None`
/// in a real session: zsh inherits `knsh`'s terminal and environment.
///
/// Without a startup directory (`launch.startup_dir` is `None`) no hook could take the descriptor over and close it,
/// so no pipe is created at all: every command the user runs would otherwise inherit its write end. zsh runs plain
/// and `sink` receives nothing.
///
/// # Errors
///
/// [`HostError::Telemetry`] if the pipe cannot be created, [`HostError::Start`] if zsh cannot be started, and
/// [`HostError::Wait`] if waiting for it fails. Nothing has been started in the first two cases.
#[cfg(target_os = "macos")]
pub fn run_recorded(
    launch: ZshLaunch<'_>,
    sink: Box<dyn TelemetrySink>,
    isolation: Option<Isolation>,
) -> Result<ExitStatus, HostError> {
    let (reader, writer) = if launch.startup_dir.is_some() {
        let (reader, writer) = TelemetryPipe::new().map_err(HostError::Telemetry)?.into_parts();
        (Some(reader), Some(writer))
    } else {
        (None, None)
    };
    let plan = ZshLaunch {
        telemetry_fd: writer.as_ref().map(AsRawFd::as_raw_fd),
        ..launch
    }
    .plan();
    let mut command = match isolation {
        None => command(&plan),
        Some(isolation) => {
            let mut base = Command::new(&plan.program);
            base.env_clear()
                .envs(isolation.env)
                .stdin(isolation.stdin)
                .stdout(isolation.stdout)
                .stderr(isolation.stderr);
            apply(&plan, base)
        }
    };
    let mut child = command.spawn().map_err(HostError::Start)?;
    // Only zsh may hold the write end, or the forwarder would never see end of file.
    drop(writer);
    let forwarder = reader.map(|reader| thread::spawn(move || forward(reader, sink)));

    // Installed after the spawn, so zsh starts with the dispositions knsh was given. Failing to install it is
    // tolerated: a human session must not be refused for it (FR-SES-22).
    let ignored = JobSignalsIgnored::install().ok();
    let status = child.wait().map_err(HostError::Wait);
    drop(ignored);

    // zsh has exited and its close-on-exec copy of the descriptor with it: the forwarder sees end of file once the
    // remaining lines are read. Bounded, in case a process zsh started before the hooks took the descriptor over
    // still holds it; the thread is then left to finish on its own.
    if let Some(forwarder) = forwarder {
        let deadline = Instant::now() + FORWARDER_DRAIN;
        while !forwarder.is_finished() && Instant::now() < deadline {
            thread::sleep(DRAIN_POLL);
        }
        if forwarder.is_finished() {
            // The forwarder cannot panic on input; a panic in the sink stays on its own thread.
            let _ = forwarder.join();
        }
    }
    status
}

/// The status `knsh` exits with after a recorded session, so its parent sees what plain zsh would have shown: zsh's
/// exit code; or, when a signal ended zsh, `knsh` ends by the same signal and returns only if that signal does not
/// terminate it, in which case the shell convention `128 + n` is returned.
#[cfg(target_os = "macos")]
#[must_use]
pub fn finish(status: ExitStatus) -> u8 {
    use std::os::unix::process::ExitStatusExt;

    match (status.code(), status.signal()) {
        // `code()` is the low 8 bits of the exit status, so the conversion cannot fail in practice.
        (Some(code), _) => u8::try_from(code).unwrap_or(u8::MAX),
        (None, Some(signal)) => {
            reraise_default(signal);
            u8::try_from(128 + signal).unwrap_or(u8::MAX)
        }
        (None, None) => u8::MAX,
    }
}

/// The forwarder: decodes lines from `reader` and delivers them until end of file, a read error, or
/// [`Flow::Stop`]. Rejected lines are dropped. Returning drops `reader`, which closes the read end.
fn forward(reader: File, mut sink: Box<dyn TelemetrySink>) {
    let mut lines = LineReader::new(BufReader::new(reader));
    while let Ok(Some(line)) = lines.next_line() {
        if let Ok(line) = line
            && sink.deliver(line) == Flow::Stop
        {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use knsh_platform::Operation;
    use knsh_platform::testing::MemFs;

    const UID: u32 = 501;

    // KNSH-019: `knsh` exits with zsh's own exit code (the signal case ends the process and is covered end to end).
    #[cfg(target_os = "macos")]
    #[test]
    fn finish_passes_on_the_exit_code() {
        use std::os::unix::process::ExitStatusExt;

        assert_eq!(finish(ExitStatus::from_raw(0)), 0);
        assert_eq!(finish(ExitStatus::from_raw(7 << 8)), 7);
        assert_eq!(finish(ExitStatus::from_raw(255 << 8)), 255);
    }

    fn setup() -> (MemFs, EnginePaths) {
        let fs = MemFs::with_uid(UID);
        fs.add_dir_all(Path::new("/Users/u")).expect("home");
        let paths = EnginePaths::for_home(Path::new("/Users/u")).expect("paths");
        (fs, paths)
    }

    fn startup_file(paths: &EnginePaths) -> PathBuf {
        paths.zsh_startup_dir().join(STARTUP_FILE)
    }

    #[test]
    fn installs_the_wrapper_owner_only() {
        let (fs, paths) = setup();
        let dir = install_zsh_startup_dir(&fs, &paths, UID).expect("install");
        assert_eq!(dir, paths.zsh_startup_dir());
        assert_eq!(fs.contents(&startup_file(&paths)).as_deref(), Some(ZSHENV.as_bytes()));
        assert_eq!(fs.metadata(&startup_file(&paths)).expect("file").mode, FILE_MODE);
        assert_eq!(fs.metadata(&dir).expect("dir").mode, DIR_MODE);
        assert_eq!(fs.metadata(dir.parent().expect("shell")).expect("dir").mode, DIR_MODE);
    }

    // A current file is left alone: no write happens (an injected write fault would otherwise surface).
    #[test]
    fn current_wrapper_is_not_rewritten() {
        let (fs, paths) = setup();
        install_zsh_startup_dir(&fs, &paths, UID).expect("install");
        fs.inject_fault(Operation::Write, 5);
        fs.inject_fault(Operation::Rename, 5);
        install_zsh_startup_dir(&fs, &paths, UID).expect("second start");
    }

    // An outdated or edited wrapper is replaced with this build's.
    #[test]
    fn stale_wrapper_is_replaced() {
        let (fs, paths) = setup();
        install_zsh_startup_dir(&fs, &paths, UID).expect("install");
        fs.atomic_replace(&startup_file(&paths), b"echo old\n", FILE_MODE)
            .expect("edit");
        install_zsh_startup_dir(&fs, &paths, UID).expect("reinstall");
        assert_eq!(fs.contents(&startup_file(&paths)).as_deref(), Some(ZSHENV.as_bytes()));
    }

    // A symlink or another user's directory where the startup directory belongs is refused, not followed.
    #[test]
    fn foreign_or_symlinked_startup_dir_is_refused() {
        let (fs, paths) = setup();
        install_zsh_startup_dir(&fs, &paths, UID).expect("install");
        fs.set_owner(&paths.zsh_startup_dir(), UID + 1).expect("chown");
        assert_eq!(
            install_zsh_startup_dir(&fs, &paths, UID),
            Err(PlatformError::ForeignOwner)
        );

        let (fs, paths) = setup();
        fs.add_dir_all(&paths.data_dir().join("shell")).expect("shell dir");
        fs.add_symlink(&paths.zsh_startup_dir(), Path::new("/tmp/elsewhere"))
            .expect("symlink");
        assert_eq!(
            install_zsh_startup_dir(&fs, &paths, UID),
            Err(PlatformError::UnexpectedKind)
        );
    }
}
