//! Lifecycle steps 9 and 10: starting an allowed line through `knsh-exec` and watching it until it ends (KNSH-051,
//! `specs/03-functional-requirements/command-lifecycle.md`).
//!
//! [`TrampolineSpawner`] is the real [`Spawner`] behind the lifecycle orchestrator (`supervisor.rs`). For each line:
//!
//! 1. **Profile (FR-LC-12, FR-SBX-03, FR-SBX-04, FR-LC-15).** The session's profile is compiled for this line by
//!    `knsh-sandbox`, tagged with its record, allowing exec only of trusted folders, the profile's bash and the
//!    binaries the line resolved to. It is written to its private `0600` file ([`ProfileFiles`]), referenced until the
//!    line ends. No file, no spawn.
//! 2. **Interpreter (FR-LC-14, NFR-COMPAT-04).** `sh` runs `/bin/sh`, `zsh` runs `/bin/zsh`, `bash` and `knsh -c` run
//!    the profile's bash (`exec.bash`, `/bin/bash` by default) ([`interpreter_path`]). Policy never saw this choice.
//! 3. **Spawn (FR-LC-13, FR-LC-16).** `knsh-exec --status-fd <n> --profile <file> --interpreter <path> --line
//!    <re-serialised line> [--arg <operand>]…` as the leader of a new process group, in the line's working directory,
//!    on the caller's three descriptors, with the environment `knshd` received (shims and session token already
//!    removed, KNSH-049) minus the dynamic linker's `DYLD_*` variables, and nothing else. An empty line runs as
//!    `:` (`knsh-exec` refuses an empty `--line`). `knshd` never applies a sandbox itself: `knsh-exec` does, after the exec
//!    (CLAUDE.md "One process starts agent commands").
//!    With output captured (KNSH-053: `exec.run` and `exec.start` without passed stdio, or any line of a session
//!    that records output), stdout and stderr are instead pipes read by `knshd` ([`crate::capture`]), stdin is the
//!    caller's or `/dev/null`, and what the line writes is teed to the caller's descriptors when there are any.
//! 4. **Watch (FR-LC-17, FR-LC-40).** `command.started` once spawned, `command.long_running` once after
//!    [`Limits::long_running`]. At `timeout_s`, or when `exec.kill` asks ([`LineControl::kill_requested`]), the whole
//!    group gets `SIGTERM`, then `SIGKILL` after [`Limits::kill_grace`]. The group is held (its leader unreaped) the
//!    whole time, so no reused process id is ever signalled; after a timeout or a kill the group is killed once more,
//!    before the leader is reaped, so no member outlives it. Captured output is then collected, waiting at most
//!    [`DRAIN_GRACE`] for a leftover writer.
//! 5. **Did it start? (NFR-REL-08).** `knsh-exec` writes its exit code to the status pipe when it fails (bad
//!    arguments, unsafe profile file, setup, a failed exec of `sandbox-exec`), and the pipe is closed on exec
//!    otherwise. A byte there means the profile was never applied and the line never ran: the spawn is reported as a
//!    failure, never as the line's exit code.
//!
//! # Known limits
//!
//! - `sandbox-exec` itself exits 65 (profile not compiled) or 71 (interpreter not executable) before the line starts;
//!   those exits cannot be told from a line that exits 65 or 71, and are reported as the line's. The profile is the
//!   compiler's deterministic output and the interpreters are always allowed, so neither is expected.
//! - Members of the group that outlive a leader that exited on its own (`server &`) are left running; only a timeout
//!   kills the group. A process that leaves the group (`setsid`) is out of reach, as for any process group.
//! - No proxy is wired yet (KNSH-059): lines are compiled without a proxy port, so the network is closed except the
//!   profile's loopback ports, and no per-command proxy credentials are given.
//! - Teeing `knsh -c` output (a session that records output) puts `knshd` in the data path: the line's stdout and
//!   stderr are pipes, not the caller's terminal, so `isatty` is false for them (stdin stays the caller's).

use std::ffi::OsString;
use std::fs::File;
use std::io::Read;
use std::os::fd::{AsRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use knsh_core::{Allowed, CanonicalPath, Profile, RecordId, SessionId};
use knsh_platform::{
    Clock, ExitStatus, Field, Level, Operation, PlatformError, ProcessGroupId, Processes, SharedFd, Signal,
    SpawnRequest, Stdio, SystemLog, Value,
};
use knsh_proto::{Interpreter, LineStatus};
use knsh_sandbox::{CommandTag, ProfileInput, compile};

use crate::capture::{CapturePlan, DRAIN_GRACE, LineCapture, Source};
use crate::exec::Stdio as LineStdio;
use crate::jobs::LineControl;
use crate::profiles::ProfileFiles;
use crate::supervisor::{LineEvents, Ran, SpawnFailure, SpawnPlan, SpawnReport, Spawner};

/// `sh` lines (FR-LC-14): bash in POSIX mode on macOS.
pub(crate) const SH: &str = "/bin/sh";
/// `zsh` lines (FR-LC-14).
pub(crate) const ZSH: &str = "/bin/zsh";

/// First pause between checks on a running line; doubled up to [`POLL_MAX`]. Short lines (most agent lines) are
/// answered within a millisecond or two of their exit; long ones cost one non-blocking `waitid` per [`POLL_MAX`].
const POLL_FIRST: Duration = Duration::from_millis(1);
/// Longest pause between checks: how late a timeout or the long-running event may be.
const POLL_MAX: Duration = Duration::from_millis(50);

/// The watch timings (`specs/09-reference/defaults-and-limits.md`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Limits {
    /// After this long, `command.long_running` is published once (FR-LC-17).
    pub(crate) long_running: Duration,
    /// After a timeout, how long the group has between `SIGTERM` and `SIGKILL` (FR-LC-40).
    pub(crate) kill_grace: Duration,
}

impl Limits {
    /// 30 s to `command.long_running`, 2 s from `SIGTERM` to `SIGKILL`.
    pub(crate) const DEFAULT: Self = Self {
        long_running: Duration::from_secs(30),
        kill_grace: Duration::from_secs(2),
    };
}

/// The interpreter that runs a line asked to run with `interpreter` under `profile` (FR-LC-14, NFR-COMPAT-04).
pub(crate) fn interpreter_path(interpreter: Interpreter, profile: &Profile) -> &Path {
    match interpreter {
        Interpreter::Sh => Path::new(SH),
        Interpreter::Zsh => Path::new(ZSH),
        // `knsh -c` is `$SHELL -c` for an agent: it gets the same bash a plain `bash -c` would.
        Interpreter::Bash | Interpreter::Knsh => profile.exec.bash.as_path(),
    }
}

/// The canonical binaries the allowed line resolved to (FR-LC-13), each once, in a stable order: the only binaries
/// outside the trusted and system folders its profile lets it execute (FR-LC-15).
pub(crate) fn resolved_binaries(allowed: &Allowed) -> Vec<CanonicalPath> {
    let mut binaries: Vec<CanonicalPath> = allowed
        .classification
        .commands()
        .iter()
        .filter_map(|command| command.program.as_ref()?.path())
        .filter_map(|path| CanonicalPath::new(path).ok())
        .collect();
    binaries.sort();
    binaries.dedup();
    binaries
}

/// Everything one spawn needs, independent of how the decision was made.
pub(crate) struct LineToRun<'a> {
    /// The line's record: named in every sandbox tag (FR-SBX-06).
    pub(crate) record_id: RecordId,
    /// Its session: named in every sandbox tag.
    pub(crate) session_id: SessionId,
    /// The session's profile, the baseline the line's profile is compiled from.
    pub(crate) profile: &'a Profile,
    /// The re-serialised line (FR-LC-13).
    pub(crate) executed: &'a str,
    /// What the line resolved to ([`resolved_binaries`]).
    pub(crate) binaries: &'a [CanonicalPath],
    /// The shell asked for.
    pub(crate) interpreter: Interpreter,
    /// `$0`, `$1`, ….
    pub(crate) args: &'a [String],
    /// The complete environment.
    pub(crate) env: &'a [(String, String)],
    /// The working directory.
    pub(crate) cwd: &'a CanonicalPath,
    /// The caller's descriptors, or `None` (output captured, stdin `/dev/null`).
    pub(crate) stdio: Option<LineStdio>,
    /// `timeout_s`.
    pub(crate) timeout: Option<Duration>,
    /// How output is captured, or `None` when it goes straight to the caller's descriptors.
    pub(crate) capture: Option<CapturePlan>,
    /// The line's handle: its kill flag is read while it runs (`exec.kill`).
    pub(crate) control: &'a LineControl,
}

/// The [`Spawner`] that runs lines through `knsh-exec` (module documentation).
pub(crate) struct TrampolineSpawner {
    /// Starts, signals and reaps the line's group.
    pub(crate) processes: Arc<dyn Processes>,
    /// Monotonic time for the watch; its `sleep` paces the checks.
    pub(crate) clock: Arc<dyn Clock>,
    /// Where compiled profiles are written.
    pub(crate) files: ProfileFiles,
    /// Where a line that could not start is reported.
    pub(crate) log: Arc<dyn SystemLog>,
    /// The `knsh-exec` binary.
    pub(crate) trampoline: PathBuf,
    /// The user's canonical home: fixed denies and endpoint sockets are below it.
    pub(crate) home: CanonicalPath,
    /// Watch timings.
    pub(crate) limits: Limits,
}

impl Spawner for TrampolineSpawner {
    fn spawn(&self, plan: SpawnPlan, events: &dyn LineEvents) -> SpawnReport {
        let SpawnPlan {
            record_id,
            line,
            allowed,
            profile,
            capture,
        } = plan;
        let binaries = resolved_binaries(&allowed);
        self.run(
            LineToRun {
                record_id,
                session_id: line.session_id,
                profile: &profile,
                executed: &allowed.executed,
                binaries: &binaries,
                interpreter: line.interpreter,
                args: &line.args,
                env: &line.env,
                cwd: &line.proposal.cwd,
                stdio: line.stdio,
                timeout: line.timeout_s.map(Duration::from_secs),
                capture,
                control: &line.control,
            },
            events,
        )
    }
}

impl TrampolineSpawner {
    /// Steps 1 to 5 of the module documentation for `line`.
    pub(crate) fn run(&self, mut line: LineToRun<'_>, events: &dyn LineEvents) -> SpawnReport {
        // Step 1. The file stays until `compiled` is dropped, after the line has ended.
        let text = compile(&ProfileInput {
            session: line.session_id,
            command: CommandTag::Line(line.record_id),
            profile: line.profile,
            home: &self.home,
            executables: line.binaries,
            proxy_port: None,
        });
        let Ok(compiled) = self.files.write(&line.profile.name, &text) else {
            return self.not_run(None, SpawnFailure::ProfileFile, line.record_id);
        };
        let sandbox_profile = Some(compiled.sandbox_profile().to_owned());

        // Steps 2 and 3. The status pipe's write end lives only in the request: once the request is dropped, only
        // the child holds it, and `knsh-exec` closes it on exec.
        let (mut status, status_writer) = match std::io::pipe() {
            Ok(pipe) => pipe,
            Err(error) => return self.not_run(sandbox_profile, start_failure(&error), line.record_id),
        };
        let (stdio, capture) = match child_stdio(line.stdio.take(), line.capture.take()) {
            Ok(prepared) => prepared,
            Err(failure) => return self.not_run(sandbox_profile, failure, line.record_id),
        };
        let request = request(&self.trampoline, compiled.path(), &line, stdio, status_writer.into());
        let spawned = self.processes.spawn(&request);
        // Closes this process's copies of the caller's descriptors, of the output pipes' write ends (so the readers
        // see end of file once the line's processes close theirs) and of the status pipe's write end.
        drop(request);
        let group = match spawned {
            Ok(group) => group,
            Err(error) => return self.not_run(sandbox_profile, SpawnFailure::Start(error), line.record_id),
        };
        events.started();

        // Step 4.
        let watched = self.watch(group, line.timeout, line.control, events);
        drop(compiled);
        let output = capture.map(|capture| capture.finish(DRAIN_GRACE));
        let (exit, timed_out) = match watched {
            Ok(watched) => watched,
            Err(error) => return self.not_run(sandbox_profile, SpawnFailure::Wait(error), line.record_id),
        };

        // Step 5. Every write end is closed by now (the trampoline exited, or closed it on exec), so this returns at
        // once: one byte if the trampoline failed, end of file otherwise. A read that fails says neither, so the
        // line is not reported as run (fail closed, NFR-REL-08).
        match read_status(&mut status) {
            Ok(None) => {}
            Ok(Some(code)) => {
                return self.not_run(sandbox_profile, SpawnFailure::Trampoline(code), line.record_id);
            }
            Err(error) => return self.not_run(sandbox_profile, SpawnFailure::Wait(error), line.record_id),
        }
        let outcome = line_status(exit)
            .map(|status| Ran { status, timed_out })
            .ok_or(SpawnFailure::Wait(PlatformError::UnknownProcessGroup));
        SpawnReport {
            sandbox_profile,
            outcome,
            output,
        }
    }

    /// Polls the group until its leader exits, publishing `command.long_running` once and enforcing `timeout` and
    /// `exec.kill`, then reaps it. Returns how the leader ended and whether the timeout fired.
    fn watch(
        &self,
        group: ProcessGroupId,
        timeout: Option<Duration>,
        control: &LineControl,
        events: &dyn LineEvents,
    ) -> Result<(ExitStatus, bool), PlatformError> {
        let processes = self.processes.as_ref();
        let start = self.clock.monotonic();
        let mut pause = POLL_FIRST;
        let mut long_running_sent = false;
        // When `SIGTERM` was sent, as time since the start, and whether `SIGKILL` followed.
        let mut terminated_at: Option<Duration> = None;
        let mut killed = false;
        // Whether the stop was the timeout's (answered `-32008`) rather than `exec.kill`'s.
        let mut timed_out = false;
        loop {
            match processes.exited(group) {
                Ok(true) => break,
                Ok(false) => {}
                Err(error) => {
                    // Fail safe: a line that cannot be watched is stopped, and reaped if possible.
                    let _ = processes.signal(group, Signal::Kill);
                    let _ = processes.wait(group);
                    return Err(error);
                }
            }
            let elapsed = self.clock.monotonic().saturating_duration_since(start);
            if !long_running_sent && elapsed >= self.limits.long_running {
                long_running_sent = true;
                events.long_running();
            }
            let timeout_due = timeout.is_some_and(|timeout| elapsed >= timeout);
            match terminated_at {
                None if timeout_due || control.kill_requested() => {
                    // The group, not the leader: everything the line started stops too (FR-LC-40). An error means
                    // the group is already gone, which the next check sees.
                    let _ = processes.signal(group, Signal::Terminate);
                    terminated_at = Some(elapsed);
                    timed_out = timeout_due;
                }
                Some(at) if !killed && elapsed >= at.saturating_add(self.limits.kill_grace) => {
                    let _ = processes.signal(group, Signal::Kill);
                    killed = true;
                }
                _ => {}
            }
            self.clock.sleep(pause);
            pause = (pause * 2).min(POLL_MAX);
        }
        if terminated_at.is_some() {
            // The leader is gone but still unreaped, so the group id is still ours: members that ignored `SIGTERM`
            // or were started after it are killed before the id is given up. `EPERM` (nothing left) is expected.
            let _ = processes.signal(group, Signal::Kill);
        }
        let exit = processes.wait(group)?;
        Ok((exit, timed_out))
    }

    /// A line that did not run to its end: logged with fixed texts only (never the line), and reported.
    fn not_run(&self, sandbox_profile: Option<String>, failure: SpawnFailure, record_id: RecordId) -> SpawnReport {
        let mut fields = vec![
            Field::new("record_id", Value::Id(record_id.ulid())),
            Field::new("reason", Value::Static(failure.kind())),
        ];
        match failure {
            SpawnFailure::Trampoline(code) => fields.push(Field::new("exit_code", Value::I64(i64::from(code)))),
            SpawnFailure::Start(error) | SpawnFailure::Wait(error) => {
                if let Some(errno) = error.errno() {
                    fields.push(Field::new("errno", Value::Errno(errno)));
                }
            }
            SpawnFailure::ProfileFile => {}
        }
        self.log.log(Level::Error, "agent line not run", &fields);
        SpawnReport {
            sandbox_profile,
            outcome: Err(failure),
            output: None,
        }
    }
}

/// The child's stdio and, when output is captured, the readers of its stdout and stderr (module documentation,
/// step 3). Without capture the caller's descriptors are passed as they are (or `/dev/null`). With capture, stdout
/// and stderr are fresh pipes; stdin stays the caller's, or `/dev/null` for a captured `exec.run`.
fn child_stdio(
    caller: Option<LineStdio>,
    capture: Option<CapturePlan>,
) -> Result<(Stdio, Option<LineCapture>), SpawnFailure> {
    let Some(plan) = capture else {
        let stdio = caller.map_or(Stdio::Null, |fds| passed(fds.stdin, fds.stdout, fds.stderr));
        return Ok((stdio, None));
    };
    let (stdout_read, stdout_write) = std::io::pipe().map_err(|error| start_failure(&error))?;
    let (stderr_read, stderr_write) = std::io::pipe().map_err(|error| start_failure(&error))?;
    let (stdin, forward_out, forward_err) = match caller {
        Some(fds) => (fds.stdin, Some(File::from(fds.stdout)), Some(File::from(fds.stderr))),
        None => (
            OwnedFd::from(File::open("/dev/null").map_err(|error| start_failure(&error))?),
            None,
            None,
        ),
    };
    let capture = LineCapture::start(
        Source {
            pipe: stdout_read,
            forward: forward_out,
        },
        Source {
            pipe: stderr_read,
            forward: forward_err,
        },
        &plan,
    )
    .map_err(|error| start_failure(&error))?;
    Ok((passed(stdin, stdout_write.into(), stderr_write.into()), Some(capture)))
}

/// The child's stdin, stdout and stderr, in that order.
fn passed(stdin: OwnedFd, stdout: OwnedFd, stderr: OwnedFd) -> Stdio {
    Stdio::Passed(Box::new([
        SharedFd::new(stdin),
        SharedFd::new(stdout),
        SharedFd::new(stderr),
    ]))
}

/// A spawn that failed before `knsh-exec` started, from an I/O error.
fn start_failure(error: &std::io::Error) -> SpawnFailure {
    SpawnFailure::Start(PlatformError::Os {
        operation: Operation::Spawn,
        errno: error.raw_os_error().unwrap_or(0),
    })
}

/// What the status pipe says once every write end is closed: `None` at end of file (`sandbox-exec` started), the
/// trampoline's exit code if it failed. `EINTR` is retried.
fn read_status(status: &mut impl Read) -> Result<Option<u8>, PlatformError> {
    let mut reported = [0u8; 1];
    loop {
        match status.read(&mut reported) {
            Ok(0) => return Ok(None),
            Ok(_) => return Ok(Some(reported[0])),
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => {
                return Err(PlatformError::Os {
                    operation: Operation::Wait,
                    errno: error.raw_os_error().unwrap_or(0),
                });
            }
        }
    }
}

/// `bash -c ''` runs nothing and exits 0, but `knsh-exec` refuses an empty line (and, as a usage error, says so
/// only through its exit code, which would read as the line's). An empty line is run as the no-op builtin `:`,
/// which behaves the same: nothing runs, exit 0.
const EMPTY_LINE: &str = ":";

/// Whether `name` is read by the dynamic linker (`DYLD_INSERT_LIBRARIES`, `DYLD_LIBRARY_PATH`, …). `knsh-exec` runs
/// unsandboxed until it becomes `sandbox-exec`, and the environment comes from the agent: a library injected into
/// it would run outside the line's profile. The interpreters in `/bin` and `sandbox-exec` drop these variables
/// anyway (System Integrity Protection), so the line loses nothing it would have had.
fn read_by_dynamic_linker(name: &str) -> bool {
    name.starts_with("DYLD_")
}

/// The `knsh-exec` invocation for `line` (module documentation, step 3).
fn request(
    trampoline: &Path,
    profile_file: &Path,
    line: &LineToRun<'_>,
    stdio: Stdio,
    status_writer: OwnedFd,
) -> SpawnRequest {
    let status_writer = SharedFd::new(status_writer);
    let mut request = SpawnRequest::new(trampoline)
        .arg("--status-fd")
        .arg(status_writer.as_raw_fd().to_string())
        .arg("--profile")
        .arg(profile_file)
        .arg("--interpreter")
        .arg(interpreter_path(line.interpreter, line.profile))
        .arg("--line")
        .arg(if line.executed.is_empty() {
            EMPTY_LINE
        } else {
            line.executed
        });
    for operand in line.args {
        request = request.arg("--arg").arg(operand);
    }
    request.env = line
        .env
        .iter()
        .filter(|(name, _)| !read_by_dynamic_linker(name))
        .map(|(name, value)| (OsString::from(name), OsString::from(value)))
        .collect();
    request.cwd = Some(line.cwd.as_path().to_path_buf());
    request.inherit = vec![status_writer];
    request.stdio = stdio;
    request
}

/// The status `exec.run` reports for a reaped leader, or `None` for one outside the shell's range.
fn line_status(exit: ExitStatus) -> Option<LineStatus> {
    match exit {
        ExitStatus::Exited(code) => u8::try_from(code).ok().map(LineStatus::Exited),
        ExitStatus::Signalled(signal) => u8::try_from(signal)
            .ok()
            .filter(|signal| (1..=127).contains(signal))
            .map(LineStatus::Signalled),
    }
}

#[cfg(test)]
mod tests;
