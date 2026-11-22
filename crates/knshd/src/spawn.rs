//! Lifecycle steps 9 and 10: starting an allowed line through `knsh-exec` and watching it until it ends (KNSH-051,
//! `specs/03-functional-requirements/command-lifecycle.md`).
//!
//! [`TrampolineSpawner`] is the real [`Spawner`] behind the lifecycle orchestrator (`supervisor.rs`). For each line:
//!
//! 0. **Proxy credentials (FR-NET-01, KNSH-059, KNSH-060).** The proxy issues the line credentials of its own, tied
//!    to its record and scoped by the session profile's host rules with the line's classes, dynamic flag and
//!    approval ([`LineAccess`]), and revokes them (closing the connections they opened) when the line ends, however
//!    it ends. A line whose credentials cannot be issued does not start. Its environment loses every inherited proxy
//!    setting (the envelope's credentials included, which would attribute its connections to the session alone) and
//!    gets its own ([`command_env`]); its profile allows the proxy's port. Without a proxy it gets neither. Revoking
//!    returns the hosts the line contacted or was refused, for its record's `network` field (FR-NET-09).
//!
//!    **Secrets (KNSH-092).** A line that receives secrets is narrowed to their hosts: its [`LineAccess`] carries
//!    each secret's `hosts`, which the proxy's host rules apply on top of the profile's (FR-SEC-03, FR-NET-10), and it
//!    gets no loopback ports, in its sandbox profile or at the proxy, so the value cannot be sent to a local service
//!    either ([`narrowed_profile`]). The secrets themselves are set as environment variables in step 3, after every
//!    inherited variable of the same name is removed.
//! 1. **Profile (FR-LC-12, FR-SBX-03, FR-SBX-04, FR-LC-15).** The session's profile is compiled for this line by
//!    `knsh-sandbox`, tagged with its record, allowing exec only of trusted folders, the profile's bash and the
//!    binaries the line resolved to. It is written to its private `0600` file ([`ProfileFiles`]), referenced until the
//!    line ends. No file, no spawn.
//! 2. **Interpreter (FR-LC-14, NFR-COMPAT-04).** `sh` runs `/bin/sh`, `zsh` runs `/bin/zsh`, `bash` and `knsh -c` run
//!    the profile's bash (`exec.bash`, `/bin/bash` by default) ([`interpreter_path`]). Policy never saw this choice.
//! 3. **Spawn (FR-LC-13, FR-LC-16).** `knsh-exec --status-fd <n> --profile <file> --interpreter <path> --line
//!    <re-serialised line> [--arg <operand>]…` as the leader of a new process group, in the line's working directory,
//!    on the caller's three descriptors, with the environment `knshd` received (shims and session token already
//!    removed, KNSH-049) minus the dynamic linker's `DYLD_*` variables, plus the line's secrets (FR-SEC-01), and
//!    nothing else. Process information stays within the line's own sandbox in every profile (FR-SEC-05, decision 8),
//!    so other processes cannot read the injected environment. An empty line runs as
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
//!    The group is kept with its session's groups while it runs ([`crate::holds`], KNSH-054): a pause stops it with
//!    `SIGSTOP` and a resume continues it; time spent paused does not count towards `timeout_s`.
//! 5. **Did it start? (NFR-REL-08).** `knsh-exec` writes its exit code to the status pipe when it fails (bad
//!    arguments, unsafe profile file, setup, a failed exec of `sandbox-exec`), and the pipe is closed on exec
//!    otherwise. A byte there means the profile was never applied and the line never ran: the spawn is reported as a
//!    failure, never as the line's exit code.
//!
//! # Native-mode lines (KNSH-108)
//!
//! [`TrampolineSpawner::spawn_native`] runs a native-mode line's interpreter instead of a stock shell: `knsh
//! --native-line <fd> <line> <operand>…` through `knsh-exec`'s program mode, under the interpreter profile
//! ([`CommandTag::Interpreter`]: exec of `knsh` only, no `fork`, no network, so no proxy credentials), keeping its end
//! of the supervision channel (`--keep-fd`). It is watched as a line is (steps 4 and 5), and once it exits whatever is
//! left of its process group is killed before it is reaped (FR-LC-58). [`TrampolineSpawner::run_command`] starts one
//! allowed command of such a line: its own proxy credentials and profile (tagged with its record, allowing exec of
//! what it resolved to), `knsh-exec --in-group … --program <canonical path> --arg …` as a member of the line's group,
//! on exactly the descriptors the interpreter passed (numbers above 2 kept with `--keep-fd`, a standard number the
//! interpreter closed given `/dev/null`, as `knsh-exec` refuses closed stdio), and waits for it to end.
//!
//! # Known limits
//!
//! - `sandbox-exec` itself exits 65 (profile not compiled) or 71 (interpreter not executable) before the line starts;
//!   those exits cannot be told from a line that exits 65 or 71, and are reported as the line's. The profile is the
//!   compiler's deterministic output and the interpreters are always allowed, so neither is expected.
//! - Members of the group that outlive a leader that exited on its own (`server &`) are left running; only a timeout
//!   kills the group. A process that leaves the group (`setsid`) is out of reach, as for any process group.
//! - Teeing `knsh -c` output (a session that records output) puts `knshd` in the data path: the line's stdout and
//!   stderr are pipes, not the caller's terminal, so `isatty` is false for them (stdin stays the caller's).

use std::borrow::Cow;
use std::ffi::OsString;
use std::fs::File;
use std::io::Read;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::ffi::OsStringExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use knsh_core::{Allowed, CanonicalPath, LineAccess, NetworkEntry, Profile, RecordId, SessionId};
use knsh_platform::{
    ChildEvent, ChildOptions, Clock, ExitStatus, Field, GroupMembership, Level, Operation, Placement, PlacementSource,
    PlatformError, ProcessGroupId, Processes, SharedFd, Signal, SpawnRequest, Stdio, SystemLog, Value,
};
use knsh_proto::{Interpreter, LineStatus};
use knsh_sandbox::{CommandTag, ProfileInput, compile};

use crate::capture::{CapturePlan, DRAIN_GRACE, LineCapture, Source};
use crate::exec::Stdio as LineStdio;
use crate::holds::Kept;
use crate::injection::Injected;
use crate::jobs::LineControl;
use crate::profiles::ProfileFiles;
use crate::proxy::{ProxyCredential, ProxyIssuer, command_env};
use crate::supervisor::{LineEvents, NativePlan, Ran, SpawnFailure, SpawnPlan, SpawnReport, Spawner};

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

/// The native interpreter of a native-mode line (KNSH-108): the `knsh` binary, given its end of the line's
/// supervision channel.
pub(crate) struct NativeInterpreter<'a> {
    /// The canonical `knsh` binary beside `knshd`: the one binary its profile lets it execute.
    pub(crate) knsh: &'a CanonicalPath,
    /// Its end of the channel, kept open across the exec under its own number.
    pub(crate) channel: SharedFd,
}

/// Everything one spawn needs, independent of how the decision was made.
pub(crate) struct LineToRun<'a> {
    /// For a native-mode line, its interpreter; `None` for a line run by a stock interpreter.
    pub(crate) native: Option<NativeInterpreter<'a>>,
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
    /// The complete environment, before step 0 replaces its proxy settings.
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
    /// What the line presents to the proxy's host rules: its classes, dynamic flag, approval and its secrets' hosts
    /// (KNSH-060, KNSH-092).
    pub(crate) access: LineAccess,
    /// The secrets it receives as environment variables (KNSH-092).
    pub(crate) secrets: &'a [Injected],
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
    /// Issues and revokes each line's proxy credentials (step 0).
    pub(crate) proxy: Arc<dyn ProxyIssuer>,
    /// The canonical `knsh` binary that runs native-mode lines (KNSH-108); `None` when it could not be found, and then
    /// no native-mode line starts.
    pub(crate) knsh: Option<CanonicalPath>,
}

/// One allowed command of a native-mode line, ready to start (KNSH-108, FR-LC-56).
pub(crate) struct CommandPlan<'a> {
    /// The command's own record: named in its sandbox tags and proxy credentials.
    pub(crate) record_id: RecordId,
    /// Its session.
    pub(crate) session_id: SessionId,
    /// The session's profile, the baseline its profile is compiled from.
    pub(crate) profile: &'a Profile,
    /// Its decision: what it resolved to (the binaries its profile allows) and what it presents to the proxy.
    pub(crate) allowed: &'a Allowed,
    /// The canonical program to run.
    pub(crate) program: &'a CanonicalPath,
    /// `argv[1..]`.
    pub(crate) args: &'a [OsString],
    /// The complete environment, before its proxy settings are replaced.
    pub(crate) env: &'a [(String, String)],
    /// The working directory.
    pub(crate) cwd: &'a CanonicalPath,
    /// The file mode creation mask the interpreter has.
    pub(crate) umask: Option<u32>,
    /// The descriptor table the interpreter passed: each number with its descriptor, increasing.
    pub(crate) descriptors: Vec<(i32, OwnedFd)>,
    /// The line's process group, which the command joins.
    pub(crate) group: ProcessGroupId,
    /// The secrets it receives (KNSH-092).
    pub(crate) secrets: &'a [Injected],
}

/// What [`TrampolineSpawner::run_command`] reports while a command runs.
pub(crate) trait CommandEvents {
    /// The command was spawned as process `pid`: the interpreter is told it runs, and `command.started` follows.
    fn started(&self, pid: i32);
}

/// Revokes a line's proxy credentials when dropped, so every way out of [`TrampolineSpawner::run`] revokes them;
/// [`RevokeOnDrop::finish`] revokes them and keeps what the proxy reported for the record.
struct RevokeOnDrop<'a> {
    proxy: &'a dyn ProxyIssuer,
    record_id: RecordId,
    revoked: bool,
}

impl RevokeOnDrop<'_> {
    /// Revokes the credentials now and returns the line's `network` entries (FR-NET-09).
    fn finish(mut self) -> Vec<NetworkEntry> {
        self.revoked = true;
        self.proxy.revoke_line(self.record_id)
    }
}

impl Drop for RevokeOnDrop<'_> {
    fn drop(&mut self) {
        if !self.revoked {
            let _ = self.proxy.revoke_line(self.record_id);
        }
    }
}

impl Spawner for TrampolineSpawner {
    fn spawn(&self, plan: SpawnPlan, events: &dyn LineEvents) -> SpawnReport {
        let SpawnPlan {
            record_id,
            line,
            allowed,
            profile,
            capture,
            secrets,
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
                native: None,
                stdio: line.stdio,
                timeout: line.timeout_s.map(Duration::from_secs),
                capture,
                control: &line.control,
                access: LineAccess::of(&allowed),
                secrets: &secrets,
            },
            events,
        )
    }

    fn spawn_native(&self, plan: NativePlan, events: &dyn LineEvents) -> SpawnReport {
        let NativePlan {
            record_id,
            line,
            profile,
            capture,
            channel,
        } = plan;
        let Some(knsh) = self.knsh.as_ref() else {
            // No `knsh` beside `knshd`: nothing can run the line (fail closed).
            return self.not_run(None, SpawnFailure::Start(PlatformError::InvalidPath), record_id);
        };
        // `knsh --native-line <fd> <line> <operand>…` (`crate::supervisor::native`); the operands are `$0`, `$1`, ….
        let channel = SharedFd::new(channel);
        let mut args = vec![
            "--native-line".to_owned(),
            channel.as_raw_fd().to_string(),
            line.proposal.command.clone(),
        ];
        args.extend(line.args.iter().cloned());
        self.run(
            LineToRun {
                record_id,
                session_id: line.session_id,
                profile: &profile,
                executed: &line.proposal.command,
                binaries: &[],
                interpreter: line.interpreter,
                args: &args,
                env: &line.env,
                cwd: &line.proposal.cwd,
                native: Some(NativeInterpreter { knsh, channel }),
                stdio: line.stdio,
                timeout: line.timeout_s.map(Duration::from_secs),
                capture,
                control: &line.control,
                access: LineAccess::default(),
                secrets: &[],
            },
            events,
        )
    }

    fn run_command(&self, plan: &CommandPlan<'_>, events: &dyn CommandEvents) -> SpawnReport {
        self.start_command(plan, events)
    }

    fn kill_members(&self, group: ProcessGroupId) {
        // Only while a member is held unreaped (the group id is then still the line's): `EPERM` or an unknown group
        // means nothing is left.
        let _ = self.processes.signal_job(group, Signal::Kill);
    }
}

impl TrampolineSpawner {
    /// Steps 0 to 5 of the module documentation for `line`.
    pub(crate) fn run(&self, line: LineToRun<'_>, events: &dyn LineEvents) -> SpawnReport {
        // KNSH-108: a native-mode line's interpreter has no network, so it gets no proxy credentials; each of its
        // commands gets its own ([`TrampolineSpawner::run_command`]).
        if line.native.is_some() {
            return self.run_with(line, None, events);
        }
        // KNSH-092: one narrowed profile for the proxy scope and the sandbox profile alike.
        let narrowed = narrowed_profile(line.profile, &line.access);
        let line = LineToRun {
            profile: &narrowed,
            ..line
        };
        // Step 0. Revoked once the line has ended (`finish`), or on a panic when `revoke` is dropped. Revoking is
        // harmless when nothing was issued.
        let revoke = RevokeOnDrop {
            proxy: self.proxy.as_ref(),
            record_id: line.record_id,
            revoked: false,
        };
        let issued = self.proxy.issue_line(
            line.session_id,
            line.record_id,
            &line.profile.network,
            line.access.clone(),
        );
        let mut report = match issued {
            Ok(credential) => self.run_with(line, credential.as_ref(), events),
            Err(_) => self.not_run(None, SpawnFailure::ProxyCredentials, line.record_id),
        };
        // After revocation the proxy has reported every connection the line made (FR-NET-09).
        report.network = revoke.finish();
        report
    }

    /// Steps 1 to 5 for `line`, whose proxy credentials (step 0) are `credential`.
    fn run_with(
        &self,
        mut line: LineToRun<'_>,
        credential: Option<&ProxyCredential>,
        events: &dyn LineEvents,
    ) -> SpawnReport {
        let env = command_env(line.env, credential);

        // Step 1. The file stays until `compiled` is dropped, after the line has ended.
        let (command, executables) = match &line.native {
            // FR-LC-52: the interpreter may execute only `knsh` itself.
            Some(native) => (
                CommandTag::Interpreter(line.record_id),
                std::slice::from_ref(native.knsh),
            ),
            None => (CommandTag::Line(line.record_id), line.binaries),
        };
        let text = compile(&ProfileInput {
            session: line.session_id,
            command,
            profile: line.profile,
            home: &self.home,
            executables,
            proxy_port: credential.map(ProxyCredential::port),
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
        let request = request(
            &self.trampoline,
            compiled.path(),
            &line,
            &env,
            stdio,
            status_writer.into(),
        );
        let spawned = self.processes.spawn(&request);
        // Closes this process's copies of the caller's descriptors, of the output pipes' write ends (so the readers
        // see end of file once the line's processes close theirs) and of the status pipe's write end.
        drop(request);
        let group = match spawned {
            Ok(group) => group,
            Err(error) => return self.not_run(sandbox_profile, SpawnFailure::Start(error), line.record_id),
        };
        // Kept with the session's groups at once, so a pause reaches it (or stops it now if the session is paused).
        let kept = events.keep(group, Arc::clone(&self.processes));
        events.started();

        // Step 4.
        let watched = self.watch(group, kept, line.timeout, line.control, events, line.native.is_some());
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
            network: Vec::new(),
        }
    }

    /// One allowed command of a native-mode line (module documentation, "Native-mode lines"): proxy credentials,
    /// profile, `knsh-exec` in program mode in the line's group, then waits for it to end. Its credentials are revoked
    /// however it ends, and their report is the record's `network`.
    pub(crate) fn start_command(&self, plan: &CommandPlan<'_>, events: &dyn CommandEvents) -> SpawnReport {
        let access = LineAccess::of(plan.allowed);
        let narrowed = narrowed_profile(plan.profile, &access);
        let revoke = RevokeOnDrop {
            proxy: self.proxy.as_ref(),
            record_id: plan.record_id,
            revoked: false,
        };
        let issued = self
            .proxy
            .issue_line(plan.session_id, plan.record_id, &narrowed.network, access);
        let mut report = match issued {
            Ok(credential) => self.start_command_with(plan, &narrowed, credential.as_ref(), events),
            Err(_) => self.not_run(None, SpawnFailure::ProxyCredentials, plan.record_id),
        };
        report.network = revoke.finish();
        report
    }

    /// [`TrampolineSpawner::start_command`] once the command's credentials are `credential`.
    fn start_command_with(
        &self,
        plan: &CommandPlan<'_>,
        profile: &Profile,
        credential: Option<&ProxyCredential>,
        events: &dyn CommandEvents,
    ) -> SpawnReport {
        let env = command_env(plan.env, credential);
        let binaries = resolved_binaries(plan.allowed);
        let text = compile(&ProfileInput {
            session: plan.session_id,
            command: CommandTag::Line(plan.record_id),
            profile,
            home: &self.home,
            executables: &binaries,
            proxy_port: credential.map(ProxyCredential::port),
        });
        let Ok(compiled) = self.files.write(&profile.name, &text) else {
            return self.not_run(None, SpawnFailure::ProfileFile, plan.record_id);
        };
        let sandbox_profile = Some(compiled.sandbox_profile().to_owned());
        let (mut status, status_writer) = match std::io::pipe() {
            Ok(pipe) => pipe,
            Err(error) => return self.not_run(sandbox_profile, start_failure(&error), plan.record_id),
        };
        let request = match command_request(&self.trampoline, compiled.path(), plan, &env, status_writer.into()) {
            Ok(request) => request,
            Err(error) => return self.not_run(sandbox_profile, start_failure(&error), plan.record_id),
        };
        let options = ChildOptions {
            group: GroupMembership::Join(plan.group),
            ..ChildOptions::default()
        };
        let spawned = self.processes.spawn_child(&request, &options);
        // This process's copies of the passed descriptors and of the status pipe's write end are closed now.
        drop(request);
        let child = match spawned {
            Ok(child) => child,
            Err(error) => return self.not_run(sandbox_profile, SpawnFailure::Start(error), plan.record_id),
        };
        events.started(child.pid());
        // Stops (a paused session's `SIGSTOP` to the line's group) and continues are waited through.
        let exit = loop {
            match self.processes.wait_child(child) {
                Ok(ChildEvent::Exited(exit)) => break exit,
                Ok(ChildEvent::Stopped(_) | ChildEvent::Continued) => {}
                Err(error) => return self.not_run(sandbox_profile, SpawnFailure::Wait(error), plan.record_id),
            }
        };
        drop(compiled);
        match read_status(&mut status) {
            Ok(None) => {}
            Ok(Some(code)) => return self.not_run(sandbox_profile, SpawnFailure::Trampoline(code), plan.record_id),
            Err(error) => return self.not_run(sandbox_profile, SpawnFailure::Wait(error), plan.record_id),
        }
        let outcome = line_status(exit)
            .map(|status| Ran {
                status,
                timed_out: false,
            })
            .ok_or(SpawnFailure::Wait(PlatformError::UnknownProcessGroup));
        SpawnReport {
            sandbox_profile,
            outcome,
            output: None,
            network: Vec::new(),
        }
    }

    /// Polls the group until its leader exits, publishing `command.long_running` once and enforcing `timeout` and
    /// `exec.kill`, then reaps it. Returns how the leader ended and whether the timeout fired.
    ///
    /// Time the session spends paused does not count towards `timeout` (KNSH-054): a paused line is stopped, not
    /// slow, and must not be killed for it once resumed. `kept` is dropped before the leader is reaped, so a pause
    /// never signals the group id once it may be reused.
    ///
    /// With `kill_leftovers` (a native-mode line's interpreter, FR-LC-58), what is left of the group once the leader
    /// exited is killed before it is reaped, as after a timeout.
    fn watch(
        &self,
        group: ProcessGroupId,
        kept: Kept,
        timeout: Option<Duration>,
        control: &LineControl,
        events: &dyn LineEvents,
        kill_leftovers: bool,
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
        // Time spent paused so far, and the elapsed time at the previous check with whether the session was paused
        // then. A pause is counted from the check that first saw it, to within one poll.
        let mut paused_for = Duration::ZERO;
        let mut last = (Duration::ZERO, false);
        loop {
            match processes.exited(group) {
                Ok(true) => break,
                Ok(false) => {}
                Err(error) => {
                    // Fail safe: a line that cannot be watched is stopped, and reaped if possible.
                    let _ = processes.signal(group, Signal::Kill);
                    drop(kept);
                    let _ = processes.wait(group);
                    return Err(error);
                }
            }
            let elapsed = self.clock.monotonic().saturating_duration_since(start);
            if last.1 {
                paused_for += elapsed.saturating_sub(last.0);
            }
            last = (elapsed, kept.paused());
            if !long_running_sent && elapsed >= self.limits.long_running {
                long_running_sent = true;
                events.long_running();
            }
            let running_for = elapsed.saturating_sub(paused_for);
            let timeout_due = timeout.is_some_and(|timeout| running_for >= timeout);
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
        if terminated_at.is_some() || kill_leftovers {
            // The leader is gone but still unreaped, so the group id is still ours: members that ignored `SIGTERM`
            // or were started after it are killed before the id is given up. `EPERM` (nothing left) is expected.
            let _ = processes.signal(group, Signal::Kill);
        }
        // Forgotten by its session before the id is given up (module documentation of `crate::holds`).
        drop(kept);
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
            SpawnFailure::ProxyCredentials | SpawnFailure::ProfileFile => {}
        }
        self.log.log(Level::Error, "agent line not run", &fields);
        SpawnReport {
            sandbox_profile,
            outcome: Err(failure),
            output: None,
            network: Vec::new(),
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
pub(crate) fn passed(stdin: OwnedFd, stdout: OwnedFd, stderr: OwnedFd) -> Stdio {
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
pub(crate) fn read_status(status: &mut impl Read) -> Result<Option<u8>, PlatformError> {
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
pub(crate) fn read_by_dynamic_linker(name: &str) -> bool {
    name.starts_with("DYLD_")
}

/// `profile` as a line presenting `access` runs under it: unchanged, or, for a line that receives secrets (its
/// access is narrowed to their hosts), without loopback ports, so neither its sandbox profile nor the proxy lets it
/// reach a local port the secrets' hosts do not name (FR-SEC-03, module documentation, step 0).
pub(crate) fn narrowed_profile<'a>(profile: &'a Profile, access: &LineAccess) -> Cow<'a, Profile> {
    if access.secret_hosts.is_empty() {
        return Cow::Borrowed(profile);
    }
    let mut narrowed = profile.clone();
    narrowed.network.loopback.clear();
    Cow::Owned(narrowed)
}

/// The `knsh-exec` invocation for `line` (module documentation, step 3).
fn request(
    trampoline: &Path,
    profile_file: &Path,
    line: &LineToRun<'_>,
    env: &[(String, String)],
    stdio: Stdio,
    status_writer: OwnedFd,
) -> SpawnRequest {
    let status_writer = SharedFd::new(status_writer);
    let mut request = SpawnRequest::new(trampoline)
        .arg("--status-fd")
        .arg(status_writer.as_raw_fd().to_string())
        .arg("--profile")
        .arg(profile_file);
    let mut inherit = vec![status_writer];
    match &line.native {
        // KNSH-108: `knsh` itself in program mode, keeping its end of the channel under its own number.
        Some(native) => {
            request = request
                .arg("--keep-fd")
                .arg(native.channel.as_raw_fd().to_string())
                .arg("--program")
                .arg(native.knsh.as_path());
            inherit.push(native.channel.clone());
        }
        None => {
            request = request
                .arg("--interpreter")
                .arg(interpreter_path(line.interpreter, line.profile))
                .arg("--line")
                .arg(if line.executed.is_empty() {
                    EMPTY_LINE
                } else {
                    line.executed
                });
        }
    }
    for operand in line.args {
        request = request.arg("--arg").arg(operand);
    }
    request.env = env
        .iter()
        .filter(|(name, _)| !read_by_dynamic_linker(name))
        // KNSH-092: a secret's variable replaces any inherited one of the same name.
        .filter(|(name, _)| !line.secrets.iter().any(|secret| secret.variable == *name))
        .map(|(name, value)| (OsString::from(name), OsString::from(value)))
        // FR-SEC-01. The copy is the child's environment; it is not zeroed, as nothing in the environment can be.
        .chain(line.secrets.iter().map(|secret| {
            (
                OsString::from(&secret.variable),
                OsString::from_vec(secret.value.expose().to_vec()),
            )
        }))
        .collect();
    request.cwd = Some(line.cwd.as_path().to_path_buf());
    request.inherit = inherit;
    request.stdio = stdio;
    request
}

/// The `knsh-exec` invocation for one command of a native-mode line (module documentation, "Native-mode lines"):
/// program mode in the line's group, the interpreter's descriptors placed at their numbers (those above 2 kept), the
/// environment without the dynamic linker's variables and with the command's secrets.
///
/// # Errors
///
/// The status pipe's write end could not be moved off a number the table uses.
fn command_request(
    trampoline: &Path,
    profile_file: &Path,
    plan: &CommandPlan<'_>,
    env: &[(String, String)],
    status_writer: OwnedFd,
) -> std::io::Result<SpawnRequest> {
    // An inherited descriptor may not share a number with a placement: duplicated until it does not (each copy holds
    // a new number while the earlier ones stay open, so this ends within the table's size).
    let mut status_writer = status_writer;
    let mut held = Vec::new();
    while plan
        .descriptors
        .iter()
        .any(|(number, _)| *number == status_writer.as_raw_fd())
    {
        let copy = status_writer.try_clone()?;
        held.push(std::mem::replace(&mut status_writer, copy));
    }
    drop(held);
    let status_writer = SharedFd::new(status_writer);
    let mut request = SpawnRequest::new(trampoline)
        .arg("--status-fd")
        .arg(status_writer.as_raw_fd().to_string())
        .arg("--in-group")
        .arg("--profile")
        .arg(profile_file);
    for (number, _) in plan.descriptors.iter().filter(|(number, _)| *number > 2) {
        request = request.arg("--keep-fd").arg(number.to_string());
    }
    request = request.arg("--program").arg(plan.program.as_path());
    for arg in plan.args {
        request = request.arg("--arg").arg(arg);
    }
    request.env = env
        .iter()
        .filter(|(name, _)| !read_by_dynamic_linker(name))
        .filter(|(name, _)| !plan.secrets.iter().any(|secret| secret.variable == *name))
        .map(|(name, value)| (OsString::from(name), OsString::from(value)))
        .chain(plan.secrets.iter().map(|secret| {
            (
                OsString::from(&secret.variable),
                OsString::from_vec(secret.value.expose().to_vec()),
            )
        }))
        .collect();
    request.cwd = Some(plan.cwd.as_path().to_path_buf());
    request.umask = plan.umask;
    // A standard number the interpreter closed stays `/dev/null`: `knsh-exec` refuses closed stdio.
    request.stdio = Stdio::Null;
    request.placements = plan
        .descriptors
        .iter()
        .map(|(number, fd)| {
            fd.try_clone().map(|fd| Placement {
                target: *number,
                source: Some(PlacementSource::Shared(SharedFd::new(fd))),
            })
        })
        .collect::<std::io::Result<Vec<_>>>()?;
    request.inherit = vec![status_writer];
    Ok(request)
}

/// The status `exec.run` reports for a reaped leader, or `None` for one outside the shell's range.
pub(crate) fn line_status(exit: ExitStatus) -> Option<LineStatus> {
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
