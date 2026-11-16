//! `exec.run` from `knsh -c`: receiving a forwarded line and handing it to the supervisor (KNSH-049, FR-LC-01,
//! FR-AGT-10).
//!
//! Step 1 of the command lifecycle (`specs/03-functional-requirements/command-lifecycle.md`): the line, its working
//! directory, the caller's environment, the operands after the line, the interpreter asked for and, with
//! `"stdio": "passed"`, the caller's stdin, stdout and stderr as descriptors. This module checks and shapes what
//! arrived; deciding and running it is the [`Supervisor`]'s (KNSH-050, KNSH-051).
//!
//! What it guarantees before the supervisor sees anything:
//!
//! - **Bound session.** Only on `agent.sock`, for the session the connection was bound to at `hello` (KNSH-048).
//!   The caller cannot name another session, and nothing the line or its environment says changes which session it
//!   is or relaxes its policy (FR-AGT-20).
//! - **Descriptors match.** Exactly three with `"stdio": "passed"`, none without; anything else is `-32602`, and the
//!   descriptors are closed unused.
//! - **The decision cannot depend on the interpreter (FR-LC-14).** What policy sees is a [`Proposal`]: the line,
//!   the working directory and the `PATH` names resolve on. It has no interpreter field, so no decision built from
//!   it can tell `sh -c` from `bash -c` or `knsh -c`.
//! - **No shims (FR-LC-16).** The shim directory is removed from the `PATH` the line runs with and resolves names
//!   on, so a shell the line starts runs directly under the line's profile, and `bash` in the line names the real
//!   bash. The session token is removed too: a supervised line runs outside the envelope and has no use for the
//!   envelope's credential.
//!
//! # Captured lines and output modes (KNSH-053)
//!
//! Without `"stdio": "passed"`, the supervisor captures the line's output and the answer is an [`ExecOutcome`]: the
//! record, the line actually spawned (FR-AUTH-33), how it ended, its duration and decision, both streams' sizes and
//! line counts, and the output the caller's `output.mode` (or the profile's default, FR-OUT-02) selects (FR-OUT-01).
//! The output is redacted (FR-OUT-06), only ever selected and cut, never summarised (FR-OUT-05), and shortened if
//! needed so the answer fits in one frame ([`MAX_EXEC_RESULT_LEN`]).
//!
//! `exec.start` takes the same parameters (never passed stdio) and answers `{record_id}` as soon as the line is
//! spawned, or with the same error `exec.run` would give if it is refused. The line is decided and run on its own
//! thread; `exec.wait` (`{record_id}`) answers what `exec.run` would have, once the line has ended, and `exec.kill`
//! (`{record_id}`) stops its whole process group ([`crate::jobs`]).
//!
//! The four are served since lines can be spawned (KNSH-051), and `exec.run` and `exec.start` are listed only where
//! the sandbox probe passed. When `knshd` cannot build its supervisor (no `knsh-exec` beside it),
//! [`unserved_handlers`] answers every call `-32005` (`capability: "sandbox"`), so no line reaches anything that
//! could not run it under its profile.

use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use knsh_core::{CanonicalPath, CapturedStream, Decision, OutputMode, RecordId, Redacted, SessionId, shape};
use knsh_proto::{
    DEFAULT_POLICY_CHECK_PATH, ErrorCode, ExecHandleParams, ExecKillResult, ExecOutcome, ExecRunParams, ExecRunResult,
    ExecStartResult, ExecStdio, Interpreter, LineStatus, MAX_EXEC_RESULT_LEN, OutputOptions, RpcError,
    SESSION_TOKEN_VAR, StreamTotals,
};

use crate::capture::LineOutput;
use crate::dispatch::{
    Answer, Call, EXEC_RUN, Endpoint, Handler, Handlers, Reply, answer, capability_unavailable, params,
};
use crate::jobs::{FlagCaller, Jobs, LineControl, StartWait, Waiting};

/// `exec.start`: start a line and answer once it is spawned.
pub(crate) const EXEC_START: &str = "exec.start";
/// `exec.wait`: the answer of a started line, once it ended.
pub(crate) const EXEC_WAIT: &str = "exec.wait";
/// `exec.kill`: stop a started line's process group.
pub(crate) const EXEC_KILL: &str = "exec.kill";

/// The variable names are resolved on, and the one the shims are stripped from.
pub(crate) const PATH_VAR: &str = "PATH";

/// What policy decides a line on (FR-LC-09, FR-LC-14): the line, where it runs, and where its names resolve.
/// Deliberately without the interpreter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Proposal {
    /// The line, exactly as the caller sent it.
    pub(crate) command: String,
    /// The working directory.
    pub(crate) cwd: CanonicalPath,
    /// The `PATH` names resolve on: the caller's, without the shim directory, or the system default.
    pub(crate) path: String,
}

/// The caller's stdin, stdout and stderr, received with the request.
#[derive(Debug)]
pub(crate) struct Stdio {
    /// Descriptor 0 of the line.
    pub(crate) stdin: OwnedFd,
    /// Descriptor 1 of the line.
    pub(crate) stdout: OwnedFd,
    /// Descriptor 2 of the line.
    pub(crate) stderr: OwnedFd,
}

/// One line as the supervisor receives it (FR-LC-01).
#[derive(Debug)]
pub(crate) struct ForwardedLine {
    /// The session the connection is bound to.
    pub(crate) session_id: SessionId,
    /// What policy decides on.
    pub(crate) proposal: Proposal,
    /// The shell that runs the line once allowed (FR-LC-14): never an input to the decision.
    pub(crate) interpreter: Interpreter,
    /// The operands after the line: `$0`, `$1`, ….
    pub(crate) args: Vec<String>,
    /// The environment the line runs with: the caller's, without the shims in `PATH` and without the session token.
    pub(crate) env: Vec<(String, String)>,
    /// The caller's stdio, or `None` when the supervisor captures output (KNSH-053).
    pub(crate) stdio: Option<Stdio>,
    /// Kill the line after this many seconds (FR-LC-40).
    pub(crate) timeout_s: Option<u64>,
    /// Its handle: start mark, kill flag and answer (`exec.start`, `exec.kill`).
    pub(crate) control: Arc<LineControl>,
}

/// How a supervised line ended.
#[derive(Debug, Clone)]
pub(crate) struct Finished {
    /// Its execution record (KNSH-052).
    pub(crate) record_id: Option<RecordId>,
    /// Its exit code or signal.
    pub(crate) status: LineStatus,
    /// The line actually spawned, after any rewrite (FR-AUTH-33), redacted.
    pub(crate) executed_command: Redacted<String>,
    /// The decision that let it run.
    pub(crate) decision: Decision,
    /// From the spawn to the end.
    pub(crate) duration_ms: u64,
    /// Its profile's default output mode (FR-OUT-02).
    pub(crate) default_mode: OutputMode,
    /// Its captured output; `None` when it ran on passed descriptors without capture.
    pub(crate) output: Option<LineOutput>,
}

/// Decides and runs forwarded lines: the lifecycle orchestrator (KNSH-050) and spawner (KNSH-051).
///
/// The contract the handler relies on: a line is run only after its whole [`Proposal`] has been allowed, and every
/// failure to decide is a denial (`-32001`), never a run. A held session is `-32007`, answered at once.
pub(crate) trait Supervisor: Send + Sync {
    /// Decides `line`, runs it if allowed, and waits for it to end. If `caller` goes away while the decision is
    /// pending, the line is cancelled and never runs (FR-LC-41).
    ///
    /// # Errors
    ///
    /// The answer for a line that did not run to its end: `-32001` denied (with `rule_id`, `reason` and `source`),
    /// `-32007` held, `-32008` timed out, and the other codes of `specs/06-api/agent-socket.md#execrun`.
    fn run(&self, line: ForwardedLine, caller: &dyn knsh_core::Caller) -> Result<Finished, RpcError>;

    /// Whether `session_id` is still live: the started lines of an ended session are forgotten ([`crate::jobs`]).
    /// Fakes that know no sessions keep every line.
    fn session_live(&self, session_id: SessionId) -> bool {
        let _ = session_id;
        true
    }
}

/// One `exec.*` method of the service.
type Method = fn(&Arc<ExecRun>, &Call<'_>) -> Reply;

/// The `exec.*` service.
pub(crate) struct ExecRun {
    supervisor: Arc<dyn Supervisor>,
    /// [`knsh_platform::EnginePaths::shim_dir`].
    shim_dir: PathBuf,
    /// Lines started with `exec.start`.
    jobs: Arc<Jobs>,
}

impl ExecRun {
    /// The service handing lines to `supervisor`, stripping `shim_dir` from their `PATH`.
    pub(crate) fn new(supervisor: Arc<dyn Supervisor>, shim_dir: PathBuf) -> Arc<Self> {
        Arc::new(Self {
            supervisor,
            shim_dir,
            jobs: Jobs::new(),
        })
    }

    /// The `exec.run`, `exec.start`, `exec.wait` and `exec.kill` handlers.
    pub(crate) fn handlers(self: &Arc<Self>) -> Handlers {
        let methods: [(&'static str, Method); 4] = [
            (EXEC_RUN, |service, call| service.run(call)),
            (EXEC_START, |service, call| service.start(call)),
            (EXEC_WAIT, |service, call| service.wait(call)),
            (EXEC_KILL, |service, call| service.kill(call)),
        ];
        methods
            .into_iter()
            .map(|(name, method)| {
                let service = Arc::clone(self);
                let handler: Handler = Arc::new(move |call: &Call<'_>| method(&service, call));
                (name, handler)
            })
            .collect()
    }

    /// `exec.run` (module documentation).
    fn run(&self, call: &Call<'_>) -> Reply {
        // Taken first, so every early return below closes them.
        let descriptors = call.descriptors.take();
        let params: ExecRunParams = params(call)?;
        let session_id = agent_session(call)?;
        let mode = params.stdio;
        let stdio = stdio(mode, descriptors)?;
        let output = params.output;
        let line = forwarded(session_id, params, stdio, &self.shim_dir);
        let finished = self.supervisor.run(line, call.caller)?;
        match mode {
            ExecStdio::Captured => captured_answer(finished, output),
            // Only how it ended (FR-OUT-04): its output went to the caller's descriptors, even when it was teed.
            ExecStdio::Passed => answer(&ExecRunResult {
                record_id: finished.record_id,
                status: finished.status,
            }),
        }
    }

    /// `exec.start`: decides and runs the line on its own thread, and answers once it is spawned.
    fn start(&self, call: &Call<'_>) -> Reply {
        let params: ExecRunParams = params(call)?;
        let session_id = agent_session(call)?;
        // Descriptors are only ever taken by `exec.run` (the dispatcher refuses them here), so a started line is
        // always captured.
        if params.stdio == ExecStdio::Passed {
            return Err(RpcError::new(ErrorCode::InvalidParams));
        }
        // Room is made before the line is decided: a start refused for lack of room must not leave a line running
        // that nobody can wait for or kill.
        self.jobs.forget_ended(|id| self.supervisor.session_live(id));
        if !self.jobs.has_room(session_id) {
            return Err(RpcError::new(ErrorCode::InvalidParams));
        }
        let output = params.output;
        let line = forwarded(session_id, params, None, &self.shim_dir);
        let control = Arc::clone(&line.control);
        let caller = Arc::new(FlagCaller::default());
        let supervisor = Arc::clone(&self.supervisor);
        let line_caller = Arc::clone(&caller);
        let line_control = Arc::clone(&control);
        std::thread::Builder::new()
            .name("knshd-line".to_owned())
            .spawn(move || line_control.finish(supervisor.run(line, line_caller.as_ref())))
            .map_err(|_| RpcError::new(ErrorCode::InternalError))?;
        let record_id = match control.wait_started(call.caller) {
            StartWait::Started(record_id) => record_id,
            // An error is the line refused, held or not started: the same answer `exec.run` would give. A success
            // without a start mark comes only from fakes; its record names it, if it was written.
            StartWait::Ended(ended) => (*ended)?
                .record_id
                .ok_or_else(|| RpcError::new(ErrorCode::InternalError))?,
            StartWait::CallerGone => {
                // FR-LC-41: the line is cancelled while its decision is pending, and never runs.
                caller.leave();
                // If the supervisor passed its last caller check just before, the line is spawned anyway: stop it,
                // since no handle for it was ever answered.
                control.request_kill();
                return Err(RpcError::new(ErrorCode::Cancelled));
            }
        };
        if let Err(error) = self.jobs.insert(session_id, record_id, Arc::clone(&control), output) {
            // Another start of the same session took the last place meanwhile: the line is refused, so it is stopped
            // rather than left running out of reach.
            control.request_kill();
            return Err(error);
        }
        answer(&ExecStartResult { record_id })
    }

    /// `exec.wait`: the answer of the line `exec.start` started, once it has ended. The first wait that returns it
    /// collects it.
    fn wait(&self, call: &Call<'_>) -> Reply {
        let (record_id, job) = self.job(call)?;
        let Some(result) = job.control.wait_finished(call.caller) else {
            // Nobody is left to read the answer; the line keeps running and can still be waited for.
            return Err(RpcError::new(ErrorCode::Cancelled));
        };
        self.jobs.remove(record_id);
        captured_answer(result?, job.output)
    }

    /// `exec.kill`: stops the started line's process group (SIGTERM, then SIGKILL after the grace).
    fn kill(&self, call: &Call<'_>) -> Reply {
        let (_, job) = self.job(call)?;
        answer(&ExecKillResult {
            killed: job.control.request_kill(),
        })
    }

    /// The started line `call`'s `record_id` names, and that record ID.
    ///
    /// # Errors
    ///
    /// `-32602` when the caller's session holds no such line: another session's line is answered as an unknown
    /// one, so record IDs reveal nothing across sessions.
    fn job(&self, call: &Call<'_>) -> Result<(RecordId, Waiting), RpcError> {
        let ExecHandleParams { record_id } = params(call)?;
        let session_id = agent_session(call)?;
        let job = self
            .jobs
            .get(session_id, record_id)
            .ok_or_else(|| RpcError::new(ErrorCode::InvalidParams))?;
        Ok((record_id, job))
    }
}

/// The agent session `call` is bound to. Agents only: `user.sock` never runs lines (the catalogue keeps it off
/// that endpoint too).
fn agent_session(call: &Call<'_>) -> Result<SessionId, RpcError> {
    if call.endpoint != Endpoint::Agent {
        return Err(RpcError::new(ErrorCode::NotAllowed));
    }
    call.binding.agent_session()
}

/// The answer for a captured line (module documentation): its output shaped by `options` or the profile's default
/// mode, fitted to one frame.
fn captured_answer(finished: Finished, options: OutputOptions) -> Reply {
    let request = options.request(finished.default_mode);
    let output = finished.output.unwrap_or_default();
    let mut outcome = ExecOutcome {
        record_id: finished.record_id,
        executed_command: finished.executed_command,
        status: finished.status,
        duration_ms: finished.duration_ms,
        decision: finished.decision,
        mode: request.mode,
        stdout: totals(&output.stdout),
        stderr: totals(&output.stderr),
        output: shape(request, &output.stdout, &output.stderr),
        cut_to_fit: false,
    };
    let result = outcome
        .to_json_within(MAX_EXEC_RESULT_LEN)
        .map_err(|_| RpcError::new(ErrorCode::InternalError))?;
    Ok(Answer::from(result))
}

/// A stream's size and line count.
fn totals(stream: &CapturedStream) -> StreamTotals {
    StreamTotals {
        size: stream.output.info().original,
        lines: stream.lines,
    }
}

/// `exec.*` when no supervisor could be built: every call is `-32005` for the sandbox, and its descriptors are
/// closed unused (fail closed, NFR-REL-08).
pub(crate) fn unserved_handlers() -> Handlers {
    let handler: Handler = Arc::new(|call: &Call<'_>| {
        drop(call.descriptors.take());
        Err(capability_unavailable("sandbox"))
    });
    [EXEC_RUN, EXEC_START, EXEC_WAIT, EXEC_KILL]
        .into_iter()
        .map(|name| (name, Arc::clone(&handler)))
        .collect()
}

/// The descriptors `mode` announces, from what arrived: three for [`ExecStdio::Passed`] (stdin, stdout, stderr in
/// that order), none otherwise. Any other count is `-32602`.
fn stdio(mode: ExecStdio, descriptors: Vec<OwnedFd>) -> Result<Option<Stdio>, RpcError> {
    if descriptors.len() != mode.descriptors() {
        return Err(RpcError::new(ErrorCode::InvalidParams));
    }
    let mut descriptors = descriptors.into_iter();
    match (descriptors.next(), descriptors.next(), descriptors.next()) {
        (Some(stdin), Some(stdout), Some(stderr)) => Ok(Some(Stdio { stdin, stdout, stderr })),
        // The count matched, so this is `Captured` with no descriptors.
        _ => Ok(None),
    }
}

/// The line the supervisor receives for `params`, sent on a connection bound to `session_id`.
fn forwarded(session_id: SessionId, params: ExecRunParams, stdio: Option<Stdio>, shim_dir: &Path) -> ForwardedLine {
    let env = supervised_env(params.env, shim_dir);
    let path = env
        .iter()
        .find(|(name, _)| name == PATH_VAR)
        .map_or_else(|| DEFAULT_POLICY_CHECK_PATH.to_owned(), |(_, value)| value.clone());
    ForwardedLine {
        session_id,
        proposal: Proposal {
            command: params.command,
            cwd: params.cwd,
            path,
        },
        interpreter: params.interpreter,
        args: params.args,
        env,
        stdio,
        timeout_s: params.timeout_s,
        control: LineControl::new(),
    }
}

/// The environment a supervised line runs with: `env` without the shim directory in `PATH` (FR-LC-16) and without
/// the session token. Everything else is kept unchanged and in order.
pub(crate) fn supervised_env(env: Vec<(String, String)>, shim_dir: &Path) -> Vec<(String, String)> {
    env.into_iter()
        .filter(|(name, _)| name != SESSION_TOKEN_VAR)
        .map(|(name, value)| {
            let value = if name == PATH_VAR {
                without_shims(&value, shim_dir)
            } else {
                value
            };
            (name, value)
        })
        .collect()
}

/// `path` without any entry naming `shim_dir`, other entries (empty ones too) kept in order. An entry names it if
/// it is the same path once trailing slashes are ignored: the forms an envelope's `PATH` holds it in.
pub(crate) fn without_shims(path: &str, shim_dir: &Path) -> String {
    let shims = trim_slashes(&shim_dir.to_string_lossy()).to_owned();
    path.split(':')
        .filter(|entry| trim_slashes(entry) != shims)
        .collect::<Vec<_>>()
        .join(":")
}

/// `entry` without trailing slashes, except that `/` stays `/`.
fn trim_slashes(entry: &str) -> &str {
    let trimmed = entry.trim_end_matches('/');
    if trimmed.is_empty() && entry.starts_with('/') {
        "/"
    } else {
        trimmed
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::sync::Mutex;

    use knsh_core::{PathContext, check_line, load_profile};
    use knsh_json::Value;
    use knsh_platform::testing::MemFs;
    use knsh_platform::{EnginePaths, Fs, PolicyDirectory};
    use knsh_proto::{ByteTransport, Denial, MethodName, Request, RequestId};

    use super::*;
    use crate::dispatch::Passed;
    use crate::dispatch::tests::{stream, subscriber};
    use crate::sessions::SessionBinding;
    use crate::sessions::tests::fixture;

    const HOME: &str = "/Users/u";

    fn shim_dir() -> PathBuf {
        EnginePaths::for_home(Path::new(HOME)).unwrap().shim_dir()
    }

    /// A supervisor that records what it receives and answers with `answer`; with `write`, it writes that to the
    /// line's stdout first, as a spawned line would. With `runs_until_killed`, it marks the line started and runs
    /// until `exec.kill`, then ends by `SIGTERM`.
    struct FakeSupervisor {
        received: Mutex<Vec<ForwardedLine>>,
        answer: Result<Finished, RpcError>,
        write: Option<&'static [u8]>,
        runs_until_killed: bool,
    }

    impl FakeSupervisor {
        fn new(answer: Result<Finished, RpcError>) -> Arc<Self> {
            Self::with_output(None, answer)
        }

        fn writing(write: &'static [u8], answer: Result<Finished, RpcError>) -> Arc<Self> {
            Self::with_output(Some(write), answer)
        }

        fn with_output(write: Option<&'static [u8]>, answer: Result<Finished, RpcError>) -> Arc<Self> {
            Arc::new(Self {
                received: Mutex::new(Vec::new()),
                answer,
                write,
                runs_until_killed: false,
            })
        }

        fn until_killed() -> Arc<Self> {
            Arc::new(Self {
                received: Mutex::new(Vec::new()),
                answer: exited(0),
                write: None,
                runs_until_killed: true,
            })
        }

        fn take(&self) -> Vec<ForwardedLine> {
            std::mem::take(&mut self.received.lock().unwrap())
        }
    }

    impl Supervisor for FakeSupervisor {
        fn run(&self, mut line: ForwardedLine, _caller: &dyn knsh_core::Caller) -> Result<Finished, RpcError> {
            if let (Some(bytes), Some(stdio)) = (self.write, line.stdio.as_mut()) {
                let mut stdout = std::fs::File::from(stdio.stdout.try_clone().unwrap());
                stdout.write_all(bytes).unwrap();
            }
            let control = Arc::clone(&line.control);
            self.received.lock().unwrap().push(line);
            if self.runs_until_killed {
                control.mark_started(RECORD);
                while !control.kill_requested() {
                    std::thread::sleep(std::time::Duration::from_millis(1));
                }
                return Ok(Finished {
                    status: LineStatus::Signalled(15),
                    ..finished(LineStatus::Exited(0), OutputMode::Full, b"", b"")
                });
            }
            self.answer.clone()
        }
    }

    const RECORD: RecordId = RecordId::from_ulid(knsh_core::Ulid::from_u128(9));

    /// A captured line that ended with `status`, wrote `stdout` and `stderr`, under a profile defaulting to `mode`.
    fn finished(status: LineStatus, mode: OutputMode, stdout: &[u8], stderr: &[u8]) -> Finished {
        let captured = |bytes: &[u8]| {
            let mut capture = knsh_core::OutputCapture::new(knsh_core::DEFAULT_OUTPUT_CAP);
            capture.push(bytes);
            capture.finish()
        };
        Finished {
            record_id: Some(RECORD),
            status,
            executed_command: Redacted::new("/usr/bin/make test".to_owned()),
            decision: Decision {
                verdict: knsh_core::DecisionVerdict::Allow,
                source: knsh_core::DecisionSource::Rule,
                rule_id: Some("exec.allow[0]".to_owned()),
                decided_by: None,
                hooks: Vec::new(),
            },
            duration_ms: 42,
            default_mode: mode,
            output: Some(LineOutput {
                stdout: captured(stdout),
                stderr: captured(stderr),
            }),
        }
    }

    // The shape a supervisor answers with, so it reads as one at the call sites.
    #[allow(clippy::unnecessary_wraps)]
    fn exited(code: u8) -> Result<Finished, RpcError> {
        Ok(Finished {
            record_id: None,
            output: None,
            ..finished(LineStatus::Exited(code), OutputMode::Full, b"", b"")
        })
    }

    /// An agent binding for a fresh agent session, and its ID.
    fn bound() -> (SessionBinding, SessionId, crate::sessions::tests::Fixture) {
        let fixture = fixture();
        let opened = fixture
            .sessions
            .open_agent(
                knsh_core::Actor::Agent(knsh_core::AgentId::new("claude-code").unwrap()),
                knsh_core::ProfileName::new("web").unwrap(),
            )
            .unwrap();
        let binding = SessionBinding::new();
        fixture
            .sessions
            .bind_agent(&binding, Some(&opened.token.encode()))
            .unwrap();
        (binding, opened.session_id, fixture)
    }

    fn request(params: &str) -> Request {
        Request {
            id: RequestId::from(1u32),
            method: MethodName::new(EXEC_RUN).unwrap(),
            params: knsh_json::parse(params.as_bytes(), 1 << 20)
                .unwrap()
                .as_object()
                .cloned(),
        }
    }

    fn call(
        service: &Arc<ExecRun>,
        endpoint: Endpoint,
        binding: &SessionBinding,
        params: &str,
        descriptors: Vec<OwnedFd>,
    ) -> Reply {
        call_method(service, EXEC_RUN, endpoint, binding, params, descriptors)
    }

    fn call_method(
        service: &Arc<ExecRun>,
        method: &str,
        endpoint: Endpoint,
        binding: &SessionBinding,
        params: &str,
        descriptors: Vec<OwnedFd>,
    ) -> Reply {
        let request = request(params);
        let passed = Passed::new(descriptors);
        service.handlers()[method](&Call {
            endpoint,
            bytes: ByteTransport::BinaryFrames,
            stream: stream(),
            request: &request,
            subscriber: subscriber(),
            binding,
            descriptors: &passed,
            caller: &knsh_core::StillWaiting,
            control: None,
        })
    }

    /// Three descriptors standing in for a caller's stdio: a pipe's write end as stdout, and the read end returned
    /// to the test.
    fn caller_stdio() -> (std::io::PipeReader, Vec<OwnedFd>) {
        let (read, write) = std::io::pipe().unwrap();
        let write = OwnedFd::from(write);
        let descriptors = vec![
            write.try_clone().unwrap(),
            write.try_clone().unwrap(),
            write.try_clone().unwrap(),
        ];
        (read, descriptors)
    }

    fn params_with(interpreter: &str) -> String {
        let shims = shim_dir().display().to_string();
        format!(
            r#"{{"command":"echo hi | tr a-z A-Z","cwd":"/Users/u/app","interpreter":"{interpreter}","stdio":"passed",
              "args":["name","one"],
              "env":{{"HOME":"/Users/u","PATH":"{shims}:/usr/bin:/bin","{SESSION_TOKEN_VAR}":"secret","LANG":"C"}}}}"#
        )
    }

    // FR-AGT-10, FR-LC-01: the supervisor receives the line, cwd, environment, operands and interpreter unchanged,
    // the bound session, and the caller's three descriptors.
    #[test]
    fn forwards_line_cwd_env_and_interpreter() {
        let (binding, session_id, _fixture) = bound();
        let supervisor = FakeSupervisor::new(exited(0));
        let service = ExecRun::new(supervisor.clone(), shim_dir());
        let (_read, descriptors) = caller_stdio();
        call(&service, Endpoint::Agent, &binding, &params_with("sh"), descriptors).unwrap();
        let [line] = <[ForwardedLine; 1]>::try_from(supervisor.take()).unwrap();
        assert_eq!(line.session_id, session_id);
        assert_eq!(line.proposal.command, "echo hi | tr a-z A-Z");
        assert_eq!(line.proposal.cwd.as_path(), Path::new("/Users/u/app"));
        assert_eq!(line.interpreter, Interpreter::Sh);
        assert_eq!(line.args, ["name", "one"]);
        assert_eq!(line.timeout_s, None);
        // All three, in order; here each is a copy of the same pipe.
        let stdio = line.stdio.as_ref().unwrap();
        let raw = [&stdio.stdin, &stdio.stdout, &stdio.stderr].map(std::os::fd::AsRawFd::as_raw_fd);
        assert!(raw[0] != raw[1] && raw[1] != raw[2]);
        let names: Vec<&str> = line.env.iter().map(|(name, _)| name.as_str()).collect();
        assert_eq!(names, ["HOME", "PATH", "LANG"], "order kept, token removed");
    }

    // FR-LC-16: the shim directory is gone from the PATH the line runs with and resolves names on.
    #[test]
    fn supervised_path_excludes_shim_directory() {
        let shims = shim_dir();
        let text = shims.display().to_string();
        for (path, expected) in [
            (format!("{text}:/usr/bin:/bin"), "/usr/bin:/bin".to_owned()),
            (format!("/usr/bin:{text}/:/bin:{text}"), "/usr/bin:/bin".to_owned()),
            (text.clone(), String::new()),
            // Empty entries (the current directory) and look-alikes are kept.
            (format!(":/usr/bin:{text}-old"), format!(":/usr/bin:{text}-old")),
        ] {
            assert_eq!(without_shims(&path, &shims), expected, "{path}");
        }
        let (binding, _, _fixture) = bound();
        let supervisor = FakeSupervisor::new(exited(0));
        let service = ExecRun::new(supervisor.clone(), shims.clone());
        let (_read, descriptors) = caller_stdio();
        call(&service, Endpoint::Agent, &binding, &params_with("bash"), descriptors).unwrap();
        let line = supervisor.take().remove(0);
        assert_eq!(line.proposal.path, "/usr/bin:/bin");
        assert!(line.env.contains(&("PATH".to_owned(), "/usr/bin:/bin".to_owned())));
        assert!(!line.env.iter().any(|(_, value)| value.contains(&text)));
    }

    // FR-LC-14: the interpreter reaches the supervisor only beside the proposal; the proposal, and so every decision
    // made from it, is the same whichever interpreter was asked for. Checked with the real policy evaluator.
    #[test]
    fn policy_verdict_independent_of_interpreter() {
        let (binding, _, _fixture) = bound();
        let supervisor = FakeSupervisor::new(exited(0));
        let service = ExecRun::new(supervisor.clone(), shim_dir());
        for interpreter in Interpreter::ALL {
            let (_read, descriptors) = caller_stdio();
            let params = params_with(interpreter.as_str()).replace("echo hi | tr a-z A-Z", "git push origin main");
            call(&service, Endpoint::Agent, &binding, &params, descriptors).unwrap();
        }
        let lines = supervisor.take();
        assert_eq!(lines.len(), Interpreter::ALL.len());
        let interpreters: Vec<Interpreter> = lines.iter().map(|line| line.interpreter).collect();
        assert_eq!(interpreters, Interpreter::ALL);
        assert!(lines.iter().all(|line| line.proposal == lines[0].proposal));

        // A profile that asks for `git push`; a fake `git` in the shim directory must not change the resolution.
        let fs = MemFs::new();
        for dir in ["/usr/bin", "/bin", "/tmp", "/Users/u/app"] {
            fs.add_dir_all(Path::new(dir)).unwrap();
        }
        fs.add_dir_all(&shim_dir()).unwrap();
        fs.write(&shim_dir().join("git"), b"#!/bin/sh\n", 0o755).unwrap();
        fs.write(Path::new("/usr/bin/git"), b"#!/bin/sh\n", 0o755).unwrap();
        let policies = EnginePaths::for_home(Path::new(HOME)).unwrap().policies_dir();
        fs.add_dir_all(&policies).unwrap();
        let web = "name = \"web\"\n[exec]\nallow = [\"git status\"]\nask = [\"git push\"]\n";
        fs.write(
            &policies.join("web.toml"),
            &crate::policy::tests::signed("web", web),
            0o600,
        )
        .unwrap();
        let context = PathContext {
            home: PathBuf::from(HOME),
            tmpdir: PathBuf::from("/tmp"),
            start_dir: PathBuf::from("/Users/u/app"),
        };
        let fs_ref: &dyn Fs = &fs;
        let signer = crate::policy::tests::test_signer();
        let profile = load_profile(
            &knsh_core::ProfileName::new("web").unwrap(),
            &PolicyDirectory::new(policies, fs_ref, &signer),
            &context,
            fs_ref,
        )
        .unwrap();
        let verdicts: Vec<_> = lines
            .iter()
            .map(|line| {
                let check = check_line(
                    &profile,
                    &line.proposal.command,
                    &line.proposal.path,
                    &line.proposal.cwd,
                    fs_ref,
                );
                let program = check.classification.commands()[0]
                    .program
                    .as_ref()
                    .and_then(|program| program.path())
                    .map(Path::to_path_buf);
                (check.decision.verdict, program)
            })
            .collect();
        assert!(verdicts.iter().all(|verdict| *verdict == verdicts[0]));
        assert_eq!(verdicts[0].0.as_str(), "ask");
        assert_eq!(verdicts[0].1.as_deref(), Some(Path::new("/usr/bin/git")));
    }

    // FR-OUT-04: the line writes to the caller's own descriptor; the answer holds the outcome and no output.
    #[test]
    fn output_goes_to_the_passed_descriptor_not_the_answer() {
        let (binding, _, _fixture) = bound();
        let supervisor = FakeSupervisor::writing(b"HI\n", exited(3));
        let service = ExecRun::new(supervisor.clone(), shim_dir());
        let (mut read, descriptors) = caller_stdio();
        let answer = call(&service, Endpoint::Agent, &binding, &params_with("knsh"), descriptors).unwrap();
        // Every copy of the write end is closed once the line is done with it.
        drop(supervisor.take());
        let mut out = String::new();
        read.read_to_string(&mut out).unwrap();
        assert_eq!(out, "HI\n");
        let result = answer.result.as_object().unwrap();
        assert_eq!(result.get("exit_code").and_then(Value::as_i64), Some(3));
        assert!(!knsh_json::write(&answer.result).unwrap().contains("HI"));
        assert_eq!(answer.bytes, None);
    }

    fn object(answer: &Answer) -> &knsh_json::Object {
        answer.result.as_object().unwrap()
    }

    fn text<'a>(answer: &'a Answer, field: &str) -> Option<&'a str> {
        object(answer).get(field).and_then(Value::as_str)
    }

    // FR-OUT-01, FR-AUTH-33: a captured line answers with its record, the line spawned, how it ended, its decision,
    // sizes, and its output in the requested mode.
    #[test]
    fn captured_line_answers_with_output_in_requested_mode() {
        let (binding, _, _fixture) = bound();
        let answer = finished(
            LineStatus::Exited(2),
            OutputMode::Full,
            b"compiling\nok\n",
            b"warning: x\n",
        );
        let service = ExecRun::new(FakeSupervisor::new(Ok(answer)), shim_dir());
        let params = r#"{"command":"make test","cwd":"/Users/u/app","output":{"mode":"truncate","max_bytes":4}}"#;
        let got = call(&service, Endpoint::Agent, &binding, params, Vec::new()).unwrap();
        assert_eq!(text(&got, "record_id"), Some("00000000000000000000000009"));
        assert_eq!(text(&got, "executed_command"), Some("/usr/bin/make test"));
        assert_eq!(object(&got).get("exit_code").and_then(Value::as_i64), Some(2));
        assert_eq!(object(&got).get("duration_ms").and_then(Value::as_i64), Some(42));
        assert_eq!(text(&got, "output_mode"), Some("truncate"));
        assert_eq!(text(&got, "stdout"), Some("comp"));
        assert_eq!(text(&got, "stdout_skipped"), Some("9"));
        assert_eq!(text(&got, "stderr"), Some("warn"));
        assert_eq!(text(&got, "stdout_size"), Some("13"));
        assert_eq!(object(&got).get("stdout_lines").and_then(Value::as_i64), Some(2));
        let decision = object(&got).get("decision").and_then(Value::as_object).unwrap();
        assert_eq!(decision.get("source").and_then(Value::as_str), Some("rule"));
        assert_eq!(got.bytes, None, "output is in the JSON answer, not a stream");
    }

    // FR-OUT-02: with no `output.mode`, the profile's default mode applies.
    #[test]
    fn uses_profile_default_mode_when_absent() {
        let (binding, _, _fixture) = bound();
        let stdout: Vec<u8> = (1..=30).flat_map(|i| format!("{i}\n").into_bytes()).collect();
        let answer = finished(LineStatus::Exited(1), OutputMode::ErrorsOnly, &stdout, b"boom\n");
        let service = ExecRun::new(FakeSupervisor::new(Ok(answer)), shim_dir());
        let got = call(
            &service,
            Endpoint::Agent,
            &binding,
            r#"{"command":"make","cwd":"/w"}"#,
            Vec::new(),
        )
        .unwrap();
        assert_eq!(text(&got, "output_mode"), Some("errors_only"));
        assert_eq!(text(&got, "stderr"), Some("boom\n"));
        let tail = (11..=30).fold(String::new(), |tail, i| tail + &i.to_string() + "\n");
        assert_eq!(text(&got, "stdout_tail"), Some(tail.as_str()));
        assert_eq!(
            object(&got).get("stdout_skipped_lines").and_then(Value::as_i64),
            Some(10)
        );
        assert!(object(&got).get("stdout").is_none());
        // The caller's mode wins over the default.
        let got = call(
            &service,
            Endpoint::Agent,
            &binding,
            r#"{"command":"make","cwd":"/w","output":{"mode":"ref"}}"#,
            Vec::new(),
        )
        .unwrap();
        assert_eq!(text(&got, "output_mode"), Some("ref"));
        assert!(object(&got).get("stderr").is_none());
    }

    // `exec.start` answers once the line is spawned; `exec.kill` stops it; `exec.wait` answers what `exec.run` would
    // have, once; another session cannot see the line.
    #[test]
    fn start_wait_and_kill_a_line() {
        let (binding, session_id, fixture) = bound();
        let supervisor = FakeSupervisor::until_killed();
        let service = ExecRun::new(supervisor.clone(), shim_dir());
        let started = call_method(
            &service,
            EXEC_START,
            Endpoint::Agent,
            &binding,
            r#"{"command":"sleep 100","cwd":"/w","output":{"mode":"ref"}}"#,
            Vec::new(),
        )
        .unwrap();
        assert_eq!(text(&started, "record_id"), Some("00000000000000000000000009"));
        assert_eq!(supervisor.take()[0].session_id, session_id);
        let handle = r#"{"record_id":"00000000000000000000000009"}"#;

        // Another session's connection: the line does not exist for it.
        let other = fixture
            .sessions
            .open_agent(
                knsh_core::Actor::Agent(knsh_core::AgentId::new("other").unwrap()),
                knsh_core::ProfileName::new("web").unwrap(),
            )
            .unwrap();
        let stranger = SessionBinding::new();
        fixture
            .sessions
            .bind_agent(&stranger, Some(&other.token.encode()))
            .unwrap();
        for method in [EXEC_WAIT, EXEC_KILL] {
            let error = call_method(&service, method, Endpoint::Agent, &stranger, handle, Vec::new()).unwrap_err();
            assert_eq!(error.code, ErrorCode::InvalidParams, "{method}");
        }

        let killed = call_method(&service, EXEC_KILL, Endpoint::Agent, &binding, handle, Vec::new()).unwrap();
        assert_eq!(object(&killed).get("killed"), Some(&Value::from(true)));
        let waited = call_method(&service, EXEC_WAIT, Endpoint::Agent, &binding, handle, Vec::new()).unwrap();
        assert_eq!(object(&waited).get("signal").and_then(Value::as_i64), Some(15));
        assert_eq!(object(&waited).get("exit_code"), Some(&Value::Null));
        assert_eq!(
            text(&waited, "output_mode"),
            Some("ref"),
            "the mode asked for at exec.start"
        );
        // Collected: the handle is gone.
        let error = call_method(&service, EXEC_WAIT, Endpoint::Agent, &binding, handle, Vec::new()).unwrap_err();
        assert_eq!(error.code, ErrorCode::InvalidParams);
        assert_eq!(service.jobs.len(), 0);
    }

    // `exec.start` of a refused line answers as `exec.run` would, and keeps nothing; passed stdio is refused.
    #[test]
    fn start_of_a_refused_line_answers_its_error() {
        let (binding, _, _fixture) = bound();
        let denial = Denial::default().to_error().unwrap();
        let service = ExecRun::new(FakeSupervisor::new(Err(denial.clone())), shim_dir());
        let error = call_method(
            &service,
            EXEC_START,
            Endpoint::Agent,
            &binding,
            r#"{"command":"rm -rf /","cwd":"/w"}"#,
            Vec::new(),
        )
        .unwrap_err();
        assert_eq!(error, denial);
        assert_eq!(service.jobs.len(), 0);
        let error = call_method(
            &service,
            EXEC_START,
            Endpoint::Agent,
            &binding,
            r#"{"command":"true","cwd":"/w","stdio":"passed"}"#,
            Vec::new(),
        )
        .unwrap_err();
        assert_eq!(error.code, ErrorCode::InvalidParams);
    }

    // A denial or a held session reaches the caller as the supervisor answered it.
    #[test]
    fn supervisor_errors_are_answered_unchanged() {
        let (binding, _, _fixture) = bound();
        let denial = Denial {
            rule_id: Some("exec.deny[0]".to_owned()),
            reason: Some("no".to_owned()),
            source: Some("rule".to_owned()),
        }
        .to_error()
        .unwrap();
        for error in [denial, RpcError::new(ErrorCode::SessionHeld)] {
            let service = ExecRun::new(FakeSupervisor::new(Err(error.clone())), shim_dir());
            let (_read, descriptors) = caller_stdio();
            let got = call(&service, Endpoint::Agent, &binding, &params_with("knsh"), descriptors).unwrap_err();
            assert_eq!(got, error);
        }
    }

    // Descriptors must match `stdio`; the session must be a bound agent session on agent.sock; params are strict.
    // Nothing reaches the supervisor otherwise.
    #[test]
    fn refuses_mismatched_descriptors_and_unbound_callers() {
        let (binding, _, _fixture) = bound();
        let supervisor = FakeSupervisor::new(exited(0));
        let service = ExecRun::new(supervisor.clone(), shim_dir());
        let passed = params_with("knsh");
        let captured = passed.replace(r#","stdio":"passed""#, "");
        let cases: Vec<(Endpoint, &SessionBinding, String, usize, ErrorCode)> = vec![
            (Endpoint::Agent, &binding, passed.clone(), 2, ErrorCode::InvalidParams),
            (Endpoint::Agent, &binding, passed.clone(), 0, ErrorCode::InvalidParams),
            (Endpoint::Agent, &binding, captured, 3, ErrorCode::InvalidParams),
            (
                Endpoint::Agent,
                &binding,
                r#"{"command":"x"}"#.to_owned(),
                3,
                ErrorCode::InvalidParams,
            ),
            (Endpoint::User, &binding, passed.clone(), 3, ErrorCode::NotAllowed),
        ];
        for (endpoint, binding, params, count, code) in cases {
            let (_read, mut descriptors) = caller_stdio();
            descriptors.truncate(count);
            let error = call(&service, endpoint, binding, &params, descriptors).unwrap_err();
            assert_eq!(error.code, code, "{params} with {count}");
        }
        let unbound = SessionBinding::new();
        let (_read, descriptors) = caller_stdio();
        let error = call(&service, Endpoint::Agent, &unbound, &passed, descriptors).unwrap_err();
        assert_eq!(error.code, ErrorCode::NotAllowed);
        assert!(supervisor.take().is_empty());
    }
}
