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
//! `exec.run` stays `planned` in the method catalogue until the supervisor exists (KNSH-050): `hello` does not list
//! it and a call is `-32601`, so no line can reach a supervisor that would not decide it. The handler is complete
//! and tested against a fake supervisor.

use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use knsh_core::{CanonicalPath, RecordId, SessionId};
use knsh_proto::{
    DEFAULT_POLICY_CHECK_PATH, ErrorCode, ExecRunParams, ExecRunResult, ExecStdio, Interpreter, LineStatus, RpcError,
    SESSION_TOKEN_VAR,
};

use crate::dispatch::{Call, EXEC_RUN, Endpoint, Handler, Handlers, Reply, answer, params};

/// The variable names are resolved on, and the one the shims are stripped from.
const PATH_VAR: &str = "PATH";

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
}

/// How a supervised line ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Finished {
    /// Its execution record (KNSH-052).
    pub(crate) record_id: Option<RecordId>,
    /// Its exit code or signal.
    pub(crate) status: LineStatus,
}

/// Decides and runs forwarded lines: the lifecycle orchestrator (KNSH-050) and spawner (KNSH-051).
///
/// The contract the handler relies on: a line is run only after its whole [`Proposal`] has been allowed, and every
/// failure to decide is a denial (`-32001`), never a run. A held session is `-32007`, answered at once.
pub(crate) trait Supervisor: Send + Sync {
    /// Decides `line`, runs it if allowed, and waits for it to end.
    ///
    /// # Errors
    ///
    /// The answer for a line that did not run to its end: `-32001` denied (with `rule_id`, `reason` and `source`),
    /// `-32007` held, `-32008` timed out, and the other codes of `specs/06-api/agent-socket.md#execrun`.
    fn run(&self, line: ForwardedLine) -> Result<Finished, RpcError>;
}

/// The `exec.run` service.
pub(crate) struct ExecRun {
    supervisor: Arc<dyn Supervisor>,
    /// [`knsh_platform::EnginePaths::shim_dir`].
    shim_dir: PathBuf,
}

impl ExecRun {
    /// The service handing lines to `supervisor`, stripping `shim_dir` from their `PATH`.
    pub(crate) fn new(supervisor: Arc<dyn Supervisor>, shim_dir: PathBuf) -> Arc<Self> {
        Arc::new(Self { supervisor, shim_dir })
    }

    /// The `exec.run` handler.
    pub(crate) fn handlers(self: &Arc<Self>) -> Handlers {
        let service = Arc::clone(self);
        let handler: Handler = Arc::new(move |call: &Call<'_>| service.run(call));
        [(EXEC_RUN, handler)].into_iter().collect()
    }

    /// `exec.run` (module documentation).
    fn run(&self, call: &Call<'_>) -> Reply {
        // Taken first, so every early return below closes them.
        let descriptors = call.descriptors.take();
        let params: ExecRunParams = params(call)?;
        // Agents only: `user.sock` never runs lines (the catalogue keeps it off that endpoint too).
        if call.endpoint != Endpoint::Agent {
            return Err(RpcError::new(ErrorCode::NotAllowed));
        }
        let session_id = call.binding.agent_session()?;
        let stdio = stdio(params.stdio, descriptors)?;
        let line = forwarded(session_id, params, stdio, &self.shim_dir);
        let finished = self.supervisor.run(line)?;
        answer(&ExecRunResult {
            record_id: finished.record_id,
            status: finished.status,
        })
    }
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
    /// line's stdout first, as a spawned line would.
    struct FakeSupervisor {
        received: Mutex<Vec<ForwardedLine>>,
        answer: Result<Finished, RpcError>,
        write: Option<&'static [u8]>,
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
            })
        }

        fn take(&self) -> Vec<ForwardedLine> {
            std::mem::take(&mut self.received.lock().unwrap())
        }
    }

    impl Supervisor for FakeSupervisor {
        fn run(&self, mut line: ForwardedLine) -> Result<Finished, RpcError> {
            if let (Some(bytes), Some(stdio)) = (self.write, line.stdio.as_mut()) {
                let mut stdout = std::fs::File::from(stdio.stdout.try_clone().unwrap());
                stdout.write_all(bytes).unwrap();
            }
            self.received.lock().unwrap().push(line);
            self.answer.clone()
        }
    }

    // The shape a supervisor answers with, so it reads as one at the call sites.
    #[allow(clippy::unnecessary_wraps)]
    fn exited(code: u8) -> Result<Finished, RpcError> {
        Ok(Finished {
            record_id: None,
            status: LineStatus::Exited(code),
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
        let request = request(params);
        let passed = Passed::new(descriptors);
        service.handlers()[EXEC_RUN](&Call {
            endpoint,
            bytes: ByteTransport::BinaryFrames,
            stream: stream(),
            request: &request,
            subscriber: subscriber(),
            binding,
            descriptors: &passed,
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
        fs.write(&policies.join("web.toml"), web.as_bytes(), 0o600).unwrap();
        let context = PathContext {
            home: PathBuf::from(HOME),
            tmpdir: PathBuf::from("/tmp"),
            start_dir: PathBuf::from("/Users/u/app"),
        };
        let fs_ref: &dyn Fs = &fs;
        let profile = load_profile(
            &knsh_core::ProfileName::new("web").unwrap(),
            &PolicyDirectory::new(policies, fs_ref),
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
