//! Forwarding one line to the supervisor and turning its answer into an exit status (KNSH-049, FR-AGT-10, FR-LC-31,
//! NFR-COMPAT-09, NFR-REL-01).
//!
//! `knsh -c 'line'` inside an envelope does not run `line`. It sends it, with the working directory, the whole
//! environment, the operands after it and the interpreter it was invoked as, over `agent.sock` as `exec.run`, its
//! own stdin, stdout and stderr attached as descriptors; then it waits, and exits as the line did. The supervisor
//! decides and runs the line on those descriptors, so the line's output goes straight to whoever reads `knsh`'s
//! output and never passes through `knsh` or the API (FR-OUT-04).
//!
//! **Nothing runs here.** No path in this module (or anything it calls) executes the line, whatever fails: an
//! unreachable `knshd`, a refused session, a connection lost mid-line, an answer that cannot be read. Each is an
//! exit status and a message on stderr, never a fallback (NFR-REL-01).
//!
//! | Answer | Exit status | On stderr |
//! | --- | --- | --- |
//! | The line exited with `n` | `n` | nothing |
//! | A signal `n` ended the line | 128 + `n` | nothing |
//! | `-32001` denied | 126 | `knsh: denied: <reason> (rule <rule_id>, <source>)` |
//! | `-32007` session held | none yet: waits [`HOLD_RETRY`] and asks again | one notice, the first time |
//! | `knshd` unreachable, `-32009`, any other error | 126 | why the line did not run, or that its outcome is unknown |
//!
//! Which envelope (if any) the caller is in is never decided here: `knshd` binds the connection by the session token
//! from the environment, or by the caller's audit token, and refuses anything else (`-32009`). Nothing else in the
//! environment, and nothing `knsh` was told, can change which session or policy applies (FR-AGT-20).

use std::ffi::{OsStr, OsString};
use std::fmt::Write as _;
use std::path::Path;
use std::time::Duration;

use knsh_core::CanonicalPath;
use knsh_json::{FromJson, ToJson, Value};
use knsh_proto::{
    Denial, ErrorCode, ExecRunParams, ExecRunResult, ExecStdio, Interpreter, LineStatus, MAX_EXEC_ARGS,
    MAX_EXEC_COMMAND_LEN, MAX_EXEC_ENV_ENTRIES,
};

use crate::cli::args::ShellInvocation;
use crate::cli::client::ClientError;
use crate::cli::terminal::escape_text;

/// The exit status of a line that did not run, or whose outcome is unknown: 126, as for a denial (FR-LC-31).
pub const NOT_RUN_STATUS: u8 = 126;

/// How long a held line waits before it is asked for again (`-32007`, KNSH-054).
pub const HOLD_RETRY: Duration = Duration::from_secs(1);

/// The program name a line without `-c` runs under when `knsh` itself was invoked (`knsh script.sh`): `knsh -c`
/// lines run with the profile's bash, so a script does too.
const KNSH_SCRIPT_SHELL: &str = "bash";

/// The line to forward, from how `knsh` was invoked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Line {
    /// The line, as given.
    pub command: OsString,
    /// The operands after it: `$0`, `$1`, ….
    pub args: Vec<OsString>,
    /// The interpreter asked for.
    pub interpreter: Interpreter,
}

/// The line `shell` asks `interpreter` to run.
///
/// With `-c`, the line and its operands exactly as given. Without (`bash script.sh a b`, or `sh` reading commands
/// from stdin), the equivalent line: the interpreter's own name followed by the operands, each single-quoted, so the
/// supervisor runs the same thing and decides it as one more command of the line (a script is code the policy sees
/// as such). `-l` and `-i` change nothing: a supervised line never reads startup files or prompts.
#[must_use]
pub fn line(shell: &ShellInvocation, interpreter: Interpreter) -> Line {
    if let Some(command) = &shell.command {
        return Line {
            command: command.clone(),
            args: shell.operands.clone(),
            interpreter,
        };
    }
    let program = match interpreter {
        Interpreter::Knsh => KNSH_SCRIPT_SHELL,
        Interpreter::Bash | Interpreter::Sh | Interpreter::Zsh => interpreter.as_str(),
    };
    let mut command = OsString::from(program);
    // A first operand that looks like an option was a script name to the shim (option processing had ended, after
    // `--`); quoting does not stop the inner shell reading it as an option, so `--` keeps it a script name.
    if shell
        .operands
        .first()
        .is_some_and(|first| first.as_encoded_bytes().first() == Some(&b'-'))
    {
        command.push(" --");
    }
    for operand in &shell.operands {
        command.push(" ");
        command.push(quote(operand));
    }
    Line {
        command,
        args: Vec::new(),
        interpreter,
    }
}

/// `word` single-quoted for a POSIX shell: `'` is written `'\''`.
fn quote(word: &OsStr) -> OsString {
    match word.to_str() {
        Some(text) => format!("'{}'", text.replace('\'', "'\\''")).into(),
        // Not UTF-8: refused by `request` anyway; kept as given, never altered.
        None => word.to_owned(),
    }
}

/// Why a line cannot be forwarded. Nothing runs either way.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// The line, an operand, the directory or an environment entry is not UTF-8: JSON cannot carry it unchanged.
    NotUtf8(&'static str),
    /// The line, the operands or the environment is over the protocol's bounds.
    TooLarge(&'static str),
    /// The working directory is not an absolute, resolved path.
    Cwd,
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotUtf8(what) => write!(f, "the {what} is not valid UTF-8, so it cannot be supervised"),
            Self::TooLarge(what) => write!(f, "the {what} is too large to be supervised"),
            Self::Cwd => f.write_str("the working directory is not an absolute, resolved path"),
        }
    }
}

/// The `exec.run` parameters for `line`, run in `cwd` with `env`: everything unchanged, stdio passed.
///
/// # Errors
///
/// A [`Refusal`] when something cannot travel unchanged: never altered to fit.
pub fn request(line: &Line, cwd: &Path, env: &[(OsString, OsString)]) -> Result<ExecRunParams, Refusal> {
    let command = utf8(&line.command, "command line")?;
    // A NUL is refused by `knshd` with the same bound as length (`out_of_range("command")`), so it is reported the
    // same way here rather than sent to be refused there.
    if command.len() > MAX_EXEC_COMMAND_LEN || command.contains('\0') {
        return Err(Refusal::TooLarge("command line"));
    }
    if line.args.len() > MAX_EXEC_ARGS {
        return Err(Refusal::TooLarge("argument list"));
    }
    let args = line
        .args
        .iter()
        .map(|arg| utf8(arg, "argument list"))
        .collect::<Result<Vec<_>, _>>()?;
    if env.len() > MAX_EXEC_ENV_ENTRIES {
        return Err(Refusal::TooLarge("environment"));
    }
    let env = env
        .iter()
        .map(|(name, value)| Ok((utf8(name, "environment")?, utf8(value, "environment")?)))
        .collect::<Result<Vec<_>, _>>()?;
    let cwd = utf8(cwd.as_os_str(), "working directory")?;
    let cwd = CanonicalPath::new(cwd).map_err(|_| Refusal::Cwd)?;
    Ok(ExecRunParams {
        command,
        cwd,
        env,
        interpreter: line.interpreter,
        args,
        stdio: ExecStdio::Passed,
        timeout_s: None,
        // Output modes are for captured lines only (FR-OUT-03): `knsh -c` output goes to its own descriptors.
        output: knsh_proto::OutputOptions::default(),
    })
}

fn utf8(text: &OsStr, what: &'static str) -> Result<String, Refusal> {
    text.to_str().map(str::to_owned).ok_or(Refusal::NotUtf8(what))
}

/// How `knsh -c` ends: its exit status, and what it prints on stderr first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Exit {
    /// The exit status.
    pub status: u8,
    /// A line for stderr, ending in a newline, or `None` when the line ran and ended by itself.
    pub message: Option<String>,
}

impl Exit {
    fn line(status: LineStatus) -> Self {
        Self {
            status: status.shell_status(),
            message: None,
        }
    }

    fn not_run(message: &str) -> Self {
        Self {
            status: NOT_RUN_STATUS,
            message: Some(format!("knsh: {message}\n")),
        }
    }
}

/// A connection to `agent.sock`, as [`forward`] uses it. The real one is a Unix socket passing this process's stdio
/// (`super::socket`); tests use a script.
pub trait AgentSocket {
    /// Connects and completes `hello`, with `session_token` when there is one.
    ///
    /// # Errors
    ///
    /// [`ClientError::Connect`] when `knshd` cannot be reached; [`ClientError::Rpc`] with `-32009` when the caller
    /// is in no live session's envelope; any other [`ClientError`].
    fn open(&mut self, session_token: Option<&str>) -> Result<(), ClientError>;

    /// Sends `exec.run` with `params` and this process's stdin, stdout and stderr, and waits for the answer.
    ///
    /// # Errors
    ///
    /// Any [`ClientError`]: an error answer, or none at all.
    fn exec_run(&mut self, params: &Value) -> Result<Value, ClientError>;
}

/// Forwards `params` over `socket` and returns how `knsh` must exit (module documentation). A held line is asked for
/// again after each `wait`; `notices` gets the one line saying so.
pub fn forward(
    socket: &mut dyn AgentSocket,
    session_token: Option<&str>,
    params: &ExecRunParams,
    wait: &mut dyn FnMut(Duration),
    notices: &mut dyn FnMut(&str),
) -> Exit {
    let Ok(params) = params.to_json() else {
        // Only possible with a repeated environment name, which an environment never has.
        return Exit::not_run("the request could not be built; the line did not run");
    };
    match socket.open(session_token) {
        Ok(()) => {}
        Err(ClientError::Rpc(error)) if error.code == ErrorCode::InvalidSessionToken => {
            return Exit::not_run(&outside_envelope(session_token.is_some()));
        }
        Err(error) => return Exit::not_run(&unavailable(&error)),
    }
    let mut told = false;
    loop {
        match socket.exec_run(&params) {
            Ok(result) => return finished(&result),
            // KNSH-054: a paused session, or one under human control, holds the line. `knsh` stays held with it
            // (asking again until the session is resumed), and does not fail: the agent sees a slow command.
            Err(ClientError::Rpc(error)) if error.code == ErrorCode::SessionHeld => {
                if !told {
                    notices(&held_notice(error.data.as_ref()));
                    told = true;
                }
                wait(HOLD_RETRY);
            }
            Err(ClientError::Rpc(error)) => return refused(&error),
            Err(error) => return Exit::not_run(&lost(&error)),
        }
    }
}

/// The exit for a result: the line's own status, or 126 when the result cannot be read.
fn finished(result: &Value) -> Exit {
    match ExecRunResult::from_json(result) {
        Ok(result) => Exit::line(result.status),
        Err(_) => Exit::not_run("knshd sent an answer this client cannot read; the line's outcome is unknown"),
    }
}

/// The exit for an error answer to `exec.run`: always 126, with the denial's reason and rule when it is one.
fn refused(error: &knsh_proto::RpcError) -> Exit {
    let Some(denial) = Denial::from_error(error) else {
        let meaning = match error.code {
            ErrorCode::InvalidSessionToken => "the agent session has ended",
            other => other.meaning(),
        };
        return Exit::not_run(&format!("{}; the line did not run to completion", lower(meaning)));
    };
    Exit::not_run(&denial_message(&denial))
}

/// `denied: <reason> (rule <rule_id>, <source>)`, with whatever parts are known, each terminal-safe: the reason may
/// quote the line, which the agent wrote.
fn denial_message(denial: &Denial) -> String {
    let mut message = String::from("denied");
    match &denial.reason {
        Some(reason) => {
            let _ = write!(message, ": {}", escape_text(reason));
        }
        None => message.push_str(" by policy"),
    }
    let details: Vec<String> = [
        denial
            .rule_id
            .as_deref()
            .map(|rule| format!("rule {}", escape_text(rule))),
        denial.source.as_deref().map(escape_text),
    ]
    .into_iter()
    .flatten()
    .collect();
    if !details.is_empty() {
        let _ = write!(message, " ({})", details.join(", "));
    }
    message
}

/// The notice for a held line, naming the session's state when `knshd` gave one.
fn held_notice(data: Option<&Value>) -> String {
    let state = data
        .and_then(Value::as_object)
        .and_then(|data| data.get("state"))
        .and_then(Value::as_str)
        .map(escape_text);
    match state {
        Some(state) => format!("knsh: the session is {state}; the line is held until it resumes\n"),
        None => "knsh: the session is held; the line waits until it resumes\n".to_owned(),
    }
}

/// Why nothing ran when `knshd` could not be asked (NFR-REL-01).
fn unavailable(error: &ClientError) -> String {
    format!("the supervisor is unavailable ({error}); the line did not run")
}

/// Why nothing ran when `knshd` bound the caller to no session.
fn outside_envelope(had_token: bool) -> String {
    if had_token {
        "the agent session has ended or its token is not valid; the line did not run".to_owned()
    } else {
        // FR-AGT-21: outside any envelope, non-interactive lines run under the `unattended` profile (a later story);
        // until then they do not run at all, and never run unsupervised.
        "not inside an agent envelope, and the unattended profile is not implemented yet; the line did not run"
            .to_owned()
    }
}

/// Why the outcome is unknown when the connection failed after the line was sent.
fn lost(error: &ClientError) -> String {
    format!("{error}; the line's outcome is unknown")
}

/// `text` with its first letter in lower case, to follow `knsh: `.
fn lower(text: &str) -> String {
    let mut chars = text.chars();
    chars
        .next()
        .map_or_else(String::new, |first| first.to_lowercase().chain(chars).collect())
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::io;

    use knsh_json::Object;
    use knsh_proto::RpcError;

    use super::*;

    /// A scripted `agent.sock`: answers `open` and each `exec.run` in turn, and remembers what was sent.
    struct Script {
        open: Option<Result<(), ClientError>>,
        answers: VecDeque<Result<Value, ClientError>>,
        tokens: Vec<Option<String>>,
        sent: Vec<Value>,
    }

    impl Script {
        fn new(open: Result<(), ClientError>, answers: Vec<Result<Value, ClientError>>) -> Self {
            Self {
                open: Some(open),
                answers: answers.into(),
                tokens: Vec::new(),
                sent: Vec::new(),
            }
        }
    }

    impl AgentSocket for Script {
        fn open(&mut self, session_token: Option<&str>) -> Result<(), ClientError> {
            self.tokens.push(session_token.map(str::to_owned));
            self.open.take().unwrap()
        }

        fn exec_run(&mut self, params: &Value) -> Result<Value, ClientError> {
            self.sent.push(params.clone());
            self.answers.pop_front().unwrap()
        }
    }

    fn params() -> ExecRunParams {
        let line = Line {
            command: OsString::from("echo hi | tr a-z A-Z"),
            args: Vec::new(),
            interpreter: Interpreter::Knsh,
        };
        request(
            &line,
            Path::new("/w"),
            &[(OsString::from("PATH"), OsString::from("/usr/bin"))],
        )
        .unwrap()
    }

    // The shape a socket answers with, so it reads as one in the scripts.
    #[allow(clippy::unnecessary_wraps)]
    fn result(text: &str) -> Result<Value, ClientError> {
        Ok(knsh_json::parse(text.as_bytes(), 1 << 16).unwrap())
    }

    fn rpc(error: RpcError) -> Result<Value, ClientError> {
        Err(ClientError::Rpc(error))
    }

    /// Runs `forward` over `script` with `token`; returns the exit, the waits and the notices.
    fn run(script: &mut Script, token: Option<&str>) -> (Exit, usize, Vec<String>) {
        let mut waits = 0;
        let mut notices = Vec::new();
        let exit = forward(script, token, &params(), &mut |_| waits += 1, &mut |text| {
            notices.push(text.to_owned());
        });
        (exit, waits, notices)
    }

    // FR-AGT-10: the line, cwd, full environment and requested interpreter go out unchanged, with stdio passed, and
    // the session token goes in `hello`.
    #[test]
    fn forwards_line_cwd_env_and_interpreter() {
        let shell = ShellInvocation {
            command: Some(OsString::from("printf '%s\\n' \"$1\" ; exit 3")),
            operands: vec![OsString::from("name"), OsString::from("one two")],
            ..ShellInvocation::default()
        };
        let line = line(&shell, Interpreter::Zsh);
        let env = vec![
            (OsString::from("PATH"), OsString::from("/shims:/usr/bin")),
            (OsString::from("EMPTY"), OsString::new()),
            (OsString::from("LANG"), OsString::from("C.UTF-8")),
        ];
        let params = request(&line, Path::new("/Users/me/app"), &env).unwrap();
        let mut script = Script::new(Ok(()), vec![result(r#"{"exit_code":0}"#)]);
        let mut waits = 0;
        forward(&mut script, Some("tok"), &params, &mut |_| waits += 1, &mut |_| {});
        assert_eq!(script.tokens, [Some("tok".to_owned())]);
        let sent = ExecRunParams::from_json(&script.sent[0]).unwrap();
        assert_eq!(sent, params);
        assert_eq!(sent.command, "printf '%s\\n' \"$1\" ; exit 3");
        assert_eq!(sent.args, ["name", "one two"]);
        assert_eq!(sent.cwd.as_path(), Path::new("/Users/me/app"));
        assert_eq!(sent.interpreter, Interpreter::Zsh);
        assert_eq!(sent.stdio, ExecStdio::Passed);
        let names: Vec<&str> = sent.env.iter().map(|(name, _)| name.as_str()).collect();
        assert_eq!(names, ["PATH", "EMPTY", "LANG"]);
    }

    // FR-AGT-10: knsh exits with the line's exit code, and says nothing.
    #[test]
    fn exits_with_line_exit_code() {
        for code in [0u8, 1, 3, 127, 255] {
            let mut script = Script::new(Ok(()), vec![result(&format!(r#"{{"exit_code":{code}}}"#))]);
            let (exit, _, _) = run(&mut script, None);
            assert_eq!(
                exit,
                Exit {
                    status: code,
                    message: None
                }
            );
        }
    }

    // FR-LC-31: a denial exits 126 with the reason and the rule on stderr.
    #[test]
    fn exits_126_and_prints_reason_on_denial() {
        let denial = Denial {
            rule_id: Some("exec.deny[2]".to_owned()),
            reason: Some("force-push is not allowed\u{1b}[2J".to_owned()),
            source: Some("rule".to_owned()),
        };
        let mut script = Script::new(Ok(()), vec![rpc(denial.to_error().unwrap())]);
        let (exit, _, _) = run(&mut script, Some("t"));
        assert_eq!(exit.status, 126);
        let message = exit.message.unwrap();
        assert_eq!(
            message, "knsh: denied: force-push is not allowed\\e[2J (rule exec.deny[2], rule)\n",
            "terminal-safe: the escape sequence is shown, not sent"
        );
        // Without details there is still a reason line.
        let mut script = Script::new(Ok(()), vec![rpc(RpcError::new(ErrorCode::Denied))]);
        let (exit, _, _) = run(&mut script, None);
        assert_eq!(exit.status, 126);
        assert_eq!(exit.message.unwrap(), "knsh: denied by policy\n");
    }

    // NFR-COMPAT-09: a line ended by signal n exits 128 + n.
    #[test]
    fn maps_signal_termination_to_128_plus_n() {
        for (signal, status) in [(2u8, 130u8), (9, 137), (15, 143)] {
            let mut script = Script::new(Ok(()), vec![result(&format!(r#"{{"signal":{signal}}}"#))]);
            let (exit, _, _) = run(&mut script, None);
            assert_eq!(exit, Exit { status, message: None });
        }
    }

    // NFR-REL-01: with knshd unreachable, nothing is sent, nothing runs, and knsh exits 126 saying why. There is no
    // local fallback to reach: the script would panic on any `exec_run`.
    #[test]
    fn never_executes_locally_when_daemon_unreachable() {
        for failure in [
            ClientError::Connect(io::Error::from(io::ErrorKind::NotFound)),
            ClientError::Connect(io::Error::from(io::ErrorKind::ConnectionRefused)),
            ClientError::Closed,
            ClientError::Protocol,
        ] {
            let mut script = Script::new(Err(failure), Vec::new());
            let (exit, _, _) = run(&mut script, Some("t"));
            assert_eq!(exit.status, 126);
            let message = exit.message.unwrap();
            assert!(message.contains("supervisor is unavailable"), "{message}");
            assert!(message.contains("did not run"), "{message}");
            assert_eq!(script.sent.len(), 0, "nothing was sent");
        }
        // Refused by knshd at hello: with a token (an ended session) or without (not in any envelope).
        for token in [Some("t"), None] {
            let mut script = Script::new(
                Err(ClientError::Rpc(RpcError::new(ErrorCode::InvalidSessionToken))),
                vec![],
            );
            let (exit, _, _) = run(&mut script, token);
            assert_eq!(exit.status, 126);
            assert!(exit.message.unwrap().contains("did not run"));
            assert_eq!(script.sent.len(), 0, "nothing was sent");
        }
        // Lost after sending: the outcome is unknown, and it is not retried (it may have run).
        let mut script = Script::new(Ok(()), vec![Err(ClientError::Closed)]);
        let (exit, _, _) = run(&mut script, None);
        assert_eq!(exit.status, 126);
        assert!(exit.message.unwrap().contains("outcome is unknown"));
        assert_eq!(script.sent.len(), 1);
    }

    // FR-OUT-04: the request asks for passed stdio and carries no output mode; the client takes only the outcome
    // from the answer, so output in a result is never printed.
    #[test]
    fn does_not_serialise_output_into_json() {
        let params = params().to_json().unwrap();
        let object = params.as_object().unwrap();
        assert_eq!(object.get("stdio").and_then(Value::as_str), Some("passed"));
        assert!(object.get("output").is_none());
        let mut script = Script::new(
            Ok(()),
            vec![result(r#"{"exit_code":0,"stdout":"LEAKED","stderr":"LEAKED"}"#)],
        );
        let (exit, _, notices) = run(&mut script, None);
        assert_eq!(
            exit,
            Exit {
                status: 0,
                message: None
            }
        );
        assert_eq!(notices.len(), 0);
    }

    // KNSH-054: a held line stays held (one notice, then waits and asks again) and finishes when the session resumes.
    #[test]
    fn stays_held_while_the_session_is_paused() {
        let state = Object::new().with("state", "paused").unwrap();
        let held = || rpc(RpcError::new(ErrorCode::SessionHeld).with_data(Value::Object(state.clone())));
        let mut script = Script::new(Ok(()), vec![held(), held(), held(), result(r#"{"exit_code":4}"#)]);
        let (exit, waits, notices) = run(&mut script, Some("t"));
        assert_eq!(
            exit,
            Exit {
                status: 4,
                message: None
            }
        );
        assert_eq!(waits, 3);
        assert_eq!(
            notices,
            ["knsh: the session is paused; the line is held until it resumes\n"]
        );
        assert_eq!(script.sent.len(), 4, "the same line, asked for again");
        assert!(script.sent.iter().all(|sent| *sent == script.sent[0]));
    }

    // Any other error answer: 126, with its meaning, never a retry.
    #[test]
    fn other_errors_exit_126() {
        for code in [
            ErrorCode::LineTimedOut,
            ErrorCode::InvalidParams,
            ErrorCode::InvalidSessionToken,
        ] {
            let mut script = Script::new(Ok(()), vec![rpc(RpcError::new(code))]);
            let (exit, waits, _) = run(&mut script, None);
            assert_eq!(exit.status, 126, "{code:?}");
            assert_eq!(waits, 0);
        }
        let mut script = Script::new(Ok(()), vec![result(r#"{"exit_code":0,"signal":9}"#)]);
        assert_eq!(run(&mut script, None).0.status, 126);
    }

    // Without -c, the equivalent line: the interpreter's name and its operands, quoted.
    #[test]
    fn script_and_stdin_forms_become_the_equivalent_line() {
        let shell = ShellInvocation {
            operands: vec![OsString::from("build.sh"), OsString::from("it's")],
            ..ShellInvocation::default()
        };
        let forwarded = line(&shell, Interpreter::Sh);
        assert_eq!(forwarded.command, "sh 'build.sh' 'it'\\''s'");
        assert_eq!(forwarded.args.len(), 0);
        assert_eq!(line(&ShellInvocation::default(), Interpreter::Bash).command, "bash");
        // `bash -- -c 'rm x'` runs a script named `-c`: forwarded so the inner bash does too, never as `bash -c`.
        let shell = ShellInvocation {
            operands: vec![OsString::from("-c"), OsString::from("rm x")],
            ..ShellInvocation::default()
        };
        assert_eq!(line(&shell, Interpreter::Bash).command, "bash -- '-c' 'rm x'");
        assert_eq!(line(&ShellInvocation::default(), Interpreter::Knsh).command, "bash");
    }

    // Input that cannot travel unchanged is refused, never altered.
    #[test]
    fn refuses_what_cannot_travel_unchanged() {
        use std::os::unix::ffi::OsStringExt;

        let bad = OsString::from_vec(vec![b'l', 0xff]);
        let line_of = |command: OsString| Line {
            command,
            args: Vec::new(),
            interpreter: Interpreter::Knsh,
        };
        assert_eq!(
            request(&line_of(bad.clone()), Path::new("/w"), &[]),
            Err(Refusal::NotUtf8("command line"))
        );
        assert_eq!(
            request(&line_of("ls".into()), Path::new("/w"), &[(OsString::from("A"), bad)]),
            Err(Refusal::NotUtf8("environment"))
        );
        assert_eq!(
            request(&line_of("ls".into()), Path::new("relative"), &[]),
            Err(Refusal::Cwd)
        );
        let long = OsString::from("x".repeat(MAX_EXEC_COMMAND_LEN + 1));
        assert_eq!(
            request(&line_of(long), Path::new("/w"), &[]),
            Err(Refusal::TooLarge("command line"))
        );
    }
}
