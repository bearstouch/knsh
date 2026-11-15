//! `knsh agent [--profile <p>] [--agent <name>] -- <cmd…>`: start an agent CLI under supervision (KNSH-056,
//! FR-AGT-01, FR-AGT-02, `specs/06-api/cli.md#agent`).
//!
//! `knsh agent` runs nothing itself. It sends the command after `--`, its working directory, its whole environment
//! and the options as `session.start_agent` on `user.sock`, with its own stdin, stdout and stderr attached as
//! descriptors, and waits: `knshd` starts the CLI in an envelope on those streams, so the CLI talks to the user's
//! terminal directly. When the CLI exits its session ends, `knshd` answers, and `knsh agent` exits as the CLI did
//! (`n`, or `128 + n` for signal `n`). With `--json` it then prints the session, actor and profile as one line.
//!
//! Checked here before anything is sent, so a mistyped command never reaches `knshd`:
//!
//! - `--profile` and `--agent` must be valid names (1–64 characters from `[A-Za-z0-9._-]`): usage error, exit 2.
//! - The command, the working directory and the environment must be UTF-8 (they travel as JSON strings) and hold
//!   no NUL: exit 1, nothing sent.
//! - The command must be found as a shell would (a path with `/`, or a name on `PATH`): `command not found`, exit
//!   127. `knshd` looks it up again itself; this only gives the familiar answer early.
//!
//! The actor is never decided here: `--agent` is sent when given, and otherwise `knshd` derives it from the command
//! (FR-AGT-02), so there is one derivation table.

use std::ffi::{OsStr, OsString};
use std::fmt;
use std::path::Path;

use knsh_core::{AgentId, CanonicalPath, ProfileName};
use knsh_json::{FromJson, ToJson};
use knsh_proto::{ErrorCode, MAX_EXEC_ARGS, MAX_EXEC_ENV_ENTRIES, SessionStartAgentParams, SessionStartAgentResult};

use crate::cli::args::ParsedCommand;
use crate::cli::client::ClientError;

/// The method `knsh agent` calls.
pub const METHOD: &str = "session.start_agent";

/// Exit status when the command cannot be found, as a shell reports it.
pub const NOT_FOUND_STATUS: u8 = 127;

/// Why a `knsh agent` command line was refused before anything was sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// `--profile` is not a valid profile name. A usage error (exit 2).
    BadProfile,
    /// `--agent` is not a valid agent name. A usage error (exit 2).
    BadAgent,
    /// Something that must travel as text is not UTF-8 or holds NUL: the command, the directory or the environment.
    NotText(&'static str),
    /// More arguments or variables than one request may carry.
    TooMany(&'static str),
    /// The working directory is not an absolute, resolved path.
    BadDirectory,
    /// The command was not found (exit 127). Holds the name as given, for the message.
    NotFound(String),
}

impl Refusal {
    /// The exit status for this refusal: 2 for usage errors, 127 for a command not found, 1 otherwise.
    #[must_use]
    pub const fn status(&self) -> u8 {
        match self {
            Self::BadProfile | Self::BadAgent => 2,
            Self::NotFound(_) => NOT_FOUND_STATUS,
            Self::NotText(_) | Self::TooMany(_) | Self::BadDirectory => 1,
        }
    }
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadProfile => f.write_str("--profile must be 1 to 64 characters from [A-Za-z0-9._-]"),
            Self::BadAgent => f.write_str("--agent must be 1 to 64 characters from [A-Za-z0-9._-]"),
            Self::NotText(what) => write!(f, "the {what} must be UTF-8 without NUL bytes; nothing was started"),
            Self::TooMany(what) => write!(f, "too many {what} to send; nothing was started"),
            Self::BadDirectory => f.write_str("the working directory is not an absolute, resolved path"),
            // The name came from the user's own command line; it is still printed through the terminal-safe escape.
            Self::NotFound(name) => write!(f, "{}: command not found", crate::cli::terminal::escape_text(name)),
        }
    }
}

impl std::error::Error for Refusal {}

/// The `session.start_agent` parameters for a parsed `knsh agent` command line run in `cwd` with environment `env`.
///
/// `executable` says whether a path names an executable file; it is how the command is looked up
/// ([`find_program`]).
///
/// # Errors
///
/// A [`Refusal`]; nothing is sent then.
pub fn params(
    parsed: &ParsedCommand,
    cwd: &Path,
    env: &[(OsString, OsString)],
    executable: &dyn Fn(&Path) -> bool,
) -> Result<SessionStartAgentParams, Refusal> {
    let profile = parsed
        .value("profile")
        .map(|name| ProfileName::new(name).map_err(|_| Refusal::BadProfile))
        .transpose()?;
    let agent = parsed
        .value("agent")
        .map(|name| AgentId::new(name).map_err(|_| Refusal::BadAgent))
        .transpose()?;
    if parsed.trailing.len() > MAX_EXEC_ARGS {
        return Err(Refusal::TooMany("arguments"));
    }
    if env.len() > MAX_EXEC_ENV_ENTRIES {
        return Err(Refusal::TooMany("environment variables"));
    }
    let command = parsed
        .trailing
        .iter()
        .map(|arg| text(arg, "command"))
        .collect::<Result<Vec<_>, _>>()?;
    let env = env
        .iter()
        .map(|(name, value)| Ok((text(name, "environment")?, text(value, "environment")?)))
        .collect::<Result<Vec<_>, Refusal>>()?;
    let cwd_text = text(cwd.as_os_str(), "working directory")?;
    let cwd = CanonicalPath::new(&cwd_text).map_err(|_| Refusal::BadDirectory)?;
    // The parser requires a command after `--`; an empty first word cannot name one.
    let program = command.first().cloned().unwrap_or_default();
    let path = env
        .iter()
        .find(|(name, _)| name == "PATH")
        .map(|(_, value)| value.as_str());
    if !find_program(&program, cwd.as_path(), path, executable) {
        return Err(Refusal::NotFound(program));
    }
    Ok(SessionStartAgentParams {
        command,
        cwd,
        env,
        profile,
        agent,
    })
}

/// `value` as UTF-8 text without NUL, or [`Refusal::NotText`] naming `what`.
fn text(value: &OsStr, what: &'static str) -> Result<String, Refusal> {
    value
        .to_str()
        .filter(|text| !text.contains('\0'))
        .map(str::to_owned)
        .ok_or(Refusal::NotText(what))
}

/// Whether `program` can be found as a shell finds a command: a name with `/` relative to `cwd`; otherwise on the
/// absolute entries of `path`. `knshd` does the same lookup, and is what decides.
#[must_use]
pub fn find_program(program: &str, cwd: &Path, path: Option<&str>, executable: &dyn Fn(&Path) -> bool) -> bool {
    if program.is_empty() {
        return false;
    }
    if program.contains('/') {
        return executable(&cwd.join(program));
    }
    path.unwrap_or_default()
        .split(':')
        .filter(|entry| entry.starts_with('/'))
        .any(|entry| executable(&Path::new(entry).join(program)))
}

/// What `knsh agent` does once `knshd` answered: the exit status, and the line to print on stdout (with `--json`).
#[must_use]
pub fn finished(result: &SessionStartAgentResult, json: bool) -> (u8, Option<String>) {
    let line = json.then(|| {
        // The result always encodes; the fallback keeps stdout valid JSON regardless.
        let text = result
            .to_json()
            .and_then(|value| knsh_json::write(&value))
            .unwrap_or_else(|_| String::from("{}"));
        format!("{text}\n")
    });
    (result.status.shell_status(), line)
}

/// Reads the answer of `session.start_agent`.
///
/// # Errors
///
/// [`ClientError::Protocol`] if it is not a valid result.
pub fn result(value: &knsh_json::Value) -> Result<SessionStartAgentResult, ClientError> {
    SessionStartAgentResult::from_json(value).map_err(|_| ClientError::Protocol)
}

/// What `knsh agent` prints on stderr when `knshd` could not start the CLI, or lost it.
#[must_use]
pub fn failure_message(error: &ClientError) -> String {
    let reason = match error {
        // FR-AGT-06: never started without the sandbox.
        ClientError::Rpc(rpc) if rpc.code == ErrorCode::CapabilityUnavailable => {
            "no sandbox on this machine, so agent sessions cannot start"
        }
        // FR-SES-03.
        ClientError::Rpc(rpc) if rpc.code == ErrorCode::NotAllowed => {
            "the profile is looser than the one of the session this was started from"
        }
        ClientError::Rpc(rpc) if rpc.code == ErrorCode::SessionNotFound => {
            "the session this was started from has ended"
        }
        ClientError::Rpc(rpc) if rpc.code == ErrorCode::InvalidParams => {
            "knshd refused the request: unknown profile, or a command it cannot run"
        }
        ClientError::Rpc(rpc) if rpc.code == ErrorCode::InternalError => {
            "knshd could not start the agent, or lost it; its session has ended"
        }
        ClientError::Connect(_) => return format!("knsh: agent: {error}\n"),
        other => return format!("knsh: agent failed: {other}\n"),
    };
    format!("knsh: agent: {reason}\n")
}

/// Sends `params` on `user.sock` at `socket` with this process's stdin, stdout and stderr attached, and waits until
/// the CLI has exited.
///
/// # Errors
///
/// Any [`ClientError`].
#[cfg(target_os = "macos")]
pub fn run(socket: &Path, params: &SessionStartAgentParams) -> Result<SessionStartAgentResult, ClientError> {
    use knsh_json::Value;
    use knsh_platform::macos::send_with_descriptors;

    use crate::agent::socket::Stdio;
    use crate::cli::client::connect_user_with_handle;

    // Taken before the connection is made, so a closed descriptor 0 is never filled by the socket (and the socket
    // never passed to the CLI as its stdin).
    let stdio = Stdio::of_this_process().map_err(ClientError::Io)?;
    let (mut client, stream) = connect_user_with_handle(socket)?;
    // The answer comes when the CLI exits, which may be hours from now.
    stream.set_read_timeout(None).map_err(ClientError::Io)?;
    let Value::Object(params) = params.to_json()? else {
        return Err(ClientError::Protocol);
    };
    let descriptors = stdio.borrowed();
    let answer = client.call_sending(METHOD, Some(params), &mut |frame| {
        send_with_descriptors(&stream, frame, &descriptors)
    })?;
    result(&answer)
}

#[cfg(test)]
mod tests {
    use knsh_core::{SessionId, Ulid};
    use knsh_proto::{LineStatus, RpcError};

    use super::*;
    use crate::cli::args::{Invocation, parse};
    use crate::cli::commands::KNSH;

    fn parsed(args: &[&str]) -> ParsedCommand {
        let full = std::iter::once("knsh").chain(args.iter().copied()).map(OsString::from);
        match parse(&KNSH, full.collect::<Vec<_>>()).unwrap() {
            Invocation::Command(parsed) => parsed,
            _ => panic!("not a command"),
        }
    }

    fn env() -> Vec<(OsString, OsString)> {
        vec![
            ("PATH".into(), "/opt/bin:relative:/bin".into()),
            ("HOME".into(), "/Users/u".into()),
        ]
    }

    /// Only `/opt/bin/claude` and `/Users/u/app/bin/tool` are executable.
    fn executable(path: &Path) -> bool {
        path == Path::new("/opt/bin/claude") || path == Path::new("/Users/u/app/bin/tool")
    }

    fn build(args: &[&str]) -> Result<SessionStartAgentParams, Refusal> {
        params(&parsed(args), Path::new("/Users/u/app"), &env(), &executable)
    }

    // FR-AGT-01: the command after `--`, unchanged, with the options, directory and environment.
    #[test]
    fn sends_command_options_directory_and_environment() {
        let params = build(&["agent", "--profile", "web-app", "--", "claude", "--resume", "--profile"]).unwrap();
        assert_eq!(params.command, ["claude", "--resume", "--profile"]);
        assert_eq!(params.profile.unwrap().as_str(), "web-app");
        assert_eq!(params.agent, None, "derived by knshd, not here");
        assert_eq!(params.cwd.as_path(), Path::new("/Users/u/app"));
        assert_eq!(params.env.len(), 2);
    }

    // FR-AGT-02: `--agent` is sent as given.
    #[test]
    fn sends_explicit_agent_name() {
        let params = build(&["agent", "--agent", "my-agent", "--", "bin/tool"]).unwrap();
        assert_eq!(params.agent.unwrap().as_str(), "my-agent");
    }

    #[test]
    fn refuses_before_sending() {
        assert_eq!(
            build(&["agent", "--profile", "a b", "--", "claude"]),
            Err(Refusal::BadProfile)
        );
        assert_eq!(
            build(&["agent", "--agent", "a/b", "--", "claude"]),
            Err(Refusal::BadAgent)
        );
        // Not on PATH, and relative PATH entries are never searched.
        assert_eq!(
            build(&["agent", "--", "relative"]),
            Err(Refusal::NotFound("relative".into()))
        );
        assert_eq!(Refusal::NotFound(String::new()).status(), NOT_FOUND_STATUS);
        assert_eq!(Refusal::BadAgent.status(), 2);
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStringExt;
            let mut parsed = parsed(&["agent", "--", "claude"]);
            parsed.trailing.push(OsString::from_vec(vec![0xff]));
            let refused = params(&parsed, Path::new("/Users/u/app"), &env(), &executable);
            assert_eq!(refused, Err(Refusal::NotText("command")));
        }
    }

    fn result(status: LineStatus) -> SessionStartAgentResult {
        SessionStartAgentResult {
            session_id: SessionId::from_ulid(Ulid::from_u128(5)),
            agent_id: AgentId::new("claude-code").unwrap(),
            profile: ProfileName::new("web-app").unwrap(),
            parent_session_id: None,
            status,
        }
    }

    // `knsh agent` exits as the CLI did; `--json` prints the session ID and profile.
    #[test]
    fn exits_with_the_cli_status_and_prints_json() {
        assert_eq!(finished(&result(LineStatus::Exited(4)), false), (4, None));
        let (status, line) = finished(&result(LineStatus::Signalled(2)), true);
        assert_eq!(status, 130);
        let line = line.unwrap();
        assert!(line.ends_with('\n'));
        let value = knsh_json::parse(line.trim_end().as_bytes(), 4096).unwrap();
        let object = value.as_object().unwrap();
        assert_eq!(
            object.get("session_id").and_then(knsh_json::Value::as_str),
            Some("00000000000000000000000005")
        );
        assert_eq!(
            object.get("profile").and_then(knsh_json::Value::as_str),
            Some("web-app")
        );
    }

    #[test]
    fn explains_refusals() {
        let message = failure_message(&ClientError::Rpc(RpcError::new(ErrorCode::CapabilityUnavailable)));
        assert!(message.contains("no sandbox"), "{message}");
        let message = failure_message(&ClientError::Rpc(RpcError::new(ErrorCode::NotAllowed)));
        assert!(message.contains("looser"), "{message}");
    }
}
