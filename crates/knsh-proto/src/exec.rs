//! `exec.run` from `knsh -c`: the forwarded line and the outcome it gets back (`specs/06-api/agent-socket.md#execrun`,
//! KNSH-049, FR-AGT-10, FR-LC-01).
//!
//! Inside an envelope, `knsh -c` (and the `sh`, `bash` and `zsh` shims) send the line exactly as the agent gave it,
//! with the working directory, the whole environment, the positional arguments after the line, and the interpreter
//! the agent asked for. Its stdin, stdout and stderr ride on the same message as descriptors (`SCM_RIGHTS`), which
//! `"stdio": "passed"` announces, so the line's output goes straight to the caller's terminal or pipes and never
//! crosses the API (FR-OUT-04). The answer carries only the outcome: the record, and the exit code or the signal
//! that ended the line.
//!
//! Every field comes from a process inside an envelope, so each is bounded and parsed strictly: a malformed value
//! is `-32602`, never repaired. Text must be UTF-8 (it travels as JSON strings) and free of NUL bytes, which no
//! `exec` could carry.
//!
//! A denial is `-32001` with `rule_id`, `reason` and `source` in `data`; [`Denial`] reads them back for the client,
//! which prints them and exits 126 (FR-LC-31).

use knsh_core::{CanonicalPath, RecordId};
use knsh_json::{Fields, FromJson, JsonError, Object, ToJson, Value};

use crate::envelope::RpcError;
use crate::error_code::ErrorCode;
use crate::session::{cwd, out_of_range, parse, path_text};

/// The environment variable that carries an envelope's session token (`specs/09-reference/file-locations.md`).
/// The supervisor sets it in the envelope (FR-AGT-03); `knsh` sends it in `hello`, and its presence is what tells
/// `knsh` it runs inside an envelope.
pub const SESSION_TOKEN_VAR: &str = "KNSH_SESSION_TOKEN";

/// The longest line one `exec.run` may carry, in bytes: the bound of `policy.check`.
pub const MAX_EXEC_COMMAND_LEN: usize = 64 * 1024;

/// Most environment variables one `exec.run` may carry. Real environments hold a few hundred; the frame limit
/// (1 MB) bounds their total size.
pub const MAX_EXEC_ENV_ENTRIES: usize = 4096;

/// Most positional arguments (`$0`, `$1`, …) one `exec.run` may carry after the line.
pub const MAX_EXEC_ARGS: usize = 4096;

/// The interpreter the caller asked for (FR-LC-14). It chooses only which shell runs the line, never how the line
/// is decided: policy is the same whichever was asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Interpreter {
    /// `knsh -c` itself (`$SHELL -c`): runs with the profile's bash.
    Knsh,
    /// The `bash` shim: runs with the profile's bash.
    Bash,
    /// The `sh` shim: runs with `/bin/sh`.
    Sh,
    /// The `zsh` shim: runs with zsh.
    Zsh,
}

impl Interpreter {
    /// Every interpreter, in declaration order.
    pub const ALL: [Self; 4] = [Self::Knsh, Self::Bash, Self::Sh, Self::Zsh];

    /// The name on the wire, which is also the program name it is invoked as.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Knsh => "knsh",
            Self::Bash => "bash",
            Self::Sh => "sh",
            Self::Zsh => "zsh",
        }
    }

    /// The interpreter called `name` exactly, if any.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|interpreter| interpreter.as_str() == name)
    }
}

/// Where the line's standard streams come from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecStdio {
    /// The caller's own stdin, stdout and stderr, passed as three descriptors with the request (`knsh -c`). The
    /// line's output goes to them and the answer carries none.
    Passed,
    /// No descriptors: the supervisor captures the output and returns it in the requested output mode (KNSH-053).
    Captured,
}

impl ExecStdio {
    /// How many descriptors the request must carry.
    #[must_use]
    pub const fn descriptors(self) -> usize {
        match self {
            Self::Passed => 3,
            Self::Captured => 0,
        }
    }
}

/// The parameters of `exec.run`, as `knsh -c` sends them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecRunParams {
    /// The line, unchanged, at most [`MAX_EXEC_COMMAND_LEN`] bytes.
    pub command: String,
    /// The working directory: absolute and resolved.
    pub cwd: CanonicalPath,
    /// The caller's whole environment, in the order sent. Names are non-empty and hold no `=`; nothing holds NUL.
    /// Absent is empty.
    pub env: Vec<(String, String)>,
    /// The interpreter asked for; [`Interpreter::Knsh`] when absent.
    pub interpreter: Interpreter,
    /// The operands after the line (`bash -c 'line' name arg…`): `$0` first, then `$1`, …. Absent is empty.
    pub args: Vec<String>,
    /// Where stdio comes from; [`ExecStdio::Captured`] when absent.
    pub stdio: ExecStdio,
    /// The line is killed after this many seconds (FR-LC-40); positive. No limit when absent.
    pub timeout_s: Option<u64>,
}

impl FromJson for ExecRunParams {
    fn from_json(value: &Value) -> Result<Self, JsonError> {
        let mut fields = Fields::new(value)?;
        let command: String = fields.required("command")?;
        let cwd = cwd(fields.required("cwd")?)?;
        let env: Option<Value> = fields.optional("env")?;
        let interpreter: Option<String> = fields.optional("interpreter")?;
        let args: Option<Vec<String>> = fields.optional("args")?;
        let stdio: Option<String> = fields.optional("stdio")?;
        let timeout_s: Option<u64> = fields.optional("timeout_s")?;
        fields.finish()?;
        if command.len() > MAX_EXEC_COMMAND_LEN || command.contains('\0') {
            return Err(out_of_range("command"));
        }
        let env = match env {
            Some(env) => environment(&env)?,
            None => Vec::new(),
        };
        let interpreter = match interpreter {
            Some(name) => Interpreter::from_name(&name).ok_or(out_of_range("interpreter"))?,
            None => Interpreter::Knsh,
        };
        let args = args.unwrap_or_default();
        if args.len() > MAX_EXEC_ARGS || args.iter().any(|arg| arg.contains('\0')) {
            return Err(out_of_range("args"));
        }
        let stdio = match stdio.as_deref() {
            Some("passed") => ExecStdio::Passed,
            None => ExecStdio::Captured,
            Some(_) => return Err(out_of_range("stdio")),
        };
        if timeout_s == Some(0) {
            return Err(out_of_range("timeout_s"));
        }
        Ok(Self {
            command,
            cwd,
            env,
            interpreter,
            args,
            stdio,
            timeout_s,
        })
    }
}

/// Reads `env`: an object of string values, each a valid variable.
fn environment(env: &Value) -> Result<Vec<(String, String)>, JsonError> {
    let Value::Object(object) = env else {
        return Err(out_of_range("env"));
    };
    if object.len() > MAX_EXEC_ENV_ENTRIES {
        return Err(out_of_range("env"));
    }
    object
        .iter()
        .map(|(name, value)| {
            let value = value.as_str().ok_or(out_of_range("env"))?;
            // A name with `=` would split differently in the child; NUL cannot be passed to `exec` at all.
            if name.is_empty() || name.contains(['=', '\0']) || value.contains('\0') {
                return Err(out_of_range("env"));
            }
            Ok((name.to_owned(), value.to_owned()))
        })
        .collect()
}

impl ToJson for ExecRunParams {
    fn to_json(&self) -> Result<Value, JsonError> {
        let mut env = Object::new();
        for (name, value) in &self.env {
            // A repeated name is refused here (strict JSON has no duplicate keys), never silently merged.
            env.insert(name.as_str(), Value::from(value.as_str()))?;
        }
        let mut object = Object::new()
            .with("command", self.command.as_str())?
            .with("cwd", path_text(&self.cwd))?
            .with("env", Value::Object(env))?
            .with("interpreter", self.interpreter.as_str())?
            .with("args", self.args.to_json()?)?;
        match self.stdio {
            ExecStdio::Passed => object.insert("stdio", Value::from("passed"))?,
            ExecStdio::Captured => {}
        }
        if let Some(timeout_s) = self.timeout_s {
            object.insert("timeout_s", timeout_s.to_json()?)?;
        }
        Ok(Value::Object(object))
    }
}

/// How a line ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LineStatus {
    /// It exited with this code.
    Exited(u8),
    /// A signal ended it: the signal number, 1 to 127.
    Signalled(u8),
}

impl LineStatus {
    /// The exit status a shell reports for it (NFR-COMPAT-09): the code itself, or 128 plus the signal number.
    #[must_use]
    pub const fn shell_status(self) -> u8 {
        match self {
            Self::Exited(code) => code,
            // At most 127 (the parser refuses more), so the sum fits.
            Self::Signalled(signal) => 128u8.saturating_add(signal),
        }
    }
}

/// The result of `exec.run` for a line run on passed descriptors: no output, only how it ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExecRunResult {
    /// The execution record, once records are written (KNSH-052).
    pub record_id: Option<RecordId>,
    /// How the line ended: `exit_code` or `signal`, exactly one of them.
    pub status: LineStatus,
}

impl FromJson for ExecRunResult {
    fn from_json(value: &Value) -> Result<Self, JsonError> {
        let mut fields = Fields::new(value)?;
        let record_id: Option<String> = fields.optional("record_id")?;
        let exit_code: Option<u8> = fields.optional("exit_code")?;
        let signal: Option<u8> = fields.optional("signal")?;
        // Every other field (decision, duration, output sizes) is the supervisor's business, not the client's.
        fields.finish()?;
        let record_id = record_id.map(|text| parse(&text, "record_id")).transpose()?;
        let status = match (exit_code, signal) {
            (Some(code), None) => LineStatus::Exited(code),
            (None, Some(signal @ 1..=127)) => LineStatus::Signalled(signal),
            (None, Some(_)) => return Err(out_of_range("signal")),
            // Neither or both: the outcome is unknown, and an unknown outcome is never guessed.
            (None, None) | (Some(_), Some(_)) => return Err(out_of_range("exit_code")),
        };
        Ok(Self { record_id, status })
    }
}

impl ToJson for ExecRunResult {
    /// `record_id`, `exit_code` and `signal`; the one that does not apply is `null`.
    fn to_json(&self) -> Result<Value, JsonError> {
        let (exit_code, signal) = match self.status {
            LineStatus::Exited(code) => (Some(code), None),
            LineStatus::Signalled(signal) => (None, Some(signal)),
        };
        Ok(Value::Object(
            Object::new()
                .with("record_id", self.record_id.map(|id| id.to_string()).to_json()?)?
                .with("exit_code", exit_code.to_json()?)?
                .with("signal", signal.to_json()?)?,
        ))
    }
}

/// The `data` of a `-32001` denial: what the client prints before it exits 126 (FR-LC-31).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Denial {
    /// The deciding rule (`exec.deny[0]`), if a rule decided.
    pub rule_id: Option<String>,
    /// Why, in words, if the engine gave a reason.
    pub reason: Option<String>,
    /// Which component decided (`rule`, `hook`, `authority`, …).
    pub source: Option<String>,
}

impl Denial {
    /// The denial `error` describes, or `None` if it is not a denial. Fields that are missing or of the wrong type
    /// are left out: a denial is a denial even when its details cannot be read.
    #[must_use]
    pub fn from_error(error: &RpcError) -> Option<Self> {
        if error.code != ErrorCode::Denied {
            return None;
        }
        let text = |name: &str| {
            error
                .data
                .as_ref()
                .and_then(Value::as_object)
                .and_then(|data| data.get(name))
                .and_then(Value::as_str)
                .map(str::to_owned)
        };
        Some(Self {
            rule_id: text("rule_id"),
            reason: text("reason"),
            source: text("source"),
        })
    }

    /// The denial as the `data` of a `-32001` error, with `null` for what is unknown.
    ///
    /// # Errors
    ///
    /// [`JsonError`] only if a field cannot be written, which strings always can.
    pub fn to_error(&self) -> Result<RpcError, JsonError> {
        let data = Object::new()
            .with("rule_id", self.rule_id.to_json()?)?
            .with("reason", self.reason.to_json()?)?
            .with("source", self.source.to_json()?)?;
        Ok(RpcError::new(ErrorCode::Denied).with_data(Value::Object(data)))
    }
}

#[cfg(test)]
mod tests {
    use knsh_json::parse as parse_json;

    use super::*;

    fn params(text: &str) -> Result<ExecRunParams, JsonError> {
        ExecRunParams::from_json(&parse_json(text.as_bytes(), 1 << 20).unwrap())
    }

    // FR-AGT-10: the line, cwd, environment, interpreter and operands round-trip unchanged.
    #[test]
    fn params_round_trip_unchanged() {
        let sent = ExecRunParams {
            command: "echo \"$1\" | tr a-z A-Z; exit 3".to_owned(),
            cwd: CanonicalPath::new("/Users/me/code/app").unwrap(),
            env: vec![
                ("PATH".to_owned(), "/shims:/usr/bin:/bin".to_owned()),
                ("EMPTY".to_owned(), String::new()),
                ("UNICODE".to_owned(), "é ✓".to_owned()),
            ],
            interpreter: Interpreter::Sh,
            args: vec!["name".to_owned(), "hi there".to_owned()],
            stdio: ExecStdio::Passed,
            timeout_s: Some(600),
        };
        let text = knsh_json::write(&sent.to_json().unwrap()).unwrap();
        assert_eq!(params(&text).unwrap(), sent);
    }

    // Defaults: only `command` and `cwd` are required.
    #[test]
    fn minimal_params_take_the_defaults() {
        let read = params(r#"{"command":"true","cwd":"/w"}"#).unwrap();
        assert_eq!(read.interpreter, Interpreter::Knsh);
        assert_eq!(read.stdio, ExecStdio::Captured);
        assert!(read.env.is_empty() && read.args.is_empty());
        assert_eq!(read.timeout_s, None);
    }

    // Untrusted input: every malformed field is refused, never repaired.
    #[test]
    fn malformed_params_are_refused() {
        let long = "x".repeat(MAX_EXEC_COMMAND_LEN + 1);
        for bad in [
            r#"{"cwd":"/w"}"#.to_owned(),
            r#"{"command":"true","cwd":"relative"}"#.to_owned(),
            r#"{"command":"true","cwd":"/w/../x"}"#.to_owned(),
            format!(r#"{{"command":"{long}","cwd":"/w"}}"#),
            r#"{"command":"a\u0000b","cwd":"/w"}"#.to_owned(),
            r#"{"command":"true","cwd":"/w","interpreter":"fish"}"#.to_owned(),
            r#"{"command":"true","cwd":"/w","interpreter":"BASH"}"#.to_owned(),
            r#"{"command":"true","cwd":"/w","stdio":"inherit"}"#.to_owned(),
            r#"{"command":"true","cwd":"/w","env":[]}"#.to_owned(),
            r#"{"command":"true","cwd":"/w","env":{"A":1}}"#.to_owned(),
            r#"{"command":"true","cwd":"/w","env":{"":"x"}}"#.to_owned(),
            r#"{"command":"true","cwd":"/w","env":{"A=B":"x"}}"#.to_owned(),
            r#"{"command":"true","cwd":"/w","env":{"A":"x\u0000"}}"#.to_owned(),
            r#"{"command":"true","cwd":"/w","args":["a\u0000"]}"#.to_owned(),
            r#"{"command":"true","cwd":"/w","args":[1]}"#.to_owned(),
            r#"{"command":"true","cwd":"/w","timeout_s":0}"#.to_owned(),
            r#"{"command":"true","cwd":"/w","timeout_s":-1}"#.to_owned(),
        ] {
            assert!(params(&bad).is_err(), "{bad}");
        }
    }

    // Each interpreter travels under its own program name.
    #[test]
    fn interpreters_are_named_by_program() {
        for interpreter in Interpreter::ALL {
            assert_eq!(Interpreter::from_name(interpreter.as_str()), Some(interpreter));
        }
        assert_eq!(Interpreter::from_name("dash"), None);
    }

    // NFR-COMPAT-09: an exit code is itself, a signal is 128 + n; the result names exactly one of them.
    #[test]
    fn result_carries_exactly_one_outcome() {
        for status in [LineStatus::Exited(3), LineStatus::Signalled(15)] {
            let result = ExecRunResult {
                record_id: None,
                status,
            };
            assert_eq!(ExecRunResult::from_json(&result.to_json().unwrap()).unwrap(), result);
        }
        assert_eq!(LineStatus::Exited(3).shell_status(), 3);
        assert_eq!(LineStatus::Signalled(15).shell_status(), 143);
        for bad in [
            "{}",
            r#"{"exit_code":0,"signal":9}"#,
            r#"{"signal":0}"#,
            r#"{"signal":128}"#,
            r#"{"exit_code":256}"#,
            r#"{"exit_code":0,"record_id":"nope"}"#,
        ] {
            let value = parse_json(bad.as_bytes(), 1024).unwrap();
            assert!(ExecRunResult::from_json(&value).is_err(), "{bad}");
        }
        // Fields the client does not need are ignored.
        let value = parse_json(br#"{"exit_code":1,"stdout":"never read","decision":{}}"#, 1024).unwrap();
        assert_eq!(ExecRunResult::from_json(&value).unwrap().status, LineStatus::Exited(1));
    }

    // FR-LC-31: a denial's rule and reason are read back from `data`, and only from a -32001.
    #[test]
    fn denial_reads_rule_and_reason() {
        let denial = Denial {
            rule_id: Some("exec.deny[0]".to_owned()),
            reason: Some("pushing is not allowed".to_owned()),
            source: Some("rule".to_owned()),
        };
        let error = denial.to_error().unwrap();
        assert_eq!(error.code, ErrorCode::Denied);
        assert_eq!(Denial::from_error(&error), Some(denial));
        assert_eq!(
            Denial::from_error(&RpcError::new(ErrorCode::Denied)),
            Some(Denial::default())
        );
        assert_eq!(Denial::from_error(&RpcError::new(ErrorCode::SessionHeld)), None);
    }
}
