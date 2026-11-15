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

use knsh_core::{
    CanonicalPath, Decision, Excerpt, HeadTail, MAX_HEAD_TAIL_LINES, MAX_TRUNCATE_BYTES, OutputMode, OutputRequest,
    RecordId, Redacted, ShapedOutput,
};
use knsh_json::{Fields, FromJson, JsonError, MAX_SAFE_INTEGER, Object, ToJson, Value};

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
    /// How much output comes back (FR-OUT-01). Only for captured lines: with [`ExecStdio::Passed`] the output goes
    /// to the caller's descriptors and modes do not apply (FR-OUT-03), so any `output` is refused.
    pub output: OutputOptions,
}

/// The `output` member of `exec.run` and `exec.start`: what the caller asked for, before the profile's default
/// mode fills in a missing `mode` (FR-OUT-02).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct OutputOptions {
    /// `output.mode`; the profile's default when absent.
    pub mode: Option<OutputMode>,
    /// `output.max_bytes`, for `truncate`: 1 to [`MAX_TRUNCATE_BYTES`].
    pub max_bytes: Option<usize>,
    /// `output.lines`, for `head_tail`: 1 to [`MAX_HEAD_TAIL_LINES`].
    pub lines: Option<usize>,
}

impl OutputOptions {
    /// Whether nothing was asked for.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.mode.is_none() && self.max_bytes.is_none() && self.lines.is_none()
    }

    /// The request these options make for a line whose profile's default mode is `default` (FR-OUT-02).
    #[must_use]
    pub fn request(self, default: OutputMode) -> OutputRequest {
        let defaults = OutputRequest::new(self.mode.unwrap_or(default));
        OutputRequest {
            max_bytes: self.max_bytes.unwrap_or(defaults.max_bytes),
            lines: self.lines.unwrap_or(defaults.lines),
            ..defaults
        }
    }

    /// Reads the `output` object strictly: a known mode, and counts within their bounds. `max_bytes` and `lines`
    /// are accepted whatever the mode, since the mode may come from the profile.
    fn from_value(value: &Value) -> Result<Self, JsonError> {
        let mut fields = Fields::new(value)?;
        let mode: Option<String> = fields.optional("mode")?;
        let max_bytes: Option<u64> = fields.optional("max_bytes")?;
        let lines: Option<u64> = fields.optional("lines")?;
        fields.finish()?;
        let mode = mode
            .map(|name| OutputMode::parse(&name).ok_or(out_of_range("output.mode")))
            .transpose()?;
        let max_bytes = max_bytes
            .map(|count| bounded(count, MAX_TRUNCATE_BYTES).ok_or(out_of_range("output.max_bytes")))
            .transpose()?;
        let lines = lines
            .map(|count| bounded(count, MAX_HEAD_TAIL_LINES).ok_or(out_of_range("output.lines")))
            .transpose()?;
        Ok(Self { mode, max_bytes, lines })
    }

    /// The `output` object; absent fields left out.
    fn to_object(self) -> Result<Object, JsonError> {
        let mut object = Object::new();
        if let Some(mode) = self.mode {
            object.insert("mode", Value::from(mode.as_str()))?;
        }
        if let Some(max_bytes) = self.max_bytes {
            object.insert("max_bytes", max_bytes.to_json()?)?;
        }
        if let Some(lines) = self.lines {
            object.insert("lines", lines.to_json()?)?;
        }
        Ok(object)
    }
}

/// `count` if it is 1 to `max`.
fn bounded(count: u64, max: usize) -> Option<usize> {
    usize::try_from(count).ok().filter(|count| (1..=max).contains(count))
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
        let output: Option<Value> = fields.optional("output")?;
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
        let output = match (output, stdio) {
            (None, _) => OutputOptions::default(),
            (Some(output), ExecStdio::Captured) => OutputOptions::from_value(&output)?,
            // FR-OUT-03: output modes apply only to captured lines; asking for one with passed stdio is a mistake.
            (Some(_), ExecStdio::Passed) => return Err(out_of_range("output")),
        };
        Ok(Self {
            command,
            cwd,
            env,
            interpreter,
            args,
            stdio,
            timeout_s,
            output,
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
        if !self.output.is_empty() {
            object.insert("output", Value::Object(self.output.to_object()?))?;
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

/// The largest captured `exec.run` result written, in bytes of JSON: one frame ([`knsh_json::MAX_PAYLOAD`]) less
/// room for the response envelope around it (`jsonrpc`, an `id` of up to 128 characters).
pub const MAX_EXEC_RESULT_LEN: usize = knsh_json::MAX_PAYLOAD - 16 * 1024;

/// How many times [`ExecOutcome::to_json_within`] shortens the output before giving up.
const MAX_FIT_ROUNDS: usize = 32;

/// Bytes cut beyond the measured excess in each round, so that a cut inside a UTF-8 sequence (which then shows as
/// U+FFFD) cannot stall the shortening.
const FIT_SLACK: usize = 64;

/// One stream's totals, returned in every output mode.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct StreamTotals {
    /// Bytes the line wrote to the stream.
    pub size: u64,
    /// Lines it wrote.
    pub lines: u64,
}

/// The answer for a captured line: `exec.run` without passed stdio, and `exec.wait` (KNSH-053,
/// `specs/06-api/agent-socket.md#result`).
#[derive(Debug, Clone)]
pub struct ExecOutcome {
    /// The execution record, or `None` if it could not be written.
    pub record_id: Option<RecordId>,
    /// The line actually spawned, after any rewrite (FR-AUTH-33), redacted.
    pub executed_command: Redacted<String>,
    /// How the line ended.
    pub status: LineStatus,
    /// From the spawn to the end, in milliseconds.
    pub duration_ms: u64,
    /// The decision that let it run.
    pub decision: Decision,
    /// The output mode applied: the caller's, or the profile's default (FR-OUT-02).
    pub mode: OutputMode,
    /// Standard output's totals.
    pub stdout: StreamTotals,
    /// Standard error's totals.
    pub stderr: StreamTotals,
    /// The output selected by `mode`, already redacted (FR-OUT-06).
    pub output: ShapedOutput,
    /// Whether output was shortened (from the middle of a whole stream, the end of a head, the start of a tail) so
    /// the answer fits in one frame.
    pub cut_to_fit: bool,
}

impl ExecOutcome {
    /// The result as JSON no longer than `limit` bytes when written: while it is longer, the longest output text is
    /// shortened and [`cut_to_fit`](Self::cut_to_fit) set. Output is only ever cut, never rewritten (FR-OUT-05).
    ///
    /// # Errors
    ///
    /// [`JsonError`] if the result cannot be written at all.
    pub fn to_json_within(&mut self, limit: usize) -> Result<Value, JsonError> {
        let mut value = self.to_json()?;
        for _ in 0..MAX_FIT_ROUNDS {
            let size = knsh_json::write(&value)?.len();
            if size <= limit {
                break;
            }
            if !shorten_longest(&mut self.output, size - limit + FIT_SLACK) {
                // Nothing left to cut: the rest of the answer alone is too large. The caller's frame check decides.
                break;
            }
            self.cut_to_fit = true;
            value = self.to_json()?;
        }
        Ok(value)
    }
}

impl ToJson for ExecOutcome {
    /// `record_id`, `executed_command`, `exit_code` and `signal` (one of them null), `duration_ms`, `decision`
    /// (`verdict`, `source`, `rule_id`), `files_changed` and `checkpoint_id` (null until checkpoints exist), the
    /// `output_mode`, both streams' `*_size` (decimal strings) and `*_lines`, `cut_to_fit`, and the mode's fields.
    fn to_json(&self) -> Result<Value, JsonError> {
        let (exit_code, signal) = match self.status {
            LineStatus::Exited(code) => (Some(code), None),
            LineStatus::Signalled(signal) => (None, Some(signal)),
        };
        let decision = Object::new()
            .with("verdict", self.decision.verdict.as_str())?
            .with("source", self.decision.source.code())?
            .with("rule_id", self.decision.rule_id.to_json()?)?;
        let mut object = Object::new()
            .with("record_id", self.record_id.map(|id| id.to_string()).to_json()?)?
            .with("executed_command", self.executed_command.expose().as_str())?
            .with("exit_code", exit_code.to_json()?)?
            .with("signal", signal.to_json()?)?
            .with("duration_ms", safe(self.duration_ms)?)?
            .with("decision", Value::Object(decision))?
            // Checkpoints arrive in phase 3: until then nothing is counted, and saying 0 would claim it was.
            .with("files_changed", Value::Null)?
            .with("checkpoint_id", Value::Null)?
            .with("output_mode", self.mode.as_str())?
            .with("stdout_size", size(self.stdout.size))?
            .with("stdout_lines", safe(self.stdout.lines)?)?
            .with("stderr_size", size(self.stderr.size))?
            .with("stderr_lines", safe(self.stderr.lines)?)?
            .with("cut_to_fit", self.cut_to_fit)?;
        match &self.output {
            ShapedOutput::Full { stdout, stderr } | ShapedOutput::Truncate { stdout, stderr } => {
                excerpt(&mut object, "stdout", stdout)?;
                excerpt(&mut object, "stderr", stderr)?;
            }
            ShapedOutput::HeadTail { stdout, stderr } => {
                head_tail(&mut object, "stdout", stdout)?;
                head_tail(&mut object, "stderr", stderr)?;
            }
            ShapedOutput::ErrorsOnly {
                stderr,
                stdout_tail,
                stdout_skipped_lines,
            } => {
                excerpt(&mut object, "stderr", stderr)?;
                object.insert("stdout_tail", text(stdout_tail))?;
                object.insert("stdout_skipped_lines", safe(*stdout_skipped_lines)?)?;
            }
            ShapedOutput::Ref => {}
        }
        Ok(Value::Object(object))
    }
}

/// `<stream>` (text) and `<stream>_skipped` (bytes of the stream not in it).
fn excerpt(object: &mut Object, stream: &str, excerpt: &Excerpt) -> Result<(), JsonError> {
    object.insert(stream, text(&excerpt.bytes))?;
    object.insert(format!("{stream}_skipped"), size(excerpt.skipped))?;
    Ok(())
}

/// `<stream>_head`, `<stream>_tail` and `<stream>_skipped_lines`.
fn head_tail(object: &mut Object, stream: &str, lines: &HeadTail) -> Result<(), JsonError> {
    object.insert(format!("{stream}_head"), text(&lines.head))?;
    object.insert(format!("{stream}_tail"), text(&lines.tail))?;
    object.insert(format!("{stream}_skipped_lines"), safe(lines.skipped_lines)?)?;
    Ok(())
}

/// Output as a JSON string. JSON strings are UTF-8, output need not be: invalid bytes show as U+FFFD, and the exact
/// bytes stay readable with `records.output` when output is recorded.
fn text(bytes: &Redacted<Vec<u8>>) -> Value {
    Value::from(String::from_utf8_lossy(bytes.expose()).into_owned())
}

/// A byte count as a decimal string (the ±2^53 rule, `specs/06-api/wire-format.md`).
fn size(count: u64) -> Value {
    Value::from(count.to_string())
}

/// A count that stays far below 2^53 in practice, clamped so it can always be written.
fn safe(count: u64) -> Result<Value, JsonError> {
    count.min(MAX_SAFE_INTEGER.unsigned_abs()).to_json()
}

/// Where a text gives way when it is shortened.
#[derive(Clone, Copy)]
enum Cut {
    /// A whole stream: its head and tail are kept.
    Middle,
    /// A start (`truncate`, a head): its end goes.
    End,
    /// An end (a tail): its start goes.
    Start,
}

/// One output text that may be shortened: its bytes, where it gives way, and the excerpt's skipped count, if any.
type Shortenable<'a> = (&'a mut Redacted<Vec<u8>>, Cut, Option<&'a mut u64>);

/// Shortens the longest text of `output` by `by` bytes (all of it, if shorter). Returns `false` if every text is
/// already empty. Bytes cut from an excerpt are added to its `skipped`.
fn shorten_longest(output: &mut ShapedOutput, by: usize) -> bool {
    let mut texts: Vec<Shortenable<'_>> = match output {
        ShapedOutput::Full { stdout, stderr } => vec![
            (&mut stdout.bytes, Cut::Middle, Some(&mut stdout.skipped)),
            (&mut stderr.bytes, Cut::Middle, Some(&mut stderr.skipped)),
        ],
        ShapedOutput::Truncate { stdout, stderr } => vec![
            (&mut stdout.bytes, Cut::End, Some(&mut stdout.skipped)),
            (&mut stderr.bytes, Cut::End, Some(&mut stderr.skipped)),
        ],
        ShapedOutput::HeadTail { stdout, stderr } => vec![
            (&mut stdout.head, Cut::End, None),
            (&mut stdout.tail, Cut::Start, None),
            (&mut stderr.head, Cut::End, None),
            (&mut stderr.tail, Cut::Start, None),
        ],
        ShapedOutput::ErrorsOnly {
            stderr, stdout_tail, ..
        } => vec![
            (&mut stderr.bytes, Cut::Middle, Some(&mut stderr.skipped)),
            (stdout_tail, Cut::Start, None),
        ],
        ShapedOutput::Ref => Vec::new(),
    };
    let Some((bytes, cut, skipped)) = texts
        .iter_mut()
        .max_by_key(|(bytes, _, _)| bytes.expose().len())
        .filter(|(bytes, _, _)| !bytes.expose().is_empty())
    else {
        return false;
    };
    let old = std::mem::take(*bytes).into_inner();
    let keep = old.len().saturating_sub(by);
    let kept = match cut {
        Cut::End => old[..keep].to_vec(),
        Cut::Start => old[old.len() - keep..].to_vec(),
        Cut::Middle => {
            let mut kept = old[..keep / 2].to_vec();
            kept.extend_from_slice(&old[old.len() - (keep - keep / 2)..]);
            kept
        }
    };
    if let Some(skipped) = skipped {
        **skipped += u64::try_from(old.len() - kept.len()).unwrap_or(u64::MAX);
    }
    **bytes = Redacted::new(kept);
    true
}

/// The result of `exec.start`: the record the started line is written to, which names it to `exec.wait` and
/// `exec.kill`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExecStartResult {
    /// The line's record.
    pub record_id: RecordId,
}

impl ToJson for ExecStartResult {
    fn to_json(&self) -> Result<Value, JsonError> {
        Ok(Value::Object(
            Object::new().with("record_id", self.record_id.to_string())?,
        ))
    }
}

/// The parameters of `exec.wait` and `exec.kill`: the `record_id` `exec.start` returned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExecHandleParams {
    /// The started line's record.
    pub record_id: RecordId,
}

impl FromJson for ExecHandleParams {
    fn from_json(value: &Value) -> Result<Self, JsonError> {
        let mut fields = Fields::new(value)?;
        let record_id: String = fields.required("record_id")?;
        fields.finish()?;
        Ok(Self {
            record_id: parse(&record_id, "record_id")?,
        })
    }
}

impl ToJson for ExecHandleParams {
    fn to_json(&self) -> Result<Value, JsonError> {
        Ok(Value::Object(
            Object::new().with("record_id", self.record_id.to_string())?,
        ))
    }
}

/// The result of `exec.kill`: whether the line was still running and was told to stop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExecKillResult {
    /// `false` when the line had already ended.
    pub killed: bool,
}

impl ToJson for ExecKillResult {
    fn to_json(&self) -> Result<Value, JsonError> {
        Ok(Value::Object(Object::new().with("killed", self.killed)?))
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
            output: OutputOptions::default(),
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

    fn outcome(mode: OutputMode, output: ShapedOutput) -> ExecOutcome {
        ExecOutcome {
            record_id: Some(RecordId::from_ulid(knsh_core::Ulid::from_u128(9))),
            executed_command: Redacted::new("/bin/echo hi".to_owned()),
            status: LineStatus::Exited(0),
            duration_ms: 12,
            decision: Decision {
                verdict: knsh_core::DecisionVerdict::Allow,
                source: knsh_core::DecisionSource::Rule,
                rule_id: Some("exec.allow[0]".to_owned()),
                decided_by: None,
            },
            mode,
            stdout: StreamTotals { size: 3, lines: 1 },
            stderr: StreamTotals { size: 0, lines: 0 },
            output,
            cut_to_fit: false,
        }
    }

    fn excerpt_of(text: &[u8]) -> Excerpt {
        Excerpt {
            bytes: Redacted::new(text.to_vec()),
            skipped: 0,
        }
    }

    // FR-OUT-01, FR-OUT-02: `output` is read strictly; a missing mode is the profile's default.
    #[test]
    fn output_options_are_strict_and_default_to_the_profile() {
        let read = params(r#"{"command":"true","cwd":"/w","output":{"mode":"head_tail","lines":5}}"#).unwrap();
        assert_eq!(read.output.mode, Some(OutputMode::HeadTail));
        assert_eq!(read.output.request(OutputMode::Full).lines, 5);
        let absent = params(r#"{"command":"true","cwd":"/w","output":{"max_bytes":10}}"#).unwrap();
        let request = absent.output.request(OutputMode::Truncate);
        assert_eq!(request.mode, OutputMode::Truncate);
        assert_eq!(request.max_bytes, 10);
        assert_eq!(
            OutputOptions::default().request(OutputMode::ErrorsOnly),
            OutputRequest::new(OutputMode::ErrorsOnly)
        );
        let sent = params(r#"{"command":"true","cwd":"/w","output":{"mode":"ref"}}"#).unwrap();
        let text = knsh_json::write(&sent.to_json().unwrap()).unwrap();
        assert_eq!(params(&text).unwrap(), sent);
        for bad in [
            r#"{"command":"true","cwd":"/w","output":{"mode":"brief"}}"#,
            r#"{"command":"true","cwd":"/w","output":{"mode":"FULL"}}"#,
            r#"{"command":"true","cwd":"/w","output":{"max_bytes":0}}"#,
            r#"{"command":"true","cwd":"/w","output":{"max_bytes":1048577}}"#,
            r#"{"command":"true","cwd":"/w","output":{"lines":0}}"#,
            r#"{"command":"true","cwd":"/w","output":{"lines":10001}}"#,
            r#"{"command":"true","cwd":"/w","output":"full"}"#,
            // FR-OUT-03: no output modes for passed stdio.
            r#"{"command":"true","cwd":"/w","stdio":"passed","output":{"mode":"full"}}"#,
        ] {
            assert!(params(bad).is_err(), "{bad}");
        }
    }

    // FR-OUT-01: `ref` returns sizes, line counts and the record, and no output text at all.
    #[test]
    fn ref_mode_returns_sizes_and_record_id_only() {
        let value = outcome(OutputMode::Ref, ShapedOutput::Ref).to_json().unwrap();
        let result = value.as_object().unwrap();
        assert_eq!(
            result.get("record_id").and_then(Value::as_str),
            Some("00000000000000000000000009")
        );
        assert_eq!(result.get("stdout_size").and_then(Value::as_str), Some("3"));
        assert_eq!(result.get("stdout_lines").and_then(Value::as_i64), Some(1));
        assert_eq!(result.get("stderr_size").and_then(Value::as_str), Some("0"));
        assert_eq!(result.get("output_mode").and_then(Value::as_str), Some("ref"));
        for field in ["stdout", "stderr", "stdout_tail", "stdout_head", "stderr_head"] {
            assert!(result.get(field).is_none(), "{field}");
        }
        assert_eq!(result.get("exit_code").and_then(Value::as_i64), Some(0));
        assert_eq!(result.get("signal"), Some(&Value::Null));
        assert_eq!(result.get("files_changed"), Some(&Value::Null));
        assert_eq!(result.get("checkpoint_id"), Some(&Value::Null));
        let decision = result.get("decision").and_then(Value::as_object).unwrap();
        assert_eq!(decision.get("verdict").and_then(Value::as_str), Some("allow"));
        assert_eq!(decision.get("rule_id").and_then(Value::as_str), Some("exec.allow[0]"));
    }

    // Output that cannot be valid UTF-8 is shown with U+FFFD; the mode's fields are named per stream.
    #[test]
    fn mode_fields_are_named_per_stream() {
        let full = outcome(
            OutputMode::Full,
            ShapedOutput::Full {
                stdout: excerpt_of(b"hi\xff\n"),
                stderr: excerpt_of(b""),
            },
        )
        .to_json()
        .unwrap();
        let full = full.as_object().unwrap();
        assert_eq!(full.get("stdout").and_then(Value::as_str), Some("hi\u{fffd}\n"));
        assert_eq!(full.get("stdout_skipped").and_then(Value::as_str), Some("0"));
        let errors = outcome(
            OutputMode::ErrorsOnly,
            ShapedOutput::ErrorsOnly {
                stderr: excerpt_of(b"bad\n"),
                stdout_tail: Redacted::new(b"last\n".to_vec()),
                stdout_skipped_lines: 7,
            },
        )
        .to_json()
        .unwrap();
        let errors = errors.as_object().unwrap();
        assert_eq!(errors.get("stderr").and_then(Value::as_str), Some("bad\n"));
        assert_eq!(errors.get("stdout_tail").and_then(Value::as_str), Some("last\n"));
        assert_eq!(errors.get("stdout_skipped_lines").and_then(Value::as_i64), Some(7));
        assert!(errors.get("stdout").is_none());
    }

    // Two 1 MB streams cannot travel in one 1 MB frame: the answer is shortened to fit, from the middle of each
    // whole stream, and says so; the skipped counts grow by what was cut.
    #[test]
    fn full_output_is_cut_to_fit_one_frame() {
        let big = vec![b'a'; knsh_core::DEFAULT_OUTPUT_CAP];
        // Control characters are escaped six times their size: the fit measures the JSON, not the bytes.
        let control = vec![1u8; knsh_core::DEFAULT_OUTPUT_CAP];
        let mut result = outcome(
            OutputMode::Full,
            ShapedOutput::Full {
                stdout: excerpt_of(&big),
                stderr: excerpt_of(&control),
            },
        );
        let value = result.to_json_within(MAX_EXEC_RESULT_LEN).unwrap();
        assert!(knsh_json::write(&value).unwrap().len() <= MAX_EXEC_RESULT_LEN);
        assert!(result.cut_to_fit);
        let object = value.as_object().unwrap();
        assert_eq!(object.get("cut_to_fit"), Some(&Value::from(true)));
        let ShapedOutput::Full { stdout, stderr } = &result.output else {
            panic!("full");
        };
        assert_eq!(stdout.bytes.expose().len() as u64 + stdout.skipped, big.len() as u64);
        assert_eq!(
            stderr.bytes.expose().len() as u64 + stderr.skipped,
            control.len() as u64
        );
        // A small answer is left alone.
        let mut small = outcome(
            OutputMode::Full,
            ShapedOutput::Full {
                stdout: excerpt_of(b"ok\n"),
                stderr: excerpt_of(b""),
            },
        );
        small.to_json_within(MAX_EXEC_RESULT_LEN).unwrap();
        assert!(!small.cut_to_fit);
    }

    #[test]
    fn handle_params_are_a_record_id() {
        let read =
            ExecHandleParams::from_json(&parse_json(br#"{"record_id":"00000000000000000000000009"}"#, 1024).unwrap())
                .unwrap();
        assert_eq!(read.record_id, RecordId::from_ulid(knsh_core::Ulid::from_u128(9)));
        for bad in ["{}", r#"{"record_id":"x"}"#, r#"{"record_id":9}"#] {
            let value = parse_json(bad.as_bytes(), 1024).unwrap();
            assert!(ExecHandleParams::from_json(&value).is_err(), "{bad}");
        }
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
