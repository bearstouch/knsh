//! The execution record model (`specs/05-models/execution-record.md`, KNSH-016).
//!
//! An [`ExecutionRecord`] is what the record store keeps for one command line. Its text fields are
//! [`Redacted`] or already-typed values ([`CanonicalPath`], IDs, timestamps), so no constructor here takes a raw
//! secret-bearing `String` (FR-REC-11) and nothing in a record prints its command by accident (NFR-PRIV-02).
//!
//! The fields every record has (the human telemetry set of FR-REC-09: `command`, `cwd`, times and `exit_code`) are
//! plain members; the fields only agent records carry are grouped in [`RecordDetails`], so the store can drop them
//! as one unit for human sessions. `sandbox_violations` is filled by the violation reader (KNSH-047), and `decision`
//! ([`RecordDecision`]) and `argv` ([`ArgvEntry`], from the line's classification) by the supervisor (KNSH-050,
//! KNSH-052). `network` ([`NetworkEntry`]) lists the hosts the proxy let the line contact or refused it (KNSH-060,
//! FR-NET-09). Fields that later phases fill (`children`, `files_changed`, …) have columns in the store's schema but
//! no member here yet: they are always empty in phase 2.

use std::fmt;
use std::str::FromStr;

use knsh_json::{Fields, FromJson, IntString, JsonError, Object, ToJson, Value};

use crate::error::CoreError;
use crate::id::{CheckpointId, RecordId, SessionId};
use crate::path::CanonicalPath;
use crate::policy::DecisionSource;
use crate::redacted::Redacted;
use crate::session::Actor;
use crate::time::Timestamp;
use crate::violation::SandboxViolation;

/// One of a command's two recorded output streams.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum OutputStream {
    /// Standard output.
    Stdout,
    /// Standard error.
    Stderr,
}

impl OutputStream {
    /// Both streams, in a fixed order.
    pub const ALL: [Self; 2] = [Self::Stdout, Self::Stderr];

    /// The wire and storage form: `stdout` or `stderr`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Stdout => "stdout",
            Self::Stderr => "stderr",
        }
    }
}

impl fmt::Display for OutputStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for OutputStream {
    type Err = CoreError;

    /// Parses `stdout` or `stderr` exactly.
    ///
    /// # Errors
    ///
    /// [`CoreError::InvalidOutputStream`] for anything else.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "stdout" => Ok(Self::Stdout),
            "stderr" => Ok(Self::Stderr),
            _ => Err(CoreError::InvalidOutputStream),
        }
    }
}

/// A record's final effective verdict (`specs/05-models/execution-record.md#decision`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DecisionVerdict {
    /// The line was allowed as received.
    Allow,
    /// The line was refused and never ran (FR-LC-30).
    Deny,
    /// A rewrite was applied and the rewritten line was allowed (FR-LC-11).
    Rewrite,
}

impl DecisionVerdict {
    /// The record spelling: `allow`, `deny` or `rewrite`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
            Self::Rewrite => "rewrite",
        }
    }
}

impl FromStr for DecisionVerdict {
    type Err = CoreError;

    /// Parses the record spelling exactly.
    ///
    /// # Errors
    ///
    /// [`CoreError::InvalidDecision`] for anything else.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "allow" => Ok(Self::Allow),
            "deny" => Ok(Self::Deny),
            "rewrite" => Ok(Self::Rewrite),
            _ => Err(CoreError::InvalidDecision),
        }
    }
}

/// The record's `decision` object: how the line was decided, by whom, and how long it took
/// (`specs/05-models/execution-record.md#decision`, KNSH-050).
///
/// The supervisor builds it from the pipeline's own decision, so the record says exactly what the pipeline decided.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RecordDecision {
    /// The final effective verdict.
    pub verdict: DecisionVerdict,
    /// Which component made the final decision.
    pub source: DecisionSource,
    /// The deciding rule (`exec.allow[1]`), when a rule decided or asked.
    pub rule_id: Option<String>,
    /// Who decided when it was not a rule: the hook, the authority or the user.
    pub decided_by: Option<String>,
    /// Time from receiving the line to the final decision, in milliseconds.
    pub latency_ms: u64,
    /// The hooks that ran for the line, in order, with their run times (FR-HOOK-05, KNSH-062). Empty when none
    /// matched, and for records written before hooks were recorded.
    pub hooks: Vec<HookRun>,
}

impl ToJson for RecordDecision {
    /// `{verdict, source, rule_id, decided_by, latency_ms}`, with `null` for what is unknown.
    fn to_json(&self) -> Result<Value, JsonError> {
        Ok(Value::Object(
            Object::new()
                .with("verdict", self.verdict.as_str())?
                .with("source", self.source.code())?
                .with("rule_id", self.rule_id.to_json()?)?
                .with("decided_by", self.decided_by.to_json()?)?
                .with("latency_ms", self.latency_ms.to_json()?)?
                .with("hooks", self.hooks.to_json()?)?,
        ))
    }
}

impl FromJson for RecordDecision {
    /// Reads the object [`ToJson`] writes: every member present (`null` where unknown), nothing else.
    fn from_json(value: &Value) -> Result<Self, JsonError> {
        let invalid = |field| JsonError::OutOfRange { field: Some(field) };
        let mut fields = Fields::new(value)?;
        let verdict: String = fields.required("verdict")?;
        let source: String = fields.required("source")?;
        let rule_id: Option<String> = fields.required("rule_id")?;
        let decided_by: Option<String> = fields.required("decided_by")?;
        let latency_ms: u64 = fields.required("latency_ms")?;
        // Optional: records written before KNSH-062 have no `hooks` member, and read back with none.
        let hooks: Option<Vec<HookRun>> = fields.optional("hooks")?;
        fields.finish_closed()?;
        let hooks = hooks.unwrap_or_default();
        if hooks.len() > MAX_HOOK_RUNS {
            return Err(invalid("hooks"));
        }
        Ok(Self {
            verdict: verdict.parse().map_err(|_| invalid("verdict"))?,
            source: DecisionSource::from_code(&source).ok_or_else(|| invalid("source"))?,
            rule_id,
            decided_by,
            latency_ms,
            hooks,
        })
    }
}

/// Most hook runs one record lists: every registered hook on both evaluation passes of a rewritten line
/// (`specs/05-models/hook.md`: at most 32 hooks, FR-LC-11: at most one rewrite).
pub const MAX_HOOK_RUNS: usize = 64;

/// How one hook ended, as its record shows it (`specs/05-models/execution-record.md#decision`, `decision.hooks`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HookResult {
    /// It answered `allow`, or printed nothing and exited 0.
    Allow,
    /// It answered `deny`, or printed nothing and exited 2.
    Deny,
    /// It answered `ask`.
    Ask,
    /// It answered `rewrite`.
    Rewrite,
    /// It answered `annotate`.
    Annotate,
    /// It could not be started, printed something unreadable, or exited abnormally: a deny (FR-HOOK-04).
    Error,
    /// It was still running at its timeout and was killed: a deny (FR-HOOK-04).
    Timeout,
    /// It was not run because its registration is invalid: a deny of every line it would match (FR-HOOK-04).
    Invalid,
}

impl HookResult {
    /// The record spelling: `allow`, `deny`, `ask`, `rewrite`, `annotate`, `error`, `timeout` or `invalid`.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
            Self::Ask => "ask",
            Self::Rewrite => "rewrite",
            Self::Annotate => "annotate",
            Self::Error => "error",
            Self::Timeout => "timeout",
            Self::Invalid => "invalid",
        }
    }

    /// Parses [`code`](Self::code) exactly.
    #[must_use]
    pub fn from_code(code: &str) -> Option<Self> {
        [
            Self::Allow,
            Self::Deny,
            Self::Ask,
            Self::Rewrite,
            Self::Annotate,
            Self::Error,
            Self::Timeout,
            Self::Invalid,
        ]
        .into_iter()
        .find(|result| result.code() == code)
    }
}

/// One hook's part in a line's decision: which hook, how it ended, how long it ran (FR-HOOK-05) and, for an
/// `annotate`, its labels.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HookRun {
    /// The hook's name, `hooks[N]` by its place in the configuration, or `hooks` when the whole configuration was
    /// invalid.
    pub hook: String,
    /// How it ended.
    pub result: HookResult,
    /// How long it ran, in milliseconds, at most its timeout; 0 for a hook that was not run.
    pub duration_ms: u64,
    /// The labels of an `annotate`; empty otherwise. Already checked against the label charset, so they hold no
    /// line text.
    pub labels: Vec<String>,
}

impl ToJson for HookRun {
    /// `{hook, result, duration_ms, labels}`.
    fn to_json(&self) -> Result<Value, JsonError> {
        Ok(Value::Object(
            Object::new()
                .with("hook", self.hook.as_str())?
                .with("result", self.result.code())?
                .with("duration_ms", self.duration_ms.to_json()?)?
                .with("labels", self.labels.to_json()?)?,
        ))
    }
}

impl FromJson for HookRun {
    /// Reads the object [`ToJson`] writes: every member present, nothing else.
    fn from_json(value: &Value) -> Result<Self, JsonError> {
        let mut fields = Fields::new(value)?;
        let hook: String = fields.required("hook")?;
        let result: String = fields.required("result")?;
        let duration_ms: u64 = fields.required("duration_ms")?;
        let labels: Vec<String> = fields.required("labels")?;
        fields.finish_closed()?;
        Ok(Self {
            hook,
            result: HookResult::from_code(&result).ok_or(JsonError::OutOfRange { field: Some("result") })?,
            duration_ms,
            labels,
        })
    }
}

/// The stored form of a record's `decision`: its JSON object as text.
///
/// # Errors
///
/// [`CoreError::InvalidDecision`] only if the object cannot be written, which a valid decision always can.
pub fn encode_decision(decision: &RecordDecision) -> Result<String, CoreError> {
    decision
        .to_json()
        .and_then(|value| knsh_json::write(&value))
        .map_err(|_| CoreError::InvalidDecision)
}

/// Reads the stored form written by [`encode_decision`].
///
/// # Errors
///
/// [`CoreError::InvalidDecision`] for text that is not such an object.
pub fn decode_decision(text: &str) -> Result<RecordDecision, CoreError> {
    knsh_json::parse(text.as_bytes(), text.len())
        .and_then(|value| RecordDecision::from_json(&value))
        .map_err(|_| CoreError::InvalidDecision)
}

/// The class of one `argv` entry, as its record shows it (`specs/05-models/execution-record.md#argvclass`).
///
/// The record's own copy of [`knsh_bash::CommandClass`]: the dynamic reason is kept as its stable code, so a stored
/// record reads back whatever reasons later parser versions add.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ArgvClass {
    /// A binary from a trusted folder; also builtins, functions defined in the line and names not found.
    Static,
    /// A known wrapper that was unwrapped; the command it runs is a separate entry linked to it.
    Wrapper,
    /// A binary from an agent-writable place, governed by `exec.project_executables`.
    ProjectExecutable,
    /// Dynamic code, with its reason code (`eval`, `interpreter_code`, a whole-line reason such as `syntax_error`, …).
    Dynamic {
        /// The [`knsh_bash::DynamicReason::code`] of why.
        reason: String,
    },
}

impl ArgvClass {
    /// The record spelling: `static`, `wrapper`, `project_executable` or `dynamic`.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Static => "static",
            Self::Wrapper => "wrapper",
            Self::ProjectExecutable => "project_executable",
            Self::Dynamic { .. } => "dynamic",
        }
    }

    /// The dynamic reason code, or `None` for a class that is not dynamic.
    #[must_use]
    pub fn reason(&self) -> Option<&str> {
        match self {
            Self::Dynamic { reason } => Some(reason),
            Self::Static | Self::Wrapper | Self::ProjectExecutable => None,
        }
    }
}

impl From<knsh_bash::CommandClass> for ArgvClass {
    fn from(class: knsh_bash::CommandClass) -> Self {
        match class {
            knsh_bash::CommandClass::Static => Self::Static,
            knsh_bash::CommandClass::Wrapper => Self::Wrapper,
            knsh_bash::CommandClass::ProjectExecutable => Self::ProjectExecutable,
            knsh_bash::CommandClass::Dynamic { reason } => Self::Dynamic {
                reason: reason.code().to_owned(),
            },
        }
    }
}

/// One entry of a record's `argv` (`specs/05-models/execution-record.md`): a simple command, a wrapper, or the
/// command a wrapper runs, with what it resolved to and its class.
///
/// Arguments are deliberately not kept: they are in `command` already, redacted as a whole line, and a copy here
/// would be a second place for a secret to leak from.
///
/// # Invariants
///
/// - `path` is set only for a binary (static, wrapper or project executable resolved to a file): never for a
///   builtin, a function, a name not found, or a name not known from the line.
/// - `wrapper` indexes an earlier entry of the same `argv`.
#[derive(Debug, Clone)]
pub struct ArgvEntry {
    /// The command name as written (after quote removal), redacted; `None` when it is built from an expansion.
    pub name: Option<Redacted<String>>,
    /// The canonical absolute path it resolved to. A path that is not valid UTF-8 is kept with U+FFFD replacements,
    /// as `cwd` is shown.
    pub path: Option<String>,
    /// Its class.
    pub class: ArgvClass,
    /// The index of the wrapper entry that runs it, if any.
    pub wrapper: Option<usize>,
    /// `false` when it receives more arguments at run time (the command `xargs` runs): rules that depend on its
    /// arguments treated them as unknown.
    pub arguments_complete: bool,
}

/// The record's `argv` for a classified line (FR-LC-05, KNSH-052): one entry per classified command, in source
/// order. A line the parser could not read has no commands, and is recorded as a single dynamic entry carrying the
/// parser's whole-line reason, so the record never shows an empty `argv` for a line that was dynamic as a whole.
/// Each name goes through `redactor`, the session's, which also made the record's `command` (FR-REC-05, KNSH-091).
#[must_use]
pub fn argv_of(classification: &knsh_bash::Classification, redactor: &crate::Redactor) -> Vec<ArgvEntry> {
    if classification.is_whole_line() {
        // The parser always gives a whole-line rejection a reason; `syntax_error` covers the impossible case without
        // ever presenting the line as anything but dynamic.
        let reason = classification
            .dynamic_parts()
            .first()
            .map_or("syntax_error", |part| part.reason.code());
        return vec![ArgvEntry {
            name: None,
            path: None,
            class: ArgvClass::Dynamic {
                reason: reason.to_owned(),
            },
            wrapper: None,
            arguments_complete: false,
        }];
    }
    classification
        .commands()
        .iter()
        .map(|command| ArgvEntry {
            // Through the same redaction as `command` (FR-REC-04, FR-REC-11): a name is line text, and must never
            // show what the redacted line hides.
            name: command.name.as_deref().map(|name| redactor.redact_text(name)),
            path: command
                .program
                .as_ref()
                .and_then(knsh_bash::Program::path)
                .map(|path| path.to_string_lossy().into_owned()),
            class: command.class.into(),
            wrapper: command.wrapper,
            arguments_complete: command.arguments_complete,
        })
        .collect()
}

impl ToJson for ArgvEntry {
    /// `{name, path, class, reason, wrapper, arguments_complete}`, with `null` for what is not set.
    fn to_json(&self) -> Result<Value, JsonError> {
        Ok(Value::Object(
            Object::new()
                .with("name", self.name.as_ref().map(|name| name.expose().clone()).to_json()?)?
                .with("path", self.path.to_json()?)?
                .with("class", self.class.code())?
                .with("reason", self.class.reason().map(str::to_owned).to_json()?)?
                .with("wrapper", self.wrapper.to_json()?)?
                .with("arguments_complete", self.arguments_complete)?,
        ))
    }
}

impl FromJson for ArgvEntry {
    /// Reads the object [`ToJson`] writes: every member present, nothing else, and a reason exactly when the class
    /// is `dynamic`.
    fn from_json(value: &Value) -> Result<Self, JsonError> {
        let invalid = |field| JsonError::OutOfRange { field: Some(field) };
        let mut fields = Fields::new(value)?;
        let name: Option<String> = fields.required("name")?;
        let path: Option<String> = fields.required("path")?;
        let class: String = fields.required("class")?;
        let reason: Option<String> = fields.required("reason")?;
        let wrapper: Option<usize> = fields.required("wrapper")?;
        let arguments_complete: bool = fields.required("arguments_complete")?;
        fields.finish_closed()?;
        let class = match (class.as_str(), reason) {
            ("static", None) => ArgvClass::Static,
            ("wrapper", None) => ArgvClass::Wrapper,
            ("project_executable", None) => ArgvClass::ProjectExecutable,
            ("dynamic", Some(reason)) if !reason.is_empty() => ArgvClass::Dynamic { reason },
            _ => return Err(invalid("class")),
        };
        Ok(Self {
            name: name.map(Redacted::new),
            path,
            class,
            wrapper,
            arguments_complete,
        })
    }
}

/// The stored form of a record's `argv`: its JSON array as text.
///
/// # Errors
///
/// [`CoreError::InvalidArgv`] only if the array cannot be written, which entries built here always can.
pub fn encode_argv(argv: &[ArgvEntry]) -> Result<String, CoreError> {
    let values = argv
        .iter()
        .map(ToJson::to_json)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| CoreError::InvalidArgv)?;
    knsh_json::write(&Value::Array(values)).map_err(|_| CoreError::InvalidArgv)
}

/// Reads the stored form written by [`encode_argv`].
///
/// # Errors
///
/// [`CoreError::InvalidArgv`] for text that is not such an array, or whose `wrapper` links do not point to an
/// earlier entry.
pub fn decode_argv(text: &str) -> Result<Vec<ArgvEntry>, CoreError> {
    let value = knsh_json::parse(text.as_bytes(), text.len()).map_err(|_| CoreError::InvalidArgv)?;
    let Value::Array(items) = value else {
        return Err(CoreError::InvalidArgv);
    };
    let argv: Vec<ArgvEntry> = items
        .iter()
        .map(ArgvEntry::from_json)
        .collect::<Result<_, _>>()
        .map_err(|_| CoreError::InvalidArgv)?;
    // The classifier lists each wrapper before the command it runs; any other link was not written by the engine.
    let linked = argv
        .iter()
        .enumerate()
        .all(|(index, entry)| entry.wrapper.is_none_or(|wrapper| wrapper < index));
    if linked { Ok(argv) } else { Err(CoreError::InvalidArgv) }
}

/// The most distinct entries one record's `network` keeps (FR-NET-09). Repeats of a kept entry only add to its
/// count; further distinct ones are dropped, so a command that tries many hosts cannot grow its record without
/// bound.
pub const MAX_NETWORK_ENTRIES: usize = 256;

/// The longest refusal reason a stored `network` entry may carry: far above the proxy's fixed names.
const MAX_NETWORK_REASON_LEN: usize = 64;

/// What the proxy did with one connection of the line (KNSH-060).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum NetworkResult {
    /// Every check passed and the tunnel opened.
    Contacted,
    /// The proxy refused the connection, for this fixed reason (`host_not_allowed`, `approval_required`, …).
    Refused(String),
}

impl NetworkResult {
    /// `contacted` or `refused`.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::Contacted => "contacted",
            Self::Refused(_) => "refused",
        }
    }

    /// The refusal reason, for a refused connection.
    #[must_use]
    pub fn reason(&self) -> Option<&str> {
        match self {
            Self::Contacted => None,
            Self::Refused(reason) => Some(reason),
        }
    }
}

/// One element of a record's `network` field: a host and port the line asked the proxy to reach, what the proxy
/// did, and how many times (FR-NET-09, KNSH-060).
///
/// # Invariants
///
/// - `count` is at least 1.
/// - A refusal reason is 1 to 64 lower-case ASCII letters and `_`: one of the proxy's fixed names, never free text.
#[derive(Debug, Clone)]
pub struct NetworkEntry {
    /// The host as the line named it: a normalised name or an IP literal, redacted like every text a record keeps.
    pub host: Redacted<String>,
    /// The port.
    pub port: u16,
    /// Contacted, or refused and why.
    pub result: NetworkResult,
    /// How many connections this entry stands for.
    pub count: u32,
}

impl NetworkEntry {
    /// One connection to `host:port` with `result`.
    #[must_use]
    pub fn new(host: Redacted<String>, port: u16, result: NetworkResult) -> Self {
        Self {
            host,
            port,
            result,
            count: 1,
        }
    }

    /// Whether `other` is a repeat of this entry: same host, port and result.
    #[must_use]
    pub fn same_connection(&self, other: &Self) -> bool {
        self.host.expose() == other.host.expose() && self.port == other.port && self.result == other.result
    }
}

impl ToJson for NetworkEntry {
    /// `{host, port, result, reason, count}`, with `reason` `null` for a contacted host.
    fn to_json(&self) -> Result<Value, JsonError> {
        Ok(Value::Object(
            Object::new()
                .with("host", self.host.expose().as_str())?
                .with("port", self.port)?
                .with("result", self.result.code())?
                .with("reason", self.result.reason().map(str::to_owned).to_json()?)?
                .with("count", self.count)?,
        ))
    }
}

impl FromJson for NetworkEntry {
    /// Reads the object [`ToJson`] writes: every member present, nothing else, a reason exactly when refused, and
    /// a count of at least 1.
    fn from_json(value: &Value) -> Result<Self, JsonError> {
        let invalid = |field| JsonError::OutOfRange { field: Some(field) };
        let mut fields = Fields::new(value)?;
        let host: String = fields.required("host")?;
        let port: u16 = fields.required("port")?;
        let result: String = fields.required("result")?;
        let reason: Option<String> = fields.required("reason")?;
        let count: u32 = fields.required("count")?;
        fields.finish_closed()?;
        if host.is_empty() {
            return Err(invalid("host"));
        }
        if count == 0 {
            return Err(invalid("count"));
        }
        let result = match (result.as_str(), reason) {
            ("contacted", None) => NetworkResult::Contacted,
            ("refused", Some(reason)) if is_reason(&reason) => NetworkResult::Refused(reason),
            _ => return Err(invalid("result")),
        };
        Ok(Self {
            host: Redacted::new(host),
            port,
            result,
            count,
        })
    }
}

/// Whether `reason` has the shape of one of the proxy's fixed refusal names.
fn is_reason(reason: &str) -> bool {
    !reason.is_empty()
        && reason.len() <= MAX_NETWORK_REASON_LEN
        && reason.bytes().all(|byte| byte.is_ascii_lowercase() || byte == b'_')
}

/// Adds `incoming` to `kept`, merging repeats of an entry already there and keeping at most `limit` distinct ones.
/// Returns how many distinct entries did not fit and were dropped.
pub fn merge_network(kept: &mut Vec<NetworkEntry>, incoming: Vec<NetworkEntry>, limit: usize) -> usize {
    let mut dropped = 0;
    for entry in incoming {
        if let Some(existing) = kept.iter_mut().find(|existing| existing.same_connection(&entry)) {
            existing.count = existing.count.saturating_add(entry.count);
        } else if kept.len() < limit {
            kept.push(entry);
        } else {
            dropped += 1;
        }
    }
    dropped
}

/// The stored form of a record's `network`: its JSON array as text.
///
/// # Errors
///
/// [`CoreError::InvalidNetwork`] if an entry breaks its invariants (a zero count, a reason that is not a fixed
/// name), so nothing the engine could not read back is stored.
pub fn encode_network(network: &[NetworkEntry]) -> Result<String, CoreError> {
    let valid = network
        .iter()
        .all(|entry| entry.count > 0 && !entry.host.expose().is_empty() && entry.result.reason().is_none_or(is_reason));
    if !valid {
        return Err(CoreError::InvalidNetwork);
    }
    let values = network
        .iter()
        .map(ToJson::to_json)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| CoreError::InvalidNetwork)?;
    knsh_json::write(&Value::Array(values)).map_err(|_| CoreError::InvalidNetwork)
}

/// Reads the stored form written by [`encode_network`].
///
/// # Errors
///
/// [`CoreError::InvalidNetwork`] for text that is not such an array.
pub fn decode_network(text: &str) -> Result<Vec<NetworkEntry>, CoreError> {
    let value = knsh_json::parse(text.as_bytes(), text.len()).map_err(|_| CoreError::InvalidNetwork)?;
    let Value::Array(items) = value else {
        return Err(CoreError::InvalidNetwork);
    };
    items
        .iter()
        .map(NetworkEntry::from_json)
        .collect::<Result<_, _>>()
        .map_err(|_| CoreError::InvalidNetwork)
}

/// Why a line's changes in a checkpoint root were not protected (FR-CKP-02, KNSH-079): the record's
/// `unprotected[].reason`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UnprotectedReason {
    /// The root's shadow was still being built when the line started (`checkpoints.required = false`).
    ShadowBuilding,
    /// The root's shadow build failed, or was stopped.
    ShadowFailed,
    /// The root has no shadow: its store could not be used, its volume cannot hold one, or none was started for it.
    NoShadow,
}

impl UnprotectedReason {
    /// The wire value: `shadow_building`, `shadow_failed` or `no_shadow`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ShadowBuilding => "shadow_building",
            Self::ShadowFailed => "shadow_failed",
            Self::NoShadow => "no_shadow",
        }
    }

    fn parse(text: &str) -> Option<Self> {
        match text {
            "shadow_building" => Some(Self::ShadowBuilding),
            "shadow_failed" => Some(Self::ShadowFailed),
            "no_shadow" => Some(Self::NoShadow),
            _ => None,
        }
    }
}

/// A checkpoint root a line touched whose changes were not protected, and why (FR-CKP-02, KNSH-079): one element of
/// the record's `unprotected` array, `{"root", "reason"}`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct UnprotectedRoot {
    /// The root. Roots come from profile text, so they are UTF-8; one that is not is written lossily.
    pub root: CanonicalPath,
    /// Why.
    pub reason: UnprotectedReason,
}

impl ToJson for UnprotectedRoot {
    fn to_json(&self) -> Result<Value, JsonError> {
        Ok(Value::Object(
            Object::new()
                .with("root", self.root.as_path().to_string_lossy().into_owned())?
                .with("reason", self.reason.as_str())?,
        ))
    }
}

impl FromJson for UnprotectedRoot {
    /// Reads the object [`ToJson`] writes: both members, nothing else, a canonical root and a known reason.
    fn from_json(value: &Value) -> Result<Self, JsonError> {
        let mut fields = Fields::new(value)?;
        let root: String = fields.required("root")?;
        let reason: String = fields.required("reason")?;
        fields.finish_closed()?;
        Ok(Self {
            root: CanonicalPath::new(root).map_err(|_| JsonError::OutOfRange { field: Some("root") })?,
            reason: UnprotectedReason::parse(&reason).ok_or(JsonError::OutOfRange { field: Some("reason") })?,
        })
    }
}

/// The stored form of a record's `unprotected`: its JSON array as text.
///
/// # Errors
///
/// [`CoreError::InvalidUnprotected`] if it cannot be written (it always can).
pub fn encode_unprotected(unprotected: &[UnprotectedRoot]) -> Result<String, CoreError> {
    let values = unprotected
        .iter()
        .map(ToJson::to_json)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| CoreError::InvalidUnprotected)?;
    knsh_json::write(&Value::Array(values)).map_err(|_| CoreError::InvalidUnprotected)
}

/// Reads the stored form written by [`encode_unprotected`].
///
/// # Errors
///
/// [`CoreError::InvalidUnprotected`] for text that is not such an array.
pub fn decode_unprotected(text: &str) -> Result<Vec<UnprotectedRoot>, CoreError> {
    let value = knsh_json::parse(text.as_bytes(), text.len()).map_err(|_| CoreError::InvalidUnprotected)?;
    let Value::Array(items) = value else {
        return Err(CoreError::InvalidUnprotected);
    };
    items
        .iter()
        .map(UnprotectedRoot::from_json)
        .collect::<Result<_, _>>()
        .map_err(|_| CoreError::InvalidUnprotected)
}

/// The most entries a record's `files_changed` lists (KNSH-082). A line may change tens of thousands of files; the
/// record keeps the first of them, sorted, and its checkpoint keeps them all, so one `npm install` cannot make a record
/// megabytes long. The `exec.run` result's `files_changed` is the full count.
pub const MAX_RECORD_FILES_CHANGED: usize = 256;

/// How a path under a checkpoint root changed (KNSH-082): one element's `change` in the record's `files_changed`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FileChange {
    /// Nothing was there before the change (its pre-image is the "did not exist" marker).
    Created,
    /// Something was there before and after (written, or replaced by another kind of entry).
    Modified,
    /// Something was there before, and nothing is after.
    Deleted,
}

impl FileChange {
    /// The wire value: `created`, `modified` or `deleted`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Created => "created",
            Self::Modified => "modified",
            Self::Deleted => "deleted",
        }
    }

    fn parse(text: &str) -> Option<Self> {
        match text {
            "created" => Some(Self::Created),
            "modified" => Some(Self::Modified),
            "deleted" => Some(Self::Deleted),
            _ => None,
        }
    }
}

/// A path's post-image identity as a record shows it (FR-CKP-09, KNSH-082): what the path looked like right after
/// the change, so undo can tell whether it still does (FR-CKP-20). Mirrors `knsh_checkpoint::PostImageIdentity`,
/// which `knsh-core` cannot name (it has no platform types).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RecordedIdentity {
    /// The inode number.
    pub inode: u64,
    /// Size in bytes.
    pub size: u64,
    /// Modification time: whole seconds since 1970-01-01 UTC.
    pub mtime_seconds: i64,
    /// Modification time: nanoseconds within the second, `0..1_000_000_000`.
    pub mtime_nanoseconds: u32,
    /// SHA-256 of the contents, for regular files under 64 MiB only; `None` when no hash was taken.
    pub sha256: Option<[u8; 32]>,
}

/// One element of a record's `files_changed` (KNSH-082): `{"path", "change", "post_image"}`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ChangedFile {
    /// The path, under one of the line's checkpoint roots. Written lossily if it is not UTF-8, as `cwd` is.
    pub path: CanonicalPath,
    /// How it changed.
    pub change: FileChange,
    /// Its post-image identity; `None` when it was deleted, or when the identity could not be read (the checkpoint
    /// is then uncertain, never given a wrong identity).
    pub post_image: Option<RecordedIdentity>,
}

impl ToJson for RecordedIdentity {
    /// `inode` and `size` are decimal strings (they may exceed 2^53); `sha256` is lower-case hex or `null`.
    fn to_json(&self) -> Result<Value, JsonError> {
        let sha256 = self.sha256.map(|digest| hex(&digest));
        Ok(Value::Object(
            Object::new()
                .with("inode", IntString(i128::from(self.inode)).to_json()?)?
                .with("size", IntString(i128::from(self.size)).to_json()?)?
                .with("mtime_seconds", self.mtime_seconds.to_json()?)?
                .with("mtime_nanoseconds", self.mtime_nanoseconds.to_json()?)?
                .with("sha256", sha256.to_json()?)?,
        ))
    }
}

impl FromJson for RecordedIdentity {
    /// Reads the object [`ToJson`] writes, and nothing else.
    fn from_json(value: &Value) -> Result<Self, JsonError> {
        let mut fields = Fields::new(value)?;
        let inode: IntString = fields.required("inode")?;
        let size: IntString = fields.required("size")?;
        let mtime_seconds: i64 = fields.required("mtime_seconds")?;
        let mtime_nanoseconds: u32 = fields.required("mtime_nanoseconds")?;
        let sha256: Option<String> = fields.optional("sha256")?;
        fields.finish_closed()?;
        let out_of_range = |field| JsonError::OutOfRange { field: Some(field) };
        if mtime_nanoseconds >= 1_000_000_000 {
            return Err(out_of_range("mtime_nanoseconds"));
        }
        Ok(Self {
            inode: u64::try_from(inode.0).map_err(|_| out_of_range("inode"))?,
            size: u64::try_from(size.0).map_err(|_| out_of_range("size"))?,
            mtime_seconds,
            mtime_nanoseconds,
            sha256: sha256
                .map(|text| unhex(&text).ok_or(out_of_range("sha256")))
                .transpose()?,
        })
    }
}

impl ToJson for ChangedFile {
    fn to_json(&self) -> Result<Value, JsonError> {
        Ok(Value::Object(
            Object::new()
                .with("path", self.path.as_path().to_string_lossy().into_owned())?
                .with("change", self.change.as_str())?
                .with("post_image", self.post_image.to_json()?)?,
        ))
    }
}

impl FromJson for ChangedFile {
    /// Reads the object [`ToJson`] writes: every member, nothing else, a canonical path and a known change.
    fn from_json(value: &Value) -> Result<Self, JsonError> {
        let mut fields = Fields::new(value)?;
        let path: String = fields.required("path")?;
        let change: String = fields.required("change")?;
        let post_image: Option<RecordedIdentity> = fields.optional("post_image")?;
        fields.finish_closed()?;
        Ok(Self {
            path: CanonicalPath::new(path).map_err(|_| JsonError::OutOfRange { field: Some("path") })?,
            change: FileChange::parse(&change).ok_or(JsonError::OutOfRange { field: Some("change") })?,
            post_image,
        })
    }
}

/// Lower-case hexadecimal.
fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut text, byte| {
            // Writing to a `String` cannot fail.
            let _ = write!(text, "{byte:02x}");
            text
        })
}

/// A SHA-256 digest from exactly 64 lower-case hexadecimal digits, the only form [`hex`] writes.
fn unhex(text: &str) -> Option<[u8; 32]> {
    let digits = text.as_bytes();
    if digits.len() != 64 {
        return None;
    }
    let value = |digit: u8| match digit {
        b'0'..=b'9' => Some(digit - b'0'),
        b'a'..=b'f' => Some(digit - b'a' + 10),
        _ => None,
    };
    let mut digest = [0; 32];
    let (pairs, _) = digits.as_chunks::<2>();
    for (byte, [high, low]) in digest.iter_mut().zip(pairs) {
        *byte = (value(*high)? << 4) | value(*low)?;
    }
    Some(digest)
}

/// The stored form of a record's `files_changed`: its JSON array as text.
///
/// # Errors
///
/// [`CoreError::InvalidFilesChanged`] if it cannot be written (a modification time outside ±2^53 seconds).
pub fn encode_files_changed(files: &[ChangedFile]) -> Result<String, CoreError> {
    let values = files
        .iter()
        .map(ToJson::to_json)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| CoreError::InvalidFilesChanged)?;
    knsh_json::write(&Value::Array(values)).map_err(|_| CoreError::InvalidFilesChanged)
}

/// Reads the stored form written by [`encode_files_changed`].
///
/// # Errors
///
/// [`CoreError::InvalidFilesChanged`] for text that is not such an array, or lists more than
/// [`MAX_RECORD_FILES_CHANGED`].
pub fn decode_files_changed(text: &str) -> Result<Vec<ChangedFile>, CoreError> {
    let value = knsh_json::parse(text.as_bytes(), text.len()).map_err(|_| CoreError::InvalidFilesChanged)?;
    let Value::Array(items) = value else {
        return Err(CoreError::InvalidFilesChanged);
    };
    if items.len() > MAX_RECORD_FILES_CHANGED {
        return Err(CoreError::InvalidFilesChanged);
    }
    items
        .iter()
        .map(ChangedFile::from_json)
        .collect::<Result<_, _>>()
        .map_err(|_| CoreError::InvalidFilesChanged)
}

/// How a record's file changes were attributed (FR-CKP-05 to FR-CKP-07, KNSH-081): the record's `attribution`, and
/// the kind of the history-tree edge its changes belong to (`specs/05-models/checkpoint.md`).
///
/// File events carry no process ID, so attribution goes by time and place: a change in a checkpoint root while a
/// supervised line runs there belongs to that line, one between lines to the envelope's agent, and one in a root no
/// envelope watches to nobody the engine supervises.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Attribution {
    /// Made while one supervised line ran alone in the root (FR-CKP-05).
    Command,
    /// Made inside an envelope while no supervised line ran in the root (FR-CKP-06).
    AgentEdit,
    /// Made while no envelope watched the root: not the agent's, so never offered for agent undo.
    External,
    /// Made while two or more supervised lines overlapped in time in one root; undone together (FR-CKP-07).
    Concurrent,
}

impl Attribution {
    /// The wire value: `command`, `agent_edit`, `external` or `concurrent`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Command => "command",
            Self::AgentEdit => "agent_edit",
            Self::External => "external",
            Self::Concurrent => "concurrent",
        }
    }

    /// Reads a wire value written by [`Attribution::as_str`]; `None` for anything else.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "command" => Some(Self::Command),
            "agent_edit" => Some(Self::AgentEdit),
            "external" => Some(Self::External),
            "concurrent" => Some(Self::Concurrent),
            _ => None,
        }
    }

    /// Whether an agent may be offered undo of changes attributed this way: never for `external` changes, which no
    /// agent session made.
    #[must_use]
    pub const fn agent_may_undo(self) -> bool {
        match self {
            Self::Command | Self::AgentEdit | Self::Concurrent => true,
            Self::External => false,
        }
    }
}

/// The fields of an execution record that only agent records carry.
///
/// A human telemetry record keeps none of them (FR-REC-09): the store replaces them with
/// [`RecordDetails::default`] before writing, whatever the caller supplied.
#[derive(Debug, Clone, Default)]
pub struct RecordDetails {
    /// The original line when a rewrite was applied (FR-REC-04), already redacted.
    pub rewritten_from: Option<Redacted<String>>,
    /// Exit code of each command in the last pipeline.
    pub pipestatus: Vec<i32>,
    /// The signal that ended the line, such as `SIGKILL`.
    pub signal: Option<String>,
    /// Sandbox profile name and a hash of the compiled profile.
    pub sandbox_profile: Option<String>,
    /// Names of the secrets injected into the line, never their values (FR-REC-11).
    pub secrets_injected: Vec<String>,
    /// The checkpoint holding the line's pre-images.
    pub checkpoint_id: Option<CheckpointId>,
    /// Denials the system reported for the line, best effort (FR-SBX-08, KNSH-047). Late ones are appended after
    /// the record is written.
    pub sandbox_violations: Vec<SandboxViolation>,
    /// How the line was decided (KNSH-050). Every agent line that reaches lifecycle step 2 has one (FR-REC-01).
    pub decision: Option<RecordDecision>,
    /// Each simple command of the line with what it resolved to and its class (KNSH-052). Empty only for a line
    /// refused before it was parsed.
    pub argv: Vec<ArgvEntry>,
    /// The hosts the proxy let the line contact or refused it, as it reported them (FR-NET-09, KNSH-060). Empty for
    /// a line that asked the proxy for nothing.
    pub network: Vec<NetworkEntry>,
    /// Checkpoint roots the line touched whose changes were not protected, and why (FR-CKP-02, KNSH-079): with
    /// `checkpoints.required = false`, a line runs at once even if a root's shadow is not ready. Empty when every
    /// root it touched was protected, or it touched none.
    pub unprotected: Vec<UnprotectedRoot>,
    /// How the line's file changes were attributed (KNSH-081): `command`, or `concurrent` when another line overlapped
    /// it in one of its checkpoint roots. `None` for a line that never ran (denied) and for records written before.
    pub attribution: Option<Attribution>,
    /// The paths the line's changes created, modified or deleted under its checkpoint roots, with their post-image
    /// identities (KNSH-082), sorted, at most [`MAX_RECORD_FILES_CHANGED`] (its checkpoint lists them all). For a
    /// `concurrent` line, those of its whole set, which cannot be told apart (FR-CKP-07). `None` for a line that
    /// touched no protected root or never ran; empty for one that changed nothing.
    pub files_changed: Option<Vec<ChangedFile>>,
}

impl RecordDetails {
    /// Whether no field is set, as for every human record.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        let Self {
            rewritten_from,
            pipestatus,
            signal,
            sandbox_profile,
            secrets_injected,
            checkpoint_id,
            sandbox_violations,
            decision,
            argv,
            network,
            unprotected,
            attribution,
            files_changed,
        } = self;
        rewritten_from.is_none()
            && pipestatus.is_empty()
            && signal.is_none()
            && sandbox_profile.is_none()
            && secrets_injected.is_empty()
            && checkpoint_id.is_none()
            && sandbox_violations.is_empty()
            && decision.is_none()
            && argv.is_empty()
            && network.is_empty()
            && unprotected.is_empty()
            && attribution.is_none()
            && files_changed.is_none()
    }
}

/// One execution record.
///
/// # Invariants
///
/// - `command` is the line actually executed, with secrets redacted before it got here (FR-REC-04, FR-REC-05).
/// - `exit_code` is `None` when the line was denied or is still running.
#[derive(Debug, Clone)]
pub struct ExecutionRecord {
    /// Primary key; orders records by creation time.
    pub record_id: RecordId,
    /// The owning session.
    pub session_id: SessionId,
    /// Who ran the line. Decides which fields are kept (FR-REC-09).
    pub actor: Actor,
    /// The line, redacted.
    pub command: Redacted<String>,
    /// Working directory at start.
    pub cwd: CanonicalPath,
    /// When the line started.
    pub started_at: Timestamp,
    /// When the line ended, if it has.
    pub ended_at: Option<Timestamp>,
    /// The line's exit code; `None` when denied or still running.
    pub exit_code: Option<i32>,
    /// Agent-only fields; always empty for a human record once stored.
    pub details: RecordDetails,
}

/// What the store kept of one recorded output stream (FR-REC-06).
///
/// When the output was larger than the cap, its head and tail are kept and the middle is dropped: the stored bytes
/// are `head ++ tail`, `skipped` bytes were dropped between them, and they were dropped at offset `skipped_at` of
/// the stored bytes (the length of the head).
///
/// # Invariants
///
/// `stored + skipped == original` and `skipped_at <= stored`; `skipped == 0` implies `skipped_at == stored`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct OutputInfo {
    /// Bytes kept, the range `records.output` can read.
    pub stored: u64,
    /// Bytes the command wrote.
    pub original: u64,
    /// Bytes dropped between head and tail.
    pub skipped: u64,
    /// Offset in the stored bytes where the dropped bytes were.
    pub skipped_at: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(host: &str, port: u16, result: NetworkResult) -> NetworkEntry {
        NetworkEntry::new(Redacted::new(host.to_owned()), port, result)
    }

    // KNSH-081: every attribution round-trips its wire value; anything else is refused. Only `external` changes are
    // kept from agent undo.
    #[test]
    fn attribution_round_trips_its_wire_value() {
        for attribution in [
            Attribution::Command,
            Attribution::AgentEdit,
            Attribution::External,
            Attribution::Concurrent,
        ] {
            assert_eq!(Attribution::parse(attribution.as_str()), Some(attribution));
            assert_eq!(attribution.agent_may_undo(), attribution != Attribution::External);
        }
        assert_eq!(Attribution::parse("Command"), None);
        assert_eq!(Attribution::parse(""), None);
    }

    // KNSH-060 (FR-NET-09): a record's `network` list round-trips its stored form, and repeats merge with counts.
    #[test]
    fn network_round_trips_and_merges_repeats() {
        let refused = || NetworkResult::Refused("approval_required".to_owned());
        let mut kept = Vec::new();
        let dropped = merge_network(
            &mut kept,
            vec![
                entry("registry.npmjs.org", 443, NetworkResult::Contacted),
                entry("github.com", 443, refused()),
                entry("registry.npmjs.org", 443, NetworkResult::Contacted),
                // Another port or another result is another entry.
                entry("registry.npmjs.org", 8443, NetworkResult::Contacted),
                entry("github.com", 443, NetworkResult::Contacted),
            ],
            MAX_NETWORK_ENTRIES,
        );
        assert_eq!(dropped, 0);
        assert_eq!(kept.len(), 4);
        assert_eq!(kept[0].count, 2);
        let text = encode_network(&kept).unwrap();
        assert_eq!(
            text.split("},{").next().unwrap(),
            r#"[{"host":"registry.npmjs.org","port":443,"result":"contacted","reason":null,"count":2"#
        );
        let back = decode_network(&text).unwrap();
        assert_eq!(back.len(), kept.len());
        for (back, kept) in back.iter().zip(&kept) {
            assert!(back.same_connection(kept));
            assert_eq!(back.count, kept.count);
        }
    }

    // Bounded: past the limit, new distinct entries are dropped and counted; repeats still merge.
    #[test]
    fn network_keeps_at_most_the_limit() {
        let mut kept = Vec::new();
        let many = (1..=5)
            .map(|port| entry("a.test", port, NetworkResult::Contacted))
            .collect();
        assert_eq!(merge_network(&mut kept, many, 3), 2);
        assert_eq!(kept.len(), 3);
        assert_eq!(
            merge_network(&mut kept, vec![entry("a.test", 1, NetworkResult::Contacted)], 3),
            0
        );
        assert_eq!(kept[0].count, 2);
    }

    // Only what the engine writes is read back: anything else is refused, never repaired.
    #[test]
    fn network_refuses_what_the_engine_never_writes() {
        for bad in [
            "{}",
            "[1]",
            r#"[{"host":"a","port":1,"result":"contacted","reason":"x","count":1}]"#,
            r#"[{"host":"a","port":1,"result":"refused","reason":null,"count":1}]"#,
            r#"[{"host":"a","port":1,"result":"refused","reason":"Not A Name","count":1}]"#,
            r#"[{"host":"a","port":1,"result":"contacted","reason":null,"count":0}]"#,
            r#"[{"host":"","port":1,"result":"contacted","reason":null,"count":1}]"#,
            r#"[{"host":"a","port":70000,"result":"contacted","reason":null,"count":1}]"#,
            r#"[{"host":"a","port":1,"result":"contacted","reason":null,"count":1,"extra":true}]"#,
        ] {
            assert_eq!(decode_network(bad).unwrap_err(), CoreError::InvalidNetwork, "{bad}");
        }
        let mut zero = entry("a", 1, NetworkResult::Contacted);
        zero.count = 0;
        assert_eq!(encode_network(&[zero]), Err(CoreError::InvalidNetwork));
        assert_eq!(
            encode_network(&[entry("a", 1, NetworkResult::Refused("free text".to_owned()))]),
            Err(CoreError::InvalidNetwork)
        );
    }

    // KNSH-079: the `unprotected` list round-trips, and only the engine's own form is read back.
    #[test]
    fn unprotected_roots_round_trip_and_refuse_other_forms() {
        let roots = vec![
            UnprotectedRoot {
                root: CanonicalPath::new("/code/app").unwrap(),
                reason: UnprotectedReason::ShadowBuilding,
            },
            UnprotectedRoot {
                root: CanonicalPath::new("/Volumes/Stick/x").unwrap(),
                reason: UnprotectedReason::NoShadow,
            },
        ];
        let text = encode_unprotected(&roots).unwrap();
        assert_eq!(
            text,
            r#"[{"root":"/code/app","reason":"shadow_building"},{"root":"/Volumes/Stick/x","reason":"no_shadow"}]"#
        );
        assert_eq!(decode_unprotected(&text).unwrap(), roots);
        for bad in [
            "{}",
            r#"[{"root":"/a"}]"#,
            r#"[{"root":"relative","reason":"no_shadow"}]"#,
            r#"[{"root":"/a","reason":"other"}]"#,
            r#"[{"root":"/a","reason":"no_shadow","extra":1}]"#,
        ] {
            assert_eq!(decode_unprotected(bad), Err(CoreError::InvalidUnprotected), "{bad}");
        }
    }

    // KNSH-082, FR-CKP-09: `files_changed` round-trips with its post-image identities (a hash only where one was
    // taken, inode and size as decimal strings), and only the engine's own form is read back.
    #[test]
    fn files_changed_round_trip_and_refuse_other_forms() {
        let files = vec![
            ChangedFile {
                path: CanonicalPath::new("/code/app/new.rs").unwrap(),
                change: FileChange::Created,
                post_image: Some(RecordedIdentity {
                    inode: u64::MAX,
                    size: 5,
                    mtime_seconds: 1_763_000_000,
                    mtime_nanoseconds: 123_456_789,
                    sha256: Some([0xab; 32]),
                }),
            },
            ChangedFile {
                path: CanonicalPath::new("/code/app/big.bin").unwrap(),
                change: FileChange::Modified,
                post_image: Some(RecordedIdentity {
                    inode: 7,
                    size: 64 << 20,
                    mtime_seconds: -1,
                    mtime_nanoseconds: 0,
                    sha256: None,
                }),
            },
            ChangedFile {
                path: CanonicalPath::new("/code/app/gone").unwrap(),
                change: FileChange::Deleted,
                post_image: None,
            },
        ];
        let text = encode_files_changed(&files).unwrap();
        assert!(text.contains(r#""inode":"18446744073709551615""#), "{text}");
        assert!(text.contains(&format!(r#""sha256":"{}""#, "ab".repeat(32))), "{text}");
        assert!(text.contains(r#""sha256":null"#), "{text}");
        assert_eq!(decode_files_changed(&text).unwrap(), files);
        assert_eq!(decode_files_changed("[]").unwrap(), Vec::new());

        let identity = r#"{"inode":"1","size":"2","mtime_seconds":3,"mtime_nanoseconds":4,"sha256":null}"#;
        for bad in [
            "{}".to_owned(),
            r#"[{"path":"/a","change":"renamed","post_image":null}]"#.to_owned(),
            r#"[{"path":"rel","change":"created","post_image":null}]"#.to_owned(),
            r#"[{"path":"/a","change":"deleted","post_image":null,"extra":1}]"#.to_owned(),
            format!(
                r#"[{{"path":"/a","change":"created","post_image":{}}}]"#,
                identity.replace(":4,", ":1000000000,")
            ),
            format!(
                r#"[{{"path":"/a","change":"created","post_image":{}}}]"#,
                identity.replace("null", r#""AB""#)
            ),
            format!(
                "[{}]",
                vec![r#"{"path":"/a","change":"deleted","post_image":null}"#; 257].join(",")
            ),
        ] {
            assert_eq!(decode_files_changed(&bad), Err(CoreError::InvalidFilesChanged), "{bad}");
        }
    }

    #[test]
    fn output_stream_round_trips_its_wire_form() {
        for stream in OutputStream::ALL {
            assert_eq!(stream.as_str().parse::<OutputStream>(), Ok(stream));
            assert_eq!(stream.to_string(), stream.as_str());
        }
        for bad in ["", "STDOUT", "stdin", "stdout "] {
            assert_eq!(
                bad.parse::<OutputStream>(),
                Err(CoreError::InvalidOutputStream),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn default_details_are_empty() {
        assert!(RecordDetails::default().is_empty());
        let details = RecordDetails {
            pipestatus: vec![0],
            ..RecordDetails::default()
        };
        assert!(!details.is_empty());
    }

    // The stored form of `decision` reads back as written; anything else is refused.
    #[test]
    fn decision_round_trips_its_json_form() {
        let decision = RecordDecision {
            verdict: DecisionVerdict::Rewrite,
            source: DecisionSource::Authority,
            rule_id: Some("exec.ask[0]".to_owned()),
            decided_by: None,
            latency_ms: 42,
            hooks: vec![
                HookRun {
                    hook: "hooks[0]".to_owned(),
                    result: HookResult::Annotate,
                    duration_ms: 7,
                    labels: vec!["reviewed".to_owned()],
                },
                HookRun {
                    hook: "hooks[1]".to_owned(),
                    result: HookResult::Allow,
                    duration_ms: 0,
                    labels: Vec::new(),
                },
            ],
        };
        let value = decision.to_json().unwrap();
        assert_eq!(RecordDecision::from_json(&value).unwrap(), decision);
        assert_eq!(decode_decision(&encode_decision(&decision).unwrap()).unwrap(), decision);
        assert_eq!(decode_decision("deny"), Err(CoreError::InvalidDecision));
        for verdict in [DecisionVerdict::Allow, DecisionVerdict::Deny, DecisionVerdict::Rewrite] {
            assert_eq!(verdict.as_str().parse::<DecisionVerdict>(), Ok(verdict));
        }
        for bad in [
            r#"{"verdict":"ask","source":"rule","rule_id":null,"decided_by":null,"latency_ms":1}"#,
            r#"{"verdict":"allow","source":"nobody","rule_id":null,"decided_by":null,"latency_ms":1}"#,
            r#"{"verdict":"allow","source":"rule","rule_id":null,"decided_by":null,"latency_ms":-1}"#,
            r#"{"verdict":"allow","source":"rule","decided_by":null,"latency_ms":1}"#,
            r#"{"verdict":"allow","source":"rule","rule_id":null,"decided_by":null,"latency_ms":1,"hooks":[{"hook":"hooks[0]","result":"maybe","duration_ms":1,"labels":[]}]}"#,
            r#"{"verdict":"allow","source":"rule","rule_id":null,"decided_by":null,"latency_ms":1,"hooks":[{"hook":"hooks[0]","result":"allow","duration_ms":1}]}"#,
        ] {
            let value = knsh_json::parse(bad.as_bytes(), bad.len()).unwrap();
            assert!(RecordDecision::from_json(&value).is_err(), "{bad}");
        }
        for result in [
            HookResult::Allow,
            HookResult::Deny,
            HookResult::Ask,
            HookResult::Rewrite,
            HookResult::Annotate,
            HookResult::Error,
            HookResult::Timeout,
            HookResult::Invalid,
        ] {
            assert_eq!(HookResult::from_code(result.code()), Some(result));
        }
    }

    // A decision stored before KNSH-062 has no `hooks` member and reads back with none.
    #[test]
    fn decision_without_hooks_member_reads_back_empty() {
        let old = r#"{"verdict":"deny","source":"hook","rule_id":null,"decided_by":"guard","latency_ms":3}"#;
        let decision = decode_decision(old).unwrap();
        assert_eq!(decision.hooks.len(), 0);
        assert_eq!(decision.decided_by.as_deref(), Some("guard"));
    }

    /// Resolves every name in `/usr/bin`, except `./tool`, a project executable, and `cd`, a builtin.
    struct Resolver;

    impl knsh_bash::Resolver for Resolver {
        fn resolve(&self, name: &str, _lookup: knsh_bash::Lookup) -> knsh_bash::Program {
            match name {
                "./tool" => knsh_bash::Program::ProjectExecutable("/p/tool".into()),
                "cd" => knsh_bash::Program::Builtin,
                _ => knsh_bash::Program::Trusted(std::path::Path::new("/usr/bin").join(name)),
            }
        }

        fn source_file(&self, _path: &str) -> knsh_bash::SourceFile {
            knsh_bash::SourceFile::Unresolved
        }
    }

    fn argv_for(line: &str) -> Vec<ArgvEntry> {
        let parsed = knsh_bash::parse_line(line);
        argv_of(
            &knsh_bash::classify(&parsed, line, &Resolver, &knsh_bash::Interpreters::defaults()),
            &crate::Redactor::default(),
        )
    }

    /// `(name, path, class, wrapper)` of one entry.
    type Summary<'a> = (Option<&'a str>, Option<&'a str>, ArgvClass, Option<usize>);

    fn summary(argv: &[ArgvEntry]) -> Vec<Summary<'_>> {
        argv.iter()
            .map(|entry| {
                (
                    entry.name.as_ref().map(|name| name.expose().as_str()),
                    entry.path.as_deref(),
                    entry.class.clone(),
                    entry.wrapper,
                )
            })
            .collect()
    }

    // KNSH-052: one entry per classified command, with its path, class and wrapper link; a builtin has no path; a
    // dynamic entry keeps its reason code; a line the parser could not read is a single dynamic entry.
    #[test]
    fn argv_follows_the_classification() {
        let dynamic = |reason: &str| ArgvClass::Dynamic {
            reason: reason.to_owned(),
        };
        assert_eq!(
            summary(&argv_for("cd /p && nice -n 5 ./tool | sh -c \"$x\"")),
            [
                (Some("cd"), None, ArgvClass::Static, None),
                (Some("nice"), Some("/usr/bin/nice"), ArgvClass::Wrapper, None),
                (Some("./tool"), Some("/p/tool"), ArgvClass::ProjectExecutable, Some(1)),
                (Some("sh"), Some("/usr/bin/sh"), dynamic("interpreter_code"), None),
            ]
        );
        assert_eq!(
            summary(&argv_for("$cmd arg")),
            [(None, None, dynamic("expanded_command_name"), None)]
        );
        let unread = argv_for("echo 'open");
        assert_eq!(summary(&unread), [(None, None, dynamic("syntax_error"), None)]);
        assert!(!unread[0].arguments_complete);
        assert!(argv_for("ls | xargs rm").iter().any(|entry| !entry.arguments_complete));
    }

    // KNSH-052: the stored form of `argv` reads back as written; anything the engine could not have written is
    // refused, including a wrapper link that does not point to an earlier entry.
    #[test]
    fn argv_round_trips_its_stored_form() {
        let argv = argv_for("env A=1 git status && eval ls");
        let decoded = decode_argv(&encode_argv(&argv).unwrap()).unwrap();
        assert_eq!(summary(&decoded), summary(&argv));
        assert_eq!(decode_argv("[]").unwrap().len(), 0);
        for bad in [
            "",
            "{}",
            r#"[{"name":null,"path":null,"class":"static","reason":null,"wrapper":0,"arguments_complete":true}]"#,
            r#"[{"name":null,"path":null,"class":"static","reason":null,"wrapper":null}]"#,
            r#"[{"name":null,"path":null,"class":"wrapper","reason":"eval","wrapper":null,"arguments_complete":true}]"#,
            r#"[{"name":null,"path":null,"class":"dynamic","reason":null,"wrapper":null,"arguments_complete":true}]"#,
            r#"[{"name":null,"path":null,"class":"static","reason":null,"wrapper":null,"arguments_complete":true,"x":1}]"#,
        ] {
            assert_eq!(
                decode_argv(bad).map(|argv| argv.len()),
                Err(CoreError::InvalidArgv),
                "{bad}"
            );
        }
    }

    // NFR-PRIV-02: a record's derived Debug never shows the command.
    #[test]
    fn record_debug_never_prints_the_command() {
        let record = ExecutionRecord {
            record_id: RecordId::from_ulid(crate::Ulid::from_u128(1)),
            session_id: SessionId::from_ulid(crate::Ulid::from_u128(2)),
            actor: Actor::Human,
            command: Redacted::new(String::from("curl -H 'token: hunter2'")),
            cwd: CanonicalPath::new("/tmp").unwrap(),
            started_at: Timestamp::UNIX_EPOCH,
            ended_at: None,
            exit_code: None,
            details: RecordDetails {
                rewritten_from: Some(Redacted::new(String::from("hunter2"))),
                ..RecordDetails::default()
            },
        };
        let printed = format!("{record:?}");
        assert!(!printed.contains("hunter2"), "{printed}");
    }
}
