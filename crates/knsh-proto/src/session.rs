//! Human sessions and their telemetry: `session.start_human`, `telemetry.command`, `telemetry.cwd`,
//! `telemetry.idle` and `session.info` (`specs/06-api/user-socket.md#human-sessions`, KNSH-021).
//!
//! `knsh` sends these on `user.sock` while it hosts a recorded human shell. Parameters come from a client, so each
//! field is bounded and parsed strictly: timestamps in the engine's form, an exit status from 0 to 255, a working
//! directory that is absolute and already resolved (no `.`, `..` or `//`), and a command line of at most
//! [`MAX_TELEMETRY_COMMAND_LEN`] bytes. Anything else is `-32602`, never repaired.
//!
//! A telemetry record carries only `command`, `cwd`, `started_at`, `ended_at` and `exit_code` (FR-REC-09): the
//! parameters have no other field, and unknown fields are ignored rather than stored.

use knsh_core::{CanonicalPath, RecordId, Session, SessionId, Timestamp};
use knsh_json::{Fields, FromJson, JsonError, Object, ToJson, Value};

/// The longest command line one `telemetry.command` may carry, in bytes. Longer lines are not recorded: a record
/// must stay small enough for a `records.query` page (one 1 MB frame), and a typed line this long is a paste.
pub const MAX_TELEMETRY_COMMAND_LEN: usize = 64 * 1024;

/// The longest working directory a telemetry call may carry, in bytes.
pub const MAX_TELEMETRY_CWD_LEN: usize = 16 * 1024;

/// The parameters of `session.start_human`: none. The session is a human one with recording on, bound to the
/// calling connection, and ends when that connection closes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SessionStartHumanParams;

impl FromJson for SessionStartHumanParams {
    fn from_json(value: &Value) -> Result<Self, JsonError> {
        Fields::new(value)?.finish()?;
        Ok(Self)
    }
}

impl ToJson for SessionStartHumanParams {
    fn to_json(&self) -> Result<Value, JsonError> {
        Ok(Value::Object(Object::new()))
    }
}

/// The result of `session.start_human`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionStartHumanResult {
    /// The new session.
    pub session_id: SessionId,
    /// Whether commands are recorded: always `true`, since `knsh` starts a session only to record (FR-SES-23).
    pub recording: bool,
}

impl ToJson for SessionStartHumanResult {
    fn to_json(&self) -> Result<Value, JsonError> {
        Ok(Value::Object(
            Object::new()
                .with("session_id", self.session_id.to_string())?
                .with("recording", self.recording)?,
        ))
    }
}

impl FromJson for SessionStartHumanResult {
    fn from_json(value: &Value) -> Result<Self, JsonError> {
        let mut fields = Fields::new(value)?;
        let session_id = parse(&fields.required::<String>("session_id")?, "session_id")?;
        let recording = fields.required("recording")?;
        fields.finish()?;
        Ok(Self { session_id, recording })
    }
}

/// The parameters of `telemetry.command`: one command line typed at the prompt, once it has finished
/// (FR-SES-21, FR-REC-09).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TelemetryCommandParams {
    /// The line as typed, at most [`MAX_TELEMETRY_COMMAND_LEN`] bytes. Bytes that were not UTF-8 arrive as U+FFFD.
    pub command: String,
    /// The working directory it started in.
    pub cwd: CanonicalPath,
    /// When it started.
    pub started_at: Timestamp,
    /// When the prompt came back. Never before `started_at`.
    pub ended_at: Timestamp,
    /// Its exit status, 0 to 255 (`128 + n` when signal `n` ended it).
    pub exit_code: u8,
}

impl FromJson for TelemetryCommandParams {
    fn from_json(value: &Value) -> Result<Self, JsonError> {
        let mut fields = Fields::new(value)?;
        let command: String = fields.required("command")?;
        let cwd = cwd(fields.required("cwd")?)?;
        let started_at = parse(&fields.required::<String>("started_at")?, "started_at")?;
        let ended_at: Timestamp = parse(&fields.required::<String>("ended_at")?, "ended_at")?;
        let exit_code = fields.required("exit_code")?;
        fields.finish()?;
        if command.len() > MAX_TELEMETRY_COMMAND_LEN {
            return Err(out_of_range("command"));
        }
        if ended_at < started_at {
            return Err(out_of_range("ended_at"));
        }
        Ok(Self {
            command,
            cwd,
            started_at,
            ended_at,
            exit_code,
        })
    }
}

impl ToJson for TelemetryCommandParams {
    fn to_json(&self) -> Result<Value, JsonError> {
        Ok(Value::Object(
            Object::new()
                .with("command", self.command.as_str())?
                .with("cwd", path_text(&self.cwd))?
                .with("started_at", self.started_at.to_string())?
                .with("ended_at", self.ended_at.to_string())?
                .with("exit_code", self.exit_code.to_json()?)?,
        ))
    }
}

/// The result of `telemetry.command`: the record written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TelemetryCommandResult {
    /// The new record.
    pub record_id: RecordId,
}

impl ToJson for TelemetryCommandResult {
    fn to_json(&self) -> Result<Value, JsonError> {
        Ok(Value::Object(
            Object::new().with("record_id", self.record_id.to_string())?,
        ))
    }
}

impl FromJson for TelemetryCommandResult {
    fn from_json(value: &Value) -> Result<Self, JsonError> {
        let mut fields = Fields::new(value)?;
        let record_id = parse(&fields.required::<String>("record_id")?, "record_id")?;
        fields.finish()?;
        Ok(Self { record_id })
    }
}

/// The parameters of `telemetry.cwd`: the shell's working directory changed. The result is an empty object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TelemetryCwdParams {
    /// The new working directory.
    pub cwd: CanonicalPath,
}

impl FromJson for TelemetryCwdParams {
    fn from_json(value: &Value) -> Result<Self, JsonError> {
        let mut fields = Fields::new(value)?;
        let cwd = cwd(fields.required("cwd")?)?;
        fields.finish()?;
        Ok(Self { cwd })
    }
}

impl ToJson for TelemetryCwdParams {
    fn to_json(&self) -> Result<Value, JsonError> {
        Ok(Value::Object(Object::new().with("cwd", path_text(&self.cwd))?))
    }
}

/// The parameters of `telemetry.idle`: none. The result is `{"emitted": bool}`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TelemetryIdleParams;

impl FromJson for TelemetryIdleParams {
    fn from_json(value: &Value) -> Result<Self, JsonError> {
        Fields::new(value)?.finish()?;
        Ok(Self)
    }
}

impl ToJson for TelemetryIdleParams {
    fn to_json(&self) -> Result<Value, JsonError> {
        Ok(Value::Object(Object::new()))
    }
}

/// The result of `session.info`: the caller's session (FR-SES-25, NFR-PRIV-05).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionInfoResult {
    /// The session.
    pub session: Session,
    /// Whether command output is recorded. Never for a human session (FR-REC-09).
    pub output_recording: bool,
}

impl ToJson for SessionInfoResult {
    /// `session_id`, `actor`, `profile`, `state`, `envelope`, `recording`, `output_recording`, `parent_session_id`.
    fn to_json(&self) -> Result<Value, JsonError> {
        let session = &self.session;
        let mut actor = Object::new().with("kind", session.actor().kind().as_str())?;
        if let Some(agent_id) = session.actor().agent_id() {
            actor.insert("agent_id", Value::from(agent_id.as_str()))?;
        }
        Ok(Value::Object(
            Object::new()
                .with("session_id", session.session_id().to_string())?
                .with("actor", actor)?
                .with("profile", session.profile().as_str())?
                .with("state", session.state().as_str())?
                .with("envelope", session.envelope())?
                .with("recording", session.recording())?
                .with("output_recording", self.output_recording)?
                .with(
                    "parent_session_id",
                    session.parent_session_id().map(|id| id.to_string()).to_json()?,
                )?,
        ))
    }
}

/// A working directory field: bounded, then checked to be absolute and resolved.
pub(crate) fn cwd(text: String) -> Result<CanonicalPath, JsonError> {
    if text.len() > MAX_TELEMETRY_CWD_LEN {
        return Err(out_of_range("cwd"));
    }
    CanonicalPath::new(text).map_err(|_| out_of_range("cwd"))
}

/// A canonical path as JSON text. Paths built by [`cwd`] came from JSON strings, so they are UTF-8; any other path
/// shows its non-UTF-8 bytes as U+FFFD, as in records.
pub(crate) fn path_text(path: &CanonicalPath) -> String {
    path.as_path().to_string_lossy().into_owned()
}

/// Parses a string field with `T`'s strict `FromStr`; a malformed value is out of range for `field`.
pub(crate) fn parse<T: std::str::FromStr>(text: &str, field: &'static str) -> Result<T, JsonError> {
    text.parse().map_err(|_| out_of_range(field))
}

/// The error for a field whose value has the right JSON type but is not valid.
pub(crate) const fn out_of_range(field: &'static str) -> JsonError {
    JsonError::OutOfRange { field: Some(field) }
}

#[cfg(test)]
mod tests {
    use knsh_core::{Actor, ProfileName, SessionSpec, Ulid};

    use super::*;

    fn object(text: &str) -> Value {
        knsh_json::parse(text.as_bytes(), 1 << 20).unwrap()
    }

    const GOOD: &str = r#"{"command":"ls -la","cwd":"/Users/u","started_at":"2026-11-14T10:00:00Z",
        "ended_at":"2026-11-14T10:00:01.5Z","exit_code":2}"#;

    #[test]
    fn telemetry_command_round_trips() {
        let params = TelemetryCommandParams::from_json(&object(GOOD)).unwrap();
        assert_eq!(params.command, "ls -la");
        assert_eq!(params.cwd.as_path(), std::path::Path::new("/Users/u"));
        assert_eq!(params.exit_code, 2);
        let again = TelemetryCommandParams::from_json(&params.to_json().unwrap()).unwrap();
        assert_eq!(again, params);
    }

    // Untrusted input: every malformed field is refused, never repaired.
    #[test]
    fn telemetry_command_rejects_malformed_fields() {
        let base = object(GOOD);
        // The good parameters with `key` replaced (or removed, for `None`).
        let replaced = |key: &str, value: Option<Value>| {
            let mut object = Object::new();
            for (name, old) in base.as_object().unwrap().iter() {
                if name != key {
                    object.insert(name, old.clone()).unwrap();
                }
            }
            if let Some(value) = value {
                object.insert(key, value).unwrap();
            }
            TelemetryCommandParams::from_json(&Value::Object(object))
        };
        let with = |key: &str, value: Value| replaced(key, Some(value));
        assert!(with("cwd", Value::from("relative")).is_err());
        assert!(with("cwd", Value::from("/a/../b")).is_err());
        assert!(with("cwd", Value::from(format!("/{}", "a".repeat(MAX_TELEMETRY_CWD_LEN)))).is_err());
        assert!(with("exit_code", Value::int(256).unwrap()).is_err());
        assert!(with("exit_code", Value::int(-1).unwrap()).is_err());
        assert!(with("started_at", Value::from("yesterday")).is_err());
        // Ended before it started.
        assert!(with("ended_at", Value::from("2026-11-14T09:59:59Z")).is_err());
        assert!(with("command", Value::from("x".repeat(MAX_TELEMETRY_COMMAND_LEN + 1))).is_err());
        assert!(with("command", Value::from("x".repeat(MAX_TELEMETRY_COMMAND_LEN))).is_ok());
        assert!(replaced("exit_code", None).is_err());
    }

    #[test]
    fn session_info_reports_every_field() {
        let session = Session::new(SessionSpec {
            session_id: SessionId::from_ulid(Ulid::from_u128(1)),
            actor: Actor::Human,
            profile: ProfileName::new("default").unwrap(),
            envelope: false,
            recording: Some(true),
            parent_session_id: None,
        })
        .unwrap();
        let text = knsh_json::write(
            &SessionInfoResult {
                session,
                output_recording: false,
            }
            .to_json()
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            text,
            r#"{"session_id":"00000000000000000000000001","actor":{"kind":"human"},"profile":"default","state":"active","envelope":false,"recording":true,"output_recording":false,"parent_session_id":null}"#
        );
    }

    #[test]
    fn start_result_and_empty_params_round_trip() {
        let result = SessionStartHumanResult {
            session_id: SessionId::from_ulid(Ulid::from_u128(9)),
            recording: true,
        };
        assert_eq!(
            SessionStartHumanResult::from_json(&result.to_json().unwrap()),
            Ok(result)
        );
        assert!(SessionStartHumanParams::from_json(&object("{}")).is_ok());
        assert!(TelemetryIdleParams::from_json(&object("[]")).is_err());
        let cwd = TelemetryCwdParams::from_json(&object(r#"{"cwd":"/tmp"}"#)).unwrap();
        assert_eq!(TelemetryCwdParams::from_json(&cwd.to_json().unwrap()), Ok(cwd));
    }
}
