//! `records.query`, `records.output` and `records.forget`: parameters and results
//! (`specs/06-api/user-socket.md#records`, KNSH-016, KNSH-017).
//!
//! Parameters come from untrusted clients, so each is bounded and parsed strictly before it is used: IDs must be
//! canonical ULIDs, times the engine's RFC 3339 form, byte counts canonical decimal strings. Anything else is
//! `-32602`, never repaired.
//!
//! Byte counts and offsets travel as decimal strings because they may exceed ±2^53
//! (`specs/06-api/wire-format.md#strict-json-profile`).

use knsh_core::{ExecutionRecord, OutputInfo, OutputStream, RecordId, SessionId, Timestamp};
use knsh_json::{Fields, FromJson, IntString, JsonError, Object, StreamId, ToJson, Value};

/// The default page size of `records.query`.
pub const DEFAULT_RECORDS_PAGE: u32 = 100;

/// The largest page size of `records.query`.
pub const MAX_RECORDS_PAGE: u32 = 1_000;

/// The longest `text` filter of `records.query`, in bytes.
pub const MAX_RECORDS_TEXT_LEN: usize = 4_096;

/// The most output bytes one `records.output` answer carries inline as base64, for clients that opted out of binary
/// frames. Its base64 form (about 683 KiB) fits in one 1 MB JSON frame with room for the rest of the answer;
/// clients read longer ranges in several calls.
pub const MAX_BASE64_OUTPUT: u64 = 512 * 1024;

/// The content type announced for an output stream: raw bytes, with no encoding promised.
pub const OUTPUT_CONTENT_TYPE: &str = "application/octet-stream";

/// The parameters of `records.query`. Every filter is optional; they combine with AND.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordsQueryParams {
    /// Only this session's records.
    pub session_id: Option<SessionId>,
    /// Only records started at or after this instant.
    pub since: Option<Timestamp>,
    /// Only records started before this instant.
    pub until: Option<Timestamp>,
    /// Only records whose `command` contains this text (case-sensitive substring), at most
    /// [`MAX_RECORDS_TEXT_LEN`] bytes.
    pub text: Option<String>,
    /// Records per page, 1 to [`MAX_RECORDS_PAGE`]; [`DEFAULT_RECORDS_PAGE`] when absent.
    pub limit: u32,
    /// The previous page's `next_cursor`: only records after it.
    pub cursor: Option<RecordId>,
}

impl FromJson for RecordsQueryParams {
    fn from_json(value: &Value) -> Result<Self, JsonError> {
        let mut fields = Fields::new(value)?;
        let session_id = parsed(fields.optional::<String>("session_id")?, "session_id")?;
        let since = parsed(fields.optional::<String>("since")?, "since")?;
        let until = parsed(fields.optional::<String>("until")?, "until")?;
        let text = fields.optional::<String>("text")?;
        if text.as_ref().is_some_and(|text| text.len() > MAX_RECORDS_TEXT_LEN) {
            return Err(out_of_range("text"));
        }
        let limit = fields.optional::<u32>("limit")?.unwrap_or(DEFAULT_RECORDS_PAGE);
        if limit == 0 || limit > MAX_RECORDS_PAGE {
            return Err(out_of_range("limit"));
        }
        let cursor = parsed(fields.optional::<String>("cursor")?, "cursor")?;
        fields.finish()?;
        Ok(Self {
            session_id,
            since,
            until,
            text,
            limit,
            cursor,
        })
    }
}

impl ToJson for RecordsQueryParams {
    /// Absent filters are left out; `limit` is always written. [`FromJson`] reads the output back to an equal value
    /// (`knsh history`, KNSH-023).
    fn to_json(&self) -> Result<Value, JsonError> {
        let mut object = Object::new();
        if let Some(session_id) = self.session_id {
            object.insert("session_id", Value::from(session_id.to_string()))?;
        }
        if let Some(since) = self.since {
            object.insert("since", Value::from(since.to_string()))?;
        }
        if let Some(until) = self.until {
            object.insert("until", Value::from(until.to_string()))?;
        }
        if let Some(text) = &self.text {
            object.insert("text", Value::from(text.as_str()))?;
        }
        object.insert("limit", self.limit.to_json()?)?;
        if let Some(cursor) = self.cursor {
            object.insert("cursor", Value::from(cursor.to_string()))?;
        }
        Ok(Value::Object(object))
    }
}

/// The parameters of `records.output`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecordsOutputParams {
    /// The record.
    pub record_id: RecordId,
    /// `stdout` or `stderr`.
    pub stream: OutputStream,
    /// The first byte to read, in the stored bytes; `0` when absent.
    pub offset: u64,
    /// At most this many bytes; to the end when absent.
    pub length: Option<u64>,
}

impl FromJson for RecordsOutputParams {
    fn from_json(value: &Value) -> Result<Self, JsonError> {
        let mut fields = Fields::new(value)?;
        let record_id = parse(&fields.required::<String>("record_id")?, "record_id")?;
        let stream = parse(&fields.required::<String>("stream")?, "stream")?;
        let offset = byte_count(fields.optional("offset")?, "offset")?.unwrap_or(0);
        let length = byte_count(fields.optional("length")?, "length")?;
        fields.finish()?;
        Ok(Self {
            record_id,
            stream,
            offset,
            length,
        })
    }
}

/// The parameters of `records.forget` (`user.sock` only, FR-REC-10).
///
/// At least one of `session_id` and `since` is required; when both are given a record must match both. A call with
/// neither is `-32602`, so no client can delete every record by omitting a field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecordsForgetParams {
    /// Only this session's records.
    pub session_id: Option<SessionId>,
    /// Only records started at or after this instant.
    pub since: Option<Timestamp>,
    /// Delete the matching checkpoints too, at once (FR-CKP-34, KNSH-088). Where checkpoints cannot be taken `knshd`
    /// answers `-32005` and deletes nothing, rather than ignoring the flag (KNSH-017).
    pub with_checkpoints: bool,
}

impl FromJson for RecordsForgetParams {
    fn from_json(value: &Value) -> Result<Self, JsonError> {
        let mut fields = Fields::new(value)?;
        let session_id = parsed(fields.optional::<String>("session_id")?, "session_id")?;
        let since = parsed(fields.optional::<String>("since")?, "since")?;
        let with_checkpoints = fields.optional::<bool>("with_checkpoints")?.unwrap_or(false);
        fields.finish()?;
        if session_id.is_none() && since.is_none() {
            return Err(JsonError::MissingField("session_id"));
        }
        Ok(Self {
            session_id,
            since,
            with_checkpoints,
        })
    }
}

impl ToJson for RecordsForgetParams {
    /// Absent selectors are left out; `with_checkpoints` is written only when set.
    fn to_json(&self) -> Result<Value, JsonError> {
        let mut object = Object::new();
        if let Some(session_id) = self.session_id {
            object.insert("session_id", Value::from(session_id.to_string()))?;
        }
        if let Some(since) = self.since {
            object.insert("since", Value::from(since.to_string()))?;
        }
        if self.with_checkpoints {
            object.insert("with_checkpoints", Value::from(true))?;
        }
        Ok(Value::Object(object))
    }
}

/// The result of `records.forget`: how many records were deleted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecordsForgetResult {
    /// The number of records deleted, with their output.
    pub deleted: u64,
}

impl ToJson for RecordsForgetResult {
    fn to_json(&self) -> Result<Value, JsonError> {
        Ok(Value::Object(Object::new().with("deleted", self.deleted.to_json()?)?))
    }
}

impl FromJson for RecordsForgetResult {
    fn from_json(value: &Value) -> Result<Self, JsonError> {
        let mut fields = Fields::new(value)?;
        let deleted = fields.required("deleted")?;
        fields.finish()?;
        Ok(Self { deleted })
    }
}

/// Parses a string field with `T`'s strict `FromStr`; a malformed value is out of range for `field`.
fn parse<T: std::str::FromStr>(text: &str, field: &'static str) -> Result<T, JsonError> {
    text.parse().map_err(|_| out_of_range(field))
}

/// [`parse`] for an optional field.
fn parsed<T: std::str::FromStr>(text: Option<String>, field: &'static str) -> Result<Option<T>, JsonError> {
    text.map(|text| parse(&text, field)).transpose()
}

/// A byte count sent as a decimal string, which must be non-negative and fit in `u64`.
fn byte_count(value: Option<IntString>, field: &'static str) -> Result<Option<u64>, JsonError> {
    value
        .map(|IntString(count)| u64::try_from(count).map_err(|_| out_of_range(field)))
        .transpose()
}

const fn out_of_range(field: &'static str) -> JsonError {
    JsonError::OutOfRange { field: Some(field) }
}

/// A byte count as a JSON string (±2^53 rule).
pub(crate) fn bytes(count: u64) -> Value {
    Value::int_string(i128::from(count))
}

/// One record in a `records.query` result, with what was kept of its output.
#[derive(Debug, Clone, Copy)]
pub struct RecordEntry<'a> {
    /// The record.
    pub record: &'a ExecutionRecord,
    /// The stored standard output, if recorded.
    pub stdout: Option<OutputInfo>,
    /// The stored standard error, if recorded.
    pub stderr: Option<OutputInfo>,
}

impl ToJson for RecordEntry<'_> {
    /// Every record has `record_id`, `session_id`, `actor`, `command`, `cwd`, `started_at`, `ended_at`,
    /// `exit_code`, `stdout` and `stderr` (the last four may be `null`). Agent records also carry their
    /// agent-only fields; human records never do (FR-REC-09).
    fn to_json(&self) -> Result<Value, JsonError> {
        let record = self.record;
        let mut actor = Object::new().with("kind", record.actor.kind().as_str())?;
        if let Some(agent_id) = record.actor.agent_id() {
            actor.insert("agent_id", Value::from(agent_id.as_str()))?;
        }
        let mut object = Object::new()
            .with("record_id", record.record_id.to_string())?
            .with("session_id", record.session_id.to_string())?
            .with("actor", actor)?
            // The command was redacted before it was stored (FR-REC-05); this is the API it is read through.
            .with("command", record.command.expose().as_str())?
            // A path need not be UTF-8; JSON strings must be. Bytes that are not valid UTF-8 show as U+FFFD.
            .with("cwd", record.cwd.as_path().to_string_lossy().into_owned())?
            .with("started_at", record.started_at.to_string())?
            .with("ended_at", record.ended_at.map(|at| at.to_string()).to_json()?)?
            .with("exit_code", record.exit_code.to_json()?)?;
        if record.actor.agent_id().is_some() {
            let details = &record.details;
            object.insert(
                "rewritten_from",
                details
                    .rewritten_from
                    .as_ref()
                    .map(|text| text.expose().clone())
                    .to_json()?,
            )?;
            object.insert("pipestatus", details.pipestatus.to_json()?)?;
            object.insert("signal", details.signal.to_json()?)?;
            object.insert("sandbox_profile", details.sandbox_profile.to_json()?)?;
            object.insert("secrets_injected", details.secrets_injected.to_json()?)?;
            object.insert(
                "checkpoint_id",
                details.checkpoint_id.map(|id| id.to_string()).to_json()?,
            )?;
            // Best effort (FR-SBX-08): what the violation reader attributed to this line, merged.
            let violations = details
                .sandbox_violations
                .iter()
                .map(ToJson::to_json)
                .collect::<Result<Vec<_>, _>>()?;
            object.insert("sandbox_violations", Value::Array(violations))?;
            // How the line was decided (KNSH-050, `execution-record.md#decision`), or null for a record written
            // before decisions were recorded.
            object.insert("decision", details.decision.to_json()?)?;
            // Each simple command with what it resolved to and its class (KNSH-052, `execution-record.md`).
            object.insert("argv", details.argv.to_json()?)?;
            // The hosts the proxy let the line contact or refused it (KNSH-060, FR-NET-09).
            object.insert("network", details.network.to_json()?)?;
            // Checkpoint roots the line touched whose changes were not protected, and why (KNSH-079, FR-CKP-02).
            object.insert("unprotected", details.unprotected.to_json()?)?;
            // How the line's file changes were attributed (KNSH-081, FR-CKP-05, FR-CKP-07), or null for a line that
            // never ran or a record written before attribution.
            let attribution = details
                .attribution
                .map_or(Value::Null, |attribution| Value::from(attribution.as_str()));
            object.insert("attribution", attribution)?;
            // The paths the line changed under its checkpoint roots, with post-image identities (KNSH-082), or null
            // for a line that touched no protected root.
            object.insert("files_changed", details.files_changed.to_json()?)?;
            // Whether the line is irreversible and why (KNSH-093, FR-IRR-04): `{"value", "reasons"}`, or null for a
            // line refused before it was classified and for records written before KNSH-093.
            object.insert("irreversible", details.irreversible.to_json()?)?;
        }
        object.insert("stdout", self.stdout.as_ref().map(output_info).transpose()?.to_json()?)?;
        object.insert("stderr", self.stderr.as_ref().map(output_info).transpose()?.to_json()?)?;
        Ok(Value::Object(object))
    }
}

/// `{size, original_size, skipped, skipped_at}` of one stored stream, as strings.
fn output_info(info: &OutputInfo) -> Result<Value, JsonError> {
    Ok(Value::Object(
        Object::new()
            .with("size", bytes(info.stored))?
            .with("original_size", bytes(info.original))?
            .with("skipped", bytes(info.skipped))?
            .with("skipped_at", bytes(info.skipped_at))?,
    ))
}

/// The result of `records.query`.
#[derive(Debug, Clone)]
pub struct RecordsQueryResult<'a> {
    /// The page, ordered by `record_id`.
    pub records: Vec<RecordEntry<'a>>,
    /// Pass as `cursor` to read the next page; `None` (`null`) on the last page.
    pub next_cursor: Option<RecordId>,
}

impl ToJson for RecordsQueryResult<'_> {
    fn to_json(&self) -> Result<Value, JsonError> {
        Ok(Value::Object(
            Object::new()
                .with("records", self.records.to_json()?)?
                .with("next_cursor", self.next_cursor.map(|id| id.to_string()).to_json()?)?,
        ))
    }
}

/// How the bytes of a `records.output` answer travel.
#[derive(Debug, Clone, Copy)]
pub enum OutputData<'a> {
    /// In binary chunks on this stream, right after the JSON answer, then an end-of-stream frame.
    Stream(StreamId),
    /// Inline as canonical base64: the client opted out of binary frames.
    Base64(&'a [u8]),
}

/// The result of `records.output`.
#[derive(Debug, Clone, Copy)]
pub struct RecordsOutputResult<'a> {
    /// The record.
    pub record_id: RecordId,
    /// The stream read.
    pub stream: OutputStream,
    /// What is stored of the stream; `None` when output was not recorded for it.
    pub info: Option<OutputInfo>,
    /// The offset read, clamped to the stored size.
    pub offset: u64,
    /// The number of bytes returned.
    pub length: u64,
    /// The bytes.
    pub data: OutputData<'a>,
}

impl ToJson for RecordsOutputResult<'_> {
    /// `size` is the total stored size of the stream, `original_size` what the command wrote; `skipped` bytes were
    /// dropped at `skipped_at` (FR-REC-06). `offset` and `length` describe the range returned, in `data` (binary
    /// stream) or `data_base64`.
    fn to_json(&self) -> Result<Value, JsonError> {
        let info = self.info.unwrap_or(OutputInfo {
            stored: 0,
            original: 0,
            skipped: 0,
            skipped_at: 0,
        });
        let mut object = Object::new()
            .with("record_id", self.record_id.to_string())?
            .with("stream", self.stream.as_str())?
            .with("recorded", self.info.is_some())?
            .with("size", bytes(info.stored))?
            .with("original_size", bytes(info.original))?
            .with("skipped", bytes(info.skipped))?
            .with("skipped_at", bytes(info.skipped_at))?
            .with("offset", bytes(self.offset))?
            .with("length", bytes(self.length))?;
        match self.data {
            OutputData::Stream(id) => object.insert(
                "data",
                Value::Object(
                    Object::new()
                        .with("stream_id", id.get())?
                        .with("size", bytes(self.length))?
                        .with("content_type", OUTPUT_CONTENT_TYPE)?,
                ),
            )?,
            OutputData::Base64(data) => object.insert("data_base64", Value::from(knsh_json::base64_encode(data)))?,
        }
        Ok(Value::Object(object))
    }
}

#[cfg(test)]
mod tests {
    use knsh_core::{Actor, AgentId, CanonicalPath, RecordDetails, Redacted};

    use super::*;

    const RECORD: &str = "01JCZ0000000000000000000AB";
    const SESSION: &str = "01JCZ0000000000000000000CD";

    fn params<T: FromJson>(text: &str) -> Result<T, JsonError> {
        T::from_json(&knsh_json::parse(text.as_bytes(), 1 << 16).unwrap())
    }

    #[test]
    fn query_params_default_and_parse() {
        let empty: RecordsQueryParams = params("{}").unwrap();
        assert_eq!(empty.limit, DEFAULT_RECORDS_PAGE);
        assert_eq!((empty.session_id, empty.since, empty.cursor), (None, None, None));

        let full: RecordsQueryParams = params(&format!(
            r#"{{"session_id":"{SESSION}","since":"2026-11-12T18:02:11Z","until":"2026-11-12T18:02:12.5Z",
               "text":"git","limit":2,"cursor":"{RECORD}","future":1}}"#
        ))
        .unwrap();
        assert_eq!(full.session_id, Some(SESSION.parse().unwrap()));
        assert_eq!(
            full.since.map(|t| t.to_string()).as_deref(),
            Some("2026-11-12T18:02:11.000000Z")
        );
        assert_eq!(full.text.as_deref(), Some("git"));
        assert_eq!((full.limit, full.cursor), (2, Some(RECORD.parse().unwrap())));

        // What a client writes, the engine reads back unchanged (KNSH-023).
        assert_eq!(RecordsQueryParams::from_json(&full.to_json().unwrap()).unwrap(), full);
        assert_eq!(
            knsh_json::write(&empty.to_json().unwrap()).unwrap(),
            format!(r#"{{"limit":{DEFAULT_RECORDS_PAGE}}}"#)
        );
    }

    #[test]
    fn query_params_are_bounded_and_strict() {
        let long = "x".repeat(MAX_RECORDS_TEXT_LEN + 1);
        for (text, field) in [
            (r#"{"limit":0}"#.to_owned(), "limit"),
            (format!(r#"{{"limit":{}}}"#, MAX_RECORDS_PAGE + 1), "limit"),
            (format!(r#"{{"text":"{long}"}}"#), "text"),
            (r#"{"session_id":"not-a-ulid"}"#.to_owned(), "session_id"),
            (r#"{"cursor":"01jcz0000000000000000000ab"}"#.to_owned(), "cursor"),
            (r#"{"since":"2026-11-12 18:02:11"}"#.to_owned(), "since"),
            (r#"{"until":"yesterday"}"#.to_owned(), "until"),
        ] {
            let error = params::<RecordsQueryParams>(&text).unwrap_err();
            assert_eq!(error, JsonError::OutOfRange { field: Some(field) }, "{text}");
        }
        assert!(params::<RecordsQueryParams>(r#"{"limit":"5"}"#).is_err());
    }

    // ±2^53 rule: byte counts are strings, read only from canonical decimal strings.
    #[test]
    fn output_params_take_byte_counts_as_strings() {
        let parsed: RecordsOutputParams = params(&format!(
            r#"{{"record_id":"{RECORD}","stream":"stderr","offset":"18446744073709551615"}}"#
        ))
        .unwrap();
        assert_eq!(parsed.stream, OutputStream::Stderr);
        assert_eq!((parsed.offset, parsed.length), (u64::MAX, None));

        for bad in [
            format!(r#"{{"record_id":"{RECORD}","stream":"stdout","offset":5}}"#),
            format!(r#"{{"record_id":"{RECORD}","stream":"stdout","offset":"-1"}}"#),
            format!(r#"{{"record_id":"{RECORD}","stream":"stdout","length":"18446744073709551616"}}"#),
            format!(r#"{{"record_id":"{RECORD}","stream":"stdin"}}"#),
            r#"{"record_id":"x","stream":"stdout"}"#.to_owned(),
            r#"{"stream":"stdout"}"#.to_owned(),
        ] {
            assert!(params::<RecordsOutputParams>(&bad).is_err(), "{bad}");
        }
    }

    // FR-REC-10: forget needs a selector; both selectors and the flag round-trip; malformed values are refused.
    #[test]
    fn forget_params_require_a_selector() {
        assert_eq!(
            params::<RecordsForgetParams>("{}").unwrap_err(),
            JsonError::MissingField("session_id")
        );
        assert!(params::<RecordsForgetParams>(r#"{"with_checkpoints":true}"#).is_err());
        let full: RecordsForgetParams = params(&format!(
            r#"{{"session_id":"{SESSION}","since":"2026-11-12T00:00:00Z","with_checkpoints":true}}"#
        ))
        .unwrap();
        assert_eq!(full.session_id, Some(SESSION.parse().unwrap()));
        assert!(full.with_checkpoints);
        assert_eq!(
            json(&full),
            format!(r#"{{"session_id":"{SESSION}","since":"2026-11-12T00:00:00.000000Z","with_checkpoints":true}}"#)
        );
        let since_only: RecordsForgetParams = params(r#"{"since":"2026-11-12T00:00:00Z"}"#).unwrap();
        assert_eq!((since_only.session_id, since_only.with_checkpoints), (None, false));
        assert_eq!(json(&since_only), r#"{"since":"2026-11-12T00:00:00.000000Z"}"#);
        for bad in [
            r#"{"session_id":"nope"}"#,
            r#"{"since":"2026-11-12"}"#,
            r#"{"since":"2026-11-12T00:00:00Z","with_checkpoints":"yes"}"#,
        ] {
            assert!(params::<RecordsForgetParams>(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn forget_result_round_trips() {
        let result = RecordsForgetResult { deleted: 42 };
        assert_eq!(json(&result), r#"{"deleted":42}"#);
        assert_eq!(params::<RecordsForgetResult>(r#"{"deleted":42}"#).unwrap(), result);
        assert!(params::<RecordsForgetResult>(r#"{"deleted":-1}"#).is_err());
    }

    fn record(actor: Actor) -> ExecutionRecord {
        ExecutionRecord {
            record_id: RECORD.parse().unwrap(),
            session_id: SESSION.parse().unwrap(),
            actor,
            command: Redacted::new(String::from("npm test")),
            cwd: CanonicalPath::new("/p").unwrap(),
            started_at: "2026-11-12T18:02:11Z".parse().unwrap(),
            ended_at: None,
            exit_code: None,
            details: RecordDetails {
                pipestatus: vec![0, 1],
                ..RecordDetails::default()
            },
        }
    }

    fn json(value: &impl ToJson) -> String {
        knsh_json::write(&value.to_json().unwrap()).unwrap()
    }

    // KNSH-081: an agent record's `attribution` is null without one, and its wire value otherwise.
    #[test]
    fn record_json_attribution() {
        let entry = |record: &ExecutionRecord| {
            json(&RecordEntry {
                record,
                stdout: None,
                stderr: None,
            })
        };
        let mut agent = record(Actor::Agent(AgentId::new("codex").unwrap()));
        let text = entry(&agent);
        assert!(text.contains(r#""attribution":null"#), "{text}");
        agent.details.attribution = Some(knsh_core::Attribution::Concurrent);
        let text = entry(&agent);
        assert!(text.contains(r#""attribution":"concurrent""#), "{text}");
    }

    // KNSH-082: an agent record's `files_changed` is null without checkpoints, and lists each changed path otherwise.
    #[test]
    fn record_json_files_changed() {
        let entry = |record: &ExecutionRecord| {
            json(&RecordEntry {
                record,
                stdout: None,
                stderr: None,
            })
        };
        let mut agent = record(Actor::Agent(AgentId::new("codex").unwrap()));
        assert!(entry(&agent).contains(r#""files_changed":null"#));
        agent.details.files_changed = Some(vec![knsh_core::ChangedFile {
            path: CanonicalPath::new("/code/app/gone").unwrap(),
            change: knsh_core::FileChange::Deleted,
            post_image: None,
        }]);
        let text = entry(&agent);
        assert!(
            text.contains(r#""files_changed":[{"path":"/code/app/gone","change":"deleted","post_image":null}]"#),
            "{text}"
        );
    }

    // FR-REC-09: the human form carries only the telemetry fields; byte counts are strings.
    #[test]
    fn record_json_by_actor() {
        let info = OutputInfo {
            stored: 10,
            original: 1 << 60,
            skipped: (1 << 60) - 10,
            skipped_at: 5,
        };
        let human = record(Actor::Human);
        assert_eq!(
            json(&RecordEntry {
                record: &human,
                stdout: None,
                stderr: None
            }),
            format!(
                r#"{{"record_id":"{RECORD}","session_id":"{SESSION}","actor":{{"kind":"human"}},"command":"npm test","cwd":"/p","started_at":"2026-11-12T18:02:11.000000Z","ended_at":null,"exit_code":null,"stdout":null,"stderr":null}}"#
            )
        );
        let agent = record(Actor::Agent(AgentId::new("codex").unwrap()));
        let text = json(&RecordsQueryResult {
            records: vec![RecordEntry {
                record: &agent,
                stdout: Some(info),
                stderr: None,
            }],
            next_cursor: Some(RECORD.parse().unwrap()),
        });
        assert!(
            text.contains(r#""actor":{"kind":"agent","agent_id":"codex"}"#),
            "{text}"
        );
        assert!(text.contains(r#""pipestatus":[0,1]"#), "{text}");
        assert!(text.contains(r#""sandbox_violations":[]"#), "{text}");
        assert!(text.contains(r#""decision":null"#), "{text}");
        // KNSH-052: secret names only, and an empty list in phase 2 (FR-REC-11); `argv` is always an array.
        assert!(text.contains(r#""secrets_injected":[]"#), "{text}");
        assert!(text.contains(r#""argv":[]"#), "{text}");
        // KNSH-060: `network` is always an array.
        assert!(text.contains(r#""network":[]"#), "{text}");
        // KNSH-079: `unprotected` is always an array.
        assert!(text.contains(r#""unprotected":[]"#), "{text}");
        let mut classified = record(Actor::Agent(AgentId::new("codex").unwrap()));
        classified.details.argv = vec![
            knsh_core::ArgvEntry {
                name: Some(Redacted::new("env".to_owned())),
                path: Some("/usr/bin/env".to_owned()),
                class: knsh_core::ArgvClass::Wrapper,
                wrapper: None,
                arguments_complete: true,
            },
            knsh_core::ArgvEntry {
                name: Some(Redacted::new("sh".to_owned())),
                path: Some("/bin/sh".to_owned()),
                class: knsh_core::ArgvClass::Dynamic {
                    reason: "interpreter_code".to_owned(),
                },
                wrapper: Some(0),
                arguments_complete: true,
            },
        ];
        let text_argv = json(&RecordEntry {
            record: &classified,
            stdout: None,
            stderr: None,
        });
        assert!(
            text_argv.contains(
                r#""argv":[{"name":"env","path":"/usr/bin/env","class":"wrapper","reason":null,"wrapper":null,"arguments_complete":true},{"name":"sh","path":"/bin/sh","class":"dynamic","reason":"interpreter_code","wrapper":0,"arguments_complete":true}]"#
            ),
            "{text_argv}"
        );
        let mut decided = record(Actor::Agent(AgentId::new("codex").unwrap()));
        decided.details.decision = Some(knsh_core::RecordDecision {
            verdict: knsh_core::DecisionVerdict::Deny,
            source: knsh_core::DecisionSource::Hook,
            rule_id: None,
            decided_by: Some("guard".to_owned()),
            latency_ms: 3,
            hooks: Vec::new(),
        });
        let text_decided = json(&RecordEntry {
            record: &decided,
            stdout: None,
            stderr: None,
        });
        assert!(
            text_decided.contains(
                r#""decision":{"verdict":"deny","source":"hook","rule_id":null,"decided_by":"guard","latency_ms":3,"hooks":[]}"#
            ),
            "{text_decided}"
        );
        assert!(
            text.contains(r#""stdout":{"size":"10","original_size":"1152921504606846976","skipped":"1152921504606846966","skipped_at":"5"}"#),
            "{text}"
        );
        assert!(text.ends_with(&format!(r#""next_cursor":"{RECORD}"}}"#)), "{text}");
    }

    #[test]
    fn output_result_names_its_stream_or_inlines_base64() {
        let info = Some(OutputInfo {
            stored: 4,
            original: 4,
            skipped: 0,
            skipped_at: 4,
        });
        let base = RecordsOutputResult {
            record_id: RECORD.parse().unwrap(),
            stream: OutputStream::Stdout,
            info,
            offset: 1,
            length: 3,
            data: OutputData::Stream(StreamId::new(7).unwrap()),
        };
        assert_eq!(
            json(&base),
            format!(
                r#"{{"record_id":"{RECORD}","stream":"stdout","recorded":true,"size":"4","original_size":"4","skipped":"0","skipped_at":"4","offset":"1","length":"3","data":{{"stream_id":7,"size":"3","content_type":"application/octet-stream"}}}}"#
            )
        );
        let inline = RecordsOutputResult {
            info: None,
            data: OutputData::Base64(b"knsh"),
            ..base
        };
        let text = json(&inline);
        assert!(text.contains(r#""recorded":false,"size":"0""#), "{text}");
        assert!(text.ends_with(r#""data_base64":"a25zaA=="}"#), "{text}");
    }
}
