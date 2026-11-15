//! `records.query`, `records.output` (KNSH-016) and `records.forget` (KNSH-017),
//! `specs/06-api/user-socket.md#records`.
//!
//! The handlers are thin: parameters are read by `knsh-proto`, records come from the [`RecordStore`], and the
//! answer is written by `knsh-proto`. Records leave the engine only through the two read methods; the SQLite file is
//! never an API (FR-REC-08).
//!
//! # Forget
//!
//! `records.forget` exists on `user.sock` only: the catalogue keeps it off `agent.sock` (`-32003` there), and the
//! handler checks the endpoint again, so an agent can never erase records. Records matching the selectors are
//! deleted with their output in one transaction (FR-REC-10, NFR-PRIV-03). `with_checkpoints` is refused with
//! `-32005` naming `checkpoints` until checkpoints exist (phase 3), before anything is deleted: the user asked for
//! more than this build can do, so it does nothing rather than half of it.
//!
//! # Scope
//!
//! Each handler takes a [`Scope`], and the store applies it inside every query, so a handler cannot return records
//! outside it. [`scope_of`] decides the scope from the caller:
//!
//! - `user.sock`: [`Scope::All`], read-only access to every session.
//! - `agent.sock`: [`Scope::Session`] of the agent session the connection was bound to at `hello` (KNSH-048). A
//!   connection whose session has ended is refused with `-32009`.
//!
//! # Errors
//!
//! Malformed parameters are `-32602`. Asking for another session, or for a record outside a session scope, is
//! `-32003` (a session-scoped caller cannot tell another session's record from a missing one). A record that does
//! not exist is `-32602` on `user.sock`. A store that could not be opened, or fails, is `-32603`: the reason is in the
//! system log, never in the answer.

use std::sync::Arc;

use knsh_json::ToJson;
use knsh_proto::{
    Backend, ByteTransport, ErrorCode, MAX_BASE64_OUTPUT, OutputData, RecordEntry, RecordsForgetParams,
    RecordsForgetResult, RecordsOutputParams, RecordsOutputResult, RecordsQueryParams, RecordsQueryResult, RpcError,
};
use knsh_store::{ForgetSelector, OutputRequest, PageSize, RecordQuery, RecordStore, Scope, StoreError};

use crate::dispatch::{Answer, Call, Endpoint, Handler, Handlers, Reply, capability_unavailable};
use crate::lifetime::{CommitFailed, PendingWrites};

/// The most bytes the records of one `records.query` answer may take as JSON: one frame, less room for the
/// response envelope (`jsonrpc`, an `id` of at most 128 bytes even fully escaped, `next_cursor`).
const QUERY_RESULT_BUDGET: usize = knsh_json::MAX_PAYLOAD - 4096;

/// The record store as the handlers see it: absent when it could not be opened at start (for example a database
/// from a newer engine, which is reported and left untouched).
#[derive(Debug, Clone, Default)]
pub(crate) struct Records {
    store: Option<RecordStore>,
}

impl Records {
    /// Handlers over `store`.
    pub(crate) const fn new(store: Option<RecordStore>) -> Self {
        Self { store }
    }

    /// No store: every call answers `-32603`.
    #[cfg(test)]
    pub(crate) const fn unavailable() -> Self {
        Self { store: None }
    }

    fn store(&self) -> Result<&RecordStore, RpcError> {
        self.store.as_ref().ok_or_else(internal_error)
    }

    /// Every record handler, by method name.
    pub(crate) fn handlers(&self) -> Handlers {
        let query = self.clone();
        let output = self.clone();
        let forget = self.clone();
        let query: Handler = Arc::new(move |call: &Call<'_>| query.query(scope_of(call)?, call));
        let output: Handler = Arc::new(move |call: &Call<'_>| output.output(scope_of(call)?, call));
        let forget: Handler = Arc::new(move |call: &Call<'_>| forget.forget(call));
        [
            ("records.query", query),
            ("records.output", output),
            ("records.forget", forget),
        ]
        .into_iter()
        .collect()
    }

    /// `records.forget`: deletes the matching records and their output, and answers how many (FR-REC-10).
    pub(crate) fn forget(&self, call: &Call<'_>) -> Reply {
        // The dispatcher already keeps this method off agent.sock; checked again so that a routing mistake can never
        // let an agent erase records.
        match call.endpoint {
            Endpoint::User => {}
            Endpoint::Agent => return Err(RpcError::new(ErrorCode::NotAllowed)),
        }
        let params: RecordsForgetParams = call.request.params().map_err(|error| RpcError::from(&error))?;
        if params.with_checkpoints {
            // Honest capabilities: phase 1 has no checkpoints to delete. Refused before any record is touched.
            return Err(capability_unavailable(Backend::Checkpoints.name()));
        }
        // The protocol already requires a selector; a mismatch is still refused rather than widened to every record.
        let selector = ForgetSelector::new(params.session_id, params.since)
            .ok_or_else(|| RpcError::new(ErrorCode::InvalidParams))?;
        let deleted = self
            .store()?
            .forget(selector)
            .map_err(|error| store_error(Scope::All, &error))?;
        let result = RecordsForgetResult { deleted }
            .to_json()
            .map_err(|_| internal_error())?;
        Ok(Answer::from(result))
    }

    /// `records.query` within `scope`.
    pub(crate) fn query(&self, scope: Scope, call: &Call<'_>) -> Reply {
        let params: RecordsQueryParams = call.request.params().map_err(|error| RpcError::from(&error))?;
        let query = RecordQuery {
            session: params.session_id,
            since: params.since,
            until: params.until,
            text: params.text,
            after: params.cursor,
            // The protocol and the store bound the page size the same way; a mismatch is still refused.
            limit: PageSize::new(params.limit).ok_or_else(|| RpcError::new(ErrorCode::InvalidParams))?,
        };
        let page = self
            .store()?
            .query(scope, query)
            .map_err(|error| store_error(scope, &error))?;
        // The answer must fit in one JSON frame. Records are unbounded in size, so the page is cut where the next
        // record would overflow the budget, and the cursor points at the last record sent: the client reads the
        // rest on the next page instead of getting `-32603` for a page that can never be written.
        let mut records = Vec::with_capacity(page.records.len());
        let mut used = 0usize;
        let mut cut = false;
        for stored in &page.records {
            let entry = RecordEntry {
                record: &stored.record,
                stdout: stored.stdout,
                stderr: stored.stderr,
            };
            let size = knsh_json::write(&entry.to_json().map_err(|_| internal_error())?)
                .map_err(|_| internal_error())?
                .len()
                // The separating comma.
                + 1;
            if used + size > QUERY_RESULT_BUDGET {
                cut = true;
                break;
            }
            used += size;
            records.push(entry);
        }
        if records.is_empty() && cut {
            // A single record larger than a frame cannot be sent as JSON at all.
            return Err(internal_error());
        }
        let next_cursor = if cut {
            records.last().map(|entry| entry.record.record_id)
        } else {
            page.next_cursor
        };
        let result = RecordsQueryResult { records, next_cursor };
        Ok(Answer::from(result.to_json().map_err(|_| internal_error())?))
    }

    /// `records.output` within `scope`. The bytes go in a binary stream, or inline as base64 for a client that
    /// opted out of binary frames, in which case at most [`MAX_BASE64_OUTPUT`] bytes are returned per call.
    pub(crate) fn output(&self, scope: Scope, call: &Call<'_>) -> Reply {
        let params: RecordsOutputParams = call.request.params().map_err(|error| RpcError::from(&error))?;
        let length = match call.bytes {
            ByteTransport::BinaryFrames => params.length,
            // Base64 grows the bytes by a third and must fit in one JSON frame with the rest of the answer.
            ByteTransport::Base64 => Some(
                params
                    .length
                    .map_or(MAX_BASE64_OUTPUT, |length| length.min(MAX_BASE64_OUTPUT)),
            ),
        };
        let request = OutputRequest {
            record_id: params.record_id,
            stream: params.stream,
            offset: params.offset,
            length,
        };
        let range = self
            .store()?
            .output(scope, request)
            .map_err(|error| store_error(scope, &error))?;
        let length = u64::try_from(range.data.len()).map_err(|_| internal_error())?;
        let data = match call.bytes {
            ByteTransport::BinaryFrames => OutputData::Stream(call.stream),
            ByteTransport::Base64 => OutputData::Base64(&range.data),
        };
        let result = RecordsOutputResult {
            record_id: params.record_id,
            stream: params.stream,
            info: range.info,
            offset: range.offset,
            length,
            data,
        }
        .to_json()
        .map_err(|_| internal_error())?;
        // Inlined bytes are already in the result; only a binary stream sends them after it.
        let bytes = match call.bytes {
            ByteTransport::BinaryFrames => Some(range.data),
            ByteTransport::Base64 => None,
        };
        Ok(Answer { result, bytes })
    }
}

/// The scope a caller may read: every session on `user.sock`, only its own on `agent.sock` (KNSH-048).
fn scope_of(call: &Call<'_>) -> Result<Scope, RpcError> {
    match call.endpoint {
        Endpoint::User => Ok(Scope::All),
        Endpoint::Agent => call.binding.agent_session().map(Scope::Session),
    }
}

/// `-32603`, with no detail: the reason belongs in the system log, never in the answer.
fn internal_error() -> RpcError {
    RpcError::new(ErrorCode::InternalError)
}

/// The API error for a store failure in `scope`.
fn store_error(scope: Scope, error: &StoreError) -> RpcError {
    let code = match (error, scope) {
        (StoreError::OutOfScope, _) | (StoreError::RecordNotFound, Scope::Session(_)) => ErrorCode::NotAllowed,
        (StoreError::RecordNotFound, Scope::All) => ErrorCode::InvalidParams,
        (
            StoreError::Platform(_)
            | StoreError::NewerSchema { .. }
            | StoreError::ForeignDatabase
            | StoreError::UnsafeFile
            | StoreError::Corrupt
            | StoreError::InvalidRecord(_)
            | StoreError::Closed
            | StoreError::ThreadStart,
            _,
        ) => ErrorCode::InternalError,
    };
    RpcError::new(code)
}

impl PendingWrites for Records {
    /// Every write is committed before it is answered, so this only waits for jobs already queued to finish.
    fn commit(&self) -> Result<(), CommitFailed> {
        match &self.store {
            Some(store) => store.sync().map_err(|_| CommitFailed("record store")),
            None => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use knsh_core::{
        Actor, AgentId, CanonicalPath, ExecutionRecord, RecordDetails, RecordId, Redacted, SessionId, Timestamp, Ulid,
    };
    use knsh_json::{Frame, FrameReader, StreamId, Value};
    use knsh_platform::macos::{RealFs, effective_uid};
    use knsh_platform::testing::FakeClock;
    use knsh_proto::{Message, MethodName, Request, RequestId, decode};
    use knsh_store::{RecordedOutput, StoreConfig};

    use super::*;
    use crate::connection::serve;
    use crate::dispatch::tests::{ok_handler, stream};
    use crate::dispatch::{Dispatcher, HELLO, Table};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    /// A private temporary directory, removed on drop.
    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            let n = COUNTER.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!("knshd-records-{}-{n}", std::process::id()));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// A store in `dir`, on a fake clock at the epoch so the pass at open deletes nothing.
    fn open_store(dir: &TempDir) -> RecordStore {
        RecordStore::open(
            &RealFs::new(),
            &dir.0.join("records.db"),
            effective_uid(),
            Arc::new(FakeClock::new(Timestamp::UNIX_EPOCH)),
            StoreConfig::default(),
        )
        .unwrap()
    }

    fn session(n: u128) -> SessionId {
        SessionId::from_ulid(Ulid::from_u128(n))
    }

    fn record_id(n: u128) -> RecordId {
        RecordId::from_ulid(Ulid::from_u128(n))
    }

    /// A store holding records 1 and 3 of session 1 and record 2 of session 2, each with stdout `out-<n>`.
    fn records(dir: &TempDir) -> Records {
        let store = open_store(dir);
        for (n, owner) in [(1, session(1)), (2, session(2)), (3, session(1))] {
            let record = ExecutionRecord {
                record_id: record_id(n),
                session_id: owner,
                actor: Actor::Agent(AgentId::new("codex").unwrap()),
                command: Redacted::new(format!("make target-{n}")),
                cwd: CanonicalPath::new("/w").unwrap(),
                started_at: Timestamp::from_unix_micros(u64::try_from(n).unwrap() * 1_000_000).unwrap(),
                ended_at: None,
                exit_code: Some(0),
                details: RecordDetails::default(),
            };
            let output = RecordedOutput {
                stdout: Some(Redacted::new(format!("out-{n}").into_bytes())),
                stderr: None,
            };
            store.write_record(record, output).unwrap();
        }
        Records::new(Some(store))
    }

    fn rpc(method: &str, params: &str) -> Request {
        Request {
            id: RequestId::from(2u32),
            method: MethodName::new(method).unwrap(),
            params: knsh_json::parse(params.as_bytes(), 1 << 16)
                .unwrap()
                .as_object()
                .cloned(),
        }
    }

    fn call(request: &Request, bytes: ByteTransport) -> Call<'_> {
        Call {
            endpoint: Endpoint::User,
            bytes,
            stream: stream(),
            request,
            subscriber: crate::dispatch::tests::subscriber(),
            binding: crate::dispatch::tests::binding(),
            descriptors: crate::dispatch::tests::no_descriptors(),
            caller: &knsh_core::StillWaiting,
        }
    }

    fn record_ids(answer: &Answer) -> Vec<String> {
        let records = answer
            .result
            .as_object()
            .unwrap()
            .get("records")
            .unwrap()
            .as_array()
            .unwrap();
        records
            .iter()
            .map(|r| {
                r.as_object()
                    .unwrap()
                    .get("record_id")
                    .unwrap()
                    .as_str()
                    .unwrap()
                    .to_owned()
            })
            .collect()
    }

    fn field<'a>(answer: &'a Answer, name: &str) -> &'a Value {
        answer.result.as_object().unwrap().get(name).unwrap()
    }

    #[test]
    fn query_reads_records_through_the_api() {
        let dir = TempDir::new();
        let records = records(&dir);
        let request = rpc(
            "records.query",
            &format!(r#"{{"session_id":"{}","limit":1}}"#, session(1)),
        );
        let answer = records
            .query(Scope::All, &call(&request, ByteTransport::BinaryFrames))
            .unwrap();
        assert_eq!(record_ids(&answer), [record_id(1).to_string()]);
        assert_eq!(
            field(&answer, "next_cursor").as_str(),
            Some(record_id(1).to_string().as_str())
        );
        assert_eq!(answer.bytes, None);

        let bad = rpc("records.query", r#"{"limit":0}"#);
        let error = records
            .query(Scope::All, &call(&bad, ByteTransport::BinaryFrames))
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::InvalidParams);
    }

    // Scoping for `agent.sock`: the same handler with a session scope returns only that session, refuses another
    // session, and cannot read another session's output.
    #[test]
    fn scoped_query_never_returns_other_sessions() {
        let dir = TempDir::new();
        let records = records(&dir);
        let scope = Scope::Session(session(1));
        let all = rpc("records.query", "{}");
        let answer = records.query(scope, &call(&all, ByteTransport::BinaryFrames)).unwrap();
        assert_eq!(
            record_ids(&answer),
            [record_id(1).to_string(), record_id(3).to_string()]
        );

        let other = rpc("records.query", &format!(r#"{{"session_id":"{}"}}"#, session(2)));
        let error = records
            .query(scope, &call(&other, ByteTransport::BinaryFrames))
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::NotAllowed);

        let foreign = rpc(
            "records.output",
            &format!(r#"{{"record_id":"{}","stream":"stdout"}}"#, record_id(2)),
        );
        let error = records
            .output(scope, &call(&foreign, ByteTransport::BinaryFrames))
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::NotAllowed);
        // On user.sock a missing record is a bad parameter.
        let missing = rpc(
            "records.output",
            &format!(r#"{{"record_id":"{}","stream":"stdout"}}"#, record_id(9)),
        );
        let error = records
            .output(Scope::All, &call(&missing, ByteTransport::BinaryFrames))
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::InvalidParams);
    }

    // Phase 1 binds no session to agent.sock connections: the record methods refuse there (fail closed).
    #[test]
    fn agent_endpoint_is_refused_until_sessions_are_bound() {
        let dir = TempDir::new();
        let handlers = records(&dir).handlers();
        let request = rpc("records.query", "{}");
        for name in ["records.query", "records.output"] {
            let error = handlers[name](&Call {
                endpoint: Endpoint::Agent,
                ..call(&request, ByteTransport::BinaryFrames)
            })
            .unwrap_err();
            assert_eq!(error.code, ErrorCode::NotAllowed, "{name}");
        }
        let answer = handlers["records.query"](&call(&request, ByteTransport::BinaryFrames)).unwrap();
        assert_eq!(record_ids(&answer).len(), 3);
    }

    // A page whose records would not fit in one frame is cut short with a cursor, never answered with -32603.
    #[test]
    fn query_page_is_cut_to_fit_one_frame() {
        let dir = TempDir::new();
        let store = open_store(&dir);
        let long = "x".repeat(16 * 1024);
        let total = 100u128;
        for n in 1..=total {
            let record = ExecutionRecord {
                record_id: record_id(n),
                session_id: session(1),
                actor: Actor::Human,
                command: Redacted::new(format!("echo {long}")),
                cwd: CanonicalPath::new("/w").unwrap(),
                started_at: Timestamp::from_unix_micros(u64::try_from(n).unwrap()).unwrap(),
                ended_at: None,
                exit_code: Some(0),
                details: RecordDetails::default(),
            };
            store.write_record(record, RecordedOutput::default()).unwrap();
        }
        let records = Records::new(Some(store));
        let mut seen = Vec::new();
        let mut cursor: Option<String> = None;
        loop {
            let params = match &cursor {
                Some(cursor) => format!(r#"{{"limit":1000,"cursor":"{cursor}"}}"#),
                None => r#"{"limit":1000}"#.to_owned(),
            };
            let request = rpc("records.query", &params);
            let answer = records
                .query(Scope::All, &call(&request, ByteTransport::BinaryFrames))
                .unwrap();
            assert!(knsh_json::write(&answer.result).unwrap().len() <= QUERY_RESULT_BUDGET + 128);
            let page = record_ids(&answer);
            assert_ne!(page.len(), 0);
            seen.extend(page);
            match field(&answer, "next_cursor").as_str() {
                Some(next) => cursor = Some(next.to_owned()),
                None => break,
            }
        }
        let expected: Vec<String> = (1..=total).map(|n| record_id(n).to_string()).collect();
        assert_eq!(seen, expected, "every record exactly once, in order");
    }

    #[test]
    fn missing_store_is_an_internal_error() {
        let request = rpc("records.query", "{}");
        let error = Records::unavailable()
            .query(Scope::All, &call(&request, ByteTransport::BinaryFrames))
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::InternalError);
        assert_eq!(Records::unavailable().commit(), Ok(()));
    }

    /// Frames each JSON text as one frame.
    fn frames(texts: &[&str]) -> Vec<u8> {
        let mut wire = knsh_json::FrameWriter::new(Vec::new());
        for text in texts {
            wire.write_json(&knsh_json::parse(text.as_bytes(), 1 << 16).unwrap())
                .unwrap();
        }
        wire.into_inner()
    }

    // Wire format: over a real connection, `records.output` answers with the JSON result naming a stream, then the
    // bytes in binary chunks on it, then an end-of-stream frame. Byte counts are strings; the range is clamped.
    #[test]
    fn output_range_returns_binary_stream() {
        let dir = TempDir::new();
        let records = records(&dir);
        let mut user = Table::new().with(HELLO, ok_handler());
        for (name, handler) in records.handlers() {
            user = user.with(name, handler);
        }
        let dispatcher = Dispatcher::from_tables(user, Table::new());
        let input = frames(&[
            r#"{"jsonrpc":"2.0","id":1,"method":"hello"}"#,
            &format!(
                r#"{{"jsonrpc":"2.0","id":2,"method":"records.output","params":{{"record_id":"{}","stream":"stdout","offset":"2","length":"100"}}}}"#,
                record_id(3)
            ),
            &format!(
                r#"{{"jsonrpc":"2.0","id":3,"method":"records.output","params":{{"record_id":"{}","stream":"stdout"}}}}"#,
                record_id(1)
            ),
        ]);
        let mut output = Vec::new();
        serve(
            Cursor::new(input),
            &mut output,
            Endpoint::User,
            None,
            &dispatcher,
            &mut || {},
            &|| {},
        );

        let mut reader = FrameReader::new(output.as_slice());
        let Some(Frame::Json(_hello)) = reader.read_frame().unwrap() else {
            panic!("no hello answer")
        };
        let mut streams = Vec::new();
        for _ in 0..2 {
            let Some(Frame::Json(payload)) = reader.read_frame().unwrap() else {
                panic!("no output answer")
            };
            let Message::Success(success) = decode(&payload).unwrap() else {
                panic!("not a success")
            };
            let result = success.result.as_object().unwrap().clone();
            let data = result.get("data").and_then(Value::as_object).unwrap();
            let id = StreamId::new(u32::try_from(data.get("stream_id").unwrap().as_i64().unwrap()).unwrap()).unwrap();
            let size: u64 = data.get("size").unwrap().as_str().unwrap().parse().unwrap();
            assert_eq!(
                data.get("content_type").and_then(Value::as_str),
                Some("application/octet-stream")
            );
            // The reader enforces that exactly `size` bytes arrive before the end frame.
            reader.open_stream(id, Some(size)).unwrap();
            let mut bytes = Vec::new();
            loop {
                match reader.read_frame().unwrap() {
                    Some(Frame::Chunk { stream, data }) if stream == id => bytes.extend_from_slice(&data),
                    Some(Frame::End { stream }) if stream == id => break,
                    other => panic!("unexpected frame {other:?}"),
                }
            }
            streams.push((id, result, bytes));
        }
        assert_eq!(reader.read_frame().unwrap(), None);

        let (first_id, first, first_bytes) = &streams[0];
        assert_eq!(first_bytes, b"t-3", "offset 2, clamped to the end");
        assert_eq!(
            first.get("size").and_then(Value::as_str),
            Some("5"),
            "total stored size, as a string"
        );
        assert_eq!(first.get("offset").and_then(Value::as_str), Some("2"));
        assert_eq!(first.get("length").and_then(Value::as_str), Some("3"));
        assert_eq!(first.get("recorded").and_then(Value::as_bool), Some(true));
        let (second_id, _, second_bytes) = &streams[1];
        assert_eq!(second_bytes, b"out-1");
        assert_ne!(first_id, second_id, "each answer gets its own stream id");
    }

    // A client that opted out of binary frames gets the bytes as base64 in the result, and no stream.
    #[test]
    fn output_is_base64_when_client_opted_out() {
        let dir = TempDir::new();
        let records = records(&dir);
        let request = rpc(
            "records.output",
            &format!(r#"{{"record_id":"{}","stream":"stdout"}}"#, record_id(1)),
        );
        let answer = records
            .output(Scope::All, &call(&request, ByteTransport::Base64))
            .unwrap();
        assert_eq!(answer.bytes, None);
        assert_eq!(field(&answer, "data_base64").as_str(), Some("b3V0LTE="));
        assert!(!answer.result.as_object().unwrap().contains_key("data"));

        // Stderr was not recorded: an empty, unrecorded range.
        let request = rpc(
            "records.output",
            &format!(r#"{{"record_id":"{}","stream":"stderr"}}"#, record_id(1)),
        );
        let answer = records
            .output(Scope::All, &call(&request, ByteTransport::BinaryFrames))
            .unwrap();
        assert_eq!(field(&answer, "recorded").as_bool(), Some(false));
        assert_eq!(answer.bytes.as_deref(), Some(&b""[..]));
    }

    fn deleted(answer: &Answer) -> i64 {
        field(answer, "deleted").as_i64().unwrap()
    }

    // FR-REC-10: forget on user.sock deletes the matching records and reports the count.
    #[test]
    fn forget_deletes_matching_records_and_reports_the_count() {
        let dir = TempDir::new();
        let records = records(&dir);
        let request = rpc("records.forget", &format!(r#"{{"session_id":"{}"}}"#, session(1)));
        let answer = records.forget(&call(&request, ByteTransport::BinaryFrames)).unwrap();
        assert_eq!(deleted(&answer), 2);

        let query = rpc("records.query", "{}");
        let left = records
            .query(Scope::All, &call(&query, ByteTransport::BinaryFrames))
            .unwrap();
        assert_eq!(record_ids(&left), [record_id(2).to_string()]);

        // `since` alone: record 2 started at second 2.
        let request = rpc("records.forget", r#"{"since":"1970-01-01T00:00:02Z"}"#);
        let answer = records.forget(&call(&request, ByteTransport::BinaryFrames)).unwrap();
        assert_eq!(deleted(&answer), 1);

        // No selector: refused, nothing deleted.
        let request = rpc("records.forget", "{}");
        let error = records
            .forget(&call(&request, ByteTransport::BinaryFrames))
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::InvalidParams);
    }

    // Honest capabilities: phase 1 has no checkpoints, so --with-checkpoints is -32005 naming them, and nothing is
    // deleted.
    #[test]
    fn with_checkpoints_reports_capability_unavailable() {
        let dir = TempDir::new();
        let records = records(&dir);
        let request = rpc(
            "records.forget",
            &format!(r#"{{"session_id":"{}","with_checkpoints":true}}"#, session(1)),
        );
        let error = records
            .forget(&call(&request, ByteTransport::BinaryFrames))
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::CapabilityUnavailable);
        let data = error.data.unwrap();
        assert_eq!(
            data.as_object().unwrap().get("capability").and_then(Value::as_str),
            Some("checkpoints")
        );
        let query = rpc("records.query", "{}");
        let left = records
            .query(Scope::All, &call(&query, ByteTransport::BinaryFrames))
            .unwrap();
        assert_eq!(record_ids(&left).len(), 3, "nothing deleted");
    }

    // records.forget is not available on agent.sock: the real phase 1 dispatcher refuses it there with -32003, and
    // the handler refuses it too if ever reached.
    #[test]
    fn forget_is_not_available_on_agent_sock() {
        let dir = TempDir::new();
        let records = records(&dir);
        let request = rpc("records.forget", &format!(r#"{{"session_id":"{}"}}"#, session(1)));
        let agent_call = Call {
            endpoint: Endpoint::Agent,
            ..call(&request, ByteTransport::BinaryFrames)
        };
        let error = records.forget(&agent_call).unwrap_err();
        assert_eq!(error.code, ErrorCode::NotAllowed);

        let probed = crate::probe::probe(&crate::probe::tests::Machine::working().probes());
        let mut handlers = crate::hello::tests::handlers();
        handlers.extend(records.handlers());
        let dispatcher = crate::hello::phase1_dispatcher(probed, handlers).unwrap();
        let error = dispatcher.call(&agent_call).unwrap_err();
        assert_eq!(error.code, ErrorCode::NotAllowed);
        let query = rpc("records.query", "{}");
        let left = records
            .query(Scope::All, &call(&query, ByteTransport::BinaryFrames))
            .unwrap();
        assert_eq!(record_ids(&left).len(), 3, "nothing deleted");
    }
}
