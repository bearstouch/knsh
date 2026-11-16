//! `agent.sock` end to end (KNSH-048): frames in and out of the real connection loop, with the dispatcher, `hello`
//! and the record, event, session and policy handlers `knshd` serves, over a real record store and a fake process
//! table.

use std::io::{Cursor, Read};
use std::sync::Arc;

use knsh_core::{
    Actor, AgentId, CanonicalPath, ExecutionRecord, ProfileName, RecordDetails, RecordId, Redacted, SessionId,
    Timestamp, Ulid,
};
use knsh_json::{Frame, FrameReader, FrameWriter, Object, Value};
use knsh_platform::{AuditToken, ProcessIdentity};
use knsh_proto::{ErrorCode, Message, RequestId, decode};
use knsh_store::RecordedOutput;

use crate::connection::{Closed, serve};
use crate::dispatch::{Dispatcher, Endpoint};
use crate::sessions::OpenedAgent;
use crate::sessions::tests::{Fixture, fixture};
use crate::violations::ReaderStatus;

/// launchd (1) → terminal (100) → envelope root (200) → agent CLI (201) → tool (202); an outsider (300).
const LAUNCHD: ProcessIdentity = ProcessIdentity::new(1, 1);
const TERMINAL: ProcessIdentity = ProcessIdentity::new(100, 1);
const ROOT: ProcessIdentity = ProcessIdentity::new(200, 1);
const AGENT: ProcessIdentity = ProcessIdentity::new(201, 1);
const TOOL: ProcessIdentity = ProcessIdentity::new(202, 1);
const OUTSIDER: ProcessIdentity = ProcessIdentity::new(300, 1);

/// The dispatcher `knshd` serves, over `fixture`'s sessions and store: `hello` and the record, event, session and
/// policy handlers (`policy.edit` with a prompt nobody answers), `approval.*` with nothing pending, and `exec.run` without a supervisor. Shared with the socket-level tests in `platform_tests`.
pub(crate) fn dispatcher(fixture: &Fixture) -> Dispatcher {
    let mut handlers = crate::records::Records::new(Some(fixture.store.clone())).handlers();
    handlers.extend(fixture.hub.handlers());
    handlers.extend(fixture.sessions.handlers());
    handlers.extend(
        crate::policy::tests::service(Arc::clone(&fixture.sessions), knsh_platform::testing::MemFs::new()).handlers(),
    );
    handlers.extend(crate::policy_edit::tests::idle_handlers());
    handlers.extend(crate::approvals::tests::idle_handlers());
    handlers.extend(crate::authority::tests::idle_handlers());
    handlers.extend(crate::exec::unserved_handlers());
    handlers.extend(crate::start_agent::unserved_handlers());
    crate::hello::dispatcher_with_violations(
        crate::probe::probe(&crate::probe::tests::Machine::working().probes()),
        handlers,
        ReaderStatus::stopped(),
        Arc::clone(&fixture.sessions),
    )
    .unwrap()
}

/// Opens an agent session on `fixture`; with `envelope`, registers that root process for it.
pub(super) fn open_agent(fixture: &Fixture, envelope: Option<ProcessIdentity>) -> OpenedAgent {
    let opened = fixture
        .sessions
        .open_agent(
            Actor::Agent(AgentId::new("claude-code").unwrap()),
            ProfileName::new("default").unwrap(),
        )
        .unwrap();
    if let Some(root) = envelope {
        fixture.sessions.register_envelope(opened.session_id, root).unwrap();
    }
    opened
}

/// A live `knshd` in miniature: sessions over a real store, and the dispatcher it serves.
struct Daemon {
    fixture: Fixture,
    dispatcher: Dispatcher,
}

fn daemon() -> Daemon {
    let fixture = fixture();
    let tree = &fixture.processes;
    tree.spawn(LAUNCHD, None);
    tree.spawn(TERMINAL, Some(LAUNCHD));
    tree.spawn(ROOT, Some(TERMINAL));
    tree.spawn(AGENT, Some(ROOT));
    tree.spawn(TOOL, Some(AGENT));
    tree.spawn(OUTSIDER, Some(TERMINAL));
    let dispatcher = dispatcher(&fixture);
    Daemon { fixture, dispatcher }
}

impl Daemon {
    /// Opens an agent session; with `envelope`, registers that root process for it.
    fn open(&self, envelope: Option<ProcessIdentity>) -> OpenedAgent {
        open_agent(&self.fixture, envelope)
    }

    /// Writes record `n` of `session` with stdout `out-<n>`.
    fn record(&self, session: SessionId, n: u128) -> RecordId {
        let record_id = RecordId::from_ulid(Ulid::from_u128(n));
        let record = ExecutionRecord {
            record_id,
            session_id: session,
            actor: Actor::Agent(AgentId::new("claude-code").unwrap()),
            command: Redacted::new(format!("make target-{n}")),
            cwd: CanonicalPath::new("/w").unwrap(),
            started_at: Timestamp::from_unix_micros(u64::try_from(n).unwrap() * 1_000_000).unwrap(),
            ended_at: None,
            exit_code: Some(0),
            details: RecordDetails::default(),
        };
        let output = RecordedOutput {
            stdout: Some(knsh_core::CappedOutput::whole(Redacted::new(
                format!("out-{n}").into_bytes(),
            ))),
            stderr: None,
        };
        self.fixture.store.write_record(record, output).unwrap();
        record_id
    }

    /// Runs one `agent.sock` connection from `peer` over `requests` (each a method and its params, numbered from
    /// 1). Returns why it closed and the answers by request number.
    fn connect(&self, peer: Option<ProcessIdentity>, requests: &[(&str, String)]) -> (Closed, Answers) {
        self.serve(Cursor::new(request_frames(requests)), peer)
    }

    /// Runs one `agent.sock` connection from `peer` reading its frames from `input`.
    fn serve(&self, input: impl Read, peer: Option<ProcessIdentity>) -> (Closed, Answers) {
        let mut output = Vec::new();
        let closed = serve(
            input,
            &mut output,
            Endpoint::Agent,
            peer.map(|process| AuditToken::for_process(process, 501)),
            &self.dispatcher,
            &mut || {},
            &|| {},
        );
        (closed, read_answers(&output))
    }
}

/// `requests` (each a method and its params) as request frames numbered from 1.
fn request_frames(requests: &[(&str, String)]) -> Vec<u8> {
    let mut input = FrameWriter::new(Vec::new());
    for (n, (method, params)) in requests.iter().enumerate() {
        let text = format!(
            r#"{{"jsonrpc":"2.0","id":{},"method":"{method}","params":{params}}}"#,
            n + 1
        );
        input
            .write_json(&knsh_json::parse(text.as_bytes(), 1 << 16).unwrap())
            .unwrap();
    }
    input.into_inner()
}

/// Every answer the server wrote to `output`, by request number.
fn read_answers(output: &[u8]) -> Answers {
    let mut answers = Vec::new();
    let mut reader = FrameReader::new(output);
    while let Some(frame) = reader.read_frame().unwrap() {
        let Frame::Json(payload) = frame else { continue };
        match decode(&payload).unwrap() {
            Message::Success(success) => answers.push((success.id, Ok(success.result))),
            Message::Error(error) => answers.push((error.id.unwrap(), Err(error.error.code))),
            Message::Request(_) | Message::Notification(_) => {}
        }
    }
    Answers(answers)
}

/// Answers by request number.
struct Answers(Vec<(RequestId, Result<Value, ErrorCode>)>);

impl Answers {
    fn get(&self, n: u32) -> Option<&Result<Value, ErrorCode>> {
        self.0
            .iter()
            .find(|(id, _)| *id == RequestId::from(n))
            .map(|(_, answer)| answer)
    }

    fn ok(&self, n: u32) -> &Object {
        match self.get(n) {
            Some(Ok(value)) => value.as_object().unwrap(),
            other => panic!("request {n}: {other:?}"),
        }
    }

    fn code(&self, n: u32) -> ErrorCode {
        match self.get(n) {
            Some(Err(code)) => *code,
            other => panic!("request {n}: {other:?}"),
        }
    }

    fn len(&self) -> usize {
        self.0.len()
    }
}

/// A `hello` from the test client carrying `session_token`, if any: a live token, a forged one or not a token at all.
fn hello_with_token(session_token: Option<&str>) -> (&'static str, String) {
    let field = session_token.map_or_else(String::new, |token| format!(r#","session_token":"{token}""#));
    (
        "hello",
        format!(r#"{{"client":"test","client_version":"1","protocols":[1],"binary_frames":false{field}}}"#),
    )
}

/// A `hello` carrying `opened`'s token, or no token at all.
fn hello(opened: Option<&OpenedAgent>) -> (&'static str, String) {
    let encoded = opened.map(|opened| opened.token.encode());
    hello_with_token(encoded.as_ref().map(|token| token.expose().as_str()))
}

fn info() -> (&'static str, String) {
    ("session.info", "{}".to_owned())
}

fn text<'a>(object: &'a Object, name: &str) -> &'a str {
    object.get(name).and_then(Value::as_str).unwrap()
}

fn record_ids(object: &Object) -> Vec<String> {
    object
        .get("records")
        .and_then(Value::as_array)
        .unwrap()
        .iter()
        .map(|entry| {
            let entry = entry.as_object().unwrap();
            let record = entry.get("record").and_then(Value::as_object).unwrap_or(entry);
            text(record, "record_id").to_owned()
        })
        .collect()
}

// FR-AGT-23: a valid token binds the connection to its session; `hello` reports it and `session.info` is that
// session's, even from a process outside every envelope (the token decides).
#[test]
fn binds_connection_to_session_for_valid_token() {
    let daemon = daemon();
    let opened = daemon.open(None);
    daemon.open(None);
    let (closed, answers) = daemon.connect(Some(OUTSIDER), &[hello(Some(&opened)), info()]);
    assert_eq!(closed, Closed::Peer);
    let session = opened.session_id.to_string();
    assert_eq!(text(answers.ok(1), "session_id"), session);
    assert_eq!(text(answers.ok(2), "session_id"), session);
    assert_eq!(answers.ok(2).get("envelope"), Some(&Value::from(true)));
}

// FR-AGT-23: without a token, or with an invalid one, a descendant of a registered envelope (or its root) is bound
// to that envelope's session by audit token.
#[test]
fn falls_back_to_audit_token_when_token_missing() {
    let daemon = daemon();
    let opened = daemon.open(Some(ROOT));
    let session = opened.session_id.to_string();
    let forged = "ab".repeat(crate::agents::TOKEN_BYTES);
    for (peer, hello) in [
        (TOOL, hello(None)),
        (AGENT, hello_with_token(Some(&forged))),
        (ROOT, hello_with_token(Some("not-a-token"))),
    ] {
        let (closed, answers) = daemon.connect(Some(peer), &[hello, info()]);
        assert_eq!(closed, Closed::Peer, "{peer}");
        assert_eq!(text(answers.ok(1), "session_id"), session, "{peer}");
        assert_eq!(text(answers.ok(2), "session_id"), session, "{peer}");
    }
}

// FR-AGT-23: a caller matching neither a token nor an envelope is refused with -32009 and the connection is closed:
// nothing after the hello is read or answered.
#[test]
fn refuses_caller_matching_no_envelope_with_32009() {
    let daemon = daemon();
    let opened = daemon.open(Some(ROOT));
    let forged = "00".repeat(crate::agents::TOKEN_BYTES);
    for (peer, hello) in [
        (Some(OUTSIDER), hello(None)),
        (Some(OUTSIDER), hello_with_token(Some(&forged))),
        // A process whose pid the envelope root used to have, at another version.
        (Some(ProcessIdentity::new(ROOT.pid(), 2)), hello(None)),
        // The kernel could not report the peer: only a token could have bound it.
        (None, hello(None)),
    ] {
        let (closed, answers) = daemon.connect(peer, &[hello, info()]);
        assert_eq!(closed, Closed::Handshake, "{peer:?}");
        assert_eq!(answers.code(1), ErrorCode::InvalidSessionToken, "{peer:?}");
        assert_eq!(answers.len(), 1, "{peer:?}: nothing is answered after the refusal");
    }
    // The token alone still works for a peer the kernel could not report.
    let (_, answers) = daemon.connect(None, &[hello(Some(&opened))]);
    assert_eq!(text(answers.ok(1), "session_id"), opened.session_id.to_string());
}

// Endpoint scoping: every call is evaluated against the bound session only. Another session's records, output and
// events are -32003; the caller's own are served, and an unfiltered query sees only them.
#[test]
fn rejects_cross_session_record_access_with_32003() {
    let daemon = daemon();
    let own = daemon.open(Some(ROOT));
    let other = daemon.open(None);
    let own_record = daemon.record(own.session_id, 1);
    let other_record = daemon.record(other.session_id, 2);
    let (closed, answers) = daemon.connect(
        Some(TOOL),
        &[
            hello(None),
            ("records.query", r#"{"limit":10}"#.to_owned()),
            (
                "records.query",
                format!(r#"{{"limit":10,"session_id":"{}"}}"#, other.session_id),
            ),
            (
                "records.output",
                format!(r#"{{"record_id":"{other_record}","stream":"stdout"}}"#),
            ),
            (
                "records.output",
                format!(r#"{{"record_id":"{own_record}","stream":"stdout"}}"#),
            ),
            (
                "events.subscribe",
                format!(r#"{{"session_id":"{}"}}"#, other.session_id),
            ),
            ("events.subscribe", format!(r#"{{"session_id":"{}"}}"#, own.session_id)),
            ("events.subscribe", "{}".to_owned()),
        ],
    );
    assert_eq!(closed, Closed::Peer);
    assert_eq!(record_ids(answers.ok(2)), [own_record.to_string()]);
    assert_eq!(answers.code(3), ErrorCode::NotAllowed);
    assert_eq!(answers.code(4), ErrorCode::NotAllowed);
    assert!(answers.get(5).is_some_and(Result::is_ok), "own output is served");
    assert_eq!(answers.code(6), ErrorCode::NotAllowed);
    assert!(answers.get(7).is_some_and(Result::is_ok), "own events by name");
    assert!(answers.get(8).is_some_and(Result::is_ok), "own events by default");
}

// FR-AGT-23: once its session ends, a token yields -32009, and a connection bound to it gets -32009 on its next call
// and is closed.
#[test]
fn rejects_expired_token_after_session_end() {
    let daemon = daemon();
    let opened = daemon.open(Some(ROOT));
    let session_id = opened.session_id;
    // A bound connection whose session ends between two calls. The handler ends it while the connection is open.
    let ender = {
        let sessions = Arc::clone(&daemon.fixture.sessions);
        move || sessions.end_agent(session_id)
    };
    let bytes = request_frames(&[hello(Some(&opened)), info(), info(), info()]);
    // Ends the session once the first two requests have been read. A frame is its 4-byte length, then that many
    // bytes.
    let frame_end =
        |at: usize| at + 4 + usize::try_from(u32::from_be_bytes(bytes[at..at + 4].try_into().unwrap())).unwrap();
    let split = frame_end(frame_end(0));
    let reader = SplitReader {
        bytes: &bytes,
        at: 0,
        split,
        on_split: Some(Box::new(ender)),
    };
    let (closed, answers) = daemon.serve(reader, None);
    assert_eq!(closed, Closed::Unbound);
    assert!(answers.get(1).is_some_and(Result::is_ok), "the hello is answered");
    assert!(
        answers.get(2).is_some_and(Result::is_ok),
        "the call before the end is served"
    );
    assert_eq!(answers.code(3), ErrorCode::InvalidSessionToken);
    assert_eq!(answers.len(), 3, "request 4 is never answered");

    // A new connection with the expired token, from inside the (revoked) envelope: refused.
    let (closed, answers) = daemon.connect(Some(TOOL), &[hello(Some(&opened))]);
    assert_eq!(closed, Closed::Handshake);
    assert_eq!(answers.code(1), ErrorCode::InvalidSessionToken);
}

// FR-SES-02: no session can be created over agent.sock: the methods are "method not found" there.
#[test]
fn session_creation_is_method_not_found_on_agent_sock() {
    let daemon = daemon();
    let opened = daemon.open(None);
    let (closed, answers) = daemon.connect(
        None,
        &[
            hello(Some(&opened)),
            ("session.start_agent", "{}".to_owned()),
            ("session.start_human", "{}".to_owned()),
        ],
    );
    assert_eq!(closed, Closed::Peer);
    assert_eq!(answers.code(2), ErrorCode::MethodNotFound);
    assert_eq!(answers.code(3), ErrorCode::MethodNotFound);
    assert_eq!(daemon.fixture.sessions.live(), 1, "nothing was created");
}

// A connection acts for one session: a repeated hello naming another session is -32009 and closes it; one naming
// the same session is answered.
#[test]
fn a_connection_is_never_moved_to_another_session() {
    let daemon = daemon();
    let first = daemon.open(None);
    let second = daemon.open(None);
    let (closed, answers) = daemon.connect(
        None,
        &[hello(Some(&first)), hello(Some(&first)), hello(Some(&second)), info()],
    );
    assert_eq!(closed, Closed::Unbound);
    assert_eq!(text(answers.ok(2), "session_id"), first.session_id.to_string());
    assert_eq!(answers.code(3), ErrorCode::InvalidSessionToken);
    assert!(answers.get(4).is_none());
}

// NFR-SEC-02: the token never reaches an answer, the store or an event: it is only ever compared.
#[test]
fn token_is_never_recorded_or_echoed() {
    let daemon = daemon();
    let opened = daemon.open(None);
    let token = opened.token.encode().expose().clone();
    let (_, answers) = daemon.connect(None, &[hello(Some(&opened)), info()]);
    let rendered = format!("{:?}", answers.0);
    assert!(!rendered.contains(&token));
    // Every file of the store (database, journal, write-ahead log).
    for entry in std::fs::read_dir(daemon.fixture.dir()).unwrap() {
        let bytes = std::fs::read(entry.unwrap().path()).unwrap();
        assert!(
            !bytes.windows(token.len()).any(|window| window == token.as_bytes()),
            "token found in the record store"
        );
    }
}

/// A reader over `bytes` that calls `on_split` once everything before `split` has been read, as if something
/// happened between two requests.
struct SplitReader<'a> {
    bytes: &'a [u8],
    at: usize,
    split: usize,
    on_split: Option<Box<dyn FnOnce() + 'a>>,
}

impl std::io::Read for SplitReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.at == self.split
            && let Some(on_split) = self.on_split.take()
        {
            on_split();
        }
        let end = if self.at < self.split {
            self.split
        } else {
            self.bytes.len()
        };
        let n = buf.len().min(end - self.at);
        buf[..n].copy_from_slice(&self.bytes[self.at..self.at + n]);
        self.at += n;
        Ok(n)
    }
}
