//! The checkpoint history service (KNSH-088): endpoints and scope, feeding, restore windows, forget and retention.

use std::path::Path;
use std::sync::Mutex;

use knsh_checkpoint::testing::{FakeNode, FakeTree, TestChange, capture_change};
use knsh_core::{Attribution, CheckpointId, RecordId, Ulid};
use knsh_json::{Object, Value};
use knsh_platform::testing::{FakeClock, RecordingLog, SeededRandom};
use knsh_proto::{MethodName, RequestId};

use super::*;
use crate::dispatch::tests::{stream, subscriber};
use crate::sessions::SessionBinding;
use crate::sessions::tests::Fixture as Sessions;

const ROOT: &str = "/Users/u/app";
const STORE: &str = "/Users/u/Library/Application Support/knsh/checkpoints";

/// 2026-11-19, in microseconds.
const NOW: u64 = 1_763_500_000_000_000;

fn root() -> CanonicalPath {
    CanonicalPath::new(ROOT).unwrap()
}

fn live(name: &str) -> std::path::PathBuf {
    Path::new(ROOT).join(name)
}

fn record(n: u128) -> RecordId {
    RecordId::from_ulid(Ulid::from_u128(n))
}

/// A checkpoint ID made `age_ms` before [`NOW`], numbered `n`.
fn checkpoint_id(n: u128, age_ms: u64) -> CheckpointId {
    let millis = NOW / 1_000 - age_ms;
    CheckpointId::from_ulid(Ulid::from_u128((u128::from(millis) << 80) | n))
}

/// Every `checkpoint.restored` published.
#[derive(Default)]
struct Published(Mutex<Vec<(SessionId, EventData)>>);

impl RestoreEvents for Published {
    fn restored(&self, session_id: SessionId, data: EventData) {
        self.0.lock().unwrap().push((session_id, data));
    }
}

/// Records each window, and on opening one reports `reported` as finished (a watcher flushing what it saw before the
/// restore), like the shadows do.
#[derive(Default)]
struct Windows {
    calls: Mutex<Vec<(&'static str, Vec<CanonicalPath>)>>,
    service: OnceLock<Arc<HistoryService>>,
    reported: Mutex<Vec<Checkpoint>>,
}

impl RestoreWindows for Windows {
    fn begin(&self, roots: &[CanonicalPath]) {
        self.calls.lock().unwrap().push(("begin", roots.to_vec()));
        let reported = std::mem::take(&mut *self.reported.lock().unwrap());
        if let Some(service) = self.service.get()
            && !reported.is_empty()
        {
            // The history lock is held by the restore here: this must queue, never wait.
            service.finished(&reported);
        }
    }

    fn end(&self, roots: &[CanonicalPath]) {
        self.calls.lock().unwrap().push(("end", roots.to_vec()));
    }
}

/// A service over a fake tree, with agent sessions to bind connections to.
struct Fixture {
    tree: Arc<FakeTree>,
    service: Arc<HistoryService>,
    published: Arc<Published>,
    windows: Arc<Windows>,
    sessions: Sessions,
    log: Arc<RecordingLog>,
}

impl Fixture {
    fn new() -> Self {
        let tree = Arc::new(FakeTree::new());
        tree.add_dir(ROOT);
        tree.add_dir(Path::new(STORE).join(knsh_checkpoint::CHECKPOINTS_DIR));
        let clock = Arc::new(FakeClock::new(Timestamp::from_unix_micros(NOW).unwrap()));
        let history = History::new(
            Arc::clone(&tree) as Arc<dyn knsh_checkpoint::ShadowFiles>,
            clock.clone(),
            Arc::new(SeededRandom::new(3)),
        );
        let published = Arc::new(Published::default());
        let log = Arc::new(RecordingLog::new());
        let service = HistoryService::new(
            history,
            Arc::clone(&published) as Arc<dyn RestoreEvents + Send + Sync>,
            clock,
            Arc::clone(&log) as Arc<dyn SystemLog>,
            Retention::default(),
        );
        let windows = Arc::new(Windows::default());
        let _ = windows.service.set(Arc::clone(&service));
        service.attach_windows(Arc::clone(&windows) as Arc<dyn RestoreWindows>);
        Self {
            tree,
            service,
            published,
            windows,
            sessions: crate::sessions::tests::fixture(),
            log,
        }
    }

    /// A new agent session, and a connection bound to it.
    fn agent(&self) -> (SessionBinding, SessionId) {
        let opened = self
            .sessions
            .sessions
            .open_agent(
                knsh_core::Actor::Agent(knsh_core::AgentId::new("claude-code").unwrap()),
                knsh_core::ProfileName::new("web").unwrap(),
            )
            .unwrap();
        let binding = SessionBinding::new();
        self.sessions
            .sessions
            .bind_agent(&binding, Some(&opened.token.encode()))
            .unwrap();
        (binding, opened.session_id)
    }

    /// Line `n` of `session` writes `contents` to `name`; its checkpoint is reported finished.
    fn line(&self, n: u128, session: SessionId, name: &str, contents: &'static [u8]) -> CheckpointId {
        self.change(n, Attribution::Command, session, name, contents, 0)
    }

    fn change(
        &self,
        n: u128,
        attribution: Attribution,
        session: SessionId,
        name: &str,
        contents: &'static [u8],
        age_ms: u64,
    ) -> CheckpointId {
        let checkpoint = self.capture(n, attribution, session, name, contents, age_ms);
        let id = checkpoint.id;
        self.service.finished(&[checkpoint]);
        id
    }

    fn capture(
        &self,
        n: u128,
        attribution: Attribution,
        session: SessionId,
        name: &str,
        contents: &'static [u8],
        age_ms: u64,
    ) -> Checkpoint {
        let records = match attribution {
            Attribution::Command | Attribution::Concurrent => vec![record(n)],
            Attribution::AgentEdit | Attribution::External => Vec::new(),
        };
        let root = root();
        capture_change(
            &self.tree,
            &TestChange {
                id: checkpoint_id(n, age_ms),
                attribution,
                records: &records,
                session,
                root: &root,
                store: Path::new(STORE),
                paths: &[name],
            },
            |tree| tree.add_file(live(name), contents),
        )
    }

    fn contents(&self, name: &str) -> Option<Vec<u8>> {
        match self.tree.node(live(name)) {
            Some(FakeNode::File(contents)) => Some(contents),
            _ => None,
        }
    }

    fn call(&self, endpoint: Endpoint, binding: &SessionBinding, method: &'static str, params: &str) -> Reply {
        self.call_bytes(endpoint, binding, method, params, ByteTransport::BinaryFrames)
    }

    fn call_bytes(
        &self,
        endpoint: Endpoint,
        binding: &SessionBinding,
        method: &'static str,
        params: &str,
        bytes: ByteTransport,
    ) -> Reply {
        let request = knsh_proto::Request {
            id: RequestId::from(1u32),
            method: MethodName::new(method).unwrap(),
            params: knsh_json::parse(params.as_bytes(), 1 << 20)
                .unwrap()
                .as_object()
                .cloned(),
        };
        self.service.handlers()[method](&Call {
            endpoint,
            bytes,
            stream: stream(),
            request: &request,
            subscriber: subscriber(),
            binding,
            descriptors: crate::dispatch::tests::no_descriptors(),
            caller: &knsh_core::StillWaiting,
            control: None,
        })
    }

    fn user(&self, method: &'static str, params: &str) -> Reply {
        self.call(Endpoint::User, &SessionBinding::new(), method, params)
    }

    fn windows(&self) -> Vec<(&'static str, Vec<CanonicalPath>)> {
        std::mem::take(&mut *self.windows.calls.lock().unwrap())
    }
}

fn object(reply: Reply) -> Object {
    reply.unwrap().result.as_object().cloned().unwrap()
}

fn code(reply: Reply) -> ErrorCode {
    reply.unwrap_err().code
}

fn reason(reply: Reply) -> String {
    let error = reply.unwrap_err();
    assert_eq!(error.code, ErrorCode::InvalidParams);
    error
        .data
        .as_ref()
        .and_then(Value::as_object)
        .and_then(|data| data.get("reason"))
        .and_then(Value::as_str)
        .unwrap()
        .to_owned()
}

fn by_record(n: u128) -> String {
    format!(r#"{{"record_id":"{}"}}"#, record(n))
}

fn listed_ids(result: &Object) -> Vec<String> {
    result
        .get("changes")
        .and_then(Value::as_array)
        .unwrap()
        .iter()
        .map(|change| {
            change
                .as_object()
                .unwrap()
                .get("checkpoint_id")
                .and_then(Value::as_str)
                .unwrap()
                .to_owned()
        })
        .collect()
}

/// Handlers over an empty history with no shadows, for tests that need every available method served.
pub(crate) fn idle_handlers() -> Handlers {
    let history = History::new(
        Arc::new(FakeTree::new()),
        Arc::new(FakeClock::new(Timestamp::UNIX_EPOCH)),
        Arc::new(SeededRandom::new(1)),
    );
    HistoryService::new(
        history,
        Arc::new(Published::default()),
        Arc::new(FakeClock::new(Timestamp::UNIX_EPOCH)),
        Arc::new(RecordingLog::new()),
        Retention::default(),
    )
    .handlers()
}

// FR-CKP-21: `force` never exists on agent.sock. Refused before the change is looked at, even the agent's own.
#[test]
fn agent_socket_rejects_force() {
    let fixture = Fixture::new();
    let (binding, own) = fixture.agent();
    fixture.tree.add_file(live("a.txt"), b"old");
    fixture.line(1, own, "a.txt", b"new");
    for method in ["checkpoint.undo", "checkpoint.redo"] {
        let forced = format!(r#"{{"record_id":"{}","force":true}}"#, record(1));
        assert_eq!(
            code(fixture.call(Endpoint::Agent, &binding, method, &forced)),
            ErrorCode::NotAllowed,
            "{method}"
        );
        // Even for a change that does not exist: nothing is looked up first.
        let unknown = format!(r#"{{"record_id":"{}","force":true}}"#, record(9));
        assert_eq!(
            code(fixture.call(Endpoint::Agent, &binding, method, &unknown)),
            ErrorCode::NotAllowed
        );
    }
    assert_eq!(
        fixture.contents("a.txt").as_deref(),
        Some(&b"new"[..]),
        "nothing restored"
    );
    assert!(fixture.windows().is_empty(), "no restore was even started");
    // Without force the agent may undo its own change.
    fixture
        .call(Endpoint::Agent, &binding, "checkpoint.undo", &by_record(1))
        .unwrap();
    assert_eq!(fixture.contents("a.txt").as_deref(), Some(&b"old"[..]));
}

// FR-CKP-21: an agent can never return every root to a state, not even through a routing mistake; and the engine
// catalogue does not serve it on agent.sock at all.
#[test]
fn agent_socket_rejects_restore() {
    let fixture = Fixture::new();
    let (binding, own) = fixture.agent();
    fixture.tree.add_file(live("a.txt"), b"old");
    fixture.line(1, own, "a.txt", b"new");
    assert_eq!(
        code(fixture.call(Endpoint::Agent, &binding, "checkpoint.restore", r#"{"state_id":0}"#)),
        ErrorCode::NotAllowed
    );
    assert_eq!(fixture.contents("a.txt").as_deref(), Some(&b"new"[..]));

    let mut handlers = crate::hello::tests::handlers();
    handlers.extend(fixture.service.handlers());
    let dispatcher = crate::hello::phase1_dispatcher(
        crate::probe::probe(&crate::probe::tests::Machine::working().probes()),
        handlers,
    )
    .unwrap();
    assert!(!dispatcher.methods(Endpoint::Agent).contains(&"checkpoint.restore"));
    assert!(dispatcher.methods(Endpoint::User).contains(&"checkpoint.restore"));
    let error = crate::dispatch::tests::call(&dispatcher, Endpoint::Agent, "checkpoint.restore").unwrap_err();
    assert_eq!(error.code, ErrorCode::NotAllowed);
}

// KNSH-088: on agent.sock checkpoint methods see only the caller's session: another session's changes are not
// listed, and acting on one (or on an external edit) is -32003.
#[test]
fn agent_socket_cannot_see_other_sessions_checkpoints() {
    let fixture = Fixture::new();
    let (binding, own) = fixture.agent();
    let (_, other) = fixture.agent();
    fixture.tree.add_file(live("a.txt"), b"a0");
    let own_id = fixture.line(1, own, "a.txt", b"a1");
    fixture.line(2, other, "b.txt", b"b1");
    fixture.change(3, Attribution::External, own, "c.txt", b"c1", 0);

    let listed = object(fixture.call(Endpoint::Agent, &binding, "checkpoint.list", "{}"));
    assert_eq!(listed_ids(&listed), vec![own_id.to_string()]);
    let all = object(fixture.user("checkpoint.list", "{}"));
    assert_eq!(listed_ids(&all).len(), 3, "the user sees every session's");

    let theirs = format!(r#"{{"session_id":"{other}"}}"#);
    assert_eq!(
        code(fixture.call(Endpoint::Agent, &binding, "checkpoint.list", &theirs)),
        ErrorCode::NotAllowed
    );
    for method in ["checkpoint.undo", "checkpoint.redo", "checkpoint.diff"] {
        assert_eq!(
            code(fixture.call(Endpoint::Agent, &binding, method, &by_record(2))),
            ErrorCode::NotAllowed,
            "{method}"
        );
    }
    let external = fixture.service.with_history(|history| {
        history
            .tree()
            .edges()
            .find(|edge| {
                matches!(
                    edge.kind,
                    EdgeKind::Change {
                        attribution: Attribution::External,
                        ..
                    }
                )
            })
            .unwrap()
            .checkpoint
    });
    let external = format!(r#"{{"checkpoint_id":"{external}"}}"#);
    assert_eq!(
        code(fixture.call(Endpoint::Agent, &binding, "checkpoint.undo", &external)),
        ErrorCode::NotAllowed
    );
    assert_eq!(fixture.contents("b.txt").as_deref(), Some(&b"b1"[..]));
    // The agent's own change is still its to undo.
    fixture
        .call(Endpoint::Agent, &binding, "checkpoint.undo", &by_record(1))
        .unwrap();
    assert_eq!(fixture.contents("a.txt").as_deref(), Some(&b"a0"[..]));
}

// KNSH-088: hello lists the checkpoint methods only where checkpoints can be taken; elsewhere every call is -32005
// naming `checkpoints`, on every endpoint.
#[test]
fn unavailable_checkpoint_capability_returns_minus_32005() {
    let fixture = Fixture::new();
    let without = crate::probe::tests::Machine::working().probes();
    let mut probed = crate::probe::probe(&without);
    let mut capabilities = probed.capabilities.as_ref().clone();
    capabilities.file_events = knsh_proto::FileEvents::None;
    probed.capabilities = Arc::new(capabilities);
    let mut handlers = crate::hello::tests::handlers();
    handlers.extend(fixture.service.handlers());
    let dispatcher = crate::hello::phase1_dispatcher(probed, handlers).unwrap();
    for endpoint in [Endpoint::User, Endpoint::Agent] {
        assert!(
            !dispatcher
                .methods(endpoint)
                .iter()
                .any(|name| name.starts_with("checkpoint.")),
            "{}",
            endpoint.name()
        );
        for method in [
            "checkpoint.list",
            "checkpoint.diff",
            "checkpoint.undo",
            "checkpoint.redo",
        ] {
            let error = crate::dispatch::tests::call(&dispatcher, endpoint, method).unwrap_err();
            assert_eq!(error.code, ErrorCode::CapabilityUnavailable, "{method}");
            let data = error.data.as_ref().and_then(Value::as_object).unwrap();
            assert_eq!(data.get("capability").and_then(Value::as_str), Some("checkpoints"));
        }
    }
    let error = crate::dispatch::tests::call(&dispatcher, Endpoint::User, "checkpoint.restore").unwrap_err();
    assert_eq!(error.code, ErrorCode::CapabilityUnavailable);
}

// KNSH-088: the user acts across sessions; an undo runs inside a window over its root, publishes
// `checkpoint.restored` (FR-CKP-25), and redo brings the change back.
#[test]
fn user_undoes_and_redoes_any_sessions_change_inside_a_window() {
    let fixture = Fixture::new();
    let (_, agent) = fixture.agent();
    fixture.tree.add_file(live("a.txt"), b"old");
    let id = fixture.line(1, agent, "a.txt", b"new");

    let undone = object(fixture.user("checkpoint.undo", &by_record(1)));
    assert_eq!(undone.get("operation").and_then(Value::as_str), Some("undo"));
    assert_eq!(
        undone.get("checkpoint_id").and_then(Value::as_str),
        Some(id.to_string().as_str())
    );
    assert_eq!(undone.get("files_restored").and_then(Value::as_i64), Some(1));
    assert_eq!(undone.get("state_id").and_then(Value::as_i64), Some(0));
    assert_eq!(fixture.contents("a.txt").as_deref(), Some(&b"old"[..]));
    assert_eq!(fixture.windows(), vec![("begin", vec![root()]), ("end", vec![root()])]);
    let published = std::mem::take(&mut *fixture.published.0.lock().unwrap());
    assert_eq!(published.len(), 1);
    assert_eq!(published[0].0, agent);

    let listed = object(fixture.user("checkpoint.list", "{}"));
    let change = listed.get("changes").and_then(Value::as_array).unwrap()[0]
        .as_object()
        .cloned()
        .unwrap();
    assert_eq!(change.get("status").and_then(Value::as_str), Some("undone"));
    assert_eq!(listed.get("head").and_then(Value::as_i64), Some(0));

    // The authority may redo it too.
    let redone = object(fixture.call(
        Endpoint::Control,
        &SessionBinding::new(),
        "checkpoint.redo",
        &by_record(1),
    ));
    assert_eq!(redone.get("operation").and_then(Value::as_str), Some("redo"));
    assert_eq!(fixture.contents("a.txt").as_deref(), Some(&b"new"[..]));
    // Asked again, the history says why it cannot: a reason, never a guess.
    assert_eq!(reason(fixture.user("checkpoint.redo", &by_record(1))), "not_undone");
    assert_eq!(reason(fixture.user("checkpoint.undo", &by_record(7))), "unknown");
}

// FR-CKP-20: an edit the engine did not record conflicts, as -32004 with the path; nothing changes.
#[test]
fn conflicting_undo_is_minus_32004_with_the_path() {
    let fixture = Fixture::new();
    fixture.tree.add_file(live("a.txt"), b"old");
    fixture.line(1, SessionId::from_ulid(Ulid::from_u128(5)), "a.txt", b"new");
    fixture.tree.replace_file(live("a.txt"), b"human edit");
    let error = fixture.user("checkpoint.undo", &by_record(1)).unwrap_err();
    assert_eq!(error.code, ErrorCode::UndoConflict);
    let conflicts = error
        .data
        .as_ref()
        .and_then(Value::as_object)
        .and_then(|data| data.get("conflicts"))
        .and_then(Value::as_array)
        .unwrap();
    assert_eq!(
        conflicts[0].as_object().unwrap().get("path").and_then(Value::as_str),
        Some(live("a.txt").to_str().unwrap())
    );
    assert_eq!(fixture.contents("a.txt").as_deref(), Some(&b"human edit"[..]));
    // The window still closed.
    assert_eq!(fixture.windows().last().map(|(kind, _)| *kind), Some("end"));
}

// KNSH-088: what the watchers report as the window opens (an edit made just before the undo) is recorded before the
// undo is planned, while the restore holds the history: the sink queues instead of waiting for the lock.
#[test]
fn changes_reported_as_a_window_opens_are_recorded_first() {
    let fixture = Fixture::new();
    let session = SessionId::from_ulid(Ulid::from_u128(5));
    fixture.tree.add_file(live("a.txt"), b"a0");
    fixture.line(1, session, "a.txt", b"a1");
    // A later edit of the same file, reported only when the undo's window opens.
    let late = fixture.capture(2, Attribution::AgentEdit, session, "a.txt", b"a2", 0);
    fixture.windows.reported.lock().unwrap().push(late);
    // The undo of line 1 now meets a later change of a.txt: FR-CKP-30, the path is listed.
    let error = fixture.user("checkpoint.undo", &by_record(1)).unwrap_err();
    assert_eq!(error.code, ErrorCode::UndoConflict);
    let conflicts = error
        .data
        .as_ref()
        .and_then(Value::as_object)
        .and_then(|data| data.get("conflicts"))
        .and_then(Value::as_array)
        .unwrap();
    assert_eq!(
        conflicts[0].as_object().unwrap().get("reason").and_then(Value::as_str),
        Some("later_change")
    );
    assert_eq!(fixture.contents("a.txt").as_deref(), Some(&b"a2"[..]));
    let listed = object(fixture.user("checkpoint.list", "{}"));
    assert_eq!(listed_ids(&listed).len(), 2, "the late edit is in the history");
}

// FR-CKP-34: `records.forget` with `with_checkpoints` removes the session's changes at once; their undo is then
// refused as expired, and other sessions' changes stay.
#[test]
fn forget_removes_a_sessions_checkpoints_at_once() {
    let fixture = Fixture::new();
    let gone = SessionId::from_ulid(Ulid::from_u128(5));
    let kept = SessionId::from_ulid(Ulid::from_u128(6));
    fixture.tree.add_file(live("a.txt"), b"a0");
    fixture.line(1, gone, "a.txt", b"a1");
    let kept_id = fixture.line(2, kept, "b.txt", b"b1");
    crate::records::ForgetCheckpoints::forget_checkpoints(fixture.service.as_ref(), Some(gone), None);
    assert_eq!(reason(fixture.user("checkpoint.undo", &by_record(1))), "expired");
    let listed = object(fixture.user("checkpoint.list", "{}"));
    assert_eq!(
        listed_ids(&listed),
        vec![kept_id.to_string()],
        "only the kept session's change is left"
    );
    fixture.user("checkpoint.undo", &by_record(2)).unwrap();
    assert_eq!(fixture.contents("b.txt"), None);
    // Without a selector nothing is removed rather than everything.
    crate::records::ForgetCheckpoints::forget_checkpoints(fixture.service.as_ref(), None, None);
}

// FR-CKP-32, FR-CKP-33: a sweep removes changes past seven days and says when the next is due (a kept change
// reaching its age limit), so the thread wakes exactly then rather than a period late.
#[test]
fn retention_sweep_removes_old_changes_and_schedules_the_next() {
    let fixture = Fixture::new();
    let session = SessionId::from_ulid(Ulid::from_u128(5));
    let week = 7 * 24 * 3_600 * 1_000;
    fixture.change(1, Attribution::Command, session, "old.txt", b"x", week + 1_000);
    // A `.env` pre-image ten minutes short of its 24 hours.
    fixture.tree.add_file(live(".env"), b"SECRET=0");
    fixture.change(
        2,
        Attribution::Command,
        session,
        ".env",
        b"SECRET=1",
        24 * 3_600 * 1_000 - 600_000,
    );
    let wait = fixture.service.sweep_once();
    assert_eq!(reason(fixture.user("checkpoint.undo", &by_record(1))), "expired");
    // The next sweep is when that pre-image reaches 24 hours, not a period later.
    assert_eq!(wait, Duration::from_secs(600));
    // With nothing due sooner, the thread still wakes within the backstop interval.
    let fresh = Fixture::new();
    assert_eq!(fresh.service.sweep_once(), MAX_SWEEP_INTERVAL);
    assert!(
        fixture
            .log
            .entries()
            .iter()
            .any(|entry| entry.message == "checkpoint retention swept")
    );
}

// The retention thread sweeps at start and when asked, and stops when told.
#[test]
fn retention_thread_sweeps_when_new_checkpoints_arrive() {
    let fixture = Fixture::new();
    fixture.service.start_retention().unwrap();
    fixture.service.request_sweep();
    fixture.service.stop_retention();
}

// KNSH-086 on the wire (KNSH-088): a diff's text goes in its own binary stream, named in the result; over base64 it
// is inline, and on the control service an answer in binary values carries one path at a time.
#[test]
fn diff_streams_each_file_after_the_answer() {
    let fixture = Fixture::new();
    let session = SessionId::from_ulid(Ulid::from_u128(5));
    fixture.tree.add_file(live("a.txt"), b"one\n");
    fixture.tree.add_file(live("b.txt"), b"two\n");
    fixture.line(1, session, "a.txt", b"uno\n");
    fixture.line(2, session, "b.txt", b"dos\n");
    let answer = fixture.user("checkpoint.diff", r#"{"state_id":0}"#).unwrap();
    let files = answer
        .result
        .as_object()
        .unwrap()
        .get("files")
        .and_then(Value::as_array)
        .unwrap();
    assert_eq!(files.len(), 2);
    assert_eq!(answer.streams.len(), 2);
    let first = files[0]
        .as_object()
        .unwrap()
        .get("diff")
        .and_then(Value::as_object)
        .unwrap();
    assert_eq!(
        first.get("stream_id").and_then(Value::as_i64),
        Some(i64::from(answer.streams[0].0.get()))
    );
    assert!(String::from_utf8_lossy(&answer.streams[0].1).contains("+uno"));

    let inline = fixture
        .call_bytes(
            Endpoint::User,
            &SessionBinding::new(),
            "checkpoint.diff",
            r#"{"state_id":0}"#,
            ByteTransport::Base64,
        )
        .unwrap();
    assert_eq!(inline.streams.len(), 0);

    let control = fixture
        .call(
            Endpoint::Control,
            &SessionBinding::new(),
            "checkpoint.diff",
            r#"{"state_id":0}"#,
        )
        .unwrap();
    assert_eq!(control.streams.len(), 1, "one data value per control message");
    assert!(
        control
            .result
            .as_object()
            .unwrap()
            .get("next_cursor")
            .and_then(Value::as_str)
            .is_some()
    );
}

// FR-CKP-21 and KNSH-086: the user restores every root to a state, inside a window over the roots on the way.
#[test]
fn user_restores_a_state() {
    let fixture = Fixture::new();
    let session = SessionId::from_ulid(Ulid::from_u128(5));
    fixture.tree.add_file(live("a.txt"), b"a0");
    fixture.line(1, session, "a.txt", b"a1");
    fixture.line(2, session, "b.txt", b"b1");
    let restored = object(fixture.user("checkpoint.restore", r#"{"state_id":0}"#));
    assert_eq!(restored.get("state_id").and_then(Value::as_i64), Some(0));
    assert_eq!(restored.get("files_restored").and_then(Value::as_i64), Some(2));
    assert_eq!(fixture.contents("a.txt").as_deref(), Some(&b"a0"[..]));
    assert_eq!(fixture.contents("b.txt"), None);
    assert_eq!(fixture.windows(), vec![("begin", vec![root()]), ("end", vec![root()])]);
    assert_eq!(
        reason(fixture.user("checkpoint.restore", r#"{"state_id":99}"#)),
        "unknown"
    );
}

// Listing pages through the history oldest first, by checkpoint.
#[test]
fn list_pages_with_a_cursor() {
    let fixture = Fixture::new();
    let session = SessionId::from_ulid(Ulid::from_u128(5));
    for n in 1..=3 {
        fixture.line(n, session, &format!("{n}.txt"), b"x");
    }
    let first = object(fixture.user("checkpoint.list", r#"{"limit":2}"#));
    assert_eq!(listed_ids(&first).len(), 2);
    let cursor = first.get("next_cursor").and_then(Value::as_str).unwrap().to_owned();
    let second = object(fixture.user("checkpoint.list", &format!(r#"{{"limit":2,"cursor":"{cursor}"}}"#)));
    assert_eq!(listed_ids(&second).len(), 1);
    assert_eq!(second.get("next_cursor"), Some(&Value::Null));
    let filtered = object(fixture.user(
        "checkpoint.list",
        &format!(r#"{{"session_id":"{}"}}"#, SessionId::from_ulid(Ulid::from_u128(6))),
    ));
    assert_eq!(listed_ids(&filtered).len(), 0);
}

// KNSH-088: a change in another root reported as the first window opens moves the head, so the restore's way now
// crosses that root too: it gets its own window before anything is written, and both close after the restore.
#[test]
fn restore_opens_a_window_on_every_root_its_way_reaches() {
    const OTHER: &str = "/Users/u/lib";
    let fixture = Fixture::new();
    let session = SessionId::from_ulid(Ulid::from_u128(5));
    let other = CanonicalPath::new(OTHER).unwrap();
    fixture.tree.add_dir(OTHER);
    fixture.tree.add_file(live("a.txt"), b"a0");
    fixture.line(1, session, "a.txt", b"a1");
    let late = capture_change(
        &fixture.tree,
        &TestChange {
            id: checkpoint_id(2, 0),
            attribution: Attribution::AgentEdit,
            records: &[],
            session,
            root: &other,
            store: Path::new(STORE),
            paths: &["b.txt"],
        },
        |tree| tree.add_file(Path::new(OTHER).join("b.txt"), b"b1"),
    );
    fixture.windows.reported.lock().unwrap().push(late);
    let restored = object(fixture.user("checkpoint.restore", r#"{"state_id":0}"#));
    assert_eq!(restored.get("state_id").and_then(Value::as_i64), Some(0));
    assert_eq!(fixture.contents("a.txt").as_deref(), Some(&b"a0"[..]));
    assert!(fixture.tree.node(Path::new(OTHER).join("b.txt")).is_none());
    assert_eq!(
        fixture.windows(),
        vec![
            ("begin", vec![root()]),
            ("begin", vec![other.clone()]),
            ("end", vec![root()]),
            ("end", vec![other]),
        ]
    );
}
