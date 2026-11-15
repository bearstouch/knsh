//! KNSH-050 integration: lines through a real `agent.sock` (a [`Server`] on temporary sockets, the dispatcher
//! `knshd` builds, `hello` with a session token, `exec.run`) to the orchestrator, with fake hooks, authority and
//! spawner. Each path is checked by its answer, the order of its session's events and its record.

use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;

use knsh_core::{AgentId, DecisionVerdict, Delivery, EventScope, HookVerdict, Redacted};
use knsh_json::{Frame, FrameReader, FrameWriter};
use knsh_platform::macos::{SystemPeerCredentials, effective_uid};
use knsh_platform::testing::{FakeClock, RecordingLog, SeededRandom};
use knsh_proto::{Message, decode};
use knsh_store::{PageSize, RecordQuery, Scope};

use super::tests::{FakeHooks, FakeSpawner, Journal};
use super::*;
use crate::dispatch::{EXEC_RUN, Endpoint};
use crate::endpoints::Listeners;
use crate::events::Subscriber;
use crate::exec::ExecRun;
use crate::server::{Config, Exit, ServeError, Server, Services, StopHandle};
use crate::sessions::tests::{Fixture, fixture};

const HOME: &str = "/Users/u";
const PROJECT: &str = "/Users/u/app";

/// An authority answering by line: `git push origin main` allowed, `git push --force` rewritten to `git status`,
/// anything else denied. Connected while the flag is set.
struct ByLine {
    connected: AtomicBool,
}

impl Authority for ByLine {
    fn connected(&self) -> bool {
        self.connected.load(Ordering::SeqCst)
    }

    fn ask(&self, request: &AskRequest<'_>, _caller: &dyn Caller) -> AskAnswer {
        let reply = match request.proposal.command.expose().as_str() {
            "git push origin main" => AskReply::Allow,
            "git push --force" => AskReply::Rewrite {
                command: "git status".to_owned(),
            },
            _ => AskReply::Deny { reason: None },
        };
        AskAnswer {
            request_id: Some(RequestId::from_ulid(Ulid::from_u128(5))),
            reply,
            decided_by: Some("Example Authority".to_owned()),
        }
    }
}

/// A running server whose `agent.sock` serves `exec.run` through the orchestrator.
struct Running {
    dir: PathBuf,
    fixture: Fixture,
    authority: Arc<ByLine>,
    journal: Arc<Journal>,
    token: String,
    session_id: SessionId,
    subscriber: Subscriber,
    stop: StopHandle,
    thread: Option<JoinHandle<Result<Exit, ServeError>>>,
}

impl Running {
    fn start(tag: &str, ask_timeout: Duration) -> Self {
        // Short: socket paths are limited to 103 bytes.
        let dir = PathBuf::from("/tmp").join(format!("knshd-l{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir(&dir).unwrap();
        let fixture = fixture();
        let opened = fixture
            .sessions
            .open_agent(
                Actor::Agent(AgentId::new("claude-code").unwrap()),
                ProfileName::new("web").unwrap(),
            )
            .unwrap();
        let subscriber = Subscriber::new();
        subscriber
            .subscribe(&fixture.hub, EventScope::Session(opened.session_id), None)
            .unwrap();
        let journal = Arc::new(Journal::default());
        let authority = Arc::new(ByLine {
            connected: AtomicBool::new(true),
        });
        let clock = Arc::new(FakeClock::new(
            Timestamp::from_unix_micros(1_800_000_000_000_000).unwrap(),
        ));
        let lifecycle = Lifecycle::new(Parts {
            sessions: Arc::clone(&fixture.sessions),
            profiles: crate::policy::tests::loader(super::tests::filesystem(&[("web", super::tests::WEB)])),
            events: Arc::clone(&fixture.hub),
            store: Some(fixture.store.clone()),
            clock: clock.clone(),
            random: Arc::new(SeededRandom::new(21)),
            hooks: Arc::new(FakeHooks {
                journal: Arc::clone(&journal),
                script: Mutex::new(Vec::<HookVerdict>::new()),
                seen: None,
            }),
            authority: authority.clone(),
            approvals: Arc::new(DenyAtTimeout { timeout: ask_timeout }),
            spawner: Arc::new(FakeSpawner::new(Arc::clone(&journal))),
        });
        let shims = knsh_platform::EnginePaths::for_home(std::path::Path::new(HOME))
            .unwrap()
            .shim_dir();
        let exec = ExecRun::new(lifecycle, shims);
        let dispatcher = crate::agents::endpoint_tests::dispatcher(&fixture).serving(
            Endpoint::Agent,
            EXEC_RUN,
            Arc::clone(&exec.handlers()[EXEC_RUN]),
        );
        let services = Services {
            dispatcher,
            credentials: Arc::new(SystemPeerCredentials::new()),
            log: Arc::new(RecordingLog::new()),
            own_uid: effective_uid(),
            clock,
            activity: Arc::clone(&fixture.sessions) as _,
            pending: Arc::new(crate::records::Records::new(Some(fixture.store.clone()))),
        };
        let listeners = Listeners {
            user: vec![UnixListener::bind(dir.join("u")).unwrap()],
            agent: vec![UnixListener::bind(dir.join("a")).unwrap()],
        };
        let server = Server::new(listeners, services, Config::DEFAULT).unwrap();
        let stop = server.stop_handle();
        let thread = Some(std::thread::spawn(move || server.run()));
        Self {
            dir,
            fixture,
            authority,
            journal,
            token: opened.token.encode().expose().clone(),
            session_id: opened.session_id,
            subscriber,
            stop,
            thread,
        }
    }

    /// Connects to `agent.sock` and binds to the session with its token.
    fn connect(&self) -> UnixStream {
        let stream = UnixStream::connect(self.dir.join("a")).unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        let hello = format!(
            r#"{{"client":"t","client_version":"1","protocols":[1],"binary_frames":false,"session_token":"{}"}}"#,
            self.token
        );
        send(&stream, 1, "hello", &hello);
        assert!(matches!(receive(&stream), Some(Message::Success(_))));
        stream
    }

    /// Runs `command` with `exec.run` on a new connection and returns the answer.
    fn run(&self, command: &str) -> Message {
        let stream = self.connect();
        send(&stream, 2, EXEC_RUN, &exec_params(command));
        receive(&stream).unwrap()
    }

    /// The session's events since the last call.
    fn events(&self) -> Vec<Arc<knsh_core::Event>> {
        self.subscriber
            .take(usize::MAX)
            .into_iter()
            .filter_map(|(_, delivery)| match delivery {
                Delivery::Event(event) => Some(event),
                Delivery::Lost(_) => None,
            })
            .collect()
    }

    /// The session's record `record_id`.
    fn record(&self, record_id: RecordId) -> ExecutionRecord {
        self.records()
            .into_iter()
            .find(|record| record.record_id == record_id)
            .unwrap()
    }

    fn records(&self) -> Vec<ExecutionRecord> {
        let page = self
            .fixture
            .store
            .query(
                Scope::All,
                RecordQuery {
                    session: Some(self.session_id),
                    since: None,
                    until: None,
                    text: None,
                    after: None,
                    limit: PageSize::new(100).unwrap(),
                },
            )
            .unwrap();
        page.records.into_iter().map(|stored| stored.record).collect()
    }

    fn spawns(&self) -> Vec<String> {
        self.journal
            .entries()
            .into_iter()
            .filter(|entry| entry.starts_with("spawn"))
            .collect()
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.stop.stop();
        let _ = self.thread.take().map(JoinHandle::join);
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn exec_params(command: &str) -> String {
    format!(r#"{{"command":"{command}","cwd":"{PROJECT}","env":{{"PATH":"/usr/bin:/bin"}}}}"#)
}

fn send(stream: &UnixStream, id: u32, method: &str, params: &str) {
    let text = format!(r#"{{"jsonrpc":"2.0","id":{id},"method":"{method}","params":{params}}}"#);
    let mut writer = FrameWriter::new(stream);
    writer
        .write_json(&knsh_json::parse(text.as_bytes(), 1 << 20).unwrap())
        .unwrap();
    writer.flush().unwrap();
}

fn receive(stream: &UnixStream) -> Option<Message> {
    match FrameReader::new(stream).read_frame() {
        Ok(Some(Frame::Json(payload))) => Some(decode(&payload).unwrap()),
        _ => None,
    }
}

/// The `record_id` of a successful `exec.run` answer.
fn record_id_of(answer: &Message) -> RecordId {
    let Message::Success(success) = answer else {
        panic!("{answer:?}");
    };
    success
        .result
        .as_object()
        .and_then(|result| result.get("record_id"))
        .and_then(Value::as_str)
        .unwrap()
        .parse()
        .unwrap()
}

/// The error of a failed answer.
fn error_of(answer: Message) -> RpcError {
    match answer {
        Message::Error(error) => error.error,
        other => panic!("{other:?}"),
    }
}

/// The record named by the session's last `command.denied` in `events`.
fn denied_record(events: &[Arc<knsh_core::Event>]) -> RecordId {
    events
        .iter()
        .rev()
        .find_map(|event| match &event.data {
            EventData::CommandDenied { record_id, .. } => *record_id,
            _ => None,
        })
        .unwrap()
}

fn names(events: &[Arc<knsh_core::Event>]) -> Vec<&'static str> {
    events.iter().map(|event| event.name()).collect()
}

fn text(redacted: &Redacted<String>) -> &str {
    redacted.expose()
}

// End to end: allow, deny, ask→allow, ask→timeout (no authority) and rewrite→allow, each by its answer, event order
// and record.
#[test]
fn lines_through_agent_sock() {
    let server = Running::start("paths", Duration::from_millis(100));
    server.events();

    // Allow: spawned as its absolute form; proposed, started, then finished; the record says the rule allowed it.
    let answer = server.run("git status");
    let record = server.record(record_id_of(&answer));
    assert_eq!(
        names(&server.events()),
        ["command.proposed", "command.started", "command.finished"]
    );
    assert_eq!(text(&record.command), "git status");
    assert_eq!(record.exit_code, Some(0));
    let decision = record.details.decision.unwrap();
    assert_eq!(
        (decision.verdict, decision.source, decision.rule_id.as_deref()),
        (DecisionVerdict::Allow, DecisionSource::Rule, Some("exec.allow[0]"))
    );
    assert_eq!(server.spawns(), ["spawn /usr/bin/git status as knsh"]);

    // Deny: -32001 naming the rule; proposed, then denied; recorded without an exit code.
    let error = error_of(server.run("rm -rf build"));
    assert_eq!(error.code, ErrorCode::Denied);
    assert_eq!(
        Denial::from_error(&error).unwrap().rule_id.as_deref(),
        Some("exec.deny[0]")
    );
    let events = server.events();
    assert_eq!(names(&events), ["command.proposed", "command.denied"]);
    let record = server.record(denied_record(&events));
    assert_eq!(record.exit_code, None);
    assert_eq!(record.details.decision.unwrap().verdict, DecisionVerdict::Deny);

    // Ask → allow: the authority's yes, named in the record.
    let answer = server.run("git push origin main");
    let record = server.record(record_id_of(&answer));
    assert_eq!(
        names(&server.events()),
        ["command.proposed", "command.started", "command.finished"]
    );
    let decision = record.details.decision.unwrap();
    assert_eq!(
        (
            decision.source,
            decision.rule_id.as_deref(),
            decision.decided_by.as_deref()
        ),
        (
            DecisionSource::Authority,
            Some("exec.ask[0]"),
            Some("Example Authority")
        )
    );

    // Rewrite → allow: the new line is proposed (naming the old one), run and recorded with the original.
    let answer = server.run("git push --force");
    let record = server.record(record_id_of(&answer));
    let events = server.events();
    assert_eq!(
        names(&events),
        [
            "command.proposed",
            "command.proposed",
            "command.started",
            "command.finished"
        ]
    );
    assert!(matches!(
        &events[1].data,
        EventData::CommandProposed { command, rewritten_from: Some(from), .. }
            if text(command) == "git status" && text(from) == "git push --force"
    ));
    assert_eq!(text(&record.command), "git status");
    assert_eq!(record.details.decision.unwrap().verdict, DecisionVerdict::Rewrite);

    // Ask → timeout, with no authority connected: standalone handling denies at the timeout (-32002).
    server.authority.connected.store(false, Ordering::SeqCst);
    let error = error_of(server.run("git push origin main"));
    assert_eq!(error.code, ErrorCode::DecisionTimeout);
    let events = server.events();
    assert_eq!(
        names(&events),
        ["command.proposed", "decision.cancelled", "command.denied"]
    );
    let record = server.record(denied_record(&events));
    assert_eq!(record.details.decision.unwrap().source, DecisionSource::Standalone);

    assert_eq!(
        server.spawns(),
        [
            "spawn /usr/bin/git status as knsh",
            "spawn /usr/bin/git push origin main as knsh",
            "spawn /usr/bin/git status as knsh",
        ]
    );
}

// FR-LC-41 over a real socket: the client sends a line that waits for approval and disconnects; the request is
// cancelled at once (not at its timeout), `decision.cancelled` names the caller going away, and nothing runs.
#[test]
fn disconnect_cancels_a_pending_line() {
    let server = Running::start("gone", Duration::from_secs(60));
    server.authority.connected.store(false, Ordering::SeqCst);
    server.events();
    let stream = server.connect();
    send(&stream, 2, EXEC_RUN, &exec_params("git push"));
    drop(stream);
    let started = Instant::now();
    let mut events = Vec::new();
    while !names(&events).contains(&"command.denied") {
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "not cancelled: {:?}",
            names(&events)
        );
        thread::sleep(Duration::from_millis(20));
        events.extend(server.events());
    }
    assert_eq!(
        names(&events),
        ["command.proposed", "decision.cancelled", "command.denied"]
    );
    assert!(matches!(
        events[1].data,
        EventData::DecisionCancelled {
            reason: CancelReason::CallerGone,
            ..
        }
    ));
    let record = server.record(denied_record(&events));
    assert_eq!(record.details.decision.unwrap().verdict, DecisionVerdict::Deny);
    assert_eq!(server.spawns(), Vec::<String>::new());
}
