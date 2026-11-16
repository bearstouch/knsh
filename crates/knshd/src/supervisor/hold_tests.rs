//! KNSH-054: pause, resume and human control, through the orchestrator and the session registry, with a spawner over
//! scripted process groups (FR-SES-10 – FR-SES-14).
//!
//! The spawner keeps each line's group with its session's, as the real one does, and holds the line running until
//! the test releases it, so a pause can be observed on a running line.

use std::sync::Mutex;
use std::sync::mpsc::{Receiver, Sender, channel};
use std::thread::{self, JoinHandle};

use knsh_core::{
    AgentId, AskAnswer, AskReply, AskRequest, DecisionVerdict, Delivery, EventScope, NoAuthority, NoHooks,
    SessionState, StillWaiting,
};
use knsh_json::Value;
use knsh_platform::testing::{FakeClock, Script, ScriptedProcesses, SeededRandom};
use knsh_platform::{Signal, SpawnRequest};
use knsh_store::{PageSize, RecordQuery, Scope};

use super::tests::{WEB, filesystem, forwarded};
use knsh_core::ProfileName;

use super::*;
use crate::events::Subscriber;
use crate::holds::GroupKind;
use crate::sessions::StateChange;
use crate::sessions::tests::{Fixture, fixture};

/// The program every scripted group runs.
const PROGRAM: &str = "/knsh/bin/knsh-exec";

/// A spawner over scripted groups: each line's group is kept with its session's, reported on `running`, and left
/// running until a message on `release`; then it is killed, forgotten and reaped, in that order.
struct GroupSpawner {
    processes: Arc<ScriptedProcesses>,
    running: Mutex<Sender<ProcessGroupId>>,
    release: Mutex<Receiver<()>>,
}

impl Spawner for GroupSpawner {
    fn spawn(&self, _plan: SpawnPlan, events: &dyn LineEvents) -> SpawnReport {
        self.processes.expect(PROGRAM, Script::RunsUntilSignalled);
        let group = self.processes.spawn(&SpawnRequest::new(PROGRAM)).unwrap();
        let kept = events.keep(group, self.processes.clone());
        events.started();
        self.running.lock().unwrap().send(group).unwrap();
        self.release.lock().unwrap().recv().unwrap();
        self.processes.signal(group, Signal::Kill).unwrap();
        drop(kept);
        self.processes.wait(group).unwrap();
        SpawnReport {
            sandbox_profile: None,
            outcome: Ok(Ran {
                status: LineStatus::Exited(0),
                timed_out: false,
            }),
            output: None,
            network: Vec::new(),
        }
    }
}

/// An authority that pauses the session while it is asked, then allows the line.
struct PausingAuthority {
    sessions: Arc<Sessions>,
    session_id: SessionId,
}

impl Authority for PausingAuthority {
    fn connected(&self) -> bool {
        true
    }

    fn ask(&self, _request: &AskRequest<'_>, _caller: &dyn Caller) -> AskAnswer {
        self.sessions.change_state(self.session_id, StateChange::Pause).unwrap();
        AskAnswer {
            request_id: None,
            reply: AskReply::Allow,
            decided_by: None,
        }
    }
}

/// A live agent session on profile `web` with an orchestrator over [`GroupSpawner`].
struct Daemon {
    fixture: Fixture,
    session_id: SessionId,
    processes: Arc<ScriptedProcesses>,
    lifecycle: Arc<Lifecycle>,
    running: Receiver<ProcessGroupId>,
    release: Sender<()>,
    subscriber: Subscriber,
}

impl Daemon {
    fn new() -> Self {
        Self::with_authority(|_, _| Arc::new(NoAuthority))
    }

    fn with_authority(authority: impl FnOnce(&Arc<Sessions>, SessionId) -> Arc<dyn Authority + Send + Sync>) -> Self {
        let fixture = fixture();
        let session_id = fixture
            .sessions
            .open_agent(
                Actor::Agent(AgentId::new("claude-code").unwrap()),
                ProfileName::new("web").unwrap(),
            )
            .unwrap()
            .session_id;
        let subscriber = Subscriber::new();
        subscriber
            .subscribe(&fixture.hub, EventScope::Session(session_id), None)
            .unwrap();
        let processes = Arc::new(ScriptedProcesses::new());
        let (running_tx, running) = channel();
        let (release, release_rx) = channel();
        let lifecycle = Lifecycle::new(Parts {
            sessions: Arc::clone(&fixture.sessions),
            profiles: crate::policy::tests::loader(filesystem(&[("web", WEB)])),
            events: Arc::clone(&fixture.hub),
            store: Some(fixture.store.clone()),
            clock: Arc::new(FakeClock::new(
                Timestamp::from_unix_micros(1_800_000_000_000_000).unwrap(),
            )),
            random: Arc::new(SeededRandom::new(5)),
            hooks: Arc::new(NoHooks),
            authority: authority(&fixture.sessions, session_id),
            approvals: crate::approvals::tests::unanswered(Duration::from_millis(50)),
            spawner: Arc::new(GroupSpawner {
                processes: processes.clone(),
                running: Mutex::new(running_tx),
                release: Mutex::new(release_rx),
            }),
            redaction: Arc::new(knsh_core::NoOutputRedaction),
        });
        Self {
            fixture,
            session_id,
            processes,
            lifecycle,
            running,
            release,
            subscriber,
        }
    }

    /// Runs `command` on a thread; returns once its group is running, with that group.
    fn start(&self, command: &str) -> (JoinHandle<Result<Finished, RpcError>>, ProcessGroupId) {
        let lifecycle = Arc::clone(&self.lifecycle);
        let line = forwarded(self.session_id, command);
        let handle = thread::spawn(move || lifecycle.run(line, &StillWaiting));
        let group = self.running.recv_timeout(Duration::from_secs(10)).unwrap();
        (handle, group)
    }

    /// Runs `command`, expected to be spawned, to its end, releasing it as soon as it runs.
    fn run(&self, command: &str) -> Result<Finished, RpcError> {
        let (handle, _group) = self.start(command);
        self.release.send(()).unwrap();
        handle.join().unwrap()
    }

    /// An envelope group, kept with the session's groups as `session.start_agent` will keep it (KNSH-056).
    fn envelope(&self) -> (ProcessGroupId, Kept) {
        self.processes.expect(PROGRAM, Script::RunsUntilSignalled);
        let group = self.processes.spawn(&SpawnRequest::new(PROGRAM)).unwrap();
        let kept =
            self.fixture
                .sessions
                .keep_group(self.session_id, group, self.processes.clone(), GroupKind::Envelope);
        (group, kept)
    }

    fn change(&self, change: StateChange) -> Result<SessionState, RpcError> {
        self.fixture.sessions.change_state(self.session_id, change)
    }

    /// The session's `session.state_changed` events since the last call, as `(from, to)`.
    fn state_changes(&self) -> Vec<(SessionState, SessionState)> {
        self.subscriber
            .take(usize::MAX)
            .into_iter()
            .filter_map(|(_, delivery)| match delivery {
                Delivery::Event(event) => match event.data {
                    EventData::SessionStateChanged { from, to } => Some((from, to)),
                    _ => None,
                },
                Delivery::Lost(_) => None,
            })
            .collect()
    }

    fn records(&self) -> Vec<ExecutionRecord> {
        let query = RecordQuery {
            session: Some(self.session_id),
            since: None,
            until: None,
            text: None,
            after: None,
            limit: PageSize::new(100).unwrap(),
        };
        let page = self.fixture.store.query(Scope::All, query).unwrap();
        page.records.into_iter().map(|stored| stored.record).collect()
    }
}

/// Asserts `error` is `-32007` with `data.state` = `state`.
fn assert_held(error: &RpcError, state: &str) {
    assert_eq!(error.code, ErrorCode::SessionHeld, "{error:?}");
    let data = error.data.as_ref().and_then(Value::as_object).unwrap();
    assert_eq!(data.get("state"), Some(&Value::from(state)));
}

// FR-SES-10: a pause sends SIGSTOP to the envelope's group and to every running line's group, through the handles
// kept for them; nothing else is signalled.
#[test]
fn pause_stops_envelope_and_running_groups() {
    let daemon = Daemon::new();
    let (envelope, _kept) = daemon.envelope();
    let (first, first_group) = daemon.start("ls");
    let (second, second_group) = daemon.start("echo hi");

    assert_eq!(daemon.change(StateChange::Pause), Ok(SessionState::Paused));
    assert_eq!(
        daemon.processes.signals(),
        [
            (envelope, Signal::Stop),
            (first_group, Signal::Stop),
            (second_group, Signal::Stop),
        ]
    );

    daemon.release.send(()).unwrap();
    daemon.release.send(()).unwrap();
    first.join().unwrap().unwrap();
    second.join().unwrap().unwrap();
}

// FR-SES-10: a resume sends SIGCONT to the same groups the pause stopped (lines first, then the envelope); a line that
// ended while paused was forgotten before it was reaped and is not signalled again.
#[test]
fn resume_continues_same_groups() {
    let daemon = Daemon::new();
    let (envelope, _kept) = daemon.envelope();
    let (first, first_group) = daemon.start("ls");
    let (second, second_group) = daemon.start("echo hi");
    daemon.change(StateChange::Pause).unwrap();

    // The first line ends (killed, as `exec.kill` would) while the session is paused.
    daemon.release.send(()).unwrap();
    let ended = first.join().unwrap().unwrap();
    let before = daemon.processes.signals().len();

    assert_eq!(daemon.change(StateChange::Resume), Ok(SessionState::Active));
    let signals = daemon.processes.signals();
    let ended_kill = (first_group, Signal::Kill);
    assert!(signals[..before].contains(&ended_kill));
    assert_eq!(
        signals[before..],
        [(second_group, Signal::Continue), (envelope, Signal::Continue)]
    );
    assert!(ended.record_id.is_some());

    daemon.release.send(()).unwrap();
    second.join().unwrap().unwrap();
}

// FR-SES-10: while paused, a new line is answered -32007 with `data.state` at once: nothing is decided, spawned or
// recorded. After the resume the same line runs.
#[test]
fn holds_new_lines_with_32007_while_paused() {
    let daemon = Daemon::new();
    daemon.change(StateChange::Pause).unwrap();

    let error = daemon
        .lifecycle
        .run(forwarded(daemon.session_id, "ls"), &StillWaiting)
        .unwrap_err();
    assert_held(&error, "paused");
    assert_eq!(daemon.processes.spawned().len(), 0);
    assert!(daemon.records().is_empty());

    daemon.change(StateChange::Resume).unwrap();
    let finished = daemon.run("ls").unwrap();
    assert_eq!(finished.status, LineStatus::Exited(0));
    assert_eq!(daemon.records().len(), 1);
}

// FR-SES-12: under human control the agent's lines are held (-32007, `human_control`) until control is handed back;
// running lines are not stopped, and the session stays the agent's: nothing it sends is treated as human.
#[test]
fn holds_lines_under_human_control() {
    let daemon = Daemon::new();
    let (_envelope, _kept) = daemon.envelope();
    let (running, _group) = daemon.start("ls");

    assert_eq!(daemon.change(StateChange::TakeControl), Ok(SessionState::HumanControl));
    assert_eq!(daemon.processes.signals(), [], "human control stops nothing");
    let error = daemon
        .lifecycle
        .run(forwarded(daemon.session_id, "echo hi"), &StillWaiting)
        .unwrap_err();
    assert_held(&error, "human_control");
    let (actor, _) = daemon.fixture.sessions.agent_of(daemon.session_id).unwrap();
    assert!(matches!(actor, Actor::Agent(_)));

    daemon.release.send(()).unwrap();
    running.join().unwrap().unwrap();
    // Only the line that was already running was recorded, as the agent's.
    let records = daemon.records();
    assert_eq!(records.len(), 1);
    assert!(matches!(records[0].actor, Actor::Agent(_)));

    daemon.change(StateChange::HandBack).unwrap();
    assert!(daemon.run("echo hi").is_ok());
}

// FR-SES-14: every transition, including the end, publishes `session.state_changed` with its `from` and `to`.
#[test]
fn emits_state_changed_on_every_transition() {
    use SessionState::{Active, Ended, HumanControl, Paused};
    let daemon = Daemon::new();
    daemon.state_changes();
    for control in [
        StateChange::Pause,
        StateChange::Resume,
        StateChange::TakeControl,
        StateChange::HandBack,
        StateChange::Pause,
    ] {
        daemon.change(control).unwrap();
    }
    daemon.fixture.sessions.end_agent(daemon.session_id);
    assert_eq!(
        daemon.state_changes(),
        [
            (Active, Paused),
            (Paused, Active),
            (Active, HumanControl),
            (HumanControl, Active),
            (Active, Paused),
            (Paused, Ended),
        ]
    );
}

// Session model: a transition the diagram does not have is -32006 naming the session, and changes nothing: no
// signal, no event, the state kept. An ended session refuses every transition with -32006.
#[test]
fn rejects_transition_from_ended_with_32006() {
    let daemon = Daemon::new();
    let (_envelope, _kept) = daemon.envelope();
    daemon.change(StateChange::Pause).unwrap();
    daemon.state_changes();
    let signals = daemon.processes.signals();

    for control in [StateChange::Pause, StateChange::TakeControl, StateChange::HandBack] {
        let error = daemon.change(control).unwrap_err();
        assert_eq!(error.code, ErrorCode::SessionNotFound, "{control:?}");
        let data = error.data.as_ref().and_then(Value::as_object).unwrap();
        assert_eq!(
            data.get("session_id"),
            Some(&Value::from(daemon.session_id.to_string()))
        );
    }
    assert_eq!(daemon.processes.signals(), signals);
    assert_eq!(daemon.state_changes(), []);
    assert_held(
        &daemon
            .lifecycle
            .run(forwarded(daemon.session_id, "ls"), &StillWaiting)
            .unwrap_err(),
        "paused",
    );

    // Ending a paused session continues its groups, so nothing stays stopped once it is gone.
    daemon.fixture.sessions.end_agent(daemon.session_id);
    assert_eq!(
        daemon.processes.signals().last().map(|(_, signal)| *signal),
        Some(Signal::Continue)
    );
    for control in [
        StateChange::Pause,
        StateChange::Resume,
        StateChange::TakeControl,
        StateChange::HandBack,
    ] {
        assert_eq!(
            daemon.change(control).unwrap_err().code,
            ErrorCode::SessionNotFound,
            "{control:?}"
        );
    }
    let error = daemon
        .lifecycle
        .run(forwarded(daemon.session_id, "ls"), &StillWaiting)
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::SessionNotFound);
}

// FR-SES-10: a session paused while its line was being decided (an ask) holds the line once allowed: it is not
// spawned, its decision is recorded as a deny, and the caller gets -32007 so it retries.
#[test]
fn holds_line_paused_during_its_decision() {
    let daemon = Daemon::with_authority(|sessions, session_id| {
        Arc::new(PausingAuthority {
            sessions: Arc::clone(sessions),
            session_id,
        })
    });
    let error = daemon
        .lifecycle
        .run(forwarded(daemon.session_id, "git push"), &StillWaiting)
        .unwrap_err();
    assert_held(&error, "paused");
    assert_eq!(daemon.processes.spawned().len(), 0);
    let records = daemon.records();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].exit_code, None);
    let decision = records[0].details.decision.clone().unwrap();
    assert_eq!(decision.verdict, DecisionVerdict::Deny);
}
