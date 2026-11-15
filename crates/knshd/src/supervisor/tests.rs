//! The orchestrator with fake hooks, authority and spawner, over a real record store and event hub (KNSH-050).

use std::path::Path;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use knsh_core::{
    DecisionVerdict, Delivery, EventScope, HookOutcome, HookVerdict, NoAuthority, NoHooks, RecordDecision, StillWaiting,
};
use knsh_json::Value;
use knsh_platform::testing::{FakeClock, MemFs, SeededRandom};
use knsh_platform::{EnginePaths, Fs};
use knsh_proto::Interpreter;
use knsh_store::{PageSize, RecordQuery, Scope};

use super::*;
use crate::events::Subscriber;
use crate::sessions::tests::{Fixture, fixture};

const HOME: &str = "/Users/u";
const PROJECT: &str = "/Users/u/app";

/// `git status`, `ls`, `echo` allowed; `git push` asked; `rm` denied.
pub(super) const WEB: &str = "name = \"web\"\n[exec]\nallow = [\"git status\", \"ls\", \"echo\"]\nask = [\"git push\"]\n\
                   deny = [\"rm\"]\n";

pub(super) fn filesystem(profiles: &[(&str, &str)]) -> MemFs {
    let fs = MemFs::new();
    for dir in ["/usr/bin", "/bin", "/tmp", PROJECT] {
        fs.add_dir_all(Path::new(dir)).unwrap();
    }
    let policies = EnginePaths::for_home(Path::new(HOME)).unwrap().policies_dir();
    fs.add_dir_all(&policies).unwrap();
    for binary in ["/usr/bin/git", "/bin/ls", "/bin/echo", "/bin/rm", "/bin/bash"] {
        fs.write(Path::new(binary), b"#!/bin/sh\n", 0o755).unwrap();
    }
    for (name, text) in profiles {
        fs.write(&policies.join(format!("{name}.toml")), text.as_bytes(), 0o600)
            .unwrap();
    }
    fs
}

/// What happened, in order, across fakes.
#[derive(Default)]
pub(super) struct Journal(Mutex<Vec<String>>);

impl Journal {
    pub(super) fn push(&self, entry: impl Into<String>) {
        self.0.lock().unwrap().push(entry.into());
    }

    pub(super) fn entries(&self) -> Vec<String> {
        self.0.lock().unwrap().clone()
    }
}

/// Hooks answering from a script, `allow` once it runs out; each run also notes how many `command.proposed`
/// events its session's subscriber had received by then.
pub(super) struct FakeHooks {
    pub(super) journal: Arc<Journal>,
    pub(super) script: Mutex<Vec<HookVerdict>>,
    pub(super) seen: Option<Arc<Subscriber>>,
}

impl Hooks for FakeHooks {
    fn run(&self, proposal: &Proposal<'_>) -> HookOutcome {
        let proposed = self.seen.as_ref().map_or(0, |subscriber| {
            subscriber
                .take(usize::MAX)
                .iter()
                .filter(
                    |(_, delivery)| matches!(delivery, Delivery::Event(event) if event.name() == "command.proposed"),
                )
                .count()
        });
        self.journal
            .push(format!("hooks {} after {proposed} proposed", proposal.command.expose()));
        let mut script = self.script.lock().unwrap();
        let verdict = if script.is_empty() {
            HookVerdict::Allow
        } else {
            script.remove(0)
        };
        let hook = (verdict != HookVerdict::Allow).then(|| "guard".to_owned());
        HookOutcome { verdict, hook }
    }
}

/// An authority answering from a script; it advances the clock by 25 ms per ask, as a person would take time.
pub(super) struct FakeAuthority {
    pub(super) journal: Arc<Journal>,
    pub(super) clock: Arc<FakeClock>,
    pub(super) script: Mutex<Vec<AskReply>>,
}

impl Authority for FakeAuthority {
    fn connected(&self) -> bool {
        true
    }

    fn ask(&self, request: &AskRequest<'_>, _caller: &dyn Caller) -> AskAnswer {
        self.journal.push(format!("ask {}", request.proposal.command.expose()));
        self.clock.advance(Duration::from_millis(25));
        AskAnswer {
            request_id: Some(RequestId::from_ulid(Ulid::from_u128(77))),
            reply: self.script.lock().unwrap().remove(0),
            decided_by: Some("Example Authority".to_owned()),
        }
    }
}

/// A spawner that records each plan and ends every line with a set outcome.
pub(super) struct FakeSpawner {
    pub(super) journal: Arc<Journal>,
    /// How each spawn ends; it publishes `command.started` unless the line never started.
    pub(super) outcome: Result<Ran, SpawnFailure>,
    /// Whether it also reports a long run.
    pub(super) long_running: bool,
}

impl FakeSpawner {
    /// A spawner whose lines exit 0.
    pub(super) fn new(journal: Arc<Journal>) -> Self {
        Self {
            journal,
            outcome: Ok(Ran {
                status: LineStatus::Exited(0),
                timed_out: false,
            }),
            long_running: false,
        }
    }
}

impl Spawner for FakeSpawner {
    fn spawn(&self, plan: SpawnPlan, events: &dyn LineEvents) -> SpawnReport {
        self.journal.push(format!(
            "spawn {} as {}",
            plan.allowed.executed,
            plan.line.interpreter.as_str()
        ));
        // The line's sandbox rules are tagged with the record it is written to (FR-SBX-06).
        self.journal.push(format!("record {}", plan.record_id));
        if !matches!(
            self.outcome,
            Err(SpawnFailure::ProfileFile | SpawnFailure::Trampoline(_))
        ) {
            events.started();
            if self.long_running {
                events.long_running();
            }
        }
        SpawnReport {
            sandbox_profile: Some(format!("{}@0123456789abcdef", plan.profile.name)),
            outcome: self.outcome,
        }
    }
}

/// A caller that goes away after `checks` liveness checks.
pub(super) struct LeavingCaller(pub(super) AtomicUsize);

impl Caller for LeavingCaller {
    fn gone(&self) -> bool {
        self.0
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |left| left.checked_sub(1))
            .is_err()
    }
}

/// An orchestrator over a fresh fixture with an open agent session on profile `web`.
struct Daemon {
    fixture: Fixture,
    session_id: SessionId,
    journal: Arc<Journal>,
    clock: Arc<FakeClock>,
    /// Shared by every orchestrator of the test: record IDs from a frozen clock differ only by their random part.
    random: Arc<SeededRandom>,
    subscriber: Arc<Subscriber>,
}

/// What to fake.
#[derive(Default)]
struct Setup {
    hooks: Vec<HookVerdict>,
    authority: Option<Vec<AskReply>>,
    approvals_timeout: Option<Duration>,
    no_store: bool,
    profiles: Option<Vec<(&'static str, &'static str)>>,
    /// The hooks count the `command.proposed` events delivered so far (and so take them off the subscriber).
    hooks_observe: bool,
    /// The spawner; one whose lines exit 0 by default.
    spawner: Option<FakeSpawner>,
}

impl Daemon {
    fn new() -> Self {
        let fixture = fixture();
        let opened = fixture
            .sessions
            .open_agent(
                Actor::Agent(knsh_core::AgentId::new("claude-code").unwrap()),
                ProfileName::new("web").unwrap(),
            )
            .unwrap();
        let subscriber = Arc::new(Subscriber::new());
        subscriber
            .subscribe(&fixture.hub, EventScope::Session(opened.session_id), None)
            .unwrap();
        Self {
            fixture,
            session_id: opened.session_id,
            journal: Arc::new(Journal::default()),
            clock: Arc::new(FakeClock::new(
                Timestamp::from_unix_micros(1_800_000_000_000_000).unwrap(),
            )),
            random: Arc::new(SeededRandom::new(11)),
            subscriber,
        }
    }

    fn lifecycle(&self, setup: Setup) -> Arc<Lifecycle> {
        let profiles = setup.profiles.unwrap_or_else(|| vec![("web", WEB)]);
        let authority: Arc<dyn Authority + Send + Sync> = match setup.authority {
            Some(script) => Arc::new(FakeAuthority {
                journal: Arc::clone(&self.journal),
                clock: Arc::clone(&self.clock),
                script: Mutex::new(script),
            }),
            None => Arc::new(NoAuthority),
        };
        let hooks: Arc<dyn Hooks + Send + Sync> = Arc::new(FakeHooks {
            journal: Arc::clone(&self.journal),
            script: Mutex::new(setup.hooks),
            seen: setup.hooks_observe.then(|| Arc::clone(&self.subscriber)),
        });
        Lifecycle::new(Parts {
            sessions: Arc::clone(&self.fixture.sessions),
            profiles: crate::policy::tests::loader(filesystem(&profiles)),
            events: Arc::clone(&self.fixture.hub),
            store: (!setup.no_store).then(|| self.fixture.store.clone()),
            clock: self.clock.clone(),
            random: self.random.clone(),
            hooks,
            authority,
            approvals: Arc::new(DenyAtTimeout {
                timeout: setup.approvals_timeout.unwrap_or(Duration::from_millis(50)),
            }),
            spawner: Arc::new(
                setup
                    .spawner
                    .unwrap_or_else(|| FakeSpawner::new(Arc::clone(&self.journal))),
            ),
        })
    }

    fn line(&self, command: &str) -> ForwardedLine {
        forwarded(self.session_id, command)
    }

    /// The names of the session's events since the last call, and the events themselves.
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

/// A line forwarded by `knsh -c` for `session_id`, with captured output.
pub(super) fn forwarded(session_id: SessionId, command: &str) -> ForwardedLine {
    ForwardedLine {
        session_id,
        proposal: crate::exec::Proposal {
            command: command.to_owned(),
            cwd: CanonicalPath::new(PROJECT).unwrap(),
            path: "/usr/bin:/bin".to_owned(),
        },
        interpreter: Interpreter::Bash,
        args: Vec::new(),
        env: Vec::new(),
        stdio: None,
        timeout_s: None,
    }
}

fn names(events: &[Arc<knsh_core::Event>]) -> Vec<&'static str> {
    events.iter().map(|event| event.name()).collect()
}

fn data_field(error: &RpcError, name: &str) -> Option<Value> {
    error.data.as_ref()?.as_object()?.get(name).cloned()
}

// FR-LC-09, FR-LC-30: nothing is spawned unless the final verdict is allow; an allowed line is spawned once, as its
// re-serialised form, with the interpreter it asked for.
#[test]
fn never_spawns_before_final_allow() {
    let daemon = Daemon::new();
    let refusals: Vec<(Setup, &str)> = vec![
        (Setup::default(), "rm -rf build"),
        (
            Setup {
                authority: Some(vec![AskReply::Deny { reason: None }]),
                ..Setup::default()
            },
            "git push",
        ),
        (Setup::default(), "git push"),
        (
            Setup {
                hooks: vec![HookVerdict::Failed],
                ..Setup::default()
            },
            "ls",
        ),
    ];
    for (setup, line) in refusals {
        let lifecycle = daemon.lifecycle(setup);
        assert!(lifecycle.run(daemon.line(line), &StillWaiting).is_err(), "{line}");
    }
    assert_eq!(daemon.spawns(), Vec::<String>::new(), "{:?}", daemon.journal.entries());

    let finished = daemon
        .lifecycle(Setup::default())
        .run(daemon.line("git status && ls"), &StillWaiting)
        .unwrap();
    assert_eq!(finished.status, LineStatus::Exited(0));
    assert_eq!(daemon.spawns(), ["spawn /usr/bin/git status && /bin/ls as bash"]);
    let record_id = finished.record_id.unwrap();
    assert!(daemon.journal.entries().contains(&format!("record {record_id}")));
    let records = daemon.records();
    let record = records.iter().find(|record| record.record_id == record_id).unwrap();
    assert_eq!(record.exit_code, Some(0));
    assert_eq!(record.command.expose(), "git status && ls");
}

// FR-LC-07: `command.proposed` is published once for the line, before its hooks run, and before any other lifecycle
// event of the line.
#[test]
fn emits_command_proposed_before_hooks() {
    let daemon = Daemon::new();
    daemon.events();
    daemon
        .lifecycle(Setup {
            hooks_observe: true,
            ..Setup::default()
        })
        .run(daemon.line("ls"), &StillWaiting)
        .unwrap();
    assert!(
        daemon
            .journal
            .entries()
            .contains(&"hooks ls after 1 proposed".to_owned()),
        "{:?}",
        daemon.journal.entries()
    );
    // The hook took the proposed event off the subscriber; the rest of the line's events follow it.
    assert_eq!(names(&daemon.events()), ["command.started", "command.finished"]);
}

// FR-LC-32, FR-REC-03, FR-LC-31: a denial is recorded with its decision and without output, `command.denied` names
// the record and the rule, and the answer is -32001 with the rule, reason and source the client prints.
#[test]
fn denial_writes_record_and_event() {
    let daemon = Daemon::new();
    daemon.events();
    let error = daemon
        .lifecycle(Setup::default())
        .run(daemon.line("ls && rm -rf build"), &StillWaiting)
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::Denied);
    let denial = Denial::from_error(&error).unwrap();
    assert_eq!(denial.rule_id.as_deref(), Some("exec.deny[0]"));
    assert_eq!(denial.source.as_deref(), Some("rule"));

    let [record] = <[ExecutionRecord; 1]>::try_from(daemon.records()).unwrap();
    assert_eq!(record.command.expose(), "ls && rm -rf build");
    assert_eq!(record.exit_code, None);
    let decision = record.details.decision.clone().unwrap();
    assert_eq!(decision.verdict, DecisionVerdict::Deny);
    assert_eq!(decision.source, DecisionSource::Rule);
    assert_eq!(decision.rule_id.as_deref(), Some("exec.deny[0]"));

    let events = daemon.events();
    assert_eq!(names(&events), ["command.proposed", "command.denied"]);
    let EventData::CommandDenied {
        record_id,
        source,
        rule_id,
        ..
    } = &events[1].data
    else {
        panic!("{:?}", events[1]);
    };
    assert_eq!(*record_id, Some(record.record_id));
    assert_eq!(*source, DecisionSource::Rule);
    assert_eq!(
        rule_id.as_ref().map(|rule| rule.expose().as_str()),
        Some("exec.deny[0]")
    );
    assert_eq!(daemon.spawns(), Vec::<String>::new());
}

// Record model: the record's decision object is the pipeline's decision, with the latency measured on the clock.
#[test]
fn decision_source_matches_deciding_component() {
    let daemon = Daemon::new();
    let lifecycle = daemon.lifecycle(Setup {
        authority: Some(vec![AskReply::Allow]),
        ..Setup::default()
    });
    lifecycle
        .run(daemon.line("git push origin main"), &StillWaiting)
        .unwrap();
    let record = daemon.records().pop().unwrap();
    assert_eq!(
        record.details.decision,
        Some(RecordDecision {
            verdict: DecisionVerdict::Allow,
            source: DecisionSource::Authority,
            rule_id: Some("exec.ask[0]".to_owned()),
            decided_by: Some("Example Authority".to_owned()),
            latency_ms: 25,
        })
    );

    let lifecycle = daemon.lifecycle(Setup {
        hooks: vec![HookVerdict::Deny {
            reason: Some("not today".to_owned()),
        }],
        ..Setup::default()
    });
    let error = lifecycle.run(daemon.line("ls"), &StillWaiting).unwrap_err();
    assert_eq!(Denial::from_error(&error).unwrap().source.as_deref(), Some("hook"));
    assert_eq!(Denial::from_error(&error).unwrap().reason.as_deref(), Some("not today"));
    let decision = daemon.records().pop().unwrap().details.decision.unwrap();
    assert_eq!(
        (decision.source, decision.decided_by.as_deref()),
        (DecisionSource::Hook, Some("guard"))
    );
}

// FR-LC-11, FR-REC-04, FR-AUTH-31: a rewrite runs the new line, which the record holds with the original; a second
// rewrite is a deny.
#[test]
fn reevaluates_rewritten_line_once() {
    let daemon = Daemon::new();
    daemon.events();
    let lifecycle = daemon.lifecycle(Setup {
        authority: Some(vec![AskReply::Rewrite {
            command: "git status".to_owned(),
        }]),
        ..Setup::default()
    });
    lifecycle.run(daemon.line("git push --force"), &StillWaiting).unwrap();
    assert_eq!(daemon.spawns(), ["spawn /usr/bin/git status as bash"]);
    let record = daemon.records().pop().unwrap();
    assert_eq!(record.command.expose(), "git status");
    assert_eq!(
        record
            .details
            .rewritten_from
            .as_ref()
            .map(|text| text.expose().as_str()),
        Some("git push --force")
    );
    assert_eq!(record.details.decision.unwrap().verdict, DecisionVerdict::Rewrite);
    assert_eq!(
        names(&daemon.events()),
        [
            "command.proposed",
            "command.proposed",
            "command.started",
            "command.finished"
        ]
    );

    let lifecycle = daemon.lifecycle(Setup {
        authority: Some(vec![
            AskReply::Rewrite {
                command: "git push origin".to_owned(),
            },
            AskReply::Rewrite {
                command: "ls".to_owned(),
            },
        ]),
        ..Setup::default()
    });
    let error = lifecycle
        .run(daemon.line("git push --force"), &StillWaiting)
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::Denied);
    assert_eq!(daemon.spawns().len(), 1, "the second line was never spawned");
}

// FR-LC-10, FR-AUTH-23, standalone mode: an ask with no authority waits, then is denied at the timeout with -32002;
// `decision.cancelled` says so, and the denial is recorded as standalone.
#[test]
fn ask_without_authority_is_denied_at_the_timeout() {
    let daemon = Daemon::new();
    daemon.events();
    let error = daemon
        .lifecycle(Setup::default())
        .run(daemon.line("git push"), &StillWaiting)
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::DecisionTimeout);
    assert_eq!(data_field(&error, "request_id"), Some(Value::Null));
    let events = daemon.events();
    assert_eq!(
        names(&events),
        ["command.proposed", "decision.cancelled", "command.denied"]
    );
    assert!(matches!(
        events[1].data,
        EventData::DecisionCancelled {
            reason: CancelReason::TimedOut,
            ..
        }
    ));
    let decision = daemon.records().pop().unwrap().details.decision.unwrap();
    assert_eq!(decision.source, DecisionSource::Standalone);
    assert_eq!(decision.rule_id.as_deref(), Some("exec.ask[0]"));
    assert_eq!(daemon.spawns(), Vec::<String>::new());
}

// FR-LC-41: a caller that disconnects while the decision is pending cancels it (-32011, `decision.cancelled`), and
// the line never runs, even when the caller leaves only after the decision and before the spawn.
#[test]
fn cancels_and_skips_spawn_when_caller_disconnects() {
    let daemon = Daemon::new();
    daemon.events();
    // Waiting for a local approval that never comes: the caller leaves on the third look.
    let lifecycle = daemon.lifecycle(Setup {
        approvals_timeout: Some(Duration::from_secs(30)),
        ..Setup::default()
    });
    let started = Instant::now();
    let error = lifecycle
        .run(daemon.line("git push"), &LeavingCaller(AtomicUsize::new(2)))
        .unwrap_err();
    assert!(started.elapsed() < Duration::from_secs(10), "cancelled, not timed out");
    assert_eq!(error.code, ErrorCode::Cancelled);
    let events = daemon.events();
    assert_eq!(
        names(&events),
        ["command.proposed", "decision.cancelled", "command.denied"]
    );
    assert!(matches!(
        events[1].data,
        EventData::DecisionCancelled {
            reason: CancelReason::CallerGone,
            request_id: None
        }
    ));
    // Allowed by the rules, but the caller is gone by the driver's last look before the spawn.
    let error = daemon
        .lifecycle(Setup::default())
        .run(daemon.line("ls"), &LeavingCaller(AtomicUsize::new(1)))
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::Cancelled);
    assert_eq!(daemon.spawns(), Vec::<String>::new());
    // Both were recorded as denials.
    let records = daemon.records();
    assert_eq!(records.len(), 2);
    assert!(
        records
            .iter()
            .all(|record| record.details.decision.as_ref().unwrap().verdict == DecisionVerdict::Deny)
    );
}

// NFR-REL-07, NFR-REL-05: failures around the decision deny the line: no record store, a profile that cannot be
// loaded, a hook that fails. Nothing is spawned.
#[test]
fn denies_on_internal_error_in_any_step() {
    let daemon = Daemon::new();
    let cases = [
        (
            Setup {
                no_store: true,
                ..Setup::default()
            },
            NO_STORE,
        ),
        (
            Setup {
                profiles: Some(Vec::new()),
                ..Setup::default()
            },
            NO_PROFILE,
        ),
        (
            Setup {
                profiles: Some(vec![("web", "name = \"web\"\n[exec]\nallow = [\"ls\"\n")]),
                ..Setup::default()
            },
            NO_PROFILE,
        ),
    ];
    for (setup, reason) in cases {
        let error = daemon
            .lifecycle(setup)
            .run(daemon.line("ls"), &StillWaiting)
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::Denied);
        assert_eq!(Denial::from_error(&error).unwrap().reason.as_deref(), Some(reason));
    }
    let error = daemon
        .lifecycle(Setup {
            hooks: vec![HookVerdict::Failed],
            ..Setup::default()
        })
        .run(daemon.line("ls"), &StillWaiting)
        .unwrap_err();
    assert_eq!(Denial::from_error(&error).unwrap().source.as_deref(), Some("hook"));
    assert_eq!(daemon.spawns(), Vec::<String>::new());
    // Every denial that could be recorded was: the profile failures and the hook failure, not the missing store.
    assert_eq!(daemon.records().len(), 3);
}

// A session that ended under the call is answered as such, and nothing is recorded or run.
#[test]
fn ended_session_runs_nothing() {
    let daemon = Daemon::new();
    daemon.fixture.sessions.end_agent(daemon.session_id);
    let error = daemon
        .lifecycle(Setup::default())
        .run(daemon.line("ls"), &StillWaiting)
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::SessionNotFound);
    assert_eq!(daemon.spawns(), Vec::<String>::new());
    assert!(daemon.records().is_empty());
}

// The production defaults decide alone: with no hooks and no authority, an allowed line runs.
#[test]
fn runs_with_no_hooks_and_no_authority() {
    let daemon = Daemon::new();
    let lifecycle = Lifecycle::new(Parts {
        sessions: Arc::clone(&daemon.fixture.sessions),
        profiles: crate::policy::tests::loader(filesystem(&[("web", WEB)])),
        events: Arc::clone(&daemon.fixture.hub),
        store: Some(daemon.fixture.store.clone()),
        clock: daemon.clock.clone(),
        random: daemon.random.clone(),
        hooks: Arc::new(NoHooks),
        authority: Arc::new(NoAuthority),
        approvals: Arc::new(DenyAtTimeout::default()),
        spawner: Arc::new(FakeSpawner::new(Arc::clone(&daemon.journal))),
    });
    // `echo` is a builtin and stays as written; `ls` runs by its absolute path.
    lifecycle.run(daemon.line("echo hi; ls"), &StillWaiting).unwrap();
    assert_eq!(daemon.spawns(), ["spawn echo hi; /bin/ls as bash"]);
    assert_eq!(DenyAtTimeout::default().timeout, DEFAULT_ASK_TIMEOUT);
}

/// A daemon whose spawner ends every line with `outcome`, reporting a long run when `long_running`.
fn spawning(daemon: &Daemon, outcome: Result<Ran, SpawnFailure>, long_running: bool) -> Arc<Lifecycle> {
    daemon.lifecycle(Setup {
        spawner: Some(FakeSpawner {
            journal: Arc::clone(&daemon.journal),
            outcome,
            long_running,
        }),
        ..Setup::default()
    })
}

// FR-LC-40: a line killed at its timeout is answered -32008 carrying its `record_id`; the record holds the signal
// that ended it and no exit code, and `command.finished` follows `command.started`.
#[test]
fn kills_process_group_on_timeout_with_32008() {
    let daemon = Daemon::new();
    daemon.events();
    let killed = Ran {
        status: LineStatus::Signalled(9),
        timed_out: true,
    };
    let error = spawning(&daemon, Ok(killed), false)
        .run(daemon.line("ls"), &StillWaiting)
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::LineTimedOut);
    let record_id = data_field(&error, "record_id").unwrap();
    let [record] = <[ExecutionRecord; 1]>::try_from(daemon.records()).unwrap();
    assert_eq!(record_id.as_str(), Some(record.record_id.to_string().as_str()));
    assert_eq!(record.details.signal.as_deref(), Some("SIGKILL"));
    assert_eq!(record.exit_code, None);
    assert_eq!(record.details.sandbox_profile.as_deref(), Some("web@0123456789abcdef"));
    assert_eq!(
        names(&daemon.events()),
        ["command.proposed", "command.started", "command.finished"]
    );

    // A line that trapped SIGTERM and exited by itself after its timeout: still -32008, and the record names the
    // signal it was sent beside its exit code.
    let daemon = Daemon::new();
    let trapped = Ran {
        status: LineStatus::Exited(0),
        timed_out: true,
    };
    let error = spawning(&daemon, Ok(trapped), false)
        .run(daemon.line("ls"), &StillWaiting)
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::LineTimedOut);
    let [record] = <[ExecutionRecord; 1]>::try_from(daemon.records()).unwrap();
    assert_eq!(record.details.signal.as_deref(), Some("SIGTERM"));
    assert_eq!(record.exit_code, Some(0));
}

// FR-LC-17: `command.started` and `command.long_running` name the line's record, its redacted line and start.
#[test]
fn publishes_started_and_long_running_for_the_record() {
    let daemon = Daemon::new();
    daemon.events();
    let exited = Ran {
        status: LineStatus::Exited(0),
        timed_out: false,
    };
    let finished = spawning(&daemon, Ok(exited), true)
        .run(daemon.line("ls"), &StillWaiting)
        .unwrap();
    let events = daemon.events();
    assert_eq!(
        names(&events),
        [
            "command.proposed",
            "command.started",
            "command.long_running",
            "command.finished"
        ]
    );
    for event in &events[1..3] {
        match &event.data {
            EventData::CommandStarted { record_id, command, .. }
            | EventData::CommandLongRunning { record_id, command, .. } => {
                assert_eq!(Some(*record_id), finished.record_id);
                assert_eq!(command.expose(), "ls");
            }
            other => panic!("{other:?}"),
        }
    }
}

// NFR-REL-08: a line whose profile `knsh-exec` could not apply did not run: answered -32603, never with an exit
// code, and recorded with neither exit code nor signal.
#[test]
fn refuses_to_run_when_profile_application_fails() {
    let daemon = Daemon::new();
    daemon.events();
    let error = spawning(&daemon, Err(SpawnFailure::Trampoline(66)), false)
        .run(daemon.line("ls"), &StillWaiting)
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::InternalError);
    let [record] = <[ExecutionRecord; 1]>::try_from(daemon.records()).unwrap();
    assert_eq!(record.exit_code, None);
    assert_eq!(record.details.signal, None);
    assert_eq!(names(&daemon.events()), ["command.proposed", "command.finished"]);
}

#[test]
fn signal_names_follow_macos() {
    assert_eq!(signal_name(9), "SIGKILL");
    assert_eq!(signal_name(15), "SIGTERM");
    assert_eq!(signal_name(31), "SIGUSR2");
    assert_eq!(signal_name(64), "SIG64");
    assert_eq!(signal_name(0), "SIG0");
}
