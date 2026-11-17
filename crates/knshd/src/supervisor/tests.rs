//! The orchestrator with fake hooks, authority and spawner, over a real record store and event hub (KNSH-050).

use std::path::Path;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use knsh_core::{
    AskAnswer, AskReply, AskRequest, DecisionVerdict, Delivery, EventScope, HookOutcome, HookVerdict, NoAuthority,
    NoHooks, RecordDecision, StillWaiting,
};
use knsh_json::Value;
use knsh_platform::testing::{FakeClock, MemFs, SeededRandom};
use knsh_platform::{EnginePaths, Fs};
use knsh_proto::Interpreter;
use knsh_store::{PageSize, RecordQuery, Scope};

use knsh_core::ProfileName;

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
    for binary in [
        "/usr/bin/git",
        "/usr/bin/env",
        "/bin/ls",
        "/bin/echo",
        "/bin/rm",
        "/bin/bash",
    ] {
        fs.write(Path::new(binary), b"#!/bin/sh\n", 0o755).unwrap();
    }
    // An agent-writable binary: a project executable (FR-POL-14).
    fs.write(&Path::new(PROJECT).join("build.sh"), b"#!/bin/sh\n", 0o755)
        .unwrap();
    for (name, text) in profiles {
        fs.write(
            &policies.join(format!("{name}.toml")),
            &crate::policy::tests::signed(name, text),
            0o600,
        )
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
        HookOutcome {
            verdict,
            hook,
            runs: Vec::new(),
        }
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
    /// What the line writes to stdout and stderr, one chunk each, when its output is captured.
    pub(super) writes: (&'static [u8], &'static [u8]),
    /// What the proxy reported for the line: the record's `network` field (KNSH-060).
    pub(super) network: Vec<knsh_core::NetworkEntry>,
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
            writes: (b"", b""),
            network: Vec::new(),
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
        // A captured line's output goes through the plan as the real readers would take it: hook, capture, sink.
        let output = plan.capture.as_ref().map(|capture| {
            self.journal
                .push(format!("capture publishing={}", capture.sink.is_some()));
            let read = |stream: OutputStream, written: &[u8]| {
                let mut kept = knsh_core::OutputCapture::new(capture.cap);
                if !written.is_empty() {
                    let chunk = capture.redaction.redact_chunk(written);
                    kept.push(chunk.expose());
                    if let Some(sink) = &capture.sink {
                        sink.chunk(stream, 0, &chunk);
                    }
                }
                kept.finish()
            };
            LineOutput {
                stdout: read(OutputStream::Stdout, self.writes.0),
                stderr: read(OutputStream::Stderr, self.writes.1),
            }
        });
        SpawnReport {
            sandbox_profile: Some(format!("{}@0123456789abcdef", plan.profile.name)),
            outcome: self.outcome,
            output,
            network: self.network.clone(),
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
    /// Standalone approvals; by default, ones nobody answers within `approvals_timeout` (KNSH-066).
    approvals: Option<Arc<crate::approvals::Approvals>>,
    no_store: bool,
    profiles: Option<Vec<(&'static str, &'static str)>>,
    /// Profile files written as given, after the signed `profiles`: unsigned or tampered files (KNSH-065).
    raw_files: Vec<(&'static str, Vec<u8>)>,
    /// The hooks count the `command.proposed` events delivered so far (and so take them off the subscriber).
    hooks_observe: bool,
    /// The spawner; one whose lines exit 0 by default.
    spawner: Option<FakeSpawner>,
    /// The output redaction hook; a pass-through by default.
    redaction: Option<Arc<dyn knsh_core::OutputRedaction>>,
    /// The live grants; none by default.
    grants: Option<Arc<crate::grants::GrantStore>>,
    /// A real authority in place of the scripted `authority` (KNSH-069).
    authority_service: Option<Arc<dyn Authority + Send + Sync>>,
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
            _ if setup.authority_service.is_some() => setup.authority_service.clone().unwrap(),
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
        let fs = filesystem(&profiles);
        let policies = EnginePaths::for_home(Path::new(HOME)).unwrap().policies_dir();
        for (name, bytes) in &setup.raw_files {
            fs.write(&policies.join(format!("{name}.toml")), bytes, 0o600).unwrap();
        }
        Lifecycle::new(Parts {
            sessions: Arc::clone(&self.fixture.sessions),
            profiles: crate::policy::tests::loader(fs),
            events: Arc::clone(&self.fixture.hub),
            store: (!setup.no_store).then(|| self.fixture.store.clone()),
            clock: self.clock.clone(),
            random: self.random.clone(),
            hooks,
            authority,
            approvals: setup.approvals.unwrap_or_else(|| {
                crate::approvals::tests::unanswered(setup.approvals_timeout.unwrap_or(Duration::from_millis(50)))
            }),
            grants: setup.grants.unwrap_or_default(),
            spawner: Arc::new(
                setup
                    .spawner
                    .unwrap_or_else(|| FakeSpawner::new(Arc::clone(&self.journal))),
            ),
            redaction: setup
                .redaction
                .unwrap_or_else(|| Arc::new(knsh_core::NoOutputRedaction)),
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
                Delivery::Lost(_) | Delivery::Engine(_) | Delivery::EngineLost(_) => None,
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
        control: crate::jobs::LineControl::new(),
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
            hooks: Vec::new(),
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
    // KNSH-066: the ask was a pending request, listed for `knsh approve`, so it has an ID.
    let Some(Value::String(request_id)) = data_field(&error, "request_id") else {
        panic!("{error:?}");
    };
    let events = daemon.events();
    assert_eq!(
        names(&events),
        ["command.proposed", "decision.cancelled", "command.denied"]
    );
    match &events[1].data {
        EventData::DecisionCancelled {
            reason: CancelReason::TimedOut,
            request_id: Some(cancelled),
        } => assert_eq!(cancelled.to_string(), request_id),
        other => panic!("{other:?}"),
    }
    let decision = daemon.records().pop().unwrap().details.decision.unwrap();
    assert_eq!(decision.source, DecisionSource::Standalone);
    assert_eq!(decision.rule_id.as_deref(), Some("exec.ask[0]"));
    assert_eq!(daemon.spawns(), Vec::<String>::new());
}

// FR-REC-03, FR-AUTH-41 (KNSH-066): without an authority, an ask answered with `knsh approve` (after the prompt)
// runs and is recorded with `decision.source = user`; one answered with `knsh deny` is refused with -32001 and
// recorded the same way, with the user's reason.
#[test]
fn records_user_as_decision_source() {
    let daemon = Daemon::new();
    let presence = Arc::new(knsh_platform::testing::ScriptedPresence::new());
    presence.approve_next();
    let approvals = crate::approvals::tests::prompting(presence.clone(), Duration::from_secs(30));
    let lifecycle = daemon.lifecycle(Setup {
        approvals: Some(Arc::clone(&approvals)),
        ..Setup::default()
    });

    let approving = crate::approvals::tests::approve_when_pending(&approvals);
    lifecycle.run(daemon.line("git push"), &StillWaiting).unwrap();
    approving.join().unwrap().unwrap();
    assert_eq!(daemon.spawns().len(), 1, "approved, so spawned");
    assert_eq!(presence.prompts().len(), 1);

    let denying = crate::approvals::tests::deny_when_pending(&approvals);
    let error = lifecycle.run(daemon.line("git push"), &StillWaiting).unwrap_err();
    denying.join().unwrap().unwrap();
    assert_eq!(error.code, ErrorCode::Denied);
    let denial = Denial::from_error(&error).unwrap();
    assert_eq!(denial.source.as_deref(), Some("user"));
    assert_eq!(denial.reason.as_deref(), Some(crate::approvals::DENIED_BY_USER));
    assert_eq!(daemon.spawns().len(), 1, "denied, so not spawned");
    assert_eq!(presence.prompts().len(), 1, "a denial needs no prompt");

    // Record IDs from the frozen clock differ only by their random part, so the two are found by verdict.
    let mut decisions: Vec<_> = daemon
        .records()
        .into_iter()
        .map(|record| record.details.decision.unwrap())
        .map(|decision| (decision.verdict, decision.source, decision.rule_id))
        .collect();
    decisions.sort_by_key(|(verdict, ..)| *verdict == DecisionVerdict::Deny);
    let rule = Some("exec.ask[0]".to_owned());
    assert_eq!(
        decisions,
        [
            (DecisionVerdict::Allow, DecisionSource::User, rule.clone()),
            (DecisionVerdict::Deny, DecisionSource::User, rule),
        ]
    );
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
            // KNSH-066: the pending request had an ID.
            request_id: Some(_)
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

// FR-POL-42 (KNSH-065): a profile file with a missing or bad signature is ignored. The line is denied with a reason
// that says so, `policy.invalid` names the profile on the session, nothing runs, and no other profile is used.
#[test]
fn ignores_file_with_bad_signature_and_emits_invalid() {
    let daemon = Daemon::new();
    // An agent-style edit: the signed file with its deny of `rm` removed, its old trailer kept.
    let signed = crate::policy::tests::signed("web", WEB);
    let tampered = String::from_utf8(signed)
        .unwrap()
        .replace("deny = [\"rm\"]", "deny = []");
    let unsigned = WEB.as_bytes().to_vec();
    for file in [tampered.into_bytes(), unsigned] {
        let error = daemon
            .lifecycle(Setup {
                raw_files: vec![("web", file)],
                ..Setup::default()
            })
            .run(daemon.line("rm -rf build"), &StillWaiting)
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::Denied);
        assert_eq!(
            Denial::from_error(&error).unwrap().reason.as_deref(),
            Some(INVALID_PROFILE)
        );
        let events = daemon.events();
        let invalid: Vec<_> = events
            .iter()
            .filter_map(|event| match &event.data {
                EventData::PolicyInvalid { profile } => Some(profile.as_str().to_owned()),
                _ => None,
            })
            .collect();
        assert_eq!(invalid, ["web"]);
    }
    assert_eq!(daemon.spawns(), Vec::<String>::new());
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
        approvals: crate::approvals::tests::unanswered(DEFAULT_ASK_TIMEOUT),
        grants: crate::grants::GrantStore::new(),
        spawner: Arc::new(FakeSpawner::new(Arc::clone(&daemon.journal))),
        redaction: Arc::new(knsh_core::NoOutputRedaction),
    });
    // `echo` is a builtin and stays as written; `ls` runs by its absolute path.
    lifecycle.run(daemon.line("echo hi; ls"), &StillWaiting).unwrap();
    assert_eq!(daemon.spawns(), ["spawn echo hi; /bin/ls as bash"]);
}

/// A daemon whose spawner ends every line with `outcome`, reporting a long run when `long_running`.
fn spawning(daemon: &Daemon, outcome: Result<Ran, SpawnFailure>, long_running: bool) -> Arc<Lifecycle> {
    daemon.lifecycle(Setup {
        spawner: Some(FakeSpawner {
            journal: Arc::clone(&daemon.journal),
            outcome,
            long_running,
            writes: (b"", b""),
            network: Vec::new(),
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

// ---- KNSH-052: agent execution records ----

/// `WEB` with command and output recording off.
const WEB_UNRECORDED: &str = "name = \"web\"\n[exec]\nallow = [\"git status\", \"ls\", \"echo\"]\nask = [\"git push\"]\n\
                              deny = [\"rm\"]\n[recording]\ncommands = false\noutput = false\n";

impl Daemon {
    /// Runs `line` one millisecond after the previous one, so record IDs (and so `records()`) follow the order the
    /// lines were run in: the last record is the last line's.
    fn next(&self, setup: Setup, line: &str) -> Result<Finished, RpcError> {
        self.clock.advance(Duration::from_millis(1));
        self.lifecycle(setup).run(self.line(line), &StillWaiting)
    }

    /// The session's records as the store holds them, with what was kept of their output.
    fn stored(&self) -> Vec<knsh_store::StoredRecord> {
        self.fixture
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
            .unwrap()
            .records
    }
}

/// `(name, path, class, reason, wrapper)` of one `argv` entry.
type ArgvSummary = (
    Option<String>,
    Option<String>,
    &'static str,
    Option<String>,
    Option<usize>,
);

/// The summary of each `argv` entry of `record`.
fn argv(record: &ExecutionRecord) -> Vec<ArgvSummary> {
    record
        .details
        .argv
        .iter()
        .map(|entry| {
            (
                entry.name.as_ref().map(|name| name.expose().clone()),
                entry.path.clone(),
                entry.class.code(),
                entry.class.reason().map(str::to_owned),
                entry.wrapper,
            )
        })
        .collect()
}

// FR-REC-01: every line that reaches lifecycle step 2 produces exactly one record, whether it ran, was denied by a
// rule or a hook, timed out waiting for an answer, was rewritten, or did not run to its end.
#[test]
fn writes_one_record_per_line_reaching_parse() {
    let daemon = Daemon::new();
    let mut answered = 0;
    let mut run = |setup: Setup, line: &str| {
        let _ = daemon.next(setup, line);
        answered += 1;
    };
    run(Setup::default(), "ls");
    run(Setup::default(), "rm -rf build");
    run(Setup::default(), "git push");
    run(
        Setup {
            hooks: vec![HookVerdict::Failed],
            ..Setup::default()
        },
        "ls",
    );
    run(
        Setup {
            authority: Some(vec![AskReply::Rewrite {
                command: "git status".to_owned(),
            }]),
            ..Setup::default()
        },
        "git push",
    );
    run(
        Setup {
            spawner: Some(FakeSpawner {
                journal: Arc::clone(&daemon.journal),
                outcome: Err(SpawnFailure::Trampoline(66)),
                long_running: false,
                writes: (b"", b""),
                network: Vec::new(),
            }),
            ..Setup::default()
        },
        "ls",
    );
    // A line the parser cannot read still reached step 2: it is recorded (as dynamic) and denied or asked.
    run(Setup::default(), "echo 'unterminated");
    let records = daemon.records();
    assert_eq!(records.len(), answered, "one record per line");
    let mut ids: Vec<_> = records.iter().map(|record| record.record_id).collect();
    ids.dedup();
    assert_eq!(ids.len(), answered, "distinct records");
    assert!(
        records.iter().all(|record| record.details.decision.is_some()),
        "every record says how it was decided"
    );
}

// FR-REC-02, NFR-REL-05: when the orchestrator answers (what `exec.run` replies with), the record is already
// committed, with the line's end, exit code and decision; the reply names exactly that record. The same holds for a
// denial, whose `command.denied` (published before the answer) names the committed record.
#[test]
fn commits_record_before_reply() {
    let daemon = Daemon::new();
    daemon.events();
    let finished = daemon.next(Setup::default(), "ls").unwrap();
    // Nothing else runs between the answer and this read: the record was written before the answer existed.
    let record_id = finished.record_id.expect("the reply names its record");
    let records = daemon.records();
    let record = records.iter().find(|record| record.record_id == record_id).unwrap();
    assert!(record.ended_at.is_some());
    assert_eq!(record.exit_code, Some(0));
    assert!(record.details.decision.is_some());

    let error = daemon.next(Setup::default(), "rm -rf build").unwrap_err();
    assert_eq!(error.code, ErrorCode::Denied);
    let denied = daemon
        .events()
        .into_iter()
        .find_map(|event| match &event.data {
            EventData::CommandDenied { record_id, .. } => Some(*record_id),
            _ => None,
        })
        .flatten()
        .expect("command.denied names the written record");
    assert!(daemon.records().iter().any(|record| record.record_id == denied));

    // A line that cannot be recorded is never run (and so never answered as run).
    let error = daemon
        .next(
            Setup {
                no_store: true,
                ..Setup::default()
            },
            "ls",
        )
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::Denied);
    assert_eq!(daemon.spawns().len(), 1, "only the first line ran");
}

// FR-REC-04: `command` is the line executed after the rewrite and `rewritten_from` the received one, for a hook's
// rewrite as for the authority's; a line that was not rewritten has no `rewritten_from`. The executed line's `argv`
// is the rewritten one's.
#[test]
fn records_rewritten_from() {
    let daemon = Daemon::new();
    daemon
        .next(
            Setup {
                hooks: vec![HookVerdict::Rewrite {
                    command: "git status".to_owned(),
                }],
                ..Setup::default()
            },
            "git push --force",
        )
        .unwrap();
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
    let decision = record.details.decision.clone().unwrap();
    assert_eq!(decision.verdict, DecisionVerdict::Rewrite);
    assert_eq!(
        decision.source,
        DecisionSource::Rule,
        "the rules allowed the rewritten line"
    );
    assert_eq!(
        argv(&record),
        [(
            Some("git".to_owned()),
            Some("/usr/bin/git".to_owned()),
            "static",
            None,
            None
        )]
    );

    daemon.next(Setup::default(), "ls").unwrap();
    assert!(daemon.records().pop().unwrap().details.rewritten_from.is_none());
}

// FR-REC-03: with command and output recording off in the profile, denials and approvals are still recorded, with
// their decision and without output.
#[test]
fn records_denial_without_output_when_recording_off() {
    let daemon = Daemon::new();
    let unrecorded = || Setup {
        profiles: Some(vec![("web", WEB_UNRECORDED)]),
        ..Setup::default()
    };
    let error = daemon.next(unrecorded(), "rm -rf build").unwrap_err();
    assert_eq!(error.code, ErrorCode::Denied);
    daemon
        .next(
            Setup {
                authority: Some(vec![AskReply::Allow]),
                ..unrecorded()
            },
            "git push",
        )
        .unwrap();

    let stored = daemon.stored();
    assert_eq!(stored.len(), 2, "the denial and the approval");
    let verdicts: Vec<_> = stored
        .iter()
        .map(|stored| {
            let decision = stored.record.details.decision.clone().unwrap();
            (decision.verdict, decision.source)
        })
        .collect();
    assert_eq!(
        verdicts,
        [
            (DecisionVerdict::Deny, DecisionSource::Rule),
            (DecisionVerdict::Allow, DecisionSource::Authority)
        ]
    );
    for stored in &stored {
        assert_eq!((stored.stdout, stored.stderr), (None, None), "no output");
    }
}

// Record model: a denied line never ran, so its exit code, signal and sandbox profile are null and it has no
// pipestatus; its start and end are still set. A line that ran has its exit code and sandbox profile, and no secret
// was injected in phase 2 (FR-REC-11).
#[test]
fn exit_code_null_for_denied_line() {
    let daemon = Daemon::new();
    daemon.next(Setup::default(), "rm -rf build").unwrap_err();
    let denied = daemon.records().pop().unwrap();
    assert_eq!(denied.exit_code, None);
    assert_eq!(denied.details.signal, None);
    assert_eq!(denied.details.sandbox_profile, None);
    assert_eq!(denied.details.pipestatus, Vec::<i32>::new());
    assert!(denied.ended_at.is_some());
    assert_eq!(denied.details.secrets_injected, Vec::<String>::new());

    let failing = FakeSpawner {
        journal: Arc::clone(&daemon.journal),
        outcome: Ok(Ran {
            status: LineStatus::Exited(3),
            timed_out: false,
        }),
        long_running: false,
        writes: (b"", b""),
        network: Vec::new(),
    };
    daemon
        .next(
            Setup {
                spawner: Some(failing),
                ..Setup::default()
            },
            "ls",
        )
        .unwrap();
    let ran = daemon.records().pop().unwrap();
    assert_eq!(ran.exit_code, Some(3));
    assert_eq!(ran.details.signal, None);
    assert_eq!(ran.details.sandbox_profile.as_deref(), Some("web@0123456789abcdef"));
    assert!(ran.ended_at.unwrap() >= ran.started_at);
    assert_eq!(ran.details.secrets_injected, Vec::<String>::new());
}

// Record model (`argv`): each simple command with its canonical path and class; a wrapper and the command it runs
// are separate entries, the inner one linked to its wrapper; a builtin has no path; a dynamic entry carries its
// reason; a binary outside the trusted folders is a project executable. Denied lines carry it too; a line the parser
// could not read is one dynamic entry with the parser's reason.
#[test]
fn argv_carries_resolved_path_and_class() {
    let daemon = Daemon::new();
    daemon.next(Setup::default(), "echo hi; env FOO=1 git status").ok();
    let record = daemon.records().pop().unwrap();
    assert_eq!(
        argv(&record),
        [
            (Some("echo".to_owned()), None, "static", None, None),
            (
                Some("env".to_owned()),
                Some("/usr/bin/env".to_owned()),
                "wrapper",
                None,
                None
            ),
            (
                Some("git".to_owned()),
                Some("/usr/bin/git".to_owned()),
                "static",
                None,
                Some(1)
            ),
        ]
    );
    assert!(record.details.argv.iter().all(|entry| entry.arguments_complete));

    daemon.next(Setup::default(), "./build.sh && eval ls").unwrap_err();
    let record = daemon.records().pop().unwrap();
    assert_eq!(record.details.decision.as_ref().unwrap().verdict, DecisionVerdict::Deny);
    let entries = argv(&record);
    assert_eq!(
        entries[0],
        (
            Some("./build.sh".to_owned()),
            Some(format!("{PROJECT}/build.sh")),
            "project_executable",
            None,
            None
        )
    );
    assert_eq!(
        entries[1],
        (Some("eval".to_owned()), None, "dynamic", Some("eval".to_owned()), None)
    );

    daemon.next(Setup::default(), "echo 'unterminated").unwrap_err();
    let record = daemon.records().pop().unwrap();
    assert_eq!(
        argv(&record),
        [(None, None, "dynamic", Some("syntax_error".to_owned()), None)]
    );
}

/// `web` that records output.
const WEB_RECORDING_OUTPUT: &str = "name = \"web\"\n[exec]\nallow = [\"git status\", \"ls\", \"echo\"]\n\
                                    ask = [\"git push\"]\n[recording]\noutput = true\n";

/// A spawner whose lines exit 0 after writing `stdout` and `stderr`.
fn writing(daemon: &Daemon, stdout: &'static [u8], stderr: &'static [u8]) -> FakeSpawner {
    FakeSpawner {
        writes: (stdout, stderr),
        ..FakeSpawner::new(Arc::clone(&daemon.journal))
    }
}

/// The stored record of the last line run, with what was kept of its output.
fn last_stored(daemon: &Daemon) -> knsh_store::StoredRecord {
    daemon.stored().pop().unwrap()
}

// FR-REC-06: with `recording.output = false` (the default), a captured line's output reaches its caller but nothing
// is stored and no `command.output` is published.
#[test]
fn stores_nothing_when_output_recording_off() {
    let daemon = Daemon::new();
    daemon.events();
    let finished = daemon
        .next(
            Setup {
                spawner: Some(writing(&daemon, b"built\n", b"warn\n")),
                ..Setup::default()
            },
            "ls",
        )
        .unwrap();
    // Captured for the caller (no passed stdio), without publishing.
    assert!(
        daemon
            .journal
            .entries()
            .contains(&"capture publishing=false".to_owned())
    );
    let output = finished.output.unwrap();
    assert_eq!(output.stdout.output.data().expose(), b"built\n");
    let stored = last_stored(&daemon);
    assert!(stored.stdout.is_none() && stored.stderr.is_none(), "nothing stored");
    assert!(!names(&daemon.events()).contains(&"command.output"));
}

// FR-LC-18: `command.output` is published (in order, per stream) only when the session records output, and the
// record keeps the output with its sizes (FR-REC-06).
#[test]
fn emits_output_events_only_when_recording() {
    let daemon = Daemon::new();
    daemon.events();
    daemon
        .next(
            Setup {
                spawner: Some(writing(&daemon, b"built\n", b"warn\n")),
                profiles: Some(vec![("web", WEB_RECORDING_OUTPUT)]),
                ..Setup::default()
            },
            "ls",
        )
        .unwrap();
    let events = daemon.events();
    assert_eq!(
        names(&events),
        [
            "command.proposed",
            "command.started",
            "command.output",
            "command.output",
            "command.finished"
        ]
    );
    let chunks: Vec<(OutputStream, Vec<u8>)> = events
        .iter()
        .filter_map(|event| match &event.data {
            EventData::CommandOutput { stream, bytes, .. } => Some((*stream, bytes.expose().clone())),
            _ => None,
        })
        .collect();
    assert_eq!(
        chunks,
        [
            (OutputStream::Stdout, b"built\n".to_vec()),
            (OutputStream::Stderr, b"warn\n".to_vec())
        ]
    );
    let stored = last_stored(&daemon);
    assert_eq!(stored.stdout.unwrap().original, 6);
    assert_eq!(stored.stderr.unwrap().stored, 5);

    // Passed descriptors in a session that does not record output: not captured at all.
    let mut line = daemon.line("ls");
    let null = || std::os::fd::OwnedFd::from(std::fs::File::open("/dev/null").unwrap());
    line.stdio = Some(crate::exec::Stdio {
        stdin: null(),
        stdout: null(),
        stderr: null(),
    });
    let before = daemon.journal.entries().len();
    let finished = daemon.lifecycle(Setup::default()).run(line, &StillWaiting).unwrap();
    assert!(finished.output.is_none());
    assert!(
        !daemon.journal.entries()[before..]
            .iter()
            .any(|entry| entry.starts_with("capture"))
    );
    assert!(!names(&daemon.events()).contains(&"command.output"));
}

// FR-EVT-07: what is stored and published is what the redaction hook returned, never the raw chunk.
#[test]
fn stores_and_emits_only_redacted_output() {
    struct Masking;
    impl knsh_core::OutputRedaction for Masking {
        fn redact_chunk(&self, chunk: &[u8]) -> Redacted<Vec<u8>> {
            Redacted::new(chunk.iter().map(|_| b'#').collect())
        }
    }
    let daemon = Daemon::new();
    daemon.events();
    let finished = daemon
        .next(
            Setup {
                spawner: Some(writing(&daemon, b"token=abc\n", b"")),
                profiles: Some(vec![("web", WEB_RECORDING_OUTPUT)]),
                redaction: Some(Arc::new(Masking)),
                ..Setup::default()
            },
            "ls",
        )
        .unwrap();
    assert_eq!(finished.output.unwrap().stdout.output.data().expose(), b"##########");
    let published = daemon.events().iter().find_map(|event| match &event.data {
        EventData::CommandOutput { bytes, .. } => Some(bytes.expose().clone()),
        _ => None,
    });
    assert_eq!(published.as_deref(), Some(&b"##########"[..]));
    let record_id = last_stored(&daemon).record.record_id;
    let range = daemon
        .fixture
        .store
        .output(
            Scope::All,
            knsh_store::OutputRequest {
                record_id,
                stream: OutputStream::Stdout,
                offset: 0,
                length: None,
            },
        )
        .unwrap();
    assert_eq!(range.data, b"##########");
}

// FR-AUTH-33: `executed_command` is the line actually spawned, after the rewrite, not the one received.
#[test]
fn returns_executed_command_after_rewrite() {
    let daemon = Daemon::new();
    let finished = daemon
        .next(
            Setup {
                authority: Some(vec![AskReply::Rewrite {
                    command: "git status".to_owned(),
                }]),
                ..Setup::default()
            },
            "git push --force",
        )
        .unwrap();
    assert_eq!(finished.executed_command.expose(), "/usr/bin/git status");
    assert_eq!(daemon.spawns(), ["spawn /usr/bin/git status as bash"]);
    assert_eq!(finished.decision.verdict, DecisionVerdict::Rewrite);
    assert_eq!(finished.default_mode, knsh_core::OutputMode::Full);
}

// FR-AUTH-33, FR-REC-04 (KNSH-070): after the authority's rewrite, the line spawned and returned by `exec.run` as
// `executed_command` is the rewritten one with its absolute paths; the record's `command` is the rewritten line and
// its `rewritten_from` the received one. The received line never runs.
#[test]
fn executed_command_reflects_rewrite() {
    let daemon = Daemon::new();
    let finished = daemon
        .next(
            Setup {
                authority: Some(vec![AskReply::Rewrite {
                    command: "ls -a".to_owned(),
                }]),
                ..Setup::default()
            },
            "git push --force",
        )
        .unwrap();
    assert_eq!(finished.executed_command.expose(), "/bin/ls -a");
    assert_eq!(daemon.spawns(), ["spawn /bin/ls -a as bash"]);
    assert_eq!(finished.decision.verdict, DecisionVerdict::Rewrite);

    let record = daemon.records().pop().unwrap();
    assert_eq!(record.command.expose(), "ls -a");
    assert_eq!(
        record
            .details
            .rewritten_from
            .as_ref()
            .map(|text| text.expose().as_str()),
        Some("git push --force")
    );
    assert_eq!(record.details.decision.unwrap().verdict, DecisionVerdict::Rewrite);
}

// FR-HOOK-20, FR-HOOK-21, FR-REC-03 (KNSH-055): five denials of one line within 60 s limit it. The sixth attempt is
// denied with source `rate_limit` without hooks or an ask (the authority's script is empty: an ask would panic), it
// is still recorded and reported, and `command.denied_repeatedly` follows only the denial that started the limit.
#[test]
fn limits_repeated_denials_without_asking() {
    let daemon = Daemon::new();
    let lifecycle = daemon.lifecycle(Setup {
        authority: Some(vec![AskReply::Deny { reason: None }; 5]),
        ..Setup::default()
    });
    for _ in 0..5 {
        daemon.clock.advance(Duration::from_secs(10));
        let error = lifecycle.run(daemon.line("git push"), &StillWaiting).unwrap_err();
        assert_eq!(Denial::from_error(&error).unwrap().source.as_deref(), Some("authority"));
    }
    let events = daemon.events();
    let published = names(&events);
    assert_eq!(
        published
            .iter()
            .filter(|name| **name == "command.denied_repeatedly")
            .count(),
        1
    );
    // Right after the fifth denial.
    assert_eq!(
        published[published.len() - 2..],
        ["command.denied", "command.denied_repeatedly"]
    );
    let EventData::CommandDeniedRepeatedly { command, until, .. } = &events.last().unwrap().data else {
        panic!("{:?}", events.last());
    };
    assert_eq!(command.expose(), "git push");
    let fifth = daemon.clock.now().unwrap();
    assert_eq!(until.as_unix_micros(), fifth.as_unix_micros() + 600_000_000);

    for _ in 0..3 {
        daemon.clock.advance(Duration::from_secs(1));
        let error = lifecycle.run(daemon.line("git push"), &StillWaiting).unwrap_err();
        assert_eq!(error.code, ErrorCode::Denied);
        let denial = Denial::from_error(&error).unwrap();
        assert_eq!(denial.source.as_deref(), Some("rate_limit"));
        assert!(denial.reason.is_some());
    }
    // Only `command.denied` for the limited attempts: no proposal, no second `command.denied_repeatedly`.
    assert_eq!(names(&daemon.events()), ["command.denied"; 3]);
    assert_eq!(
        daemon.journal.entries().iter().filter(|e| e.starts_with("ask")).count(),
        5
    );
    let records = daemon.records();
    assert_eq!(records.len(), 8);
    let limited = records
        .iter()
        .filter(|record| record.details.decision.as_ref().unwrap().source == DecisionSource::RateLimit)
        .count();
    assert_eq!(limited, 3);
    // Another line is decided as usual.
    lifecycle.run(daemon.line("git status"), &StillWaiting).unwrap();
}

// FR-HOOK-20: denials spread over more than 60 s do not limit the line.
#[test]
fn does_not_limit_denials_spread_over_a_minute() {
    let daemon = Daemon::new();
    let lifecycle = daemon.lifecycle(Setup::default());
    for _ in 0..6 {
        daemon.clock.advance(Duration::from_secs(15));
        let error = lifecycle.run(daemon.line("rm -rf build"), &StillWaiting).unwrap_err();
        assert_eq!(Denial::from_error(&error).unwrap().source.as_deref(), Some("rule"));
    }
    assert!(!names(&daemon.events()).contains(&"command.denied_repeatedly"));
}

// FR-HOOK-20: the limit lifts 10 minutes after it started, on the injected clock, and the line is asked about again.
#[test]
fn lifts_limit_after_ten_minutes_on_the_injected_clock() {
    let daemon = Daemon::new();
    let mut script = vec![AskReply::Deny { reason: None }; 5];
    script.push(AskReply::Allow);
    let lifecycle = daemon.lifecycle(Setup {
        authority: Some(script),
        ..Setup::default()
    });
    for _ in 0..5 {
        lifecycle.run(daemon.line("git push"), &StillWaiting).unwrap_err();
    }
    daemon.clock.advance(Duration::from_secs(599));
    let error = lifecycle.run(daemon.line("git push"), &StillWaiting).unwrap_err();
    assert_eq!(
        Denial::from_error(&error).unwrap().source.as_deref(),
        Some("rate_limit")
    );
    daemon.clock.advance(Duration::from_secs(1));
    let finished = lifecycle.run(daemon.line("git push"), &StillWaiting).unwrap();
    assert_eq!(finished.decision.source, DecisionSource::Authority);
}

// FR-HOOK-20: the limit is per session; another session's same line is still asked about.
#[test]
fn limits_are_per_session() {
    let daemon = Daemon::new();
    let mut script = vec![AskReply::Deny { reason: None }; 5];
    script.push(AskReply::Allow);
    let lifecycle = daemon.lifecycle(Setup {
        authority: Some(script),
        ..Setup::default()
    });
    for _ in 0..5 {
        lifecycle.run(daemon.line("git push"), &StillWaiting).unwrap_err();
    }
    let other = daemon
        .fixture
        .sessions
        .open_agent(
            Actor::Agent(knsh_core::AgentId::new("claude-code").unwrap()),
            ProfileName::new("web").unwrap(),
        )
        .unwrap()
        .session_id;
    let finished = lifecycle.run(forwarded(other, "git push"), &StillWaiting).unwrap();
    assert_eq!(finished.decision.source, DecisionSource::Authority);
    let error = lifecycle.run(daemon.line("git push"), &StillWaiting).unwrap_err();
    assert_eq!(
        Denial::from_error(&error).unwrap().source.as_deref(),
        Some("rate_limit")
    );
}

// FR-HOOK-20: a cancelled line is not a denial and is not counted.
#[test]
fn cancellations_are_not_counted() {
    let daemon = Daemon::new();
    let lifecycle = daemon.lifecycle(Setup::default());
    for _ in 0..6 {
        let error = lifecycle
            .run(daemon.line("git push"), &LeavingCaller(AtomicUsize::new(0)))
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::Cancelled);
    }
    assert!(!names(&daemon.events()).contains(&"command.denied_repeatedly"));
}

// FR-HOOK-20: the rewritten line of a second pass is checked too. A rewrite into a limited line is denied with source
// `rate_limit`, after the one ask that produced the rewrite and no other.
#[test]
fn limits_a_rewrite_into_a_limited_line() {
    let daemon = Daemon::new();
    let lifecycle = daemon.lifecycle(Setup {
        authority: Some(vec![AskReply::Rewrite {
            command: "rm -rf build".to_owned(),
        }]),
        ..Setup::default()
    });
    for _ in 0..5 {
        lifecycle.run(daemon.line("rm -rf build"), &StillWaiting).unwrap_err();
    }
    // Minutes pass while the authority considers the ask: the limit is judged at the clock's time, not the receipt.
    daemon.clock.advance(Duration::from_secs(300));
    let error = lifecycle.run(daemon.line("git push"), &StillWaiting).unwrap_err();
    assert_eq!(
        Denial::from_error(&error).unwrap().source.as_deref(),
        Some("rate_limit")
    );
    assert_eq!(
        daemon.journal.entries().iter().filter(|e| e.starts_with("ask")).count(),
        1
    );
    let record = daemon
        .records()
        .into_iter()
        .find(|r| r.details.rewritten_from.is_some())
        .unwrap();
    assert_eq!(record.command.expose(), "rm -rf build");
}

// KNSH-060 (FR-NET-09): the hosts the proxy reported for the line are written to its record's `network` field.
#[test]
fn record_carries_the_lines_network() {
    let daemon = Daemon::new();
    let mut spawner = FakeSpawner::new(Arc::clone(&daemon.journal));
    spawner.network = vec![
        knsh_core::NetworkEntry::new(
            Redacted::new("registry.npmjs.org".to_owned()),
            443,
            knsh_core::NetworkResult::Contacted,
        ),
        knsh_core::NetworkEntry::new(
            Redacted::new("github.com".to_owned()),
            443,
            knsh_core::NetworkResult::Refused("approval_required".to_owned()),
        ),
    ];
    daemon
        .lifecycle(Setup {
            spawner: Some(spawner),
            ..Setup::default()
        })
        .run(daemon.line("ls"), &StillWaiting)
        .unwrap();
    let [record] = <[ExecutionRecord; 1]>::try_from(daemon.records()).unwrap();
    let hosts: Vec<(&str, Option<&str>)> = record
        .details
        .network
        .iter()
        .map(|entry| (entry.host.expose().as_str(), entry.result.reason()))
        .collect();
    assert_eq!(
        hosts,
        [("registry.npmjs.org", None), ("github.com", Some("approval_required"))]
    );
}

// FR-AUTH-20, FR-AUTH-23 (KNSH-069): with an authority registered, an ask is sent to it as `decision.requested`;
// with no answer, the line is denied at 90 s on the clock with -32002 naming the request, recorded with source
// `authority`, and the authority is told with `decision.cancelled`.
#[test]
fn authority_timeout_is_32002() {
    let daemon = Daemon::new();
    daemon.events();
    let (decisions, wire) = crate::decisions::tests::on_wire(daemon.clock.clone(), crate::grants::GrantStore::new());
    let lifecycle = daemon.lifecycle(Setup {
        authority_service: Some(decisions),
        ..Setup::default()
    });
    let line = daemon.line("git push origin main");
    let running = std::thread::spawn(move || lifecycle.run(line, &StillWaiting));
    let request_id = crate::decisions::tests::requested_id(&wire.wait_for(1)[0].1);
    daemon.clock.advance(DEFAULT_ASK_TIMEOUT);
    let error = running.join().unwrap().unwrap_err();
    assert_eq!(error.code, ErrorCode::DecisionTimeout);
    assert_eq!(
        data_field(&error, "request_id"),
        Some(Value::String(request_id.to_string()))
    );
    assert_eq!(wire.wait_for(2).len(), 2, "decision.cancelled sent to the authority");
    assert_eq!(
        names(&daemon.events()),
        ["command.proposed", "decision.cancelled", "command.denied"],
        "decision.requested is never an event (FR-EVT-06)"
    );
    let decision = daemon.records().pop().unwrap().details.decision.unwrap();
    assert_eq!(decision.source, DecisionSource::Authority);
    assert_eq!(daemon.spawns(), Vec::<String>::new());
}

// FR-AUTH-21, FR-POL-60, FR-POL-62 (KNSH-069): an `allow` with a session grant runs the line, and the same line
// then runs again without asking, decided by the grant.
#[test]
fn authority_grant_allows_the_line_again() {
    let daemon = Daemon::new();
    let grants = crate::grants::GrantStore::new();
    let (decisions, wire) = crate::decisions::tests::on_wire(daemon.clock.clone(), Arc::clone(&grants));
    let lifecycle = daemon.lifecycle(Setup {
        authority_service: Some(decisions.clone()),
        grants: Some(grants),
        ..Setup::default()
    });
    let line = daemon.line("git push origin main");
    let asking = Arc::clone(&lifecycle);
    let running = std::thread::spawn(move || asking.run(line, &StillWaiting).map(drop));
    let request_id = crate::decisions::tests::requested_id(&wire.wait_for(1)[0].1);
    let answer =
        format!(r#"{{"request_id":"{request_id}","verdict":"allow","grant":{{"scope":"session","duration_s":3600}}}}"#);
    crate::decisions::tests::respond_on(
        &decisions,
        crate::dispatch::Endpoint::Control,
        Some(crate::decisions::tests::AUTHORITY),
        &answer,
    )
    .unwrap();
    running.join().unwrap().unwrap();

    lifecycle
        .run(daemon.line("git push origin main"), &StillWaiting)
        .unwrap();
    // Record IDs from the frozen clock order by their random part, so the records are compared as a set.
    let mut decisions: Vec<_> = daemon
        .records()
        .into_iter()
        .map(|record| {
            let decision = record.details.decision.unwrap();
            (format!("{:?}", decision.source), decision.rule_id)
        })
        .collect();
    decisions.sort();
    let asked = Some("exec.ask[0]".to_owned());
    assert_eq!(
        decisions,
        [("Authority".to_owned(), asked.clone()), ("Grant".to_owned(), asked)]
    );
    assert_eq!(wire.wait_for(1).len(), 1, "the granted line was not asked about");
    assert_eq!(daemon.spawns().len(), 2);
}
