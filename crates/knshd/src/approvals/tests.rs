use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};

use knsh_bash::{Classification, Interpreters, Lookup, Program, SourceFile, classify, parse_line};
use knsh_core::{Actor, AgentId, CanonicalPath, Proposal, Redacted, SessionId, StillWaiting};
use knsh_json::FromJson;
use knsh_platform::testing::{FakeClock, RecordingLog, ScriptedPresence, SeededRandom};
use knsh_proto::{ByteTransport, MethodName, Request};

use super::*;
use crate::dispatch::tests::{stream, subscriber};
use crate::sessions::SessionBinding;

const CWD: &str = "/Users/me/app";

/// Every program resolves to `/bin/<name>`.
struct Resolver;

impl knsh_bash::Resolver for Resolver {
    fn resolve(&self, name: &str, _lookup: Lookup) -> Program {
        Program::Trusted(Path::new("/bin").join(name))
    }

    fn source_file(&self, _path: &str) -> SourceFile {
        SourceFile::Unresolved
    }
}

/// `approval.*` with no pending request and a prompt nobody answers: for dispatcher tests that need every catalogued
/// handler.
pub(crate) fn idle_handlers() -> Handlers {
    Harness::new(Duration::from_secs(1)).approvals.handlers()
}

/// Approvals whose prompt nobody answers: every ask waits for `timeout` (or an `approval.deny`), then is denied. The
/// supervisor's tests use it as standalone mode.
pub(crate) fn unanswered(timeout: Duration) -> Arc<Approvals> {
    Harness::new(timeout).approvals
}

/// Approvals prompting through `presence`, for tests that approve through the handlers.
pub(crate) fn prompting(presence: Arc<ScriptedPresence>, timeout: Duration) -> Arc<Approvals> {
    Approvals::new(
        Arc::new(FakeClock::new(
            Timestamp::from_unix_micros(1_800_000_000_000_000).unwrap(),
        )),
        Arc::new(SeededRandom::new(3)),
        presence,
        Arc::new(RecordingLog::new()),
        timeout,
    )
}

/// Approves the one pending request through `approval.approve` as soon as it is listed, on `user.sock`.
pub(crate) fn approve_when_pending(approvals: &Arc<Approvals>) -> JoinHandle<Reply> {
    answer_when_pending(approvals, APPROVAL_APPROVE)
}

/// Denies the one pending request through `approval.deny` as soon as it is listed, on `user.sock`.
pub(crate) fn deny_when_pending(approvals: &Arc<Approvals>) -> JoinHandle<Reply> {
    answer_when_pending(approvals, APPROVAL_DENY)
}

fn answer_when_pending(approvals: &Arc<Approvals>, method: &'static str) -> JoinHandle<Reply> {
    let approvals = Arc::clone(approvals);
    thread::spawn(move || {
        let started = Instant::now();
        let id = loop {
            if let Some(id) = approvals.state().pending.keys().next().copied() {
                break id;
            }
            assert!(started.elapsed() < Duration::from_secs(5), "no request became pending");
            thread::sleep(Duration::from_millis(1));
        };
        let harness = Harness {
            presence: Arc::new(ScriptedPresence::new()),
            approvals,
        };
        harness.call_on(Endpoint::User, method, &format!(r#"{{"request_id":"{id}"}}"#))
    })
}

struct Harness {
    presence: Arc<ScriptedPresence>,
    approvals: Arc<Approvals>,
}

/// A caller whose connection the test closes.
#[derive(Default)]
struct Leaving(AtomicBool);

impl Caller for Leaving {
    fn gone(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

fn session() -> SessionId {
    SessionId::from_ulid(Ulid::from_u128(7))
}

impl Harness {
    fn new(timeout: Duration) -> Self {
        let presence = Arc::new(ScriptedPresence::new());
        let approvals = prompting(presence.clone(), timeout);
        Self { presence, approvals }
    }

    /// Asks about `line` on its own thread, as the orchestrator does for an agent's call, with `caller` waiting.
    fn ask(&self, line: &str, caller: Arc<dyn Caller + Send + Sync>) -> JoinHandle<AskAnswer> {
        let approvals = Arc::clone(&self.approvals);
        let line = line.to_owned();
        let asking = thread::spawn(move || {
            let classification: Classification =
                classify(&parse_line(&line), &line, &Resolver, &Interpreters::defaults());
            let actor = Actor::Agent(AgentId::new("claude-code").unwrap());
            let command = Redacted::new(line.clone());
            let cwd = CanonicalPath::new(CWD).unwrap();
            let proposal = Proposal {
                session_id: session(),
                actor: &actor,
                command: &command,
                cwd: &cwd,
                rewritten_from: None,
                classification: &classification,
                redactor: &knsh_core::Redactor::default(),
            };
            let profile = knsh_core::ProfileName::new("web").unwrap();
            let request = AskRequest {
                proposal: &proposal,
                rule_id: Some("exec.ask[0]"),
                hook: None,
                profile: &profile,
                irreversible: &flag_of(&line),
            };
            approvals.ask(&request, caller.as_ref())
        });
        // The request is listed once the ask has registered it.
        let started = Instant::now();
        while self.approvals.state().pending.is_empty() && !asking.is_finished() {
            assert!(started.elapsed() < Duration::from_secs(5), "the ask never registered");
            thread::sleep(Duration::from_millis(1));
        }
        asking
    }

    fn call_on(&self, endpoint: Endpoint, method: &'static str, params: &str) -> Reply {
        let request = Request {
            id: knsh_proto::RequestId::from(1u32),
            method: MethodName::new(method).unwrap(),
            params: knsh_json::parse(params.as_bytes(), 1 << 20)
                .unwrap()
                .as_object()
                .cloned(),
        };
        self.approvals.handlers()[method](&Call {
            endpoint,
            bytes: ByteTransport::BinaryFrames,
            stream: stream(),
            request: &request,
            subscriber: subscriber(),
            binding: &SessionBinding::new(),
            descriptors: crate::dispatch::tests::no_descriptors(),
            caller: &StillWaiting,
            control: None,
        })
    }

    fn list(&self) -> Vec<PendingApproval> {
        let reply = self.call_on(Endpoint::User, APPROVAL_LIST, "{}").unwrap();
        ApprovalListResult::from_json(&reply.result).unwrap().requests
    }

    fn approve(&self, id: RequestId) -> Reply {
        self.call_on(Endpoint::User, APPROVAL_APPROVE, &format!(r#"{{"request_id":"{id}"}}"#))
    }

    fn deny(&self, id: RequestId) -> Reply {
        self.call_on(Endpoint::User, APPROVAL_DENY, &format!(r#"{{"request_id":"{id}"}}"#))
    }
}

fn verdict(reply: Reply) -> ApprovalVerdict {
    ApprovalAnswerResult::from_json(&reply.unwrap().result).unwrap().verdict
}

fn data_field(error: &RpcError, name: &str) -> Option<Value> {
    error.data.as_ref()?.as_object()?.get(name).cloned()
}

// FR-AUTH-40: a pending ask is listed with its request ID, session, actor, redacted command, working directory,
// matched rule and `timeout_at`; the listed ID is the one the ask reports, and an answered ask leaves the list.
#[test]
fn lists_pending_requests() {
    let harness = Harness::new(Duration::from_secs(30));
    assert_eq!(harness.list(), Vec::new());
    let asking = harness.ask("git push origin main", Arc::new(StillWaiting));

    let listed = harness.list();
    assert_eq!(listed.len(), 1);
    let entry = &listed[0];
    assert_eq!(entry.session_id, session());
    assert_eq!(entry.actor, Actor::Agent(AgentId::new("claude-code").unwrap()));
    assert_eq!(entry.command, "git push origin main");
    assert_eq!(entry.cwd, CWD);
    assert_eq!(entry.matched_rule.as_deref(), Some("exec.ask[0]"));
    assert_eq!(entry.hook, None);
    // FR-IRR-05 (KNSH-093): `knsh approvals` sees why the line is irreversible.
    assert_eq!(
        entry.irreversible,
        Some(knsh_proto::Irreversible {
            value: true,
            reasons: vec!["git push".to_owned()],
        })
    );
    // The injected clock's start plus the 30 s timeout.
    assert_eq!(entry.timeout_at.to_string(), "2027-01-15T08:00:30.000000Z");

    assert_eq!(verdict(harness.deny(entry.request_id)), ApprovalVerdict::Deny);
    let answered = asking.join().unwrap();
    assert_eq!(answered.request_id, Some(entry.request_id));
    assert_eq!(harness.list(), Vec::new());
}

// FR-AUTH-41, FR-AUTH-42: an approval counts only after knshd's own prompt succeeds. The prompt names the exact
// command, its directory and session, and waits no longer than the request has left. A refused or unanswered prompt
// is -32001 from the user and leaves the request pending; every attempt prompts afresh.
#[test]
fn approve_requires_authentication() {
    let harness = Harness::new(Duration::from_secs(30));
    let asking = harness.ask("git push origin main", Arc::new(StillWaiting));
    let id = harness.list()[0].request_id;

    harness.presence.refuse_next(NotAuthenticated::Failed);
    for _ in 0..2 {
        // The second attempt meets a prompt nobody answers: the fake's default, as with nobody at the Mac.
        let error = harness.approve(id).unwrap_err();
        assert_eq!(error.code, ErrorCode::Denied);
        let denial = Denial::from_error(&error).unwrap();
        assert_eq!(denial.source.as_deref(), Some("user"));
        assert!(denial.reason.unwrap().starts_with("not authenticated: "));
        assert_eq!(harness.list().len(), 1, "still pending");
        assert!(!asking.is_finished());
    }

    harness.presence.approve_next();
    assert_eq!(verdict(harness.approve(id)), ApprovalVerdict::Allow);
    let answered = asking.join().unwrap();
    assert_eq!(answered.reply, AskReply::Allow);
    assert_eq!(answered.request_id, Some(id));

    let prompts = harness.presence.prompts();
    assert_eq!(prompts.len(), 3, "every attempt prompts afresh");
    let expected = format!(
        "approve the agent command: git push origin main (cwd {CWD}, session {})",
        session()
    );
    for prompt in &prompts {
        assert_eq!(prompt.reason, expected);
        assert!(prompt.timeout <= Duration::from_secs(30), "{:?}", prompt.timeout);
    }
}

// FR-AUTH-22, FR-AUTH-23: an answer for a request that has timed out or been cancelled is refused, with no prompt:
// -32002 and -32011 with the request ID. One already answered, or never made, is -32602.
#[test]
fn approve_of_expired_request_refused() {
    let harness = Harness::new(Duration::from_millis(50));
    let answer = harness.ask("git push", Arc::new(StillWaiting)).join().unwrap();
    assert_eq!(answer.reply, AskReply::TimedOut);
    let timed_out = answer.request_id.unwrap();
    assert_eq!(harness.list(), Vec::new());
    harness.presence.approve_next();
    let error = harness.approve(timed_out).unwrap_err();
    assert_eq!(error.code, ErrorCode::DecisionTimeout);
    assert_eq!(
        data_field(&error, "request_id"),
        Some(Value::from(timed_out.to_string().as_str()))
    );
    assert_eq!(harness.deny(timed_out).unwrap_err().code, ErrorCode::DecisionTimeout);
    assert_eq!(harness.presence.prompts(), Vec::new(), "an ended request never prompts");

    let harness = Harness::new(Duration::from_secs(30));
    let caller = Arc::new(Leaving::default());
    let asking = harness.ask("git push", caller.clone());
    let cancelled = harness.list()[0].request_id;
    caller.0.store(true, Ordering::SeqCst);
    assert_eq!(asking.join().unwrap().reply, AskReply::CallerGone);
    let error = harness.approve(cancelled).unwrap_err();
    assert_eq!(error.code, ErrorCode::Cancelled);
    assert_eq!(
        data_field(&error, "request_id"),
        Some(Value::from(cancelled.to_string().as_str()))
    );
    assert_eq!(harness.presence.prompts(), Vec::new());

    let asking = harness.ask("git push", Arc::new(StillWaiting));
    let answered = harness.list()[0].request_id;
    assert_eq!(verdict(harness.deny(answered)), ApprovalVerdict::Deny);
    asking.join().unwrap();
    assert_eq!(harness.approve(answered).unwrap_err().code, ErrorCode::InvalidParams);
    assert_eq!(harness.deny(answered).unwrap_err().code, ErrorCode::InvalidParams);

    let unknown = RequestId::from_ulid(Ulid::from_u128(99));
    assert_eq!(harness.approve(unknown).unwrap_err().code, ErrorCode::InvalidParams);
    assert_eq!(harness.presence.prompts(), Vec::new());
}

// FR-AUTH-23: an approval sent after the request's deadline is refused before any prompt, even while its waiting ask
// has not collected it yet. A deadline passing while the prompt is up is covered by
// `prompt_success_after_the_request_ended_is_refused`.
#[test]
fn approval_landing_after_the_timeout_is_refused() {
    let harness = Harness::new(Duration::from_millis(500));
    let asking = harness.ask("git push", Arc::new(StillWaiting));
    let id = harness.list()[0].request_id;
    let deadline = harness.approvals.state().pending.get(&id).map(|p| p.deadline).unwrap();
    while Instant::now() < deadline {
        thread::sleep(Duration::from_millis(5));
    }
    harness.presence.approve_next();
    assert_eq!(harness.approve(id).unwrap_err().code, ErrorCode::DecisionTimeout);
    assert_eq!(asking.join().unwrap().reply, AskReply::TimedOut);
}

// The story's proposal: a denial needs no prompt, and gives the agent a fixed reason.
#[test]
fn deny_needs_no_prompt() {
    let harness = Harness::new(Duration::from_secs(30));
    let asking = harness.ask("rm -rf build", Arc::new(StillWaiting));
    let id = harness.list()[0].request_id;
    assert_eq!(verdict(harness.deny(id)), ApprovalVerdict::Deny);
    assert_eq!(
        asking.join().unwrap().reply,
        AskReply::Deny {
            reason: Some(DENIED_BY_USER.to_owned())
        }
    );
    assert_eq!(harness.presence.prompts(), Vec::new());
}

// FR-AUTH-43: the methods answer only on user.sock; on agent.sock they are -32003 even if dispatched there.
#[test]
fn refuses_agent_endpoint() {
    let harness = Harness::new(Duration::from_secs(30));
    let asking = harness.ask("git push", Arc::new(StillWaiting));
    let id = harness.list()[0].request_id;
    harness.presence.approve_next();
    let params = format!(r#"{{"request_id":"{id}"}}"#);
    for (method, params) in [
        (APPROVAL_LIST, "{}"),
        (APPROVAL_APPROVE, params.as_str()),
        (APPROVAL_DENY, params.as_str()),
    ] {
        let error = harness.call_on(Endpoint::Agent, method, params).unwrap_err();
        assert_eq!(error.code, ErrorCode::NotAllowed, "{method}");
    }
    assert_eq!(harness.presence.prompts(), Vec::new());
    assert_eq!(harness.list().len(), 1, "still pending");
    harness.deny(id).unwrap();
    asking.join().unwrap();
}

#[test]
fn malformed_request_id_is_invalid_params() {
    let harness = Harness::new(Duration::from_secs(1));
    for params in ["{}", r#"{"request_id":"nope"}"#, r#"{"request_id":1}"#] {
        let error = harness.call_on(Endpoint::User, APPROVAL_APPROVE, params).unwrap_err();
        assert_eq!(error.code, ErrorCode::InvalidParams, "{params}");
    }
    assert_eq!(harness.presence.prompts(), Vec::new());
}

// Only the most recent ended requests are remembered, so memory stays bounded under a stream of asks.
#[test]
fn remembers_a_bounded_number_of_ended_requests() {
    let mut state = State::default();
    for n in 0..=ENDED_MEMORY {
        state.end(
            RequestId::from_ulid(Ulid::from_u128(u128::try_from(n).unwrap() + 1)),
            Ended::TimedOut,
        );
    }
    assert_eq!(state.ended.len(), ENDED_MEMORY);
    let oldest = RequestId::from_ulid(Ulid::from_u128(1));
    let Err(error) = state.answerable(oldest, Instant::now()) else {
        panic!("a forgotten request is not pending");
    };
    assert_eq!(error.code, ErrorCode::InvalidParams, "forgotten, so unknown");
}

/// A prompt that runs `during` while it is up (the user still looking at it), then answers as `inner` scripts.
#[derive(Default)]
struct PromptUp {
    inner: ScriptedPresence,
    during: Mutex<Option<Box<dyn FnOnce() + Send>>>,
}

impl UserPresence for PromptUp {
    fn authenticate(
        &self,
        reason: &PromptReason,
        timeout: Duration,
    ) -> Result<knsh_platform::Authenticated, NotAuthenticated> {
        let during = self.during.lock().unwrap().take();
        if let Some(during) = during {
            during();
        }
        self.inner.authenticate(reason, timeout)
    }
}

/// A harness whose prompt is `presence`.
fn prompt_up_harness(presence: Arc<PromptUp>, timeout: Duration) -> Harness {
    let approvals = Approvals::new(
        Arc::new(FakeClock::new(
            Timestamp::from_unix_micros(1_800_000_000_000_000).unwrap(),
        )),
        Arc::new(SeededRandom::new(5)),
        presence,
        Arc::new(RecordingLog::new()),
        timeout,
    );
    Harness {
        presence: Arc::new(ScriptedPresence::new()),
        approvals,
    }
}

// FR-AUTH-22, FR-AUTH-23: the request is checked again after the prompt. A successful prompt does not approve a
// request that was denied, or that timed out, while the prompt was up; the first answer stands.
#[test]
fn prompt_success_after_the_request_ended_is_refused() {
    // Denied with `knsh deny` while the prompt was up.
    let presence = Arc::new(PromptUp::default());
    presence.inner.approve_next();
    let harness = prompt_up_harness(Arc::clone(&presence), Duration::from_secs(30));
    let asking = harness.ask("git push", Arc::new(StillWaiting));
    let id = harness.list()[0].request_id;
    let denier = Harness {
        presence: Arc::new(ScriptedPresence::new()),
        approvals: Arc::clone(&harness.approvals),
    };
    *presence.during.lock().unwrap() = Some(Box::new(move || {
        assert_eq!(verdict(denier.deny(id)), ApprovalVerdict::Deny);
    }));
    assert_eq!(harness.approve(id).unwrap_err().code, ErrorCode::InvalidParams);
    assert_eq!(
        asking.join().unwrap().reply,
        AskReply::Deny {
            reason: Some(DENIED_BY_USER.to_owned())
        }
    );
    assert_eq!(presence.inner.prompts().len(), 1);

    // Timed out while the prompt was up.
    let presence = Arc::new(PromptUp::default());
    presence.inner.approve_next();
    let harness = prompt_up_harness(Arc::clone(&presence), Duration::from_millis(300));
    let asking = harness.ask("git push", Arc::new(StillWaiting));
    let id = harness.list()[0].request_id;
    let deadline = harness.approvals.state().pending.get(&id).map(|p| p.deadline).unwrap();
    *presence.during.lock().unwrap() = Some(Box::new(move || {
        while Instant::now() < deadline {
            thread::sleep(Duration::from_millis(5));
        }
    }));
    assert_eq!(harness.approve(id).unwrap_err().code, ErrorCode::DecisionTimeout);
    assert_eq!(asking.join().unwrap().reply, AskReply::TimedOut);
}

/// The irreversible flag the pipeline gives `line` in these tests: `git push` for a push, none otherwise (KNSH-093).
fn flag_of(line: &str) -> knsh_core::Irreversibility {
    let mut flag = knsh_core::Irreversibility::none();
    if line.starts_with("git push") {
        flag.add("git push");
    }
    flag
}
