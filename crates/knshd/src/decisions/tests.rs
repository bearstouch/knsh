//! Decision protocol tests (KNSH-069; FR-AUTH-20 to FR-AUTH-24, FR-EVT-06, FR-LC-41, FR-POL-62).

use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::Instant;

use knsh_bash::{Interpreters, Lookup, Program, SourceFile, classify, parse_line};
use knsh_core::{Actor, AgentId, CanonicalPath, Proposal, Redacted, StillWaiting};
use knsh_json::{FromJson, Value as Json};
use knsh_platform::testing::{FakeClock, RecordingLog, SeededRandom};
use knsh_proto::{ByteTransport, DecisionRequestedParams, Request};

use super::*;
use crate::dispatch::tests::{no_descriptors, stream, subscriber};
use crate::sessions::SessionBinding;

const CWD: &str = "/Users/me/app";
const LINE: &str = "git push origin main";
/// Wall time at the start of every test: 2027-01-15T08:00:00Z.
const START_MICROS: u64 = 1_800_000_000_000_000;

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

/// The control service as the courier sees it: collects every notification, per connection.
#[derive(Default)]
pub(crate) struct Wire {
    sent: Mutex<Vec<(ConnectionId, Json)>>,
    arrived: Condvar,
}

impl AuthorityLink for Wire {
    fn notify(&self, connection: ConnectionId, json: &[u8]) -> Result<(), ()> {
        let message = knsh_json::parse(json, knsh_json::MAX_PAYLOAD).map_err(|_| ())?;
        lock(&self.sent).push((connection, message));
        self.arrived.notify_all();
        Ok(())
    }
}

impl Wire {
    /// Waits until `count` notifications have arrived in all, then returns them all.
    pub(crate) fn wait_for(&self, count: usize) -> Vec<(ConnectionId, Json)> {
        let mut sent = lock(&self.sent);
        let started = Instant::now();
        while sent.len() < count {
            assert!(
                started.elapsed() < Duration::from_secs(5),
                "only {} notifications",
                sent.len()
            );
            sent = self
                .arrived
                .wait_timeout(sent, Duration::from_millis(10))
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
        sent.clone()
    }
}

/// A caller whose connection the test closes.
#[derive(Default)]
struct Leaving(AtomicBool);

impl Caller for Leaving {
    fn gone(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

struct Harness {
    decisions: Arc<Decisions>,
    wire: Arc<Wire>,
    clock: Arc<FakeClock>,
    log: Arc<RecordingLog>,
    grants: Arc<GrantStore>,
}

fn session() -> SessionId {
    SessionId::from_ulid(Ulid::from_u128(7))
}

fn profile() -> ProfileName {
    ProfileName::new("web").unwrap()
}

/// The protocol with the default 90 s timeout on `clock`, putting grants in `grants`, its courier delivering to the
/// returned [`Wire`], and [`AUTHORITY`] registered: for the orchestrator's tests.
pub(crate) fn on_wire(clock: Arc<FakeClock>, grants: Arc<GrantStore>) -> (Arc<Decisions>, Arc<Wire>) {
    let decisions = Decisions::with_default_timeout(
        clock,
        Arc::new(SeededRandom::new(5)),
        Arc::new(RecordingLog::new()),
        grants,
    );
    let wire = Arc::new(Wire::default());
    let link: Arc<dyn AuthorityLink> = wire.clone();
    decisions.attach(Arc::downgrade(&link)).unwrap();
    decisions.registered(AUTHORITY);
    (decisions, wire)
}

/// The request ID of `decision.requested` notification `message`.
pub(crate) fn requested_id(message: &Json) -> RequestId {
    requested(message).request_id
}

/// `decision.respond` with `params` on `endpoint`, from control connection `connection` when there is one.
pub(crate) fn respond_on(
    decisions: &Arc<Decisions>,
    endpoint: Endpoint,
    connection: Option<ConnectionId>,
    params: &str,
) -> Reply {
    let request = Request {
        id: knsh_proto::RequestId::from(1u32),
        method: MethodName::new(DECISION_RESPOND).unwrap(),
        params: knsh_json::parse(params.as_bytes(), 1 << 20)
            .unwrap()
            .as_object()
            .cloned(),
    };
    decisions.handlers()[DECISION_RESPOND](&Call {
        endpoint,
        bytes: ByteTransport::BinaryFrames,
        stream: stream(),
        request: &request,
        subscriber: subscriber(),
        binding: &SessionBinding::new(),
        descriptors: no_descriptors(),
        caller: &StillWaiting,
        control: connection,
    })
}

/// Asks `decisions` about `line` on its own thread, as the orchestrator does, with `caller` waiting; returns once the
/// request is pending.
pub(crate) fn ask(asked: &Arc<Decisions>, line: &str, caller: Arc<dyn Caller + Send + Sync>) -> JoinHandle<AskAnswer> {
    ask_rewritten(asked, line, None, caller)
}

/// [`ask`], for a line that replaced `rewritten_from` (FR-AUTH-30) when one is given.
fn ask_rewritten(
    asked: &Arc<Decisions>,
    line: &str,
    rewritten_from: Option<&str>,
    caller: Arc<dyn Caller + Send + Sync>,
) -> JoinHandle<AskAnswer> {
    let before = asked.state().pending.len();
    let decisions = Arc::clone(asked);
    let line = line.to_owned();
    let rewritten_from = rewritten_from.map(|from| Redacted::new(from.to_owned()));
    let asking = thread::spawn(move || {
        let classification = classify(&parse_line(&line), &line, &Resolver, &Interpreters::defaults());
        let actor = Actor::Agent(AgentId::new("claude-code").unwrap());
        let command = Redacted::new(line.clone());
        let cwd = CanonicalPath::new(CWD).unwrap();
        let proposal = Proposal {
            session_id: session(),
            actor: &actor,
            command: &command,
            cwd: &cwd,
            rewritten_from: rewritten_from.as_ref(),
            classification: &classification,
        };
        let profile = profile();
        let request = AskRequest {
            proposal: &proposal,
            rule_id: Some("exec.ask[0]"),
            hook: None,
            profile: &profile,
        };
        decisions.ask(&request, caller.as_ref())
    });
    let started = Instant::now();
    while asked.state().pending.len() == before && !asking.is_finished() {
        assert!(started.elapsed() < Duration::from_secs(5), "the ask never registered");
        thread::sleep(Duration::from_millis(1));
    }
    asking
}

/// The `method` and `params` of a notification.
fn parts(message: &Json) -> (&str, &Json) {
    let object = message.as_object().unwrap();
    let method = object.get("method").and_then(Json::as_str).unwrap();
    (method, object.get("params").unwrap())
}

fn requested(message: &Json) -> DecisionRequestedParams {
    let (method, params) = parts(message);
    assert_eq!(method, DECISION_REQUESTED);
    DecisionRequestedParams::from_json(params).unwrap()
}

fn cancelled(message: &Json) -> DecisionCancelledParams {
    let (method, params) = parts(message);
    assert_eq!(method, DECISION_CANCELLED);
    DecisionCancelledParams::from_json(params).unwrap()
}

impl Harness {
    /// The protocol with the default 90 s timeout, on a fake clock, its courier delivering to a [`Wire`].
    fn new() -> Self {
        let clock = Arc::new(FakeClock::new(Timestamp::from_unix_micros(START_MICROS).unwrap()));
        let log = Arc::new(RecordingLog::new());
        let grants = GrantStore::new();
        let decisions = Decisions::with_default_timeout(
            clock.clone(),
            Arc::new(SeededRandom::new(5)),
            log.clone(),
            Arc::clone(&grants),
        );
        let wire = Arc::new(Wire::default());
        let link: Arc<dyn AuthorityLink> = wire.clone();
        decisions.attach(Arc::downgrade(&link)).unwrap();
        Self {
            decisions,
            wire,
            clock,
            log,
            grants,
        }
    }

    /// Asks about `line` on its own thread (see [`ask`]).
    fn ask(&self, line: &str, caller: Arc<dyn Caller + Send + Sync>) -> JoinHandle<AskAnswer> {
        ask(&self.decisions, line, caller)
    }

    /// `decision.respond` with `params` on `endpoint`, from control connection `connection` when there is one.
    fn respond_on(&self, endpoint: Endpoint, connection: Option<ConnectionId>, params: &str) -> Reply {
        respond_on(&self.decisions, endpoint, connection, params)
    }

    /// `decision.respond` from control connection `connection`.
    fn respond(&self, connection: ConnectionId, params: &str) -> DecisionRespondResult {
        let reply = self.respond_on(Endpoint::Control, Some(connection), params).unwrap();
        DecisionRespondResult::from_json(&reply.result).unwrap()
    }

    /// The one request now pending.
    fn pending_id(&self) -> RequestId {
        let state = self.decisions.state();
        assert_eq!(state.pending.len(), 1);
        *state.pending.keys().next().unwrap()
    }

    /// The `reason` of every "decision answer ignored" log entry.
    fn ignored_reasons(&self) -> Vec<Value> {
        self.log
            .entries()
            .into_iter()
            .filter(|entry| entry.message == "decision answer ignored")
            .flat_map(|entry| entry.fields.into_iter().map(|field| field.value))
            .collect()
    }

    /// Nothing the log holds mentions the command (FR-AUTH-22: logged without command text).
    fn assert_log_has_no_command(&self) {
        let logged = format!("{:?}", self.log.entries());
        assert!(!logged.contains("git push"), "{logged}");
    }
}

/// The registered authority's connection.
pub(crate) const AUTHORITY: ConnectionId = ConnectionId(1);

// FR-AUTH-30 (KNSH-070): a rewritten line that asks again reaches the authority as `decision.requested` with
// `rewritten_from`, the line it replaced, beside the rewritten `command`.
#[test]
fn sends_rewritten_from_with_second_ask() {
    let harness = Harness::new();
    harness.decisions.registered(AUTHORITY);
    let asking = ask_rewritten(
        &harness.decisions,
        "git push --dry-run",
        Some(LINE),
        Arc::new(StillWaiting),
    );
    let sent = harness.wire.wait_for(1);
    let request = requested(&sent[0].1);
    assert_eq!(request.command, "git push --dry-run");
    assert_eq!(request.rewritten_from.as_deref(), Some(LINE));
    let (_, params) = parts(&sent[0].1);
    assert_eq!(
        params.as_object().unwrap().get("rewritten_from").and_then(Json::as_str),
        Some(LINE)
    );

    let id = request.request_id;
    harness.respond(AUTHORITY, &format!(r#"{{"request_id":"{id}","verdict":"allow"}}"#));
    assert_eq!(asking.join().unwrap().reply, AskReply::Allow);
}

// FR-AUTH-20, FR-EVT-06: `decision.requested` carries the request ID, session, actor, redacted command, working
// directory, matched rule, irreversibility and `timeout_at`, and goes only to the registered authority's connection.
#[test]
fn sends_request_with_all_fields() {
    let harness = Harness::new();
    harness.decisions.registered(AUTHORITY);
    assert!(harness.decisions.connected());
    let asking = harness.ask(LINE, Arc::new(StillWaiting));
    let id = harness.pending_id();

    let sent = harness.wire.wait_for(1);
    assert_eq!(sent.len(), 1, "one notification, to one connection");
    assert_eq!(sent[0].0, AUTHORITY);
    let request = requested(&sent[0].1);
    assert_eq!(request.request_id, id);
    assert_eq!(request.session_id, session());
    assert_eq!(request.actor, Actor::Agent(AgentId::new("claude-code").unwrap()));
    assert_eq!(request.command, LINE);
    assert_eq!(request.rewritten_from, None);
    assert_eq!(request.cwd, CWD);
    assert_eq!(request.matched_rule.as_deref(), Some("exec.ask[0]"));
    assert_eq!(request.hook, None);
    // Present, as `null`, until lines are classified for irreversibility (KNSH-093).
    let (_, params) = parts(&sent[0].1);
    assert_eq!(params.as_object().unwrap().get("irreversible"), Some(&Json::Null));
    // 90 s after the request was made, on the wall clock (FR-AUTH-23).
    assert_eq!(request.timeout_at.as_unix_micros(), START_MICROS + 90_000_000);

    harness.respond(AUTHORITY, &format!(r#"{{"request_id":"{id}","verdict":"deny"}}"#));
    asking.join().unwrap();
}

// FR-AUTH-21: `allow`, `deny` (with its reason) and `rewrite` (with its line) are each given to the matching request,
// and the waiting ask returns them.
#[test]
fn applies_allow_answer() {
    let harness = Harness::new();
    harness.decisions.registered(AUTHORITY);
    for (answer, expected) in [
        (r#""verdict":"allow","reason":"ok""#, AskReply::Allow),
        (
            r#""verdict":"deny","reason":"not on Fridays""#,
            AskReply::Deny {
                reason: Some("not on Fridays".to_owned()),
            },
        ),
        (
            r#""verdict":"rewrite","command":"git push --dry-run origin main""#,
            AskReply::Rewrite {
                command: "git push --dry-run origin main".to_owned(),
            },
        ),
    ] {
        let asking = harness.ask(LINE, Arc::new(StillWaiting));
        let id = harness.pending_id();
        let result = harness.respond(AUTHORITY, &format!(r#"{{"request_id":"{id}",{answer}}}"#));
        assert_eq!(
            result,
            DecisionRespondResult {
                applied: true,
                grant_id: None
            }
        );
        let answered = asking.join().unwrap();
        assert_eq!(answered.request_id, Some(id));
        assert_eq!(answered.reply, expected);
        assert!(harness.decisions.state().pending.is_empty());
    }
    // An answer is applied once: a second one for the same request is ignored.
    let id = harness.decisions.state().ended.back().unwrap().0;
    let again = harness.respond(AUTHORITY, &format!(r#"{{"request_id":"{id}","verdict":"allow"}}"#));
    assert!(!again.applied);
    assert_eq!(harness.ignored_reasons(), [Value::Static("already_answered")]);
}

// FR-AUTH-23: with nobody answering, the request waits 90 s on the clock, not a moment less, then times out (the
// orchestrator answers `-32002`, `supervisor::tests::authority_timeout_is_32002`); the authority is told, and its late
// answer is ignored.
#[test]
fn denies_at_ninety_second_timeout_with_32002() {
    let harness = Harness::new();
    harness.decisions.registered(AUTHORITY);
    let asking = harness.ask(LINE, Arc::new(StillWaiting));
    let id = harness.pending_id();
    harness.wire.wait_for(1);

    harness.clock.advance(Duration::from_secs(89));
    thread::sleep(CALLER_POLL * 3);
    assert!(!asking.is_finished(), "denied before 90 s");
    harness.clock.advance(Duration::from_secs(1));
    let answered = asking.join().unwrap();
    assert_eq!(answered.reply, AskReply::TimedOut);
    assert_eq!(answered.request_id, Some(id));

    let sent = harness.wire.wait_for(2);
    assert_eq!(
        cancelled(&sent[1].1),
        DecisionCancelledParams {
            request_id: id,
            reason: CancelReason::TimedOut
        }
    );
    let late = harness.respond(AUTHORITY, &format!(r#"{{"request_id":"{id}","verdict":"allow"}}"#));
    assert!(!late.applied);
    assert_eq!(harness.ignored_reasons(), [Value::Static("timed_out")]);
}

// FR-AUTH-22, FR-LC-41: a caller that disconnects cancels its request: the ask ends as cancelled, the authority gets
// `decision.cancelled`, and its late answer is ignored and logged without the command.
#[test]
fn ignores_late_answer_after_cancellation() {
    let harness = Harness::new();
    harness.decisions.registered(AUTHORITY);
    let caller = Arc::new(Leaving::default());
    let asking = harness.ask(LINE, caller.clone());
    let id = harness.pending_id();
    harness.wire.wait_for(1);

    caller.0.store(true, Ordering::SeqCst);
    assert_eq!(asking.join().unwrap().reply, AskReply::CallerGone);
    let sent = harness.wire.wait_for(2);
    assert_eq!(sent[1].0, AUTHORITY);
    assert_eq!(
        cancelled(&sent[1].1),
        DecisionCancelledParams {
            request_id: id,
            reason: CancelReason::CallerGone
        }
    );

    let late = harness.respond(
        AUTHORITY,
        &format!(r#"{{"request_id":"{id}","verdict":"allow","grant":{{"scope":"session","duration_s":60}}}}"#),
    );
    assert_eq!(
        late,
        DecisionRespondResult {
            applied: false,
            grant_id: None
        }
    );
    assert_eq!(harness.ignored_reasons(), [Value::Static("cancelled")]);
    // A late answer's grant is not created either.
    assert_eq!(harness.grants.snapshot(), knsh_core::GrantSet::new());
    harness.assert_log_has_no_command();
}

// FR-AUTH-24: when the authority's connection ends, its requests keep waiting; when an authority registers again,
// every request still pending and not timed out is sent to it, unchanged, and only the new connection may answer.
#[test]
fn resends_pending_on_reconnect() {
    let harness = Harness::new();
    harness.decisions.registered(AUTHORITY);
    let first = harness.ask(LINE, Arc::new(StillWaiting));
    let first_id = harness.pending_id();
    let original = harness.wire.wait_for(1)[0].1.clone();

    harness.decisions.unregistered(AUTHORITY);
    assert!(!harness.decisions.connected());
    // A request made while no authority is registered waits for one, unsent.
    let second = harness.ask("npm publish", Arc::new(StillWaiting));
    // One that times out meanwhile is not sent again.
    harness.clock.advance(Duration::from_secs(60));
    let third = harness.ask("cargo publish", Arc::new(StillWaiting));
    harness.clock.advance(Duration::from_secs(31));
    assert_eq!(first.join().unwrap().reply, AskReply::TimedOut);
    assert_eq!(second.join().unwrap().reply, AskReply::TimedOut);
    assert_eq!(harness.wire.wait_for(1).len(), 1, "nothing sent without an authority");

    let reconnected = ConnectionId(2);
    harness.decisions.registered(reconnected);
    let sent = harness.wire.wait_for(2);
    assert_eq!(sent.len(), 2, "only the request still pending is sent again");
    assert_eq!(sent[1].0, reconnected);
    let resent = requested(&sent[1].1);
    assert_eq!(resent.command, "cargo publish");
    let third_id = resent.request_id;
    assert_ne!(third_id, first_id);
    // Sent again as it was first made: same ID and `timeout_at`.
    assert_eq!(requested(&original).request_id, first_id);

    // The old connection cannot answer; the new one can.
    let refused = harness
        .respond_on(
            Endpoint::Control,
            Some(AUTHORITY),
            &format!(r#"{{"request_id":"{third_id}","verdict":"allow"}}"#),
        )
        .unwrap_err();
    assert_eq!(refused.code, ErrorCode::NotAllowed);
    assert!(
        harness
            .respond(
                reconnected,
                &format!(r#"{{"request_id":"{third_id}","verdict":"allow"}}"#)
            )
            .applied
    );
    assert_eq!(third.join().unwrap().reply, AskReply::Allow);
}

// FR-AUTH-24: a request already sent to an authority that then disconnects is sent, byte for byte, to the next one
// (same ID and `timeout_at`), which can then answer it.
#[test]
fn resends_a_request_the_old_authority_was_sent() {
    let harness = Harness::new();
    harness.decisions.registered(AUTHORITY);
    let asking = harness.ask(LINE, Arc::new(StillWaiting));
    let id = harness.pending_id();
    let original = harness.wire.wait_for(1)[0].1.clone();
    harness.decisions.unregistered(AUTHORITY);
    harness.clock.advance(Duration::from_secs(30));

    let reconnected = ConnectionId(2);
    harness.decisions.registered(reconnected);
    let sent = harness.wire.wait_for(2);
    assert_eq!(sent.len(), 2);
    assert_eq!(sent[1], (reconnected, original));
    assert!(
        harness
            .respond(reconnected, &format!(r#"{{"request_id":"{id}","verdict":"allow"}}"#))
            .applied
    );
    assert_eq!(asking.join().unwrap().reply, AskReply::Allow);
}

// FR-POL-62, KNSH-042: a `grant` with an `allow` creates a grant for the asked line, scoped to the session (or its
// profile), expiring `duration_s` after the answer; its ID is returned.
#[test]
fn creates_grant_from_answer() {
    let harness = Harness::new();
    harness.decisions.registered(AUTHORITY);
    for (scope, expected) in [
        ("session", GrantScope::Session(session())),
        ("profile", GrantScope::Profile(profile())),
    ] {
        let asking = harness.ask(LINE, Arc::new(StillWaiting));
        let id = harness.pending_id();
        let result = harness.respond(
            AUTHORITY,
            &format!(r#"{{"request_id":"{id}","verdict":"allow","grant":{{"scope":"{scope}","duration_s":3600}}}}"#),
        );
        assert!(result.applied);
        assert_eq!(asking.join().unwrap().reply, AskReply::Allow);
        let grant_id = result.grant_id.expect("a grant was created");
        let grants = harness.grants.snapshot();
        let now = Timestamp::from_unix_micros(START_MICROS).unwrap();
        let grant = grants.list(now).find(|grant| grant.id() == grant_id).unwrap();
        assert_eq!(grant.scope(), &expected);
        assert_eq!(grant.rule(), LINE);
        // Exact: it covers the asked line, not the same command with more arguments.
        assert!(grant.is_exact());
        assert_eq!(grant.expires_at().as_unix_micros(), START_MICROS + 3_600_000_000);
    }

    // A line that cannot be written as a rule gets no grant; the allow still applies.
    let asking = harness.ask("git push $REMOTE main", Arc::new(StillWaiting));
    let id = harness.pending_id();
    let result = harness.respond(
        AUTHORITY,
        &format!(r#"{{"request_id":"{id}","verdict":"allow","grant":{{"scope":"session","duration_s":60}}}}"#),
    );
    assert_eq!(
        result,
        DecisionRespondResult {
            applied: true,
            grant_id: None
        }
    );
    assert_eq!(asking.join().unwrap().reply, AskReply::Allow);
    assert_eq!(
        harness
            .grants
            .snapshot()
            .list(Timestamp::from_unix_micros(START_MICROS).unwrap())
            .count(),
        2
    );
}

// FR-AUTH-22: an answer for a request that never existed is ignored and logged with a fixed reason, never the
// command; a pending request is untouched by it.
#[test]
fn ignores_unknown_request_id() {
    let harness = Harness::new();
    harness.decisions.registered(AUTHORITY);
    let asking = harness.ask(LINE, Arc::new(StillWaiting));
    let unknown = RequestId::from_ulid(Ulid::from_u128(42));
    let result = harness.respond(AUTHORITY, &format!(r#"{{"request_id":"{unknown}","verdict":"allow"}}"#));
    assert!(!result.applied);
    assert_eq!(harness.ignored_reasons(), [Value::Static("unknown_request")]);
    harness.assert_log_has_no_command();
    assert!(!asking.is_finished());
    let id = harness.pending_id();
    harness.respond(AUTHORITY, &format!(r#"{{"request_id":"{id}","verdict":"deny"}}"#));
    assert_eq!(asking.join().unwrap().reply, AskReply::Deny { reason: None });
}

// Only the registered authority answers: a socket, a control connection that did not register, or any connection
// while none is registered is `-32003`; a malformed answer is `-32602`. Neither touches the request.
#[test]
fn refuses_answers_not_from_the_authority() {
    let harness = Harness::new();
    let asking = harness.ask(LINE, Arc::new(StillWaiting));
    let id = harness.pending_id();
    let allow = format!(r#"{{"request_id":"{id}","verdict":"allow"}}"#);
    let code = |reply: Reply| reply.unwrap_err().code;
    // No authority registered yet.
    assert_eq!(
        code(harness.respond_on(Endpoint::Control, Some(AUTHORITY), &allow)),
        ErrorCode::NotAllowed
    );
    harness.decisions.registered(AUTHORITY);
    for (endpoint, connection) in [
        (Endpoint::User, None),
        (Endpoint::Agent, None),
        (Endpoint::Control, Some(ConnectionId(9))),
    ] {
        assert_eq!(
            code(harness.respond_on(endpoint, connection, &allow)),
            ErrorCode::NotAllowed
        );
    }
    let malformed = format!(r#"{{"request_id":"{id}","verdict":"rewrite"}}"#);
    assert_eq!(
        code(harness.respond_on(Endpoint::Control, Some(AUTHORITY), &malformed)),
        ErrorCode::InvalidParams
    );
    assert!(!asking.is_finished());
    assert!(harness.respond(AUTHORITY, &allow).applied);
    assert_eq!(asking.join().unwrap().reply, AskReply::Allow);
}
