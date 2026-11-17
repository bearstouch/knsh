//! The decision protocol with the authority (KNSH-069; FR-AUTH-20 to FR-AUTH-24, FR-EVT-06, FR-LC-41,
//! `specs/06-api/control-service.md#decision-protocol`).
//!
//! When an authority is registered, the orchestrator asks it through [`Decisions`] (its [`Authority`]):
//!
//! 1. **Request.** The ask becomes a pending request with a new request ID and a `timeout_at`, and
//!    `decision.requested` is sent to the authority, and only to it (FR-AUTH-20, FR-EVT-06): request ID, session,
//!    actor, redacted command, working directory, matched rule, irreversibility and `timeout_at`. It is never
//!    published as an event.
//! 2. **Answer.** The authority calls `decision.respond` with `allow`, `deny` or `rewrite` (with `command`), an
//!    optional `grant` and an optional `reason` (FR-AUTH-21). Only the registered authority's connection may answer;
//!    any other is `-32003`. The answer is given to the matching pending request, and the waiting ask returns it.
//! 3. **Timeout.** A request nobody answered within the timeout (90 s by default, FR-AUTH-23) is denied: the
//!    caller gets `-32002`.
//! 4. **Cancellation.** If the caller disconnects first, the request is cancelled and the line never runs
//!    (FR-AUTH-22, FR-LC-41). Both endings send `decision.cancelled` to the authority, so it can withdraw its prompt;
//!    the orchestrator publishes the `decision.cancelled` event as well.
//! 5. **Reconnection.** When the authority's connection ends, its requests keep waiting. When an authority
//!    registers again, every request still pending and not timed out is sent to it again, with its original ID and
//!    `timeout_at` (FR-AUTH-24).
//!
//! An answer for a request that is unknown, already answered, timed out or cancelled is ignored (`applied: false`)
//! and logged with a fixed reason only, never the command (FR-AUTH-22).
//!
//! # Grants
//!
//! A `grant` in an `allow` creates a grant (KNSH-042, FR-POL-62) for the asked line ([`line_grant_rule`]), scoped to
//! the asking session or its profile, lasting `duration_s` from the answer. It is created only when the answer is
//! applied, and returned as `grant_id`. A line that cannot be written as a rule, a clock or random source that
//! fails, or a full store means no grant (`grant_id: null`, logged); the verdict still applies, since a missing grant
//! only ever asks more.
//!
//! # Sending
//!
//! Notifications to the authority are sent by one courier thread, in the order they were queued. Queuing never
//! blocks or locks a connection, so they can be queued from inside a call on the authority's own connection
//! (`authority.register` re-sending its requests) without deadlocking on that connection's lock, and the answer to
//! that call is always sent before them. A notification that cannot be delivered is dropped: the request still ends
//! by its answer, its timeout or its caller.
//!
//! # Concurrency
//!
//! One lock, [`Decisions::state`]. Lock order: the registration's lock (which calls [`AuthorityWatch`]), then this
//! one, then the grant store's; nothing is sent while it is held. A waiting ask sleeps on [`Decisions::changed`] and
//! wakes on any answer, or every [`CALLER_POLL`] to check its caller and deadline. Deadlines are on the injected
//! clock's monotonic reading, so a wall-clock step never stretches or shortens a request; `timeout_at` is the wall
//! clock's view of the same deadline, for display.

use std::collections::{BTreeMap, VecDeque};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError, Weak};
use std::thread;
use std::time::Duration;

use knsh_core::{
    AskAnswer, AskReply, AskRequest, Authority, Caller, CancelReason, Grant, GrantId, GrantScope, ProfileName,
    RequestId, SessionId, Timestamp, Ulid, line_grant_rule,
};
use knsh_json::ToJson;
use knsh_platform::{Clock, ConnectionId, Field, Level, Monotonic, Random, SystemLog, Value};
use knsh_proto::{
    DECISION_CANCELLED, DECISION_REQUESTED, DecisionAnswer, DecisionCancelledParams, DecisionRequestedParams,
    DecisionRespondParams, DecisionRespondResult, ErrorCode, GrantRequest, GrantRequestScope, Message, MethodName,
    Notification, PendingApproval, RpcError, encode,
};

use crate::dispatch::{Call, Endpoint, Handler, Handlers, Reply, answer, params};
use crate::grants::GrantStore;
use crate::supervisor::DEFAULT_ASK_TIMEOUT;

/// The method the authority answers with.
const DECISION_RESPOND: &str = "decision.respond";

/// How many ended requests are remembered, to log why a late answer was ignored: as many as standalone approvals
/// remember.
const ENDED_MEMORY: usize = 256;

/// How often a waiting ask checks whether its caller is still there (FR-LC-41).
const CALLER_POLL: Duration = Duration::from_millis(100);

/// Delivers notifications to a control connection: the control service ([`crate::control::ControlEndpoint`]).
pub(crate) trait AuthorityLink: Send + Sync {
    /// Sends `json`, one JSON-RPC notification, to `connection`, in order with its answers.
    ///
    /// # Errors
    ///
    /// `Err` if the connection is not open or the send failed.
    fn notify(&self, connection: ConnectionId, json: &[u8]) -> Result<(), ()>;
}

/// Told when an authority registers and when its connection ends ([`crate::authority::Registration`]).
pub(crate) trait AuthorityWatch: Send + Sync {
    /// `connection` is now the authority.
    fn registered(&self, connection: ConnectionId);
    /// `connection`, the authority, has gone.
    fn unregistered(&self, connection: ConnectionId);
}

/// One notification for the courier.
struct Notice {
    connection: ConnectionId,
    json: Vec<u8>,
}

/// The decision protocol (module documentation). One per `knshd`.
pub(crate) struct Decisions {
    /// The authority and the requests. Lock order in the module documentation.
    state: Mutex<State>,
    /// Signalled whenever a request is answered.
    changed: Condvar,
    /// Queues notifications for the courier; the courier starts with [`Decisions::attach`].
    outbox: Mutex<Sender<Notice>>,
    /// The courier's end, until it starts.
    inbox: Mutex<Option<Receiver<Notice>>>,
    /// Where answered grants go.
    grants: Arc<GrantStore>,
    /// Deadlines, `timeout_at`, request and grant IDs, grant expiry.
    clock: Arc<dyn Clock>,
    /// Request and grant IDs.
    random: Arc<dyn Random>,
    /// Fixed messages only: never a command.
    log: Arc<dyn SystemLog>,
    /// How long a request waits for an answer (FR-AUTH-23).
    timeout: Duration,
}

/// What [`Decisions::state`] guards.
#[derive(Default)]
struct State {
    /// The registered authority's connection, if one is registered.
    authority: Option<ConnectionId>,
    /// The pending requests, in ID (creation) order.
    pending: BTreeMap<RequestId, Pending>,
    /// The most recently ended requests and how they ended, oldest first, at most [`ENDED_MEMORY`]: only to log why
    /// a late answer was ignored.
    ended: VecDeque<(RequestId, Ended)>,
}

/// One pending request.
struct Pending {
    /// The `decision.requested` notification, encoded once and re-sent as is on reconnection (FR-AUTH-24).
    requested: Vec<u8>,
    /// When it is denied if nobody answers.
    deadline: Monotonic,
    /// What a grant from its answer would cover: the session, its profile and the line as a rule, if it can be one.
    grant_target: GrantTarget,
    /// The authority's answer, once given; the waiting ask takes it and ends the request.
    answer: Option<AskReply>,
}

/// What a grant made from a request's answer applies to. Cloned out of the lock, so the grant is made without it.
#[derive(Clone)]
struct GrantTarget {
    session_id: SessionId,
    profile: ProfileName,
    /// The asked line as a command pattern; `None` when it cannot be written as one.
    rule: Option<String>,
}

/// How a request ended, for the log of an ignored answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ended {
    Answered,
    TimedOut,
    Cancelled,
}

impl Ended {
    /// The log's `reason` for an answer to a request that ended this way.
    const fn ignored_because(self) -> &'static str {
        match self {
            Self::Answered => "already_answered",
            Self::TimedOut => "timed_out",
            Self::Cancelled => "cancelled",
        }
    }
}

impl State {
    /// Ends `id`: removes it from the pending requests and remembers how it ended.
    fn end(&mut self, id: RequestId, how: Ended) {
        self.pending.remove(&id);
        if self.ended.len() == ENDED_MEMORY {
            self.ended.pop_front();
        }
        self.ended.push_back((id, how));
    }

    /// How `id` ended, if it is remembered.
    fn ended(&self, id: RequestId) -> Option<Ended> {
        self.ended
            .iter()
            .rev()
            .find(|(ended, _)| *ended == id)
            .map(|(_, how)| *how)
    }
}

impl Decisions {
    /// The protocol, holding requests for `timeout` each and putting answered grants in `grants`.
    pub(crate) fn new(
        clock: Arc<dyn Clock>,
        random: Arc<dyn Random>,
        log: Arc<dyn SystemLog>,
        grants: Arc<GrantStore>,
        timeout: Duration,
    ) -> Arc<Self> {
        let (outbox, inbox) = mpsc::channel();
        Arc::new(Self {
            state: Mutex::new(State::default()),
            changed: Condvar::new(),
            outbox: Mutex::new(outbox),
            inbox: Mutex::new(Some(inbox)),
            grants,
            clock,
            random,
            log,
            timeout,
        })
    }

    /// The protocol with the default timeout of 90 s (FR-AUTH-23).
    pub(crate) fn with_default_timeout(
        clock: Arc<dyn Clock>,
        random: Arc<dyn Random>,
        log: Arc<dyn SystemLog>,
        grants: Arc<GrantStore>,
    ) -> Arc<Self> {
        Self::new(clock, random, log, grants, DEFAULT_ASK_TIMEOUT)
    }

    /// Starts the courier, delivering every queued and future notification through `link`. Weak, so the courier
    /// never keeps the control service alive. Only the first call starts it.
    ///
    /// # Errors
    ///
    /// `Err` if the courier thread could not start: nothing will reach the authority, so every request it would
    /// have been sent times out and is denied (fail closed).
    pub(crate) fn attach(&self, link: Weak<dyn AuthorityLink>) -> Result<(), ()> {
        let Some(inbox) = lock(&self.inbox).take() else {
            return Ok(());
        };
        let started = thread::Builder::new()
            .name("knshd-decisions".to_owned())
            .spawn(move || courier(&inbox, &link));
        if started.is_err() {
            self.log.log(Level::Error, "decision courier not started", &[]);
            return Err(());
        }
        Ok(())
    }

    /// The live grants answers add to, which every line is evaluated with.
    pub(crate) fn grants(&self) -> Arc<GrantStore> {
        Arc::clone(&self.grants)
    }

    /// The handler for `decision.respond`.
    pub(crate) fn handlers(self: &Arc<Self>) -> Handlers {
        let decisions = Arc::clone(self);
        let respond: Handler = Arc::new(move |call: &Call<'_>| decisions.respond(call));
        [(DECISION_RESPOND, respond)].into_iter().collect()
    }

    /// The state, even if a thread panicked while holding it: every update is a single insert, remove or field.
    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Queues `json` for `connection`. Never blocks; a courier that has stopped drops it.
    fn send(&self, connection: ConnectionId, json: Vec<u8>) {
        let _ = lock(&self.outbox).send(Notice { connection, json });
    }

    /// `decision.respond` (module documentation, step 2).
    fn respond(&self, call: &Call<'_>) -> Reply {
        let Some(connection) = control_connection(call) else {
            return Err(RpcError::new(ErrorCode::NotAllowed));
        };
        let DecisionRespondParams {
            request_id,
            answer: verdict,
            grant,
            reason,
        } = params(call)?;
        let mut state = self.state();
        // Only the registered authority answers: another verified control connection may be waiting to register.
        if state.authority != Some(connection) {
            drop(state);
            self.log.log(
                Level::Notice,
                "decision answer refused: not from the registered authority",
                &[],
            );
            return Err(RpcError::new(ErrorCode::NotAllowed));
        }
        let now = self.clock.monotonic();
        let open = match state.pending.get_mut(&request_id) {
            // Past its deadline but not yet collected by its waiting ask: it has already timed out (FR-AUTH-23), so a
            // late answer can never turn a timeout into an allow.
            Some(pending) if now >= pending.deadline => Err(Ended::TimedOut.ignored_because()),
            // The first answer stands; a second one never replaces it.
            Some(pending) if pending.answer.is_some() => Err(Ended::Answered.ignored_because()),
            Some(pending) => Ok(pending),
            None => Err(state
                .ended(request_id)
                .map_or("unknown_request", Ended::ignored_because)),
        };
        let pending = match open {
            Ok(pending) => pending,
            Err(why) => {
                drop(state);
                // FR-AUTH-22: ignored and logged with a fixed reason, never the command.
                self.log.log(
                    Level::Notice,
                    "decision answer ignored",
                    &[Field::new("reason", Value::Static(why))],
                );
                return answer(&DecisionRespondResult {
                    applied: false,
                    grant_id: None,
                });
            }
        };
        pending.answer = Some(match verdict {
            DecisionAnswer::Allow => AskReply::Allow,
            DecisionAnswer::Deny => AskReply::Deny { reason },
            DecisionAnswer::Rewrite { command } => AskReply::Rewrite { command },
        });
        // Copied only when a grant is asked for, so the grant is made after the lock is released (the grant store's
        // lock comes after this one, and nothing slow runs under it).
        let grant = grant.map(|grant| (grant, pending.grant_target.clone()));
        drop(state);
        self.changed.notify_all();
        self.log.log(Level::Notice, "decision answered by the authority", &[]);
        let grant_id = grant.and_then(|(grant, target)| self.create_grant(grant, target));
        answer(&DecisionRespondResult {
            applied: true,
            grant_id,
        })
    }

    /// Creates the grant an applied answer asked for (module documentation, "Grants"), or logs why it could not.
    fn create_grant(&self, request: GrantRequest, target: GrantTarget) -> Option<GrantId> {
        let refuse = |why: &'static str| {
            self.log.log(
                Level::Notice,
                "grant from the authority's answer not created",
                &[Field::new("reason", Value::Static(why))],
            );
            None
        };
        let Some(rule) = target.rule else {
            return refuse("line_not_a_rule");
        };
        let Some((now, id)) = self.new_id() else {
            return refuse("no_clock_or_random");
        };
        let expires_at = request
            .duration_s
            .checked_mul(1_000_000)
            .and_then(|micros| now.as_unix_micros().checked_add(micros))
            .and_then(|micros| Timestamp::from_unix_micros(micros).ok());
        let Some(expires_at) = expires_at else {
            return refuse("expiry_out_of_range");
        };
        let scope = match request.scope {
            GrantRequestScope::Session => GrantScope::Session(target.session_id),
            GrantRequestScope::Profile => GrantScope::Profile(target.profile),
        };
        let id = GrantId::from_ulid(id);
        // `line_grant_rule` already checked the rule is a valid pattern, so this is a second check, not a new case.
        // Exact: the grant covers the asked line, not the same command with more arguments (KNSH-069).
        let Ok(grant) = Grant::exact(id, scope, &rule, expires_at) else {
            return refuse("line_not_a_rule");
        };
        if self.grants.insert(grant, now).is_err() {
            return refuse("store_refused");
        }
        self.log
            .log(Level::Notice, "grant created from the authority's answer", &[]);
        Some(id)
    }

    /// The current wall time and a new ULID at it, or `None` if the clock or random source failed.
    fn new_id(&self) -> Option<(Timestamp, Ulid)> {
        let now = self.clock.now().ok()?;
        let mut random = [0; 10];
        self.random.fill(&mut random).ok()?;
        Some((now, Ulid::new(now.as_unix_millis(), random).ok()?))
    }

    /// The pending request for `request` (step 1), or `None` if the clock, random source or encoding failed.
    fn request(&self, request: &AskRequest<'_>) -> Option<(RequestId, Pending)> {
        let (now, id) = self.new_id()?;
        let request_id = RequestId::from_ulid(id);
        let timeout = u64::try_from(self.timeout.as_micros()).ok()?;
        let timeout_at = Timestamp::from_unix_micros(now.as_unix_micros().checked_add(timeout)?).ok()?;
        let deadline = self.clock.monotonic().checked_add(self.timeout)?;
        let proposal = request.proposal;
        let params: DecisionRequestedParams = PendingApproval {
            request_id,
            session_id: proposal.session_id,
            actor: proposal.actor.clone(),
            // Redacted text only: the authority never sees a secret (FR-REC-05).
            command: proposal.command.expose().clone(),
            rewritten_from: proposal.rewritten_from.map(|from| from.expose().clone()),
            cwd: proposal.cwd.as_path().to_string_lossy().into_owned(),
            matched_rule: request.rule_id.map(str::to_owned),
            hook: request.hook.map(str::to_owned),
            // Not classified yet (KNSH-093): reported as unknown, never as reversible.
            irreversible: None,
            timeout_at,
        };
        let requested = notification(DECISION_REQUESTED, &params)?;
        let grant_target = GrantTarget {
            session_id: proposal.session_id,
            profile: request.profile.clone(),
            rule: line_grant_rule(proposal.classification),
        };
        Some((
            request_id,
            Pending {
                requested,
                deadline,
                grant_target,
                answer: None,
            },
        ))
    }

    /// Waits for `id` to be answered, time out or lose its caller, and ends it (steps 2 to 4).
    fn wait(&self, id: RequestId, caller: &dyn Caller) -> AskReply {
        loop {
            // The caller is checked without the lock: it peeks at a socket.
            let gone = caller.gone();
            let mut state = self.state();
            let Some(pending) = state.pending.get_mut(&id) else {
                // Only this ask ends its own request; a missing one is a bug. Deny (fail closed).
                return AskReply::Failed;
            };
            if let Some(reply) = pending.answer.take() {
                state.end(id, Ended::Answered);
                return reply;
            }
            let left = pending.deadline.saturating_duration_since(self.clock.monotonic());
            // A caller that left wins over a timeout reached at the same look: the line must not run either way, and
            // `caller_gone` is the truer reason (FR-LC-41).
            let ending = if gone {
                Some((Ended::Cancelled, CancelReason::CallerGone, AskReply::CallerGone))
            } else if left.is_zero() {
                Some((Ended::TimedOut, CancelReason::TimedOut, AskReply::TimedOut))
            } else {
                None
            };
            if let Some((how, reason, reply)) = ending {
                state.end(id, how);
                let authority = state.authority;
                drop(state);
                // The authority was sent the request (now or on registering), so it is told it ended.
                if let Some(connection) = authority {
                    self.cancel(connection, id, reason);
                }
                return reply;
            }
            // Spurious wake-ups only cost another look.
            drop(
                self.changed
                    .wait_timeout(state, left.min(CALLER_POLL))
                    .unwrap_or_else(PoisonError::into_inner),
            );
        }
    }

    /// Sends `decision.cancelled` for `id` to `connection`.
    fn cancel(&self, connection: ConnectionId, request_id: RequestId, reason: CancelReason) {
        match notification(DECISION_CANCELLED, &DecisionCancelledParams { request_id, reason }) {
            Some(json) => self.send(connection, json),
            None => self.log.log(Level::Error, "decision.cancelled not encoded", &[]),
        }
    }
}

impl Authority for Decisions {
    fn connected(&self) -> bool {
        self.state().authority.is_some()
    }

    fn ask(&self, request: &AskRequest<'_>, caller: &dyn Caller) -> AskAnswer {
        let Some((request_id, pending)) = self.request(request) else {
            self.log.log(Level::Error, "decision request not made", &[]);
            return AskAnswer {
                request_id: None,
                reply: AskReply::Failed,
                decided_by: None,
            };
        };
        let requested = pending.requested.clone();
        let authority = {
            let mut state = self.state();
            state.pending.insert(request_id, pending);
            state.authority
        };
        // Without an authority now (it left since the orchestrator looked), the request waits for one to register
        // or for its timeout (FR-AUTH-24).
        if let Some(connection) = authority {
            self.send(connection, requested);
        }
        let reply = self.wait(request_id, caller);
        AskAnswer {
            request_id: Some(request_id),
            reply,
            decided_by: None,
        }
    }
}

impl AuthorityWatch for Decisions {
    fn registered(&self, connection: ConnectionId) {
        let now = self.clock.monotonic();
        let resend: Vec<Vec<u8>> = {
            let mut state = self.state();
            state.authority = Some(connection);
            // FR-AUTH-24: every request still waiting and not timed out, oldest first.
            state
                .pending
                .values()
                .filter(|pending| pending.answer.is_none() && now < pending.deadline)
                .map(|pending| pending.requested.clone())
                .collect()
        };
        for json in resend {
            self.send(connection, json);
        }
    }

    fn unregistered(&self, connection: ConnectionId) {
        let mut state = self.state();
        if state.authority == Some(connection) {
            state.authority = None;
        }
    }
}

/// The control connection a call came on, or `None` when it came on a socket.
fn control_connection(call: &Call<'_>) -> Option<ConnectionId> {
    match (call.endpoint, call.control) {
        (Endpoint::Control, Some(connection)) => Some(connection),
        (Endpoint::User | Endpoint::Agent | Endpoint::Control, _) => None,
    }
}

/// `{"jsonrpc":"2.0","method":<method>,"params":<params>}`, or `None` if it cannot be encoded.
fn notification(method: &str, params: &impl ToJson) -> Option<Vec<u8>> {
    let params = params.to_json().ok()?.as_object()?.clone();
    let message = Message::Notification(Notification {
        method: MethodName::new(method).ok()?,
        params: Some(params),
    });
    encode(&message).ok().map(String::into_bytes)
}

/// The courier: delivers queued notifications in order until every sender is gone. A notification for a link that
/// no longer exists, or that cannot be delivered, is dropped.
fn courier(inbox: &Receiver<Notice>, link: &Weak<dyn AuthorityLink>) {
    while let Ok(Notice { connection, json }) = inbox.recv() {
        if let Some(link) = link.upgrade() {
            let _ = link.notify(connection, &json);
        }
    }
}

/// Takes a lock even if another thread panicked while holding it: every update under these locks is one step.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

#[cfg(test)]
pub(crate) mod tests;
