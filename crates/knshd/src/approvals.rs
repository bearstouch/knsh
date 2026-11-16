//! Standalone approvals: `approval.list`, `approval.approve` and `approval.deny` on `user.sock` (KNSH-066;
//! FR-AUTH-40 to FR-AUTH-43, `specs/06-api/user-socket.md#approvals`,
//! `specs/04-non-functional-requirements/reliability.md#standalone-mode`).
//!
//! When no authority is connected, the orchestrator hands each ask to [`Approvals`] (its [`LocalApprovals`]). The
//! ask becomes a pending request with a new request ID and a `timeout_at`, and the agent's call waits on it. The
//! user answers from another terminal:
//!
//! - **`approval.list`** (`knsh approvals`) shows every pending request: request ID, session, actor, redacted command,
//!   working directory, matched rule (or hook), irreversibility and `timeout_at` (FR-AUTH-40).
//! - **`approval.approve`** (`knsh approve <id>`) makes `knshd` show the system Touch ID or password prompt itself,
//!   naming the exact command, its directory and session (FR-AUTH-41, decision 12). Only a successful prompt
//!   approves: any other outcome is `-32001` with `source: "user"`, and the request stays pending. No parameter skips
//!   the prompt, and the prompt waits at most until the request's own timeout (FR-AUTH-42).
//! - **`approval.deny`** (`knsh deny <id>`) refuses the request without a prompt: denying is never less safe
//!   (the story's proposal, recorded in the spec).
//!
//! A request ends exactly once, under the lock: answered, timed out (FR-AUTH-23) or cancelled because its caller
//! left (FR-AUTH-22). An answer for a request that has ended is refused: `-32002` when it timed out, `-32011` when it
//! was cancelled, `-32602` when it was already answered or is unknown. The last [`ENDED_MEMORY`] ended requests are
//! remembered so the refusal can say which.
//!
//! The agent never sees a yes/no question (FR-AUTH-43): `user.sock` is denied in every envelope, these methods are not
//! on `agent.sock`, and the prompt is a system dialog shown by `knshd`, not text in any terminal.
//!
//! The recorded decision's source is `user` for both answers (FR-REC-03): the pipeline sets it for any answer that
//! came through [`LocalApprovals`]. A request nobody answered is denied with source `standalone`.
//!
//! # Concurrency
//!
//! One lock, [`Approvals::state`], a leaf: nothing else is locked and no prompt is shown while it is held. A waiting
//! ask sleeps on [`Approvals::changed`] and wakes on any answer, or every [`CALLER_POLL`] to check its caller and
//! deadline. Deadlines are monotonic ([`Instant`]), so a wall-clock step never stretches or shortens a request;
//! `timeout_at` is the injected wall clock's view of the same deadline, for display.

use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use knsh_core::{AskAnswer, AskReply, AskRequest, Caller, LocalApprovals, RequestId, Timestamp, Ulid};
use knsh_json::{Object, Value};
use knsh_platform::{Clock, Level, NotAuthenticated, PromptReason, Random, SystemLog, UserPresence};
use knsh_proto::{
    ApprovalAnswerParams, ApprovalAnswerResult, ApprovalListParams, ApprovalListResult, ApprovalVerdict, Denial,
    ErrorCode, PendingApproval, RpcError,
};

use crate::dispatch::{Call, Endpoint, Handler, Handlers, Reply, answer, params};
use crate::supervisor::DEFAULT_ASK_TIMEOUT;

/// The method that lists pending requests.
const APPROVAL_LIST: &str = "approval.list";
/// The method that approves one, after the prompt.
const APPROVAL_APPROVE: &str = "approval.approve";
/// The method that denies one.
const APPROVAL_DENY: &str = "approval.deny";

/// How often a waiting ask checks whether its caller is still there.
const CALLER_POLL: Duration = Duration::from_millis(100);

/// How many ended requests are remembered, to tell a late answer why it is refused. Older ones are reported as
/// unknown, which is refused all the same.
pub(crate) const ENDED_MEMORY: usize = 256;

/// The reason a user's denial gives the agent.
pub(crate) const DENIED_BY_USER: &str = "denied by the user (knsh deny)";

/// The pending asks and the methods that answer them. One per `knshd`, shared by the orchestrator (which adds
/// requests) and the `user.sock` handlers (which answer them).
pub(crate) struct Approvals {
    /// Pending and recently ended requests. A leaf lock (module documentation, "Concurrency").
    state: Mutex<State>,
    /// Signalled whenever a request is answered.
    changed: Condvar,
    /// `timeout_at` and request IDs.
    clock: Arc<dyn Clock>,
    /// Request IDs.
    random: Arc<dyn Random>,
    /// The Touch ID or password prompt, shown by `knshd` itself.
    presence: Arc<dyn UserPresence>,
    /// Answers are logged without the command.
    log: Arc<dyn SystemLog>,
    /// How long a request waits for an answer (FR-AUTH-23).
    timeout: Duration,
}

/// What [`Approvals::state`] guards.
#[derive(Default)]
struct State {
    /// The pending requests, in ID (creation) order.
    pending: BTreeMap<RequestId, Pending>,
    /// The most recently ended requests and how they ended, oldest first, at most [`ENDED_MEMORY`].
    ended: VecDeque<(RequestId, Ended)>,
}

/// One pending request.
struct Pending {
    /// What `approval.list` shows.
    shown: PendingApproval,
    /// What the prompt names: the exact command, its directory and session.
    prompt: PromptReason,
    /// When it is denied if nobody answers.
    deadline: Instant,
    /// The user's answer, once given; the waiting ask takes it and ends the request.
    answer: Option<AskReply>,
}

/// How a request ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ended {
    /// The user approved or denied it.
    Answered,
    /// Nobody answered before its deadline.
    TimedOut,
    /// Its caller left first.
    Cancelled,
}

impl State {
    /// Ends `id`: removes it from the pending requests and remembers how it ended.
    fn end(&mut self, id: RequestId, how: Ended) -> Option<Pending> {
        let pending = self.pending.remove(&id);
        if self.ended.len() == ENDED_MEMORY {
            self.ended.pop_front();
        }
        self.ended.push_back((id, how));
        pending
    }

    /// The request `id`, if it is still pending and can be answered at `now`; otherwise the refusal to answer with.
    fn answerable(&mut self, id: RequestId, now: Instant) -> Result<&mut Pending, RpcError> {
        let Some(pending) = self.pending.get_mut(&id) else {
            let how = self
                .ended
                .iter()
                .rev()
                .find(|(ended, _)| *ended == id)
                .map(|(_, how)| *how);
            return Err(ended_error(id, how));
        };
        // Past its deadline but not yet collected by its waiting ask: already timed out (FR-AUTH-23).
        if now >= pending.deadline {
            return Err(ended_error(id, Some(Ended::TimedOut)));
        }
        if pending.answer.is_some() {
            return Err(ended_error(id, Some(Ended::Answered)));
        }
        Ok(pending)
    }
}

impl Approvals {
    /// The service, holding requests for `timeout` each and prompting through `presence`.
    pub(crate) fn new(
        clock: Arc<dyn Clock>,
        random: Arc<dyn Random>,
        presence: Arc<dyn UserPresence>,
        log: Arc<dyn SystemLog>,
        timeout: Duration,
    ) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(State::default()),
            changed: Condvar::new(),
            clock,
            random,
            presence,
            log,
            timeout,
        })
    }

    /// The service with the default timeout of 90 s (FR-AUTH-23).
    pub(crate) fn with_default_timeout(
        clock: Arc<dyn Clock>,
        random: Arc<dyn Random>,
        presence: Arc<dyn UserPresence>,
        log: Arc<dyn SystemLog>,
    ) -> Arc<Self> {
        Self::new(clock, random, presence, log, DEFAULT_ASK_TIMEOUT)
    }

    /// The three handlers.
    pub(crate) fn handlers(self: &Arc<Self>) -> Handlers {
        let lister = Arc::clone(self);
        let list: Handler = Arc::new(move |call: &Call<'_>| lister.list(call));
        let approver = Arc::clone(self);
        let approve: Handler = Arc::new(move |call: &Call<'_>| approver.approve(call));
        let denier = Arc::clone(self);
        let deny: Handler = Arc::new(move |call: &Call<'_>| denier.deny(call));
        [
            (APPROVAL_LIST, list),
            (APPROVAL_APPROVE, approve),
            (APPROVAL_DENY, deny),
        ]
        .into_iter()
        .collect()
    }

    /// The state, even if a thread panicked while holding it: every update is a single insert or remove, so the map
    /// is never half-changed.
    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// `approval.list`: every pending request, oldest first. Requests past their deadline are left out: they can no
    /// longer be approved.
    fn list(&self, call: &Call<'_>) -> Reply {
        user_only(call)?;
        let ApprovalListParams = params(call)?;
        let now = Instant::now();
        let requests = self
            .state()
            .pending
            .values()
            .filter(|pending| pending.answer.is_none() && now < pending.deadline)
            .map(|pending| pending.shown.clone())
            .collect();
        answer(&ApprovalListResult { requests })
    }

    /// `approval.approve`: the prompt first, then the answer, if the request is still pending (module
    /// documentation).
    fn approve(&self, call: &Call<'_>) -> Reply {
        user_only(call)?;
        let ApprovalAnswerParams { request_id } = params(call)?;
        // Checked before the prompt, so an ended request never shows one; the lock is released before the prompt.
        let (prompt, left) = {
            let now = Instant::now();
            let mut state = self.state();
            let pending = state.answerable(request_id, now)?;
            (pending.prompt.clone(), pending.deadline.saturating_duration_since(now))
        };
        // Never longer than the request has left: a prompt that outlives its request could only be refused.
        let _proof = self.presence.authenticate(&prompt, left).map_err(|refusal| {
            self.log.log(Level::Notice, "approval refused: not authenticated", &[]);
            not_authenticated(refusal)
        })?;
        // Checked again: the request may have timed out, been cancelled or answered while the prompt was up.
        self.answer(request_id, AskReply::Allow)?;
        self.log.log(Level::Notice, "ask approved by the user", &[]);
        answer(&ApprovalAnswerResult {
            request_id,
            verdict: ApprovalVerdict::Allow,
        })
    }

    /// `approval.deny`: no prompt, since a denial is never less safe.
    fn deny(&self, call: &Call<'_>) -> Reply {
        user_only(call)?;
        let ApprovalAnswerParams { request_id } = params(call)?;
        let reason = Some(DENIED_BY_USER.to_owned());
        self.answer(request_id, AskReply::Deny { reason })?;
        self.log.log(Level::Notice, "ask denied by the user", &[]);
        answer(&ApprovalAnswerResult {
            request_id,
            verdict: ApprovalVerdict::Deny,
        })
    }

    /// Gives `reply` to the pending request `id` and wakes its ask, or refuses if it can no longer be answered.
    fn answer(&self, id: RequestId, reply: AskReply) -> Result<(), RpcError> {
        let mut state = self.state();
        state.answerable(id, Instant::now())?.answer = Some(reply);
        drop(state);
        self.changed.notify_all();
        Ok(())
    }

    /// A new request ID and its `timeout_at`, or `None` if the clock or random source failed.
    fn identify(&self) -> Option<(RequestId, Timestamp)> {
        let now = self.clock.now().ok()?;
        let mut random = [0; 10];
        self.random.fill(&mut random).ok()?;
        let id = RequestId::from_ulid(Ulid::new(now.as_unix_millis(), random).ok()?);
        let timeout = u64::try_from(self.timeout.as_micros()).ok()?;
        let timeout_at = Timestamp::from_unix_micros(now.as_unix_micros().checked_add(timeout)?).ok()?;
        Some((id, timeout_at))
    }

    /// Waits for `id` to be answered, time out or lose its caller, and ends it.
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
            if gone {
                state.end(id, Ended::Cancelled);
                return AskReply::CallerGone;
            }
            let left = pending.deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                state.end(id, Ended::TimedOut);
                return AskReply::TimedOut;
            }
            // Spurious wake-ups only cost another look.
            drop(
                self.changed
                    .wait_timeout(state, left.min(CALLER_POLL))
                    .unwrap_or_else(PoisonError::into_inner),
            );
        }
    }
}

impl LocalApprovals for Approvals {
    fn ask(&self, request: &AskRequest<'_>, caller: &dyn Caller) -> AskAnswer {
        let failed = AskAnswer {
            request_id: None,
            reply: AskReply::Failed,
            decided_by: None,
        };
        let Some((request_id, timeout_at)) = self.identify() else {
            return failed;
        };
        let proposal = request.proposal;
        let command = proposal.command.expose();
        let pending = Pending {
            shown: PendingApproval {
                request_id,
                session_id: proposal.session_id,
                actor: proposal.actor.clone(),
                command: command.clone(),
                rewritten_from: proposal.rewritten_from.map(|from| from.expose().clone()),
                cwd: proposal.cwd.as_path().to_string_lossy().into_owned(),
                matched_rule: request.rule_id.map(str::to_owned),
                hook: request.hook.map(str::to_owned),
                // Not classified yet (KNSH-093): reported as unknown, never as reversible.
                irreversible: None,
                timeout_at,
            },
            prompt: PromptReason::agent_command(command, proposal.cwd, proposal.session_id),
            deadline: Instant::now() + self.timeout,
            answer: None,
        };
        self.state().pending.insert(request_id, pending);
        let reply = self.wait(request_id, caller);
        AskAnswer {
            request_id: Some(request_id),
            reply,
            decided_by: None,
        }
    }
}

/// `-32003` unless the call came on `user.sock`. The catalogue lists these methods only there; this is the second
/// lock on the door (FR-AUTH-43).
fn user_only(call: &Call<'_>) -> Result<(), RpcError> {
    match call.endpoint {
        Endpoint::User => Ok(()),
        // The authority answers asks with `decision.respond` (KNSH-069), never through the local approvals.
        Endpoint::Agent | Endpoint::Control => Err(RpcError::new(ErrorCode::NotAllowed)),
    }
}

/// The refusal for an answer to a request that is not pending: `-32002` when it timed out, `-32011` when its caller
/// left (both with `data.request_id`, as `exec.run` reports them), `-32602` with `data.reason` when it was already
/// answered or is unknown.
fn ended_error(id: RequestId, how: Option<Ended>) -> RpcError {
    let (code, data) = match how {
        Some(Ended::TimedOut) => (
            ErrorCode::DecisionTimeout,
            Object::new().with("request_id", id.to_string()),
        ),
        Some(Ended::Cancelled) => (ErrorCode::Cancelled, Object::new().with("request_id", id.to_string())),
        Some(Ended::Answered) => (
            ErrorCode::InvalidParams,
            Object::new().with("reason", "the request was already answered"),
        ),
        None => (
            ErrorCode::InvalidParams,
            Object::new().with("reason", "no pending request has this ID"),
        ),
    };
    let error = RpcError::new(code);
    match data {
        Ok(data) => error.with_data(Value::Object(data)),
        Err(_) => error,
    }
}

/// `-32001` from the user: the prompt did not succeed, so nothing was approved (decision 12).
fn not_authenticated(refusal: NotAuthenticated) -> RpcError {
    Denial {
        rule_id: None,
        reason: Some(format!("not authenticated: {refusal}")),
        source: Some(String::from("user")),
    }
    .to_error()
    .unwrap_or_else(|_| RpcError::new(ErrorCode::Denied))
}

#[cfg(test)]
pub(crate) mod tests;
