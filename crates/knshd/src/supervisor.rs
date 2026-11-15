//! The lifecycle orchestrator: the driver that takes each forwarded agent line through the eleven lifecycle steps
//! (KNSH-050, `specs/03-functional-requirements/command-lifecycle.md`).
//!
//! The decision itself is the pure pipeline [`knsh_core::decide`] (steps 2 to 8). This module performs its effects:
//!
//! - **Before the decision**: the line's record ID (from the injected clock and random source), the session's actor
//!   and profile, and the profile loaded as `policy.check` loads it. Any failure here denies the line (NFR-REL-07):
//!   no clock or random bytes, no record store to record into, a profile that cannot be loaded.
//! - **During it**: `command.proposed` is published for each evaluation pass ([`ProposedEvents`]); hooks, the
//!   authority and standalone approvals are trait objects ([`Hooks`], [`Authority`], [`LocalApprovals`]).
//! - **After it**: a refused line publishes `decision.cancelled` when it was cancelled or timed out, writes its record
//!   (FR-REC-03), publishes `command.denied` (FR-LC-32) and is answered `-32001`, `-32002` or `-32011`. An allowed
//!   line is checked against its caller once more (FR-LC-41), handed to the [`Spawner`] (KNSH-051), recorded, and
//!   `command.finished` is published (FR-LC-19).
//!
//! Nothing is spawned unless the pipeline returned [`Outcome::Run`] and the caller is still connected (FR-LC-09,
//! FR-LC-30). Everything before the spawn runs inside a `catch_unwind` boundary as defence in depth: a panic there is
//! a deny.
//!
//! The record's `decision` object is the pipeline's [`Decision`] with the measured latency
//! ([`Decision::to_record`]), so the two always match. `latency_ms` is the time from receiving the line to the final
//! decision, on the injected clock.
//!
//! # Not yet served
//!
//! `exec.run` stays `planned` until the spawner exists (KNSH-051), so `knshd` does not build this orchestrator yet;
//! tests drive it with fakes, end to end through `agent.sock`. Grants are not consulted until the grant store exists
//! (KNSH-073): every line is evaluated without them, which only ever asks more.

use std::panic::{self, AssertUnwindSafe};
use std::path::Path;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use knsh_core::{
    Actor, Allowed, AskAnswer, AskReply, AskRequest, Authority, BinaryLookup, Caller, CancelReason, CanonicalPath,
    Decision, DecisionSource, Effects, EventData, ExecutionRecord, Hooks, INTERNAL_ERROR, LineInput, LocalApprovals,
    Observer, Outcome, Profile, ProfileName, Proposal, RecordDetails, RecordId, Refusal, RefusalKind, RequestId,
    SessionId, Timestamp, Ulid, decide, redact,
};
use knsh_json::{Object, ToJson, Value};
use knsh_platform::{Clock, Random};
use knsh_proto::{Denial, ErrorCode, LineStatus, RpcError};
use knsh_store::{RecordStore, RecordedOutput};

use crate::events::EventHub;
use crate::exec::{Finished, ForwardedLine, Supervisor};
use crate::policy::ProfileLoader;
use crate::sessions::Sessions;

/// How long an ask waits for an answer by default (FR-AUTH-23).
pub(crate) const DEFAULT_ASK_TIMEOUT: Duration = Duration::from_secs(90);

/// How often a waiting ask checks whether its caller is still there.
const CALLER_POLL: Duration = Duration::from_millis(100);

/// Reasons for denials the driver makes itself, before the pipeline decides. Fixed texts.
const NO_STORE: &str = "the record store is unavailable, so the line cannot be recorded and was denied (fail closed)";
const NO_PROFILE: &str = "the session's profile could not be loaded, so the line was denied (fail closed)";
const NO_CLOCK: &str = "the supervisor could not read its clock or random source, so the line was denied (fail closed)";
/// Reason for a line allowed by the pipeline whose caller left before it could be spawned (FR-LC-41).
const GONE_BEFORE_SPAWN: &str = "the caller disconnected before the line started, so it was cancelled";

/// Lifecycle steps 9 and 10: starting an allowed line through `knsh-exec` and waiting for it (KNSH-051).
pub(crate) trait Spawner: Send + Sync {
    /// Runs `plan` and waits for it to end.
    ///
    /// # Errors
    ///
    /// The answer for a line that did not run to its end: `-32008` when killed at its timeout, `-32603` when it could
    /// not be started (the line did not run).
    fn spawn(&self, plan: SpawnPlan) -> Result<LineStatus, RpcError>;
}

/// An allowed line, ready to spawn: what was received with it and what the decision made of it.
#[derive(Debug)]
pub(crate) struct SpawnPlan {
    /// The record the line is written to.
    pub(crate) record_id: RecordId,
    /// The line as received: interpreter, operands, environment, descriptors, timeout.
    pub(crate) line: ForwardedLine,
    /// The decision: the re-serialised line to run and its profile.
    pub(crate) allowed: Allowed,
}

/// Standalone handling when no authority is connected and local approvals are not available yet (KNSH-066 adds
/// `knsh approve`): the request waits, so the caller can still go away, and is denied at the timeout
/// (`specs/04-non-functional-requirements/reliability.md#standalone-mode`).
#[derive(Debug, Clone, Copy)]
pub(crate) struct DenyAtTimeout {
    /// How long a request waits.
    pub(crate) timeout: Duration,
}

impl Default for DenyAtTimeout {
    fn default() -> Self {
        Self {
            timeout: DEFAULT_ASK_TIMEOUT,
        }
    }
}

impl LocalApprovals for DenyAtTimeout {
    fn ask(&self, _request: &AskRequest<'_>, caller: &dyn Caller) -> AskAnswer {
        // Monotonic: a wall clock stepping back must not hold a request longer than its timeout.
        let deadline = Instant::now() + self.timeout;
        let reply = loop {
            if caller.gone() {
                break AskReply::CallerGone;
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                break AskReply::TimedOut;
            }
            thread::sleep(left.min(CALLER_POLL));
        };
        AskAnswer {
            request_id: None,
            reply,
            decided_by: None,
        }
    }
}

/// The effects the orchestrator needs, shared by every connection.
pub(crate) struct Parts {
    /// The live sessions: the bound session's actor and profile.
    pub(crate) sessions: Arc<Sessions>,
    /// Loads the session's profile.
    pub(crate) profiles: ProfileLoader,
    /// Where lifecycle events go.
    pub(crate) events: Arc<EventHub>,
    /// Where records go; `None` when it could not be opened, and then every line is denied.
    pub(crate) store: Option<RecordStore>,
    /// Record IDs and latency.
    pub(crate) clock: Arc<dyn Clock>,
    /// Record IDs.
    pub(crate) random: Arc<dyn Random>,
    /// The `command.proposed` hooks (KNSH-062).
    pub(crate) hooks: Arc<dyn Hooks + Send + Sync>,
    /// The authority, when one is connected (KNSH-069).
    pub(crate) authority: Arc<dyn Authority + Send + Sync>,
    /// Standalone approvals (KNSH-066).
    pub(crate) approvals: Arc<dyn LocalApprovals + Send + Sync>,
    /// Starts allowed lines (KNSH-051).
    pub(crate) spawner: Arc<dyn Spawner>,
}

/// The orchestrator: the [`Supervisor`] behind `exec.run`.
pub(crate) struct Lifecycle {
    parts: Parts,
}

/// A line that may be spawned: everything its record needs once it ends. A line that may not is an `Err` holding
/// its answer, already recorded and reported.
struct Ready {
    record_id: RecordId,
    actor: Actor,
    allowed: Box<Allowed>,
    latency_ms: u64,
    /// When the line was received: the record's start if the clock cannot be read at the spawn.
    received_at: Timestamp,
}

impl Lifecycle {
    /// The orchestrator over `parts`.
    pub(crate) fn new(parts: Parts) -> Arc<Self> {
        Arc::new(Self { parts })
    }

    /// Steps 1 to 8 and the handling of a refusal, for `line` from `caller` (module documentation).
    fn prepare(&self, line: &ForwardedLine, caller: &dyn Caller) -> Result<Ready, RpcError> {
        let parts = &self.parts;
        let session_id = line.session_id;
        // The session ended under the call: there is no one to record for, and nothing runs.
        let (actor, profile_name) = parts.sessions.agent_of(session_id)?;
        let Some((received_at, record_id)) = self.record_id() else {
            return Err(self.refuse_early(line, &actor, None, NO_CLOCK));
        };
        let record = Some((record_id, received_at));
        // A line that cannot be recorded must not run (NFR-REL-05, FR-REC-02).
        if parts.store.is_none() {
            return Err(self.refuse_early(line, &actor, record, NO_STORE));
        }
        let Some(profile) = self.profile(&profile_name, line) else {
            return Err(self.refuse_early(line, &actor, record, NO_PROFILE));
        };

        let observer = ProposedEvents {
            events: &parts.events,
            session_id,
            actor: &actor,
        };
        let lookup = FsLookup(parts.profiles.fs());
        let effects = Effects {
            lookup: &lookup,
            observer: &observer,
            hooks: &*parts.hooks,
            authority: &*parts.authority,
            approvals: &*parts.approvals,
            caller,
        };
        let input = LineInput {
            session_id,
            actor: &actor,
            profile: &profile,
            grants: None,
            command: &line.proposal.command,
            cwd: &line.proposal.cwd,
            env_path: &line.proposal.path,
        };
        let outcome = decide(&input, &effects);
        let latency_ms = self.since(received_at);
        let refusal = match outcome {
            // FR-LC-41: the caller left after the decision but before the spawn: the line still never runs. Nobody
            // decided this, so it is recorded like a cancellation inside the pipeline: a deny by standalone rules.
            Outcome::Run(allowed) if caller.gone() => Refusal {
                decision: Decision::deny(DecisionSource::Standalone, None, None),
                command: allowed.command,
                rewritten_from: allowed.rewritten_from,
                reason: Some(GONE_BEFORE_SPAWN.to_owned()),
                kind: RefusalKind::Cancelled { request_id: None },
            },
            Outcome::Run(allowed) => {
                return Ok(Ready {
                    record_id,
                    actor,
                    allowed,
                    latency_ms,
                    received_at,
                });
            }
            Outcome::Refused(refusal) => *refusal,
        };
        Err(self.refused(line, &actor, record_id, received_at, latency_ms, &refusal))
    }

    /// The time the line was received and its record ID, or `None` if the clock or random source failed.
    fn record_id(&self) -> Option<(Timestamp, RecordId)> {
        let now = self.parts.clock.now().ok()?;
        let mut random = [0; 10];
        self.parts.random.fill(&mut random).ok()?;
        let ulid = Ulid::new(now.as_unix_millis(), random).ok()?;
        Some((now, RecordId::from_ulid(ulid)))
    }

    /// The session's profile, or `None` if it cannot be loaded.
    fn profile(&self, name: &ProfileName, line: &ForwardedLine) -> Option<Profile> {
        self.parts.profiles.load(name, line.proposal.cwd.as_path()).ok()
    }

    /// Milliseconds since `then` on the injected clock; 0 if the clock cannot be read or stepped back.
    fn since(&self, then: Timestamp) -> u64 {
        self.parts.clock.now().map_or(0, |now| {
            now.as_unix_micros().saturating_sub(then.as_unix_micros()) / 1000
        })
    }

    /// A deny the driver makes before the pipeline runs (module documentation, "Before the decision"): recorded
    /// when a record ID and a store exist, reported, and answered `-32001`.
    fn refuse_early(
        &self,
        line: &ForwardedLine,
        actor: &Actor,
        record: Option<(RecordId, Timestamp)>,
        reason: &str,
    ) -> RpcError {
        let refusal = Refusal {
            decision: Decision::deny(DecisionSource::Rule, None, None),
            command: line.proposal.command.clone(),
            rewritten_from: None,
            reason: Some(reason.to_owned()),
            kind: RefusalKind::Denied,
        };
        // Without a record ID (no clock or random bytes) nothing can be recorded; the denial is still reported.
        let Some((record_id, received_at)) = record else {
            self.publish_denied(line, actor, None, &refusal);
            return denial_error(&refusal);
        };
        let latency_ms = self.since(received_at);
        self.refused(line, actor, record_id, received_at, latency_ms, &refusal)
    }

    /// A refused line (FR-LC-30 to FR-LC-32, FR-LC-41): `decision.cancelled` if it was cancelled or timed out, its
    /// record, `command.denied`, and the error to answer with. The order is the spec's: the pending decision ends
    /// before the denial is recorded, and `command.denied` names the record only once it was written.
    fn refused(
        &self,
        line: &ForwardedLine,
        actor: &Actor,
        record_id: RecordId,
        received_at: Timestamp,
        latency_ms: u64,
        refusal: &Refusal,
    ) -> RpcError {
        let session_id = line.session_id;
        let cancelled = match refusal.kind {
            RefusalKind::Denied => None,
            RefusalKind::TimedOut { request_id } => Some((request_id, CancelReason::TimedOut)),
            RefusalKind::Cancelled { request_id } => Some((request_id, CancelReason::CallerGone)),
        };
        if let Some((request_id, reason)) = cancelled {
            let data = EventData::DecisionCancelled { request_id, reason };
            let _ = self.parts.events.publish(session_id, actor, data);
        }
        // FR-REC-03: always recorded, without output, whatever the recording settings.
        let record = ExecutionRecord {
            record_id,
            session_id,
            actor: actor.clone(),
            command: redact(&refusal.command),
            cwd: line.proposal.cwd.clone(),
            started_at: received_at,
            ended_at: Some(self.parts.clock.now().unwrap_or(received_at)),
            exit_code: None,
            details: RecordDetails {
                rewritten_from: refusal.rewritten_from.as_deref().map(redact),
                decision: Some(refusal.decision.to_record(latency_ms)),
                ..RecordDetails::default()
            },
        };
        let written = self.write(record);
        self.publish_denied(line, actor, written.then_some(record_id), refusal);
        match refusal.kind {
            RefusalKind::Denied => denial_error(refusal),
            RefusalKind::TimedOut { request_id } => request_error(ErrorCode::DecisionTimeout, request_id),
            RefusalKind::Cancelled { request_id } => request_error(ErrorCode::Cancelled, request_id),
        }
    }

    /// Publishes `command.denied` (FR-LC-32). Best effort, like every event.
    fn publish_denied(&self, line: &ForwardedLine, actor: &Actor, record_id: Option<RecordId>, refusal: &Refusal) {
        let data = EventData::CommandDenied {
            record_id,
            command: redact(&refusal.command),
            cwd: line.proposal.cwd.clone(),
            source: refusal.decision.source,
            rule_id: refusal.decision.rule_id.as_deref().map(redact),
            reason: refusal.reason.as_deref().map(redact),
        };
        let _ = self.parts.events.publish(line.session_id, actor, data);
    }

    /// Writes `record`; whether it was written.
    fn write(&self, record: ExecutionRecord) -> bool {
        self.parts
            .store
            .as_ref()
            .is_some_and(|store| store.write_record(record, RecordedOutput::default()).is_ok())
    }

    /// Step 11 for a line that was spawned (FR-LC-19): its record, then `command.finished`. Returns whether the
    /// record was written. The full record (argv, output, signal, file changes) is KNSH-052's.
    #[allow(clippy::too_many_arguments)]
    fn finished(
        &self,
        session_id: SessionId,
        actor: &Actor,
        record_id: RecordId,
        cwd: &CanonicalPath,
        started_at: Timestamp,
        allowed: &Allowed,
        latency_ms: u64,
        status: Option<LineStatus>,
    ) -> bool {
        let ended_at = self.parts.clock.now().unwrap_or(started_at);
        let exit_code = match status {
            Some(LineStatus::Exited(code)) => Some(i32::from(code)),
            Some(LineStatus::Signalled(_)) | None => None,
        };
        let command = redact(&allowed.command);
        let record = ExecutionRecord {
            record_id,
            session_id,
            actor: actor.clone(),
            command: command.clone(),
            cwd: cwd.clone(),
            started_at,
            ended_at: Some(ended_at),
            exit_code,
            details: RecordDetails {
                rewritten_from: allowed.rewritten_from.as_deref().map(redact),
                decision: Some(allowed.decision.to_record(latency_ms)),
                ..RecordDetails::default()
            },
        };
        let written = self.write(record);
        if written {
            let data = EventData::CommandFinished {
                record_id,
                command,
                cwd: cwd.clone(),
                started_at,
                ended_at,
                exit_code,
            };
            let _ = self.parts.events.publish(session_id, actor, data);
        }
        written
    }
}

impl Supervisor for Lifecycle {
    fn run(&self, line: ForwardedLine, caller: &dyn Caller) -> Result<Finished, RpcError> {
        // Defence in depth (NFR-REL-07): a panic before the spawn is a deny. Only shared references cross.
        let Ready {
            record_id,
            actor,
            allowed,
            latency_ms,
            received_at,
        } = panic::catch_unwind(AssertUnwindSafe(|| self.prepare(&line, caller)))
            .unwrap_or_else(|_| Err(denial(None, Some(INTERNAL_ERROR.to_owned()), DecisionSource::Rule)))?;
        let session_id = line.session_id;
        let cwd = line.proposal.cwd.clone();
        // Never a 1970 start, which retention would expire at once.
        let started_at = self.parts.clock.now().unwrap_or(received_at);
        let plan = SpawnPlan {
            record_id,
            line,
            allowed: (*allowed).clone(),
        };
        let spawned = self.parts.spawner.spawn(plan);
        let status = spawned.as_ref().ok().copied();
        let written = self.finished(
            session_id, &actor, record_id, &cwd, started_at, &allowed, latency_ms, status,
        );
        let status = spawned?;
        Ok(Finished {
            record_id: written.then_some(record_id),
            status,
        })
    }
}

/// Binary lookups through the platform filesystem, as a sized value the pipeline can hold as `&dyn BinaryLookup`.
struct FsLookup<'a>(&'a dyn knsh_platform::Fs);

impl BinaryLookup for FsLookup<'_> {
    fn canonicalise(&self, path: &Path) -> Option<CanonicalPath> {
        BinaryLookup::canonicalise(self.0, path)
    }

    fn is_executable_file(&self, path: &CanonicalPath) -> bool {
        BinaryLookup::is_executable_file(self.0, path)
    }
}

/// Publishes `command.proposed` for each pass of one line (lifecycle step 3).
struct ProposedEvents<'a> {
    events: &'a EventHub,
    session_id: SessionId,
    actor: &'a Actor,
}

impl Observer for ProposedEvents<'_> {
    fn proposed(&self, proposal: &Proposal<'_>) {
        let data = EventData::CommandProposed {
            command: proposal.command.clone(),
            cwd: proposal.cwd.clone(),
            rewritten_from: proposal.rewritten_from.cloned(),
        };
        // Best effort (FR-EVT-04): a full or failing bus never decides a line.
        let _ = self.events.publish(self.session_id, self.actor, data);
    }
}

/// `-32001` with the refusal's rule, reason and source: what `knsh -c` prints before it exits 126 (FR-LC-31).
fn denial_error(refusal: &Refusal) -> RpcError {
    denial(
        refusal.decision.rule_id.clone(),
        refusal.reason.clone(),
        refusal.decision.source,
    )
}

/// `-32001` with its `data`; a bare `-32001` if the data cannot be written, so the line is still denied.
fn denial(rule_id: Option<String>, reason: Option<String>, source: DecisionSource) -> RpcError {
    Denial {
        rule_id,
        reason,
        source: Some(source.code().to_owned()),
    }
    .to_error()
    .unwrap_or_else(|_| RpcError::new(ErrorCode::Denied))
}

/// `code` with `data.request_id` (`-32002`, `-32011`), `null` when no request had been made.
fn request_error(code: ErrorCode, request_id: Option<RequestId>) -> RpcError {
    let data = request_id
        .map(|id| id.to_string())
        .to_json()
        .and_then(|id| Object::new().with("request_id", id));
    match data {
        Ok(data) => RpcError::new(code).with_data(Value::Object(data)),
        Err(_) => RpcError::new(code),
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod socket_tests;
