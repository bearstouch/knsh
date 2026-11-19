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
//! # Repeated denials (KNSH-055)
//!
//! The orchestrator owns the daemon's [`DenialLimiter`]. The pipeline asks it, at the time of each pass, whether
//! the line is limited ([`RateLimits`]), and denies a limited line with source `rate_limit` before any hook
//! or ask (FR-HOOK-20). After a refusal is recorded and `command.denied` published, the denial is counted unless the
//! limiter itself caused it, the line was cancelled, or it was refused before it was parsed; the denial that starts a
//! limit publishes `command.denied_repeatedly` right after its `command.denied` (FR-HOOK-21). Time comes from the
//! injected clock. The limiter's lock is a leaf: nothing else is locked or called while it is held.
//!
//! # Output (KNSH-053)
//!
//! A line's output is captured when the caller did not pass its stdio (`exec.run` and `exec.start` from an agent
//! that integrates natively) or when the session records output: its profile's `recording.output` (FR-REC-06), or
//! what the authority set for the session with `recording.set` (KNSH-071), which takes its place. Only in
//! the second case is it stored with the record and published as `command.output` (FR-LC-18): with
//! `recording.output = false` (the default) nothing is stored and nothing is emitted, and a captured line's output
//! goes only to its caller. Every chunk passes the [`OutputRedaction`] hook first (FR-EVT-07).
//!
//! # Held lines (KNSH-054)
//!
//! A line for a session that is paused or under human control is answered `-32007` with `data.state` before anything
//! else, and nothing about it is recorded: the client sends it again (FR-SES-10, FR-SES-12). The session is checked
//! once more after the decision, which may have waited on an ask for a long time: a line allowed for a session that
//! was paused or taken over meanwhile is recorded as a deny with [`HELD_AFTER_DECISION`] and answered `-32007` too.
//! A line spawned in the instant between that check and a pause is stopped as soon as its group is kept
//! ([`crate::holds`]).
//!
//! Nothing is spawned unless the pipeline returned [`Outcome::Run`] and the caller is still connected (FR-LC-09,
//! FR-LC-30). Everything before the spawn runs inside a `catch_unwind` boundary as defence in depth: a panic there is
//! a deny.
//!
//! The record's `decision` object is the pipeline's [`Decision`] with the measured latency
//! ([`Decision::to_record`]), so the two always match. `latency_ms` is the time from receiving the line to the final
//! decision, on the injected clock.
//!
//! # Grants
//!
//! Every line is evaluated with a copy of the live grants ([`GrantStore`]) at the injected clock's time (FR-POL-60,
//! KNSH-042): a grant only ever turns an ask into an allow. If the clock cannot be read, no grant applies.

use std::panic::{self, AssertUnwindSafe};
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use knsh_checkpoint::{Gate, ShadowProgress, gate, line_touches_root};
use knsh_core::{
    Actor, Allowed, Authority, BinaryLookup, Caller, CancelReason, CanonicalPath, Counted, Decision, DecisionSource,
    DenialLimiter, Effects, EventData, ExecutionRecord, Hooks, INTERNAL_ERROR, LineInput, LineKey, LocalApprovals,
    NetworkEntry, Observer, Outcome, OutputRedaction, OutputStream, Profile, Proposal, RateLimits, RecordDetails,
    RecordId, Redacted, Refusal, RefusalKind, RequestId, SessionId, Timestamp, Ulid, UnprotectedReason,
    UnprotectedRoot, argv_of, decide, redact,
};
use knsh_json::{Object, ToJson, Value};
use knsh_platform::{Clock, ProcessGroupId, Processes, Random};
use knsh_proto::{Denial, ErrorCode, LineStatus, RpcError};
use knsh_store::{RecordStore, RecordedOutput};

use crate::capture::{CapturePlan, LineOutput, OutputSink};
use crate::events::EventHub;
use crate::exec::{Finished, ForwardedLine, Supervisor};
use crate::grants::GrantStore;
use crate::holds::{GroupKind, Kept};
use crate::jobs::LineControl;
use crate::policy::ProfileLoader;
use crate::sessions::Sessions;
use crate::shadows::ClosedLine;

/// How long an ask waits for an answer by default (FR-AUTH-23).
pub(crate) const DEFAULT_ASK_TIMEOUT: Duration = Duration::from_secs(90);

/// Reasons for denials the driver makes itself, before the pipeline decides. Fixed texts.
const NO_STORE: &str = "the record store is unavailable, so the line cannot be recorded and was denied (fail closed)";
const NO_PROFILE: &str = "the session's profile could not be loaded, so the line was denied (fail closed)";
/// Reason for a line whose profile file (or a parent's) has a missing or bad signature (FR-POL-42, KNSH-065).
const INVALID_PROFILE: &str =
    "the session's policy file has a missing or bad signature and was ignored, so the line was denied (fail closed)";
const NO_CLOCK: &str = "the supervisor could not read its clock or random source, so the line was denied (fail closed)";
/// Reason for a line allowed by the pipeline whose session was paused or taken over before it could be spawned
/// (FR-SES-10, FR-SES-12). The client sends the line again and it is decided afresh.
const HELD_AFTER_DECISION: &str =
    "the session was paused or taken over while the line was decided, so it was held and did not start";
/// Reason for a line allowed by the pipeline whose session ended before it could be spawned.
const ENDED_AFTER_DECISION: &str = "the session ended while the line was decided, so it did not start";
/// Reason for a line allowed by the pipeline whose caller left before it could be spawned (FR-LC-41).
const GONE_BEFORE_SPAWN: &str = "the caller disconnected before the line started, so it was cancelled";
/// Reason for a line refused because a checkpoint root it touches has no shadow, or its shadow failed, while the
/// profile requires checkpoints (FR-CKP-02, KNSH-079): it would have run unprotected.
const NO_SHADOW: &str = "checkpoints are required but a checkpoint root the line touches cannot be protected, so it was denied (fail closed)";
/// Reason recorded for a line answered `-32010`: a root's shadow was still being built and the caller did not wait.
const SHADOW_NOT_READY: &str =
    "a checkpoint root the line touches is still being shadowed and the caller did not wait, so it did not start";
/// How long one wait for a shadow lasts before the caller and the session are checked again (FR-CKP-02).
const SHADOW_WAIT_SLICE: Duration = Duration::from_millis(100);

/// Lifecycle steps 9 and 10: starting an allowed line through `knsh-exec` and waiting for it (KNSH-051,
/// [`crate::spawn::TrampolineSpawner`]).
pub(crate) trait Spawner: Send + Sync {
    /// Runs `plan`, reports its start and a long run through `events`, and waits for it to end.
    fn spawn(&self, plan: SpawnPlan, events: &dyn LineEvents) -> SpawnReport;
}

/// What a [`Spawner`] reports while a line runs (FR-LC-17). Best effort: an event never decides anything.
pub(crate) trait LineEvents {
    /// The line was spawned as `group` by `processes`: keeps the group as one of its session's, so a pause stops it
    /// (FR-SES-10). The spawner drops the handle before it reaps the group.
    fn keep(&self, group: ProcessGroupId, processes: Arc<dyn Processes>) -> Kept;
    /// The line was spawned: `command.started`.
    fn started(&self);
    /// The line is still running after the long-running threshold: `command.long_running`, at most once.
    fn long_running(&self);
}

/// An allowed line, ready to spawn: what was received with it and what the decision made of it.
#[derive(Debug)]
pub(crate) struct SpawnPlan {
    /// The record the line is written to.
    pub(crate) record_id: RecordId,
    /// The line as received: interpreter, operands, environment, descriptors, timeout.
    pub(crate) line: ForwardedLine,
    /// The decision: the re-serialised line to run, what it resolved to and its profile.
    pub(crate) allowed: Allowed,
    /// The session's profile, as loaded for the decision: the baseline the line's sandbox profile is compiled
    /// from, and its bash (FR-LC-12, FR-LC-14).
    pub(crate) profile: Profile,
    /// How its output is captured, or `None` when it goes straight to the caller's descriptors (module
    /// documentation, "Output").
    pub(crate) capture: Option<CapturePlan>,
}

/// How a spawn went.
#[derive(Debug)]
pub(crate) struct SpawnReport {
    /// The record's `sandbox_profile`, once the line's profile was written (FR-SBX-07).
    pub(crate) sandbox_profile: Option<String>,
    /// How the line ended, or why it did not run to its end.
    pub(crate) outcome: Result<Ran, SpawnFailure>,
    /// Its captured output, when it was captured and the line was spawned.
    pub(crate) output: Option<LineOutput>,
    /// The hosts the proxy let the line contact or refused it: the record's `network` field (FR-NET-09, KNSH-060).
    pub(crate) network: Vec<NetworkEntry>,
}

/// A line that ran and was reaped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Ran {
    /// Its exit code or the signal that ended it.
    pub(crate) status: LineStatus,
    /// Whether it was killed at its `timeout_s` (FR-LC-40): answered `-32008`.
    pub(crate) timed_out: bool,
}

/// Why a line did not run to its end. Each is answered `-32603`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SpawnFailure {
    /// The proxy could not issue the line's own credentials (FR-NET-01): nothing was started.
    ProxyCredentials,
    /// Its compiled profile could not be written and checked: nothing was started.
    ProfileFile,
    /// `knsh-exec` could not be started.
    Start(knsh_platform::PlatformError),
    /// `knsh-exec` started but failed with this exit code before `sandbox-exec` ran: the profile was never applied
    /// and the line never ran (NFR-REL-08).
    Trampoline(u8),
    /// The line could not be watched or reaped; it was killed.
    Wait(knsh_platform::PlatformError),
}

impl SpawnFailure {
    /// A fixed name for logs.
    pub(crate) const fn kind(self) -> &'static str {
        match self {
            Self::ProxyCredentials => "proxy_credentials",
            Self::ProfileFile => "profile_file",
            Self::Start(_) => "start",
            Self::Trampoline(_) => "profile_not_applied",
            Self::Wait(_) => "wait",
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
    /// Standalone approvals: `knsh approve` and `knsh deny` ([`crate::approvals::Approvals`], KNSH-066).
    pub(crate) approvals: Arc<dyn LocalApprovals + Send + Sync>,
    /// The live grants, a copy of which every line is evaluated with (KNSH-042, KNSH-069).
    pub(crate) grants: Arc<GrantStore>,
    /// Starts allowed lines (KNSH-051).
    pub(crate) spawner: Arc<dyn Spawner>,
    /// The hook every output chunk passes before it is stored, emitted or returned (FR-EVT-07): a pass-through
    /// until secret redaction arrives (KNSH-091).
    pub(crate) redaction: Arc<dyn OutputRedaction>,
}

/// `command.started` and `command.long_running` for one line, from the [`Spawner`] (FR-LC-17).
struct RunningEvents<'a> {
    events: &'a EventHub,
    session_id: SessionId,
    actor: &'a Actor,
    record_id: RecordId,
    command: Redacted<String>,
    cwd: &'a CanonicalPath,
    started_at: Timestamp,
    /// Told when the line is spawned, so `exec.start` can answer.
    control: &'a LineControl,
    /// Keeps the line's process group with its session's (KNSH-054).
    sessions: &'a Sessions,
    /// The line's process group once spawned: at its end, members still alive are asked which files they hold for
    /// writing (FR-CKP-24, KNSH-085).
    group: Mutex<Option<ProcessGroupId>>,
}

impl RunningEvents<'_> {
    /// Best effort (FR-EVT-04): an event that cannot be published never changes how the line runs.
    fn publish(&self, data: EventData) {
        let _ = self.events.publish(self.session_id, self.actor, data);
    }
}

impl LineEvents for RunningEvents<'_> {
    fn keep(&self, group: ProcessGroupId, processes: Arc<dyn Processes>) -> Kept {
        *self.group.lock().unwrap_or_else(PoisonError::into_inner) = Some(group);
        self.sessions
            .keep_group(self.session_id, group, processes, GroupKind::Line)
    }

    fn started(&self) {
        self.control.mark_started(self.record_id);
        self.publish(EventData::CommandStarted {
            record_id: self.record_id,
            command: self.command.clone(),
            cwd: self.cwd.clone(),
            started_at: self.started_at,
        });
    }

    fn long_running(&self) {
        self.publish(EventData::CommandLongRunning {
            record_id: self.record_id,
            command: self.command.clone(),
            cwd: self.cwd.clone(),
            started_at: self.started_at,
        });
    }
}

/// `command.output` for one line (FR-LC-18): owned, because the capture's reader threads may outlive the call.
struct OutputEvents {
    events: Arc<EventHub>,
    session_id: SessionId,
    actor: Actor,
    record_id: RecordId,
}

impl OutputSink for OutputEvents {
    fn chunk(&self, stream: OutputStream, offset: u64, bytes: &Redacted<Vec<u8>>) {
        let data = EventData::CommandOutput {
            record_id: self.record_id,
            stream,
            offset,
            bytes: bytes.clone(),
        };
        // Best effort (FR-EVT-04): a full or failing bus never changes how the line runs.
        let _ = self.events.publish(self.session_id, &self.actor, data);
    }
}

/// The orchestrator: the [`Supervisor`] behind `exec.run`.
pub(crate) struct Lifecycle {
    parts: Parts,
    /// Denials counted per session and line (KNSH-055). A leaf lock (module documentation, "Repeated denials").
    limiter: Mutex<DenialLimiter>,
}

/// A line that may be spawned: everything its record needs once it ends. A line that may not is an `Err` holding
/// its answer, already recorded and reported.
struct Ready {
    record_id: RecordId,
    actor: Actor,
    allowed: Box<Allowed>,
    /// The session's profile the line was decided with, for its sandbox profile.
    profile: Box<Profile>,
    latency_ms: u64,
    /// When the line was received: the record's start if the clock cannot be read at the spawn.
    received_at: Timestamp,
    /// Checkpoint roots it touches whose changes are not protected: the record's `unprotected` (KNSH-079).
    unprotected: Vec<UnprotectedRoot>,
    /// Checkpoint roots it touches whose shadow is ready: their watchers mark its start and run the line-end flush
    /// (KNSH-080).
    protected: Vec<CanonicalPath>,
}

/// Why the checkpoint gate stopped an allowed line (FR-CKP-02).
enum Blocked {
    /// The caller did not wait for a shadow still being built: `-32010`.
    NotReady {
        root: CanonicalPath,
        progress: ShadowProgress,
    },
    /// A root will never be protected and the profile requires checkpoints: denied (fail closed).
    NoShadow,
    /// The caller left while it waited.
    CallerGone,
    /// The session was paused, taken over or ended while it waited: the hold (`-32007`) or `-32006`.
    Held(RpcError),
}

impl Lifecycle {
    /// The orchestrator over `parts`.
    pub(crate) fn new(parts: Parts) -> Arc<Self> {
        Arc::new(Self {
            parts,
            limiter: Mutex::new(DenialLimiter::new()),
        })
    }

    /// Steps 1 to 8 and the handling of a refusal, for `line` from `caller` (module documentation).
    fn prepare(&self, line: &ForwardedLine, caller: &dyn Caller) -> Result<Ready, RpcError> {
        let parts = &self.parts;
        let session_id = line.session_id;
        // The session ended under the call: there is no one to record for, and nothing runs. A session that holds its
        // lines answers `-32007` here, before anything is recorded (module documentation, "Held lines").
        let (actor, profile_name) = parts.sessions.runnable(session_id)?;
        let Some((received_at, record_id)) = self.record_id() else {
            return Err(self.refuse_early(line, &actor, None, NO_CLOCK));
        };
        let record = Some((record_id, received_at));
        // A line that cannot be recorded must not run (NFR-REL-05, FR-REC-02).
        if parts.store.is_none() {
            return Err(self.refuse_early(line, &actor, record, NO_STORE));
        }
        let profile = match self.parts.profiles.load(&profile_name, line.proposal.cwd.as_path()) {
            Ok(profile) => profile,
            Err(error) => {
                // FR-POL-42: a policy file with a missing or bad signature is reported on the session, and the line
                // is denied; the session never falls back to another profile.
                let reason = match crate::policy::invalid_profile(&error) {
                    Some(invalid) => {
                        let data = EventData::PolicyInvalid { profile: invalid };
                        let _ = self.parts.events.publish(line.session_id, &actor, data);
                        INVALID_PROFILE
                    }
                    None => NO_PROFILE,
                };
                return Err(self.refuse_early(line, &actor, record, reason));
            }
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
            limits: &Limits {
                limiter: &self.limiter,
                clock: &*parts.clock,
                received_at,
            },
        };
        // A copy, so no lock is held while the decision waits on an ask. Without a clock no grant applies (fail
        // closed: an ask stays an ask).
        let grants = parts.grants.snapshot();
        let input = LineInput {
            session_id,
            actor: &actor,
            profile: &profile,
            grants: parts.clock.now().ok().map(|now| (&grants, now)),
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
                classification: Some(allowed.classification),
                line_key: None,
            },
            // The session was paused or taken over while the line was decided (module documentation, "Held lines"):
            // recorded as a deny so the decision is not lost, and answered with the hold so the client retries.
            Outcome::Run(allowed) if let Err(hold) = parts.sessions.runnable(session_id) => {
                return Err(self.blocked(
                    line,
                    &actor,
                    (record_id, received_at, latency_ms),
                    allowed,
                    Blocked::Held(hold),
                ));
            }
            // FR-CKP-02: an allowed line touching a checkpoint root whose shadow is not ready waits, fails with
            // `-32010`, or is denied, as `checkpoints.required` and the caller ask. Recorded as a deny when stopped,
            // like a held line, so the decision is not lost.
            Outcome::Run(allowed) => match self.checkpoint_gate(line, &profile, caller) {
                Ok((unprotected, protected)) => {
                    return Ok(Ready {
                        record_id,
                        actor,
                        allowed,
                        profile: Box::new(profile),
                        latency_ms,
                        received_at,
                        unprotected,
                        protected,
                    });
                }
                Err(blocked) => {
                    return Err(self.blocked(line, &actor, (record_id, received_at, latency_ms), allowed, blocked));
                }
            },
            Outcome::Refused(refusal) => *refusal,
        };
        Err(self.refused(line, &actor, record_id, received_at, latency_ms, &refusal))
    }

    /// Records an allowed line that may not be spawned as a deny, so its decision is not lost, and returns its answer
    /// (module documentation, "Held lines"; FR-CKP-02, KNSH-079): the session's hold (`-32007`, or `-32006` if it
    /// ended), `-32010` with the root and progress, `-32001` (no shadow, fail closed) or `-32011` (caller gone).
    /// `record` is the line's record ID, receipt time and decision latency. The rules allowed the line, so none of
    /// these counts as a denial of it (FR-HOOK-20).
    fn blocked(
        &self,
        line: &ForwardedLine,
        actor: &Actor,
        (record_id, received_at, latency_ms): (RecordId, Timestamp, u64),
        allowed: Box<Allowed>,
        blocked: Blocked,
    ) -> RpcError {
        let (reason, kind) = match &blocked {
            Blocked::NotReady { .. } => (SHADOW_NOT_READY, RefusalKind::Denied),
            Blocked::NoShadow => (NO_SHADOW, RefusalKind::Denied),
            Blocked::CallerGone => (GONE_BEFORE_SPAWN, RefusalKind::Cancelled { request_id: None }),
            Blocked::Held(hold) if hold.code == ErrorCode::SessionHeld => (HELD_AFTER_DECISION, RefusalKind::Denied),
            Blocked::Held(_) => (ENDED_AFTER_DECISION, RefusalKind::Denied),
        };
        let refusal = Refusal {
            decision: Decision::deny(DecisionSource::Standalone, None, None),
            command: allowed.command,
            rewritten_from: allowed.rewritten_from,
            reason: Some(reason.to_owned()),
            kind,
            classification: Some(allowed.classification),
            line_key: None,
        };
        let error = self.refused(line, actor, record_id, received_at, latency_ms, &refusal);
        match blocked {
            Blocked::NotReady { root, progress } => not_ready(&root, progress),
            Blocked::Held(hold) => hold,
            Blocked::NoShadow | Blocked::CallerGone => error,
        }
    }

    /// The checkpoint gate for an allowed line (FR-CKP-02, KNSH-079): the roots of `profile` the line touches
    /// ([`line_touches_root`]), each with its session's shadow, decided by [`gate`]. A waiting caller waits in slices
    /// of [`SHADOW_WAIT_SLICE`], and stops waiting when it disconnects or its session is held or ends. Returns the
    /// roots whose changes are not protected, for the record, and the touched roots that are (KNSH-080).
    fn checkpoint_gate(
        &self,
        line: &ForwardedLine,
        profile: &Profile,
        caller: &dyn Caller,
    ) -> Result<(Vec<UnprotectedRoot>, Vec<CanonicalPath>), Blocked> {
        let sessions = &self.parts.sessions;
        let session_id = line.session_id;
        let touched: Vec<&CanonicalPath> = profile
            .checkpoints
            .roots
            .iter()
            .filter(|root| line_touches_root(root, &line.proposal.cwd, &profile.fs.write))
            .collect();
        let mut waited = false;
        loop {
            let roots: Vec<_> = touched
                .iter()
                .map(|root| ((*root).clone(), sessions.shadow_readiness(session_id, root)))
                .collect();
            match gate(profile.checkpoints.required, line.checkpoint_wait, &roots) {
                Gate::Run { unprotected } => {
                    // After a wait, the caller and the session are checked once more: either may have changed during
                    // the last slice, and a line held or abandoned meanwhile must not start (FR-LC-41, "Held lines").
                    if waited {
                        if caller.gone() {
                            return Err(Blocked::CallerGone);
                        }
                        if let Err(hold) = sessions.runnable(session_id) {
                            return Err(Blocked::Held(hold));
                        }
                    }
                    let protected = touched
                        .iter()
                        .filter(|root| unprotected.iter().all(|(other, _)| other != **root))
                        .map(|root| (*root).clone())
                        .collect();
                    let unprotected = unprotected
                        .into_iter()
                        .map(|(root, reason)| UnprotectedRoot { root, reason })
                        .collect();
                    return Ok((unprotected, protected));
                }
                Gate::NotReady { root, progress } => return Err(Blocked::NotReady { root, progress }),
                // Every reason denies alike; listed so a new one is considered here.
                Gate::Deny {
                    reason:
                        UnprotectedReason::ShadowBuilding | UnprotectedReason::ShadowFailed | UnprotectedReason::NoShadow,
                    ..
                } => return Err(Blocked::NoShadow),
                Gate::Wait { root } => {
                    if caller.gone() {
                        return Err(Blocked::CallerGone);
                    }
                    if let Err(hold) = sessions.runnable(session_id) {
                        return Err(Blocked::Held(hold));
                    }
                    let _ = sessions.wait_for_shadow(session_id, &root, SHADOW_WAIT_SLICE);
                    waited = true;
                }
            }
        }
    }

    /// The time the line was received and its record ID, or `None` if the clock or random source failed.
    fn record_id(&self) -> Option<(Timestamp, RecordId)> {
        let now = self.parts.clock.now().ok()?;
        let mut random = [0; 10];
        self.parts.random.fill(&mut random).ok()?;
        let ulid = Ulid::new(now.as_unix_millis(), random).ok()?;
        Some((now, RecordId::from_ulid(ulid)))
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
            // Refused before step 2: the line was never parsed, so its record has no `argv` and no rate-limit key.
            classification: None,
            line_key: None,
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
        // FR-REC-03: always recorded, without output, whatever the recording settings (`recording.commands` and the
        // session's `recording` never suppress an agent record, FR-REC-01).
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
                argv: refusal.classification.as_ref().map(argv_of).unwrap_or_default(),
                ..RecordDetails::default()
            },
        };
        let written = self.write(record, RecordedOutput::default());
        self.publish_denied(line, actor, written.then_some(record_id), refusal);
        self.count_denial(line, actor, refusal, received_at);
        match refusal.kind {
            RefusalKind::Denied => denial_error(refusal),
            RefusalKind::TimedOut { request_id } => request_error(ErrorCode::DecisionTimeout, request_id),
            RefusalKind::Cancelled { request_id } => request_error(ErrorCode::Cancelled, request_id),
        }
    }

    /// Counts `refusal` towards rate limiting its line (FR-HOOK-20), and publishes `command.denied_repeatedly` when
    /// this denial starts a limit (FR-HOOK-21). Not counted: a denial by the limit itself (it would only prolong it),
    /// a cancellation (nobody denied the line), and a line refused before it was parsed (it has no key).
    fn count_denial(&self, line: &ForwardedLine, actor: &Actor, refusal: &Refusal, received_at: Timestamp) {
        let Some(key) = refusal.line_key else { return };
        let counts = match refusal.kind {
            RefusalKind::Denied | RefusalKind::TimedOut { .. } => refusal.decision.source != DecisionSource::RateLimit,
            RefusalKind::Cancelled { .. } => false,
        };
        if !counts {
            return;
        }
        // The time of the denial; the line's receipt time if the clock cannot be read now.
        let now = self.parts.clock.now().unwrap_or(received_at);
        let counted = lock(&self.limiter).record_denial(line.session_id, key, now);
        if let Counted::Started { until } = counted {
            let data = EventData::CommandDeniedRepeatedly {
                command: redact(&refusal.command),
                cwd: line.proposal.cwd.clone(),
                until,
            };
            // Best effort (FR-EVT-04): the limit applies whether or not the event is delivered.
            let _ = self.parts.events.publish(line.session_id, actor, data);
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

    /// Writes `record` with `output`; whether it was written.
    fn write(&self, record: ExecutionRecord, output: RecordedOutput) -> bool {
        self.parts
            .store
            .as_ref()
            .is_some_and(|store| store.write_record(record, output).is_ok())
    }

    /// Step 11 for a line handed to the spawner (FR-LC-19): its record, with its output when `record_output`
    /// (FR-REC-06), then `command.finished`. Returns whether the record was written, and when the line ended; the
    /// caller answers only after this returns, so the reply never precedes the commit (FR-REC-02, NFR-REL-05). A line
    /// that did not run to its end is recorded too, with neither exit code nor signal (NFR-REL-08). Its file changes
    /// are recorded from `closed`: how they were attributed (`attribution`, KNSH-081), and their checkpoint
    /// (`checkpoint_id`, `files_changed` with post-image identities, KNSH-082); roots whose changes were not protected
    /// are listed too (`unprotected`, KNSH-079).
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
        report: &SpawnReport,
        record_output: bool,
        unprotected: Vec<UnprotectedRoot>,
        closed: &ClosedLine,
    ) -> (bool, Timestamp) {
        let ended_at = self.parts.clock.now().unwrap_or(started_at);
        let ran = report.outcome.as_ref().ok();
        let (exit_code, signal) = match ran {
            // FR-LC-40: a timed-out line always got `SIGTERM` first; one that then exited by itself (it trapped the
            // signal) records that signal beside its exit code. Had `SIGKILL` ended it, it would be `Signalled`.
            Some(Ran {
                status: LineStatus::Exited(code),
                timed_out,
            }) => (Some(i32::from(*code)), timed_out.then(|| signal_name(15))),
            // A line ended by a signal (at its timeout or not) records that signal.
            Some(Ran {
                status: LineStatus::Signalled(number),
                ..
            }) => (None, Some(signal_name(*number))),
            None => (None, None),
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
                argv: argv_of(&allowed.classification),
                signal,
                sandbox_profile: report.sandbox_profile.clone(),
                network: report.network.clone(),
                // FR-CKP-02 with `required = false`: the roots this line changed unprotected (KNSH-079).
                unprotected,
                // FR-CKP-05, FR-CKP-07: the line's own changes (`command`), or a set it overlapped (`concurrent`).
                attribution: Some(closed.attribution),
                // KNSH-082, FR-CKP-11: its checkpoint, and the paths it changed with their post-image identities;
                // nothing for a line that touched no protected root.
                checkpoint_id: closed.checkpoint.as_ref().map(|checkpoint| checkpoint.id),
                files_changed: closed.protected.then(|| {
                    closed
                        .checkpoint
                        .as_ref()
                        .map(|checkpoint| checkpoint.files.clone())
                        .unwrap_or_default()
                }),
                // `pipestatus` stays empty: the line runs in a separate bash whose `PIPESTATUS` is not reported back
                // yet (KNSH-100). `secrets_injected` stays empty: no secret is injected in phase 2 (FR-REC-11).
                ..RecordDetails::default()
            },
        };
        // FR-REC-06: stored only when the session records output; already redacted and capped when captured.
        let output = match &report.output {
            Some(output) if record_output => RecordedOutput {
                stdout: Some(output.stdout.output.clone()),
                stderr: Some(output.stderr.output.clone()),
            },
            Some(_) | None => RecordedOutput::default(),
        };
        let written = self.write(record, output);
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
        (written, ended_at)
    }

    /// How `line` is captured (module documentation, "Output"), given whether its session records output: `None` when
    /// its output goes straight to passed descriptors in a session that does not record output.
    fn capture_plan(
        &self,
        line: &ForwardedLine,
        record_output: bool,
        actor: &Actor,
        record_id: RecordId,
    ) -> Option<CapturePlan> {
        if line.stdio.is_some() && !record_output {
            return None;
        }
        let sink = record_output.then(|| {
            Arc::new(OutputEvents {
                events: Arc::clone(&self.parts.events),
                session_id: line.session_id,
                actor: actor.clone(),
                record_id,
            }) as Arc<dyn OutputSink>
        });
        Some(CapturePlan {
            redaction: Arc::clone(&self.parts.redaction),
            // A line is only spawned with a store (it is denied otherwise), so this is the store's cap.
            cap: self
                .parts
                .store
                .as_ref()
                .map_or(knsh_core::DEFAULT_OUTPUT_CAP, RecordStore::output_cap),
            sink,
        })
    }
}

impl Supervisor for Lifecycle {
    fn run(&self, line: ForwardedLine, caller: &dyn Caller) -> Result<Finished, RpcError> {
        // Defence in depth (NFR-REL-07): a panic before the spawn is a deny. Only shared references cross.
        let Ready {
            record_id,
            actor,
            allowed,
            profile,
            latency_ms,
            received_at,
            unprotected,
            protected,
        } = panic::catch_unwind(AssertUnwindSafe(|| self.prepare(&line, caller)))
            .unwrap_or_else(|_| Err(denial(None, Some(INTERNAL_ERROR.to_owned()), DecisionSource::Rule)))?;
        let session_id = line.session_id;
        let cwd = line.proposal.cwd.clone();
        let control = Arc::clone(&line.control);
        // KNSH-071: `recording.set` may have set output recording for the session in place of its profile's. Read
        // once, so the capture and the record agree for the whole line.
        let record_output = self
            .parts
            .sessions
            .output_recording_of(session_id)
            .unwrap_or(profile.recording.output);
        let default_mode = profile.output.mode;
        let capture = self.capture_plan(&line, record_output, &actor, record_id);
        // Never a 1970 start, which retention would expire at once.
        let started_at = self.parts.clock.now().unwrap_or(received_at);
        let events = RunningEvents {
            events: &self.parts.events,
            session_id,
            actor: &actor,
            record_id,
            command: redact(&allowed.command),
            cwd: &cwd,
            started_at,
            control: &control,
            sessions: &self.parts.sessions,
            group: Mutex::new(None),
        };
        let plan = SpawnPlan {
            record_id,
            line,
            allowed: (*allowed).clone(),
            profile: *profile,
            capture,
        };
        // KNSH-080, KNSH-081: the start of the line's window in each protected root it touches; changes there are the
        // line's from now on. Never waits.
        let checkpoint_line = self
            .parts
            .sessions
            .open_checkpoint_lines(session_id, record_id, &protected);
        let report = self.parts.spawner.spawn(plan, &events);
        // Decision 16: the line has been reaped; its file events are flushed with a marker before it is recorded, the
        // one place the decision path waits for the watcher (bounded per root). Only then is its attribution read,
        // so every change it made has been attributed (KNSH-081).
        // FR-CKP-24 (decision 17): the group's members that outlive the line, and the session's envelopes, are asked
        // which files they still hold for writing; those files are possibly torn.
        let group = *events.group.lock().unwrap_or_else(PoisonError::into_inner);
        let processes = self.parts.sessions.line_processes(session_id, group);
        let closed = Sessions::close_checkpoint_lines(checkpoint_line, &processes);
        // KNSH-082: counted when the line touched a protected root, null otherwise. Read before `closed.uncertain` is
        // consumed below.
        let files_changed = closed
            .protected
            .then(|| closed.checkpoint.as_ref().map_or(0, |checkpoint| checkpoint.count));
        let checkpoint_id = closed.checkpoint.as_ref().map(|checkpoint| checkpoint.id);
        let (written, ended_at) = self.finished(
            session_id,
            &actor,
            record_id,
            &cwd,
            started_at,
            &allowed,
            latency_ms,
            &report,
            record_output,
            unprotected,
            &closed,
        );
        let record_id = written.then_some(record_id);
        // FR-CKP-04: the line's checkpoints in these roots are uncertain (the roots were rescanned).
        for (root, reason) in closed.uncertain {
            let data = EventData::CheckpointUncertain {
                root,
                record_id,
                reason,
            };
            let _ = self.parts.events.publish(session_id, &actor, data);
        }
        match report.outcome {
            Ok(Ran {
                timed_out: false,
                status,
            }) => Ok(Finished {
                record_id,
                status,
                files_changed,
                checkpoint_id,
                // FR-AUTH-33: the line actually spawned, after any rewrite.
                executed_command: redact(&allowed.executed),
                decision: allowed.decision.clone(),
                duration_ms: ended_at.as_unix_micros().saturating_sub(started_at.as_unix_micros()) / 1000,
                default_mode,
                output: report.output,
            }),
            // FR-LC-40: killed at its timeout, `-32008` with the record (or `null` if it could not be written).
            Ok(Ran { timed_out: true, .. }) => Err(record_error(ErrorCode::LineTimedOut, record_id)),
            // The line did not run to its end; its record says so (no exit code, no signal).
            Err(_) => Err(RpcError::new(ErrorCode::InternalError)),
        }
    }

    fn session_live(&self, session_id: SessionId) -> bool {
        self.parts.sessions.agent_of(session_id).is_ok()
    }
}

/// The limiter as the pipeline sees it for one line: read at the time of each check, from the injected clock.
///
/// Not at the line's receipt time: a pass after a rewrite is checked after the ask, possibly minutes later, and a
/// limit started since then would end more than [`knsh_core::LIMIT_DURATION`] after the receipt time, which the
/// limiter takes for a clock step back and ignores.
struct Limits<'a> {
    limiter: &'a Mutex<DenialLimiter>,
    clock: &'a dyn Clock,
    /// The fallback when the clock cannot be read.
    received_at: Timestamp,
}

impl RateLimits for Limits<'_> {
    fn limited(&self, session_id: SessionId, line: LineKey) -> bool {
        let now = self.clock.now().unwrap_or(self.received_at);
        lock(self.limiter).limited(session_id, line, now)
    }
}

/// Locks the limiter. A panic while it was held cannot leave it inconsistent in a way that matters: at worst one
/// line's count is off, which only moves when a limit starts.
fn lock(limiter: &Mutex<DenialLimiter>) -> MutexGuard<'_, DenialLimiter> {
    limiter.lock().unwrap_or_else(PoisonError::into_inner)
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

/// `code` with `data.record_id` (`-32008`), `null` when the record could not be written.
fn record_error(code: ErrorCode, record_id: Option<RecordId>) -> RpcError {
    let data = record_id
        .map(|id| id.to_string())
        .to_json()
        .and_then(|id| Object::new().with("record_id", id));
    match data {
        Ok(data) => RpcError::new(code).with_data(Value::Object(data)),
        Err(_) => RpcError::new(code),
    }
}

/// `-32010` (FR-CKP-02, `specs/06-api/errors.md`): `data.root`, the first root still being shadowed, and
/// `data.progress`, how far its build is: `{"files", "folders", "folders_pending"}`.
fn not_ready(root: &CanonicalPath, progress: ShadowProgress) -> RpcError {
    // Counts beyond 2^53 cannot be exact JSON integers (I-JSON); no tree comes near, and then `data` is left out.
    let data = || -> Result<Object, knsh_json::JsonError> {
        let progress = Object::new()
            .with("files", progress.files.to_json()?)?
            .with("folders", progress.folders.to_json()?)?
            .with("folders_pending", progress.folders_pending.to_json()?)?;
        Object::new()
            .with("root", root.as_path().to_string_lossy().into_owned())?
            .with("progress", progress)
    };
    match data() {
        Ok(data) => RpcError::new(ErrorCode::CheckpointNotReady).with_data(Value::Object(data)),
        Err(_) => RpcError::new(ErrorCode::CheckpointNotReady),
    }
}

/// The record's `signal` for signal `number`: its macOS name, such as `SIGKILL`, or `SIG<number>` for one without.
pub(crate) fn signal_name(number: u8) -> String {
    const NAMES: [&str; 31] = [
        "SIGHUP",
        "SIGINT",
        "SIGQUIT",
        "SIGILL",
        "SIGTRAP",
        "SIGABRT",
        "SIGEMT",
        "SIGFPE",
        "SIGKILL",
        "SIGBUS",
        "SIGSEGV",
        "SIGSYS",
        "SIGPIPE",
        "SIGALRM",
        "SIGTERM",
        "SIGURG",
        "SIGSTOP",
        "SIGTSTP",
        "SIGCONT",
        "SIGCHLD",
        "SIGTTIN",
        "SIGTTOU",
        "SIGIO",
        "SIGXCPU",
        "SIGXFSZ",
        "SIGVTALRM",
        "SIGPROF",
        "SIGWINCH",
        "SIGINFO",
        "SIGUSR1",
        "SIGUSR2",
    ];
    usize::from(number)
        .checked_sub(1)
        .and_then(|index| NAMES.get(index))
        .map_or_else(|| format!("SIG{number}"), |name| (*name).to_owned())
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
mod checkpoint_tests;
#[cfg(test)]
mod hold_tests;
#[cfg(test)]
mod socket_tests;
