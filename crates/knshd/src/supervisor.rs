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
//! goes only to its caller. Every chunk passes the session's redaction first (FR-EVT-07).
//!
//! # Redaction (KNSH-091)
//!
//! The session's [`Redactor`] is taken once per line, right after its profile is loaded ([`Redactors::for_session`]),
//! and that one instance redacts everything about the line: what the pipeline gives hooks, the authority and
//! `command.proposed`, the record (`command`, `rewritten_from`, `argv` names, network hosts), every lifecycle event,
//! the captured output and what `exec.run` returns (FR-SEC-11, FR-REC-05, FR-EVT-07, FR-OUT-06). A secret set that
//! cannot be redacted denies the line (fail closed), and what is recorded and published of it is the plain marker,
//! as for a line refused before its profile was loaded when even the provided secrets cannot be redacted.
//!
//! # Secrets (KNSH-092)
//!
//! An allowed line whose commands match `[secrets.env]` entries (the decision asked for it unless a grant covered it,
//! FR-SEC-02) is given those secrets as environment variables (FR-SEC-01). After the checkpoint gate, they are looked
//! up through the session's redactors ([`crate::injection`], [`Redactors::inject`]), which checks that the line's
//! redactor holds every value; a secret that cannot be had, a variable the engine reserves, or a set that changed
//! under the line denies it, recorded like a held line, with a reason naming the secret (fail closed). The spawner
//! sets the variables and narrows the line's network to the secrets' hosts (FR-SEC-03). Once the line is spawned,
//! `secret.injected` names each secret and the line, and the record's `secrets_injected` lists the names (FR-SEC-06).
//! Dynamic code never receives one (FR-SEC-04).
//!
//! # Irreversible lines (KNSH-093)
//!
//! The pipeline classifies every line it parses as irreversible or not (FR-IRR-01) and asks about a flagged line as
//! `approvals.irreversible` says (FR-IRR-05); a refused line's record keeps that classification. Once an allowed line
//! has run, what it was seen doing is added ([`knsh_core::mark_observed`], FR-IRR-03): an approval or upload-capable
//! host the proxy reported it contacted, and paths written outside the checkpoint roots (none are observed yet: file
//! events cover the roots only). The marks go to the line's checkpoint ([`IrreversibleMarks`], so its undo lists them,
//! FR-IRR-06) and to its record, before `command.finished` is published.
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
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError};
use std::time::Duration;

use knsh_checkpoint::{Gate, ShadowProgress, gate, line_touches_root};
use knsh_core::{
    Actor, Allowed, Authority, BinaryLookup, Caller, CancelReason, CanonicalPath, CheckpointId, Counted, Decision,
    DecisionSource, DenialLimiter, Effects, EventData, ExecMode, ExecutionRecord, Hooks, INTERNAL_ERROR, LineInput,
    LineKey, LocalApprovals, NetworkEntry, Observer, Outcome, OutputStream, Profile, Proposal, RateLimits,
    RecordDetails, RecordId, Redacted, Redactor, Refusal, RefusalKind, RequestId, SessionId, Timestamp, Ulid,
    UnprotectedReason, UnprotectedRoot, argv_of, decide, mark_observed,
};
use knsh_json::{Object, ToJson, Value};
use knsh_platform::{Clock, ExecVerdict, ProcessGroupId, Processes, Random};
use knsh_proto::{Denial, ErrorCode, LineStatus, RpcError};
use knsh_store::{RecordStore, RecordedOutput};

use crate::capture::{CapturePlan, LineOutput, OutputSink};
use crate::endpoint_security::{ExecGate, ExecPolicy, ExecRequest};
use crate::events::EventHub;
use crate::exec::{Finished, ForwardedLine, Supervisor};
use crate::grants::GrantStore;
use crate::holds::{GroupKind, Kept};
use crate::injection::{self, Injected, InjectionError};
use crate::jobs::LineControl;
use crate::policy::ProfileLoader;
use crate::redaction::{Redactors, redact_or_hide};
use crate::sessions::Sessions;
use crate::shadows::ClosedLine;

#[cfg(target_os = "macos")]
mod native;

/// How long an ask waits for an answer by default (FR-AUTH-23).
pub(crate) const DEFAULT_ASK_TIMEOUT: Duration = Duration::from_secs(90);

/// Reasons for denials the driver makes itself, before the pipeline decides. Fixed texts.
const NO_STORE: &str = "the record store is unavailable, so the line cannot be recorded and was denied (fail closed)";
const NO_PROFILE: &str = "the session's profile could not be loaded, so the line was denied (fail closed)";
/// Reason for a line whose session's secrets cannot be redacted (KNSH-091).
const NO_REDACTION: &str =
    "the session's secrets could not be set up for redaction, so the line was denied (fail closed)";
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
/// Reason for an exec seen through Endpoint Security whose decision rewrote it (KNSH-094): the exec is already under
/// way with its own arguments, so a rewrite cannot be applied.
const EXEC_REWRITE: &str = "a rewrite cannot be applied to a program the agent runs directly, so it was denied";
/// Reason for an allowed exec whose session was paused, taken over or ended while it was decided (KNSH-094).
const EXEC_HELD: &str = "the session was paused, taken over or ended while the program was decided, so it was denied";
/// Reason for an exec whose decision allowed it after the Endpoint Security deadline (KNSH-094): the kernel was
/// already told to deny it (fail closed).
const EXEC_DEADLINE: &str =
    "the decision was not made before the Endpoint Security deadline, so the program was denied";
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

    /// Runs a native-mode line's interpreter (KNSH-108, FR-LC-52) as [`Spawner::spawn`] runs a line, and kills what is
    /// left of its process group once it exits (FR-LC-58). A spawner without native mode starts nothing.
    fn spawn_native(&self, plan: NativePlan, events: &dyn LineEvents) -> SpawnReport {
        let _ = (plan, events);
        not_started()
    }

    /// Starts one allowed command of a native-mode line in the line's process group and waits for it to end
    /// (FR-LC-56), telling `events` once it runs. A spawner without native mode starts nothing.
    fn run_command(
        &self,
        plan: &crate::spawn::CommandPlan<'_>,
        events: &dyn crate::spawn::CommandEvents,
    ) -> SpawnReport {
        let _ = (plan, events);
        not_started()
    }

    /// Kills the members of `group` (a native-mode line's) still running, while one is held unreaped (FR-LC-58).
    fn kill_members(&self, group: ProcessGroupId) {
        let _ = group;
    }
}

/// The report of a spawner that cannot start what it was given.
fn not_started() -> SpawnReport {
    SpawnReport {
        sandbox_profile: None,
        outcome: Err(SpawnFailure::Start(knsh_platform::PlatformError::InvalidPath)),
        output: None,
        network: Vec::new(),
    }
}

/// A native-mode line, admitted and ready to run in its interpreter (KNSH-108).
#[derive(Debug)]
pub(crate) struct NativePlan {
    /// The line record.
    pub(crate) record_id: RecordId,
    /// The line as received: operands, environment, descriptors, timeout.
    pub(crate) line: ForwardedLine,
    /// The session's profile: the interpreter's file rules.
    pub(crate) profile: Profile,
    /// How its output is captured, as for a line.
    pub(crate) capture: Option<CapturePlan>,
    /// The interpreter's end of the line's supervision channel.
    pub(crate) channel: std::os::fd::OwnedFd,
}

/// Where a line's irreversible marks go once it has run (KNSH-093, FR-IRR-03, FR-IRR-06): the checkpoint history, so
/// undoing the line's checkpoint lists what it cannot take back. Must not block on a restore in progress.
pub(crate) trait IrreversibleMarks: Send + Sync {
    /// Notes `reasons` (never empty) on `checkpoint`, which holds the line's changes.
    fn mark(&self, checkpoint: CheckpointId, reasons: &[String]);
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
    /// The secrets it receives as environment variables, already looked up and covered by its redactor (module
    /// documentation, "Secrets"); its network is narrowed to their hosts by its decision's capabilities.
    pub(crate) secrets: Vec<Injected>,
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
    /// Each session's redactor, taken once per line for every path of the line (KNSH-091, module documentation).
    pub(crate) redactors: Arc<Redactors>,
    /// [`knsh_platform::EnginePaths::shim_dir`]: removed from the `PATH` of every command of a native-mode line, as
    /// from a forwarded line's (FR-LC-16, KNSH-108).
    pub(crate) shim_dir: std::path::PathBuf,
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
    /// The names of the secrets the line receives, each once: `secret.injected` names each once it is spawned
    /// (FR-SEC-06).
    secrets: Vec<String>,
    /// Whether the line was spawned: only then was it given its secrets, and its record names them.
    spawned: AtomicBool,
    /// The line record of a native-mode line's command (FR-LC-54), named by `command.started`.
    parent_record_id: Option<RecordId>,
}

impl RunningEvents<'_> {
    /// Best effort (FR-EVT-04): an event that cannot be published never changes how the line runs.
    fn publish(&self, data: EventData) {
        let _ = self.events.publish(self.session_id, self.actor, data);
    }

    /// The record's `secrets_injected`: the names of the line's secrets once it was spawned; a line that never
    /// started was given nothing (FR-SEC-06, FR-REC-11).
    fn secrets_injected(&self) -> Vec<String> {
        if self.spawned.load(Ordering::SeqCst) {
            self.secrets.clone()
        } else {
            Vec::new()
        }
    }
}

impl LineEvents for RunningEvents<'_> {
    fn keep(&self, group: ProcessGroupId, processes: Arc<dyn Processes>) -> Kept {
        *self.group.lock().unwrap_or_else(PoisonError::into_inner) = Some(group);
        self.sessions
            .keep_group(self.session_id, group, processes, GroupKind::Line)
    }

    fn started(&self) {
        self.spawned.store(true, Ordering::SeqCst);
        self.control.mark_started(self.record_id);
        self.publish(EventData::CommandStarted {
            record_id: self.record_id,
            command: self.command.clone(),
            cwd: self.cwd.clone(),
            started_at: self.started_at,
            parent_record_id: self.parent_record_id,
        });
        // FR-SEC-06: the name and the line, never the value.
        for name in self
            .secrets
            .iter()
            .filter_map(|name| knsh_core::SecretName::new(name).ok())
        {
            self.publish(EventData::SecretInjected {
                record_id: self.record_id,
                name,
                command: self.command.clone(),
            });
        }
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
    /// The checkpoint history, once attached ([`Lifecycle::attach_marks`]). Without one no line has a checkpoint in a
    /// history, and the marks are kept in the record only.
    marks: OnceLock<Arc<dyn IrreversibleMarks>>,
}

/// A line that may be spawned: everything its record needs once it ends. A line that may not is an `Err` holding
/// its answer, already recorded and reported.
struct Ready {
    record_id: RecordId,
    /// The session's redactor the line was decided with: its record, events and output use the same (KNSH-091).
    redactor: Redactor,
    actor: Actor,
    allowed: Box<Allowed>,
    /// The session's profile the line was decided with, for its sandbox profile.
    profile: Box<Profile>,
    latency_ms: u64,
    /// When the line was received: the record's start if the clock cannot be read at the spawn.
    received_at: Timestamp,
    /// What the checkpoint gate and the secrets let it start with.
    admitted: Admitted,
}

/// What [`Lifecycle::admit`] lets an allowed line start with.
struct Admitted {
    /// Checkpoint roots it touches whose changes are not protected: the record's `unprotected` (KNSH-079).
    unprotected: Vec<UnprotectedRoot>,
    /// Checkpoint roots it touches whose shadow is ready: their watchers mark its start and run the line-end flush
    /// (KNSH-080).
    protected: Vec<CanonicalPath>,
    /// The secrets it receives (KNSH-092).
    secrets: Vec<Injected>,
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
    /// It cannot be given the secrets it needs (KNSH-092): denied, with this reason naming the secret.
    Secret(String),
}

/// What the pipeline decided for one line, with what its record needs ([`Lifecycle::evaluate`]).
struct Evaluated {
    record_id: RecordId,
    /// When the line was received.
    received_at: Timestamp,
    /// From receipt to the decision.
    latency_ms: u64,
    actor: Actor,
    /// The session's profile the line was decided with.
    profile: Profile,
    /// The session's redactor the line was decided with (KNSH-091).
    redactor: Redactor,
    outcome: Outcome,
}

/// What every line needs before it is decided: its record, the session's actor, profile and redactor
/// ([`Lifecycle::context`]).
pub(super) struct Context {
    record_id: RecordId,
    /// When the line was received.
    received_at: Timestamp,
    actor: Actor,
    /// The session's profile, as loaded for the line.
    profile: Profile,
    /// The session's redactor for every path of the line (KNSH-091).
    redactor: Redactor,
}

/// Where a decided line came from: what the record's `decision.source` says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Origin {
    /// A line forwarded over `agent.sock`: the source is whoever decided.
    Line,
    /// An exec inside an envelope, seen by the Endpoint Security descendant client (KNSH-094): always
    /// `endpoint_security`, with the rule and who decided kept in `rule_id` and `decided_by`.
    EndpointSecurity,
}

impl Origin {
    /// The recorded source of a decision made by `source`.
    const fn source(self, source: DecisionSource) -> DecisionSource {
        match self {
            Self::Line => source,
            Self::EndpointSecurity => DecisionSource::EndpointSecurity,
        }
    }
}

impl Lifecycle {
    /// The orchestrator over `parts`.
    pub(crate) fn new(parts: Parts) -> Arc<Self> {
        Arc::new(Self {
            parts,
            limiter: Mutex::new(DenialLimiter::new()),
            marks: OnceLock::new(),
        })
    }

    /// Sends every later line's irreversible marks to `marks` as well as to its record (KNSH-093).
    pub(crate) fn attach_marks(&self, marks: Arc<dyn IrreversibleMarks>) {
        // Set once at start; a second call would be a wiring mistake and is ignored.
        let _ = self.marks.set(marks);
    }

    /// Steps 1 to 8 and the handling of a refusal, for `line` from `caller` (module documentation), once its
    /// `context` is set up.
    fn prepare(&self, line: &ForwardedLine, caller: &dyn Caller, context: Context) -> Result<Ready, RpcError> {
        let parts = &self.parts;
        let session_id = line.session_id;
        let Evaluated {
            record_id,
            received_at,
            latency_ms,
            actor,
            profile,
            redactor,
            outcome,
        } = self.decide_in(line, caller, context);
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
                irreversible: Some(allowed.irreversible),
            },
            // The session was paused or taken over while the line was decided (module documentation, "Held lines"):
            // recorded as a deny so the decision is not lost, and answered with the hold so the client retries.
            Outcome::Run(allowed) if let Err(hold) = parts.sessions.runnable(session_id) => {
                return Err(self.blocked(
                    line,
                    &actor,
                    &redactor,
                    (record_id, received_at, latency_ms),
                    allowed,
                    Blocked::Held(hold),
                ));
            }
            // FR-CKP-02: an allowed line touching a checkpoint root whose shadow is not ready waits, fails with
            // `-32010`, or is denied, as `checkpoints.required` and the caller ask. Recorded as a deny when stopped,
            // like a held line, so the decision is not lost.
            Outcome::Run(allowed) => match self.admit(line, &profile, caller, &allowed, &redactor) {
                Ok(admitted) => {
                    return Ok(Ready {
                        record_id,
                        redactor,
                        actor,
                        allowed,
                        profile: Box::new(profile),
                        latency_ms,
                        received_at,
                        admitted,
                    });
                }
                Err(blocked) => {
                    return Err(self.blocked(
                        line,
                        &actor,
                        &redactor,
                        (record_id, received_at, latency_ms),
                        allowed,
                        blocked,
                    ));
                }
            },
            Outcome::Refused(refusal) => *refusal,
        };
        let record = (record_id, received_at, latency_ms);
        Err(self.refused(line, &actor, Some(&redactor), record, &refusal))
    }

    /// The decision itself, shared by forwarded lines and execs seen through Endpoint Security (KNSH-094): the
    /// session's actor and profile, a record ID, the session's redactor, then the pipeline ([`decide`]). A deny made
    /// before the pipeline runs is recorded and reported here, with `origin`'s source, and returned as its answer.
    fn evaluate(&self, line: &ForwardedLine, caller: &dyn Caller, origin: Origin) -> Result<Evaluated, RpcError> {
        let context = self.context(line, origin)?;
        Ok(self.decide_in(line, caller, context))
    }

    /// What `line` needs before it is decided: the session's actor and profile, a record ID and the session's
    /// redactor. A deny made here is recorded and reported, with `origin`'s source, and returned as its answer; a held
    /// or ended session is answered at once, with nothing recorded.
    fn context(&self, line: &ForwardedLine, origin: Origin) -> Result<Context, RpcError> {
        let parts = &self.parts;
        let session_id = line.session_id;
        // The session ended under the call: there is no one to record for, and nothing runs. A session that holds its
        // lines answers `-32007` here, before anything is recorded (module documentation, "Held lines").
        let (actor, profile_name) = parts.sessions.runnable(session_id)?;
        // Before the profile is loaded, a refusal is redacted of the provided secrets, or hidden entirely if even
        // those cannot be redacted (module documentation, "Redaction").
        let early = || parts.redactors.for_session(session_id, None).ok();
        let Some((received_at, record_id)) = self.record_id() else {
            return Err(self.refuse_early(line, &actor, None, early().as_ref(), NO_CLOCK, origin));
        };
        let record = Some((record_id, received_at));
        // A line that cannot be recorded must not run (NFR-REL-05, FR-REC-02).
        if parts.store.is_none() {
            return Err(self.refuse_early(line, &actor, record, early().as_ref(), NO_STORE, origin));
        }
        let profile = self
            .load_profile(line, &actor, &profile_name)
            .map_err(|reason| self.refuse_early(line, &actor, record, early().as_ref(), reason, origin))?;
        // KNSH-091: the one redactor of every path of this line. A set that cannot be redacted denies it, and nothing
        // of the line is kept or published but the marker.
        let Ok(redactor) = parts.redactors.for_session(session_id, Some(&profile)) else {
            return Err(self.refuse_early(line, &actor, record, None, NO_REDACTION, origin));
        };
        Ok(Context {
            record_id,
            received_at,
            actor,
            profile,
            redactor,
        })
    }

    /// The pipeline ([`decide`]) for `line` in its `context`.
    fn decide_in(&self, line: &ForwardedLine, caller: &dyn Caller, context: Context) -> Evaluated {
        let parts = &self.parts;
        let session_id = line.session_id;
        let Context {
            record_id,
            received_at,
            actor,
            profile,
            redactor,
        } = context;
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
            redactor: &redactor,
        };
        let outcome = decide(&input, &effects);
        let latency_ms = self.since(received_at);
        Evaluated {
            record_id,
            received_at,
            latency_ms,
            actor,
            profile,
            redactor,
            outcome,
        }
    }

    /// The checkpoint gate, then the secrets for an allowed line (KNSH-092): last, so a line that waited on a shadow
    /// gets its secrets as they are when it starts.
    fn admit(
        &self,
        line: &ForwardedLine,
        profile: &Profile,
        caller: &dyn Caller,
        allowed: &Allowed,
        redactor: &Redactor,
    ) -> Result<Admitted, Blocked> {
        let (unprotected, protected) = self.checkpoint_gate(line, profile, caller)?;
        let secrets = self.secrets_for(line.session_id, allowed, profile, redactor)?;
        Ok(Admitted {
            unprotected,
            protected,
            secrets,
        })
    }

    /// The secrets `allowed` receives, looked up for its session with the redactor it was decided with (module
    /// documentation, "Secrets"), or why it is denied.
    fn secrets_for(
        &self,
        session_id: SessionId,
        allowed: &Allowed,
        profile: &Profile,
        redactor: &Redactor,
    ) -> Result<Vec<Injected>, Blocked> {
        let blocked = |error: InjectionError| Blocked::Secret(injection::denial_reason(&error));
        let reserved =
            |variable: &str| crate::proxy::is_proxy_var(variable) || crate::spawn::read_by_dynamic_linker(variable);
        let needed = injection::needed(allowed, profile, reserved).map_err(blocked)?;
        if needed.is_empty() {
            return Ok(Vec::new());
        }
        let names: Vec<_> = needed.iter().map(|secret| secret.name.clone()).collect();
        let values = self
            .parts
            .redactors
            .inject(session_id, redactor, &names)
            .map_err(blocked)?;
        injection::pair(needed, values).map_err(blocked)
    }

    /// The session's profile for `line`, or the reason to deny it. FR-POL-42: a policy file with a missing or bad
    /// signature is reported on the session, and the line is denied; the session never falls back to another
    /// profile.
    fn load_profile(
        &self,
        line: &ForwardedLine,
        actor: &Actor,
        name: &knsh_core::ProfileName,
    ) -> Result<Profile, &'static str> {
        self.parts.profiles.load(name, line.proposal.cwd.as_path()).map_err(
            |error| match crate::policy::invalid_profile(&error) {
                Some(invalid) => {
                    let data = EventData::PolicyInvalid { profile: invalid };
                    let _ = self.parts.events.publish(line.session_id, actor, data);
                    INVALID_PROFILE
                }
                None => NO_PROFILE,
            },
        )
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
        redactor: &Redactor,
        record: (RecordId, Timestamp, u64),
        allowed: Box<Allowed>,
        blocked: Blocked,
    ) -> RpcError {
        let (reason, kind) = match &blocked {
            Blocked::NotReady { .. } => (SHADOW_NOT_READY, RefusalKind::Denied),
            Blocked::NoShadow => (NO_SHADOW, RefusalKind::Denied),
            Blocked::CallerGone => (GONE_BEFORE_SPAWN, RefusalKind::Cancelled { request_id: None }),
            Blocked::Held(hold) if hold.code == ErrorCode::SessionHeld => (HELD_AFTER_DECISION, RefusalKind::Denied),
            Blocked::Held(_) => (ENDED_AFTER_DECISION, RefusalKind::Denied),
            Blocked::Secret(reason) => (reason.as_str(), RefusalKind::Denied),
        };
        let refusal = Refusal {
            decision: Decision::deny(DecisionSource::Standalone, None, None),
            command: allowed.command,
            rewritten_from: allowed.rewritten_from,
            reason: Some(reason.to_owned()),
            kind,
            classification: Some(allowed.classification),
            line_key: None,
            irreversible: Some(allowed.irreversible),
        };
        let error = self.refused(line, actor, Some(redactor), record, &refusal);
        match blocked {
            Blocked::NotReady { root, progress } => not_ready(&root, progress),
            Blocked::Held(hold) => hold,
            Blocked::NoShadow | Blocked::CallerGone | Blocked::Secret(_) => error,
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
    /// when a record ID and a store exist, reported, and answered `-32001`. Its text goes through `redactor`, or is
    /// hidden entirely without one (module documentation, "Redaction").
    fn refuse_early(
        &self,
        line: &ForwardedLine,
        actor: &Actor,
        record: Option<(RecordId, Timestamp)>,
        redactor: Option<&Redactor>,
        reason: &str,
        origin: Origin,
    ) -> RpcError {
        let refusal = Refusal {
            decision: Decision::deny(origin.source(DecisionSource::Rule), None, None),
            command: line.proposal.command.clone(),
            rewritten_from: None,
            reason: Some(reason.to_owned()),
            kind: RefusalKind::Denied,
            // Refused before step 2: the line was never parsed, so its record has no `argv` and no rate-limit key.
            classification: None,
            line_key: None,
            irreversible: None,
        };
        // Without a record ID (no clock or random bytes) nothing can be recorded; the denial is still reported.
        let Some((record_id, received_at)) = record else {
            self.publish_denied(line, actor, redactor, None, &refusal);
            return denial_error(&refusal);
        };
        let latency_ms = self.since(received_at);
        self.refused(line, actor, redactor, (record_id, received_at, latency_ms), &refusal)
    }

    /// A refused line (FR-LC-30 to FR-LC-32, FR-LC-41): `decision.cancelled` if it was cancelled or timed out, its
    /// record, `command.denied`, and the error to answer with. The order is the spec's: the pending decision ends
    /// before the denial is recorded, and `command.denied` names the record only once it was written. `record` is the
    /// line's record ID, receipt time and decision latency. Every text goes through `redactor`, the session's, or is
    /// hidden without one (KNSH-091).
    fn refused(
        &self,
        line: &ForwardedLine,
        actor: &Actor,
        redactor: Option<&Redactor>,
        (record_id, received_at, latency_ms): (RecordId, Timestamp, u64),
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
            command: redact_or_hide(redactor, &refusal.command),
            cwd: line.proposal.cwd.clone(),
            started_at: received_at,
            ended_at: Some(self.parts.clock.now().unwrap_or(received_at)),
            exit_code: None,
            details: RecordDetails {
                parent_record_id: line.parent_record_id,
                rewritten_from: refusal
                    .rewritten_from
                    .as_deref()
                    .map(|from| redact_or_hide(redactor, from)),
                decision: Some(refusal.decision.to_record(latency_ms)),
                // Without a redactor nothing of the line is kept, its command names included.
                argv: refusal
                    .classification
                    .as_ref()
                    .zip(redactor)
                    .map(|(classification, redactor)| argv_of(classification, redactor))
                    .unwrap_or_default(),
                // FR-IRR-04: a refused line keeps its classification (KNSH-093).
                irreversible: refusal.irreversible.clone(),
                ..RecordDetails::default()
            },
        };
        let written = self.write(record, RecordedOutput::default());
        self.publish_denied(line, actor, redactor, written.then_some(record_id), refusal);
        self.count_denial(line, actor, redactor, refusal, received_at);
        match refusal.kind {
            RefusalKind::Denied => denial_error(refusal),
            RefusalKind::TimedOut { request_id } => request_error(ErrorCode::DecisionTimeout, request_id),
            RefusalKind::Cancelled { request_id } => request_error(ErrorCode::Cancelled, request_id),
        }
    }

    /// Counts `refusal` towards rate limiting its line (FR-HOOK-20), and publishes `command.denied_repeatedly` when
    /// this denial starts a limit (FR-HOOK-21). Not counted: a denial by the limit itself (it would only prolong it),
    /// a cancellation (nobody denied the line), and a line refused before it was parsed (it has no key).
    fn count_denial(
        &self,
        line: &ForwardedLine,
        actor: &Actor,
        redactor: Option<&Redactor>,
        refusal: &Refusal,
        received_at: Timestamp,
    ) {
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
                command: redact_or_hide(redactor, &refusal.command),
                cwd: line.proposal.cwd.clone(),
                until,
            };
            // Best effort (FR-EVT-04): the limit applies whether or not the event is delivered.
            let _ = self.parts.events.publish(line.session_id, actor, data);
        }
    }

    /// Publishes `command.denied` (FR-LC-32), its texts through `redactor` (KNSH-091). Best effort, like every event.
    fn publish_denied(
        &self,
        line: &ForwardedLine,
        actor: &Actor,
        redactor: Option<&Redactor>,
        record_id: Option<RecordId>,
        refusal: &Refusal,
    ) {
        let data = EventData::CommandDenied {
            record_id,
            command: redact_or_hide(redactor, &refusal.command),
            cwd: line.proposal.cwd.clone(),
            source: refusal.decision.source,
            rule_id: refusal
                .decision
                .rule_id
                .as_deref()
                .map(|rule| redact_or_hide(redactor, rule)),
            reason: refusal.reason.as_deref().map(|reason| redact_or_hide(redactor, reason)),
            parent_record_id: line.parent_record_id,
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
    /// are listed too (`unprotected`, KNSH-079), and the names of the secrets it was given (`secrets_injected`,
    /// FR-SEC-06).
    #[allow(clippy::too_many_arguments)]
    fn finished(
        &self,
        session_id: SessionId,
        actor: &Actor,
        redactor: &Redactor,
        record_id: RecordId,
        cwd: &CanonicalPath,
        started_at: Timestamp,
        allowed: &Allowed,
        latency_ms: u64,
        report: &SpawnReport,
        record_output: bool,
        unprotected: Vec<UnprotectedRoot>,
        closed: Option<&ClosedLine>,
        secrets_injected: Vec<String>,
        profile: &Profile,
        parent_record_id: Option<RecordId>,
    ) -> (bool, Timestamp) {
        let ended_at = self.parts.clock.now().unwrap_or(started_at);
        let irreversible = self.mark_irreversible(allowed, profile, report, closed);
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
        // KNSH-091, FR-REC-05: the text hooks and the authority saw, made by the same redactor.
        let command = redactor.redact_text(&allowed.command);
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
                // FR-LC-54: a native-mode line's command names its line.
                parent_record_id,
                rewritten_from: allowed.rewritten_from.as_deref().map(|from| redactor.redact_text(from)),
                decision: Some(allowed.decision.to_record(latency_ms)),
                argv: argv_of(&allowed.classification, redactor),
                signal,
                sandbox_profile: report.sandbox_profile.clone(),
                // Hosts were redacted by the proxy's report with this session's redactor, the line's (KNSH-091).
                network: report.network.clone(),
                // FR-CKP-02 with `required = false`: the roots this line changed unprotected (KNSH-079).
                unprotected,
                // FR-CKP-05, FR-CKP-07: the line's own changes (`command`), or a set it overlapped (`concurrent`). A
                // native-mode line's command has none of its own: its changes are its line's (KNSH-108).
                attribution: closed.map(|closed| closed.attribution),
                // KNSH-082, FR-CKP-11: its checkpoint, and the paths it changed with their post-image identities;
                // nothing for a line that touched no protected root.
                checkpoint_id: closed
                    .and_then(|closed| closed.checkpoint.as_ref())
                    .map(|checkpoint| checkpoint.id),
                files_changed: closed.filter(|closed| closed.protected).map(|closed| {
                    closed
                        .checkpoint
                        .as_ref()
                        .map(|checkpoint| checkpoint.files.clone())
                        .unwrap_or_default()
                }),
                // FR-SEC-06, FR-REC-11: names only, never a value.
                secrets_injected,
                irreversible: Some(irreversible),
                // `pipestatus` stays empty: the line runs in a separate bash whose `PIPESTATUS` is not reported back
                // yet (KNSH-100).
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
                parent_record_id,
            };
            let _ = self.parts.events.publish(session_id, actor, data);
        }
        (written, ended_at)
    }

    /// The line's irreversible flag once it has run (module documentation, "Irreversible lines"): its classification
    /// with what it was seen doing added (FR-IRR-03), noted on its checkpoint too when it has one (FR-IRR-06). Called
    /// before its record is written and `command.finished` published.
    fn mark_irreversible(
        &self,
        allowed: &Allowed,
        profile: &Profile,
        report: &SpawnReport,
        closed: Option<&ClosedLine>,
    ) -> knsh_core::Irreversibility {
        let mut irreversible = allowed.irreversible.clone();
        // Coverage (KNSH-093): file events are watched only under the checkpoint roots, so no write outside them is
        // observed yet; the proxy reports every connection.
        mark_observed(profile, &mut irreversible, &report.network, &[]);
        if irreversible.value()
            && let (Some(checkpoint), Some(marks)) =
                (closed.and_then(|closed| closed.checkpoint.as_ref()), self.marks.get())
        {
            marks.mark(checkpoint.id, irreversible.reasons());
        }
        irreversible
    }

    /// Whether the session records output: what `recording.set` set for it, in place of its profile's
    /// `recording.output` (KNSH-071). Read once per line, so its capture and its record agree.
    fn records_output(&self, session_id: SessionId, profile: &Profile) -> bool {
        self.parts
            .sessions
            .output_recording_of(session_id)
            .unwrap_or(profile.recording.output)
    }

    /// How `line` is captured (module documentation, "Output"), given whether its session records output: `None` when
    /// its output goes straight to passed descriptors in a session that does not record output.
    fn capture_plan(
        &self,
        line: &ForwardedLine,
        record_output: bool,
        actor: &Actor,
        record_id: RecordId,
        redactor: &Redactor,
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
            // FR-EVT-07, FR-OUT-06: the line's own redactor, so output and record hide the same secrets (KNSH-091).
            redactor: redactor.clone(),
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
        let context = panic::catch_unwind(AssertUnwindSafe(|| self.context(&line, Origin::Line)))
            .unwrap_or_else(|_| Err(denial(None, Some(INTERNAL_ERROR.to_owned()), DecisionSource::Rule)))?;
        // KNSH-108 (FR-LC-50): the session's profile alone chooses native mode.
        if context.profile.exec.mode == ExecMode::Native {
            return self.run_native(line, caller, context);
        }
        self.run_line(line, caller, context)
    }

    fn session_live(&self, session_id: SessionId) -> bool {
        self.parts.sessions.agent_of(session_id).is_ok()
    }
}

impl Lifecycle {
    /// A line-mode line once its `context` is set up (module documentation): decided as a whole, then run by a stock
    /// interpreter.
    fn run_line(&self, line: ForwardedLine, caller: &dyn Caller, context: Context) -> Result<Finished, RpcError> {
        let Ready {
            record_id,
            redactor,
            actor,
            allowed,
            profile,
            latency_ms,
            received_at,
            admitted,
        } = panic::catch_unwind(AssertUnwindSafe(|| self.prepare(&line, caller, context)))
            .unwrap_or_else(|_| Err(denial(None, Some(INTERNAL_ERROR.to_owned()), DecisionSource::Rule)))?;
        let session_id = line.session_id;
        let cwd = line.proposal.cwd.clone();
        let control = Arc::clone(&line.control);
        let record_output = self.records_output(session_id, &profile);
        let default_mode = profile.output.mode;
        let capture = self.capture_plan(&line, record_output, &actor, record_id, &redactor);
        // Never a 1970 start, which retention would expire at once.
        let started_at = self.parts.clock.now().unwrap_or(received_at);
        let events = RunningEvents {
            events: &self.parts.events,
            session_id,
            actor: &actor,
            record_id,
            command: redactor.redact_text(&allowed.command),
            cwd: &cwd,
            started_at,
            control: &control,
            sessions: &self.parts.sessions,
            group: Mutex::new(None),
            secrets: injection::injected_names(&admitted.secrets),
            spawned: AtomicBool::new(false),
            parent_record_id: None,
        };
        // What the line reached is judged against the profile it ran with (KNSH-093), after the plan takes it.
        let observing = profile.clone();
        let plan = SpawnPlan {
            record_id,
            line,
            allowed: (*allowed).clone(),
            profile: *profile,
            capture,
            secrets: admitted.secrets,
        };
        // KNSH-080, KNSH-081: the start of the line's window in each protected root it touches; changes there are the
        // line's from now on. Never waits.
        let checkpoint_line = self
            .parts
            .sessions
            .open_checkpoint_lines(session_id, record_id, &admitted.protected);
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
            &redactor,
            record_id,
            &cwd,
            started_at,
            &allowed,
            latency_ms,
            &report,
            record_output,
            admitted.unprotected,
            Some(&closed),
            events.secrets_injected(),
            &observing,
            None,
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
                executed_command: redactor.redact_text(&allowed.executed),
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
}

impl ExecPolicy for Lifecycle {
    /// An exec inside an envelope (KNSH-094, `crate::endpoint_security`): decided by the same steps as a forwarded
    /// line ([`Lifecycle::evaluate`]: hooks, rules, grants, asks, rate limits), with `gate` as its caller so an ask
    /// ends at the Endpoint Security deadline. Its record has source `endpoint_security`. Unlike a forwarded line,
    /// nothing is spawned and no checkpoint gate or secret applies: the exec runs in the agent's own process, inside
    /// its envelope, with what it already has.
    fn decide_exec(&self, request: &ExecRequest, gate: &ExecGate) -> ExecVerdict {
        let line = exec_line(request);
        // A deny before the pipeline ran was recorded there; a held or ended session records nothing.
        let Ok(Evaluated {
            record_id,
            received_at,
            latency_ms,
            actor,
            redactor,
            outcome,
            ..
        }) = self.evaluate(&line, gate, Origin::EndpointSecurity)
        else {
            return ExecVerdict::Deny;
        };
        let record = (record_id, received_at, latency_ms);
        let deny = |allowed: Box<Allowed>, reason: &str, kind: RefusalKind| Refusal {
            decision: Decision::deny(DecisionSource::EndpointSecurity, None, None),
            command: allowed.command,
            rewritten_from: allowed.rewritten_from,
            reason: Some(reason.to_owned()),
            kind,
            classification: Some(allowed.classification),
            line_key: None,
            irreversible: Some(allowed.irreversible),
        };
        let refusal = match outcome {
            // The exec is already under way with its own arguments: a rewrite cannot be applied to it.
            Outcome::Run(allowed) if allowed.rewritten_from.is_some() => {
                deny(allowed, EXEC_REWRITE, RefusalKind::Denied)
            }
            Outcome::Run(allowed) if self.parts.sessions.runnable(request.session_id).is_err() => {
                deny(allowed, EXEC_HELD, RefusalKind::Denied)
            }
            Outcome::Run(allowed) => {
                if gate.claim_allow() {
                    self.exec_allowed(&line, &actor, &redactor, record, &allowed);
                    return ExecVerdict::Allow;
                }
                deny(allowed, EXEC_DEADLINE, RefusalKind::Cancelled { request_id: None })
            }
            Outcome::Refused(refusal) => {
                let mut refusal = *refusal;
                // A denial by the rate limit itself is never counted again (FR-HOOK-20); its source is replaced below.
                if refusal.decision.source == DecisionSource::RateLimit {
                    refusal.line_key = None;
                }
                refusal.decision.source = DecisionSource::EndpointSecurity;
                refusal
            }
        };
        self.refused(&line, &actor, Some(&redactor), record, &refusal);
        ExecVerdict::Deny
    }
}

impl Lifecycle {
    /// Records an allowed exec (KNSH-094): its decision with source `endpoint_security`, what it resolved to and
    /// whether it is irreversible. It runs in the agent's process, so the record has no exit code; it ends when it
    /// was decided. Written after the allow was claimed, which cannot wait: a failed write leaves the exec allowed and
    /// unrecorded, as the deadline leaves no time to undo it (`specs/03-functional-requirements/agent-integration.md`).
    fn exec_allowed(
        &self,
        line: &ForwardedLine,
        actor: &Actor,
        redactor: &Redactor,
        (record_id, received_at, latency_ms): (RecordId, Timestamp, u64),
        allowed: &Allowed,
    ) {
        let mut decision = allowed.decision.clone();
        decision.source = DecisionSource::EndpointSecurity;
        let record = ExecutionRecord {
            record_id,
            session_id: line.session_id,
            actor: actor.clone(),
            command: redactor.redact_text(&allowed.command),
            cwd: line.proposal.cwd.clone(),
            started_at: received_at,
            ended_at: Some(self.parts.clock.now().unwrap_or(received_at)),
            exit_code: None,
            details: RecordDetails {
                parent_record_id: line.parent_record_id,
                decision: Some(decision.to_record(latency_ms)),
                argv: argv_of(&allowed.classification, redactor),
                irreversible: Some(allowed.irreversible.clone()),
                ..RecordDetails::default()
            },
        };
        let _ = self.write(record, RecordedOutput::default());
    }
}

/// `request` as a forwarded line, so it goes through the same steps. The interpreter is never an input to a decision
/// (FR-LC-14) and nothing is spawned, so the line's run fields are empty.
fn exec_line(request: &ExecRequest) -> ForwardedLine {
    ForwardedLine {
        session_id: request.session_id,
        proposal: crate::exec::Proposal {
            command: request.command.clone(),
            cwd: request.cwd.clone(),
            path: request.path.clone(),
        },
        interpreter: knsh_proto::Interpreter::Bash,
        args: Vec::new(),
        env: Vec::new(),
        stdio: None,
        timeout_s: None,
        checkpoint_wait: false,
        control: LineControl::new(),
        parent_record_id: None,
    }
}

/// Native mode needs the macOS supervision channel (KNSH-108): elsewhere a native-mode line is denied (fail closed).
#[cfg(not(target_os = "macos"))]
impl Lifecycle {
    fn run_native(&self, line: ForwardedLine, _caller: &dyn Caller, context: Context) -> Result<Finished, RpcError> {
        let refusal = Refusal {
            decision: Decision::deny(DecisionSource::Standalone, None, None),
            command: line.proposal.command.clone(),
            rewritten_from: None,
            reason: Some("native mode is not available on this platform, so the line was denied".to_owned()),
            kind: RefusalKind::Denied,
            classification: None,
            line_key: None,
            irreversible: None,
        };
        let record = (context.record_id, context.received_at, 0);
        Err(self.refused(&line, &context.actor, Some(&context.redactor), record, &refusal))
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
