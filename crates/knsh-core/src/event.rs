//! Events: the envelope, the phase 1 payloads, and the bus that numbers, buffers and queues them (KNSH-018).
//!
//! # Model
//!
//! An [`Event`] is the envelope of `specs/05-models/event.md`: `event` (the name, from [`EventData::name`]), `id`,
//! `seq`, `ts`, `session_id`, `actor` and `data`. [`EventData`] is a closed enum of the payloads phase 1 emits; every
//! text field in it is [`Redacted`] or a typed value (IDs, timestamps, [`CanonicalPath`], states), never a raw
//! `String`, so nothing that has not been through redaction can be put in an event (FR-EVT-07).
//!
//! # Bus
//!
//! [`EventBus`] is the pure core of the event bus. It has no locks and no I/O: `knshd` owns one behind its own lock,
//! supplies the event IDs and timestamps from its injected clock and random source, and wakes subscribers.
//!
//! - **Numbering.** `seq` starts at 1 for each session and increases by exactly one per event, with no gaps
//!   (FR-EVT-02). The first event of a session is always `session.started`; nothing is accepted after
//!   `session.ended`.
//! - **Buffer.** The last [`EVENT_BUFFER_LEN`] events of each session are kept; older ones are dropped (FR-EVT-03).
//!   The buffers of the last [`MAX_ENDED_BUFFERS`] ended sessions are kept too, so a subscriber can still catch up
//!   on a session that has just ended; older ended sessions are forgotten.
//! - **Subscriptions.** Each subscription has its own bounded queue. Publishing appends to every matching queue and
//!   never waits for a subscriber (FR-EVT-04). A queue that would grow past its bound drops its oldest event and
//!   remembers the lost range per session, which [`EventBus::take`] reports as a [`Lost`] delivery before any later
//!   event of that session: the subscriber is told, and reads what it missed from the record store.
//! - **Scope.** A [`EventScope::Session`] subscription receives only that session's events (FR-EVT-01).
//! - **Engine events.** A few events belong to the engine, not to a session: `authority.connected` and
//!   `authority.disconnected` (FR-AUTH-02, KNSH-068). An [`EngineEvent`] has no session and no actor; it is numbered
//!   in one engine sequence of its own (from 1, gapless, per bus), is not buffered (there is nothing to resume: a
//!   `since_seq` names a session), and is queued only for [`EventScope::All`] subscriptions, in publication order with
//!   the session events. When a queue overflows, dropped engine events are reported as an [`EngineLost`] range.
//! - **Resume.** A session subscription may start after a `since_seq`: the buffered events after it are queued in
//!   the same step that registers the subscription, so nothing is delivered twice and nothing falls between the
//!   replay and the live events (FR-EVT-03).
//!
//! Specification: `specs/05-models/event.md`, `specs/03-functional-requirements/events.md` (FR-EVT-01 to FR-EVT-04,
//! FR-EVT-07), `specs/06-api/user-socket.md#events`.

use std::collections::{BTreeMap, VecDeque};
use std::sync::Arc;

use crate::error::CoreError;
use crate::id::{CheckpointId, EventId, RecordId, RequestId, SessionId};
use crate::path::CanonicalPath;
use crate::policy::DecisionSource;
use crate::record::Attribution;
use crate::redacted::Redacted;
use crate::session::{Actor, ProfileName, Session, SessionState, StateChanged};
use crate::time::Timestamp;
use crate::violation::SandboxViolation;

/// The most paths one `agent.edit` event lists (KNSH-081); further paths of the same batch are only counted, so one
/// burst of edits cannot make an event of unbounded size.
pub const AGENT_EDIT_PATHS: usize = 256;

/// Events kept per session for `since_seq` resumes (FR-EVT-03), and the bound of each subscription's queue.
pub const EVENT_BUFFER_LEN: usize = 10_000;

/// Buffers of ended sessions kept, most recently ended first. Older ones are dropped, and subscribing to such a
/// session is "not found or ended" (`-32006`).
pub const MAX_ENDED_BUFFERS: usize = 64;

/// The payload of one event: its name and its `data` member.
///
/// Every text field is [`Redacted`] or typed (FR-EVT-07). The enum is closed: a new event is a new variant, and
/// every `match` on it must decide what to do with it.
#[derive(Clone, Debug)]
pub enum EventData {
    /// `session.started`: a session began. Always the session's first event (`seq` 1).
    SessionStarted {
        /// The policy profile the session runs under.
        profile: ProfileName,
        /// Whether this is an agent session started with `knsh agent`.
        envelope: bool,
        /// Whether command recording is on.
        recording: bool,
        /// The parent session, when the session was started from another one (FR-SES-03).
        parent_session_id: Option<SessionId>,
    },
    /// `session.ended`: the session exited. Always the session's last event.
    SessionEnded,
    /// `session.state_changed`: paused, resumed, taken over by the human, handed back or ended (FR-SES-14).
    SessionStateChanged {
        /// The state before the change.
        from: SessionState,
        /// The state after the change.
        to: SessionState,
    },
    /// `session.idle`: a human prompt has waited 5 s for input.
    SessionIdle,
    /// `command.finished`: a line exited and its record is written (human telemetry in phase 1).
    CommandFinished {
        /// The record written for the line.
        record_id: RecordId,
        /// The line, already redacted (FR-EVT-07).
        command: Redacted<String>,
        /// The working directory the line ran in.
        cwd: CanonicalPath,
        /// When the line started.
        started_at: Timestamp,
        /// When it exited.
        ended_at: Timestamp,
        /// Its exit code; `None` when it is not known (for example, killed by a signal).
        exit_code: Option<i32>,
    },
    /// `cwd.changed`: the session's working directory changed.
    CwdChanged {
        /// The new working directory.
        cwd: CanonicalPath,
    },
    /// `sandbox.violation`: the system reported a sandbox denial attributed to the session by its tag, best effort
    /// (FR-SBX-08, KNSH-047). Repeats within the merge window are one event with their count.
    SandboxViolation(Box<SandboxViolation>),
    /// `command.proposed`: lifecycle step 3 (FR-LC-07, KNSH-050), once for each line the supervisor evaluates and
    /// before its hooks run: once for the line received, and once more for the line a rewrite produced.
    CommandProposed {
        /// The line, redacted: what hooks and the authority see (FR-REC-05).
        command: Redacted<String>,
        /// The working directory the line would run in.
        cwd: CanonicalPath,
        /// The line before a rewrite, when this is the rewritten one (FR-AUTH-30).
        rewritten_from: Option<Redacted<String>>,
    },
    /// `command.denied`: a line was refused and never ran (FR-LC-32).
    CommandDenied {
        /// The record of the denial (FR-REC-03), or `None` if it could not be written.
        record_id: Option<RecordId>,
        /// The line that was refused, redacted.
        command: Redacted<String>,
        /// The working directory it would have run in.
        cwd: CanonicalPath,
        /// Which component refused it.
        source: DecisionSource,
        /// The rule that matched, when a rule decided.
        rule_id: Option<Redacted<String>>,
        /// Why, in words, when the engine has a reason.
        reason: Option<Redacted<String>>,
    },
    /// `command.denied_repeatedly`: the same normalised line was denied often enough in its session that it is now
    /// denied without asking anyone until `until` (FR-HOOK-20, FR-HOOK-21, KNSH-055). Published once when limiting
    /// starts, right after the `command.denied` of the denial that started it.
    CommandDeniedRepeatedly {
        /// The line that is limited, redacted: the one whose denial started the limit.
        command: Redacted<String>,
        /// The working directory of that denial.
        cwd: CanonicalPath,
        /// When the limit lifts.
        until: Timestamp,
    },
    /// `command.started`: an allowed line was spawned through `knsh-exec` (FR-LC-17, KNSH-051).
    CommandStarted {
        /// The record the line is written to when it ends.
        record_id: RecordId,
        /// The line that runs (after any rewrite), redacted.
        command: Redacted<String>,
        /// The working directory it runs in.
        cwd: CanonicalPath,
        /// When it was spawned.
        started_at: Timestamp,
    },
    /// `command.long_running`: a line is still running after the long-running threshold, 30 s by default
    /// (FR-LC-17, KNSH-051). Published at most once per line.
    CommandLongRunning {
        /// The line's record.
        record_id: RecordId,
        /// The line, redacted.
        command: Redacted<String>,
        /// The working directory it runs in.
        cwd: CanonicalPath,
        /// When it was spawned.
        started_at: Timestamp,
    },
    /// `command.output`: one chunk of a running line's output, published only when the session records output
    /// (FR-LC-18, KNSH-053). A stream's chunks are published in order; the bytes travel beside the JSON as a binary
    /// stream (or base64 for a client that opted out of binary frames).
    CommandOutput {
        /// The line's record.
        record_id: RecordId,
        /// Which stream the chunk is from.
        stream: crate::record::OutputStream,
        /// Where the chunk starts in the stream, as captured (after redaction).
        offset: u64,
        /// The chunk, already through the redaction hook (FR-EVT-07).
        bytes: Redacted<Vec<u8>>,
    },
    /// `proxy.denied`: the proxy refused a connection of the session (FR-NET-09, KNSH-060). Published for refusals
    /// whose credentials were live, so the session is known; refusals before that are only logged.
    ProxyDenied {
        /// The line whose credentials made the request, or `None` for the envelope's own connection: envelope-level
        /// connections are attributed to the session alone.
        record_id: Option<RecordId>,
        /// How the client spoke to the proxy (`http` or `socks5`), when known.
        protocol: Option<&'static str>,
        /// The host the request named, redacted, or `None` when it named no valid one.
        host: Option<Redacted<String>>,
        /// The port the request named, when it named a valid destination.
        port: Option<u16>,
        /// The proxy's fixed reason (`host_not_allowed`, `approval_required`, `address_not_allowed`, …).
        reason: &'static str,
    },
    /// `decision.cancelled`: a pending decision ended without an answer (FR-LC-41, FR-AUTH-22, FR-AUTH-23).
    DecisionCancelled {
        /// The pending request, when the line had reached the ask step; `None` if it was still in its hooks.
        request_id: Option<RequestId>,
        /// Why it ended.
        reason: CancelReason,
    },
    /// `policy.invalid`: a policy file the session needed has a missing or bad signature, so it was ignored and the
    /// line refused, never run under another profile (FR-POL-42, KNSH-065).
    PolicyInvalid {
        /// The profile whose file failed its check: the session's own profile or a parent it `extends`.
        profile: ProfileName,
    },
    /// `file.changed`: a path under one of the session's checkpoint roots changed, by any process (FR-EVT-08,
    /// KNSH-080). Published once the watcher has brought the root's shadow in step with it.
    FileChanged {
        /// The checkpoint root.
        root: CanonicalPath,
        /// The path that changed (created, written, removed or replaced), inside `root`.
        path: CanonicalPath,
    },
    /// `agent.edit`: paths under a checkpoint root changed inside an envelope while no supervised line ran there
    /// (FR-CKP-06, KNSH-081). Published once the watcher has brought the root's shadow in step with them, at most
    /// [`AGENT_EDIT_PATHS`] paths per event.
    AgentEdit {
        /// The checkpoint root.
        root: CanonicalPath,
        /// The paths that changed, inside `root`, sorted; at most [`AGENT_EDIT_PATHS`].
        paths: Vec<CanonicalPath>,
        /// How many more paths changed than `paths` lists (each was still published as `file.changed`), saturating.
        omitted: u32,
    },
    /// `checkpoint.uncertain`: file events of a root may have been lost, so the root was rescanned and the changes of
    /// that window cannot be attributed with certainty (FR-CKP-04, NFR-REL-04, KNSH-080).
    CheckpointUncertain {
        /// The checkpoint root.
        root: CanonicalPath,
        /// The line whose window it was, or `None` for a window outside any line.
        record_id: Option<RecordId>,
        /// Why.
        reason: UncertainReason,
    },
    /// `checkpoint.created`: the pre-images and post-image identities of one change were stored as a checkpoint
    /// (FR-CKP-11, KNSH-082). Published once the change's edge has closed, on each session it belongs to.
    CheckpointCreated {
        /// The checkpoint.
        checkpoint_id: CheckpointId,
        /// How its change was attributed.
        attribution: Attribution,
        /// The lines whose change it holds: one for `command`, the set for `concurrent`, none for agent or external
        /// edits.
        record_ids: Vec<RecordId>,
        /// The checkpoint roots it covers.
        roots: Vec<CanonicalPath>,
        /// How many paths it holds.
        files_changed: u64,
        /// Whether it is uncertain: events may have been lost, or a pre-image or post-image could not be captured,
        /// so it may be incomplete (never wrong).
        uncertain: bool,
    },
}

/// Why the changes of a window in a checkpoint root are uncertain (`checkpoint.uncertain`, FR-CKP-04, KNSH-080).
/// Ordered by declaration, so a set of reasons is reported in a stable order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum UncertainReason {
    /// The system reported dropped events (`MustScanSubDirs`, `UserDropped`, `KernelDropped`).
    EventsDropped,
    /// The system's event identifiers wrapped around (`EventIdsWrapped`).
    EventIdsWrapped,
    /// The root itself, or a folder above it, was moved, removed or recreated, or a volume below it unmounted.
    RootChanged,
    /// More paths changed at once than the watcher keeps one by one: it fell back to rescanning the whole root.
    TooManyEvents,
    /// The line-end procedure did not see its marker, or did not settle the shadow, before its deadline (decision 16).
    FlushTimedOut,
    /// `knshd` was not running for a while, so changes in that gap were not watched (NFR-REL-04).
    RestartGap,
    /// The root is not watched: its file-event stream could not be started or has stopped.
    NotWatched,
    /// The shadow could not be brought in step with a change (a file operation failed).
    ShadowUpdateFailed,
    /// A changed path's pre-image could not be moved into its checkpoint, or its post-image identity could not be
    /// read (KNSH-082): the checkpoint lacks that path's data rather than holding a wrong one.
    CaptureFailed,
}

impl UncertainReason {
    /// The wire value: `events_dropped`, `event_ids_wrapped`, `root_changed`, `too_many_events`, `flush_timed_out`,
    /// `restart_gap`, `not_watched`, `shadow_update_failed` or `capture_failed`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EventsDropped => "events_dropped",
            Self::EventIdsWrapped => "event_ids_wrapped",
            Self::RootChanged => "root_changed",
            Self::TooManyEvents => "too_many_events",
            Self::FlushTimedOut => "flush_timed_out",
            Self::RestartGap => "restart_gap",
            Self::NotWatched => "not_watched",
            Self::ShadowUpdateFailed => "shadow_update_failed",
            Self::CaptureFailed => "capture_failed",
        }
    }
}

/// Why a pending decision was cancelled (`decision.cancelled`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CancelReason {
    /// The caller disconnected while the decision was pending (FR-LC-41): the line never runs.
    CallerGone,
    /// No answer came before the timeout (FR-AUTH-23): the line is denied.
    TimedOut,
}

impl CancelReason {
    /// The wire spelling: `caller_gone` or `timed_out`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CallerGone => "caller_gone",
            Self::TimedOut => "timed_out",
        }
    }
}

/// The payload of an engine event: one that belongs to no session (KNSH-068).
///
/// Closed, like [`EventData`]: a new engine event is a new variant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EngineEventData {
    /// `authority.connected`: an authority registered on the control service (FR-AUTH-01, FR-AUTH-02).
    AuthorityConnected,
    /// `authority.disconnected`: the registered authority's connection ended (FR-AUTH-02).
    AuthorityDisconnected,
    /// `policy.updated`: the authority pushed a policy snapshot, which was loaded (FR-POL-53, KNSH-071). A pushed
    /// profile can be used by sessions of any agent, so the event belongs to the engine rather than one session.
    PolicyUpdated {
        /// The profile the snapshot defines.
        profile: ProfileName,
        /// When the snapshot expires (FR-POL-50).
        expires_at: Timestamp,
    },
}

impl EngineEventData {
    /// The event name, the envelope's `event` member.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::AuthorityConnected => "authority.connected",
            Self::AuthorityDisconnected => "authority.disconnected",
            Self::PolicyUpdated { .. } => "policy.updated",
        }
    }
}

/// One engine event, as delivered to subscribers: the envelope of `specs/05-models/event.md` with no session and no
/// actor (`session_id` and `actor` are `null` on the wire), and `seq` in the engine's own sequence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EngineEvent {
    /// Unique event ID.
    pub id: EventId,
    /// Position in the engine sequence: 1 for the bus's first engine event, then one more per engine event.
    pub seq: u64,
    /// When the event was published, UTC microseconds.
    pub ts: Timestamp,
    /// The name and payload.
    pub data: EngineEventData,
}

impl EngineEvent {
    /// The event name, the envelope's `event` member.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        self.data.name()
    }
}

impl EventData {
    /// The raw bytes the event carries beside its JSON: a `command.output` chunk. `None` for every other event.
    #[must_use]
    pub fn bytes(&self) -> Option<&Redacted<Vec<u8>>> {
        match self {
            Self::CommandOutput { bytes, .. } => Some(bytes),
            Self::SessionStarted { .. }
            | Self::SessionEnded
            | Self::SessionStateChanged { .. }
            | Self::SessionIdle
            | Self::CommandFinished { .. }
            | Self::CwdChanged { .. }
            | Self::SandboxViolation(_)
            | Self::ProxyDenied { .. }
            | Self::CommandProposed { .. }
            | Self::CommandDenied { .. }
            | Self::CommandDeniedRepeatedly { .. }
            | Self::DecisionCancelled { .. }
            | Self::PolicyInvalid { .. }
            | Self::CommandStarted { .. }
            | Self::CommandLongRunning { .. }
            | Self::FileChanged { .. }
            | Self::AgentEdit { .. }
            | Self::CheckpointUncertain { .. }
            | Self::CheckpointCreated { .. } => None,
        }
    }

    /// The event name, the envelope's `event` member, for example `session.started`.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::SessionStarted { .. } => "session.started",
            Self::SessionEnded => "session.ended",
            Self::SessionStateChanged { .. } => crate::session::STATE_CHANGED_EVENT,
            Self::SessionIdle => "session.idle",
            Self::CommandFinished { .. } => "command.finished",
            Self::CwdChanged { .. } => "cwd.changed",
            Self::SandboxViolation(_) => "sandbox.violation",
            Self::ProxyDenied { .. } => "proxy.denied",
            Self::CommandProposed { .. } => "command.proposed",
            Self::CommandDenied { .. } => "command.denied",
            Self::CommandDeniedRepeatedly { .. } => "command.denied_repeatedly",
            Self::DecisionCancelled { .. } => "decision.cancelled",
            Self::CommandStarted { .. } => "command.started",
            Self::CommandLongRunning { .. } => "command.long_running",
            Self::CommandOutput { .. } => "command.output",
            Self::PolicyInvalid { .. } => "policy.invalid",
            Self::FileChanged { .. } => "file.changed",
            Self::AgentEdit { .. } => "agent.edit",
            Self::CheckpointUncertain { .. } => "checkpoint.uncertain",
            Self::CheckpointCreated { .. } => "checkpoint.created",
        }
    }

    /// The `session.started` payload of a session that was just created.
    #[must_use]
    pub fn started(session: &Session) -> Self {
        Self::SessionStarted {
            profile: session.profile().clone(),
            envelope: session.envelope(),
            recording: session.recording(),
            parent_session_id: session.parent_session_id(),
        }
    }

    /// The `session.state_changed` payload of a transition (FR-SES-14).
    #[must_use]
    pub const fn state_changed(change: &StateChanged) -> Self {
        Self::SessionStateChanged {
            from: change.from,
            to: change.to,
        }
    }
}

/// One event, as delivered to subscribers (`specs/05-models/event.md`).
#[derive(Clone, Debug)]
pub struct Event {
    /// Unique event ID.
    pub id: EventId,
    /// Position in the session's sequence: 1 for `session.started`, then one more per event (FR-EVT-02).
    pub seq: u64,
    /// When the event was published, UTC microseconds.
    pub ts: Timestamp,
    /// The session the event belongs to.
    pub session_id: SessionId,
    /// The session's actor, fixed for the session's whole life (FR-SES-01).
    pub actor: Actor,
    /// The name and payload.
    pub data: EventData,
}

impl Event {
    /// The event name, the envelope's `event` member.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        self.data.name()
    }
}

/// Identifies a subscription within one [`EventBus`]. Never reused while the bus lives.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct SubscriptionId(u64);

impl SubscriptionId {
    /// Wraps a wire value. The bus decides which values name a live subscription; any other is simply unknown.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// The wire value: a positive integer.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Which events a subscription receives (FR-EVT-01).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum EventScope {
    /// Every session's events (`user.sock` and the control service).
    All,
    /// Only this session's events.
    Session(SessionId),
}

impl EventScope {
    fn includes(self, session_id: SessionId) -> bool {
        match self {
            Self::All => true,
            Self::Session(scoped) => scoped == session_id,
        }
    }
}

/// Events of one session that a subscription will never receive: its queue overflowed while the subscriber fell
/// behind (FR-EVT-04). The subscriber reads what it needs from the record store.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Lost {
    /// The session whose events were lost.
    pub session_id: SessionId,
    /// The first lost `seq`.
    pub from_seq: u64,
    /// The last lost `seq` (inclusive). Every `seq` between the two was lost, and none outside them.
    pub to_seq: u64,
}

/// Engine events that a subscription will never receive: its queue overflowed (FR-EVT-04). Like [`Lost`], with the
/// engine sequence instead of a session's.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct EngineLost {
    /// The first lost engine `seq`.
    pub from_seq: u64,
    /// The last lost engine `seq` (inclusive).
    pub to_seq: u64,
}

/// What [`EventBus::take`] hands a subscriber, in delivery order.
#[derive(Clone, Debug)]
pub enum Delivery {
    /// The next event.
    Event(Arc<Event>),
    /// A range of events that will never be delivered. Always reported before any later event of its session.
    Lost(Lost),
    /// The next engine event (KNSH-068). Only [`EventScope::All`] subscriptions receive these.
    Engine(Arc<EngineEvent>),
    /// A range of engine events that will never be delivered. Always reported before any later engine event.
    EngineLost(EngineLost),
}

/// What [`EventBus::subscribe`] tells the new subscriber.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Subscribed {
    /// The new subscription.
    pub id: SubscriptionId,
    /// For a session scope, the oldest `seq` still buffered: how far back a resume can reach. `None` for
    /// [`EventScope::All`].
    pub oldest_seq: Option<u64>,
    /// For a session scope, the newest `seq` published so far. `None` for [`EventScope::All`].
    pub latest_seq: Option<u64>,
    /// Whether `since_seq` was older than the buffer: events after it and before `oldest_seq` are not delivered,
    /// and delivery starts at `oldest_seq` instead.
    pub gap: bool,
}

/// What [`EventBus::publish`] did.
#[derive(Clone, Debug)]
pub struct Published {
    /// The event, as numbered and buffered.
    pub event: Arc<Event>,
    /// Every subscription that received it, so the caller can wake their readers.
    pub delivered_to: Vec<SubscriptionId>,
}

/// What [`EventBus::publish_engine`] did.
#[derive(Clone, Debug)]
pub struct PublishedEngine {
    /// The event, as numbered.
    pub event: Arc<EngineEvent>,
    /// Every subscription that received it, so the caller can wake their readers.
    pub delivered_to: Vec<SubscriptionId>,
}

/// Sizes of the bus. [`BusLimits::default`] is the specified configuration; tests use smaller ones.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct BusLimits {
    /// Events kept per session ([`EVENT_BUFFER_LEN`]).
    pub buffer_len: usize,
    /// Events a subscription may have waiting before the oldest are dropped ([`EVENT_BUFFER_LEN`]).
    pub queue_len: usize,
    /// Buffers of ended sessions kept ([`MAX_ENDED_BUFFERS`]).
    pub ended_buffers: usize,
}

impl Default for BusLimits {
    fn default() -> Self {
        Self {
            buffer_len: EVENT_BUFFER_LEN,
            queue_len: EVENT_BUFFER_LEN,
            ended_buffers: MAX_ENDED_BUFFERS,
        }
    }
}

/// The buffered events of one session.
#[derive(Debug)]
struct Buffer {
    /// The session's actor; every later event must carry the same one.
    actor: Actor,
    /// The `seq` the next event gets.
    next_seq: u64,
    /// The newest events, oldest first, with consecutive `seq`s.
    events: VecDeque<Arc<Event>>,
    /// Whether `session.ended` was published: nothing more is accepted.
    ended: bool,
}

impl Buffer {
    fn oldest_seq(&self) -> Option<u64> {
        self.events.front().map(|event| event.seq)
    }

    fn latest_seq(&self) -> Option<u64> {
        self.next_seq.checked_sub(1).filter(|&seq| seq > 0)
    }
}

/// One waiting event of a subscription: a session's or the engine's.
#[derive(Debug)]
enum Queued {
    Session(Arc<Event>),
    Engine(Arc<EngineEvent>),
}

/// One subscription's undelivered events.
#[derive(Debug)]
struct Subscription {
    scope: EventScope,
    /// Waiting events, oldest first. Per session, and for the engine, their `seq`s are consecutive.
    queue: VecDeque<Queued>,
    /// Dropped ranges per session, not yet reported.
    lost: BTreeMap<SessionId, Lost>,
    /// Dropped engine events, not yet reported.
    engine_lost: Option<EngineLost>,
}

impl Subscription {
    /// Queues `event`, dropping the oldest waiting event if the queue is full (FR-EVT-04).
    fn push(&mut self, event: Arc<Event>, limit: usize) {
        self.push_queued(Queued::Session(event), limit);
    }

    /// Queues `queued`, dropping the oldest waiting event if the queue is full (FR-EVT-04).
    fn push_queued(&mut self, queued: Queued, limit: usize) {
        self.queue.push_back(queued);
        while self.queue.len() > limit {
            let Some(dropped) = self.queue.pop_front() else {
                break;
            };
            // A stream's queued events are consecutive and the oldest goes first, so each drop extends the range
            // already recorded for its session (or the engine), or starts one.
            match dropped {
                Queued::Session(dropped) => {
                    self.lost
                        .entry(dropped.session_id)
                        .and_modify(|lost| lost.to_seq = dropped.seq)
                        .or_insert(Lost {
                            session_id: dropped.session_id,
                            from_seq: dropped.seq,
                            to_seq: dropped.seq,
                        });
                }
                Queued::Engine(dropped) => {
                    let lost = self.engine_lost.get_or_insert(EngineLost {
                        from_seq: dropped.seq,
                        to_seq: dropped.seq,
                    });
                    lost.to_seq = dropped.seq;
                }
            }
        }
    }
}

/// The event bus: per-session numbering and buffers, and per-subscription queues. See the module docs.
///
/// # Invariants
///
/// - Each buffer holds at most `limits.buffer_len` events with consecutive `seq`s ending at `next_seq - 1`.
/// - Each queue holds at most `limits.queue_len` events.
/// - At most `limits.ended_buffers` buffers belong to ended sessions.
#[derive(Debug)]
pub struct EventBus {
    limits: BusLimits,
    buffers: BTreeMap<SessionId, Buffer>,
    /// Ended sessions whose buffers are still kept, oldest first.
    ended: VecDeque<SessionId>,
    subscriptions: BTreeMap<SubscriptionId, Subscription>,
    /// The next subscription ID; starts at 1.
    next_subscription: u64,
    /// The `seq` the next engine event gets; starts at 1.
    next_engine_seq: u64,
}

impl Default for EventBus {
    fn default() -> Self {
        Self::new(BusLimits::default())
    }
}

impl EventBus {
    /// An empty bus with these limits. A limit of zero is raised to one: a bus must keep at least the last event.
    #[must_use]
    pub fn new(limits: BusLimits) -> Self {
        Self {
            limits: BusLimits {
                buffer_len: limits.buffer_len.max(1),
                queue_len: limits.queue_len.max(1),
                ended_buffers: limits.ended_buffers,
            },
            buffers: BTreeMap::new(),
            ended: VecDeque::new(),
            subscriptions: BTreeMap::new(),
            next_subscription: 1,
            next_engine_seq: 1,
        }
    }

    /// The actor of `session_id` if the session has started and not ended: who its later events must name. Lets a
    /// publisher that only knows the session (the sandbox violation reader, KNSH-047) publish for it.
    #[must_use]
    pub fn session_actor(&self, session_id: SessionId) -> Option<&Actor> {
        self.buffers
            .get(&session_id)
            .filter(|buffer| !buffer.ended)
            .map(|buffer| &buffer.actor)
    }

    /// Numbers `data` as the session's next event, buffers it and queues it for every subscription in scope.
    ///
    /// `id` and `ts` come from the caller's clock and random source. Never waits for a subscriber: a full queue
    /// drops its own oldest event instead (FR-EVT-04).
    ///
    /// # Errors
    ///
    /// Nothing is numbered, buffered or queued on error.
    ///
    /// - [`CoreError::SessionExists`] for `session.started` of a session that already has events.
    /// - [`CoreError::SessionNotFoundOrEnded`] for any other event of a session without `session.started`, or of
    ///   one that has ended.
    /// - [`CoreError::EventActorMismatch`] if `actor` is not the actor the session started with (FR-SES-01).
    pub fn publish(
        &mut self,
        session_id: SessionId,
        actor: &Actor,
        data: EventData,
        id: EventId,
        ts: Timestamp,
    ) -> Result<Published, CoreError> {
        let is_start = matches!(data, EventData::SessionStarted { .. });
        let is_end = matches!(data, EventData::SessionEnded);
        let buffer = match (self.buffers.get_mut(&session_id), is_start) {
            (Some(_), true) => return Err(CoreError::SessionExists),
            (None, false) => return Err(CoreError::SessionNotFoundOrEnded),
            (None, true) => self.buffers.entry(session_id).or_insert(Buffer {
                actor: actor.clone(),
                next_seq: 1,
                events: VecDeque::new(),
                ended: false,
            }),
            (Some(buffer), false) => {
                if buffer.ended {
                    return Err(CoreError::SessionNotFoundOrEnded);
                }
                if buffer.actor != *actor {
                    return Err(CoreError::EventActorMismatch);
                }
                buffer
            }
        };
        let event = Arc::new(Event {
            id,
            seq: buffer.next_seq,
            ts,
            session_id,
            actor: buffer.actor.clone(),
            data,
        });
        buffer.next_seq += 1;
        buffer.events.push_back(Arc::clone(&event));
        if buffer.events.len() > self.limits.buffer_len {
            buffer.events.pop_front();
        }
        if is_end {
            buffer.ended = true;
            self.ended.push_back(session_id);
            self.forget_old_ended();
        }
        let mut delivered_to = Vec::new();
        for (&subscription_id, subscription) in &mut self.subscriptions {
            if subscription.scope.includes(session_id) {
                subscription.push(Arc::clone(&event), self.limits.queue_len);
                delivered_to.push(subscription_id);
            }
        }
        Ok(Published { event, delivered_to })
    }

    /// Numbers `data` as the engine's next event and queues it for every [`EventScope::All`] subscription. Engine
    /// events are not buffered. Never waits for a subscriber (FR-EVT-04). Never fails.
    pub fn publish_engine(&mut self, data: EngineEventData, id: EventId, ts: Timestamp) -> PublishedEngine {
        let event = Arc::new(EngineEvent {
            id,
            seq: self.next_engine_seq,
            ts,
            data,
        });
        self.next_engine_seq += 1;
        let mut delivered_to = Vec::new();
        for (&subscription_id, subscription) in &mut self.subscriptions {
            if subscription.scope == EventScope::All {
                subscription.push_queued(Queued::Engine(Arc::clone(&event)), self.limits.queue_len);
                delivered_to.push(subscription_id);
            }
        }
        PublishedEngine { event, delivered_to }
    }

    /// Drops the buffers of the oldest ended sessions beyond the limit. Subscriptions keep whatever they had already
    /// queued from them.
    fn forget_old_ended(&mut self) {
        while self.ended.len() > self.limits.ended_buffers {
            if let Some(session_id) = self.ended.pop_front() {
                self.buffers.remove(&session_id);
            }
        }
    }

    /// Registers a subscription to `scope`. With `since_seq` (session scope only), the buffered events after it are
    /// queued at once, in the same step, so delivery resumes exactly after `since_seq` (FR-EVT-03). Without it, the
    /// subscription receives events published from now on.
    ///
    /// When `since_seq` is older than the buffer, delivery starts at the oldest buffered event and
    /// [`Subscribed::gap`] is set (at most once beyond the buffer, FR-EVT-04).
    ///
    /// # Errors
    ///
    /// Nothing is registered on error.
    ///
    /// - [`CoreError::SessionNotFoundOrEnded`] if the session has no buffer: it never started, or it ended and its
    ///   buffer was dropped.
    /// - [`CoreError::InvalidSinceSeq`] if `since_seq` is given without a session scope, or is newer than the
    ///   session's latest event.
    pub fn subscribe(&mut self, scope: EventScope, since_seq: Option<u64>) -> Result<Subscribed, CoreError> {
        let mut subscription = Subscription {
            scope,
            queue: VecDeque::new(),
            lost: BTreeMap::new(),
            engine_lost: None,
        };
        let (oldest_seq, latest_seq, gap) = match scope {
            EventScope::All => {
                if since_seq.is_some() {
                    return Err(CoreError::InvalidSinceSeq);
                }
                (None, None, false)
            }
            EventScope::Session(session_id) => {
                let buffer = self.buffers.get(&session_id).ok_or(CoreError::SessionNotFoundOrEnded)?;
                let (oldest, latest) = (buffer.oldest_seq(), buffer.latest_seq());
                let gap = match since_seq {
                    None => false,
                    Some(since) => {
                        if since > latest.unwrap_or(0) {
                            return Err(CoreError::InvalidSinceSeq);
                        }
                        for event in buffer.events.iter().filter(|event| event.seq > since) {
                            subscription.push(Arc::clone(event), self.limits.queue_len);
                        }
                        // `since + 1` is the first event the subscriber wants; the buffer starts later.
                        oldest.is_some_and(|oldest| since.saturating_add(1) < oldest)
                    }
                };
                (oldest, latest, gap)
            }
        };
        let id = SubscriptionId(self.next_subscription);
        self.next_subscription += 1;
        self.subscriptions.insert(id, subscription);
        Ok(Subscribed {
            id,
            oldest_seq,
            latest_seq,
            gap,
        })
    }

    /// Ends a subscription and drops what it had queued. Returns whether it existed.
    pub fn unsubscribe(&mut self, id: SubscriptionId) -> bool {
        self.subscriptions.remove(&id).is_some()
    }

    /// Takes up to `max` deliveries from a subscription's queue, in order: lost ranges first (each precedes every
    /// later event of its session), then events. Returns `None` if the subscription does not exist.
    pub fn take(&mut self, id: SubscriptionId, max: usize) -> Option<Vec<Delivery>> {
        let subscription = self.subscriptions.get_mut(&id)?;
        let mut taken = Vec::new();
        if taken.len() < max
            && let Some(lost) = subscription.engine_lost.take()
        {
            taken.push(Delivery::EngineLost(lost));
        }
        while taken.len() < max {
            let Some((_, lost)) = subscription.lost.pop_first() else {
                break;
            };
            taken.push(Delivery::Lost(lost));
        }
        while taken.len() < max {
            let Some(queued) = subscription.queue.pop_front() else {
                break;
            };
            taken.push(match queued {
                Queued::Session(event) => Delivery::Event(event),
                Queued::Engine(event) => Delivery::Engine(event),
            });
        }
        Some(taken)
    }

    /// Whether the subscription has something waiting. `false` for an unknown subscription.
    #[must_use]
    pub fn has_pending(&self, id: SubscriptionId) -> bool {
        self.subscriptions.get(&id).is_some_and(|subscription| {
            !subscription.queue.is_empty() || !subscription.lost.is_empty() || subscription.engine_lost.is_some()
        })
    }

    /// The oldest buffered `seq` of a session, or `None` if it has no buffer.
    #[must_use]
    pub fn oldest_seq(&self, session_id: SessionId) -> Option<u64> {
        self.buffers.get(&session_id).and_then(Buffer::oldest_seq)
    }

    /// The newest `seq` of a session, or `None` if it has no buffer.
    #[must_use]
    pub fn latest_seq(&self, session_id: SessionId) -> Option<u64> {
        self.buffers.get(&session_id).and_then(Buffer::latest_seq)
    }

    /// The number of live subscriptions.
    #[must_use]
    pub fn subscription_count(&self) -> usize {
        self.subscriptions.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::AgentId;
    use crate::ulid::Ulid;

    fn sid(n: u128) -> SessionId {
        SessionId::from_ulid(Ulid::from_u128(n))
    }

    fn agent() -> Actor {
        Actor::Agent(AgentId::new("claude-code").unwrap())
    }

    /// Publishes with a fixed event ID and time: the bus never reads them.
    fn publish(bus: &mut EventBus, session: u128, data: EventData) -> Result<Published, CoreError> {
        bus.publish(
            sid(session),
            &agent(),
            data,
            EventId::from_ulid(Ulid::from_u128(1)),
            Timestamp::from_unix_micros(0).unwrap(),
        )
    }

    fn start(bus: &mut EventBus, session: u128) {
        publish(
            bus,
            session,
            EventData::SessionStarted {
                profile: ProfileName::new("default").unwrap(),
                envelope: true,
                recording: true,
                parent_session_id: None,
            },
        )
        .unwrap();
    }

    fn idle(bus: &mut EventBus, session: u128) -> u64 {
        publish(bus, session, EventData::SessionIdle).unwrap().event.seq
    }

    /// Everything waiting for `id`.
    fn drain(bus: &mut EventBus, id: SubscriptionId) -> Vec<Delivery> {
        bus.take(id, usize::MAX).unwrap()
    }

    fn seqs(deliveries: &[Delivery]) -> Vec<u64> {
        deliveries
            .iter()
            .map(|delivery| match delivery {
                Delivery::Event(event) => event.seq,
                other => panic!("unexpected delivery {other:?}"),
            })
            .collect()
    }

    fn engine(bus: &mut EventBus, data: EngineEventData) -> PublishedEngine {
        bus.publish_engine(
            data,
            EventId::from_ulid(Ulid::from_u128(1)),
            Timestamp::from_unix_micros(0).unwrap(),
        )
    }

    // FR-AUTH-02, KNSH-068: engine events are numbered in their own gapless sequence, reach only subscriptions to
    // every session, and keep their place among the session events.
    #[test]
    fn engine_events_reach_all_scope_subscriptions_in_order() {
        let mut bus = EventBus::default();
        start(&mut bus, 1);
        let all = bus.subscribe(EventScope::All, None).unwrap().id;
        let one = bus.subscribe(EventScope::Session(sid(1)), None).unwrap().id;
        let connected = engine(&mut bus, EngineEventData::AuthorityConnected);
        assert_eq!(connected.event.seq, 1);
        assert_eq!(connected.event.name(), "authority.connected");
        assert_eq!(connected.delivered_to, [all]);
        idle(&mut bus, 1);
        let disconnected = engine(&mut bus, EngineEventData::AuthorityDisconnected);
        assert_eq!(disconnected.event.seq, 2);
        assert_eq!(disconnected.event.name(), "authority.disconnected");

        let names: Vec<_> = drain(&mut bus, all)
            .iter()
            .map(|delivery| match delivery {
                Delivery::Event(event) => event.name(),
                Delivery::Engine(event) => event.name(),
                other => panic!("unexpected delivery {other:?}"),
            })
            .collect();
        assert_eq!(names, ["authority.connected", "session.idle", "authority.disconnected"]);
        assert_eq!(
            seqs(&drain(&mut bus, one)),
            [2],
            "a session subscription never sees engine events"
        );
    }

    // FR-EVT-04 for engine events: an overflowing queue reports the dropped engine events as one range.
    #[test]
    fn dropped_engine_events_are_reported_as_lost() {
        let mut bus = small(4, 2);
        let all = bus.subscribe(EventScope::All, None).unwrap().id;
        for _ in 0..4 {
            engine(&mut bus, EngineEventData::AuthorityConnected);
        }
        assert!(bus.has_pending(all));
        let deliveries = drain(&mut bus, all);
        assert!(
            matches!(
                deliveries.as_slice(),
                [
                    Delivery::EngineLost(EngineLost { from_seq: 1, to_seq: 2 }),
                    Delivery::Engine(third),
                    Delivery::Engine(fourth),
                ] if third.seq == 3 && fourth.seq == 4
            ),
            "{deliveries:?}"
        );
        assert!(!bus.has_pending(all));
    }

    fn small(buffer_len: usize, queue_len: usize) -> EventBus {
        EventBus::new(BusLimits {
            buffer_len,
            queue_len,
            ended_buffers: 2,
        })
    }

    // FR-EVT-02: seq starts at 1 and increases by exactly one per session, independently for each session.
    #[test]
    fn seq_is_gapless_per_session() {
        let mut bus = EventBus::default();
        start(&mut bus, 1);
        start(&mut bus, 2);
        let mut one = vec![1];
        let mut two = vec![1];
        for round in 0..50 {
            one.push(idle(&mut bus, 1));
            if round % 3 == 0 {
                two.push(idle(&mut bus, 2));
            }
        }
        assert_eq!(one, (1..=51).collect::<Vec<_>>());
        assert_eq!(two, (1..=18).collect::<Vec<_>>());
        assert_eq!(bus.latest_seq(sid(1)), Some(51));
    }

    // FR-EVT-03: the last 10,000 events of a session are kept; older ones are dropped.
    #[test]
    fn buffer_keeps_last_10000_events() {
        let mut bus = EventBus::default();
        start(&mut bus, 1);
        for _ in 0..12_499 {
            idle(&mut bus, 1);
        }
        assert_eq!(bus.latest_seq(sid(1)), Some(12_500));
        assert_eq!(bus.oldest_seq(sid(1)), Some(2_501), "exactly 10,000 kept");

        // A resume from just before the oldest buffered event gets all 10,000 and no gap.
        let resumed = bus.subscribe(EventScope::Session(sid(1)), Some(2_500)).unwrap();
        assert!(!resumed.gap);
        let delivered = seqs(&drain(&mut bus, resumed.id));
        assert_eq!(delivered, (2_501..=12_500).collect::<Vec<_>>());
    }

    // FR-EVT-04: publishing never waits for a subscriber that does not read. Its queue keeps the newest events and
    // reports the dropped range, once, before the next event of that session.
    #[test]
    fn slow_subscriber_does_not_block_publisher() {
        let mut bus = small(100, 5);
        start(&mut bus, 1);
        let slow = bus.subscribe(EventScope::All, None).unwrap();
        for _ in 0..20 {
            idle(&mut bus, 1);
        }
        assert_eq!(bus.latest_seq(sid(1)), Some(21), "every publish succeeded");
        let deliveries = drain(&mut bus, slow.id);
        let Delivery::Lost(lost) = &deliveries[0] else {
            panic!("the subscriber is told first: {deliveries:?}")
        };
        assert_eq!(
            *lost,
            Lost {
                session_id: sid(1),
                from_seq: 2,
                to_seq: 16
            }
        );
        assert_eq!(seqs(&deliveries[1..]), vec![17, 18, 19, 20, 21]);
        assert!(drain(&mut bus, slow.id).is_empty(), "reported once");

        // Caught up: the next events arrive with no further loss.
        idle(&mut bus, 1);
        assert_eq!(seqs(&drain(&mut bus, slow.id)), vec![22]);
    }

    // FR-EVT-01: a session-scoped subscription never receives another session's events, live or replayed.
    #[test]
    fn scoped_subscription_never_sees_other_sessions() {
        let mut bus = EventBus::default();
        start(&mut bus, 1);
        start(&mut bus, 2);
        idle(&mut bus, 2);
        let scoped = bus.subscribe(EventScope::Session(sid(1)), Some(0)).unwrap();
        let all = bus.subscribe(EventScope::All, None).unwrap();
        for _ in 0..3 {
            idle(&mut bus, 2);
            idle(&mut bus, 1);
        }
        let mine = drain(&mut bus, scoped.id);
        assert_eq!(mine.len(), 4, "session.started and three idles");
        for delivery in &mine {
            let Delivery::Event(event) = delivery else {
                panic!("nothing was lost")
            };
            assert_eq!(event.session_id, sid(1));
        }
        assert_eq!(drain(&mut bus, all.id).len(), 6, "an unscoped subscription sees both");
    }

    // FR-EVT-03: a resume inside the buffer continues exactly after since_seq, and later events follow with no
    // duplicate and no gap.
    #[test]
    fn resume_from_since_seq_has_no_duplicates_or_gaps() {
        let mut bus = EventBus::default();
        start(&mut bus, 1);
        for _ in 0..9 {
            idle(&mut bus, 1);
        }
        let first = bus.subscribe(EventScope::Session(sid(1)), None).unwrap();
        idle(&mut bus, 1);
        let seen = seqs(&drain(&mut bus, first.id));
        assert_eq!(seen, vec![11], "without since_seq, only new events");
        bus.unsubscribe(first.id);

        // Reconnect: published while away, then resume after the last seen.
        idle(&mut bus, 1);
        idle(&mut bus, 1);
        let resumed = bus.subscribe(EventScope::Session(sid(1)), Some(11)).unwrap();
        assert_eq!(
            (resumed.oldest_seq, resumed.latest_seq, resumed.gap),
            (Some(1), Some(13), false)
        );
        idle(&mut bus, 1);
        assert_eq!(seqs(&drain(&mut bus, resumed.id)), vec![12, 13, 14]);

        // Resuming at the latest seq delivers nothing old; since_seq 0 replays from the start.
        let at_latest = bus.subscribe(EventScope::Session(sid(1)), Some(14)).unwrap();
        assert!(drain(&mut bus, at_latest.id).is_empty());
        let from_start = bus.subscribe(EventScope::Session(sid(1)), Some(0)).unwrap();
        assert_eq!(seqs(&drain(&mut bus, from_start.id)), (1..=14).collect::<Vec<_>>());
    }

    // FR-EVT-04: a since_seq older than the buffer reports how far back the buffer reaches and starts there.
    #[test]
    fn since_seq_outside_buffer_reports_oldest_available() {
        let mut bus = small(5, 100);
        start(&mut bus, 1);
        for _ in 0..9 {
            idle(&mut bus, 1);
        }
        let resumed = bus.subscribe(EventScope::Session(sid(1)), Some(2)).unwrap();
        assert_eq!(
            (resumed.oldest_seq, resumed.latest_seq, resumed.gap),
            (Some(6), Some(10), true)
        );
        assert_eq!(seqs(&drain(&mut bus, resumed.id)), vec![6, 7, 8, 9, 10]);

        // Exactly one before the oldest is still inside: nothing between is missing.
        let edge = bus.subscribe(EventScope::Session(sid(1)), Some(5)).unwrap();
        assert!(!edge.gap);
    }

    #[test]
    fn since_seq_is_refused_without_a_session_or_beyond_the_latest() {
        let mut bus = EventBus::default();
        start(&mut bus, 1);
        assert_eq!(bus.subscribe(EventScope::All, Some(0)), Err(CoreError::InvalidSinceSeq));
        assert_eq!(
            bus.subscribe(EventScope::Session(sid(1)), Some(2)),
            Err(CoreError::InvalidSinceSeq)
        );
        assert_eq!(
            bus.subscribe(EventScope::Session(sid(9)), None),
            Err(CoreError::SessionNotFoundOrEnded)
        );
        assert_eq!(bus.subscription_count(), 0, "nothing registered on error");
    }

    // FR-SES-01, FR-EVT-02: a session's events start with session.started, carry its actor, and stop at
    // session.ended. Refused events are not numbered.
    #[test]
    fn session_lifecycle_bounds_its_events() {
        let mut bus = small(10, 10);
        assert_eq!(
            publish(&mut bus, 1, EventData::SessionIdle).map(|_| ()),
            Err(CoreError::SessionNotFoundOrEnded)
        );
        start(&mut bus, 1);
        assert_eq!(
            publish(
                &mut bus,
                1,
                EventData::SessionStarted {
                    profile: ProfileName::new("default").unwrap(),
                    envelope: false,
                    recording: false,
                    parent_session_id: None,
                }
            )
            .map(|_| ()),
            Err(CoreError::SessionExists)
        );
        let human = bus.publish(
            sid(1),
            &Actor::Human,
            EventData::SessionIdle,
            EventId::from_ulid(Ulid::from_u128(1)),
            Timestamp::from_unix_micros(0).unwrap(),
        );
        assert_eq!(human.map(|_| ()), Err(CoreError::EventActorMismatch));
        let ended = publish(&mut bus, 1, EventData::SessionEnded).unwrap();
        assert_eq!(ended.event.seq, 2, "refused events took no seq");
        assert_eq!(
            publish(&mut bus, 1, EventData::SessionIdle).map(|_| ()),
            Err(CoreError::SessionNotFoundOrEnded)
        );
        // The ended session's buffer is still there to catch up on.
        assert!(bus.subscribe(EventScope::Session(sid(1)), Some(0)).is_ok());
    }

    // Only the most recently ended sessions keep their buffers; live sessions are never dropped.
    #[test]
    fn ended_buffers_are_bounded() {
        let mut bus = small(10, 10);
        start(&mut bus, 100);
        for session in 1..=3 {
            start(&mut bus, session);
            publish(&mut bus, session, EventData::SessionEnded).unwrap();
        }
        assert_eq!(bus.latest_seq(sid(1)), None, "the oldest ended buffer was dropped");
        assert_eq!(bus.latest_seq(sid(2)), Some(2));
        assert_eq!(bus.latest_seq(sid(3)), Some(2));
        assert_eq!(bus.latest_seq(sid(100)), Some(1), "a live session is kept");
        assert_eq!(
            bus.subscribe(EventScope::Session(sid(1)), None),
            Err(CoreError::SessionNotFoundOrEnded)
        );
    }

    #[test]
    fn unsubscribe_stops_delivery() {
        let mut bus = EventBus::default();
        start(&mut bus, 1);
        let sub = bus.subscribe(EventScope::All, None).unwrap();
        idle(&mut bus, 1);
        assert!(bus.has_pending(sub.id));
        assert!(bus.unsubscribe(sub.id));
        assert!(!bus.unsubscribe(sub.id));
        let published = publish(&mut bus, 1, EventData::SessionIdle).unwrap();
        assert_eq!(published.delivered_to, Vec::<SubscriptionId>::new());
        assert!(bus.take(sub.id, 10).is_none());
        assert!(!bus.has_pending(sub.id));
    }

    #[test]
    fn take_respects_max_and_keeps_order() {
        let mut bus = EventBus::default();
        start(&mut bus, 1);
        let sub = bus.subscribe(EventScope::Session(sid(1)), Some(0)).unwrap();
        for _ in 0..4 {
            idle(&mut bus, 1);
        }
        assert_eq!(seqs(&bus.take(sub.id, 2).unwrap()), vec![1, 2]);
        assert_eq!(seqs(&bus.take(sub.id, 2).unwrap()), vec![3, 4]);
        assert_eq!(seqs(&bus.take(sub.id, 2).unwrap()), vec![5]);
    }

    #[test]
    fn payload_names_follow_the_catalog() {
        let path = CanonicalPath::new("/tmp").unwrap();
        let at = Timestamp::from_unix_micros(0).unwrap();
        let names: Vec<_> = [
            EventData::SessionEnded,
            EventData::SessionStateChanged {
                from: SessionState::Active,
                to: SessionState::Paused,
            },
            EventData::SessionIdle,
            EventData::CommandFinished {
                record_id: RecordId::from_ulid(Ulid::from_u128(1)),
                command: Redacted::new("ls".to_owned()),
                cwd: path.clone(),
                started_at: at,
                ended_at: at,
                exit_code: Some(0),
            },
            EventData::CwdChanged { cwd: path },
        ]
        .iter()
        .map(EventData::name)
        .collect();
        assert_eq!(
            names,
            [
                "session.ended",
                "session.state_changed",
                "session.idle",
                "command.finished",
                "cwd.changed"
            ]
        );
    }
}
