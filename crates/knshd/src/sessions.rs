//! The live session registry and human telemetry: `session.start_human`, `telemetry.command`, `telemetry.cwd`,
//! `telemetry.idle` and `session.info` (`specs/06-api/user-socket.md#human-sessions`, KNSH-021).
//!
//! # Human sessions
//!
//! `knsh` hosting a recorded shell connects to `user.sock` and calls `session.start_human`. The session (actor
//! `human`, recording on, never an envelope) is bound to that connection ([`SessionBinding`]): the telemetry calls
//! on the same connection report its command lines, and it ends (`session.state_changed` to `ended`, then
//! `session.ended`) when the connection closes, however `knsh` went away. No call names a session, so one
//! connection can never write into another's session.
//!
//! - `telemetry.command`: one finished command line. The record keeps only `command`, `cwd`, `started_at`,
//!   `ended_at` and `exit_code` (FR-REC-09; the store drops anything else for a human actor too), is committed, and
//!   only then is `command.finished` published.
//! - `telemetry.cwd`: `cwd.changed`.
//! - `telemetry.idle`: `session.idle`, at most once between two commands (FR-SES-24). `knsh` already sends it only
//!   once; the daemon checks again, so a confused client cannot flood subscribers.
//! - `session.info`: the bound session's actor, profile, state and recording settings (FR-SES-25, NFR-PRIV-05). On
//!   `agent.sock` it is the agent session the connection was bound to at `hello`.
//!
//! The other methods exist on `user.sock` only (the catalogue keeps them off `agent.sock`, and each handler checks
//! the endpoint again): nothing inside an envelope may create a session (FR-SES-02) or write records as a human.
//!
//! # Agent sessions
//!
//! An agent session is opened with a session token and registers the root process of each of its envelopes
//! ([`Sessions::open_agent_in`], [`Sessions::register_envelope`]); both are kept in [`AgentAccess`]. An `agent.sock`
//! connection is bound to one of them at `hello` ([`Sessions::bind_agent`], KNSH-048), and unlike a human session it
//! does not end with the connection: it ends with its envelope ([`Sessions::end_agent`]), which revokes its token
//! and envelopes first, so nothing can bind to it, or keep acting through a binding, once it is ending.
//!
//! # Pause, resume and human control (KNSH-054)
//!
//! [`Sessions::change_state`] pauses, resumes, takes control of or hands back a session: the registry applies the
//! transition, [`Holds`] sends the signals it calls for to the session's kept process groups (FR-SES-10), the
//! session's row is rewritten and `session.state_changed` is published (FR-SES-14). A transition the state diagram
//! does not have, or one on a session that is not live, is `-32006` and changes nothing. While a session is paused or
//! under human control, [`Sessions::runnable`] answers `-32007` with `data.state` for each new line (FR-SES-10,
//! FR-SES-12); the client retries (`specs/03-functional-requirements/sessions.md`, "Holding a line"). The authority
//! calls these through the control service's `session.*` methods (`crate::supervise`, KNSH-071), which also end agent
//! sessions ([`Sessions::end_for_authority`]), create ones with no envelope ([`Sessions::create_agent`]) and change
//! their recording ([`Sessions::set_recording`]).
//!
//! # Paused by expired pushed policy (KNSH-072)
//!
//! When pushed policy expires, `crate::expiry` pauses each active agent session using it
//! ([`Sessions::pause_for_expiry`]) and the registry remembers why. Such a session leaves `paused` only through
//! [`Sessions::release_from_expiry`]: when the authority pushes a snapshot it loads again, or when the user selects a
//! signed local profile for it with `knsh profile use` (FR-POL-51). `session.resume` is refused for it with `-32006`:
//! resuming it under policy that no longer loads would only deny its lines, and nothing else may move it to another
//! profile (FR-POL-52). The mark is dropped when the session ends.
//!
//! # Errors
//!
//! A telemetry call or `session.info` on a connection without a session is `-32003`; a second `session.start_human`
//! on the same connection is `-32602`. A store that is unavailable or fails is `-32603`: the reason never reaches the
//! answer. Events are best effort: a record that was written is answered even if its event could not be published.
//!
//! # Locks
//!
//! Lock order: a connection's [`SessionBinding`], then the registry, then the set of sessions paused by expired
//! policy, then [`AgentAccess`] or [`Holds`] (never both), then the event hub's own lock. The registry lock is never
//! held while waiting for the record store, and the agent table is never held while reading the process table.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError};
use std::time::Duration;

use knsh_checkpoint::{LineProcesses, RootReadiness};
use knsh_core::{
    Actor, ActorKind, CanonicalPath, CoreError, EventData, ExecutionRecord, Profile, ProfileName, ProfileOrder,
    RecordDetails, RecordId, Redacted, SessionId, SessionRegistry, SessionSpec, SessionState, Timestamp, Transition,
    Ulid, UnprotectedReason,
};
use knsh_json::{Object, Value};
use knsh_platform::{
    AuditToken, Authenticated, Clock, ProcessGroupId, ProcessIdentity, ProcessTree, Processes, Random,
};
use knsh_proto::{
    CheckpointBackend, ErrorCode, RpcError, SessionInfoResult, SessionStartHumanParams, SessionStartHumanResult,
    TelemetryCommandParams, TelemetryCommandResult, TelemetryCwdParams, TelemetryIdleParams,
};
use knsh_store::RecordStore;

use crate::agents::{AgentAccess, Grant, SessionToken, invalid_session_token};
use crate::dispatch::{Answer, Call, Endpoint, Handler, Handlers, Reply, answer, params};
use crate::events::EventHub;
use crate::holds::{GroupKind, Holds, Kept};
use crate::lifetime::Activity;
use crate::shadows::{CheckpointLine, ClosedLine, Shadows};

/// The profile recorded for human sessions. Nothing in a human session is enforced (FR-SES-22); profiles are loaded
/// from files in phase 2 (KNSH-039), and until then every session runs under this name.
const HUMAN_PROFILE: &str = "default";

/// Takes a lock even if another thread panicked while holding it: every critical section below leaves its data
/// consistent at each step.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// `session` as `session.info` shows it. Its output recording is what `recording.set` set, otherwise `false`.
///
/// Human sessions never record output (FR-REC-09). Without a setting, an agent session records its lines' output
/// when its profile sets `recording.output` (KNSH-053); reporting that here needs the profile, which the registry does
/// not load, so it reads false (pending: wire the profile loader into `session.info`).
fn session_info(session: knsh_core::Session) -> SessionInfoResult {
    SessionInfoResult {
        output_recording: session.output_recording().unwrap_or(false),
        session,
    }
}

/// The engine's live sessions and the human telemetry handlers. One per `knshd`, shared by every connection.
pub(crate) struct Sessions {
    registry: Mutex<SessionRegistry>,
    /// Absent when the record store could not be opened: recorded sessions are then refused (`-32603`).
    store: Option<RecordStore>,
    events: Arc<EventHub>,
    clock: Arc<dyn Clock>,
    random: Arc<dyn Random>,
    /// Live agent sessions' tokens and envelopes (KNSH-048).
    agents: AgentAccess,
    /// Agent sessions' kept process groups, stopped while paused (KNSH-054).
    holds: Holds,
    /// Agent sessions paused because their pushed policy expired (module documentation, KNSH-072).
    expiry_paused: Mutex<BTreeSet<SessionId>>,
    /// Agent sessions' checkpoint shadows (KNSH-079), attached once at start-up; absent in tests that need none.
    shadows: OnceLock<Arc<Shadows>>,
}

/// A state change asked of a live session (KNSH-054): the edges of the state diagram other than ending, which has its
/// own path ([`Sessions::end_agent`]) because it also revokes the session's token and envelopes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StateChange {
    /// `active → paused` (FR-SES-10).
    Pause,
    /// `paused → active` (FR-SES-10).
    Resume,
    /// `active → human_control` (FR-SES-12).
    TakeControl,
    /// `human_control → active` (FR-SES-12).
    HandBack,
}

impl StateChange {
    /// The registry's transition for this change.
    const fn transition(self) -> Transition {
        match self {
            Self::Pause => Transition::Pause,
            Self::Resume => Transition::Resume,
            Self::TakeControl => Transition::TakeControl,
            Self::HandBack => Transition::HandBack,
        }
    }
}

/// Who asked for a state change, which decides how a session paused by expired pushed policy is treated (module
/// documentation, "Paused by expired pushed policy").
enum Cause {
    /// The authority or the user, through `session.*`: a session paused by expiry is not resumed this way.
    Request,
    /// A pushed policy the session uses expired: the session is marked.
    Expiry,
    /// The session's policy loads again (`None`), or the user selected a local profile for it (`Some`).
    Released(Option<ProfileName>),
}

/// The session bound to one connection, if any, and who is at its other end. Created by the connection, released
/// when it closes.
#[derive(Default)]
pub(crate) struct SessionBinding {
    bound: Mutex<Option<Bound>>,
    /// The peer's audit token, read when the connection was accepted (`None` if the kernel could not report it).
    /// On `agent.sock` it is how a caller without a session token is matched to its envelope (FR-AGT-23); on
    /// `user.sock`, how `session.start_agent` finds the session a nested `knsh agent` runs inside (FR-SES-03).
    peer: Option<AuditToken>,
}

/// A connection's session.
enum Bound {
    /// A human session the connection started; it ends with the connection.
    Human {
        session_id: SessionId,
        /// Whether `session.idle` was already published since the last command (FR-SES-24).
        idle_reported: bool,
        /// Ends the session when the connection closes.
        owner: Arc<Sessions>,
    },
    /// The agent session an `agent.sock` connection was bound to at `hello`. It outlives the connection.
    Agent(Arc<Grant>),
}

impl SessionBinding {
    /// A binding with no session and no known peer.
    #[cfg(test)]
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// A binding with no session yet, for a connection whose peer has audit token `peer` (`None` if the kernel
    /// could not report it: the peer can then only bind with a session token).
    pub(crate) fn for_peer(peer: Option<AuditToken>) -> Self {
        Self {
            bound: Mutex::new(None),
            peer,
        }
    }

    /// The peer's audit token, if the kernel reported one: how `session.start_agent` finds the envelope a caller
    /// runs in (FR-SES-03).
    pub(crate) fn peer(&self) -> Option<AuditToken> {
        self.peer
    }

    /// Ends the bound human session, if any: the connection closed. Called once, after the last call of the
    /// connection. An agent session is only unbound: it lives as long as its envelope, not its connections.
    pub(crate) fn release(&self) {
        let bound = lock(&self.bound).take();
        match bound {
            Some(Bound::Human { session_id, owner, .. }) => owner.end(session_id),
            Some(Bound::Agent(_)) | None => {}
        }
    }

    /// The bound human session, for a telemetry call.
    pub(crate) fn session_id(&self) -> Result<SessionId, RpcError> {
        match lock(&self.bound).as_ref() {
            Some(Bound::Human { session_id, .. }) => Ok(*session_id),
            Some(Bound::Agent(_)) | None => Err(RpcError::new(ErrorCode::NotAllowed)),
        }
    }

    /// The agent session this `agent.sock` connection acts for: every agent call is evaluated against it alone
    /// (KNSH-048).
    ///
    /// # Errors
    ///
    /// `-32009` if the session has ended since the connection was bound; `-32003` if the connection has no agent
    /// session (never the case after a successful `hello` on `agent.sock`; refused rather than widened).
    pub(crate) fn agent_session(&self) -> Result<SessionId, RpcError> {
        match lock(&self.bound).as_ref() {
            Some(Bound::Agent(grant)) => grant.session_id(),
            Some(Bound::Human { .. }) | None => Err(RpcError::new(ErrorCode::NotAllowed)),
        }
    }
}

/// An agent session just opened, with the token its envelope's environment will carry (`session.start_agent`,
/// KNSH-056).
pub(crate) struct OpenedAgent {
    /// The new session.
    pub(crate) session_id: SessionId,
    /// Its token. Never logged or stored; only written into the envelope's environment.
    pub(crate) token: SessionToken,
}

impl Drop for SessionBinding {
    /// A connection that ends without reaching [`SessionBinding::release`] (its thread unwound) still ends its
    /// session: a session left in the registry would never end and would keep `knshd` alive forever.
    fn drop(&mut self) {
        self.release();
    }
}

impl Sessions {
    /// The registry, empty, writing to `store` and publishing to `events`; IDs come from `clock` and `random`.
    pub(crate) fn new(
        store: Option<RecordStore>,
        events: Arc<EventHub>,
        clock: Arc<dyn Clock>,
        random: Arc<dyn Random>,
        processes: Arc<dyn ProcessTree>,
    ) -> Arc<Self> {
        Arc::new(Self {
            registry: Mutex::new(SessionRegistry::new()),
            store,
            events,
            clock,
            random,
            agents: AgentAccess::new(processes),
            holds: Holds::new(),
            expiry_paused: Mutex::new(BTreeSet::new()),
            shadows: OnceLock::new(),
        })
    }

    /// Attaches the checkpoint shadows (KNSH-079): from now on every agent session that ends, however it ends, has
    /// its shadow builds stopped. Only the first call has an effect.
    pub(crate) fn attach_shadows(&self, shadows: Arc<Shadows>) {
        let _ = self.shadows.set(shadows);
    }

    /// How far the shadow of `root` is for `session_id` (FR-CKP-02). Without attached shadows no root has one.
    pub(crate) fn shadow_readiness(&self, session_id: SessionId, root: &CanonicalPath) -> RootReadiness {
        match self.shadows.get() {
            Some(shadows) => shadows.readiness(session_id, root),
            None => RootReadiness::Unavailable(UnprotectedReason::NoShadow),
        }
    }

    /// Waits at most `slice` for the shadow of `root` to settle, and returns its readiness then.
    pub(crate) fn wait_for_shadow(
        &self,
        session_id: SessionId,
        root: &CanonicalPath,
        slice: Duration,
    ) -> RootReadiness {
        match self.shadows.get() {
            Some(shadows) => shadows.wait(session_id, root, slice),
            None => RootReadiness::Unavailable(UnprotectedReason::NoShadow),
        }
    }

    /// Line `record_id` of `session_id` touching the protected `roots` starts (KNSH-080, KNSH-081): marks its start
    /// in each root's watcher and in the attribution ledger. Never waits. Nothing without attached shadows.
    pub(crate) fn open_checkpoint_lines(
        &self,
        session_id: SessionId,
        record_id: RecordId,
        roots: &[CanonicalPath],
    ) -> CheckpointLine {
        match self.shadows.get() {
            Some(shadows) => shadows.open_lines(session_id, record_id, roots),
            None => CheckpointLine::unprotected(record_id),
        }
    }

    /// The line of `line` has been reaped: the line-end flush of each root (decision 16), the files `processes` still
    /// hold for writing (FR-CKP-24, KNSH-085), then its attribution. Returns the roots whose checkpoints are
    /// uncertain, and why (FR-CKP-04), and the record's `attribution` (FR-CKP-05, FR-CKP-07).
    pub(crate) fn close_checkpoint_lines(line: CheckpointLine, processes: &LineProcesses) -> ClosedLine {
        crate::shadows::close_lines(line, processes)
    }

    /// The processes a line of `session_id` that ran as `group` may have left writing: the group's members and the
    /// session's envelopes (FR-CKP-24, KNSH-085).
    pub(crate) fn line_processes(&self, session_id: SessionId, group: Option<ProcessGroupId>) -> LineProcesses {
        LineProcesses {
            group: group.map(ProcessGroupId::as_raw),
            envelopes: self.agents.envelopes(session_id),
        }
    }

    /// `hello`'s `checkpoints` (KNSH-079): each root of a running agent session once its shadow settled. Empty
    /// without attached shadows.
    pub(crate) fn checkpoint_report(&self) -> BTreeMap<String, CheckpointBackend> {
        self.shadows
            .get()
            .map(|shadows| shadows.capability_report())
            .unwrap_or_default()
    }

    /// Starts the checkpoint shadows of the agent session `session_id`, which runs `profile` (FR-CKP-01). Returns at
    /// once: the builds run in the background. Nothing happens without attached shadows.
    pub(crate) fn start_shadows(&self, session_id: SessionId, profile: &Profile) {
        if let Some(shadows) = self.shadows.get() {
            // KNSH-081: changes between the lines of a session in an envelope are its agent edits. A session that
            // already ended has no envelope to speak of; its builds are stopped just below.
            let envelope = lock(&self.registry)
                .get(session_id)
                .is_ok_and(knsh_core::Session::envelope);
            shadows.start(session_id, profile, envelope);
            // The session may have ended between opening and here, and `end` then found no builds to stop. Checked
            // after the builds are in the table: an end that comes later stops them itself, one that came earlier is
            // seen now, so a build never outlives its session (KNSH-079).
            if lock(&self.registry).get(session_id).is_err() {
                shadows.end(session_id);
            }
        }
    }

    /// Every session handler, by method name.
    pub(crate) fn handlers(self: &Arc<Self>) -> Handlers {
        [
            ("session.start_human", self.handler(Self::start_human)),
            (
                "telemetry.command",
                self.handler(|sessions, call| sessions.command(call)),
            ),
            ("telemetry.cwd", self.handler(|sessions, call| sessions.cwd(call))),
            ("telemetry.idle", self.handler(|sessions, call| sessions.idle(call))),
            ("session.info", self.handler(|sessions, call| sessions.info(call))),
        ]
        .into_iter()
        .collect()
    }

    /// A handler running `method` on its own reference to the registry, so that it outlives the caller's.
    fn handler(self: &Arc<Self>, method: impl Fn(&Arc<Self>, &Call<'_>) -> Reply + Send + Sync + 'static) -> Handler {
        let sessions = Arc::clone(self);
        Arc::new(move |call: &Call<'_>| method(&sessions, call))
    }

    /// The number of live sessions.
    #[cfg(test)]
    pub(crate) fn live(&self) -> usize {
        lock(&self.registry).len()
    }

    /// `session.start_human`: creates a recorded human session, writes its row, publishes `session.started` and binds
    /// it to the calling connection.
    fn start_human(self: &Arc<Self>, call: &Call<'_>) -> Reply {
        user_only(call.endpoint)?;
        let SessionStartHumanParams = params(call)?;
        let store = self.store()?;
        let mut binding = lock(&call.binding.bound);
        if binding.is_some() {
            // One session per connection: a second one would make "the caller's session" ambiguous.
            return Err(RpcError::new(ErrorCode::InvalidParams));
        }
        let now = self.clock.now().map_err(|_| internal_error())?;
        let session_id = SessionId::from_ulid(self.ulid(now)?);
        let profile = ProfileName::new(HUMAN_PROFILE).map_err(|_| internal_error())?;
        let session = lock(&self.registry)
            .create(SessionSpec {
                session_id,
                actor: Actor::Human,
                profile,
                envelope: false,
                recording: Some(true),
                parent_session_id: None,
            })
            .cloned()
            .map_err(|_| internal_error())?;
        if store.write_session(&session, now).is_err() {
            // Without its row, its records could not be written either: undo, silently (nothing was published).
            let _ = lock(&self.registry).transition(session_id, Transition::End);
            return Err(internal_error());
        }
        // Best effort: a session whose start could not be published still records (see the module docs).
        let _ = self.events.session_started(&session);
        *binding = Some(Bound::Human {
            session_id,
            idle_reported: false,
            owner: Arc::clone(self),
        });
        answer(&SessionStartHumanResult {
            session_id,
            recording: session.recording(),
        })
    }

    /// `telemetry.command`: writes the record of one finished command line, then publishes `command.finished`.
    fn command(&self, call: &Call<'_>) -> Reply {
        user_only(call.endpoint)?;
        let TelemetryCommandParams {
            command,
            cwd,
            started_at,
            ended_at,
            exit_code,
        } = params(call)?;
        let session_id = call.binding.session_id()?;
        let store = self.store()?;
        let now = self.clock.now().map_err(|_| internal_error())?;
        // Records sort by ID in creation order, so the ID is made from now, not from when the line started.
        let record_id = RecordId::from_ulid(self.ulid(now)?);
        let command = Redacted::new(command);
        let record = ExecutionRecord {
            record_id,
            session_id,
            actor: Actor::Human,
            command: command.clone(),
            cwd: cwd.clone(),
            started_at,
            ended_at: Some(ended_at),
            exit_code: Some(i32::from(exit_code)),
            // FR-REC-09: a human record has none of the agent fields.
            details: RecordDetails::default(),
        };
        // The event follows the commit: a subscriber never hears of a record that was not stored.
        store
            .write_record(record, knsh_store::RecordedOutput::default())
            .map_err(|_| internal_error())?;
        let _ = self.events.publish(
            session_id,
            &Actor::Human,
            EventData::CommandFinished {
                record_id,
                command,
                cwd,
                started_at,
                ended_at,
                exit_code: Some(i32::from(exit_code)),
            },
        );
        // A new command: the next idle prompt is reported again (FR-SES-24).
        if let Some(Bound::Human { idle_reported, .. }) = lock(&call.binding.bound).as_mut() {
            *idle_reported = false;
        }
        answer(&TelemetryCommandResult { record_id })
    }

    /// `telemetry.cwd`: publishes `cwd.changed`.
    fn cwd(&self, call: &Call<'_>) -> Reply {
        user_only(call.endpoint)?;
        let TelemetryCwdParams { cwd } = params(call)?;
        let session_id = call.binding.session_id()?;
        let _ = self
            .events
            .publish(session_id, &Actor::Human, EventData::CwdChanged { cwd });
        Ok(Answer::from(Value::Object(Object::new())))
    }

    /// `telemetry.idle`: publishes `session.idle` unless it was already published since the last command. Answers
    /// whether it was.
    fn idle(&self, call: &Call<'_>) -> Reply {
        user_only(call.endpoint)?;
        let TelemetryIdleParams = params(call)?;
        let mut binding = lock(&call.binding.bound);
        let Some(Bound::Human {
            session_id,
            idle_reported,
            ..
        }) = binding.as_mut()
        else {
            return Err(RpcError::new(ErrorCode::NotAllowed));
        };
        let emitted = !*idle_reported;
        if emitted {
            *idle_reported = true;
            let _ = self.events.publish(*session_id, &Actor::Human, EventData::SessionIdle);
        }
        let result = Object::new().with("emitted", emitted).map_err(|_| internal_error())?;
        Ok(Answer::from(Value::Object(result)))
    }

    /// `session.info`: the caller's own session: the human session the connection started on `user.sock`, the
    /// agent session it was bound to on `agent.sock`.
    fn info(&self, call: &Call<'_>) -> Reply {
        let session_id = match call.endpoint {
            Endpoint::User => call.binding.session_id()?,
            Endpoint::Agent => call.binding.agent_session()?,
            // The authority has no session of its own; the catalogue does not list this method there.
            Endpoint::Control => return Err(RpcError::new(ErrorCode::NotAllowed)),
        };
        let session = lock(&self.registry)
            .get(session_id)
            .cloned()
            .map_err(|_| match call.endpoint {
                // A human session ends only when its connection closes, after its last call; kept for safety.
                // (The control service never gets here: it was refused above.)
                Endpoint::User | Endpoint::Control => session_gone(session_id),
                // An agent session ended between the binding check and this read: the binding is expired.
                Endpoint::Agent => invalid_session_token(),
            })?;
        answer(&session_info(session))
    }

    /// Opens a top-level agent session running `profile` for `actor` ([`Sessions::open_agent_in`] with no parent).
    ///
    /// # Errors
    ///
    /// As [`Sessions::open_agent_in`].
    #[cfg(test)]
    pub(crate) fn open_agent(&self, actor: Actor, profile: ProfileName) -> Result<OpenedAgent, RpcError> {
        self.open_agent_in(actor, profile, None, &knsh_core::EqualProfileOnly)
    }

    /// Opens an agent session running `profile` for `actor`, with its envelope flag set, and issues its session
    /// token: writes its row, publishes `session.started`, and returns the token for the envelope's environment.
    /// The caller (`session.start_agent`, KNSH-056, on `user.sock` only) then registers the envelope's root
    /// process with [`Sessions::register_envelope_leader`].
    ///
    /// A session started from inside another one records it as `parent` (FR-SES-03); `order` decides whether
    /// `profile` is equal to or stricter than the parent's. The registry checks this under its lock, against the
    /// parent as it is then, so a parent that ended in the meantime is refused rather than recorded.
    ///
    /// # Errors
    ///
    /// Nothing is left behind on any of these.
    ///
    /// - `-32006` naming `parent` if it is no longer a live session.
    /// - `-32003` if `profile` is looser than the parent's, or the parent cannot have an agent child.
    /// - `-32603` if the registry, the store, the clock or the random source fails.
    pub(crate) fn open_agent_in(
        &self,
        actor: Actor,
        profile: ProfileName,
        parent: Option<SessionId>,
        order: &dyn ProfileOrder,
    ) -> Result<OpenedAgent, RpcError> {
        self.open_agent_session(actor, profile, parent, order, true)
    }

    /// Opens an agent session with no envelope for an agent the authority starts itself (`session.create`, KNSH-071,
    /// FR-SES-02): the agent binds to it on `agent.sock` with the returned token. Top level, so no parent.
    ///
    /// # Errors
    ///
    /// As [`Sessions::open_agent_in`].
    pub(crate) fn create_agent(&self, actor: Actor, profile: ProfileName) -> Result<OpenedAgent, RpcError> {
        self.open_agent_session(actor, profile, None, &knsh_core::EqualProfileOnly, false)
    }

    /// [`Sessions::open_agent_in`], with or without an envelope.
    fn open_agent_session(
        &self,
        actor: Actor,
        profile: ProfileName,
        parent: Option<SessionId>,
        order: &dyn ProfileOrder,
        envelope: bool,
    ) -> Result<OpenedAgent, RpcError> {
        let now = self.clock.now().map_err(|_| internal_error())?;
        let session_id = SessionId::from_ulid(self.ulid(now)?);
        let spec = SessionSpec {
            session_id,
            actor,
            profile,
            envelope,
            recording: None,
            parent_session_id: parent,
        };
        let session = lock(&self.registry)
            .create_with(spec, order)
            .cloned()
            .map_err(|error| match (error, parent) {
                (CoreError::ParentNotFoundOrEnded, Some(parent)) => session_gone(parent),
                // FR-SES-03: a looser profile than the parent's is not this caller's to choose.
                (CoreError::ProfileNotStricter | CoreError::HumanChildOfAgent, _) => {
                    RpcError::new(ErrorCode::NotAllowed)
                }
                _ => internal_error(),
            })?;
        let undo = || {
            let _ = lock(&self.registry).transition(session_id, Transition::End);
        };
        // A recorded session needs its row before any of its records; an unrecorded one may run without a store.
        let written = match (&self.store, session.recording()) {
            (Some(store), _) => store.write_session(&session, now).is_ok(),
            (None, recording) => !recording,
        };
        if !written {
            undo();
            return Err(internal_error());
        }
        let Ok(token) = self.agents.issue(session_id, self.random.as_ref()) else {
            undo();
            return Err(internal_error());
        };
        let _ = self.events.session_started(&session);
        Ok(OpenedAgent { session_id, token })
    }

    /// The live agent session a caller runs inside, if any: the one whose token is `token` (taken from the caller's
    /// environment), else the one whose envelope the `peer` descends from (FR-SES-03). The same matching as
    /// [`Sessions::bind_agent`], without binding anything.
    pub(crate) fn enclosing(&self, token: Option<&Redacted<String>>, peer: Option<AuditToken>) -> Option<SessionId> {
        self.agents.bind(token, peer).ok()?.session_id().ok()
    }

    /// Registers the envelope whose leader is the unreaped child `pid` as one of `session_id`'s
    /// ([`Sessions::register_envelope`]). The caller holds the child unreaped, so `pid` still names it.
    ///
    /// # Errors
    ///
    /// `-32006` if the session is not live or the process cannot be read.
    pub(crate) fn register_envelope_leader(&self, session_id: SessionId, pid: i32) -> Result<(), RpcError> {
        let root = self.agents.identity(pid).ok_or_else(|| session_gone(session_id))?;
        self.register_envelope(session_id, root)
    }

    /// Registers `root`, the first process of an envelope of the agent session `session_id`: callers without a
    /// token that descend from it are bound to the session (FR-AGT-23), even after `root` execs. The supervisor
    /// reads `root` while it holds the unreaped child, so its pid cannot have been reused.
    ///
    /// # Errors
    ///
    /// `-32006` if `session_id` is not a live agent session, or if `root` is no longer the live process at that pid
    /// version (nothing is registered then).
    pub(crate) fn register_envelope(&self, session_id: SessionId, root: ProcessIdentity) -> Result<(), RpcError> {
        if self.agents.register_envelope(session_id, root) {
            Ok(())
        } else {
            Err(session_gone(session_id))
        }
    }

    /// Ends the agent session `session_id`: its envelope is gone. Its token and envelopes are revoked before
    /// anything else, then it ends as every session does.
    pub(crate) fn end_agent(&self, session_id: SessionId) {
        self.end(session_id);
    }

    /// Binds an `agent.sock` connection to its agent session at `hello`: by `token` if it is live, else by the
    /// peer's audit token (FR-AGT-23). A connection is bound once; a repeated `hello` must name the same session.
    ///
    /// # Errors
    ///
    /// `-32009` if no live session matches, or if a repeated `hello` would move the connection to another session.
    pub(crate) fn bind_agent(
        &self,
        binding: &SessionBinding,
        token: Option<&Redacted<String>>,
    ) -> Result<SessionId, RpcError> {
        let grant = self.agents.bind(token, binding.peer)?;
        let session_id = grant.session_id()?;
        let mut bound = lock(&binding.bound);
        match bound.as_ref() {
            None => *bound = Some(Bound::Agent(grant)),
            Some(Bound::Agent(existing)) if Arc::ptr_eq(existing, &grant) => {}
            // Another session, or a human one (never on agent.sock): one connection acts for one session only.
            Some(Bound::Agent(_) | Bound::Human { .. }) => return Err(invalid_session_token()),
        }
        Ok(session_id)
    }

    /// The profile of the live session `session_id`, for `policy.check` (KNSH-043). Reads the registry only.
    ///
    /// # Errors
    ///
    /// `-32006` naming the session if it is not live (never started, or ended).
    pub(crate) fn profile_of(&self, session_id: SessionId) -> Result<ProfileName, RpcError> {
        lock(&self.registry)
            .get(session_id)
            .map(|session| session.profile().clone())
            .map_err(|_| session_gone(session_id))
    }

    /// The actor and profile of the live agent session `session_id`, for the supervisor (KNSH-050). Reads the
    /// registry only.
    ///
    /// # Errors
    ///
    /// `-32006` naming the session if it is not live.
    pub(crate) fn agent_of(&self, session_id: SessionId) -> Result<(Actor, ProfileName), RpcError> {
        lock(&self.registry)
            .get(session_id)
            .map(|session| (session.actor().clone(), session.profile().clone()))
            .map_err(|_| session_gone(session_id))
    }

    /// The actor and profile of the live agent session `session_id` if it may start a new line now: the hold
    /// check of the supervisor (FR-SES-10, FR-SES-12). Reads the registry only.
    ///
    /// # Errors
    ///
    /// - `-32006` naming the session if it is not live.
    /// - `-32007` with `data.state` (`paused` or `human_control`) if the session holds its lines. Nothing about the
    ///   line is recorded: it was never proposed, and the client sends it again.
    pub(crate) fn runnable(&self, session_id: SessionId) -> Result<(Actor, ProfileName), RpcError> {
        let registry = lock(&self.registry);
        let session = registry.get(session_id).map_err(|_| session_gone(session_id))?;
        match session.state() {
            SessionState::Active => Ok((session.actor().clone(), session.profile().clone())),
            state @ (SessionState::Paused | SessionState::HumanControl) => Err(held(state)),
            // Never in the registry (it drops ended sessions); refused like an unknown session all the same.
            SessionState::Ended => Err(session_gone(session_id)),
        }
    }

    /// Pauses, resumes, takes control of or hands back the live session `session_id` (module documentation,
    /// "Pause, resume and human control"). Returns the new state.
    ///
    /// The signals are sent while the registry is still locked, so a line kept by [`Sessions::keep_group`] is either
    /// kept before the move (and signalled by it) or after it (and stopped at once if the session is now paused).
    ///
    /// # Errors
    ///
    /// `-32006` naming the session if it is not live, or if the state diagram has no such edge from its state
    /// (pausing a paused session, resuming an active one, taking control of a paused one…), or when resuming a
    /// session paused by expired pushed policy (module documentation, KNSH-072): the state is unchanged and no event
    /// is published.
    pub(crate) fn change_state(&self, session_id: SessionId, change: StateChange) -> Result<SessionState, RpcError> {
        self.move_session(session_id, change, Cause::Request)
    }

    /// Pauses the live, active agent session `session_id` because the pushed policy it uses expired (FR-POL-51,
    /// FR-SES-13), and remembers why: it then resumes only through [`Sessions::release_from_expiry`].
    ///
    /// # Errors
    ///
    /// `-32006` naming the session if it is not live or not active (paused, under human control); `-32003` for a
    /// human session, which is never paused (FR-SES-22). Nothing changes then.
    pub(crate) fn pause_for_expiry(&self, session_id: SessionId) -> Result<(), RpcError> {
        self.move_session(session_id, StateChange::Pause, Cause::Expiry)
            .map(drop)
    }

    /// Resumes the session `session_id` that [`Sessions::pause_for_expiry`] paused, under its own profile: the
    /// authority pushed a snapshot it loads with again (FR-POL-51).
    ///
    /// # Errors
    ///
    /// `-32006` naming the session if it is not live or was not paused by expired policy (already released, or
    /// paused by the authority); nothing changes then.
    pub(crate) fn release_from_expiry(&self, session_id: SessionId) -> Result<(), RpcError> {
        self.move_session(session_id, StateChange::Resume, Cause::Released(None))
            .map(drop)
    }

    /// Runs the session `session_id` that [`Sessions::pause_for_expiry`] paused under the local `profile` and resumes
    /// it: the user selected it with `knsh profile use` and passed the prompt, which `_proof` stands for (FR-POL-51).
    /// The two moves happen under one lock, so no line runs between them. This is the only way a session's profile
    /// changes (FR-POL-52).
    ///
    /// # Errors
    ///
    /// As [`Sessions::release_from_expiry`]; nothing changes then.
    pub(crate) fn select_profile_after_expiry(
        &self,
        session_id: SessionId,
        profile: ProfileName,
        _proof: &Authenticated,
    ) -> Result<(), RpcError> {
        self.move_session(session_id, StateChange::Resume, Cause::Released(Some(profile)))
            .map(drop)
    }

    /// The live agent sessions that are `active`, with their profiles, in ID (start) order: those a pushed policy's
    /// expiry may pause.
    pub(crate) fn active_agents(&self) -> Vec<(SessionId, ProfileName)> {
        lock(&self.registry)
            .iter()
            .filter(|session| session.actor().kind() == ActorKind::Agent && session.state() == SessionState::Active)
            .map(|session| (session.session_id(), session.profile().clone()))
            .collect()
    }

    /// The live sessions paused by expired pushed policy, with their profiles, in ID (start) order.
    pub(crate) fn expiry_paused(&self) -> Vec<(SessionId, ProfileName)> {
        let registry = lock(&self.registry);
        let paused = lock(&self.expiry_paused);
        paused
            .iter()
            .filter_map(|session_id| registry.get(*session_id).ok())
            .map(|session| (session.session_id(), session.profile().clone()))
            .collect()
    }

    /// One state change of a live session, for `cause` (see [`Cause`]): the transition, its signals, the mark of a
    /// session paused by expired policy, the row and `session.state_changed`.
    fn move_session(&self, session_id: SessionId, change: StateChange, cause: Cause) -> Result<SessionState, RpcError> {
        let (session, change) = {
            let mut registry = lock(&self.registry);
            let mut expiry_paused = lock(&self.expiry_paused);
            let marked = expiry_paused.contains(&session_id);
            // Every refusal is decided before anything moves, so a refused change leaves the session, its mark and its
            // process groups as they were.
            match &cause {
                // FR-POL-52: resuming a session paused by expiry would only run its lines under policy that no longer
                // loads, so `session.resume` is refused; only a new snapshot or `knsh profile use` releases it.
                Cause::Request if marked && change == StateChange::Resume => return Err(session_gone(session_id)),
                // FR-SES-22: a human session is never paused, so expiry refuses it outright rather than pausing it. An
                // unknown or ended session is `-32006`, as the transition would answer.
                Cause::Expiry => {
                    let session = registry.get(session_id).map_err(|_| session_gone(session_id))?;
                    if session.actor().kind() == ActorKind::Human {
                        return Err(RpcError::new(ErrorCode::NotAllowed));
                    }
                }
                // A release undoes only the expiry's own pause: a session paused by the authority, or already released
                // by a snapshot or another selection, stays as it is.
                Cause::Released(_) if !marked => return Err(session_gone(session_id)),
                // Any other request, and a release of a marked session, meet the state diagram below as any change
                // does: pausing or taking control of a paused session has no edge there.
                Cause::Request | Cause::Released(_) => {}
            }
            // A session that is not live, or has no such edge from its state (an expiry pause of a session already
            // paused or under human control), is refused here, before its mark changes.
            let change = registry
                .transition(session_id, change.transition())
                .map_err(|_| session_gone(session_id))?;
            // The mark follows the transition under the same locks, so no caller sees a session paused by expiry
            // without its mark, or resumed with it.
            match cause {
                Cause::Request => {}
                Cause::Expiry => {
                    expiry_paused.insert(session_id);
                }
                Cause::Released(profile) => {
                    expiry_paused.remove(&session_id);
                    if let Some(profile) = profile {
                        // Never fails: only agent sessions are marked, and this one is live (it just resumed). The
                        // profile changes before the registry lock is released, so no line runs between the resume
                        // and the selection (FR-POL-51).
                        let _ = registry.select_profile(session_id, profile);
                    }
                }
            }
            self.holds.moved(session_id, change.from, change.to);
            let session = registry
                .get(session_id)
                .cloned()
                .map_err(|_| session_gone(session_id))?;
            (session, change)
        };
        // Best effort, like every event and like `end`: the move happened and holds lines whatever the store says.
        if let (Some(store), Ok(now)) = (&self.store, self.clock.now()) {
            let _ = store.write_session(&session, now);
        }
        let _ = self.events.state_changed(&change);
        Ok(change.to)
    }

    /// Keeps `group`, spawned by `processes`, as one of `session_id`'s process groups until the returned handle is
    /// dropped (FR-SES-10): a pause stops it, a resume continues it. A group kept while the session is paused is
    /// stopped at once. For a session that is no longer live the handle is detached and never signalled.
    ///
    /// Drop the handle before reaping the group's leader ([`Kept`]).
    pub(crate) fn keep_group(
        &self,
        session_id: SessionId,
        group: ProcessGroupId,
        processes: Arc<dyn Processes>,
        kind: GroupKind,
    ) -> Kept {
        let registry = lock(&self.registry);
        match registry.get(session_id) {
            Ok(session) => self.holds.keep(session_id, session.state(), group, processes, kind),
            Err(_) => Holds::detached(),
        }
    }

    /// Every live session, in ID (start) order, each as `session.info` shows it (`session.list`, KNSH-071).
    pub(crate) fn list(&self) -> Vec<SessionInfoResult> {
        lock(&self.registry)
            .iter()
            .map(|session| session_info(session.clone()))
            .collect()
    }

    /// The live session `session_id` as `session.info` shows it.
    ///
    /// # Errors
    ///
    /// `-32006` naming the session if it is not live.
    #[cfg(test)]
    pub(crate) fn info_of(&self, session_id: SessionId) -> Result<SessionInfoResult, RpcError> {
        let registry = lock(&self.registry);
        let session = registry.get(session_id).map_err(|_| session_gone(session_id))?;
        Ok(session_info(session.clone()))
    }

    /// The live agent session `session_id`, refusing a human one: the authority supervises agents, and nothing in a
    /// human session may be blocked or ended for the human (FR-SES-22).
    ///
    /// # Errors
    ///
    /// `-32006` naming the session if it is not live; `-32003` if it is a human session.
    pub(crate) fn agent_session(&self, session_id: SessionId) -> Result<(), RpcError> {
        let registry = lock(&self.registry);
        let session = registry.get(session_id).map_err(|_| session_gone(session_id))?;
        match session.actor() {
            Actor::Agent(_) => Ok(()),
            Actor::Human => Err(RpcError::new(ErrorCode::NotAllowed)),
        }
    }

    /// Changes what the live agent session `session_id` records (`recording.set`, KNSH-071) and rewrites its row;
    /// returns it as `session.info` now shows it. Output recording set here takes the place of the profile's
    /// `recording.output` for the session's next lines ([`Sessions::output_recording_of`]).
    ///
    /// # Errors
    ///
    /// `-32006` naming the session if it is not live; `-32003` for a human session, which is left unchanged.
    pub(crate) fn set_recording(
        &self,
        session_id: SessionId,
        commands: Option<bool>,
        output: Option<bool>,
    ) -> Result<SessionInfoResult, RpcError> {
        let session = lock(&self.registry)
            .set_recording(session_id, commands, output)
            .cloned()
            .map_err(|error| match error {
                CoreError::HumanRecording => RpcError::new(ErrorCode::NotAllowed),
                _ => session_gone(session_id),
            })?;
        // Best effort, like a state change: the setting applies from now whatever the store says.
        if let (Some(store), Ok(now)) = (&self.store, self.clock.now()) {
            let _ = store.write_session(&session, now);
        }
        Ok(session_info(session))
    }

    /// Output recording as `recording.set` set it for the live session `session_id`, or `None` when its profile
    /// decides (or the session is not live).
    pub(crate) fn output_recording_of(&self, session_id: SessionId) -> Option<bool> {
        lock(&self.registry)
            .get(session_id)
            .ok()
            .and_then(knsh_core::Session::output_recording)
    }

    /// Ends the live agent session `session_id` for the authority (`session.end`, KNSH-071): its envelopes' process
    /// groups get `SIGTERM`, so the agent CLI started by `knsh agent` exits, then the session ends as every session
    /// does (its token and envelopes are revoked first, so no line can start for it).
    ///
    /// # Errors
    ///
    /// `-32006` naming the session if it is not live; `-32003` for a human session, which ends only with its own
    /// connection.
    pub(crate) fn end_for_authority(&self, session_id: SessionId) -> Result<(), RpcError> {
        self.agent_session(session_id)?;
        self.holds.terminate_envelopes(session_id);
        self.end(session_id);
        Ok(())
    }

    /// Ends `session_id`: its connection closed. Writes the ended state and publishes `session.state_changed` to
    /// `ended`, then `session.ended`.
    fn end(&self, session_id: SessionId) {
        // First, so that nothing binds to the session, or acts through an existing binding, while it ends.
        self.agents.revoke(session_id);
        let (session, change) = {
            let mut registry = lock(&self.registry);
            // Already gone (never expected: each binding ends its session once): nothing to write or publish.
            let Ok(mut session) = registry.get(session_id).cloned() else {
                return;
            };
            let Ok(change) = registry.transition(session_id, Transition::End) else {
                return;
            };
            // An ended session is no longer paused by anything.
            lock(&self.expiry_paused).remove(&session_id);
            // A session ending while paused continues its kept groups: nothing it started may stay stopped.
            self.holds.moved(session_id, change.from, change.to);
            // The registry dropped the session; the copy follows it to `ended` for the store row.
            let _ = session.apply(Transition::End);
            (session, change)
        };
        // Best effort, like every event: the connection is already closed, so there is no one to report a failure to.
        if let (Some(store), Ok(now)) = (&self.store, self.clock.now()) {
            let _ = store.write_session(&session, now);
        }
        let _ = self.events.state_changed(&change);
        // Outside every lock: the shadow table is a leaf, and its builds are only told to stop.
        if let Some(shadows) = self.shadows.get() {
            shadows.end(session_id);
        }
    }

    /// The record store, or `-32603` when it could not be opened at start.
    fn store(&self) -> Result<&RecordStore, RpcError> {
        self.store.as_ref().ok_or_else(internal_error)
    }

    /// A fresh ULID stamped `now`.
    fn ulid(&self, now: Timestamp) -> Result<Ulid, RpcError> {
        let mut random = [0; 10];
        self.random.fill(&mut random).map_err(|_| internal_error())?;
        Ulid::new(now.as_unix_millis(), random).map_err(|_: CoreError| internal_error())
    }
}

impl Activity for Sessions {
    /// A recording human session keeps `knshd` alive (`specs/02-architecture/process-model.md`).
    fn keeps_alive(&self) -> bool {
        lock(&self.registry).keeps_alive()
    }
}

/// These methods serve `user.sock` only; the catalogue already says so, checked again so that a routing mistake can
/// never let an envelope create a session or write human records.
fn user_only(endpoint: Endpoint) -> Result<(), RpcError> {
    match endpoint {
        Endpoint::User => Ok(()),
        Endpoint::Agent | Endpoint::Control => Err(RpcError::new(ErrorCode::NotAllowed)),
    }
}

/// `-32603`, without the reason (see the module docs).
fn internal_error() -> RpcError {
    RpcError::new(ErrorCode::InternalError)
}

/// `-32007` with `data.state`: the session holds its lines (FR-SES-10, FR-SES-12).
fn held(state: SessionState) -> RpcError {
    let error = RpcError::new(ErrorCode::SessionHeld);
    match Object::new().with("state", state.as_str()) {
        Ok(data) => error.with_data(Value::Object(data)),
        Err(_) => error,
    }
}

/// `-32006` naming the session.
fn session_gone(session_id: SessionId) -> RpcError {
    let error = RpcError::new(ErrorCode::SessionNotFound);
    match Object::new().with("session_id", session_id.to_string()) {
        Ok(data) => error.with_data(Value::Object(data)),
        Err(_) => error,
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use knsh_core::Timestamp;
    use knsh_platform::macos::{RealFs, effective_uid};
    use knsh_platform::testing::{FakeClock, FakeProcessTree, SeededRandom};
    use knsh_proto::{ByteTransport, MethodName, Request, RequestId};
    use knsh_store::{PageSize, RecordQuery, Scope, StoreConfig};

    use super::*;
    use crate::dispatch::tests::{stream, subscriber};
    use crate::events::Subscriber;

    /// A temporary directory for the record store, removed on drop.
    pub(crate) struct TempDir(std::path::PathBuf);

    impl TempDir {
        fn new() -> Self {
            use std::sync::atomic::{AtomicU64, Ordering};
            static COUNTER: AtomicU64 = AtomicU64::new(0);
            let n = COUNTER.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!("knshd-sessions-{}-{n}", std::process::id()));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// The live sessions with a real record store and event hub, so a test can see what was written and published.
    pub(crate) struct Fixture {
        dir: TempDir,
        pub(crate) store: RecordStore,
        pub(crate) hub: Arc<EventHub>,
        pub(crate) sessions: Arc<Sessions>,
        /// The fake process table agent connections are matched against, unless the fixture was built on another.
        pub(crate) processes: Arc<FakeProcessTree>,
    }

    impl Fixture {
        /// The directory holding the record store's files.
        pub(crate) fn dir(&self) -> &std::path::Path {
            &self.dir.0
        }
    }

    pub(crate) fn fixture() -> Fixture {
        fixture_on(None)
    }

    /// [`fixture`], matching agent callers against `processes` (the real process table, say) instead of the fake.
    pub(crate) fn fixture_on(processes: Option<Arc<dyn ProcessTree>>) -> Fixture {
        fixture_with(processes, crate::events::tests::hub())
    }

    /// [`fixture_on`], publishing through `hub`: the phase 2 qualification (KNSH-076) stamps events with the system
    /// clock, so their `ts` can be compared with the time a subscriber receives them.
    pub(crate) fn fixture_with(processes: Option<Arc<dyn ProcessTree>>, hub: Arc<EventHub>) -> Fixture {
        let dir = TempDir::new();
        let clock = Arc::new(FakeClock::new(
            Timestamp::from_unix_micros(1_800_000_000_000_000).unwrap(),
        ));
        let store = RecordStore::open(
            &RealFs::new(),
            &dir.0.join("records.db"),
            effective_uid(),
            clock.clone(),
            StoreConfig::default(),
        )
        .unwrap();
        let fake = Arc::new(FakeProcessTree::new());
        let sessions = Sessions::new(
            Some(store.clone()),
            Arc::clone(&hub),
            clock,
            Arc::new(SeededRandom::new(3)),
            processes.unwrap_or_else(|| fake.clone()),
        );
        Fixture {
            dir,
            store,
            hub,
            sessions,
            processes: fake,
        }
    }

    fn call_on(
        sessions: &Arc<Sessions>,
        endpoint: Endpoint,
        binding: &SessionBinding,
        method: &'static str,
        params: &str,
    ) -> Reply {
        let request = Request {
            id: RequestId::from(1u32),
            method: MethodName::new(method).unwrap(),
            params: knsh_json::parse(params.as_bytes(), 1 << 16)
                .unwrap()
                .as_object()
                .cloned(),
        };
        sessions.handlers()[method](&Call {
            endpoint,
            bytes: ByteTransport::BinaryFrames,
            stream: stream(),
            request: &request,
            subscriber: subscriber(),
            binding,
            descriptors: crate::dispatch::tests::no_descriptors(),
            caller: &knsh_core::StillWaiting,
            control: None,
        })
    }

    fn call(sessions: &Arc<Sessions>, binding: &SessionBinding, method: &'static str, params: &str) -> Reply {
        call_on(sessions, Endpoint::User, binding, method, params)
    }

    fn field<'a>(answer: &'a Answer, name: &str) -> &'a Value {
        answer.result.as_object().unwrap().get(name).unwrap()
    }

    const COMMAND: &str = r#"{"command":"ls -la","cwd":"/Users/u","started_at":"2027-01-15T08:00:00Z",
        "ended_at":"2027-01-15T08:00:02Z","exit_code":1}"#;

    /// Subscribes to every session's events on a fresh connection subscriber.
    pub(crate) fn watch(hub: &Arc<EventHub>) -> Subscriber {
        let watcher = Subscriber::new();
        watcher.subscribe(hub, knsh_core::EventScope::All, None).unwrap();
        watcher
    }

    pub(crate) fn event_names(watcher: &Subscriber) -> Vec<String> {
        watcher
            .take(100)
            .into_iter()
            .filter_map(|(_, delivery)| match delivery {
                knsh_core::Delivery::Event(event) => Some(event.name().to_owned()),
                knsh_core::Delivery::Lost(_) | knsh_core::Delivery::Engine(_) | knsh_core::Delivery::EngineLost(_) => {
                    None
                }
            })
            .collect()
    }

    // KNSH-021 (FR-SES-21, FR-REC-09): a human session records each typed line with the telemetry fields only, emits
    // `session.started`, `command.finished`, `cwd.changed`, and ends with `session.ended` when its connection closes.
    #[test]
    fn human_session_records_commands_and_ends_with_its_connection() {
        let fixture = fixture();
        let watcher = watch(&fixture.hub);
        let binding = SessionBinding::new();
        let started = call(&fixture.sessions, &binding, "session.start_human", "{}").unwrap();
        assert_eq!(field(&started, "recording"), &Value::from(true));
        let session_id: SessionId = field(&started, "session_id").as_str().unwrap().parse().unwrap();
        assert!(fixture.sessions.keeps_alive(), "a recording session keeps knshd alive");

        for _ in 0..3 {
            call(&fixture.sessions, &binding, "telemetry.command", COMMAND).unwrap();
        }
        call(&fixture.sessions, &binding, "telemetry.cwd", r#"{"cwd":"/tmp"}"#).unwrap();

        let page = fixture
            .store
            .query(
                Scope::All,
                RecordQuery {
                    session: Some(session_id),
                    since: None,
                    until: None,
                    text: None,
                    after: None,
                    limit: PageSize::new(100).unwrap(),
                },
            )
            .unwrap();
        assert_eq!(page.records.len(), 3);
        let record = &page.records[0].record;
        assert_eq!(record.actor, Actor::Human);
        assert_eq!(record.command.expose(), "ls -la");
        assert_eq!(record.exit_code, Some(1));
        assert!(record.ended_at.is_some());
        assert!(record.details.is_empty());
        assert!(page.records[0].stdout.is_none() && page.records[0].stderr.is_none());

        binding.release();
        assert_eq!(fixture.sessions.live(), 0);
        assert!(!fixture.sessions.keeps_alive());
        assert_eq!(
            event_names(&watcher),
            [
                "session.started",
                "command.finished",
                "command.finished",
                "command.finished",
                "cwd.changed",
                "session.state_changed",
                "session.ended",
            ]
        );
        // Released twice (never happens): nothing more.
        binding.release();
        assert_eq!(event_names(&watcher), Vec::<String>::new());
    }

    // KNSH-021 (FR-SES-25, NFR-PRIV-05): `session.info` reports actor, profile, state and recording for the caller's
    // session; without one it is refused. On agent.sock a connection with no agent session is refused too.
    #[test]
    fn session_info_reports_recording_state() {
        let fixture = fixture();
        let binding = SessionBinding::new();
        let refused = call(&fixture.sessions, &binding, "session.info", "{}").unwrap_err();
        assert_eq!(refused.code, ErrorCode::NotAllowed);
        call(&fixture.sessions, &binding, "session.start_human", "{}").unwrap();
        let info = call(&fixture.sessions, &binding, "session.info", "{}").unwrap();
        assert_eq!(field(&info, "recording"), &Value::from(true));
        assert_eq!(field(&info, "output_recording"), &Value::from(false));
        assert_eq!(field(&info, "state"), &Value::from("active"));
        assert_eq!(field(&info, "profile"), &Value::from(HUMAN_PROFILE));
        assert_eq!(
            field(&info, "actor").as_object().unwrap().get("kind"),
            Some(&Value::from("human"))
        );
        let agent = call_on(&fixture.sessions, Endpoint::Agent, &binding, "session.info", "{}").unwrap_err();
        assert_eq!(agent.code, ErrorCode::NotAllowed);
        binding.release();
    }

    // FR-SES-24: the daemon publishes `session.idle` once per idle prompt, even if a client repeats it.
    #[test]
    fn idle_is_published_once_between_commands() {
        let fixture = fixture();
        let binding = SessionBinding::new();
        call(&fixture.sessions, &binding, "session.start_human", "{}").unwrap();
        let watcher = watch(&fixture.hub);
        let emitted = |answer: Answer| field(&answer, "emitted") == &Value::from(true);
        assert!(emitted(
            call(&fixture.sessions, &binding, "telemetry.idle", "{}").unwrap()
        ));
        assert!(!emitted(
            call(&fixture.sessions, &binding, "telemetry.idle", "{}").unwrap()
        ));
        call(&fixture.sessions, &binding, "telemetry.command", COMMAND).unwrap();
        assert!(emitted(
            call(&fixture.sessions, &binding, "telemetry.idle", "{}").unwrap()
        ));
        assert_eq!(
            event_names(&watcher),
            ["session.idle", "command.finished", "session.idle"]
        );
        binding.release();
    }

    // Fail closed: telemetry without a session, a second session on one connection, any of these methods on
    // agent.sock, and malformed params are all refused, and nothing is written.
    #[test]
    fn telemetry_is_refused_outside_a_bound_session() {
        let fixture = fixture();
        let binding = SessionBinding::new();
        for (method, params) in [
            ("telemetry.command", COMMAND),
            ("telemetry.cwd", r#"{"cwd":"/"}"#),
            ("telemetry.idle", "{}"),
        ] {
            let error = call(&fixture.sessions, &binding, method, params).unwrap_err();
            assert_eq!(error.code, ErrorCode::NotAllowed, "{method}");
        }
        for method in ["session.start_human", "telemetry.idle"] {
            let error = call_on(&fixture.sessions, Endpoint::Agent, &binding, method, "{}").unwrap_err();
            assert_eq!(error.code, ErrorCode::NotAllowed, "{method}");
        }
        assert_eq!(fixture.sessions.live(), 0);

        call(&fixture.sessions, &binding, "session.start_human", "{}").unwrap();
        let again = call(&fixture.sessions, &binding, "session.start_human", "{}").unwrap_err();
        assert_eq!(again.code, ErrorCode::InvalidParams);
        assert_eq!(fixture.sessions.live(), 1);
        let bad = call(
            &fixture.sessions,
            &binding,
            "telemetry.command",
            r#"{"command":"x","cwd":"relative","started_at":"2027-01-15T08:00:00Z","ended_at":"2027-01-15T08:00:00Z","exit_code":0}"#,
        )
        .unwrap_err();
        assert_eq!(bad.code, ErrorCode::InvalidParams);
        binding.release();
    }

    // KNSH-021: over a real connection, the session lives as long as the connection: when `knsh` goes away the
    // connection loop ends it, and `session.ended` is published.
    #[test]
    fn closing_the_connection_ends_its_session() {
        use crate::dispatch::tests::ok_handler;
        use crate::dispatch::{Dispatcher, HELLO, Table};

        let fixture = fixture();
        let watcher = watch(&fixture.hub);
        let mut user = Table::new().with(HELLO, ok_handler());
        for (name, handler) in fixture.sessions.handlers() {
            user = user.with(name, handler);
        }
        let dispatcher = Dispatcher::from_tables(user, Table::new());
        let mut input = knsh_json::FrameWriter::new(Vec::new());
        for text in [
            r#"{"jsonrpc":"2.0","id":1,"method":"hello"}"#,
            r#"{"jsonrpc":"2.0","id":2,"method":"session.start_human"}"#,
        ] {
            input
                .write_json(&knsh_json::parse(text.as_bytes(), 4096).unwrap())
                .unwrap();
        }
        let mut output = Vec::new();
        crate::connection::serve(
            std::io::Cursor::new(input.into_inner()),
            &mut output,
            Endpoint::User,
            None,
            &dispatcher,
            &mut || {},
            &|| {},
        );
        assert_eq!(fixture.sessions.live(), 0);
        assert_eq!(
            event_names(&watcher),
            ["session.started", "session.state_changed", "session.ended"]
        );
    }

    // A connection that unwinds before `release` still ends its session, so knshd is not kept alive forever.
    #[test]
    fn dropping_a_binding_ends_its_session() {
        let fixture = fixture();
        let binding = SessionBinding::new();
        call(&fixture.sessions, &binding, "session.start_human", "{}").unwrap();
        assert_eq!(fixture.sessions.live(), 1);
        drop(binding);
        assert_eq!(fixture.sessions.live(), 0);
        assert!(!fixture.sessions.keeps_alive());
    }

    // Without a record store a recorded session cannot exist: refused, and nothing is left in the registry.
    #[test]
    fn no_store_refuses_recorded_sessions() {
        let sessions = Sessions::new(
            None,
            crate::events::tests::hub(),
            Arc::new(FakeClock::new(Timestamp::UNIX_EPOCH)),
            Arc::new(SeededRandom::new(1)),
            Arc::new(FakeProcessTree::new()),
        );
        let binding = SessionBinding::new();
        let error = call(&sessions, &binding, "session.start_human", "{}").unwrap_err();
        assert_eq!(error.code, ErrorCode::InternalError);
        assert_eq!(sessions.live(), 0);
    }
}
