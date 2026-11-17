//! The session model: actor, profile, envelope, recording, parent link and the state machine.
//!
//! A session has exactly one actor, fixed at creation (FR-SES-01). [`Session`] exposes no way to change the actor:
//! its fields are private and only the state moves, through [`Session::apply`], which follows the diagram in
//! `specs/03-functional-requirements/sessions.md#states` exactly and yields a [`StateChanged`] event value for every
//! change (FR-SES-14). A refused transition returns an error and leaves the state as it was.
//!
//! Specification: `specs/05-models/session.md`, `specs/03-functional-requirements/sessions.md` (FR-SES-01,
//! FR-SES-03, FR-SES-04, FR-SES-14).

use std::fmt;

use crate::error::CoreError;
use crate::id::SessionId;

/// Longest accepted [`AgentId`] or [`ProfileName`], in bytes (`specs/05-models/session.md`).
pub const MAX_NAME_LEN: usize = 64;

/// Checks the shared name rule: 1 to [`MAX_NAME_LEN`] bytes from `[A-Za-z0-9._-]`.
///
/// The narrow alphabet keeps these names safe to place in event payloads, record columns and log lines without
/// escaping, and rules out look-alike Unicode and control characters coming from an untrusted client.
fn is_valid_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= MAX_NAME_LEN
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// Identifies the agent behind an agent session (`actor.agent_id`), for example `claude-code`.
///
/// # Invariants
///
/// 1 to [`MAX_NAME_LEN`] bytes from `[A-Za-z0-9._-]`.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct AgentId(String);

impl AgentId {
    /// Validates and wraps an agent identifier.
    ///
    /// # Errors
    ///
    /// [`CoreError::InvalidAgentId`] if `s` is empty, longer than [`MAX_NAME_LEN`] bytes or holds a character
    /// outside `[A-Za-z0-9._-]`.
    pub fn new(s: &str) -> Result<Self, CoreError> {
        if is_valid_name(s) {
            Ok(Self(s.to_owned()))
        } else {
            Err(CoreError::InvalidAgentId)
        }
    }

    /// The actor of an agent session started without `--agent` (FR-AGT-02): derived from the command's program,
    /// `program` being `argv[0]` as given (a name or a path). Its last path component is looked up in
    /// [`DERIVED_AGENT_IDS`] (`claude` becomes `claude-code`); a program the table does not name is its own
    /// identifier (`/opt/bin/aider` becomes `aider`).
    ///
    /// # Errors
    ///
    /// [`CoreError::InvalidAgentId`] if that component is not a valid identifier (empty, too long, or holding a
    /// character outside `[A-Za-z0-9._-]`): the caller must name the agent with `--agent` then, rather than have a
    /// name made up for it.
    pub fn derive_from_program(program: &str) -> Result<Self, CoreError> {
        // `rsplit` always yields at least one item; a trailing `/` leaves it empty, which is refused below.
        let name = program.rsplit('/').next().unwrap_or_default();
        let derived = DERIVED_AGENT_IDS
            .iter()
            .find_map(|(binary, agent_id)| (*binary == name).then_some(*agent_id))
            .unwrap_or(name);
        Self::new(derived)
    }

    /// The identifier text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Agent CLIs whose actor is not their binary's name: `(binary, agent_id)` (FR-AGT-02,
/// `specs/08-integrations/agent-clis.md#starting`). Each actor is named after the CLI's preset (KNSH-058).
pub const DERIVED_AGENT_IDS: &[(&str, &str)] = &[("claude", "claude-code"), ("codex", "codex-cli")];

impl fmt::Display for AgentId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Names the policy profile a session runs under (`profile`).
///
/// # Invariants
///
/// 1 to [`MAX_NAME_LEN`] bytes from `[A-Za-z0-9._-]`.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct ProfileName(String);

impl ProfileName {
    /// Validates and wraps a profile name.
    ///
    /// # Errors
    ///
    /// [`CoreError::InvalidProfileName`] if `s` is empty, longer than [`MAX_NAME_LEN`] bytes or holds a character
    /// outside `[A-Za-z0-9._-]`.
    pub fn new(s: &str) -> Result<Self, CoreError> {
        if is_valid_name(s) {
            Ok(Self(s.to_owned()))
        } else {
            Err(CoreError::InvalidProfileName)
        }
    }

    /// The name text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ProfileName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The kind of actor behind a session (`actor.kind`).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum ActorKind {
    /// A person typing in their own terminal. Observed only, never blocked (FR-SES-22).
    Human,
    /// An AI agent whose lines are decided on before they run.
    Agent,
}

impl ActorKind {
    /// The wire form: `human` or `agent`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Human => "human",
            Self::Agent => "agent",
        }
    }
}

/// Who a session belongs to (`actor`).
///
/// The agent identifier lives inside the [`Agent`](Self::Agent) variant, so "required for agents, absent for humans"
/// holds by construction rather than by a check that could be forgotten.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub enum Actor {
    /// A human session; it has no agent identifier.
    Human,
    /// An agent session with its identifier.
    Agent(AgentId),
}

impl Actor {
    /// Builds an actor from its wire parts, `actor.kind` and the optional `actor.agent_id`.
    ///
    /// # Errors
    ///
    /// - [`CoreError::AgentIdRequired`] for an agent without an identifier.
    /// - [`CoreError::AgentIdForHuman`] for a human with one: accepting and dropping it would hide a confused or
    ///   lying client.
    pub fn from_parts(kind: ActorKind, agent_id: Option<AgentId>) -> Result<Self, CoreError> {
        match (kind, agent_id) {
            (ActorKind::Human, None) => Ok(Self::Human),
            (ActorKind::Human, Some(_)) => Err(CoreError::AgentIdForHuman),
            (ActorKind::Agent, Some(id)) => Ok(Self::Agent(id)),
            (ActorKind::Agent, None) => Err(CoreError::AgentIdRequired),
        }
    }

    /// `actor.kind`.
    #[must_use]
    pub const fn kind(&self) -> ActorKind {
        match self {
            Self::Human => ActorKind::Human,
            Self::Agent(_) => ActorKind::Agent,
        }
    }

    /// `actor.agent_id`: present for agents, absent for humans.
    #[must_use]
    pub const fn agent_id(&self) -> Option<&AgentId> {
        match self {
            Self::Human => None,
            Self::Agent(id) => Some(id),
        }
    }
}

/// Where a session is in its life (`state`).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum SessionState {
    /// Normal operation: agent lines run after a decision.
    Active,
    /// Envelope and running commands are stopped; new agent lines are held (`-32007`).
    Paused,
    /// The human works in their own session; agent lines are held (`-32007`) until handed back.
    HumanControl,
    /// The session exited; it is refused everywhere (`-32006`). Terminal: no transition leaves it.
    Ended,
}

impl SessionState {
    /// The wire form: `active`, `paused`, `human_control` or `ended`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Paused => "paused",
            Self::HumanControl => "human_control",
            Self::Ended => "ended",
        }
    }
}

impl fmt::Display for SessionState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A request to move a session between states, named after the edges of the state diagram.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Transition {
    /// `active → paused`.
    Pause,
    /// `paused → active`.
    Resume,
    /// `active → human_control`.
    TakeControl,
    /// `human_control → active`.
    HandBack,
    /// `active | paused | human_control → ended`.
    End,
}

impl Transition {
    /// The verb used in messages: `pause`, `resume`, `take control of`, `hand back` or `end`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pause => "pause",
            Self::Resume => "resume",
            Self::TakeControl => "take control of",
            Self::HandBack => "hand back",
            Self::End => "end",
        }
    }

    /// The state this transition leads to from `from`, or `None` when the diagram has no such edge.
    ///
    /// This is the whole state machine. The `match` is exhaustive over both enums with no catch-all, so adding a
    /// state or a transition fails to compile until every pair has been decided.
    // One arm per edge mirrors the diagram line by line, and the refused pairs are listed state by state rather
    // than folded together, so a reader can check them against the spec table directly.
    #[allow(clippy::match_same_arms, clippy::unnested_or_patterns)]
    #[must_use]
    pub const fn target(self, from: SessionState) -> Option<SessionState> {
        use SessionState::{Active, Ended, HumanControl, Paused};
        match (self, from) {
            (Self::Pause, Active) => Some(Paused),
            (Self::Resume, Paused) => Some(Active),
            (Self::TakeControl, Active) => Some(HumanControl),
            (Self::HandBack, HumanControl) => Some(Active),
            (Self::End, Active | Paused | HumanControl) => Some(Ended),
            // Pausing twice, resuming a running session, nesting control or leaving `ended` are not edges in the
            // diagram. Refusing them, rather than treating them as no-ops, keeps every emitted event a real change.
            (Self::Pause, Paused | HumanControl | Ended)
            | (Self::Resume, Active | HumanControl | Ended)
            | (Self::TakeControl, Paused | HumanControl | Ended)
            | (Self::HandBack, Active | Paused | Ended)
            | (Self::End, Ended) => None,
        }
    }
}

/// Name of the event emitted for every state change (FR-SES-14).
pub const STATE_CHANGED_EVENT: &str = "session.state_changed";

/// The value of one `session.state_changed` event (FR-SES-14), produced by every successful transition.
///
/// It carries what the event envelope and its `data` need (`specs/05-models/event.md`); the event bus adds `id`,
/// `seq` and `ts`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct StateChanged {
    /// The session that changed.
    pub session_id: SessionId,
    /// The session's actor, for the envelope's `actor` field.
    pub actor: Actor,
    /// The state before the change.
    pub from: SessionState,
    /// The state after the change. Always different from `from`.
    pub to: SessionState,
}

impl StateChanged {
    /// The event name, [`STATE_CHANGED_EVENT`].
    #[must_use]
    pub const fn event(&self) -> &'static str {
        STATE_CHANGED_EVENT
    }
}

/// What a caller supplies to create a session. The registry checks it and fills in the defaults.
#[derive(Clone, Debug)]
pub struct SessionSpec {
    /// The new session's identifier. Generated by the caller from the injected clock and random source.
    pub session_id: SessionId,
    /// The actor, fixed for the session's whole life (FR-SES-01).
    pub actor: Actor,
    /// The policy profile.
    pub profile: ProfileName,
    /// Whether this is an agent session started with `knsh agent`. Must be `false` for humans.
    pub envelope: bool,
    /// Recording; `None` takes the default for the actor (FR-SES-04).
    pub recording: Option<bool>,
    /// The session this one was started from, if any (FR-SES-03).
    pub parent_session_id: Option<SessionId>,
}

/// One session.
///
/// # Invariants
///
/// - The actor, profile, envelope flag and parent link never change after creation: there are no setters, and the
///   fields are private (FR-SES-01).
/// - The recording settings of an agent session change only through [`set_recording`](Self::set_recording)
///   (`recording.set`, KNSH-071); a human session's never change once it exists, and it never records output.
/// - `envelope` is `true` only for agent sessions.
/// - The state only moves along the edges of the diagram, through [`apply`](Self::apply).
// Field names follow the wire names in `specs/05-models/session.md`, including `session_id`.
#[allow(clippy::struct_field_names)]
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Session {
    session_id: SessionId,
    actor: Actor,
    profile: ProfileName,
    envelope: bool,
    recording: bool,
    /// Output recording set for this session by `recording.set`; `None` follows its profile's `recording.output`.
    output_recording: Option<bool>,
    parent_session_id: Option<SessionId>,
    state: SessionState,
}

impl Session {
    /// Creates a session in state `active` from a spec, applying the recording default (FR-SES-04).
    ///
    /// This checks the session on its own. Checks that need other sessions (unique ID, live parent, profile
    /// strictness) are done by [`SessionRegistry::create`](crate::SessionRegistry::create).
    ///
    /// # Errors
    ///
    /// [`CoreError::EnvelopeForHuman`] if a human session asks for an envelope: envelopes exist only for agents
    /// started with `knsh agent`.
    pub fn new(spec: SessionSpec) -> Result<Self, CoreError> {
        let SessionSpec {
            session_id,
            actor,
            profile,
            envelope,
            recording,
            parent_session_id,
        } = spec;
        if envelope && actor.kind() == ActorKind::Human {
            return Err(CoreError::EnvelopeForHuman);
        }
        let recording = recording.unwrap_or_else(|| default_recording(actor.kind()));
        Ok(Self {
            session_id,
            actor,
            profile,
            envelope,
            recording,
            output_recording: None,
            parent_session_id,
            state: SessionState::Active,
        })
    }

    /// `session_id`.
    #[must_use]
    pub const fn session_id(&self) -> SessionId {
        self.session_id
    }

    /// `actor`.
    #[must_use]
    pub const fn actor(&self) -> &Actor {
        &self.actor
    }

    /// `profile`.
    #[must_use]
    pub const fn profile(&self) -> &ProfileName {
        &self.profile
    }

    /// `envelope`.
    #[must_use]
    pub const fn envelope(&self) -> bool {
        self.envelope
    }

    /// `recording`.
    #[must_use]
    pub const fn recording(&self) -> bool {
        self.recording
    }

    /// Output recording as set for this session by `recording.set` (KNSH-071), or `None` when it follows the
    /// profile's `recording.output`.
    #[must_use]
    pub const fn output_recording(&self) -> Option<bool> {
        self.output_recording
    }

    /// Changes what an agent session records (`recording.set`, KNSH-071): `commands` sets `recording`, `output` sets
    /// output recording for the session in place of its profile's; `None` leaves that setting as it is.
    ///
    /// Turning command recording off never suppresses an agent's records: every line is recorded whatever the
    /// setting (FR-REC-01, FR-REC-03). What it withholds is the line's output, with `output` (FR-REC-06).
    ///
    /// # Errors
    ///
    /// [`CoreError::HumanRecording`] for a human session, which is left unchanged: a human's recording is theirs to
    /// choose, never an authority's (FR-SES-04), and a human session never records output (FR-REC-09).
    pub fn set_recording(&mut self, commands: Option<bool>, output: Option<bool>) -> Result<(), CoreError> {
        if self.actor.kind() == ActorKind::Human {
            return Err(CoreError::HumanRecording);
        }
        if let Some(commands) = commands {
            self.recording = commands;
        }
        if output.is_some() {
            self.output_recording = output;
        }
        Ok(())
    }

    /// `parent_session_id`.
    #[must_use]
    pub const fn parent_session_id(&self) -> Option<SessionId> {
        self.parent_session_id
    }

    /// `state`.
    #[must_use]
    pub const fn state(&self) -> SessionState {
        self.state
    }

    /// Moves the session along one edge of the state diagram and returns the `session.state_changed` value.
    ///
    /// # Errors
    ///
    /// [`CoreError::InvalidTransition`] if the diagram has no such edge from the current state. The state is left
    /// unchanged and no event is produced.
    pub fn apply(&mut self, transition: Transition) -> Result<StateChanged, CoreError> {
        let from = self.state;
        let to = transition
            .target(from)
            .ok_or(CoreError::InvalidTransition { from, transition })?;
        self.state = to;
        Ok(StateChanged {
            session_id: self.session_id,
            actor: self.actor.clone(),
            from,
            to,
        })
    }
}

/// The recording default for an actor (FR-SES-04, `specs/04-non-functional-requirements/privacy.md`): off for
/// humans, whose terminals are private by default, and on for agents, whose lines are the thing being audited.
#[must_use]
pub const fn default_recording(kind: ActorKind) -> bool {
    match kind {
        ActorKind::Human => false,
        ActorKind::Agent => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ulid::Ulid;

    fn sid(n: u128) -> SessionId {
        SessionId::from_ulid(Ulid::from_u128(n))
    }

    fn agent() -> Actor {
        Actor::Agent(AgentId::new("claude-code").unwrap())
    }

    // FR-AGT-02: `claude` (by name or by path) is the `claude-code` actor.
    #[test]
    fn derives_claude_code_actor_from_claude() {
        for program in ["claude", "/opt/homebrew/bin/claude", "./claude"] {
            assert_eq!(AgentId::derive_from_program(program).unwrap().as_str(), "claude-code");
        }
    }

    // FR-AGT-02, KNSH-058: `codex` is the `codex-cli` actor, named after its preset.
    #[test]
    fn derives_codex_cli_actor_from_codex() {
        for program in ["codex", "/opt/homebrew/bin/codex"] {
            assert_eq!(AgentId::derive_from_program(program).unwrap().as_str(), "codex-cli");
        }
    }

    // FR-AGT-02: a program the table does not name is its own actor; one that is not a valid name is refused.
    #[test]
    fn derives_other_actors_from_the_program_name() {
        assert_eq!(
            AgentId::derive_from_program("/usr/local/bin/aider").unwrap().as_str(),
            "aider"
        );
        for program in ["", "/opt/bin/", "my agent", "agent\u{e9}"] {
            assert_eq!(AgentId::derive_from_program(program), Err(CoreError::InvalidAgentId));
        }
    }

    fn spec(actor: Actor) -> SessionSpec {
        SessionSpec {
            session_id: sid(1),
            envelope: actor.kind() == ActorKind::Agent,
            actor,
            profile: ProfileName::new("default").unwrap(),
            recording: None,
            parent_session_id: None,
        }
    }

    const ALL_STATES: [SessionState; 4] = [
        SessionState::Active,
        SessionState::Paused,
        SessionState::HumanControl,
        SessionState::Ended,
    ];
    const ALL_TRANSITIONS: [Transition; 5] = [
        Transition::Pause,
        Transition::Resume,
        Transition::TakeControl,
        Transition::HandBack,
        Transition::End,
    ];

    /// Puts a fresh session into `state` through legal edges only.
    fn session_in(state: SessionState) -> Session {
        let mut s = Session::new(spec(agent())).unwrap();
        let path: &[Transition] = match state {
            SessionState::Active => &[],
            SessionState::Paused => &[Transition::Pause],
            SessionState::HumanControl => &[Transition::TakeControl],
            SessionState::Ended => &[Transition::End],
        };
        for t in path {
            s.apply(*t).unwrap();
        }
        assert_eq!(s.state(), state);
        s
    }

    // FR-SES-01: the actor is set at creation and no transition, in any state, changes it. `Session` has no setter
    // and private fields, so the only way to touch it would be through `apply`.
    #[test]
    fn actor_is_immutable_after_creation() {
        for state in ALL_STATES {
            for t in ALL_TRANSITIONS {
                let mut s = session_in(state);
                let before = s.actor().clone();
                let _ = s.apply(t);
                assert_eq!(s.actor(), &before);
            }
        }
        let human = Session::new(spec(Actor::Human)).unwrap();
        assert_eq!(human.actor().kind(), ActorKind::Human);
        assert_eq!(human.actor().agent_id(), None);
    }

    // Model validity: `actor.agent_id` is required for agents and absent for humans, and must be a valid name.
    #[test]
    fn agent_requires_agent_id() {
        assert_eq!(
            Actor::from_parts(ActorKind::Agent, None),
            Err(CoreError::AgentIdRequired)
        );
        let id = AgentId::new("claude-code").unwrap();
        assert_eq!(
            Actor::from_parts(ActorKind::Agent, Some(id.clone())),
            Ok(Actor::Agent(id.clone()))
        );
        assert_eq!(
            Actor::from_parts(ActorKind::Human, Some(id)),
            Err(CoreError::AgentIdForHuman)
        );
        assert_eq!(Actor::from_parts(ActorKind::Human, None), Ok(Actor::Human));

        assert_eq!(AgentId::new(""), Err(CoreError::InvalidAgentId));
        assert_eq!(AgentId::new("has space"), Err(CoreError::InvalidAgentId));
        assert_eq!(AgentId::new("ctl\u{7}"), Err(CoreError::InvalidAgentId));
        assert_eq!(
            AgentId::new("clаude"),
            Err(CoreError::InvalidAgentId),
            "Cyrillic look-alike"
        );
        assert!(AgentId::new(&"a".repeat(MAX_NAME_LEN)).is_ok());
        assert_eq!(
            AgentId::new(&"a".repeat(MAX_NAME_LEN + 1)),
            Err(CoreError::InvalidAgentId)
        );
        assert_eq!(ProfileName::new("web/app"), Err(CoreError::InvalidProfileName));
        assert_eq!(ProfileName::new("web-app_1.2").unwrap().as_str(), "web-app_1.2");
    }

    // KNSH-071: `recording.set` changes an agent session's recording settings, one at a time or both; a human
    // session's are refused and stay as they were.
    #[test]
    fn sets_recording_of_agent_sessions_only() {
        let mut session = Session::new(spec(agent())).unwrap();
        assert_eq!((session.recording(), session.output_recording()), (true, None));
        session.set_recording(None, Some(true)).unwrap();
        assert_eq!((session.recording(), session.output_recording()), (true, Some(true)));
        session.set_recording(Some(false), None).unwrap();
        assert_eq!((session.recording(), session.output_recording()), (false, Some(true)));

        let mut human = Session::new(spec(Actor::Human)).unwrap();
        assert_eq!(human.set_recording(Some(true), None), Err(CoreError::HumanRecording));
        assert_eq!(human.set_recording(None, Some(true)), Err(CoreError::HumanRecording));
        assert_eq!((human.recording(), human.output_recording()), (false, None));
    }

    // FR-SES-04: recording defaults to off for humans and on for agents; an explicit choice wins.
    #[test]
    fn human_recording_defaults_off_agent_on() {
        assert!(!Session::new(spec(Actor::Human)).unwrap().recording());
        assert!(Session::new(spec(agent())).unwrap().recording());

        let mut human_on = spec(Actor::Human);
        human_on.recording = Some(true);
        assert!(Session::new(human_on).unwrap().recording());
        let mut agent_off = spec(agent());
        agent_off.recording = Some(false);
        assert!(!Session::new(agent_off).unwrap().recording());
    }

    #[test]
    fn human_session_cannot_have_an_envelope() {
        let mut s = spec(Actor::Human);
        s.envelope = true;
        assert_eq!(Session::new(s), Err(CoreError::EnvelopeForHuman));
    }

    #[test]
    fn transitions_follow_the_state_diagram_exactly() {
        use SessionState::{Active, Ended, HumanControl, Paused};
        let legal = [
            (Transition::Pause, Active, Paused),
            (Transition::Resume, Paused, Active),
            (Transition::TakeControl, Active, HumanControl),
            (Transition::HandBack, HumanControl, Active),
            (Transition::End, Active, Ended),
            (Transition::End, Paused, Ended),
            (Transition::End, HumanControl, Ended),
        ];
        for state in ALL_STATES {
            for t in ALL_TRANSITIONS {
                let expected = legal
                    .iter()
                    .find(|(lt, from, _)| *lt == t && *from == state)
                    .map(|(_, _, to)| *to);
                assert_eq!(t.target(state), expected, "{t:?} from {state}");
            }
        }
    }

    // Failure safety: a refused transition reports the state and the request and leaves the session untouched.
    #[test]
    fn invalid_transition_keeps_state() {
        for state in ALL_STATES {
            for t in ALL_TRANSITIONS {
                if t.target(state).is_some() {
                    continue;
                }
                let mut s = session_in(state);
                let before = s.clone();
                assert_eq!(
                    s.apply(t),
                    Err(CoreError::InvalidTransition {
                        from: state,
                        transition: t
                    })
                );
                assert_eq!(s, before);
            }
        }
    }

    // FR-SES-14: every successful transition yields exactly one `session.state_changed` value describing it.
    #[test]
    fn every_transition_emits_state_changed() {
        for state in ALL_STATES {
            for t in ALL_TRANSITIONS {
                let Some(to) = t.target(state) else { continue };
                let mut s = session_in(state);
                let event = s.apply(t).unwrap();
                assert_eq!(event.event(), "session.state_changed");
                assert_eq!(
                    event,
                    StateChanged {
                        session_id: sid(1),
                        actor: agent(),
                        from: state,
                        to
                    }
                );
                assert_ne!(event.from, event.to);
                assert_eq!(s.state(), to);
            }
        }
    }

    #[test]
    fn wire_forms_match_the_spec() {
        assert_eq!(ActorKind::Human.as_str(), "human");
        assert_eq!(ActorKind::Agent.as_str(), "agent");
        let names: Vec<_> = ALL_STATES.iter().map(|s| s.as_str()).collect();
        assert_eq!(names, ["active", "paused", "human_control", "ended"]);
    }
}
