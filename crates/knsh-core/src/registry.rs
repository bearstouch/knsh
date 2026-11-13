//! The registry of live sessions.
//!
//! Holds every session that has not ended, keyed by [`SessionId`]. It performs the checks that need more than one
//! session: unique identifiers, a live parent (FR-SES-03) and the parent's profile bound for agent children. A
//! session that ends is removed in the same step, so every later lookup answers "not found or ended"
//! ([`CoreError::SessionNotFoundOrEnded`], mapped to `-32006` by `knsh-proto`).
//!
//! Pure and single-owner: no locks inside. `knshd` owns one registry behind its own lock.
//!
//! Specification: `specs/05-models/session.md`, `specs/03-functional-requirements/sessions.md` (FR-SES-03,
//! FR-SES-14), `specs/06-api/errors.md` (`-32006`).

use std::collections::BTreeMap;

use crate::error::CoreError;
use crate::id::SessionId;
use crate::session::{ActorKind, ProfileName, Session, SessionSpec, StateChanged, Transition};

/// Decides whether a child profile is equal to or stricter than its parent's (FR-SES-03).
///
/// This is the hook point for agent children. Phase 1 uses [`EqualProfileOnly`]; the policy model (phase 2)
/// supplies a real ordering. Implementations must answer `false` whenever they cannot tell: an unknown profile
/// must never let an agent escape to a looser one.
pub trait ProfileOrder {
    /// Whether `child` is at least as strict as `parent`.
    fn at_least_as_strict(&self, child: &ProfileName, parent: &ProfileName) -> bool;
}

/// The phase 1 ordering: only the parent's own profile is accepted.
///
/// Equality always satisfies "equal or stricter", so this is safe without a policy model; it refuses stricter
/// profiles too until phase 2 can compare them.
#[derive(Clone, Copy, Debug, Default)]
pub struct EqualProfileOnly;

impl ProfileOrder for EqualProfileOnly {
    fn at_least_as_strict(&self, child: &ProfileName, parent: &ProfileName) -> bool {
        child == parent
    }
}

/// Every live session, with the profile ordering used to check agent children.
///
/// # Invariants
///
/// - Holds no session in state `ended`.
/// - Each session's `parent_session_id` named a live session when it was created.
#[derive(Debug, Default)]
pub struct SessionRegistry<P = EqualProfileOnly> {
    sessions: BTreeMap<SessionId, Session>,
    order: P,
}

impl SessionRegistry<EqualProfileOnly> {
    /// An empty registry with the phase 1 profile ordering, [`EqualProfileOnly`].
    #[must_use]
    pub fn new() -> Self {
        Self::with_order(EqualProfileOnly)
    }
}

impl<P: ProfileOrder> SessionRegistry<P> {
    /// An empty registry that checks agent children with `order`.
    #[must_use]
    pub fn with_order(order: P) -> Self {
        Self {
            sessions: BTreeMap::new(),
            order,
        }
    }

    /// Creates a session in state `active` and returns it.
    ///
    /// # Errors
    ///
    /// Nothing is added on error.
    ///
    /// - [`CoreError::SessionExists`] if a live session already has this identifier.
    /// - [`CoreError::ParentNotFoundOrEnded`] if `parent_session_id` names no live session.
    /// - [`CoreError::HumanChildOfAgent`] if a human session names an agent session as its parent: a human session
    ///   is never enforced (FR-SES-22), so allowing it would let an agent escape its profile (FR-SES-03, FR-SES-12).
    /// - [`CoreError::ProfileNotStricter`] if an agent child's profile is not at least as strict as its parent's
    ///   (FR-SES-03). Human children of human sessions are not checked: nothing in a human session is enforced.
    /// - Any error of [`Session::new`].
    pub fn create(&mut self, spec: SessionSpec) -> Result<&Session, CoreError> {
        let id = spec.session_id;
        if self.sessions.contains_key(&id) {
            return Err(CoreError::SessionExists);
        }
        if let Some(parent_id) = spec.parent_session_id {
            let parent = self.sessions.get(&parent_id).ok_or(CoreError::ParentNotFoundOrEnded)?;
            match (spec.actor.kind(), parent.actor().kind()) {
                // Fail closed: a child of an agent session is still the agent's work, and a human session is never
                // enforced, so it must not become an unenforced way out of the envelope (FR-SES-12).
                (ActorKind::Human, ActorKind::Agent) => return Err(CoreError::HumanChildOfAgent),
                (ActorKind::Human, ActorKind::Human) => {}
                (ActorKind::Agent, ActorKind::Human | ActorKind::Agent) => {
                    if !self.order.at_least_as_strict(&spec.profile, parent.profile()) {
                        return Err(CoreError::ProfileNotStricter);
                    }
                }
            }
        }
        let session = Session::new(spec)?;
        Ok(self.sessions.entry(id).or_insert(session))
    }

    /// Looks up a live session.
    ///
    /// # Errors
    ///
    /// [`CoreError::SessionNotFoundOrEnded`] if no session has this identifier or it has ended. The two cases are
    /// deliberately the same answer (`-32006`).
    pub fn get(&self, id: SessionId) -> Result<&Session, CoreError> {
        self.sessions.get(&id).ok_or(CoreError::SessionNotFoundOrEnded)
    }

    /// Applies a transition to a live session and returns its `session.state_changed` value (FR-SES-14). A
    /// session that reaches `ended` is removed.
    ///
    /// # Errors
    ///
    /// - [`CoreError::SessionNotFoundOrEnded`] if the session is unknown or has ended.
    /// - [`CoreError::InvalidTransition`] if the state diagram has no such edge; the state is unchanged.
    pub fn transition(&mut self, id: SessionId, transition: Transition) -> Result<StateChanged, CoreError> {
        let session = self.sessions.get_mut(&id).ok_or(CoreError::SessionNotFoundOrEnded)?;
        let event = session.apply(transition)?;
        if transition == Transition::End {
            self.sessions.remove(&id);
        }
        Ok(event)
    }

    /// Whether any envelope or recording session is live: what keeps `knshd` running between connections
    /// (`specs/02-architecture/process-model.md`).
    #[must_use]
    pub fn keeps_alive(&self) -> bool {
        self.sessions.values().any(|s| s.envelope() || s.recording())
    }

    /// The live sessions, oldest first (ULIDs sort by creation time).
    pub fn iter(&self) -> impl Iterator<Item = &Session> {
        self.sessions.values()
    }

    /// The number of live sessions.
    #[must_use]
    pub fn len(&self) -> usize {
        self.sessions.len()
    }

    /// Whether no session is live.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::{Actor, AgentId, SessionState};
    use crate::ulid::Ulid;

    fn sid(n: u128) -> SessionId {
        SessionId::from_ulid(Ulid::from_u128(n))
    }

    fn profile(name: &str) -> ProfileName {
        ProfileName::new(name).unwrap()
    }

    fn human(n: u128) -> SessionSpec {
        SessionSpec {
            session_id: sid(n),
            actor: Actor::Human,
            profile: profile("default"),
            envelope: false,
            recording: None,
            parent_session_id: None,
        }
    }

    fn agent(n: u128, profile_name: &str, parent: Option<u128>) -> SessionSpec {
        SessionSpec {
            session_id: sid(n),
            actor: Actor::Agent(AgentId::new("claude-code").unwrap()),
            profile: profile(profile_name),
            envelope: true,
            recording: None,
            parent_session_id: parent.map(sid),
        }
    }

    // -32006: an ended session answers lookups and transitions exactly like one that never existed.
    #[test]
    fn ended_session_lookup_is_not_found() {
        let mut reg = SessionRegistry::new();
        reg.create(human(1)).unwrap();
        assert_eq!(reg.get(sid(1)).unwrap().state(), SessionState::Active);

        let event = reg.transition(sid(1), Transition::End).unwrap();
        assert_eq!(event.to, SessionState::Ended);
        assert_eq!(reg.get(sid(1)), Err(CoreError::SessionNotFoundOrEnded));
        assert_eq!(reg.get(sid(2)), Err(CoreError::SessionNotFoundOrEnded));
        assert_eq!(
            reg.transition(sid(1), Transition::Resume),
            Err(CoreError::SessionNotFoundOrEnded)
        );
        assert_eq!(
            reg.transition(sid(1), Transition::End),
            Err(CoreError::SessionNotFoundOrEnded)
        );
        assert!(reg.is_empty());
    }

    #[test]
    fn registry_transitions_emit_and_refusals_keep_state() {
        let mut reg = SessionRegistry::new();
        reg.create(agent(1, "default", None)).unwrap();
        let event = reg.transition(sid(1), Transition::Pause).unwrap();
        assert_eq!((event.from, event.to), (SessionState::Active, SessionState::Paused));
        assert_eq!(
            reg.transition(sid(1), Transition::TakeControl),
            Err(CoreError::InvalidTransition {
                from: SessionState::Paused,
                transition: Transition::TakeControl
            })
        );
        assert_eq!(reg.get(sid(1)).unwrap().state(), SessionState::Paused);
    }

    #[test]
    fn duplicate_id_is_refused_and_keeps_the_original() {
        let mut reg = SessionRegistry::new();
        reg.create(human(1)).unwrap();
        assert_eq!(
            reg.create(agent(1, "default", None)).map(|_| ()),
            Err(CoreError::SessionExists)
        );
        assert_eq!(reg.get(sid(1)).unwrap().actor(), &Actor::Human);
        assert_eq!(reg.len(), 1);
    }

    // FR-SES-03: a child records its parent, which must be live when the child starts.
    #[test]
    fn child_records_live_parent() {
        let mut reg = SessionRegistry::new();
        reg.create(human(1)).unwrap();
        let child = reg.create(agent(2, "default", Some(1))).unwrap();
        assert_eq!(child.parent_session_id(), Some(sid(1)));

        assert_eq!(
            reg.create(agent(3, "default", Some(9))).map(|_| ()),
            Err(CoreError::ParentNotFoundOrEnded)
        );
        reg.transition(sid(1), Transition::End).unwrap();
        assert_eq!(
            reg.create(agent(4, "default", Some(1))).map(|_| ()),
            Err(CoreError::ParentNotFoundOrEnded)
        );
        assert_eq!(reg.len(), 1);
    }

    // FR-SES-03: agent children go through the profile-order hook; human children do not.
    #[test]
    fn agent_child_profile_goes_through_the_order_hook() {
        /// A two-step ordering standing in for the phase 2 policy model; unknown names are never stricter.
        struct Ranked;
        impl ProfileOrder for Ranked {
            fn at_least_as_strict(&self, child: &ProfileName, parent: &ProfileName) -> bool {
                let rank = |p: &ProfileName| ["loose", "strict"].iter().position(|n| *n == p.as_str());
                matches!((rank(child), rank(parent)), (Some(c), Some(p)) if c >= p)
            }
        }

        let mut reg = SessionRegistry::new();
        reg.create(agent(1, "web-app", None)).unwrap();
        assert!(reg.create(agent(2, "web-app", Some(1))).is_ok());
        assert_eq!(
            reg.create(agent(3, "other", Some(1))).map(|_| ()),
            Err(CoreError::ProfileNotStricter)
        );
        let mut human_child = human(4);
        human_child.parent_session_id = Some(sid(1));
        assert_eq!(
            reg.create(human_child).map(|_| ()),
            Err(CoreError::HumanChildOfAgent),
            "a human session must not start inside an agent session (FR-SES-12)"
        );
        reg.create(human(5)).unwrap();
        let mut human_of_human = human(6);
        human_of_human.parent_session_id = Some(sid(5));
        human_of_human.profile = profile("other");
        assert!(
            reg.create(human_of_human).is_ok(),
            "human children of humans are not checked"
        );

        let mut reg = SessionRegistry::with_order(Ranked);
        reg.create(agent(1, "loose", None)).unwrap();
        assert!(reg.create(agent(2, "strict", Some(1))).is_ok());
        assert_eq!(
            reg.create(agent(3, "loose", Some(2))).map(|_| ()),
            Err(CoreError::ProfileNotStricter)
        );
    }

    #[test]
    fn keeps_alive_while_an_envelope_or_recording_session_lives() {
        let mut reg = SessionRegistry::new();
        reg.create(human(1)).unwrap();
        assert!(
            !reg.keeps_alive(),
            "a human session with recording off keeps nothing alive (FR-SES-23)"
        );
        reg.create(agent(2, "default", None)).unwrap();
        assert!(reg.keeps_alive());
        reg.transition(sid(2), Transition::End).unwrap();
        assert!(!reg.keeps_alive());
        let mut recording = human(3);
        recording.recording = Some(true);
        reg.create(recording).unwrap();
        assert!(reg.keeps_alive());
    }
}
