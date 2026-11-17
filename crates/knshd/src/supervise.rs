//! The authority's session methods on the control service: `session.create`, `session.end`, `session.pause`,
//! `session.resume`, `session.take_control`, `session.release_control`, `session.list` and `recording.set` (KNSH-071;
//! FR-SES-02, FR-SES-10, FR-SES-12, FR-SES-14, FR-SES-25; `specs/06-api/control-service.md#sessions`).
//!
//! Each one is the session registry's own operation ([`Sessions`]), so a session paused from here behaves exactly
//! as KNSH-054 specifies: its kept process groups get `SIGSTOP`, new lines are held with `-32007`, and
//! `session.state_changed` is published.
//!
//! # Agent sessions only
//!
//! The authority supervises agents. Every method that acts on one session refuses a human session with `-32003`:
//! nothing in a human session may be blocked (FR-SES-22), a human session ends only with its own connection, and a
//! human's recording is the human's choice (FR-SES-04). `session.list` lists every live session, human ones
//! included, since it only reads.
//!
//! # Errors
//!
//! Malformed params are `-32602`. A session that is not live is `-32006` naming it, as is a move the state diagram
//! does not have (pausing a paused session). For `session.create`, a profile that does not exist is `-32602` and one
//! that does not load (invalid, a bad signature, an expired snapshot) is `-32603`; nothing is created then.
//!
//! The methods are served on the control service only: the catalogue lists them nowhere else, and each handler checks
//! the endpoint again.

use std::sync::Arc;

use knsh_core::{Actor, ProfileErrorKind, ProfileOrigin, SessionState};
use knsh_proto::{
    ErrorCode, NoParams, RecordingSetParams, RpcError, SessionCreateParams, SessionCreateResult, SessionListResult,
    SessionStateResult, SessionTargetParams,
};

use crate::dispatch::{Call, Endpoint, Handler, Handlers, Reply, answer, params};
use crate::policy::ProfileLoader;
use crate::sessions::{Sessions, StateChange};

/// The authority's session methods.
pub(crate) struct Supervise {
    sessions: Arc<Sessions>,
    /// Checks that a new session's profile loads before the session exists.
    profiles: ProfileLoader,
}

impl Supervise {
    /// The methods over `sessions`, checking new sessions' profiles with `profiles`.
    pub(crate) fn new(sessions: Arc<Sessions>, profiles: ProfileLoader) -> Arc<Self> {
        Arc::new(Self { sessions, profiles })
    }

    /// Every handler, by method name.
    pub(crate) fn handlers(self: &Arc<Self>) -> Handlers {
        let change = |change: StateChange| self.handler(move |supervise, call| supervise.change(call, change));
        [
            ("session.create", self.handler(Self::create)),
            ("session.end", self.handler(Self::end)),
            ("session.pause", change(StateChange::Pause)),
            ("session.resume", change(StateChange::Resume)),
            ("session.take_control", change(StateChange::TakeControl)),
            ("session.release_control", change(StateChange::HandBack)),
            ("session.list", self.handler(Self::list)),
            ("recording.set", self.handler(Self::recording)),
        ]
        .into_iter()
        .collect()
    }

    /// A handler running `method` on its own reference to the service.
    fn handler(self: &Arc<Self>, method: impl Fn(&Self, &Call<'_>) -> Reply + Send + Sync + 'static) -> Handler {
        let supervise = Arc::clone(self);
        Arc::new(move |call: &Call<'_>| {
            control_only(call)?;
            method(&supervise, call)
        })
    }

    /// `session.create`: an agent session with no envelope, for an agent the authority starts itself; its token is
    /// returned for that agent's `hello` (FR-SES-02).
    fn create(&self, call: &Call<'_>) -> Reply {
        let SessionCreateParams { agent, profile } = params(call)?;
        // The profile must load now, as the session's first line will load it, so a session never exists for a
        // profile that cannot decide anything. Paths resolve from the home directory, as for `policy.set`.
        self.profiles.load(&profile, self.profiles.home()).map_err(|error| {
            let missing = *error.kind() == ProfileErrorKind::ProfileNotFound
                && error.origin() == Some(&ProfileOrigin::Profile(profile.clone()));
            RpcError::new(if missing {
                ErrorCode::InvalidParams
            } else {
                ErrorCode::InternalError
            })
        })?;
        let opened = self.sessions.create_agent(Actor::Agent(agent), profile)?;
        answer(&SessionCreateResult {
            session_id: opened.session_id,
            session_token: opened.token.encode().expose().clone(),
        })
    }

    /// `session.end`: ends a live agent session; its envelopes get `SIGTERM`.
    fn end(&self, call: &Call<'_>) -> Reply {
        let SessionTargetParams { session_id } = params(call)?;
        self.sessions.end_for_authority(session_id)?;
        answer(&SessionStateResult {
            session_id,
            state: SessionState::Ended,
        })
    }

    /// `session.pause`, `session.resume`, `session.take_control` and `session.release_control`.
    fn change(&self, call: &Call<'_>, change: StateChange) -> Reply {
        let SessionTargetParams { session_id } = params(call)?;
        self.sessions.agent_session(session_id)?;
        let state = self.sessions.change_state(session_id, change)?;
        answer(&SessionStateResult { session_id, state })
    }

    /// `session.list`: every live session.
    fn list(&self, call: &Call<'_>) -> Reply {
        let NoParams = params(call)?;
        answer(&SessionListResult {
            sessions: self.sessions.list(),
        })
    }

    /// `recording.set`: changes what an agent session records; answered with the session as `session.info` shows it.
    fn recording(&self, call: &Call<'_>) -> Reply {
        let RecordingSetParams {
            session_id,
            commands,
            output,
        } = params(call)?;
        answer(&self.sessions.set_recording(session_id, commands, output)?)
    }
}

/// Refuses a call that did not come through the control service: the trusted, verified authority only.
pub(crate) fn control_only(call: &Call<'_>) -> Result<(), RpcError> {
    match call.endpoint {
        Endpoint::Control => Ok(()),
        Endpoint::User | Endpoint::Agent => Err(RpcError::new(ErrorCode::NotAllowed)),
    }
}

#[cfg(test)]
pub(crate) mod tests;
