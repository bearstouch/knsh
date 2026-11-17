//! The policy and grant methods: `policy.set` and `policy.get` for the authority on the control service, and
//! `policy.grant`, `policy.grants` and `policy.revoke` for the authority and for the user on `user.sock` (KNSH-071,
//! KNSH-073; FR-POL-01, FR-POL-50, FR-POL-53, FR-POL-60 to FR-POL-62, NFR-SEC-04;
//! `specs/06-api/control-service.md#policy`, `specs/06-api/user-socket.md#grants`).
//!
//! # `policy.set`
//!
//! The snapshot is checked with the loader policy files go through (FR-POL-01), as it would load once stored: its
//! `extends` chain is read from the other pushed snapshots and the signed files. A snapshot that does not load, is
//! already expired, or names the built-in `unattended` profile is `-32602` and nothing changes. Otherwise it is saved
//! to the state store, takes the place of any earlier snapshot and of the file of its name ([`crate::pushed`]), and
//! `policy.updated` is published (FR-POL-53). Lines decided from then on load it; an envelope already running keeps
//! the sandbox profile it was started with. Agent sessions paused because their snapshot had expired resume if their
//! profile loads again (`crate::expiry`, KNSH-072).
//!
//! # Grants
//!
//! `policy.grant` makes a grant (FR-POL-62) for a live agent session or for a profile, lasting `duration_s` from now,
//! with a rule read like an `exec.allow` entry. It is saved before it applies (FR-POL-60); one that cannot be saved is
//! not made (`-32603`). `policy.grants` lists the live grants, authority's and answers' alike, and `policy.revoke`
//! removes one at once (FR-POL-61).
//!
//! The authority is trusted to decide (it was verified on the control service). On `user.sock` the caller may be any
//! of the user's processes, so `policy.grant` there first checks everything the authority's would (the scope, the
//! rule) and then has `knshd` show the Touch ID or password prompt itself (FR-POL-62, NFR-SEC-04): `grant the agent
//! command rule: <rule> (session <id> | profile <name>, for <duration>)`. Any outcome but success is `-32001` with
//! `source: "user"` and nothing is created; no parameter skips the prompt. After the prompt the scope is checked
//! again (the session may have ended meanwhile) and the grant lasts `duration_s` from then, not from the request.
//! The grants the user makes are the same as the authority's: listed by `policy.grants` and revoked by
//! `policy.revoke` on either endpoint. Neither of those needs authentication: listing changes nothing, and a
//! revocation only removes a permission. None of the three is ever on `agent.sock` (`-32003`): an agent can never
//! widen its own policy.
//!
//! # Errors
//!
//! Malformed params are `-32602`; a clock, random source or state store that fails is `-32603`. Nothing logged here
//! holds a profile's text or a rule.

use std::sync::Arc;

use knsh_core::{
    EngineEventData, Grant, GrantId, GrantScope, LookupError, ProfileSource, Timestamp, UNATTENDED_PROFILE, Ulid,
};
use knsh_platform::{Clock, Field, Level, PromptReason, Random, SystemLog, UserPresence, Value};
use knsh_proto::{
    ErrorCode, GrantEntry, GrantTargetParam, NoParams, PolicyGetParams, PolicyGetResult, PolicyGrantParams,
    PolicyGrantResult, PolicyGrantsResult, PolicyRevokeParams, PolicyRevokeResult, PolicySetParams, PolicySetResult,
    PolicySource, RpcError, grant_duration_text,
};

use crate::dispatch::{Call, Endpoint, Handler, Handlers, Reply, answer, params};
use crate::events::EventHub;
use crate::expiry::PolicyExpiry;
use crate::grants::{GrantError, GrantStore};
use crate::policy::ProfileLoader;
use crate::policy_edit::{EDIT_PROMPT_TIMEOUT, not_authenticated};
use crate::pushed::{PushError, PushedPolicies, Snapshot};
use crate::sessions::Sessions;
use crate::supervise::control_only;

/// The authority's policy and grant methods.
pub(crate) struct PolicyAdmin {
    /// Loads and checks profiles; reads pushed snapshots before files.
    profiles: ProfileLoader,
    pushed: Arc<PushedPolicies>,
    grants: Arc<GrantStore>,
    sessions: Arc<Sessions>,
    events: Arc<EventHub>,
    /// Resumes the sessions a new snapshot lets load again (KNSH-072).
    expiry: Arc<PolicyExpiry>,
    clock: Arc<dyn Clock>,
    random: Arc<dyn Random>,
    /// The Touch ID or password prompt for the user's `policy.grant`, shown by `knshd` itself (KNSH-073).
    presence: Arc<dyn UserPresence>,
    log: Arc<dyn SystemLog>,
}

/// How long the user's `policy.grant` prompt waits: as long as `knsh policy edit`'s, shorter than the CLI's read
/// timeout, so the CLI always gets the answer.
pub(crate) const GRANT_PROMPT_TIMEOUT: std::time::Duration = EDIT_PROMPT_TIMEOUT;

/// What [`PolicyAdmin`] is built from.
pub(crate) struct PolicyAdminParts {
    /// The loader, reading `pushed` before files.
    pub(crate) profiles: ProfileLoader,
    /// The pushed snapshots.
    pub(crate) pushed: Arc<PushedPolicies>,
    /// The live grants.
    pub(crate) grants: Arc<GrantStore>,
    /// The live sessions, for session-scoped grants.
    pub(crate) sessions: Arc<Sessions>,
    /// Where `policy.updated` is published.
    pub(crate) events: Arc<EventHub>,
    /// The sessions paused by expired pushed policy, resumed by a snapshot they load with (KNSH-072).
    pub(crate) expiry: Arc<PolicyExpiry>,
    /// Expiry and grant IDs.
    pub(crate) clock: Arc<dyn Clock>,
    /// Grant IDs.
    pub(crate) random: Arc<dyn Random>,
    /// The prompt for the user's grants on `user.sock`.
    pub(crate) presence: Arc<dyn UserPresence>,
    /// Fixed reasons only.
    pub(crate) log: Arc<dyn SystemLog>,
}

impl PolicyAdmin {
    /// The methods over `parts`.
    pub(crate) fn new(parts: PolicyAdminParts) -> Arc<Self> {
        let PolicyAdminParts {
            profiles,
            pushed,
            grants,
            sessions,
            events,
            expiry,
            clock,
            random,
            presence,
            log,
        } = parts;
        Arc::new(Self {
            profiles,
            pushed,
            grants,
            sessions,
            events,
            expiry,
            clock,
            random,
            presence,
            log,
        })
    }

    /// Every handler, by method name.
    pub(crate) fn handlers(self: &Arc<Self>) -> Handlers {
        [
            ("policy.set", self.handler(control_only, Self::set)),
            ("policy.get", self.handler(control_only, Self::get)),
            ("policy.grant", self.handler(not_agent, Self::grant)),
            ("policy.grants", self.handler(not_agent, Self::list_grants)),
            ("policy.revoke", self.handler(not_agent, Self::revoke)),
        ]
        .into_iter()
        .collect()
    }

    /// A handler running `method` on its own reference to the service once `allowed` accepts the call's endpoint.
    /// The catalogue already keeps each method off the other endpoints; this is the second lock on the door.
    fn handler(
        self: &Arc<Self>,
        allowed: fn(&Call<'_>) -> Result<(), RpcError>,
        method: fn(&Self, &Call<'_>) -> Reply,
    ) -> Handler {
        let admin = Arc::clone(self);
        Arc::new(move |call: &Call<'_>| {
            allowed(call)?;
            method(&admin, call)
        })
    }

    /// The current wall time, or `-32603`.
    fn now(&self) -> Result<Timestamp, RpcError> {
        self.clock.now().map_err(|_| internal_error())
    }

    /// `policy.set` (module documentation).
    fn set(&self, call: &Call<'_>) -> Reply {
        let PolicySetParams {
            profile,
            policy,
            expires_at,
        } = params(call)?;
        // The built-in profile is the engine's own, never replaced (FR-POL-03); and a snapshot already expired could
        // never apply (FR-POL-50).
        if profile.as_str() == UNATTENDED_PROFILE || expires_at <= self.now()? {
            return Err(RpcError::new(ErrorCode::InvalidParams));
        }
        let snapshot = Snapshot {
            profile: profile.clone(),
            policy,
            expires_at,
        };
        if self.profiles.check_snapshot(snapshot.clone()).is_err() {
            self.log
                .log(Level::Notice, "pushed policy refused: it does not load", &[]);
            return Err(RpcError::new(ErrorCode::InvalidParams));
        }
        let replaced = self.pushed.set(snapshot).map_err(|error| match error {
            PushError::Full => RpcError::new(ErrorCode::InvalidParams),
            PushError::NotSaved(_) => internal_error(),
        })?;
        // FR-POL-53. Best effort, like every event: the snapshot is stored and applies whether or not it was heard.
        let _ = self
            .events
            .publish_engine(EngineEventData::PolicyUpdated { profile, expires_at });
        // FR-POL-51: the authority is back; sessions paused because their snapshot expired resume if they load now.
        self.expiry.snapshot_pushed();
        answer(&PolicySetResult { replaced })
    }

    /// `policy.get`: where a profile name loads from now, and its text.
    fn get(&self, call: &Call<'_>) -> Reply {
        let PolicyGetParams { profile } = params(call)?;
        if profile.as_str() == UNATTENDED_PROFILE {
            return answer(&PolicyGetResult {
                profile,
                source: PolicySource::Builtin,
                policy: None,
                expires_at: None,
                expired: false,
            });
        }
        if let Some(snapshot) = self.pushed.get(&profile) {
            // A clock that cannot be read counts as expired, as it does for loading.
            let expired = self.pushed.now().is_none_or(|now| now >= snapshot.expires_at);
            return answer(&PolicyGetResult {
                profile,
                source: PolicySource::Pushed,
                policy: Some(snapshot.policy),
                expires_at: Some(snapshot.expires_at),
                expired,
            });
        }
        let body = self
            .profiles
            .directory()
            .read_profile(&profile)
            .map_err(|error| match error {
                LookupError::NotFound => RpcError::new(ErrorCode::InvalidParams),
                LookupError::Failed | LookupError::SignatureInvalid => internal_error(),
            })?;
        let policy = String::from_utf8(body).map_err(|_| internal_error())?;
        answer(&PolicyGetResult {
            profile,
            source: PolicySource::File,
            policy: Some(policy),
            expires_at: None,
            expired: false,
        })
    }

    /// `policy.grant` (module documentation, "Grants"): made at once for the authority, after the prompt for the user.
    fn grant(&self, call: &Call<'_>) -> Reply {
        let PolicyGrantParams {
            target,
            rule,
            duration_s,
        } = params(call)?;
        let scope = self.scope(&target)?;
        let (grant, now) = match call.endpoint {
            Endpoint::Control => self.make_grant(scope, &rule, duration_s)?,
            Endpoint::User => self.user_grant(scope, &rule, duration_s)?,
            // Refused by the handler already (`not_agent`); never served, whatever the catalogue says.
            Endpoint::Agent => return Err(RpcError::new(ErrorCode::NotAllowed)),
        };
        let (grant_id, expires_at) = (grant.id(), grant.expires_at());
        self.grants.insert(grant, now).map_err(|error| match error {
            // Too many grants, or (never expected with a fresh ID) one with this ID.
            GrantError::Refused(_) => RpcError::new(ErrorCode::InvalidParams),
            GrantError::NotSaved(_) => internal_error(),
        })?;
        let message = match call.endpoint {
            Endpoint::User => "grant created by the user after authentication",
            Endpoint::Control | Endpoint::Agent => "grant created by the authority",
        };
        self.log.log(
            Level::Notice,
            message,
            &[Field::new("event", Value::Static("policy.grant"))],
        );
        answer(&PolicyGrantResult { grant_id, expires_at })
    }

    /// The user's grant on `user.sock` (FR-POL-62, NFR-SEC-04): checked in full before the prompt, so nothing the
    /// engine would refuse is ever put to the user, then made only after the prompt succeeds.
    fn user_grant(&self, scope: GrantScope, rule: &str, duration_s: u64) -> Result<(Grant, Timestamp), RpcError> {
        // A rule that is not a command pattern is refused here, without a prompt. The grant itself is made again
        // after the prompt, so that it lasts `duration_s` from when the user agreed.
        let _ = self.make_grant(scope.clone(), rule, duration_s)?;
        let reason = PromptReason::change("grant the agent command rule", &prompt_detail(&scope, rule, duration_s));
        let _proof = self
            .presence
            .authenticate(&reason, GRANT_PROMPT_TIMEOUT)
            .map_err(|refusal| {
                self.log
                    .log(Level::Notice, "user grant refused: not authenticated", &[]);
                not_authenticated(&refusal)
            })?;
        // The session may have ended while the prompt was up: a grant for it would never be consulted.
        if let GrantScope::Session(session_id) = &scope {
            self.sessions.agent_session(*session_id)?;
        }
        self.make_grant(scope, rule, duration_s)
    }

    /// What a grant applies to: a live agent session, or a profile by name.
    ///
    /// # Errors
    ///
    /// `-32006` for a session that is not live, `-32003` for a human one ([`Sessions::agent_session`]).
    fn scope(&self, target: &GrantTargetParam) -> Result<GrantScope, RpcError> {
        match target {
            GrantTargetParam::Session(session_id) => {
                // A live agent session: a grant for a human session would never be consulted (FR-SES-22).
                self.sessions.agent_session(*session_id)?;
                Ok(GrantScope::Session(*session_id))
            }
            GrantTargetParam::Profile(profile) => Ok(GrantScope::Profile(profile.clone())),
        }
    }

    /// A new grant for `scope` and `rule`, with a fresh ID, expiring `duration_s` from now; and that now.
    ///
    /// # Errors
    ///
    /// `-32602` for a rule that is not a command pattern (blank, naming a path): the caller's mistake. `-32603` when
    /// the clock or the random source fails, or the expiry is out of range.
    fn make_grant(&self, scope: GrantScope, rule: &str, duration_s: u64) -> Result<(Grant, Timestamp), RpcError> {
        let now = self.now()?;
        let expires_at = duration_s
            .checked_mul(1_000_000)
            .and_then(|micros| now.as_unix_micros().checked_add(micros))
            .and_then(|micros| Timestamp::from_unix_micros(micros).ok())
            .ok_or_else(internal_error)?;
        let grant_id = GrantId::from_ulid(self.ulid(now)?);
        let grant =
            Grant::new(grant_id, scope, rule, expires_at).map_err(|_| RpcError::new(ErrorCode::InvalidParams))?;
        Ok((grant, now))
    }

    /// `policy.grants`: every live grant.
    fn list_grants(&self, call: &Call<'_>) -> Reply {
        let NoParams = params(call)?;
        let now = self.now()?;
        let grants = self.grants.list(now).iter().map(entry).collect();
        answer(&PolicyGrantsResult { grants })
    }

    /// `policy.revoke`: removes a live grant at once.
    fn revoke(&self, call: &Call<'_>) -> Reply {
        let PolicyRevokeParams { grant_id } = params(call)?;
        let now = self.now()?;
        let revoked = self.grants.revoke(grant_id, now).is_some();
        answer(&PolicyRevokeResult { revoked })
    }

    /// A fresh ULID stamped `now`.
    fn ulid(&self, now: Timestamp) -> Result<Ulid, RpcError> {
        let mut random = [0; 10];
        self.random.fill(&mut random).map_err(|_| internal_error())?;
        Ulid::new(now.as_unix_millis(), random).map_err(|_| internal_error())
    }
}

/// `-32003` on `agent.sock`: grants are made, listed and revoked by the authority or the user only (FR-POL-62).
fn not_agent(call: &Call<'_>) -> Result<(), RpcError> {
    match call.endpoint {
        Endpoint::User | Endpoint::Control => Ok(()),
        Endpoint::Agent => Err(RpcError::new(ErrorCode::NotAllowed)),
    }
}

/// What the user's prompt names after its action (`grant the agent command rule: …`): the rule as given, its scope
/// and how long it lasts, e.g. `git push (profile web, for 1h 30m)`. The rule is escaped by [`PromptReason::change`].
fn prompt_detail(scope: &GrantScope, rule: &str, duration_s: u64) -> String {
    // Session IDs are ULIDs and profile names `[A-Za-z0-9._-]`: neither needs escaping.
    let target = match scope {
        GrantScope::Session(session_id) => format!("session {session_id}"),
        GrantScope::Profile(profile) => format!("profile {profile}"),
    };
    format!("{rule} ({target}, for {})", grant_duration_text(duration_s))
}

/// One grant as `policy.grants` lists it.
fn entry(grant: &Grant) -> GrantEntry {
    let target = match grant.scope() {
        GrantScope::Session(session_id) => GrantTargetParam::Session(*session_id),
        GrantScope::Profile(profile) => GrantTargetParam::Profile(profile.clone()),
    };
    GrantEntry {
        grant_id: grant.id(),
        target,
        rule: grant.rule().to_owned(),
        exact: grant.is_exact(),
        expires_at: grant.expires_at(),
    }
}

fn internal_error() -> RpcError {
    RpcError::new(ErrorCode::InternalError)
}

#[cfg(test)]
mod tests;
