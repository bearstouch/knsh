//! The authority's policy and grant methods on the control service: `policy.set`, `policy.get`, `policy.grant`,
//! `policy.grants` and `policy.revoke` (KNSH-071; FR-POL-01, FR-POL-50, FR-POL-53, FR-POL-60 to FR-POL-62;
//! `specs/06-api/control-service.md#policy`).
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
//! # Errors
//!
//! Malformed params are `-32602`; a clock, random source or state store that fails is `-32603`. Nothing logged here
//! holds a profile's text or a rule.

use std::sync::Arc;

use knsh_core::{
    EngineEventData, Grant, GrantId, GrantScope, LookupError, ProfileSource, Timestamp, UNATTENDED_PROFILE, Ulid,
};
use knsh_platform::{Clock, Field, Level, Random, SystemLog, Value};
use knsh_proto::{
    ErrorCode, GrantEntry, GrantTargetParam, NoParams, PolicyGetParams, PolicyGetResult, PolicyGrantParams,
    PolicyGrantResult, PolicyGrantsResult, PolicyRevokeParams, PolicyRevokeResult, PolicySetParams, PolicySetResult,
    PolicySource, RpcError,
};

use crate::dispatch::{Call, Handler, Handlers, Reply, answer, params};
use crate::events::EventHub;
use crate::expiry::PolicyExpiry;
use crate::grants::{GrantError, GrantStore};
use crate::policy::ProfileLoader;
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
    log: Arc<dyn SystemLog>,
}

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
            log,
        })
    }

    /// Every handler, by method name.
    pub(crate) fn handlers(self: &Arc<Self>) -> Handlers {
        [
            ("policy.set", self.handler(Self::set)),
            ("policy.get", self.handler(Self::get)),
            ("policy.grant", self.handler(Self::grant)),
            ("policy.grants", self.handler(Self::list_grants)),
            ("policy.revoke", self.handler(Self::revoke)),
        ]
        .into_iter()
        .collect()
    }

    /// A handler running `method` on its own reference to the service, for control-service calls only.
    fn handler(self: &Arc<Self>, method: fn(&Self, &Call<'_>) -> Reply) -> Handler {
        let admin = Arc::clone(self);
        Arc::new(move |call: &Call<'_>| {
            // The catalogue lists these on the control service only; checked again here (the user's Touch ID
            // `policy.grant` is KNSH-073's and goes through its own handler).
            control_only(call)?;
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

    /// `policy.grant` (module documentation, "Grants").
    fn grant(&self, call: &Call<'_>) -> Reply {
        let PolicyGrantParams {
            target,
            rule,
            duration_s,
        } = params(call)?;
        let scope = match target {
            GrantTargetParam::Session(session_id) => {
                // A live agent session: a grant for a human session would never be consulted (FR-SES-22).
                self.sessions.agent_session(session_id)?;
                GrantScope::Session(session_id)
            }
            GrantTargetParam::Profile(profile) => GrantScope::Profile(profile),
        };
        let now = self.now()?;
        let expires_at = duration_s
            .checked_mul(1_000_000)
            .and_then(|micros| now.as_unix_micros().checked_add(micros))
            .and_then(|micros| Timestamp::from_unix_micros(micros).ok())
            .ok_or_else(internal_error)?;
        let grant_id = GrantId::from_ulid(self.ulid(now)?);
        // A rule that is not a command pattern (blank, naming a path) is the caller's mistake.
        let grant =
            Grant::new(grant_id, scope, &rule, expires_at).map_err(|_| RpcError::new(ErrorCode::InvalidParams))?;
        self.grants.insert(grant, now).map_err(|error| match error {
            // Too many grants, or (never expected with a fresh ID) one with this ID.
            GrantError::Refused(_) => RpcError::new(ErrorCode::InvalidParams),
            GrantError::NotSaved(_) => internal_error(),
        })?;
        self.log.log(
            Level::Notice,
            "grant created by the authority",
            &[Field::new("event", Value::Static("policy.grant"))],
        );
        answer(&PolicyGrantResult { grant_id, expires_at })
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
