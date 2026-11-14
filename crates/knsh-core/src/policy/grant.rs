//! Grants: time-limited rules on top of a profile (KNSH-042; FR-POL-60, FR-POL-61; `specs/05-models/grant.md`).
//!
//! A [`Grant`] ("allow `git push` in this session for one hour") has an ID, a [`GrantScope`] naming the one session or
//! the one profile it applies to, a command `rule` and an `expires_at`. [`GrantSet`] holds the live grants and lists
//! (`policy.grants`) and revokes (`policy.revoke`) them; [`evaluate_line_with_grants`](super::evaluate_line_with_grants)
//! applies them to a line.
//!
//! # What a grant does
//!
//! A grant only ever answers an `ask`: a line the profile asks about is allowed, with source
//! [`DecisionSource::Grant`](super::DecisionSource::Grant), when **every** part that asks is a command a live grant
//! covers. It never changes a part the profile allows or denies, so a `deny` anywhere in the line still denies it, and
//! it never touches what the line may receive: dynamic code keeps its clamps (FR-POL-20, FR-POL-21) and the fixed
//! denies (FR-POL-30) stay in the sandbox profile, which grants do not reach.
//!
//! A grant's rule is a command pattern read like an `exec.allow` entry (KNSH-040), and it must match the command
//! **whatever** its unknown arguments turn out to be, as an allow rule must: a grant for `git push` covers
//! `git push origin main` but not `git $X`. A part with no command of its own (a line the parser could not read, a
//! construct such as `[[ … ]]`) can never be covered.
//!
//! # Time
//!
//! `knsh-core` does no I/O, so every operation that depends on expiry takes `now`, which `knshd` reads from the
//! injected `knsh_platform::Clock`. A grant applies while `now < expires_at`: from `expires_at` on it never matches,
//! is never listed and can no longer be revoked (it is already gone). If the clock cannot be read, the caller must
//! not apply grants, so an ask stays an ask (fail closed).
//!
//! Creation is authorised elsewhere: only the authority, or the user with Touch ID, may create grants (FR-POL-62,
//! KNSH-071, KNSH-073). Persistence in `knshd`'s state store is KNSH-074's.

use std::collections::BTreeMap;

use knsh_bash::ClassifiedCommand;

use super::layer::is_pattern;
use super::rules::matches_certainly;
use crate::error::CoreError;
use crate::id::{GrantId, SessionId};
use crate::session::ProfileName;
use crate::time::Timestamp;

/// Most grants a [`GrantSet`] holds at once. Bounds the memory and the per-line matching work grants can cause; an
/// authority that needs more is scoping them too broadly or too long.
pub const MAX_GRANTS: usize = 1024;

/// What a grant applies to (`scope` in `specs/05-models/grant.md`).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum GrantScope {
    /// `session`: only lines of this session.
    Session(SessionId),
    /// `profile`: lines of every session running under this profile.
    Profile(ProfileName),
}

impl GrantScope {
    /// The spelling of the scope's kind in the API: `session` or `profile`.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Session(_) => "session",
            Self::Profile(_) => "profile",
        }
    }

    /// Whether this scope covers a line of `session`, which runs under `profile`.
    fn covers(&self, session: SessionId, profile: &ProfileName) -> bool {
        match self {
            Self::Session(scoped) => *scoped == session,
            Self::Profile(scoped) => scoped == profile,
        }
    }
}

/// One grant (module documentation).
///
/// # Invariants
///
/// `rule` is a valid command pattern, as the profile loader accepts in `exec.allow`: non-empty, bounded, free of
/// control characters, with a first word naming a program rather than a path. The fields are private so the rule
/// cannot be replaced by one that was never checked.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Grant {
    id: GrantId,
    scope: GrantScope,
    rule: String,
    expires_at: Timestamp,
}

impl Grant {
    /// Builds a grant, checking its rule.
    ///
    /// # Errors
    ///
    /// [`CoreError::InvalidGrantRule`] if `rule` is not a command pattern (see the type's invariants). A blank rule or
    /// a path would never match anything, and a grant that silently does nothing hides the mistake.
    pub fn new(id: GrantId, scope: GrantScope, rule: &str, expires_at: Timestamp) -> Result<Self, CoreError> {
        if !is_pattern(rule) {
            return Err(CoreError::InvalidGrantRule);
        }
        Ok(Self {
            id,
            scope,
            rule: rule.to_owned(),
            expires_at,
        })
    }

    /// The grant's ID, used with `policy.revoke`.
    #[must_use]
    pub const fn id(&self) -> GrantId {
        self.id
    }

    /// What the grant applies to.
    #[must_use]
    pub const fn scope(&self) -> &GrantScope {
        &self.scope
    }

    /// The command pattern the grant allows.
    #[must_use]
    pub fn rule(&self) -> &str {
        &self.rule
    }

    /// The first instant at which the grant no longer applies.
    #[must_use]
    pub const fn expires_at(&self) -> Timestamp {
        self.expires_at
    }

    /// Whether the grant has expired at `now` (module documentation, "Time").
    #[must_use]
    pub fn is_expired(&self, now: Timestamp) -> bool {
        now >= self.expires_at
    }

    /// Whether the grant covers `command` in `session`, running under `profile`, at `now`: unexpired, in scope, and
    /// with a rule that certainly matches the command.
    fn covers(&self, session: SessionId, profile: &ProfileName, command: &ClassifiedCommand, now: Timestamp) -> bool {
        !self.is_expired(now) && self.scope.covers(session, profile) && matches_certainly(&self.rule, command)
    }
}

/// The live grants, keyed by ID (module documentation). Expired grants are dropped whenever the set is changed, and
/// are ignored everywhere before that.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GrantSet {
    // A map ordered by ID: ULIDs order by creation time, so listing is oldest first and deterministic.
    grants: BTreeMap<GrantId, Grant>,
}

impl GrantSet {
    /// An empty set.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds `grant`, first dropping every grant expired at `now`.
    ///
    /// # Errors
    ///
    /// Leaves the set's live grants unchanged and returns:
    ///
    /// - [`CoreError::GrantExpired`] if `grant` has already expired at `now`: it could never apply.
    /// - [`CoreError::GrantExists`] if a live grant already has its ID; a grant is never silently replaced.
    /// - [`CoreError::TooManyGrants`] if the set already holds [`MAX_GRANTS`] live grants.
    pub fn insert(&mut self, grant: Grant, now: Timestamp) -> Result<(), CoreError> {
        if grant.is_expired(now) {
            return Err(CoreError::GrantExpired);
        }
        self.prune(now);
        if self.grants.contains_key(&grant.id) {
            return Err(CoreError::GrantExists);
        }
        if self.grants.len() >= MAX_GRANTS {
            return Err(CoreError::TooManyGrants);
        }
        self.grants.insert(grant.id, grant);
        Ok(())
    }

    /// Removes the grant `id` (`policy.revoke`), first dropping every grant expired at `now`. The grant stops
    /// matching immediately: the next evaluation no longer sees it.
    ///
    /// # Errors
    ///
    /// [`CoreError::GrantNotFound`] if no live grant has this ID: it never existed, was revoked, or has expired.
    pub fn revoke(&mut self, id: GrantId, now: Timestamp) -> Result<Grant, CoreError> {
        self.prune(now);
        self.grants.remove(&id).ok_or(CoreError::GrantNotFound)
    }

    /// The grants live at `now` (`policy.grants`), oldest first.
    pub fn list(&self, now: Timestamp) -> impl Iterator<Item = &Grant> {
        self.grants.values().filter(move |grant| !grant.is_expired(now))
    }

    /// Drops every grant expired at `now` and returns how many were dropped.
    pub fn prune(&mut self, now: Timestamp) -> usize {
        let before = self.grants.len();
        self.grants.retain(|_, grant| !grant.is_expired(now));
        before - self.grants.len()
    }

    /// The oldest grant live at `now` that covers `command` in `session`, running under `profile`.
    pub(crate) fn covering(
        &self,
        session: SessionId,
        profile: &ProfileName,
        command: &ClassifiedCommand,
        now: Timestamp,
    ) -> Option<&Grant> {
        self.grants
            .values()
            .find(|grant| grant.covers(session, profile, command, now))
    }
}

#[cfg(test)]
mod tests;
