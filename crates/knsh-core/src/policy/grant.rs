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
//! KNSH-071, KNSH-073). `knshd` keeps them in its state store (KNSH-071).
//!
//! # A grant from an answer
//!
//! A `grant` in `decision.respond` (KNSH-069) names only a scope and a duration: its rule is the asked line itself,
//! read by [`line_grant_rule`]. Only a line that is one simple command whose every word is known can be written as a
//! rule; anything else gets no grant rather than one that covers more than was asked about. Such a grant is
//! [exact](Grant::exact): it covers the command with exactly the asked arguments, not the same command with more
//! (no FR-POL-16 extension), so a grant for `rm -r build` never covers `rm -r build /`.

use std::collections::BTreeMap;

use knsh_bash::{Classification, ClassifiedCommand};

use super::layer::is_pattern;
use super::rules::{matches_certainly, matches_exactly};
use crate::error::CoreError;
use crate::id::{GrantId, SessionId};
use crate::lifecycle::redact;
use crate::redacted::holds_redaction_marker;
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
    /// Whether the rule matches only the command with exactly its arguments ([`Grant::exact`]).
    exact: bool,
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
        Self::build(id, scope, rule, false, expires_at)
    }

    /// Builds an exact grant: its rule matches the command with exactly the rule's arguments, never with more (no
    /// FR-POL-16 extension). Made from one asked line ([`line_grant_rule`], KNSH-069), so it covers that line and
    /// not a longer one the authority was never shown.
    ///
    /// # Errors
    ///
    /// As [`Grant::new`].
    pub fn exact(id: GrantId, scope: GrantScope, rule: &str, expires_at: Timestamp) -> Result<Self, CoreError> {
        Self::build(id, scope, rule, true, expires_at)
    }

    fn build(
        id: GrantId,
        scope: GrantScope,
        rule: &str,
        exact: bool,
        expires_at: Timestamp,
    ) -> Result<Self, CoreError> {
        if !is_pattern(rule) {
            return Err(CoreError::InvalidGrantRule);
        }
        Ok(Self {
            id,
            scope,
            rule: rule.to_owned(),
            exact,
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

    /// Whether the rule matches only the command with exactly its arguments ([`Grant::exact`]).
    #[must_use]
    pub const fn is_exact(&self) -> bool {
        self.exact
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
        let matches = if self.exact {
            matches_exactly(&self.rule, command)
        } else {
            matches_certainly(&self.rule, command)
        };
        !self.is_expired(now) && self.scope.covers(session, profile) && matches
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

/// The rule a grant made from an answer to `classification`'s line gets (module documentation, "A grant from an
/// answer"), or `None` when the line cannot be written as one.
///
/// The rule is the command's name and arguments as written, joined by single spaces. `None` unless:
///
/// - the line was parsed and is exactly one simple command, with no wrapper, substitution or other dynamic part, so
///   the rule names everything the line runs;
/// - every word is known (no expansion), non-empty, and holds no whitespace or `*`: a pattern splits on spaces and
///   reads `*` as a wildcard, so such a word would make the rule match other commands;
/// - the text holds no secret: redaction leaves it unchanged, since grants are listed and stored;
/// - it is a valid command pattern (a name without `/`, no control characters, bounded length).
///
/// Use it with [`Grant::exact`], so the grant covers the same command with more arguments only if asked again.
#[must_use]
pub fn line_grant_rule(classification: &Classification) -> Option<String> {
    if classification.is_whole_line() || !classification.dynamic_parts().is_empty() {
        return None;
    }
    let [command] = classification.commands() else {
        return None;
    };
    if !command.arguments_complete {
        return None;
    }
    let mut words = Vec::with_capacity(command.arguments.len() + 1);
    words.push(command.name.as_deref()?);
    for argument in &command.arguments {
        words.push(argument.text.as_deref()?);
    }
    let literal = |word: &&str| !word.is_empty() && !word.contains('*') && !word.chars().any(char::is_whitespace);
    if !words.iter().all(literal) {
        return None;
    }
    let rule = words.join(" ");
    // Grants are listed and stored, so a rule redaction would change (or one already holding the marker, which could
    // not be told apart from a redacted secret) gets no grant rather than a secret written down.
    let holds_secret = redact(&rule).expose() != &rule || holds_redaction_marker(&rule);
    (!holds_secret && is_pattern(&rule)).then_some(rule)
}

#[cfg(test)]
mod tests;
