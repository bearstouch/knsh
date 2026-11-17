//! The live grants (KNSH-042 model; FR-POL-60 to FR-POL-62, `specs/05-models/grant.md`).
//!
//! One [`GrantStore`] per `knshd`, shared by those who create grants and the orchestrator, which evaluates every agent
//! line with a snapshot of it. The authority creates grants with a `grant` in `decision.respond`
//! ([`crate::decisions`], KNSH-069) and with `policy.grant`, lists them with `policy.grants` and revokes them with
//! `policy.revoke` ([`crate::policy_admin`], KNSH-071). The user's `policy.grant` with Touch ID is KNSH-073's.
//!
//! # Persistence
//!
//! Every change is saved to the state store ([`crate::state`]) before it takes effect, so the grants survive a
//! restart (FR-POL-60). A grant that cannot be saved is not created. A revocation always takes effect in memory,
//! saved or not: removing a permission must never wait on a disk; one that could not be saved is logged, and the
//! grant would come back only after a restart, until its expiry.
//!
//! # Concurrency
//!
//! One lock, held while a change is saved so the file follows the order of changes. Lock order: this lock, then the
//! state store's; nothing else is locked or called while it is held. The orchestrator takes a copy rather than
//! holding it through a decision, which may wait on an ask for a long time.

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use knsh_core::{CoreError, Grant, GrantId, GrantSet, Timestamp};
use knsh_platform::{Level, SystemLog};

use crate::state::{SaveError, StateStore};

/// Why a grant was not created.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum GrantError {
    /// The set refused it: already expired, its ID taken, or the store full ([`GrantSet::insert`]).
    Refused(CoreError),
    /// It could not be saved to the state store.
    NotSaved(SaveError),
}

/// The live grants.
pub(crate) struct GrantStore {
    set: Mutex<GrantSet>,
    state: Arc<StateStore>,
    log: Arc<dyn SystemLog>,
}

impl GrantStore {
    /// An empty store kept in memory only, for tests.
    #[cfg(test)]
    pub(crate) fn new() -> Arc<Self> {
        let log: Arc<dyn SystemLog> = Arc::new(knsh_platform::testing::RecordingLog::new());
        Self::persisted(StateStore::in_memory(Arc::clone(&log)), log, Vec::new(), None)
    }

    /// A store saving to `state`, holding the `restored` grants that are still live at `now` (all of them when the
    /// clock could not be read: they still expire when judged, and are pruned at the next save).
    pub(crate) fn persisted(
        state: Arc<StateStore>,
        log: Arc<dyn SystemLog>,
        restored: Vec<Grant>,
        now: Option<Timestamp>,
    ) -> Arc<Self> {
        let mut set = GrantSet::new();
        let judged_at = now.unwrap_or(Timestamp::UNIX_EPOCH);
        for grant in restored {
            // Restored without a second save: the file already holds them.
            let _ = set.insert(grant, judged_at);
        }
        Arc::new(Self {
            set: Mutex::new(set),
            state,
            log,
        })
    }

    /// The set, even if a thread panicked while holding it: every change is one insert or remove, made on a copy and
    /// kept only once saved.
    fn set(&self) -> MutexGuard<'_, GrantSet> {
        self.set.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Adds `grant`, judged at `now`, and saves the live grants.
    ///
    /// # Errors
    ///
    /// [`GrantError`]: the live grants are unchanged, in memory and on disk.
    pub(crate) fn insert(&self, grant: Grant, now: Timestamp) -> Result<(), GrantError> {
        let mut set = self.set();
        let mut next = set.clone();
        next.insert(grant, now).map_err(GrantError::Refused)?;
        self.state
            .save_grants(next.list(now).cloned().collect())
            .map_err(GrantError::NotSaved)?;
        *set = next;
        Ok(())
    }

    /// Revokes the live grant `id` at `now` and returns it; `None` for an unknown or expired one.
    pub(crate) fn revoke(&self, id: GrantId, now: Timestamp) -> Option<Grant> {
        let mut set = self.set();
        let revoked = set.revoke(id, now).ok()?;
        if self.state.save_grants(set.list(now).cloned().collect()).is_err() {
            // Revoked in memory all the same (module documentation, "Persistence").
            self.log.log(
                Level::Error,
                "revoked grant not removed from the state file; it applies again after a restart until it expires",
                &[],
            );
        }
        Some(revoked)
    }

    /// The live grants at `now`, in ID order.
    pub(crate) fn list(&self, now: Timestamp) -> Vec<Grant> {
        self.set().list(now).cloned().collect()
    }

    /// A copy of the live grants, for one line's decision.
    pub(crate) fn snapshot(&self) -> GrantSet {
        self.set().clone()
    }
}

#[cfg(test)]
mod tests {
    use knsh_core::{GrantScope, ProfileName, Ulid};
    use knsh_platform::testing::RecordingLog;

    use super::*;

    fn at(seconds: u64) -> Timestamp {
        Timestamp::from_unix_micros(seconds * 1_000_000).unwrap()
    }

    fn grant(n: u128, expires: u64) -> Grant {
        Grant::new(
            GrantId::from_ulid(Ulid::from_u128(n)),
            GrantScope::Profile(ProfileName::new("web").unwrap()),
            "git push",
            at(expires),
        )
        .unwrap()
    }

    // FR-POL-60, FR-POL-61: every change is saved; a revoked grant leaves the file and the list.
    #[test]
    fn saves_inserts_and_revocations() {
        let log = Arc::new(RecordingLog::new());
        let state = StateStore::in_memory(log.clone());
        let store = GrantStore::persisted(state.clone(), log, Vec::new(), None);
        store.insert(grant(1, 100), at(10)).unwrap();
        store.insert(grant(2, 100), at(10)).unwrap();
        assert_eq!(state.saved().grants, [grant(1, 100), grant(2, 100)]);
        assert_eq!(
            store.revoke(GrantId::from_ulid(Ulid::from_u128(1)), at(20)),
            Some(grant(1, 100))
        );
        assert_eq!(state.saved().grants, [grant(2, 100)]);
        assert_eq!(store.list(at(20)), [grant(2, 100)]);
        // Unknown, already revoked, or expired: nothing to revoke.
        assert_eq!(store.revoke(GrantId::from_ulid(Ulid::from_u128(1)), at(20)), None);
        assert_eq!(store.revoke(GrantId::from_ulid(Ulid::from_u128(2)), at(100)), None);
    }

    // Restored grants that have expired are dropped.
    #[test]
    fn restores_only_live_grants() {
        let log = Arc::new(RecordingLog::new());
        let store = GrantStore::persisted(
            StateStore::in_memory(log.clone()),
            log,
            vec![grant(1, 5), grant(2, 100)],
            Some(at(10)),
        );
        assert_eq!(store.list(at(10)), [grant(2, 100)]);
    }
}
