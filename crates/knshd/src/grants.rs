//! The live grants (KNSH-042 model; FR-POL-60 to FR-POL-62, `specs/05-models/grant.md`).
//!
//! One [`GrantStore`] per `knshd`, shared by those who create grants and the orchestrator, which evaluates every agent
//! line with a snapshot of it. Today only the authority creates grants, through a `grant` in `decision.respond`
//! ([`crate::decisions`], KNSH-069); `policy.grant`, `policy.grants` and `policy.revoke` arrive with KNSH-071 and
//! KNSH-073.
//!
//! Held in memory only: grants are lost when `knshd` exits until the state store keeps them (KNSH-074). Losing a
//! grant only ever asks more, never less.
//!
//! # Concurrency
//!
//! One lock, a leaf: nothing else is locked or called while it is held. The orchestrator takes a copy rather than
//! holding it through a decision, which may wait on an ask for a long time.

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use knsh_core::{CoreError, Grant, GrantSet, Timestamp};

/// The live grants.
#[derive(Default)]
pub(crate) struct GrantStore {
    set: Mutex<GrantSet>,
}

impl GrantStore {
    /// An empty store.
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// The set, even if a thread panicked while holding it: every change is one insert or remove.
    fn set(&self) -> MutexGuard<'_, GrantSet> {
        self.set.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Adds `grant`, judged at `now`.
    ///
    /// # Errors
    ///
    /// As [`GrantSet::insert`]: the grant has already expired, its ID is taken, or the store is full. The live
    /// grants are then unchanged.
    pub(crate) fn insert(&self, grant: Grant, now: Timestamp) -> Result<(), CoreError> {
        self.set().insert(grant, now)
    }

    /// A copy of the live grants, for one line's decision.
    pub(crate) fn snapshot(&self) -> GrantSet {
        self.set().clone()
    }
}
