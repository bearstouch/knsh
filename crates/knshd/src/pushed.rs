//! Policy pushed by the authority with `policy.set` (FR-POL-01, FR-POL-50 to FR-POL-53; KNSH-071).
//!
//! A snapshot is one profile's text, as a policy file would hold it, with an `expires_at`. [`PushedPolicies`] keeps
//! one per profile name, saved in the state store ([`crate::state`]) so it survives a restart.
//!
//! # How a snapshot is used
//!
//! A pushed profile takes the place of the file of the same name, for every load: a session's lines, its envelope,
//! `policy.check`, and any profile whose `extends` names it. [`PushedSource`] puts the snapshots in front of the
//! policies directory for the one loader both go through (`crate::policy::ProfileLoader`), so a snapshot is read and
//! checked exactly as a file is (FR-POL-01).
//!
//! # Expiry: never a silent fallback
//!
//! From its `expires_at` on, a snapshot no longer loads, and neither does the file of the same name: the profile does
//! not load at all, so every line of a session using it is denied (FR-POL-52) until the authority pushes a new
//! snapshot. The same holds when the clock cannot be read. `crate::expiry` pauses those sessions, until a new
//! snapshot loads or the user selects a local profile for them with `knsh profile use` (KNSH-072).
//!
//! # Concurrency
//!
//! One lock, held while the change is saved, so the state file follows the order of changes. Lock order: this lock,
//! then the state store's.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use knsh_core::{LookupError, ProfileName, ProfileSource, Timestamp};
use knsh_platform::Clock;

use crate::state::{SaveError, StateStore};

/// Most snapshots held at once: one per profile the authority manages. Bounds the state file and memory.
pub(crate) const MAX_SNAPSHOTS: usize = 64;

/// One pushed profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Snapshot {
    /// The profile it defines.
    pub(crate) profile: ProfileName,
    /// Its text, in the profile file format.
    pub(crate) policy: String,
    /// When it stops applying (FR-POL-50).
    pub(crate) expires_at: Timestamp,
}

impl Snapshot {
    /// Whether the snapshot applies at `now`; `None` (the clock failed) never applies.
    fn live_at(&self, now: Option<Timestamp>) -> bool {
        now.is_some_and(|now| now < self.expires_at)
    }
}

/// Why a snapshot was not stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PushError {
    /// [`MAX_SNAPSHOTS`] other profiles already have one.
    Full,
    /// The state store refused or failed the save.
    NotSaved(SaveError),
}

/// The pushed snapshots (module documentation).
pub(crate) struct PushedPolicies {
    snapshots: Mutex<BTreeMap<ProfileName, Snapshot>>,
    state: Arc<StateStore>,
    clock: Arc<dyn Clock>,
}

impl PushedPolicies {
    /// Snapshots `restored` from the state store, saving later changes to `state`, judged by `clock`.
    pub(crate) fn new(state: Arc<StateStore>, clock: Arc<dyn Clock>, restored: Vec<Snapshot>) -> Arc<Self> {
        let snapshots = restored
            .into_iter()
            .take(MAX_SNAPSHOTS)
            .map(|snapshot| (snapshot.profile.clone(), snapshot))
            .collect();
        Arc::new(Self {
            snapshots: Mutex::new(snapshots),
            state,
            clock,
        })
    }

    /// Stores `snapshot` in place of any snapshot of its profile and saves the set. Returns whether one was
    /// replaced. The caller has already checked that it loads.
    ///
    /// # Errors
    ///
    /// [`PushError`]: nothing changed, in memory or on disk.
    pub(crate) fn set(&self, snapshot: Snapshot) -> Result<bool, PushError> {
        let mut snapshots = lock(&self.snapshots);
        let replaced = snapshots.contains_key(&snapshot.profile);
        if !replaced && snapshots.len() >= MAX_SNAPSHOTS {
            return Err(PushError::Full);
        }
        let mut next = snapshots.clone();
        next.insert(snapshot.profile.clone(), snapshot);
        self.state
            .save_snapshots(next.values().cloned().collect())
            .map_err(PushError::NotSaved)?;
        *snapshots = next;
        Ok(replaced)
    }

    /// The snapshot of `profile`, live or expired.
    pub(crate) fn get(&self, profile: &ProfileName) -> Option<Snapshot> {
        lock(&self.snapshots).get(profile).cloned()
    }

    /// The profiles whose snapshot no longer applies: expired, or every one while the clock cannot be read (as for
    /// loading). These load from nothing until replaced (FR-POL-52); `crate::expiry` pauses their sessions.
    pub(crate) fn expired(&self) -> BTreeSet<ProfileName> {
        let now = self.now();
        lock(&self.snapshots)
            .values()
            .filter(|snapshot| !snapshot.live_at(now))
            .map(|snapshot| snapshot.profile.clone())
            .collect()
    }

    /// The current wall time, `None` if the clock fails (which no snapshot is live at).
    pub(crate) fn now(&self) -> Option<Timestamp> {
        self.clock.now().ok()
    }

    /// A source reading `profile` from its snapshot when one was pushed, from `files` otherwise (module
    /// documentation), as of now.
    pub(crate) fn source<'a>(&self, files: &'a dyn ProfileSource) -> PushedSource<'a> {
        PushedSource {
            snapshots: lock(&self.snapshots).clone(),
            candidate: None,
            now: self.now(),
            files,
        }
    }
}

/// Profiles read from the pushed snapshots first, then from files (module documentation). A copy of the snapshots,
/// so a load never holds the lock.
pub(crate) struct PushedSource<'a> {
    snapshots: BTreeMap<ProfileName, Snapshot>,
    /// A snapshot being checked by `policy.set`, read before anything else for its profile.
    candidate: Option<Snapshot>,
    now: Option<Timestamp>,
    files: &'a dyn ProfileSource,
}

impl PushedSource<'_> {
    /// The same source with `candidate` read for its profile in place of anything else, whatever its expiry: what
    /// `policy.set` checks before it stores the snapshot (it refuses an expired one separately).
    pub(crate) fn with_candidate(mut self, candidate: Snapshot) -> Self {
        self.candidate = Some(candidate);
        self
    }
}

impl ProfileSource for PushedSource<'_> {
    fn read_profile(&self, name: &ProfileName) -> Result<Vec<u8>, LookupError> {
        if let Some(candidate) = self.candidate.as_ref().filter(|candidate| candidate.profile == *name) {
            return Ok(candidate.policy.clone().into_bytes());
        }
        match self.snapshots.get(name) {
            Some(snapshot) if snapshot.live_at(self.now) => Ok(snapshot.policy.clone().into_bytes()),
            // FR-POL-52: an expired snapshot does not load, and the file of its name is not read in its place.
            Some(_) => Err(LookupError::Failed),
            None => self.files.read_profile(name),
        }
    }
}

/// Takes the lock even if a thread panicked while holding it: the map is replaced whole, after its save.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use knsh_platform::Fs;
    use knsh_platform::testing::{FakeClock, RecordingLog};

    use super::*;
    use crate::state::tests::snapshot;

    struct Files;

    impl ProfileSource for Files {
        fn read_profile(&self, name: &ProfileName) -> Result<Vec<u8>, LookupError> {
            Ok(format!("# file {name}\n").into_bytes())
        }
    }

    fn at(seconds: u64) -> Timestamp {
        Timestamp::from_unix_micros(seconds * 1_000_000).unwrap()
    }

    fn pushed(now: u64) -> (Arc<PushedPolicies>, Arc<FakeClock>, Arc<StateStore>) {
        let clock = Arc::new(FakeClock::new(at(now)));
        let state = StateStore::in_memory(Arc::new(RecordingLog::new()));
        (
            PushedPolicies::new(state.clone(), clock.clone(), Vec::new()),
            clock,
            state,
        )
    }

    fn read(pushed: &PushedPolicies, name: &str) -> Result<String, LookupError> {
        pushed
            .source(&Files)
            .read_profile(&ProfileName::new(name).unwrap())
            .map(|bytes| String::from_utf8(bytes).unwrap())
    }

    // FR-POL-01: a live snapshot is read in place of the file of its name; other names still come from files.
    #[test]
    fn snapshot_takes_the_place_of_the_file() {
        let (pushed, _, state) = pushed(10);
        assert_eq!(pushed.set(snapshot("web", at(20))), Ok(false));
        assert_eq!(read(&pushed, "web").unwrap(), "name = \"web\"\n");
        assert_eq!(read(&pushed, "other").unwrap(), "# file other\n");
        assert_eq!(state.saved().snapshots, [snapshot("web", at(20))]);
        assert_eq!(pushed.set(snapshot("web", at(30))), Ok(true), "replaced");
        assert_eq!(state.saved().snapshots, [snapshot("web", at(30))]);
    }

    // FR-POL-52: from `expires_at` on, the profile loads from nothing, never from its file.
    #[test]
    fn expired_snapshot_never_falls_back_to_the_file() {
        let (pushed, clock, _) = pushed(10);
        pushed.set(snapshot("web", at(20))).unwrap();
        clock.advance(std::time::Duration::from_secs(10));
        assert_eq!(read(&pushed, "web"), Err(LookupError::Failed));
        assert!(
            pushed.get(&ProfileName::new("web").unwrap()).is_some(),
            "kept until replaced"
        );
        assert_eq!(
            pushed.expired().into_iter().collect::<Vec<_>>(),
            [ProfileName::new("web").unwrap()]
        );
        pushed.set(snapshot("web", at(40))).unwrap();
        assert!(pushed.expired().is_empty(), "a new snapshot applies again");
    }

    // A snapshot that cannot be saved is not stored.
    #[test]
    fn refuses_snapshots_that_cannot_be_saved() {
        let fs = crate::state::tests::fs();
        fs.write(
            &crate::state::tests::path(),
            b"{",
            knsh_platform::engine_dirs::FILE_MODE,
        )
        .unwrap();
        let (state, _) = StateStore::open(
            fs,
            crate::state::tests::path(),
            knsh_platform::testing::DEFAULT_UID,
            Arc::new(RecordingLog::new()),
        );
        let pushed = PushedPolicies::new(state, Arc::new(FakeClock::new(at(10))), Vec::new());
        assert_eq!(
            pushed.set(snapshot("web", at(20))),
            Err(PushError::NotSaved(SaveError::Frozen))
        );
        assert_eq!(read(&pushed, "web").unwrap(), "# file web\n");
    }
}
