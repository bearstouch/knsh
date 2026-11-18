//! Checkpoint shadows of live agent sessions (KNSH-079, FR-CKP-01, FR-CKP-02; `specs/03-functional-requirements/
//! checkpoints.md`).
//!
//! When an agent session starts, [`Shadows::start`] places each of its profile's `checkpoints.roots` in a store
//! ([`knsh_checkpoint::place_roots`], KNSH-078) and starts one background shadow build per root that clones
//! ([`knsh_checkpoint::start_shadow`]). Session start never waits for a build. When the session ends,
//! [`Shadows::end`] stops its builds.
//!
//! - **Roots without a shadow.** A root whose method is `plain-copy` or `none` gets no shadow: plain-copy shadows
//!   are not built yet, and a `none` root has no store. Such a root reports `none` in the capability report and its
//!   lines are not protected ([`UnprotectedReason::NoShadow`]); with `checkpoints.required = true` they are denied.
//! - **The capability report** (`hello`'s `checkpoints`, [`Shadows::capability_report`]) lists each root of a
//!   running agent session once its shadow has settled: its method when the shadow is complete, `none` when the build
//!   failed or there is none. A root still being built is not listed yet (`specs/05-models/capabilities.md`).
//!   A root shared by two sessions reports the weaker of the two.
//! - **Logs.** Each build's end is logged with its file count and duration, never a path (NFR-PRIV-02); a build over
//!   [`knsh_checkpoint::SHADOW_BUDGET`] is logged as an error (decision 15).
//!
//! # Locks
//!
//! The session table is a leaf: no other lock is taken, and nothing waits, while it is held. A caller waiting on a
//! shadow ([`Shadows::wait`]) holds only that shadow's own lock, inside `knsh-checkpoint`.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread;
use std::time::Duration;

use knsh_checkpoint::{
    Method, RootReadiness, SHADOW_THREADS, Shadow, ShadowFailure, ShadowFiles, ShadowPlan, ShadowStatus, place_roots,
    shadow_dir, start_shadow,
};
use knsh_core::{CanonicalPath, Profile, SessionId, UnprotectedReason};
use knsh_platform::{Clock, EnginePaths, Field, Fs, Level, PlatformError, SystemLog, Value, Volumes};
use knsh_proto::CheckpointBackend;

/// The effects shadows need.
pub(crate) struct ShadowParts {
    /// Store placement: folders, modes, format files.
    pub(crate) fs: Arc<dyn Fs>,
    /// Store placement: which volume each root and store is on.
    pub(crate) volumes: Arc<dyn Volumes>,
    /// What builds clone with.
    pub(crate) files: Arc<dyn ShadowFiles>,
    /// Times builds.
    pub(crate) clock: Arc<dyn Clock>,
    /// The engine directories: the home store, and folders never shadowed.
    pub(crate) paths: EnginePaths,
    /// The user the engine runs as.
    pub(crate) uid: u32,
    /// Where build ends are logged.
    pub(crate) log: Arc<dyn SystemLog>,
}

/// One root of one session.
struct RootShadow {
    root: CanonicalPath,
    method: Method,
    /// Its build; `None` when the root has no shadow (module documentation).
    shadow: Option<Arc<Shadow>>,
}

/// The shadows of every live agent session. One per `knshd`.
pub(crate) struct Shadows {
    parts: ShadowParts,
    sessions: Mutex<BTreeMap<SessionId, Vec<RootShadow>>>,
}

impl Shadows {
    /// No session yet.
    pub(crate) fn new(parts: ShadowParts) -> Arc<Self> {
        Arc::new(Self {
            parts,
            sessions: Mutex::new(BTreeMap::new()),
        })
    }

    fn table(&self) -> MutexGuard<'_, BTreeMap<SessionId, Vec<RootShadow>>> {
        self.sessions.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Starts the shadows of `session_id`'s roots, from `profile` as the session runs it (FR-CKP-01). Returns once
    /// each build has started, without waiting for any. A session with no roots gets nothing.
    pub(crate) fn start(&self, session_id: SessionId, profile: &Profile) {
        let roots = &profile.checkpoints.roots;
        if roots.is_empty() {
            return;
        }
        let parts = &self.parts;
        let stores = place_roots(
            parts.fs.as_ref(),
            parts.volumes.as_ref(),
            &parts.paths,
            parts.uid,
            roots,
        );
        let session = session_id.to_string();
        let shadows = stores
            .into_iter()
            .enumerate()
            .map(|(index, placed)| {
                let shadow = match (placed.method, &placed.store) {
                    (Method::ApfsClone, Some(store)) => {
                        let (dir, parents) = shadow_dir(store, &session, index);
                        // Never shadowed: the root's store (a root may contain it) and the engine folders.
                        let mut skip: Vec<PathBuf> = parts.paths.fixed_denies().into();
                        skip.push(store.clone());
                        let plan = ShadowPlan {
                            root: placed.root.clone(),
                            dir,
                            parents,
                            exclude: profile.checkpoints.exclude.clone(),
                            skip,
                            threads: SHADOW_THREADS,
                        };
                        let shadow = start_shadow(Arc::clone(&parts.files), Arc::clone(&parts.clock), plan);
                        self.report_when_settled(session_id, index, &shadow);
                        Some(shadow)
                    }
                    // Plain-copy shadows are not built yet, and a `none` root has no store: no shadow, reported
                    // honestly as `none` (module documentation).
                    (Method::ApfsClone | Method::PlainCopy | Method::None, _) => None,
                };
                RootShadow {
                    root: placed.root,
                    method: placed.method,
                    shadow,
                }
            })
            .collect();
        // A session id is never reused; were it here already, the older builds are stopped, not leaked. Stopped once
        // the table lock is released, which stays a leaf.
        let previous = self.table().insert(session_id, shadows);
        if let Some(previous) = previous {
            cancel_all(&previous);
        }
    }

    /// Stops the builds of `session_id`, which has ended, and forgets them.
    pub(crate) fn end(&self, session_id: SessionId) {
        let removed = self.table().remove(&session_id);
        if let Some(shadows) = removed {
            cancel_all(&shadows);
        }
    }

    /// How far the shadow of `root` is for `session_id` (FR-CKP-02). A root the session has no shadow for (it was not
    /// a root when the session started, or the session has none) is [`UnprotectedReason::NoShadow`].
    pub(crate) fn readiness(&self, session_id: SessionId, root: &CanonicalPath) -> RootReadiness {
        match self.shadow_of(session_id, root) {
            Some(shadow) => RootReadiness::of(&shadow.status()),
            None => RootReadiness::Unavailable(UnprotectedReason::NoShadow),
        }
    }

    /// Waits at most `slice` for the shadow of `root` to settle, and returns its readiness then.
    pub(crate) fn wait(&self, session_id: SessionId, root: &CanonicalPath, slice: Duration) -> RootReadiness {
        // Looked up first, so the table lock is not held while waiting.
        match self.shadow_of(session_id, root) {
            Some(shadow) => RootReadiness::of(&shadow.wait(slice)),
            None => RootReadiness::Unavailable(UnprotectedReason::NoShadow),
        }
    }

    fn shadow_of(&self, session_id: SessionId, root: &CanonicalPath) -> Option<Arc<Shadow>> {
        self.table()
            .get(&session_id)?
            .iter()
            .find(|entry| &entry.root == root)
            .and_then(|entry| entry.shadow.clone())
    }

    /// `hello`'s `checkpoints`: each root of a running agent session whose shadow has settled, with how it is
    /// protected (module documentation).
    pub(crate) fn capability_report(&self) -> BTreeMap<String, CheckpointBackend> {
        let mut report: BTreeMap<String, CheckpointBackend> = BTreeMap::new();
        for entry in self.table().values().flatten() {
            let backend = match &entry.shadow {
                None => CheckpointBackend::None,
                Some(shadow) => match shadow.status() {
                    ShadowStatus::Building(_) => continue,
                    ShadowStatus::Complete(_) => backend_of(entry.method),
                    ShadowStatus::Failed(_) | ShadowStatus::Cancelled => CheckpointBackend::None,
                },
            };
            let key = entry.root.as_path().to_string_lossy().into_owned();
            report
                .entry(key)
                .and_modify(|kept| *kept = weaker(*kept, backend))
                .or_insert(backend);
        }
        report
    }

    /// Logs the end of `shadow`'s build, from a thread of its own (best effort: a thread that cannot start only
    /// loses the log entry).
    fn report_when_settled(&self, session_id: SessionId, index: usize, shadow: &Arc<Shadow>) {
        let shadow = Arc::clone(shadow);
        let log = Arc::clone(&self.parts.log);
        let _ = thread::Builder::new().name("knsh-shadow-report".into()).spawn(move || {
            let status = loop {
                match shadow.wait(Duration::from_secs(60)) {
                    ShadowStatus::Building(_) => {}
                    settled => break settled,
                }
            };
            log_settled(log.as_ref(), session_id, index, &status);
        });
    }
}

fn cancel_all(shadows: &[RootShadow]) {
    for shadow in shadows.iter().filter_map(|entry| entry.shadow.as_ref()) {
        shadow.cancel();
    }
}

/// The capability value of a root whose shadow is complete.
fn backend_of(method: Method) -> CheckpointBackend {
    match method {
        Method::ApfsClone => CheckpointBackend::ApfsClone,
        Method::PlainCopy => CheckpointBackend::PlainCopy,
        Method::None => CheckpointBackend::None,
    }
}

/// The less protective of two capability values.
fn weaker(a: CheckpointBackend, b: CheckpointBackend) -> CheckpointBackend {
    let rank = |backend| match backend {
        CheckpointBackend::None => 0,
        CheckpointBackend::PlainCopy => 1,
        CheckpointBackend::ApfsClone => 2,
    };
    if rank(a) <= rank(b) { a } else { b }
}

/// One log entry for a settled build: counts and time only, never a path (NFR-PRIV-02).
fn log_settled(log: &dyn SystemLog, session_id: SessionId, index: usize, status: &ShadowStatus) {
    let session = Field::new("session", Value::Id(session_id.ulid()));
    let root = Field::new("root_index", Value::U64(index as u64));
    match status {
        ShadowStatus::Complete(summary) => {
            let millis = u64::try_from(summary.duration.as_millis()).unwrap_or(u64::MAX);
            let fields = [
                session,
                root,
                Field::new("files", Value::U64(summary.files)),
                Field::new("folders", Value::U64(summary.folders)),
                Field::new("excluded_folders", Value::U64(summary.excluded_folders)),
                Field::new("special_files", Value::U64(summary.special_count)),
                Field::new("duration_ms", Value::U64(millis)),
            ];
            // Decision 15: a build over NFR-PERF-06's budget is reported, so slow machines and cold caches show up.
            let (level, message) = if summary.over_budget {
                (Level::Error, "checkpoint shadow built over its time budget")
            } else {
                (Level::Notice, "checkpoint shadow built")
            };
            log.log(level, message, &fields);
        }
        ShadowStatus::Failed(failure) => {
            let (reason, errno) = match failure {
                ShadowFailure::RootNotAFolder => ("root_not_a_folder", 0),
                ShadowFailure::ShadowExists => ("shadow_exists", 0),
                ShadowFailure::Threads => ("threads", 0),
                ShadowFailure::Platform(PlatformError::Os { errno, .. }) => ("platform", *errno),
                ShadowFailure::Platform(_) => ("platform", 0),
            };
            let fields = [
                session,
                root,
                Field::new("reason", Value::Static(reason)),
                Field::new("errno", Value::Errno(errno)),
            ];
            log.log(
                Level::Error,
                "checkpoint shadow failed; the root is not protected",
                &fields,
            );
        }
        ShadowStatus::Cancelled => log.log(Level::Info, "checkpoint shadow stopped", &[session, root]),
        ShadowStatus::Building(_) => {}
    }
}

#[cfg(test)]
pub(crate) mod tests;
