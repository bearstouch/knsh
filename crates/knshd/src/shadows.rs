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
//! - **Watchers (KNSH-080).** Each root with a shadow also gets a file-event watcher ([`knsh_checkpoint::start_watch`]),
//!   started **before** its build so nothing written during the build is missed, and stopped with the build when the
//!   session ends. It keeps the shadow in step with changes by any process and publishes `file.changed` on the
//!   session (FR-EVT-08, FR-CKP-03), and `checkpoint.uncertain` with no record for lost events while no line runs
//!   (FR-CKP-04). A watcher that cannot start is logged; the root's lines are then reported uncertain
//!   (`not_watched`) when they end, since its shadow can no longer be trusted to follow the tree.
//! - **Lines (KNSH-080).** [`Shadows::open_lines`] marks a line's start in each protected root it touches, and
//!   [`close_lines`] runs the line-end procedure of decision 16 once the line has been reaped: the one place
//!   the decision path waits for a watcher, at most [`knsh_checkpoint::FLUSH_DEADLINE`] per root.
//!
//! # Locks
//!
//! The session table is a leaf: no other lock is taken, and nothing waits, while it is held. A caller waiting on a
//! shadow ([`Shadows::wait`]) holds only that shadow's own lock, inside `knsh-checkpoint`. Watchers are looked up
//! under the table lock and used after it is released; their reports publish events (the hub's lock), never under
//! the table lock.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread;
use std::time::Duration;

use knsh_checkpoint::{
    CheckpointError, FLUSH_DEADLINE, LineClose, LineMark, Method, RootReadiness, SHADOW_THREADS, STREAM_LATENCY,
    Shadow, ShadowFailure, ShadowFiles, ShadowPlan, ShadowStatus, WatchPlan, WatchReport, Watcher, marker_dir,
    place_roots, shadow_dir, start_shadow, start_watch,
};
use knsh_core::{CanonicalPath, EventData, Profile, RecordId, SessionId, UncertainReason, UnprotectedReason};
use knsh_platform::{Clock, EnginePaths, Field, FileEvents, Fs, Level, PlatformError, SystemLog, Value, Volumes};
use knsh_proto::CheckpointBackend;

use crate::events::EventHub;

/// Where checkpoint events go: `file.changed` and `checkpoint.uncertain` on a session (KNSH-080). Best effort, like
/// every event (FR-EVT-04).
pub(crate) trait CheckpointEvents: Send + Sync {
    /// `file.changed`: `path` under `root` changed, by any process (FR-EVT-08).
    fn file_changed(&self, session_id: SessionId, root: &CanonicalPath, path: &CanonicalPath);

    /// `checkpoint.uncertain`: events of `root` may have been lost in the window of line `record_id`, or outside any
    /// line when `None` (FR-CKP-04, NFR-REL-04).
    fn uncertain(
        &self,
        session_id: SessionId,
        root: &CanonicalPath,
        record_id: Option<RecordId>,
        reason: UncertainReason,
    );
}

impl CheckpointEvents for EventHub {
    fn file_changed(&self, session_id: SessionId, root: &CanonicalPath, path: &CanonicalPath) {
        let data = EventData::FileChanged {
            root: root.clone(),
            path: path.clone(),
        };
        // Best effort: a session that ended meanwhile simply gets no event.
        let _ = self.publish_for_session(session_id, data);
    }

    fn uncertain(
        &self,
        session_id: SessionId,
        root: &CanonicalPath,
        record_id: Option<RecordId>,
        reason: UncertainReason,
    ) {
        let data = EventData::CheckpointUncertain {
            root: root.clone(),
            record_id,
            reason,
        };
        let _ = self.publish_for_session(session_id, data);
    }
}

/// A watcher's reports, for one session.
struct SessionReport {
    session_id: SessionId,
    events: Arc<dyn CheckpointEvents>,
}

impl WatchReport for SessionReport {
    fn changed(&self, root: &CanonicalPath, path: &CanonicalPath) {
        self.events.file_changed(self.session_id, root, path);
    }

    fn uncertain(&self, root: &CanonicalPath, reason: UncertainReason) {
        self.events.uncertain(self.session_id, root, None, reason);
    }
}

/// A line's start in one protected root ([`Shadows::open_lines`]).
pub(crate) struct OpenLine {
    root: CanonicalPath,
    /// The root's watcher and the line's mark in it; `None` when the root has a shadow but no watcher.
    watched: Option<(Arc<Watcher>, LineMark)>,
}

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
    /// File-event streams for the watchers (KNSH-080).
    pub(crate) file_events: Arc<dyn FileEvents>,
    /// Where `file.changed` and `checkpoint.uncertain` are published.
    pub(crate) events: Arc<dyn CheckpointEvents>,
}

/// One root of one session.
struct RootShadow {
    root: CanonicalPath,
    method: Method,
    /// Its build; `None` when the root has no shadow (module documentation).
    shadow: Option<Arc<Shadow>>,
    /// Its file-event watcher; `None` without a shadow, or when the watcher could not start.
    watcher: Option<Arc<Watcher>>,
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
                let (shadow, watcher) = match (placed.method, &placed.store) {
                    (Method::ApfsClone, Some(store)) => {
                        let (dir, parents) = shadow_dir(store, &session, index);
                        // Never shadowed: the root's store (a root may contain it) and the engine folders.
                        let mut skip: Vec<PathBuf> = parts.paths.fixed_denies().into();
                        skip.push(store.clone());
                        // The watcher first, so a change made while the build runs is not missed (KNSH-080).
                        let watcher = self.start_watcher(session_id, index, store, &placed.root, &dir, profile, &skip);
                        let plan = ShadowPlan {
                            root: placed.root.clone(),
                            dir,
                            parents,
                            exclude: profile.checkpoints.exclude.clone(),
                            skip,
                            threads: SHADOW_THREADS,
                        };
                        let shadow = start_shadow(Arc::clone(&parts.files), Arc::clone(&parts.clock), plan);
                        if let Some(watcher) = &watcher {
                            watcher.follow(Arc::clone(&shadow));
                        }
                        self.report_when_settled(session_id, index, &shadow);
                        (Some(shadow), watcher)
                    }
                    // Plain-copy shadows are not built yet, and a `none` root has no store: no shadow, reported
                    // honestly as `none` (module documentation).
                    (Method::ApfsClone | Method::PlainCopy | Method::None, _) => (None, None),
                };
                RootShadow {
                    root: placed.root,
                    method: placed.method,
                    shadow,
                    watcher,
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

    /// Starts the watcher of root number `index` of `session_id` (KNSH-080). `None`, logged, if it cannot start.
    #[allow(clippy::too_many_arguments)]
    fn start_watcher(
        &self,
        session_id: SessionId,
        index: usize,
        store: &Path,
        root: &CanonicalPath,
        shadow: &Path,
        profile: &Profile,
        skip: &[PathBuf],
    ) -> Option<Arc<Watcher>> {
        let parts = &self.parts;
        let (markers, marker_parents) = marker_dir(store, &session_id.to_string(), index);
        let plan = WatchPlan {
            root: root.clone(),
            shadow: shadow.to_path_buf(),
            markers,
            marker_parents,
            exclude: profile.checkpoints.exclude.clone(),
            skip: skip.to_vec(),
            latency: STREAM_LATENCY,
            flush_deadline: FLUSH_DEADLINE,
        };
        let report = Arc::new(SessionReport {
            session_id,
            events: Arc::clone(&parts.events),
        });
        match start_watch(
            parts.file_events.as_ref(),
            Arc::clone(&parts.files),
            Arc::clone(&parts.clock),
            report,
            plan,
        ) {
            Ok(watcher) => Some(watcher),
            Err(error) => {
                log_watch_failed(parts.log.as_ref(), session_id, index, error);
                None
            }
        }
    }

    /// A line of `session_id` touching `roots` starts (KNSH-080): marks its start in each root that has a shadow, so
    /// [`close_lines`] can tell whether events were lost while it ran. Never waits.
    pub(crate) fn open_lines(&self, session_id: SessionId, roots: &[CanonicalPath]) -> Vec<OpenLine> {
        // Collected under the table lock and marked after it is released: the table is a leaf lock (module
        // documentation), and marking takes each watcher's own.
        let watched: Vec<(CanonicalPath, Option<Arc<Watcher>>)> = {
            let table = self.table();
            let Some(entries) = table.get(&session_id) else {
                return Vec::new();
            };
            roots
                .iter()
                .filter_map(|root| {
                    let entry = entries.iter().find(|entry| &entry.root == root)?;
                    // A root without a shadow is already listed as unprotected; there is nothing to close.
                    entry.shadow.as_ref()?;
                    Some((root.clone(), entry.watcher.clone()))
                })
                .collect()
        };
        watched
            .into_iter()
            .map(|(root, watcher)| OpenLine {
                root,
                watched: watcher.map(|watcher| {
                    let mark = watcher.open_line();
                    (watcher, mark)
                }),
            })
            .collect()
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

/// The line of `lines` has ended and been reaped: closes it in each root (decision 16), one after the other, and
/// returns the roots whose checkpoints are uncertain, and why (FR-CKP-04). A root without a watcher is uncertain
/// (`not_watched`).
pub(crate) fn close_lines(lines: Vec<OpenLine>) -> Vec<(CanonicalPath, UncertainReason)> {
    lines
        .into_iter()
        .filter_map(|line| {
            let close = match line.watched {
                Some((watcher, mark)) => watcher.close_line(mark),
                None => LineClose::Uncertain(UncertainReason::NotWatched),
            };
            match close {
                LineClose::Certain => None,
                LineClose::Uncertain(reason) => Some((line.root, reason)),
            }
        })
        .collect()
}

/// Stops the builds and the watchers of a session that ended.
fn cancel_all(shadows: &[RootShadow]) {
    for entry in shadows {
        if let Some(watcher) = &entry.watcher {
            watcher.stop();
        }
        if let Some(shadow) = &entry.shadow {
            shadow.cancel();
        }
    }
}

/// One log entry for a watcher that could not start: the root's lines will be reported uncertain.
fn log_watch_failed(log: &dyn SystemLog, session_id: SessionId, index: usize, error: CheckpointError) {
    let (reason, errno) = match error {
        CheckpointError::Platform(PlatformError::Os { errno, .. }) => ("platform", errno),
        CheckpointError::Platform(_) => ("platform", 0),
        CheckpointError::Threads => ("threads", 0),
        CheckpointError::IdentityUnstable => ("identity_unstable", 0),
    };
    let fields = [
        Field::new("session", Value::Id(session_id.ulid())),
        Field::new("root_index", Value::U64(index as u64)),
        Field::new("reason", Value::Static(reason)),
        Field::new("errno", Value::Errno(errno)),
    ];
    log.log(
        Level::Error,
        "checkpoint file-event watcher did not start; changes in the root are uncertain",
        &fields,
    );
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
