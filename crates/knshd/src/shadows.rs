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
//! - **Attribution (KNSH-081).** One [`Attributor`] for the daemon keeps the [`Ledger`] of every root, keyed by root
//!   so lines of one session are never another session's agent edits. Each session's roots are registered with it
//!   (with whether the session runs in an envelope), every `file.changed` a watcher reports goes to it, and each
//!   line is started in it by [`Shadows::open_lines`] and ended by [`close_lines`] **after** its line-end flush, so
//!   every change of the line has been attributed before the line's attribution is read for its record
//!   (FR-CKP-05, FR-CKP-07). The watchers other sessions keep on the line's roots are flushed too: they report the
//!   line's changes as well, and must not do so after it ended. Agent edits are published as `agent.edit` on each envelope session watching the root,
//!   one per batch the watcher applied (FR-CKP-06). Closed edges go to an [`EdgeSink`]: the history tree (KNSH-083)
//!   will take them; until then they are dropped.
//! - **Capture (KNSH-082).** Each change a watcher reports carries its pre-image (the shadow copy the watcher moved
//!   into the root's holding folder) and its post-image identity. The attributor attributes it and begins its capture
//!   in one critical section, then [`Captures::add`] keeps it in the checkpoint of its edge, in the root's store
//!   (FR-CKP-08, FR-CKP-09). When an edge closes and its checkpoint is final, `checkpoint.created` is published on
//!   each of its sessions (FR-CKP-11). A line's uncertain roots mark its checkpoint uncertain before it ends, and so
//!   does an uncertain window outside lines for the run of edits it opens (FR-CKP-04). [`close_lines`] returns the
//!   line's checkpoint for its record (`checkpoint_id`, `files_changed`).
//!
//! # Locks
//!
//! The session table is a leaf: no other lock is taken, and nothing waits, while it is held. The attributor's ledger
//! lock is taken only without the table lock; the [`EdgeSink`] is called under it (so edges arrive in the order they
//! closed) and must not block or call back. The captures' lock is taken under it (lock order: ledger, then
//! captures), never the other way round; a capture's renames happen after both are released. Events are published
//! after it is released. A caller waiting on a shadow ([`Shadows::wait`]) holds only that shadow's own lock, inside
//! `knsh-checkpoint`. Watchers are looked up under the table lock and used after it is released; their reports
//! publish events (the hub's lock), never under the table lock.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread;
use std::time::Duration;

use knsh_checkpoint::{
    Captures, Change, Checkpoint, CheckpointError, CheckpointSummary, Edge, FLUSH_DEADLINE, Ledger, LineClose,
    LineMark, Method, RootReadiness, SHADOW_THREADS, STREAM_LATENCY, Shadow, ShadowFailure, ShadowFiles, ShadowPlan,
    ShadowStatus, WatchPlan, WatchReport, Watcher, held_dir, marker_dir, place_roots, shadow_dir, start_shadow,
    start_watch,
};
use knsh_core::{
    Attribution, CanonicalPath, EventData, Profile, RecordId, SessionId, UncertainReason, UnprotectedReason,
};
use knsh_platform::{
    Clock, EnginePaths, Field, FileEvents, Fs, Level, PlatformError, Random, SystemLog, Value, Volumes,
};
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

    /// `agent.edit`: `paths` under `root` changed inside the envelope of `session_id` while no line ran there, and
    /// `omitted` more were not listed (FR-CKP-06, KNSH-081).
    fn agent_edit(&self, session_id: SessionId, root: &CanonicalPath, paths: &[CanonicalPath], omitted: u32);

    /// `checkpoint.created`: `checkpoint` was taken, and belongs to `session_id` (FR-CKP-11, KNSH-082).
    fn checkpoint_created(&self, session_id: SessionId, checkpoint: &Checkpoint);
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

    fn agent_edit(&self, session_id: SessionId, root: &CanonicalPath, paths: &[CanonicalPath], omitted: u32) {
        let data = EventData::AgentEdit {
            root: root.clone(),
            paths: paths.to_vec(),
            omitted,
        };
        let _ = self.publish_for_session(session_id, data);
    }

    fn checkpoint_created(&self, session_id: SessionId, checkpoint: &Checkpoint) {
        let data = EventData::CheckpointCreated {
            checkpoint_id: checkpoint.id,
            attribution: checkpoint.attribution,
            record_ids: checkpoint.records.iter().copied().collect(),
            roots: checkpoint.paths.keys().cloned().collect(),
            files_changed: checkpoint.path_count() as u64,
            uncertain: checkpoint.is_uncertain(),
        };
        let _ = self.publish_for_session(session_id, data);
    }
}

/// Where closed edges go (KNSH-081): the units the history tree (KNSH-083) will store (their checkpoints are taken by
/// [`Captures`], KNSH-082). Called under the attributor's lock, in the order the edges closed; must not block or call
/// back into the attributor.
pub(crate) trait EdgeSink: Send + Sync {
    /// `edges` closed, oldest first.
    fn closed(&self, edges: Vec<Edge>);
}

/// The edge sink until the history tree exists (KNSH-083): closed edges are dropped. Their checkpoints are still
/// taken, and records still carry their attribution.
pub(crate) struct UncapturedEdges;

impl EdgeSink for UncapturedEdges {
    fn closed(&self, edges: Vec<Edge>) {
        drop(edges);
    }
}

/// The daemon's attribution of changes in checkpoint roots (KNSH-081), and their capture (KNSH-082): the [`Ledger`]
/// behind its lock, the [`Captures`], and where what they decide goes.
pub(crate) struct Attributor {
    ledger: Mutex<Ledger>,
    captures: Captures,
    events: Arc<dyn CheckpointEvents>,
    edges: Arc<dyn EdgeSink>,
}

impl Attributor {
    fn new(events: Arc<dyn CheckpointEvents>, edges: Arc<dyn EdgeSink>, captures: Captures) -> Arc<Self> {
        Arc::new(Self {
            ledger: Mutex::new(Ledger::new()),
            captures,
            events,
            edges,
        })
    }

    /// Runs `change` on the ledger and the captures, then hands the edges it closed to the captures and the sink,
    /// under the same lock (module documentation, "Locks"). The checkpoints that finished are published once the lock
    /// is released.
    fn with<R>(&self, change: impl FnOnce(&mut Ledger, &Captures) -> R) -> R {
        let (result, finished) = {
            // The ledger stays consistent at each step of every operation, so a panic elsewhere cannot corrupt it.
            let mut ledger = self.ledger.lock().unwrap_or_else(PoisonError::into_inner);
            let result = change(&mut ledger, &self.captures);
            let closed = ledger.take_closed();
            let finished = if closed.is_empty() {
                Vec::new()
            } else {
                let finished = self.captures.closed(&closed);
                self.edges.closed(closed);
                finished
            };
            (result, finished)
        };
        self.publish_created(&finished);
        result
    }

    /// Attributes `change` of `root`, reported by `session_id`'s watcher, and captures it in its edge's checkpoint in
    /// `store` (KNSH-082). A change no session claims keeps nothing.
    fn capture(&self, session_id: SessionId, store: &Path, root: &CanonicalPath, change: Change) {
        // Attributed and begun in one critical section, so the edge cannot close before the change is added.
        let ticket = self.with(|ledger, captures| ledger.changed(root, &change.path).map(|edge| captures.begin(edge)));
        match ticket {
            Some(ticket) => {
                let finished = self.captures.add(ticket, session_id, store, root, change);
                self.publish_created(&finished);
            }
            None => self.captures.discard(change),
        }
    }

    /// `checkpoint.created` for each of `finished`, on each session it belongs to (FR-CKP-11).
    fn publish_created(&self, finished: &[Checkpoint]) {
        for checkpoint in finished {
            for session_id in &checkpoint.sessions {
                self.events.checkpoint_created(*session_id, checkpoint);
            }
        }
    }

    /// Publishes the agent edits of `root` not reported yet, as one `agent.edit` on each envelope session watching
    /// it (FR-CKP-06).
    fn publish_agent_edits(&self, root: &CanonicalPath) {
        let Some(edits) = self.with(|ledger, _| ledger.take_agent_edits(root)) else {
            return;
        };
        for session_id in &edits.sessions {
            self.events
                .agent_edit(*session_id, &edits.root, &edits.paths, edits.omitted);
        }
    }
}

/// A watcher's reports, for one session.
struct SessionReport {
    session_id: SessionId,
    /// The root's store, where its checkpoints are kept (KNSH-082).
    store: PathBuf,
    events: Arc<dyn CheckpointEvents>,
    attributor: Arc<Attributor>,
}

impl WatchReport for SessionReport {
    fn changed(&self, root: &CanonicalPath, change: Change) {
        let path = change.path.clone();
        // Attributed and captured first, so anyone who saw `file.changed` sees the change already attributed
        // (KNSH-081) and its pre-image kept (KNSH-082).
        self.attributor.capture(self.session_id, &self.store, root, change);
        self.events.file_changed(self.session_id, root, &path);
    }

    fn uncertain(&self, root: &CanonicalPath, reason: UncertainReason) {
        // FR-CKP-04: the checkpoint of the edits this window opens may miss changes.
        self.attributor.with(|ledger, captures| {
            if let Some(edge) = ledger.edge_of(root) {
                captures.mark_uncertain(edge, reason);
            }
        });
        self.events.uncertain(self.session_id, root, None, reason);
    }

    fn settled(&self, root: &CanonicalPath) {
        self.attributor.publish_agent_edits(root);
    }
}

/// A line's start in one protected root ([`Shadows::open_lines`]).
struct OpenLine {
    root: CanonicalPath,
    /// The root's watcher and the line's mark in it; `None` when the root has a shadow but no watcher.
    watched: Option<(Arc<Watcher>, LineMark)>,
}

/// A line's start in every protected root it touches, and in the attribution ledger ([`Shadows::open_lines`]).
/// Give it to [`close_lines`] once the line has been reaped.
#[must_use = "a checkpoint line must be closed with `close_lines`"]
pub(crate) struct CheckpointLine {
    record_id: RecordId,
    roots: Vec<OpenLine>,
    /// Where the line was started; `None` when it touches no protected root, or there are no shadows.
    attributor: Option<Arc<Attributor>>,
    /// The session table, to find at close time the watchers other sessions keep on the line's roots
    /// ([`close_lines`]); `None` exactly when `attributor` is.
    table: Option<Arc<Table>>,
}

impl CheckpointLine {
    /// A line touching no protected root: nothing to flush, attributed `command`.
    pub(crate) fn unprotected(record_id: RecordId) -> Self {
        Self {
            record_id,
            roots: Vec::new(),
            attributor: None,
            table: None,
        }
    }
}

/// The shadows of every live agent session, by session.
type Table = Mutex<BTreeMap<SessionId, Vec<RootShadow>>>;

/// What closing a line found ([`close_lines`]).
#[derive(Debug)]
pub(crate) struct ClosedLine {
    /// The roots whose checkpoints are uncertain, and why (FR-CKP-04).
    pub(crate) uncertain: Vec<(CanonicalPath, UncertainReason)>,
    /// The record's `attribution` (FR-CKP-05, FR-CKP-07).
    pub(crate) attribution: Attribution,
    /// Whether the line touched a protected root: its record then has `files_changed` (KNSH-082).
    pub(crate) protected: bool,
    /// The line's checkpoint, for the record's `checkpoint_id` and `files_changed` (KNSH-082); `None` when it
    /// changed nothing in a protected root.
    pub(crate) checkpoint: Option<CheckpointSummary>,
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
    /// Where `file.changed`, `checkpoint.uncertain` and `agent.edit` are published.
    pub(crate) events: Arc<dyn CheckpointEvents>,
    /// Where closed edges go (KNSH-081): [`UncapturedEdges`] until the history tree exists.
    pub(crate) edges: Arc<dyn EdgeSink>,
    /// Checkpoint identifiers (KNSH-082).
    pub(crate) random: Arc<dyn Random>,
}

/// One root of one session.
struct RootShadow {
    root: CanonicalPath,
    method: Method,
    /// Its build; `None` when the root has no shadow (module documentation).
    shadow: Option<Arc<Shadow>>,
    /// Its file-event watcher; `None` without a shadow, or when the watcher could not start.
    watcher: Option<Arc<Watcher>>,
    /// Whether its session runs in an envelope, as registered with the attributor (KNSH-081).
    envelope: bool,
}

/// The shadows of every live agent session. One per `knshd`.
pub(crate) struct Shadows {
    parts: ShadowParts,
    sessions: Arc<Table>,
    attributor: Arc<Attributor>,
}

impl Shadows {
    /// No session yet.
    pub(crate) fn new(parts: ShadowParts) -> Arc<Self> {
        let captures = Captures::new(
            Arc::clone(&parts.files),
            Arc::clone(&parts.clock),
            Arc::clone(&parts.random),
        );
        let attributor = Attributor::new(Arc::clone(&parts.events), Arc::clone(&parts.edges), captures);
        Arc::new(Self {
            parts,
            sessions: Arc::new(Mutex::new(BTreeMap::new())),
            attributor,
        })
    }

    fn table(&self) -> MutexGuard<'_, BTreeMap<SessionId, Vec<RootShadow>>> {
        self.sessions.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Starts the shadows of `session_id`'s roots, from `profile` as the session runs it (FR-CKP-01). Returns once
    /// each build has started, without waiting for any. A session with no roots gets nothing. `envelope` tells
    /// whether the session runs in an envelope: changes between its lines are then its agent edits (KNSH-081).
    pub(crate) fn start(&self, session_id: SessionId, profile: &Profile, envelope: bool) {
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
                        // Registered before the watcher can report anything, so its first change is attributed with
                        // the session's envelope known (KNSH-081).
                        self.attributor
                            .with(|ledger, _| ledger.watch(&placed.root, session_id, envelope));
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
                    envelope,
                }
            })
            .collect();
        // A session id is never reused; were it here already, the older builds are stopped, not leaked. Stopped once
        // the table lock is released, which stays a leaf.
        let previous = self.table().insert(session_id, shadows);
        if let Some(previous) = previous {
            self.cancel_all(session_id, &previous);
        }
    }

    /// Stops the builds of `session_id`, which has ended, and forgets them.
    pub(crate) fn end(&self, session_id: SessionId) {
        let removed = self.table().remove(&session_id);
        if let Some(shadows) = removed {
            self.cancel_all(session_id, &shadows);
        }
    }

    /// Stops the builds and the watchers of `session_id`, which ended, then takes its roots out of the attribution
    /// ledger: stopped first, so no change of its watchers arrives after it no longer watches (KNSH-081).
    fn cancel_all(&self, session_id: SessionId, shadows: &[RootShadow]) {
        cancel_all(shadows);
        self.attributor.with(|ledger, _| {
            for entry in shadows.iter().filter(|entry| entry.shadow.is_some()) {
                ledger.unwatch(&entry.root, session_id, entry.envelope);
            }
        });
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
        let (held, held_parents) = held_dir(store, &session_id.to_string(), index);
        let plan = WatchPlan {
            root: root.clone(),
            shadow: shadow.to_path_buf(),
            markers,
            marker_parents,
            held,
            held_parents,
            exclude: profile.checkpoints.exclude.clone(),
            skip: skip.to_vec(),
            latency: STREAM_LATENCY,
            flush_deadline: FLUSH_DEADLINE,
        };
        let report = Arc::new(SessionReport {
            session_id,
            store: store.to_path_buf(),
            events: Arc::clone(&parts.events),
            attributor: Arc::clone(&self.attributor),
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

    /// Line `record_id` of `session_id` touching `roots` starts (KNSH-080, KNSH-081): marks its start in each root
    /// that has a shadow, so [`close_lines`] can tell whether events were lost while it ran, and starts it in the
    /// attribution ledger, so changes in those roots are its own from now on. Never waits.
    pub(crate) fn open_lines(
        &self,
        session_id: SessionId,
        record_id: RecordId,
        roots: &[CanonicalPath],
    ) -> CheckpointLine {
        // Collected under the table lock and marked after it is released: the table is a leaf lock (module
        // documentation), and marking takes each watcher's own.
        let watched: Vec<(CanonicalPath, Option<Arc<Watcher>>)> = {
            let table = self.table();
            let Some(entries) = table.get(&session_id) else {
                return CheckpointLine::unprotected(record_id);
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
        if watched.is_empty() {
            return CheckpointLine::unprotected(record_id);
        }
        let shadowed: Vec<CanonicalPath> = watched.iter().map(|(root, _)| root.clone()).collect();
        self.attributor
            .with(|ledger, _| ledger.line_started(record_id, session_id, &shadowed));
        let roots = watched
            .into_iter()
            .map(|(root, watcher)| OpenLine {
                root,
                watched: watcher.map(|watcher| {
                    let mark = watcher.open_line();
                    (watcher, mark)
                }),
            })
            .collect();
        CheckpointLine {
            record_id,
            roots,
            attributor: Some(Arc::clone(&self.attributor)),
            table: Some(Arc::clone(&self.sessions)),
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

/// The line of `line` has ended and been reaped: closes it in each root (decision 16), one after the other, then
/// ends it in the attribution ledger. Returns the roots whose checkpoints are uncertain, and why (FR-CKP-04; a root
/// without a watcher is `not_watched`), the line's attribution (FR-CKP-05, FR-CKP-07), and its checkpoint (KNSH-082):
/// final when its edge closed with it, the changes so far while a concurrent line still runs.
///
/// The ledger is told last: by then each watcher has applied every event of the line, so all of its changes are
/// attributed before its attribution is read. That includes the watchers other sessions keep on the same roots
/// (flushed, not closed: their uncertainty is their own session's): each reports the line's changes too, and one
/// reported after the line ended would be attributed to whatever follows it, an agent edit of another session
/// for instance (KNSH-081).
pub(crate) fn close_lines(line: CheckpointLine) -> ClosedLine {
    let CheckpointLine {
        record_id,
        roots,
        attributor,
        table,
    } = line;
    let peers = table.map(|table| peer_watchers(&table, &roots)).unwrap_or_default();
    let uncertain = close_roots(roots);
    for peer in peers {
        // Best effort, bounded by the flush deadline: a peer that is late only risks attributing a late event of
        // the line to the next run, which undo's post-image check makes safe (FR-CKP-20).
        let _ = peer.flush();
    }
    let protected = attributor.is_some();
    let ended = attributor.and_then(|attributor| {
        let ended = attributor.with(|ledger, captures| {
            // FR-CKP-04: marked before the line ends, so its checkpoint is uncertain when it is finished.
            if let Some(edge) = ledger.running_edge(record_id) {
                for (_, reason) in &uncertain {
                    captures.mark_uncertain(edge.id, *reason);
                }
            }
            ledger.line_ended(record_id)
        })?;
        Some((ended, attributor.captures.summary(ended.edge)))
    });
    let (attribution, checkpoint) = match ended {
        Some((ended, checkpoint)) => (ended.attribution, checkpoint),
        None => (Attribution::Command, None),
    };
    ClosedLine {
        uncertain,
        attribution,
        protected,
        checkpoint,
    }
}

/// The running watchers on the roots of `lines` other than the line's own: those of other sessions sharing a root.
/// Looked up when the line ends, not when it starts, so a session that started meanwhile is included. Collected
/// under the table lock and used after it is released (module documentation, "Locks").
fn peer_watchers(table: &Table, lines: &[OpenLine]) -> Vec<Arc<Watcher>> {
    let table = table.lock().unwrap_or_else(PoisonError::into_inner);
    let mut peers: Vec<Arc<Watcher>> = Vec::new();
    for line in lines {
        let own = line.watched.as_ref().map(|(watcher, _)| watcher);
        for entry in table.values().flatten() {
            let Some(watcher) = &entry.watcher else {
                continue;
            };
            if entry.root != line.root
                || own.is_some_and(|own| Arc::ptr_eq(own, watcher))
                || peers.iter().any(|kept| Arc::ptr_eq(kept, watcher))
            {
                continue;
            }
            peers.push(Arc::clone(watcher));
        }
    }
    peers
}

/// Runs the line-end procedure in each root of a line, and returns the roots whose checkpoints are uncertain.
fn close_roots(lines: Vec<OpenLine>) -> Vec<(CanonicalPath, UncertainReason)> {
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
