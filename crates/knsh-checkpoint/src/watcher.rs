//! The file-event watcher: keeps each root's shadow in step with the live tree, from file events by any process, and
//! rescans when events are lost (FR-CKP-03, FR-CKP-04, FR-EVT-08, NFR-REL-04, KNSH-080).
//!
//! [`start_watch`] starts one file-event stream per root, on the root and on its marker folder in the root's store,
//! and one worker thread. It is started **before** the shadow build, so a change made while the build runs is not
//! missed: its event waits until the build is complete ([`Watcher::follow`]), then is applied.
//!
//! # Three threads, one lock
//!
//! - **The stream's thread** (the sink, [`FileEventSink`]) only sorts each event and adds its path to a pending set,
//!   under the watcher's lock. It never touches a file, so it never falls behind because of the disk.
//! - **The worker** takes the pending set and brings the shadow in step with each path ([`Watcher`]'s module
//!   documentation below), then reports every path that really changed (`file.changed`) and every uncertain window
//!   outside a line (`checkpoint.uncertain`) through [`WatchReport`].
//! - **The decision path** calls only [`Watcher::open_line`] (no waiting) and [`Watcher::close_line`], the line-end
//!   flush, which is the one place it waits for the watcher (bounded by [`FLUSH_DEADLINE`]).
//!
//! The lock is a leaf: no other lock is taken, and no file is touched, while it is held. The worker releases it
//! before any file operation.
//!
//! # Coalescing with bounded memory
//!
//! Paths are kept relative to the root, once each, in a set of at most [`MAX_PENDING_PATHS`]: a burst touching the
//! same file many times costs one entry. A burst touching more paths than that collapses the set into one rescan of
//! the whole root, which needs no memory per path, and marks the window uncertain (`too_many_events`).
//!
//! # Bringing the shadow in step
//!
//! **Flags are not a change log** (decision 16): an event only means "this path may have changed". For each path, the
//! live entry and its shadow copy are read with `lstat` and compared by kind, size and modification time (a clone
//! keeps both, claim C3):
//!
//! - gone from the live tree: the shadow copy is removed (a folder with everything below it);
//! - a file or symlink that differs, or is new: the shadow copy is replaced by a new clone;
//! - a folder that is new, or replaced something else: created in the shadow, and everything below it is reconciled;
//! - a folder named in an event that created or renamed it: everything below it is reconciled too, since moving a
//!   folder in reports only the folder;
//! - an excluded folder (`checkpoints.exclude`), the store, the engine folders and special files are never shadowed.
//!
//! Only paths that differed are reported as changed, so an event that changed nothing (an attribute the system set,
//! a repeated flag) reports nothing. A missing parent in the shadow is created first. If the root itself is gone or
//! is no longer a folder, nothing is removed from the shadow: it keeps the last known state until the root returns.
//!
//! **Pre-images (KNSH-082, FR-CKP-08).** A shadow copy is never simply deleted: before a file or symlink copy is
//! replaced or removed, it is **moved** (one rename, on the store's volume) into the root's holding folder
//! ([`held_dir`]), and the change is reported with it as its pre-image ([`Change`]). A path that was not in the shadow
//! is reported with the "did not exist" marker, and a folder with a folder marker; a removed folder reports each entry
//! below it as deleted too, each with its own pre-image. The report then decides what to keep ([`crate::capture`]).
//! Right after the shadow follows the path, its **post-image identity** is read from the live tree (FR-CKP-09).
//! Only changed paths are touched, so capture costs as much as the change, not as the root (FR-CKP-10).
//!
//! **Capture failures** never record wrong data and never leave the shadow behind the tree. A copy that cannot be
//! moved is removed as before (the shadow stays consistent) and reported with a *lost* pre-image; a new version that
//! cannot be cloned puts the held copy back, so the shadow keeps its last known state and a later event retries; a
//! post-image that cannot be read is reported *unknown*. Each makes its checkpoint uncertain. Should the copy be
//! neither cloned nor put back, the path is remembered, so a retry reports its pre-image as lost rather than claiming
//! it did not exist.
//!
//! # Lost events and uncertain windows (FR-CKP-04)
//!
//! An event flagged `MustScanSubDirs`, `UserDropped` or `KernelDropped` rescans the folder it names (observed to be
//! the watched root itself, decision 16); one on the marker folder, `EventIdsWrapped` or `RootChanged` rescans the
//! whole root (after checking the root is still a folder). Each also starts a new **uncertain window**: an epoch
//! counter moves on. A line takes the epoch when it starts ([`Watcher::open_line`]) and compares it when it ends
//! ([`Watcher::close_line`]): if it moved, the line's checkpoints are uncertain. A drop while no line is open is
//! reported at once, for the agent edits of that window (`checkpoint.uncertain` with no record).
//!
//! # Closing a line (decision 16)
//!
//! A flush alone does not deliver a line's events (claim C4). [`Watcher::close_line`] creates a marker file in the
//! marker folder, which the same stream watches, then flushes every [`FLUSH_INTERVAL`] until the marker's own event
//! has arrived: by then every earlier event of the line has too, unless events were dropped. It also stops when a drop
//! arrives (the marker folder gets one too) or at [`FLUSH_DEADLINE`] on the injected clock. It then waits, within the
//! same deadline, until the worker has applied everything received so far, so the shadow matches the line's end.
//! A drop, a missing marker or a shadow not settled in time makes the line's checkpoints uncertain.
//!
//! # Restart (NFR-REL-04)
//!
//! [`Watcher::resume`] takes over a shadow left by an earlier `knshd` run: the whole root is rescanned against it and
//! the gap is reported as uncertain (`restart_gap`), since nothing watched the root meanwhile.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::thread;
use std::time::Duration;

use knsh_core::{CanonicalPath, UncertainReason};
use knsh_platform::{
    Clock, FileEvent, FileEventFlags, FileEventSink, FileEventStream, FileEvents, FileIdentity, FileKind, Monotonic,
    PlatformError,
};

use crate::capture::{Change, PostImage, PreImage};
use crate::error::CheckpointError;
use crate::identity::post_image;
use crate::shadow::{MAX_FOLDER_ENTRIES, Shadow, ShadowFiles, ShadowStatus};

/// How long the system may hold events before delivering them. The line-end procedure flushes, so this only bounds
/// how stale the shadow is between lines; 0.05 s was one of the latencies measured for decision 16.
pub const STREAM_LATENCY: Duration = Duration::from_millis(50);

/// Distinct paths kept per root before the watcher falls back to rescanning the whole root (bounded memory).
pub const MAX_PENDING_PATHS: usize = 8192;

/// How long closing a line may take at most: waiting for the marker, then for the shadow to settle (decision 16,
/// proposed 1 s; observed 6.6 to 9.3 ms at p50).
pub const FLUSH_DEADLINE: Duration = Duration::from_secs(1);

/// How often the line-end procedure flushes while it waits for its marker (decision 16).
pub const FLUSH_INTERVAL: Duration = Duration::from_millis(1);

/// The folder below a store that holds marker folders: `<store>/markers/<session>/<root index>/`.
pub const MARKERS_DIR: &str = "markers";

/// The folder below a store that holds pre-images taken out of a shadow, until capture moves them into their
/// checkpoint: `<store>/held/<session>/<root index>/` (KNSH-082).
pub const HELD_DIR: &str = "held";

/// Where the holding folder of a session's root number `index` lives in `store`, and its parents to create, outermost
/// first (KNSH-082). In the store, on the root's volume (a shadow copy is moved, never copied), owner-only and never
/// shadowed or watched.
#[must_use]
pub fn held_dir(store: &Path, session: &str, index: usize) -> (PathBuf, Vec<PathBuf>) {
    let held = store.join(HELD_DIR);
    let session_dir = held.join(session);
    (session_dir.join(index.to_string()), vec![held, session_dir])
}

/// Where the marker folder of a session's root number `index` lives in `store`, and its parents to create, outermost
/// first. In the store, so on the root's volume and owner-only, and never shadowed.
#[must_use]
pub fn marker_dir(store: &Path, session: &str, index: usize) -> (PathBuf, Vec<PathBuf>) {
    let markers = store.join(MARKERS_DIR);
    let session_dir = markers.join(session);
    (session_dir.join(index.to_string()), vec![markers, session_dir])
}

/// Where the watcher reports what it found. Called on the watcher's own thread; must not block for long.
pub trait WatchReport: Send + Sync {
    /// `change.path` under `root` changed, and the shadow now follows it (`file.changed`, FR-EVT-08), with its
    /// pre-image and post-image identity (KNSH-082). A [`PreImage::Held`] file now belongs to the report: it moves it
    /// into a checkpoint or removes it.
    fn changed(&self, root: &CanonicalPath, change: Change);

    /// Events of `root` may have been lost while no line was open, so the root was rescanned
    /// (`checkpoint.uncertain` with no record, FR-CKP-04, NFR-REL-04). Lines learn of theirs from
    /// [`Watcher::close_line`].
    fn uncertain(&self, root: &CanonicalPath, reason: UncertainReason);

    /// Something changed in `folder`, an excluded folder of `root` (`checkpoints.exclude`), which is not shadowed or
    /// captured: an undo lists it as not restored (FR-CKP-31, KNSH-084). Reported once per event, so possibly many
    /// times per folder. Nothing by default.
    fn excluded(&self, root: &CanonicalPath, folder: CanonicalPath) {
        let _ = (root, folder);
    }

    /// The worker has applied one batch of events to the shadow of `root`: every [`WatchReport::changed`] of it has
    /// been called. Where agent edits are reported, one `agent.edit` per batch (KNSH-081). Nothing by default.
    fn settled(&self, root: &CanonicalPath) {
        let _ = root;
    }
}

/// What to watch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WatchPlan {
    /// The checkpoint root.
    pub root: CanonicalPath,
    /// Its shadow folder ([`crate::shadow_dir`]).
    pub shadow: PathBuf,
    /// The marker folder ([`marker_dir`]), created by [`start_watch`] if missing; the same stream watches it.
    pub markers: PathBuf,
    /// Its parents to create if missing, outermost first, each inside the store.
    pub marker_parents: Vec<PathBuf>,
    /// The holding folder for pre-images ([`held_dir`], KNSH-082), created by [`start_watch`] if missing. On the
    /// shadow's volume, and not watched.
    pub held: PathBuf,
    /// Its parents to create if missing, outermost first, each inside the store.
    pub held_parents: Vec<PathBuf>,
    /// Folder names not shadowed, at any depth (`checkpoints.exclude`, FR-CKP-31).
    pub exclude: Vec<String>,
    /// Folders never shadowed, by full path: the checkpoint store and the engine directories.
    pub skip: Vec<PathBuf>,
    /// How long the system may hold events ([`STREAM_LATENCY`] in `knshd`).
    pub latency: Duration,
    /// How long closing a line may take ([`FLUSH_DEADLINE`] in `knshd`).
    pub flush_deadline: Duration,
}

/// A line's view of a root, taken when it starts ([`Watcher::open_line`]). Give it back to
/// [`Watcher::close_line`] when the line ends.
#[derive(Debug)]
#[must_use = "a line mark must be closed with `Watcher::close_line`"]
pub struct LineMark {
    /// The uncertain-window epoch when the line started.
    epoch: u64,
}

/// What closing a line found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LineClose {
    /// Every event of the line arrived and the shadow follows the line's end.
    Certain,
    /// The line's checkpoints in this root are uncertain (FR-CKP-04), and why. The root is rescanned.
    Uncertain(UncertainReason),
}

/// How a pending path is brought in step.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Depth {
    /// The entry itself (and, if it became a folder, everything below it).
    Entry,
    /// The entry and everything below it.
    Tree,
}

/// What the shadow is built from.
enum Basis {
    /// Nothing yet: events are kept, not applied.
    Waiting,
    /// The shadow being built; applied once it is complete.
    Building(Arc<Shadow>),
    /// A complete shadow.
    Ready,
}

/// The watcher's state, under its one lock.
struct State {
    basis: Basis,
    /// Paths to bring in step, relative to the root ("" is the root).
    pending: BTreeMap<PathBuf, Depth>,
    /// The whole root must be rescanned (a drop on the root, wrapped ids, an overflow of `pending`).
    rescan_root: bool,
    /// The uncertain-window epoch: moves on at every drop, wrap, root change or overflow once the shadow is ready.
    epoch: u64,
    /// Why the epoch last moved.
    last_reason: Option<UncertainReason>,
    /// Uncertain windows to report while no line is open, at most one per reason.
    reports: BTreeSet<UncertainReason>,
    /// Lines open now.
    lines_open: usize,
    /// Batches received so far; the worker has applied every batch up to `applied`.
    received: u64,
    applied: u64,
    /// Marker files the line-end procedure is waiting for, and whether each arrived.
    markers: BTreeMap<PathBuf, bool>,
    /// The worker stopped, or should: the session ended, or the shadow build failed.
    stopped: bool,
}

/// Shared between the sink, the worker and the callers.
struct Inner {
    plan: WatchPlan,
    state: Mutex<State>,
    /// Signalled when there is work for the worker, or it should stop.
    work: Condvar,
    /// Signalled when a marker arrives or the worker applied a batch.
    progress: Condvar,
    /// Marker files made so far, for unique names.
    markers_made: AtomicU64,
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    // Every critical section leaves the state consistent at each step, so a panic elsewhere cannot corrupt it.
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The watcher of one root. Dropping the last handle does not stop it: call [`Watcher::stop`].
pub struct Watcher {
    inner: Arc<Inner>,
    files: Arc<dyn ShadowFiles>,
    clock: Arc<dyn Clock>,
    /// The stream; taken (and so stopped) by [`Watcher::stop`].
    stream: Mutex<Option<Box<dyn FileEventStream>>>,
}

/// Starts watching `plan.root`: creates the marker folder, starts the stream on the root and the marker folder, and
/// starts the worker. Events are kept from now on, and applied once [`Watcher::follow`] or [`Watcher::resume`] says
/// what the shadow is.
///
/// # Errors
///
/// [`CheckpointError::Platform`] if the marker folder cannot be made or the stream cannot start;
/// [`CheckpointError::Threads`] if the worker cannot start. Nothing keeps running then.
pub fn start_watch(
    events: &dyn FileEvents,
    files: Arc<dyn ShadowFiles>,
    clock: Arc<dyn Clock>,
    report: Arc<dyn WatchReport>,
    plan: WatchPlan,
) -> Result<Arc<Watcher>, CheckpointError> {
    make_marker_dirs(files.as_ref(), &plan)?;
    let inner = Arc::new(Inner {
        plan,
        state: Mutex::new(State {
            basis: Basis::Waiting,
            pending: BTreeMap::new(),
            rescan_root: false,
            epoch: 0,
            last_reason: None,
            reports: BTreeSet::new(),
            lines_open: 0,
            received: 0,
            applied: 0,
            markers: BTreeMap::new(),
            stopped: false,
        }),
        work: Condvar::new(),
        progress: Condvar::new(),
        markers_made: AtomicU64::new(0),
    });
    let paths = [inner.plan.root.as_path().to_path_buf(), inner.plan.markers.clone()];
    let sink = Arc::new(Sink(Arc::clone(&inner)));
    let stream = events.watch(&paths, inner.plan.latency, sink)?;
    let watcher = Arc::new(Watcher {
        inner: Arc::clone(&inner),
        files: Arc::clone(&files),
        clock,
        stream: Mutex::new(Some(stream)),
    });
    let worker = Worker {
        inner,
        files,
        report,
        held_made: AtomicU64::new(0),
        orphans: Mutex::new(Orphans::default()),
    };
    if thread::Builder::new()
        .name("knsh-watch".into())
        .spawn(move || worker.run())
        .is_err()
    {
        watcher.stop();
        return Err(CheckpointError::Threads);
    }
    Ok(watcher)
}

/// Creates the marker and holding folders and their parents, accepting ones that exist only if they are real folders
/// (never a symlink that would carry markers or pre-images elsewhere).
fn make_marker_dirs(files: &dyn ShadowFiles, plan: &WatchPlan) -> Result<(), CheckpointError> {
    let markers = plan.marker_parents.iter().chain(std::iter::once(&plan.markers));
    let held = plan.held_parents.iter().chain(std::iter::once(&plan.held));
    for dir in markers.chain(held) {
        match files.make_dir(dir) {
            Ok(()) => {}
            Err(error) if is_exists(&error) => match files.kind(dir) {
                Ok(FileKind::Directory) => {}
                Ok(FileKind::File | FileKind::Symlink | FileKind::Other) => {
                    return Err(PlatformError::UnexpectedKind.into());
                }
                Err(error) => return Err(error.into()),
            },
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

impl Watcher {
    /// The root watched.
    #[must_use]
    pub fn root(&self) -> &CanonicalPath {
        &self.inner.plan.root
    }

    /// Applies events once `shadow`'s build is complete. If the build fails or is cancelled, the watcher stops.
    pub fn follow(&self, shadow: Arc<Shadow>) {
        let mut state = lock(&self.inner.state);
        if matches!(state.basis, Basis::Waiting) {
            state.basis = Basis::Building(shadow);
            self.inner.work.notify_all();
        }
    }

    /// Takes over a shadow an earlier `knshd` run left (NFR-REL-04): the whole root is rescanned against it, and the
    /// gap is reported as uncertain (`restart_gap`).
    pub fn resume(&self) {
        let mut state = lock(&self.inner.state);
        if matches!(state.basis, Basis::Waiting) {
            state.basis = Basis::Ready;
            state.rescan_root = true;
            new_window(&mut state, UncertainReason::RestartGap);
            self.inner.work.notify_all();
        }
    }

    /// Stops the stream and the worker. Pending changes are dropped. Idempotent.
    pub fn stop(&self) {
        // Dropping the stream first: once it returns, no event is delivered any more.
        drop(lock(&self.stream).take());
        let mut state = lock(&self.inner.state);
        state.stopped = true;
        self.inner.work.notify_all();
        self.inner.progress.notify_all();
    }

    /// Whether the watcher is running: its shadow is complete (or being built) and it was not stopped.
    #[must_use]
    pub fn is_running(&self) -> bool {
        !lock(&self.inner.state).stopped
    }

    /// A line touching the root starts (FR-CKP-04): takes the uncertain-window epoch. Never waits.
    pub fn open_line(&self) -> LineMark {
        let mut state = lock(&self.inner.state);
        state.lines_open += 1;
        LineMark { epoch: state.epoch }
    }

    /// The line of `mark` has ended and been reaped: the line-end procedure of decision 16 (module documentation).
    /// Returns whether its changes in this root are certain. Waits at most the plan's flush deadline, on the
    /// injected clock.
    #[allow(
        clippy::needless_pass_by_value,
        reason = "taking the mark by value means each line is closed exactly once"
    )]
    pub fn close_line(&self, mark: LineMark) -> LineClose {
        let outcome = self.settle(mark.epoch);
        let mut state = lock(&self.inner.state);
        state.lines_open = state.lines_open.saturating_sub(1);
        outcome
    }

    /// Waits, at most the plan's flush deadline, until every event that happened before this call has been applied
    /// (the procedure of [`Watcher::close_line`] for no line of this watcher). Returns whether it was in time and
    /// no event was lost meanwhile.
    ///
    /// For attribution (KNSH-081): when sessions share a root, each has its own watcher, and a line of one must not
    /// end before the others have reported its changes, or they would be attributed after it. Unlike a line it opens
    /// no window of its own, so an uncertain window it meets is still reported to the watcher's session as usual.
    pub fn flush(&self) -> bool {
        let epoch = lock(&self.inner.state).epoch;
        matches!(self.settle(epoch), LineClose::Certain)
    }

    /// Waits for the marker and then for the worker; see [`Watcher::close_line`].
    fn settle(&self, epoch: u64) -> LineClose {
        let deadline = LineDeadline::start(self.clock.as_ref(), self.inner.plan.flush_deadline);
        {
            let mut state = lock(&self.inner.state);
            if state.stopped {
                return LineClose::Uncertain(UncertainReason::NotWatched);
            }
            if !is_ready(&mut state) {
                // A shadow still being built when the line started: its record already says the root is not
                // protected (FR-CKP-02), and there is nothing to settle against yet.
                return LineClose::Certain;
            }
            self.inner.work.notify_all();
        }
        let marker = self.next_marker();
        lock(&self.inner.state).markers.insert(marker.clone(), false);
        let marker_in_time = self.await_marker(&marker, epoch, &deadline);
        let mut state = lock(&self.inner.state);
        state.markers.remove(&marker);
        let (mut state, applied_in_time) = self.await_applied(state, &deadline);
        // Checked in this order: a stopped watcher explains everything after it, and a new window carries a more
        // precise reason than a timeout it may have caused.
        if state.stopped {
            return LineClose::Uncertain(UncertainReason::NotWatched);
        }
        if state.epoch != epoch {
            return LineClose::Uncertain(state.last_reason.unwrap_or(UncertainReason::EventsDropped));
        }
        if !(marker_in_time && applied_in_time) {
            // The line's events are not known to be complete: rescan, as for a drop.
            state.rescan_root = true;
            self.inner.work.notify_all();
            return LineClose::Uncertain(UncertainReason::FlushTimedOut);
        }
        LineClose::Certain
    }

    /// Creates `marker`, then flushes every [`FLUSH_INTERVAL`] until its event arrives, a new uncertain window opens
    /// or the watcher stops. Returns `false` if the marker could not be made or the deadline passed first.
    fn await_marker(&self, marker: &Path, epoch: u64, deadline: &LineDeadline<'_>) -> bool {
        if self.files.create_file(marker).is_err() {
            // Without a marker there is no way to know the line's events all arrived.
            return false;
        }
        let mut flushes = 0u64;
        let in_time = loop {
            if let Some(stream) = lock(&self.stream).as_ref() {
                stream.flush();
            }
            {
                let state = lock(&self.inner.state);
                let arrived = state.markers.get(marker).copied().unwrap_or(false);
                // A drop ends the wait at once: the marker may never come (decision 16). The caller then reports
                // the drop, not a timeout.
                if arrived || state.epoch != epoch || state.stopped {
                    break true;
                }
            }
            flushes += 1;
            if deadline.passed(flushes) {
                break false;
            }
            self.clock.sleep(FLUSH_INTERVAL);
        };
        // Best effort: a marker left behind is only an empty file in the store.
        let _ = self.files.remove(marker, false);
        in_time
    }

    /// Waits until the worker has applied every batch received so far (the line's events, up to its marker), so the
    /// shadow matches the line's end. Returns the guard and `false` if the deadline passed first.
    fn await_applied<'a>(
        &'a self,
        mut state: MutexGuard<'a, State>,
        deadline: &LineDeadline<'_>,
    ) -> (MutexGuard<'a, State>, bool) {
        let target = state.received;
        let mut waits = 0u64;
        while state.applied < target && !state.stopped {
            if deadline.passed(waits) {
                return (state, false);
            }
            let (next, _) = self
                .inner
                .progress
                .wait_timeout(state, FLUSH_INTERVAL)
                .unwrap_or_else(PoisonError::into_inner);
            state = next;
            // The worker runs on real time, so this wait is also bounded by a count of real slices.
            waits += 1;
        }
        (state, true)
    }

    /// A new marker path, unique for this watcher.
    fn next_marker(&self) -> PathBuf {
        let n = self.inner.markers_made.fetch_add(1, Ordering::Relaxed);
        self.inner.plan.markers.join(format!("m-{n}"))
    }
}

/// The flush deadline of one line end, shared by its two waits (the marker, then the worker).
struct LineDeadline<'a> {
    clock: &'a dyn Clock,
    started: Monotonic,
    limit: Duration,
    /// [`flushes_within`] `limit`: the bound on slices of one wait.
    max_slices: u64,
}

impl<'a> LineDeadline<'a> {
    fn start(clock: &'a dyn Clock, limit: Duration) -> Self {
        Self {
            clock,
            started: clock.monotonic(),
            limit,
            max_slices: flushes_within(limit),
        }
    }

    /// Whether a wait that has used `slices` of [`FLUSH_INTERVAL`] must stop: the injected clock reached the limit,
    /// or the slices did (a clock that does not move must not make the wait endless).
    fn passed(&self, slices: u64) -> bool {
        self.clock.monotonic().saturating_duration_since(self.started) >= self.limit || slices >= self.max_slices
    }
}

/// Flushes (or waits) of [`FLUSH_INTERVAL`] that fit in `deadline`, at least one: a second bound beside the clock,
/// so a clock that does not move cannot make the wait endless.
fn flushes_within(deadline: Duration) -> u64 {
    // One more than the slices that fit, so with a clock that moves the clock deadline is the one reached.
    let slices = deadline.as_nanos() / FLUSH_INTERVAL.as_nanos().max(1);
    u64::try_from(slices).unwrap_or(u64::MAX).saturating_add(1)
}

/// Whether the shadow is complete. A build that completed but that the worker has not noticed yet counts, and is
/// recorded as the basis now, so events and lines right after the build are treated as after it. (Lock order: the
/// watcher's lock, then the shadow's own; the shadow never takes the watcher's.)
fn is_ready(state: &mut State) -> bool {
    let complete = match &state.basis {
        Basis::Ready => return true,
        Basis::Building(shadow) => matches!(shadow.status(), ShadowStatus::Complete(_)),
        Basis::Waiting => false,
    };
    if complete {
        state.basis = Basis::Ready;
    }
    complete
}

/// Starts a new uncertain window for `reason`, and queues its report if no line is open to report it.
fn new_window(state: &mut State, reason: UncertainReason) {
    state.epoch += 1;
    state.last_reason = Some(reason);
    if state.lines_open == 0 {
        state.reports.insert(reason);
    }
}

/// The stream's sink: sorts events into the pending set. Runs on the stream's thread; never touches a file.
struct Sink(Arc<Inner>);

impl FileEventSink for Sink {
    fn deliver(&self, events: &[FileEvent]) {
        let inner = &self.0;
        let mut state = lock(&inner.state);
        if state.stopped {
            return;
        }
        for event in events {
            sort(&inner.plan, &mut state, event);
        }
        state.received += 1;
        inner.work.notify_all();
        inner.progress.notify_all();
    }
}

/// Adds one event to the state.
fn sort(plan: &WatchPlan, state: &mut State, event: &FileEvent) {
    let ready = is_ready(state);
    let flags = event.flags;
    if let Some(arrived) = state.markers.get_mut(&event.path) {
        *arrived = true;
    }
    let in_markers = event.path.starts_with(&plan.markers);
    // These concern the whole stream, not one path: a drop reported on the marker folder means the root's events may
    // have been lost too, since one stream carries both.
    let whole_root = if flags.ids_wrapped() {
        Some(UncertainReason::EventIdsWrapped)
    } else if flags.root_changed() {
        Some(UncertainReason::RootChanged)
    } else if flags.needs_rescan() && in_markers {
        Some(UncertainReason::EventsDropped)
    } else {
        None
    };
    if let Some(reason) = whole_root {
        rescan_all(state, ready, reason);
        return;
    }
    // Marker files are the line-end procedure's own; they are never shadowed.
    if in_markers {
        return;
    }
    let Ok(relative) = event.path.strip_prefix(plan.root.as_path()) else {
        return;
    };
    // Never shadowed: the shadow, the store and the engine folders. When the root holds the store, the worker's own
    // clones come back as events; dropped here, they neither fill the pending set (and collapse it into a
    // `too_many_events` window) nor wake the worker for nothing.
    if plan.skip.iter().any(|skip| event.path.starts_with(skip)) || event.path.starts_with(&plan.shadow) {
        return;
    }
    if flags.needs_rescan() {
        // A drop on the root itself is a whole-root rescan; one on a folder below it rescans only that folder.
        if relative.as_os_str().is_empty() {
            rescan_all(state, ready, UncertainReason::EventsDropped);
        } else {
            add(state, ready, relative, Depth::Tree);
            if ready {
                new_window(state, UncertainReason::EventsDropped);
            }
        }
        return;
    }
    // A folder created or moved in reports only itself, so everything below it is reconciled too.
    let depth = if flags.is_dir() && flags.intersects(FileEventFlags::ITEM_CREATED.union(FileEventFlags::ITEM_RENAMED))
    {
        Depth::Tree
    } else {
        Depth::Entry
    };
    add(state, ready, relative, depth);
}

/// Queues a rescan of the whole root, and opens an uncertain window once the shadow is ready (before that, the
/// rescan only completes what the build saw; no checkpoint exists yet).
fn rescan_all(state: &mut State, ready: bool, reason: UncertainReason) {
    state.rescan_root = true;
    state.pending.clear();
    if ready {
        new_window(state, reason);
    }
}

/// Adds `relative` to the pending set, keeping the deeper of two depths. Past [`MAX_PENDING_PATHS`] distinct paths the
/// set collapses into one rescan of the root (bounded memory).
fn add(state: &mut State, ready: bool, relative: &Path, depth: Depth) {
    if state.rescan_root {
        return;
    }
    if let Some(kept) = state.pending.get_mut(relative) {
        *kept = (*kept).max(depth);
        return;
    }
    if state.pending.len() >= MAX_PENDING_PATHS {
        rescan_all(state, ready, UncertainReason::TooManyEvents);
        return;
    }
    state.pending.insert(relative.to_path_buf(), depth);
}

/// One batch of work, taken from the state.
struct Batch {
    rescan_root: bool,
    pending: BTreeMap<PathBuf, Depth>,
    reports: BTreeSet<UncertainReason>,
    /// The batches received when this was taken.
    received: u64,
}

/// Paths remembered as having lost their shadow copy ([`Worker::orphans`]) at most. Beyond, the watcher no longer
/// knows which paths the shadow lacks, so every path missing from the shadow reports a lost pre-image from then on:
/// uncertain, never "did not exist".
const MAX_ORPHANS: usize = 8192;

/// How many names in the holding folder [`InStep::discard`] tries before giving a pre-image up as lost: a name can be
/// taken by a pre-image an earlier run left behind (it never replaces one).
const HELD_ATTEMPTS: usize = 64;

/// The paths whose shadow copy was taken out and could be neither replaced nor put back ([`Worker::orphans`]).
#[derive(Default)]
struct Orphans {
    /// Relative to the root, at most [`MAX_ORPHANS`].
    paths: BTreeSet<PathBuf>,
    /// One more did not fit: any path missing from the shadow may be one.
    overflowed: bool,
}

impl Orphans {
    /// Remembers `relative` as an orphan.
    fn remember(&mut self, relative: &Path) {
        if self.paths.len() < MAX_ORPHANS {
            self.paths.insert(relative.to_path_buf());
        } else {
            self.overflowed = true;
        }
    }

    /// Whether `relative`, missing from the shadow, may have held something the shadow lost.
    fn may_hold(&self, relative: &Path) -> bool {
        self.overflowed || self.paths.contains(relative)
    }
}

/// The worker thread.
struct Worker {
    inner: Arc<Inner>,
    files: Arc<dyn ShadowFiles>,
    report: Arc<dyn WatchReport>,
    /// Pre-images held so far, for unique names in the holding folder.
    held_made: AtomicU64,
    /// Paths, relative to the root, whose shadow copy was taken out and could be neither replaced nor put back
    /// (module documentation, "Capture failures"): the shadow no longer knows what they held, so their next change
    /// reports a lost pre-image, never "did not exist". Only the worker uses it; the lock is uncontended.
    orphans: Mutex<Orphans>,
}

impl Worker {
    fn run(&self) {
        if !self.wait_for_shadow() {
            return;
        }
        while let Some(batch) = self.next_batch() {
            for reason in &batch.reports {
                self.report.uncertain(&self.inner.plan.root, *reason);
            }
            let failed = self.apply(&batch);
            // Before the batch counts as applied, so a line end waiting for it sees what this reports (KNSH-081).
            self.report.settled(&self.inner.plan.root);
            let mut state = lock(&self.inner.state);
            if failed {
                // The shadow may not follow the live tree: a later event retries the paths; the window is uncertain.
                new_window(&mut state, UncertainReason::ShadowUpdateFailed);
            }
            state.applied = state.applied.max(batch.received);
            self.inner.progress.notify_all();
        }
    }

    /// Waits until the shadow is complete; `false` if the watcher stopped or the build did not complete (it then
    /// stops: an incomplete shadow cannot be kept in step).
    fn wait_for_shadow(&self) -> bool {
        loop {
            let shadow = {
                let mut state = lock(&self.inner.state);
                loop {
                    if state.stopped {
                        return false;
                    }
                    match &state.basis {
                        Basis::Ready => return true,
                        Basis::Building(shadow) => break Arc::clone(shadow),
                        Basis::Waiting => {
                            state = self.inner.work.wait(state).unwrap_or_else(PoisonError::into_inner);
                        }
                    }
                }
            };
            // Waited on outside the lock, in slices, so a stop is seen.
            match shadow.wait(Duration::from_millis(100)) {
                ShadowStatus::Building(_) => {}
                ShadowStatus::Complete(_) => {
                    lock(&self.inner.state).basis = Basis::Ready;
                    return true;
                }
                ShadowStatus::Failed(_) | ShadowStatus::Cancelled => {
                    let mut state = lock(&self.inner.state);
                    state.stopped = true;
                    self.inner.progress.notify_all();
                    return false;
                }
            }
        }
    }

    /// Waits for work and takes it; `None` once stopped.
    fn next_batch(&self) -> Option<Batch> {
        let mut state = lock(&self.inner.state);
        loop {
            if state.stopped {
                self.inner.progress.notify_all();
                return None;
            }
            let has_work = state.rescan_root
                || !state.pending.is_empty()
                || !state.reports.is_empty()
                || state.received > state.applied;
            if has_work {
                break;
            }
            state = self.inner.work.wait(state).unwrap_or_else(PoisonError::into_inner);
        }
        Some(Batch {
            rescan_root: std::mem::take(&mut state.rescan_root),
            pending: std::mem::take(&mut state.pending),
            reports: std::mem::take(&mut state.reports),
            received: state.received,
        })
    }

    /// Brings the shadow in step with `batch`. Returns whether a file operation failed.
    fn apply(&self, batch: &Batch) -> bool {
        let step = InStep {
            plan: &self.inner.plan,
            files: self.files.as_ref(),
            report: self.report.as_ref(),
            held_made: &self.held_made,
            orphans: &self.orphans,
        };
        // The root must still be a folder; otherwise the shadow keeps its last known state (module documentation).
        match self.files.kind(self.inner.plan.root.as_path()) {
            Ok(FileKind::Directory) => {}
            Ok(FileKind::File | FileKind::Symlink | FileKind::Other) => return false,
            Err(error) if error.is_not_found() => return false,
            Err(_) => return true,
        }
        if batch.rescan_root {
            return step.path(Path::new(""), Depth::Tree).is_err();
        }
        let mut failed = false;
        // Sorted, so a folder comes before what is below it; below a reconciled tree, nothing is left to do.
        let mut done: Option<&Path> = None;
        for (relative, depth) in &batch.pending {
            if done.is_some_and(|tree| relative.starts_with(tree)) {
                continue;
            }
            if step.entry(relative, *depth).is_err() {
                failed = true;
            }
            if *depth == Depth::Tree {
                done = Some(relative);
            }
        }
        failed
    }
}

/// One pass of bringing paths in step.
struct InStep<'a> {
    plan: &'a WatchPlan,
    files: &'a dyn ShadowFiles,
    report: &'a dyn WatchReport,
    held_made: &'a AtomicU64,
    orphans: &'a Mutex<Orphans>,
}

/// A file operation failed; the path stays as it was.
struct Failed;

impl InStep<'_> {
    /// Brings a pending path in step, after making sure every folder above it is a real folder on both sides.
    ///
    /// `lstat` follows every component but the last, and the shadow holds clones of the root's symlinks. A pending
    /// path below a folder the agent has since replaced by a symlink (`rm -r d; ln -s ../../x d`, then `d/f`'s own
    /// event) would otherwise be read, cloned into or removed **through** the shadow's copy of that symlink: outside
    /// the shadow, in any folder the user can write. So each folder above the entry is checked outermost first, by
    /// `lstat` on both sides; at the first one that is not a folder on both sides, that folder is brought in step
    /// instead (which replaces or removes everything below it in the shadow) and the entry is left alone.
    fn entry(&self, relative: &Path, depth: Depth) -> Result<(), Failed> {
        // Each event's own path (never a rescan passing by, which would list excluded folders on every rescan).
        self.report_excluded(relative);
        if !self.watched(relative) {
            return Ok(());
        }
        let mut above = PathBuf::new();
        let parents: Vec<&OsStr> = relative.parent().map_or_else(Vec::new, |parent| {
            parent.components().map(Component::as_os_str).collect()
        });
        for name in parents {
            above.push(name);
            let live = self.read(&self.plan.root.as_path().join(&above))?;
            let copy = self.read(&self.plan.shadow.join(&above))?;
            let both_folders = live.is_some_and(|live| live.kind == FileKind::Directory)
                && copy.is_some_and(|copy| copy.kind == FileKind::Directory);
            if !both_folders {
                // A live folder makes a missing or wrong copy a new folder, reconciled with everything below it (the
                // entry included); anything else replaces or removes the copy, and the entry with it.
                return self.path(&above, Depth::Entry);
            }
        }
        self.path(relative, depth)
    }

    /// Brings the shadow copy of `relative` in step with the live entry (module documentation). Every folder above
    /// `relative` must already be a real folder in the shadow ([`InStep::entry`]).
    fn path(&self, relative: &Path, depth: Depth) -> Result<(), Failed> {
        if !self.watched(relative) {
            return Ok(());
        }
        let live = self.plan.root.as_path().join(relative);
        let copy = self.plan.shadow.join(relative);
        let now = self.read(&live)?;
        if now.is_some() {
            // The shadow folder holding it first; bringing that in step may already have handled this entry, so the
            // copy is read after.
            self.parent(relative)?;
        }
        let then = self.read(&copy)?;
        match (now, then) {
            (None, None) => Ok(()),
            // Gone from the live tree: so from the shadow (a folder with everything below it), each copy kept as a
            // pre-image.
            (None, Some(then)) => {
                let pre = self.discard(&live, &copy, then.kind)?;
                self.report(relative, &live, pre, PostImage::Deleted);
                Ok(())
            }
            (Some(now), then) => match now.kind {
                FileKind::Directory => self.folder(relative, &live, &copy, then, depth),
                FileKind::File | FileKind::Symlink => {
                    if then.is_some_and(|then| same(&now, &then)) {
                        return Ok(());
                    }
                    let pre = self.pre_image(relative, &live, &copy, then)?;
                    match self.files.clone_file(&live, &copy) {
                        Ok(()) => {}
                        // Removed since it was read: what the shadow held is now deleted. Its own event finds nothing
                        // left to do, so the change is reported here.
                        Err(error) if error.is_not_found() => {
                            self.report(relative, &live, pre, PostImage::Deleted);
                            return Ok(());
                        }
                        Err(_) => return Err(self.put_back(relative, &live, &copy, pre)),
                    }
                    let post = self.post_image(&live);
                    self.report(relative, &live, pre, post);
                    Ok(())
                }
                // Special files hold no contents to restore and are never shadowed; a copy of what was there before
                // is taken out, since the path no longer holds it.
                FileKind::Other => {
                    if let Some(then) = then {
                        let pre = self.discard(&live, &copy, then.kind)?;
                        let post = self.post_image(&live);
                        self.report(relative, &live, pre, post);
                    }
                    Ok(())
                }
            },
        }
    }

    /// A live folder at `relative`.
    fn folder(
        &self,
        relative: &Path,
        live: &Path,
        copy: &Path,
        then: Option<FileIdentity>,
        depth: Depth,
    ) -> Result<(), Failed> {
        // An excluded folder is never shadowed (FR-CKP-31); only folders are excluded.
        if self.excluded_name(relative) {
            return Ok(());
        }
        let pre = match then {
            Some(then) if then.kind == FileKind::Directory => None,
            then => Some(self.pre_image(relative, live, copy, then)?),
        };
        let created = pre.is_some();
        if let Some(pre) = pre {
            match self.files.make_dir(copy) {
                Ok(()) => {}
                Err(error) if is_exists(&error) => {}
                Err(_) => return Err(self.put_back(relative, live, copy, pre)),
            }
            let post = self.post_image(live);
            self.report(relative, live, pre, post);
        }
        if created || depth == Depth::Tree {
            self.reconcile(relative, live, copy)?;
        }
        Ok(())
    }

    /// Brings every entry below the folder `relative` in step: names in either tree, each as a tree.
    fn reconcile(&self, relative: &Path, live: &Path, copy: &Path) -> Result<(), Failed> {
        let mut names: BTreeSet<OsString> = BTreeSet::new();
        for folder in [live, copy] {
            match self.files.list(folder, MAX_FOLDER_ENTRIES) {
                Ok(listed) => names.extend(listed),
                // Gone since it was read: its own event follows.
                Err(error) if error.is_not_found() => {}
                Err(_) => return Err(Failed),
            }
        }
        let mut result = Ok(());
        for name in names.iter().filter(|name| is_entry_name(name)) {
            if self.path(&relative.join(name), Depth::Tree).is_err() {
                result = Err(Failed);
            }
        }
        result
    }

    /// Makes sure the shadow folder holding `relative` exists, bringing the parent in step first if not.
    fn parent(&self, relative: &Path) -> Result<(), Failed> {
        let Some(parent) = relative.parent() else {
            return Ok(());
        };
        if parent.as_os_str().is_empty() {
            return Ok(());
        }
        match self.read(&self.plan.shadow.join(parent))? {
            Some(identity) if identity.kind == FileKind::Directory => Ok(()),
            // Missing or not a folder: the parent's own change was not applied yet (it is pending, or was lost).
            Some(_) | None => self.path(parent, Depth::Entry),
        }
    }

    /// The identity at `path`, `None` if nothing is there.
    fn read(&self, path: &Path) -> Result<Option<FileIdentity>, Failed> {
        match self.files.identity(path) {
            Ok(identity) => Ok(Some(identity)),
            Err(error) if error.is_not_found() => Ok(None),
            Err(_) => Err(Failed),
        }
    }

    /// What the shadow held at `relative` before this change, taken out of the shadow so the new version can take its
    /// place: the "did not exist" marker when it held nothing (or a lost pre-image for an [orphan](Worker::orphans)),
    /// else [`InStep::discard`].
    fn pre_image(
        &self,
        relative: &Path,
        live: &Path,
        copy: &Path,
        then: Option<FileIdentity>,
    ) -> Result<PreImage, Failed> {
        match then {
            Some(then) => self.discard(live, copy, then.kind),
            None if lock(self.orphans).may_hold(relative) => Ok(PreImage::Lost),
            None => Ok(PreImage::NotExisted),
        }
    }

    /// Takes the shadow entry `copy` (of the live path `live`) out of the shadow and returns it as a pre-image
    /// (FR-CKP-08). A file or symlink is moved into the holding folder; if that fails it is removed instead, so the
    /// shadow stays consistent, and its pre-image is lost. A folder is a folder marker: everything below it is taken out
    /// first, and each entry reported deleted with its own pre-image. Never follows a symlink: a folder is entered only
    /// if `lstat` says it is one.
    fn discard(&self, live: &Path, copy: &Path, kind: FileKind) -> Result<PreImage, Failed> {
        match kind {
            FileKind::File | FileKind::Symlink => {
                for _ in 0..HELD_ATTEMPTS {
                    let held = self.next_held();
                    match self.files.rename_new(copy, &held) {
                        Ok(()) => return Ok(PreImage::Held(held)),
                        // A name an earlier run left taken: never replaced, the next one is tried.
                        Err(error) if is_exists(&error) => {}
                        // Gone since it was read: nothing left to keep or remove.
                        Err(error) if error.is_not_found() => return Ok(PreImage::Lost),
                        Err(_) => break,
                    }
                }
                self.remove_entry(copy, false)?;
                Ok(PreImage::Lost)
            }
            FileKind::Directory => {
                let names = match self.files.list(copy, MAX_FOLDER_ENTRIES) {
                    Ok(names) => names,
                    Err(error) if error.is_not_found() => return Ok(PreImage::Folder),
                    Err(_) => return Err(Failed),
                };
                for name in names.iter().filter(|name| is_entry_name(name)) {
                    let (entry, below) = (copy.join(name), live.join(name));
                    if let Some(identity) = self.read(&entry)? {
                        let pre = self.discard(&below, &entry, identity.kind)?;
                        if let Ok(relative) = below.strip_prefix(self.plan.root.as_path()) {
                            self.report(relative, &below, pre, PostImage::Deleted);
                        }
                    }
                }
                self.remove_entry(copy, true)?;
                Ok(PreImage::Folder)
            }
            // The shadow never holds special files; one found there is removed, and what it held is unknown.
            FileKind::Other => {
                self.remove_entry(copy, false)?;
                Ok(PreImage::Lost)
            }
        }
    }

    /// The new version of `relative` could not be put in the shadow after its copy was taken out as `pre`. The copy is
    /// moved back, so the shadow keeps its last known state and a later event retries (module documentation,
    /// "Capture failures"). If it cannot be, the change is reported with the pre-image it has and an unknown
    /// post-image, and the path is remembered as an orphan.
    fn put_back(&self, relative: &Path, live: &Path, copy: &Path, pre: PreImage) -> Failed {
        match &pre {
            // Nothing was taken out: the shadow is as it was.
            PreImage::NotExisted => return Failed,
            PreImage::Held(held) if self.files.rename_new(held, copy).is_ok() => return Failed,
            PreImage::Held(_) | PreImage::Folder | PreImage::Lost => {}
        }
        self.report(relative, live, pre, PostImage::Unknown);
        lock(self.orphans).remember(relative);
        Failed
    }

    /// The post-image identity of the live path `live`, read right after the shadow followed it (FR-CKP-09). A path
    /// removed since is deleted: its own event follows, and reports the removal.
    fn post_image(&self, live: &Path) -> PostImage {
        post_image(self.files, live)
    }

    /// A new path in the holding folder, unique for this watcher.
    fn next_held(&self) -> PathBuf {
        let n = self.held_made.fetch_add(1, Ordering::Relaxed);
        self.plan.held.join(format!("p-{n}"))
    }

    /// Removes the shadow entry `copy`: an empty folder (`folder`), or a file or symlink. Gone already is fine.
    fn remove_entry(&self, copy: &Path, folder: bool) -> Result<(), Failed> {
        match self.files.remove(copy, folder) {
            Ok(()) => Ok(()),
            Err(error) if error.is_not_found() => Ok(()),
            Err(_) => Err(Failed),
        }
    }

    /// Whether `relative` is shadowed at all: inside no excluded folder, the store, the engine folders or the shadow.
    fn watched(&self, relative: &Path) -> bool {
        // Event paths come from the system; a component that would leave the root is never joined.
        if relative
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
        {
            return false;
        }
        let live = self.plan.root.as_path().join(relative);
        if self.plan.skip.iter().any(|skip| live.starts_with(skip)) || live.starts_with(&self.plan.shadow) {
            return false;
        }
        // Every folder above the entry: excluded by name at any depth (the entry itself is checked once it is known
        // to be a folder).
        let mut above = relative.components();
        above.next_back();
        !above.any(|component| self.is_excluded(component.as_os_str()))
    }

    /// Reports the outermost excluded folder at or above `relative` as changed (FR-CKP-31), if there is one and the
    /// path is otherwise one the watcher follows (not the store, the engine folders or the shadow). Only folders are
    /// excluded: an entry that merely has an excluded name is reported only while it is a folder.
    fn report_excluded(&self, relative: &Path) {
        if relative
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
        {
            return;
        }
        let live = self.plan.root.as_path().join(relative);
        if self.plan.skip.iter().any(|skip| live.starts_with(skip)) || live.starts_with(&self.plan.shadow) {
            return;
        }
        let mut folder = PathBuf::new();
        let mut components = relative.components().peekable();
        while let Some(component) = components.next() {
            folder.push(component);
            if !self.is_excluded(component.as_os_str()) {
                continue;
            }
            let path = self.plan.root.as_path().join(&folder);
            let last = components.peek().is_none();
            if last && !matches!(self.files.kind(&path), Ok(FileKind::Directory)) {
                // A file named like an excluded folder is protected like any other (or already gone).
                return;
            }
            if let Ok(folder) = CanonicalPath::new(path) {
                self.report.excluded(&self.plan.root, folder);
            }
            return;
        }
    }

    /// Whether the last name of `relative` is an excluded folder name.
    fn excluded_name(&self, relative: &Path) -> bool {
        relative.file_name().is_some_and(|name| self.is_excluded(name))
    }

    fn is_excluded(&self, name: &OsStr) -> bool {
        name.to_str()
            .is_some_and(|name| self.plan.exclude.iter().any(|excluded| excluded == name))
    }

    /// Reports the change of `relative` (at `live`) with its pre-image and post-image. A path that is not canonical (it
    /// cannot be, from a canonical root and normal names) is not reported, and its held pre-image is removed. The path
    /// is no longer an [orphan](Worker::orphans): the shadow follows it again, or its change was reported.
    fn report(&self, relative: &Path, live: &Path, pre: PreImage, post: PostImage) {
        if !matches!(post, PostImage::Unknown) {
            lock(self.orphans).paths.remove(relative);
        }
        match CanonicalPath::new(live) {
            Ok(path) => self.report.changed(&self.plan.root, Change { path, pre, post }),
            Err(_) => {
                if let PreImage::Held(held) = pre {
                    let _ = self.files.remove(&held, false);
                }
            }
        }
    }
}

/// Whether a live entry and its shadow copy hold the same thing: kind, size and modification time (a clone keeps
/// size and `mtime`, claim C3; the inode differs by design).
fn same(now: &FileIdentity, then: &FileIdentity) -> bool {
    now.kind == then.kind && now.size == then.size && now.modified == then.modified
}

/// Whether a listed name is a real entry: never `.`, `..` or empty, which would name the folder itself or its parent.
fn is_entry_name(name: &OsStr) -> bool {
    name != "." && name != ".." && !name.is_empty()
}

/// `EEXIST` from any operation.
fn is_exists(error: &PlatformError) -> bool {
    // `libc` is reserved to `knsh-platform` (NFR-SUP-02); `EEXIST` is 17 on every system this builds for.
    const EEXIST: i32 = 17;
    matches!(error, PlatformError::Os { errno: EEXIST, .. })
}

#[cfg(test)]
mod tests;
