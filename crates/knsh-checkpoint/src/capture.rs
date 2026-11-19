//! Capture: each change's pre-images and post-image identities, stored as a checkpoint (FR-CKP-08 to FR-CKP-11,
//! KNSH-082).
//!
//! # How a checkpoint is taken
//!
//! 1. **The watcher sets each shadow copy aside** before it replaces or removes it ([`crate::watcher`]): the copy is
//!    moved, one rename on the store's volume, into the root's holding folder, and the change is reported as a
//!    [`Change`]: the path, its [`PreImage`] (the held copy, a "did not exist" marker, a folder marker, or *lost*),
//!    and its [`PostImage`] (the live path's identity right after the change, or *deleted*).
//! 2. **The change is attributed** to the open edge of its root ([`crate::Ledger`]), under the ledger's lock, which
//!    also starts its capture here ([`Captures::begin`]), so an edge never closes between the two.
//! 3. **[`Captures::add`] keeps it in the edge's checkpoint.** The first pre-image of a path in an edge is the one
//!    kept: it is what the path held before the edge. A held copy is moved again, into
//!    `<store>/checkpoints/<checkpoint id>/`, the checkpoint's own folder in the root's store (same volume, so still
//!    a rename). A later change of the same path in the same edge only updates its post-image, and its held copy (an
//!    intermediate version) is removed.
//! 4. **When the ledger closes the edge** ([`Captures::closed`]) and no change of it is still being added, the
//!    checkpoint is final: a [`Checkpoint`], for `checkpoint.created` (FR-CKP-11) and the history tree (KNSH-083).
//!
//! Nothing here walks a root or reads a file's contents: the cost is a few renames per changed path, so it grows with
//! the change, not with the project (FR-CKP-10). The post-image hash, the one read of contents, was taken by the
//! watcher for files under 64 MiB only (FR-CKP-09).
//!
//! # Uncertain, never wrong
//!
//! A checkpoint is **uncertain** when events may have been lost in its window (FR-CKP-04, marked by `knshd` through
//! [`Captures::mark_uncertain`]), or when capture itself failed ([`UncertainReason::CaptureFailed`]): a pre-image the
//! watcher could not set aside or that could not be moved into the checkpoint, or a post-image that could not be read.
//! The path is then recorded as [`StoredPreImage::Lost`] or [`PostImage::Unknown`], never with a guess (a lost copy is
//! never "did not exist"). The watcher keeps the shadow consistent in each case.
//!
//! # Bounds and locks
//!
//! A checkpoint lists at most [`MAX_CHECKPOINT_PATHS`] paths; further paths make it uncertain (`too_many_events`)
//! and their held copies are removed. Only a small summary of each finished checkpoint is kept, for the line's record
//! ([`Captures::summary`]), and only until [`RECENT_CHECKPOINTS`] newer ones exist: the full checkpoint goes to whoever
//! finished it, and the history tree (KNSH-083) is where checkpoints are kept for good.
//!
//! The captures lock is taken under the ledger's lock (lock order: ledger, then captures) and never the other way
//! round. Renames and removals happen outside it, except creating a checkpoint's folder (once per checkpoint and
//! store), so two changes of one checkpoint never race to create it.
//!
//! **Pending:** checkpoints are not yet written to disk with an index of their paths (the history tree's persistence,
//! KNSH-083). Retention removes a checkpoint's folder once the checkpoint is in the history ([`crate::retention`],
//! KNSH-087); until `knshd` feeds the history (KNSH-088), finished checkpoints are not removed. Pre-images of changes
//! no session claimed are removed at once.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use knsh_core::{
    Attribution, CanonicalPath, ChangedFile, CheckpointId, FileChange, MAX_RECORD_FILES_CHANGED, RecordId,
    RecordedIdentity, SessionId, TornReason, Ulid, UncertainReason,
};
use knsh_platform::{Clock, FileKind, PlatformError, Random};

use crate::attribution::{Edge, EdgeId, MAX_EDGE_PATHS};
use crate::identity::PostImageIdentity;
use crate::shadow::ShadowFiles;
use crate::torn::{MAX_TORN_PATHS, sqlite_marks};

/// The folder below a store that holds checkpoints: `<store>/checkpoints/<checkpoint id>/`.
pub const CHECKPOINTS_DIR: &str = "checkpoints";

/// The most paths one checkpoint lists: as many as an edge ([`MAX_EDGE_PATHS`]).
pub const MAX_CHECKPOINT_PATHS: usize = MAX_EDGE_PATHS;

/// The most excluded folders one checkpoint lists (FR-CKP-31); more are not listed, and the checkpoint says so
/// ([`Checkpoint::excluded_overflowed`]).
pub const MAX_EXCLUDED: usize = 256;

/// Finished checkpoints [`Captures::summary`] can still find. A summary is read right after its line ends, so a few
/// dozen suffice; each lists at most [`MAX_RECORD_FILES_CHANGED`] paths, so the cache stays small.
pub const RECENT_CHECKPOINTS: usize = 64;

/// What a changed path held before the change, as the watcher reports it (FR-CKP-08).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PreImage {
    /// Nothing: the path did not exist (the "did not exist" marker).
    NotExisted,
    /// A folder. Its entries are changes of their own.
    Folder,
    /// A file or symlink, whose shadow copy was moved here, into the root's holding folder
    /// ([`crate::held_dir`]). Whoever receives the change owns the file: it keeps it or removes it.
    Held(PathBuf),
    /// Something whose copy could not be set aside: unknown, so its checkpoint is uncertain.
    Lost,
}

/// What a changed path looked like right after the change (FR-CKP-09).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PostImage {
    /// Its identity: inode, size, modification time, and a content hash for files under 64 MiB.
    Present(PostImageIdentity),
    /// Nothing is there: it was deleted.
    Deleted,
    /// Its identity could not be read: unknown, so its checkpoint is uncertain.
    Unknown,
}

/// One change of one path under a checkpoint root, as the watcher reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Change {
    /// The path that changed.
    pub path: CanonicalPath,
    /// What it held before.
    pub pre: PreImage,
    /// What it holds now.
    pub post: PostImage,
}

/// A path's pre-image as its checkpoint keeps it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoredPreImage {
    /// The path did not exist before the change.
    NotExisted,
    /// The path was a folder.
    Folder,
    /// The path was this file or symlink, now in the checkpoint's folder in the root's store.
    Kept(PathBuf),
    /// Unknown: it could not be captured, and the checkpoint is uncertain.
    Lost,
}

/// One path of a checkpoint: its pre-image and its post-image identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapturedPath {
    /// What the path held before the edge.
    pub pre: StoredPreImage,
    /// What it held at the edge's last change of it.
    pub post: PostImage,
}

impl CapturedPath {
    /// How the path changed over the edge; `None` when it did not exist before and does not after (created and
    /// removed within the edge), which a checkpoint does not list.
    #[must_use]
    pub fn change(&self) -> Option<FileChange> {
        match (&self.pre, &self.post) {
            (StoredPreImage::NotExisted, PostImage::Deleted) => None,
            (StoredPreImage::NotExisted, PostImage::Present(_) | PostImage::Unknown) => Some(FileChange::Created),
            (StoredPreImage::Folder | StoredPreImage::Kept(_) | StoredPreImage::Lost, PostImage::Deleted) => {
                Some(FileChange::Deleted)
            }
            (StoredPreImage::Folder | StoredPreImage::Kept(_) | StoredPreImage::Lost, _) => Some(FileChange::Modified),
        }
    }
}

/// One checkpoint: the pre-images of every path changed by one edge, with their post-image identities
/// (`specs/05-models/checkpoint.md`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checkpoint {
    /// Its identifier: the record's `checkpoint_id`.
    pub id: CheckpointId,
    /// The edge whose change it holds.
    pub edge: EdgeId,
    /// How the edge's change was attributed.
    pub attribution: Attribution,
    /// The lines of the edge: one for `command`, the set for `concurrent`, none otherwise.
    pub records: BTreeSet<RecordId>,
    /// The sessions it belongs to: the edge's, and every session whose watcher reported one of its changes.
    pub sessions: BTreeSet<SessionId>,
    /// Each changed path, by checkpoint root.
    pub paths: BTreeMap<CanonicalPath, BTreeMap<CanonicalPath, CapturedPath>>,
    /// Why it is uncertain; empty when it is not.
    pub uncertain: BTreeSet<UncertainReason>,
    /// The store of each root it has paths in: where its pre-images are, and where an undo saves the current
    /// versions (KNSH-084).
    pub stores: BTreeMap<CanonicalPath, PathBuf>,
    /// Excluded folders (`checkpoints.exclude`) the edge changed something in, by root: not protected, so an undo
    /// lists them as not restored (FR-CKP-31). At most [`MAX_EXCLUDED`].
    pub excluded: BTreeMap<CanonicalPath, BTreeSet<CanonicalPath>>,
    /// More excluded folders changed than `excluded` lists.
    pub excluded_overflowed: bool,
    /// Paths that are possibly torn, with why (FR-CKP-24, KNSH-085, [`crate::torn`]): undo and redo skip them
    /// without `force`. May name paths the checkpoint does not list (a file held for writing that showed no change).
    pub possibly_torn: BTreeMap<CanonicalPath, TornReason>,
}

impl Checkpoint {
    /// How many paths it holds.
    #[must_use]
    pub fn path_count(&self) -> usize {
        self.paths.values().map(BTreeMap::len).sum()
    }

    /// Whether it is uncertain: it may be incomplete (module documentation).
    #[must_use]
    pub fn is_uncertain(&self) -> bool {
        !self.uncertain.is_empty()
    }

    /// The record's `files_changed`: its paths with their post-image identities, sorted, at most
    /// [`MAX_RECORD_FILES_CHANGED`].
    #[must_use]
    pub fn files_changed(&self) -> Vec<ChangedFile> {
        files_changed(&self.paths)
    }
}

/// What a line's record says of its checkpoint ([`Captures::summary`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckpointSummary {
    /// The checkpoint.
    pub id: CheckpointId,
    /// Its paths, sorted, at most [`MAX_RECORD_FILES_CHANGED`].
    pub files: Vec<ChangedFile>,
    /// How many paths it holds in all.
    pub count: u64,
    /// Whether it is uncertain.
    pub uncertain: bool,
}

/// A change being captured: from [`Captures::begin`], to give to [`Captures::add`] exactly once.
#[derive(Debug)]
#[must_use = "a capture ticket must be given to `Captures::add`"]
pub struct Ticket {
    edge: EdgeId,
}

/// A checkpoint being taken: its edge is open, or closed with changes still being added.
struct Open {
    id: CheckpointId,
    paths: BTreeMap<CanonicalPath, BTreeMap<CanonicalPath, CapturedPath>>,
    count: usize,
    uncertain: BTreeSet<UncertainReason>,
    sessions: BTreeSet<SessionId>,
    stores: BTreeMap<CanonicalPath, PathBuf>,
    excluded: BTreeMap<CanonicalPath, BTreeSet<CanonicalPath>>,
    excluded_count: usize,
    excluded_overflowed: bool,
    /// Possibly-torn paths marked so far (FR-CKP-24), at most [`MAX_TORN_PATHS`].
    torn: BTreeMap<CanonicalPath, TornReason>,
    /// Every file of the checkpoint is possibly torn, for this reason: its writers could not be checked, or more
    /// paths were marked than [`MAX_TORN_PATHS`].
    torn_all: Option<TornReason>,
    /// Pre-images kept so far, for unique names in the checkpoint's folders.
    kept: u64,
    /// The checkpoint's folder in each store it has one in.
    folders: BTreeSet<PathBuf>,
    /// Changes begun and not yet added.
    in_flight: usize,
    /// The edge, once the ledger has closed it.
    closed: Option<Edge>,
}

#[derive(Default)]
struct State {
    open: BTreeMap<EdgeId, Open>,
    /// Summaries of finished checkpoints by edge, oldest first, at most [`RECENT_CHECKPOINTS`]. Summaries, not the
    /// checkpoints: each lists at most [`MAX_RECORD_FILES_CHANGED`] paths, so the cache stays small however large the
    /// checkpoints were (a full one goes to whoever finished it).
    recent: VecDeque<(EdgeId, CheckpointSummary)>,
}

/// The checkpoints being taken, one per open edge with changes (module documentation). One per `knshd`.
pub struct Captures {
    files: Arc<dyn ShadowFiles>,
    clock: Arc<dyn Clock>,
    random: Arc<dyn Random>,
    /// Stands in for random bytes if the random source fails, so identifiers stay distinct.
    fallback: AtomicU64,
    state: Mutex<State>,
}

/// What [`Captures::add`] does outside its lock.
enum Then {
    /// Nothing more.
    Nothing,
    /// Removes a held copy it does not keep.
    Remove(PathBuf),
    /// Moves the held copy into the checkpoint.
    Keep { held: PathBuf, kept: PathBuf },
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    // Each critical section leaves the state consistent at every step, so a panic elsewhere cannot corrupt it.
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

impl Captures {
    /// No checkpoint yet. Files are moved with `files`; identifiers come from `clock` and `random`.
    #[must_use]
    pub fn new(files: Arc<dyn ShadowFiles>, clock: Arc<dyn Clock>, random: Arc<dyn Random>) -> Self {
        Self {
            files,
            clock,
            random,
            fallback: AtomicU64::new(0),
            state: Mutex::new(State::default()),
        }
    }

    /// A change attributed to `edge` is about to be added. Call it under the ledger's lock, in the same critical
    /// section that attributed the change: the edge cannot close before the change is added ([`Captures::add`]).
    pub fn begin(&self, edge: EdgeId) -> Ticket {
        let mut state = lock(&self.state);
        self.open(&mut state, edge).in_flight += 1;
        Ticket { edge }
    }

    /// Adds `change` of `root`, reported by `session_id`'s watcher, to the checkpoint of the ticket's edge (module
    /// documentation, step 3). `store` is the root's store, where the checkpoint's folder is. Returns the checkpoints
    /// this finished: the edge closed while the change was being added.
    #[allow(
        clippy::needless_pass_by_value,
        reason = "taking the ticket by value means each begun change is added exactly once"
    )]
    pub fn add(
        &self,
        ticket: Ticket,
        session_id: SessionId,
        store: &Path,
        root: &CanonicalPath,
        change: Change,
    ) -> Vec<Checkpoint> {
        let Change { path, pre, post } = change;
        // FR-CKP-24: a SQLite database with a journal beside it, or a journal file. Read before the lock: at most a
        // few `lstat`s.
        let is_file = matches!(post, PostImage::Present(identity) if identity.identity.kind == FileKind::File);
        let sqlite = sqlite_marks(self.files.as_ref(), &path, is_file);
        let then = {
            let mut state = lock(&self.state);
            let open = self.open(&mut state, ticket.edge);
            for marked in sqlite {
                mark_torn(open, marked, TornReason::SqliteJournal);
            }
            open.sessions.insert(session_id);
            open.stores.entry(root.clone()).or_insert_with(|| store.to_path_buf());
            if matches!(post, PostImage::Unknown) {
                open.uncertain.insert(UncertainReason::CaptureFailed);
            }
            if let Some(captured) = open.paths.get_mut(root).and_then(|paths| paths.get_mut(&path)) {
                // A later change of a path in the same edge: the first pre-image stays (what the path held before
                // the edge), the post-image is the latest.
                captured.post = post;
                discard(pre)
            } else if open.count >= MAX_CHECKPOINT_PATHS {
                open.uncertain.insert(UncertainReason::TooManyEvents);
                discard(pre)
            } else {
                let (stored, then) = match pre {
                    PreImage::NotExisted => (StoredPreImage::NotExisted, Then::Nothing),
                    PreImage::Folder => (StoredPreImage::Folder, Then::Nothing),
                    PreImage::Lost => {
                        open.uncertain.insert(UncertainReason::CaptureFailed);
                        (StoredPreImage::Lost, Then::Nothing)
                    }
                    PreImage::Held(held) => {
                        if let Some(folder) = self.folder(open, store) {
                            let kept = folder.join(open.kept.to_string());
                            open.kept += 1;
                            (StoredPreImage::Kept(kept.clone()), Then::Keep { held, kept })
                        } else {
                            // No folder to keep it in: recorded as lost, never as something it is not.
                            open.uncertain.insert(UncertainReason::CaptureFailed);
                            (StoredPreImage::Lost, Then::Remove(held))
                        }
                    }
                };
                open.count += 1;
                open.paths
                    .entry(root.clone())
                    .or_default()
                    .insert(path.clone(), CapturedPath { pre: stored, post });
                then
            }
        };
        match then {
            Then::Nothing => {}
            Then::Remove(held) => self.remove(&held),
            Then::Keep { held, kept } => {
                if self.files.rename_new(&held, &kept).is_err() {
                    // Recorded as lost, never as what it is not; the held copy is not left behind.
                    self.remove(&held);
                    let mut state = lock(&self.state);
                    if let Some(open) = state.open.get_mut(&ticket.edge) {
                        open.uncertain.insert(UncertainReason::CaptureFailed);
                        if let Some(captured) = open.paths.get_mut(root).and_then(|paths| paths.get_mut(&path)) {
                            captured.pre = StoredPreImage::Lost;
                        }
                    }
                }
            }
        }
        let mut state = lock(&self.state);
        if let Some(open) = state.open.get_mut(&ticket.edge) {
            open.in_flight = open.in_flight.saturating_sub(1);
        }
        finish_ready(&mut state, ticket.edge).into_iter().collect()
    }

    /// A change that belongs to no edge (no session protects its root any more): its held copy is removed.
    pub fn discard(&self, change: Change) {
        if let Then::Remove(held) = discard(change.pre) {
            self.remove(&held);
        }
    }

    /// Something changed in the excluded folder `folder` of `root` (FR-CKP-31), during `edge`: not protected, so not
    /// captured, but listed so that an undo can say it was not restored. Call it under the ledger's lock, while the
    /// edge is open. Excluded changes alone make no checkpoint: with nothing to restore, there is nothing to undo.
    pub fn excluded(&self, edge: EdgeId, root: &CanonicalPath, folder: CanonicalPath) {
        let mut state = lock(&self.state);
        let open = self.open(&mut state, edge);
        if open.excluded.get(root).is_some_and(|listed| listed.contains(&folder)) {
            return;
        }
        if open.excluded_count >= MAX_EXCLUDED {
            open.excluded_overflowed = true;
            return;
        }
        open.excluded_count += 1;
        open.excluded.entry(root.clone()).or_default().insert(folder);
    }

    /// Changes of `edge` may be missing (FR-CKP-04): its checkpoint is uncertain, and exists even if no change of it
    /// was captured, so the line's record can say so. Call it under the ledger's lock, while the edge is open.
    pub fn mark_uncertain(&self, edge: EdgeId, reason: UncertainReason) {
        let mut state = lock(&self.state);
        self.open(&mut state, edge).uncertain.insert(reason);
    }

    /// `path` is possibly torn in `edge`'s change, for `reason` (FR-CKP-24): a process of the line held it for writing
    /// when the line ended ([`crate::held_in_roots`]). Call it under the ledger's lock, while the edge is open. The
    /// first reason given for a path is kept; past [`MAX_TORN_PATHS`] paths every file of the change is
    /// [`TornReason::Unchecked`].
    pub fn mark_possibly_torn(&self, edge: EdgeId, path: CanonicalPath, reason: TornReason) {
        let mut state = lock(&self.state);
        mark_torn(self.open(&mut state, edge), path, reason);
    }

    /// Every file of `edge`'s change is possibly torn, for `reason` (FR-CKP-24): the line's writers could not be
    /// checked, so none can be shown untorn (fail closed). Call it under the ledger's lock, while the edge is open.
    pub fn mark_all_possibly_torn(&self, edge: EdgeId, reason: TornReason) {
        let mut state = lock(&self.state);
        let open = self.open(&mut state, edge);
        open.torn_all.get_or_insert(reason);
    }

    /// The ledger closed `edges` (call it under the ledger's lock). Returns the checkpoints this finished: those with
    /// no change still being added. An edge with no change and nothing uncertain has no checkpoint.
    pub fn closed(&self, edges: &[Edge]) -> Vec<Checkpoint> {
        let mut state = lock(&self.state);
        let mut finished = Vec::new();
        for edge in edges {
            if let Some(open) = state.open.get_mut(&edge.id) {
                open.closed = Some(edge.clone());
                finished.extend(finish_ready(&mut state, edge.id));
            }
        }
        finished
    }

    /// What the record of a line whose changes are in `edge` says of its checkpoint: final once the edge closed, the
    /// changes so far while another line of a concurrent set still runs. `None` when the edge has no checkpoint (it
    /// changed nothing) or it is no longer among the [`RECENT_CHECKPOINTS`].
    #[must_use]
    pub fn summary(&self, edge: EdgeId) -> Option<CheckpointSummary> {
        let state = lock(&self.state);
        if let Some(open) = state.open.get(&edge) {
            return Some(CheckpointSummary {
                id: open.id,
                files: files_changed(&open.paths),
                count: listed(&open.paths),
                uncertain: !open.uncertain.is_empty(),
            });
        }
        state
            .recent
            .iter()
            .rev()
            .find(|(finished, _)| *finished == edge)
            .map(|(_, summary)| summary.clone())
    }

    /// The checkpoint of `edge`, started if there is none yet.
    fn open<'a>(&self, state: &'a mut State, edge: EdgeId) -> &'a mut Open {
        state.open.entry(edge).or_insert_with(|| Open {
            id: self.new_id(),
            paths: BTreeMap::new(),
            count: 0,
            uncertain: BTreeSet::new(),
            sessions: BTreeSet::new(),
            stores: BTreeMap::new(),
            excluded: BTreeMap::new(),
            excluded_count: 0,
            excluded_overflowed: false,
            torn: BTreeMap::new(),
            torn_all: None,
            kept: 0,
            folders: BTreeSet::new(),
            in_flight: 0,
            closed: None,
        })
    }

    /// The checkpoint's folder in `store`, `<store>/checkpoints/<id>/`, created if missing (under the lock: once per
    /// checkpoint and store). `None` if it cannot be made.
    fn folder(&self, open: &mut Open, store: &Path) -> Option<PathBuf> {
        let checkpoints = store.join(CHECKPOINTS_DIR);
        let folder = checkpoints.join(open.id.to_string());
        if open.folders.contains(&folder) {
            return Some(folder);
        }
        for dir in [&checkpoints, &folder] {
            if !make_dir(self.files.as_ref(), dir) {
                return None;
            }
        }
        open.folders.insert(folder.clone());
        Some(folder)
    }

    /// A new checkpoint identifier: a ULID from the clock and the random source. If either fails, the time is 0 or a
    /// counter stands in for the random bytes, so the identifier is still distinct within this `knshd`.
    fn new_id(&self) -> CheckpointId {
        new_checkpoint_id(self.clock.as_ref(), self.random.as_ref(), &self.fallback)
    }

    /// Removes a held copy, best effort: a leftover is only a file in the owner-only store.
    fn remove(&self, held: &Path) {
        let _ = self.files.remove(held, false);
    }
}

/// A new checkpoint identifier: a ULID from `clock` and `random`. If either fails, the time is 0 or `fallback`, a
/// counter, stands in for the random bytes, so the identifier is still distinct within this `knshd`.
pub(crate) fn new_checkpoint_id(clock: &dyn Clock, random: &dyn Random, fallback: &AtomicU64) -> CheckpointId {
    let millis = clock.now().map_or(0, knsh_core::Timestamp::as_unix_millis);
    let mut bytes = [0u8; 10];
    if random.fill(&mut bytes).is_err() {
        let count = fallback.fetch_add(1, Ordering::Relaxed);
        bytes[2..].copy_from_slice(&count.to_be_bytes());
    }
    let ulid = Ulid::new(millis, bytes).unwrap_or_else(|_| Ulid::new(0, bytes).unwrap_or(Ulid::from_u128(0)));
    CheckpointId::from_ulid(ulid)
}

/// What to do with the pre-image of a change that is not kept: a held copy is removed.
fn discard(pre: PreImage) -> Then {
    match pre {
        PreImage::Held(held) => Then::Remove(held),
        PreImage::NotExisted | PreImage::Folder | PreImage::Lost => Then::Nothing,
    }
}

/// Creates the folder `dir`, owner-only, accepting one that exists only if it is a real folder (never a symlink that
/// would carry pre-images elsewhere).
fn make_dir(files: &dyn ShadowFiles, dir: &Path) -> bool {
    // `libc` is reserved to `knsh-platform` (NFR-SUP-02); `EEXIST` is 17 on every system this builds for.
    const EEXIST: i32 = 17;
    match files.make_dir(dir) {
        Ok(()) => true,
        Err(PlatformError::Os { errno: EEXIST, .. }) => matches!(files.kind(dir), Ok(FileKind::Directory)),
        Err(_) => false,
    }
}

/// Finishes the checkpoint of `edge` if its edge closed and no change of it is still being added: its summary is kept
/// among the recent ones and the checkpoint returned. A checkpoint left with nothing to list and nothing uncertain is dropped.
fn finish_ready(state: &mut State, edge: EdgeId) -> Option<Checkpoint> {
    let ready = state
        .open
        .get(&edge)
        .is_some_and(|open| open.closed.is_some() && open.in_flight == 0);
    if !ready {
        return None;
    }
    let open = state.open.remove(&edge)?;
    let closed = open.closed?;
    let mut paths = open.paths;
    // Created and removed within the edge: nothing to restore, nothing to list.
    for listed in paths.values_mut() {
        listed.retain(|_, captured| captured.change().is_some());
    }
    paths.retain(|_, listed| !listed.is_empty());
    if paths.is_empty() && open.uncertain.is_empty() {
        return None;
    }
    let mut sessions = closed.sessions;
    sessions.extend(open.sessions);
    let mut possibly_torn = open.torn;
    if let Some(reason) = open.torn_all {
        for (path, captured) in paths.values().flat_map(BTreeMap::iter) {
            if holds_file(captured) {
                possibly_torn.entry(path.clone()).or_insert(reason);
            }
        }
    }
    let checkpoint = Checkpoint {
        id: open.id,
        edge,
        attribution: closed.attribution,
        records: closed.records,
        sessions,
        paths,
        uncertain: open.uncertain,
        stores: open.stores,
        excluded: open.excluded,
        excluded_overflowed: open.excluded_overflowed,
        possibly_torn,
    };
    if state.recent.len() >= RECENT_CHECKPOINTS {
        state.recent.pop_front();
    }
    let summary = CheckpointSummary {
        id: checkpoint.id,
        files: checkpoint.files_changed(),
        count: checkpoint.path_count() as u64,
        uncertain: checkpoint.is_uncertain(),
    };
    state.recent.push_back((edge, summary));
    Some(checkpoint)
}

/// Marks `path` possibly torn in `open` for `reason`, keeping the first reason; past [`MAX_TORN_PATHS`] paths the
/// whole change is [`TornReason::Unchecked`] instead.
fn mark_torn(open: &mut Open, path: CanonicalPath, reason: TornReason) {
    if open.torn.contains_key(&path) {
        return;
    }
    if open.torn.len() >= MAX_TORN_PATHS {
        open.torn_all.get_or_insert(TornReason::Unchecked);
        return;
    }
    open.torn.insert(path, reason);
}

/// Whether a captured path is or was a file or symlink (not only a folder): what a torn write can affect.
fn holds_file(captured: &CapturedPath) -> bool {
    let post_file = matches!(
        captured.post,
        PostImage::Present(identity) if identity.identity.kind != FileKind::Directory
    );
    post_file
        || matches!(captured.pre, StoredPreImage::Kept(_) | StoredPreImage::Lost)
        || matches!(captured.post, PostImage::Unknown)
}

/// How many paths `paths` lists that changed over the edge.
fn listed(paths: &BTreeMap<CanonicalPath, BTreeMap<CanonicalPath, CapturedPath>>) -> u64 {
    let count = paths
        .values()
        .flat_map(BTreeMap::values)
        .filter(|captured| captured.change().is_some())
        .count();
    count as u64
}

/// The record's `files_changed` of `paths`: sorted by path, at most [`MAX_RECORD_FILES_CHANGED`].
fn files_changed(paths: &BTreeMap<CanonicalPath, BTreeMap<CanonicalPath, CapturedPath>>) -> Vec<ChangedFile> {
    let mut files: Vec<ChangedFile> = paths
        .values()
        .flat_map(BTreeMap::iter)
        .filter_map(|(path, captured)| {
            Some(ChangedFile {
                path: path.clone(),
                change: captured.change()?,
                post_image: match captured.post {
                    PostImage::Present(identity) => Some(recorded(&identity)),
                    PostImage::Deleted | PostImage::Unknown => None,
                },
            })
        })
        .collect();
    // Roots are disjoint or nested; sorting the whole list keeps it in path order either way.
    files.sort_by(|a, b| a.path.cmp(&b.path));
    files.dedup_by(|a, b| a.path == b.path);
    files.truncate(MAX_RECORD_FILES_CHANGED);
    files
}

/// A post-image identity as a record shows it.
fn recorded(identity: &PostImageIdentity) -> RecordedIdentity {
    RecordedIdentity {
        inode: identity.identity.inode,
        size: identity.identity.size,
        mtime_seconds: identity.identity.modified.seconds,
        mtime_nanoseconds: identity.identity.modified.nanoseconds,
        sha256: identity.hash.map(|hash| *hash.as_bytes()),
    }
}

#[cfg(test)]
mod tests;
