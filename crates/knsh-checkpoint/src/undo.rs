//! Undo and redo (KNSH-084): the history tree (KNSH-083) and the checkpoints its edges hold, with the restore rules
//! of FR-CKP-20 to FR-CKP-25, FR-CKP-31 and FR-CKP-36.
//!
//! [`History`] keeps the [`HistoryTree`] and the full [`Checkpoint`] of every edge and of every set of saved versions.
//! [`History::record`] adds each finished checkpoint as a change. [`History::undo`] and [`History::redo`]:
//!
//! 1. refuse `force` from any caller but the user or the authority (FR-CKP-21), and an agent's request for a change
//!    that is not its own session's, or for external edits, which are never offered for agent undo;
//! 2. ask the tree for a [`Plan`](knsh_core::Plan) (step back, step forward, or revert an older change, FR-CKP-30),
//!    which changes nothing;
//! 3. [`restore`] the plan's checkpoint, with the identity check of every path, saving the current versions first
//!    (FR-CKP-20, FR-CKP-22, FR-CKP-23; any conflict changes nothing);
//! 4. commit the plan: the tree records only a restore that happened. The saved versions become the checkpoint redo
//!    restores (or, for a revert, the new `undo` edge's checkpoint); a step forward needs none, so they are removed,
//!    as is any set of saved versions the tree released; the checkpoints later undos and redos check the restored
//!    paths against get their new identities ([`History`]'s post-image refresh, same contents only);
//! 5. publish `checkpoint.restored` on each session of the change (FR-CKP-25), and return what was restored, the
//!    excluded folders it changed, which were not restored (FR-CKP-31), and what it did that cannot be undone
//!    (FR-CKP-36: those changes' files are still restored).
//!
//! Every method takes `&mut self`, so the tree cannot change between a plan and its commit; the caller holds the
//! history behind one lock and keeps the time it is held to one restore.
//!
//! **Pending:** the history lives in memory: it is written to disk with retention (KNSH-087), and fed with finished
//! checkpoints and called by the API endpoints in `knshd` (KNSH-088).

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::sync::atomic::AtomicU64;

use knsh_core::{
    Attribution, CanonicalPath, Change, CheckpointId, EdgeKind, EventData, HistoryError, HistoryTree, RecordId,
    RestoreOperation, SessionId, StateId,
};
use knsh_platform::{Clock, FileKind, Random};

use crate::capture::{Checkpoint, PostImage, new_checkpoint_id};
use crate::error::CheckpointError;
use crate::restore::{RestoreRequest, remove_checkpoint_files, restore};
use crate::shadow::ShadowFiles;

/// Who asks for an undo or redo: what decides whether `force` is allowed (FR-CKP-21) and which changes are visible.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Caller {
    /// An agent on `agent.sock`, acting for its session: only that session's own changes, never `force`.
    Agent(SessionId),
    /// The user, on `user.sock`.
    User,
    /// The registered authority, through the control service.
    Authority,
}

impl Caller {
    /// Whether this caller may use `force` (FR-CKP-21).
    #[must_use]
    pub const fn may_force(self) -> bool {
        match self {
            Self::User | Self::Authority => true,
            Self::Agent(_) => false,
        }
    }
}

/// Which change to undo or redo.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target {
    /// The change of a line (`checkpoint.undo {record_id}`): for a line of a concurrent set, the whole set
    /// (FR-CKP-07).
    Record(RecordId),
    /// The change held by a checkpoint, such as a run of agent edits, which has no record.
    Checkpoint(CheckpointId),
}

/// An undo or redo request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Request {
    /// The change.
    pub target: Target,
    /// Who asks.
    pub caller: Caller,
    /// Restore paths whose identity no longer matches, losing what is there now (user and authority only).
    pub force: bool,
}

/// What an undo or redo did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Restored {
    /// Undo or redo.
    pub operation: RestoreOperation,
    /// The change undone or redone: its checkpoint.
    pub checkpoint: CheckpointId,
    /// The change's lines.
    pub records: Vec<RecordId>,
    /// The sessions it belongs to; `checkpoint.restored` was published on each.
    pub sessions: Vec<SessionId>,
    /// The checkpoint roots it covers.
    pub roots: Vec<CanonicalPath>,
    /// The state the history is in now.
    pub head: StateId,
    /// The paths restored, sorted.
    pub restored: Vec<CanonicalPath>,
    /// Excluded folders the change changed something in: not protected, so not restored (FR-CKP-31).
    pub not_restored: Vec<CanonicalPath>,
    /// More excluded folders were changed than `not_restored` lists.
    pub not_restored_incomplete: bool,
    /// What the change did that no restore can undo, such as a network request (FR-CKP-36). Its files were still
    /// restored.
    pub irreversible: Vec<String>,
    /// Whether `force` overrode an identity check.
    pub forced: bool,
}

/// Where `checkpoint.restored` goes (FR-CKP-25).
pub trait RestoreEvents {
    /// Publishes `data` (a [`EventData::CheckpointRestored`]) on session `session_id`.
    fn restored(&self, session_id: SessionId, data: EventData);
}

/// The history of checkpoints, and undo and redo over it (module documentation). One per `knshd`.
pub struct History {
    files: Arc<dyn ShadowFiles>,
    clock: Arc<dyn Clock>,
    random: Arc<dyn Random>,
    fallback: AtomicU64,
    tree: HistoryTree,
    /// Every checkpoint the tree refers to: each edge's, and each set of saved versions.
    checkpoints: BTreeMap<CheckpointId, Checkpoint>,
    /// What each change did that cannot be undone (FR-CKP-36), by its checkpoint.
    irreversible: BTreeMap<CheckpointId, BTreeSet<String>>,
}

impl History {
    /// An empty history. Files are restored with `files`; identifiers of saved versions come from `clock` and
    /// `random`.
    #[must_use]
    pub fn new(files: Arc<dyn ShadowFiles>, clock: Arc<dyn Clock>, random: Arc<dyn Random>) -> Self {
        Self {
            files,
            clock,
            random,
            fallback: AtomicU64::new(0),
            tree: HistoryTree::new(),
            checkpoints: BTreeMap::new(),
            irreversible: BTreeMap::new(),
        }
    }

    /// The history tree.
    #[must_use]
    pub const fn tree(&self) -> &HistoryTree {
        &self.tree
    }

    /// The checkpoint `id`: an edge's, or a set of saved versions.
    #[must_use]
    pub fn checkpoint(&self, id: CheckpointId) -> Option<&Checkpoint> {
        self.checkpoints.get(&id)
    }

    /// Adds a finished checkpoint as a new change from the current state (KNSH-083). An uncertain checkpoint may miss
    /// paths, so it counts as overlapping every later change when an older change is undone (FR-CKP-30, fail
    /// closed).
    ///
    /// # Errors
    ///
    /// [`CheckpointError::History`] if its checkpoint or one of its records is already in the history.
    pub fn record(&mut self, checkpoint: Checkpoint) -> Result<StateId, CheckpointError> {
        let paths = checkpoint.paths.values().flat_map(BTreeMap::keys).cloned().collect();
        let state = self.tree.record(Change {
            checkpoint: checkpoint.id,
            attribution: checkpoint.attribution,
            records: checkpoint.records.clone(),
            sessions: checkpoint.sessions.clone(),
            paths,
            overflowed: checkpoint.is_uncertain(),
        })?;
        self.checkpoints.insert(checkpoint.id, checkpoint);
        Ok(state)
    }

    /// Notes what the change held by `checkpoint` did that cannot be undone (FR-CKP-36), copied from its record's
    /// classification (KNSH-093). Its undo still restores its files, and lists these.
    pub fn mark_irreversible(&mut self, checkpoint: CheckpointId, reasons: impl IntoIterator<Item = String>) {
        self.irreversible.entry(checkpoint).or_default().extend(reasons);
    }

    /// Undoes a change: restores its pre-images where the live files still match its post-images, after saving the
    /// current versions so redo is possible (module documentation).
    ///
    /// # Errors
    ///
    /// [`CheckpointError::ForceNotAllowed`]; [`CheckpointError::NotOwnChange`]; [`CheckpointError::History`] if the
    /// tree refuses (unknown change, not in effect, or overlapped by later changes, FR-CKP-30);
    /// [`CheckpointError::Conflicts`] (`-32004`, nothing changed); or any error of [`restore`]. The history is
    /// unchanged after every error.
    pub fn undo(&mut self, request: &Request, events: &dyn RestoreEvents) -> Result<Restored, CheckpointError> {
        self.run(RestoreOperation::Undo, request, events)
    }

    /// Redoes an undone change: restores the versions its undo saved, under the same checks as [`History::undo`].
    ///
    /// # Errors
    ///
    /// As [`History::undo`]; [`CheckpointError::History`] also if the change was not undone, or a newer change
    /// started another branch since (`checkpoint.restore` returns to it, KNSH-086).
    pub fn redo(&mut self, request: &Request, events: &dyn RestoreEvents) -> Result<Restored, CheckpointError> {
        self.run(RestoreOperation::Redo, request, events)
    }

    /// Undo or redo, in the steps of the module documentation.
    fn run(
        &mut self,
        operation: RestoreOperation,
        request: &Request,
        events: &dyn RestoreEvents,
    ) -> Result<Restored, CheckpointError> {
        if request.force && !request.caller.may_force() {
            return Err(CheckpointError::ForceNotAllowed);
        }
        let target = self.resolve(request.target)?;
        let origin = self.origin(target)?;
        self.authorize(request.caller, origin)?;
        let plan = match operation {
            RestoreOperation::Undo => self.tree.plan_undo(target)?,
            RestoreOperation::Redo => self.tree.plan_redo(target)?,
        };
        let source = self
            .checkpoints
            .get(&plan.restore_from())
            .ok_or(CheckpointError::History(HistoryError::UnknownChange))?;
        let saved_id = self.fresh_id();
        let outcome = restore(
            self.files.as_ref(),
            &RestoreRequest {
                from: source,
                saved: saved_id,
                force: request.force,
            },
        )?;
        let saved = Checkpoint {
            id: saved_id,
            edge: source.edge,
            attribution: source.attribution,
            records: BTreeSet::new(),
            sessions: source.sessions.clone(),
            paths: outcome.saved,
            uncertain: BTreeSet::new(),
            stores: source.stores.clone(),
            excluded: BTreeMap::new(),
            excluded_overflowed: false,
        };
        let committed = match self.tree.commit(&plan, plan.saves_current().then_some(saved_id)) {
            Ok(committed) => committed,
            Err(error) => {
                // Unreachable with `&mut self` and a fresh identifier; if it ever happens, the files go back to what
                // the tree says they are.
                self.put_back(&saved);
                return Err(error.into());
            }
        };
        if plan.saves_current() {
            self.checkpoints.insert(saved_id, saved.clone());
        } else {
            // A step forward: the versions it replaced are the change's own pre-images, kept on its edge.
            remove_checkpoint_files(self.files.as_ref(), saved_id, &saved.paths, &saved.stores);
        }
        // The restored files were rewritten (new times, maybe new inodes): every checkpoint a later undo or redo checks
        // them against must describe them. Done once the saved versions are in place, since a revert's new `undo`
        // edge is then the newest edge of its paths.
        self.refresh_post_images(&saved);
        if let Some(released) = committed.released
            && let Some(checkpoint) = self.checkpoints.remove(&released)
        {
            remove_checkpoint_files(self.files.as_ref(), released, &checkpoint.paths, &checkpoint.stores);
        }
        let restored = self.report(operation, origin, committed.head, outcome.restored, outcome.forced);
        publish(events, &restored);
        Ok(restored)
    }

    /// After a committed restore, sets the post-image of each path `restored` restored, in each checkpoint that a
    /// later undo or redo checks that path against, to what the restore left there (`restored`'s post-images): the
    /// newest edge from the root to the head that lists the path (what undoing the latest change of it checks, such
    /// as the change before the one just undone, or the change just redone), and the saved versions of each edge the
    /// head stepped back from (what redoing it checks). Without this, undoing two changes of one file in turn would
    /// find the file "changed" by the first undo.
    ///
    /// Only where the recorded post-image already describes the same contents ([`same_contents`]): the restore wrote
    /// a known version, so a mismatch means that version is not what this checkpoint recorded, and the stale
    /// post-image stays, so the path conflicts rather than an unrecorded version being treated as recorded (FR-CKP-20).
    fn refresh_post_images(&mut self, restored: &Checkpoint) {
        let mut lineage = Vec::new();
        let mut state = self.tree.head();
        while let Some(edge) = self.tree.parent_edge(state) {
            lineage.push(edge.checkpoint);
            state = edge.from;
        }
        let redo: Vec<CheckpointId> = self
            .tree
            .children(self.tree.head())
            .into_iter()
            .filter_map(|edge| edge.saved)
            .collect();
        for path_and_now in restored.paths.values().flat_map(BTreeMap::iter) {
            let (path, now) = path_and_now;
            // `lineage` is newest first.
            let latest = lineage.iter().copied().find(|id| {
                self.checkpoints
                    .get(id)
                    .is_some_and(|checkpoint| checkpoint.paths.values().any(|listed| listed.contains_key(path)))
            });
            for id in latest.into_iter().chain(redo.iter().copied()) {
                let Some(checkpoint) = self.checkpoints.get_mut(&id) else {
                    continue;
                };
                for captured in checkpoint.paths.values_mut().filter_map(|listed| listed.get_mut(path)) {
                    if same_contents(&captured.post, &now.post) {
                        captured.post = now.post;
                    }
                }
            }
        }
    }

    /// The edge `target` names.
    fn resolve(&self, target: Target) -> Result<CheckpointId, CheckpointError> {
        match target {
            Target::Record(record) => self
                .tree
                .edge_for_record(record)
                .map(|edge| edge.checkpoint)
                .ok_or(CheckpointError::History(HistoryError::UnknownChange)),
            Target::Checkpoint(checkpoint) => Ok(checkpoint),
        }
    }

    /// The change behind edge `edge`: itself, or the change an `undo` edge reverted.
    fn origin(&self, edge: CheckpointId) -> Result<CheckpointId, CheckpointError> {
        let edge_of = self
            .tree
            .edge(edge)
            .ok_or(CheckpointError::History(HistoryError::UnknownChange))?;
        match &edge_of.kind {
            EdgeKind::Change { .. } => Ok(edge),
            EdgeKind::Undo { of } => Ok(*of),
        }
    }

    /// Whether `caller` may undo or redo the change `origin`: an agent only its own session's, never external edits.
    fn authorize(&self, caller: Caller, origin: CheckpointId) -> Result<(), CheckpointError> {
        let Caller::Agent(session) = caller else {
            return Ok(());
        };
        let own = self.tree.edge(origin).is_some_and(|edge| match &edge.kind {
            EdgeKind::Change {
                attribution, sessions, ..
            } => *attribution != Attribution::External && sessions.contains(&session),
            EdgeKind::Undo { .. } => false,
        });
        if own {
            Ok(())
        } else {
            Err(CheckpointError::NotOwnChange)
        }
    }

    /// What the caller is told, about the change `origin`.
    fn report(
        &self,
        operation: RestoreOperation,
        origin: CheckpointId,
        head: StateId,
        restored: Vec<CanonicalPath>,
        forced: bool,
    ) -> Restored {
        let change = self.checkpoints.get(&origin);
        let roots: BTreeSet<CanonicalPath> = change
            .map(|change| change.paths.keys().chain(change.excluded.keys()).cloned().collect())
            .unwrap_or_default();
        Restored {
            operation,
            checkpoint: origin,
            records: change
                .map(|change| change.records.iter().copied().collect())
                .unwrap_or_default(),
            sessions: change
                .map(|change| change.sessions.iter().copied().collect())
                .unwrap_or_default(),
            roots: roots.into_iter().collect(),
            head,
            restored,
            not_restored: change
                .map(|change| change.excluded.values().flatten().cloned().collect())
                .unwrap_or_default(),
            not_restored_incomplete: change.is_some_and(|change| change.excluded_overflowed),
            irreversible: self
                .irreversible
                .get(&origin)
                .map(|reasons| reasons.iter().cloned().collect())
                .unwrap_or_default(),
            forced,
        }
    }

    /// A checkpoint identifier no edge or checkpoint of the history uses.
    fn fresh_id(&self) -> CheckpointId {
        loop {
            let id = new_checkpoint_id(self.clock.as_ref(), self.random.as_ref(), &self.fallback);
            if !self.checkpoints.contains_key(&id) && self.tree.edge(id).is_none() {
                return id;
            }
        }
    }

    /// Restores `saved` (the versions a restore replaced) after the tree refused to record that restore, then removes
    /// both sets of copies. Best effort: the restore's own checks keep it from overwriting anything changed since.
    fn put_back(&self, saved: &Checkpoint) {
        let back = self.fresh_id();
        if let Ok(outcome) = restore(
            self.files.as_ref(),
            &RestoreRequest {
                from: saved,
                saved: back,
                force: false,
            },
        ) {
            remove_checkpoint_files(self.files.as_ref(), back, &outcome.saved, &saved.stores);
        }
        remove_checkpoint_files(self.files.as_ref(), saved.id, &saved.paths, &saved.stores);
    }
}

/// Whether the post-images `recorded` and `now` describe the same version of a path, whatever its inode and time:
/// both absent, both folders, or both of one kind and size with the same content hash (none for files of 64 MiB or
/// more, and symlinks). An unknown post-image matches nothing.
fn same_contents(recorded: &PostImage, now: &PostImage) -> bool {
    match (recorded, now) {
        (PostImage::Deleted, PostImage::Deleted) => true,
        (PostImage::Present(recorded), PostImage::Present(now)) => {
            recorded.identity.kind == now.identity.kind
                && match now.identity.kind {
                    FileKind::Directory => true,
                    // Fail closed: a file without a hash (64 MiB or more) cannot be shown to hold the same contents,
                    // so an unrecorded same-size edit is never laundered into the history.
                    FileKind::File => {
                        recorded.identity.size == now.identity.size
                            && recorded.hash.is_some()
                            && recorded.hash == now.hash
                    }
                    FileKind::Symlink | FileKind::Other => {
                        recorded.identity.size == now.identity.size && recorded.hash == now.hash
                    }
                }
        }
        (PostImage::Deleted | PostImage::Present(_) | PostImage::Unknown, _) => false,
    }
}

/// Publishes `checkpoint.restored` for `restored` on each of its sessions (FR-CKP-25).
fn publish(events: &dyn RestoreEvents, restored: &Restored) {
    let data = EventData::CheckpointRestored {
        checkpoint_id: restored.checkpoint,
        operation: restored.operation,
        record_ids: restored.records.clone(),
        roots: restored.roots.clone(),
        files_restored: restored.restored.len() as u64,
        forced: restored.forced,
    };
    for session_id in &restored.sessions {
        events.restored(*session_id, data.clone());
    }
}

#[cfg(test)]
mod tests;
