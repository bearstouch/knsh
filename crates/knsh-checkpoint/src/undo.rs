//! Undo and redo (KNSH-084): the history tree (KNSH-083) and the checkpoints its edges hold, with the restore rules
//! of FR-CKP-20 to FR-CKP-25, FR-CKP-31 and FR-CKP-36.
//!
//! [`History`] keeps the [`HistoryTree`] and the full [`Checkpoint`] of every edge and of every set of saved versions.
//! [`History::record`] adds each finished checkpoint as a change. [`History::undo`] and [`History::redo`]:
//!
//! 1. refuse `force` from any caller but the user or the authority (FR-CKP-21), and an agent's request for a change
//!    that is not its own session's, or for external edits, which are never offered for agent undo;
//! 2. ask the tree for a [`Plan`] (step back, step forward, or revert an older change, FR-CKP-30),
//!    which changes nothing;
//! 3. [`restore`] the plan's checkpoint, with the identity check of every path, saving the current versions first
//!    (FR-CKP-20, FR-CKP-22, FR-CKP-23; any conflict changes nothing);
//! 4. commit the plan: the tree records only a restore that happened. The saved versions become the checkpoint redo
//!    restores (or, for a revert, the new `undo` edge's checkpoint); a step forward needs none, so they are removed,
//!    as is any set of saved versions the tree released; the checkpoints later undos and redos check the restored
//!    paths against get their new identities ([`History`]'s post-image refresh, same contents only);
//! 5. publish `checkpoint.restored` on each session of the change (FR-CKP-25), and return what was restored, the
//!    excluded folders it changed, which were not restored (FR-CKP-31), what it did that cannot be undone
//!    (FR-CKP-36: those changes' files are still restored), and its possibly-torn files (FR-CKP-24, KNSH-085):
//!    skipped with their reasons without `force`, or restored and listed as forced with it.
//!
//! A possibly-torn path restored under `force` stays possibly torn in the saved versions, so redoing it needs
//! `force` too: what the undo replaced is the same version the change left, which may be torn.
//!
//! Every method takes `&mut self`, so the tree cannot change between a plan and its commit; the caller holds the
//! history behind one lock and keeps the time it is held to one restore.
//!
//! # Restoring a state (KNSH-086)
//!
//! [`History::restore_state`] (`checkpoint.restore`, user and authority only) returns every root to any state of the
//! tree at once. The tree gives the way there ([`Route`]): back over each later change to the last state shared with
//! the target, then forward over the changes of the target's branch. Each step is an ordinary step back or step
//! forward, with its own identity checks, saved versions and journal, so redo and later restores keep working.
//!
//! - **Nothing changes on a conflict.** Before the first step, every path on the way is checked at once against one
//!   checkpoint standing for the whole way: its post-image from the first step that restores it (what must be there
//!   now) and its pre-image from the last (what will be there). Any conflict is `-32004` with the paths, before
//!   anything is written (FR-CKP-20).
//! - **Possibly-torn paths** of any change on the way are skipped by every step without `force` (FR-CKP-24).
//! - **Identities follow the steps.** Each step rewrites files (new times); the checkpoints the next steps check
//!   those paths against get the new identities, same contents only, like the post-image refresh of undo and redo.
//! - **A failure part-way** (a file changed between the check and its step, a write error) takes back the steps
//!   already taken, newest first, by the opposite steps, and returns the error: files and history are as before,
//!   with new times. If taking back fails too, [`CheckpointError::RestoreStopped`] names the state reached; each
//!   step is whole, so the files match it. `checkpoint.restored` is published per step only once every step is done.
//!
//! # Expired changes (KNSH-087)
//!
//! Retention and forget ([`crate::retention`]) remove checkpoints and expire their edges in the tree; undo, redo,
//! restore and diff of a change removed, or across one, are refused as [`HistoryError::Expired`].
//!
//! `knshd` keeps one history behind a lock, records each finished checkpoint, runs retention and serves the
//! `checkpoint.*` methods from it (KNSH-088). **Pending:** the history lives in memory: writing it to disk (the
//! tree's stored form exists, the checkpoints' does not yet), so a restarted `knshd` starts with an empty history.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::sync::atomic::AtomicU64;

use knsh_core::{
    Action, Attribution, CanonicalPath, Change, CheckpointId, EdgeKind, EventData, HistoryError, HistoryTree, Plan,
    RecordId, RestoreOperation, Route, SessionId, StateId, TornPath, TornReason,
};
use knsh_platform::{Clock, FileKind, Random};

use crate::capture::{Checkpoint, PostImage, new_checkpoint_id};
use crate::error::CheckpointError;
use crate::identity::post_image;
use crate::restore::{RestoreRequest, check_only, remove_checkpoint_files, restore};
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
    /// Whether `force` overrode an identity check or restored a possibly-torn file.
    pub forced: bool,
    /// Possibly-torn files not restored, with why (FR-CKP-24): `force` was not given. Sorted.
    pub skipped_torn: Vec<TornPath>,
    /// Possibly-torn files restored because `force` was given (FR-CKP-24). Sorted.
    pub forced_torn: Vec<TornPath>,
}

/// A request to return every root to a state (`checkpoint.restore`, KNSH-086).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StateRequest {
    /// The state to return to: any state of the tree, on the head's branch or another.
    pub state: StateId,
    /// Who asks: only the user or the authority may.
    pub caller: Caller,
    /// Restore paths whose identity no longer matches, and possibly-torn paths, losing what is there now.
    pub force: bool,
}

/// What a restore to a state did: one undo or redo per change on the way, in the order taken.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateRestored {
    /// The state the history was in before.
    pub from: StateId,
    /// The state it is in now: the one asked for.
    pub head: StateId,
    /// Each step: an undo of each later change (newest first), then a redo of each change of the other branch
    /// (oldest first). Empty when the history was already in that state.
    pub steps: Vec<Restored>,
}

impl StateRestored {
    /// Every path restored by any step, sorted, each once.
    #[must_use]
    pub fn restored(&self) -> Vec<CanonicalPath> {
        let paths: BTreeSet<&CanonicalPath> = self.steps.iter().flat_map(|step| &step.restored).collect();
        paths.into_iter().cloned().collect()
    }

    /// Whether `force` overrode an identity check or restored a possibly-torn file in any step.
    #[must_use]
    pub fn forced(&self) -> bool {
        self.steps.iter().any(|step| step.forced)
    }

    /// Excluded folders the changes on the way changed: not restored (FR-CKP-31). Sorted, each once.
    #[must_use]
    pub fn not_restored(&self) -> Vec<CanonicalPath> {
        let paths: BTreeSet<&CanonicalPath> = self.steps.iter().flat_map(|step| &step.not_restored).collect();
        paths.into_iter().cloned().collect()
    }

    /// Whether more excluded folders were changed than [`StateRestored::not_restored`] lists.
    #[must_use]
    pub fn not_restored_incomplete(&self) -> bool {
        self.steps.iter().any(|step| step.not_restored_incomplete)
    }

    /// What the changes on the way did that no restore can undo (FR-CKP-36). Sorted, each once.
    #[must_use]
    pub fn irreversible(&self) -> Vec<String> {
        let reasons: BTreeSet<&String> = self.steps.iter().flat_map(|step| &step.irreversible).collect();
        reasons.into_iter().cloned().collect()
    }

    /// Possibly-torn files skipped by any step (FR-CKP-24). Sorted, each once.
    #[must_use]
    pub fn skipped_torn(&self) -> Vec<TornPath> {
        let torn: BTreeSet<&TornPath> = self.steps.iter().flat_map(|step| &step.skipped_torn).collect();
        torn.into_iter().cloned().collect()
    }

    /// Possibly-torn files restored under `force` by any step (FR-CKP-24). Sorted, each once.
    #[must_use]
    pub fn forced_torn(&self) -> Vec<TornPath> {
        let torn: BTreeSet<&TornPath> = self.steps.iter().flat_map(|step| &step.forced_torn).collect();
        torn.into_iter().cloned().collect()
    }
}

/// Which way a step of a restore to a state goes over its edge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Direction {
    /// Back to the edge's parent state, restoring its checkpoint.
    Back,
    /// Forward to the edge's child state, restoring the versions its undo saved.
    Forward,
}

/// One step of a restore to a state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RouteStep {
    edge: CheckpointId,
    direction: Direction,
    /// The checkpoint the step restores.
    source: CheckpointId,
    /// What the step is to the change: stepping back over a change undoes it, over a revert redoes its change.
    operation: RestoreOperation,
    /// The change reported.
    origin: CheckpointId,
}

/// How one restore is reported and whether it may override checks.
#[derive(Debug, Clone, Copy)]
struct Step {
    operation: RestoreOperation,
    origin: CheckpointId,
    force: bool,
}

/// Where `checkpoint.restored` goes (FR-CKP-25).
pub trait RestoreEvents {
    /// Publishes `data` (a [`EventData::CheckpointRestored`]) on session `session_id`.
    fn restored(&self, session_id: SessionId, data: EventData);
}

/// The history of checkpoints, and undo and redo over it (module documentation). One per `knshd`.
pub struct History {
    pub(crate) files: Arc<dyn ShadowFiles>,
    pub(crate) clock: Arc<dyn Clock>,
    random: Arc<dyn Random>,
    fallback: AtomicU64,
    pub(crate) tree: HistoryTree,
    /// Every checkpoint the tree refers to: each edge's, and each set of saved versions.
    pub(crate) checkpoints: BTreeMap<CheckpointId, Checkpoint>,
    /// What each change did that cannot be undone (FR-CKP-36), by its checkpoint.
    pub(crate) irreversible: BTreeMap<CheckpointId, BTreeSet<String>>,
    /// The bytes of each checkpoint's kept pre-images by store, as retention last measured them (KNSH-087,
    /// [`crate::retention`]); dropped when the checkpoint changes or goes.
    pub(crate) sizes: BTreeMap<CheckpointId, BTreeMap<std::path::PathBuf, u64>>,
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
            sizes: BTreeMap::new(),
        }
    }

    /// The history tree.
    #[must_use]
    pub const fn tree(&self) -> &HistoryTree {
        &self.tree
    }

    /// How files are read and restored.
    pub(crate) fn files(&self) -> &dyn ShadowFiles {
        self.files.as_ref()
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
        // While the edge is still in the tree its sessions are known: authorize first, so an agent learns nothing
        // about another session's change, not even that it expired.
        let origin = match self.tree.edge(target) {
            Some(_) => {
                let origin = self.origin(target)?;
                self.authorize(request.caller, origin)?;
                Some(origin)
            }
            None => None,
        };
        // KNSH-087: a change retention or forget removed is refused as expired before anything else is looked at.
        if self.tree.is_expired(target) {
            return Err(CheckpointError::History(HistoryError::Expired));
        }
        let origin = origin.ok_or(CheckpointError::History(HistoryError::UnknownChange))?;
        let plan = match operation {
            RestoreOperation::Undo => self.tree.plan_undo(target)?,
            RestoreOperation::Redo => self.tree.plan_redo(target)?,
        };
        let restored = self.perform(
            &plan,
            Step {
                operation,
                origin,
                force: request.force,
            },
            &BTreeMap::new(),
            &[],
        )?;
        publish(events, &restored);
        Ok(restored)
    }

    /// Returns every root to state `request.state` at once, undoing all later changes (and redoing the changes of
    /// another branch, when the state is on one): `checkpoint.restore` (KNSH-086, module documentation of
    /// [`crate::undo`], "Restoring a state").
    ///
    /// # Errors
    ///
    /// [`CheckpointError::RestoreNotAllowed`] for an agent; [`CheckpointError::History`] for an unknown state (or a
    /// change on the way whose saved versions are gone); [`CheckpointError::Conflicts`] (`-32004`) if any path on the
    /// way cannot be restored, and nothing changed; any error of [`restore`] for a step, after the steps already taken
    /// were undone; [`CheckpointError::RestoreStopped`] if undoing them failed too.
    pub fn restore_state(
        &mut self,
        request: &StateRequest,
        events: &dyn RestoreEvents,
    ) -> Result<StateRestored, CheckpointError> {
        match request.caller {
            Caller::User | Caller::Authority => {}
            Caller::Agent(_) => return Err(CheckpointError::RestoreNotAllowed),
        }
        let from = self.tree.head();
        let route = self.tree.route(from, request.state)?;
        let steps = self.route_steps(&route)?;
        if steps.is_empty() {
            return Ok(StateRestored {
                from,
                head: from,
                steps: Vec::new(),
            });
        }
        // Every path on the way checked at once, before the first step writes anything (FR-CKP-20).
        let whole = self.composite(&steps)?;
        check_only(self.files.as_ref(), &whole, request.force)?;
        // Without `force`, a path possibly torn in any change on the way is skipped by every step, so the steps
        // stay consistent with each other and with the check above (FR-CKP-24).
        let skip = if request.force {
            BTreeMap::new()
        } else {
            whole.possibly_torn
        };
        let mut done: Vec<(RouteStep, Restored)> = Vec::new();
        for (index, step) in steps.iter().enumerate() {
            let ahead: Vec<CheckpointId> = steps[index + 1..].iter().map(|step| step.source).collect();
            match self.take_step(step, request.force, &skip, &ahead) {
                Ok(restored) => done.push((*step, restored)),
                Err(error) => return Err(self.unwind(&done, step.source, request.force, &skip, error)),
            }
        }
        for (_, restored) in &done {
            publish(events, restored);
        }
        Ok(StateRestored {
            from,
            head: self.tree.head(),
            steps: done.into_iter().map(|(_, restored)| restored).collect(),
        })
    }

    /// The steps of `route`: back over each edge (restoring its own checkpoint), then forward over each edge
    /// (restoring the versions its undo saved).
    fn route_steps(&self, route: &Route) -> Result<Vec<RouteStep>, CheckpointError> {
        let unknown = CheckpointError::History(HistoryError::UnknownChange);
        let mut steps = Vec::with_capacity(route.back.len() + route.forward.len());
        for &edge in &route.back {
            let reverts = matches!(self.tree.edge(edge).ok_or(unknown.clone())?.kind, EdgeKind::Undo { .. });
            steps.push(RouteStep {
                edge,
                direction: Direction::Back,
                source: edge,
                // Stepping back over a revert redoes the change it reverted.
                operation: if reverts {
                    RestoreOperation::Redo
                } else {
                    RestoreOperation::Undo
                },
                origin: self.origin(edge)?,
            });
        }
        for &edge in &route.forward {
            let edge_of = self.tree.edge(edge).ok_or(unknown.clone())?;
            // Every edge off the head's path was left by stepping back over it, which saved the versions it
            // replaced; one without them cannot be returned to.
            let source = edge_of.saved.ok_or(CheckpointError::History(HistoryError::NotUndone))?;
            let reverts = matches!(edge_of.kind, EdgeKind::Undo { .. });
            steps.push(RouteStep {
                edge,
                direction: Direction::Forward,
                source,
                operation: if reverts {
                    RestoreOperation::Undo
                } else {
                    RestoreOperation::Redo
                },
                origin: self.origin(edge)?,
            });
        }
        Ok(steps)
    }

    /// One checkpoint standing for the whole way of `steps`, for the check before the first step: each path's
    /// post-image is from the first step that restores it (what it must be now), its pre-image from the last (what
    /// it will be at the end). Possibly-torn marks and stores are those of every step.
    fn composite(&self, steps: &[RouteStep]) -> Result<Checkpoint, CheckpointError> {
        let mut whole: Option<Checkpoint> = None;
        let mut root_of: BTreeMap<CanonicalPath, CanonicalPath> = BTreeMap::new();
        for step in steps {
            let source = self
                .checkpoints
                .get(&step.source)
                .ok_or(CheckpointError::History(HistoryError::UnknownChange))?;
            let whole = whole.get_or_insert_with(|| Checkpoint {
                id: source.id,
                edge: source.edge,
                attribution: source.attribution,
                records: BTreeSet::new(),
                sessions: BTreeSet::new(),
                paths: BTreeMap::new(),
                uncertain: BTreeSet::new(),
                stores: BTreeMap::new(),
                excluded: BTreeMap::new(),
                excluded_overflowed: false,
                possibly_torn: BTreeMap::new(),
            });
            for (root, listed) in &source.paths {
                for (path, captured) in listed {
                    if let Some(first_root) = root_of.get(path) {
                        // A later step: the path ends at this step's version.
                        if let Some(entry) = whole.paths.get_mut(first_root).and_then(|paths| paths.get_mut(path)) {
                            entry.pre = captured.pre.clone();
                        }
                    } else {
                        root_of.insert(path.clone(), root.clone());
                        whole
                            .paths
                            .entry(root.clone())
                            .or_default()
                            .insert(path.clone(), captured.clone());
                    }
                }
            }
            for (path, reason) in &source.possibly_torn {
                whole.possibly_torn.entry(path.clone()).or_insert(*reason);
            }
            for (root, store) in &source.stores {
                whole.stores.entry(root.clone()).or_insert_with(|| store.clone());
            }
        }
        whole.ok_or(CheckpointError::History(HistoryError::UnknownChange))
    }

    /// Takes one step of a restore to a state: plans it with the tree (which must agree it is the step expected)
    /// and performs it.
    fn take_step(
        &mut self,
        step: &RouteStep,
        force: bool,
        skip: &BTreeMap<CanonicalPath, TornReason>,
        ahead: &[CheckpointId],
    ) -> Result<Restored, CheckpointError> {
        let plan = match step.direction {
            Direction::Back => self.tree.plan_undo(step.edge)?,
            Direction::Forward => self.tree.plan_redo(step.edge)?,
        };
        let expected = match (step.direction, plan.action()) {
            (Direction::Back, Action::StepBack { edge, .. })
            | (Direction::Forward, Action::StepForward { edge, .. }) => {
                edge == step.edge && plan.restore_from() == step.source
            }
            (
                Direction::Back | Direction::Forward,
                Action::StepBack { .. } | Action::StepForward { .. } | Action::Revert { .. },
            ) => false,
        };
        if !expected {
            // The tree and the route disagree; never restore something other than the step checked.
            return Err(CheckpointError::History(HistoryError::Stale));
        }
        self.perform(
            &plan,
            Step {
                operation: step.operation,
                origin: step.origin,
                force,
            },
            skip,
            ahead,
        )
    }

    /// After a step of a restore to a state failed with `failed` (its own restore rolled back, so the paths of its
    /// checkpoint `failed_source` were rewritten): takes back each step of `done`, newest first, by the opposite
    /// step. Returns `failed` if every one was taken back (the files and the history are as before the restore, with
    /// new modification times), or [`CheckpointError::RestoreStopped`] at the state reached otherwise. Nothing is
    /// taken back when the failed step could not roll itself back ([`CheckpointError::RollbackFailed`]): its journal
    /// must first put its paths back at the next start. `skip` is the possibly-torn set the steps skipped: taking a
    /// step back skips the same paths, so it never writes a path the step itself left alone.
    fn unwind(
        &mut self,
        done: &[(RouteStep, Restored)],
        failed_source: CheckpointId,
        force: bool,
        skip: &BTreeMap<CanonicalPath, TornReason>,
        failed: CheckpointError,
    ) -> CheckpointError {
        if matches!(failed, CheckpointError::RollbackFailed(_)) {
            return CheckpointError::RestoreStopped(self.tree.head());
        }
        // The failed step's rollback rewrote its paths: the steps taking back must find their new identities.
        let sources: Vec<CheckpointId> = done
            .iter()
            .rev()
            .filter_map(|(step, _)| self.reverse_source(step))
            .collect();
        self.refresh_from_live(failed_source, &sources);
        for (index, (step, _)) in done.iter().enumerate().rev() {
            // The sources of the steps still to take back, so each finds the identities the previous one left.
            let ahead: Vec<CheckpointId> = done[..index]
                .iter()
                .rev()
                .filter_map(|(earlier, _)| self.reverse_source(earlier))
                .collect();
            let reverse = RouteStep {
                edge: step.edge,
                direction: match step.direction {
                    Direction::Back => Direction::Forward,
                    Direction::Forward => Direction::Back,
                },
                source: match self.reverse_source(step) {
                    Some(source) => source,
                    None => return CheckpointError::RestoreStopped(self.tree.head()),
                },
                operation: match step.operation {
                    RestoreOperation::Undo => RestoreOperation::Redo,
                    RestoreOperation::Redo => RestoreOperation::Undo,
                },
                origin: step.origin,
            };
            if self.take_step(&reverse, force, skip, &ahead).is_err() {
                return CheckpointError::RestoreStopped(self.tree.head());
            }
        }
        failed
    }

    /// Reads the live identity of each path checkpoint `of` lists and gives it, in the first checkpoint of `ahead`
    /// listing the path, as its post-image where it records the same contents ([`same_contents`]) **and the same
    /// inode**. The engine did not write what it reads here (a rollback writes in place, but a step-1 conflict wrote
    /// nothing): only a new time is accepted. A new inode with the same contents (a symlink retargeted to a name of
    /// the same length, which has no hash; a file swapped for a hard link elsewhere) stays a conflict (FR-CKP-20).
    fn refresh_from_live(&mut self, of: CheckpointId, ahead: &[CheckpointId]) {
        let Some(paths) = self.checkpoints.get(&of).map(|checkpoint| {
            checkpoint
                .paths
                .values()
                .flat_map(BTreeMap::keys)
                .cloned()
                .collect::<BTreeSet<_>>()
        }) else {
            return;
        };
        let now: BTreeMap<CanonicalPath, PostImage> = paths
            .into_iter()
            .map(|path| {
                let post = post_image(self.files.as_ref(), path.as_path());
                (path, post)
            })
            .collect();
        self.refresh_ahead(&now, ahead, true);
    }

    /// The checkpoint taking back `step` restores: the versions saved when it stepped back, or the edge's own
    /// pre-images when it stepped forward.
    fn reverse_source(&self, step: &RouteStep) -> Option<CheckpointId> {
        match step.direction {
            Direction::Back => self.tree.edge(step.edge).and_then(|edge| edge.saved),
            Direction::Forward => Some(step.edge),
        }
    }

    /// Carries out `plan` (steps 3 and 4 of the module documentation) and reports it, publishing nothing. Paths in
    /// `skip` are skipped as possibly torn, on top of those the restored checkpoint marks. After the restore, the
    /// first checkpoint of `ahead` listing each restored path gets its new identity too (same contents only): the
    /// next steps of a restore to a state check against them.
    fn perform(
        &mut self,
        plan: &Plan,
        step: Step,
        skip: &BTreeMap<CanonicalPath, TornReason>,
        ahead: &[CheckpointId],
    ) -> Result<Restored, CheckpointError> {
        let stored = self
            .checkpoints
            .get(&plan.restore_from())
            .ok_or(CheckpointError::History(HistoryError::UnknownChange))?;
        let widened;
        let source = if skip.is_empty() {
            stored
        } else {
            let mut copy = stored.clone();
            for (path, reason) in skip {
                copy.possibly_torn.entry(path.clone()).or_insert(*reason);
            }
            widened = copy;
            &widened
        };
        let saved_id = self.fresh_id();
        let result = restore(
            self.files.as_ref(),
            &RestoreRequest {
                from: source,
                saved: saved_id,
                force: step.force,
            },
        );
        let outcome = match result {
            Ok(outcome) => outcome,
            Err(error @ (CheckpointError::RolledBack(_) | CheckpointError::Conflicts(_))) => {
                // A rollback wrote the old versions back (new times): a retry must find them as recorded, not as
                // changed by someone else. Same contents only, so nothing unrecorded is taken for recorded.
                let from = plan.restore_from();
                self.refresh_from_live(from, &[from]);
                return Err(error);
            }
            Err(error) => return Err(error),
        };
        let mut saved = Checkpoint {
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
            possibly_torn: BTreeMap::new(),
        };
        let committed = match self.tree.commit(plan, plan.saves_current().then_some(saved_id)) {
            Ok(committed) => committed,
            Err(error) => {
                // Unreachable with `&mut self` and a fresh identifier; if it ever happens, the files go back to what
                // the tree says they are.
                self.put_back(&saved);
                return Err(error.into());
            }
        };
        // Set only now: `put_back` above must restore every path it saved, torn or not.
        saved.possibly_torn = outcome
            .forced_torn
            .iter()
            .map(|torn| (torn.path.clone(), torn.reason))
            .collect();
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
        let now: BTreeMap<CanonicalPath, PostImage> = saved
            .paths
            .values()
            .flat_map(BTreeMap::iter)
            .map(|(path, captured)| (path.clone(), captured.post))
            .collect();
        self.refresh_ahead(&now, ahead, false);
        if let Some(released) = committed.released
            && let Some(checkpoint) = self.checkpoints.remove(&released)
        {
            self.sizes.remove(&released);
            remove_checkpoint_files(self.files.as_ref(), released, &checkpoint.paths, &checkpoint.stores);
        }
        let mut restored = self.report(
            step.operation,
            step.origin,
            committed.head,
            outcome.restored,
            outcome.forced,
        );
        restored.skipped_torn = outcome.skipped;
        restored.forced_torn = outcome.forced_torn;
        Ok(restored)
    }

    /// Sets the post-image of each path of `now`, in the first checkpoint of `ahead` that lists it, to its post-image
    /// in `now` (what is there now), where it records the same contents ([`same_contents`]). With `same_inode` (`now`
    /// was read from live files the engine did not just write), only where it records the same inode too
    /// ([`same_inode`]).
    fn refresh_ahead(&mut self, now: &BTreeMap<CanonicalPath, PostImage>, ahead: &[CheckpointId], same_inode: bool) {
        for (path, now) in now {
            let next = ahead.iter().copied().find(|id| {
                self.checkpoints
                    .get(id)
                    .is_some_and(|checkpoint| checkpoint.paths.values().any(|listed| listed.contains_key(path)))
            });
            let Some(checkpoint) = next.and_then(|id| self.checkpoints.get_mut(&id)) else {
                continue;
            };
            for captured in checkpoint.paths.values_mut().filter_map(|listed| listed.get_mut(path)) {
                if same_contents(&captured.post, now) && (!same_inode || self::same_inode(&captured.post, now)) {
                    captured.post = *now;
                }
            }
        }
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
                .ok_or_else(|| CheckpointError::History(self.missing_record(record))),
            Target::Checkpoint(checkpoint) => Ok(checkpoint),
        }
    }

    /// Why line `record` has no change in the history: it expired (KNSH-087), or it is unknown.
    pub(crate) fn missing_record(&self, record: RecordId) -> HistoryError {
        if self.tree.is_record_expired(record) {
            HistoryError::Expired
        } else {
            HistoryError::UnknownChange
        }
    }

    /// The change behind edge `edge`: itself, or the change an `undo` edge reverted.
    pub(crate) fn origin(&self, edge: CheckpointId) -> Result<CheckpointId, CheckpointError> {
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
    pub(crate) fn authorize(&self, caller: Caller, origin: CheckpointId) -> Result<(), CheckpointError> {
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

    /// Whether `caller` may see and act on `edge` (`checkpoint.list` on `agent.sock`, KNSH-088): the user and the
    /// authority see every edge; an agent only its own session's changes, and the reverts of them, never external
    /// edits (the same rule undo and redo apply).
    #[must_use]
    pub fn visible_to(&self, caller: Caller, edge: CheckpointId) -> bool {
        match caller {
            Caller::User | Caller::Authority => true,
            Caller::Agent(_) => self
                .origin(edge)
                .is_ok_and(|origin| self.authorize(caller, origin).is_ok()),
        }
    }

    /// The checkpoint roots an undo or redo of `target` may write in (KNSH-088): those of the change, of the
    /// versions its undo saved, of the change it reverts, and of any revert of it. `knshd` stops attributing changes
    /// there while it restores ([`crate::attribution::Ledger::restore_started`]). Empty for an unknown target; the
    /// undo or redo itself then reports why.
    #[must_use]
    pub fn target_roots(&self, target: Target) -> Vec<CanonicalPath> {
        let Ok(checkpoint) = self.resolve(target) else {
            return Vec::new();
        };
        let mut related = vec![checkpoint];
        for edge in self.tree.edges() {
            let reverts_it = matches!(edge.kind, EdgeKind::Undo { of } if of == checkpoint);
            if edge.checkpoint == checkpoint || reverts_it {
                related.push(edge.checkpoint);
                related.extend(edge.saved);
                if let EdgeKind::Undo { of } = edge.kind {
                    related.push(of);
                }
            }
        }
        self.roots_of(&related)
    }

    /// The checkpoint roots a restore to `state` may write in (KNSH-088): those of every change on the way from the
    /// current state, and of the versions their undos saved. Empty for an unknown state or a way that crosses an
    /// expired change; the restore itself then reports why.
    #[must_use]
    pub fn state_roots(&self, state: StateId) -> Vec<CanonicalPath> {
        let Ok(route) = self.tree.route(self.tree.head(), state) else {
            return Vec::new();
        };
        let mut related = Vec::new();
        for checkpoint in route.back.iter().chain(&route.forward) {
            related.push(*checkpoint);
            if let Some(edge) = self.tree.edge(*checkpoint) {
                related.extend(edge.saved);
            }
        }
        self.roots_of(&related)
    }

    /// Every root the checkpoints `ids` hold paths, stores or excluded folders in, sorted, each once.
    fn roots_of(&self, ids: &[CheckpointId]) -> Vec<CanonicalPath> {
        let roots: BTreeSet<&CanonicalPath> = ids
            .iter()
            .filter_map(|id| self.checkpoints.get(id))
            .flat_map(|checkpoint| {
                checkpoint
                    .paths
                    .keys()
                    .chain(checkpoint.stores.keys())
                    .chain(checkpoint.excluded.keys())
            })
            .collect();
        roots.into_iter().cloned().collect()
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
            skipped_torn: Vec::new(),
            forced_torn: Vec::new(),
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

/// Whether `recorded` and `now` are the same entry: both absent, or present with the same kind and inode. What a
/// refresh from live files needs on top of [`same_contents`]: a symlink has no content hash, and a new inode may be a
/// hard link to a file outside the root, which a write in place would then change.
fn same_inode(recorded: &PostImage, now: &PostImage) -> bool {
    match (recorded, now) {
        (PostImage::Deleted, PostImage::Deleted) => true,
        (PostImage::Present(recorded), PostImage::Present(now)) => {
            recorded.identity.kind == now.identity.kind && recorded.identity.inode == now.identity.inode
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
