//! The history tree of checkpoints: states, edges, undo and redo as pure computations (KNSH-083, FR-CKP-30).
//!
//! # Model
//!
//! States form a tree, like commits (`specs/05-models/checkpoint.md`, "History tree"). A [`StateId`] names the
//! contents of every checkpoint root at one point in time; a [`HistoryEdge`] leads from one state to the next and is
//! identified by the [`CheckpointId`] holding its pre-images. The tree has one current state, the **head**.
//!
//! An edge is one of two [`EdgeKind`]s:
//!
//! - **`change`**: a line, a concurrent set or a run of agent or external edits ([`Change`], FR-CKP-05 to
//!   FR-CKP-07), added by [`HistoryTree::record`] as a new edge from the head. When the head already has children (it
//!   was reached by an undo), the new edge starts a new branch; the old branch stays until retention removes it
//!   (KNSH-087).
//! - **`undo`**: the undo of an older change, which cannot move the head back without also undoing the later changes.
//!   It is a new edge from the head, like a `git revert`, whose checkpoint holds the versions saved before the undo.
//!
//! # Undo and redo
//!
//! Every undo and redo is computed in two steps, so the tree never records a restore that did not happen:
//!
//! 1. [`HistoryTree::plan_undo`] or [`HistoryTree::plan_redo`] decides, without changing anything, which
//!    checkpoint's versions to restore and where the head goes ([`Plan`], [`Action`]), or refuses ([`HistoryError`]).
//! 2. The caller restores the files (KNSH-084, with the identity checks of FR-CKP-20), saving the current versions
//!    first when the plan says so, then calls [`HistoryTree::commit`]. A plan made before any other change of the
//!    tree is refused as [`HistoryError::Stale`].
//!
//! The three actions:
//!
//! - **Step back** (undo of the latest edge in effect): restore the edge's pre-images and move the head to its parent
//!   state. The versions saved first are kept on the edge, and the edge and every state beyond it stay in the tree,
//!   so redo stays possible.
//! - **Step forward** (redo of an edge the head stepped back from): restore the versions that undo saved and move the
//!   head to the edge's child state. Only from the edge's parent state: once a new change started another branch,
//!   going back is `checkpoint.restore` (KNSH-086), so redo is [`HistoryError::RedoBlocked`].
//! - **Revert** (undo of an older edge): allowed only if no later edge on the way to the head touched the same paths
//!   (FR-CKP-30); otherwise [`HistoryError::Conflict`] lists the paths. An edge whose path list overflowed proves
//!   nothing about the paths it did not list, so it conflicts with any later edge (fail closed). Redo of a reverted
//!   edge is the undo of its `undo` edge, under the same rules.
//!
//! An edge is **in effect** when it lies on the path from the root to the head and no `undo` edge in effect after it
//! undid it. Only edges in effect can be undone.
//!
//! # Expiry (KNSH-087)
//!
//! Retention (FR-CKP-32) and `knsh forget --with-checkpoints` (FR-CKP-34) remove checkpoints; [`HistoryTree::expire`]
//! records that in the tree, so the undo or redo of a removed change is refused as [`HistoryError::Expired`], never
//! attempted. Expiring an edge:
//!
//! - marks it **expired**: it can no longer be crossed either way (its pre-images and the versions its undo saved are
//!   gone), and so is every `undo` edge that reverted it (redoing the change would be its undo);
//! - removes every edge that can only be reached by crossing an expired edge (branches hanging off states before an
//!   expired edge on the head's path, and everything beyond an expired edge off it), since no undo, redo or restore
//!   could reach them; and the expired edges at the root, which nothing later needs;
//! - keeps an expired edge on the head's path between edges still kept, with its path list, so the undo of an older
//!   change is still refused when it overlapped (FR-CKP-30).
//!
//! Every checkpoint the tree stops referencing is returned for the caller to remove. The checkpoints and records of
//! removed edges are remembered (at most [`MAX_FORGOTTEN`] of each, oldest dropped first) so asking for them still
//! says `Expired` rather than unknown.
//!
//! # Persistence
//!
//! [`HistoryTree::encode`] writes one strict JSON object with a `format` version ([`HISTORY_FORMAT`]);
//! [`HistoryTree::decode`] reads only that form and checks every invariant, so a corrupt file is refused rather than
//! half-read, and a newer one is reported as [`HistoryError::NewerFormat`] so the caller recovers without
//! overwriting it (CLAUDE.md "Persistence"). Writing the file atomically is the caller's job: this module does no
//! I/O.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use knsh_json::{Fields, JsonError, MAX_SAFE_INTEGER, Object, Value};

use crate::id::{CheckpointId, RecordId, SessionId};
use crate::path::CanonicalPath;
use crate::record::Attribution;

/// The version of the stored history tree that [`HistoryTree::encode`] writes and [`HistoryTree::decode`] reads.
///
/// 2 since KNSH-087 (expired edges, `forgotten` and `forgotten_records`). Format 1 (KNSH-083) was never written to
/// disk, so it is not read: any other version than this one is refused.
pub const HISTORY_FORMAT: u64 = 2;

/// The largest stored history tree [`HistoryTree::decode`] reads, in bytes (256 MiB).
///
/// Retention (FR-CKP-32: at most 200 checkpoints per root) keeps real trees far below this; it only bounds what a
/// corrupt or hostile file can make the reader allocate.
pub const MAX_HISTORY_LEN: usize = 256 << 20;

/// The highest state number: the integers JSON carries exactly (±2^53).
const MAX_STATE: u64 = MAX_SAFE_INTEGER.unsigned_abs();

/// The most removed checkpoints, and the most removed records, a tree remembers as expired ([`HistoryTree::expire`]);
/// beyond that the oldest (lowest identifier, so earliest created) are forgotten and reported as unknown.
pub const MAX_FORGOTTEN: usize = 65_536;

/// Identifies a state of the history tree, the contents of every checkpoint root at one point in time (the API's
/// `state_id`).
///
/// # Invariants
///
/// Numbers are handed out in increasing order and never reused within a tree, so a child state always has a higher
/// number than its parent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StateId(u64);

impl StateId {
    /// The state numbered `number`, as a caller names it (`checkpoint.restore`, `checkpoint.diff`, KNSH-086); `None`
    /// above ±2^53, which no tree hands out. Whether the tree holds it is [`HistoryTree::has_state`].
    #[must_use]
    pub const fn new(number: u64) -> Option<Self> {
        if number <= MAX_STATE { Some(Self(number)) } else { None }
    }

    /// The number behind it.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl fmt::Display for StateId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

/// A captured change to add to the tree: one closed edge of the attribution ledger with its checkpoint (KNSH-081,
/// KNSH-082).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Change {
    /// The checkpoint holding its pre-images; identifies the edge.
    pub checkpoint: CheckpointId,
    /// How it was attributed.
    pub attribution: Attribution,
    /// Its lines: one for `command`, the set for `concurrent`, none otherwise.
    pub records: BTreeSet<RecordId>,
    /// The sessions it belongs to.
    pub sessions: BTreeSet<SessionId>,
    /// The paths it changed.
    pub paths: BTreeSet<CanonicalPath>,
    /// More paths changed than `paths` lists (the ledger's limit), so `paths` is incomplete.
    pub overflowed: bool,
}

/// What an edge of the tree stands for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EdgeKind {
    /// A captured change ([`Change`]).
    Change {
        /// How it was attributed.
        attribution: Attribution,
        /// Its lines.
        records: BTreeSet<RecordId>,
        /// The sessions it belongs to.
        sessions: BTreeSet<SessionId>,
    },
    /// The undo of an older edge, made on top of later changes (a revert).
    Undo {
        /// The edge it undid.
        of: CheckpointId,
    },
}

/// One edge of the tree, from one state to the next.
///
/// # Invariants
///
/// `from < to`; `to` has no other incoming edge; `checkpoint` and `saved` are used by no other edge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoryEdge {
    /// The checkpoint holding the pre-images of its paths: what undoing it restores.
    pub checkpoint: CheckpointId,
    /// The state it starts from.
    pub from: StateId,
    /// The state it leads to.
    pub to: StateId,
    /// What it stands for.
    pub kind: EdgeKind,
    /// The paths it changed. An `undo` edge changed the paths of the edge it undid.
    pub paths: BTreeSet<CanonicalPath>,
    /// `paths` is incomplete.
    pub overflowed: bool,
    /// The versions saved when the head last stepped back over it, which redo restores. `None` while it is not
    /// undone that way, and once it expired.
    pub saved: Option<CheckpointId>,
    /// Its checkpoint was removed by retention or forget ([`HistoryTree::expire`]): it can no longer be undone,
    /// redone or crossed by a restore.
    pub expired: bool,
}

/// What an undo or redo does ([`Plan::action`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Restore the pre-images of `edge` and move the head back to `to`, its parent state. The current versions must
    /// be saved first, for redo.
    StepBack {
        /// The edge undone.
        edge: CheckpointId,
        /// The state the head moves to.
        to: StateId,
    },
    /// Restore the versions `saved` by the undo of `edge` and move the head forward to `to`, its child state.
    StepForward {
        /// The edge redone.
        edge: CheckpointId,
        /// The checkpoint holding the versions to restore.
        saved: CheckpointId,
        /// The state the head moves to.
        to: StateId,
    },
    /// Restore the pre-images of `edge`, an older edge, over later changes that touched none of its paths. The
    /// current versions must be saved first; their checkpoint becomes a new `undo` edge to a new state.
    Revert {
        /// The edge undone.
        edge: CheckpointId,
    },
}

/// An undo or redo the tree allowed, to perform and then [`commit`](HistoryTree::commit).
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use = "a plan changes nothing until it is committed"]
pub struct Plan {
    action: Action,
    /// The head and generation the plan was made against: a commit of a plan made before any later change of the
    /// tree is stale.
    head: StateId,
    generation: u64,
}

impl Plan {
    /// What to do.
    #[must_use]
    pub const fn action(&self) -> Action {
        self.action
    }

    /// The checkpoint whose versions to restore.
    #[must_use]
    pub const fn restore_from(&self) -> CheckpointId {
        match self.action {
            Action::StepBack { edge, .. } | Action::Revert { edge } => edge,
            Action::StepForward { saved, .. } => saved,
        }
    }

    /// Whether the current versions must be saved before restoring, and their checkpoint given to
    /// [`HistoryTree::commit`]: for every undo, never for a step forward (the versions it replaces are already the
    /// edge's pre-images).
    #[must_use]
    pub const fn saves_current(&self) -> bool {
        match self.action {
            Action::StepBack { .. } | Action::Revert { .. } => true,
            Action::StepForward { .. } => false,
        }
    }
}

/// The way from one state of the tree to another ([`HistoryTree::route`], KNSH-086): back over `back`, from the
/// start up to the last state both share, then forward over `forward` down to the end.
///
/// Walking it changes the files as stepping back over each edge of `back` (restoring its pre-images) and then
/// forward over each edge of `forward` (restoring the versions its undo saved) would, which is how
/// `checkpoint.restore` returns every root to a state and how `checkpoint.diff` finds each path's version at one.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Route {
    /// The edges to step back over, newest first: the first leads to the start state.
    pub back: Vec<CheckpointId>,
    /// The edges to step forward over, oldest first: the last leads to the end state.
    pub forward: Vec<CheckpointId>,
}

impl Route {
    /// Whether the two states are the same.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.back.is_empty() && self.forward.is_empty()
    }
}

/// What a commit did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Committed {
    /// The head after it.
    pub head: StateId,
    /// A checkpoint of saved versions the tree no longer references, which the caller may remove: the versions a
    /// step forward restored, or those an earlier undo of the same edge saved.
    pub released: Option<CheckpointId>,
}

/// Why the tree refused an operation, or a stored tree could not be read. The tree is unchanged after every error.
///
/// Messages name no path: paths may be private, and errors are logged and sent over the wire (NFR-PRIV-02).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HistoryError {
    /// No edge has this checkpoint: it never existed or retention removed it.
    UnknownChange,
    /// No state of the tree has this number: it never existed or retention removed it (KNSH-086).
    UnknownState,
    /// The change is not in effect: it was already undone, or lies on a branch the head left.
    NotInEffect,
    /// Redo of a change that is in effect, or was not undone by stepping back.
    NotUndone,
    /// Redo of a change whose parent state is not the head: later changes started another branch, so redo would lose
    /// them. Returning to that branch is `checkpoint.restore`.
    RedoBlocked,
    /// Undo of an older change that later changes overlap (FR-CKP-30).
    Conflict {
        /// The paths both the change and a later change touched.
        paths: BTreeSet<CanonicalPath>,
        /// The change or a later one listed only part of its paths, so other paths may conflict too.
        incomplete: bool,
    },
    /// The plan was made before a later change of the tree; plan again.
    Stale,
    /// The commit was given saved versions when the plan needs none, or none when it needs them
    /// ([`Plan::saves_current`]).
    SavedVersions,
    /// The checkpoint already identifies an edge or saved versions in the tree.
    DuplicateCheckpoint,
    /// The record already belongs to an edge in the tree.
    DuplicateRecord,
    /// Every state number has been used.
    StatesExhausted,
    /// The change's checkpoint was removed by retention or `knsh forget --with-checkpoints` (FR-CKP-32 to
    /// FR-CKP-34), or the way to a state crosses such a change: it can no longer be undone, redone or restored.
    Expired,
    /// A path is not valid UTF-8, which the stored form cannot hold.
    UnencodablePath,
    /// The stored tree is larger than [`MAX_HISTORY_LEN`].
    TooLarge,
    /// The stored tree was written by a newer version (its `format`); it must be left as found.
    NewerFormat(u64),
    /// The stored tree is not in the form [`HistoryTree::encode`] writes, or breaks an invariant of the tree.
    Corrupt,
}

impl fmt::Display for HistoryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownChange => f.write_str("no change in the history has this checkpoint"),
            Self::UnknownState => f.write_str("no state in the history has this number"),
            Self::NotInEffect => f.write_str("the change is not in effect: already undone or on another branch"),
            Self::NotUndone => f.write_str("the change was not undone, so there is nothing to redo"),
            Self::RedoBlocked => f.write_str("later changes started another branch; restore the state instead"),
            Self::Conflict { paths, incomplete } => {
                write!(f, "later changes touched {} of the same paths", paths.len())?;
                if *incomplete {
                    f.write_str(" (path lists are incomplete, others may conflict)")?;
                }
                Ok(())
            }
            Self::Stale => f.write_str("the history changed since the plan was made"),
            Self::SavedVersions => f.write_str("saved versions do not match the plan"),
            Self::DuplicateCheckpoint => f.write_str("the checkpoint is already in the history"),
            Self::DuplicateRecord => f.write_str("the record already belongs to a change in the history"),
            Self::StatesExhausted => f.write_str("the history has used every state number"),
            Self::Expired => f.write_str("the change's checkpoint has expired and was removed"),
            Self::UnencodablePath => f.write_str("a path is not valid UTF-8"),
            Self::TooLarge => f.write_str("the stored history is too large"),
            Self::NewerFormat(format) => write!(f, "the stored history has newer format {format}"),
            Self::Corrupt => f.write_str("the stored history is not in the engine's format"),
        }
    }
}

impl std::error::Error for HistoryError {}

/// The history tree (module documentation). Pure: it holds no files and does no I/O.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoryTree {
    root: StateId,
    head: StateId,
    /// The number the next new state gets.
    next_state: u64,
    edges: BTreeMap<CheckpointId, HistoryEdge>,
    /// The incoming edge of every state but the root.
    parents: BTreeMap<StateId, CheckpointId>,
    /// The edge holding each record's change.
    records: BTreeMap<RecordId, CheckpointId>,
    /// Checkpoints of edges removed by [`HistoryTree::expire`], at most [`MAX_FORGOTTEN`].
    forgotten: BTreeSet<CheckpointId>,
    /// Records of edges removed by [`HistoryTree::expire`], at most [`MAX_FORGOTTEN`].
    forgotten_records: BTreeSet<RecordId>,
    /// Counts changes of the tree, so a plan made before one is stale. Not stored: plans do not outlive the process.
    generation: u64,
}

impl Default for HistoryTree {
    fn default() -> Self {
        Self::new()
    }
}

/// The edges from the root to the head, oldest first, and which edges in effect were undone by which `undo` edge.
struct HeadPath {
    edges: Vec<CheckpointId>,
    undone_by: BTreeMap<CheckpointId, CheckpointId>,
}

impl HeadPath {
    fn contains(&self, edge: CheckpointId) -> bool {
        self.edges.contains(&edge)
    }

    fn in_effect(&self, edge: CheckpointId) -> bool {
        self.contains(edge) && !self.undone_by.contains_key(&edge)
    }
}

impl HistoryTree {
    /// An empty tree: one state, which is both root and head.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            root: StateId(0),
            head: StateId(0),
            next_state: 1,
            edges: BTreeMap::new(),
            parents: BTreeMap::new(),
            records: BTreeMap::new(),
            forgotten: BTreeSet::new(),
            forgotten_records: BTreeSet::new(),
            generation: 0,
        }
    }

    /// The current state.
    #[must_use]
    pub const fn head(&self) -> StateId {
        self.head
    }

    /// The oldest state kept.
    #[must_use]
    pub const fn root(&self) -> StateId {
        self.root
    }

    /// How many edges the tree holds.
    #[must_use]
    pub fn len(&self) -> usize {
        self.edges.len()
    }

    /// Whether the tree holds no edge.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.edges.is_empty()
    }

    /// The edge identified by `checkpoint`.
    #[must_use]
    pub fn edge(&self, checkpoint: CheckpointId) -> Option<&HistoryEdge> {
        self.edges.get(&checkpoint)
    }

    /// The edge holding line `record`'s change: for a line of a concurrent set, the whole set (FR-CKP-07).
    #[must_use]
    pub fn edge_for_record(&self, record: RecordId) -> Option<&HistoryEdge> {
        self.records
            .get(&record)
            .and_then(|checkpoint| self.edges.get(checkpoint))
    }

    /// The edge leading to `state`; `None` for the root or an unknown state.
    #[must_use]
    pub fn parent_edge(&self, state: StateId) -> Option<&HistoryEdge> {
        self.parents
            .get(&state)
            .and_then(|checkpoint| self.edges.get(checkpoint))
    }

    /// The edges leaving `state`, one per branch, oldest first.
    #[must_use]
    pub fn children(&self, state: StateId) -> Vec<&HistoryEdge> {
        let mut children: Vec<&HistoryEdge> = self.edges.values().filter(|edge| edge.from == state).collect();
        children.sort_by_key(|edge| edge.to);
        children
    }

    /// Every edge, in no particular order.
    pub fn edges(&self) -> impl Iterator<Item = &HistoryEdge> {
        self.edges.values()
    }

    /// Whether the change identified by `checkpoint` expired ([`HistoryTree::expire`]): its edge is marked expired,
    /// or was removed and is still remembered.
    #[must_use]
    pub fn is_expired(&self, checkpoint: CheckpointId) -> bool {
        self.edges
            .get(&checkpoint)
            .map_or_else(|| self.forgotten.contains(&checkpoint), |edge| edge.expired)
    }

    /// Whether line `record`'s change expired ([`HistoryTree::is_expired`]).
    #[must_use]
    pub fn is_record_expired(&self, record: RecordId) -> bool {
        self.edge_for_record(record)
            .map_or_else(|| self.forgotten_records.contains(&record), |edge| edge.expired)
    }

    /// The edge identified by `checkpoint`, refusing an expired one.
    fn live_edge(&self, checkpoint: CheckpointId) -> Result<&HistoryEdge, HistoryError> {
        match self.edges.get(&checkpoint) {
            Some(edge) if edge.expired => Err(HistoryError::Expired),
            Some(edge) => Ok(edge),
            None if self.forgotten.contains(&checkpoint) => Err(HistoryError::Expired),
            None => Err(HistoryError::UnknownChange),
        }
    }

    /// Whether `state` is a state of the tree: its root or the end of one of its edges.
    #[must_use]
    pub fn has_state(&self, state: StateId) -> bool {
        state == self.root || self.parents.contains_key(&state)
    }

    /// The way from state `from` to state `to` ([`Route`]): the edges from `from` back to the last state both share,
    /// then the edges from there down to `to`. Empty when they are the same state. Changes nothing.
    ///
    /// # Errors
    ///
    /// [`HistoryError::UnknownState`] if either is not a state of the tree; [`HistoryError::Expired`] if the way
    /// crosses an expired edge, whose versions are gone.
    pub fn route(&self, from: StateId, to: StateId) -> Result<Route, HistoryError> {
        if !self.has_state(from) || !self.has_state(to) {
            return Err(HistoryError::UnknownState);
        }
        let up = self.ancestry(from);
        let down = self.ancestry(to);
        // Both lists end at the root; the shared tail is the way from their last shared state to the root.
        let shared = up
            .iter()
            .rev()
            .zip(down.iter().rev())
            .take_while(|(a, b)| a == b)
            .count();
        let back = up[..up.len() - shared].to_vec();
        let mut forward = down[..down.len() - shared].to_vec();
        forward.reverse();
        if back.iter().chain(&forward).any(|edge| self.is_expired(*edge)) {
            return Err(HistoryError::Expired);
        }
        Ok(Route { back, forward })
    }

    /// The edges from `state` up to the root, newest first. `state` must be a state of the tree.
    fn ancestry(&self, state: StateId) -> Vec<CheckpointId> {
        let mut edges = Vec::new();
        let mut state = state;
        while let Some(&checkpoint) = self.parents.get(&state) {
            edges.push(checkpoint);
            // Parents always have lower numbers (`from < to`), so this ends at the root.
            match self.edges.get(&checkpoint) {
                Some(edge) => state = edge.from,
                None => break,
            }
        }
        edges
    }

    /// Whether the edge identified by `checkpoint` is in effect: part of the head state and not undone.
    #[must_use]
    pub fn is_in_effect(&self, checkpoint: CheckpointId) -> bool {
        self.head_path().in_effect(checkpoint)
    }

    /// Adds `change` as a new edge from the head to a new state, which becomes the head. If the head already has
    /// children (it was reached by an undo), this starts a new branch and the old ones stay.
    ///
    /// # Errors
    ///
    /// [`HistoryError::DuplicateCheckpoint`] or [`HistoryError::DuplicateRecord`] if the change's checkpoint or one
    /// of its records is already in the tree; [`HistoryError::StatesExhausted`] if no state number is left.
    pub fn record(&mut self, change: Change) -> Result<StateId, HistoryError> {
        if self.is_used(change.checkpoint) {
            return Err(HistoryError::DuplicateCheckpoint);
        }
        if change.records.iter().any(|record| self.records.contains_key(record)) {
            return Err(HistoryError::DuplicateRecord);
        }
        let to = self.new_state()?;
        for record in &change.records {
            self.records.insert(*record, change.checkpoint);
        }
        self.insert_edge(HistoryEdge {
            checkpoint: change.checkpoint,
            from: self.head,
            to,
            kind: EdgeKind::Change {
                attribution: change.attribution,
                records: change.records,
                sessions: change.sessions,
            },
            paths: change.paths,
            overflowed: change.overflowed,
            saved: None,
            expired: false,
        });
        self.head = to;
        self.generation += 1;
        Ok(to)
    }

    /// Plans the undo of the edge identified by `checkpoint`: a step back if it is the latest edge in effect,
    /// otherwise a revert if no later edge touched its paths (FR-CKP-30). Changes nothing.
    ///
    /// # Errors
    ///
    /// [`HistoryError::UnknownChange`], [`HistoryError::Expired`], [`HistoryError::NotInEffect`], or
    /// [`HistoryError::Conflict`] with the paths a later edge also touched.
    pub fn plan_undo(&self, checkpoint: CheckpointId) -> Result<Plan, HistoryError> {
        let edge = self.live_edge(checkpoint)?;
        let path = self.head_path();
        if !path.in_effect(checkpoint) {
            return Err(HistoryError::NotInEffect);
        }
        if edge.to == self.head {
            return Ok(self.plan(Action::StepBack {
                edge: checkpoint,
                to: edge.from,
            }));
        }
        self.check_later_changes(edge, &path)?;
        Ok(self.plan(Action::Revert { edge: checkpoint }))
    }

    /// Plans the redo of the edge identified by `checkpoint`, restoring the versions saved by the matching undo: a
    /// step forward if the head stepped back over it, or the undo of the `undo` edge that reverted it. Changes
    /// nothing.
    ///
    /// # Errors
    ///
    /// [`HistoryError::UnknownChange`]; [`HistoryError::Expired`] if it, or the `undo` edge that reverted it,
    /// expired; [`HistoryError::NotUndone`] if it is in effect or has no saved versions;
    /// [`HistoryError::RedoBlocked`] if the head is not its parent state; or any error of undoing the `undo` edge
    /// ([`HistoryTree::plan_undo`]).
    pub fn plan_redo(&self, checkpoint: CheckpointId) -> Result<Plan, HistoryError> {
        let edge = self.live_edge(checkpoint)?;
        let path = self.head_path();
        if path.contains(checkpoint) {
            // On the head's path, the edge can only be undone by a revert; redoing it undoes that revert.
            return match path.undone_by.get(&checkpoint) {
                Some(&revert) => self.plan_undo(revert),
                None => Err(HistoryError::NotUndone),
            };
        }
        if edge.from != self.head {
            return Err(HistoryError::RedoBlocked);
        }
        let saved = edge.saved.ok_or(HistoryError::NotUndone)?;
        Ok(self.plan(Action::StepForward {
            edge: checkpoint,
            saved,
            to: edge.to,
        }))
    }

    /// Records that `plan` was carried out. `saved` is the checkpoint holding the versions saved before restoring,
    /// exactly when [`Plan::saves_current`] says so.
    ///
    /// # Errors
    ///
    /// [`HistoryError::Stale`] if the tree changed since the plan was made; [`HistoryError::SavedVersions`] if
    /// `saved` does not match the plan; [`HistoryError::DuplicateCheckpoint`] if `saved` is already in the tree;
    /// [`HistoryError::StatesExhausted`] if a revert needs a state number and none is left.
    pub fn commit(&mut self, plan: &Plan, saved: Option<CheckpointId>) -> Result<Committed, HistoryError> {
        if plan.generation != self.generation || plan.head != self.head {
            return Err(HistoryError::Stale);
        }
        // Every arm checks before it mutates, so the tree is unchanged on error. The `get_mut`/`get` lookups cannot
        // fail for a plan that passed the staleness check above; they map to `Stale` rather than panic.
        let released = match (plan.action, saved) {
            (Action::StepBack { .. } | Action::Revert { .. }, Some(saved)) if self.is_used(saved) => {
                return Err(HistoryError::DuplicateCheckpoint);
            }
            (Action::StepBack { edge, to }, Some(saved)) => {
                // A second step back over the same edge supersedes the versions an earlier one saved.
                let edge = self.edges.get_mut(&edge).ok_or(HistoryError::Stale)?;
                let released = edge.saved.replace(saved);
                self.head = to;
                released
            }
            (Action::StepForward { edge, to, .. }, None) => {
                // The saved versions are back in place; undoing again saves them anew.
                let edge = self.edges.get_mut(&edge).ok_or(HistoryError::Stale)?;
                let released = edge.saved.take();
                self.head = to;
                released
            }
            (Action::Revert { edge }, Some(saved)) => {
                let target = self.edges.get(&edge).ok_or(HistoryError::Stale)?;
                let (paths, overflowed) = (target.paths.clone(), target.overflowed);
                let to = self.new_state()?;
                self.insert_edge(HistoryEdge {
                    checkpoint: saved,
                    from: self.head,
                    to,
                    kind: EdgeKind::Undo { of: edge },
                    paths,
                    overflowed,
                    saved: None,
                    expired: false,
                });
                self.head = to;
                None
            }
            // `saved` must be given exactly when the plan saves the current versions (`Plan::saves_current`).
            (Action::StepBack { .. } | Action::Revert { .. }, None) | (Action::StepForward { .. }, Some(_)) => {
                return Err(HistoryError::SavedVersions);
            }
        };
        self.generation += 1;
        Ok(Committed {
            head: self.head,
            released,
        })
    }

    /// Expires the change identified by `checkpoint`, whose checkpoint retention or forget removes (module
    /// documentation, "Expiry"), and returns every checkpoint the tree no longer references, sorted: the edge's own,
    /// the versions its undo saved, and those of each edge expired or removed with it. The caller removes their files.
    ///
    /// With `scrub` (forget, FR-CKP-34), the expired edges also drop their path lists and count as overflowed, so
    /// nothing of what the user asked to forget stays in the tree, and an older change kept is still never undone
    /// over them unchecked (FR-CKP-30, fail closed). Expiring an edge already expired changes nothing but `scrub`.
    ///
    /// # Errors
    ///
    /// [`HistoryError::UnknownChange`] if no edge has this checkpoint (one already removed is not an error: nothing is
    /// left to expire).
    pub fn expire(&mut self, checkpoint: CheckpointId, scrub: bool) -> Result<Vec<CheckpointId>, HistoryError> {
        if !self.edges.contains_key(&checkpoint) {
            return if self.forgotten.contains(&checkpoint) {
                Ok(Vec::new())
            } else {
                Err(HistoryError::UnknownChange)
            };
        }
        let mut released = BTreeSet::new();
        let mut queue = vec![checkpoint];
        let mut seen = BTreeSet::new();
        while let Some(id) = queue.pop() {
            if !seen.insert(id) {
                continue;
            }
            let Some(edge) = self.edges.get_mut(&id) else {
                continue;
            };
            if !edge.expired {
                edge.expired = true;
                released.insert(id);
            }
            released.extend(edge.saved.take());
            if scrub {
                edge.paths.clear();
                edge.overflowed = true;
            }
            // Redoing a change reverted by an `undo` edge is that edge's undo: it goes with the change.
            queue.extend(
                self.edges
                    .values()
                    .filter(|other| matches!(other.kind, EdgeKind::Undo { of } if of == id))
                    .map(|other| other.checkpoint),
            );
        }
        self.remove_unreachable(&mut released);
        self.generation += 1;
        Ok(released.into_iter().collect())
    }

    /// Removes every edge no undo, redo or restore can use any more, adding the checkpoints they referenced to
    /// `released`: those that can only be reached by crossing an expired edge, then the expired edges at the root.
    /// The edges on the way from the root to the head are kept (expired or not), so later changes are still checked
    /// against them (FR-CKP-30).
    fn remove_unreachable(&mut self, released: &mut BTreeSet<CheckpointId>) {
        let trunk: BTreeSet<CheckpointId> = self.ancestors(self.head).into_iter().collect();
        // The states reachable from the head over edges not expired, either way.
        let mut reachable = BTreeSet::from([self.head]);
        let mut frontier = vec![self.head];
        while let Some(state) = frontier.pop() {
            let near = self.edges.values().filter(|edge| !edge.expired).filter_map(|edge| {
                if edge.from == state {
                    Some(edge.to)
                } else if edge.to == state {
                    Some(edge.from)
                } else {
                    None
                }
            });
            let near: Vec<StateId> = near.collect();
            for next in near {
                if reachable.insert(next) {
                    frontier.push(next);
                }
            }
        }
        let unreachable: Vec<CheckpointId> = self
            .edges
            .values()
            .filter(|edge| {
                let kept = trunk.contains(&edge.checkpoint)
                    || (reachable.contains(&edge.from) && reachable.contains(&edge.to));
                !kept
            })
            .map(|edge| edge.checkpoint)
            .collect();
        for checkpoint in unreachable {
            self.remove_edge(checkpoint, released);
        }
        // The expired edges at the root are needed by nothing: no kept edge is older than them.
        while self.root != self.head {
            let Some(first) = self.edges.values().find(|edge| edge.from == self.root) else {
                break;
            };
            if !first.expired {
                break;
            }
            let (checkpoint, to) = (first.checkpoint, first.to);
            self.remove_edge(checkpoint, released);
            self.root = to;
        }
    }

    /// Removes edge `checkpoint` from the tree, remembering it (and its records) as expired and adding the
    /// checkpoints it referenced to `released`.
    fn remove_edge(&mut self, checkpoint: CheckpointId, released: &mut BTreeSet<CheckpointId>) {
        let Some(edge) = self.edges.remove(&checkpoint) else {
            return;
        };
        self.parents.remove(&edge.to);
        // An expired edge's checkpoint and saved versions were released when it expired.
        if !edge.expired {
            released.insert(edge.checkpoint);
            released.extend(edge.saved);
        }
        if let EdgeKind::Change { records, .. } = &edge.kind {
            for record in records {
                self.records.remove(record);
                remember(&mut self.forgotten_records, *record);
            }
        }
        remember(&mut self.forgotten, edge.checkpoint);
    }

    /// The stored form: one JSON object with `format` [`HISTORY_FORMAT`], read back by [`HistoryTree::decode`].
    ///
    /// # Errors
    ///
    /// [`HistoryError::UnencodablePath`] if a path is not valid UTF-8 (APFS names always are).
    pub fn encode(&self) -> Result<String, HistoryError> {
        // Parents before children, so the reader can check each edge against the ones before it.
        let mut edges: Vec<&HistoryEdge> = self.edges.values().collect();
        edges.sort_by_key(|edge| edge.to);
        let edges = edges.into_iter().map(edge_to_json).collect::<Result<Vec<_>, _>>()?;
        let object = put(Object::new(), "format", state_number(HISTORY_FORMAT)?)?;
        let object = put(object, "root", state_number(self.root.0)?)?;
        let object = put(object, "head", state_number(self.head.0)?)?;
        let object = put(object, "next_state", state_number(self.next_state)?)?;
        let object = put(object, "edges", Value::Array(edges))?;
        let object = put(object, "forgotten", id_list(&self.forgotten))?;
        let object = put(object, "forgotten_records", id_list(&self.forgotten_records))?;
        knsh_json::write(&Value::Object(object)).map_err(|_| HistoryError::Corrupt)
    }

    /// Reads the stored form [`HistoryTree::encode`] writes, checking every invariant of the tree.
    ///
    /// # Errors
    ///
    /// [`HistoryError::TooLarge`] over [`MAX_HISTORY_LEN`] bytes; [`HistoryError::NewerFormat`] for a newer `format`;
    /// [`HistoryError::Corrupt`] for anything else that is not exactly that form or breaks an invariant (an unknown
    /// parent state, a state with two parents, a duplicate checkpoint or record, an `undo` edge that does not follow
    /// the edge it undid, a head that is not a state).
    pub fn decode(bytes: &[u8]) -> Result<Self, HistoryError> {
        if bytes.len() > MAX_HISTORY_LEN {
            return Err(HistoryError::TooLarge);
        }
        let value = knsh_json::parse(bytes, MAX_HISTORY_LEN).map_err(|_| HistoryError::Corrupt)?;
        let mut fields = Fields::new(&value).map_err(|_| HistoryError::Corrupt)?;
        // The format is checked first: a newer file may have any other shape, and must be reported as newer.
        let format = read_number(&mut fields, "format")?;
        if format > HISTORY_FORMAT {
            return Err(HistoryError::NewerFormat(format));
        }
        if format != HISTORY_FORMAT {
            return Err(HistoryError::Corrupt);
        }
        let root = StateId(read_number(&mut fields, "root")?);
        let head = StateId(read_number(&mut fields, "head")?);
        let next_state = read_number(&mut fields, "next_state")?;
        let edges: Vec<Value> = fields.required("edges").map_err(|_| HistoryError::Corrupt)?;
        let forgotten: Vec<String> = fields.required("forgotten").map_err(|_| HistoryError::Corrupt)?;
        let forgotten_records: Vec<String> = fields
            .required("forgotten_records")
            .map_err(|_| HistoryError::Corrupt)?;
        fields.finish_closed().map_err(|_| HistoryError::Corrupt)?;
        if forgotten.len() > MAX_FORGOTTEN || forgotten_records.len() > MAX_FORGOTTEN {
            return Err(HistoryError::Corrupt);
        }
        let forgotten =
            read_set(&forgotten, "forgotten", |text| text.parse().ok()).map_err(|_| HistoryError::Corrupt)?;
        let forgotten_records = read_set(&forgotten_records, "forgotten_records", |text| text.parse().ok())
            .map_err(|_| HistoryError::Corrupt)?;
        if root.0 >= next_state {
            return Err(HistoryError::Corrupt);
        }
        let mut tree = Self {
            root,
            head: root,
            next_state,
            forgotten,
            forgotten_records,
            ..Self::new()
        };
        for value in &edges {
            tree.decode_edge(value)?;
        }
        if head != root && !tree.parents.contains_key(&head) {
            return Err(HistoryError::Corrupt);
        }
        // Saved versions are checkpoints of their own: each held by one edge, and never an edge's checkpoint.
        let saved: Vec<CheckpointId> = tree.edges.values().filter_map(|edge| edge.saved).collect();
        let distinct: BTreeSet<CheckpointId> = saved.iter().copied().collect();
        if distinct.len() != saved.len()
            || distinct
                .iter()
                .any(|id| tree.edges.contains_key(id) || tree.forgotten.contains(id))
        {
            return Err(HistoryError::Corrupt);
        }
        // A removed edge is never also in the tree.
        if tree.edges.keys().any(|id| tree.forgotten.contains(id))
            || tree
                .records
                .keys()
                .any(|record| tree.forgotten_records.contains(record))
        {
            return Err(HistoryError::Corrupt);
        }
        tree.head = head;
        Ok(tree)
    }

    /// Reads one stored edge and adds it, refusing one that breaks an invariant given the edges before it.
    fn decode_edge(&mut self, value: &Value) -> Result<(), HistoryError> {
        let edge = edge_from_json(value).map_err(|_| HistoryError::Corrupt)?;
        let from_known = edge.from == self.root || self.parents.contains_key(&edge.from);
        // `from < to` with parents listed first keeps the tree acyclic; `to` must be a new state below `next_state`.
        let to_new = edge.to != self.root && !self.parents.contains_key(&edge.to);
        if !from_known || !to_new || edge.from >= edge.to || edge.to.0 >= self.next_state {
            return Err(HistoryError::Corrupt);
        }
        // An expired edge's saved versions were released with it.
        if self.edges.contains_key(&edge.checkpoint) || (edge.expired && edge.saved.is_some()) {
            return Err(HistoryError::Corrupt);
        }
        match &edge.kind {
            EdgeKind::Change { records, .. } => {
                for record in records {
                    if self.records.insert(*record, edge.checkpoint).is_some() {
                        return Err(HistoryError::Corrupt);
                    }
                }
            }
            // An undo edge undoes an edge in effect at its start state (the only kind `plan_undo` allows), and
            // touches exactly that edge's paths: a shorter list would hide conflicts from FR-CKP-30. An expired
            // change takes its undo edges with it, which may outlive it in the tree (`expire`, scrubbed or not).
            EdgeKind::Undo { of } => match self.edges.get(of) {
                None if edge.expired => {}
                Some(target) if target.expired && !edge.expired => return Err(HistoryError::Corrupt),
                Some(target)
                    if self.path_to(edge.from).in_effect(*of)
                        && (edge.expired || (target.paths == edge.paths && target.overflowed == edge.overflowed)) => {}
                Some(_) | None => return Err(HistoryError::Corrupt),
            },
        }
        self.insert_edge(edge);
        Ok(())
    }

    /// Wraps `action` with the head and generation it was planned against, for the staleness check in `commit`.
    fn plan(&self, action: Action) -> Plan {
        Plan {
            action,
            head: self.head,
            generation: self.generation,
        }
    }

    /// Refuses the revert of `edge` if a later edge on the head's path touched one of its paths, or if a path list
    /// involved is incomplete (FR-CKP-30).
    fn check_later_changes(&self, edge: &HistoryEdge, path: &HeadPath) -> Result<(), HistoryError> {
        let later: Vec<&HistoryEdge> = path
            .edges
            .iter()
            .skip_while(|checkpoint| **checkpoint != edge.checkpoint)
            .skip(1)
            .filter_map(|checkpoint| self.edges.get(checkpoint))
            .collect();
        let conflicts: BTreeSet<CanonicalPath> = later
            .iter()
            .flat_map(|later| later.paths.intersection(&edge.paths))
            .cloned()
            .collect();
        // An overflowed list proves nothing about the paths it left out, so any later edge may overlap it.
        let incomplete = !later.is_empty() && (edge.overflowed || later.iter().any(|later| later.overflowed));
        if conflicts.is_empty() && !incomplete {
            Ok(())
        } else {
            Err(HistoryError::Conflict {
                paths: conflicts,
                incomplete,
            })
        }
    }

    /// The edges from the root to the head and which of them were undone by an `undo` edge in effect.
    fn head_path(&self) -> HeadPath {
        self.path_to(self.head)
    }

    /// The edges from the root to `state` and which of them were undone by an `undo` edge in effect there.
    fn path_to(&self, state: StateId) -> HeadPath {
        let edges = self.ancestors(state);
        // Newest first: an `undo` edge counts only if no later `undo` edge undid it in turn.
        let mut undone_by = BTreeMap::new();
        for checkpoint in edges.iter().rev() {
            if undone_by.contains_key(checkpoint) {
                continue;
            }
            if let Some(EdgeKind::Undo { of }) = self.edges.get(checkpoint).map(|edge| &edge.kind) {
                undone_by.insert(*of, *checkpoint);
            }
        }
        HeadPath { edges, undone_by }
    }

    /// The edges from the root to `state`, oldest first.
    fn ancestors(&self, state: StateId) -> Vec<CheckpointId> {
        let mut edges = Vec::new();
        let mut state = state;
        while let Some(&checkpoint) = self.parents.get(&state) {
            edges.push(checkpoint);
            match self.edges.get(&checkpoint) {
                Some(edge) => state = edge.from,
                // `insert_edge` keeps `parents` and `edges` in step, so this cannot happen; stop rather than panic.
                None => break,
            }
        }
        edges.reverse();
        edges
    }

    /// Whether `checkpoint` already identifies an edge or the saved versions of one.
    fn is_used(&self, checkpoint: CheckpointId) -> bool {
        self.edges.contains_key(&checkpoint)
            || self.forgotten.contains(&checkpoint)
            || self.edges.values().any(|edge| edge.saved == Some(checkpoint))
    }

    /// Hands out the next state number, refusing past the integers JSON carries exactly.
    fn new_state(&mut self) -> Result<StateId, HistoryError> {
        if self.next_state >= MAX_STATE {
            return Err(HistoryError::StatesExhausted);
        }
        let state = StateId(self.next_state);
        self.next_state += 1;
        Ok(state)
    }

    /// Adds `edge` and its parent link; callers have checked the invariants of [`HistoryEdge`].
    fn insert_edge(&mut self, edge: HistoryEdge) {
        self.parents.insert(edge.to, edge.checkpoint);
        self.edges.insert(edge.checkpoint, edge);
    }
}

/// Adds `id` to `set`, dropping the lowest identifiers (the oldest) beyond [`MAX_FORGOTTEN`].
fn remember<T: Ord + Copy>(set: &mut BTreeSet<T>, id: T) {
    set.insert(id);
    while set.len() > MAX_FORGOTTEN {
        set.pop_first();
    }
}

/// A state number or format as a JSON integer.
fn state_number(number: u64) -> Result<Value, HistoryError> {
    i64::try_from(number)
        .ok()
        .and_then(|number| Value::int(number).ok())
        .ok_or(HistoryError::Corrupt)
}

/// A field holding a non-negative JSON integer.
fn read_number(fields: &mut Fields<'_>, name: &'static str) -> Result<u64, HistoryError> {
    let value: Value = fields.required(name).map_err(|_| HistoryError::Corrupt)?;
    non_negative(&value).ok_or(HistoryError::Corrupt)
}

/// The value as a non-negative integer, or `None` for anything else.
fn non_negative(value: &Value) -> Option<u64> {
    value.as_i64().and_then(|number| u64::try_from(number).ok())
}

/// A set of IDs as a JSON array of their text forms, in the set's (sorted) order.
fn id_list<T: fmt::Display>(ids: &BTreeSet<T>) -> Value {
    Value::Array(ids.iter().map(|id| Value::from(id.to_string())).collect())
}

/// Writes one edge object, the form [`edge_from_json`] reads.
fn edge_to_json(edge: &HistoryEdge) -> Result<Value, HistoryError> {
    let paths = edge
        .paths
        .iter()
        .map(|path| path.as_path().to_str().map(Value::from))
        .collect::<Option<Vec<_>>>()
        .ok_or(HistoryError::UnencodablePath)?;
    let object = put(Object::new(), "checkpoint", edge.checkpoint.to_string())?;
    let object = put(object, "from", state_number(edge.from.0)?)?;
    let object = put(object, "to", state_number(edge.to.0)?)?;
    let object = match &edge.kind {
        EdgeKind::Change {
            attribution,
            records,
            sessions,
        } => {
            let object = put(object, "kind", "change")?;
            let object = put(object, "attribution", attribution.as_str())?;
            let object = put(object, "records", id_list(records))?;
            put(object, "sessions", id_list(sessions))?
        }
        EdgeKind::Undo { of } => {
            let object = put(object, "kind", "undo")?;
            put(object, "of", of.to_string())?
        }
    };
    let saved = edge.saved.map_or(Value::Null, |saved| Value::from(saved.to_string()));
    let object = put(object, "paths", Value::Array(paths))?;
    let object = put(object, "overflowed", edge.overflowed)?;
    let object = put(object, "saved", saved)?;
    let object = put(object, "expired", edge.expired)?;
    Ok(Value::Object(object))
}

/// Adds a member the writer builds itself; a duplicate key would be a bug here, reported rather than written.
fn put(object: Object, key: &str, value: impl Into<Value>) -> Result<Object, HistoryError> {
    object.with(key, value).map_err(|_| HistoryError::Corrupt)
}

/// Reads one edge object: every member of its kind, nothing else, sorted and distinct lists.
fn edge_from_json(value: &Value) -> Result<HistoryEdge, JsonError> {
    let out_of_range = |field: &'static str| JsonError::OutOfRange { field: Some(field) };
    let mut fields = Fields::new(value)?;
    let checkpoint: String = fields.required("checkpoint")?;
    let from: Value = fields.required("from")?;
    let to: Value = fields.required("to")?;
    let kind: String = fields.required("kind")?;
    let kind = match kind.as_str() {
        "change" => {
            let attribution: String = fields.required("attribution")?;
            EdgeKind::Change {
                attribution: Attribution::parse(&attribution).ok_or(out_of_range("attribution"))?,
                records: read_set(&fields.required::<Vec<String>>("records")?, "records", |text| {
                    text.parse().ok()
                })?,
                sessions: read_set(&fields.required::<Vec<String>>("sessions")?, "sessions", |text| {
                    text.parse().ok()
                })?,
            }
        }
        "undo" => {
            let of: String = fields.required("of")?;
            EdgeKind::Undo {
                of: of.parse().map_err(|_| out_of_range("of"))?,
            }
        }
        _ => return Err(out_of_range("kind")),
    };
    let paths = read_set(&fields.required::<Vec<String>>("paths")?, "paths", |text| {
        CanonicalPath::new(text).ok()
    })?;
    let overflowed: bool = fields.required("overflowed")?;
    let saved: Option<String> = fields.required("saved")?;
    let expired: bool = fields.required("expired")?;
    fields.finish_closed()?;
    let state = |value: &Value, field| non_negative(value).map(StateId).ok_or(out_of_range(field));
    Ok(HistoryEdge {
        checkpoint: checkpoint.parse().map_err(|_| out_of_range("checkpoint"))?,
        from: state(&from, "from")?,
        to: state(&to, "to")?,
        kind,
        paths,
        overflowed,
        saved: saved
            .map(|saved| saved.parse().map_err(|_| out_of_range("saved")))
            .transpose()?,
        expired,
    })
}

/// Reads a list of strings into a set, refusing an item `parse` refuses and a duplicate (the writer writes none).
fn read_set<T: Ord>(
    items: &[String],
    field: &'static str,
    parse: impl Fn(&str) -> Option<T>,
) -> Result<BTreeSet<T>, JsonError> {
    let count = items.len();
    let set = items
        .iter()
        .map(|item| parse(item).ok_or(JsonError::OutOfRange { field: Some(field) }))
        .collect::<Result<BTreeSet<T>, _>>()?;
    if set.len() == count {
        Ok(set)
    } else {
        Err(JsonError::OutOfRange { field: Some(field) })
    }
}

/// Whether a restore undid a change or redid it (`checkpoint.restored`, KNSH-084).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RestoreOperation {
    /// `checkpoint.undo`: the change's pre-images were restored.
    Undo,
    /// `checkpoint.redo`: the versions its undo saved were restored.
    Redo,
}

impl RestoreOperation {
    /// The wire value: `undo` or `redo`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Undo => "undo",
            Self::Redo => "redo",
        }
    }
}

/// Why a path cannot be restored (`-32004`, FR-CKP-20, KNSH-084). Ordered by declaration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ConflictReason {
    /// The live file no longer matches its recorded post-image identity: something changed it after the change.
    Changed,
    /// The change left something at the path, and nothing is there now.
    Missing,
    /// The change left nothing at the path, and something is there now.
    Exists,
    /// The post-image identity could not be read when the change was captured, so the live file cannot be checked.
    Unverifiable,
    /// The version to restore could not be captured (the checkpoint is uncertain): there is nothing to restore.
    PreImageLost,
    /// Restoring would remove a folder that holds entries the change did not record.
    FolderNotEmpty,
    /// The folder the path must be restored into does not exist and is not restored either.
    ParentMissing,
}

impl ConflictReason {
    /// The wire value: `changed`, `missing`, `exists`, `unverifiable`, `pre_image_lost`, `folder_not_empty` or
    /// `parent_missing`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Changed => "changed",
            Self::Missing => "missing",
            Self::Exists => "exists",
            Self::Unverifiable => "unverifiable",
            Self::PreImageLost => "pre_image_lost",
            Self::FolderNotEmpty => "folder_not_empty",
            Self::ParentMissing => "parent_missing",
        }
    }

    /// Whether `force` (user and authority only, FR-CKP-21) restores the path anyway. Only an identity check can be
    /// overridden: what was recorded no longer matches, and the caller accepts losing what is there now. Nothing
    /// overrides a missing version or a restore that would delete unrecorded entries or cannot be placed.
    #[must_use]
    pub const fn forceable(self) -> bool {
        match self {
            Self::Changed | Self::Missing | Self::Exists | Self::Unverifiable => true,
            Self::PreImageLost | Self::FolderNotEmpty | Self::ParentMissing => false,
        }
    }
}

/// One path an undo or redo refused to restore, with why (`-32004` `conflicts`, FR-CKP-20).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RestoreConflict {
    /// The path.
    pub path: CanonicalPath,
    /// Why.
    pub reason: ConflictReason,
}

/// Why a path of a change is **possibly torn** (FR-CKP-24, KNSH-085): its captured versions may mix writes from
/// before and after the capture, so undo and redo skip it unless `force` is given (user and authority only,
/// FR-CKP-21). Ordered by declaration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TornReason {
    /// A process of the line, or still alive in its envelope, held the file open for writing when the line ended
    /// (decision 17).
    OpenForWriting,
    /// A process of the line, or still alive in its envelope, had the file mapped writable when the line ended:
    /// stores through a live mapping move neither size, time nor events (decision 17).
    MappedWritable,
    /// A SQLite database with a `-wal`, `-shm` or `-journal` file beside it (or that file itself): the database is
    /// only consistent together with its journal, which a restore of one file cannot keep.
    SqliteJournal,
    /// The processes that might hold files open could not all be listed or read when the line ended, so none of
    /// the change's files can be shown untorn (fail closed).
    Unchecked,
}

impl TornReason {
    /// The wire value: `open_for_writing`, `mapped_writable`, `sqlite_journal` or `unchecked`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OpenForWriting => "open_for_writing",
            Self::MappedWritable => "mapped_writable",
            Self::SqliteJournal => "sqlite_journal",
            Self::Unchecked => "unchecked",
        }
    }
}

/// One possibly-torn path an undo or redo skipped, or restored under `force` (FR-CKP-24).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TornPath {
    /// The path.
    pub path: CanonicalPath,
    /// Why it is possibly torn.
    pub reason: TornReason,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ulid::Ulid;

    fn checkpoint(n: u8) -> CheckpointId {
        CheckpointId::from_ulid(Ulid::new(1_700_000_000_000 + u64::from(n), [n; 10]).unwrap())
    }

    fn record_id(n: u8) -> RecordId {
        RecordId::from_ulid(Ulid::new(1_600_000_000_000 + u64::from(n), [n; 10]).unwrap())
    }

    fn session() -> SessionId {
        SessionId::from_ulid(Ulid::new(1_500_000_000_000, [9; 10]).unwrap())
    }

    fn path(text: &str) -> CanonicalPath {
        CanonicalPath::new(text).unwrap()
    }

    fn line(n: u8, paths: &[&str]) -> Change {
        Change {
            checkpoint: checkpoint(n),
            attribution: Attribution::Command,
            records: BTreeSet::from([record_id(n)]),
            sessions: BTreeSet::from([session()]),
            paths: paths.iter().map(|text| path(text)).collect(),
            overflowed: false,
        }
    }

    /// Plans and commits an undo, saving the current versions as checkpoint `saved`.
    fn undo(tree: &mut HistoryTree, edge: u8, saved: u8) -> Committed {
        let plan = tree.plan_undo(checkpoint(edge)).unwrap();
        tree.commit(&plan, Some(checkpoint(saved))).unwrap()
    }

    // KNSH-086: the way between two states goes back to the last state they share, then down the other branch.
    #[test]
    fn route_goes_back_to_the_shared_state_then_forward() {
        let mut tree = HistoryTree::new();
        let s1 = tree.record(line(1, &["/p/a"])).unwrap();
        let s2 = tree.record(line(2, &["/p/b"])).unwrap();
        let s3 = tree.record(line(3, &["/p/c"])).unwrap();
        undo(&mut tree, 3, 30);
        undo(&mut tree, 2, 20);
        // A new change from s1 starts another branch: s1 -> s4 -> s5.
        let s4 = tree.record(line(4, &["/p/d"])).unwrap();
        let s5 = tree.record(line(5, &["/p/e"])).unwrap();
        assert_eq!(tree.head(), s5);

        assert_eq!(
            tree.route(s5, s3).unwrap(),
            Route {
                back: vec![checkpoint(5), checkpoint(4)],
                forward: vec![checkpoint(2), checkpoint(3)],
            }
        );
        assert_eq!(
            tree.route(s5, tree.root()).unwrap(),
            Route {
                back: vec![checkpoint(5), checkpoint(4), checkpoint(1)],
                forward: vec![],
            }
        );
        assert_eq!(
            tree.route(s1, s2).unwrap(),
            Route {
                back: vec![],
                forward: vec![checkpoint(2)],
            }
        );
        assert!(tree.route(s4, s4).unwrap().is_empty());
        assert!(tree.has_state(s3) && tree.has_state(tree.root()));
        let unknown = StateId::new(99).unwrap();
        assert!(!tree.has_state(unknown));
        assert_eq!(tree.route(s5, unknown), Err(HistoryError::UnknownState));
        assert_eq!(tree.route(unknown, s5), Err(HistoryError::UnknownState));
        assert_eq!(StateId::new(MAX_STATE + 1), None);
        assert_eq!(StateId::new(7).map(StateId::get), Some(7));
    }

    #[test]
    fn undo_moves_to_parent_and_keeps_branch() {
        let mut tree = HistoryTree::new();
        let s1 = tree.record(line(1, &["/p/a"])).unwrap();
        let s2 = tree.record(line(2, &["/p/b"])).unwrap();

        let plan = tree.plan_undo(checkpoint(2)).unwrap();
        assert_eq!(
            plan.action(),
            Action::StepBack {
                edge: checkpoint(2),
                to: s1
            }
        );
        assert_eq!(plan.restore_from(), checkpoint(2));
        assert!(plan.saves_current());
        let committed = tree.commit(&plan, Some(checkpoint(20))).unwrap();

        assert_eq!(
            committed,
            Committed {
                head: s1,
                released: None
            }
        );
        assert_eq!(tree.head(), s1);
        // The abandoned branch is still reachable, with the versions saved for redo.
        let kept = tree.edge(checkpoint(2)).unwrap();
        assert_eq!((kept.from, kept.to, kept.saved), (s1, s2, Some(checkpoint(20))));
        assert_eq!(tree.children(s1), vec![kept]);
        assert!(!tree.is_in_effect(checkpoint(2)));
        assert!(tree.is_in_effect(checkpoint(1)));
        // Undoing it again is refused: it is no longer in effect.
        assert_eq!(tree.plan_undo(checkpoint(2)), Err(HistoryError::NotInEffect));
    }

    #[test]
    fn redo_after_undo_returns_to_child_state() {
        let mut tree = HistoryTree::new();
        tree.record(line(1, &["/p/a"])).unwrap();
        let s2 = tree.record(line(2, &["/p/a"])).unwrap();
        undo(&mut tree, 2, 20);
        let s0 = undo(&mut tree, 1, 10).head;
        assert_eq!(s0, tree.root());

        // Redo in order: each restores the versions its undo saved.
        let plan = tree.plan_redo(checkpoint(1)).unwrap();
        assert_eq!(plan.restore_from(), checkpoint(10));
        assert!(!plan.saves_current());
        assert_eq!(tree.commit(&plan, None).unwrap().released, Some(checkpoint(10)));
        let plan = tree.plan_redo(checkpoint(2)).unwrap();
        assert_eq!(
            plan.action(),
            Action::StepForward {
                edge: checkpoint(2),
                saved: checkpoint(20),
                to: s2
            }
        );
        assert_eq!(
            tree.commit(&plan, None).unwrap(),
            Committed {
                head: s2,
                released: Some(checkpoint(20))
            }
        );
        assert!(tree.is_in_effect(checkpoint(2)));
        assert_eq!(tree.edge(checkpoint(2)).unwrap().saved, None);
        // Nothing left to redo.
        assert_eq!(tree.plan_redo(checkpoint(2)), Err(HistoryError::NotUndone));
    }

    #[test]
    fn redo_out_of_order_is_blocked() {
        let mut tree = HistoryTree::new();
        tree.record(line(1, &["/p/a"])).unwrap();
        tree.record(line(2, &["/p/b"])).unwrap();
        undo(&mut tree, 2, 20);
        undo(&mut tree, 1, 10);
        // Change 2 starts from a state that is not the head.
        assert_eq!(tree.plan_redo(checkpoint(2)), Err(HistoryError::RedoBlocked));
    }

    // FR-CKP-30
    #[test]
    fn undo_of_older_change_conflicts_when_later_change_touched_path() {
        let mut tree = HistoryTree::new();
        tree.record(line(1, &["/p/a", "/p/b"])).unwrap();
        tree.record(line(2, &["/p/b", "/p/c"])).unwrap();
        tree.record(line(3, &["/p/d"])).unwrap();
        let before = tree.clone();

        assert_eq!(
            tree.plan_undo(checkpoint(1)),
            Err(HistoryError::Conflict {
                paths: BTreeSet::from([path("/p/b")]),
                incomplete: false
            })
        );
        assert_eq!(tree, before);
    }

    // FR-CKP-30: a later edge that listed only part of its paths may hide a conflict.
    #[test]
    fn undo_of_older_change_conflicts_when_path_list_overflowed() {
        let mut tree = HistoryTree::new();
        tree.record(line(1, &["/p/a"])).unwrap();
        tree.record(Change {
            overflowed: true,
            ..line(2, &["/p/z"])
        })
        .unwrap();
        assert_eq!(
            tree.plan_undo(checkpoint(1)),
            Err(HistoryError::Conflict {
                paths: BTreeSet::new(),
                incomplete: true
            })
        );
        // The latest edge can still be stepped back over: nothing later could conflict.
        assert!(tree.plan_undo(checkpoint(2)).is_ok());
    }

    // FR-CKP-30
    #[test]
    fn undo_of_older_change_succeeds_on_disjoint_paths() {
        let mut tree = HistoryTree::new();
        let s1 = tree.record(line(1, &["/p/a"])).unwrap();
        let s2 = tree.record(line(2, &["/p/b"])).unwrap();

        let plan = tree.plan_undo(checkpoint(1)).unwrap();
        assert_eq!(plan.action(), Action::Revert { edge: checkpoint(1) });
        assert_eq!(plan.restore_from(), checkpoint(1));
        let committed = tree.commit(&plan, Some(checkpoint(10))).unwrap();

        // A new state on top of the later change, reached by an undo edge holding the saved versions.
        let revert = tree.edge(checkpoint(10)).unwrap();
        assert_eq!((revert.from, revert.to), (s2, committed.head));
        assert_eq!(revert.kind, EdgeKind::Undo { of: checkpoint(1) });
        assert_eq!(revert.paths, BTreeSet::from([path("/p/a")]));
        assert!(committed.head > s2 && s1 < s2);
        assert!(!tree.is_in_effect(checkpoint(1)));
        assert!(tree.is_in_effect(checkpoint(2)));
        assert_eq!(tree.plan_undo(checkpoint(1)), Err(HistoryError::NotInEffect));

        // Redo of the reverted change undoes the undo edge, the latest: a step back to before the revert.
        let plan = tree.plan_redo(checkpoint(1)).unwrap();
        assert_eq!(
            plan.action(),
            Action::StepBack {
                edge: checkpoint(10),
                to: s2
            }
        );
        tree.commit(&plan, Some(checkpoint(11))).unwrap();
        assert!(tree.is_in_effect(checkpoint(1)));
        assert_eq!(tree.head(), s2);
    }

    #[test]
    fn redo_of_reverted_change_after_later_changes_follows_the_conflict_rule() {
        let mut tree = HistoryTree::new();
        tree.record(line(1, &["/p/a"])).unwrap();
        tree.record(line(2, &["/p/b"])).unwrap();
        undo(&mut tree, 1, 10);
        tree.record(line(3, &["/p/a"])).unwrap();
        // The undo edge is older now, and change 3 touched its path.
        assert_eq!(
            tree.plan_redo(checkpoint(1)),
            Err(HistoryError::Conflict {
                paths: BTreeSet::from([path("/p/a")]),
                incomplete: false
            })
        );
    }

    #[test]
    fn new_change_after_undo_starts_new_branch() {
        let mut tree = HistoryTree::new();
        let s1 = tree.record(line(1, &["/p/a"])).unwrap();
        let s2 = tree.record(line(2, &["/p/a"])).unwrap();
        undo(&mut tree, 2, 20);

        let s3 = tree.record(line(3, &["/p/a"])).unwrap();
        assert_eq!(tree.head(), s3);
        let branches: Vec<StateId> = tree.children(s1).iter().map(|edge| edge.to).collect();
        assert_eq!(branches, vec![s2, s3]);
        // The old branch stays, with its saved versions, but cannot be redone over the new change.
        assert_eq!(tree.edge(checkpoint(2)).unwrap().saved, Some(checkpoint(20)));
        assert_eq!(tree.plan_redo(checkpoint(2)), Err(HistoryError::RedoBlocked));
        assert_eq!(tree.edge_for_record(record_id(3)).unwrap().to, s3);
    }

    #[test]
    fn concurrent_set_is_one_edge_for_each_of_its_lines() {
        let mut tree = HistoryTree::new();
        let set = Change {
            attribution: Attribution::Concurrent,
            records: BTreeSet::from([record_id(1), record_id(2)]),
            ..line(1, &["/p/a"])
        };
        tree.record(set).unwrap();
        assert_eq!(tree.edge_for_record(record_id(2)).unwrap().checkpoint, checkpoint(1));
        assert_eq!(tree.edge_for_record(record_id(1)).unwrap().checkpoint, checkpoint(1));
    }

    #[test]
    fn refuses_duplicates_and_leaves_tree_unchanged() {
        let mut tree = HistoryTree::new();
        tree.record(line(1, &["/p/a"])).unwrap();
        let before = tree.clone();
        assert_eq!(tree.record(line(1, &["/p/b"])), Err(HistoryError::DuplicateCheckpoint));
        let reused_record = Change {
            checkpoint: checkpoint(2),
            ..line(1, &["/p/b"])
        };
        assert_eq!(tree.record(reused_record), Err(HistoryError::DuplicateRecord));
        assert_eq!(tree, before);

        let plan = tree.plan_undo(checkpoint(1)).unwrap();
        assert_eq!(
            tree.commit(&plan, Some(checkpoint(1))),
            Err(HistoryError::DuplicateCheckpoint)
        );
        assert_eq!(tree.commit(&plan, None), Err(HistoryError::SavedVersions));
        assert_eq!(tree, before);
    }

    #[test]
    fn stale_plan_is_refused() {
        let mut tree = HistoryTree::new();
        tree.record(line(1, &["/p/a"])).unwrap();
        let plan = tree.plan_undo(checkpoint(1)).unwrap();
        tree.record(line(2, &["/p/b"])).unwrap();
        let before = tree.clone();
        assert_eq!(tree.commit(&plan, Some(checkpoint(10))), Err(HistoryError::Stale));
        assert_eq!(tree, before);
        // A plan cannot be committed twice either.
        let plan = tree.plan_undo(checkpoint(2)).unwrap();
        tree.commit(&plan, Some(checkpoint(20))).unwrap();
        assert_eq!(tree.commit(&plan, Some(checkpoint(21))), Err(HistoryError::Stale));
    }

    #[test]
    fn unknown_change_is_refused() {
        let tree = HistoryTree::new();
        assert_eq!(tree.plan_undo(checkpoint(1)), Err(HistoryError::UnknownChange));
        assert_eq!(tree.plan_redo(checkpoint(1)), Err(HistoryError::UnknownChange));
    }

    #[test]
    fn serialised_tree_round_trips() {
        // Every kind of edge, saved versions, an overflowed list and two branches from one state.
        let mut tree = HistoryTree::new();
        tree.record(line(1, &["/p/a"])).unwrap();
        tree.record(line(2, &["/p/b"])).unwrap();
        undo(&mut tree, 1, 10);
        let branch_point = tree
            .record(Change {
                attribution: Attribution::AgentEdit,
                records: BTreeSet::new(),
                overflowed: true,
                ..line(3, &["/p/c", "/p/d"])
            })
            .unwrap();
        undo(&mut tree, 3, 30);
        tree.record(line(4, &["/p/e"])).unwrap();
        assert_eq!(tree.children(tree.parent_edge(branch_point).unwrap().from).len(), 2);

        let text = tree.encode().unwrap();
        assert!(text.starts_with(r#"{"format":2,"#));
        let read = HistoryTree::decode(text.as_bytes()).unwrap();
        // Equal except the in-memory generation, which is not stored.
        assert_eq!(read.encode().unwrap(), text);
        assert_eq!(
            (read.root(), read.head(), read.len()),
            (tree.root(), tree.head(), tree.len())
        );
        for edge in tree.edges() {
            assert_eq!(read.edge(edge.checkpoint), Some(edge));
        }
        assert_eq!(read.edge_for_record(record_id(2)), tree.edge_for_record(record_id(2)));
        assert_eq!(read.is_in_effect(checkpoint(1)), tree.is_in_effect(checkpoint(1)));
        assert_eq!(
            HistoryTree::decode(HistoryTree::new().encode().unwrap().as_bytes()),
            Ok(HistoryTree::new())
        );
    }

    #[test]
    fn newer_format_is_reported_as_newer() {
        let text = r#"{"format":3,"anything":true}"#;
        assert_eq!(HistoryTree::decode(text.as_bytes()), Err(HistoryError::NewerFormat(3)));
    }

    #[test]
    fn refuses_corrupt_stored_trees() {
        let mut tree = HistoryTree::new();
        tree.record(line(1, &["/p/a"])).unwrap();
        tree.record(line(2, &["/p/b"])).unwrap();
        let good = tree.encode().unwrap();
        let first = checkpoint(1).to_string();
        let second = checkpoint(2).to_string();
        let record = record_id(1).to_string();
        let corrupt = [
            String::new(),
            "[]".to_owned(),
            r#"{"format":0,"root":0,"head":0,"next_state":1,"edges":[]}"#.to_owned(),
            // Format 1 (KNSH-083) lacks the KNSH-087 fields and was never written: refused, not guessed at.
            r#"{"format":1,"root":0,"head":0,"next_state":1,"edges":[]}"#.to_owned(),
            r#"{"format":2,"root":0,"head":0,"next_state":1,"edges":[],"extra":1}"#.to_owned(),
            // Head is not a state; root not below next_state.
            r#"{"format":2,"root":0,"head":5,"next_state":1,"edges":[]}"#.to_owned(),
            r#"{"format":2,"root":3,"head":3,"next_state":3,"edges":[]}"#.to_owned(),
            // An edge from an unknown state, a state with two parents, and an edge pointing backwards.
            good.replace(r#""from":1"#, r#""from":7"#),
            good.replace(r#""from":1,"to":2"#, r#""from":0,"to":1"#),
            good.replace(r#""from":0,"to":1"#, r#""from":1,"to":0"#),
            // A checkpoint used twice, a record in two edges, saved versions reusing an edge's checkpoint.
            good.replace(&second, &first),
            good.replace(&record_id(2).to_string(), &record),
            good.replacen(r#""saved":null"#, &format!(r#""saved":"{second}""#), 1),
            // An undo edge of a change that is not before it, a relative path, an unknown attribution, a duplicate.
            good.replace(
                &format!(
                    r#""kind":"change","attribution":"command","records":["{record}"],"sessions":["{}"]"#,
                    session()
                ),
                &format!(r#""kind":"undo","of":"{second}""#),
            ),
            good.replace(r#""/p/a""#, r#""p/a""#),
            good.replacen(r#""command""#, r#""robot""#, 1),
            good.replace(r#"["/p/a"]"#, r#"["/p/a","/p/a"]"#),
        ];
        for text in &corrupt {
            assert_ne!(text, &good, "the corruption must change the text");
            assert_eq!(
                HistoryTree::decode(text.as_bytes()),
                Err(HistoryError::Corrupt),
                "{text}"
            );
        }
    }

    // FR-CKP-30: a stored undo edge must undo an edge in effect and carry its paths, or conflicts could be missed.
    #[test]
    fn refuses_stored_undo_edges_that_break_the_conflict_rule() {
        let mut tree = HistoryTree::new();
        tree.record(line(1, &["/p/a"])).unwrap();
        tree.record(line(2, &["/p/b"])).unwrap();
        undo(&mut tree, 1, 10);
        tree.record(line(3, &["/p/c"])).unwrap();
        let good = tree.encode().unwrap();
        assert!(HistoryTree::decode(good.as_bytes()).is_ok());
        let first = checkpoint(1).to_string();
        let revert = format!(r#""kind":"undo","of":"{first}","paths":["/p/a"],"overflowed":false"#);
        assert!(good.contains(&revert));
        let change3 = format!(
            r#""kind":"change","attribution":"command","records":["{}"],"sessions":["{}"],"paths":["/p/c"]"#,
            record_id(3),
            session()
        );
        assert!(good.contains(&change3));
        let corrupt = [
            // The undo edge lists fewer paths than the edge it undid, or claims a complete list for an overflowed one.
            good.replace(
                &revert,
                &format!(r#""kind":"undo","of":"{first}","paths":[],"overflowed":false"#),
            ),
            good.replace(
                &revert,
                &format!(r#""kind":"undo","of":"{first}","paths":["/p/a"],"overflowed":true"#),
            ),
            // A second undo of a change the first one already undid.
            good.replace(&change3, &format!(r#""kind":"undo","of":"{first}","paths":["/p/a"]"#)),
        ];
        for text in &corrupt {
            assert_ne!(text, &good, "the corruption must change the text");
            assert_eq!(
                HistoryTree::decode(text.as_bytes()),
                Err(HistoryError::Corrupt),
                "{text}"
            );
        }
    }

    #[test]
    fn refuses_oversized_stored_tree() {
        let text = vec![b' '; MAX_HISTORY_LEN + 1];
        assert_eq!(HistoryTree::decode(&text), Err(HistoryError::TooLarge));
    }

    // FR-CKP-24 (KNSH-085): the wire values of why a path is possibly torn.
    #[test]
    fn torn_reasons_have_stable_wire_values() {
        let all = [
            TornReason::OpenForWriting,
            TornReason::MappedWritable,
            TornReason::SqliteJournal,
            TornReason::Unchecked,
        ];
        let wire: Vec<&str> = all.iter().map(|reason| reason.as_str()).collect();
        assert_eq!(
            wire,
            ["open_for_writing", "mapped_writable", "sqlite_journal", "unchecked"]
        );
        // A mapping outranks a descriptor when both hold a file (`knsh_checkpoint::held_in_roots`).
        assert!(TornReason::MappedWritable > TornReason::OpenForWriting);
    }

    // KNSH-087: a stored tree whose saved versions reuse a forgotten checkpoint id is corrupt.
    #[test]
    fn refuses_stored_saved_versions_that_were_forgotten() {
        let mut tree = HistoryTree::new();
        tree.record(line(1, &["/p/a"])).unwrap();
        tree.record(line(2, &["/p/b"])).unwrap();
        undo(&mut tree, 2, 20);
        // The oldest change is removed at the root: its checkpoint id is forgotten.
        assert_eq!(tree.expire(checkpoint(1), false), Ok(vec![checkpoint(1)]));
        assert!(tree.edge(checkpoint(1)).is_none());
        let good = tree.encode().unwrap();
        assert!(HistoryTree::decode(good.as_bytes()).is_ok());
        let saved = format!(r#""saved":"{}""#, checkpoint(20));
        assert!(good.contains(&saved));
        // Saved versions that claim a forgotten checkpoint id would refer to files already removed.
        let corrupt = good.replace(&saved, &format!(r#""saved":"{}""#, checkpoint(1)));
        assert_ne!(corrupt, good);
        assert_eq!(HistoryTree::decode(corrupt.as_bytes()), Err(HistoryError::Corrupt));
    }

    // KNSH-087: undo and redo of a change whose checkpoint was removed say so, and the tree drops what nothing needs.
    #[test]
    fn expired_changes_report_expired_and_leave_the_root() {
        let mut tree = HistoryTree::new();
        tree.record(line(1, &["/p/a"])).unwrap();
        let s2 = tree.record(line(2, &["/p/b"])).unwrap();
        tree.record(line(3, &["/p/c"])).unwrap();

        // The middle change: kept as expired (an older change is still there), its checkpoint released.
        assert_eq!(tree.expire(checkpoint(2), false), Ok(vec![checkpoint(2)]));
        assert!(tree.is_expired(checkpoint(2)) && tree.is_record_expired(record_id(2)));
        assert_eq!(tree.plan_undo(checkpoint(2)), Err(HistoryError::Expired));
        assert_eq!(tree.plan_redo(checkpoint(2)), Err(HistoryError::Expired));
        assert_eq!(tree.route(tree.head(), tree.root()), Err(HistoryError::Expired));
        // The older change can still be reverted: the expired one kept its paths, which do not overlap.
        assert!(tree.plan_undo(checkpoint(1)).is_ok());
        // The latest one can still be undone.
        undo(&mut tree, 3, 30);
        assert_eq!(tree.head(), s2);

        // Expiring the oldest leaves both expired edges at the root: removed, and still reported as expired.
        assert_eq!(tree.expire(checkpoint(1), false), Ok(vec![checkpoint(1)]));
        assert_eq!(tree.root(), s2);
        assert!(tree.edge(checkpoint(1)).is_none() && tree.edge(checkpoint(2)).is_none());
        assert_eq!(tree.plan_undo(checkpoint(1)), Err(HistoryError::Expired));
        assert!(tree.is_record_expired(record_id(1)) && tree.edge_for_record(record_id(1)).is_none());
        assert_eq!(
            tree.expire(checkpoint(1), false),
            Ok(vec![]),
            "already gone: nothing to do"
        );
        assert_eq!(tree.expire(checkpoint(99), false), Err(HistoryError::UnknownChange));
        assert_eq!(tree.plan_undo(checkpoint(99)), Err(HistoryError::UnknownChange));
        // The undone change is still redoable.
        assert!(tree.plan_redo(checkpoint(3)).is_ok());
    }

    // KNSH-087: branches only reachable over an expired change go, with their saved versions.
    #[test]
    fn expiring_releases_branches_only_reachable_over_it() {
        let mut tree = HistoryTree::new();
        let s1 = tree.record(line(1, &["/p/a"])).unwrap();
        tree.record(line(2, &["/p/b"])).unwrap();
        tree.record(line(3, &["/p/c"])).unwrap();
        undo(&mut tree, 3, 30);
        undo(&mut tree, 2, 20);
        assert_eq!(tree.head(), s1);

        // Off the head's path: the change, what lies beyond it, and their saved versions.
        let released = tree.expire(checkpoint(2), false).unwrap();
        assert_eq!(
            released,
            vec![checkpoint(2), checkpoint(3), checkpoint(20), checkpoint(30)]
        );
        assert_eq!(tree.len(), 1);
        assert_eq!(tree.plan_redo(checkpoint(2)), Err(HistoryError::Expired));
        assert_eq!(tree.plan_redo(checkpoint(3)), Err(HistoryError::Expired));
        assert!(tree.plan_undo(checkpoint(1)).is_ok());

        // On the head's path: the branches off the states before it can no longer be reached.
        let mut tree = HistoryTree::new();
        tree.record(line(1, &["/p/a"])).unwrap();
        undo(&mut tree, 1, 10);
        let s2 = tree.record(line(2, &["/p/b"])).unwrap();
        let released = tree.expire(checkpoint(2), false).unwrap();
        assert_eq!(released, vec![checkpoint(1), checkpoint(2), checkpoint(10)]);
        assert!(tree.is_empty());
        assert_eq!((tree.root(), tree.head()), (s2, s2));
        assert_eq!(tree.plan_redo(checkpoint(1)), Err(HistoryError::Expired));
    }

    // KNSH-087: a change reverted by an undo edge takes it along: redoing the change would be undoing that edge.
    #[test]
    fn expiring_a_reverted_change_expires_its_undo_edge() {
        let mut tree = HistoryTree::new();
        tree.record(line(1, &["/p/a"])).unwrap();
        tree.record(line(2, &["/p/b"])).unwrap();
        undo(&mut tree, 1, 10);
        assert_eq!(
            tree.expire(checkpoint(1), false),
            Ok(vec![checkpoint(1), checkpoint(10)])
        );
        assert_eq!(tree.plan_redo(checkpoint(1)), Err(HistoryError::Expired));
        assert_eq!(tree.plan_undo(checkpoint(10)), Err(HistoryError::Expired));
        // A revert of the later change over the expired undo edge: disjoint paths, so still allowed (FR-CKP-30).
        assert!(tree.plan_undo(checkpoint(2)).is_ok());

        // The stored form keeps expired edges and what was removed.
        let text = tree.encode().unwrap();
        let read = HistoryTree::decode(text.as_bytes()).unwrap();
        assert_eq!(read.encode().unwrap(), text);
        assert!(read.is_expired(checkpoint(1)) && read.is_expired(checkpoint(10)));
        assert_eq!(read.plan_redo(checkpoint(1)), Err(HistoryError::Expired));
    }

    // FR-CKP-34 with FR-CKP-30: a forgotten change keeps no paths, and counts as touching every path.
    #[test]
    fn scrubbed_expiry_drops_paths_and_fails_closed() {
        let mut tree = HistoryTree::new();
        tree.record(line(1, &["/p/a"])).unwrap();
        tree.record(line(2, &["/p/b"])).unwrap();
        tree.record(line(3, &["/p/c"])).unwrap();
        assert!(tree.plan_undo(checkpoint(1)).is_ok());

        tree.expire(checkpoint(2), true).unwrap();
        let edge = tree.edge(checkpoint(2)).unwrap();
        assert!(edge.expired && edge.paths.is_empty() && edge.overflowed);
        assert_eq!(
            tree.plan_undo(checkpoint(1)),
            Err(HistoryError::Conflict {
                paths: BTreeSet::new(),
                incomplete: true,
            })
        );
        let text = tree.encode().unwrap();
        assert!(!text.contains("/p/b"));
        assert!(HistoryTree::decode(text.as_bytes()).is_ok());
    }

    #[test]
    fn refuses_stored_expiry_that_breaks_invariants() {
        let mut tree = HistoryTree::new();
        tree.record(line(1, &["/p/a"])).unwrap();
        tree.record(line(2, &["/p/b"])).unwrap();
        tree.record(line(3, &["/p/c"])).unwrap();
        tree.expire(checkpoint(2), false).unwrap();
        tree.expire(checkpoint(1), false).unwrap();
        let good = tree.encode().unwrap();
        assert!(HistoryTree::decode(good.as_bytes()).is_ok());
        let third = checkpoint(3).to_string();
        let corrupt = [
            // A removed checkpoint still in the tree; an expired edge keeping saved versions.
            good.replacen(&checkpoint(1).to_string(), &third, 1),
            good.replace(r#""saved":null,"expired":false"#, r#""saved":null,"expired":true"#)
                .replacen(r#""saved":null"#, &format!(r#""saved":"{}""#, checkpoint(40)), 1),
        ];
        for text in &corrupt {
            assert_ne!(text, &good);
            assert_eq!(
                HistoryTree::decode(text.as_bytes()),
                Err(HistoryError::Corrupt),
                "{text}"
            );
        }
    }
}
