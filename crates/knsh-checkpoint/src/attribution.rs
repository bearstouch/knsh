//! Change attribution: which unit of undo each change in a checkpoint root belongs to (FR-CKP-05, FR-CKP-06,
//! FR-CKP-07, KNSH-081).
//!
//! The [`Ledger`] is a pure model, with no I/O, no clock and no lock: `knshd` keeps one for the whole daemon behind
//! its own lock and feeds it what happens, in the order it happens. It groups changes into [`Edge`]s, the units the
//! history tree (KNSH-083) stores and undo applies to (`specs/05-models/checkpoint.md`).
//!
//! # By time and place
//!
//! File events carry no process ID, so a change is attributed by **when** the watcher applied it and **which root**
//! it is in, never by who made it:
//!
//! - **While supervised lines run in the root**, the change belongs to them. One line alone makes a `command` edge
//!   (FR-CKP-05). Lines that overlap in time in one root form one `concurrent` edge (FR-CKP-07): their changes cannot
//!   be told apart, so they are undone together. Overlap is transitive, and crosses roots through a line touching
//!   several: A and B overlapping in one root, and B and C in another, are one set {A, B, C}.
//! - **While no line runs there and an envelope session watches the root**, the change is an `agent_edit` of the
//!   envelope's agent (FR-CKP-06), such as its built-in edit tool. Consecutive agent edits form one edge, closed when
//!   the next line in the root starts or the envelope stops watching. Each batch of them is also reported for the
//!   `agent.edit` event ([`Ledger::take_agent_edits`]).
//! - **Otherwise** (no envelope watches the root: only sessions without an envelope, `session.create`) the change is
//!   `external`: no agent session made it inside an envelope, so it is never offered for agent undo
//!   ([`Edge::agent_may_undo`]).
//!
//! The ledger is keyed by root, not by session: a line of one session in a root another session also protects makes
//! that root busy for both, so the other session's watcher never reports the line's changes as its own agent edits.
//! A concurrent set may therefore hold lines of more than one session.
//!
//! # Accepted imprecision
//!
//! - A human (or any other process) writing in the root at the same moment is attributed to the agent or the line
//!   running then. The specification accepts this: undo restores a path only if it still matches its recorded
//!   post-image identity (FR-CKP-20, KNSH-084), so a wrong attribution can refuse an undo but never overwrite work.
//! - A line's end is exact: the line-end procedure (decision 16) applies every event of the line before
//!   [`Ledger::line_ended`] is called. Its start is not: opening a line never waits for the watcher, so a change made
//!   just before the line, whose event the watcher had not applied yet, is attributed to the line.
//!
//! # Invariants
//!
//! - A line's attribution is final when it ends: an edge only grows while one of its lines runs, so a line that ends
//!   alone in its edge stays `command`, and one that shared it is `concurrent`. The record's `attribution` is
//!   therefore always the attribution of the closed edge holding it.
//! - Every edge is closed exactly once and handed out once ([`Ledger::take_closed`]).
//! - Memory is bounded per edge ([`MAX_EDGE_PATHS`], then [`Edge::overflowed`]) and per `agent.edit` batch
//!   ([`AGENT_EDIT_PATHS`]); a root's state is forgotten once nothing refers to it.

use std::collections::{BTreeMap, BTreeSet};

use knsh_core::{AGENT_EDIT_PATHS, Attribution, CanonicalPath, RecordId, SessionId};

/// The most paths one edge lists. Further changes still belong to the edge; it is marked [`Edge::overflowed`], so
/// capture (KNSH-082) knows its list is incomplete instead of trusting it.
pub const MAX_EDGE_PATHS: usize = 65_536;

/// Identifies an edge within one [`Ledger`]; increases with each new edge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EdgeId(u64);

impl EdgeId {
    /// The number behind it.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// One unit of undo: a line, a concurrent set or a run of agent or external edits, from one state to the next
/// (`specs/05-models/checkpoint.md`, "Edge").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Edge {
    /// Its identifier in the ledger.
    pub id: EdgeId,
    /// How its changes were attributed. `command` and `concurrent` edges hold lines; `agent_edit` and `external`
    /// edges hold none.
    pub attribution: Attribution,
    /// The lines whose changes it holds: one for `command`, two or more for `concurrent`, none otherwise.
    pub records: BTreeSet<RecordId>,
    /// The sessions it belongs to: those of its lines, or the envelope sessions watching the root of agent edits.
    /// Empty for `external` edges.
    pub sessions: BTreeSet<SessionId>,
    /// The paths that changed, by checkpoint root. A line that changed nothing has an edge with no paths.
    pub paths: BTreeMap<CanonicalPath, BTreeSet<CanonicalPath>>,
    /// More than [`MAX_EDGE_PATHS`] paths changed: `paths` is incomplete.
    pub overflowed: bool,
}

impl Edge {
    /// Whether an agent may be offered undo of this edge: never for `external` changes (KNSH-081).
    #[must_use]
    pub const fn agent_may_undo(&self) -> bool {
        self.attribution.agent_may_undo()
    }

    /// How many paths it lists.
    #[must_use]
    pub fn path_count(&self) -> usize {
        self.paths.values().map(BTreeSet::len).sum()
    }

    fn new(id: EdgeId, attribution: Attribution) -> Self {
        Self {
            id,
            attribution,
            records: BTreeSet::new(),
            sessions: BTreeSet::new(),
            paths: BTreeMap::new(),
            overflowed: false,
        }
    }

    /// Adds `path` under `root`, or marks the edge overflowed once it lists [`MAX_EDGE_PATHS`].
    fn add_path(&mut self, root: &CanonicalPath, path: &CanonicalPath) {
        if self.paths.get(root).is_some_and(|listed| listed.contains(path)) {
            return;
        }
        if self.path_count() >= MAX_EDGE_PATHS {
            self.overflowed = true;
            return;
        }
        self.paths.entry(root.clone()).or_default().insert(path.clone());
    }

    /// Takes everything `other` holds: two edges whose lines overlapped became one set.
    fn absorb(&mut self, other: Self) {
        self.records.extend(other.records);
        self.sessions.extend(other.sessions);
        self.overflowed |= other.overflowed;
        for (root, paths) in other.paths {
            for path in paths {
                self.add_path(&root, &path);
            }
        }
    }
}

/// How a line that ended was attributed ([`Ledger::line_ended`]): the record's `attribution`, and the edge holding
/// its changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LineAttribution {
    /// `command`, or `concurrent` when another line overlapped it in one of its roots.
    pub attribution: Attribution,
    /// The edge holding its changes (and those of the lines it overlapped).
    pub edge: EdgeId,
}

/// One batch of agent edits in a root, for the `agent.edit` event (FR-CKP-06).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentEdits {
    /// The checkpoint root.
    pub root: CanonicalPath,
    /// The envelope sessions watching the root when the edits were made: each is told.
    pub sessions: BTreeSet<SessionId>,
    /// The paths that changed, sorted, at most [`AGENT_EDIT_PATHS`].
    pub paths: Vec<CanonicalPath>,
    /// How many more paths changed than `paths` lists, saturating.
    pub omitted: u32,
}

/// An edge still accumulating changes.
struct OpenEdge {
    edge: Edge,
    /// Its lines still running; a line edge closes when this empties.
    running: BTreeSet<RecordId>,
}

/// A line that is running.
struct Line {
    edge: EdgeId,
    /// The roots it touches, each once.
    roots: Vec<CanonicalPath>,
}

/// Agent edits of a root not yet reported.
#[derive(Default)]
struct PendingEdits {
    paths: BTreeSet<CanonicalPath>,
    omitted: u32,
    sessions: BTreeSet<SessionId>,
}

impl PendingEdits {
    fn is_empty(&self) -> bool {
        self.paths.is_empty() && self.omitted == 0
    }

    /// Notes an agent edit of `path` for the envelope `sessions`. The batch lists at most [`AGENT_EDIT_PATHS`]
    /// paths, so one event stays bounded however many files the agent touched; the rest are only counted.
    fn record(&mut self, sessions: &BTreeSet<SessionId>, path: &CanonicalPath) {
        self.sessions.extend(sessions.iter().copied());
        if self.paths.contains(path) {
            return;
        }
        if self.paths.len() < AGENT_EDIT_PATHS {
            self.paths.insert(path.clone());
        } else {
            self.omitted = self.omitted.saturating_add(1);
        }
    }
}

/// What the ledger knows of one root.
#[derive(Default)]
struct Root {
    /// The lines running in it.
    running: BTreeSet<RecordId>,
    /// The edge of those lines; `Some` exactly while `running` is not empty.
    busy: Option<EdgeId>,
    /// The open `agent_edit` or `external` edge, while no line runs.
    idle: Option<EdgeId>,
    /// How many registrations watch it, envelope or not ([`Ledger::watch`]). While none does and no line runs, a
    /// change reported for it (a stopped watcher's last batch) belongs to nobody and is dropped, so an idle run is
    /// never opened that nothing would close.
    watchers: usize,
    /// Envelope sessions watching it, with how many times each registered (a session may list a root twice).
    envelopes: BTreeMap<SessionId, usize>,
    /// Agent edits not yet reported.
    pending: PendingEdits,
}

impl Root {
    /// Nothing refers to it any more, so it can be forgotten.
    fn is_unused(&self) -> bool {
        self.running.is_empty()
            && self.busy.is_none()
            && self.idle.is_none()
            && self.watchers == 0
            && self.envelopes.is_empty()
            && self.pending.is_empty()
    }
}

/// The attribution of every change in every checkpoint root (module documentation). One per `knshd`.
#[derive(Default)]
pub struct Ledger {
    next_edge: u64,
    roots: BTreeMap<CanonicalPath, Root>,
    lines: BTreeMap<RecordId, Line>,
    open: BTreeMap<EdgeId, OpenEdge>,
    /// Edges closed and not yet taken.
    closed: Vec<Edge>,
}

impl Ledger {
    /// An empty ledger: no root watched, no line running.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// `session_id` watches `root` (its agent session started protecting it); `envelope` tells whether the session
    /// runs inside an envelope, which makes changes between lines its agent edits.
    ///
    /// An `external` run open in the root is closed when the first envelope arrives: later changes are agent edits.
    pub fn watch(&mut self, root: &CanonicalPath, session_id: SessionId, envelope: bool) {
        let state = self.roots.entry(root.clone()).or_default();
        state.watchers += 1;
        if !envelope {
            // A session without an envelope changes nothing about how idle changes are attributed (module
            // documentation): they stay `external` unless an envelope also watches the root.
            return;
        }
        let first = state.envelopes.is_empty();
        *state.envelopes.entry(session_id).or_insert(0) += 1;
        if first {
            self.close_idle(root);
        }
    }

    /// `session_id` stopped watching `root` (its session ended). Undoes one [`Ledger::watch`] with the same
    /// arguments. An `agent_edit` run open in the root is closed when its last envelope leaves: later changes there
    /// are `external`. Any idle run is closed when the last watcher of any kind leaves: nothing reports changes
    /// there any more, so nothing else would ever close it, and the root could never be forgotten.
    pub fn unwatch(&mut self, root: &CanonicalPath, session_id: SessionId, envelope: bool) {
        let Some(state) = self.roots.get_mut(root) else {
            return;
        };
        state.watchers = state.watchers.saturating_sub(1);
        let mut close = state.watchers == 0;
        if envelope && let Some(count) = state.envelopes.get_mut(&session_id) {
            *count -= 1;
            if *count == 0 {
                state.envelopes.remove(&session_id);
                // Only the envelope leaving can turn agent edits into external ones.
                close |= state.envelopes.is_empty();
            }
        }
        if close {
            self.close_idle(root);
        }
        self.forget_if_unused(root);
    }

    /// Line `record_id` of `session_id` starts, touching the protected `roots` (FR-CKP-05, FR-CKP-07).
    ///
    /// In each root, an open agent-edit or external run is closed first: what changed before the line is not the
    /// line's. The line then joins the edge of the lines already running in any of its roots, merging those edges
    /// into one concurrent set, or starts a `command` edge of its own. A line already started is ignored.
    pub fn line_started(&mut self, record_id: RecordId, session_id: SessionId, roots: &[CanonicalPath]) {
        if self.lines.contains_key(&record_id) {
            return;
        }
        let mut roots = roots.to_vec();
        roots.sort();
        roots.dedup();
        for root in &roots {
            self.close_idle(root);
        }
        // The edges of the lines this one overlaps: the busy edge of each of its roots.
        let overlapped: BTreeSet<EdgeId> = roots
            .iter()
            .filter_map(|root| self.roots.get(root).and_then(|state| state.busy))
            .collect();
        let edge = match overlapped.first() {
            Some(&target) => {
                for &other in overlapped.iter().skip(1) {
                    self.merge(target, other);
                }
                target
            }
            None => self.new_edge(Attribution::Command, BTreeSet::new()),
        };
        if let Some(open) = self.open.get_mut(&edge) {
            open.edge.records.insert(record_id);
            open.edge.sessions.insert(session_id);
            open.running.insert(record_id);
            if open.edge.records.len() > 1 {
                open.edge.attribution = Attribution::Concurrent;
            }
        }
        for root in &roots {
            let state = self.roots.entry(root.clone()).or_default();
            state.running.insert(record_id);
            state.busy = Some(edge);
        }
        self.lines.insert(record_id, Line { edge, roots });
    }

    /// Line `record_id` has ended and every event of it has been applied (decision 16). Returns how it was
    /// attributed, final from now on (module documentation, "Invariants"); `None` for a line never started.
    ///
    /// Its edge closes once none of its lines runs any more.
    pub fn line_ended(&mut self, record_id: RecordId) -> Option<LineAttribution> {
        let line = self.lines.remove(&record_id)?;
        for root in &line.roots {
            if let Some(state) = self.roots.get_mut(root) {
                state.running.remove(&record_id);
                if state.running.is_empty() {
                    state.busy = None;
                }
            }
            self.forget_if_unused(root);
        }
        let open = self.open.get_mut(&line.edge)?;
        open.running.remove(&record_id);
        let attribution = LineAttribution {
            attribution: open.edge.attribution,
            edge: line.edge,
        };
        if open.running.is_empty() {
            self.close(line.edge);
        }
        Some(attribution)
    }

    /// `path` under `root` changed, and the root's shadow now follows it (the watcher's report). Attributed to the
    /// lines running in the root, else to an agent-edit run if an envelope watches it, else to an external run.
    /// Dropped when no line runs there and nothing watches the root any more (the last batch of a watcher stopped
    /// with its session): no session protects it, and an idle run opened now would never close.
    pub fn changed(&mut self, root: &CanonicalPath, path: &CanonicalPath) {
        let Some(edge) = self.edge_for_change(root) else {
            return;
        };
        let Some(open) = self.open.get_mut(&edge) else {
            return;
        };
        open.edge.add_path(root, path);
        if open.edge.attribution == Attribution::AgentEdit
            && let Some(state) = self.roots.get_mut(root)
        {
            state.pending.record(&open.edge.sessions, path);
        }
    }

    /// The agent edits of `root` not reported yet, for one `agent.edit` event (FR-CKP-06); `None` when there are
    /// none. Called after each batch the watcher applied.
    pub fn take_agent_edits(&mut self, root: &CanonicalPath) -> Option<AgentEdits> {
        let state = self.roots.get_mut(root)?;
        let pending = std::mem::take(&mut state.pending);
        self.forget_if_unused(root);
        if pending.is_empty() {
            return None;
        }
        Some(AgentEdits {
            root: root.clone(),
            sessions: pending.sessions,
            paths: pending.paths.into_iter().collect(),
            omitted: pending.omitted,
        })
    }

    /// Closes the agent-edit or external run of every root (for example before the history tree is written), so
    /// the next change starts a new edge.
    pub fn close_idle_runs(&mut self) {
        let roots: Vec<CanonicalPath> = self.roots.keys().cloned().collect();
        for root in &roots {
            self.close_idle(root);
            self.forget_if_unused(root);
        }
    }

    /// The edges closed since the last call, in the order they closed: what the history tree stores (KNSH-083).
    pub fn take_closed(&mut self) -> Vec<Edge> {
        std::mem::take(&mut self.closed)
    }

    /// The open edge of line `record_id`, while it runs: what it would be attributed if it ended now.
    #[must_use]
    pub fn running_edge(&self, record_id: RecordId) -> Option<&Edge> {
        let line = self.lines.get(&record_id)?;
        self.open.get(&line.edge).map(|open| &open.edge)
    }

    /// The open edge a change in `root` belongs to: the lines running there, else the root's idle run, else a new
    /// idle run, `agent_edit` of the envelopes watching the root or `external` when none does. `None` when no line
    /// runs there and nothing watches it.
    fn edge_for_change(&mut self, root: &CanonicalPath) -> Option<EdgeId> {
        let state = self.roots.get(root)?;
        if let Some(edge) = state.busy.or(state.idle) {
            return Some(edge);
        }
        if state.watchers == 0 {
            return None;
        }
        let sessions: BTreeSet<SessionId> = state.envelopes.keys().copied().collect();
        let attribution = if sessions.is_empty() {
            Attribution::External
        } else {
            Attribution::AgentEdit
        };
        let edge = self.new_edge(attribution, sessions);
        if let Some(state) = self.roots.get_mut(root) {
            state.idle = Some(edge);
        }
        Some(edge)
    }

    fn new_edge(&mut self, attribution: Attribution, sessions: BTreeSet<SessionId>) -> EdgeId {
        let id = EdgeId(self.next_edge);
        self.next_edge += 1;
        let mut edge = Edge::new(id, attribution);
        edge.sessions = sessions;
        self.open.insert(
            id,
            OpenEdge {
                edge,
                running: BTreeSet::new(),
            },
        );
        id
    }

    /// Merges the open line edge `other` into `target`: a line overlapped both. Every reference to `other` now
    /// names `target`.
    fn merge(&mut self, target: EdgeId, other: EdgeId) {
        let Some(absorbed) = self.open.remove(&other) else {
            return;
        };
        for line in self.lines.values_mut() {
            if line.edge == other {
                line.edge = target;
            }
        }
        for state in self.roots.values_mut() {
            if state.busy == Some(other) {
                state.busy = Some(target);
            }
        }
        if let Some(open) = self.open.get_mut(&target) {
            open.running.extend(absorbed.running);
            open.edge.absorb(absorbed.edge);
            open.edge.attribution = Attribution::Concurrent;
        }
    }

    /// Closes the open agent-edit or external run of `root`, if any.
    fn close_idle(&mut self, root: &CanonicalPath) {
        let idle = self.roots.get_mut(root).and_then(|state| state.idle.take());
        if let Some(edge) = idle {
            self.close(edge);
        }
    }

    fn close(&mut self, edge: EdgeId) {
        if let Some(open) = self.open.remove(&edge) {
            self.closed.push(open.edge);
        }
    }

    fn forget_if_unused(&mut self, root: &CanonicalPath) {
        if self.roots.get(root).is_some_and(Root::is_unused) {
            self.roots.remove(root);
        }
    }
}

#[cfg(test)]
mod tests;
