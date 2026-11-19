# KNSH-083 — History tree

[Phase 3](README.md#phase-3--reverse-and-protect) · [Story index and plan](README.md)

| Phase | Epic | Size | Depends on | Crates | Requirements |
| --- | --- | --- | --- | --- | --- |
| 3 | Checkpoints | M (3) | [KNSH-002](KNSH-002-core-value-types-ulids-canonical-paths-redacted-text.md) | `knsh-core` | FR-CKP-30, history tree in [checkpoints](../03-functional-requirements/checkpoints.md) |

**Description.** As the checkpoint engine, I want a pure model of states and edges, like commits, so that undo,
redo and restore are computed without I/O. Scope: states, edges (line, agent edit, concurrent set), undo as moving
back along an edge while keeping the branch, redo, the "older change only if no later change touched the same paths"
rule, and persistence format. Out of scope: file operations.

**Acceptance criteria**
- [x] Undo of an edge moves to its parent state and keeps the abandoned branch reachable for redo.
- [x] Undo of an older change is allowed only if no later change touched the same paths; otherwise the result lists
      the conflicting paths (FR-CKP-30).
- [x] Redo restores the versions saved by the matching undo.
- [x] A new change after an undo creates a new branch; old branches stay until retention removes them.
- [x] The model is a pure function library with no I/O, serialisable with a version field.

**Unit tests**
- `undo_moves_to_parent_and_keeps_branch`
- `redo_after_undo_returns_to_child_state`
- `undo_of_older_change_conflicts_when_later_change_touched_path` (FR-CKP-30)
- `undo_of_older_change_succeeds_on_disjoint_paths` (FR-CKP-30)
- `new_change_after_undo_starts_new_branch`
- `serialised_tree_round_trips`

**Implementation (KNSH-083).** `knsh_core::HistoryTree` (`crates/knsh-core/src/history.rs`), pure and without I/O:

- **States and edges.** `StateId` numbers states in increasing order, never reused. `HistoryTree::record(Change)` adds a
  closed edge (`command`, `concurrent`, `agent_edit` or `external`, with its records, sessions, paths and overflow
  flag) from the head; when the head already has children, the new edge starts another branch. Edges are identified
  by their `CheckpointId`; `edge_for_record` finds a line's edge (the whole set for a concurrent line).
- **Plan, then commit.** `plan_undo` and `plan_redo` change nothing and return a `Plan` (`StepBack`, `StepForward` or
  `Revert`) naming the checkpoint whose versions to restore; `commit(plan, saved)` records it after the restore
  (KNSH-084), with the checkpoint of the versions saved before an undo. A plan made before any later change of the tree
  is `Stale`, so the tree never records a restore that did not happen.
- **Undo.** The latest edge in effect: step back to its parent, keeping the edge and the versions saved on it for
  redo. An older edge: allowed only if no later edge on the head's path touched one of its paths, otherwise
  `Conflict` lists them (FR-CKP-30); an overflowed path list on either side conflicts with any later edge (fail
  closed). An allowed older undo becomes an `undo` edge from the head to a new state, like `git revert`.
- **Redo.** Step forward over an edge the head stepped back from, restoring the saved versions; only from its parent
  state (`RedoBlocked` once a new change started another branch: that is `checkpoint.restore`, KNSH-086). Redo of a
  reverted edge is the undo of its `undo` edge, under the same conflict rule.
- **Persistence.** `encode`/`decode`: one strict JSON object with `format: 1`, edges parents first. Decode checks
  size (256 MiB), closed objects, and every tree invariant (known parent, one parent per state, `from < to`, unique
  checkpoints, records and saved versions, `undo` edges after the edge they undid, head is a state); a newer format
  is `NewerFormat` so the caller leaves the file as found.

**Pending:** feeding the attribution ledger's closed edges and their checkpoints into the tree and writing it to disk
atomically in `knshd` (with undo and redo, KNSH-084, and the endpoints, KNSH-088); removing old branches and states by
retention (KNSH-087); `checkpoint.restore` to a state (KNSH-086).
