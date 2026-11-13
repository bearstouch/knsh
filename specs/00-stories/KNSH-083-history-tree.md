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
- [ ] Undo of an edge moves to its parent state and keeps the abandoned branch reachable for redo.
- [ ] Undo of an older change is allowed only if no later change touched the same paths; otherwise the result lists
      the conflicting paths (FR-CKP-30).
- [ ] Redo restores the versions saved by the matching undo.
- [ ] A new change after an undo creates a new branch; old branches stay until retention removes them.
- [ ] The model is a pure function library with no I/O, serialisable with a version field.

**Unit tests**
- `undo_moves_to_parent_and_keeps_branch`
- `redo_after_undo_returns_to_child_state`
- `undo_of_older_change_conflicts_when_later_change_touched_path` (FR-CKP-30)
- `undo_of_older_change_succeeds_on_disjoint_paths` (FR-CKP-30)
- `new_change_after_undo_starts_new_branch`
- `serialised_tree_round_trips`
