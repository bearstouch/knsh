# KNSH-086 — `checkpoint.restore` and `checkpoint.diff`

[Phase 3](README.md#phase-3--reverse-and-protect) · [Story index and plan](README.md)

| Phase | Epic | Size | Depends on | Crates | Requirements |
| --- | --- | --- | --- | --- | --- |
| 3 | Checkpoints | L (5) | [KNSH-004](KNSH-004-frame-codec-and-binary-streams.md), [KNSH-084](KNSH-084-undo-and-redo.md) | `knsh-checkpoint`, `knsh-proto` | FR-CKP-20, history tree operations |

**Description.** As a user or authority, I want to return every root to an earlier state at once and to see per-file
diffs between states, so that I can recover from a run of bad changes and review what an agent did. Scope:
`restore {state_id}` (undo all later changes, same identity rules), `diff {record_id | state_id}` with path lists and
per-file diffs streamed as binary chunks. Out of scope: endpoint permissions (KNSH-088).

**Acceptance criteria**
- [ ] `restore` to a state undoes every later change, applying the same identity check per path; any conflict returns
      `-32004` with the paths and changes nothing.
- [ ] `restore` is available only to user and authority callers.
- [ ] `diff` lists created, modified and deleted paths between two states.
- [ ] Per-file contents travel as binary chunks with an opening JSON message (ID, size, content type) and an
      end-of-stream frame; clients without binary support receive base64.
- [ ] Binary files are reported as changed without a text diff.

**Unit tests**
- `restore_to_state_undoes_all_later_changes`
- `restore_conflict_changes_nothing`
- `diff_lists_created_modified_deleted_paths`
- `diff_streams_file_contents_as_binary_chunks`
- `diff_falls_back_to_base64_for_clients_without_binary_frames`
