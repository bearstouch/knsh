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
- [x] `restore` to a state undoes every later change, applying the same identity check per path; any conflict returns
      `-32004` with the paths and changes nothing.
- [x] `restore` is available only to user and authority callers.
- [x] `diff` lists created, modified and deleted paths between two states.
- [x] Per-file contents travel as binary chunks with an opening JSON message (ID, size, content type) and an
      end-of-stream frame; clients without binary support receive base64.
- [x] Binary files are reported as changed without a text diff.

**Unit tests**
- `restore_to_state_undoes_all_later_changes`
- `restore_conflict_changes_nothing`
- `diff_lists_created_modified_deleted_paths`
- `diff_streams_file_contents_as_binary_chunks`
- `diff_falls_back_to_base64_for_clients_without_binary_frames`

**Notes (implementation, KNSH-086)**
- `knsh-core`: `HistoryTree::route` and `has_state`, `StateId::new`, `HistoryError::UnknownState`; the diff model
  (`DiffTarget`, `FileDiff`, `EntryKind`, `NoTextDiff`) and a bounded Myers unified diff (`unified`).
- `knsh-checkpoint`: `History::restore_state` (whole-way check, steps through undo and redo, take-back on failure),
  `History::diff` (versions at a state, pages); a rolled-back restore refreshes its checkpoint's post-images (same
  inode and contents only) so it can be retried.
- `knsh-platform`: `Volumes::read_regular` (no final symlink, regular files only); `PlatformShadowFiles::read_file`
  now uses it, as the `ShadowFiles` contract always said.
- `knsh-proto`: `CheckpointRestoreParams`/`Result`, `CheckpointDiffParams`, `diff_answer` (streams or base64).
- Extra tests: `restore_reaches_a_state_on_another_branch`, `restore_failure_part_way_takes_back_earlier_steps`,
  `restore_skips_possibly_torn_paths_without_force`, `live_file_swapped_for_a_symlink_is_not_followed`,
  `agent_sees_only_its_own_changes`, `base64_answer_ends_before_the_budget`.
- **Pending:** wiring the methods into `knshd`'s endpoints, agent-socket scoping and the CLI (KNSH-088); redaction of
  diff contents (KNSH-090).
- **Verified:** fmt, build `--locked`, clippy `-D warnings`, doc `-D warnings`, normal suite (`--lib --bins`: 1,743
  passed; the known `knshd` hook-timeout flake failed once under load and passed 3/3 alone). The `knsh-checkpoint`
  integration targets (`undo_macos`, `shadow_macos`, `watch_macos`) passed before the review fixes. **Pending:** the
  full suite after the review fixes (run on request).
