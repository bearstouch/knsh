# KNSH-088 — Checkpoint API and CLI

[Phase 3](README.md#phase-3--reverse-and-protect) · [Story index and plan](README.md)

| Phase | Epic | Size | Depends on | Crates | Requirements |
| --- | --- | --- | --- | --- | --- |
| 3 | Checkpoints | M (3) | [KNSH-048](KNSH-048-agent-sock-endpoint-session-tokens-and-audit-token-fallback.md), [KNSH-084](KNSH-084-undo-and-redo.md), [KNSH-086](KNSH-086-checkpoint-restore-and-checkpoint-diff.md) | `knshd`, `knsh-proto`, `knsh` | FR-CKP-21, API endpoint tables |

**Description.** As an agent, user or authority, I want the checkpoint operations on the right endpoints with the
right scope, so that agents can undo their own changes but never force or restore. Scope: `checkpoint.list`,
`diff`, `undo`, `redo` on `agent.sock` (own session, no `force`); all `checkpoint.*` including `restore` and `force`
on `user.sock` and the control service; `knsh undo`, `knsh redo`, `knsh checkpoints` with `--json`.
Also wires KNSH-087 into `knshd`: run `History::retain` at start and whenever its `next_due` comes (so sensitive
pre-images never outlive 24 hours), and pass `records.forget`'s `with_checkpoints` to `History::forget` instead of
answering `-32005`.

**Acceptance criteria**
- [x] On `agent.sock`, checkpoint methods see only the caller's session; other sessions return `-32003`.
      Observed in `knshd` unit tests: `checkpoint.list` lists only the caller's changes and refuses another session
      filter; undo, redo and diff of another session's line, or of an external edit, are `-32003`.
- [x] `force` and `checkpoint.restore` are rejected on `agent.sock` (FR-CKP-21). `force` is `-32003` before the change
      is even looked up; `checkpoint.restore` is not served there (`-32003` from the catalogue, and from the handler).
- [x] `user.sock` and the control service can use every checkpoint method across sessions (unit tests call each
      handler as the user and as the authority).
- [x] `knsh undo`, `knsh redo` and `knsh checkpoints` call `user.sock` and support `--json` (CLI unit tests over a
      scripted connection; not yet run against a live `knshd`: pending manual check).
- [x] The method catalogue in `hello` lists checkpoint methods only when the capability is available; otherwise
      calls return `-32005`. The capability is `checkpoints`, present when `file_events` is (the per-root report is
      live and never decides the method list).

**Also wired (KNSH-087).** `knshd` records each finished checkpoint in one in-memory `History`; a retention thread
sweeps at start, when `next_due` comes and after new checkpoints arrive; `records.forget` with `with_checkpoints`
calls `History::forget` before deleting records; `recover_restores` runs on the home store at start. The engine's own
restores are bracketed so their writes are never recorded as a change (`Ledger::restore_started`,
`RestoreWindows`). `checkpoint.diff` answers carry one binary stream per file.

**Pending.** The history is not written to disk (a restarted `knshd` starts empty); recovering restore journals in
stores on other volumes; showing `possibly_torn` in `checkpoint.list` and records; diff by state on `agent.sock` still
reports an unknown or expired state before authorizing; full suite and a live end-to-end run.

**Unit tests**
- `agent_socket_rejects_force` (FR-CKP-21)
- `agent_socket_rejects_restore` (FR-CKP-21)
- `agent_socket_cannot_see_other_sessions_checkpoints`
- `unavailable_checkpoint_capability_returns_minus_32005`
- `cli_undo_json_output_matches_api_result`
- `user_undoes_and_redoes_any_sessions_change_inside_a_window`, `conflicting_undo_is_minus_32004_with_the_path`,
  `changes_reported_as_a_window_opens_are_recorded_first`, `forget_removes_a_sessions_checkpoints_at_once`,
  `retention_sweep_removes_old_changes_and_schedules_the_next`, `diff_streams_each_file_after_the_answer`,
  `user_restores_a_state`, `list_pages_with_a_cursor` (`knshd`)
- `a_restore_window_keeps_the_engines_writes_out_of_every_edge` (`knshd` shadows),
  `changes_while_the_engine_restores_belong_to_no_edge`, `a_line_overlapping_a_restore_is_reported_as_missing_changes`
  (ledger)
- `with_checkpoints_forgets_the_matching_checkpoints_too` (FR-CKP-34)
- `checkpoint_methods_follow_the_checkpoint_capability`, `undo_params_take_exactly_one_target`,
  `history_refusals_map_to_api_errors` (`knsh-proto`)
