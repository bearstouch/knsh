# KNSH-088 — Checkpoint API and CLI

[Phase 3](README.md#phase-3--reverse-and-protect) · [Story index and plan](README.md)

| Phase | Epic | Size | Depends on | Crates | Requirements |
| --- | --- | --- | --- | --- | --- |
| 3 | Checkpoints | M (3) | [KNSH-048](KNSH-048-agent-sock-endpoint-session-tokens-and-audit-token-fallback.md), [KNSH-084](KNSH-084-undo-and-redo.md), [KNSH-086](KNSH-086-checkpoint-restore-and-checkpoint-diff.md) | `knshd`, `knsh-proto`, `knsh` | FR-CKP-21, API endpoint tables |

**Description.** As an agent, user or authority, I want the checkpoint operations on the right endpoints with the
right scope, so that agents can undo their own changes but never force or restore. Scope: `checkpoint.list`,
`diff`, `undo`, `redo` on `agent.sock` (own session, no `force`); all `checkpoint.*` including `restore` and `force`
on `user.sock` and the control service; `knsh undo`, `knsh redo`, `knsh checkpoints` with `--json`.

**Acceptance criteria**
- [ ] On `agent.sock`, checkpoint methods see only the caller's session; other sessions return `-32003`.
- [ ] `force` and `checkpoint.restore` are rejected on `agent.sock` (FR-CKP-21).
- [ ] `user.sock` and the control service can use every checkpoint method across sessions.
- [ ] `knsh undo`, `knsh redo` and `knsh checkpoints` call `user.sock` and support `--json`.
- [ ] The method catalogue in `hello` lists checkpoint methods only when the capability is available; otherwise
      calls return `-32005`.

**Unit tests**
- `agent_socket_rejects_force` (FR-CKP-21)
- `agent_socket_rejects_restore` (FR-CKP-21)
- `agent_socket_cannot_see_other_sessions_checkpoints`
- `unavailable_checkpoint_capability_returns_minus_32005`
- `cli_undo_json_output_matches_api_result`
