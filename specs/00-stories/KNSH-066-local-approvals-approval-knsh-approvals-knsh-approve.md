# KNSH-066 — Local approvals: `approval.*`, `knsh approvals`, `knsh approve`

[Phase 2](README.md#phase-2--contain-and-decide) · [Story index and plan](README.md)

| Phase | Epic | Size | Depends on | Crates | Requirements |
| --- | --- | --- | --- | --- | --- |
| 2 | Authority | M (3) | [KNSH-050](KNSH-050-supervisor-lifecycle-orchestrator.md), [KNSH-064](KNSH-064-localauthentication-service-touch-id-or-password.md) | `knshd`, `knsh` | FR-AUTH-40 – FR-AUTH-43, [user socket](../06-api/user-socket.md), [reliability](../04-non-functional-requirements/reliability.md) |

**Description.** As a user without an authority app, I want to list and approve pending asks from my terminal with
Touch ID, so that agents can still be unblocked safely.

**Acceptance criteria**
- [x] `approval.list` on `user.sock` returns pending asks with request ID, session, redacted command, matched rule,
      irreversibility and `timeout_at`. `knsh approvals` prints them. *(`irreversible` is `null` until lines are
      classified for it, KNSH-093.)*
- [x] `approval.approve` (`knsh approve <request_id>`) succeeds only after the `knshd` prompt shows the exact command
      and authentication passes. *(Observed with the scripted prompt in `knshd`'s tests; the real Touch ID or
      password prompt from an installed `knshd` is pending a manual run.)*
- [x] `approval.deny` denies the pending ask.
- [x] An approval for a request that has already timed out or been cancelled is refused.
- [x] No yes/no prompt ever appears in the agent session's own terminal. *(By construction: the methods are on
      `user.sock` only, `-32003` if dispatched on `agent.sock`, and the only prompt is `knshd`'s system dialog.)*
- [x] Approvals and denials are recorded with `decision.source = user`.

**Unit tests**
- `lists_pending_requests` — FR-AUTH-40 (`knshd`, `approvals`).
- `approve_requires_authentication` — FR-AUTH-41 (`knshd`, `approvals`).
- `approve_of_expired_request_refused` — FR-AUTH-22 (`knshd`, `approvals`).
- `records_user_as_decision_source` — FR-REC-03 (`knshd`, `supervisor`).

**Integration tests**
- **Pending (manual):** `knsh approve` against an installed `knshd` with an agent line waiting: the Touch ID or
  password prompt names the command, a cancelled prompt leaves the ask pending, and a successful one runs the line.

**Notes**
- Spec gap: whether `approval.deny` also needs authentication is not specified. Propose no, since denying is never
  less safe.
- Spec gap, resolved ([user socket](../06-api/user-socket.md#approvals), [CLI](../06-api/cli.md#approvals)):
  `approval.deny` needs no authentication, and `knsh deny <request_id>` is added to the CLI. An answer to a request
  that has ended is `-32002` (timed out), `-32011` (cancelled) or `-32602` (already answered or unknown).
- Implemented: `knsh-proto` `approval` (params and results); `knshd` `approvals::Approvals`, the `LocalApprovals`
  behind the orchestrator (replacing the deny-at-timeout placeholder) and the three `user.sock` handlers; `knsh`
  `knsh approvals`, `knsh approve`, `knsh deny`. Asks waiting without an authority now carry a request ID in
  `-32002`, `-32011` and `decision.cancelled`.
