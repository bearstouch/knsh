# KNSH-066 — Local approvals: `approval.*`, `knsh approvals`, `knsh approve`

[Phase 2](README.md#phase-2--contain-and-decide) · [Story index and plan](README.md)

| Phase | Epic | Size | Depends on | Crates | Requirements |
| --- | --- | --- | --- | --- | --- |
| 2 | Authority | M (3) | [KNSH-050](KNSH-050-supervisor-lifecycle-orchestrator.md), [KNSH-064](KNSH-064-localauthentication-service-touch-id-or-password.md) | `knshd`, `knsh` | FR-AUTH-40 – FR-AUTH-43, [user socket](../06-api/user-socket.md), [reliability](../04-non-functional-requirements/reliability.md) |

**Description.** As a user without an authority app, I want to list and approve pending asks from my terminal with
Touch ID, so that agents can still be unblocked safely.

**Acceptance criteria**
- [ ] `approval.list` on `user.sock` returns pending asks with request ID, session, redacted command, matched rule,
      irreversibility and `timeout_at`. `knsh approvals` prints them.
- [ ] `approval.approve` (`knsh approve <request_id>`) succeeds only after the `knshd` prompt shows the exact command
      and authentication passes.
- [ ] `approval.deny` denies the pending ask.
- [ ] An approval for a request that has already timed out or been cancelled is refused.
- [ ] No yes/no prompt ever appears in the agent session's own terminal.
- [ ] Approvals and denials are recorded with `decision.source = user`.

**Unit tests**
- `lists_pending_requests` — FR-AUTH-40.
- `approve_requires_authentication` — FR-AUTH-41.
- `approve_of_expired_request_refused` — FR-AUTH-22.
- `records_user_as_decision_source` — FR-REC-03.

**Notes**
- Spec gap: whether `approval.deny` also needs authentication is not specified. Propose no, since denying is never
  less safe.
