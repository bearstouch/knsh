# KNSH-043 — `policy.check` dry run

[Phase 2](README.md#phase-2--contain-and-decide) · [Story index and plan](README.md)

| Phase | Epic | Size | Depends on | Crates | Requirements |
| --- | --- | --- | --- | --- | --- |
| 2 | Policy | S (2) | [KNSH-014](KNSH-014-hello-handshake-method-catalogue-and-capability-probe-v1.md), [KNSH-041](KNSH-041-line-verdicts-dynamic-code-limits-fixed-denies-and-the.md) | `knsh-proto`, `knshd` | FR-POL-70 |

**Description.** As an agent or user, I want to ask what policy would decide for a line without running it, so that
approval fatigue drops and agents can plan. Scope: `policy.check` on `agent.sock` (caller's session profile) and
`user.sock` (named session or profile); returns verdict, matched rules, classes and dynamic reasons. Hooks and the
authority are not consulted.

**Acceptance criteria**
- [x] Result includes `verdict`, `rule_id`s, per-command classes and `dynamic` reasons.
- [x] No record is written, no event is emitted and no process is spawned (verified by fakes).
- [x] Listed in `hello` methods on both sockets.
- [x] Malformed params → JSON-RPC invalid params; never a partial answer.

**Unit tests**
- `policy_check_returns_ask_for_git_push`.
- `policy_check_spawns_nothing_and_writes_no_record`.
- `policy_check_reports_dynamic_reason`.
