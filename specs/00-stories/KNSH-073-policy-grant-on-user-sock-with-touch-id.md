# KNSH-073 — `policy.grant` on `user.sock` with Touch ID

[Phase 2](README.md#phase-2--contain-and-decide) · [Story index and plan](README.md)

| Phase | Epic | Size | Depends on | Crates | Requirements |
| --- | --- | --- | --- | --- | --- |
| 2 | Authority | S (2) | [KNSH-042](KNSH-042-grants.md), [KNSH-064](KNSH-064-localauthentication-service-touch-id-or-password.md) | `knshd` | FR-POL-62, NFR-SEC-04, [user socket](../06-api/user-socket.md) |

**Description.** As a user without an authority app, I want to create a grant from the CLI with Touch ID, so that I
can allow a repeated action for a limited time.

**Acceptance criteria**
- [ ] `policy.grant` on `user.sock` creates a grant only after the `knshd` prompt shows the rule, scope and
      duration, and authentication passes.
- [ ] Grants created this way are listed and revocable like authority grants.
- [ ] `policy.grant` is not available on `agent.sock`.

**Unit tests**
- `user_grant_requires_authentication` — FR-POL-62.
- `user_grant_absent_on_agent_socket` — FR-POL-62.

**Notes**
- [CLI](../06-api/cli.md) lists no `knsh` command for grants. Propose `knsh policy grant`.
