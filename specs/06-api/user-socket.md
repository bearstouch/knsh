# `user.sock`

Reachable by the user's processes outside envelopes. Every envelope and command profile denies it.

| Method | Purpose |
| --- | --- |
| `session.start_agent`, `session.list`, `session.end` | Start and manage agent sessions (`knsh agent`) |
| `records.query`, `records.output`, `events.subscribe` | Read-only access to all sessions, for observers and the CLI |
| `checkpoint.*` | All checkpoint operations, including `restore` and `force` |
| `approval.list`, `approval.approve`, `approval.deny` | Pending asks; approving needs Touch ID or password, checked by `knshd` |
| `policy.check`, `policy.edit`, `profile.use`, `policy.grant` | Policy changes and grants need Touch ID or password |
| `records.forget` | Delete records, optionally with checkpoints (`knsh forget`) |

## Authentication

- `approval.approve`, `policy.edit`, `profile.use` and `policy.grant` require Touch ID or the user's password. `knshd` shows the system authentication prompt itself, with the exact command or change in it.
- The caller cannot claim that the user is present; no parameter skips the prompt.
- `knsh authority trust` also requires Touch ID or password inside `knshd`.
