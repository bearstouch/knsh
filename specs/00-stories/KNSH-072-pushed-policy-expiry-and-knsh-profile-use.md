# KNSH-072 — Pushed-policy expiry and `knsh profile use`

[Phase 2](README.md#phase-2--contain-and-decide) · [Story index and plan](README.md)

| Phase | Epic | Size | Depends on | Crates | Requirements |
| --- | --- | --- | --- | --- | --- |
| 2 | Authority | M (3) | [KNSH-065](KNSH-065-policy-file-signing-and-knsh-policy-edit.md), [KNSH-071](KNSH-071-control-methods-session-policy-recording-set.md) | `knshd`, `knsh` | FR-POL-51, FR-POL-52, FR-SES-13 |

**Description.** As a user, I want sessions on expired pushed policy paused until I act, so that the engine never
silently falls back to another policy.

**Acceptance criteria**
- [ ] When a snapshot's `expires_at` passes, every agent session using it is paused (`session.state_changed`).
- [ ] The session resumes when the authority pushes a valid snapshot, or when the user runs `knsh profile use <name>`
      and authenticates with Touch ID.
- [ ] `knsh profile use` accepts only signed local profiles.
- [ ] No code path switches a session's policy without one of these two events.

**Unit tests**
- `pauses_sessions_on_snapshot_expiry` — FR-POL-51 (fake clock).
- `resumes_on_new_snapshot` — FR-POL-51.
- `profile_use_requires_authentication` — FR-POL-51.
- `never_falls_back_silently` — FR-POL-52.
