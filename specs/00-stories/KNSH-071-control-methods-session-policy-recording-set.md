# KNSH-071 — Control methods: `session.*`, `policy.*`, `recording.set`

[Phase 2](README.md#phase-2--contain-and-decide) · [Story index and plan](README.md)

| Phase | Epic | Size | Depends on | Crates | Requirements |
| --- | --- | --- | --- | --- | --- |
| 2 | Authority | L (5) | [KNSH-042](KNSH-042-grants.md), [KNSH-054](KNSH-054-pause-resume-and-human-control.md), [KNSH-068](KNSH-068-knsh-authority-trust-and-authority-registration.md) | `knshd`, `knsh-proto` | FR-SES-02, FR-POL-01, FR-POL-50, FR-POL-53, FR-POL-60 – FR-POL-62, [control service](../06-api/control-service.md) |

**Description.** As an authority, I want to manage sessions, push policy, manage grants and change recording, so
that I can supervise agents end to end.

**Acceptance criteria**
- [ ] The `session.*` methods create, end, pause, resume, take control and release control of any session.
- [ ] `policy.set` accepts a snapshot only with `expires_at`, validates it with the same loader as files, and emits
      `policy.updated`.
- [ ] `policy.get`, `policy.grant`, `policy.grants` and `policy.revoke` behave as specified. Grants have an ID, a
      scope and an `expires_at`.
- [ ] `recording.set` toggles command or output recording for a session, and `session.info` reflects it.
- [ ] Every `user.sock` read and checkpoint method is available on the control service across all sessions.
- [ ] Pushed policy and grants are persisted in the state store (atomic replace, owner-only).

**Unit tests**
- `policy_set_requires_expires_at` — FR-POL-50.
- `policy_set_emits_policy_updated` — FR-POL-53.
- `grant_revoke_removes_grant` — FR-POL-61.
- `recording_set_updates_session_info` — FR-SES-25.
- `pause_via_control_matches_user_pause` — FR-SES-10.

**Notes**
- Spec gap: the individual `session.*` method names on the control service are not listed (for example
  `session.pause`, `session.take_control`). Name them in [control service](../06-api/control-service.md).
