# KNSH-074 — Fail-closed operation and state across restarts

[Phase 2](README.md#phase-2--contain-and-decide) · [Story index and plan](README.md)

| Phase | Epic | Size | Depends on | Crates | Requirements |
| --- | --- | --- | --- | --- | --- |
| 2 | Reliability | M (3) | [KNSH-042](KNSH-042-grants.md), [KNSH-050](KNSH-050-supervisor-lifecycle-orchestrator.md), [KNSH-071](KNSH-071-control-methods-session-policy-recording-set.md) | `knshd`, `knsh` | NFR-REL-01, NFR-REL-03, NFR-REL-06, NFR-REL-08, NFR-REL-09, [reliability](../04-non-functional-requirements/reliability.md) |

**Description.** As a user, I want agents blocked, not unleashed, whenever any part of the engine is missing, so that
a crash never becomes a bypass.

**Acceptance criteria**
- [ ] With `knshd` stopped, `knsh -c` inside an envelope runs nothing, and envelope network fails because the proxy
      is gone.
- [ ] With `knshd` stopped, human sessions keep working and telemetry is dropped.
- [ ] launchd restarts `knshd` after a crash while envelopes exist. Grants and pushed policy are restored from the
      state store, and authority-supplied state that is memory-only is not.
- [ ] A corrupt or newer state file triggers recovery and is never overwritten.
- [ ] The engine works fully without an authority: local profiles apply, and asks are approved locally or denied at
      the timeout.

**Unit tests**
- `restores_grants_after_restart` — NFR-REL-06.
- `restores_pushed_policy_after_restart` — NFR-REL-06.
- `corrupt_state_file_is_not_overwritten` — persistence rules.
- `asks_denied_at_timeout_without_authority` — NFR-REL-09.

**Integration tests**
- Kill `knshd` during an agent session. A new `knsh -c` fails without running anything, and after the restart the
  next line runs normally.
