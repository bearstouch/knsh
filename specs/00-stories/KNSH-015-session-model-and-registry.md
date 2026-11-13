# KNSH-015 — Session model and registry

[Phase 1](README.md#phase-1--observe-advisory) · [Story index and plan](README.md)

| Phase | Epic | Size | Depends on | Crates | Requirements |
| --- | --- | --- | --- | --- | --- |
| 1 | Sessions | M (3) | [KNSH-002](KNSH-002-core-value-types-ulids-canonical-paths-redacted-text.md) | `knsh-core` | FR-SES-01, FR-SES-03, FR-SES-04, FR-SES-14, [session](../05-models/session.md) |

**Description.** As the engine, I want a pure session model with the fields and state machine from the spec, so that
every later feature attaches to sessions consistently. Phase 1 creates human sessions; agent creation arrives in
phase 2, but the model already holds `actor.kind = agent`, `envelope`, `profile` and `parent_session_id`.

**Acceptance criteria**
- [ ] Fields: `session_id` (ULID), `actor.kind`, `actor.agent_id` (required for agents, absent for humans),
      `profile`, `envelope`, `recording`, `parent_session_id`, `state`.
- [ ] The actor is fixed at creation; no API changes it.
- [ ] Defaults: `recording = false` for humans, `true` for agents (FR-SES-04).
- [ ] State transitions exactly as in [sessions](../03-functional-requirements/sessions.md#states); invalid
      transitions return an error and leave state unchanged; every change produces a `session.state_changed` event
      value.
- [ ] A child session records `parent_session_id`; for agent children the profile must equal or be stricter than
      the parent's (enforced in phase 2; the hook point exists).
- [ ] Ended sessions answer lookups with "not found or ended" (maps to `-32006`).

**Unit tests**
- `actor_is_immutable_after_creation` — FR-SES-01.
- `agent_requires_agent_id` — model validity.
- `human_recording_defaults_off_agent_on` — FR-SES-04.
- `invalid_transition_keeps_state` — failure safety.
- `every_transition_emits_state_changed` — FR-SES-14.
- `ended_session_lookup_is_not_found` — `-32006`.
