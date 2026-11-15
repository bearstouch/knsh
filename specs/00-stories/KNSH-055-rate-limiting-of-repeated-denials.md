# KNSH-055 — Rate limiting of repeated denials

[Phase 2](README.md#phase-2--contain-and-decide) · [Story index and plan](README.md)

| Phase | Epic | Size | Depends on | Crates | Requirements |
| --- | --- | --- | --- | --- | --- |
| 2 | Supervisor | S (2) | [KNSH-050](KNSH-050-supervisor-lifecycle-orchestrator.md) | `knsh-core` | FR-HOOK-20, FR-HOOK-21 |

**Description.** As the authority, I want a looping agent's repeated denied line to stop reaching me, so that I am
not flooded with asks.

**Acceptance criteria**
- [x] When the same normalised line is denied **5 times within 60 s** in one session, further attempts are denied
      without asking anyone for **10 minutes**, with `decision.source = rate_limit`.
- [x] `command.denied_repeatedly` is emitted once when limiting starts, not on every later denial.
- [x] The limit is per session. Other sessions are unaffected.
- [x] Limited attempts still produce records (FR-REC-03).
- [x] Time comes from the injected clock.

**Unit tests**
- `limits_after_five_denials_within_sixty_seconds` — FR-HOOK-20.
- `does_not_limit_when_denials_spread_over_sixty_seconds` — FR-HOOK-20.
- `lifts_limit_after_ten_minutes` — FR-HOOK-20.
- `emits_denied_repeatedly_once` — FR-HOOK-21.
- `limits_are_per_session` — FR-HOOK-20.

**Notes**
- Spec gap closed in [hooks.md](../03-functional-requirements/hooks.md#rate-limiting): the normalised line is the
  re-serialised line with resolved paths (KNSH-038). Subcommand options are deliberately not merged, so one denied
  line never limits a different one.
