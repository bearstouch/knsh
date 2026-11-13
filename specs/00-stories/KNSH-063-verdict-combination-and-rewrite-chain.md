# KNSH-063 — Verdict combination and rewrite chain

[Phase 2](README.md#phase-2--contain-and-decide) · [Story index and plan](README.md)

| Phase | Epic | Size | Depends on | Crates | Requirements |
| --- | --- | --- | --- | --- | --- |
| 2 | Hooks | M (3) | [KNSH-062](KNSH-062-hook-configuration-and-runner.md) | `knsh-core` | FR-HOOK-10 – FR-HOOK-13 |

**Description.** As the engine, I want hook and policy verdicts combined in one well-defined way, so that the most
restrictive answer always wins.

**Acceptance criteria**
- [ ] Hooks run in declared order, and the first `deny` stops the chain.
- [ ] A `rewrite` replaces the line for later hooks and for policy.
- [ ] `annotate` adds labels to the record without affecting the verdict.
- [ ] The final verdict is the most restrictive of all hook verdicts and policy: deny, then ask, then allow.
- [ ] A rewrite applies only when the final verdict is not deny.

**Unit tests**
- `first_deny_stops_chain` — FR-HOOK-10.
- `later_hooks_see_rewritten_line` — FR-HOOK-10.
- `policy_evaluates_rewritten_line` — FR-HOOK-11.
- `final_verdict_is_most_restrictive` — FR-HOOK-12.
- `rewrite_discarded_when_final_verdict_deny` — FR-HOOK-13.
- `annotate_does_not_change_verdict` — hook model.
