# KNSH-063 — Verdict combination and rewrite chain

[Phase 2](README.md#phase-2--contain-and-decide) · [Story index and plan](README.md)

| Phase | Epic | Size | Depends on | Crates | Requirements |
| --- | --- | --- | --- | --- | --- |
| 2 | Hooks | M (3) | [KNSH-062](KNSH-062-hook-configuration-and-runner.md) | `knsh-core` | FR-HOOK-10 – FR-HOOK-13 |

**Description.** As the engine, I want hook and policy verdicts combined in one well-defined way, so that the most
restrictive answer always wins.

**Acceptance criteria**
- [x] Hooks run in declared order, and the first `deny` stops the chain.
- [x] A `rewrite` replaces the line for later hooks and for policy.
- [x] `annotate` adds labels to the record without affecting the verdict.
- [x] The final verdict is the most restrictive of all hook verdicts and policy: deny, then ask, then allow.
- [x] A rewrite applies only when the final verdict is not deny.

**Unit tests**
- `first_deny_stops_chain` — FR-HOOK-10.
- `later_hooks_see_rewritten_line` — FR-HOOK-10.
- `policy_evaluates_rewritten_line` — FR-HOOK-11.
- `final_verdict_is_most_restrictive` — FR-HOOK-12.
- `rewrite_discarded_when_final_verdict_deny` — FR-HOOK-13.
- `annotate_does_not_change_verdict` — hook model.

**Notes**
- Most of the behaviour landed with the pipeline ([KNSH-050](KNSH-050-supervisor-lifecycle-orchestrator.md)) and the
  chain ([KNSH-062](KNSH-062-hook-configuration-and-runner.md)). This story makes the ordering one explicit rule
  (`knsh-core` `lifecycle::combine`: `Strictness`, `most_restrictive`), used by step 5 of the pipeline, and adds the
  tests above (`hook/tests.rs` for the chain, `lifecycle/tests.rs` for the pipeline).
- Spec gap, resolved: the finer rules are written down in
  [hooks](../03-functional-requirements/hooks.md#combining-verdicts): a rewrite ends its pass and every hook runs
  again on the new line (so a rewriting hook must allow its own output, FR-AUTH-31); asks of a rewritten pass are not
  carried over; a denied rewrite is recorded as `deny` with the rewritten line as `command` and the received one as
  `rewritten_from`.
