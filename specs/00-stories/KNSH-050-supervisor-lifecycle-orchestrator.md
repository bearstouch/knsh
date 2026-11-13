# KNSH-050 — Supervisor lifecycle orchestrator

[Phase 2](README.md#phase-2--contain-and-decide) · [Story index and plan](README.md)

| Phase | Epic | Size | Depends on | Crates | Requirements |
| --- | --- | --- | --- | --- | --- |
| 2 | Supervisor | XL (8) | [KNSH-038](KNSH-038-line-re-serialisation-with-resolved-absolute-paths.md), [KNSH-041](KNSH-041-line-verdicts-dynamic-code-limits-fixed-denies-and-the.md), [KNSH-048](KNSH-048-agent-sock-endpoint-session-tokens-and-audit-token-fallback.md) | `knsh-core`, `knshd` | FR-LC-01 – FR-LC-19, FR-LC-30 – FR-LC-32, FR-LC-41, FR-HOOK-11, FR-POL-18, NFR-REL-07 |

**Description.** As the engine, I want one orchestrator that drives every agent line through the eleven lifecycle
steps, so that every line is decided as a whole before any part of it runs.

In scope:
- A pure decision pipeline in `knsh-core`: parse, classify, hooks slot, policy, ask slot, rewrite once, profile
  selection.
- A thin driver in `knshd` that performs the effects: events, hook runner, authority, spawn, record.
- Hooks, authority and spawning are trait objects, so the pipeline is tested with fakes.

Out of scope: implementations of hooks (KNSH-062), the authority (KNSH-069) and spawning (KNSH-051).

**Acceptance criteria**
- [ ] Every received line passes the steps in order. No spawn happens before the final verdict is allow.
- [ ] `command.proposed` is emitted once per line, before hooks run.
- [ ] Policy is evaluated on the whole (possibly rewritten) line. Deny if any part denies, ask if any part asks.
- [ ] An ask with no authority connected goes to standalone handling (local approval, or deny at the timeout).
- [ ] A rewrite triggers exactly one re-run of steps 2 to 5. A second rewrite denies the line (FR-AUTH-31).
- [ ] Any error in any step (parse failure, hook error, store failure before the decision, internal panic caught at
      the boundary) results in **deny**, never a spawn.
- [ ] A denied line emits `command.denied` with the rule ID, writes a record (FR-REC-03), and makes the client exit 126.
- [ ] If the caller disconnects while a decision is pending, the request is cancelled (`decision.cancelled`) and the
      line never runs (FR-LC-41).
- [ ] The pipeline's decision and the record's `decision` object match (`verdict`, `source`, `rule_id`,
      `decided_by`, `latency_ms`).

**Unit tests**
- `never_spawns_before_final_allow` — FR-LC-09.
- `emits_command_proposed_before_hooks` — FR-LC-07.
- `denies_whole_line_when_any_part_denied` — FR-POL-18.
- `asks_whole_line_when_any_part_asks` — FR-POL-18.
- `reevaluates_rewritten_line_once` — FR-LC-11.
- `denies_on_second_rewrite` — FR-AUTH-31.
- `denies_on_internal_error_in_any_step` — NFR-REL-07.
- `cancels_and_skips_spawn_when_caller_disconnects` — FR-LC-41.
- `denial_writes_record_and_event` — FR-LC-32, FR-REC-03.
- `decision_source_matches_deciding_component` — record model.

**Integration tests**
- An end-to-end line through `agent.sock` with fake hooks and authority: allow, deny, ask→allow, ask→timeout and
  rewrite→allow paths, each checked by event order and record contents.

**Notes**
- Panics are denied by lint outside tests. A `catch_unwind` boundary exists only as defence in depth, and any panic
  it catches is a deny.
- Could be split into KNSH-050a (pure pipeline in core) and KNSH-050b (daemon driver and events) if the seam is clean.
