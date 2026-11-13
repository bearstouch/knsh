# KNSH-052 — Agent execution records

[Phase 2](README.md#phase-2--contain-and-decide) · [Story index and plan](README.md)

| Phase | Epic | Size | Depends on | Crates | Requirements |
| --- | --- | --- | --- | --- | --- |
| 2 | Supervisor | M (3) | [KNSH-016](KNSH-016-record-store-with-records-query-and-records-output.md), [KNSH-050](KNSH-050-supervisor-lifecycle-orchestrator.md) | `knsh-store`, `knshd` | FR-REC-01 – FR-REC-04, FR-REC-11, NFR-REL-05, [execution record](../05-models/execution-record.md) |

**Description.** As an observer or authority, I want one complete record per agent line, written before the client
gets its reply, so that every decision and execution is auditable even if the client dies.

**Acceptance criteria**
- [ ] Every line that reaches lifecycle step 2 produces exactly one record: ran, denied or rewritten.
- [ ] The record is committed before the reply is sent to the client.
- [ ] `command` holds the executed line after any rewrite, and `rewritten_from` holds the original.
- [ ] `argv` lists each simple command with its absolute path and class (`static`, `wrapper`, `dynamic`,
      `project_executable`).
- [ ] `decision` holds `verdict`, `source`, `rule_id`, `decided_by` and `latency_ms`.
- [ ] `exit_code`, `pipestatus`, `signal`, `started_at`, `ended_at` (UTC, microseconds) and `sandbox_profile`
      (name and hash) are filled for lines that ran. `exit_code` is null for denied lines.
- [ ] Denials and approvals are recorded even when command recording is off, and without output.
- [ ] `secrets_injected` is an empty list in phase 2 and never contains values.

**Unit tests**
- `writes_one_record_per_line_reaching_parse` — FR-REC-01.
- `commits_record_before_reply` — FR-REC-02.
- `records_rewritten_from` — FR-REC-04.
- `records_denial_without_output_when_recording_off` — FR-REC-03.
- `exit_code_null_for_denied_line` — record model.
- `argv_carries_resolved_path_and_class` — record model.
