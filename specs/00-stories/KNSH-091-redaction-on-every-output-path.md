# KNSH-091 — Redaction on every output path

[Phase 3](README.md#phase-3--reverse-and-protect) · [Story index and plan](README.md)

| Phase | Epic | Size | Depends on | Crates | Requirements |
| --- | --- | --- | --- | --- | --- |
| 3 | Secrets | M (3) | [KNSH-052](KNSH-052-agent-execution-records.md), [KNSH-062](KNSH-062-hook-configuration-and-runner.md), [KNSH-069](KNSH-069-decision-protocol.md), [KNSH-090](KNSH-090-redaction-engine.md) | `knshd`, `knsh-store` | FR-SEC-11, FR-REC-05, FR-EVT-07, FR-OUT-06, FR-AUTH-32, NFR-PRIV-02 |

**Description.** As a user, I want redaction applied before anything is stored, emitted, returned or sent to hooks or
the authority, so that secrets never leak through the engine's own outputs. Scope: records, `command.output` events,
`exec.run` output, hook input, `decision.requested`, and refusal to rewrite lines containing a marker.

**Acceptance criteria**
- [ ] Record `command`, stored output and `rewritten_from` are redacted before writing (FR-REC-05).
- [ ] Events and `exec.run` output are redacted before sending (FR-EVT-07, FR-OUT-06).
- [ ] Hooks and the authority receive the same redacted text as the record (FR-REC-05).
- [ ] A rewrite of a line that contains a redaction marker is refused and the line denied (FR-AUTH-32).
- [ ] A single shared redactor instance per session is used, so all paths see the same secret set.

**Unit tests**
- `record_command_is_redacted_before_write` (FR-REC-05)
- `command_output_event_is_redacted` (FR-EVT-07)
- `hook_input_matches_redacted_record_text` (FR-REC-05)
- `rewrite_of_line_with_marker_is_denied` (FR-AUTH-32)
