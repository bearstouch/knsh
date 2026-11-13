# KNSH-081 — Change attribution

[Phase 3](README.md#phase-3--reverse-and-protect) · [Story index and plan](README.md)

| Phase | Epic | Size | Depends on | Crates | Requirements |
| --- | --- | --- | --- | --- | --- |
| 3 | Checkpoints | L (5) | [KNSH-050](KNSH-050-supervisor-lifecycle-orchestrator.md), [KNSH-080](KNSH-080-file-event-watcher-and-rescans.md) | `knsh-checkpoint`, `knshd` | FR-CKP-05, FR-CKP-06, FR-CKP-07 |

**Description.** As the supervisor, I want each change attributed to a supervised line, an agent edit, a concurrent
set or an external actor, so that undo applies to the right unit. Scope: windows per running line, agent edits
(changes inside an envelope outside any line), concurrent sets for overlapping lines in one root, `external` for
changes outside agent sessions, `agent.edit` events, and the record's `attribution` field.
Out of scope: capturing pre-images (KNSH-082).

**Acceptance criteria**
- [ ] Changes during a supervised line are attributed `command` to that line (FR-CKP-05).
- [ ] Changes inside an envelope with no line running become `agent_edit` and emit `agent.edit` (FR-CKP-06).
- [ ] Two lines overlapping in time in one root form one `concurrent` set, undone together (FR-CKP-07).
- [ ] Changes with no agent session active are `external` and are not offered for agent undo.
- [ ] The record's `attribution` matches the edge stored in the history tree.

**Unit tests**
- `change_during_line_is_attributed_to_line` (FR-CKP-05)
- `change_between_lines_in_envelope_is_agent_edit` (FR-CKP-06)
- `overlapping_lines_in_same_root_form_concurrent_set` (FR-CKP-07)
- `non_overlapping_lines_in_different_roots_stay_separate`
- `change_without_agent_session_is_external`

**Notes**
- File events carry no process ID, so a human edit at the same moment can be attributed to the agent. This is
  accepted by the spec; the post-image check in KNSH-084 prevents damage. Document it in the crate header.
