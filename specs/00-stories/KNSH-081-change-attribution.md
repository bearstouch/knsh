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
- [x] Changes during a supervised line are attributed `command` to that line (FR-CKP-05).
- [x] Changes inside an envelope with no line running become `agent_edit` and emit `agent.edit` (FR-CKP-06).
- [x] Two lines overlapping in time in one root form one `concurrent` set, undone together (FR-CKP-07). The set is
      one edge holding every member line; undo itself is KNSH-084.
- [x] Changes with no agent session active are `external` and are not offered for agent undo
      (`Edge::agent_may_undo`; the undo endpoint that checks it is KNSH-084).
- [x] The record's `attribution` matches the edge stored in the history tree: it equals the attribution of the closed
      edge holding the line. Storing that edge in the tree is KNSH-083; until then closed edges are dropped.

**Unit tests**
- `change_during_line_is_attributed_to_line` (FR-CKP-05)
- `change_between_lines_in_envelope_is_agent_edit` (FR-CKP-06)
- `overlapping_lines_in_same_root_form_concurrent_set` (FR-CKP-07)
- `non_overlapping_lines_in_different_roots_stay_separate`
- `change_without_agent_session_is_external`

**Notes**
- File events carry no process ID, so a human edit at the same moment can be attributed to the agent. This is
  accepted by the spec; the post-image check in KNSH-084 prevents damage. Document it in the crate header.

**Implementation (KNSH-081).**
- **Model.** `knsh_core::Attribution` (`command`, `agent_edit`, `external`, `concurrent`), the record's
  `attribution` (store column present since schema version 1; `records.query` shows it, null when absent), and
  `agent.edit {root, paths, omitted}` (at most `AGENT_EDIT_PATHS` = 256 paths).
- **Ledger.** `knsh_checkpoint::attribution::Ledger`, pure: lines started and ended per root, changes attributed by
  time and root, overlapping lines merged into one concurrent edge (transitively, across roots through a line touching
  several), agent-edit and external runs between lines, closed `Edge`s handed out in order. Bounded: 65,536 paths per
  edge (then `overflowed`), roots forgotten when unused.
- **knshd.** One `Attributor` per daemon, keyed by root; watchers feed it each applied change and each settled batch
  (`WatchReport::settled`, new); sessions register their roots with their envelope flag; the supervisor starts the
  line in it before spawning and reads its attribution after the line-end flush. Closed edges go to an `EdgeSink`
  (`UncapturedEdges` drops them until KNSH-082 and KNSH-083).

**Pending:** storing edges in the history tree (KNSH-083) and undo of a concurrent set as one (KNSH-084); a real
envelope end-to-end run. **Known limit:** a change made just before a line starts, whose event the watcher had not
applied yet, is attributed to the line (opening a line never waits, decision 16).
