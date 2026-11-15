# KNSH-054 — Pause, resume and human control

[Phase 2](README.md#phase-2--contain-and-decide) · [Story index and plan](README.md)

| Phase | Epic | Size | Depends on | Crates | Requirements |
| --- | --- | --- | --- | --- | --- |
| 2 | Supervisor | L (5) | [KNSH-015](KNSH-015-session-model-and-registry.md), [KNSH-051](KNSH-051-spawning-interpreter-selection-process-groups-and-timeouts.md) | `knsh-core`, `knshd` | FR-SES-10 – FR-SES-14, [session](../05-models/session.md) |

**Description.** As the user or authority, I want to pause an agent session or take control of it, so that I can stop
the agent mid-task and inspect or intervene safely.

**Acceptance criteria**
- [x] Pausing sends `SIGSTOP` to the envelope's process group and to every running line's process group. Resuming
      sends `SIGCONT` to the same groups.
- [x] While paused or under human control, new lines are held and the caller sees `-32007` with `data.state`.
- [ ] A process that left its group with `setsid` keeps running while paused, still sandboxed (documented
      behaviour, not a bug).
- [x] Human control holds agent lines until control is handed back. Nothing typed into the envelope is treated as
      human.
- [x] Every transition emits `session.state_changed`. Illegal transitions (for example resuming an ended session)
      return `-32006`.
- [x] Signals target process groups through kept handles, never bare PIDs that may have been reused.

**Unit tests**
- `pause_stops_envelope_and_running_groups` — FR-SES-10 (fake process service).
- `resume_continues_same_groups` — FR-SES-10.
- `holds_new_lines_with_32007_while_paused` — FR-SES-10.
- `holds_lines_under_human_control` — FR-SES-12.
- `emits_state_changed_on_every_transition` — FR-SES-14.
- `rejects_transition_from_ended_with_32006` — session model.

**Notes**
- Spec gap (settled): `exec.*` returns `-32007` immediately and `knsh -c` waits and retries
  ([sessions](../03-functional-requirements/sessions.md), "Holding a line"). The rest of the behaviour is in
  "Pausing and taking control" on the same page.
- The `setsid` criterion is documented behaviour (FR-SES-11, `crates/knshd/src/holds.rs`); no test observes a
  `setsid` process keeping running while paused, so it stays unchecked.
- The pause criterion is met by the mechanism (`Sessions::keep_group` with `GroupKind::Envelope`, tested with fake
  and real process groups); end to end it also needs the envelope wiring below.
- Pending: the envelope's group is kept by `session.start_agent` (KNSH-056) and the `session.*` control methods
  that pause and take control arrive with KNSH-071; until then only tests reach `Sessions::change_state`.
