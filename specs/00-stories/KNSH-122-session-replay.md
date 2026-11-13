# KNSH-122 — Session replay

[Phase 6](README.md#phase-6--later-unsized-backlog) · [Story index and plan](README.md)

**Source.** Roadmap, phase 6.

**Description.** Replay a recorded agent session for review: the sequence of lines, decisions, output (when
recorded) and file changes.

**Open questions**
- Replay as presentation only (read records) or re-execution? Re-execution conflicts with "never replay typed input"
  style safety rules and needs its own policy.
- What happens when output recording was off (the default)?

**Acceptance criteria**
- [ ] Spec page written and reviewed.
