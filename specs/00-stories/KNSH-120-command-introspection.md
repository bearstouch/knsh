# KNSH-120 — Command introspection

[Phase 6](README.md#phase-6--later-unsized-backlog) · [Story index and plan](README.md)

**Source.** [../01-overview/roadmap.md](../01-overview/roadmap.md), phase 6.

**Description.** Let clients ask what a command is and what it will do before it runs, beyond what `policy.check`
already reports (for example: resolved binary, classes, likely file and network effects, help text).

**Open questions**
- Is this an extension of `policy.check` or a new method family?
- Which information may be shown to agents on `agent.sock` without helping them evade rules?
- Is any of it derived from running the command (help output), and if so, under which profile?

**Acceptance criteria**
- [ ] Spec page written and reviewed.
