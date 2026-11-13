# KNSH-125 — Revisit: agents as a separate macOS user (managed deployments)

[Phase 6](README.md#phase-6--later-unsized-backlog) · [Story index and plan](README.md)

**Source.** Decision 4 in [../09-reference/decisions.md](../09-reference/decisions.md).

**Description.** Run agents as a separate macOS user for managed enterprise deployments. Not in the first release:
it needs a root helper (breaking the no-root design) and causes file-ownership friction with projects, git and
caches.

**Open questions**
- Is the Endpoint Security descendant client (KNSH-094) enough to make this unnecessary?
- What would a root helper's minimal interface be, and who installs it (MDM)?
- How are project files shared between the user and the agent user?

**Acceptance criteria**
- [ ] Spec page (or decision update) written and reviewed.
