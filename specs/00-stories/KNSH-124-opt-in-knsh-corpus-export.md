# KNSH-124 — Opt-in `knsh corpus export`

[Phase 6](README.md#phase-6--later-unsized-backlog) · [Story index and plan](README.md)

**Source.** [../09-reference/decisions.md](../09-reference/decisions.md), decision 7;
[../07-testing/agent-command-corpus.md](../07-testing/agent-command-corpus.md).

**Description.** Let users contribute agent command lines to the corpus. Opt-in, normalised (paths, user names, hosts
and anything secret-like become placeholders) and showing the user every line before sharing.

**Open questions**
- Where does exported data go, given the engine makes no network requests of its own (NFR-PRIV-01)? Probably a local
  file the user shares manually.
- How is normalisation verified to remove secrets reliably?

**Acceptance criteria**
- [ ] Spec page written and reviewed.
