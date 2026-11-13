# KNSH-121 — MCP client

[Phase 6](README.md#phase-6--later-unsized-backlog) · [Story index and plan](README.md)

**Source.** Roadmap, phase 6.

**Description.** An MCP client inside the engine, so that tools exposed over MCP can be reached under the same
recording, policy and sandbox rules as shell commands.

**Open questions**
- Is it a client (engine calls MCP servers) or a server (engine exposes `exec.run` to agents over MCP)? The roadmap
  says client; confirm.
- How do MCP tool calls map to records, decisions and network rules?
- Which transport, and how does it fit the "no network requests of its own" rule (NFR-PRIV-01)?

**Acceptance criteria**
- [ ] Spec page written and reviewed.
