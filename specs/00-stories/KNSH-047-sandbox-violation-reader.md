# KNSH-047 — Sandbox violation reader

[Phase 2](README.md#phase-2--contain-and-decide) · [Story index and plan](README.md)

| Phase | Epic | Size | Depends on | Crates | Requirements |
| --- | --- | --- | --- | --- | --- |
| 2 | Sandbox | L (5) | [KNSH-025](KNSH-025-spike-seatbelt-behaviour-c1-c2-c8.md), [KNSH-045](KNSH-045-seatbelt-compiler-executables-services-sockets-network.md) | `knsh-platform`, `knshd` | FR-SBX-06, FR-SBX-08 |

**Description.** As a subscriber, I want sandbox denials reported by the system attributed to a session and command,
best effort, so that agents and humans understand why something failed. Scope: a platform service streaming unified
log entries with the knsh tag (approach from KNSH-025); parsing tags to session, command and rule; emitting
`sandbox.violation` and attaching to the record's `sandbox_violations`.

**Acceptance criteria**
- [ ] The reader runs as the user without admin rights.
- [ ] Entries without a parseable knsh tag are ignored, never mis-attributed.
- [ ] Duplicates within a short window are merged; delayed entries arriving after a record is finished are appended
  to that record.
- [ ] Reader failure is reported through the capability report and never blocks or fails a command.
- [ ] The log message parser is a pure function with tests over captured real samples (from KNSH-025).

**Unit tests**
- `parses_tagged_denial_message`.
- `ignores_untagged_message`.
- `merges_duplicate_denials`.
- `attaches_late_denial_to_finished_record`.

**Notes.** — Format can change between macOS versions; samples per version are kept as fixtures.
