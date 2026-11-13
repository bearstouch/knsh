# KNSH-095 — Phase 3 performance qualification

[Phase 3](README.md#phase-3--reverse-and-protect) · [Story index and plan](README.md)

| Phase | Epic | Size | Depends on | Crates | Requirements |
| --- | --- | --- | --- | --- | --- |
| 3 | Qualification | M (3) | [KNSH-084](KNSH-084-undo-and-redo.md) | benches, `knsh-checkpoint` | NFR-PERF-05, NFR-PERF-06 |

**Description.** As the release owner, I want the checkpoint performance targets measured on an Apple silicon laptop,
so that phase 3 ships with honest numbers. Scope: benchmarks following
[../07-testing/performance-validation.md](../07-testing/performance-validation.md).

**Acceptance criteria**
- [ ] Checkpoint work after a line is measured for 0, 1, 100 and 10,000 changed files and compared with
      under 20 ms plus 1 ms per changed file (NFR-PERF-05).
- [ ] The initial shadow of a 100,000-file root is measured against under 10 s in the background (NFR-PERF-06).
- [ ] Results, hardware and macOS version are recorded; missed targets are reported as missed, with a follow-up
      story, not hidden.
- [ ] Benchmarks are runnable with one command and documented.

**Unit tests**
- None: benchmark story. Benchmarks live under `benches/` and are runnable without network.
