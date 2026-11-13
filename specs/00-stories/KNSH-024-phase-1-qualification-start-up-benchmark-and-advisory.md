# KNSH-024 — Phase 1 qualification: start-up benchmark and advisory labelling

[Phase 1](README.md#phase-1--observe-advisory) · [Story index and plan](README.md)

| Phase | Epic | Size | Depends on | Crates | Requirements |
| --- | --- | --- | --- | --- | --- |
| 1 | Qualification | S (2) | [KNSH-021](KNSH-021-human-telemetry-recording-indicator-and-idle-event.md) | `knsh`, `knshd` | NFR-PERF-04, [roadmap](../01-overview/roadmap.md), [performance validation](../07-testing/performance-validation.md) |

**Description.** As a maintainer, I want phase 1 measured against its start-up target and clearly labelled as
advisory, so that nobody mistakes it for a security tool.

**Acceptance criteria**
- [ ] A benchmark measures time to first prompt for plain zsh vs `knsh`-hosted zsh (recording off and on); the
      added time is under 50 ms at p95 on an Apple silicon laptop. The result and machine are recorded.
- [ ] `knsh --version`, `hello` and the README state that phase 1 is advisory: no security guarantees, not for
      running agents unattended.
- [ ] Any target not met is recorded as an open item, not marked as passed.

**Unit tests**
- `version_output_contains_advisory_label` — labelling.

**Integration tests**
- Start-up benchmark script with results stored under `.build/`.
