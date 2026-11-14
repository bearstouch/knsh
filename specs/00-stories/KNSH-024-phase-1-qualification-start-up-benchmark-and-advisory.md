# KNSH-024 — Phase 1 qualification: start-up benchmark and advisory labelling

[Phase 1](README.md#phase-1--observe-advisory) · [Story index and plan](README.md)

| Phase | Epic | Size | Depends on | Crates | Requirements |
| --- | --- | --- | --- | --- | --- |
| 1 | Qualification | S (2) | [KNSH-021](KNSH-021-human-telemetry-recording-indicator-and-idle-event.md) | `knsh`, `knshd` | NFR-PERF-04, [roadmap](../01-overview/roadmap.md), [performance validation](../07-testing/performance-validation.md) |

**Description.** As a maintainer, I want phase 1 measured against its start-up target and clearly labelled as
advisory, so that nobody mistakes it for a security tool.

**Acceptance criteria**
- [x] A benchmark measures time to first prompt for plain zsh vs `knsh`-hosted zsh (recording off and on); the
      added time is under 50 ms at p95 on an Apple silicon laptop. The result and machine are recorded.
- [x] `knsh --version`, `hello` and the README state that phase 1 is advisory: no security guarantees, not for
      running agents unattended.
- [x] Any target not met is recorded as an open item, not marked as passed.

**Unit tests**
- `version_output_contains_advisory_label` — labelling.

**Integration tests**
- Start-up benchmark script with results stored under `.build/`.

**Notes.** `scripts/startup-bench.sh` (`xtask/src/bin/startup_bench.rs`) measured the added start-up on an Apple M1
Pro; the result and machine are in [performance validation](../07-testing/performance-validation.md#start-up-benchmark-nfr-perf-04-knsh-024)
and the full report under `.build/startup-bench/`. A missed target or a machine other than Apple silicon makes the
benchmark exit non-zero and list an open item; its unit tests check that. `knsh --version` prints the advisory label
(`cli::version`); `hello` has reported `advisory: true` since KNSH-014; the repository README opens with the same
warning. **Pending:** bash start-up is not benchmarked, and recording on is measured without a `knshd` listening (it is
off the prompt path by design); neither is claimed as passed.
