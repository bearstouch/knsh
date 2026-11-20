# KNSH-095 — Phase 3 performance qualification

[Phase 3](README.md#phase-3--reverse-and-protect) · [Story index and plan](README.md)

| Phase | Epic | Size | Depends on | Crates | Requirements |
| --- | --- | --- | --- | --- | --- |
| 3 | Qualification | M (3) | [KNSH-084](KNSH-084-undo-and-redo.md) | benches, `knsh-checkpoint` | NFR-PERF-05, NFR-PERF-06 |

**Description.** As the release owner, I want the checkpoint performance targets measured on an Apple silicon laptop,
so that phase 3 ships with honest numbers. Scope: benchmarks following
[../07-testing/performance-validation.md](../07-testing/performance-validation.md).

**Acceptance criteria**
- [x] Checkpoint work after a line is measured for 0, 1, 100 and 10,000 changed files and compared with
      under 20 ms plus 1 ms per changed file (NFR-PERF-05).
- [x] The initial shadow of a 100,000-file root is measured against under 10 s in the background (NFR-PERF-06).
- [x] Results, hardware and macOS version are recorded; missed targets are reported as missed, with a follow-up
      story, not hidden.
- [x] Benchmarks are runnable with one command and documented.

**Unit tests**
- None: benchmark story. Benchmarks live under `benches/` and are runnable without network.

**Notes (KNSH-095)**
- Where it lives: `crates/knsh-checkpoint/benches/phase3/` (`cargo bench`, `harness = false`, no third-party bench
  crate), run with `scripts/qualify-phase3.sh`; method and results in
  [performance validation](../07-testing/performance-validation.md#phase-3-qualification-nfr-perf-05--06-knsh-095),
  report in [qualification/](../07-testing/qualification/phase-3-performance-2026-11-20.md). `knshd` has no library,
  so the bench wires the watcher, ledger, captures and history as `knshd`'s `shadows` module does.
- Result (2026-11-20, M1 Pro, macOS 26.6.2, machine under heavy load): NFR-PERF-05 **met** for 100 files and
  **missed** for 0, 1 (tail) and 10,000 files (every line uncertain after an `FSEvents` drop, its checkpoint about
  half complete at the 1 s flush deadline): follow-up [KNSH-126](KNSH-126-certain-checkpoints-for-large-lines.md).
  NFR-PERF-06 **missed** warm (10.37 to 12.61 s): follow-up [KNSH-127](KNSH-127-faster-initial-shadow.md).
- **Pending:** cold-cache shadow (`KNSH_BENCH_PURGE=1`), a rerun on an idle machine, other machines and macOS 14
  and 15.
