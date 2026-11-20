# KNSH-127 — Initial shadow of 100,000 files under 10 s

[Phase 3](README.md#phase-3--reverse-and-protect) · [Story index and plan](README.md)

| Phase | Epic | Size | Depends on | Crates | Requirements |
| --- | --- | --- | --- | --- | --- |
| 3 | Checkpoints | M (3) | [KNSH-095](KNSH-095-phase-3-performance-qualification.md) | `knsh-checkpoint` | NFR-PERF-06, FR-CKP-01, decision 15 |

**Description.** As an agent user, I want the shadow of a large root built within NFR-PERF-06's 10 s, warm or cold,
so that lines in a required root do not wait long after the session starts. Follow-up of the NFR-PERF-06 miss found
by the phase 3 qualification (KNSH-095,
[performance validation](../07-testing/performance-validation.md#phase-3-qualification-nfr-perf-05--06-knsh-095)).

What was observed (M1 Pro, macOS 26.6.2, internal SSD, warm cache): three builds of 100,000 files in 4,101 folders
took 10.37, 12.19 and 12.61 s, against 7.4 to 7.7 s in the KNSH-077 spike and 9.72 to 9.88 s in shorter trial runs
the same day. The machine was under heavy load during the run (1-minute load average 96). The cold cache was not
measured.

Scope:
- Rerun `scripts/qualify-phase3.sh` on an idle machine, and with `KNSH_BENCH_PURGE=1` for the cold cache.
- If 10 s is still missed: evaluate decision 15's fallback (one `clonefile(2)` per top-level folder that is not
  excluded; 1.6 to 4.4 s in the spike) behind its own spike, or another pool size or QoS class, and update
  decision 15. Otherwise revisit the target with the measured figures.

**Acceptance criteria**
- [ ] Warm and cold runs of 100,000 files on an idle Apple silicon laptop are recorded in
      [performance validation](../07-testing/performance-validation.md), each under 10 s, or the target is revised
      in [performance](../04-non-functional-requirements/performance.md) with the reason.
- [ ] Decision 15 records the outcome.

**Unit tests**
- None unless the builder changes; then the existing `shadow` unit tests cover the new strategy.
