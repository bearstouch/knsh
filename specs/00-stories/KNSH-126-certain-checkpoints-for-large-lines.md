# KNSH-126 — Certain checkpoints for lines that change thousands of files

[Phase 3](README.md#phase-3--reverse-and-protect) · [Story index and plan](README.md)

| Phase | Epic | Size | Depends on | Crates | Requirements |
| --- | --- | --- | --- | --- | --- |
| 3 | Checkpoints | L (5) | [KNSH-095](KNSH-095-phase-3-performance-qualification.md) | `knsh-checkpoint`, `knsh-platform` | NFR-PERF-05, FR-CKP-03, FR-CKP-04, FR-CKP-10, decision 16 |

**Description.** As an agent user, I want a line that changes thousands of files (`npm install`, `git checkout`, a
code generator) to get a complete, certain checkpoint within NFR-PERF-05's budget, so that it can be undone like a
small one. Follow-up of the NFR-PERF-05 miss found by the phase 3 qualification (KNSH-095,
[performance validation](../07-testing/performance-validation.md#phase-3-qualification-nfr-perf-05--06-knsh-095)).

What was observed (M1 Pro, macOS 26.6.2, internal SSD): a line appending to 10,000 files of a 10,000-file root makes
the `FSEvents` stream report a drop (`MustScanSubDirs` on the root or the marker folder) every time, so the line
closes uncertain (`events_dropped`) and the whole root is rescanned. With the production flush deadline (1 s,
decision 16) the line's answer is ready after about 1.0 s, but its checkpoint holds only 4,980 to 5,311 of the 10,000
changed files: the rest are applied after the line ended and attributed to whatever follows. With a 60 s deadline the
checkpoint is complete after 3.3 to 4.5 s, inside the 10.02 s budget, but still uncertain. Lines of 100 files meet the
target. Lines of 0 and 1 file are inside it at p50 (14.5 and 15.5 ms) but single lines took up to 39 and 164 ms,
on a machine under heavy load (1-minute load average 96).

Three problems to resolve:
1. **The drop.** Find out whether it is `UserDropped` (the client did not consume fast enough) or `KernelDropped`,
   and at what change count it starts (between 100 and 10,000 files). Options to evaluate: a different stream latency
   or `kFSEventStreamCreateFlagNoDefer`, a faster sink, or accepting the drop and making the rescan's result certain
   for the line when the root is only rescanned against its own shadow while no other process writes there.
2. **The deadline.** A fixed 1 s flush deadline is shorter than NFR-PERF-05 allows for lines over about 980 files
   (20 ms + 1 ms per file), so a large line's checkpoint is cut short although the budget is not used up. Scale the
   deadline with the work the watcher has received, or keep waiting while the worker makes progress, bounded by the
   requirement's budget.
3. **The small-line tail.** Rerun on an idle machine; if 0- and 1-file lines still exceed 20 ms + 1 ms per file,
   break their time down (marker flush, worker wake-up, held-file scan of the process table) and cut it.

Out of scope: the initial shadow (NFR-PERF-06), [KNSH-127](KNSH-127-faster-initial-shadow.md).

**Acceptance criteria**
- [ ] The cause of the drop is recorded (user or kernel dropped, and from which change count), in
      [decisions](../09-reference/decisions.md) (decision 16) or [verification claims](../07-testing/verification-claims.md).
- [ ] `scripts/qualify-phase3.sh` reports NFR-PERF-05 **met** for 0, 1, 100 and 10,000 changed files on an idle
      machine: every line closes certain, its checkpoint holds exactly the changed files and is recorded in the history,
      and every line is under 20 ms + 1 ms per changed file.
- [ ] The flush deadline rule is updated in the spec ([checkpoints](../03-functional-requirements/checkpoints.md),
      decision 16) if it changes.

**Unit tests**
- `large_line_waits_while_the_worker_makes_progress` — a line whose worker is still applying events when the fixed
  deadline passes is not cut short while within its budget (NFR-PERF-05), with the fake clock.
- `line_closes_uncertain_when_the_budget_runs_out` — fail closed: past the budget the line is uncertain (FR-CKP-04).

**Integration tests**
- `watch_macos`: a line changing 10,000 files closes certain and its checkpoint lists every one.
