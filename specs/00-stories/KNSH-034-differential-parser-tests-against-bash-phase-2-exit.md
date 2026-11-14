# KNSH-034 — Differential parser tests against bash (phase 2 exit criterion)

[Phase 2](README.md#phase-2--contain-and-decide) · [Story index and plan](README.md)

| Phase | Epic | Size | Depends on | Crates | Requirements |
| --- | --- | --- | --- | --- | --- |
| 2 | Parser | L (5) | [KNSH-032](KNSH-032-parser-limits-and-dynamic-fallback.md), [KNSH-033](KNSH-033-agent-command-corpus-pipeline.md) | `knsh-bash` (tests), `tools/difftest` | decision 6, NFR-COMPAT-07 |

**Description.** As the release owner, I want a differential harness that compares our accept/reject verdict with
bash's for every corpus line, and reports exact-parse coverage, so that the phase 2 exit criterion is measured, not
assumed. Scope: run `bash -n` (3.2 at `/bin/bash`, and 5.x when available) per line; compare with
`ParseOutcome`; report percentages; also diff against brush as an oracle where helpful.

**Acceptance criteria**
- [ ] CI job runs the harness on every release and on parser changes, and publishes a report. *Implemented
  (`scripts/check.sh difftest` on every push and tag; report in the job summary and as an artefact); pending its
  first observed CI run.*
- [ ] **Gate:** at least 95% of corpus lines parse `Exact`. *Measured and enforced on release runs; **not met**:
  219 of 235 seed lines (93.19%). The parser covers decision 6; the rest are 10 lines dynamic by decision 6
  (`eval`, `source`, `coproc`, expanded command names, here-documents fed to interpreters) and 6 lines with `time`,
  array assignments or `[[ ]]`, which decision 6 does not make exact. Needs agent-trace sources (KNSH-033) and/or a
  decision 6 scope change.*
- [x] **Gate:** every line where bash rejects is not `Exact` in ours, and every line we parse `Exact` is accepted by
  bash; any mismatch fails the job and is listed. *Observed against bash 3.2.57 (0 mismatches); bash 5.x pending
  (not installed here; used in CI when the runner has it).*
- [x] Bash version used is recorded in the report.

Measurement details: [conformance](../07-testing/conformance.md#measurement-knsh-034).

**Unit tests**
- `harness_flags_line_we_accept_and_bash_rejects` — synthetic mismatch fails.
- `harness_counts_dynamic_lines_as_not_exact`.
- `report_includes_bash_version_and_percentages`.
