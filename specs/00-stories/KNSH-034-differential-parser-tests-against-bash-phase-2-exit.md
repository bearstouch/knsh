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
- [ ] CI job runs the harness on every release and on parser changes, and publishes a report.
- [ ] **Gate:** at least 95% of corpus lines parse `Exact`.
- [ ] **Gate:** every line where bash rejects is not `Exact` in ours, and every line we parse `Exact` is accepted by
  bash; any mismatch fails the job and is listed.
- [ ] Bash version used is recorded in the report.

**Unit tests**
- `harness_flags_line_we_accept_and_bash_rejects` — synthetic mismatch fails.
- `harness_counts_dynamic_lines_as_not_exact`.
- `report_includes_bash_version_and_percentages`.
