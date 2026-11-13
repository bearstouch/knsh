# KNSH-109 — Conformance gate: bash test suite, Oils subset, 99% corpus

[Phase 4](README.md#phase-4--native-interpreter) · [Story index and plan](README.md)

| Phase | Epic | Size | Depends on | Crates | Requirements |
| --- | --- | --- | --- | --- | --- |
| 4 | Qualification | L (5) | [KNSH-098](KNSH-098-word-splitting-quote-removal-and-pathname-expansion.md), [KNSH-099](KNSH-099-redirections-and-descriptor-management.md), [KNSH-100](KNSH-100-pipelines-subshells-and-job-control.md), [KNSH-101](KNSH-101-core-builtins.md), [KNSH-102](KNSH-102-builtins-test-printf-read.md), [KNSH-103](KNSH-103-functions-scopes-and-arrays.md), [KNSH-104](KNSH-104-traps-signals-set-and-shopt-options.md), [KNSH-105](KNSH-105-process-substitution-coproc-and-here-documents.md), [KNSH-106](KNSH-106-posix-mode.md), [KNSH-107](KNSH-107-interactive-line-editor-and-history.md), [KNSH-108](KNSH-108-per-simple-command-decisions.md) | CI | NFR-COMPAT-02, NFR-COMPAT-05, NFR-COMPAT-07, NFR-COMPAT-11 |

**Description.** As the release owner, I want automated conformance runs that prove native mode is compatible
enough to ship, so that phase 4 meets its gate.

Scope: CI jobs running the bash test suite, the bash-compatible subset of the Oils cross-shell tests, and the
agent-command corpus under `knsh` native mode and bash 5.2; a report with pass rates, failures by category, and a
bash 3.2 vs 5.2 difference list ([../07-testing/conformance.md](../07-testing/conformance.md)).

**Acceptance criteria**
- [ ] At least 99% of corpus commands behave as in bash 5.2 (same stdout, stderr shape, exit status, file effects).
- [ ] Bash test suite and Oils subset results are published per release, with known failures listed.
- [ ] Every known difference is either fixed or documented in the compatibility page.
- [ ] The gate runs on every release in CI (NFR-COMPAT-07).

**Unit tests**
- `report_computes_pass_rate_per_suite`
- `corpus_comparison_detects_status_mismatch`
- `corpus_comparison_detects_output_mismatch`

**Notes.** "Behaves as in bash" needs an exact comparison definition (environment, time, randomness). Add it to
`conformance.md` before the gate is enforced.
