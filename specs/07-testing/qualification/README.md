# Release qualification reports

Reports stored with each release: written by `scripts/qualify-phase2.sh` (KNSH-076) or `scripts/qualify-phase3.sh`
(KNSH-095) and copied here unchanged, so the
numbers a release was qualified on stay with it. Methods: [performance validation](../performance-validation.md) and
[developer tools](../../08-integrations/developer-tools.md#compatibility-list).

| File | What it holds |
| --- | --- |
| [phase-2-performance-2026-11-18.md](phase-2-performance-2026-11-18.md) | NFR-PERF-01, -02, -03, -07, -08 on an Apple M1 Pro, macOS 26.6.2: machine, every series (n, min, p50, p95, p99, max), result and open items |
| [phase-2-performance-samples-2026-11-18.csv](phase-2-performance-samples-2026-11-18.csv) | Every raw sample of that run: requirement, series, index, value, unit |
| [phase-3-performance-2026-11-20.md](phase-3-performance-2026-11-20.md) | NFR-PERF-05 and NFR-PERF-06 on an Apple M1 Pro, macOS 26.6.2: machine, every series, the invalid samples (why each is invalid), result and open items |
| [phase-3-performance-samples-2026-11-20.csv](phase-3-performance-samples-2026-11-20.csv) | Every raw sample of that run: requirement, series, index, value, unit, valid |
| [phase-2-tools-2026-11-18.md](phase-2-tools-2026-11-18.md) | The developer-tool run: per tool and variant, the version, the control outside any sandbox, the command-profile and envelope results, and the names the proxy was asked for |

A miss stays a miss: reports are never edited after the run. A rerun adds new files with its own date.
