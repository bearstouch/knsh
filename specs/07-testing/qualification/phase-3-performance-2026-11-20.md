# Phase 3 performance qualification (KNSH-095)

Method: `specs/07-testing/performance-validation.md`, "Phase 3 qualification". Every bound is strict; a target holds when every sample is valid and the largest is under it. Percentiles are nearest rank.

| | |
| --- | --- |
| Date (UTC) | 2026-11-20 14:31:28 |
| Machine | MacBookPro18,3, Apple M1 Pro (8 CPUs, 16 GiB) |
| macOS | 26.6.2 (25G83) |
| Commit | 9abf2b1 + uncommitted changes |
| Build | release (`cargo bench`, bench profile) |
| Volume | Apfs at /System/Volumes/Data |
| Settings | 20 lines per size (5 of 10,000 files) after one warm-up each, 3 shadow runs, purge off |

## Results

| Requirement | Measure | Target | Figure | Result |
| --- | --- | --- | --- | --- |
| NFR-PERF-05 | production deadline (1 s): 0 changed files | < 20 ms (20 ms + 0 × 1 ms) | max 39.10 ms (p50 14.48, p95 31.45, n 20) | **missed** |
| NFR-PERF-05 | production deadline (1 s): 1 changed files | < 21 ms (20 ms + 1 × 1 ms) | max 164.49 ms (p50 15.52, p95 57.75, n 20) | **missed** |
| NFR-PERF-05 | production deadline (1 s): 100 changed files | < 120 ms (20 ms + 100 × 1 ms) | max 64.47 ms (p50 41.62, p95 48.27, n 20) | **met** |
| NFR-PERF-05 | production deadline (1 s): 10000 changed files | < 10020 ms (20 ms + 10000 × 1 ms) | max 1004.68 ms, 5 invalid | **missed** |
| NFR-PERF-06 | 100,000 files, warm cache | < 10 s | max 12.61 s (p50 12.19, p95 12.61, n 3) | **missed** |
| NFR-PERF-06 | 100,000 files, cold cache (after purge) | < 10 s | not measured | **not measured** |

## Series

| Requirement | Series | n | invalid | min | p50 | p95 | p99 | max | unit |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| NFR-PERF-05 | production deadline (1 s): 0 changed files | 20 | 0 | 12.59 | 14.48 | 31.45 | 39.10 | 39.10 | ms |
| NFR-PERF-05 | production deadline (1 s): 1 changed files | 20 | 0 | 12.12 | 15.52 | 57.75 | 164.49 | 164.49 | ms |
| NFR-PERF-05 | production deadline (1 s): 100 changed files | 20 | 0 | 35.14 | 41.62 | 48.27 | 64.47 | 64.47 | ms |
| NFR-PERF-05 | production deadline (1 s): 10000 changed files | 0 | 5 | – | – | – | – | – | ms |
| NFR-PERF-05 | diagnostic: 60 s deadline: 0 changed files | 20 | 0 | 7.59 | 14.27 | 18.45 | 29.72 | 29.72 | ms |
| NFR-PERF-05 | diagnostic: 60 s deadline: 1 changed files | 20 | 0 | 6.08 | 13.96 | 20.45 | 28.92 | 28.92 | ms |
| NFR-PERF-05 | diagnostic: 60 s deadline: 100 changed files | 20 | 0 | 28.76 | 38.90 | 64.64 | 97.87 | 97.87 | ms |
| NFR-PERF-05 | diagnostic: 60 s deadline: 10000 changed files | 0 | 5 | – | – | – | – | – | ms |
| NFR-PERF-06 | 100,000 files, warm cache | 3 | 0 | 10.37 | 12.19 | 12.61 | 12.61 | 12.61 | s |
| NFR-PERF-06 | 100,000 files, cold cache (after purge) | 0 | 0 | – | – | – | – | – | s |
| NFR-PERF-06 | diagnostic: removing a 100,000-file shadow | 3 | 0 | 6.11 | 6.43 | 6.94 | 6.94 | 6.94 | s |

## Invalid samples

- production deadline (1 s): 10000 changed files, sample 0: 1004.36 ms: line closed uncertain (EventsDropped); checkpoint holds 4980 of 10000 changed files; checkpoint uncertain; checkpoint paths differ: 5020 missing, 0 unexpected
- production deadline (1 s): 10000 changed files, sample 1: 1003.48 ms: line closed uncertain (EventsDropped); checkpoint holds 5150 of 10000 changed files; checkpoint uncertain; checkpoint paths differ: 4850 missing, 0 unexpected
- production deadline (1 s): 10000 changed files, sample 2: 1003.13 ms: line closed uncertain (EventsDropped); checkpoint holds 5283 of 10000 changed files; checkpoint uncertain; checkpoint paths differ: 4717 missing, 0 unexpected
- production deadline (1 s): 10000 changed files, sample 3: 1004.68 ms: line closed uncertain (EventsDropped); checkpoint holds 5060 of 10000 changed files; checkpoint uncertain; checkpoint paths differ: 4940 missing, 0 unexpected
- production deadline (1 s): 10000 changed files, sample 4: 1003.58 ms: line closed uncertain (EventsDropped); checkpoint holds 5311 of 10000 changed files; checkpoint uncertain; checkpoint paths differ: 4689 missing, 0 unexpected
- diagnostic: 60 s deadline: 10000 changed files, sample 0: 3501.81 ms: line closed uncertain (EventsDropped); checkpoint uncertain
- diagnostic: 60 s deadline: 10000 changed files, sample 1: 3568.85 ms: line closed uncertain (EventsDropped); checkpoint uncertain
- diagnostic: 60 s deadline: 10000 changed files, sample 2: 3301.27 ms: line closed uncertain (EventsDropped); checkpoint uncertain
- diagnostic: 60 s deadline: 10000 changed files, sample 3: 3661.67 ms: line closed uncertain (EventsDropped); checkpoint uncertain
- diagnostic: 60 s deadline: 10000 changed files, sample 4: 4507.73 ms: line closed uncertain (EventsDropped); checkpoint uncertain

## Open items

- NFR-PERF-05 missed: production deadline (1 s): 0 changed files: max 39.10 ms (p50 14.48, p95 31.45, n 20) against < 20 ms (20 ms + 0 × 1 ms).
- NFR-PERF-05 missed: production deadline (1 s): 1 changed files: max 164.49 ms (p50 15.52, p95 57.75, n 20) against < 21 ms (20 ms + 1 × 1 ms).
- NFR-PERF-05 missed: production deadline (1 s): 10000 changed files: max 1004.68 ms, 5 invalid against < 10020 ms (20 ms + 10000 × 1 ms).
- NFR-PERF-06 missed: 100,000 files, warm cache: max 12.61 s (p50 12.19, p95 12.61, n 3) against < 10 s.
- NFR-PERF-06 not measured: 100,000 files, cold cache (after purge).
- NFR-PERF-06 cold cache not measured: KNSH_BENCH_PURGE=1 was not set.
