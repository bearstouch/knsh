# Performance

Targets to validate on an Apple silicon laptop; the shadow figure especially is unproven. How they are measured is in [../testing/performance-validation.md](../testing/performance-validation.md).

| ID | Measure | Target |
| --- | --- | --- |
| NFR-PERF-01 | Supervisor decision, no hooks and no authority involved | p95 under 5 ms |
| NFR-PERF-02 | Spawn overhead of a supervised line compared with plain `bash -c` | p95 under 15 ms |
| NFR-PERF-03 | Hooks | Their own run time, up to the 2 s timeout, reported per record |
| NFR-PERF-04 | Start-up time added to a human session | under 50 ms |
| NFR-PERF-05 | Checkpoint work after a line | under 20 ms plus 1 ms per changed file |
| NFR-PERF-06 | Initial shadow of a 100,000-file root | under 10 s, in the background |
| NFR-PERF-07 | Event delivery to a subscriber | p95 under 10 ms |
| NFR-PERF-08 | `knshd` memory when idle | under 50 MB |

## Design constraints that support these targets

- JSON is used on the wire because its cost (microseconds per message) is negligible next to starting a sandboxed process.
- Checkpoint cost grows with the number of files changed, not with project size.
- Output from `knsh -c` never crosses the API; stdio descriptors are passed directly.
