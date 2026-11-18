# Phase 2 performance qualification (KNSH-076)

Targets: `specs/04-non-functional-requirements/performance.md`. Method: `specs/07-testing/performance-validation.md`. Raw samples: `phase-2-performance-samples-2026-11-18.csv` beside this report.

## Machine

| Field | Value |
| --- | --- |
| Model | MacBookPro18,3 |
| CPU | Apple M1 Pro |
| Architecture | arm64 |
| Logical CPUs | 8 |
| Memory (GiB) | 16 |
| macOS | 26.6.2 (25G83) |
| Commit | 4dc927c |
| Build | release |
| Date | 2026-11-18T00:23:24Z |

## Summary

| Requirement | Target | Figure | Measured | Result |
| --- | --- | --- | --- | --- |
| NFR-PERF-01 | Supervisor decision without hooks or authority: p95 under 5 ms over the corpus | p95 over every timed line | 0.29 ms | met |
| NFR-PERF-02 | Spawn overhead versus plain `bash -c`: p95 under 15 ms for trivial commands | worst added p95 (supervised p95 − plain p95) | 55.14 ms | **missed** |
| NFR-PERF-03 | Hook time reported per record, bounded by its timeout | slowest decision of a line whose hook hangs (timeout 500 ms; must be under timeout + 500 ms) | 507.19 ms | met |
| NFR-PERF-07 | Event delivery: p95 under 10 ms | p95 of `ts` to receipt | 0.05 ms | met |
| NFR-PERF-08 | `knshd` idle memory under 50 MB | largest resident size over the last samples | 8.98 MB | met |

## NFR-PERF-01 — Supervisor decision without hooks or authority: p95 under 5 ms over the corpus

Each corpus line is handed to the supervisor (`exec.run`'s path, without the socket) of a miniature `knshd`. An allowed line is timed until the supervisor hands it to the spawner (which starts nothing); a refused line until it is answered, record write included (an upper bound). Every round uses a new session, so the repeated-denial limiter never shortens a refusal.

| Series | n | min (ms) | p50 | p95 | p99 | max |
| --- | --- | --- | --- | --- | --- | --- |
| all lines | 2350 | 0.07 | 0.18 | 0.29 | 0.53 | 9.71 |
| allowed: to spawner hand-off | 1175 | 0.07 | 0.10 | 0.15 | 0.25 | 2.85 |
| refused: to answer (record written) | 1175 | 0.13 | 0.23 | 0.32 | 5.37 | 9.71 |
| record latency_ms (whole ms) | 2350 | 0.00 | 0.00 | 0.00 | 0.00 | 6.00 |

- 235 corpus lines × 5 timed rounds (after 1 warm-up) × 2 profiles: 1175 allowed, 1175 refused.
- Profiles: one with `exec.default`, `exec.project_executables` and `approvals.irreversible` all `allow`, one with `exec.default` and `exec.project_executables` `deny`; no hooks, no authority, no grants.
- The `record latency_ms` series is the supervisor's own figure in each record (whole milliseconds, rounded down): a cross-check of the wall-clock series, not the figure judged.

Result: **met**.

## NFR-PERF-02 — Spawn overhead versus plain `bash -c`: p95 under 15 ms for trivial commands

A small C timer (`posix_spawn` to `waitpid`, monotonic clock) runs each trivial line repeatedly, outside any envelope with plain `bash -c`, and inside an envelope through the `knsh` client. The overhead is the difference of the nearest-rank p95s.

| Series | n | min (ms) | p50 | p95 | p99 | max |
| --- | --- | --- | --- | --- | --- | --- |
| diag: sandbox-exec alone: true | 100 | 9.49 | 9.97 | 10.63 | 19.62 | 23.53 |
| diag: supervisor in-process: true | 100 | 28.47 | 33.96 | 51.16 | 63.01 | 64.90 |
| knsh: echo | 100 | 35.16 | 40.08 | 56.17 | 69.80 | 70.30 |
| knsh: true | 100 | 35.40 | 40.07 | 57.52 | 71.24 | 79.41 |
| plain: echo | 100 | 2.02 | 2.14 | 2.40 | 2.70 | 2.74 |
| plain: true | 100 | 2.00 | 2.16 | 2.38 | 2.63 | 2.91 |

- `true`: added p95 55.14 ms (knsh 57.52 − plain 2.38); added p50 37.92 ms.
- `echo hi`: added p95 53.77 ms (knsh 56.17 − plain 2.40); added p50 37.94 ms.
- 20 runs of each line per round, 5 timed rounds after 1 warm-up; plain and supervised runs alternate each round.
- Diagnostic series (not judged), to show where the time goes: `diag: sandbox-exec alone: true` is `sandbox-exec` with an allow-everything profile running `bash -c true` (the floor any sandboxed line pays); `diag: supervisor in-process: true` is the supervisor's own path for `true` in-process, without the `knsh` client or the socket (decision, record, profile file, `knsh-exec`, `sandbox-exec`, `bash`, reaping).
- Supervised = `"$SHELL" -c <line>` inside a real envelope: the `knsh` client starts, connects to `agent.sock`, says `hello`, sends `exec.run`; the supervisor decides, records, writes the line's profile and starts it through `knsh-exec` and `sandbox-exec`; `bash` runs the line. Plain = `/bin/bash -c <line>` outside any envelope.

Result: **missed**: worst added p95 (supervised p95 − plain p95) is 55.14 ms, not under 15 ms.

## NFR-PERF-03 — Hook time reported per record, bounded by its timeout

Three hooks are registered in the configuration file and run by the real hook runner: one answers at once, one sleeps 100 ms, one hangs past its 500 ms timeout. Each record of a matching line must list exactly its hook, with the expected result and a `duration_ms` no larger than the hook's timeout; a line whose hook hangs must be decided shortly after the timeout.

| Series | n | min (ms) | p50 | p95 | p99 | max |
| --- | --- | --- | --- | --- | --- | --- |
| hooks[0] reported duration_ms (echo hooked; timeout 2000 ms) | 50 | 6.00 | 9.00 | 20.00 | 25.00 | 25.00 |
| hooks[1] reported duration_ms (printf x; timeout 2000 ms) | 50 | 114.00 | 132.00 | 144.00 | 157.00 | 157.00 |
| hooks[2] reported duration_ms (date; timeout 500 ms) | 10 | 500.00 | 500.00 | 500.00 | 500.00 | 500.00 |
| hanging hook: line decided after (wall) | 10 | 503.88 | 505.44 | 507.19 | 507.19 | 507.19 |

- Hook time is the hook's own run time, not a target: it is reported per record (FR-HOOK-05) and bounded by the hook's `timeout_ms` (at most 60 s).

Result: **met**.

## NFR-PERF-07 — Event delivery: p95 under 10 ms

A subscriber connects to the real `user.sock`, says `hello` and subscribes to every session (`events.subscribe`). The corpus then runs through the supervisor (decided and recorded, nothing started), publishing `command.proposed`, `command.finished`, `command.denied` and the session events. Delay = the system clock when a notification has been read and parsed − its `ts`, which the hub stamps with the system clock as it publishes.

| Series | n | min (ms) | p50 | p95 | p99 | max |
| --- | --- | --- | --- | --- | --- | --- |
| ts to receipt | 2355 | 0.02 | 0.03 | 0.05 | 0.12 | 1.16 |

- 235 corpus lines × 5 timed rounds after 1 warm-up; events of the warm-up are discarded. `events.lost` notifications: 0.

Result: **met**.

## NFR-PERF-08 — `knshd` idle memory under 50 MB

The release `knshd` is started by launchd under a test job (own label, Mach service and home under `/private/tmp`), as `tests/launchd_agent.rs` does. One connection says `hello` and closes; no session is opened. After 70 s idle, `ps -o rss=` is then read 10 times a second apart. MB = 10^6 bytes (stricter than MiB).

| Series | n | min (MB) | p50 | p95 | p99 | max |
| --- | --- | --- | --- | --- | --- | --- |
| knshd RSS at idle | 10 | 8.98 | 8.98 | 8.98 | 8.98 | 8.98 |

- Not measured here: memory after a long busy period. A real `knshd` runs agent lines only for profiles signed after Touch ID or a password, which an unattended run cannot provide.

Result: **met**.

## Open items

- NFR-PERF-02 missed: worst added p95 (supervised p95 − plain p95) is 55.14 ms, not under 15 ms
