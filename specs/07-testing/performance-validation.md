# Performance validation

Targets ([performance](../04-non-functional-requirements/performance.md)) are validated on an Apple silicon laptop. The shadow figure especially is unproven.

| Target | Measurement |
| --- | --- |
| Supervisor decision p95 < 5 ms | Time from receive to verdict, with no hooks and no authority, over the corpus |
| Spawn overhead p95 < 15 ms | Supervised line vs plain `bash -c` for trivial commands (`true`, `echo`) |
| Hooks | Per-record hook time, bounded by the 2 s timeout |
| Human start-up < 50 ms | Time to first prompt with and without `knsh` integration mode |
| Checkpoint work < 20 ms + 1 ms per changed file | After lines changing 0, 1, 100 and 10,000 files |
| Initial shadow of 100,000 files < 10 s | Per-file CoW clone of a 100,000-file root, background |
| Event delivery p95 < 10 ms | Emit to subscriber receipt |
| Idle memory < 50 MB | `knshd` RSS after idle with no sessions |

## Start-up benchmark (NFR-PERF-04, KNSH-024)

`scripts/startup-bench.sh` builds a release `knsh` and runs `xtask`'s `startup_bench`. It times, on a
pseudo-terminal (`script -q /dev/null <shell>`), from spawn to the first prompt of three variants: plain `/bin/zsh -i`,
and `knsh` hosting zsh with human recording off and on. Each variant uses a temporary `HOME` whose `.zshrc` only sets a
marker prompt carrying `$KNSH_RECORDING`, so a run that is not in the recording state it claims aborts the benchmark.
Variants are interleaved in a rotating order; warm-up rounds are discarded. Added time is the `knsh` percentile minus
the plain zsh percentile (nearest rank). Recording on runs with no `knshd` listening: `knsh` reaches `knshd` only from a
worker thread after the shell has started (NFR-REL-02), so the daemon is off the path to the first prompt.

Results go to `.build/startup-bench/<UTC stamp>/` (`report.md` with the machine, `samples.csv`). The script exits
non-zero, and the report lists an open item, when the target is missed or the machine is not an Apple silicon Mac.

| Date | Machine | Commit | Runs | Added p95, recording off | Added p95, recording on | Result |
| --- | --- | --- | --- | --- | --- | --- |
| 2026-11-14 | MacBookPro18,3, Apple M1 Pro (8 CPUs, 16 GiB), macOS 26.6.2, zsh 5.9 | 7f37751 + KNSH-024 (uncommitted) | 100 (+3 warm-up) | 8.5 ms (plain p95 21.3, knsh 29.8) | 8.7 ms (knsh 30.0) | **Met** (< 50 ms) |

Not yet measured: the cost of `knsh` hosting **bash** (the target names zsh first; bash start-up is not benchmarked),
older macOS versions, and a cold first start after boot (all runs here are warm).

## Phase 2 qualification (NFR-PERF-01, -02, -03, -07, -08; KNSH-076)

`scripts/qualify-phase2.sh perf` builds the workspace in release and runs `qualification::perf::phase_2_performance`
(`crates/knshd/src/qualification/perf.rs`), an ignored test that drives the threat-model suite's miniature `knshd`
(the parts `main` wires: record store, event hub, profile loader, supervisor, `knsh-exec`, proxy and the real
sockets). A real `knshd` runs agent lines only for profiles signed after Touch ID, so an unattended run cannot use
one, except for idle memory, which needs no session.

| Target | How it is measured |
| --- | --- |
| Decision (NFR-PERF-01) | Every line of the agent-command corpus, under an allow-everything profile and a deny-everything one, with no hooks and no authority. An allowed line is timed until the supervisor hands it to the spawner (a stub that starts nothing); a refused line until it is answered, record write included, which is an upper bound. A new session every round, so the repeated-denial limiter never shortens a refusal. The record's own `latency_ms` is reported as a cross-check |
| Spawn overhead (NFR-PERF-02) | A C timer (`posix_spawn` to `waitpid`, monotonic clock) runs `true` and `echo hi` repeatedly: inside a real envelope as `"$SHELL" -c <line>` (the `knsh` client, `agent.sock`, `exec.run`, decision, record, profile file, `knsh-exec`, `sandbox-exec`, `bash`), and outside any envelope as `/bin/bash -c <line>`. Overhead = p95 difference. Diagnostic series, not judged: `sandbox-exec` alone, and the supervisor's path in-process without the client |
| Hooks (NFR-PERF-03) | Three hooks run by the real hook runner (immediate, 100 ms, hanging past a 500 ms timeout). Each record must list its hook with the expected result and a `duration_ms` no larger than the timeout; a line whose hook hangs must be decided within its timeout plus 500 ms (the runner's 250 ms drain and process exit) |
| Event delivery (NFR-PERF-07) | A subscriber on the real `user.sock` (`hello`, `events.subscribe`) while the corpus runs: system clock when a notification has been read and parsed, minus its `ts`, which the hub stamps with the system clock as it publishes. Any `events.lost` fails the run |
| Idle memory (NFR-PERF-08) | The release `knshd` started by launchd under a test job (own label, Mach service and home under `/private/tmp`). One `hello`, then no connection and no session; after the idle period (`KNSH_QUALIFICATION_IDLE_S`, default 60 s) `ps -o rss=` is read 10 times a second apart. MB = 10^6 bytes |

Percentiles are nearest rank. Every bound is strict ("under"). The report (`performance.md`: machine, macOS version,
commit, build, every series' n/min/p50/p95/p99/max, open items) and the raw samples (`performance-samples.csv`) go to
`.build/qualification/<UTC stamp>/`; the release's copy is stored in [qualification/](qualification/). A miss is
reported with its figure and listed as an open item; the script then exits non-zero.

| Date | Machine | Commit | Decision p95 | Spawn overhead p95 | Hooks | Event delivery p95 | Idle RSS | Report |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 2026-11-18 | MacBookPro18,3, Apple M1 Pro (8 CPUs, 16 GiB), macOS 26.6.2 (25G83), release build | 4dc927c | 0.29 ms: **met** | 55.14 ms added (`true`; `echo hi` 53.77 ms): **missed** | **met** (hanging hook's line decided ≤ 507.19 ms at a 500 ms timeout) | 0.05 ms: **met** | 8.98 MB: **met** | [qualification/](qualification/phase-2-performance-2026-11-18.md) |

**Open: NFR-PERF-02 is missed.** A supervised trivial line adds about 38 ms at p50 and 54–55 ms at p95 over plain
`bash -c`. The diagnostic series place the cost in the supervisor's spawn path, not in the client:
the supervisor alone (in-process, no `knsh` client or socket) takes 34.0 ms at p50 and 51.2 ms at p95 for `true`,
of which `sandbox-exec` with an allow-everything profile is 10.0 ms at p50. The remainder is the line's own
bookkeeping before and after `sandbox-exec` (proxy credentials, profile file written and checked, record writes,
`knsh-exec`, reaping), still to be broken down. Not measured: memory after a long busy period (a real `knshd` runs
agent lines only for signed profiles), and machines other than this one.

Related verification claims: per-file copy-on-write cloning speed, and FSEvents flushing ([verification-claims.md](verification-claims.md)).

## Redaction throughput (FR-SEC-10, KNSH-090)

`knsh-core`'s ignored test `redaction::tests::redaction_throughput` streams 16 MiB through one `RedactStream` in
64 KiB chunks (a pipe read) with 16 secrets of 38 bytes, so 112 raw and 48 decoded patterns. It measures two inputs:
build-log text with one secret every 64 KiB, and random bytes. Run it with `cargo test -p knsh-core --release --lib
-- --ignored --nocapture redaction_throughput`. There is no target yet: output is capped at 1 MB per stream
(FR-REC-06), so at these rates redacting a full cap takes about 10 ms.

| Date | Machine | Commit | Build log | Random bytes |
| --- | --- | --- | --- | --- |
| 2026-11-19 | MacBookPro18,3, Apple M1 Pro, macOS 26.6.2, release build | b0c4ae6 + KNSH-090 (uncommitted) | 93 MiB/s | 114 MiB/s |
