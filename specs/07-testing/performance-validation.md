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

Related verification claims: per-file copy-on-write cloning speed, and FSEvents flushing ([verification-claims.md](verification-claims.md)).
