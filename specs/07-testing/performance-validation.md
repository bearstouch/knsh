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

Related verification claims: per-file copy-on-write cloning speed, and FSEvents flushing ([verification-claims.md](verification-claims.md)).
