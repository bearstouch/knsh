//! Phase 3 performance qualification (KNSH-095): NFR-PERF-05 and NFR-PERF-06 measured on the real platform
//! services (`specs/07-testing/performance-validation.md`, "Phase 3 qualification").
//!
//! - **Checkpoint work after a line (NFR-PERF-05).** A root of 10,000 files (100 folders of 100) is shadowed and
//!   watched as `knshd` does it ([`Rig`] wires the watcher, the attribution ledger, the captures and the history the
//!   way `knshd`'s `shadows` module does). Each line is a `/bin/sh` process in its own process group that appends to
//!   0, 1, 100 or 10,000 of those files. Once the line is reaped, the clock starts, and it stops when the line's end
//!   is done: the marker flush and the worker settling (decision 16), the held-file scan of its process group
//!   (decision 17), the ledger ending the line, its checkpoint finishing and being recorded in the history
//!   (KNSH-088). That is the work the line's answer waits for. A sample counts only if the line closed certain, the
//!   held-file scan checked its processes, and its checkpoint holds exactly the changed files (each pre-image kept,
//!   none possibly torn), is not uncertain, and is in the history; otherwise it is reported **invalid** with its
//!   figure. The target holds when every sample is valid and the largest is under
//!   20 ms + 1 ms per changed file (the requirement names no percentile, so no sample may miss).
//!   The production flush deadline (1 s) caps how long a line waits; a diagnostic configuration with a 60 s deadline
//!   shows the cost when nothing is cut short. It is reported and not judged.
//! - **Initial shadow (NFR-PERF-06).** A root of 100,000 files in 4,000 folders is shadowed by the real builder
//!   (4 threads at `QoS` utility, decision 15), timed by the builder's own monotonic clock, several times. With
//!   `KNSH_BENCH_PURGE=1` each run is also repeated after `sudo -n /usr/sbin/purge` (cold cache); without it the cold
//!   cache stays **not measured**. Every run must be under 10 s.
//!
//! Run it with `scripts/qualify-phase3.sh` (one command; builds in release, no network). Settings:
//! `KNSH_BENCH_ROUNDS` (lines per size, default 20), `KNSH_BENCH_ROUNDS_LARGE` (lines of 10,000 files, default 5),
//! `KNSH_BENCH_SHADOW_RUNS` (default 3), `KNSH_BENCH_PURGE`, `KNSH_BENCH_DIR` (working folder, which decides the
//! volume; default `.build/phase3-work` in the workspace) and `KNSH_QUALIFICATION_DIR` (where the report goes).
//!
//! Writes `phase-3-performance.md` and `phase-3-performance-samples.csv`, prints the report, and exits 1 when a
//! target is missed or not measured (honesty rule: a miss is reported with its figure, never as a pass).

#[cfg(target_os = "macos")]
mod bench;

#[cfg(target_os = "macos")]
fn main() -> std::process::ExitCode {
    bench::main()
}

#[cfg(not(target_os = "macos"))]
fn main() -> std::process::ExitCode {
    eprintln!("phase3: macOS only");
    std::process::ExitCode::from(2)
}
