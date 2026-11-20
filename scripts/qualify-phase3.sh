#!/usr/bin/env bash
# Phase 3 performance qualification (KNSH-095): checkpoint work after a line (NFR-PERF-05) and the initial shadow of
# a 100,000-file root (NFR-PERF-06), on the real platform services.
#
#   scripts/qualify-phase3.sh
#
# Runs knsh-checkpoint's `phase3` benchmark (crates/knsh-checkpoint/benches/phase3/) in release, offline. It works in
# .build/phase3-work/ (removed as it goes), so it measures the volume the checkout is on, which must be APFS; set
# KNSH_BENCH_DIR to measure another one. The report goes to .build/qualification/<UTC stamp>/:
#
#   phase-3-performance.md, phase-3-performance-samples.csv   (specs/07-testing/performance-validation.md)
#
# and a copy at .build/qualification/latest-phase3/. Store the release's copy under specs/07-testing/qualification/.
#
# Settings: KNSH_BENCH_ROUNDS (lines per size, default 20), KNSH_BENCH_ROUNDS_LARGE (lines of 10,000 files, default
# 5), KNSH_BENCH_SHADOW_RUNS (default 3), KNSH_BENCH_PURGE=1 (also time each shadow after `sudo -n /usr/sbin/purge`,
# a cold cache; needs a cached sudo ticket, run `sudo -v` first), KNSH_BENCH_DIR.
#
# Needs: an Apple silicon Mac on macOS 14 or later, about 1 GB free on the measured volume, no network.
#
# Exit status: 2 when not on macOS; 0 when every target was met; 1 when one was missed or not measured (the report lists it as an open
# item, never as passed), or the run failed. The report is written before the exit.
set -euo pipefail

cd "$(dirname "$0")/.."

if [[ "$(uname -s)" != Darwin ]]; then
    echo "qualify-phase3: macOS only" >&2
    exit 2
fi

export CARGO_NET_OFFLINE=true

stamp="$(date -u +%Y%m%dT%H%M%SZ)"
out=".build/qualification/$stamp"
mkdir -p "$out"
export KNSH_QUALIFICATION_DIR="$PWD/$out"
# cargo runs the bench from the crate's folder: a relative working folder is taken from here instead.
if [[ -n "${KNSH_BENCH_DIR:-}" && "$KNSH_BENCH_DIR" != /* ]]; then
    export KNSH_BENCH_DIR="$PWD/$KNSH_BENCH_DIR"
fi

status=0
cargo bench -p knsh-checkpoint --bench phase3 --offline --locked || status=1

if [[ -f "$out/phase-3-performance.md" ]]; then
    rm -rf .build/qualification/latest-phase3
    cp -R "$out" .build/qualification/latest-phase3
fi
printf '\nReport: %s\n' "$out"
exit "$status"
