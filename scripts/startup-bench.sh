#!/usr/bin/env bash
# Start-up benchmark for integration mode (KNSH-024, NFR-PERF-04).
#
#   scripts/startup-bench.sh [--runs <n>] [--warmup <n>]
#
# Builds a release knsh, then times the first prompt of plain /bin/zsh and of knsh-hosted
# zsh with recording off and on, on a pseudo-terminal, in a temporary HOME (never the
# user's own). Results go to .build/startup-bench/<UTC stamp>/ (report.md, samples.csv)
# and .build/startup-bench/latest.md. Method: specs/07-testing/performance-validation.md.
#
# Exit status: 0 when knsh adds under 50 ms at p95 on an Apple silicon Mac; 1 when it does
# not, or the machine does not qualify (recorded as an open item in the report); 2 on a
# usage error; 3 when the benchmark itself failed. macOS only.
set -euo pipefail

cd "$(dirname "$0")/.."

if [[ "$(uname -s)" != Darwin ]]; then
    echo "startup-bench: macOS only (integration mode is measured on an Apple silicon Mac)" >&2
    exit 2
fi

export CARGO_NET_OFFLINE=true

# The shipped profile: what a user's shell starts. The benchmark binary itself is dev-only.
cargo build --release --offline --locked -p knsh -p xtask --bin knsh --bin startup_bench

exec target/release/startup_bench --knsh target/release/knsh --out .build/startup-bench "$@"
