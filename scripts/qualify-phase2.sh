#!/usr/bin/env bash
# Phase 2 qualification (KNSH-076): performance targets and the developer-tool compatibility list.
#
#   scripts/qualify-phase2.sh [perf|tools]...     (default: both, in that order)
#
# Builds the workspace in release (the binaries that ship, and knsh-exec, knsh and knshd beside the test binary),
# then runs the ignored qualification tests in crates/knshd/src/qualification/ one at a time, so no measurement
# shares the machine with another. Reports go to .build/qualification/<UTC stamp>/:
#
#   performance.md, performance-samples.csv   NFR-PERF-01, -02, -03, -07, -08 (specs/07-testing/performance-validation.md)
#   tools.md                                  the developer-tool list (specs/08-integrations/developer-tools.md)
#
# and a copy at .build/qualification/latest/. Store the release's copy under specs/07-testing/qualification/.
#
# Settings: KNSH_QUALIFICATION_ROUNDS (timed rounds, default 5), KNSH_QUALIFICATION_IDLE_S (knshd idle period before
# its memory is read, default 60).
#
# Needs: an Apple silicon Mac with a GUI login session (idle memory loads a test launchd job into gui/<uid>, never
# the user's own agent), the Command Line Tools (`cc`), and for `tools` the network and the tools under test.
#
# Exit status: 0 when every requested run passed; 1 when a performance target was missed or not measured (the report
# lists it as an open item, never as passed), or a run failed. Each report is written before its run fails.
set -euo pipefail

cd "$(dirname "$0")/.."

if [[ "$(uname -s)" != Darwin ]]; then
    echo "qualify-phase2: macOS only" >&2
    exit 2
fi

export CARGO_NET_OFFLINE=true

runs=("$@")
if [[ ${#runs[@]} -eq 0 ]]; then
    runs=(perf tools)
fi
for run in "${runs[@]}"; do
    case "$run" in
        perf | tools) ;;
        *)
            echo "unknown run: $run (known: perf tools)" >&2
            exit 2
            ;;
    esac
done

stamp="$(date -u +%Y%m%dT%H%M%SZ)"
out=".build/qualification/$stamp"
mkdir -p "$out"
export KNSH_QUALIFICATION_DIR="$PWD/$out"

cargo build --release --workspace --offline --locked

status=0
for run in "${runs[@]}"; do
    case "$run" in
        perf) test=qualification::perf::phase_2_performance ;;
        tools) test=qualification::compat::tool_compatibility ;;
    esac
    printf '\n==> %s\n' "$run"
    cargo test --release -p knshd --offline --locked "$test" -- --ignored --exact --nocapture --test-threads=1 \
        || status=1
done

rm -rf .build/qualification/latest
cp -R "$out" .build/qualification/latest
printf '\nReports: %s\n' "$out"
exit "$status"
