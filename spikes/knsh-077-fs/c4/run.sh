#!/bin/bash
# KNSH-077 C4: FSEvents completeness at a line end with 1, 4 and 16 concurrent writers, dropped-event flags,
# root changes and memory-mapped writers. See ../README.md. Usage: c4/run.sh [rounds=100]
set -euo pipefail
. "$(dirname "$0")/../helpers/common.sh"

ROUNDS=${1:-100}
cc_build "$BIN/fsew" "$HERE/c4/fsew.c" -framework CoreServices

# fresh <name>: an empty watched root (and its sibling marker folder) under $OUT/c4.
fresh() {
    rm -rf "$OUT/c4/$1" "$OUT/c4/$1-markers"
    mkdir -p "$OUT/c4/$1"
    echo "$OUT/c4/$1"
}

RUN=$RESULTS/c4-$OSVER-runs.txt
machine >"$RUN"
case_run() { # <writers> <latency> <procedure> [options...]
    local w=$1 lat=$2 proc=$3
    shift 3
    echo "== writers=$w latency=$lat procedure=$proc $*" | tee -a "$RUN" >&2
    limit 900 "$BIN/fsew" run "$(fresh "run-$w-$proc")" "$w" "$ROUNDS" 50 "$lat" "$proc" "$@" | tee -a "$RUN" |
        grep -E '^(expected|clean_rounds|rounds_with)' >&2
    echo >>"$RUN"
}
for w in 1 4 16; do
    case_run "$w" 0.5 flush
    case_run "$w" 0.5 mloop outside
done
case_run 4 0.5 none
case_run 4 0.5 mflush
case_run 4 0.5 marker
case_run 16 0.05 flush
case_run 16 0.05 mloop outside
case_run 16 0.0 mloop outside nodefer

OV=$RESULTS/c4-$OSVER-overflow.txt
machine >"$OV"
for args in "16 20000 10" "16 20000 0" "1 2000 0"; do
    set -- $args
    echo "== overflow writers=$1 ops=$2 block_s=$3" >>"$OV"
    limit 900 "$BIN/fsew" overflow "$(fresh overflow)" "$1" "$2" "$3" >>"$OV"
    echo >>"$OV"
done

{ machine; limit 60 "$BIN/fsew" rootchange "$(fresh rootchange)"; } >"$RESULTS/c4-$OSVER-rootchange.txt"
{ machine; limit 900 "$BIN/fsew" mmap "$(fresh mmap)" 40; } >"$RESULTS/c4-$OSVER-mmap.txt"
echo "results in $RESULTS/c4-$OSVER-*" >&2
