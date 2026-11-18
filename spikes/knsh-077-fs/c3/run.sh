#!/bin/bash
# KNSH-077 C3: per-file copy-on-write shadow timings of a 100,000-file root, clone attributes, and clones taken
# during unflushed memory-mapped writes. See ../README.md. Usage: c3/run.sh [reps=3] [--regen]
set -euo pipefail
. "$(dirname "$0")/../helpers/common.sh"

REPS=${1:-3}
SRC=$HERE/c3
cc_build "$BIN/gentree" "$SRC/gentree.c"
cc_build "$BIN/clonetree" "$SRC/clonetree.c"
cc_build "$BIN/mmapclone" "$SRC/mmapclone.c"

TREE=$OUT/tree
SHADOW=$OUT/shadow
[ "${2:-}" = --regen ] && rm -rf "$TREE"
rm -rf "$SHADOW"
if [ ! -d "$TREE" ]; then
    echo "generating $TREE" >&2
    "$BIN/gentree" "$TREE" 100000 77 >"$OUT/tree.shape"
fi
{ machine; echo "# generator: gentree <dest> 100000 77"; cat "$OUT/tree.shape"; } >"$RESULTS/c3-$OSVER-tree.txt"

TSV=$RESULTS/c3-$OSVER-timings.tsv
{
    machine
    echo "# page cache warm (the tree was read or written shortly before; purge needs root, so cold runs are not measured)"
    echo -e "rep\tmode\tthreads\tpriority\twall_s\tuser_s\tsys_s\tfiles\tdirs\tfree_before\tfree_after\textra_bytes"
} >"$TSV"

for rep in $(seq 1 "$REPS"); do
    for variant in "file 1" "file 4" "file 8" "file 1 bg" "file 4 bg" "file 4 utility" "file 8 utility" "dir" "dir bg" "dir utility"; do
        set -- $variant
        mode=$1
        shift
        if [ "$mode" = dir ]; then
            line=$(limit 600 "$BIN/clonetree" dir "$TREE" "$SHADOW" "$@")
        else
            line=$(limit 600 "$BIN/clonetree" file "$TREE" "$SHADOW" "$@")
        fi
        echo -e "$rep\t$line" | tee -a "$TSV" >&2
        if [ "$rep" = 1 ] && { [ "$variant" = "file 4" ] || [ "$variant" = dir ]; }; then
            { machine; echo "# clonetree verify <tree> <shadow> after: $variant"; "$BIN/clonetree" verify "$TREE" "$SHADOW"; } \
                >"$RESULTS/c3-$OSVER-verify-${mode}.txt"
        fi
        echo -e "$rep\t$(limit 600 "$BIN/clonetree" rm "$SHADOW")" | tee -a "$TSV" >&2
    done
done

mkdir -p "$OUT/attrs" "$OUT/mmap"
{ machine; "$BIN/clonetree" attrs "$OUT/attrs"; } | scrub >"$RESULTS/c3-$OSVER-attrs.txt"
{ machine; limit 900 "$BIN/mmapclone" "$OUT/mmap" 40; } | scrub >"$RESULTS/c3-$OSVER-mmap.txt"
echo "results in $RESULTS/c3-$OSVER-*" >&2
