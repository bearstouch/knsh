# KNSH-077 spike: file-system behaviour (C3, C4)

Throwaway prototypes that measure what the checkpoint engine relies on: how fast a copy-on-write shadow of a
100,000-file root can be built and what a clone holds while another process has unflushed memory-mapped writes (C3),
and whether flushing FSEvents at the end of a supervised line delivers the writes other processes made milliseconds
earlier, and how dropped events surface (C4). The results feed APFS services (KNSH-078), the shadow builder
(KNSH-079), the watcher (KNSH-080), attribution (KNSH-081) and capture (KNSH-082). Nothing here is shipped, built by
Cargo or called by the product.

**The written result is in [verification claims](../../specs/07-testing/verification-claims.md#file-system-results-knsh-077-c3-c4)**,
with proposed decisions 15 to 17 in [decisions](../../specs/09-reference/decisions.md).

## Files

| Path | What it is |
| --- | --- |
| `c3/run.sh` | C3: builds the tools, generates the tree once, times every shadow strategy `reps` times (default 3), verifies two shadows, then runs the attribute and memory-mapped cases |
| `c3/gentree.c` | Deterministic 100,000-file tree (seed 77): fan-out 5 to depth 5 (3,906 folders), 1–50 files per folder, sizes from 0 B to 4 MiB in six log-uniform buckets (2.76 GiB). The shape is in its header and in `results/c3-<ver>-tree.txt` |
| `c3/clonetree.c` | `file` (per-file `clonefileat(2)`, folders recreated, 1–N threads), `dir` (one `clonefile(2)` of the root), `rm` (`removefile(3)`), each optionally in the Darwin background band (`bg`) or at QoS utility (`utility`), with wall, user and system time and free space before and after; `verify` (attributes of every file, content of every 50th); `attrs` (setuid, flags, xattrs, hard link, timestamps on one file) |
| `c3/mmapclone.c` | Clones a file while a separate process holds unflushed `MAP_SHARED` stores: content and `stat` of source and clone before and after `msync`, after the writer exits and for 40 s after; a file extended by `ftruncate`; torn clones under a continuous mmap or `pwrite` writer; and whether the writer can be found (`proc_listpidspath`, descriptors, mapped regions) |
| `c4/run.sh` | C4: every line-end procedure with 1, 4 and 16 writers, the overflow cases, a renamed root and memory-mapped writers |
| `c4/fsew.c` | One FSEvents stream (file events) and its writers, spawned as separate processes. `run` (one round = one line), `overflow`, `rootchange`, `mmap`; see its header |
| `helpers/common.sh` | `cc_build`, `limit` (hard time limit), `machine` (the header of every result file), `scrub` (home and user name to placeholders) |
| `results/` | Results per macOS version: `c3-<ver>-{tree,timings,verify-*,attrs,mmap}`, `c4-<ver>-{runs,overflow,rootchange,mmap}` |

## Running

Run as a normal user, never with `sudo`, on a quiet machine (other disk activity shows up in the timings and in the
free-space deltas). Work files go to `~/.cache/knsh-spike-077.noindex/` (override with `KNSH_SPIKE_077_DIR`; it must
be on the APFS volume under test): a `*.noindex` folder is skipped by Spotlight, which would otherwise index 100,000
files during the timings. The tree takes about 2.8 GiB and is kept between runs; delete the folder when done.

```sh
spikes/knsh-077-fs/c3/run.sh            # about 20 min; first run also generates the tree
spikes/knsh-077-fs/c3/run.sh 3 --regen  # regenerate the tree first
spikes/knsh-077-fs/c4/run.sh            # about 15 min; 100 rounds per case
spikes/knsh-077-fs/c4/run.sh 20         # quicker, 20 rounds per case
```

The page cache is warm in every timing: `purge` needs root. Cold-cache timings are pending.

## Still to do

- Rerun both on macOS 14 and 15 (C3's first criterion asks for each version).
- Cold-cache shadow timings (needs `sudo purge` between runs, or a reboot).
- A root on an external or slower APFS volume, and a root with very large or highly fragmented files.
