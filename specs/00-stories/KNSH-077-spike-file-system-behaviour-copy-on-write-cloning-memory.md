# KNSH-077 — Spike: file-system behaviour: copy-on-write cloning, memory-mapped writes and file-event flushing (C3, C4)

[Phase 3](README.md#phase-3--reverse-and-protect) · [Story index and plan](README.md)

| Phase | Epic | Size | Depends on | Crates | Requirements |
| --- | --- | --- | --- | --- | --- |
| 3 | Spikes | XL (8) | — | throwaway prototype (not merged into `knsh-*`), throwaway prototype | NFR-PERF-06, FR-CKP-01, FR-CKP-24, claim C3, FR-CKP-03, FR-CKP-04, FR-CKP-05, claim C4 |

**Description.** Merged from *Spike: per-file copy-on-write cloning speed and memory-mapped writes (C3)* and *Spike: file-event flushing with concurrent writers (C4)*: they are done and validated together because both claims are measured on the same checkpoint test rig.

*Spike: per-file copy-on-write cloning speed and memory-mapped writes (C3).* As the checkpoint engineer, I want measured evidence that per-file APFS cloning of a large root is
fast enough, and that a clone taken while another process holds unflushed memory-mapped writes behaves
predictably, so that the shadow design (FR-CKP-01) and the possibly-torn rule (FR-CKP-24) rest on facts.
Scope: a timed prototype using `clonefile(2)` file by file over a generated 100,000-file tree on Apple silicon,
on macOS 14, 15 and current; a test with a writer that maps a file, writes without `msync`, and a concurrent clone.
Out of scope: production code, FSEvents (covered in this story).

*Spike: file-event flushing with concurrent writers (C4).* As the checkpoint engineer, I want to know whether flushing FSEvents
(`FSEventStreamFlushSync`) at the end of a supervised line reliably delivers writes made milliseconds earlier by
another process, and how dropped-event flags surface, so that attribution (FR-CKP-05) and the uncertain marking
(FR-CKP-04) can be built correctly. Scope: a stress test with N concurrent writers, a "line end" marker and a
flush, counting missed and late events; forced overflow to observe `MustScanSubDirs`/dropped flags.
Out of scope: production watcher (KNSH-080).

**Acceptance criteria**
*Spike: per-file copy-on-write cloning speed and memory-mapped writes (C3)*

- [ ] Wall time, CPU time and extra disk usage for cloning a 100,000-file root are recorded per macOS version,
      with the tree shape (file count, size distribution, depth) documented so the run is reproducible.
      *(macOS 26.6.2 recorded; macOS 14 and 15 pending.)*
- [x] The result states whether the < 10 s background target (NFR-PERF-06) holds; if not, it proposes a change
      (e.g. lazy shadowing, directory-level clones) as a decision entry for review, not as silent behaviour.
- [x] Behaviour of a clone taken during unflushed `mmap` writes is documented (what content the clone holds,
      whether `mtime`/size change), with a reproducer script.
- [x] Claim C3 in [../07-testing/verification-claims.md](../07-testing/verification-claims.md) is marked
      verified, failed or partially verified, with the evidence linked.
- [x] Runs that could not be performed here (e.g. an older macOS version) are recorded as **pending**.

*Spike: file-event flushing with concurrent writers (C4)*

- [x] Miss rate and latency distribution of events after a flush are recorded for 1, 4 and 16 concurrent writers.
- [x] The flags reported when the kernel or user-space queue drops events are documented, with the folder scope
      they identify.
- [x] The result states the flush procedure the watcher must use at line end, or records that flushing is not
      sufficient and proposes a fallback (e.g. a bounded rescan of touched folders) as a decision entry.
- [x] Claim C4 is marked verified, failed or partially verified, with evidence.

**Unit tests**
*Spike: per-file copy-on-write cloning speed and memory-mapped writes (C3)*

- None: spike. The reproducer scripts are kept under `spikes/knsh-077-fs/c3/` for re-running.

*Spike: file-event flushing with concurrent writers (C4)*

- None: spike. Reproducer kept under `spikes/knsh-077-fs/c4/`.

**Exit questions**
*Spike: per-file copy-on-write cloning speed and memory-mapped writes (C3)*

- Is per-file cloning within budget, or does the shadow need a different strategy?
- Can a torn memory-mapped write be detected after the fact, or only by observing open/mapped files during the change?
- Does cloning preserve the attributes needed for post-image identity (inode differs by design; size, mtime)?

*Spike: file-event flushing with concurrent writers (C4)*

- After a flush, can we treat the event set as complete for a line, or must every checkpoint near a line boundary be
  considered possibly uncertain?
- Which event flags must trigger a rescan and an `uncertain` mark?

**Results (2026-11-18, macOS 26.6.2, Apple M1 Pro, warm cache).** In
[verification claims](../07-testing/verification-claims.md#file-system-results-knsh-077-c3-c4), harnesses in
[`spikes/knsh-077-fs/`](../../spikes/knsh-077-fs/README.md) (one folder, `c3/` and `c4/`, following the other
spikes' layout), with proposed [decisions](../09-reference/decisions.md) 15 to 17.

- C3, **partially verified**: per-file cloning of 100,000 files takes 11.6–12.4 s on one thread (over the 10 s
  target) and 7.3–7.7 s on 4 threads at normal or utility QoS (within it), but 33–51 s in the background band;
  decision 15 keeps per-file cloning on 4 threads at QoS utility and records a directory-level clone (1.6–1.7 s) as
  a fallback to evaluate. Clones keep size, `mtime`, mode (setuid and setgid cleared), flags and xattrs. A clone holds
  unflushed mapped stores, but memory-mapped writes never change `mtime` or size and clones during continuous stores
  are torn, so "possibly torn" can only be detected by watching open and mapped files during the change
  (decision 17).
- C4, **refuted for a flush alone, verified for a marker procedure**: `FSEventStreamFlushSync` at line end left
  26–99.9% of the line's events undelivered; a marker file in an engine folder plus a flush every millisecond until
  its event arrives left none missing in any round without a drop flag (6.6–9.3 ms p50). 16 concurrent writers cause
  `UserDropped|MustScanSubDirs` on the watched root itself in 68–93% of lines; FSEvents flags accumulate and say
  only that a path may have changed; a live mmap writer produces no event until it exits (decisions 16, 17).
- **Pending:** macOS 14 and 15 (so the first C3 criterion stays open), cold-cache timings, external volumes, `KernelDropped`, writers inside a real envelope.
