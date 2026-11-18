# KNSH-079 — Shadow builder

[Phase 3](README.md#phase-3--reverse-and-protect) · [Story index and plan](README.md)

| Phase | Epic | Size | Depends on | Crates | Requirements |
| --- | --- | --- | --- | --- | --- |
| 3 | Checkpoints | L (5) | [KNSH-078](KNSH-078-apfs-platform-services-and-checkpoint-storage-layout.md) | `knsh-checkpoint`, `knshd` | FR-CKP-01, FR-CKP-02, NFR-PERF-06 |

**Description.** As an agent session, I want a shadow of each checkpoint root built in the background when the
session starts, so that pre-images exist for any later change. Scope: background clone of each root file by file,
progress tracking, excluded paths skipped, waiting or `-32010` for lines that touch a root before its shadow is
complete when `checkpoints.required = true`. Out of scope: keeping the shadow current (KNSH-080).

**Acceptance criteria**
- [x] Starting an agent session with checkpoint roots starts one background shadow build per root without blocking
      session start.
- [x] Excluded paths (`checkpoints.exclude`, default `node_modules`, `target`, `.venv`, `dist`, `build`) are not
      shadowed.
- [x] While `required = true` and the shadow is incomplete, a line that touches the root waits; if the caller does
      not wait, the call fails with `-32010` and `data` carries `root` and progress (FR-CKP-02).
- [x] With `required = false`, lines run immediately and their records say the change was not protected.
- [x] A shadow build failure is reported (capability for that root becomes `none`) and, with `required = true`,
      lines touching the root fail closed rather than run unprotected.
- [x] Symlinks are not followed out of the root; special files are skipped and listed.

**Unit tests**
- `line_touching_root_waits_until_shadow_complete` (FR-CKP-02)
- `non_waiting_caller_gets_minus_32010_with_progress` (FR-CKP-02)
- `excluded_folders_are_not_shadowed` (FR-CKP-31)
- `shadow_failure_with_required_true_denies_line` (fail closed)
- `symlink_pointing_outside_root_is_not_followed`

**Integration tests**
- Build a shadow of a 10,000-file temp tree through the real clone service and compare file contents.

**Notes**

- **The caller's choice (FR-CKP-02).** `exec.run` and `exec.start` take `checkpoint_wait` (default `true`); `false`
  makes a line that would wait fail with `-32010` instead. `data.progress` is `{files, folders, folders_pending}`
  ([errors](../06-api/errors.md)).
- **Which lines touch a root.** Its `cwd` is in the root, or `fs.write` holds a path in or above the root
  ([checkpoints](../03-functional-requirements/checkpoints.md#taking-checkpoints)).
- **Records.** A new record field, `unprotected` (`{root, reason}`), stored from record schema version 2.
- **Plain-copy roots** get no shadow yet and are reported `none` (honest capabilities), so with `required = true`
  their lines are denied. Removing a shadow when its session ends is left to retention (KNSH-087).

**Results (2026-11-18, macOS 26.6.2).** `knsh_checkpoint::shadow` (builder, gate, `line_touches_root`),
`knsh_checkpoint::testing::FakeTree`, `knshd::shadows` (registry, `hello`), the supervisor gate, the record field
and migration. Observed: a 10,000-file tree (plus a symlink out of the root, an excluded folder and a FIFO) shadowed
through the real clone service on the home APFS volume in 0.89 s on 4 threads at the utility class (warm cache),
every file identical with its own inode. **Pending:** a 100,000-file root and cold-cache timing (NFR-PERF-06, the
performance validation), macOS 14 and 15, a root on a second APFS volume, and an end-to-end run through a real
`session.start_agent` envelope. Also pending: the walk is by path, so a folder swapped for a symlink during the build
(a racing writer, such as the envelope) is followed for that folder; an `openat`-relative walk with `O_NOFOLLOW` is
needed before restore trusts shadow contents.
