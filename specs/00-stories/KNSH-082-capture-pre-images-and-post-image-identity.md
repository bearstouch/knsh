# KNSH-082 — Capture: pre-images and post-image identity

[Phase 3](README.md#phase-3--reverse-and-protect) · [Story index and plan](README.md)

| Phase | Epic | Size | Depends on | Crates | Requirements |
| --- | --- | --- | --- | --- | --- |
| 3 | Checkpoints | L (5) | [KNSH-081](KNSH-081-change-attribution.md) | `knsh-checkpoint` | FR-CKP-08, FR-CKP-09, FR-CKP-10, FR-CKP-11 |

**Description.** As the checkpoint engine, I want each change's pre-images and post-image identities stored as a
checkpoint, so that undo knows what to restore and when it is safe. Scope: after each line or agent edit, move the
shadow copy into the checkpoint as the pre-image (or a "did not exist" marker), record post-image identity, clone
the new version into the shadow, emit `checkpoint.created`, and fill the record's `files_changed` and
`checkpoint_id`. Out of scope: restore (KNSH-084).

**Acceptance criteria**
- [x] For every changed path, the checkpoint holds the pre-image or a not-existed marker (FR-CKP-08).
- [x] Each path has post-image identity: inode, size, mtime, and a content hash only for files under 64 MB (FR-CKP-09).
- [x] Deleted files are captured with their pre-image and a "deleted" post-image.
- [x] Capture cost is proportional to the number of changed files, not the size of the root (FR-CKP-10).
- [x] `checkpoint.created` is emitted and the record carries `checkpoint_id` and `files_changed` (FR-CKP-11).
- [x] A capture failure leaves the shadow consistent and marks the checkpoint uncertain instead of recording wrong data.

**Unit tests**
- `created_file_records_not_existed_marker` (FR-CKP-08)
- `modified_file_moves_shadow_copy_to_pre_image` (FR-CKP-08)
- `deleted_file_keeps_pre_image` (FR-CKP-08)
- `post_image_identity_has_hash_under_64_mib_only` (FR-CKP-09)
- `capture_touches_only_changed_paths` (FR-CKP-10)
- `capture_failure_marks_checkpoint_uncertain`

**Implementation (KNSH-082).**
- **Watcher.** Before a file's or symlink's shadow copy is replaced or removed it is moved (a rename, never a copy)
  into `held/<session>/<root index>/` in the store and reported with the change as its pre-image; a path the shadow
  did not hold is "did not exist", a folder a folder marker, and a removed folder reports every entry below it. The
  live path's post-image identity (inode, size, mtime, SHA-256 under 64 MiB) is read right after. Failures never
  record wrong data: a copy that cannot be moved is removed and *lost*, a clone that fails puts the copy back, an
  unreadable identity is *unknown*, and paths whose copy was lost are remembered (past 8,192, every missing path is
  *lost*). A holding name left by an earlier run is skipped, never replaced.
- **Captures.** `knsh_checkpoint::capture::Captures`: one checkpoint per edge, begun under the ledger's lock so the
  edge cannot finish before the change is added; first pre-image and last post-image per path; pre-images moved into
  `checkpoints/<checkpoint id>/`; created-then-removed paths dropped; at most 65,536 paths, then uncertain.
- **Wire and record.** `checkpoint.created {checkpoint_id, attribution, record_ids, roots, files_changed,
  uncertain}`; the record's `checkpoint_id` and `files_changed` (at most 256 entries with post-image identity, store
  column present since schema version 1); `exec.run`'s `files_changed` count (null outside protected roots);
  `UncertainReason::CaptureFailed` on checkpoints.
- **Review fixes:** a forgotten orphan past the limit reported "did not exist"; a holding name taken by an earlier run
  destroyed a good pre-image.

**Pending:** an on-disk index of each checkpoint (with the history tree, KNSH-083), retention of checkpoint folders
and sweeping leftover held files (KNSH-087), plain-copy roots. **Known limit:** with sessions sharing a root, a
lagging watcher can capture a change in the next line's checkpoint with an older pre-image (see the checkpoints
spec); fixed by one capturing watcher per root or a peer flush at line start, before undo (KNSH-084).
