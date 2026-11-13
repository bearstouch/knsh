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
- [ ] For every changed path, the checkpoint holds the pre-image or a not-existed marker (FR-CKP-08).
- [ ] Each path has post-image identity: inode, size, mtime, and a content hash only for files under 64 MB (FR-CKP-09).
- [ ] Deleted files are captured with their pre-image and a "deleted" post-image.
- [ ] Capture cost is proportional to the number of changed files, not the size of the root (FR-CKP-10).
- [ ] `checkpoint.created` is emitted and the record carries `checkpoint_id` and `files_changed` (FR-CKP-11).
- [ ] A capture failure leaves the shadow consistent and marks the checkpoint uncertain instead of recording wrong data.

**Unit tests**
- `created_file_records_not_existed_marker` (FR-CKP-08)
- `modified_file_moves_shadow_copy_to_pre_image` (FR-CKP-08)
- `deleted_file_keeps_pre_image` (FR-CKP-08)
- `post_image_identity_has_hash_under_64_mib_only` (FR-CKP-09)
- `capture_touches_only_changed_paths` (FR-CKP-10)
- `capture_failure_marks_checkpoint_uncertain`
