# KNSH-087 — Exclusions, retention and sensitive files

[Phase 3](README.md#phase-3--reverse-and-protect) · [Story index and plan](README.md)

| Phase | Epic | Size | Depends on | Crates | Requirements |
| --- | --- | --- | --- | --- | --- |
| 3 | Checkpoints | M (3) | [KNSH-082](KNSH-082-capture-pre-images-and-post-image-identity.md) | `knsh-checkpoint` | FR-CKP-31, FR-CKP-32, FR-CKP-33, FR-CKP-34, NFR-PRIV-07 |

**Description.** As a user, I want checkpoint storage bounded and sensitive pre-images removed quickly, so that
checkpoints do not fill the disk or keep secrets around. Scope: configurable excludes, retention by the first limit
reached, sensitive-pattern expiry, `forget --with-checkpoints`. Out of scope: record retention (phase 1).

**Acceptance criteria**
- [ ] Defaults exclude `node_modules`, `target`, `.venv`, `dist`, `build`; `checkpoints.exclude` overrides them.
- [ ] Retention removes the oldest checkpoints when the first limit is reached: 5 GB of checkpoint data per volume,
      200 checkpoints per root, or 7 days (FR-CKP-32).
- [ ] Pre-images matching `.env*`, `*.pem`, `*.key` or `id_*` are deleted after at most 24 hours (FR-CKP-33).
- [ ] `knsh forget --with-checkpoints` removes the matching checkpoints at once (FR-CKP-34).
- [ ] Removing a checkpoint updates the history tree so redo or undo of removed edges reports "expired", not a crash.

**Unit tests**
- `retention_removes_oldest_after_200_checkpoints_per_root` (FR-CKP-32)
- `retention_removes_checkpoints_older_than_7_days` (FR-CKP-32)
- `retention_enforces_5_gb_per_volume` (FR-CKP-32)
- `sensitive_pre_image_deleted_after_24_hours` (FR-CKP-33)
- `forget_with_checkpoints_removes_immediately` (FR-CKP-34)
- `undo_of_expired_edge_reports_expired`
