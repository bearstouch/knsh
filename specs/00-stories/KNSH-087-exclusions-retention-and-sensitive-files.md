# KNSH-087 — Exclusions, retention and sensitive files

[Phase 3](README.md#phase-3--reverse-and-protect) · [Story index and plan](README.md)

| Phase | Epic | Size | Depends on | Crates | Requirements |
| --- | --- | --- | --- | --- | --- |
| 3 | Checkpoints | M (3) | [KNSH-082](KNSH-082-capture-pre-images-and-post-image-identity.md) | `knsh-checkpoint` | FR-CKP-31, FR-CKP-32, FR-CKP-33, FR-CKP-34, NFR-PRIV-07 |

**Description.** As a user, I want checkpoint storage bounded and sensitive pre-images removed quickly, so that
checkpoints do not fill the disk or keep secrets around. Scope: configurable excludes, retention by the first limit
reached, sensitive-pattern expiry, `forget --with-checkpoints`. Out of scope: record retention (phase 1).

**Acceptance criteria**
- [x] Defaults exclude `node_modules`, `target`, `.venv`, `dist`, `build`; `checkpoints.exclude` overrides them.
- [x] Retention removes the oldest checkpoints when the first limit is reached: 5 GB of checkpoint data per volume,
      200 checkpoints per root, or 7 days (FR-CKP-32). Observed in `knsh-checkpoint` unit tests (`History::retain`;
      the 5 GB limit with scaled-down bytes); running the sweep in `knshd` is pending (KNSH-088).
- [x] Pre-images matching `.env*`, `*.pem`, `*.key` or `id_*` are deleted after at most 24 hours (FR-CKP-33).
      Observed in unit tests; each sweep returns when the next is due, which `knshd` must honour (pending, KNSH-088).
- [x] `knsh forget --with-checkpoints` removes the matching checkpoints at once (FR-CKP-34). The removal
      (`History::forget`) is implemented and tested; `records.forget` calls it since KNSH-088.
- [x] Removing a checkpoint updates the history tree so redo or undo of removed edges reports "expired", not a crash.

**Implementation notes.** `knsh_core::HistoryTree::expire` and `HistoryError::Expired`; `knsh_checkpoint::retention`
(`Retention`, `Forget`, `Swept`, `History::retain`, `History::forget`). Pending beyond KNSH-088: removing shadows,
holding and marker folders when their session ends, and sweeping files left in a store by a failed removal.

**Unit tests**
- `retention_removes_oldest_after_200_checkpoints_per_root` (FR-CKP-32)
- `retention_removes_checkpoints_older_than_7_days` (FR-CKP-32)
- `retention_enforces_5_gb_per_volume` (FR-CKP-32)
- `sensitive_pre_image_deleted_after_24_hours` (FR-CKP-33)
- `forget_with_checkpoints_removes_immediately` (FR-CKP-34)
- `undo_of_expired_edge_reports_expired`
- `forget_scrubs_a_revert_whose_change_is_gone` (FR-CKP-34, from the independent review)
- `forget_since_selects_a_change_stepped_back_over_after_the_instant` (FR-CKP-34)
- `agent_of_another_session_is_refused_before_expiry_is_reported` (agent scope, KNSH-084)
