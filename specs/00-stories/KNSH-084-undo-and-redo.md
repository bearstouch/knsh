# KNSH-084 — Undo and redo

[Phase 3](README.md#phase-3--reverse-and-protect) · [Story index and plan](README.md)

| Phase | Epic | Size | Depends on | Crates | Requirements |
| --- | --- | --- | --- | --- | --- |
| 3 | Checkpoints | XL (8) | [KNSH-082](KNSH-082-capture-pre-images-and-post-image-identity.md), [KNSH-083](KNSH-083-history-tree.md) | `knsh-checkpoint` | FR-CKP-20, FR-CKP-21, FR-CKP-22, FR-CKP-23, FR-CKP-25, FR-CKP-31, FR-CKP-36 |

**Description.** As a user or agent, I want to undo and redo a change, restoring files only when it is safe, so that
mistakes can be reversed without overwriting work the engine did not record. Scope: identity check per path,
conflicts with `-32004`, in-place restore preserving inode, hard links and open descriptors, mtime set to now,
saving current versions before undo so redo is possible, excluded paths listed as not restored,
`checkpoint.restored`, and `force` handling (only via `user.sock` and the authority).
Out of scope: torn-file detection (KNSH-085), `restore` to a state (KNSH-086), endpoint wiring (KNSH-088).

**Acceptance criteria**
- [x] A path is restored only if the live file matches its recorded post-image identity; otherwise it is a conflict
      and nothing changes for that change (FR-CKP-20).
- [x] Conflicts return `-32004` with the conflicting paths and reasons; no partial restore happens.
- [x] Restore writes old contents into the existing file; inode and hard links stay the same (FR-CKP-22).
- [x] The restored file's mtime is set to now (FR-CKP-23).
- [x] Before undoing, the current versions are saved so redo is possible.
- [x] Excluded paths are listed in the result as not restored (FR-CKP-31).
- [x] The engine API accepts `force` only from callers flagged as user or authority; an agent-scoped call with
      `force` is rejected (FR-CKP-21).
- [x] `checkpoint.restored` is emitted (FR-CKP-25).
- [x] An undo of a change flagged irreversible restores its files and lists what cannot be undone (FR-CKP-36).
- [x] A failure in the middle of a restore leaves every file either fully old or fully new, never mixed.

**Unit tests**
- `undo_restores_when_identity_matches` (FR-CKP-20)
- `undo_is_conflict_when_file_changed_after_capture` (FR-CKP-20)
- `conflict_changes_nothing_across_all_paths` (atomicity)
- `restore_preserves_inode_and_hard_links` (FR-CKP-22)
- `restore_sets_mtime_to_now` (FR-CKP-23)
- `redo_after_undo_restores_saved_versions`
- `force_rejected_for_agent_scoped_caller` (FR-CKP-21)
- `excluded_paths_listed_as_not_restored` (FR-CKP-31)

**Integration tests**
- Undo of a real `sed -i` edit while another process holds the file open: the descriptor still reads the restored
  contents.

**Notes**
- Atomic multi-file restore on a single volume needs a journal; describe the approach in the module docs.
- Implemented in `knsh_checkpoint::{restore, undo}` (journal approach in the `restore` module docs). The engine API
  enforces `force` and session scope; the endpoints that expose it are KNSH-088, and calling `recover_restores` at
  `knshd` start is wired there too (**pending**).
