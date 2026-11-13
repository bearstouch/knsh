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
- [ ] Starting an agent session with checkpoint roots starts one background shadow build per root without blocking
      session start.
- [ ] Excluded paths (`checkpoints.exclude`, default `node_modules`, `target`, `.venv`, `dist`, `build`) are not
      shadowed.
- [ ] While `required = true` and the shadow is incomplete, a line that touches the root waits; if the caller does
      not wait, the call fails with `-32010` and `data` carries `root` and progress (FR-CKP-02).
- [ ] With `required = false`, lines run immediately and their records say the change was not protected.
- [ ] A shadow build failure is reported (capability for that root becomes `none`) and, with `required = true`,
      lines touching the root fail closed rather than run unprotected.
- [ ] Symlinks are not followed out of the root; special files are skipped and listed.

**Unit tests**
- `line_touching_root_waits_until_shadow_complete` (FR-CKP-02)
- `non_waiting_caller_gets_minus_32010_with_progress` (FR-CKP-02)
- `excluded_folders_are_not_shadowed` (FR-CKP-31)
- `shadow_failure_with_required_true_denies_line` (fail closed)
- `symlink_pointing_outside_root_is_not_followed`

**Integration tests**
- Build a shadow of a 10,000-file temp tree through the real clone service and compare file contents.
