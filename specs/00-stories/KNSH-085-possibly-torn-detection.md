# KNSH-085 — Possibly-torn detection

[Phase 3](README.md#phase-3--reverse-and-protect) · [Story index and plan](README.md)

| Phase | Epic | Size | Depends on | Crates | Requirements |
| --- | --- | --- | --- | --- | --- |
| 3 | Checkpoints | M (3) | [KNSH-084](KNSH-084-undo-and-redo.md) | `knsh-checkpoint`, `knsh-platform` | FR-CKP-24 |

**Description.** As the checkpoint engine, I want files that were open for writing or memory-mapped during a change,
and SQLite databases with journal files, marked possibly torn, so that they are not restored without `force`.
Scope: detection based on KNSH-077 findings; SQLite detection by `-wal`, `-shm` or `-journal` siblings.
Out of scope: repairing torn files.

**Acceptance criteria**
- [x] A SQLite database with a `-wal`, `-shm` or `-journal` file beside it is marked possibly torn.
- [x] A file detected as open for writing or memory-mapped during the change is marked possibly torn, using the
      method chosen in KNSH-077.
- [x] Undo and redo skip possibly-torn files without `force` and list them with the reason.
- [x] With `force` (user or authority only) the file is restored and the result says it was forced.

**Unit tests**
- `sqlite_with_wal_is_possibly_torn` (FR-CKP-24)
- `mapped_file_is_possibly_torn` (FR-CKP-24)
- `possibly_torn_file_skipped_without_force`
- `forced_restore_of_torn_file_is_reported`

**Notes**
- If KNSH-077 shows mapped writes cannot be detected reliably, record the limit in the checkpoint spec page rather
  than claiming detection.
