# KNSH-011 — Engine directories, permissions and backup exclusion

[Phase 1](README.md#phase-1--observe-advisory) · [Story index and plan](README.md)

| Phase | Epic | Size | Depends on | Crates | Requirements |
| --- | --- | --- | --- | --- | --- |
| 1 | Daemon | S (2) | [KNSH-007](KNSH-007-platform-interface-and-test-fakes.md) | `knsh-platform`, `knshd` | NFR-PRIV-04, NFR-SEC-08, [file locations](../09-reference/file-locations.md) |

**Description.** As a user, I want the engine's data kept private and out of Spotlight and Time Machine, so that
records never leak through indexing or backups. Create `~/Library/Application Support/knsh/` (with `run/` and
`checkpoints/`) and `~/.config/knsh/` on first use, owner-only. Out of scope: checkpoints on other volumes (phase 3).

**Acceptance criteria**
- [ ] Directories are created with mode 0700, files with 0600; existing directories with wider modes are tightened,
      and a directory owned by another user is refused with an error (never used).
- [ ] Engine data directories are excluded from Spotlight and Time Machine; exclusion is verified after creation.
- [ ] Paths come from one module (no path literals elsewhere), so later profile stories can deny them as a set.
- [ ] Creation is idempotent and safe if two processes race.

**Unit tests**
- `creates_engine_dirs_owner_only` — 0700/0600 (fake fs).
- `tightens_existing_wide_permissions` — NFR-SEC-08.
- `refuses_directory_owned_by_other_user` — fail closed.
- `engine_paths_listed_in_one_place` — the path set used for fixed denies is complete.

**Integration tests**
- On a temp `HOME`, verify the exclusion attribute and Spotlight marker on the real filesystem.

**Notes.** — Which exclusion mechanism (backup-exclude extended attribute vs `tmutil`) works without admin rights
should be confirmed and written into the story PR.
