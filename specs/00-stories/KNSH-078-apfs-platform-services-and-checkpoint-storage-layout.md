# KNSH-078 — APFS platform services and checkpoint storage layout

[Phase 3](README.md#phase-3--reverse-and-protect) · [Story index and plan](README.md)

| Phase | Epic | Size | Depends on | Crates | Requirements |
| --- | --- | --- | --- | --- | --- |
| 3 | Checkpoints | XL (8) | [KNSH-007](KNSH-007-platform-interface-and-test-fakes.md), [KNSH-011](KNSH-011-engine-directories-permissions-and-backup-exclusion.md), [KNSH-077](KNSH-077-spike-file-system-behaviour-copy-on-write-cloning-memory.md) | `knsh-platform`, `knsh-checkpoint` | FR-CKP-01, FR-CKP-09, FR-CKP-35, NFR-PRIV-04 |

**Description.** Merged from *APFS clone, volume and hashing platform services* and *Checkpoint storage layout per volume*: they are done and validated together because the storage layout is validated through the clone and volume services.

*APFS clone, volume and hashing platform services.* As the checkpoint engine, I want platform services to clone a file, identify the volume and file
system of a path, read file identity, and hash file contents, behind `knsh-platform` traits with fakes, so that the
checkpoint logic stays pure and testable. Scope: `clonefile` wrapper, `statfs`-based volume ID and file-system type
(APFS or not), identity (inode, size, mtime with nanoseconds), streaming SHA-256 through CommonCrypto, and fakes in
the `testing` feature. Out of scope: storage layout (covered in this story), any policy about when to clone.

*Checkpoint storage layout per volume.* As the checkpoint engine, I want a store per volume so that clones always stay on the same volume
as the files they protect. Scope: home volume store in `~/Library/Application Support/knsh/checkpoints/`; a writable
`.knsh-checkpoints/` folder on other APFS volumes; plain copies in the home store for non-APFS or unwritable volumes;
versioned on-disk format; owner-only permissions; Spotlight and Time Machine exclusion; capability reporting per root.
Out of scope: what goes into a checkpoint (KNSH-082).

**Acceptance criteria**
*APFS clone, volume and hashing platform services*

- [x] `clone_file(src, dst)` succeeds within one APFS volume and returns a typed error (not a panic) across volumes
      or on non-APFS file systems.
- [x] `volume_of(path)` returns a stable volume ID and reports whether the volume supports clones.
- [x] `identity(path)` returns inode, size and mtime; `hash(path)` streams the file and never loads it whole.
- [x] Hashing is skipped for files of 64 MB or more, and the identity records that no hash was taken (FR-CKP-09).
- [x] All `unsafe` FFI blocks carry `// SAFETY:` comments; every public item has `///` docs with `# Errors`.
- [x] Fakes allow tests to simulate clone failure, volume boundaries and identity changes deterministically.

*Checkpoint storage layout per volume*

- [x] A root on the home volume uses the home store; a root on another APFS volume uses `.knsh-checkpoints/` on that
      volume when it is writable; otherwise plain copies are stored in the home store.
- [x] Plain-copy checkpoints are limited to 50 MB per change; a change over the limit is recorded as not protected,
      not silently truncated (FR-CKP-35).
- [ ] The capability report (`hello`) lists each root with its method (`apfs-clone`, plain copies, or `none`).
      *Partially met:* the per-root report (`knsh_checkpoint::capability_report`) and the wire value `plain-copy` exist
      and are tested; `knshd` fills `hello` from live session roots with the shadow builder (KNSH-079).
- [x] Store directories are 0700 and files 0600, excluded from Spotlight and Time Machine, and denied to envelopes
      and commands (engine paths).
- [x] The store has a format version; a newer or corrupt store triggers recovery and is never overwritten.

**Unit tests**
*APFS clone, volume and hashing platform services*

- `clone_fails_with_cross_volume_error_in_fake` — typed error path (FR-CKP-35).
- `identity_without_hash_for_files_at_or_over_64_mib` — boundary at exactly 64 MB (FR-CKP-09).
- `hash_matches_known_sha256_vectors` — CommonCrypto binding is correct.
- `hash_streams_in_bounded_chunks` — no whole-file allocation.

*Checkpoint storage layout per volume*

- `home_volume_root_uses_home_store`
- `other_apfs_volume_uses_local_checkpoint_folder`
- `non_apfs_root_falls_back_to_plain_copies` (FR-CKP-35)
- `plain_copy_change_over_50_mb_is_marked_unprotected` (FR-CKP-35)
- `newer_store_version_is_not_overwritten`
- `capability_report_lists_method_per_root`

**Integration tests**
*APFS clone, volume and hashing platform services*

- Clone and hash real files in a temp dir on the home APFS volume; verify the clone has identical content and a
  different inode.

**Notes**
*Checkpoint storage layout per volume*

- The capability value string for plain copies is fixed as `plain-copy` in [../05-models/capabilities.md](../05-models/capabilities.md).

**Results (2026-11-18, macOS 26.6.2).** `knsh_platform::Volumes` (`SystemVolumes`, `FakeVolumes`),
`knsh_checkpoint::{post_image_identity, place_roots, capability_report}`. Observed on the home APFS volume: clones have
identical contents and a new inode; cloning to `/dev` returns `EXDEV` (`CrossVolume`); FIFOs are refused without
blocking. The `.knsh-checkpoints` deny holds under real `sandbox-exec` (read, list, write, create, rename, case
variants). Review addition: volumes mounted with `MNT_IGNORE_OWNERSHIP` (the default for external disks) never get a
store, since owner-only modes mean nothing there; their roots use plain copies. **Pending:** a real second APFS volume
and a non-APFS volume (only fakes and devfs were exercised), macOS 14 and 15, and `hello` wiring (KNSH-079).
