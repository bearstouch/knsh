# KNSH-115 — inotify/fanotify watcher and reflink checkpoints

[Phase 5](README.md#phase-5--linux) · [Story index and plan](README.md)

| Phase | Epic | Size | Depends on | Crates | Requirements |
| --- | --- | --- | --- | --- | --- |
| 5 | Checkpoints | XL (8) | [KNSH-110](KNSH-110-portable-platform-split-and-linux-ci.md) | `knsh-platform`, `knsh-checkpoint` | platform-support.md (File events), FR-CKP-03, FR-CKP-04, platform-support.md (Checkpoints), FR-CKP-35 |

**Description.** Merged from *inotify and fanotify watcher* and *Reflink checkpoints and plain-copy fallback*: they are done and validated together because checkpoint capture is validated through the watcher.

*inotify and fanotify watcher.* As the checkpoint manager on Linux, I need file events from inotify (fanotify when privileged), so
that shadows stay current and dropped events are detected.

*Reflink checkpoints and plain-copy fallback.* As the checkpoint manager on Linux, I need copy-on-write clones on btrfs and XFS (`FICLONE`) and
plain copies elsewhere, so that checkpoints work on common Linux filesystems.

**Acceptance criteria**
*inotify and fanotify watcher*

- [ ] Recursive watches cover each checkpoint root, including directories created later.
- [ ] `IN_Q_OVERFLOW` triggers a rescan and marks checkpoints uncertain (FR-CKP-04).
- [ ] Watch-limit exhaustion is reported via `hello` and treated like dropped events.

*Reflink checkpoints and plain-copy fallback*

- [ ] Reflinks are used on btrfs and XFS; the capability report names the method per root.
- [ ] Other filesystems fall back to plain copies limited to 50 MB per change (FR-CKP-35).
- [ ] Checkpoints stay on the same filesystem as the files they protect.

**Unit tests**
*inotify and fanotify watcher*

- `new_directory_gets_watch`
- `queue_overflow_marks_uncertain`
- `watch_limit_exhaustion_reported`

*Reflink checkpoints and plain-copy fallback*

- `reflink_used_when_supported`
- `plain_copy_fallback_respects_50mb_limit`
- `capability_report_names_method_per_root`

**Integration tests**
*inotify and fanotify watcher*

- Concurrent writer stress test, mirroring claim C4.
