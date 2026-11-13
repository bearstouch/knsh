# Platform support

macOS 14 and later ships first. Linux follows once the macOS engine is stable (phase 5). Windows is a non-goal.

| Concern | macOS 14 and later (first) | Linux (later) |
| --- | --- | --- |
| Sandbox | Seatbelt profiles, plus an Endpoint Security descendant client on macOS 27 and later, applied by `knsh-exec` | Landlock and seccomp applied by `knsh-exec`; namespaces where available |
| Network filter | Local proxy + sandbox | Local proxy + seccomp or a network namespace |
| Checkpoints | APFS copy-on-write clones | Reflinks on btrfs and XFS; plain copies elsewhere |
| File events | FSEvents | inotify; fanotify when privileged |
| Secrets | Keychain | Secret Service, or authority-provided only |
| Hashing and signatures | CommonCrypto | Replacement required (same dependency rules) |
| Control channel | XPC service with peer code-signing requirement | Socket activated by systemd + `SO_PEERCRED` + executable path and hash |
| Daemon | launchd user agent | systemd user unit |
| System log | Unified logging | journald |

The API, records, events, policy format and checkpoint rules are the same on both. Only the backends differ, and `hello` reports which are active ([capabilities](../05-models/capabilities.md)).
