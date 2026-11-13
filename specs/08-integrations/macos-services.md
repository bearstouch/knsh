# macOS services

All macOS services sit behind one internal platform interface, called directly from Rust ([implementation](../02-architecture/implementation.md)). A small Swift helper may be used only where Rust is impractical, never on the decision or enforcement path.

| Service | Used for | Notes |
| --- | --- | --- |
| launchd | Running `knshd` as a user agent; creating `agent.sock`, `user.sock` and the control service before `knshd` runs | No other process can claim those names; restarts `knshd` on crash |
| XPC | Control service `knsh.control` | Peer code-signing requirements in both directions |
| Keychain | Policy signing key, authority trust record, secrets (service `knsh`) | Items readable only by `knshd`'s code signature |
| LocalAuthentication | Touch ID or password for approvals, policy edits, grants, trust | Prompt shown by `knshd`; minimal Objective-C runtime calls or the Swift helper |
| FSEvents | Keeping checkpoint shadows current; `file.changed` | Dropped events trigger a rescan and mark checkpoints uncertain |
| Seatbelt (`sandbox-exec`) | Envelope and per-command profiles, applied by `knsh-exec` with `-f` | Deprecated but relied on by Codex CLI, Claude Code, Chromium, VS Code (decision 1) |
| Endpoint Security descendant client (`es_new_descendants_client`) | Deciding every exec inside envelopes, macOS 27+ | Needs Apple's Endpoint Security entitlement (decision 3) |
| APFS clones | Checkpoint shadows and pre-images | Same-volume only |
| Unified logging | System log subsystem `knsh`; reading tagged sandbox denials | Best effort |
| CommonCrypto | Hashing and policy signatures | |
| SQLite (system library) | Record store | |
| Spotlight, Time Machine | Exclusion of engine paths | Time Machine: extended attribute `com.apple.metadata:com_apple_backup_excludeItem` set to the same binary plist `tmutil addexclusion` writes (sticky item exclusion, no admin rights; `tmutil addexclusion -p` would need them). Spotlight: an empty `.metadata_never_index` file in each engine directory, which macOS 26.6 was observed to ignore below the volume root (claim C11, open). Both read back after writing (KNSH-011) |
| Audit tokens | Matching `agent.sock` callers without a session token to their envelope | |

Claims about these services that must be verified before phase 2 are listed in [../07-testing/verification-claims.md](../07-testing/verification-claims.md).
