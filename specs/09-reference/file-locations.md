# File locations (macOS)

| Data | Path or name |
| --- | --- |
| Configuration, hooks and policy files | `~/.config/knsh/` (policies in `~/.config/knsh/policies/`; integrity-protected) |
| Records, grants, pushed policy | `~/Library/Application Support/knsh/` |
| Checkpoints, home volume | `~/Library/Application Support/knsh/checkpoints/` |
| Checkpoints, other APFS volumes | `.knsh-checkpoints/` on that volume, when writable; otherwise plain copies in the home store |
| Agent socket | `~/Library/Application Support/knsh/run/agent.sock` |
| User socket | `~/Library/Application Support/knsh/run/user.sock` |
| Control service | XPC Mach service `knsh.control` (final name tied to the signing identity) |
| Launch agent | `~/Library/LaunchAgents/knsh.knshd.plist`, label `knsh.knshd`, owner-only; written by `knsh daemon install` |
| System log | Unified logging subsystem `knsh` |
| Keychain secrets | Service `knsh` |

## Rules

- All engine paths are denied to every envelope and command, readable by the user only, and excluded from Spotlight and Time Machine.
- Checkpoints sit on the same volume as the files they protect, because copy-on-write clones only work within one APFS volume.

## Environment variables

| Variable | Set in | Meaning |
| --- | --- | --- |
| `SHELL` | Envelopes | `knsh` |
| `PATH` | Envelopes | Shim directory first |
| Session token | Envelopes | Authenticates `agent.sock` requests |
| Proxy settings | Envelopes and supervised lines | Per-envelope or per-command proxy credentials |
| `KNSH_RECORDING` | Recording sessions | `1` when recording |
| Secret variables | Matching supervised lines | As named in `[secrets.env]` |
