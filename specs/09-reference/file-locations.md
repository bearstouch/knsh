# File locations (macOS)

| Data | Path or name |
| --- | --- |
| Configuration, hooks and policy files | `~/.config/knsh/` (policies in `~/.config/knsh/policies/`; integrity-protected) |
| Records, grants, pushed policy | `~/Library/Application Support/knsh/` (records in `records.db`, owner-only `0600`) |
| Checkpoints, home volume | `~/Library/Application Support/knsh/checkpoints/` |
| Checkpoints, other APFS volumes | `.knsh-checkpoints/` on that volume, when writable; otherwise plain copies in the home store |
| zsh startup wrapper (integration mode) | `~/Library/Application Support/knsh/shell/zsh/.zshenv` (owner-only; rewritten by `knsh` when outdated) |
| bash startup wrapper (integration mode, recording only) | `~/Library/Application Support/knsh/shell/bash/bashrc` (owner-only; rewritten by `knsh` when outdated) |
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
| `KNSH_ZSH_ZDOTDIR`, `KNSH_TELEMETRY_FD` | Only between `knsh` and its zsh startup wrapper | The user's `ZDOTDIR` and the telemetry descriptor; removed before any user file runs |
| `KNSH_TELEMETRY_FD`, `KNSH_TELEMETRY_PPID`, `KNSH_BASH_BOOT` | Only between `knsh` and its bash startup wrapper, while recording | The telemetry descriptor, `knsh`'s process ID and (login shells) the wrapper's path; removed before `~/.bashrc` runs (non-login) or at the first prompt (login) |
| Secret variables | Matching supervised lines | As named in `[secrets.env]` |
