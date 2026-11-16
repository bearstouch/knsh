# File locations (macOS)

| Data | Path or name |
| --- | --- |
| Configuration, hooks and policy files | `~/.config/knsh/` (policies in `~/.config/knsh/policies/`; integrity-protected) |
| User settings | `~/.config/knsh/config.toml` (`[recording] human`, `[shell] hosted`; written by the user, read by `knsh`; `[[hooks]]`, read by `knshd` for every agent line, [hook](../05-models/hook.md)) |
| Records, grants, pushed policy | `~/Library/Application Support/knsh/` (records in `records.db`, owner-only `0600`) |
| Checkpoints, home volume | `~/Library/Application Support/knsh/checkpoints/` |
| Compiled sandbox profiles | `~/Library/Application Support/knsh/profiles/<sha256>.sb` (directory `0700`, files `0600`, written atomically; removed when no running envelope or line uses them, and swept at `knshd` start; FR-SBX-07) |
| Checkpoints, other APFS volumes | `.knsh-checkpoints/` on that volume, when writable; otherwise plain copies in the home store |
| zsh startup wrapper (integration mode) | `~/Library/Application Support/knsh/shell/zsh/.zshenv` (owner-only; rewritten by `knsh` when outdated) |
| bash startup wrapper (integration mode, when recording or with terminal marks) | `~/Library/Application Support/knsh/shell/bash/bashrc` (owner-only; rewritten by `knsh` when outdated) |
| Shim directory | `~/Library/Application Support/knsh-shims/` (`sh`, `bash`, `zsh`: symbolic links to the `knsh` binary; directory `0700`; created by `knsh`). Deliberately **outside** the fixed denies, since envelopes must look it up and run it; it holds nothing secret and is not a security boundary (KNSH-049) |
| Agent socket | `~/Library/Application Support/knsh/run/agent.sock` |
| User socket | `~/Library/Application Support/knsh/run/user.sock` |
| Control service | XPC Mach service `knsh.control` (final name tied to the signing identity) |
| Launch agent | `~/Library/LaunchAgents/knsh.knshd.plist`, label `knsh.knshd`, owner-only; written by `knsh daemon install` |
| System log | Unified logging subsystem `knsh` |
| Keychain secrets | Service `knsh` |

## Rules

- All engine paths are denied to every envelope and command, readable by the user only, and excluded from Spotlight and Time Machine. The shim directory is not an engine path in this sense: it sits beside the data directory, not in it.
- Checkpoints sit on the same volume as the files they protect, because copy-on-write clones only work within one APFS volume.

## Environment variables

| Variable | Set in | Meaning |
| --- | --- | --- |
| `SHELL` | Envelopes | `knsh` |
| `PATH` | Envelopes | Shim directory first |
| `KNSH_SESSION_TOKEN` | Envelopes | The session token: `knsh` sends it in `hello` on `agent.sock`. Removed from supervised lines |
| Proxy settings | Envelopes and supervised lines | Per-envelope or per-command proxy credentials |
| `KNSH_RECORDING` | Recording sessions | `1` when recording; removed from a shell that is not recorded |
| `KNSH_ZSH_ZDOTDIR`, `KNSH_TELEMETRY_FD` | Only between `knsh` and its zsh startup wrapper | The user's `ZDOTDIR` and the telemetry descriptor; removed before any user file runs |
| `KNSH_TELEMETRY_FD`, `KNSH_TELEMETRY_PPID`, `KNSH_BASH_BOOT` | Only between `knsh` and its bash startup wrapper, while recording | The telemetry descriptor, `knsh`'s process ID and (login shells) the wrapper's path; removed before `~/.bashrc` runs (non-login) or at the first prompt (login) |
| Secret variables | Matching supervised lines | As named in `[secrets.env]` |
