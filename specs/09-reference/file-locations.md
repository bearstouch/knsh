# File locations (macOS)

| Data | Path or name |
| --- | --- |
| Configuration, hooks and policy files | `~/.config/knsh/` (policies in `~/.config/knsh/policies/`; integrity-protected) |
| User settings | `~/.config/knsh/config.toml` (`[recording] human`, `[shell] hosted`; written by the user, read by `knsh`; `[[hooks]]`, read by `knshd` for every agent line, [hook](../05-models/hook.md)) |
| Records, grants, pushed policy | `~/Library/Application Support/knsh/` (records in `records.db`; grants and pushed policy in `state.json`, written atomically by `knshd`, KNSH-071; both owner-only `0600`. An
unusable state file is set aside as `state.json.corrupt-<µs>` or `state.json.newer-<µs>`, never overwritten, KNSH-074) |
| Checkpoints, home volume | `~/Library/Application Support/knsh/checkpoints/` (the **home store**: directory `0700`, files `0600`, Spotlight marker and Time Machine exclusion; a `format` file holds `knsh-checkpoints <version>\n`, version 1, KNSH-078) |
| Compiled sandbox profiles | `~/Library/Application Support/knsh/profiles/<sha256>.sb` (directory `0700`, files `0600`, written atomically; removed when no running envelope or line uses them, and swept at `knshd` start; FR-SBX-07) |
| Checkpoints, other APFS volumes | `.knsh-checkpoints/` at that volume's mount point (for example `/Volumes/External/.knsh-checkpoints/`), when the volume is writable, honours ownership (not mounted with `MNT_IGNORE_OWNERSHIP`, the default for external disks, on which owner-only modes protect nothing) and the store can be used; otherwise plain copies in the home store. Same modes, exclusions and `format` file as the home store. A store owned by another user, a symlink in its place, a newer or corrupt `format` file, or entries without one: the store is left as found and not used (KNSH-078) |
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
- `.knsh-checkpoints` is a reserved name: every path with that component is a fixed deny, wherever the volume is mounted ([policy](../03-functional-requirements/policy.md#fixed-denies)).

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
