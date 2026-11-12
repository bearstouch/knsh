# Compatibility

Humans keep their own zsh or bash; agent lines run in stock bash under the supervisor. A feature that breaks bash compatibility is not shipped as a default.

## Modes

| | Human sessions | Agent lines (phase 2) | Native mode (phase 4) |
| --- | --- | --- | --- |
| Interpreter | Stock zsh or bash, hosted by `knsh` (integration mode) | The stock interpreter the caller asked for (`sh`, `bash` or `zsh`), one per line, spawned by the supervisor | `knsh`'s own interpreter |
| What is observed | Each command line, through `preexec` and `precmd`, as telemetry | The whole line, parsed before it runs | Every simple command, including inside scripts and functions |
| Decisions and sandbox | None | Per line, enforced by the sandbox | Per simple command |
| Script compatibility | Exactly the host shell's | Exactly the interpreter used | Target: bash 5.2, including bash's POSIX mode when started as `sh` or with `--posix`; at least 99% of a corpus of agent-generated commands behaving as in bash |

## Requirements

| ID | Requirement |
| --- | --- |
| NFR-COMPAT-01 | Existing bash and zsh scripts, rc files and agent-generated commands must run unchanged. |
| NFR-COMPAT-02 | **Bash compatibility is the target.** The native interpreter must aim to run bash scripts and interactive bash usage unchanged. POSIX behaviour comes through bash's own POSIX mode, not as a separate dialect, and bash extensions (arrays, `[[ ]]`, process substitution, `shopt` options) are in scope. |
| NFR-COMPAT-03 | **zsh is supported by running real zsh**, in integration mode for humans and for agent lines that ask for it. The native interpreter does not emulate zsh. |
| NFR-COMPAT-04 | Agent lines must use `/bin/bash` (bash 3.2 on macOS) unless the profile names another (for example Homebrew bash 5), so agents see the same bash a plain `bash -c` would give them. |
| NFR-COMPAT-05 | Differences between bash 3.2 and 5.2 that agents rely on must be covered by the corpus tests. |
| NFR-COMPAT-06 | Interactive zsh users must be able to stay in integration mode permanently. |
| NFR-COMPAT-07 | Conformance must be measured in CI on every release ([conformance](../testing/conformance.md)). |
| NFR-COMPAT-08 | `knsh` must be addable to `/etc/shells`, with the user's permission, so it works as a login shell with `chsh`. Login and startup-file behaviour follow the hosted shell. |
| NFR-COMPAT-09 | Exit status must follow bash: 127 for command not found, 128 plus the signal number for signals. A policy denial uses 126, with the reason always printed on stderr and kept in the record ([exit codes](../reference/exit-codes.md)). |
| NFR-COMPAT-10 | In every mode the engine must emit OSC 7 (working directory) and OSC 133 (prompt, command, output and exit code). |
| NFR-COMPAT-11 | Native mode must reach at least 99% of the agent-command corpus behaving as in bash 5.2. |
