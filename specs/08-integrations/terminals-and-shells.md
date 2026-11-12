# Terminals and shells

Kinetic Shell is not a terminal emulator; it runs inside any terminal.

## Integration mode (human sessions)

- `knsh` hosts stock zsh or bash.
- When recording is on, `preexec` and `precmd` hooks record each command line as telemetry (`command`, `cwd`, times, `exit_code`).
- Nothing is decided, rewritten or blocked, and the hooks are never relied on for security.
- Start-up overhead target: under 50 ms.
- Interactive zsh users can stay in integration mode permanently; the native interpreter (phase 4) does not emulate zsh.

## Terminal markup

In every mode the engine emits:

| Sequence | Purpose |
| --- | --- |
| OSC 7 | Working directory |
| OSC 133 | Prompt, command, output and exit code marks |

Any terminal that supports them can mark commands.

## Login shell

`knsh` can be added to `/etc/shells`, with the user's permission, so it works as a login shell with `chsh`. Login and startup-file behaviour follow the hosted shell.

## Recording indicator

A recording session sets `KNSH_RECORDING=1`, so prompts can show that recording is on.

## Startup files

Agents can never write shell startup files (`~/.zshrc`, `~/.zprofile`, `~/.bashrc`, `~/.bash_profile`, `~/.profile`); these are fixed write denies in every profile.
