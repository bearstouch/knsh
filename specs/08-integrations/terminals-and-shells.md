# Terminals and shells

Kinetic Shell is not a terminal emulator; it runs inside any terminal.

## Integration mode (human sessions)

- `knsh` hosts stock zsh or bash.
- When recording is on, `preexec` and `precmd` hooks record each command line as telemetry (`command`, `cwd`, times, `exit_code`).
- Nothing is decided, rewritten or blocked, and the hooks are never relied on for security.
- Start-up overhead target: under 50 ms.
- Interactive zsh users can stay in integration mode permanently; the native interpreter (phase 4) does not emulate zsh.

### Hosting zsh (implementation choice, KNSH-019)

The spec only requires the user's startup files to run unchanged. `knsh` meets that as follows; this is an
implementation choice, not a requirement.

- **When:** `knsh` with no `-c` line or script operand, interactive because of `-i` or because standard input and
  standard error are terminals. It runs `/bin/zsh`. `argv[0]` is `-zsh` for a login shell, and `-i` is passed on.
- **Startup directory:** `knsh` keeps one static wrapper, `.zshenv` in `~/Library/Application Support/knsh/shell/zsh/`
  (owner-only, written by atomic replace when missing or outdated). It starts zsh with `ZDOTDIR` pointing there. The
  user's own `ZDOTDIR` goes in `KNSH_ZSH_ZDOTDIR`; that variable is absent when `ZDOTDIR` was unset.
- **Restore first:** the wrapper restores the user's `ZDOTDIR` exactly (unset, empty or set) and removes the knsh
  variables. Then it sources the user's `.zshenv` from `${ZDOTDIR-$HOME}`, with `FUNCTION_ARGZERO` off meanwhile so
  that `$0` is the shell's name there, as when zsh reads the file itself. zsh looks `ZDOTDIR` up again for every
  later file, so zsh itself reads `/etc/zprofile`, `.zprofile`, `/etc/zshrc`, `.zshrc`, `/etc/zlogin`, `.zlogin` and
  `.zlogout`, in its own order, from wherever the user's files left `ZDOTDIR`. Child processes inherit the user's
  value.
- **Hooks:** hooks are added only when recording is on. `KNSH_TELEMETRY_FD` names an inherited, non-blocking pipe. The
  wrapper reopens it close-on-exec with `zsh/system`'s `sysopen` and closes the original, so no command inherits it.
  It then appends `_knsh_preexec` and `_knsh_precmd` with `add-zsh-hook` after the user's `.zshenv`, falling back to
  appending to the arrays. They run under `emulate -L zsh` and ignore `SIGPIPE` only while they run, because
  interactive zsh dies of `SIGPIPE` when the reader has gone. All their output goes to `/dev/null`. The line format is
  `knsh1<TAB>preexec<TAB><cwd><TAB><command>` and `knsh1<TAB>precmd<TAB><status><TAB><cwd>`. Fields use the escapes
  `\\ \n \t \r \0`. `knsh` stamps times on receipt.
- **Process model:** with recording off, `knsh` `exec`s zsh, so exit status, signals, job control and terminal
  ownership are zsh's own and no `knsh` process remains. With recording on (KNSH-021), zsh is a child. `knsh` never
  touches the terminal and ignores `SIGINT`, `SIGQUIT` and `SIGTSTP` while zsh runs. It exits with zsh's status, or by
  re-raising the signal that ended zsh.
- **Fallback:** if the startup directory cannot be installed (for example `HOME` is unset), plain zsh starts after a
  one-line warning. A human shell is never refused.
- **Limits:** an rc file that *assigns* `preexec_functions` or `precmd_functions` without keeping their entries drops
  the hooks. Only telemetry is lost. `/etc/zshenv`, read before the wrapper, still sees the wrapper's `ZDOTDIR`; macOS
  ships no `/etc/zshenv`. A `.zshenv` that itself turns `FUNCTION_ARGZERO` off finds it back on afterwards.

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
