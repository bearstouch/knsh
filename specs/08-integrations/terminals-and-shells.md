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

### Hosting bash (implementation choice, KNSH-020)

As for zsh, the spec only requires the user's startup files to run unchanged; this is how `knsh` does it.

- **Which shell:** `knsh` hosts bash when `$SHELL` is an absolute path to a program named `bash`, and runs that very
  binary (`/bin/bash` 3.2, Homebrew's bash 5, …). Otherwise it hosts zsh. `argv[0]` is `-bash` for a login shell,
  and `-i` is passed on. When that bash cannot be started, or resolves to `knsh` itself, zsh starts instead (a human
  shell is never refused).
- **Recording off:** `knsh` `exec`s plain bash with no file and no variable of its own, so `/etc/profile`,
  `~/.bash_profile`, `~/.bash_login`, `~/.profile`, `~/.bashrc` and `~/.bash_logout` run exactly as in plain bash,
  and exit status, signals, job control and terminal ownership are bash's own.
- **Recording on, non-login shell:** bash starts with `--rcfile` pointing at the static wrapper
  `~/Library/Application Support/knsh/shell/bash/bashrc` (owner-only, written by atomic replace when missing or
  outdated). The wrapper takes the knsh variables out of the environment, sources `~/.bashrc` as bash would have, then
  adds the hooks.
- **Recording on, login shell:** no option or file can replace a login bash's profile files, and bash 3.2 reads no
  other file. Bash starts exactly as a plain login shell, with `PROMPT_COMMAND` set to a fixed bootstrap (followed by
  the inherited `PROMPT_COMMAND`, if any). At the first prompt, after every startup file, the bootstrap sources the
  wrapper. The wrapper removes the bootstrap from `PROMPT_COMMAND` (string or array) and adds the hooks. A bash
  started by a startup file inherits the bootstrap but has another parent, so it removes it and adds nothing.
- **Hooks:** `PROMPT_COMMAND` becomes `_knsh_precmd`, then the user's entries, then `_knsh_arm`. The string form
  becomes three lines; the array form (bash 5.1+) becomes three or more elements. A `DEBUG` trap runs `_knsh_debug`
  and then the user's own trap, if there was one. The trap reports a line only for the first command after
  `_knsh_arm` that is not one of the hooks' own, and not during programmable completion or `bind -x`. So a line gives
  exactly one started and one finished telemetry line, whatever it contains. The command text is the newest history
  entry. A line that ran no simple command in the shell itself, such as a subshell or a function definition, is
  reported by `_knsh_precmd` when it reached history. `_knsh_precmd` moves our entries back to the ends of
  `PROMPT_COMMAND` if something added entries around them. `knsh` also drops repeated started lines and orphan
  finished lines (`PromptCycle`).
- **`$?` and `PIPESTATUS`:** the trap records them before our `PROMPT_COMMAND` entries run. After each entry, a
  `case` gives them back by rebuilding the pipeline from `(exit n)` subshells, up to 8 commands. A failing pipeline is
  rebuilt as `… && :`, and an inverted one (`! cmd`) as `! …`, so neither `set -e` nor an `ERR` trap sees a failure.
  bash 3.2 does not keep `PIPESTATUS` across a `DEBUG` trap. The trap gives it back itself where no pipeline is being
  built: before the first command of a line, and before the first command of the user's `PROMPT_COMMAND`. Under
  `extdebug` the trap returns 0, so no command is skipped.
- **Descriptors:** the inherited write end is non-blocking, and bash also holds a read end that it never reads. A write
  therefore never blocks and never raises `SIGPIPE`, which kills interactive bash. Once the pipe is full, writes fail
  silently. Both ends are passed at descriptor 20 or above, because an interactive login bash 3.2 closes the
  descriptors 3 to 19 that it inherits. Every write first checks that the descriptor is still a pipe.
- **bash 3.2 quirks handled:** bash 3.2 hides the `DEBUG` trap inside a function and inside a file read with `.`, and
  puts back the trap it had on entry. So the user's trap is read at the top level: after `~/.bashrc`, or by the
  bootstrap itself. Our trap is set at the top level of the wrapper. In the login case, a user trap from the profile
  files makes bash 3.2 undo ours when the bootstrap returns, so the first `PROMPT_COMMAND` entry sets it at the next
  prompt.
- **Limits:**
  - Stock bash cannot make a descriptor close-on-exec, so commands inherit the two telemetry descriptors.
  - In a recorded login shell, the profile files see the bootstrap `PROMPT_COMMAND` and the variables
    `KNSH_TELEMETRY_FD`, `KNSH_TELEMETRY_PPID` and `KNSH_BASH_BOOT`. A profile file that assigns `PROMPT_COMMAND`
    without keeping its value turns telemetry off for the session, and the variables then stay in the environment.
  - In a recorded login shell, the first line is reported only at the next prompt (start time and directory taken
    then) when something runs after the bootstrap in the first `PROMPT_COMMAND`, or when the user has a `DEBUG` trap
    on bash 3.2.
  - `PROMPT_COMMAND` is no longer exported, so a nested bash does not inherit the user's `PROMPT_COMMAND`.
  - On bash 3.2, within one line, a command after a pipeline sees a one-element `PIPESTATUS`, as with any `DEBUG`
    trap in bash 3.2. The prompt, the next line and the user's `PROMPT_COMMAND` see the right value. Pipelines of
    more than 8 commands give back `$?` only. `$_` is not given back after a pipeline. In a recorded non-login
    shell, the first prompt sees `$?` but not the `PIPESTATUS` that `~/.bashrc` left, because bash 3.2 resets
    `PIPESTATUS` after a file read with `.`.
  - A line that never reaches history (`HISTCONTROL=ignorespace`, history off) is reported as the command bash is
    about to run, or as the newest entry when that entry starts with it (a repeat under `ignoredups`).
  - Assigning `PROMPT_COMMAND` interactively removes the hooks. Replacing the `DEBUG` trap leaves lines reported at the
    prompt only. On bash 3.2, a `bind -x` command may be reported as a line. Under `set -x` the hooks' commands are
    traced.
  - The user's own `DEBUG` trap also runs before the hooks' own `PROMPT_COMMAND` commands, so it runs more often per
    prompt than in plain bash (visible only for traps with side effects, such as `return 1` under `extdebug`).
  - The trap function runs before every simple command, which costs a few microseconds per command. Each typed line
    and each prompt fork once, for `$(history 1)`.
- **Verified:** bash 3.2 (`/bin/bash`) end to end. Homebrew bash 5 still needs to be verified: the tests run under
  it whenever one is installed.

## Terminal markup

In every mode the engine emits:

| Sequence | Purpose |
| --- | --- |
| OSC 7 | Working directory |
| OSC 133 | Prompt, command, output and exit code marks |

Any terminal that supports them can mark commands.

## Login shell

`knsh` can be added to `/etc/shells`, with the user's permission, so it works as a login shell with `chsh`. Login and startup-file behaviour follow the hosted shell.

## Recording a human session

Recording is off by default (FR-SES-04). The user turns it on in `~/.config/knsh/config.toml`:

```toml
[recording]
human = true
```

- Only an explicit `human = true` turns it on. No file, `human = false`, or anything unclear (a file that cannot be
  read, TOML outside the [configuration subset](../05-models/policy-profile.md#toml-subset), a `human` that is not a
  boolean, any other key inside `[recording]`) keeps it off; an unclear file is reported once on stderr, and the shell
  starts either way. Other top-level tables are left to other settings. There is no command-line flag: `knsh`'s shell
  invocation follows bash's syntax.
- **Off:** `knsh` `exec`s the shell and never connects to `knshd` (FR-SES-23).
- **On (KNSH-021):** the shell runs as a child with the hooks. Once it has started, a worker thread in `knsh`
  connects to `user.sock` and calls [`session.start_human`](../06-api/user-socket.md#human-sessions); the session is
  bound to that connection and ends (`session.ended`) when it closes, so when `knsh` exits. Each command line becomes
  one `telemetry.command` when its prompt returns (`command`, `cwd` where it started, `started_at` and `ended_at`
  stamped by `knsh` when the hook lines arrive, `exit_code`), a different working directory at the start or end of a
  line becomes `telemetry.cwd`, and a prompt that has waited 5 s for the next line becomes `telemetry.idle`, once,
  and again only after the next line (FR-SES-24). "Waiting for input" means no line was submitted: `knsh` cannot see
  keystrokes. The prompt counts as shown when the session starts and after each line. `exit` and a line still running
  when the shell exits produce no record.
- **Never in the way (NFR-REL-02):** the hooks never wait (KNSH-019, KNSH-020), and nothing between them and `knshd`
  makes the shell wait: `knsh` queues up to 1024 lines for the worker and drops the rest. A failed connection or call
  drops the telemetry silently; the worker tries again at the next line, at most once every 30 s, in a new session.
  Starting the session may take up to 5 s (launchd starts `knshd` on demand), and each later call up to 1 s, on the
  worker only. When the shell exits, `knsh` waits at most 500 ms for queued lines to be sent.
- Not recorded: a line over 64 KiB, or one whose working directory is not an absolute, resolved path. Bytes that are
  not UTF-8 are recorded as U+FFFD.
- The connection is made only after the shell has started, so no command run from the shell can inherit it.

## Recording indicator

A recording session sets `KNSH_RECORDING=1` in the shell's environment, so prompts can show that recording is on
(FR-SES-25). It is set only when the hooks are installed and telemetry flows to `knsh`; it reflects the setting, not
whether `knshd` is reachable at that moment (telemetry is then dropped, NFR-REL-02). A shell that is not recorded never
has it, even when `knsh` inherited it from a recorded parent. `session.info` reports `recording` for the caller's
session ([user socket](../06-api/user-socket.md#human-sessions)).

## Startup files

Agents can never write shell startup files (`~/.zshrc`, `~/.zprofile`, `~/.bashrc`, `~/.bash_profile`, `~/.profile`); these are fixed write denies in every profile.
