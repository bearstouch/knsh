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

- **Which shell:** `knsh` hosts bash when `[shell] hosted` names it ([login shell](#login-shell)) or, with no
  setting, when `$SHELL` is an absolute path to a program named `bash`, and runs that very binary (`/bin/bash` 3.2,
  Homebrew's bash 5, …). Otherwise it hosts zsh. `argv[0]` is `-bash` for a login shell,
  and `-i` is passed on. When that bash cannot be started, or resolves to `knsh` itself, zsh starts instead (a human
  shell is never refused).
- **When the wrapper is read:** when recording is on, or when the [terminal marks](#terminal-markup) are wanted
  (`knsh`'s standard output is a terminal, KNSH-022), or both. With neither, `knsh` `exec`s plain bash with no file and
  no variable of its own, so `/etc/profile`, `~/.bash_profile`, `~/.bash_login`, `~/.profile`, `~/.bashrc` and
  `~/.bash_logout` run exactly as in plain bash.
- **Recording off:** `knsh` `exec`s bash (with the wrapper only for the marks), so exit status, signals, job control
  and terminal ownership are bash's own. The wrapper installs hooks only in the bash whose parent is the one `knsh`
  names in `KNSH_TELEMETRY_PPID`: `knsh` itself when bash is its child (recording on), `knsh`'s own parent when `knsh`
  replaces itself with bash.
- **Non-login shell:** bash starts with `--rcfile` pointing at the static wrapper
  `~/Library/Application Support/knsh/shell/bash/bashrc` (owner-only, written by atomic replace when missing or
  outdated). The wrapper takes the knsh variables out of the environment, sources `~/.bashrc` as bash would have, then
  adds the hooks.
- **Login shell:** no option or file can replace a login bash's profile files, and bash 3.2 reads no
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
  - In a login shell that reads the wrapper (recorded, or with the marks), the profile files see the bootstrap
    `PROMPT_COMMAND` and the variables `KNSH_TELEMETRY_FD` (recorded only), `KNSH_TELEMETRY_PPID`, `KNSH_BASH_BOOT`
    and `KNSH_TERMINAL_MARKS` (marks only). A profile file that assigns `PROMPT_COMMAND`
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

### In integration mode (KNSH-022)

- **When:** `knsh` asks the hosted shell for the marks (`KNSH_TERMINAL_MARKS=1`, removed by the wrapper before any
  user file runs) only when its own standard output is a terminal, whether or not recording is on. The hooks also
  check, at every write, that standard output is still a terminal; otherwise they write nothing. A shell started
  without the wrapper (it could not be installed) has no marks.
- **What, in order, for each command line:** before the prompt, `ESC ]133;D;<exit> BEL` for the line that ran (only
  after its `C`), then `ESC ]7;file://<host><path> BEL`, then `ESC ]133;A BEL`; `ESC ]133;B BEL` at the end of the
  prompt, where the typed line begins; `ESC ]133;C BEL` when the line is about to run. A line that ran nothing (an
  empty line) gets no `C` and no `D`. OSC 7 is written before every prompt, so on start and after every directory
  change. The host is the shell's host name (`$HOST`, `$HOSTNAME`); host and path have every byte other than
  `A-Z a-z 0-9 / . _ ~ -` written as `%XX` (upper-case hex, UTF-8 bytes as they are).
- **zsh:** a second pair of hooks, `_knsh_mark_precmd` and `_knsh_mark_preexec`, added with `add-zsh-hook` like the
  telemetry hooks. `B` is appended to `PS1` inside `%{ %}` (only with `PROMPT_PERCENT`, the default) and taken off
  again by the next hook unless something has set `PS1` since. Whenever hooks were added after them, the marks' hooks
  move themselves to the end of `precmd_functions` and `preexec_functions` (by `add-zsh-hook -d` then
  `add-zsh-hook`), so that `PS1` is final when `B` is added.
- **bash:** the hooks of [hosting bash](#hosting-bash-implementation-choice-knsh-020): `_knsh_precmd` writes `D`,
  OSC 7 and `A`; `_knsh_arm`, the last `PROMPT_COMMAND` entry, appends `B` to `PS1` inside `\[ \]`; the `DEBUG`
  trap writes `C` before the first command of a typed line. Without recording, no history lookup is made, so the
  marks alone fork nothing. In a login shell the bootstrap marks the first prompt itself.
- **Limits:** in zsh, a hook that a later startup file (`.zshrc`) adds and that assigns `PS1` runs after the marks'
  hooks on the first prompt only, so that first prompt may lack `B`. In bash without recording, a `PROMPT_COMMAND`
  entry added interactively runs after `_knsh_arm` once, and counts as a typed line there (a stray `C`) until the
  next prompt puts `_knsh_arm` back at the end. A line that runs no simple command in bash itself (a subshell, a
  function definition) gets no `C` or `D`.

### In native mode (KNSH-107)

The native shell writes the same bytes itself (`knsh_interp::interactive::marks`, the reference being
`knsh::integration::marks`), only when `knsh`'s standard output is a terminal: before each prompt `D;<exit>` for the
line that ran, OSC 7 for the working directory and `A`; `B` once after the prompt is drawn (not with every redraw of
the line); `C` when the typed line is about to run, also when it runs nothing (an assignment, a builtin). The host is
the system's host name (`gethostname`).

## Native mode (KNSH-107)

`[shell] hosted = "native"` runs `knsh`'s own interpreter (`knsh-interp`) as the human's interactive shell instead
of hosting zsh or bash. `knsh --native` selects it for one invocation instead, overriding `[shell] hosted` and any error in the file
(FR-SES-26); the precedence is `--native`, then `[shell] hosted`, then the bash `$SHELL` names, then `/bin/zsh`. The flag
has no effect on `-c` lines or inside an envelope, where the profile's `exec.mode` alone decides (FR-LC-50). It is opt-in: until the phase 4 gate (KNSH-109) is green it is never the default, and zsh users
stay in integration mode (NFR-COMPAT-06).

- **Process:** `knsh` itself is the shell. It takes the terminal for job control (its own process group, the terminal's
  foreground group), ignores `SIGINT`, `SIGQUIT` and `SIGTSTP` itself while its foreground jobs get them with their
  default actions, and exits with the shell's status or by the signal that ended it. Commands start through the
  platform spawner directly: nothing in a human session is decided, rewritten or blocked (FR-SES-22), and every error
  (a construct the interpreter refuses, a failed expansion, an unreadable history file) is reported while the shell
  goes on.
- **Startup files, as bash:** a login shell (`-knsh`, `-l`, `--login`) reads `/etc/profile` and the first of
  `~/.bash_profile`, `~/.bash_login`, `~/.profile`, and `~/.bash_logout` when it exits; any other interactive shell
  reads `~/.bashrc`. `--norc`, `--noprofile` and `--rcfile` are not taken yet.
- **Line editor:** in-house (no readline or line-editing crate, per the dependency policy). Emacs keys as readline's
  defaults (movement by character and word, kills into a 10-entry kill ring with yank and yank-pop, transpose, case
  changes, undo and revert, history walk, incremental search with Ctrl-R and Ctrl-S, Meta-. for the last argument,
  quoted insert, clear screen) and vi mode basics (`set -o vi`: insert and command modes, counts, the motions
  `h l 0 ^ $ w b e W B E f F t T`, the operators `d c y` and `dd cc yy`, `x X D C S s r ~ p P u i a I A`, `k j`
  for history). The cursor moves over whole cells: a wide character takes two columns, and a character with its
  combining marks is one step. A lone `ESC` waits 100 ms for the rest of a key sequence. While a line is edited the
  terminal delivers Ctrl-C, Ctrl-Z and Ctrl-\ as keys: Ctrl-C abandons the line (`^C`, `$?` 130).
- **Prompts:** `PS1` and `PS2` with every bash escape (`\u \h \H \w \W \d \t \T \@ \A \D{…} \j \l \s \v \V \!
  \# \$ \nnn \[ \]` …), then expanded as a here-document is (`promptvars`); `PROMPT_DIRTRIM`; `PROMPT_COMMAND`
  (string or array) before each prompt. Bash's defaults when unset: `PS1='\s-\v\$ '`, `PS2='> '`.
- **History:** the list with `HISTSIZE` and `HISTFILESIZE` (500 by default), `HISTCONTROL` (`ignorespace`,
  `ignoredups`, `ignoreboth`, `erasedups`), `HISTFILE` (default `~/.bash_history`) read after the startup files and
  written at exit (replaced, or appended to with `shopt -s histappend`, then cut to `HISTFILESIZE` lines; owner-only,
  by atomic replace); a command read over several lines is one entry (`cmdhist`, `lithist`). History expansion
  (`set -H`): `!!`, `!n`, `!-n`, `!string`, `!?string?`, `!#`, `^old^new`, word designators and the modifiers
  `h t r e p q x s & g a`; `:G` is reported as not supported, never expanded differently. The `history` builtin takes
  `-c -d -a -r -w -p -s` and a count (`-n` is reported as not supported).
- **Completion:** Tab completes the word before the cursor, a second Tab lists the possibilities in columns (asking
  first above 100): command names in command position, variable names after `$`, file names otherwise (quoted, `/`
  after directories), or what `complete` specifies for the command (`-W`, `-F` with `COMP_WORDS`, `COMP_CWORD`,
  `COMP_LINE`, `COMP_POINT` and `COMPREPLY`, the actions, `-X`, `-P`, `-S`, `-o` options, `-D`, `-E`, `-I`).
  `compgen` prints the same matches. Not supported: `-C`, `-G`, and the user, group, host and service actions.
- **Not yet:** `.inputrc` and `bind`, `fc`, `HISTIGNORE`, `HISTTIMEFORMAT`, `compopt`, `IGNOREEOF`; Ctrl-C does not
  interrupt a loop the shell runs itself (its programs get it).
- **Recording (FR-SES-27):** with `[recording] human = true`, a native session is recorded like a hosted one. The
  interpreter reports each command line it runs to `knsh` (`knsh_interp::interactive::LineObserver`): when it starts,
  with the working directory and the line as typed, and when it finishes, with `$?` and the working directory then.
  These are the same two events as `preexec` and `precmd` and take the same path to `knshd` (`user.sock`, the
  worker's bounded queue, a connection opened only once the shell is running). Lines typed in `PROMPT_COMMAND` or
  start-up files are not recorded. A recorded session exports `KNSH_RECORDING=1` to its commands; any other never
  has it, even when inherited (FR-SES-25). A slow or absent `knshd` never delays or blocks the shell (FR-SES-22).
- **Start-up time (NFR-PERF-04):** measured in the story ([KNSH-107](../00-stories/KNSH-107-interactive-line-editor-and-history.md)).

## Login shell

`knsh` can be added to `/etc/shells`, with the user's permission, so it works as a login shell with `chsh`. Login and startup-file behaviour follow the hosted shell.

- **Login invocation:** `argv[0]` starting with `-` (as `login(1)` and terminals start a login shell: `-knsh`), `-l`
  or `--login` starts the hosted shell as a login shell (`argv[0]` `-zsh` or `-bash`), which then reads its login
  files as it always does.
- **Hosted shell:** set in `~/.config/knsh/config.toml`, since `$SHELL` names `knsh` itself once it is the login
  shell:

  ```toml
  [shell]
  hosted = "zsh"   # "zsh" (/bin/zsh), "bash" (/bin/bash), "native" (knsh's own interpreter, KNSH-107),
                   # or an absolute path to a program named zsh or bash
  banner = true    # false silences the session start and end messages
  ```

  The start message (the first line of `knsh --version`) goes to stderr, and
  only when stderr is a terminal. The end message is printed only where `knsh` outlives the shell (native mode, a
  recorded session); a shell `knsh` replaces itself with (`exec`) ends with no `knsh` left to print it.

  Without the setting, `knsh` hosts the bash `$SHELL` names, if it is one (KNSH-020), and `/bin/zsh` otherwise, so
  zsh by default. An invalid choice (another value or type, an unknown key inside `[shell]`, a file that cannot be
  read or parsed, a program that is not an executable file or is `knsh` itself) starts `/bin/zsh` with a one-line
  warning on stderr, never no shell. A chosen zsh or bash that then fails to start falls back to `/bin/zsh` too.
- **`/etc/shells`:** `knsh shell install` ([CLI](../06-api/cli.md#login-shell)) adds the resolved path of the running
  `knsh` after an explicit yes on a terminal, through `sudo`. Nothing else ever edits `/etc/shells`. The user then
  runs `chsh -s <path>` themselves.

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
