# Native mode

By default `knsh` hosts your own zsh or bash. Native mode is the alternative: `knsh` runs its own bash 5.2 interpreter, so it is the shell, not just a wrapper around one. It is opt-in, and it is bash, never zsh.

Use native mode if you want `knsh` to see and decide every single command inside scripts and functions that an agent runs. For your own daily shell, the default hosted mode is usually the better choice, especially if you use zsh.

## Turn it on for your own shell

```toml
# ~/.config/knsh/config.toml
[shell]
hosted = "native"
```

Start `knsh` as usual. Nothing in your own native session is decided, rewritten or blocked.

## Native mode for agents

Agent lines can also run in native mode. Set it in a [policy profile](policy.md):

```toml
[exec]
mode = "native"
```

| `exec.mode` | What happens |
| --- | --- |
| `"line"` (the default) | The whole command line is decided first, then runs in a stock bash (`/bin/bash` 3.2 unless the profile names another with `exec.bash`). |
| `"native"` | The line runs in `knsh`'s interpreter, and every simple command it starts is decided one by one, including inside scripts, functions, loops and substitutions. |

A preset can't set `exec.mode`.

## What your native shell does

**Startup files.** As bash does. A login shell reads `/etc/profile` and the first of `~/.bash_profile`, `~/.bash_login` and `~/.profile`, and `~/.bash_logout` when it exits. Any other interactive shell reads `~/.bashrc`. `--norc`, `--noprofile` and `--rcfile` aren't supported yet.

**Line editing.** A built-in editor with readline's default Emacs keys: movement by character and word, kill and yank, transpose, case changes, undo, history search with <kbd>Ctrl</kbd>-<kbd>R</kbd> and <kbd>Ctrl</kbd>-<kbd>S</kbd>, <kbd>Meta</kbd>-<kbd>.</kbd> for the last argument. Vi mode is available with `set -o vi` (insert and command modes, counts, the usual motions and operators). <kbd>Ctrl</kbd>-<kbd>C</kbd> abandons the line you are typing.

**Prompts.** `PS1` and `PS2` with all of bash's escapes, `PROMPT_DIRTRIM`, and `PROMPT_COMMAND` (string or array). When unset, bash's defaults apply.

**History.** `HISTSIZE` and `HISTFILESIZE` (500 by default), `HISTCONTROL`, and `HISTFILE` (`~/.bash_history` by default), written when the shell exits. History expansion (`!!`, `!n`, `!string`, `^old^new`, word designators and modifiers) works. The history list never holds more than 100,000 entries.

**Completion.** <kbd>Tab</kbd> completes command names, variables and file names; press it twice to list matches (after asking when there are more than 100). Completion specs defined with `complete` work (`-W`, `-F` with `COMP_WORDS` and friends, `-o` options), and `compgen` prints the same matches.

**Terminal marks.** The same working-directory and prompt marks as in [hosted mode](shell.md#terminal-marks).

## Limits

- Variables that bash maintains itself, such as `EPOCHSECONDS` and `RANDOM`, and the `kill` builtin, are refused.
- Not available yet: `.inputrc` and `bind`, `fc`, `HISTIGNORE`, `HISTTIMEFORMAT`, `compopt`, `IGNOREEOF`, the `-n` option of `history`, and a few completion options (`-C`, `-G`, and user, group, host and service names).
- <kbd>Ctrl</kbd>-<kbd>C</kbd> doesn't interrupt a loop the shell itself runs (programs it starts do receive it).
- A native session isn't recorded. With `[recording] human = true`, `knsh` says so once.
- Several inputs have size caps, for example 1 MiB for one line you type and for a sourced file, and 1,000 levels of nesting. See [Limits and defaults](../reference/limits.md#native-mode).

## How close to bash is it?

On release builds, `knsh`'s interpreter is measured against bash 5.2. On the collection of real commands agents run, 234 of 235 behave exactly as in bash. Against bash's own conformance tests it is less complete, which is why native mode is opt-in. If a script behaves differently, run it with your normal shell.
