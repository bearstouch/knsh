# Using knsh as your shell

`knsh` can be your everyday shell. It hosts your own zsh or bash, so your prompt, aliases, plugins and startup files keep working, and it adds terminal marks and, if you want, recording. Nothing you type in your own shell is decided, rewritten or blocked.

## Start it

Type `knsh` in a terminal. `knsh` picks the shell to host like this:

1. The shell named in `[shell] hosted` in `~/.config/knsh/config.toml`, if you set one.
2. Otherwise your `$SHELL`, if it is bash.
3. Otherwise `/bin/zsh`.

`knsh` runs your normal startup files as that shell always does (`~/.zshrc`, `~/.bashrc` and so on). You don't edit any dotfile to use it.

Only an interactive `knsh` on a terminal is your own shell. A non-interactive `knsh` is treated as an agent: `knsh -c '…'`, a script run as `knsh script.sh`, or commands piped into it.

!!! warning "`knsh -c` is not a way to run your own commands"
    Outside an agent envelope, `knsh -c` runs the line under a built-in, locked-down profile called `unattended`: only plain read-only commands run, nothing can use the network, and anything that would need approval is denied (there is nobody to ask). It exists so that an agent CLI started by mistake with `SHELL=knsh`, but not through `knsh agent`, fails safe. For your own scripts and one-liners, use your normal shell (`zsh -c`, `bash -c`).

## Choose which shell to host

Create or edit `~/.config/knsh/config.toml`:

```toml
[shell]
hosted = "zsh"
```

| Value | Meaning |
| --- | --- |
| `"zsh"` | `/bin/zsh` |
| `"bash"` | `/bin/bash` (the macOS version, 3.2) |
| An absolute path | A program named `zsh` or `bash`, for example Homebrew's `/opt/homebrew/bin/bash` |
| `"native"` | `knsh`'s own bash interpreter. See [Native mode](native-mode.md). |

If the setting is invalid (an unknown value, an unknown key under `[shell]`, a file that can't be read, a program that isn't executable or is `knsh` itself), `knsh` starts `/bin/zsh` and prints a one-line warning. You are never left without a shell.

## Use knsh as your login shell

Terminals and `login` start a login shell when the program name starts with `-`. `knsh` follows that convention, and also accepts `-l` and `--login`. A login shell reads its login files (`~/.zprofile`, `~/.bash_profile`, …) as usual.

To make `knsh` your account's login shell:

1. Set `[shell] hosted` in `~/.config/knsh/config.toml`. Do this first: once `knsh` is your login shell, `$SHELL` names `knsh` itself and can't tell it what to host.
2. Add `knsh` to the list of allowed shells:

    ```sh
    knsh shell install
    ```

    It shows the exact path and asks `[y/N]`. On `y`, it appends the path to `/etc/shells` using `sudo`, which asks for your password. It needs a terminal, and it changes nothing without your answer. If the path is already listed, it does nothing.

3. Switch to it with the command `knsh` prints:

    ```sh
    chsh -s /path/to/knsh
    ```

`knsh shell install` never runs `chsh` for you.

!!! warning "Remote commands and tools that read your login shell"
    Programs that run commands through your login shell with `-c`, such as `ssh host command`, `scp`, `rsync` over ssh, and apps that run `$SHELL -l -c …`, are treated as unattended lines and are denied or restricted. Until you need `knsh` as the login shell, it is safer to leave your account shell as it is and start `knsh` from your terminal's own settings (most terminals let you choose a startup command).

## Terminal marks

When `knsh`'s output is a terminal, it makes the hosted shell write two kinds of marks that terminals can use:

| Mark | What a terminal can do with it |
| --- | --- |
| Working directory (OSC 7) | Open new tabs in the same folder. |
| Prompt, command, output and exit-code marks (OSC 133) | Jump between prompts, select a command's output, show success or failure. |

Terminals that don't understand them ignore them. When output is not a terminal (a pipe, a file), no marks are written.

## What `knsh` changes in your shell

Very little. With recording off and no terminal marks, `knsh` replaces itself with your shell and is gone, so signals, job control and the exit status are your shell's own. To add marks or recording, it starts your shell with a small startup wrapper in `~/Library/Application Support/knsh/shell/`, which restores your environment and runs your own startup files first.

A few things can switch the extras off without affecting your shell:

- A startup file that replaces `precmd_functions` or `preexec_functions` (zsh), or reassigns `PROMPT_COMMAND` without keeping its old value (bash), drops the recording hooks. Only recording and marks are lost.
- Setting `PROMPT_COMMAND` yourself, interactively, in bash removes the hooks until the next shell.

## Add a recording indicator to your prompt

When recording is on, `knsh` sets `KNSH_RECORDING=1` in the shell, so your prompt can show it. For zsh:

```zsh
PROMPT='${KNSH_RECORDING:+[rec] }'$PROMPT
```

See [Recording and history](recording.md) for how to turn recording on.
