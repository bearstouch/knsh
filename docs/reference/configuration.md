# Files and settings

## Where things are

| What | Where |
| --- | --- |
| Settings and hooks | `~/.config/knsh/config.toml` |
| Policy profiles | `~/.config/knsh/policies/<profile>.toml` (signed by `knshd`) |
| Your hook programs | Anywhere inside `~/.config/knsh/`, for example `~/.config/knsh/hooks/` |
| History | `~/Library/Application Support/knsh/records.db` |
| Grants and pushed policy | `~/Library/Application Support/knsh/state.json` |
| Checkpoints (home volume) | `~/Library/Application Support/knsh/checkpoints/` |
| Checkpoints (other APFS volumes) | `.knsh-checkpoints/` at the volume's top folder |
| Compiled sandbox profiles | `~/Library/Application Support/knsh/profiles/` (cleaned up automatically) |
| Shell startup wrappers | `~/Library/Application Support/knsh/shell/` |
| Shims for `sh`, `bash`, `zsh` | `~/Library/Application Support/knsh-shims/` |
| Sockets | `~/Library/Application Support/knsh/run/` |
| Launch agent | `~/Library/LaunchAgents/knsh.knshd.plist` |
| Secrets | Your Keychain, service name `knsh` |
| Logs | The macOS unified log, subsystem `knsh` |

The engine's folders are owner-only (directories `0700`, files `0600`), excluded from Spotlight and Time Machine, and off limits to every agent and every command it runs. No profile can change that. The shims folder is the one exception: agents must be able to find and run it, and it holds nothing secret.

If the state file can't be used, `knsh` sets it aside as `state.json.corrupt-<time>` or `state.json.newer-<time>` and starts clean. It never overwrites it.

To see recent log lines:

```sh
log show --last 10m --predicate 'subsystem == "knsh"'
```

## `config.toml`

```toml
[shell]
hosted = "zsh"        # "zsh", "bash", "native", or an absolute path to a program named zsh or bash

[recording]
human = true          # record your own commands (off by default)

[[hooks]]
event = "command.proposed"
match = { binary = ["rm", "git"] }
run = "~/.config/knsh/hooks/guard.sh"
timeout_ms = 2000
```

| Setting | Effect | Details |
| --- | --- | --- |
| `[shell] hosted` | Which shell `knsh` hosts for you. | [Using knsh as your shell](../guides/shell.md) |
| `[recording] human` | Record your own commands. Only `true` turns it on. | [Recording and history](../guides/recording.md) |
| `[[hooks]]` | Checks run before agent commands. | [Hooks](../guides/hooks.md) |

The file uses the same small TOML subset as policy profiles. Other tables in the file are left alone. An unknown key inside `[shell]` or `[recording]` makes the setting invalid: `knsh` reports it once and uses the default, and your shell starts anyway. For `[[hooks]]`, a file that can't be read denies every agent command (see [Hooks](../guides/hooks.md#failing-closed)).

## Environment variables

| Variable | Where | Meaning |
| --- | --- | --- |
| `SHELL` | Inside envelopes | `knsh`. |
| `PATH` | Inside envelopes | The shim folder comes first. |
| `HTTPS_PROXY`, `HTTP_PROXY` (and lowercase) | Inside envelopes and agent commands | The local proxy, with credentials made for that session or command. |
| `NODE_USE_ENV_PROXY=1`, `GIT_HTTP_PROXY_AUTHMETHOD=basic` | Inside envelopes | Make Node and git use that proxy. |
| `KNSH_RECORDING` | Your shell | `1` while your commands are recorded. Use it to show a recording indicator in your prompt. |
| Your secret variables | Matching agent commands | As named in `[secrets.env]`. |

`knsh` also uses a few private variables between itself and its startup wrappers (`KNSH_ZSH_ZDOTDIR`, `KNSH_TELEMETRY_FD`, and similar). They're removed before your own startup files run, except in a bash login shell, where your profile files can see them.

In bash, the recording hooks use two extra file descriptors, which commands you run can inherit.

## Startup files an agent can never touch

Agents can never write `~/.zshrc`, `~/.zprofile`, `~/.bashrc`, `~/.bash_profile` or `~/.profile`, in any profile.
