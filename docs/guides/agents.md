# Agents in envelopes

`knsh agent` starts an agent CLI, such as Claude Code or Codex CLI, inside an *envelope*: a macOS sandbox with nothing allowed by default. Every command the agent runs is checked against a [policy profile](policy.md), run in a sandbox of its own, recorded, and, for file changes, [undoable](undo.md).

You need the background service for this: run `knsh daemon install` once ([Getting started](../getting-started.md#start-the-background-service)).

## Start an agent

```sh
cd ~/code/my-project
knsh agent --profile web-app -- claude
```

Everything after `--` is the command to run, passed through unchanged. `knsh agent` stays in the foreground and exits the way the agent did: with its exit code, or `128` plus the signal number if a signal ended it.

| Option | Meaning |
| --- | --- |
| `--profile <name>` | The [policy profile](policy.md) to use. A name of 1 to 64 letters, digits, `.`, `_` or `-`. |
| `--agent <name>` | The name recorded as the actor in history. By default it comes from the command: `claude` is `claude-code`, `codex` is `codex-cli`, anything else its own file name. Required if the file name has other characters. |
| `--json` | When the agent exits, print one JSON line with the session, agent, profile and exit information. |

The agent runs in the folder you started `knsh agent` from, with your environment. A command that can't be found exits with 127.

## What the agent gets

Inside the envelope:

- `SHELL` is `knsh`, and a folder of shims comes first on `PATH`, so when the agent runs `sh`, `bash` or `zsh` by name, or runs a command through `$SHELL -c`, the command goes to `knsh`, which asks the supervisor to decide it.
- Proxy settings (`HTTPS_PROXY`, `HTTP_PROXY` and their lowercase forms) point to a local proxy that only lets through the hosts your profile allows. Proxy variables you had set, such as `ALL_PROXY` and `NO_PROXY`, are removed. See [Network access](network.md).
- A private session token, so `knsh` inside the envelope can prove which session it belongs to.

An interactive `knsh` started inside an envelope is not your shell: whatever is typed there is treated as the agent's own commands.

## What happens to each command

1. **Read.** The command line is parsed. Anything that can't be understood reliably, such as `eval`, `bash -c '…'`, `python -c '…'` or a line built from unknown expansions, is treated as *dynamic code*.
2. **Decide.** The profile's rules say allow, ask or deny. See [Policy profiles](policy.md).
3. **Ask, if needed.** The command waits for you or your approval app. See [Approvals and grants](approvals.md).
4. **Run.** The command runs in a sandbox built for it, with its own network credentials.
5. **Record.** The command, the decision, and what changed are saved.

A denied command exits with status `126` and the reason is always printed on stderr, so the agent can read why and adapt.

!!! info "Rules are not the wall"
    Command rules are a filter for intent: they make approvals specific and stop honest mistakes. What actually limits an agent is the sandbox (files, programs, sockets), the network proxy and the credentials it is given. A clever command line can't talk its way past the sandbox.

## Presets

A preset gives the agent CLI what it needs to work itself: its API host, and its own configuration folder. You name one in your profile with `preset = "…"`.

| Preset | Writable folders | Hosts it adds |
| --- | --- | --- |
| `claude-code` | the project, `~/.claude`, `~/.claude.json` | `api.anthropic.com`, `platform.claude.com` (sign-in refresh) |
| `codex-cli` | the project, `~/.codex` | `api.openai.com`, `chatgpt.com`, `auth.openai.com` |
| `generic` | the project | none: you must name the model host in `network.hosts`, or a local model's port in `network.loopback` |

A preset only adds to lists. It never turns the network on: your profile still needs `[network] mode = "allowlist"`, or the agent can't reach its own API.

!!! warning "The agent can edit its own settings"
    Presets make `~/.claude` and `~/.codex` writable, as those tools need. An agent could therefore change its own tool's settings there (for example Claude Code's hooks), which take effect the next time you start that tool outside `knsh`. Edits are recorded as agent edits, and you can look at them with `knsh history`.

## Turn off the agent's own sandbox

macOS can't apply a second sandbox inside a sandboxed process. If an agent CLI sandboxes its own commands, those commands fail inside the envelope. `knsh agent` reads the CLI's settings before starting it and warns on stderr if its sandbox is on, or if it couldn't read a setting. It never changes your settings and never stops the CLI.

| CLI | Sandbox by default | How to turn it off |
| --- | --- | --- |
| Claude Code | Off | Leave `sandbox.enabled` unset or `false` in its settings. |
| Codex CLI | **On** | `--sandbox danger-full-access` (or `-s`), `--dangerously-bypass-approvals-and-sandbox`, `-c sandbox_mode=danger-full-access`, or `sandbox_mode = "danger-full-access"` in `~/.codex/config.toml`. |

Turning off the tool's own sandbox is safe here only because the envelope replaces it.

## Make sure the agent uses `knsh`

Per-command decisions only happen when the agent's shell tool goes through `knsh`:

| What the agent runs | Decided one by one | Confined by |
| --- | --- | --- |
| `$SHELL -c`, or `sh` / `bash` / `zsh` by name | Yes | A sandbox built for that command |
| `/bin/bash -c`, `#!/bin/bash` scripts, or any command by absolute path | No | The envelope's sandbox |
| The agent's built-in file-edit and fetch tools | No | The envelope's sandbox, recorded as agent edits |

Commands in the second and third rows are still sandboxed and recorded; they just skip the per-command decision. Check once, after setting up a new agent version, that a command it runs shows up in `knsh history`.

Also set the agent's own tool timeout to be longer than the approval timeout (90 seconds by default). Otherwise the agent gives up before you've had a chance to answer.

## Pause, hold and stop

- Killing `knsh agent` closes its connection, and the service then stops the agent's whole process group.
- If a session is paused or an approval app has taken control, new commands are held rather than failed: `knsh -c` prints one notice, waits and tries again, so the agent just sees a slow command.
- The agent runs in a process group of its own, not your terminal's foreground group. <kbd>Ctrl</kbd>-<kbd>C</kbd> in the terminal reaches `knsh agent`, not the agent. Agent CLIs run the terminal in raw mode and read <kbd>Ctrl</kbd>-<kbd>C</kbd> as input anyway.

## Sessions started from inside a session

A session started from inside another one gets the same profile or a stricter one. If you ask for a looser profile, `knsh agent` refuses with an error.

## When something is refused

`knsh agent` exits with 1 and prints the reason when:

- no sandbox is available on this Mac,
- the profile is looser than the session it is started from,
- the profile doesn't exist or doesn't load, or `knshd` can't run the command,
- the agent couldn't be started, or the connection to `knshd` was lost.

See [Troubleshooting](../reference/troubleshooting.md).
