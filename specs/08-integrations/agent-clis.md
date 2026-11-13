# Agent CLIs

How agent CLIs such as Claude Code and Codex CLI run under Kinetic Shell. Requirements are in [../03-functional-requirements/agent-integration.md](../03-functional-requirements/agent-integration.md).

## Starting

```sh
knsh agent --profile web-app -- claude
```

`knshd` starts the CLI through `knsh-exec` inside an envelope, with:

| Setting | Value |
| --- | --- |
| `SHELL` | `knsh` |
| `PATH` | Shim directory first (`sh`, `bash`, `zsh` → `knsh -c`) |
| Session token | In the environment, used by the `knsh` client in `hello` |
| Proxy settings | Per-envelope proxy credentials |
| Actor | `--agent <name>`, or derived from the command (`claude` → `claude-code`) |

## Presets

A preset grants what the CLI itself needs: its model API host (for example `api.anthropic.com`), its own configuration and credential folder (for example `~/.claude`), and the project. It may also set tool-specific proxy settings and classes, such as letting `git fetch` reach github.com.

| Preset | Status in phase 2 |
| --- | --- |
| `claude-code` | Tested |
| Codex CLI | Tested |
| Generic | For other CLIs |

How each CLI chooses its shell is verified per release.

## Requirements on the CLI

| Requirement | Why |
| --- | --- |
| The CLI's shell tool honours `SHELL` or calls `sh`/`bash` by name | Otherwise commands run directly in the envelope without per-command decisions (except on macOS 27+, see decision 3) |
| The CLI's own sandbox is turned off | macOS cannot apply a second sandbox inside a sandboxed process; the envelope replaces it |
| The CLI's tool timeout is longer than the authority decision timeout (default 90 s) | Otherwise the CLI gives up before a human can approve |

## Behaviour by command path

| What the agent runs | Decided per command | Confined |
| --- | --- | --- |
| `$SHELL -c`, `sh`/`bash`/`zsh` by name | Yes, by the supervisor | Per-command profile |
| `/bin/bash -c`, `#!/bin/bash` scripts, absolute paths | No (yes on macOS 27+ with Endpoint Security) | Envelope profile |
| Built-in file-edit and fetch tools | No | Envelope profile; recorded as agent edits |

## Using the API directly

Agents that integrate natively can call `exec.run` on `agent.sock` instead of `knsh -c`, to choose an output mode and receive structured results ([agent socket](../06-api/agent-socket.md)).
