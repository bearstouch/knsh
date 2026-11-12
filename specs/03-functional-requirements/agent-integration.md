# Agent integration

An agent CLI runs inside an **envelope**: a sandboxed process tree started by `knsh agent`. Everything the agent does directly (its own file edits, network calls and helper processes) is confined by the envelope, and every shell command it issues is executed by the supervisor outside the envelope, under a profile of its own.

## Starting an agent

```sh
knsh agent --profile web-app -- claude
```

| ID | Requirement |
| --- | --- |
| FR-AGT-01 | `knsh agent` must ask `knshd` over `user.sock` to create an agent session. |
| FR-AGT-02 | The actor must be the name given with `--agent`, or derived from the command (`claude` becomes `claude-code`). |
| FR-AGT-03 | `knshd` must compile the envelope profile and start the agent CLI through `knsh-exec`, with `SHELL` set to `knsh`, the shim directory first in `PATH`, a session token in the environment, and network routed through the proxy. |
| FR-AGT-04 | The envelope must allow what the CLI itself needs: its model API host (for example `api.anthropic.com`), its own configuration and credential folder (for example `~/.claude`), and the project. Profiles ship presets for supported CLIs ([agent CLIs](../integrations/agent-clis.md)). |
| FR-AGT-05 | The agent CLI's own sandbox must be turned off inside an envelope, because macOS cannot apply a second sandbox inside a sandboxed process. The envelope replaces it. |
| FR-AGT-06 | Agent sessions must refuse to start when the capability probe reports `sandbox: none`. |

## How commands reach the supervisor

| What the agent runs | What happens |
| --- | --- |
| `$SHELL -c '…'`, which is `knsh -c` | The client forwards the line, working directory, environment and stdio descriptors over `agent.sock`; the supervisor decides and spawns it |
| `sh`, `bash` or `zsh` by name | The shims route it to `knsh -c`, as above |
| `/bin/bash -c …`, a `#!/bin/bash` script, or any binary by absolute path | Runs directly inside the envelope: confined by the envelope profile and visible through its file and network effects, but not decided command by command, except on macOS 27 and later, where every exec is decided through Endpoint Security (decision 3) |
| The agent's built-in file-edit and fetch tools | Run inside the envelope: limited by its file and network rules; file changes are recorded as **agent edits** ([checkpoints](checkpoints.md)) |

| ID | Requirement |
| --- | --- |
| FR-AGT-10 | Inside an envelope, `knsh -c` and the `sh`/`bash`/`zsh` shims must forward the command line, working directory, environment and stdio descriptors to the supervisor over `agent.sock`, then exit with the supervisor's exit code. |
| FR-AGT-11 | Nothing the agent starts directly may exceed the envelope profile. |
| FR-AGT-12 | Only commands spawned by the supervisor may receive more than the envelope allows, and only when policy or an approval grants it. |
| FR-AGT-13 | On macOS 27 and later, where the Endpoint Security descendant client is available, `knshd` must decide every exec inside an envelope, including binaries run by absolute path. |

## Who counts as an agent

| ID | Requirement |
| --- | --- |
| FR-AGT-20 | Any process inside an envelope must be treated as the agent, whatever it claims. Commands typed into an envelope's terminal are agent commands too, and labels never relax policy. |
| FR-AGT-21 | A non-interactive `knsh` or `knsh -c` outside any envelope (for example an agent CLI started with `SHELL=knsh` but not through `knsh agent`) must run under the `unattended` profile: supervised, sandboxed, and denied anything that needs approval. |
| FR-AGT-22 | Only an interactive `knsh` on a terminal outside any envelope is a human session. |
| FR-AGT-23 | A request on `agent.sock` without a valid session token must be matched to its envelope through the caller's audit token. If that fails, it must be refused (`-32009`). |

## Supported agent CLIs

| ID | Requirement |
| --- | --- |
| FR-AGT-30 | Any CLI whose shell tool honours `SHELL` or calls `sh` or `bash` by name must get per-command decisions. |
| FR-AGT-31 | A CLI that hard-codes `/bin/bash` must still run, confined by its envelope, but loses per-command decisions (except under FR-AGT-13). |
| FR-AGT-32 | Phase 2 must ship tested presets for Claude Code and Codex CLI and a generic preset for others. How each CLI chooses its shell is verified per release. |
