# Agent CLIs

How agent CLIs such as Claude Code and Codex CLI run under Kinetic Shell. Requirements are in [../03-functional-requirements/agent-integration.md](../03-functional-requirements/agent-integration.md).

## Starting

```sh
knsh agent --profile web-app -- claude
```

`knshd` compiles the envelope profile (the session's profile with its preset, deny by default, `agent.sock` the only Unix socket it may connect to) and starts the CLI through `knsh-exec` inside an envelope, in a process group of its own, with:

| Setting | Value |
| --- | --- |
| `SHELL` | `knsh` |
| `PATH` | Shim directory first (`sh`, `bash`, `zsh` → `knsh -c`) |
| Session token | In the environment, used by the `knsh` client in `hello` |
| Proxy settings | Per-envelope proxy credentials ([decision 14](../09-reference/decisions.md)): `HTTPS_PROXY`, `https_proxy`, `HTTP_PROXY`, `http_proxy` set to `http://knsh-<id>:<token>@127.0.0.1:<port>`, `NODE_USE_ENV_PROXY=1`, `GIT_HTTP_PROXY_AUTHMETHOD=basic`. Inherited proxy settings (`ALL_PROXY`, `NO_PROXY`, the tool-specific ones) are removed. Issued when the session opens, revoked when it ends. None until the proxy runs (KNSH-059): the envelope then reaches only its loopback ports |
| Actor | `--agent <name>`, or derived from the command's file name (table below) |

| Command | Actor |
| --- | --- |
| `claude` | `claude-code` |
| `codex` | `codex-cli` |
| anything else | its own file name, if it is 1–64 characters from `[A-Za-z0-9._-]`; otherwise `--agent` is required |

## Presets

A preset grants what the CLI itself needs: its model API host (for example `api.anthropic.com`), its own configuration and credential folder (for example `~/.claude`), and the project. It may also set tool-specific proxy settings and class host rules (`network.class_hosts`, [policy](../03-functional-requirements/policy.md)), such as letting `git fetch` reach github.com. Presets are TOML shipped in the engine (`knsh-core`, `policy/presets/`) and only add to lists. Each path a preset writes is also added to `fs.read` when the profile lists its reads.

| Preset | Writes (and reads) | Hosts (`network.hosts`) | Tool-specific settings | Read from |
| --- | --- | --- | --- | --- |
| `claude-code` | `${PROJECT}`, `~/.claude`, `~/.claude.json` | `api.anthropic.com` (model API), `platform.claude.com` (OAuth token refresh for claude.ai sign-in) | None: the native build reads `HTTPS_PROXY`/`HTTP_PROXY` itself | Claude Code 2.1.325 |
| `codex-cli` | `${PROJECT}`, `~/.codex` | `api.openai.com` (model API with an API key), `chatgpt.com` (model API with ChatGPT sign-in), `auth.openai.com` (token refresh) | None: it reads `HTTPS_PROXY`/`HTTP_PROXY` itself | Codex CLI 0.165.0 |
| `generic` | `${PROJECT}` | None. The profile must name the model host (`network.hosts` under `network.mode = "allowlist"`) or a local model's port (`network.loopback`); the loader refuses it otherwise (`MissingKey` at `network.hosts`) | None | — |

A preset grants hosts, never `network.mode`: a profile that leaves the mode at its default (`none`) keeps the CLI off the network. No shipped preset sets class host rules; a profile adds them where its commands need them.

The hosts and folders were read from the installed releases' binaries (URLs, settings keys and environment variables they name), not from a run with network access; the manual integration check below confirms them per release.

**Known limit: writable CLI settings.** The presets make `~/.claude` and `~/.codex` writable, as the CLIs need
(FR-AGT-04). An agent can therefore edit the CLI's own settings there (Claude Code's hooks in
`~/.claude/settings.json`, Codex's `config.toml`), which take effect the next time the user starts the CLI outside an
envelope. Edits are recorded as agent edits; denying the settings files inside those folders is a follow-up to
decide in the [threat model](../04-non-functional-requirements/security.md).

**Known limit: fetch is broad.** `network:fetch` includes commands such as `npm install`, whose install scripts run
code: a host listed under `network.class_hosts.fetch` is open to those scripts too.

### Turning off the CLI's own sandbox

macOS cannot apply a second sandbox inside a sandboxed process (FR-AGT-05), so a CLI that sandboxes its own commands fails inside an envelope. `knsh agent` reads the CLI's settings before starting it and prints a warning on stderr when its sandbox is on, or when a setting it needs cannot be read or understood. It never changes the settings and never stops the CLI.

| CLI | Default | Turned off by | What `knsh agent` reads, highest precedence first |
| --- | --- | --- | --- |
| Claude Code | Off | `"sandbox": {"enabled": false}`, or no `sandbox.enabled` | Managed settings (`/Library/Application Support/ClaudeCode/managed-settings.json`), `--settings` (file or inline JSON), `.claude/settings.local.json` and `.claude/settings.json` in the working directory, `settings.json` in `CLAUDE_CONFIG_DIR` or `~/.claude`. The first that sets `sandbox.enabled` decides |
| Codex CLI | **On** (`read-only` or `workspace-write`) | `--sandbox danger-full-access` (`-s`), `--dangerously-bypass-approvals-and-sandbox`, `-c sandbox_mode=danger-full-access`, or `sandbox_mode = "danger-full-access"` in `config.toml` | The flags, then `-c sandbox_mode=…`, then `config.toml` in `CODEX_HOME` or `~/.codex`: the selected profile's `sandbox_mode` (`--profile`/`-p`, or the file's own `profile`), then the top-level one. A file outside the TOML subset `knsh` reads is reported as not checked |

### Per-release checklist

Run for each new release of a CLI with a preset, before the preset is marked as tested for it. Record the release and the results in the preset file's header and in the table above.

1. **Shell.** The CLI's shell tool honours `SHELL` or calls `sh`, `bash` or `zsh` by name (FR-AGT-30). Inside an envelope `SHELL` is `knsh` and the shims come first on `PATH`. Claude Code 2.1.325 uses `CLAUDE_CODE_SHELL` or `SHELL` only when the path contains `bash` or `zsh`, so with `SHELL=knsh` it takes `zsh` from `PATH`, which is the shim; check that a command it runs arrives at the supervisor. Codex CLI's shell choice must be checked the same way.
2. **Model host and sign-in.** Model traffic reaches only the preset's hosts and passes the TLS server-name check (FR-NET-06); a session survives a token refresh.
3. **Configuration folder.** The CLI starts, resumes a session and saves its state with only the preset's paths writable (Claude Code also writes `~/.claude.json`; check it is saved when a temporary file beside it in `~` is refused).
4. **Proxy.** The CLI's own HTTP client uses `HTTPS_PROXY` with Basic credentials; a CLI that needs a tool-specific setting gets it in its preset (FR-NET-12).
5. **Sandbox switch.** The settings and flags in the table above still turn the CLI's sandbox off, and `knsh agent` warns when it is on.

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
