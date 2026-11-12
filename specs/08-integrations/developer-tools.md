# Developer tools

How common developer tools behave inside envelopes and per-command profiles.

## Proxy settings

Every envelope and supervised line gets its own proxy credentials in its proxy settings. All other network traffic is refused.

| Tool behaviour | Result |
| --- | --- |
| Honours standard proxy settings (curl, git over HTTPS, npm, pip, cargo) | Works, subject to host rules (to be verified per tool) |
| Ignores proxy settings (ssh git remotes, some Node and Java HTTP clients) | Blocked, not leaked |
| Has tool-specific proxy configuration | Presets set it |
| Connects to a local dev server or database | Allowed on `network.loopback` ports |
| Uses DNS directly | Blocked; the resolver service is denied, the proxy resolves names |

## Tools that sandbox themselves

A process that is already sandboxed cannot apply another profile. These fail inside an envelope or command profile:

- Chromium and Playwright browsers
- `swift build`
- Some Bazel setups
- Agent CLIs' own sandboxes (which must be turned off inside an envelope)

A profile can name **trusted tools**, which the supervisor runs without a per-command profile, only after an approval or grant. Each release publishes a compatibility list.

## Project executables

Binaries in agent-writable places (`node_modules/.bin`, `./scripts`) never match name rules. They fall under `exec.project_executables` (`allow`, `ask` or `deny`).

## Unix sockets

The Docker socket and the SSH agent socket are denied unless the profile allows them.

## Checkpoint exclusions

`node_modules`, `target`, `.venv`, `dist` and `build` are excluded from checkpoints by default. Undoing an `npm install` leaves `node_modules` out of step with the lockfile until install runs again.

## Publishing commands

Lines that receive secrets can run lifecycle scripts that read them (for example npm). Presets can rewrite publishing commands to skip lifecycle scripts where the tool allows it.
