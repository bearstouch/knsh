# Introduction

Kinetic Shell is a bash/zsh-compatible shell that lets AI agents run commands under recording, policy, operating-system sandboxing and best-effort undo.

It provides **mechanisms only**: the engine records, enforces and reports, while an external **authority** (a trusted client application) decides and presents.

## Binaries

| Binary | Role |
| --- | --- |
| `knsh` | The human's interactive shell; inside an agent's envelope, a thin client that forwards commands to the supervisor; the command-line interface to the API |
| `knshd` | The per-user daemon and **supervisor**: decides on and spawns every shell command an agent issues |
| `knsh-exec` | A small single-threaded sandbox trampoline that applies a sandbox profile and then runs the command |

## How it works, in one paragraph

An agent CLI (for example Claude Code) runs inside an **envelope**: a sandboxed process tree started by `knsh agent`. Its `SHELL` is `knsh`, so every shell command it issues is forwarded to `knshd`. The supervisor parses the whole line, runs hooks, evaluates policy, asks the authority if needed, and spawns the line through `knsh-exec` under a per-command sandbox profile, with network only through its own proxy. Every line becomes a structured record and a stream of events, and file changes are checkpointed so they can be undone where that is safe. Humans keep their own zsh or bash, observed only if they opt in, and are never blocked.

## Reading guide

| If you want to know… | Read |
| --- | --- |
| Why the system exists and what it will not do | [goals-and-non-goals.md](goals-and-non-goals.md), [design-principles.md](design-principles.md) |
| How the pieces fit | [../02-architecture/system-overview.md](../02-architecture/system-overview.md) |
| What happens when an agent runs a command | [../03-functional-requirements/command-lifecycle.md](../03-functional-requirements/command-lifecycle.md) |
| How to build a client or authority | [../06-api/README.md](../06-api/README.md), [../08-integrations/authority-apps.md](../08-integrations/authority-apps.md) |
| What the engine protects against | [../04-non-functional-requirements/security.md](../04-non-functional-requirements/security.md) |
| When each piece ships | [roadmap.md](roadmap.md) |
