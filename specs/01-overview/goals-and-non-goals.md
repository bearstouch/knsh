# Goals and non-goals

## Goals

| # | Goal | Main documents |
| --- | --- | --- |
| G1 | Run existing bash and zsh scripts, rc files and agent-generated commands unchanged. | [compatibility](../nonfunctional-requirements/compatibility.md) |
| G2 | Run agent CLIs inside an operating-system envelope, and run every shell command they issue through a supervisor that decides before anything starts. | [agent integration](../functional-requirements/agent-integration.md), [command lifecycle](../functional-requirements/command-lifecycle.md) |
| G3 | Turn every agent command into a structured record and a stream of events. | [execution records](../functional-requirements/execution-records.md), [events](../functional-requirements/events.md) |
| G4 | Let an authority allow, deny, rewrite or hold agent commands before they run. | [authority](../functional-requirements/authority.md), [hooks](../functional-requirements/hooks.md) |
| G5 | Limit files, network and credentials per agent and per command at the operating-system level. | [sandbox profiles](../functional-requirements/sandbox-profiles.md), [network proxy](../functional-requirements/network-proxy.md), [secrets](../functional-requirements/secrets.md) |
| G6 | Make agent file changes reversible where that is safe, and say clearly when it is not. | [checkpoints](../functional-requirements/checkpoints.md), [irreversible actions](../functional-requirements/irreversible-actions.md) |
| G7 | Fail closed for agents when any part of the system is missing. | [reliability](../nonfunctional-requirements/reliability.md) |

## Non-goals

- **A user interface.** The engine ships a CLI and an API; presentation belongs to clients.
- **A new scripting language as the default.** Structured pipelines are optional and late ([roadmap](roadmap.md), phase 6).
- **A terminal emulator.** The engine runs inside any terminal.
- **Guaranteed undo.** Checkpoints are best-effort and refuse to restore when unsure ([checkpoints](../functional-requirements/checkpoints.md)).
- **Restricting human sessions.** Humans are observed when they opt in, never blocked.
- **Remote or cloud storage, and Windows support.**
