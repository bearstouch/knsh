# Goals and non-goals

## Goals

| # | Goal | Main documents |
| --- | --- | --- |
| G1 | Run existing bash and zsh scripts, rc files and agent-generated commands unchanged. | [compatibility](../04-non-functional-requirements/compatibility.md) |
| G2 | Run agent CLIs inside an operating-system envelope, and run every shell command they issue through a supervisor that decides before anything starts. | [agent integration](../03-functional-requirements/agent-integration.md), [command lifecycle](../03-functional-requirements/command-lifecycle.md) |
| G3 | Turn every agent command into a structured record and a stream of events. | [execution records](../03-functional-requirements/execution-records.md), [events](../03-functional-requirements/events.md) |
| G4 | Let an authority allow, deny, rewrite or hold agent commands before they run. | [authority](../03-functional-requirements/authority.md), [hooks](../03-functional-requirements/hooks.md) |
| G5 | Limit files, network and credentials per agent and per command at the operating-system level. | [sandbox profiles](../03-functional-requirements/sandbox-profiles.md), [network proxy](../03-functional-requirements/network-proxy.md), [secrets](../03-functional-requirements/secrets.md) |
| G6 | Make agent file changes reversible where that is safe, and say clearly when it is not. | [checkpoints](../03-functional-requirements/checkpoints.md), [irreversible actions](../03-functional-requirements/irreversible-actions.md) |
| G7 | Fail closed for agents when any part of the system is missing. | [reliability](../04-non-functional-requirements/reliability.md) |

## Non-goals

- **A user interface.** The engine ships a CLI and an API; presentation belongs to clients.
- **A new scripting language as the default.** Structured pipelines are optional and late ([roadmap](roadmap.md), phase 6).
- **A terminal emulator.** The engine runs inside any terminal.
- **Guaranteed undo.** Checkpoints are best-effort and refuse to restore when unsure ([checkpoints](../03-functional-requirements/checkpoints.md)).
- **Restricting human sessions.** Humans are observed when they opt in, never blocked.
- **Remote or cloud storage, and Windows support.**
