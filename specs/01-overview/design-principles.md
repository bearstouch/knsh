# Design principles

Every other document follows these principles. When a design choice conflicts with one of them, the principle wins unless a decision in [../reference/decisions.md](../reference/decisions.md) says otherwise.

| Principle | Meaning |
| --- | --- |
| **Mechanism, not policy** | The engine evaluates and enforces rules it is given; it never authors them. |
| **The operating system enforces; the shell observes** | Hard limits come from the sandbox, the network proxy and credential scoping. Command rules are intent filters on top of them. |
| **One process starts agent commands** | The supervisor in `knshd` spawns every shell command an agent issues. Nothing inside an agent's envelope can grant itself more. |
| **Fail closed for agents, open for humans** | An agent action nobody can approve is denied; a human at a prompt is never blocked. |
| **Local and private by default** | Recording is opt-in for humans, redacted before storage, and never leaves the machine. |
| **Compatibility first** | A feature that breaks bash compatibility is not shipped as a default. |
| **Honest capabilities** | The engine reports what it can guarantee on this machine instead of silently degrading. |
