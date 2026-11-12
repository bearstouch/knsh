# Enforcement model

Two kinds of profile confine every agent. Both deny by default and are enforced by the kernel.

| Profile | Applies to | Started by |
| --- | --- | --- |
| **Envelope profile** | The agent CLI and everything it starts directly (its own file edits, network calls, helper processes, binaries run by absolute path) | `knshd`, through `knsh-exec`, when the agent session starts |
| **Per-command profile** | Each line the supervisor spawns | `knshd`, through `knsh-exec`, for every supervised line |

The envelope is the floor: nothing the agent starts directly can exceed it. Only commands spawned by the supervisor can receive more than the envelope allows, and only when policy or an approval grants it.

## Layers

| Layer | What it enforces | Authority of its reports |
| --- | --- | --- |
| Seatbelt sandbox | Files, executables, system services, Unix sockets, network (only to proxy and allowed loopback ports), process information | File denials read from the system log, best effort |
| Endpoint Security descendant client (macOS 27+) | Every exec inside an envelope, decided by `knshd` | Authoritative |
| Network proxy | Hosts, per-command identity, name and address checks | Authoritative |
| Credential scoping | Secrets only to approved matching lines, network narrowed to the secret's hosts | — |
| Command rules (policy) | Intent filters: make approvals specific and stop honest mistakes | Not a hard limit |

## Applying profiles

- `knshd` compiles each profile into a private file in an engine path. `knsh-exec`, which is single-threaded, applies it and then runs the command.
- Profiles are never applied inside `knshd` between `fork` and `exec`, which is unsafe in a multithreaded process.
- `knsh-exec` applies the profile by running Apple's `sandbox-exec` tool with the profile in a private file (`-f`), the same deprecated but widely relied-on tool Codex CLI and Claude Code use (decision 1 in [decisions](../reference/decisions.md)). A file also avoids command-line length limits.
- On macOS 27 and later, `knshd` also runs an Endpoint Security descendant client over every envelope as a second layer (decision 3).
- If neither works, the capability probe reports `sandbox: none` and agent sessions refuse to start.

## No nesting

A process that is already sandboxed cannot apply another profile. Consequences:

- Tools that sandbox themselves (Chromium and Playwright browsers, `swift build`, some Bazel setups) and agent CLIs' own sandboxes fail inside an envelope or command profile.
- An agent CLI's own sandbox must be turned off inside an envelope; the envelope replaces it.
- A profile can name **trusted tools**, which the supervisor runs without a per-command profile, only after an approval or grant.
- Each release publishes a compatibility list ([developer tools](../integrations/developer-tools.md)).

## Violations

- Network refusals come from the proxy and are authoritative.
- File denials are read from the system log by tag, best effort: they can be delayed, merged, or change format between macOS versions.
- Every deny rule carries a knsh tag, so reported violations can be traced to a session and command.

The contents of each profile are specified in [../functional-requirements/sandbox-profiles.md](../functional-requirements/sandbox-profiles.md).
