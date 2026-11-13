# Kinetic Shell — Specifications

Nov 12, 2026 · Helder Vasconcelos

Kinetic Shell is a bash/zsh-compatible shell that lets AI agents run commands under recording, policy, operating-system sandboxing and best-effort undo. This folder splits the specification into topic documents. Start with [01-overview/introduction.md](01-overview/introduction.md).

## Conventions

- Requirements are numbered: `FR-<AREA>-NN` for functional requirements, `NFR-<AREA>-NN` for non-functional requirements. IDs are stable; new requirements get new numbers.
- "Must" marks a requirement; "should" marks a recommendation.
- Section references of the form "(section N)" in earlier drafts are replaced by links to the document that now holds that content.
- Terms in **bold** on first use are defined in [09-reference/glossary.md](09-reference/glossary.md).

## Document map

### Stories

| Document | Contents |
| --- | --- |
| [00-stories/README.md](00-stories/README.md) | Implementation stories by phase: conventions, sizes, phase gates and the full catalogue |

### Overview

| Document | Contents |
| --- | --- |
| [introduction.md](01-overview/introduction.md) | What Kinetic Shell is, the three binaries, reading guide |
| [goals-and-non-goals.md](01-overview/goals-and-non-goals.md) | Goals and explicit non-goals |
| [design-principles.md](01-overview/design-principles.md) | The principles every other document follows |
| [roadmap.md](01-overview/roadmap.md) | Phases 1–6 and what each delivers |

### Architecture

| Document | Contents |
| --- | --- |
| [system-overview.md](02-architecture/system-overview.md) | Binaries, components and the overall diagram |
| [endpoints.md](02-architecture/endpoints.md) | `agent.sock`, `user.sock`, the XPC control service, trust boundaries |
| [process-model.md](02-architecture/process-model.md) | `knshd` lifecycle under launchd, data locations |
| [enforcement-model.md](02-architecture/enforcement-model.md) | Envelope and per-command profiles, `knsh-exec`, layering |
| [implementation.md](02-architecture/implementation.md) | Implementation language and platform interface |
| [platform-support.md](02-architecture/platform-support.md) | macOS and Linux backends |

### Functional requirements

| Document | Contents |
| --- | --- |
| [README.md](03-functional-requirements/README.md) | Index of requirement areas and ID prefixes |
| [agent-integration.md](03-functional-requirements/agent-integration.md) | Envelopes, starting agents, how commands reach the supervisor |
| [sessions.md](03-functional-requirements/sessions.md) | Session creation, actors, states, human sessions |
| [command-lifecycle.md](03-functional-requirements/command-lifecycle.md) | The eleven-step agent command lifecycle |
| [execution-records.md](03-functional-requirements/execution-records.md) | When records are written, redaction, retention |
| [events.md](03-functional-requirements/events.md) | Event delivery and sequencing |
| [hooks.md](03-functional-requirements/hooks.md) | Hook execution, verdicts, combining, rate limiting |
| [policy.md](03-functional-requirements/policy.md) | Profiles, matching, integrity, grants |
| [authority.md](03-functional-requirements/authority.md) | The authority, trust, decisions, rewrites, local approvals |
| [sandbox-profiles.md](03-functional-requirements/sandbox-profiles.md) | What envelope and command profiles contain |
| [network-proxy.md](03-functional-requirements/network-proxy.md) | Per-command identity, host rules, connection checks |
| [secrets.md](03-functional-requirements/secrets.md) | Secret storage, injection and redaction |
| [output-modes.md](03-functional-requirements/output-modes.md) | Output modes for `exec.run` |
| [checkpoints.md](03-functional-requirements/checkpoints.md) | Shadows, attribution, capture, restore, history tree |
| [irreversible-actions.md](03-functional-requirements/irreversible-actions.md) | Flagging actions checkpoints cannot undo |

### Non-functional requirements

| Document | Contents |
| --- | --- |
| [security.md](04-non-functional-requirements/security.md) | Threat model and security requirements |
| [reliability.md](04-non-functional-requirements/reliability.md) | Fail-closed behaviour and standalone mode |
| [performance.md](04-non-functional-requirements/performance.md) | Performance targets |
| [privacy.md](04-non-functional-requirements/privacy.md) | Recording defaults, locality, deletion |
| [compatibility.md](04-non-functional-requirements/compatibility.md) | Bash/zsh compatibility, exit status, interpreters |
| [supply-chain.md](04-non-functional-requirements/supply-chain.md) | Dependency policy |

### API

| Document | Contents |
| --- | --- |
| [README.md](06-api/README.md) | API overview, endpoints, versioning |
| [wire-format.md](06-api/wire-format.md) | Frames, binary streams, strict JSON profile |
| [handshake.md](06-api/handshake.md) | `hello` and capability reporting |
| [agent-socket.md](06-api/agent-socket.md) | Methods on `agent.sock` |
| [user-socket.md](06-api/user-socket.md) | Methods on `user.sock` |
| [control-service.md](06-api/control-service.md) | Methods on the XPC control service, decision protocol |
| [errors.md](06-api/errors.md) | Error codes |
| [cli.md](06-api/cli.md) | The `knsh` command-line interface |

### Models

| Document | Contents |
| --- | --- |
| [session.md](05-models/session.md) | Session fields and states |
| [execution-record.md](05-models/execution-record.md) | Execution record fields |
| [event.md](05-models/event.md) | Event envelope and catalog |
| [policy-profile.md](05-models/policy-profile.md) | Policy profile TOML schema |
| [grant.md](05-models/grant.md) | Grants |
| [hook.md](05-models/hook.md) | Hook registration and verdicts |
| [checkpoint.md](05-models/checkpoint.md) | Checkpoints, states, post-image identity |
| [secret.md](05-models/secret.md) | Secret definitions |
| [capabilities.md](05-models/capabilities.md) | Capability report returned by `hello` |

### Integrations

| Document | Contents |
| --- | --- |
| [agent-clis.md](08-integrations/agent-clis.md) | Running Claude Code, Codex CLI and other agent CLIs |
| [authority-apps.md](08-integrations/authority-apps.md) | Building a trusted authority application |
| [hooks.md](08-integrations/hooks.md) | Writing hooks |
| [macos-services.md](08-integrations/macos-services.md) | launchd, XPC, Keychain, LocalAuthentication, FSEvents, Seatbelt, Endpoint Security |
| [developer-tools.md](08-integrations/developer-tools.md) | Proxy settings, self-sandboxing tools, trusted tools |
| [terminals-and-shells.md](08-integrations/terminals-and-shells.md) | Integration mode, OSC 7/133, login shell setup |

### Testing

| Document | Contents |
| --- | --- |
| [test-strategy.md](07-testing/test-strategy.md) | Overall test approach and CI gates |
| [conformance.md](07-testing/conformance.md) | Bash conformance and parser exit criteria |
| [agent-command-corpus.md](07-testing/agent-command-corpus.md) | Sources and normalisation of the corpus |
| [fuzzing.md](07-testing/fuzzing.md) | Fuzzing of hand-written parsers |
| [performance-validation.md](07-testing/performance-validation.md) | How performance targets are measured |
| [verification-claims.md](07-testing/verification-claims.md) | Platform claims to verify before phase 2 |

### Reference

| Document | Contents |
| --- | --- |
| [glossary.md](09-reference/glossary.md) | Terms |
| [defaults-and-limits.md](09-reference/defaults-and-limits.md) | Every default value and limit in one table |
| [exit-codes.md](09-reference/exit-codes.md) | Exit codes of `knsh` and supervised lines |
| [file-locations.md](09-reference/file-locations.md) | Paths, sockets and service names |
| [decisions.md](09-reference/decisions.md) | Decision log and open questions |

## Source mapping

| Original section | New location |
| --- | --- |
| 1. Overview | `01-overview/` |
| 2. Architecture | `02-architecture/`, `04-non-functional-requirements/supply-chain.md`, `09-reference/file-locations.md` |
| 3. Agent integration | `03-functional-requirements/agent-integration.md`, `08-integrations/agent-clis.md` |
| 4. Sessions and the command lifecycle | `03-functional-requirements/sessions.md`, `03-functional-requirements/command-lifecycle.md`, `05-models/session.md` |
| 5. Execution records | `03-functional-requirements/execution-records.md`, `05-models/execution-record.md` |
| 6. Events and hooks | `03-functional-requirements/events.md`, `03-functional-requirements/hooks.md`, `05-models/event.md`, `05-models/hook.md`, `08-integrations/hooks.md` |
| 7. Policy and the authority | `03-functional-requirements/policy.md`, `03-functional-requirements/authority.md`, `05-models/policy-profile.md`, `05-models/grant.md`, `08-integrations/authority-apps.md` |
| 8. Sandbox, network, secrets and output | `02-architecture/enforcement-model.md`, `03-functional-requirements/sandbox-profiles.md`, `network-proxy.md`, `secrets.md`, `output-modes.md` |
| 9. Checkpoints | `03-functional-requirements/checkpoints.md`, `03-functional-requirements/irreversible-actions.md`, `05-models/checkpoint.md` |
| 10. API | `06-api/` |
| 11. Compatibility, standalone mode and privacy | `04-non-functional-requirements/compatibility.md`, `reliability.md`, `privacy.md`, `08-integrations/terminals-and-shells.md` |
| 12. Security, performance, platforms and roadmap | `04-non-functional-requirements/security.md`, `performance.md`, `02-architecture/platform-support.md`, `01-overview/roadmap.md`, `09-reference/decisions.md`, `07-testing/verification-claims.md` |
