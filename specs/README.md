# Kinetic Shell — Specifications

Nov 12, 2026 · Helder Vasconcelos

Kinetic Shell is a bash/zsh-compatible shell that lets AI agents run commands under recording, policy, operating-system sandboxing and best-effort undo. This folder splits the specification into topic documents. Start with [overview/introduction.md](overview/introduction.md).

## Conventions

- Requirements are numbered: `FR-<AREA>-NN` for functional requirements, `NFR-<AREA>-NN` for non-functional requirements. IDs are stable; new requirements get new numbers.
- "Must" marks a requirement; "should" marks a recommendation.
- Section references of the form "(section N)" in earlier drafts are replaced by links to the document that now holds that content.
- Terms in **bold** on first use are defined in [reference/glossary.md](reference/glossary.md).

## Document map

### Overview

| Document | Contents |
| --- | --- |
| [introduction.md](overview/introduction.md) | What Kinetic Shell is, the three binaries, reading guide |
| [goals-and-non-goals.md](overview/goals-and-non-goals.md) | Goals and explicit non-goals |
| [design-principles.md](overview/design-principles.md) | The principles every other document follows |
| [roadmap.md](overview/roadmap.md) | Phases 1–6 and what each delivers |

### Architecture

| Document | Contents |
| --- | --- |
| [system-overview.md](architecture/system-overview.md) | Binaries, components and the overall diagram |
| [endpoints.md](architecture/endpoints.md) | `agent.sock`, `user.sock`, the XPC control service, trust boundaries |
| [process-model.md](architecture/process-model.md) | `knshd` lifecycle under launchd, data locations |
| [enforcement-model.md](architecture/enforcement-model.md) | Envelope and per-command profiles, `knsh-exec`, layering |
| [implementation.md](architecture/implementation.md) | Implementation language and platform interface |
| [platform-support.md](architecture/platform-support.md) | macOS and Linux backends |

### Functional requirements

| Document | Contents |
| --- | --- |
| [README.md](functional-requirements/README.md) | Index of requirement areas and ID prefixes |
| [agent-integration.md](functional-requirements/agent-integration.md) | Envelopes, starting agents, how commands reach the supervisor |
| [sessions.md](functional-requirements/sessions.md) | Session creation, actors, states, human sessions |
| [command-lifecycle.md](functional-requirements/command-lifecycle.md) | The eleven-step agent command lifecycle |
| [execution-records.md](functional-requirements/execution-records.md) | When records are written, redaction, retention |
| [events.md](functional-requirements/events.md) | Event delivery and sequencing |
| [hooks.md](functional-requirements/hooks.md) | Hook execution, verdicts, combining, rate limiting |
| [policy.md](functional-requirements/policy.md) | Profiles, matching, integrity, grants |
| [authority.md](functional-requirements/authority.md) | The authority, trust, decisions, rewrites, local approvals |
| [sandbox-profiles.md](functional-requirements/sandbox-profiles.md) | What envelope and command profiles contain |
| [network-proxy.md](functional-requirements/network-proxy.md) | Per-command identity, host rules, connection checks |
| [secrets.md](functional-requirements/secrets.md) | Secret storage, injection and redaction |
| [output-modes.md](functional-requirements/output-modes.md) | Output modes for `exec.run` |
| [checkpoints.md](functional-requirements/checkpoints.md) | Shadows, attribution, capture, restore, history tree |
| [irreversible-actions.md](functional-requirements/irreversible-actions.md) | Flagging actions checkpoints cannot undo |

### Non-functional requirements

| Document | Contents |
| --- | --- |
| [security.md](nonfunctional-requirements/security.md) | Threat model and security requirements |
| [reliability.md](nonfunctional-requirements/reliability.md) | Fail-closed behaviour and standalone mode |
| [performance.md](nonfunctional-requirements/performance.md) | Performance targets |
| [privacy.md](nonfunctional-requirements/privacy.md) | Recording defaults, locality, deletion |
| [compatibility.md](nonfunctional-requirements/compatibility.md) | Bash/zsh compatibility, exit status, interpreters |
| [supply-chain.md](nonfunctional-requirements/supply-chain.md) | Dependency policy |

### API

| Document | Contents |
| --- | --- |
| [README.md](api/README.md) | API overview, endpoints, versioning |
| [wire-format.md](api/wire-format.md) | Frames, binary streams, strict JSON profile |
| [handshake.md](api/handshake.md) | `hello` and capability reporting |
| [agent-socket.md](api/agent-socket.md) | Methods on `agent.sock` |
| [user-socket.md](api/user-socket.md) | Methods on `user.sock` |
| [control-service.md](api/control-service.md) | Methods on the XPC control service, decision protocol |
| [errors.md](api/errors.md) | Error codes |
| [cli.md](api/cli.md) | The `knsh` command-line interface |

### Models

| Document | Contents |
| --- | --- |
| [session.md](models/session.md) | Session fields and states |
| [execution-record.md](models/execution-record.md) | Execution record fields |
| [event.md](models/event.md) | Event envelope and catalog |
| [policy-profile.md](models/policy-profile.md) | Policy profile TOML schema |
| [grant.md](models/grant.md) | Grants |
| [hook.md](models/hook.md) | Hook registration and verdicts |
| [checkpoint.md](models/checkpoint.md) | Checkpoints, states, post-image identity |
| [secret.md](models/secret.md) | Secret definitions |
| [capabilities.md](models/capabilities.md) | Capability report returned by `hello` |

### Integrations

| Document | Contents |
| --- | --- |
| [agent-clis.md](integrations/agent-clis.md) | Running Claude Code, Codex CLI and other agent CLIs |
| [authority-apps.md](integrations/authority-apps.md) | Building a trusted authority application |
| [hooks.md](integrations/hooks.md) | Writing hooks |
| [macos-services.md](integrations/macos-services.md) | launchd, XPC, Keychain, LocalAuthentication, FSEvents, Seatbelt, Endpoint Security |
| [developer-tools.md](integrations/developer-tools.md) | Proxy settings, self-sandboxing tools, trusted tools |
| [terminals-and-shells.md](integrations/terminals-and-shells.md) | Integration mode, OSC 7/133, login shell setup |

### Testing

| Document | Contents |
| --- | --- |
| [test-strategy.md](testing/test-strategy.md) | Overall test approach and CI gates |
| [conformance.md](testing/conformance.md) | Bash conformance and parser exit criteria |
| [agent-command-corpus.md](testing/agent-command-corpus.md) | Sources and normalisation of the corpus |
| [fuzzing.md](testing/fuzzing.md) | Fuzzing of hand-written parsers |
| [performance-validation.md](testing/performance-validation.md) | How performance targets are measured |
| [verification-claims.md](testing/verification-claims.md) | Platform claims to verify before phase 2 |

### Reference

| Document | Contents |
| --- | --- |
| [glossary.md](reference/glossary.md) | Terms |
| [defaults-and-limits.md](reference/defaults-and-limits.md) | Every default value and limit in one table |
| [exit-codes.md](reference/exit-codes.md) | Exit codes of `knsh` and supervised lines |
| [file-locations.md](reference/file-locations.md) | Paths, sockets and service names |
| [decisions.md](reference/decisions.md) | Decision log and open questions |

## Source mapping

| Original section | New location |
| --- | --- |
| 1. Overview | `overview/` |
| 2. Architecture | `architecture/`, `nonfunctional-requirements/supply-chain.md`, `reference/file-locations.md` |
| 3. Agent integration | `functional-requirements/agent-integration.md`, `integrations/agent-clis.md` |
| 4. Sessions and the command lifecycle | `functional-requirements/sessions.md`, `functional-requirements/command-lifecycle.md`, `models/session.md` |
| 5. Execution records | `functional-requirements/execution-records.md`, `models/execution-record.md` |
| 6. Events and hooks | `functional-requirements/events.md`, `functional-requirements/hooks.md`, `models/event.md`, `models/hook.md`, `integrations/hooks.md` |
| 7. Policy and the authority | `functional-requirements/policy.md`, `functional-requirements/authority.md`, `models/policy-profile.md`, `models/grant.md`, `integrations/authority-apps.md` |
| 8. Sandbox, network, secrets and output | `architecture/enforcement-model.md`, `functional-requirements/sandbox-profiles.md`, `network-proxy.md`, `secrets.md`, `output-modes.md` |
| 9. Checkpoints | `functional-requirements/checkpoints.md`, `functional-requirements/irreversible-actions.md`, `models/checkpoint.md` |
| 10. API | `api/` |
| 11. Compatibility, standalone mode and privacy | `nonfunctional-requirements/compatibility.md`, `reliability.md`, `privacy.md`, `integrations/terminals-and-shells.md` |
| 12. Security, performance, platforms and roadmap | `nonfunctional-requirements/security.md`, `performance.md`, `architecture/platform-support.md`, `overview/roadmap.md`, `reference/decisions.md`, `testing/verification-claims.md` |
