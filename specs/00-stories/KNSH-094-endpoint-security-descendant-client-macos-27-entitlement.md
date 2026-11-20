# KNSH-094 — Endpoint Security descendant client (macOS 27+, entitlement-gated)

[Phase 3](README.md#phase-3--reverse-and-protect) · [Story index and plan](README.md)

| Phase | Epic | Size | Depends on | Crates | Requirements |
| --- | --- | --- | --- | --- | --- |
| 3 | Endpoint Security | XL (8) | [KNSH-057](KNSH-057-envelope-profile-and-launch.md) | `knsh-platform`, `knshd` | FR-AGT-13, decisions 1 and 3 |

**Description.** As the supervisor on macOS 27 and later, I want an Endpoint Security descendant client
(`es_new_descendants_client`) over every envelope, so that every exec inside an envelope, including `/bin/bash` by
absolute path, is decided by `knshd`. Scope: create the client for each envelope `knshd` starts, authorise exec events
through the same policy path, report the backend in capabilities, and fall back to envelope-only confinement on
macOS 14–26. Out of scope: authorising events beyond exec until the open questions are answered.

**Gate:** this story cannot be completed until Apple grants the Endpoint Security entitlement. The application
should already be in (decision 3). Without the entitlement, the story stays open and its acceptance checks stay
**pending**; it does not block the phase 3 release.

**Acceptance criteria**
- [ ] On macOS 27+, with the entitlement, every exec inside an envelope produces an authorisation event decided by
      the supervisor's policy path; denied execs fail in the agent's process.
- [ ] Exec decisions are recorded like supervised lines, with a source that shows they came from Endpoint Security.
- [ ] `hello` reports the Endpoint Security layer only when it is active; otherwise the sandbox value is unchanged.
- [ ] On macOS 14–26, or without the entitlement, the envelope alone confines direct execution and no error is shown
      to the agent.
- [ ] Decision deadlines imposed by Endpoint Security are met; on timeout the exec is denied (fail closed).

**Unit tests**
- `exec_event_uses_supervisor_policy_path` (FR-AGT-13)
- `es_capability_reported_only_when_active`
- `exec_decision_timeout_denies` (fail closed)
- `older_macos_falls_back_to_envelope_only`

**Integration tests**
- Run `/bin/bash -c 'git push'` by absolute path inside an envelope on macOS 27 and confirm it is decided (pending
  until the entitlement and macOS 27 hardware are available).

**Status (mechanism implemented; gated).** The capability value (`seatbelt+endpoint_security`), the probe, one
client per envelope, exec decisions through the supervisor's pipeline with source `endpoint_security`, and deny at
the deadline are implemented and unit-tested against a scripted client
([agent integration](../03-functional-requirements/agent-integration.md#exec-decisions-through-endpoint-security-knsh-094)).
The macOS binding of `es_new_descendants_client` is not written: it always reports unavailable, so `hello` keeps
`seatbelt` everywhere today. Every acceptance check above stays **pending** until the entitlement is granted and the
binding is verified on macOS 27 ([verification claims](../07-testing/verification-claims.md#endpoint-security-macos-27)).

**Notes**
- Still open (see [../09-reference/decisions.md](../09-reference/decisions.md)):
  1. Whether Apple grants the entitlement to a broadly distributed developer tool.
  2. Which events the descendant client can authorise beyond exec (file opens, network), and what happens to pending
     and later operations if `knshd` exits. Verify on macOS 27 before relying on it.
- The catalogue places this story in phase 3; the roadmap does not assign a phase. Confirm placement when the
  entitlement answer arrives.
