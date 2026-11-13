# KNSH-026 — Spike: code-signed identity: Keychain, Touch ID from launchd and XPC peer requirements (C5, C6, C7)

[Phase 2](README.md#phase-2--contain-and-decide) · [Story index and plan](README.md)

| Phase | Epic | Size | Depends on | Crates | Requirements |
| --- | --- | --- | --- | --- | --- |
| 2 | Spikes | XL (8) | — | none | C5, C6, FR-POL-40, FR-AUTH-11, FR-AUTH-41, C7, FR-AUTH-12 – FR-AUTH-15 |

**Description.** Merged from *Spike: Keychain access control and Touch ID from a launchd agent (C5, C6)* and *Spike: XPC peer code-signing requirements (C7)*: they are done and validated together because all three claims need the same signed builds and signing setup.

*Spike: Keychain access control and Touch ID from a launchd agent (C5, C6).* As the engine team, I want to know whether Keychain items can be restricted to `knshd`'s code
signature across updates and Homebrew builds, and whether a launchd user agent can show the LocalAuthentication
prompt, so that policy signing, authority trust and approvals can rely on them. Scope: prototypes with ad-hoc and
Developer ID signatures; prompts with and without a logged-in GUI session. Out of scope: production bindings.

*Spike: XPC peer code-signing requirements (C7).* As the engine team, I want to verify peer code-signing requirements on XPC connections in both
directions on macOS 14+, so that the control service can trust only the registered authority. Scope: a launchd-declared
Mach service and a signed client; requirement strings with team ID, identifier, hardened runtime and no
`get-task-allow`. Out of scope: the JSON-RPC protocol on XPC.

**Acceptance criteria**
*Spike: Keychain access control and Touch ID from a launchd agent (C5, C6)*

- [ ] For ad-hoc and Developer ID signatures, it is recorded whether a Keychain item created by one build is readable
  by the next build, and not readable by an unrelated binary of the same user (C5).
- [ ] The behaviour of a Homebrew-built (locally signed) `knshd` is recorded.
- [ ] A launchd user agent shows the Touch ID / password prompt with custom text containing a command line, in a GUI
  session; the behaviour without a GUI session (SSH login) is recorded (C6).
- [ ] Results are written under C5 and C6; any refuted claim has a proposed decision or spec change.

*Spike: XPC peer code-signing requirements (C7)*

- [ ] The service rejects a client that does not meet the requirement, on macOS 14, 15 and current.
- [ ] The client rejects a service that does not meet its requirement.
- [ ] Behaviour after the peer calls `exec` (identity change) is recorded.
- [ ] The minimum-version check approach (bundle version from the peer's code signature) is demonstrated.
- [ ] A client with a debugging entitlement is rejected.
- [ ] Results recorded under C7.

**Exit questions**
*Spike: Keychain access control and Touch ID from a launchd agent (C5, C6)*

- Which access-control mechanism (ACL, data-protection Keychain with access group, partition list) should
  `knsh-platform` use?
- What must approvals do when no GUI session exists (deny with a clear reason is the fail-closed default)?

*Spike: XPC peer code-signing requirements (C7)*

- Which API (`xpc_connection_set_peer_code_signing_requirement` or audit-token + `SecCode` checks) is used on macOS 14?
