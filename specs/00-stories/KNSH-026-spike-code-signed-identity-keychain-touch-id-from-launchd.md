# KNSH-026 — Spike: code-signed identity: Keychain, Touch ID from launchd and XPC peer requirements (C5, C6, C7)

[Phase 2](README.md#phase-2--contain-and-decide) · [Story index and plan](README.md)

| Phase | Epic | Size | Depends on | Crates | Requirements |
| --- | --- | --- | --- | --- | --- |
| 2 | Spikes | XL (8) | — | none (throwaway prototypes) | C5, C6, FR-POL-40, FR-AUTH-11, FR-AUTH-41, C7, FR-AUTH-12 – FR-AUTH-15 |

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

- [x] For ad-hoc and Developer ID signatures, it is recorded whether a Keychain item created by one build is readable
  by the next build, and not readable by an unrelated binary of the same user (C5).
- [x] The behaviour of a Homebrew-built (locally signed) `knshd` is recorded.
- [ ] A launchd user agent shows the Touch ID / password prompt with custom text containing a command line, in a GUI
  session; the behaviour without a GUI session (SSH login) is recorded (C6).
- [x] Results are written under C5 and C6; any refuted claim has a proposed decision or spec change.

*Spike: XPC peer code-signing requirements (C7)*

- [ ] The service rejects a client that does not meet the requirement, on macOS 14, 15 and current.
- [x] The client rejects a service that does not meet its requirement.
- [x] Behaviour after the peer calls `exec` (identity change) is recorded.
- [x] The minimum-version check approach (bundle version from the peer's code signature) is demonstrated.
- [x] A client with a debugging entitlement is rejected.
- [x] Results recorded under C7.

**Exit questions**
*Spike: Keychain access control and Touch ID from a launchd agent (C5, C6)*

- Which access-control mechanism (ACL, data-protection Keychain with access group, partition list) should
  `knsh-platform` use?
- What must approvals do when no GUI session exists (deny with a clear reason is the fail-closed default)?

*Spike: XPC peer code-signing requirements (C7)*

- Which API (`xpc_connection_set_peer_code_signing_requirement` or audit-token + `SecCode` checks) is used on macOS 14?

**Notes.** Done on macOS 26.6.2 (Apple M1 Pro, lid closed) with the throwaway harnesses in
[`spikes/knsh-026-identity/`](../../spikes/knsh-026-identity/README.md), using a real Developer ID Application
certificate. The results are under C5, C6 and C7 in
[verification claims](../07-testing/verification-claims.md#code-signed-identity-results-knsh-026-c5-c6-c7), with
proposed [decisions](../09-reference/decisions.md) 11 to 13, a proposed fixed write deny on `~/Library/Keychains` in
[sandbox profiles](../03-functional-requirements/sandbox-profiles.md), and notes in
[authority](../03-functional-requirements/authority.md) and [macOS services](../08-integrations/macos-services.md).

- C5: a file-based keychain item created by a Developer ID build stays readable by the next build and by no unrelated
  binary. Ad-hoc and Homebrew builds are trusted by code hash, so the next build cannot read it (a real `brew upgrade`
  loses it; `brew reinstall` of the same source keeps it). **Refined claim:** any same-user process can overwrite the
  value without a prompt; code outside the team then changes the partition list, so `knshd`'s read fails instead of
  returning the forged value, and a sandbox write deny on `~/Library/Keychains` stops the overwrite entirely. The
  data-protection keychain needs a restricted entitlement: a bare binary carrying it is killed at launch.
- C6: a launchd agent in the GUI domain showed the prompt, titled with the process name, with the 107-character
  reason (a full command line) in full; the user approved with the password. A background-domain job without
  graphics access also got its prompt onto the console. With the lid closed, only the password was offered.
- C7: the service rejected ad-hoc, other-identifier and `get-task-allow` clients through the XPC requirement, and
  clients without hardened runtime, below the minimum version or without a version through `SecCode` checks. A peer
  that execs after sending is rejected by audit-token checks, while a pid-based check would accept it. The client
  rejected impostor services, but only after its first message had reached them.

**Pending (unchecked boxes):** the C6 prompt box needs the case without a GUI session: an SSH login with nobody at the
console (Remote Login was off; a background-domain job is not the same thing). The first C7 box needs macOS 14 and
15. Also pending, without a box: the Touch ID sensor (lid open), C6 cancellation and timeout (the user typed the
password every time), and the data-protection keychain with a provisioning profile.

**Exit questions.**

- *Which access-control mechanism should `knsh-platform` use?* The file-based (legacy) keychain with the default ACL,
  from a Developer ID-signed `knshd`, never showing the "allow access" dialog; a read failure on an existing item is
  tampering and fails closed; every profile denies writes under `~/Library/Keychains`. The data-protection keychain
  with an access group once `knshd` ships in an app bundle with a provisioning profile, after verifying it. Ad-hoc and
  Homebrew-from-source builds report Keychain features as degraded (decision 11). The partition list is not something
  `knshd` sets; it records the last writer and is how tampering shows.
- *What must approvals do when no GUI session exists?* Deny with a clear reason. Any outcome other than success,
  including no answer by `timeout_at`, denies; the context is invalidated at the timeout. `knshd` cannot rely on an
  error to detect "no GUI", because the prompt reached the console from a session without graphics access
  (decision 12).
- *Which API is used on macOS 14?* `xpc_connection_set_peer_code_signing_requirement` (macOS 12+) on every peer
  connection, plus `SecCodeCreateWithXPCMessage` on every message for hardened runtime, debuggability and
  `CFBundleVersion`; never the pid. The authority's first message carries nothing sensitive (decision 13).
