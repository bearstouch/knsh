# KNSH-067 — XPC control service with peer verification

[Phase 2](README.md#phase-2--contain-and-decide) · [Story index and plan](README.md)

| Phase | Epic | Size | Depends on | Crates | Requirements |
| --- | --- | --- | --- | --- | --- |
| 2 | Authority | XL (8) | [KNSH-013](KNSH-013-knshd-connection-server-dispatcher-and-idle-exit.md), [KNSH-026](KNSH-026-spike-code-signed-identity-keychain-touch-id-from-launchd.md) | `knsh-platform`, `knshd` | FR-AUTH-12 – FR-AUTH-16, NFR-SEC-01, [control service](../06-api/control-service.md), [wire format](../06-api/wire-format.md) |

**Description.** As the engine, I want the control service reachable only by the trusted, code-signed authority, so
that no agent or impostor can make decisions.

**Acceptance criteria**
- [x] `knsh.control` is declared in `knshd`'s launchd configuration, so no other process can register it. *(Declared
      since KNSH-012; `knshd` now serves it with `xpc_connection_create_mach_service`. launchd gives the name to the
      first job that declares it: see the FR-AUTH-12 note in [authority](../03-functional-requirements/authority.md).)*
- [x] Each connection must meet a peer code-signing requirement: a Developer ID or App Store signature, the trusted
      team ID and identifier, and no debugging entitlement. *(Set with
      `xpc_connection_set_peer_code_signing_requirement` on every peer; the requirement compiles, and an ad-hoc-signed
      peer was refused by XPC before any message (`knsh-platform` tests, macOS 26.6.2). Acceptance of a Developer
      ID-signed authority is pending, below.)*
- [x] Hardened runtime and the minimum version are checked on every connection. *(On every message, by audit token:
      `SecCodeCreateWithXPCMessage`, then hardened runtime, a valid live signature, `CS_GET_TASK_ALLOW`/`CS_DEBUGGED`
      and `CFBundleVersion`. Decided by a pure gate tested with a fake code-signing service; the facts were read from
      live code (the test binary) on macOS 26.6.2.)*
- [ ] JSON-RPC payloads travel in XPC messages, with raw bytes as XPC data values. The same strict JSON profile and
      schema apply. *(Implemented ([wire format](../06-api/wire-format.md#control-service-xpc)): verified messages are
      served by the same session rules and dispatch tables as the sockets, tested in `knshd`. **Pending:** a verified
      message end to end over XPC needs a Developer ID-signed peer.)*
- [x] A connection that fails any check is dropped before any message is processed. *(Observed for the requirement
      and for no trust over a real XPC connection; a sender refused by the per-message checks is cancelled before its
      message is read, observed over a real XPC connection with a fake code-signing service.)*
- [x] No trusted authority configured means every connection is refused. *(Observed: cancelled before it is resumed.
      The trust record arrives with KNSH-068; until then `knshd` trusts nothing.)*

**Unit tests**
- `builds_requirement_from_trust_record` — FR-AUTH-13 (pure string builder).
- `rejects_peer_without_hardened_runtime` — FR-AUTH-14 (fake code-signing service).
- `rejects_peer_below_min_version` — FR-AUTH-14.
- `rejects_peer_with_debug_entitlement` — FR-AUTH-13.
- `refuses_all_when_no_authority_trusted` — FR-AUTH-12.

All five are in `knsh-platform` (`control`). Also: `refuses_every_connection_without_a_trusted_authority`,
`drops_a_peer_that_fails_the_requirement_before_any_message`, `compiles_the_peer_requirement` and
`reads_signature_facts_of_live_code` (`knsh-platform`, `macos::xpc`, real XPC and Security calls on an anonymous
listener), `drops_a_sender_that_fails_the_per_message_checks_before_reading` and
`serves_a_verified_sender_and_rechecks_every_message` (`macos::xpc`, real XPC with the peer requirement `always` and a
fake code-signing service, so the per-message gate, the reply path and the re-check after a sender stops verifying run
over a real connection), and `serves_json_rpc_after_hello` and `closes_on_handshake_violation_and_malformed_json` (`knshd`,
`control`).

**Integration tests**
- **Pending (needs Developer ID):** a signed test authority connects. An ad-hoc-signed copy is refused. Re-check the
  peer after it execs (claim C7). *(The ad-hoc refusal is observed in-process on an anonymous listener; the rest
  needs a signed authority and an installed, signed `knshd`.)*

**Notes**
- Could be split into 255a (XPC transport and framing) and 255b (code-signing verification).
- From KNSH-026 ([C7 results](../07-testing/verification-claims.md#code-signed-identity-results-knsh-026-c5-c6-c7), proposed decision 13): `xpc_connection_set_peer_code_signing_requirement` on
  each peer plus `SecCodeCreateWithXPCMessage` for hardened runtime, `CS_GET_TASK_ALLOW`/`CS_DEBUGGED` and
  `CFBundleVersion`; never the pid (a peer can exec a trusted binary after sending). The tested requirement string is in
  the results. launchd gives the name to the first job that declares it.
- Observed while implementing (macOS 26.6.2, a fresh unsigned test binary): the first Security framework call of a
  process took 6–17 s, later ones about 0.3 ms. `knshd` compiles the requirement when it starts serving, so with a
  trust record (KNSH-068) its start may be slowed once; recheck with a signed `knshd`.
- What `knshd` sends (answers, events) goes to whatever process holds the connection: a peer that exec'd since its
  last message would receive it until its next message is refused. Nothing sent carries a secret yet; KNSH-069
  (decision requests) and KNSH-089 (secrets) must keep that in mind.
