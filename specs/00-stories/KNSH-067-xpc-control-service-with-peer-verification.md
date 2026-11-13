# KNSH-067 — XPC control service with peer verification

[Phase 2](README.md#phase-2--contain-and-decide) · [Story index and plan](README.md)

| Phase | Epic | Size | Depends on | Crates | Requirements |
| --- | --- | --- | --- | --- | --- |
| 2 | Authority | XL (8) | [KNSH-013](KNSH-013-knshd-connection-server-dispatcher-and-idle-exit.md), [KNSH-026](KNSH-026-spike-code-signed-identity-keychain-touch-id-from-launchd.md) | `knsh-platform`, `knshd` | FR-AUTH-12 – FR-AUTH-16, NFR-SEC-01, [control service](../06-api/control-service.md), [wire format](../06-api/wire-format.md) |

**Description.** As the engine, I want the control service reachable only by the trusted, code-signed authority, so
that no agent or impostor can make decisions.

**Acceptance criteria**
- [ ] `knsh.control` is declared in `knshd`'s launchd configuration, so no other process can register it.
- [ ] Each connection must meet a peer code-signing requirement: a Developer ID or App Store signature, the trusted
      team ID and identifier, and no debugging entitlement.
- [ ] Hardened runtime and the minimum version are checked on every connection.
- [ ] JSON-RPC payloads travel in XPC messages, with raw bytes as XPC data values. The same strict JSON profile and
      schema apply.
- [ ] A connection that fails any check is dropped before any message is processed.
- [ ] No trusted authority configured means every connection is refused.

**Unit tests**
- `builds_requirement_from_trust_record` — FR-AUTH-13 (pure string builder).
- `rejects_peer_without_hardened_runtime` — FR-AUTH-14 (fake code-signing service).
- `rejects_peer_below_min_version` — FR-AUTH-14.
- `rejects_peer_with_debug_entitlement` — FR-AUTH-13.
- `refuses_all_when_no_authority_trusted` — FR-AUTH-12.

**Integration tests**
- **Pending (needs Developer ID):** a signed test authority connects. An ad-hoc-signed copy is refused. Re-check the
  peer after it execs (claim C7).

**Notes**
- Could be split into 255a (XPC transport and framing) and 255b (code-signing verification).
