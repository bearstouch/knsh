# KNSH-092 — Secret injection and network narrowing

[Phase 3](README.md#phase-3--reverse-and-protect) · [Story index and plan](README.md)

| Phase | Epic | Size | Depends on | Crates | Requirements |
| --- | --- | --- | --- | --- | --- |
| 3 | Secrets | L (5) | [KNSH-042](KNSH-042-grants.md), [KNSH-060](KNSH-060-proxy-connection-rules-host-rules-address-checks-and.md), [KNSH-089](KNSH-089-secret-stores-keychain-and-authority-supplied-secrets.md), [KNSH-091](KNSH-091-redaction-on-every-output-path.md) | `knsh-core`, `knshd`, `knsh-proxy` | FR-SEC-01 – FR-SEC-06, FR-NET-10 |

**Description.** As an agent running an approved publishing command, I want the needed secret injected as an
environment variable, with network limited to the secret's hosts, so that the token works but can only go where it is
meant to. Scope: `[secrets.env]` matching by `inject_for`, ask unless a grant covers the line, never for dynamic
code, network narrowing via the proxy, `secret.injected` events, `secrets_injected` in records.

**Acceptance criteria**
- [ ] A secret is injected only into supervised lines matching its `inject_for` patterns (FR-SEC-01).
- [ ] Such lines ask unless a grant covers them (FR-SEC-02).
- [ ] The receiving line can reach only the secret's `hosts` through the proxy (FR-SEC-03, FR-NET-10).
- [ ] Dynamic code never receives a secret, even if it matches a pattern (FR-SEC-04).
- [ ] `secret.injected` reports name and command, never the value; the record lists names only (FR-SEC-06).
- [ ] The injected line's profile restricts process information to its own sandbox (FR-SEC-05, decision 8).
- [ ] If the secret is unavailable, the line is denied with a reason that names the secret.

**Unit tests**
- `secret_injected_only_for_matching_line` (FR-SEC-01)
- `matching_line_asks_without_grant` (FR-SEC-02)
- `grant_allows_injection_without_ask` (FR-SEC-02)
- `dynamic_code_never_receives_secret` (FR-SEC-04)
- `network_narrowed_to_secret_hosts` (FR-SEC-03)
- `secret_injected_event_contains_name_not_value` (FR-SEC-06)
- `unavailable_secret_denies_line`

**Integration tests**
- A supervised `curl` with an injected token reaches the allowed host and is refused for any other host.
