# KNSH-114 — Network confinement: seccomp or network namespace

[Phase 5](README.md#phase-5--linux) · [Story index and plan](README.md)

| Phase | Epic | Size | Depends on | Crates | Requirements |
| --- | --- | --- | --- | --- | --- |
| 5 | Network | L (5) | [KNSH-113](KNSH-113-landlock-and-seccomp-in-knsh-exec.md) | `knsh-exec`, `knsh-proxy` | platform-support.md (Network filter), FR-NET-01 – FR-NET-13 |

**Description.** As the engine on Linux, I need supervised lines and envelopes to reach only the proxy and allowed
loopback ports, so that the proxy remains the only path out.

**Acceptance criteria**
- [ ] With a network namespace, the only reachable endpoints are the proxy and allowed loopback ports.
- [ ] Without namespaces, a seccomp filter restricts `connect` to permitted addresses, or the probe reports
      `network_filter: none` and agent sessions do not get network.
- [ ] Local DNS resolution is impossible from inside a profile (FR-NET-08).

**Unit tests**
- `namespace_setup_exposes_only_proxy_port`
- `seccomp_connect_filter_rejects_other_addresses`
- `dns_socket_blocked`

**Integration tests**
- Container: `curl` via proxy works; direct `curl --noproxy '*'` fails.
