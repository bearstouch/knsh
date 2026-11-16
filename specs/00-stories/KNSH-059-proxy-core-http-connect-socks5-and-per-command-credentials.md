# KNSH-059 — Proxy core: HTTP CONNECT, SOCKS5 and per-command credentials

[Phase 2](README.md#phase-2--contain-and-decide) · [Story index and plan](README.md)

| Phase | Epic | Size | Depends on | Crates | Requirements |
| --- | --- | --- | --- | --- | --- |
| 2 | Proxy | XL (8) | [KNSH-007](KNSH-007-platform-interface-and-test-fakes.md), [KNSH-027](KNSH-027-spike-per-command-proxy-credentials-and-tls-server-names.md) | `knsh-proxy` | FR-NET-01, FR-NET-13, NFR-SUP-01, [network proxy](../03-functional-requirements/network-proxy.md), FR-NET-05 |

**Description.** Merged from *Proxy core: HTTP CONNECT and per-command credentials* and *SOCKS5 support*: they are done and validated together because the same client test matrix exercises both protocols.

*Proxy core: HTTP CONNECT and per-command credentials.* As the engine, I want a local HTTP CONNECT proxy that knows which command and session each
connection belongs to, so that network rules can be enforced per command.

Built on standard threads and kqueue, with no third-party crates and a hand-written request parser.

*SOCKS5 support.* As a tool that only speaks SOCKS, I want the proxy to accept SOCKS5 with per-command credentials,
so that my traffic is checked like everything else.

**Acceptance criteria**
*Proxy core: HTTP CONNECT and per-command credentials*

- [x] The proxy listens on a loopback port that is allowed in every profile, and on nothing else.
- [x] Every spawned line and every envelope gets unique proxy credentials, which are revoked when the line or session
      ends.
- [x] A request with missing or unknown credentials is refused (`407`), and the refusal is reported.
- [x] CONNECT requests are parsed with strict limits (request-line and header size, header count). Malformed requests
      are refused, never repaired.
- [x] The proxy makes no requests of its own (FR-NET-13).
- [x] Connections are tunnelled byte for byte after the checks pass. Idle and total timeouts are enforced.

*SOCKS5 support*

- [x] SOCKS5 with username/password authentication (RFC 1929) maps credentials to command and session.
- [x] Other authentication methods, SOCKS4, UDP ASSOCIATE and BIND are refused.
- [x] Domain-name targets go through the same host rules and address checks as CONNECT. IP-literal targets are
      refused unless allowlisted.

**Unit tests**
*Proxy core: HTTP CONNECT and per-command credentials*

- `maps_credentials_to_command_and_session` — FR-NET-01.
- `refuses_unknown_credentials_with_407` — FR-NET-01.
- `revokes_credentials_when_line_ends` — FR-NET-01.
- `rejects_oversized_request_line` — NFR-SEC-07.
- `rejects_malformed_connect_without_recovery` — NFR-SEC-05.

*SOCKS5 support*

- `accepts_socks5_with_valid_credentials` — FR-NET-01.
- `refuses_no_auth_method` — FR-NET-01.
- `refuses_udp_associate_and_bind` — FR-NET-05.
- `refuses_ip_literal_target` — FR-NET-05.

**Notes**
*Proxy core: HTTP CONNECT and per-command credentials*

- KNSH-027 (C9, proposed decision 14): the `407` must carry `Proxy-Authenticate: Basic`, because git sends
  credentials only after that challenge; accept only the Basic scheme. The client matrix for the integration tests is
  the one in `spikes/knsh-027-proxy/`: curl, git, npm, pip, cargo and Node (`NODE_USE_ENV_PROXY=1`) over CONNECT;
  curl, git, npm and cargo over SOCKS5.
- Spec gap: plain-HTTP requests in absolute-URI form (not CONNECT) are not specified. Propose supporting them with a
  Host-header check equivalent to the TLS server-name check. Otherwise refuse them. KNSH-027 observed curl and Node
  sending `http://` URLs this way, with a matching `Host` header.

*SOCKS5 support*

- The spec says "SOCKS" without a version. SOCKS5 only is a proposal to confirm in the spec.

**Implementation status (KNSH-059)**

- `knsh-proxy`: credentials (`credentials.rs`), strict HTTP head reader (`http.rs`), SOCKS5 reader (`socks5.rs`),
  destinations (`target.rs`), the `ConnectionGate` and `ProxyReport` seams (`gate.rs`), byte-for-byte relay with idle
  and total timeouts (`relay.rs`), and the server on a kqueue accept loop with one thread per connection
  (`server.rs`). Fuzz target `proxy_handshake`.
- `knshd`: starts the proxy on `127.0.0.1:<ephemeral>`; envelopes (KNSH-057) and every spawned line get their own
  credentials and the proxy port in their profile; a line's inherited proxy settings are replaced by its own; line
  credentials are revoked when the line ends, a session's when its envelope ends, closing their tunnels.
- Decisions taken here (written into [network proxy](../03-functional-requirements/network-proxy.md#proxy-core-knsh-059)
  and [limits](../09-reference/defaults-and-limits.md)): SOCKS5 only (SOCKS4 rejected); plain-HTTP absolute-URI
  requests are refused with `405` rather than forwarded; a name whose last label is numeric is refused.
- The refusal "is reported" to the system log for now; the `proxy.denied` event and the record's `network` field are
  KNSH-060.

**Verified:** unit tests above, plus server tests over real loopback sockets (byte-for-byte tunnel, pipelined bytes,
owner passed to the gate, 407 cases, revocation closing live tunnels, malformed and oversized heads, `405`, IP
literals over both protocols, SOCKS5 refusals, handshake, idle and total timeouts, connection limit). Real clients
through the proxy on macOS 26: curl over CONNECT and over `socks5h` with URL credentials, curl without credentials
gets `407`, git authenticates after the `407` challenge. Fuzz target `proxy_handshake` ran 60 s (1.8 M inputs)
without a failure.

**Pending:** the rest of the KNSH-027 client matrix (npm, pip, cargo and Node over CONNECT; git, npm and cargo over
SOCKS5) needs real hosts, which the proxy refuses until host rules (KNSH-060) and the TLS server-name check (KNSH-061)
exist. Until then `knshd` runs the proxy with a gate that refuses every destination, and `hello` still reports
`network_filter: none`.
