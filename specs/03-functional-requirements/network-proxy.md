# Network proxy

`knshd` runs a local HTTP CONNECT and SOCKS5 proxy. Sandbox profiles allow network only to the proxy's port and the profile's loopback ports, so every outbound connection from an envelope or a supervised line goes through it.

| ID | Requirement |
| --- | --- |
| FR-NET-01 | **Per-command identity:** every spawned line, and every envelope, must get its own proxy credentials in its proxy settings, so each request is tied to one command and session. |
| FR-NET-02 | **Host rules:** `network.hosts` must be open to every command in the session. |
| FR-NET-03 | `network.approval_hosts` must be reachable only by commands whose class allows it (a preset can let `git fetch` reach github.com) or that were approved (`git push`). |
| FR-NET-04 | `network.mode = "none"` must refuse all outbound connections except allowed loopback ports. |
| FR-NET-05 | **Names only:** destinations must be names, not IP addresses, unless allowlisted. |
| FR-NET-06 | The name in the TLS handshake (server name) must match the requested host. The proxy reads it from the handshake without decrypting. |
| FR-NET-07 | The proxy must resolve names itself and refuse any that point to loopback, link-local or private addresses unless allowlisted, which blocks DNS rebinding. |
| FR-NET-08 | **No local DNS:** the resolver service must be denied inside profiles, so DNS queries cannot carry data out. |
| FR-NET-09 | Every refused connection must emit `proxy.denied`; hosts contacted or refused must be listed in the record's `network` field. Proxy refusals are authoritative. |
| FR-NET-10 | A line that receives a secret must have its network narrowed to that secret's `hosts` ([secrets](secrets.md)). |
| FR-NET-11 | Dynamic code must be limited to `network.hosts` and can never reach `approval_hosts` ([policy](policy.md#dynamic-code)). |
| FR-NET-12 | Presets should set tool-specific proxy settings where tools have them ([developer tools](../08-integrations/developer-tools.md)). |
| FR-NET-13 | The proxy must make no requests of its own; it only forwards traffic for sessions. |

## Proxy core (KNSH-059)

- **Listener.** One ephemeral port on `127.0.0.1`, and nothing else. Every compiled profile (envelope and line)
  allows outbound TCP to it.
- **Credentials.** Each envelope gets credentials when its session opens; each supervised line gets its own when it
  is spawned, replacing every inherited proxy setting (its envelope's included). A line's are revoked when it ends,
  a session's (envelope and lines) when its envelope ends, and revoking also closes the connections they opened. A
  command whose credentials cannot be issued does not start. Ids are never reused; tokens are 32 letters and digits,
  compared in constant time.
- **HTTP.** Only `CONNECT host:port` (authority form) with `Proxy-Authorization: Basic` is served. Missing or
  unknown credentials, or another scheme, get `407` with `Proxy-Authenticate: Basic realm="knsh"`. The head is read
  strictly ([limits](../09-reference/defaults-and-limits.md)): CRLF line endings only, no folded headers, at most one
  `Proxy-Authorization`, no `Transfer-Encoding` and no non-zero `Content-Length`. Malformed requests get `400`
  (`431` over a size limit) and are never repaired. Other methods, plain-HTTP requests in absolute-URI form
  included, get `405`: they are not forwarded until a `Host`-header check equivalent to FR-NET-06 exists.
- **SOCKS5.** SOCKS version 5 only, with RFC 1929 username and password (the same `knsh-<id>` user and token); a
  greeting that does not offer it gets "no acceptable methods". Only CONNECT is served: BIND and UDP ASSOCIATE get
  "command not supported". SOCKS4 and SOCKS4a are rejected.
- **Destinations.** Both protocols produce the same destination: a host name (lower case, no trailing dot) or an IP
  literal, and a port. A SOCKS5 domain that spells an address is an IP literal, and a name whose last label is a
  number (`127.1`, `0x7f.1`) is refused, since resolvers read it as an address. IP literals are refused unless
  allowlisted (FR-NET-05); names go through the host rules and address checks, which give the exact address to
  connect to.
- **Tunnels.** Bytes are relayed unchanged both ways, half closes included, under the idle and total timeouts.
- **Reporting.** Every refusal is reported with its reason, protocol, session and record when known, and port; never
  the credentials. The system log entry (`proxy refused a connection`) names no host; `proxy.denied` and the
  record's `network` field (KNSH-060, below) do.

## Host rules, name resolution and address checks (KNSH-060)

Each envelope and each line has a scope, set when its credentials are issued and dropped when they are revoked: the
session profile's `[network]` policy (for a line, the profile its decision was made under) and who asks. A connection
whose credentials have no scope is refused (`no_host_rules`). For each connection, in order:

1. **Loopback ports.** A loopback address (`127.0.0.0/8`, `::1`) or the name `localhost` (or a name below it, RFC
   6761) on a port in `network.loopback` is allowed in either mode: the sandbox profile already lets the command reach
   that port (FR-NET-04). `localhost` is never resolved; it is `127.0.0.1`, then `::1`.
2. **IP literals** are refused (`ip_literal`) unless allowlisted: an address listed in a host rule the requester may
   use (FR-NET-05).
3. **Host rules** (`knsh-core`'s `check_host`, a pure function of the network policy, the requester and the host):
   - `network.mode = "none"`: every host is refused (`network_off`, FR-NET-04).
   - `network.hosts`: open to every command of the session, the envelope included (FR-NET-02).
   - `network.approval_hosts`: refused to the envelope, which has no classes and is never approved; refused to a line
     holding dynamic code, even approved (`dynamic_code`, FR-NET-11, FR-POL-21); reached by a line whose classes open
     it under `network.class_hosts`, or that was approved (by the authority or the user) or allowed by a grant;
     otherwise refused (`approval_required`, FR-NET-03).
   - Any other host: refused (`host_not_allowed`).
4. **Resolution.** An allowed name is resolved by the proxy itself (`getaddrinfo` in `knshd`; commands never
   resolve, FR-NET-08). No address, or a resolver error, is `unresolved`. If **any** address is internal (below) and
   not allowlisted, the name is refused (`address_not_allowed`, FR-NET-07). An internal address is allowlisted when it
   is listed in a host rule the requester may use, or is a loopback address on a `network.loopback` port.
5. **Connect.** The proxy connects to the checked addresses, in the resolver's order, the first that answers winning,
   all within the connect timeout. It never resolves the name again, so a later answer (DNS rebinding) cannot change
   where this connection goes.

**Host entries.** `network.hosts`, `network.approval_hosts` and `network.class_hosts.*` entries match a host as
follows: a name matches the same name (ASCII case and one trailing dot ignored); `*.example.com` matches every name
strictly below `example.com` (not `example.com` itself); an IP address, written plainly or in brackets (`10.0.0.5`,
`[fd00::1]`), matches that address however it is spelled, and is how a profile allowlists an IP literal or an internal
address. Any other entry (a `*` elsewhere, a port) matches nothing. A class host is matched the same way.

**Internal addresses** (FR-NET-07). IPv4: `0.0.0.0/8`, `10.0.0.0/8`, `100.64.0.0/10` (carrier-grade NAT),
`127.0.0.0/8`, `169.254.0.0/16`, `172.16.0.0/12`, `192.0.0.0/24`, `192.168.0.0/16`, `198.18.0.0/15`, and
`224.0.0.0` and above (multicast, reserved, broadcast). IPv6: `::`, `::1`, `fc00::/7`, `fe80::/10`, `fec0::/10`,
`ff00::/8`, and IPv4-mapped (`::ffff:0:0/96`), IPv4-compatible (`::/96`) and NAT64 (`64:ff9b::/96`) addresses, judged
by the IPv4 address they carry.

**Reporting** (FR-NET-09). A refusal whose credentials were live is published as `proxy.denied` for the owner's
session ([event](../05-models/event.md#phase-2-payloads)): `record_id` names the line, and is `null` for the
envelope's own connections, which are attributed to the session alone. Refusals before credentials are known (missing
or unknown credentials, a malformed greeting) have no session and are only logged. A line's refusals and contacts (a
connection that passed every check and whose tunnel opened) are collected while it runs and written to its record's
`network` field ([execution record](../05-models/execution-record.md#network)). The proxy reports a connection before
the revocation that ends its line returns, so every connection the line made is in its record; a connection revoked
while its destination was still being checked may report its refusal later, which is published but not recorded.

`hello` reports `network_filter: none` until the TLS server-name check (FR-NET-06, KNSH-061) is in force too.

## Known limits

- Name resolution blocks the connection's thread (`getaddrinfo` has no timeout of its own); a slow resolver delays
  only that connection, and connections are bounded by the proxy's connection limit.
- An allowlisted host that accepts uploads (a package registry, a git host) can receive data. Keep upload-capable hosts in `approval_hosts`, and let irreversible flags gate publishing commands.
- Tools that ignore proxy settings (ssh git remotes, some Node and Java HTTP clients) are blocked, not leaked.
- Credentials travel as the user and password of an HTTP proxy URL and arrive as `Proxy-Authorization: Basic`. git
  sends them only after a `407` with `Proxy-Authenticate: Basic`, so the challenge is required; Node uses the proxy
  only with `NODE_USE_ENV_PROXY=1`; pip (without PySocks) and Node cannot use SOCKS5 (C9, proposed
  [decision 14](../09-reference/decisions.md)).
- Plain-HTTP requests through the proxy (absolute-URI form) are refused (`405`); curl and Node send `http://` URLs
  that way (KNSH-027), so plain-HTTP fetches fail until a `Host`-header check exists.
- A client that uses Encrypted Client Hello shows a public name in its handshake, not the requested host, and is
  refused by FR-NET-06. None of curl, git, npm, pip, cargo or Node did on macOS 26.6 (C10).
