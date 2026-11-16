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
  the credentials. Until KNSH-060 the report goes to the system log (`proxy refused a connection`), and `proxy.denied`
  follows with it.
- **Until host rules exist (KNSH-060)** the proxy refuses every destination, so envelopes and lines reach nothing
  but their loopback ports, and `hello` reports `network_filter: none`.

## Known limits

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
