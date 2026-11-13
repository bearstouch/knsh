# Network proxy

`knshd` runs a local HTTP and SOCKS proxy. Sandbox profiles allow network only to the proxy's port and the profile's loopback ports, so every outbound connection from an envelope or a supervised line goes through it.

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

## Known limits

- An allowlisted host that accepts uploads (a package registry, a git host) can receive data. Keep upload-capable hosts in `approval_hosts`, and let irreversible flags gate publishing commands.
- Tools that ignore proxy settings (ssh git remotes, some Node and Java HTTP clients) are blocked, not leaked.
