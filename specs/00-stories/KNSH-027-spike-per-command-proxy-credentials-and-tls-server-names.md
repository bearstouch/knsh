# KNSH-027 — Spike: per-command proxy credentials and TLS server names with common tools (C9, C10)

[Phase 2](README.md#phase-2--contain-and-decide) · [Story index and plan](README.md)

| Phase | Epic | Size | Depends on | Crates | Requirements |
| --- | --- | --- | --- | --- | --- |
| 2 | Spikes | M (3) | — | none (throwaway prototypes) | C9, C10, FR-NET-01, FR-NET-06 |

**Description.** As the engine team, I want to know which tools honour proxy settings with embedded credentials and
send a readable TLS server name, so that per-command identity and server-name checks are viable. Scope: curl, git
(HTTPS), npm, pip, cargo, Node's `http`/`https`/`fetch` clients; HTTP CONNECT and SOCKS5; credentials in
`HTTPS_PROXY`/`ALL_PROXY` and tool-specific settings. Out of scope: the production proxy.

**Acceptance criteria**
- [x] For each tool, it is recorded whether it uses the proxy, sends the credentials, and supports CONNECT and/or SOCKS5.
- [x] For curl, git and npm, the ClientHello server name is captured and matches the requested host (C10).
- [x] Tools that ignore proxy settings are listed with the setting a preset could use instead.
- [x] Results recorded under C9 and C10.

**Exit questions**
- Which credential transport (userinfo in proxy URL, `Proxy-Authorization`, SOCKS5 username) works across all tools?

**Results (2026-11-14, macOS 26.6.2).** In [verification claims](../07-testing/verification-claims.md#proxy-results-knsh-027-c9-c10),
harness in [`spikes/knsh-027-proxy/`](../../spikes/knsh-027-proxy/README.md). The exit question is answered there and
in proposed [decision 14](../09-reference/decisions.md): the user and password in an HTTP proxy URL (sent as
`Proxy-Authorization: Basic`) is the only transport that worked for every tool; git needs a `407` Basic challenge
first and Node needs `NODE_USE_ENV_PROXY=1`. **Pending:** macOS 14 and 15, and a run inside a real envelope (no sandbox
was applied here).
