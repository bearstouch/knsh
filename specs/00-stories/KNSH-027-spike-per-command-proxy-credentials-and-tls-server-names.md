# KNSH-027 — Spike: per-command proxy credentials and TLS server names with common tools (C9, C10)

[Phase 2](README.md#phase-2--contain-and-decide) · [Story index and plan](README.md)

| Phase | Epic | Size | Depends on | Crates | Requirements |
| --- | --- | --- | --- | --- | --- |
| 2 | Spikes | M (3) | — | none | C9, C10, FR-NET-01, FR-NET-06 |

**Description.** As the engine team, I want to know which tools honour proxy settings with embedded credentials and
send a readable TLS server name, so that per-command identity and server-name checks are viable. Scope: curl, git
(HTTPS), npm, pip, cargo, Node's `http`/`https`/`fetch` clients; HTTP CONNECT and SOCKS5; credentials in
`HTTPS_PROXY`/`ALL_PROXY` and tool-specific settings. Out of scope: the production proxy.

**Acceptance criteria**
- [ ] For each tool, it is recorded whether it uses the proxy, sends the credentials, and supports CONNECT and/or SOCKS5.
- [ ] For curl, git and npm, the ClientHello server name is captured and matches the requested host (C10).
- [ ] Tools that ignore proxy settings are listed with the setting a preset could use instead.
- [ ] Results recorded under C9 and C10.

**Exit questions**
- Which credential transport (userinfo in proxy URL, `Proxy-Authorization`, SOCKS5 username) works across all tools?
