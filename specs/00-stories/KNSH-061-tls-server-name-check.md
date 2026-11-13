# KNSH-061 — TLS server-name check

[Phase 2](README.md#phase-2--contain-and-decide) · [Story index and plan](README.md)

| Phase | Epic | Size | Depends on | Crates | Requirements |
| --- | --- | --- | --- | --- | --- |
| 2 | Proxy | L (5) | [KNSH-059](KNSH-059-proxy-core-http-connect-socks5-and-per-command-credentials.md) | `knsh-proxy` | FR-NET-06, NFR-SUP-06, [fuzzing](../07-testing/fuzzing.md) |

**Description.** As the engine, I want the proxy to read the server name from each TLS ClientHello without
decrypting, so that a tunnel opened for one host cannot be used to talk to another.

**Acceptance criteria**
- [ ] After CONNECT, the proxy reads the first TLS record(s) up to a fixed limit and parses the ClientHello SNI
      extension with a hand-written parser.
- [ ] The tunnel opens only if the SNI matches the CONNECT host (case-insensitive, no trailing dot).
- [ ] A missing SNI, a mismatched SNI, a malformed ClientHello or data that is not TLS is refused, unless the host is
      explicitly configured for non-TLS use.
- [ ] The parser never panics and never allocates beyond the record-size limit. It has a fuzz target.

**Unit tests**
- `extracts_sni_from_client_hello` — FR-NET-06.
- `refuses_mismatched_sni` — FR-NET-06.
- `refuses_missing_sni` — FR-NET-06.
- `refuses_truncated_client_hello` — NFR-SEC-05.
- `handles_client_hello_split_across_records` — FR-NET-06.

**Integration tests**
- curl, git and npm through the proxy to an allowed host succeed. A forged SNI is refused. Results feed claim C10.

**Notes**
- Spec gap: Encrypted Client Hello (ECH) hides the real SNI. Propose treating ECH as a missing SNI (refuse), and say
  so in the spec.
