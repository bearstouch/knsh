# KNSH-048 — `agent.sock` endpoint, session tokens and audit-token fallback

[Phase 2](README.md#phase-2--contain-and-decide) · [Story index and plan](README.md)

| Phase | Epic | Size | Depends on | Crates | Requirements |
| --- | --- | --- | --- | --- | --- |
| 2 | Supervisor | L (5) | [KNSH-013](KNSH-013-knshd-connection-server-dispatcher-and-idle-exit.md), [KNSH-015](KNSH-015-session-model-and-registry.md) | `knshd`, `knsh-proto`, `knsh-platform` | FR-AGT-23, FR-SES-02, NFR-SEC-02, [endpoints](../02-architecture/endpoints.md), [agent socket](../06-api/agent-socket.md) |

**Description.** As the supervisor, I want a separate `agent.sock` endpoint that ties every request to exactly one
agent session, so that a process inside an envelope can act only on its own session.

In scope:
- Accepting connections on the launchd-created `agent.sock`.
- Validating the session token sent in `hello`. Without a valid token, the caller is matched to its envelope through
  its audit token.
- Scoping every method to that session, and an envelope registry that maps envelope process trees to sessions.

Out of scope: the methods themselves (KNSH-053 and others) and creating sessions, which is never allowed on this
endpoint.

**Acceptance criteria**
- [ ] `hello` with a valid session token binds the connection to that session, and the result carries its `session_id`.
- [ ] `hello` with a missing, invalid or expired token is matched by audit token: a caller whose process is
      a descendant of a registered envelope is bound to that envelope's session.
- [ ] A caller that matches neither a token nor an envelope is refused with `-32009`, and the connection is closed.
- [ ] Every method call is evaluated against the bound session only. Naming another session's record, event stream or
      checkpoint returns `-32003`.
- [ ] `session.start_agent` and any other session-creating method are not in this endpoint's catalogue. Calling one
      returns JSON-RPC "method not found".
- [ ] A token is invalidated when its session ends, after which it yields `-32009`.
- [ ] Tokens are at least 128 bits from the platform random source, compared in constant time, and never logged
      or recorded.

**Unit tests**
- `binds_connection_to_session_for_valid_token` — FR-AGT-23.
- `falls_back_to_audit_token_when_token_missing` — FR-AGT-23.
- `refuses_caller_matching_no_envelope_with_32009` — FR-AGT-23.
- `rejects_cross_session_record_access_with_32003` — endpoint scoping.
- `rejects_expired_token_after_session_end` — FR-AGT-23.
- `catalogue_has_no_session_creation_methods` — FR-SES-02.
- `token_comparison_is_constant_time` — NFR-SEC-02 (structural test on the comparison helper).

**Integration tests**
- A child process spawned under a fake envelope registry connects without a token and is bound by audit token.
- A process outside every envelope connecting to `agent.sock` is refused.

**Notes**
- Audit-token lookup (`getsockopt(LOCAL_PEERTOKEN)`, then a process-ancestry check) lives behind a `knsh-platform` trait,
  so the matching logic is pure and testable.
- PID reuse: match on the audit token (which includes the PID version), never on a bare PID.
