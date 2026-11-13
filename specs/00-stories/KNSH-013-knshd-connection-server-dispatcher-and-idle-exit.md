# KNSH-013 — `knshd` connection server, dispatcher and idle exit

[Phase 1](README.md#phase-1--observe-advisory) · [Story index and plan](README.md)

| Phase | Epic | Size | Depends on | Crates | Requirements |
| --- | --- | --- | --- | --- | --- |
| 1 | Daemon | XL (8) | [KNSH-008](KNSH-008-json-rpc-envelope-and-error-codes.md), [KNSH-012](KNSH-012-launchd-user-agent-and-socket-activation.md), [KNSH-015](KNSH-015-session-model-and-registry.md) | `knshd` | [API overview](../06-api/README.md), [wire format](../06-api/wire-format.md), NFR-SEC-07, [process model](../02-architecture/process-model.md) |

**Description.** Merged from *`knshd` connection server and dispatcher* and *`knshd` idle exit and lifetime*: they are done and validated together because one launchd lifecycle integration test covers serving and idle exit.

*`knshd` connection server and dispatcher.* As a client, I want `knshd` to accept connections on its sockets, read frames, and dispatch
JSON-RPC methods per endpoint, so that every later method plugs into one server. kqueue accept loop, a worker
thread per connection (bounded), per-endpoint method tables, orderly shutdown. No async runtime.

*`knshd` idle exit and lifetime.* As a user, I want `knshd` to run only while needed, so that it costs nothing when idle. It stays
alive while any envelope or recording session exists and exits after 10 idle minutes.

**Acceptance criteria**
*`knshd` connection server and dispatcher*

- [x] Each endpoint has its own dispatch table; a method not in that endpoint's table returns `-32601` (unknown)
      or `-32003` (known but not allowed on this endpoint).
- [x] The first message must be `hello`; anything else first gets `-32600` and the connection is closed.
- [x] Oversized frames close the connection before allocation (KNSH-004); malformed JSON returns `-32700` and the
      connection is closed.
- [x] A slow or stuck client cannot block other connections; the number of concurrent connections is bounded and
      excess connections are refused.
- [x] Shutdown stops accepting, lets in-flight requests finish within a bound, then closes.
- [x] No message content is written to the system log.

*`knshd` idle exit and lifetime*

- [x] With no sessions and no connections, `knshd` exits after 10 minutes (injected clock).
- [x] Any active recording session, envelope or open connection resets the idle timer. (Observed with a fake
      session source; the session registry is wired in with KNSH-015.)
- [x] Exit is clean: pending record writes are committed first. (Observed with a fake writer; the record store is
      wired in with KNSH-016.)
- [ ] Human sessions with recording off never contact `knshd` (verified with KNSH-021). **Pending** KNSH-021.

**Unit tests**
*`knshd` connection server and dispatcher*

- `method_not_on_endpoint_returns_minus_32003` — endpoint scoping.
- `first_message_must_be_hello` — handshake order.
- `malformed_json_closes_connection_with_minus_32700` — strict profile.
- `connection_limit_refuses_excess` — resource bound.
- `stuck_client_does_not_block_others` — isolation (fake sockets).

*`knshd` idle exit and lifetime*

- `exits_after_10_idle_minutes` — fake clock.
- `active_recording_session_prevents_exit` — lifetime rule.
- `pending_writes_committed_before_exit` — data safety.
