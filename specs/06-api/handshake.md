# Handshake

Every client starts with `hello`, which settles the protocol version and reports what this machine can guarantee.

```json
// client → engine
{"jsonrpc": "2.0", "id": 1, "method": "hello",
 "params": {"client": "my-agent", "client_version": "0.4.0", "protocols": [1], "session_token": "…"}}

// engine → client
{"jsonrpc": "2.0", "id": 1, "result": {"engine_version": "0.1.0", "protocol": 1,
 "platform": "macos-15-arm64", "session_id": "…", "advisory": false, "binary_frames": true,
 "capabilities": {"sandbox": "seatbelt", "network_filter": "proxy", "file_events": "fsevents",
   "secrets": "keychain", "checkpoints": {"/Users/me/code/app": "apfs-clone"},
   "methods": ["exec.run", "records.query", "…"],
   "deprecated": {"records.old": {"since": "0.3", "earliest_removal": "0.6"}}}}}
```

## Request parameters

| Field | Type | Notes |
| --- | --- | --- |
| `client` | string | Client name, at most 128 bytes |
| `client_version` | string | Client version, at most 128 bytes |
| `protocols` | array of int | Protocol versions the client supports: 1 to 16 non-negative integers |
| `session_token` | string | Optional. On `agent.sock`, the token from the envelope's environment, at most 256 bytes. Without a valid token the caller is matched to its envelope by audit token, or refused (`-32009`, and the connection is closed); see [binding](agent-socket.md#binding-a-connection-to-its-session). Ignored on `user.sock` |
| `binary_frames` | bool | Optional, default `true`. A client that cannot handle binary frames sends `false` and receives raw bytes base64-encoded inside JSON for the rest of the connection |

Parameters that are missing, of the wrong type or over their limits are invalid params (`-32602`). Unknown fields are
ignored. A failed first `hello` closes the connection. A later `hello` on an open connection is answered like any
other call and, when it succeeds, its `binary_frames` applies from then on.

## Result

| Field | Type | Notes |
| --- | --- | --- |
| `engine_version` | string | |
| `protocol` | int | The chosen protocol version: the highest one both sides support |
| `platform` | string | `<os>-<major>-<arch>`, e.g. `macos-15-arm64`, with Apple's architecture names (`arm64`, `x86_64`). The major version is probed; if it cannot be read it is `unknown` (`macos-unknown-arm64`), never guessed |
| `session_id` | ULID | On `agent.sock`, the session the connection is now bound to; absent on `user.sock` |
| `advisory` | bool | `true` for builds that give no security guarantees (phase 1: not for running agents unattended) |
| `binary_frames` | bool | Whether raw bytes travel in binary frames (`true`) or as base64 inside JSON (`false`) on this connection |
| `capabilities` | object | See [../05-models/capabilities.md](../05-models/capabilities.md) |

## Rules

- `protocol` is one integer. Within a version, changes are additive only, and clients ignore fields they do not know.
- If none of the client's `protocols` is supported, `hello` fails with `-32005` and `data.capability` `"protocol"`,
  and the connection is closed.
- A method or capability is available only if `hello` lists it. A missing backend is reported as `none`, never silently replaced.
- A removed method keeps working for two engine minor releases after `hello` marks it deprecated: deprecated in
  0.3, it is still served by 0.4 and 0.5 and may be removed from 0.6 (`earliest_removal`). `capabilities.deprecated`
  lists every deprecated method among `methods`, keyed by name, with `since` and `earliest_removal`.
- Every method is declared once, in the method catalogue (`knsh-proto`), with its endpoints, whether the build
  implements it, the backend it needs and its deprecation. The dispatch tables and `capabilities.methods` are both
  generated from it, so `methods` lists exactly the methods callable on that endpoint on this machine.
