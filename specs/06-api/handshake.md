# Handshake

Every client starts with `hello`, which settles the protocol version and reports what this machine can guarantee.

```json
// client → engine
{"jsonrpc": "2.0", "id": 1, "method": "hello",
 "params": {"client": "my-agent", "client_version": "0.4.0", "protocols": [1], "session_token": "…"}}

// engine → client
{"jsonrpc": "2.0", "id": 1, "result": {"engine_version": "0.1.0", "protocol": 1,
 "platform": "macos-15-arm64", "session_id": "…",
 "capabilities": {"sandbox": "seatbelt", "network_filter": "proxy", "file_events": "fsevents",
   "secrets": "keychain", "checkpoints": {"/Users/me/code/app": "apfs-clone"},
   "methods": ["exec.run", "records.query", "…"]}}}
```

## Request parameters

| Field | Type | Notes |
| --- | --- | --- |
| `client` | string | Client name |
| `client_version` | string | Client version |
| `protocols` | array of int | Protocol versions the client supports |
| `session_token` | string | On `agent.sock`, the token from the envelope's environment. Without a valid token the caller is matched to its envelope by audit token, or refused (`-32009`) |
| Binary frame support | — | A client that cannot handle binary frames says so here and receives raw bytes base64-encoded inside JSON |

## Result

| Field | Type | Notes |
| --- | --- | --- |
| `engine_version` | string | |
| `protocol` | int | The chosen protocol version |
| `platform` | string | e.g. `macos-15-arm64` |
| `session_id` | ULID | On `agent.sock`, the caller's session |
| `capabilities` | object | See [../models/capabilities.md](../models/capabilities.md) |

## Rules

- `protocol` is one integer. Within a version, changes are additive only, and clients ignore fields they do not know.
- A method or capability is available only if `hello` lists it. A missing backend is reported as `none`, never silently replaced.
- A removed method keeps working for two engine minor releases after `hello` marks it deprecated.
