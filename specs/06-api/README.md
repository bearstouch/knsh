# API overview

The API is **JSON-RPC 2.0** on all three endpoints: in length-prefixed frames on the two Unix sockets, and the same messages carried in XPC messages on the control service. Every client starts with `hello`, which settles the protocol version and reports what this machine can guarantee.

| Endpoint | Callers | Scope | Methods |
| --- | --- | --- | --- |
| `agent.sock` | Processes inside envelopes | The caller's own session | [agent-socket.md](agent-socket.md) |
| `user.sock` | User processes outside envelopes | All sessions; security changes need Touch ID | [user-socket.md](user-socket.md) |
| Control (XPC) | The trusted authority only | All sessions | [control-service.md](control-service.md) |

## Documents

| Document | Contents |
| --- | --- |
| [wire-format.md](wire-format.md) | Frame layout, binary streams, strict JSON profile |
| [handshake.md](handshake.md) | `hello`, versioning and deprecation |
| [agent-socket.md](agent-socket.md) | `exec.*`, `policy.check`, own records, events and checkpoints |
| [user-socket.md](user-socket.md) | Session management, observers, approvals, policy edits, `forget` |
| [control-service.md](control-service.md) | Authority registration, decision protocol, policy, secrets |
| [errors.md](errors.md) | Error codes |
| [cli.md](cli.md) | The `knsh` CLI that wraps the API |

## Envelope

Every message is one JSON-RPC 2.0 object: a request (`id`, `method`, `params`), a notification (no `id`), a success
response (`id`, `result`) or an error response (`id`, `error` with `code`, `message` and optional `data`). The engine
reads them strictly; anything else is an invalid request (`-32600`, see [errors.md](errors.md)):

- `jsonrpc` must be exactly `"2.0"`.
- Batches (a JSON array of messages) are not supported: one frame carries one message.
- An envelope holds only the members listed above. Extensions go inside `params`, `result` or `data`, where unknown
  fields are ignored.
- `id` is an integer within ±2^53, written without a fraction or exponent, or a string of at most 128 bytes. A
  request `id` is never `null`; an error response carries `id: null` only when the request's `id` could not be read.
- `params`, when present, is an object (parameters by name). An array is invalid params (`-32602`).
- The engine never answers a notification (a valid call without `id`) or a response (a message with `result` or
  `error`), not even with an error. A message that is neither, such as one with a wrong `jsonrpc` and no `id`, is an
  invalid request and is answered with `id: null`.

**Method names** have the form `area.verb`: two segments separated by one dot, each a lowercase ASCII letter followed
by lowercase letters, digits or `_` (for example `exec.run`, `session.start_agent`), at most 64 bytes in all. The
single exception is `hello`, the handshake. The `rpc` area is reserved by JSON-RPC. A malformed name is answered as an
unknown method (`-32601`).

## Versioning

- `protocol` is one integer. Within a version, changes are additive only, and clients ignore fields they do not know.
- A method or capability is available only if `hello` lists it.
- A removed method keeps working for two engine minor releases after `hello` marks it deprecated.
