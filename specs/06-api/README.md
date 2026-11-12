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

## Versioning

- `protocol` is one integer. Within a version, changes are additive only, and clients ignore fields they do not know.
- A method or capability is available only if `hello` lists it.
- A removed method keeps working for two engine minor releases after `hello` marks it deprecated.
