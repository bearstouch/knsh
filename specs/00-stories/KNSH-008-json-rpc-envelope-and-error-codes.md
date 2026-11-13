# KNSH-008 — JSON-RPC envelope and error codes

[Phase 0](README.md#phase-0--foundations) · [Story index and plan](README.md)

| Phase | Epic | Size | Depends on | Crates | Requirements |
| --- | --- | --- | --- | --- | --- |
| 0 | Wire protocol | M (3) | [KNSH-003](KNSH-003-strict-json-reader-and-writer.md), [KNSH-004](KNSH-004-frame-codec-and-binary-streams.md) | `knsh-proto` | [API overview](../06-api/README.md), [errors](../06-api/errors.md) |

**Description.** As a client or the engine, I want typed JSON-RPC 2.0 requests, responses, notifications and errors,
with the engine error codes defined once, so that every endpoint shares one schema. Out of scope: individual method
params (added by the stories that implement each method).

**Acceptance criteria**
- [ ] Types for request (`jsonrpc: "2.0"`, `id`, `method`, `params`), success response, error response and
      notification; `jsonrpc` other than `"2.0"` is rejected.
- [ ] An `ErrorCode` enum with `-32700`, `-32600`, `-32601`, `-32602`, `-32603` and engine codes `-32001` – `-32011`
      with the meanings and `data` shapes in [errors.md](../06-api/errors.md); the enum is the only place these numbers
      appear.
- [ ] Strict-profile parse failures map to `-32700`; unknown methods to `-32601`; invalid params to `-32602`.
- [ ] A `MethodName` type validates names (`area.verb`) used by the method catalogue later (KNSH-014).

**Unit tests**
- `parse_error_maps_to_minus_32700` — strict profile.
- `error_codes_match_spec_table` — every code and meaning in the spec table is present exactly once.
- `rejects_wrong_jsonrpc_version` — envelope validity.
- `round_trips_request_response_notification` — codec.
