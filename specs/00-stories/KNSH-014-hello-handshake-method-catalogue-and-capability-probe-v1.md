# KNSH-014 — `hello` handshake, method catalogue and capability probe v1

[Phase 1](README.md#phase-1--observe-advisory) · [Story index and plan](README.md)

| Phase | Epic | Size | Depends on | Crates | Requirements |
| --- | --- | --- | --- | --- | --- |
| 1 | API / Daemon | XL (8) | [KNSH-007](KNSH-007-platform-interface-and-test-fakes.md), [KNSH-013](KNSH-013-knshd-connection-server-dispatcher-and-idle-exit.md) | `knsh-proto`, `knshd`, `knsh-platform` | NFR-SEC-10, [handshake](../06-api/handshake.md), [capabilities](../05-models/capabilities.md), NFR-REL-08 |

**Description.** Merged from *`hello` handshake and method catalogue* and *Capability probe v1*: they are done and validated together because `hello` is how the capability probe is observed.

*`hello` handshake and method catalogue.* As a client, I want `hello` to settle the protocol version and tell me which methods and backends
this machine has, so that I never call something that is not there. One method catalogue declares every method,
its endpoints, its availability and deprecation; dispatch tables and the `methods` list are generated from it.

*Capability probe v1.* As a client, I want the engine to report which backends actually work here, so that guarantees are
honest. v1 probes: `sandbox` (presence and a trivial successful run of `sandbox-exec`; reported but unused in phase 1),
`network_filter` (`none` in phase 1), `file_events` (FSEvents available), `secrets` (`none` in phase 1),
`checkpoints` (`none` in phase 1), `platform` string. Later phases extend the probe.

**Acceptance criteria**
*`hello` handshake and method catalogue*

- [ ] `hello` params: `client`, `client_version`, `protocols`, optional `session_token`, optional binary-frame
      opt-out; result: `engine_version`, `protocol`, `platform` (e.g. `macos-15-arm64`), `session_id` where
      applicable, `capabilities`.
- [ ] If none of the client's `protocols` is supported, the call fails and the connection closes.
- [ ] `capabilities.methods` lists exactly the methods available on that endpoint on this machine.
- [ ] Missing backends are reported as `none`, never omitted or replaced (NFR-SEC-10).
- [ ] Deprecated methods are marked in `hello` and keep working for two engine minor releases (catalogue field).
- [ ] Phase 1 builds report themselves as advisory (see KNSH-024).

*Capability probe v1*

- [ ] Each probe runs a real check, not a version guess, and reports `none` on any failure.
- [ ] Probing is bounded in time; a hanging probe reports `none`.
- [ ] Results are cached per `knshd` lifetime and re-probed on restart.
- [ ] Phase 1 reports `network_filter: none`, `secrets: none`, `checkpoints: {}` (or `none`) — no feature is claimed
      before it exists.

**Unit tests**
*`hello` handshake and method catalogue*

- `methods_list_matches_catalogue_for_endpoint` — single source of truth.
- `unsupported_protocol_list_is_refused` — version negotiation.
- `missing_backend_reported_as_none` — honest capabilities.
- `binary_opt_out_switches_to_base64` — wire format fallback.

*Capability probe v1*

- `failed_probe_reports_none` — honest capabilities (fake process runner).
- `hanging_probe_times_out_as_none` — bounded probing (fake clock).
- `platform_string_format` — `macos-<major>-<arch>`.
