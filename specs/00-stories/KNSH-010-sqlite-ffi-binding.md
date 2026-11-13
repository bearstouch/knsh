# KNSH-010 — SQLite FFI binding

[Phase 0](README.md#phase-0--foundations) · [Story index and plan](README.md)

| Phase | Epic | Size | Depends on | Crates | Requirements |
| --- | --- | --- | --- | --- | --- |
| 0 | Platform | L (5) | [KNSH-007](KNSH-007-platform-interface-and-test-fakes.md) | `knsh-platform` (module `sqlite`) | [supply chain](../04-non-functional-requirements/supply-chain.md) (system SQLite, no crates), FR-REC-08 |

**Description.** As the record store, I want a minimal safe wrapper over the system SQLite library, so that records
are stored without a third-party crate. Hand-written `extern` declarations for open (with flags), prepare, bind
(int, text, blob, null), step, column readers, reset, finalize, exec, busy timeout and error messages. Out of scope:
the record schema (KNSH-016).

**Acceptance criteria**
- [ ] Links against the system `libsqlite3` on macOS; no bundled SQLite and no build-time download.
- [ ] All `unsafe` is inside this module with `// SAFETY:` comments; the public API is safe: statements cannot
      outlive their connection, and `Drop` finalizes statements and closes connections.
- [ ] Only bound parameters are supported for values; there is no API that formats values into SQL text.
- [ ] Every SQLite error becomes a typed error with the result code; no panics.
- [ ] Database files are created with mode 0600 (via KNSH-007 `Fs`), and the connection uses WAL mode with a busy
      timeout.
- [ ] Transactions are exposed as a guard that rolls back on drop unless committed.

**Unit tests**
- `insert_and_query_with_bound_parameters` — basic use (temp dir).
- `transaction_rolls_back_on_drop` — failure safety.
- `statement_error_returns_typed_code` — constraint violation yields typed error.
- `database_file_created_owner_only` — 0600.
- `blob_round_trip_preserves_bytes` — binary output storage.
