# KNSH-016 — Record store with `records.query` and `records.output`

[Phase 1](README.md#phase-1--observe-advisory) · [Story index and plan](README.md)

| Phase | Epic | Size | Depends on | Crates | Requirements |
| --- | --- | --- | --- | --- | --- |
| 1 | Records / API | XL (8) | [KNSH-010](KNSH-010-sqlite-ffi-binding.md), [KNSH-014](KNSH-014-hello-handshake-method-catalogue-and-capability-probe-v1.md), [KNSH-015](KNSH-015-session-model-and-registry.md) | `knsh-store`, `knsh-proto`, `knshd` | FR-REC-02, FR-REC-08, FR-REC-09, FR-REC-11, NFR-REL-05, [execution record](../05-models/execution-record.md), [user socket](../06-api/user-socket.md), [agent socket](../06-api/agent-socket.md) |

**Description.** Merged from *Record store schema and writer* and *`records.query` and `records.output`*: they are done and validated together because records written are validated by reading them back through the query methods.

*Record store schema and writer.* As the engine, I want a versioned SQLite schema for sessions and execution records, so that
records are written durably by `knshd` itself. The schema holds every field of the execution record model (most
are empty in phase 1); human telemetry records hold only `command`, `cwd`, times and `exit_code`. Output is stored
as blob references when recording output is on.

*`records.query` and `records.output`.* As an observer or the CLI, I want to query records and fetch output ranges through the API, so that
the SQLite file never becomes an API. On `user.sock`: all sessions, read-only. The `agent.sock` variant (own session
only) is wired in phase 2 using the same handler with a scope parameter.

**Acceptance criteria**
*Record store schema and writer*

- [ ] Schema version is stored; migrations run forward in a transaction; a database with a newer version is not
      opened for writing and is reported, never overwritten (persistence rule).
- [ ] The writer is single-threaded (one writer thread), and a record is committed before the caller is answered.
- [ ] Human records store only `command`, `cwd`, `started_at`, `ended_at`, `exit_code` — other columns stay null
      even if the caller supplies them (FR-REC-09).
- [ ] Output blobs are capped at 1 MB per stream by default; beyond it head and tail are kept with a skipped-byte
      count (FR-REC-06).
- [ ] No API takes secret values; text fields take `Redacted<String>` or an already-redacted type (FR-REC-11).
- [ ] The database file lives under the engine data directory with 0600.

*`records.query` and `records.output`*

- [ ] `records.query` filters by session, time range and text match on `command`, with a page size limit and a
      cursor; results are ordered by `record_id`.
- [ ] `records.output` returns a byte range of a stream as a binary stream (or base64 if the client opted out),
      with total size; ranges beyond the end are clamped.
- [ ] Large byte counts are sent as strings (±2^53 rule).
- [ ] A query scope parameter restricts results to one session; the handler cannot return records outside the
      scope (tested now, used on `agent.sock` in phase 2).

**Unit tests**
*Record store schema and writer*

- `human_record_drops_non_telemetry_fields` — FR-REC-09.
- `record_committed_before_reply` — FR-REC-02 (writer acknowledges after commit).
- `newer_schema_is_not_overwritten` — persistence rule.
- `output_over_cap_keeps_head_and_tail` — FR-REC-06.
- `migration_failure_rolls_back` — failure safety.

*`records.query` and `records.output`*

- `query_filters_by_session_and_time` — behaviour.
- `query_pagination_is_stable` — cursor.
- `output_range_returns_binary_stream` — wire format.
- `scoped_query_never_returns_other_sessions` — scoping for `agent.sock`.
