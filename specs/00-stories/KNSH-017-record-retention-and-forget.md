# KNSH-017 — Record retention and `forget`

[Phase 1](README.md#phase-1--observe-advisory) · [Story index and plan](README.md)

| Phase | Epic | Size | Depends on | Crates | Requirements |
| --- | --- | --- | --- | --- | --- |
| 1 | Records | L (5) | [KNSH-016](KNSH-016-record-store-with-records-query-and-records-output.md), [KNSH-023](KNSH-023-cli-knsh-history-and-knsh-events.md) | `knsh-store`, `knshd`, `knsh` | FR-REC-07, FR-REC-10, NFR-PRIV-03 |

**Description.** Merged from *Record retention* and *`forget` (API and CLI)*: they are done and validated together because both are deletion paths over the same store and share their tests.

*Record retention.* As a user, I want old records removed automatically, so that the store stays bounded. Retention is
30 days or 2 GB, whichever comes first, configurable per profile (`recording.retention_days`).

*`forget` (API and CLI).* As a user, I want to delete records for a session or since a date. `--with-checkpoints` is accepted
and becomes effective in phase 3.

**Acceptance criteria**
*Record retention*

- [x] Records older than the retention period are deleted, oldest first, with their output blobs.
- [x] When the store exceeds 2 GB, oldest records are deleted until under the limit.
- [x] Retention runs periodically and at start, in the writer thread, without blocking record writes for long
      (batched deletes).
- [x] Denial and approval records follow the same retention (no special keeping beyond the limit).
- [x] Time comes from the injected clock.

*`forget` (API and CLI)*

- [x] `forget {session_id}` and `forget {since}` on `user.sock` delete matching records and their output blobs in one
      transaction; on error nothing is deleted.
- [x] `knsh forget --session <id>` and `--since <date>` call it and report the count; at least one selector is
      required.
- [x] `--with-checkpoints` in phase 1 reports that checkpoints are not available (`-32005`), rather than silently
      ignoring the flag.
- [x] Not available on `agent.sock`.

**Unit tests**
*Record retention*

- `deletes_records_older_than_retention` — FR-REC-07 (fake clock).
- `size_limit_deletes_oldest_first` — FR-REC-07.
- `per_profile_retention_overrides_default` — configurability.
- `retention_deletes_output_blobs_with_records` — no orphaned output.

*`forget` (API and CLI)*

- `forget_session_deletes_records_and_blobs` — FR-REC-10.
- `forget_is_atomic_on_error` — failure safety.
- `forget_requires_a_selector` — CLI validation.
- `with_checkpoints_reports_capability_unavailable` — honest capabilities.

**Notes**
*Record retention*

— How a per-profile retention applies to a store shared by sessions with different profiles is not
specified; propose "per record, using the profile of its session" in the spec. *Resolved:* specified in
[execution records](../03-functional-requirements/execution-records.md#retention) — per record by its session's
profile, the default for unknown sessions, and one 2 GB limit for the whole store.

*Implementation notes (KNSH-017)*

- The size limit is measured as the store's live pages (`page_count − freelist_count`); freed pages are reused, so
  the file stays bounded without a `VACUUM`.
- `records.forget` overwrites deleted content (`secure_delete`) and truncates the write-ahead log afterwards.
- `knsh forget` uses a minimal `user.sock` client (`knsh::cli::client`) that KNSH-023 extends.
- Per-profile periods are a store setting; `knshd` passes the defaults until profile files are loaded.
