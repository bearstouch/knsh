# `user.sock`

Reachable by the user's processes outside envelopes. Every envelope and command profile denies it.

| Method | Purpose |
| --- | --- |
| `session.start_agent`, `session.list`, `session.end` | Start and manage agent sessions (`knsh agent`) |
| `records.query`, `records.output`, `events.subscribe` | Read-only access to all sessions, for observers and the CLI |
| `checkpoint.*` | All checkpoint operations, including `restore` and `force` |
| `approval.list`, `approval.approve`, `approval.deny` | Pending asks; approving needs Touch ID or password, checked by `knshd` |
| `policy.check`, `policy.edit`, `profile.use`, `policy.grant` | Policy changes and grants need Touch ID or password |
| `records.forget` | Delete records, optionally with checkpoints (`knsh forget`) |

## Authentication

- `approval.approve`, `policy.edit`, `profile.use` and `policy.grant` require Touch ID or the user's password. `knshd` shows the system authentication prompt itself, with the exact command or change in it.
- The caller cannot claim that the user is present; no parameter skips the prompt.
- `knsh authority trust` also requires Touch ID or password inside `knshd`.

## Records

`records.query` and `records.output` are the only way to read execution records (FR-REC-08). On `user.sock` they see every session. On `agent.sock` the same methods see only the caller's own session; until a session is bound to an `agent.sock` connection (KNSH-048) every call there is refused with `-32003`. Byte counts and offsets are decimal strings (±2^53 rule, [wire-format.md](wire-format.md#strict-json-profile)).

### `records.query`

| Param | Type | Meaning |
| --- | --- | --- |
| `session_id` | ULID, optional | Only this session's records. Another session than the caller's own on `agent.sock` is `-32003` |
| `since` | timestamp, optional | Only records started at or after this instant |
| `until` | timestamp, optional | Only records started before this instant |
| `text` | string, optional | Only records whose `command` contains this text (case-sensitive substring, no wildcards), at most 4096 bytes |
| `limit` | int, optional | Records per page, 1 to 1000; default 100 |
| `cursor` | ULID, optional | The previous page's `next_cursor` |

Timestamps use the engine's form, `YYYY-MM-DDTHH:MM:SS[.ffffff]Z` (one to six fractional digits, UTC only). Malformed or out-of-range params are `-32602`.

Result: `{"records": [...], "next_cursor": "01J…" | null}`. Records are ordered by `record_id` (creation order); `next_cursor` is `null` on the last page. A page may hold fewer than `limit` records with a non-null `next_cursor` when more would not fit in one frame (1 MB); a single record too large for a frame is `-32603`. Paging by cursor is stable: records added between calls sort after every earlier page. Each record has `record_id`, `session_id`, `actor`, `command`, `cwd`, `started_at`, `ended_at`, `exit_code`, `stdout` and `stderr`; agent records also have `rewritten_from`, `pipestatus`, `signal`, `sandbox_profile`, `secrets_injected` and `checkpoint_id`, human records never do (FR-REC-09). `stdout` and `stderr` are `null` when output was not recorded, otherwise `{"size", "original_size", "skipped", "skipped_at"}`: `size` bytes are stored, the command wrote `original_size`, and `skipped` bytes were dropped at offset `skipped_at` of the stored bytes (head and tail kept, FR-REC-06). A `cwd` that is not valid UTF-8 is shown with U+FFFD replacements.

### `records.output`

| Param | Type | Meaning |
| --- | --- | --- |
| `record_id` | ULID | The record |
| `stream` | `stdout` \| `stderr` | The stream |
| `offset` | string, optional | First byte, in the stored bytes; default `"0"` |
| `length` | string, optional | At most this many bytes; default to the end |

Ranges beyond the end are clamped, never refused. Result: `record_id`, `stream`, `recorded` (false when no output was recorded for the stream; all sizes are then `"0"`), `size` (total stored size), `original_size`, `skipped`, `skipped_at`, and the range returned as `offset` and `length`. The bytes follow as a binary stream named in `data`: `{"stream_id": n, "size": "<length>", "content_type": "application/octet-stream"}`. A client that opted out of binary frames in `hello` receives `data_base64` instead, and at most 524288 bytes per call (so the answer fits in one frame); it reads longer ranges in several calls.

A `record_id` that does not exist is `-32602` on `user.sock`; on `agent.sock` a record of another session is indistinguishable from a missing one and is `-32003`.
