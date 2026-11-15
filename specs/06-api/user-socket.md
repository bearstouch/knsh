# `user.sock`

Reachable by the user's processes outside envelopes. Every envelope and command profile denies it.

| Method | Purpose |
| --- | --- |
| `session.start_agent`, `session.list`, `session.end` | Start and manage agent sessions (`knsh agent`) |
| `session.start_human`, `telemetry.command`, `telemetry.cwd`, `telemetry.idle` | A recorded human session and its telemetry, sent by `knsh` ([below](#human-sessions)) |
| `session.info` | The caller's own session: actor, profile, state, recording settings |
| `records.query`, `records.output`, `events.subscribe`, `events.unsubscribe` | Read-only access to all sessions, for observers and the CLI |
| `checkpoint.*` | All checkpoint operations, including `restore` and `force` |
| `approval.list`, `approval.approve`, `approval.deny` | Pending asks; approving needs Touch ID or password, checked by `knshd` |
| `policy.check` | Dry run of a line against a named session's or profile's policy ([parameters](agent-socket.md#policycheck)); no authentication |
| `policy.edit`, `profile.use`, `policy.grant` | Policy changes and grants need Touch ID or password |
| `records.forget` | Delete records, optionally with checkpoints (`knsh forget`) |

## Authentication

- `approval.approve`, `policy.edit`, `profile.use` and `policy.grant` require Touch ID or the user's password. `knshd` shows the system authentication prompt itself, with the exact command or change in it.
- The caller cannot claim that the user is present; no parameter skips the prompt.
- `knsh authority trust` also requires Touch ID or password inside `knshd`.

## Human sessions

`knsh` hosting a recorded human shell ([terminals and shells](../08-integrations/terminals-and-shells.md#recording-a-human-session))
starts a session over its own `user.sock` connection and reports each command line on it (KNSH-021, FR-SES-21). The
session is **bound to the connection**: no call names a session, so one connection can never write into another's,
and the session ends when the connection closes, however `knsh` went away (`session.state_changed` to `ended`, then
`session.ended`). These methods exist on `user.sock` only: nothing inside an envelope may create a session (FR-SES-02)
or write records as a human.

### `session.start_human`

No params. Creates a session with `actor.kind` `human`, `recording` true, `envelope` false, no parent, and the profile
`default` (nothing in a human session is enforced; profiles are loaded in phase 2), writes its row, publishes
`session.started`, and binds it to the connection. Result: `{"session_id": "01J…", "recording": true}`.

A second call on the same connection is `-32602`. Without a record store (it could not be opened) the call is
`-32603` and no session exists.

### `telemetry.command`

| Param | Type | Meaning |
| --- | --- | --- |
| `command` | string | The line as typed, at most 65536 bytes |
| `cwd` | path | The working directory it started in: absolute, without `.`, `..` or `//`, at most 16384 bytes |
| `started_at` | timestamp | When it started |
| `ended_at` | timestamp | When the prompt came back; not before `started_at` |
| `exit_code` | int | 0 to 255 |

Writes one record with exactly these fields (FR-REC-09; no output, no agent fields), commits it, then publishes
`command.finished`. Result: `{"record_id": "01J…"}`. The record ID is made when the record is written, so records
keep creation order.

### `telemetry.cwd`

`{"cwd": path}`, with the same rules as above. Publishes `cwd.changed`. Result: `{}`.

### `telemetry.idle`

No params. Publishes `session.idle` unless it was already published since the session's last `telemetry.command`
(FR-SES-24): `knsh` sends it once per idle prompt, and `knshd` checks again. Result: `{"emitted": bool}`.

### `session.info`

No params. The caller's own session (FR-SES-25, NFR-PRIV-05):

```json
{"session_id": "01J…", "actor": {"kind": "human"}, "profile": "default", "state": "active", "envelope": false,
 "recording": true, "output_recording": false, "parent_session_id": null}
```

`recording` says whether command lines are recorded, `output_recording` whether their output is (never for a human
session). On `user.sock` the caller's session is the one bound to the connection. On `agent.sock` it is the session
the connection was bound to at `hello` ([binding](agent-socket.md#binding-a-connection-to-its-session)); once that
session has ended it is `-32009`.

### Errors

A telemetry call or `session.info` on a connection without a session is `-32003`. Malformed params are `-32602`. A
store that fails is `-32603`. Events are best effort: a record that was written is answered even if its event could
not be published.

## Records

`records.query` and `records.output` are the only way to read execution records (FR-REC-08). On `user.sock` they see every session. On `agent.sock` the same methods see only the session the connection is bound to; naming another session, or another session's record, is `-32003`. Byte counts and offsets are decimal strings (±2^53 rule, [wire-format.md](wire-format.md#strict-json-profile)).

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

Result: `{"records": [...], "next_cursor": "01J…" | null}`. Records are ordered by `record_id` (creation order); `next_cursor` is `null` on the last page. A page may hold fewer than `limit` records with a non-null `next_cursor` when more would not fit in one frame (1 MB); a single record too large for a frame is `-32603`. Paging by cursor is stable: records added between calls sort after every earlier page. Each record has `record_id`, `session_id`, `actor`, `command`, `cwd`, `started_at`, `ended_at`, `exit_code`, `stdout` and `stderr`; agent records also have `rewritten_from`, `pipestatus`, `signal`, `sandbox_profile`, `secrets_injected`, `checkpoint_id`, `sandbox_violations`, `decision` and `argv` ([execution record](../05-models/execution-record.md)), human records never do (FR-REC-09). `stdout` and `stderr` are `null` when output was not recorded, otherwise `{"size", "original_size", "skipped", "skipped_at"}`: `size` bytes are stored, the command wrote `original_size`, and `skipped` bytes were dropped at offset `skipped_at` of the stored bytes (head and tail kept, FR-REC-06). A `cwd` that is not valid UTF-8 is shown with U+FFFD replacements.

### `records.output`

| Param | Type | Meaning |
| --- | --- | --- |
| `record_id` | ULID | The record |
| `stream` | `stdout` \| `stderr` | The stream |
| `offset` | string, optional | First byte, in the stored bytes; default `"0"` |
| `length` | string, optional | At most this many bytes; default to the end |

Ranges beyond the end are clamped, never refused. Result: `record_id`, `stream`, `recorded` (false when no output was recorded for the stream; all sizes are then `"0"`), `size` (total stored size), `original_size`, `skipped`, `skipped_at`, and the range returned as `offset` and `length`. The bytes follow as a binary stream named in `data`: `{"stream_id": n, "size": "<length>", "content_type": "application/octet-stream"}`. A client that opted out of binary frames in `hello` receives `data_base64` instead, and at most 524288 bytes per call (so the answer fits in one frame); it reads longer ranges in several calls.

A `record_id` that does not exist is `-32602` on `user.sock`; on `agent.sock` a record of another session is indistinguishable from a missing one and is `-32003`.

### `records.forget`

`user.sock` only: on `agent.sock` it is `-32003`, so an agent can never erase records (FR-REC-10, NFR-PRIV-03).

| Param | Type | Meaning |
| --- | --- | --- |
| `session_id` | ULID, optional | Delete this session's records |
| `since` | timestamp, optional | Delete records started at or after this instant |
| `with_checkpoints` | bool, optional | Delete the matching records' checkpoints too; default `false` |

At least one of `session_id` and `since` is required (`-32602` otherwise); with both, a record must match both. The matching records and their stored output are deleted in one transaction: on error nothing is deleted. Deleted content is overwritten in the database file and the write-ahead log is truncated, so forgotten text does not stay on disk. The session itself (its row: actor, profile, state) is kept.

Result: `{"deleted": n}`, the number of records deleted.

Until checkpoints exist (phase 3), `with_checkpoints: true` is refused with `-32005` and `data.capability` `"checkpoints"`, before anything is deleted: the flag is never silently ignored.

## Events

`events.subscribe` and `events.unsubscribe` deliver the events of [../05-models/event.md](../05-models/event.md) live, with the delivery rules of [events](../03-functional-requirements/events.md) (KNSH-018). On `user.sock` a subscription sees every session, or one session with `session_id`. On `agent.sock` it sees only the session the connection is bound to: without `session_id` that session, and naming another is `-32003`.

### `events.subscribe`

| Param | Type | Meaning |
| --- | --- | --- |
| `session_id` | ULID, optional | Only this session's events; every session when absent |
| `since_seq` | int, optional | Resume after this `seq`: the buffered events after it are sent first. Requires `session_id`. Absent: only events published from now on |

Result: `{"subscription_id": n, "oldest_seq": n | null, "latest_seq": n | null, "gap": bool}`. `subscription_id` is a positive integer, unique in the engine. With `session_id`, `oldest_seq` is the oldest `seq` still buffered (how far back a resume can reach) and `latest_seq` the newest published; without it both are `null`. `gap` is `true` when `since_seq` is older than the buffer: delivery then starts at `oldest_seq`, and the events in between are read from the record store (at most once beyond the buffer, FR-EVT-04). With `since_seq` inside the buffer, delivery resumes exactly after it, with no duplicate and no gap between the replayed and the live events. `since_seq: 0` replays the whole buffer.

After the answer, each event arrives as a notification whose `method` is the event name and whose `params` are the event envelope plus `subscription_id`:

```json
{"jsonrpc": "2.0", "method": "session.state_changed", "params": {"event": "session.state_changed", "id": "01J…",
  "seq": 3, "ts": "2026-11-12T18:02:11.204913Z", "session_id": "01J…", "actor": {"kind": "agent",
  "agent_id": "claude-code"}, "data": {"from": "active", "to": "paused"}, "subscription_id": 1}}
```

Events of one session arrive in `seq` order; events of different sessions are not ordered relative to each other. The answer to `events.subscribe` always precedes its first event. Publishing never waits for a subscriber: each subscription queues at most 10,000 events, and a subscriber that falls further behind loses its oldest queued events. It is told with an `events.lost` notification, sent before any later event of that session:

```json
{"jsonrpc": "2.0", "method": "events.lost", "params": {"subscription_id": 1, "session_id": "01J…", "from_seq": 2,
  "to_seq": 16}}
```

Every `seq` from `from_seq` to `to_seq` inclusive will never be delivered on this subscription. An event too large for one frame is announced the same way, as a range of one.

Errors: malformed params, `since_seq` without `session_id`, `since_seq` newer than the session's latest event, and a connection that already holds 16 subscriptions are `-32602`. A session with no buffered events (never started, or ended and its buffer dropped) is `-32006` with `data.session_id`. The buffers of the 64 most recently ended sessions are kept, so a subscriber can still catch up on a session that just ended.

### `events.unsubscribe`

| Param | Type | Meaning |
| --- | --- | --- |
| `subscription_id` | int | A subscription made on the same connection |

Result: `{}`. Nothing more is sent for the subscription after the answer. Another connection's subscription, or one already ended, is `-32602`. Closing the connection ends all its subscriptions.
