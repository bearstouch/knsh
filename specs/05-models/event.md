# Event

Delivery rules are in [../03-functional-requirements/events.md](../03-functional-requirements/events.md).

## Envelope

```json
{"event": "command.finished", "id": "01J…", "seq": 4182, "ts": "2026-11-12T18:02:11.204913Z",
 "session_id": "01J…", "actor": {"kind": "agent", "agent_id": "claude-code"}, "data": {…}}
```

| Field | Type | Notes |
| --- | --- | --- |
| `event` | string | Event name from the catalog |
| `id` | ULID | Unique event ID |
| `seq` | int | Starts at 1 (`session.started`) and increases by one per event of the session, with no gaps; used with `events.subscribe {since_seq}` |
| `ts` | timestamp | UTC, microseconds |
| `session_id` | ULID | |
| `actor` | object | `kind`, `agent_id` |
| `data` | object | Event-specific payload |

Every text in `data` is redacted before the event is published (FR-EVT-07): the engine's event types accept only
redacted text and typed values. Subscribers receive events as notifications ([user socket](../06-api/user-socket.md#events)).

## Phase 1 payloads

| Event | `data` |
| --- | --- |
| `session.started` | `profile`, `envelope` (bool), `recording` (bool), `parent_session_id` (ULID or `null`). Always `seq` 1 |
| `session.ended` | `{}`. Always the session's last event, right after `session.state_changed` to `ended` |
| `session.state_changed` | `from`, `to`: `active`, `paused`, `human_control` or `ended` |
| `session.idle` | `{}` |
| `command.finished` | `record_id`, `command` (redacted), `cwd`, `started_at`, `ended_at`, `exit_code` (int or `null`) |
| `cwd.changed` | `cwd` |

A `cwd` that is not valid UTF-8 is shown with U+FFFD replacements, as in records.

## Phase 2 payloads

| Event | `data` |
| --- | --- |
| `command.proposed` | `command` (redacted), `cwd`, `rewritten_from` (the line before a rewrite, redacted, or `null`). Published once for each line the supervisor evaluates, before that line's hooks run: once for the line received, and once more for the line a rewrite produced (KNSH-050) |
| `command.denied` | `record_id` (the denial's record, or `null` if it could not be written), `command` (redacted), `cwd`, `source` (as the record's `decision.source`), `rule_id` (or `null`), `reason` (or `null`). Published after the denial's record is written (KNSH-050) |
| `decision.cancelled` | `request_id` (the pending request, or `null` when the line had not reached the ask step), `reason`: `caller_gone` (the caller disconnected, FR-LC-41) or `timed_out` (no answer before the timeout, FR-AUTH-23). Always followed by the line's `command.denied` (KNSH-050) |
| `command.started` | `record_id` (the record the line is written to when it ends), `command` (the line that runs, after any rewrite, redacted), `cwd`, `started_at`. Published once the line was spawned through `knsh-exec` (KNSH-051) |
| `command.long_running` | The same fields as `command.started`. Published once, when the line is still running after the long-running threshold (30 s) (KNSH-051) |
| `sandbox.violation` | A [sandbox violation](execution-record.md#sandbox_violations): `session_id`, `record_id` (ULID, or `null` for a denial inside an envelope), `rule`, `operation`, `argument` (string or `null`), `process`, `pid`, `count`, `at`. Published only for a live session named by the denial's tag; repeats within 3 s are one event with their `count` (KNSH-047) |

## Catalog

| Event | Emitted when | Can block |
| --- | --- | --- |
| `session.started`, `session.ended` | A session begins or exits | No |
| `session.state_changed` | Paused, resumed, human control, handed back, ended | No |
| `session.idle` | A human prompt has waited for input for 5 s | No |
| `command.proposed` | Lifecycle step 3 | Yes, through hooks |
| `decision.requested` | Policy returned ask; sent to the authority only | Yes, waits for an answer |
| `decision.cancelled` | The caller went away or the request timed out | No |
| `command.denied` | A line was refused | No |
| `command.denied_repeatedly` | Rate limiting started for a repeated line | No |
| `command.started` | The line was spawned | No |
| `command.output` | Output chunk, only when output recording is on | No |
| `command.long_running` | Still running after 30 s (configurable) | No |
| `command.finished` | The line exited and the record is written | No |
| `agent.edit` | Files changed inside an envelope outside any supervised command | No |
| `cwd.changed` | The working directory changed | No |
| `file.changed` | A path under a checkpoint root changed, by any process | No |
| `checkpoint.created`, `checkpoint.restored`, `checkpoint.uncertain` | A checkpoint was taken, restored, or marked uncertain after dropped file events | No |
| `proxy.denied` | The proxy refused a connection | No |
| `sandbox.violation` | The system reported a sandbox denial, best effort | No |
| `secret.injected` | A secret was given to a command (name only) | No |
| `policy.updated`, `policy.invalid` | A snapshot was loaded, or a policy file failed its integrity check | No |
| `authority.connected`, `authority.disconnected` | The authority connected or disconnected | No |
