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
| `session_id` | ULID or `null` | `null` for an engine event |
| `actor` | object or `null` | `kind`, `agent_id`; `null` for an engine event |
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
| `command.denied_repeatedly` | `command` (the limited line, redacted), `cwd`, `until` (when the limit lifts). Published once when rate limiting starts for a line, right after the `command.denied` of the denial that started it; the attempts it then denies publish only `command.denied` (FR-HOOK-21, KNSH-055) |
| `decision.cancelled` | `request_id` (the pending request, or `null` when the line had not reached the ask step), `reason`: `caller_gone` (the caller disconnected, FR-LC-41) or `timed_out` (no answer before the timeout, FR-AUTH-23). Always followed by the line's `command.denied` (KNSH-050) |
| `command.started` | `record_id` (the record the line is written to when it ends), `command` (the line that runs, after any rewrite, redacted), `cwd`, `started_at`. Published once the line was spawned through `knsh-exec` (KNSH-051) |
| `command.long_running` | The same fields as `command.started`. Published once, when the line is still running after the long-running threshold (30 s) (KNSH-051) |
| `command.output` | `record_id`, `stream` (`stdout` or `stderr`), `offset` (where the chunk starts in the stream as captured, decimal string), `size` (decimal string), and the bytes: `data` (`stream_id`, `size`, `content_type`) naming the binary stream that follows the notification, or `data_base64` for a client that opted out of binary frames ([wire format](../06-api/wire-format.md)). Published only when the session's profile records output (`recording.output`), in order per stream, each chunk at most 8 KiB and already through redaction (FR-EVT-07), and only for the first 1 MB of each stream: beyond it the record keeps head and tail but no more chunks are published, so one line cannot flood the bus. Nothing is published for a line after its `command.finished` (KNSH-053) |
| `proxy.denied` | `record_id` (the line whose credentials made the request, or `null` for the envelope's own connection, attributed to the session alone), `protocol` (`http`, `socks5`, or `null`), `host` (the host the request named, or `null` if it named no valid one), `port` (int or `null`), `reason` (the proxy's fixed reason, as in the record's [`network`](execution-record.md#network)). Published for every refusal of a request whose credentials were live; refusals before that have no session and are only logged (FR-NET-09, KNSH-060) |
| `policy.invalid` | `profile`: the profile whose file has a missing or bad signature (the session's own, or a parent it `extends`). Published on the session whose line needed the file; the line is denied and nothing falls back to another profile. Without a session (starting a session, `policy.check`) the failure is in the system log and the call fails (FR-POL-42, KNSH-065) |
| `authority.connected`, `authority.disconnected` | `{}`. Engine events: `session_id` and `actor` are `null`, `seq` counts the engine's own events from 1 per `knshd` run, and only subscriptions to every session receive them; not buffered, so not resumable. Published when an authority registers (`authority.register`) and when its connection ends (FR-AUTH-02, KNSH-068) |
| `policy.updated` | `profile` (the profile the snapshot defines) and `expires_at`. An engine event, like `authority.connected`: `session_id` and `actor` are `null`, and only subscriptions to every session receive it. Published when the authority's `policy.set` snapshot was checked and stored (FR-POL-53, KNSH-071) |
| `sandbox.violation` | A [sandbox violation](execution-record.md#sandbox_violations): `session_id`, `record_id` (ULID, or `null` for a denial inside an envelope), `rule`, `operation`, `argument` (string or `null`), `process`, `pid`, `count`, `at`. Published only for a live session named by the denial's tag; repeats within 3 s are one event with their `count` (KNSH-047) |

## Phase 3 payloads

| Event | `data` |
| --- | --- |
| `file.changed` | `root` (the checkpoint root), `path` (the path inside it that changed: created, written, removed or replaced). Published on every agent session protecting the root, once its shadow follows the change, whichever process made it; an event that changed nothing is not published (FR-EVT-08, KNSH-080) |
| `checkpoint.uncertain` | `root`, `record_id` (the line whose checkpoints are uncertain, published after its `command.finished`; `null` for a window outside any line), `reason`: `events_dropped`, `event_ids_wrapped`, `root_changed`, `too_many_events`, `flush_timed_out`, `restart_gap`, `not_watched` or `shadow_update_failed`. The root is rescanned (FR-CKP-04, NFR-REL-04, KNSH-080) |

Paths that are not valid UTF-8 are shown with U+FFFD replacements, as in records.

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
