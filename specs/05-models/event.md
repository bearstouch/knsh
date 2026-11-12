# Event

Delivery rules are in [../functional-requirements/events.md](../functional-requirements/events.md).

## Envelope

```json
{"event": "command.finished", "id": "01J…", "seq": 4182, "ts": "2026-11-12T18:02:11.204913Z",
 "session_id": "01J…", "actor": {"kind": "agent", "agent_id": "claude-code"}, "data": {…}}
```

| Field | Type | Notes |
| --- | --- | --- |
| `event` | string | Event name from the catalog |
| `id` | ULID | Unique event ID |
| `seq` | int | Increases per session; used with `events.subscribe {since_seq}` |
| `ts` | timestamp | UTC, microseconds |
| `session_id` | ULID | |
| `actor` | object | `kind`, `agent_id` |
| `data` | object | Event-specific payload |

## Catalog

| Event | Emitted when | Can block |
| --- | --- | --- |
| `session.started`, `session.ended` | A session begins or exits | No |
| `session.state_changed` | Paused, resumed, human control, handed back | No |
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
