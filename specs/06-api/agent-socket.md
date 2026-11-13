# `agent.sock`

Reachable by processes inside envelopes. Every method is scoped to the caller's session.

| Method | Purpose |
| --- | --- |
| `exec.run` | Run a line and wait; returns the record ID, `executed_command`, exit code, output in the requested mode, and the decision |
| `exec.start`, `exec.wait`, `exec.kill` | The same for long-running lines; output arrives as events |
| `policy.check` | Dry run: what policy would decide for a line, without running it |
| `records.query`, `records.output` | The session's own records and output ranges ([parameters](user-socket.md#records)) |
| `events.subscribe`, `events.unsubscribe` | The session's own events, optionally from `since_seq` |
| `checkpoint.list`, `checkpoint.diff`, `checkpoint.undo`, `checkpoint.redo` | The session's own changes, without `force` |
| `session.info` | Actor, profile, state, recording settings |

## `exec.run`

### Request

| Param | Type | Notes |
| --- | --- | --- |
| `command` | string | The line to run |
| `cwd` | path | Working directory |
| `timeout_s` | int | The line is killed after this, with `-32008` |
| `output.mode` | string | `full`, `truncate`, `head_tail`, `errors_only` or `ref` ([output modes](../03-functional-requirements/output-modes.md)); default from the profile |
| `output.max_bytes` | int | For `truncate` |
| `output.lines` | int | For `head_tail` |

### Example

```json
{"jsonrpc": "2.0", "id": 7, "method": "exec.run",
 "params": {"command": "npm test", "cwd": "/Users/me/code/app", "timeout_s": 600,
   "output": {"mode": "errors_only"}}}

{"jsonrpc": "2.0", "id": 7, "result": {"record_id": "01J…", "executed_command": "npm test",
   "exit_code": 1, "duration_ms": 18421, "stderr": "…", "stdout_tail": "…", "skipped_lines": 2140,
   "decision": {"verdict": "allow", "source": "rule", "rule_id": "exec.allow[1]"},
   "files_changed": 3, "checkpoint_id": "…"}}
```

### Result

| Field | Notes |
| --- | --- |
| `record_id` | The execution record |
| `executed_command` | The line actually run, after any rewrite |
| `exit_code` | Exit code of the line |
| `duration_ms` | Run time |
| Output fields | Depend on the mode (`stdout`, `stderr`, `stdout_tail`, `skipped_lines`, sizes) |
| `decision` | `verdict`, `source`, `rule_id` |
| `files_changed` | Count of changed paths under checkpoint roots |
| `checkpoint_id` | Checkpoint holding the pre-images, or null |

### Errors

`-32001` denied, `-32002` no decision before timeout, `-32007` session held, `-32008` killed at timeout, `-32010` checkpoint not ready, `-32011` cancelled. See [errors.md](errors.md).

## Restrictions

- `force` is never accepted on this endpoint.
- Sessions cannot be created from this endpoint.
- Records, events and checkpoints of other sessions are never visible (`-32003`).
