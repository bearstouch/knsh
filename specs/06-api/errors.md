# Errors

Standard JSON-RPC errors apply (for example `-32700` parse error for input that violates the [strict JSON profile](wire-format.md#strict-json-profile)). Engine-specific codes:

| Code | Meaning | `data` |
| --- | --- | --- |
| -32001 | Denied by policy, hook, authority or rate limit | `rule_id`, `reason`, `source` |
| -32002 | No decision before the timeout | `request_id` |
| -32003 | Caller not allowed on this endpoint or session | none |
| -32004 | Undo or redo conflict | Conflicting paths and reasons |
| -32005 | Capability not available on this machine | Capability name |
| -32006 | Session not found or ended | `session_id` |
| -32007 | Session paused or under human control; the line is held | `state` |
| -32008 | The line exceeded its timeout and was killed | `record_id` |
| -32009 | Session token missing, invalid or expired | none |
| -32010 | Checkpoint not ready: the root's shadow is still being built | `root`, progress |
| -32011 | Request cancelled | `request_id` |

Process exit codes seen by `knsh -c` callers are in [../09-reference/exit-codes.md](../09-reference/exit-codes.md).
