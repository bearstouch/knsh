# Errors

Standard JSON-RPC errors apply:

| Code | Meaning | When |
| --- | --- | --- |
| -32700 | Parse error | The message violates the [strict JSON profile](wire-format.md#strict-json-profile) |
| -32600 | Invalid Request | The message is strict JSON but not a valid [envelope](README.md#envelope) |
| -32601 | Method not found | The method name is malformed, unknown, or not available on this endpoint |
| -32602 | Invalid params | `params` does not match the method's parameters |
| -32603 | Internal error | The engine failed to build its answer |

The `message` of an error is the meaning in these tables. It never echoes text from the request. Engine-specific
codes:

| Code | Meaning | `data` |
| --- | --- | --- |
| -32001 | Denied by policy, hook, authority or rate limit | `rule_id`, `reason`, `source` |
| -32002 | No decision before the timeout | `request_id` |
| -32003 | Caller not allowed on this endpoint or session | none |
| -32004 | Undo, redo or restore conflict | `conflicts`: one {path, reason} object per conflicting path, and nothing was restored (checkpoint.restore checks every path on the way first, KNSH-086); reason is changed, missing, exists, unverifiable, pre_image_lost, folder_not_empty or parent_missing ([checkpoints](../03-functional-requirements/checkpoints.md#restore-rules), KNSH-084) |
| -32005 | Capability not available on this machine | `capability` |
| -32006 | Session not found or ended | `session_id` |
| -32007 | Session paused or under human control; the line is held | `state` |
| -32008 | The line exceeded its timeout and was killed | `record_id` |
| -32009 | Session token missing, invalid or expired | none |
| -32010 | Checkpoint not ready: the root's shadow is still being built | `root`, `progress` |
| -32011 | Request cancelled | `request_id` |

`-32010`'s `progress` is an object (KNSH-079): `files` (files and symlinks cloned so far), `folders` (folders listed)
and `folders_pending` (folders found but not listed yet). It is answered only when the caller sent
`checkpoint_wait: false`; otherwise the line waits ([`exec.run`](agent-socket.md#execrun)).

`-32009` is answered on `agent.sock` when a `hello` matches neither a live session token nor a registered envelope by
audit token, or when the session the connection was bound to has ended. The connection is closed after the answer
([binding](agent-socket.md#binding-a-connection-to-its-session)).

Process exit codes seen by `knsh -c` callers are in [../09-reference/exit-codes.md](../09-reference/exit-codes.md).

The error codes are defined once, in `knsh-proto` (`ErrorCode`); a unit test checks that enum against these tables.
