# `agent.sock`

Reachable by processes inside envelopes. Every method is scoped to the caller's session.

| Method | Purpose |
| --- | --- |
| `exec.run` | Run a line and wait; returns the record ID, `executed_command`, exit code, output in the requested mode, and the decision |
| `exec.start`, `exec.wait`, `exec.kill` | The same for long-running lines; output arrives as events |
| `policy.check` | Dry run: what policy would decide for a line, without running it ([below](#policycheck)); `-32003` until sessions are bound to `agent.sock` connections (KNSH-048) |
| `records.query`, `records.output` | The session's own records and output ranges ([parameters](user-socket.md#records)) |
| `events.subscribe`, `events.unsubscribe` | The session's own events, optionally from `since_seq` |
| `checkpoint.list`, `checkpoint.diff`, `checkpoint.undo`, `checkpoint.redo` | The session's own changes, without `force` |
| `session.info` | Actor, profile, state, recording settings ([result](user-socket.md#sessioninfo)); `-32003` until sessions are bound to `agent.sock` connections (KNSH-048) |

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

## `policy.check`

A dry run (FR-POL-70, KNSH-043): the line is parsed, its command names are resolved, it is classified and decided
against a profile's rules exactly as `exec.run` would before running it, and nothing else happens. No record is
written, no event is published and no process is started. Hooks, the authority and grants are not consulted, so a line
the rules ask about is answered `ask` even if a grant or the authority would allow it.

On `agent.sock` the line is checked against the caller's own session's profile; `session_id` and `profile` are
refused with `-32003`. Until a session is bound to an `agent.sock` connection (KNSH-048) every call there is `-32003`,
after its params are checked. On `user.sock` exactly one of `session_id` and `profile` is required.

### Request

| Param | Type | Notes |
| --- | --- | --- |
| `command` | string | The line, at most 65536 bytes |
| `cwd` | path | Working directory names are resolved from and `${PROJECT}` is found from: absolute, without `.`, `..` or `//`, at most 16384 bytes |
| `path` | string, optional | The `PATH` names are resolved on, at most 65536 bytes; default `/usr/bin:/bin:/usr/sbin:/sbin` |
| `session_id` | ULID, optional | `user.sock`: check against this live session's profile |
| `profile` | string, optional | `user.sock`: check against this profile. `unattended` is the built-in profile; any other name is `<name>.toml` in the policies directory |

Profile paths are expanded with `knshd`'s `HOME` and `TMPDIR`. A file read by `source` or `.` is not trusted until the
session's write roots are known (KNSH-050), so every `source` is reported as dynamic code; this only errs towards a
stricter answer.

### Example

```json
{"jsonrpc": "2.0", "id": 3, "method": "policy.check",
 "params": {"command": "git push origin main", "cwd": "/Users/me/code/app", "profile": "web"}}

{"jsonrpc": "2.0", "id": 3, "result": {"profile": "web", "verdict": "ask", "source": "rule",
   "rule_id": "exec.ask[0]", "reason": null,
   "matched_rules": [{"command": 0, "verdict": "ask", "rule_id": "exec.ask[0]"}],
   "commands": [{"name": "git", "program": "/usr/bin/git", "class": "static", "dynamic_reason": null,
     "wrapper": null}],
   "dynamic": [], "network_classes": ["network:publish"]}}
```

### Result

| Field | Notes |
| --- | --- |
| `profile` | The profile that decided |
| `verdict` | `allow`, `ask` or `deny` |
| `source` | `rule`, or `standalone` for an ask the `unattended` profile denies |
| `rule_id` | The deciding rule or setting (`exec.allow[n]`, `exec.ask[n]`, `exec.deny[n]`, `exec.project_executables`, `exec.default`), or null for a line with no parts and for a failed evaluation |
| `reason` | Why, when the rule alone does not say (an `unattended` deny, a failed evaluation), or null |
| `matched_rules` | Every part's decision: `command` (index into `commands`, or null for a dynamic part decided by `exec.default`), `verdict`, `rule_id` |
| `commands` | Every simple command, wrapper and wrapped command in source order: `name` (null when built from an expansion), `program` (the resolved binary, or null for a builtin, a function or a name not found), `class` (`static`, `wrapper`, `project_executable`, `dynamic`), `dynamic_reason` (null unless `dynamic`), `wrapper` (index of the wrapper running it, or null) |
| `dynamic` | Every dynamic part of the line: `reason` (`interpreter_code`, `eval`, `source`, …) and its byte range `start`, `end` |
| `network_classes` | The network classes the line would present to host rules; empty for dynamic code |

### Errors

Malformed params, two targets, or none on `user.sock` are `-32602`, as is a `profile` that does not exist. A
`session_id` that is not live is `-32006`. A profile that cannot be loaded (invalid, unreadable, a missing parent) is
`-32603`, without the reason, as is a result too large for one frame (1 MB). An answer is either the whole result or an error, never part of a result.

## Restrictions

- `force` is never accepted on this endpoint.
- Sessions cannot be created from this endpoint.
- Records, events and checkpoints of other sessions are never visible (`-32003`).
