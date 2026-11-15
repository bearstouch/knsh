# `agent.sock`

Reachable by processes inside envelopes. Every method is scoped to the caller's session.

## Binding a connection to its session

`hello` binds the connection to exactly one agent session (FR-AGT-23, KNSH-048), and `hello`'s result names it in
`session_id`:

1. **Session token.** The `session_token` from the envelope's environment, if it is the live token of a session.
   Tokens are 256 bits from the platform random source, sent as 64 lowercase hex characters, compared in constant
   time, and never logged, stored or recorded (NFR-SEC-02).
2. **Audit token.** Otherwise (no token, or one that is malformed, unknown or expired), the kernel's audit token for
   the connection (`LOCAL_PEERTOKEN`): if the caller's process is the root of a registered envelope or descends from
   one, the connection is bound to that envelope's session; the nearest envelope wins. Processes are never matched by
   pid alone: the caller by pid and pid version (as its audit token names it), envelope roots and ancestors by pid and
   the kernel's unique id, which unlike the pid version survives `exec`. A process that reuses a dead envelope's pid
   is not inside it, and a root stays its envelope's root after it execs. A process
   whose parent chain cannot be read, or that was re-parented away from its envelope (its parent exited), is not
   inside it either.
3. Otherwise `-32009`, and the connection is closed.

A connection is bound once: a later `hello` must resolve to the same session, or it is `-32009` and the connection is
closed. When a session ends its token and envelopes are revoked; a connection bound to it gets `-32009` on its next
call and is closed. The session outlives its connections: closing one does not end it.

| Method | Purpose |
| --- | --- |
| `exec.run` | Run a line and wait; returns the record ID, `executed_command`, exit code, output in the requested mode, and the decision |
| `exec.start`, `exec.wait`, `exec.kill` | The same for long-running lines; output arrives as events |
| `policy.check` | Dry run: what policy would decide for a line, without running it ([below](#policycheck)) |
| `records.query`, `records.output` | The session's own records and output ranges ([parameters](user-socket.md#records)) |
| `events.subscribe`, `events.unsubscribe` | The session's own events, optionally from `since_seq` |
| `checkpoint.list`, `checkpoint.diff`, `checkpoint.undo`, `checkpoint.redo` | The session's own changes, without `force` |
| `session.info` | Actor, profile, state, recording settings of the connection's session ([result](user-socket.md#sessioninfo)) |

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
| `env` | object | The caller's whole environment, name to value (KNSH-049). Names are non-empty and hold no `=`; nothing holds NUL; at most 4096 entries. Absent is empty |
| `interpreter` | string | `knsh` (default), `bash`, `sh` or `zsh`: the shell the line runs with once allowed (FR-LC-14). It never affects the decision |
| `args` | array of strings | The operands after the line (`bash -c 'line' name arg…`): `$0`, then `$1`, …; at most 4096 |
| `stdio` | string | `passed`: the request carries the caller's stdin, stdout and stderr as three descriptors (`SCM_RIGHTS`, [wire format](wire-format.md#descriptors)). The line runs on them, and the result holds no output (FR-OUT-04). Absent: output is captured and returned in `output.mode` (KNSH-053) |

The line is at most 65536 bytes and holds no NUL; `cwd` is absolute and resolved; `timeout_s` is positive. Anything
else, or a descriptor count other than three with `stdio: "passed"` and zero without, is `-32602`, and the
descriptors are closed unused.

### What the supervisor receives (KNSH-049)

The line, `cwd`, `env`, `args` and `interpreter` arrive unchanged, with two exceptions applied before anything else
sees them: the shim directory is removed from `PATH` (FR-LC-16), and the session token variable is removed (a
supervised line runs outside the envelope and has no use for its credential). Names are resolved on that `PATH`, or
`/usr/bin:/bin:/usr/sbin:/sbin` without one. Policy decides on the line, `cwd` and `PATH` only: the interpreter is not
an input to the decision (FR-LC-14).

`exec.run` stays `planned` in the method catalogue until lines can be spawned (KNSH-051): until then `hello` does not
list it and a call is `-32601`. The supervisor that decides each line exists (KNSH-050) and is tested end to end
through `agent.sock` with a fake spawner.

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

With `stdio: "passed"` (from `knsh -c`), the result is the outcome only: `record_id` (or null), and exactly one of
`exit_code` (0–255) and `signal` (1–127, the signal that ended the line), the other null. The client exits with the
code, or with 128 plus the signal (NFR-COMPAT-09).

### Errors

`-32001` denied, `-32002` no decision before timeout, `-32007` session held, `-32008` killed at timeout, `-32010` checkpoint not ready, `-32011` cancelled. See [errors.md](errors.md).

`-32002` and `-32011` carry `request_id`, which is `null` when no request had been made yet (for example a line
cancelled while its hooks ran). `-32011` is only ever seen by a caller that is still reading: it is the answer to a
line whose caller disconnected (FR-LC-41).

## `policy.check`

A dry run (FR-POL-70, KNSH-043): the line is parsed, its command names are resolved, it is classified and decided
against a profile's rules exactly as `exec.run` would before running it, and nothing else happens. No record is
written, no event is published and no process is started. Hooks, the authority and grants are not consulted, so a line
the rules ask about is answered `ask` even if a grant or the authority would allow it.

On `agent.sock` the line is checked against the profile of the session the connection is bound to; `session_id` and
`profile` are refused with `-32003`. On `user.sock` exactly one of `session_id` and `profile` is required.

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
- Sessions cannot be created from this endpoint (FR-SES-02): `session.start_agent`, `session.start_human` and any
  other session-creating method are not part of its protocol, and calling one is "method not found" (`-32601`), not
  `-32003`. The method catalogue refuses to declare one on `agent.sock`.
- Records, events and checkpoints of other sessions are never visible (`-32003`). Without `session_id`,
  `records.query` and `events.subscribe` see only the connection's own session.
