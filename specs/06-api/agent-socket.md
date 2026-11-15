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
| `exec.start`, `exec.wait`, `exec.kill` | The same for long-running lines ([below](#execstart-execwait-execkill)); output arrives as `command.output` events when the session records output, and in the `exec.wait` result |
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
| `output.mode` | string | `full`, `truncate`, `head_tail`, `errors_only` or `ref` ([output modes](../03-functional-requirements/output-modes.md)); default from the profile (`output.mode`, FR-OUT-02) |
| `output.max_bytes` | int | For `truncate`: 1 to 1048576; default 65536 |
| `output.lines` | int | For `head_tail`: 1 to 10000; default 20 |
| `env` | object | The caller's whole environment, name to value (KNSH-049). Names are non-empty and hold no `=`; nothing holds NUL; at most 4096 entries. Absent is empty |
| `interpreter` | string | `knsh` (default), `bash`, `sh` or `zsh`: the shell the line runs with once allowed (FR-LC-14). It never affects the decision |
| `args` | array of strings | The operands after the line (`bash -c 'line' name arg…`): `$0`, then `$1`, …; at most 4096 |
| `stdio` | string | `passed`: the request carries the caller's stdin, stdout and stderr as three descriptors (`SCM_RIGHTS`, [wire format](wire-format.md#descriptors)). The line runs on them, and the result holds no output (FR-OUT-04). Absent: output is captured and returned in `output.mode` (KNSH-053) |

The line is at most 65536 bytes and holds no NUL; `cwd` is absolute and resolved; `timeout_s` is positive. Anything
else, an unknown `output.mode`, a count out of range, `output` together with `stdio: "passed"` (FR-OUT-03), or a
descriptor count other than three with `stdio: "passed"` and zero without, is `-32602`, and the descriptors are
closed unused. `max_bytes` and `lines` are accepted whatever the mode, since the mode may come from the profile.

### What the supervisor receives (KNSH-049)

The line, `cwd`, `env`, `args` and `interpreter` arrive unchanged, with two exceptions applied before anything else
sees them: the shim directory is removed from `PATH` (FR-LC-16), and the session token variable is removed (a
supervised line runs outside the envelope and has no use for its credential). Names are resolved on that `PATH`, or
`/usr/bin:/bin:/usr/sbin:/sbin` without one. Policy decides on the line, `cwd` and `PATH` only: the interpreter is not
an input to the decision (FR-LC-14).

`exec.run` is served since lines can be spawned (KNSH-051), and listed only where the sandbox probe passed. If
`knshd` cannot find `knsh-exec` beside itself, every call (and every call of `exec.start`, `exec.wait` and
`exec.kill`) is `-32005` (`capability: "sandbox"`). How a line is spawned, watched and timed out is in
[command lifecycle](../03-functional-requirements/command-lifecycle.md#spawning-knsh-051).

Without `stdio: "passed"`, the line runs with stdin on `/dev/null` and its stdout and stderr captured by the
supervisor (KNSH-053, [capture](../03-functional-requirements/command-lifecycle.md#output-capture-knsh-053)), and the
result carries its output in the requested mode.

### Example

```json
{"jsonrpc": "2.0", "id": 7, "method": "exec.run",
 "params": {"command": "npm test", "cwd": "/Users/me/code/app", "timeout_s": 600,
   "output": {"mode": "errors_only"}}}

{"jsonrpc": "2.0", "id": 7, "result": {"record_id": "01J…", "executed_command": "/usr/local/bin/npm test",
   "exit_code": 1, "signal": null, "duration_ms": 18421,
   "decision": {"verdict": "allow", "source": "rule", "rule_id": "exec.allow[1]"},
   "files_changed": null, "checkpoint_id": null, "output_mode": "errors_only",
   "stdout_size": "183402", "stdout_lines": 2160, "stderr_size": "912", "stderr_lines": 14, "cut_to_fit": false,
   "stderr": "…", "stderr_skipped": "0", "stdout_tail": "…", "stdout_skipped_lines": 2140}}
```

### Result

| Field | Notes |
| --- | --- |
| `record_id` | The execution record, or null if it could not be written |
| `executed_command` | The line actually spawned, after any rewrite and with each command's canonical path (FR-AUTH-33, FR-LC-13), redacted |
| `exit_code`, `signal` | Exactly one is set: the exit code (0–255), or the signal (1–127) that ended the line, for example after `exec.kill` |
| `duration_ms` | From the spawn to the end |
| `decision` | `verdict`, `source`, `rule_id` |
| `files_changed` | Count of changed paths under checkpoint roots; null until checkpoints exist (phase 3) |
| `checkpoint_id` | Checkpoint holding the pre-images, or null |
| `output_mode` | The mode applied: the caller's, or the profile's default |
| `stdout_size`, `stderr_size` | Bytes the line wrote to each stream (decimal strings), in every mode |
| `stdout_lines`, `stderr_lines` | Lines it wrote to each stream, in every mode |
| `cut_to_fit` | Whether output text was shortened so the answer fits in one frame (below) |
| Mode fields | `full` and `truncate`: `stdout`, `stderr`, `stdout_skipped`, `stderr_skipped`. `head_tail`: `stdout_head`, `stdout_tail`, `stdout_skipped_lines` and the same for `stderr`. `errors_only`: `stderr`, `stderr_skipped`, `stdout_tail`, `stdout_skipped_lines`. `ref`: none. `*_skipped` counts bytes of the stream not returned (decimal strings) ([output modes](../03-functional-requirements/output-modes.md)) |

Output text is the captured bytes after redaction (FR-OUT-06) as a JSON string; bytes that are not valid UTF-8 show as
U+FFFD (the exact bytes stay readable with `records.output` when output is recorded). The whole answer must fit in one
frame (1 MB, [wire format](wire-format.md#frames-unix-sockets)): when it would not, the longest output text is
shortened (a whole stream from its middle, a head from its end, a tail from its start) until it fits, `cut_to_fit` is
`true`, and the bytes cut are added to the stream's `*_skipped`. Output is only ever selected and cut, never
summarised (FR-OUT-05).

With `stdio: "passed"` (from `knsh -c`), the result is the outcome only: `record_id` (or null), and exactly one of
`exit_code` (0–255) and `signal` (1–127, the signal that ended the line), the other null. The client exits with the
code, or with 128 plus the signal (NFR-COMPAT-09).

### Errors

`-32001` denied, `-32002` no decision before timeout, `-32007` session held, `-32008` killed at timeout, `-32010` checkpoint not ready, `-32011` cancelled. See [errors.md](errors.md).

`-32002` and `-32011` carry `request_id`, which is `null` when no request had been made yet (for example a line
cancelled while its hooks ran). `-32011` is only ever seen by a caller that is still reading: it is the answer to a
line whose caller disconnected (FR-LC-41).

## `exec.start`, `exec.wait`, `exec.kill`

For lines that run long (KNSH-053). The line is identified by the `record_id` `exec.start` returns.

| Method | Params | Result |
| --- | --- | --- |
| `exec.start` | Those of `exec.run`, without `stdio` (the line is always captured; `stdio: "passed"` or descriptors are `-32602`) | `{"record_id"}` as soon as the line is spawned |
| `exec.wait` | `{"record_id"}` | The same result as `exec.run`, once the line has ended, in the `output` asked for at `exec.start` |
| `exec.kill` | `{"record_id"}` | `{"killed": true}` if the line was still running and was stopped, `false` if it had already ended |

- `exec.start` is decided exactly as `exec.run` is: a refused, held or unstartable line is answered with the error
  `exec.run` would give (`-32001`, `-32002`, `-32007`, `-32011`, `-32603`) and nothing is kept. If the caller
  disconnects before the line is spawned, the line is cancelled and never runs (FR-LC-41). Once spawned, the line
  runs to its end whatever happens to the connection.
- `exec.wait` takes no timeout: it waits until the line ends (its `timeout_s` bounds it; `exec.kill` ends it sooner).
  The first `exec.wait` that answers collects the result; a later `exec.wait`, or `exec.kill`, for that `record_id` is
  `-32602`. A line killed at its `timeout_s` is answered `-32008` with `record_id`. If the caller disconnects while
  waiting, the wait ends (`-32011`) and the line can still be waited for.
- `exec.kill` stops the line's whole process group as a timeout does: `SIGTERM`, `SIGKILL` after 2 s, and a last
  `SIGKILL` to the group before the leader is reaped. The line is then answered with the `signal` that ended it,
  not `-32008`.
- A `record_id` the session did not start (another session's, or unknown) is `-32602`. A session holds at most 64
  started lines whose results were not collected; at that bound the oldest finished one is forgotten, and when all
  64 are still running `exec.start` is `-32602` before the line is decided, so nothing runs. The started lines of a
  session that has ended are forgotten (nobody can name them any more).
- While a call blocks (`exec.run`, `exec.wait`), the connection writes nothing else: events of its subscriptions
  follow the answer. A client that wants `command.output` while it waits subscribes on a second connection.

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
