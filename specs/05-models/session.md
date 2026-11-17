# Session

A session has exactly one actor, fixed at start. Behaviour is specified in [../03-functional-requirements/sessions.md](../03-functional-requirements/sessions.md).

| Field | Type | Notes |
| --- | --- | --- |
| `session_id` | ULID | Unique, sortable by start time |
| `actor.kind` | `human` \| `agent` | Fixed at start |
| `actor.agent_id` | string | Required for agents, absent for humans, e.g. `claude-code`. 1–64 characters from `[A-Za-z0-9._-]` |
| `profile` | string | Policy profile name. 1–64 characters from `[A-Za-z0-9._-]` |
| `envelope` | bool | True for agent sessions started with `knsh agent`; always false for humans |
| `recording` | bool | Off by default for humans, on by default for agents. The authority may change an agent session's with [`recording.set`](../06-api/control-service.md#recordingset) (KNSH-071), which may also set its output recording in place of the profile's; a human session's never changes |
| `parent_session_id` | ULID or null | Set for sessions started from inside another session |
| `state` | `active` \| `paused` \| `human_control` \| `ended` | |

## States

| State | Meaning | New agent commands |
| --- | --- | --- |
| `active` | Normal operation | Run after decision |
| `paused` | Envelope and running commands receive `SIGSTOP` | Held (`-32007`) |
| `human_control` | The human works in their own session | Held (`-32007`) until handed back |
| `ended` | Session exited | Refused (`-32006`) |

Only the edges in the [state diagram](../03-functional-requirements/sessions.md#states) are allowed; any other
request (pausing a paused session, leaving `ended`) is refused with `-32006` and the state is unchanged. Every allowed edge,
including the one into `ended`, emits `session.state_changed`. An ended session is dropped from the live registry,
so later lookups answer "not found or ended" (`-32006`), the same as an unknown ID.

A child agent session's profile must equal or be stricter than its parent's (FR-SES-03): without `--profile` it gets
the parent's, and a looser one is refused (`-32003`, [`session.start_agent`](../06-api/user-socket.md#sessionstart_agent)).
A human session cannot have an agent session as its parent: it would be unenforced, an escape from the agent's
profile (FR-SES-12).

### Profile strictness

A child profile is **equal or stricter** when everything it allows, the parent allows too, and everything the parent
denies, it still denies (KNSH-056). The resolved profiles (after `extends`, the preset and defaults) are compared key
by key. Where two values cannot be compared exactly, only the same value counts, so an unknown is never looser:

| Key | The child is no looser when |
| --- | --- |
| `fs.read` | the parent reads `all`, or every child read path is at or below a parent read path |
| `fs.write` | every child write root is at or below a parent write root |
| `fs.deny` | every parent deny is at or below a child deny |
| `exec.allow` | every child pattern is a parent `exec.allow` pattern (same text) |
| `exec.ask` | every child pattern is a parent `exec.allow` or `exec.ask` pattern, and every parent pattern is a child `exec.ask` or `exec.deny` pattern |
| `exec.deny` | every parent pattern is a child `exec.deny` pattern |
| `exec.default`, `exec.project_executables`, `approvals.irreversible` | the child's action is the parent's or stricter (`allow` < `ask` < `deny`) |
| `exec.trusted_folders`, `exec.trusted_tools` | a subset of the parent's |
| `exec.interpreters`, `exec.bash` | equal |
| `network.mode` | `none`, or both `allowlist` |
| `network.hosts`, `network.loopback`, `network.non_tls_hosts` | a subset of the parent's |
| `network.approval_hosts` | a subset of the parent's `hosts` and `approval_hosts` |
| `network.class_hosts` | per class, a subset of the parent's `hosts` and of the parent's `class_hosts` for that class |
| `approvals.irreversible_commands` | a superset of the parent's |
| `checkpoints` | `required` kept, every parent root kept, `exclude` a subset of the parent's |
| `recording` | `commands` and `output` on wherever the parent's are, `retention_days` at least the parent's |
| `secrets.env` | every child entry is the parent's, unchanged |

`name`, `extends`, `preset` and `output.mode` are not compared: the first three only say where values came from,
and the output mode shapes what the agent reads back, not what it may do.

## Session token

Agent sessions get a session token in the envelope's environment. Clients pass it in `hello`. A missing, invalid or expired token yields `-32009` unless the caller can be matched to its envelope by audit token.

A token is 256 bits from the platform random source, carried as 64 lowercase hex characters. It is compared in
constant time and never logged, stored in the record store, or recorded. It expires when its session ends: from then
on it yields `-32009`, and connections already bound to the session get `-32009` on their next call
([agent socket](../06-api/agent-socket.md#binding-a-connection-to-its-session), KNSH-048).
