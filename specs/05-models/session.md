# Session

A session has exactly one actor, fixed at start. Behaviour is specified in [../03-functional-requirements/sessions.md](../03-functional-requirements/sessions.md).

| Field | Type | Notes |
| --- | --- | --- |
| `session_id` | ULID | Unique, sortable by start time |
| `actor.kind` | `human` \| `agent` | Fixed at start |
| `actor.agent_id` | string | Required for agents, absent for humans, e.g. `claude-code`. 1–64 characters from `[A-Za-z0-9._-]` |
| `profile` | string | Policy profile name. 1–64 characters from `[A-Za-z0-9._-]` |
| `envelope` | bool | True for agent sessions started with `knsh agent`; always false for humans |
| `recording` | bool | Off by default for humans, on by default for agents |
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

A child agent session's profile must equal or be stricter than its parent's (FR-SES-03). Until the policy model can
compare profiles (phase 2), only the parent's own profile is accepted. A human session cannot have an agent
session as its parent: it would be unenforced, an escape from the agent's profile (FR-SES-12).

## Session token

Agent sessions get a session token in the envelope's environment. Clients pass it in `hello`. A missing, invalid or expired token yields `-32009` unless the caller can be matched to its envelope by audit token.

A token is 256 bits from the platform random source, carried as 64 lowercase hex characters. It is compared in
constant time and never logged, stored in the record store, or recorded. It expires when its session ends: from then
on it yields `-32009`, and connections already bound to the session get `-32009` on their next call
([agent socket](../06-api/agent-socket.md#binding-a-connection-to-its-session), KNSH-048).
