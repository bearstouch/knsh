# Session

A session has exactly one actor, fixed at start. Behaviour is specified in [../functional-requirements/sessions.md](../functional-requirements/sessions.md).

| Field | Type | Notes |
| --- | --- | --- |
| `session_id` | ULID | Unique, sortable by start time |
| `actor.kind` | `human` \| `agent` | Fixed at start |
| `actor.agent_id` | string | Required for agents, e.g. `claude-code` |
| `profile` | string | Policy profile name |
| `envelope` | bool | True for agent sessions started with `knsh agent` |
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

## Session token

Agent sessions get a session token in the envelope's environment. Clients pass it in `hello`. A missing, invalid or expired token yields `-32009` unless the caller can be matched to its envelope by audit token.
