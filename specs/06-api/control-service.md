# Control service

An XPC Mach service (`knsh.control`, final name tied to the signing identity) reachable only by the trusted, code-signed authority. Messages carry the same JSON-RPC payloads as the sockets; raw bytes are XPC data values. Trust and verification are specified in [../03-functional-requirements/authority.md](../03-functional-requirements/authority.md).

| Method | Purpose |
| --- | --- |
| `authority.register` | Become the authority (one at a time) |
| `decision.respond` | Answer a `decision.requested` |
| `session.*` | Create, end, pause, resume, take and release control of any session |
| `policy.set`, `policy.get`, `policy.grant`, `policy.grants`, `policy.revoke` | Push and read policy, manage grants |
| `secrets.provide`, `secrets.revoke` | Time-limited secrets held in memory |
| `recording.set` | Turn command or output recording on or off for a session |
| Every `user.sock` read and checkpoint method | Across all sessions |

## Decision protocol

```json
// engine → authority
{"method": "decision.requested", "params": {"request_id": "…", "session_id": "…",
  "actor": {"kind": "agent", "agent_id": "claude-code"}, "command": "git push origin main",
  "cwd": "/Users/me/code/app", "matched_rule": "exec.ask[0]",
  "irreversible": {"value": true, "reasons": ["network", "git push"]}, "timeout_at": "…"}}

// authority → engine
{"method": "decision.respond", "params": {"request_id": "…", "verdict": "allow",
  "grant": {"scope": "session", "duration_s": 3600}, "reason": "approved by user"}}
```

### `decision.requested` params

| Field | Notes |
| --- | --- |
| `request_id` | Unique per request |
| `session_id`, `actor` | Who is asking |
| `command` | Redacted line |
| `rewritten_from` | Present when the line was rewritten once already |
| `cwd` | Working directory |
| `matched_rule` | Rule that asked, e.g. `exec.ask[0]` |
| `irreversible` | `value` and `reasons` |
| `timeout_at` | When the request will be denied |

### `decision.respond` params

| Field | Notes |
| --- | --- |
| `request_id` | The request answered |
| `verdict` | `allow`, `deny` or `rewrite` |
| `command` | Required for `rewrite` |
| `grant` | Optional: `scope` (`session` or `profile`) and `duration_s` |
| `reason` | Shown to the agent on deny; kept in the record |

### Rules

- Default timeout 90 s; at the timeout the request is denied.
- If the caller disconnects, the engine sends `decision.cancelled` and ignores a late answer.
- If the authority disconnects, pending requests are re-sent on reconnect if not timed out.
- A second rewrite is refused and the line denied; a line containing a redaction marker cannot be rewritten.

## `policy.set`

Pushes a policy snapshot. A snapshot must carry `expires_at`; on expiry, sessions using it are paused ([policy](../03-functional-requirements/policy.md#lifetime-of-pushed-policy)).

## `secrets.provide`

Supplies a named secret for a limited time, held only in memory and lost when `knshd` exits. `secrets.revoke` removes it at once.
