# Control service

An XPC Mach service (`knsh.control`, final name tied to the signing identity) reachable only by the trusted, code-signed authority. Messages carry the same JSON-RPC payloads as the sockets; raw bytes are XPC data values. Trust and verification are specified in [../03-functional-requirements/authority.md](../03-functional-requirements/authority.md).

| Method | Purpose |
| --- | --- |
| `authority.register` | Become the authority (one at a time, [below](#authorityregister)) |
| `decision.respond` | Answer a `decision.requested` |
| `session.*` | Create, end, pause, resume, take and release control of any session |
| `policy.set`, `policy.get`, `policy.grant`, `policy.grants`, `policy.revoke` | Push and read policy, manage grants |
| `secrets.provide`, `secrets.revoke` | Time-limited secrets held in memory |
| `recording.set` | Turn command or output recording on or off for a session |
| Every `user.sock` read and checkpoint method | Across all sessions |

## Verification

Implemented in KNSH-067 (decision 13), FR-AUTH-12 – FR-AUTH-14:

- `knshd` serves the Mach name its launch agent declares, and sets the trusted authority's peer code-signing
  requirement on every connection before resuming it: Apple-anchored, the trusted team and identifier, a Developer ID
  or Mac App Store certificate, and no `get-task-allow` entitlement. XPC refuses a peer that does not meet it before
  any message is delivered.
- For **every message**, before it is read, `knshd` identifies the sender by the message's audit token (never by pid)
  and checks hardened runtime, a valid live signature, that it is neither debuggable nor being debugged, and that its
  `CFBundleVersion` is at least the trusted minimum. Any failure, or any doubt, closes the connection without an
  answer.
- Peers running as another user (or root) are refused.
- With no trusted authority, every connection is refused before it is resumed.
- An open, verified connection keeps `knshd` alive, like a socket connection.
- The trust record is the one `knsh authority trust` stored ([`authority.trust`](user-socket.md#authoritytrust),
  KNSH-068), read when `knshd` starts. A record that cannot be read means nothing is trusted. When the user trusts
  another authority, the running service switches to it at once and closes every connection verified under the old
  record.

## `authority.register`

Implemented in KNSH-068 (FR-AUTH-01, FR-AUTH-02). No params (`{}`). Result: `{"registered": true}`.

- The first verified connection to call it becomes the authority, and `authority.connected` is published. Calling it
  again on the same connection changes nothing and publishes nothing.
- While one is registered, any other connection's call is `-32003` (decided with KNSH-068; the spec named no code).
- When the authority's connection ends (it closed, failed a per-message check, or its trust was replaced),
  `authority.disconnected` is published and another connection may register.
- Both are engine events, with no session and no actor ([events](user-socket.md#events)), delivered to every
  subscription to all sessions.
- The authority sends `hello` and `authority.register` before it has checked `knshd`'s reply against its own peer
  requirement (FR-AUTH-15), so neither carries anything sensitive.

## Decision protocol

Implemented in KNSH-069 (FR-AUTH-20 – FR-AUTH-24, FR-EVT-06, FR-LC-41). While an authority is registered, every ask
(lifecycle step 6) is sent to it; with none registered, asks wait for local approval ([approvals](user-socket.md#approvals)).

```json
// engine → authority
{"method": "decision.requested", "params": {"request_id": "…", "session_id": "…",
  "actor": {"kind": "agent", "agent_id": "claude-code"}, "command": "git push origin main", "rewritten_from": null,
  "cwd": "/Users/me/code/app", "matched_rule": "exec.ask[0]", "hook": null,
  "irreversible": {"value": true, "reasons": ["network", "git push"]}, "timeout_at": "…"}}

// authority → engine
{"method": "decision.respond", "params": {"request_id": "…", "verdict": "allow",
  "grant": {"scope": "session", "duration_s": 3600}, "reason": "approved by user"}}
// → {"applied": true, "grant_id": "01J…"}

// engine → authority
{"method": "decision.cancelled", "params": {"request_id": "…", "reason": "caller_gone"}}
```

### `decision.requested` params

A JSON-RPC notification, sent only to the registered authority's connection (FR-EVT-06): it is never published as an
event. The same members as an entry of [`approval.list`](user-socket.md#approvallist).

| Field | Notes |
| --- | --- |
| `request_id` | Unique per request |
| `session_id`, `actor` | Who is asking |
| `command` | Redacted line |
| `rewritten_from` | The redacted line before a rewrite, when this line is one; otherwise `null` |
| `cwd` | Working directory |
| `matched_rule` | Rule that asked, e.g. `exec.ask[0]`; `null` when only a hook asked |
| `hook` | The hook that asked, when one did; otherwise `null` |
| `irreversible` | `value` and `reasons`; `null` until lines are classified for irreversibility (KNSH-093) |
| `timeout_at` | When the request will be denied |

### `decision.respond` params

| Field | Notes |
| --- | --- |
| `request_id` | The request answered |
| `verdict` | `allow`, `deny` or `rewrite` |
| `command` | Required for `rewrite`, refused otherwise: 1 to 65,536 bytes (the `exec.run` limit) |
| `grant` | Optional, with `allow` only: `scope` (`session` or `profile`) and `duration_s` (1 to 2,592,000, 30 days) |
| `reason` | Optional, at most 1024 bytes. Shown to the agent on deny |

Result: `{"applied", "grant_id"}`. `applied` is `true` when the answer was given to its pending request. `grant_id`
names the grant the answer created (for `policy.revoke`), or is `null`.

- Only the registered authority's connection may answer: from any other connection, or while none is registered,
  the call is `-32003`. Malformed params are `-32602`; nothing is applied and the request keeps waiting.
- An answer for a request that is unknown, already answered, timed out or cancelled is ignored: `applied: false`,
  logged with a fixed reason, never the command (FR-AUTH-22).
- A `grant` creates a grant (KNSH-042, FR-POL-62) for the asked line, scoped to the asking session or its profile,
  lasting `duration_s` from the answer. Its rule is the asked line ([grant](../05-models/grant.md)). When the line
  cannot be written as a rule, or the grant cannot be stored, no grant is created (`grant_id: null`) and the `allow`
  still applies.

### `decision.cancelled` params

`request_id` and `reason`: `caller_gone` (the caller disconnected, FR-AUTH-22) or `timed_out` (no answer before
`timeout_at`, FR-AUTH-23). Sent to the registered authority whenever a request ends without an answer, so it can
withdraw its prompt. The `decision.cancelled` [event](../05-models/event.md) is published for the line as well.

### Rules

- Default timeout 90 s; at the timeout the request is denied, and the caller gets `-32002` with `data.request_id`.
- If the caller disconnects, the engine sends `decision.cancelled` and ignores a late answer.
- If the authority disconnects, its requests keep waiting. When an authority registers, every request still pending
  and not timed out is sent to it again, unchanged (same `request_id` and `timeout_at`), after the answer to its
  `authority.register` (FR-AUTH-24).
- A second rewrite is refused and the line denied; a line containing a redaction marker cannot be rewritten.
- Notifications are sent in order. One that cannot be delivered is dropped; the request still ends by its answer, its
  timeout or its caller.

## `policy.set`

Pushes a policy snapshot. A snapshot must carry `expires_at`; on expiry, sessions using it are paused ([policy](../03-functional-requirements/policy.md#lifetime-of-pushed-policy)).

## `secrets.provide`

Supplies a named secret for a limited time, held only in memory and lost when `knshd` exits. `secrets.revoke` removes it at once.
