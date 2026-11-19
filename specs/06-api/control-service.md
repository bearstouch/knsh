# Control service

An XPC Mach service (`knsh.control`, final name tied to the signing identity) reachable only by the trusted, code-signed authority. Messages carry the same JSON-RPC payloads as the sockets; raw bytes are XPC data values. Trust and verification are specified in [../03-functional-requirements/authority.md](../03-functional-requirements/authority.md).

| Method | Purpose |
| --- | --- |
| `authority.register` | Become the authority (one at a time, [below](#authorityregister)) |
| `decision.respond` | Answer a `decision.requested` |
| `session.create`, `session.end`, `session.pause`, `session.resume`, `session.take_control`, `session.release_control`, `session.list` | Create, end, pause, resume, take and release control of any agent session; list every session ([below](#sessions)) |
| `policy.set`, `policy.get`, `policy.grant`, `policy.grants`, `policy.revoke` | Push and read policy, manage grants ([below](#policy)) |
| `secrets.provide`, `secrets.revoke` | Time-limited secrets held in memory ([below](#secretsprovide)) |
| `recording.set` | Turn command or output recording on or off for a session ([below](#recordingset)) |
| `records.query`, `records.output`, `events.subscribe`, `events.unsubscribe`, `checkpoint.*` | Every `user.sock` read and checkpoint method, across all sessions |

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

## Sessions

Implemented in KNSH-071 (FR-SES-02, FR-SES-10, FR-SES-12, FR-SES-14). The authority supervises **agent** sessions:
every method that acts on one session refuses a human session with `-32003`, since nothing in a human session may be
blocked (FR-SES-22), a human session ends only with its own connection, and a human's recording is theirs to choose.
A session that is not live is `-32006` naming it, as is a move the [state diagram](../03-functional-requirements/sessions.md#states)
does not have (pausing a paused session); nothing changes then. Each move is the session registry's own (KNSH-054):
signals to the session's kept process groups, `-32007` for new lines while held, and `session.state_changed`.

| Method | Params | Result |
| --- | --- | --- |
| `session.create` | `agent` (an `agent_id`), `profile` | `{"session_id", "session_token"}` |
| `session.end` | `session_id` | `{"session_id", "state": "ended"}` |
| `session.pause` | `session_id` | `{"session_id", "state": "paused"}` |
| `session.resume` | `session_id` | `{"session_id", "state": "active"}` |
| `session.take_control` | `session_id` | `{"session_id", "state": "human_control"}` |
| `session.release_control` | `session_id` | `{"session_id", "state": "active"}` |
| `session.list` | none | `{"sessions": [...]}`: every live session (human ones too), each as [`session.info`](user-socket.md#sessioninfo) shows one, in start order |

- **`session.create`** makes an agent session with no envelope (`envelope: false`, recording on), for an agent the
  authority starts itself (FR-SES-02). The agent binds to it on `agent.sock` by passing `session_token` in `hello`
  (or as `KNSH_SESSION_TOKEN`), like a line inside an envelope; the token is sent only to the authority. The profile
  must load now: one that does not exist is `-32602`, one that does not load (invalid, a bad signature, an expired
  snapshot) is `-32603`, and nothing is created. `session.started` is published.
- **`session.end`** sends `SIGTERM` to the session's envelope process groups (through kept handles; the agent CLI of
  `knsh agent` exits and its call returns), revokes its token and envelopes, and ends it (`session.state_changed` to
  `ended`, then `session.ended`). A line already running is not stopped; nothing new can start.
- On `user.sock`, `session.list` and `session.end` (for `knsh agent`) are not implemented yet: not listed in `hello`
  and answered `-32601` there.

## Policy

Implemented in KNSH-071 (FR-POL-01, FR-POL-50 – FR-POL-53, FR-POL-60 – FR-POL-62).

### `policy.set`

Pushes a policy snapshot: `profile` (the name it defines), `policy` (its text, a profile in the
[policy profile](../05-models/policy-profile.md) format, at most 1 MiB) and `expires_at`. Result: `{"replaced": bool}`,
whether a snapshot of that profile was replaced.

- A snapshot without `expires_at`, or one already expired, is `-32602` (FR-POL-50). So is one naming the built-in
  `unattended` profile, which is never replaced.
- It is checked with the loader policy files go through (FR-POL-01), as it would load once stored: its `extends`
  chain is read from the other snapshots and the signed files. One that does not load is `-32602`; nothing changes.
- It is saved to `knshd`'s [state store](#state-store) first; one that cannot be saved is `-32603`. Up to 64
  profiles may have a snapshot; another profile's is then `-32602`.
- From then on it takes the place of the policy file of the same name for every load (a session's lines,
  `session.create`, `policy.check`, and profiles that `extends` it), and `policy.updated` is published (FR-POL-53), an
  engine event with `{profile, expires_at}`. An envelope already running keeps the sandbox profile it started with.
- From `expires_at` on (or while the clock cannot be read), the profile loads from nothing: not from the snapshot,
  and never from the file of its name (FR-POL-52), so lines of sessions using it are denied. A snapshot is replaced
  only by another `policy.set`.
- **Expiry pauses sessions** (KNSH-072, FR-POL-51, FR-SES-13). `knshd` checks every second; each active agent session
  whose profile is an expired snapshot, or `extends` one, is paused (`session.state_changed`). A session under human
  control is paused once handed back; a human session never is. Such a session resumes only when (a) a `policy.set`
  makes its profile load again (it resumes under its own profile, before the answer), or (b) the user runs
  [`knsh profile use`](user-socket.md#profileuse) with Touch ID or the password (it then runs under that signed local
  profile). `session.resume` on it is `-32006`, and nothing else changes its profile (FR-POL-52). A session the
  authority paused itself is not resumed by a snapshot.

### `policy.get`

`{"profile"}`. Where that name loads from now, and its text:
`{"profile", "source", "policy", "expires_at", "expired"}`. `source` is `pushed` (with the snapshot's text,
`expires_at`, and whether it has `expired`), `file` (the signed file's body; `expires_at` `null`) or `builtin`
(`unattended`; `policy` `null`). A name with neither a snapshot nor a file is `-32602`; a file that cannot be read or
whose signature does not verify is `-32603`.

### `policy.grant`

Makes a [grant](../05-models/grant.md) (FR-POL-62): `scope` `session` with `session_id` (a live agent session;
`-32006` if not live, `-32003` for a human one), or `scope` `profile` with `profile`; `rule`, a command pattern read
like an `exec.allow` entry (1 to 4096 bytes); `duration_s`, 1 to 2,592,000 (30 days). Result:
`{"grant_id", "expires_at"}`. A rule that is not a command pattern (blank, naming a path) or a full grant store
(1024 grants) is `-32602`. The grant is saved to the state store before it applies; one that cannot be saved is
`-32603` and no grant exists. The user makes the same grants on `user.sock` after Touch ID or the password
([KNSH-073](user-socket.md#grants)).

### `policy.grants`

No params. `{"grants": [...]}`: every live grant, the authority's and those its answers created, oldest first, each
`{"grant_id", "scope", "session_id", "profile", "rule", "exact", "expires_at"}` (`session_id` or `profile` is
`null` according to the scope; `exact` is true for a grant made from an answer, KNSH-069). The user's grants
(KNSH-073) are listed too, and `policy.grants` and `policy.revoke` are also on [`user.sock`](user-socket.md#grants).

### `policy.revoke`

`{"grant_id"}`. Removes the grant at once: the next line no longer sees it (FR-POL-61). Result: `{"revoked": bool}`;
`false` for an unknown, already revoked or expired grant. A revocation always takes effect in memory; if it cannot be
saved it is logged, and the grant would apply again only after a restart, until it expires.

### State store

Grants and pushed snapshots are kept in `state.json` in the engine data directory
([file locations](../09-reference/file-locations.md)): a versioned JSON file, rewritten whole on every change with an
atomic replace (temporary file, flush, rename), owner-only `0600`, written only by `knshd`. At start `knshd` restores
the snapshots and the grants still live. A file is never overwritten when it cannot be used
([KNSH-074](../00-stories/KNSH-074-fail-closed-operation-and-state-across-restarts.md)):

- **Recovery.** A file that is not a `0600` regular file of the user (a symlink, a directory, another owner or mode),
  is larger than any file `knshd` writes, does not parse, or has an older or newer version is renamed at start,
  without replacing anything, to `state.json.corrupt-<µs>` (`state.json.newer-<µs>` for a newer version, `<µs>` the
  start time in Unix microseconds, `.<n>` appended if the name is taken). The rename moves a symlink itself, never its
  target. `knshd` logs it and starts with no grants and no pushed policy, which fails closed: grants only add
  permissions, and a profile whose snapshot is lost falls back to its signed local file or is paused (KNSH-072). The
  set-aside file is never read or written again; a newer `knshd` or the user may inspect it.
- **Frozen.** A file that cannot be examined (an I/O or permission error, which may pass) or whose rename fails is
  left as it is, and every change that would save (`policy.set`, `policy.grant`, an answer's grant) is refused
  (`-32603`) until a later start can read or set it aside.

## `recording.set`

Implemented in KNSH-071 (FR-SES-25). `session_id` and at least one of `commands` and `output` (booleans). `commands`
sets the session's `recording`; `output` sets output recording for the session in place of its profile's
`recording.output`, for its next lines. Result: the session as [`session.info`](user-socket.md#sessioninfo) shows it,
which the session's own `session.info` then reports too, and its stored row follows. Turning `commands` off never
suppresses an agent's records: every line is still recorded (FR-REC-01, FR-REC-03); what the settings withhold is
output (FR-REC-06). A human session is `-32003`; neither params is `-32602`.

## `secrets.provide`

Implemented in KNSH-089 (FR-SEC-07). Supplies a named secret for a limited time, held only in `knshd`'s memory and
lost when it exits. Params: `name` (a [secret](../05-models/secret.md) name: 1 to 64 characters from
`[A-Za-z0-9._-]`), `value` (a string of 1 byte to 64 KiB) and `duration_s` (1 s to 24 hours). Result:
`{"name": …, "expires_at": …, "replaced": bool}`, never the value.

- A missing or invalid member is `-32602`, and nothing is stored. Providing a name again replaces its value and
  expiry (`replaced: true`).
- At most 256 names may be provided at once; another name is then `-32602`. A replacement is always accepted, and
  expired secrets free their place.
- The secret is unavailable from `expires_at` on, or once the same duration has passed on the monotonic clock,
  whichever comes first, so moving the system clock back never extends it. A wall clock that cannot be read makes
  every provided secret unavailable. Expired secrets are dropped from memory within about a second, and at every
  lookup.
- While it lives, a provided secret takes the place of a Keychain item of the same name.
- It is never written to the [state store](#state-store) or any other file, and never sent to any client: no method
  returns a secret value.
- Without a secret store (`secrets: "none"` in `hello`), both methods are `-32005` naming `secrets`.

## `secrets.revoke`

Implemented in KNSH-089 (FR-SEC-07). Params: `name`. Result: `{"revoked": bool}`, whether a live provided secret of
that name was removed. It is unavailable from that moment, and its memory is zeroed. Revoking a name that is not
provided (never, or already expired or revoked) is `{"revoked": false}`, not an error. Keychain items are never
touched. An invalid name is `-32602`.
