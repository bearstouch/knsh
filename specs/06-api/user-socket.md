# `user.sock`

Reachable by the user's processes outside envelopes. Every envelope and command profile denies it.

| Method | Purpose |
| --- | --- |
| `session.start_agent`, `session.list`, `session.end` | Start and manage agent sessions (`knsh agent`) |
| `session.start_human`, `telemetry.command`, `telemetry.cwd`, `telemetry.idle` | A recorded human session and its telemetry, sent by `knsh` ([below](#human-sessions)) |
| `session.info` | The caller's own session: actor, profile, state, recording settings |
| `records.query`, `records.output`, `events.subscribe`, `events.unsubscribe` | Read-only access to all sessions, for observers and the CLI |
| `checkpoint.*` | All checkpoint operations, including `restore` and `force` |
| `approval.list`, `approval.approve`, `approval.deny` | Pending asks; approving needs Touch ID or password, checked by `knshd` ([below](#approvals)) |
| `policy.check` | Dry run of a line against a named session's or profile's policy ([parameters](agent-socket.md#policycheck)); no authentication |
| `policy.read`, `policy.edit` | Read a policy file for editing, and save it signed after Touch ID or password ([below](#policy-files)) |
| `profile.use` | Profile selection needs Touch ID or password ([below](#profile-selection)) |
| `policy.grant`, `policy.grants`, `policy.revoke` | Make a grant after Touch ID or password; list and revoke grants ([below](#grants)) |
| `records.forget` | Delete records, optionally with checkpoints (`knsh forget`) |
| `authority.trust` | Trust one authority app after Touch ID or password ([below](#authoritytrust)) |

## Authentication

- `approval.approve`, `policy.edit`, `profile.use` and `policy.grant` require Touch ID or the user's password. `knshd` shows the system authentication prompt itself, with the exact command or change in it.
- The caller cannot claim that the user is present; no parameter skips the prompt.
- `knsh authority trust` (`authority.trust`) also requires Touch ID or password inside `knshd`, for a first record and
  for replacing one alike ([below](#authoritytrust)).

## Human sessions

`knsh` hosting a recorded human shell ([terminals and shells](../08-integrations/terminals-and-shells.md#recording-a-human-session))
starts a session over its own `user.sock` connection and reports each command line on it (KNSH-021, FR-SES-21). The
session is **bound to the connection**: no call names a session, so one connection can never write into another's,
and the session ends when the connection closes, however `knsh` went away (`session.state_changed` to `ended`, then
`session.ended`). These methods exist on `user.sock` only: nothing inside an envelope may create a session (FR-SES-02)
or write records as a human.

### `session.start_human`

No params. Creates a session with `actor.kind` `human`, `recording` true, `envelope` false, no parent, and the profile
`default` (nothing in a human session is enforced; profiles are loaded in phase 2), writes its row, publishes
`session.started`, and binds it to the connection. Result: `{"session_id": "01J…", "recording": true}`.

A second call on the same connection is `-32602`. Without a record store (it could not be opened) the call is
`-32603` and no session exists.

### `telemetry.command`

| Param | Type | Meaning |
| --- | --- | --- |
| `command` | string | The line as typed, at most 65536 bytes |
| `cwd` | path | The working directory it started in: absolute, without `.`, `..` or `//`, at most 16384 bytes |
| `started_at` | timestamp | When it started |
| `ended_at` | timestamp | When the prompt came back; not before `started_at` |
| `exit_code` | int | 0 to 255 |

Writes one record with exactly these fields (FR-REC-09; no output, no agent fields), commits it, then publishes
`command.finished`. Result: `{"record_id": "01J…"}`. The record ID is made when the record is written, so records
keep creation order.

### `telemetry.cwd`

`{"cwd": path}`, with the same rules as above. Publishes `cwd.changed`. Result: `{}`.

### `telemetry.idle`

No params. Publishes `session.idle` unless it was already published since the session's last `telemetry.command`
(FR-SES-24): `knsh` sends it once per idle prompt, and `knshd` checks again. Result: `{"emitted": bool}`.

### `session.info`

No params. The caller's own session (FR-SES-25, NFR-PRIV-05):

```json
{"session_id": "01J…", "actor": {"kind": "human"}, "profile": "default", "state": "active", "envelope": false,
 "recording": true, "output_recording": false, "parent_session_id": null}
```

`recording` says whether command lines are recorded, `output_recording` whether their output is (never for a human
session). On `user.sock` the caller's session is the one bound to the connection. On `agent.sock` it is the session
the connection was bound to at `hello` ([binding](agent-socket.md#binding-a-connection-to-its-session)); once that
session has ended it is `-32009`.

### Errors

A telemetry call or `session.info` on a connection without a session is `-32003`. Malformed params are `-32602`. A
store that fails is `-32603`. Events are best effort: a record that was written is answered even if its event could
not be published.

## Agent sessions

`knsh agent` ([CLI](cli.md#agent)) starts an agent CLI in a new agent session over its own `user.sock` connection
(KNSH-056, FR-AGT-01). The method exists on `user.sock` only: on `agent.sock` it is unknown (`-32601`) and not listed
in `hello` (FR-SES-02).

### `session.start_agent`

The request carries the caller's stdin, stdout and stderr as three descriptors (`SCM_RIGHTS`), announced by
`"stdio": "passed"`, as [`exec.run`](agent-socket.md#execrun) does; any other count is `-32602`. The call is answered
when the CLI exits, so the client's read has no deadline.

| Param | Type | Meaning |
| --- | --- | --- |
| `command` | array of strings | The CLI's argv after `--`, `argv[0]` first: 1 to 4096 entries, no NUL, `argv[0]` not empty |
| `cwd` | path | The working directory: absolute and resolved |
| `env` | object | The caller's whole environment (names non-empty, without `=`; no NUL). Absent is empty |
| `profile` | string | `--profile`. Absent: the parent session's profile when nested, `default` otherwise |
| `agent` | string | `--agent`: the actor's `agent_id`. Absent: derived from `argv[0]` (FR-AGT-02, below) |
| `stdio` | string | Required: `"passed"` |

`knshd` then:

1. **Actor (FR-AGT-02).** `agent`, or the last path component of `argv[0]` mapped through the derivation table
   (`claude` → `claude-code`; any other name is its own `agent_id`). A name outside `[A-Za-z0-9._-]{1,64}` is `-32602`.
2. **Parent (FR-SES-03).** The live agent session the caller runs inside: the one whose token is
   `KNSH_SESSION_TOKEN` in `env`, else the one whose registered envelope the caller's process descends from (its
   audit token, as on [`agent.sock`](agent-socket.md#binding-a-connection-to-its-session)). Inside an envelope the
   sandbox denies `user.sock`, so this is a second line of defence: a nested session can only be as strict.
3. **Profile.** `profile`, else the parent's, else `default`. A named profile that does not exist is `-32602`; one
   that cannot be loaded is `-32603`. With a parent, the profile must be equal to or stricter than the parent's
   as it runs, resolved when the parent started (its `${PROJECT}`, not one found from this `cwd`)
   ([strictness](../05-models/session.md#profile-strictness)); a looser one is `-32003` and nothing starts. Without
   `profile`, the child runs the parent's resolved profile unchanged.
4. **Program.** `argv[0]` with a `/` is taken relative to `cwd`; a name is looked up on the absolute entries of
   `env`'s `PATH`, skipping the shim directory. It must be an executable file, or the call is `-32602`.
5. **Start.** The session is created (`actor.kind` `agent`, `envelope` true, recording on by default,
   `parent_session_id`), its row written and `session.started` published. The CLI is started through `knsh-exec` in a
   new process group on the passed descriptors, with the session's profile compiled for an envelope and the
   environment of [agent CLIs](../08-integrations/agent-clis.md#starting): `env` without `KNSH_SESSION_TOKEN` and the
   dynamic linker's `DYLD_*` variables, with `SHELL` set to `knsh`, the shim directory first on `PATH` and the new
   session's token. The group's leader is registered as the session's envelope and kept for pause and resume.
6. **Wait.** When the CLI exits, what is left of its group gets `SIGTERM`. If the caller disconnects first, the
   group gets `SIGTERM`, then `SIGKILL` after 2 s.
7. **End.** The session ends (`session.state_changed` to `ended`, then `session.ended`) and its token and envelope
   are revoked, whatever happened after step 5.

Result, once the session has ended:

```json
{"session_id": "01J…", "agent_id": "claude-code", "profile": "web-app", "parent_session_id": null,
 "exit_code": 0, "signal": null}
```

Exactly one of `exit_code` and `signal` is set. A CLI that could not be started (the trampoline failed, the profile
file could not be written), or whose caller left, is `-32603` with no reason; its session has still ended.

When the [capability probe](../05-models/capabilities.md) reports `sandbox: none` the method is not listed in `hello`
and every call is `-32005` with `data.capability` `sandbox` (FR-AGT-06): no session is created.

## Records

`records.query` and `records.output` are the only way to read execution records (FR-REC-08). On `user.sock` they see every session. On `agent.sock` the same methods see only the session the connection is bound to; naming another session, or another session's record, is `-32003`. Byte counts and offsets are decimal strings (±2^53 rule, [wire-format.md](wire-format.md#strict-json-profile)).

### `records.query`

| Param | Type | Meaning |
| --- | --- | --- |
| `session_id` | ULID, optional | Only this session's records. Another session than the caller's own on `agent.sock` is `-32003` |
| `since` | timestamp, optional | Only records started at or after this instant |
| `until` | timestamp, optional | Only records started before this instant |
| `text` | string, optional | Only records whose `command` contains this text (case-sensitive substring, no wildcards), at most 4096 bytes |
| `limit` | int, optional | Records per page, 1 to 1000; default 100 |
| `cursor` | ULID, optional | The previous page's `next_cursor` |

Timestamps use the engine's form, `YYYY-MM-DDTHH:MM:SS[.ffffff]Z` (one to six fractional digits, UTC only). Malformed or out-of-range params are `-32602`.

Result: `{"records": [...], "next_cursor": "01J…" | null}`. Records are ordered by `record_id` (creation order); `next_cursor` is `null` on the last page. A page may hold fewer than `limit` records with a non-null `next_cursor` when more would not fit in one frame (1 MB); a single record too large for a frame is `-32603`. Paging by cursor is stable: records added between calls sort after every earlier page. Each record has `record_id`, `session_id`, `actor`, `command`, `cwd`, `started_at`, `ended_at`, `exit_code`, `stdout` and `stderr`; agent records also have `rewritten_from`, `pipestatus`, `signal`, `sandbox_profile`, `secrets_injected`, `checkpoint_id`, `sandbox_violations`, `decision` and `argv` ([execution record](../05-models/execution-record.md)), human records never do (FR-REC-09). `stdout` and `stderr` are `null` when output was not recorded, otherwise `{"size", "original_size", "skipped", "skipped_at"}`: `size` bytes are stored, the command wrote `original_size`, and `skipped` bytes were dropped at offset `skipped_at` of the stored bytes (head and tail kept, FR-REC-06). A `cwd` that is not valid UTF-8 is shown with U+FFFD replacements.

### `records.output`

| Param | Type | Meaning |
| --- | --- | --- |
| `record_id` | ULID | The record |
| `stream` | `stdout` \| `stderr` | The stream |
| `offset` | string, optional | First byte, in the stored bytes; default `"0"` |
| `length` | string, optional | At most this many bytes; default to the end |

Ranges beyond the end are clamped, never refused. Result: `record_id`, `stream`, `recorded` (false when no output was recorded for the stream; all sizes are then `"0"`), `size` (total stored size), `original_size`, `skipped`, `skipped_at`, and the range returned as `offset` and `length`. The bytes follow as a binary stream named in `data`: `{"stream_id": n, "size": "<length>", "content_type": "application/octet-stream"}`. A client that opted out of binary frames in `hello` receives `data_base64` instead, and at most 524288 bytes per call (so the answer fits in one frame); it reads longer ranges in several calls.

A `record_id` that does not exist is `-32602` on `user.sock`; on `agent.sock` a record of another session is indistinguishable from a missing one and is `-32003`.

### `records.forget`

`user.sock` only: on `agent.sock` it is `-32003`, so an agent can never erase records (FR-REC-10, NFR-PRIV-03).

| Param | Type | Meaning |
| --- | --- | --- |
| `session_id` | ULID, optional | Delete this session's records |
| `since` | timestamp, optional | Delete records started at or after this instant |
| `with_checkpoints` | bool, optional | Delete the matching records' checkpoints too; default `false` |

At least one of `session_id` and `since` is required (`-32602` otherwise); with both, a record must match both. The matching records and their stored output are deleted in one transaction: on error nothing is deleted. Deleted content is overwritten in the database file and the write-ahead log is truncated, so forgotten text does not stay on disk. The session itself (its row: actor, profile, state) is kept.

Result: `{"deleted": n}`, the number of records deleted.

Until checkpoints exist (phase 3), `with_checkpoints: true` is refused with `-32005` and `data.capability` `"checkpoints"`, before anything is deleted: the flag is never silently ignored.

## Events

`events.subscribe` and `events.unsubscribe` deliver the events of [../05-models/event.md](../05-models/event.md) live, with the delivery rules of [events](../03-functional-requirements/events.md) (KNSH-018). On `user.sock` a subscription sees every session, or one session with `session_id`. On `agent.sock` it sees only the session the connection is bound to: without `session_id` that session, and naming another is `-32003`.

### `events.subscribe`

| Param | Type | Meaning |
| --- | --- | --- |
| `session_id` | ULID, optional | Only this session's events; every session when absent |
| `since_seq` | int, optional | Resume after this `seq`: the buffered events after it are sent first. Requires `session_id`. Absent: only events published from now on |

Result: `{"subscription_id": n, "oldest_seq": n | null, "latest_seq": n | null, "gap": bool}`. `subscription_id` is a positive integer, unique in the engine. With `session_id`, `oldest_seq` is the oldest `seq` still buffered (how far back a resume can reach) and `latest_seq` the newest published; without it both are `null`. `gap` is `true` when `since_seq` is older than the buffer: delivery then starts at `oldest_seq`, and the events in between are read from the record store (at most once beyond the buffer, FR-EVT-04). With `since_seq` inside the buffer, delivery resumes exactly after it, with no duplicate and no gap between the replayed and the live events. `since_seq: 0` replays the whole buffer.

After the answer, each event arrives as a notification whose `method` is the event name and whose `params` are the event envelope plus `subscription_id`:

```json
{"jsonrpc": "2.0", "method": "session.state_changed", "params": {"event": "session.state_changed", "id": "01J…",
  "seq": 3, "ts": "2026-11-12T18:02:11.204913Z", "session_id": "01J…", "actor": {"kind": "agent",
  "agent_id": "claude-code"}, "data": {"from": "active", "to": "paused"}, "subscription_id": 1}}
```

Events of one session arrive in `seq` order; events of different sessions are not ordered relative to each other. The answer to `events.subscribe` always precedes its first event. Publishing never waits for a subscriber: each subscription queues at most 10,000 events, and a subscriber that falls further behind loses its oldest queued events. It is told with an `events.lost` notification, sent before any later event of that session:

```json
{"jsonrpc": "2.0", "method": "events.lost", "params": {"subscription_id": 1, "session_id": "01J…", "from_seq": 2,
  "to_seq": 16}}
```

Every `seq` from `from_seq` to `to_seq` inclusive will never be delivered on this subscription. An event too large for one frame is announced the same way, as a range of one.

**Engine events** (`authority.connected`, `authority.disconnected`; KNSH-068) belong to no session. They use the same
envelope with `"session_id": null` and `"actor": null`, and their `seq` counts the engine's own events (from 1 per
`knshd` run, gapless). They reach only subscriptions to every session (no `session_id`), in publication order with
the session events, and are not buffered, so they cannot be resumed. Lost engine events are announced with
`"session_id": null` in `events.lost`.

Errors: malformed params, `since_seq` without `session_id`, `since_seq` newer than the session's latest event, and a connection that already holds 16 subscriptions are `-32602`. A session with no buffered events (never started, or ended and its buffer dropped) is `-32006` with `data.session_id`. The buffers of the 64 most recently ended sessions are kept, so a subscriber can still catch up on a session that just ended.

### `events.unsubscribe`

| Param | Type | Meaning |
| --- | --- | --- |
| `subscription_id` | int | A subscription made on the same connection |

Result: `{}`. Nothing more is sent for the subscription after the answer. Another connection's subscription, or one already ended, is `-32602`. Closing the connection ends all its subscriptions.

## Policy files

`knsh policy edit` ([CLI](cli.md#policy-edit)) reads a profile's file and saves it signed (KNSH-065, FR-POL-40 to
FR-POL-42). Both methods are on `user.sock` only; `agent.sock` never lists them. The format and the key are in
[policy integrity](../03-functional-requirements/policy.md#integrity).

### `policy.read`

`{"profile": "<name>"}` → `{"profile", "text", "state", "reason"}`. `text` is the file without its signature line
(empty for a new profile). `state` is `new` (no file), `valid`, or `invalid`, with `reason` `signature_missing`,
`signature_bad` or `key_unavailable` (otherwise `null`). No authentication: the file is the user's own. A profile
name outside `[A-Za-z0-9._-]{1,64}` or `unattended` (built in, no file) is `-32602`; a file that cannot be read or is
not UTF-8 is `-32603`.

### `policy.edit`

`{"profile": "<name>", "text": "<toml>"}` → `{"profile", "changed"}`. `text` is at most 1 MiB (the profile limit)
and gets a final newline if it lacks one. In order:

1. Text equal to the file's and a `valid` file: `changed: false`; no prompt, no write.
2. The text must load as profile `<name>` with its `extends` chain (parents must be signed) from `knshd`'s `HOME`;
   otherwise `-32602` with the loader's reason in `data.reason`. Nothing broken is signed.
3. `knshd` shows the Touch ID or password prompt itself: `change the policy profile: <name> (<n> bytes, sha256
   <first 16 hex digits>)`, waiting at most 120 s. Any outcome but success is `-32001` with `source: "user"`,
   `rule_id: null` and `reason: "not authenticated: …"`; nothing is written. No parameter skips the prompt.
4. The signed file replaces the old one atomically (`0600`). The Keychain key is created on the first signature. A key
   that cannot be read or created, or a failed write, is `-32603` and the old file is kept.

Saves are serialised in `knshd`. `unattended` is `-32602`.

## Profile selection

### `profile.use`

`knsh profile use` ([CLI](cli.md#profile-use)) runs the agent sessions paused by expired pushed policy under a signed
local profile (KNSH-072, FR-POL-51, FR-POL-52). On `user.sock` only; `agent.sock` and the control service never list
it (`-32003` there).

`{"profile": "<name>"}` → `{"profile", "sessions"}`: `sessions` lists the IDs of the sessions now running under
`<name>`, resumed, in ID order. In order:

1. `<name>` must be a **signed local profile**: `<name>.toml` in the policies directory, loading with its `extends`
   chain read from files only, every file's signature verifying (FR-POL-42). Otherwise `-32602` with the reason in
   `data.reason`: the built-in `unattended` (no file), a name the authority pushed a snapshot for, a profile that
   `extends` one (the loader reads a snapshot in place of a file of its name, so it would not run as the file says),
   a missing, unsigned or invalid file. Nothing is asked.
2. With no session paused by expired pushed policy: `sessions: []`; no prompt, nothing changes.
3. `knshd` shows the Touch ID or password prompt itself: `use the local policy profile: <name> for <n> agent
   session(s) paused by expired pushed policy`, waiting at most 120 s. Any outcome but success is `-32001` with
   `source: "user"` and `reason: "not authenticated: …"`; nothing changes. No parameter skips the prompt.
4. Step 1 is checked again (the authority may have pushed meanwhile). Each session the prompt counted that is still
   paused by expiry then runs under `<name>` and resumes (`session.state_changed` to `active`), in one step: no line
   runs between the two. A session resumed by a new snapshot meanwhile keeps its own profile. An envelope already
   running keeps the sandbox profile it started with; its next lines are decided with `<name>`.

Selections are serialised in `knshd`. A session's profile changes in no other way (FR-POL-52).

## Grants

`knsh policy grant`, `knsh policy grants` and `knsh policy revoke` ([CLI](cli.md#grants)) let a user without an
authority app allow a repeated action for a limited time (KNSH-073, FR-POL-60 to FR-POL-62). The methods take and
answer exactly what the [control service's](control-service.md#policygrant) do, and work on the same grants: a grant
the user makes is listed and revoked like the authority's, on either endpoint. None of the three is on `agent.sock`
(`-32003`, never listed): an agent can never widen its own policy.

### `policy.grant`

Params, result and errors as on the [control service](control-service.md#policygrant). In order:

1. The params, the scope (`session`: a live agent session, `-32006` if not live, `-32003` for a human one) and the
   rule (a command pattern) are checked; any refusal comes before a prompt.
2. `knshd` shows the Touch ID or password prompt itself: `grant the agent command rule: <rule> (session <id>, for
   <duration>)` or `(profile <name>, for <duration>)`, the rule escaped as in every prompt
   ([decision 12](../09-reference/decisions.md)) and the duration exact (`1h 30m`, `1d 1m 1s`). It waits at most
   120 s. Any outcome but success is `-32001` with `source: "user"`, `rule_id: null` and `reason: "not
   authenticated: …"`; no grant exists. No parameter skips the prompt (NFR-SEC-04).
3. A session scope is checked again (the session may have ended while the prompt was up). The grant then lasts
   `duration_s` from that moment and is saved before it applies, as the authority's.

### `policy.grants` and `policy.revoke`

As on the [control service](control-service.md#policygrants): every live grant, the authority's, its answers' and the
user's; and removal at once. No authentication: listing changes nothing, and a revocation only removes a permission.

## Authority trust

`knsh authority trust` ([CLI](cli.md#authority-trust)) trusts one authority app (KNSH-068, FR-AUTH-10, FR-AUTH-11).
The control service then accepts only that app ([control service](control-service.md#verification)).

### `authority.trust`

| Param | Type | Meaning |
| --- | --- | --- |
| `team_id` | string | The Apple developer team ID: exactly ten characters from `A-Z` and `0-9` |
| `identifier` | string | The app's signing identifier: 1 to 255 characters from `A-Z`, `a-z`, `0-9`, `.` and `-`, not starting or ending with `.` |
| `min_version` | string | The oldest accepted `CFBundleVersion`: one to three dot-separated numbers of at most 9 digits (`2`, `1.4`, `10.0.3`) |

1. Params that do not match are `-32602`, before anything else: no prompt is shown.
2. `knshd` reads the current record. One that exists but cannot be read or is not in the engine's format (tampering,
   or a locked keychain; decision 11) is `-32603`: no prompt, nothing written.
3. Exactly the record already trusted: nothing is asked or written (`changed: false`).
4. `knshd` shows the Touch ID or password prompt itself: `trust the authority app: <identifier> (team <team>, version
   <v> or later)`, or `replace the trusted authority app: <old> with <new>` when one is trusted. Any outcome but
   success is `-32001` with `source: "user"`; nothing is written.
5. The record is stored as a generic-password item (service `knsh.authority-trust`, account `v1`) in the file-based
   login keychain, created by `knshd` so only `knshd`'s designated requirement can read it (FR-AUTH-11). A
   replacement updates the item's value in place. A failed write is `-32603`; the previous record stays in force.
6. The running control service switches to the new record at once: every connection verified under the old one is
   closed, so a registered authority disconnects (`authority.disconnected`).

Result: `{"team_id", "identifier", "min_version", "changed", "replaced"}`, the record as stored (the version in its
three-part form, `1.4.0`), whether anything was written, and whether a different record was replaced. Only on
`user.sock`: `-32003` elsewhere.

Removing trust is not specified yet (proposed: `knsh authority untrust`, with Touch ID). Until then an item that
cannot be read is removed by hand with `security delete-generic-password -s knsh.authority-trust`.

## Approvals

With no authority connected, an ask (lifecycle step 6) becomes a pending request that the user answers from another
terminal with `knsh approvals`, `knsh approve` and `knsh deny` (KNSH-066, FR-AUTH-40 to FR-AUTH-43,
[standalone mode](../04-non-functional-requirements/reliability.md#standalone-mode)). The agent's call waits on it.
All three methods are on `user.sock` only: `agent.sock` never lists them, and a call dispatched there is `-32003`.
Nothing in an agent session's terminal asks anything (FR-AUTH-43).

A request ends exactly once: answered, timed out after 90 s (FR-AUTH-23, denied with source `standalone`), or
cancelled because its caller left (FR-AUTH-22). Its `request_id` is then the one in `-32002`, `-32011` and
`decision.cancelled`. Answers recorded through these methods have `decision.source` `user` (FR-REC-03); a denial
gives the agent the reason `denied by the user (knsh deny)`.

### `approval.list`

No params. Result: `{"requests": [...]}`, pending requests in `request_id` (creation) order, each as the authority
would see it in `decision.requested`:

```json
{"request_id": "01J…", "session_id": "01J…", "actor": {"kind": "agent", "agent_id": "claude-code"},
 "command": "git push origin main", "rewritten_from": null, "cwd": "/Users/me/code/app",
 "matched_rule": "exec.ask[0]", "hook": null, "irreversible": null, "timeout_at": "2026-11-16T10:01:30.000000Z"}
```

`command` and `rewritten_from` are redacted. `matched_rule` is `null` when only a hook asked; `hook` names it.
`irreversible` is `{"value", "reasons"}`, or `null` until lines are classified for irreversibility (KNSH-093). A
request past its `timeout_at` is not listed. No authentication: listing changes nothing.

### `approval.approve`

`{"request_id": "01J…"}` → `{"request_id", "verdict": "allow"}`. In order:

1. The request must be pending, or the call is refused without a prompt (below).
2. `knshd` shows the Touch ID or password prompt itself: `approve the agent command: <command> (cwd <dir>, session
   <id>)`, with control and invisible characters escaped ([decision 12](../09-reference/decisions.md)). It waits at
   most until the request's `timeout_at`. Any outcome but success is `-32001` with `source: "user"`, `rule_id: null`
   and `reason: "not authenticated: …"`; the request stays pending. No parameter skips the prompt (FR-AUTH-42).
3. The request must still be pending after the prompt; the line then runs as approved.

### `approval.deny`

`{"request_id": "01J…"}` → `{"request_id", "verdict": "deny"}`. No authentication: a denial is never less safe than
waiting (decided with KNSH-066).

### Errors

An answer to a request that is not pending is refused: `-32002` with `data.request_id` when it timed out (even if
its waiting call has not noticed yet), `-32011` with `data.request_id` when it was cancelled, and `-32602` with
`data.reason` when it was already answered or no such request exists. The last 256 ended requests are remembered to
tell these apart; older ones are reported as unknown. A malformed `request_id` is `-32602`.
