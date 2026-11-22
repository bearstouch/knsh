# Execution record

One record per agent command line that reaches lifecycle step 2. Stored in the record store (SQLite, internal format); exposed only through `records.query` and `records.output`. Behaviour is in [../03-functional-requirements/execution-records.md](../03-functional-requirements/execution-records.md).

| Field | Type | Notes |
| --- | --- | --- |
| `record_id` | ULID | Primary key |
| `session_id` | ULID | Owning session |
| `actor` | object | `kind` and `agent_id` |
| `attribution` | `command` \| `agent_edit` \| `external` \| `concurrent` \| null | How the record's file changes were attributed ([checkpoints](../03-functional-requirements/checkpoints.md#taking-checkpoints)). A line that ran is `command`, or `concurrent` when another line overlapped it in one of its roots; it always equals the attribution of the history-tree edge holding the line. `agent_edit` and `external` belong to edges without a line. Null for a denied line and for records written before KNSH-081 |
| `command` | string | The line actually executed, after any rewrite, with secrets redacted. For a denied line, the line the denial applies to: a rewritten line denied in its own pass is recorded as rewritten ([combining verdicts](../03-functional-requirements/hooks.md#combining-verdicts)) |
| `rewritten_from` | string or null | The original line when a rewrite was accepted, whether the rewritten line then ran (verdict `rewrite`) or was denied (verdict `deny`) |
| `argv` | array | Each simple command with resolved absolute path and class (`static`, `wrapper`, `dynamic`, `project_executable`). A wrapper and the command it runs are separate entries, the inner one linked to its wrapper; a dynamic entry carries its reason code |
| `cwd` | path | Working directory at start |
| `parent_record_id` | ULID or null | For one simple command of a native-mode line, the line's record (FR-LC-54, KNSH-108); null for every other record. Stored from record schema version 3 |
| `decision` | object | See below |
| `sandbox_profile` | string | Profile name and a hash of the compiled profile: `<profile name>@<first 16 lower-case hex digits of the SHA-256 of the compiled profile bytes>`, for example `web-app@ba7816bf8f01cfea`. The profile file `knsh-exec` applied is named by the full hash (FR-SBX-07, KNSH-045) |
| `secrets_injected` | array | Secret names only, never values |
| `started_at`, `ended_at` | timestamp | UTC, microseconds |
| `exit_code` | int or null | Exit code of the line; null when denied or still running |
| `pipestatus` | array | Exit code of each command in the last pipeline. Empty until the supervisor reads `PIPESTATUS` back from the line's bash (KNSH-100); `exit_code` is always filled for a line that exited |
| `signal` | string or null | e.g. `SIGKILL` |
| `stdout`, `stderr` | blob reference | Only when output recording is on; capped at 1 MB each by default, then head and tail kept |
| `children` | array | Processes seen in the command's process groups, best effort |
| `files_changed` | array or null | Paths created, modified or deleted under checkpoint roots, with post-image identity: `{path, change, post_image}`, `change` one of `created`, `modified`, `deleted`; `post_image` is `{inode, size, mtime_seconds, mtime_nanoseconds, sha256}` (`inode` and `size` decimal strings, `sha256` lower-case hex for regular files under 64 MiB, else null), or null for a deleted path or one whose identity could not be read (its checkpoint is then uncertain). Sorted, at most 256 (the checkpoint lists them all). For a `concurrent` line, the set's. Empty when the line changed nothing in a protected root; null when it touched none or never ran (KNSH-082) |
| `network` | array | Hosts contacted or refused, as reported by the proxy ([below](#network)) |
| `unprotected` | array | Checkpoint roots the line touched whose changes were not protected: `{root, reason}`, `reason` one of `shadow_building` (the root's shadow was not complete yet, with `checkpoints.required = false`), `shadow_failed`, `no_shadow`. Empty when every root it touched was protected (KNSH-079, FR-CKP-02). Stored from record schema version 2 |
| `checkpoint_id` | ID or null | Checkpoint holding the pre-images; null when the line changed nothing in a protected root and none of them was uncertain (KNSH-082) |
| `irreversible` | object or null | `{"value", "reasons"}`: from classification before the line runs, and for a line that ran also from what it was seen doing ([irreversible actions](../03-functional-requirements/irreversible-actions.md#reasons)). `value` is `true` exactly when there is a reason; at most 64 reasons. Null for a line refused before it was classified and for records written before KNSH-093 |
| `sandbox_violations` | array | Denials the system reported for this command, best effort |

## `decision`

| Field | Values |
| --- | --- |
| `verdict` | `allow`, `deny`, `rewrite` (final effective verdict) |
| `source` | `rule`, `hook`, `authority`, `user`, `standalone`, `rate_limit`, `grant` (a grant answered the rules' ask, KNSH-042), `endpoint_security` (an exec inside an envelope seen by the Endpoint Security descendant client, decided by the same pipeline; `rule_id` and `decided_by` still name the rule, hook, authority or user behind the verdict, KNSH-094), `native` (the line record of a native-mode line, which is admitted without a decision of its own: each of its commands has a record with its own decision, FR-LC-51, KNSH-108) |
| `rule_id` | e.g. `exec.allow[1]`, `exec.ask[0]` |
| `decided_by` | Who decided (hook, authority, user) |
| `latency_ms` | Time to decide: from receiving the line to its final decision, in milliseconds |
| `hooks` | The hooks that ran for the line, in order, across both evaluation passes of a rewritten line (FR-HOOK-05, KNSH-062). Each element: `hook` (`hooks[N]`, or `hooks` when the whole hook configuration was invalid), `result` (`allow`, `deny`, `ask`, `rewrite`, `annotate`, `error`, `timeout`, or `invalid` for a hook that was not run because its registration is invalid), `duration_ms` (its run time, at most its timeout) and `labels` (an `annotate`'s labels, otherwise empty). Empty when no hook matched; absent from records written before KNSH-062 and read back as empty |

The supervisor builds the record's `decision` from the pipeline's own decision, so the two always agree (KNSH-050).
A line cancelled because its caller disconnected (FR-LC-41) is recorded as `deny` with source `standalone`: nobody
decided it, and it never ran. An exec decided through Endpoint Security (KNSH-094) is recorded with source `endpoint_security`: its `command` is the exec as a line (the executable's canonical path and `argv[1..]`, each quoted as one word), `exit_code` is null (it runs in the agent's process, not under the supervisor) and `ended_at` is when it was decided. `records.query` returns the object as `decision`, or `null` for records written before
decisions were recorded.

## `sandbox_violations`

Denials the system reported for the line, attributed by the tag of the rule that matched (FR-SBX-06), best effort
(FR-SBX-08, KNSH-047). Each element:

| Field | Values |
| --- | --- |
| `session_id`, `record_id` | From the tag `knsh:<session>:<record>:<rule>`; `record_id` is `null` for an envelope's denial (`env`), which is published but attached to no record |
| `rule` | The deny rule that matched, e.g. `fixed.engine`, `fs.deny[0]`, `services.dns` |
| `operation` | The Seatbelt operation, e.g. `file-read-data`, `mach-lookup`, `network-outbound` |
| `argument` | What was denied as the system names it (a canonical path, a service name, `remote:*:53`), or `null` |
| `process`, `pid` | The denied process's name and id as logged; informational (the pid may since have been reused) |
| `count` | How many identical denials (same tag, process, operation and argument) this element stands for, at least 1 |
| `at` | When the first of them reached the engine |

Repeats arriving within 3 s of the first merge into one element, including the system's own "N duplicate reports"
summaries. Denials arriving after the record was written are appended to it, merging into an existing element when
they repeat one. A record keeps at most 256 distinct elements. A denial is never attached to a record its tag does
not name exactly (another session's record, an unknown record, a human record). Some denials are never reported by
the system (signals, `ENOENT` cases, dropped entries, built-in refusals: [verification claims](../07-testing/verification-claims.md#c2-denials-in-the-unified-log)).

## `network`

The hosts the line asked the proxy to reach, as the proxy reported them (FR-NET-09, KNSH-060), in order of first
appearance. The envelope's own connections belong to the session and are in no record. Each element:

| Field | Values |
| --- | --- |
| `host` | The host the line named: a normalised name (lower case, no trailing dot) or an IP literal |
| `port` | The port it named |
| `result` | `contacted` (every check passed and the tunnel opened) or `refused` |
| `reason` | For a refused connection, the proxy's reason: `host_not_allowed`, `network_off`, `approval_required`, `dynamic_code`, `secret_hosts`, `ip_literal`, `address_not_allowed`, `unresolved`, `unreachable`, `timeout`, `no_host_rules`, `not_tls`, `server_name_missing`, `server_name_mismatch`, …; `null` when contacted |
| `count` | How many connections this element stands for, at least 1 |

Repeats (same host, port, result and reason) merge into one element with their count. A record keeps at most 256
distinct elements. A refusal decided after the line ended (its connection was still being checked when its
credentials were revoked) is published as `proxy.denied` but not added to the record.

## `argv`

One element per entry of the line's classification (KNSH-036), in source order: each wrapper before the command it
runs, each command before those in its substitutions (KNSH-052). Arguments are not repeated here: they are in
`command`, which is redacted as a whole.

| Field | Values |
| --- | --- |
| `name` | The command name as written, after quote removal and redaction; `null` when it is built from an expansion |
| `path` | The canonical absolute path the name resolved to, for a binary; `null` for a builtin, a function defined in the line, a name not found, or a name not known from the line. A path that is not valid UTF-8 is shown with U+FFFD replacements |
| `class` | `static`, `wrapper`, `dynamic` or `project_executable` (below) |
| `reason` | The dynamic reason code for a `dynamic` entry, otherwise `null` |
| `wrapper` | Index of the wrapper entry that runs this one, or `null` |
| `arguments_complete` | `false` when the command receives arguments only known at run time (the command `xargs` runs) |

A line the parser could not read has no entries of its own; it is recorded as one `dynamic` entry with `name`,
`path` and `wrapper` `null` and the parser's whole-line reason (`syntax_error`, `input_too_large`, …). A line refused
before it was parsed (the supervisor could not load its profile), or denied because the supervisor itself failed
while deciding it (an internal error, NFR-REL-07), has an empty `argv`.
Denied lines carry `argv` like lines that ran.

## `argv[].class`

| Class | Meaning |
| --- | --- |
| `static` | A binary resolved from a trusted folder, matched by name rules; also builtins, calls of functions defined in the line, and names not found (which fail with 127) |
| `wrapper` | A known wrapper (`env`, `command`, `exec`, `nice`, `nohup`, `time`, `timeout`, `xargs`, and the `builtin` builtin) that was unwrapped. A wrapper binary outside the trusted folders is unwrapped too but keeps `project_executable` |
| `dynamic` | Dynamic code: never inherits classes, network limited to `hosts`, no secrets. The reason is one of a closed set (`eval`, `source`, `interpreter_code`, `interpreter_stdin`, `expanded_command_name`, `expanded_argument`, `unknown_wrapper_option`, `code_variable`, `interpreter_input`, and the parser's whole-line reasons) |
| `project_executable` | A binary from an agent-writable place, governed by `project_executables` |

The command `xargs` runs receives arguments only known at run time: its entry marks its arguments as incomplete, and
rules that depend on arguments treat them as unknown. `command -v` and `command -V` run nothing, so no inner entry is
made.

## Human telemetry records

When recording is on, human records hold only `command`, `cwd`, `started_at`, `ended_at` and `exit_code`.
