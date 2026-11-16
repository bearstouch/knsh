# Hook

Hooks are registered in the user's configuration file, `~/.config/knsh/config.toml` (the directory envelopes cannot
read or write, FR-HOOK-07). Behaviour is in [../03-functional-requirements/hooks.md](../03-functional-requirements/hooks.md).

```toml
[[hooks]]
event = "command.proposed"
match = { binary = ["rm", "git"] }
run = "~/.config/knsh/hooks/guard.sh"
timeout_ms = 2000
```

| Key | Type | Notes |
| --- | --- | --- |
| `event` | string | Required. Only `command.proposed` |
| `match` | table | Optional. Its only key is `binary`, a non-empty list of command names (no `/`). Without `match` the hook runs for every agent line |
| `run` | path | Required. An absolute path, or `~` / `~/…` expanded to the user's home. With symlinks followed, it must name an existing regular file inside `~/.config/knsh/`, owned by the user, not writable by group or others, with an execute bit set |
| `timeout_ms` | int | Required. 1 to 60000. A timeout is a deny |

Hooks are known by their place in the file: `hooks[0]`, `hooks[1]`, … This name is the record's `decision.decided_by`
when a hook decides. At most 32 hooks may be registered.

## Validation and failing closed (FR-HOOK-04)

The file is read for every agent line evaluated, so an edit applies to the next line. Validation never drops a hook:

| Problem | Effect |
| --- | --- |
| No `config.toml`, or no `hooks` key | No hooks |
| The file cannot be read, is larger than the TOML subset allows, or is not valid TOML of the [subset](policy-profile.md#toml-subset) | Every agent line is denied (source `hook`): whether hooks are registered cannot be known |
| `hooks` is not an array of tables, or holds more than 32 | Every agent line is denied (source `hook`) |
| One entry is invalid: an unknown key, a missing key, another `event`, a `run` that is relative, missing, not executable, outside `~/.config/knsh/`, not the user's or writable by others, a `timeout_ms` out of range | That hook denies every line it would match. A `match` that is itself invalid matches every line |

A hook runs with the user's privileges outside any sandbox, so its executable must be somewhere no envelope can
write: `~/.config/knsh/` is a fixed deny of every profile (FR-HOOK-07). A hook file an agent could rewrite, in a
project for instance, would let it plant code that runs unsandboxed
([security](../04-non-functional-requirements/security.md)); such a registration is invalid. What the hook itself
runs is the hook author's responsibility ([writing hooks](../08-integrations/hooks.md)).

## Match

`binary` matches a line when any command of the line (each entry of its [`argv`](execution-record.md#argv),
wrappers and the commands they run included) has that name: the basename of the binary it resolved to, or the
basename of the name as written. A line with any dynamic code (`eval`, `bash -c`, a line the parser could not read,
…) matches every `binary` list, since what it runs is not known from the line.

## Running

The executable is started directly (never through a shell), outside any sandbox (FR-HOOK-06), as the leader of a new
process group, with:

- stdin: the input below, then end of file;
- stdout: read by the supervisor, at most 256 KiB;
- stderr: `/dev/null` (hook output is never logged);
- working directory `/`; environment `PATH=/usr/bin:/bin:/usr/sbin:/sbin` and `HOME` only.

At `timeout_ms` the hook's process group is killed (`SIGKILL`). When the hook exits its process group is killed as
well, so nothing it started keeps running.

## Input

One JSON object on stdin: the `command.proposed` [event](event.md) as `event`, `session_id`, `actor` and `data`
(`command`, `cwd`, `rewritten_from`, all redacted). It has no `id`, `seq` or `ts`: the hook input is not a delivery
from the event bus.

```json
{"event": "command.proposed", "session_id": "01J…", "actor": {"kind": "agent", "agent_id": "claude-code"},
 "data": {"command": "rm -rf build", "cwd": "/Users/me/project", "rewritten_from": null}}
```

## Output

Either nothing, or one JSON object on stdout (whitespace around it allowed). Stdout that holds only whitespace is
nothing.

| Member | Type | Notes |
| --- | --- | --- |
| `verdict` | string | Required: `allow`, `deny`, `ask`, `rewrite` or `annotate` |
| `reason` | string | Optional, any verdict; at most 1024 bytes, no control characters. Shown to the agent on `deny` |
| `command` | string | Required for `rewrite`, refused otherwise: the new line |
| `labels` | array of strings | Required for `annotate` (1 to 16), refused otherwise; each 1 to 64 bytes of `A-Z a-z 0-9 . _ : -` |

No other member is accepted.

| Verdict | Effect |
| --- | --- |
| `allow` | No objection |
| `deny` | Refuse, with a reason shown to the agent |
| `ask` | Escalate to the authority |
| `rewrite` | Replace the line; later hooks see the new line |
| `annotate` | Add labels to the record; no decision |

| Hook ended with | Verdict |
| --- | --- |
| Nothing on stdout, exit 0 | `allow` |
| Nothing on stdout, exit 2 | `deny` |
| Nothing on stdout, any other exit code or a signal | Error: deny |
| A valid object, exit 0 | The object's verdict |
| A valid object, any other exit or a signal | Error: deny |
| Stdout that is not a valid object, or longer than 256 KiB | Error: deny |
| Still running at `timeout_ms` | Timeout: deny |
| Could not be started | Error: deny |

## Record

Each hook that ran, or that was invalid and denied, is listed in the record's
[`decision.hooks`](execution-record.md#decision) with its run time (FR-HOOK-05).
