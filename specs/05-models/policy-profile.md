# Policy profile

Profiles are TOML files in `~/.config/knsh/policies/` (signed by `knshd`), or snapshots pushed by the authority with `policy.set`. They are parsed by a hand-written parser for the TOML subset shown here. Evaluation rules are in [../03-functional-requirements/policy.md](../03-functional-requirements/policy.md).

## Example

```toml
name = "web-app"
extends = "base"
preset = "claude-code"            # what the CLI itself needs: API host, ~/.claude

[fs]
read  = "all"                    # everything except deny
write = ["${PROJECT}", "${TMPDIR}"]
deny  = ["~/.ssh", "~/.aws", "~/.gnupg", "~/Library/Keychains", "~/Library/Mail", "~/Library/Messages"]

[exec]
allow   = ["git", "npm", "node", "python3", "cargo", "make", "rg"]
ask     = ["git push", "rm -rf *", "brew *"]
deny    = ["sudo *", "security *", "launchctl *", "open *", "osascript *"]
project_executables = "allow"    # node_modules/.bin, ./scripts: allow | ask | deny
default = "ask"

[network]
mode  = "allowlist"              # none | allowlist
hosts = ["registry.npmjs.org", "pypi.org"]
approval_hosts = ["github.com"]  # only for commands whose class or approval includes them
loopback = [3000, 5432]          # local dev servers and databases

[approvals]
irreversible = "ask"

[checkpoints]
roots = ["${PROJECT}"]
required = true

[recording]
commands = true
output = false
retention_days = 30

[secrets.env]
NPM_TOKEN = { secret = "npm-token", inject_for = ["npm publish"], hosts = ["registry.npmjs.org"] }
```

## TOML subset

The parser (`knsh-toml`) reads exactly this subset of TOML 1.0, with TOML 1.0 semantics, and rejects everything else with an error naming line and column. The same subset is used for hooks ([hook](hook.md)) and other configuration files.

- Comments, blank lines, `\n` or `\r\n` line ends.
- Bare, basic-quoted and literal-quoted keys, and dotted keys made of them.
- `[table]`, `[a.b]` and `[[array-of-tables]]` headers.
- Single-line basic strings (TOML 1.0 escapes) and single-line literal strings.
- Decimal integers in the signed 64-bit range (underscores between digits allowed).
- `true` and `false`.
- Arrays, possibly over several lines, with comments between elements and an optional trailing comma.
- Inline tables, on one line, without a trailing comma.

Outside the subset, and rejected as such: dates and times, floats (including `inf` and `nan`), multi-line strings and hexadecimal, octal or binary integers. As in TOML, duplicate keys and tables defined twice (by headers, dotted keys or inline) are errors. A leading byte-order mark is rejected. Input is limited to 1 MiB and 32 levels of nested tables and arrays. A spec example that needs more TOML extends this list first.

## Keys

| Key | Type | Meaning |
| --- | --- | --- |
| `name` | string | Profile name |
| `extends` | string | Parent profile |
| `preset` | string | What the agent CLI itself needs (API host, config folder) |
| `fs.read` | `"all"` or list | Readable paths; `"all"` means everything except `fs.deny` |
| `fs.write` | list of paths | Write roots |
| `fs.deny` | list of paths | Never readable or writable |
| `exec.allow`, `exec.ask`, `exec.deny` | list of patterns | Command rules; names match trusted binaries and builtins only; the first word must not contain `/` |
| `exec.project_executables` | `allow` \| `ask` \| `deny` | Binaries from agent-writable places |
| `exec.interpreters.<family>` | table | Adds an interpreter family, or options to a known one, for dynamic-code detection (below). **Proposed** (KNSH-036) |
| `exec.default` | `allow` \| `ask` \| `deny` | When no rule matches |
| `exec.trusted_folders` | list of paths | Folders added to the default trusted folders (FR-POL-13). **Proposed** (KNSH-039) |
| `exec.trusted_tools` | list of patterns | Tools run without a per-command profile, after an approval or grant (FR-SBX-09). **Proposed** (KNSH-039) |
| `exec.bash` | path | The bash that runs agent lines. **Proposed** (KNSH-039) |
| `network.mode` | `none` \| `allowlist` | |
| `network.hosts` | list | Open to every command. Entries are names, `*.` wildcards (every name strictly below) or IP addresses ([matching](../03-functional-requirements/network-proxy.md#host-rules-name-resolution-and-address-checks-knsh-060)) |
| `network.approval_hosts` | list | Only for commands whose class or approval includes them |
| `network.class_hosts.fetch`, `network.class_hosts.publish` | list | Approval hosts a line reaches by its class alone, without an approval: each must be in `network.approval_hosts`. Presets may add to them. **Proposed** (KNSH-058) |
| `network.loopback` | list of ports | Loopback ports allowed |
| `network.non_tls_hosts` | list | Hosts whose tunnels may carry anything, not only TLS naming the host: the proxy skips the server-name check for them ([FR-NET-06](../03-functional-requirements/network-proxy.md#tls-server-name-check-knsh-061)). Matched like `network.hosts` entries; never makes a host reachable. Not allowed in presets. **Proposed** (KNSH-061) |
| `approvals.irreversible` | `allow` \| `ask` \| `deny` | Treatment of irreversible lines |
| `approvals.irreversible_commands` | list of patterns | Commands the profile adds to the irreversible list. **Proposed** (KNSH-039) |
| `checkpoints.roots` | list of paths | Protected roots |
| `checkpoints.required` | bool | Lines touching a root wait for its shadow |
| `checkpoints.exclude` | list | Default `node_modules`, `target`, `.venv`, `dist`, `build` |
| `recording.commands`, `recording.output` | bool | Recording settings |
| `recording.retention_days` | int | Record retention |
| `output.mode` | `full` \| `truncate` \| `head_tail` \| `errors_only` \| `ref` | Default `exec.run` output mode (FR-OUT-02). **Proposed** (KNSH-039) |
| `secrets.env.<VAR>` | table | Secret injection ([secret](secret.md)) |

### `exec.interpreters` (proposed, KNSH-036)

Interpreters given code on the command line (`python3 -c`, `node -e`) or no script are dynamic code (FR-LC-05). The
engine has a built-in table: `sh`, `bash`, `zsh` and the other shells, `python` (and `pypy`), `node`, `ruby`, `perl`,
`php`, `deno`, `bun` and `osascript`. A family is matched by the resolved binary's base name without a version suffix,
so `python3.12` is `python`. A profile extends the table:

```toml
[exec.interpreters.lua]
code_options  = ["-e"]            # the value (or the option itself) is code
value_options = ["-l"]            # take the next argument as their value
stdin_options = ["-i"]            # make it read its program from standard input
script_options = []               # name the program to run, like a script operand (python -m)
info_options  = ["-v"]            # with no script, it runs nothing
code_subcommands = []             # first operands that run code (deno eval)
reads_stdin_without_script = true
cluster_values_from_next = false  # a value option inside a cluster takes the next argument (bash -oc errexit code)
```

Every key but the table name is optional. Options are spelled `-x` (clusters with other short options) or `--name`
(also matches `--name=value`). The family name must be a base name without a version suffix (`lua`, not `lua5.4`). An
entry for a family the table already has only adds options: a profile can make detection stricter, never weaker.

Profiles may also set trusted binary folders, trusted tools (run without a per-command profile after approval), an
irreversible-command list, the agent's bash path, and the default output mode. KNSH-039 proposes the keys
`exec.trusted_folders`, `exec.trusted_tools`, `approvals.irreversible_commands`, `exec.bash` and `output.mode` for them
(table above).

## Defaults

Every key is optional except `name`. An unset key takes its default:

| Key | Default |
| --- | --- |
| `fs.read` | `"all"` (FR-POL-12) |
| `fs.write`, `fs.deny` | none (the fixed denies of FR-POL-30 are added by the sandbox compiler, never by the profile) |
| `exec.allow`, `exec.ask`, `exec.deny`, `exec.trusted_tools` | none |
| `exec.project_executables` | `ask` |
| `exec.default` | `ask`: a command no rule names is never run without a decision |
| `exec.trusted_folders` | none beyond the defaults (`/usr/bin`, `/bin`, `/usr/sbin`, `/opt/homebrew/bin`, `/usr/local/bin`) |
| `exec.bash` | `/bin/bash` |
| `network.mode` | `none` |
| `network.hosts`, `network.approval_hosts`, `network.loopback` | none |
| `approvals.irreversible` | `ask` |
| `approvals.irreversible_commands` | none |
| `checkpoints.roots` | none |
| `checkpoints.required` | `false` |
| `checkpoints.exclude` | `node_modules`, `target`, `.venv`, `dist`, `build` (a profile's list replaces it) |
| `recording.commands`, `recording.output` | `true`, `false` |
| `recording.retention_days` | 30 (1 to 36500) |
| `output.mode` | `full` |

## Loading

The loader (KNSH-039, `knsh-core`) turns a profile into one resolved value, or refuses it whole; an invalid profile is
never partially applied.

- **Validation.** Unknown keys, wrong types and invalid values are errors naming the dotted key (`fs.write[1]`) and its
  line and column. A profile loaded by name must have that `name`.
- **`extends`.** Parents are read by name from the same place, up to 8 profiles in a chain. A key the child sets
  replaces the parent's value whole (`exec.allow` is not appended to); keyed tables (`exec.interpreters.<family>`,
  `secrets.env.<VAR>`) are merged per entry. `preset` is inherited like any key. A cycle is an error.
- **`preset`.** Presets are profile fragments shipped as data with the engine (`claude-code`, `codex-cli`, `generic`;
  their contents are KNSH-058's). A preset may only add to path and host lists (`fs.read` as a list, `fs.write`,
  `fs.deny`, `exec.trusted_folders`, `network.hosts`, `network.approval_hosts`, `network.loopback`,
  `checkpoints.roots`); its entries are appended to the profile's. It never changes any other setting, so it cannot
  weaken a profile. An unknown preset is an error.
- **Paths.** A path is absolute, or starts with `~`, `${PROJECT}`, `${HOME}` or `${TMPDIR}`, followed by nothing or
  `/`. Any other `$`, `~user`, a relative path and `..` are errors. After expansion every path is canonicalised with
  symlinks followed. A path that does not exist yet (`~/.aws` on a machine without it) keeps its deepest existing
  ancestor's canonical form with the rest appended, so a deny still covers it if it is created later; any lookup
  failure other than "not found" refuses the profile. A dangling symlink on the way counts as such a failure, not as
  "not found", because the sandbox matches the link's target, never the link's own path. A path is at most 4096
  bytes as written. Two entries resolving to the same path are kept once.
- **Fixed denies.** A path in a key that grants access (`fs.read` as a list, `fs.write`, `exec.trusted_folders`,
  `exec.bash`, `checkpoints.roots`) may not be an engine path or lie below one (FR-POL-30, KNSH-041); the error names
  the key. A path above one is accepted, since the sandbox compiler carves the fixed denies out of it. See
  [policy](../03-functional-requirements/policy.md#fixed-denies).

## Variables

| Variable | Value |
| --- | --- |
| `${PROJECT}` | The git root, or the session's start directory when there is none |
| `${HOME}` | Home directory |
| `${TMPDIR}` | Temporary directory |

All paths are resolved to canonical form, with symlinks followed, before matching.

## Rule IDs

Rules are identified by section and index, e.g. `exec.allow[1]`, `exec.ask[0]`. These appear in records, errors and `decision.requested`.

The index is zero-based and refers to the **resolved** profile's list. Because `extends` replaces a list whole and a
preset never adds command rules, it is the entry's position in the nearest profile of the chain that sets that list:
if `web-app` sets `exec.ask` and extends `base`, `exec.ask[0]` is `web-app`'s first entry; if `web-app` leaves
`exec.ask` unset, it is `base`'s. A decision made by a setting rather than a rule has the setting's key as its ID:
`exec.project_executables` (a binary outside the trusted folders, FR-POL-14) or `exec.default` (no rule matched,
FR-POL-17). Matching is described in [policy](../03-functional-requirements/policy.md#resolution-and-matching).
