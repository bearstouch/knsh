# Policy profile

Profiles are TOML files in `~/.config/knsh/policies/` (signed by `knshd`), or snapshots pushed by the authority with `policy.set`. They are parsed by a hand-written parser for the TOML subset shown here. Evaluation rules are in [../functional-requirements/policy.md](../functional-requirements/policy.md).

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

## Keys

| Key | Type | Meaning |
| --- | --- | --- |
| `name` | string | Profile name |
| `extends` | string | Parent profile |
| `preset` | string | What the agent CLI itself needs (API host, config folder) |
| `fs.read` | `"all"` or list | Readable paths; `"all"` means everything except `fs.deny` |
| `fs.write` | list of paths | Write roots |
| `fs.deny` | list of paths | Never readable or writable |
| `exec.allow`, `exec.ask`, `exec.deny` | list of patterns | Command rules; names match trusted binaries only |
| `exec.project_executables` | `allow` \| `ask` \| `deny` | Binaries from agent-writable places |
| `exec.default` | `allow` \| `ask` \| `deny` | When no rule matches |
| `network.mode` | `none` \| `allowlist` | |
| `network.hosts` | list | Open to every command |
| `network.approval_hosts` | list | Only for commands whose class or approval includes them |
| `network.loopback` | list of ports | Loopback ports allowed |
| `approvals.irreversible` | `ask` \| … | Treatment of irreversible lines |
| `checkpoints.roots` | list of paths | Protected roots |
| `checkpoints.required` | bool | Lines touching a root wait for its shadow |
| `checkpoints.exclude` | list | Default `node_modules`, `target`, `.venv`, `dist`, `build` |
| `recording.commands`, `recording.output` | bool | Recording settings |
| `recording.retention_days` | int | Record retention |
| `secrets.env.<VAR>` | table | Secret injection ([secret](secret.md)) |

Profiles may also set: trusted binary folders, trusted tools (run without a per-command profile after approval), an irreversible-command list, the agent's bash path, and the default output mode.

## Variables

| Variable | Value |
| --- | --- |
| `${PROJECT}` | The git root, or the session's start directory when there is none |
| `${HOME}` | Home directory |
| `${TMPDIR}` | Temporary directory |

All paths are resolved to canonical form, with symlinks followed, before matching.

## Rule IDs

Rules are identified by section and index, e.g. `exec.allow[1]`, `exec.ask[0]`. These appear in records, errors and `decision.requested`.
