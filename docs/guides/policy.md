# Policy profiles

A policy profile says what an agent may read, write, run and reach, and what needs your approval. Profiles are small TOML files. `knsh` never writes policy for you: it only enforces what you give it.

## Where profiles live

Profiles are files named `<profile>.toml` in `~/.config/knsh/policies/`. They are signed by `knshd`, and an unsigned or altered file is ignored, so a profile can't be changed by anything but you. Create and edit them with:

```sh
knsh policy edit web-app
```

1. `knsh` opens the current text in `$VISUAL`, else `$EDITOR`, else `vi`.
2. When you close the editor, it shows the size and a short fingerprint of the text, and a prompt appears on your Mac's screen with the same fingerprint.
3. Approve with Touch ID or your password. The file is signed and saved: `Signed and saved profile web-app.`

If the text doesn't change, nothing is sent (`No changes to profile web-app.`). If the profile doesn't load (a typo in a key, a wrong type), the error names the key and the line, and your edited text is kept in a temporary file whose path is printed, so you don't lose it. If the existing file is unsigned or has a bad signature, `knsh` warns you before you edit, because `knshd` is ignoring it until you save.

A profile name uses 1 to 64 letters, digits, `.`, `_` or `-`. The profile `unattended` is built in and can't be edited.

## A complete example

```toml
name = "web-app"
extends = "base"
preset = "claude-code"            # what the agent CLI itself needs: its API host, ~/.claude

[fs]
read  = "all"                     # everything except deny
write = ["${PROJECT}", "${TMPDIR}"]
deny  = ["~/.ssh", "~/.aws", "~/.gnupg", "~/Library/Keychains", "~/Library/Mail", "~/Library/Messages"]

[exec]
allow   = ["git", "npm", "node", "python3", "cargo", "make", "rg"]
ask     = ["git push", "rm -rf *", "brew *"]
deny    = ["sudo *", "security *", "launchctl *", "open *", "osascript *"]
project_executables = "allow"     # node_modules/.bin, ./scripts: allow | ask | deny
default = "ask"

[network]
mode  = "allowlist"               # none | allowlist
hosts = ["registry.npmjs.org", "pypi.org"]
approval_hosts = ["github.com"]   # only for commands that are approved or whose class allows it
loopback = [3000, 5432]           # local dev servers and databases

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

Every key is optional except `name`. An unset key takes its default (see [the table below](#defaults)).

Profiles use a small subset of TOML: comments, tables, strings, whole numbers, booleans, arrays and one-line inline tables. Dates, decimals and multi-line strings are rejected with an error naming the line and column. A profile file can be at most 1 MiB. A profile that doesn't load is refused completely, never partly applied.

## Paths

A path in a profile is absolute, or starts with `~`, `${PROJECT}`, `${HOME}` or `${TMPDIR}`.

| Variable | Value |
| --- | --- |
| `${PROJECT}` | The git root of the folder you started in, or that folder if it isn't in a git repository |
| `${HOME}` | Your home folder |
| `${TMPDIR}` | The temporary folder |

Relative paths and `..` aren't allowed. Paths are resolved with symlinks followed before they are compared, so a link can't point past a rule. A path that doesn't exist yet, such as `~/.aws` on a Mac without it, still works in `deny`: the rule applies if the folder appears later.

Your engine folders (`~/.config/knsh/` and `~/Library/Application Support/knsh/`) are always off limits to agents, and no profile can open them. Profiles that name them in a key that grants access are refused.

## Files: `[fs]`

| Key | Meaning |
| --- | --- |
| `fs.read` | `"all"` (the default), or a list of readable paths. `"all"` means everything except `fs.deny`. |
| `fs.write` | Folders the agent may write to. Nothing else is writable. |
| `fs.deny` | Paths that can be neither read nor written. |

Agents can never write your shell startup files (`~/.zshrc`, `~/.zprofile`, `~/.bashrc`, `~/.bash_profile`, `~/.profile`), whatever the profile says.

## Commands: `[exec]`

| Key | Meaning |
| --- | --- |
| `exec.allow`, `exec.ask`, `exec.deny` | Lists of command patterns. |
| `exec.default` | `allow`, `ask` or `deny`: what happens when no rule matches. Default `ask`. |
| `exec.project_executables` | What to do with a program found in a place the agent can write, such as `node_modules/.bin` or `./scripts`: `allow`, `ask` or `deny`. Default `ask`. |
| `exec.trusted_folders` | Extra folders whose programs count as trusted (see below). |
| `exec.trusted_tools` | Patterns for tools that run without a per-command sandbox profile, after approval. |
| `exec.bash` | The bash that runs agent lines. Default `/bin/bash` (version 3.2). |
| `exec.mode` | `line` (default) or `native`. See [Native mode](native-mode.md). |
| `exec.interpreters.<family>` | Teaches `knsh` another interpreter that runs code from its arguments (see below). |

### Writing patterns

A pattern is words separated by spaces. The first word is a program name and can't contain `/`.

- `*` is the only wildcard. Inside a word it matches any run of characters (`*.txt`, `--force*`). A word that is exactly `*` matches any number of whole arguments, including none.
- A pattern with no `*` also matches the same command with more arguments: `git push` matches `git push origin main`, but not `git pushx`.
- A pattern with a `*` matches exactly: `rm *.txt` matches `rm a.txt` but not `rm a.txt b.txt`. Use `rm *` for any arguments.
- There's no way to write a literal `*`. `?` and `[` are ordinary characters.

For tools with subcommands (git, npm, pnpm, yarn, cargo, docker, kubectl, gh, terraform, pip, go), options before the subcommand are ignored when matching, so `git -c user.name=x push` matches `git push`.

### Which program a name means

A name rule such as `git` matches only a program found in a **trusted folder**: `/usr/bin`, `/bin`, `/usr/sbin`, `/opt/homebrew/bin` and `/usr/local/bin`, plus any you add with `exec.trusted_folders`. Bash builtins (`cd`, `echo`, `eval`) are matched by name.

A program somewhere else, such as `./scripts/build.sh` or `node_modules/.bin/eslint`, never matches a name rule, even a deny rule. It falls under `exec.project_executables` instead. That stops an agent from writing its own `git` in the project and having it allowed.

### Which rule wins

For every command in the line, **deny beats ask beats allow**. If no rule matches, `exec.default` applies. For a whole line, the line is denied if any part is denied, and asks if any part asks. Within one list, the first match gives the rule name you see in history and approvals, like `exec.ask[0]`.

Unknown arguments are treated carefully. If an argument comes from an expansion, such as `rm $X` or `git $X`, a deny or ask rule that *could* match applies, while an allow rule applies only if it would match whatever the argument turns out to be. So `rm $X` is denied by `rm -rf *`, and `git $X` still asks under `git push`.

### Dynamic code

Commands that run code the line doesn't spell out, such as `eval`, `bash -c '…'`, `python3 -c '…'` or `node -e '…'`, are *dynamic code*. They are allowed or asked as the profile says, but they get less: they can only reach `network.hosts` (never approval hosts), and they never receive [secrets](secrets.md). One dynamic part limits the whole line.

`knsh` knows the shells, `python`, `node`, `ruby`, `perl`, `php`, `deno`, `bun` and `osascript`. To teach it another interpreter:

```toml
[exec.interpreters.lua]
code_options  = ["-e"]            # the option's value is code
value_options = ["-l"]            # options that take the next argument as their value
stdin_options = ["-i"]            # options that make it read its program from standard input
script_options = []               # options that name the program to run
info_options  = ["-v"]            # with no script, it runs nothing
code_subcommands = []             # first arguments that run code (like deno eval)
reads_stdin_without_script = true
```

Every key but the table name is optional. An entry can only add to a known interpreter, so a profile can make detection stricter but never weaker.

## Network: `[network]`

See [Network access](network.md) for how these work.

| Key | Meaning |
| --- | --- |
| `network.mode` | `none` (default) or `allowlist`. |
| `network.hosts` | Hosts every command may reach. Names, `*.example.com` wildcards, or IP addresses. |
| `network.approval_hosts` | Hosts reachable only by an approved command, or one whose kind of action allows it. |
| `network.class_hosts.fetch`, `.publish` | Approval hosts that commands reach by what they do (download or upload), without an approval. Each must also be in `approval_hosts`. |
| `network.loopback` | Local ports the agent may connect to. |
| `network.non_tls_hosts` | Hosts whose connections may carry something other than TLS for that name. |

## Approvals: `[approvals]`

| Key | Meaning |
| --- | --- |
| `approvals.irreversible` | `allow`, `ask` (default) or `deny`: what to do with commands that can't be undone, such as `git push`. See [Undo and checkpoints](undo.md#actions-that-cant-be-undone). |
| `approvals.irreversible_commands` | More command patterns to treat as irreversible. |
| `approvals.upload_hosts` | More hosts to treat as places data can be uploaded to. |

## Checkpoints: `[checkpoints]`

| Key | Meaning |
| --- | --- |
| `checkpoints.roots` | Folders whose changes are protected for undo. |
| `checkpoints.required` | If `true`, commands that touch a root wait until its snapshot is ready. Default `false`. |
| `checkpoints.exclude` | Folder names not protected. Default `node_modules`, `target`, `.venv`, `dist`, `build`. Your list replaces the default. |

## Recording and output

| Key | Meaning |
| --- | --- |
| `recording.commands` | Record the agent's commands. Default `true`. |
| `recording.output` | Record their output. Default `false`. |
| `recording.retention_days` | Days to keep records, 1 to 36500. Default 30. |
| `output.mode` | How much output an agent that calls the engine directly gets back: `full` (default), `truncate`, `head_tail`, `errors_only` or `ref`. |

## Secrets: `[secrets.env]`

See [Secrets](secrets.md).

## Inheriting from another profile

`extends = "base"` starts from another profile in the same folder, up to 8 profiles deep. A key you set **replaces** the parent's value completely: setting `exec.allow` in the child doesn't add to the parent's list. Tables keyed by name (`exec.interpreters.<family>`, `secrets.env.<VAR>`) are merged entry by entry. A cycle is an error.

A session started from inside another session must use the same profile or a stricter one.

## Presets

`preset = "claude-code"`, `"codex-cli"` or `"generic"` adds what that agent CLI needs. A preset only appends to path and host lists, so it can't weaken your profile. See [Agents in envelopes](agents.md#presets).

## Defaults

| Key | Default |
| --- | --- |
| `fs.read` | `"all"` |
| `fs.write`, `fs.deny` | none |
| `exec.allow`, `exec.ask`, `exec.deny` | none |
| `exec.default`, `exec.project_executables` | `ask` |
| `exec.mode` | `line` |
| `exec.bash` | `/bin/bash` |
| `network.mode` | `none` |
| `approvals.irreversible` | `ask` |
| `checkpoints.roots` | none |
| `checkpoints.required` | `false` |
| `checkpoints.exclude` | `node_modules`, `target`, `.venv`, `dist`, `build` |
| `recording.commands` / `recording.output` | `true` / `false` |
| `recording.retention_days` | 30 |
| `output.mode` | `full` |

An unconfigured profile is therefore strict: it asks about every command, has no network and writes nowhere.

## The built-in `unattended` profile

`knsh -c` outside an envelope, for instance when an agent CLI runs with `SHELL=knsh` but wasn't started by `knsh agent`, uses this profile. It is part of `knsh` and can't be replaced or edited.

- It can read everything except credential folders (`~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.kube`, `~/.docker`, `~/.config/gh`, `~/.netrc`, `~/.git-credentials`, `~/.npmrc`, `~/.pypirc`, `~/Library/Keychains`, `~/Library/Cookies`, `~/Library/Mail`, `~/Library/Messages`). It writes only to `${TMPDIR}`. There is no network.
- It allows plain read-only commands: `ls`, `cat`, `head`, `tail`, `grep`, `rg`, `find` (without `-exec`, `-ok` or `-delete`), `diff`, `sort`, `git status`, `git log`, `git diff` and the like.
- Everything else asks, and since nobody can answer, **asking means denied**. Irreversible commands are denied.

## Check a profile

There is no dry-run command yet (`knsh policy check` reports that it isn't implemented). To test a profile, save it with `knsh policy edit`, start an agent with it, and look at the result with `knsh history`: each record says which rule decided the command (for example `exec.ask[1]` or `exec.default`).
