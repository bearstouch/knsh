# Policy

A policy profile says what an agent may read, write, run and reach, and what needs approval. Command rules are intent filters that make approvals specific and stop honest mistakes; the hard limits are the sandbox, its executable rules, the proxy and credential scoping ([enforcement model](../02-architecture/enforcement-model.md)). The file format is in [../05-models/policy-profile.md](../05-models/policy-profile.md).

## Sources

| ID | Requirement |
| --- | --- |
| FR-POL-01 | Profiles must be loadable from TOML files in `~/.config/knsh/policies/`, or from snapshots pushed by the authority with `policy.set`. |
| FR-POL-02 | Profiles may `extends` another profile and name a `preset` for what the agent CLI itself needs. |
| FR-POL-03 | The engine must never author policy; it only evaluates and enforces what it is given. |

## Resolution and matching

| ID | Requirement |
| --- | --- |
| FR-POL-10 | `${PROJECT}` must resolve to the git root, or the session's start directory when there is none; `${HOME}` and `${TMPDIR}` resolve as usual. |
| FR-POL-11 | All paths must be resolved to canonical form (`/private/var/…`), with symlinks followed, before matching. |
| FR-POL-12 | `fs.read = "all"` must be the default: everything except the deny list. |
| FR-POL-13 | A name rule (such as `git`) must match only a binary resolved from a trusted folder: `/usr/bin`, `/bin`, `/usr/sbin`, `/opt/homebrew/bin`, `/usr/local/bin`, plus folders the profile adds. Bash builtins, which bash runs itself, are matched by name too. |
| FR-POL-14 | A binary found in an agent-writable place (such as `node_modules/.bin`) must never match a name rule and must fall under `project_executables` (`allow`, `ask` or `deny`). |
| FR-POL-15 | Patterns are globs over normalised arguments. For tools with subcommands in the classifier's table (git, npm, cargo, docker, kubectl and others), options before the subcommand must be normalised, so `git -c x=y push` matches `git push`. |
| FR-POL-16 | A pattern without `*` must also match the same command with arguments. |
| FR-POL-17 | Precedence across all matching rules must be deny, then ask, then allow. No match uses `exec.default`. |
| FR-POL-18 | For a whole line, the verdict is deny if any part is denied, ask if any part asks. |

**Subcommand normalisation (FR-POL-15).** The classifier's table (`knsh-bash`, `SUBCOMMAND_TABLE`: git, npm, pnpm,
yarn, cargo, docker, kubectl, gh, terraform, pip, go) lists, per tool, the global options accepted before the
subcommand and the subcommands. Only a binary resolved in a trusted folder whose base name is in the table is
normalised, to `[tool, subcommand, …remaining arguments]`, with each skipped option recorded by name (never its value).
The subcommand is never guessed: an option the table does not know, an argument built from an expansion before the
subcommand, a value option followed by a word that looks like an option, a first operand the table does not list
(`git co`, a package script, cargo's built-in aliases, which a project's `[alias]` can override), an option that runs
nothing (`--version`), or arguments that are incomplete (a command run by `xargs`, which appends or replaces words)
keeps the raw argv, and rules match on that.

**Rule matching (FR-POL-13 – FR-POL-17, KNSH-040).** `knsh-core`'s `evaluate_command` decides one classified simple
command and returns the verdict with the rule ID that decided it.

- *Who rules name.* A binary resolved in a trusted folder is matched by its base name, either the resolved binary's or
  the name as written (`/usr/bin/git` and `git` are both `git`; `vi` linking to `/usr/bin/vim` is both `vi` and
  `vim`, so a deny cannot be stepped around through another spelling). Only the resolved name allows: the name as
  written may be a symlink the agent made (`./git` linking to `/bin/rm` runs `rm`), so it counts for deny and ask
  rules only. A bash builtin (`cd`, `echo`, `eval`,
  `source`) is matched by its name: bash runs it itself, so no file the agent wrote can stand in for it. Any other
  binary never matches a rule and gets `exec.project_executables`, even when a deny rule names it (FR-POL-14). A
  function defined in the line, a name not found and a name built from an expansion match no rule and get
  `exec.default`; the function's body is decided command by command, and dynamic code is limited by the line verdict
  (FR-POL-20, KNSH-041).
- *Patterns.* Words separated by spaces; the first names the program and must not contain `/` (the loader refuses a
  pattern without words or with a path as its name, so a deny rule never silently names nothing). Later words are
  matched in order against the normalised arguments when the command was normalised, and against the arguments as
  written otherwise; a rule matching either form matches, so `git -c *` still denies `git -c x=y push`.
- *Globs.* Only `*` is special, matched against argument strings and never the filesystem. Inside a word it matches
  any run of characters within one argument (`*.txt`, `--force*`, or `g*` as the name). A word that is exactly `*`
  matches any number of whole arguments, none included: `rm -rf *` matches `rm -rf`, `rm -rf /` and `rm -rf a b`.
  A pattern with no `*` at all also matches with more arguments (FR-POL-16): `git push` matches `git push origin
  main` but not `git pushx`. A pattern with a `*` matches exactly (`rm *.txt` does not match `rm a.txt b.txt`). There
  is no escape for a literal `*`; `?` and `[` are ordinary characters.
- *Unknown arguments.* An argument built from an expansion (including an unquoted filename glob such as `*.txt`,
  which bash expands) may become any number of words, and the arguments of a command `xargs` runs are unknown
  (more are appended, or any is replaced). A deny or ask rule that may match such a command applies; an allow rule
  applies only if it matches whatever the arguments become. So `rm $X` is denied by `rm -rf *`, `git $X` is asked
  by `git push`, and `git` still allows `git $X`. When a tool in the subcommand table is kept raw because an option
  the table does not know, or an expansion, comes before the subcommand (`git --unknown push`, `git -c $X push`),
  the leading arguments may be global options, so a deny or ask rule may match from any argument on: `git push`
  asks for both, while an allow still matches only the raw argv.
- *Precedence.* Deny beats ask beats allow across every matching rule; within a list the first match (lowest index)
  is the rule ID. No match gives `exec.default` with the rule ID `exec.default`; a project executable has the rule ID
  `exec.project_executables`.

**Network-intent classes (FR-LC-06, FR-NET-03).** Each listed subcommand carries one or more of `network:none`,
`network:fetch` (downloads or reads remote state: `git fetch`, `npm install`, `kubectl get`) and `network:publish`
(uploads or changes remote state: `git push`, `npm publish`, `kubectl apply`); a group (`gh pr`) carries the union of
its members. Classes list everything a command may do, so a host rule must allow every class of a command. A command
that is not normalised has no classes, so it reaches `approval_hosts` only with an approval. Dynamic code never has
classes (FR-POL-20).

**Class host rules (FR-NET-03, KNSH-058, proposed).** `network.class_hosts` names, per class that connects, the
approval hosts a line reaches by its classes alone, without an approval:

```toml
[network]
approval_hosts = ["github.com"]
[network.class_hosts]
fetch = ["github.com"]     # `git fetch` reaches github.com; `git push` still needs an approval
```

The keys are `fetch` and `publish` (`network:none` connects nowhere). A line reaches a host by class when it presents
at least one class that connects and **every** class it presents that connects lists the host, so `git fetch && git
push` needs github.com under both. A line with no classes (dynamic code, a program the table does not normalise)
never reaches an approval host by class. Every host listed must be in the resolved profile's
`network.approval_hosts`; the loader refuses one that is not (`InvalidValue` at `network.class_hosts.<class>[i]`), so
a class rule never opens a host the profile does not name. An `extends` child replaces each class's list whole; a
preset appends to it. Under profile strictness (FR-SES-03) a child's class host must be open to that class, or to every
command, in the parent. The line decision carries the result as `capabilities.class_hosts`; the proxy enforces it
(KNSH-060).

**Line verdicts (FR-POL-18, FR-LC-09, KNSH-041).** `knsh-core`'s `evaluate_line` decides a whole classified line
before any of it runs and returns `LineDecision { verdict, source, rule_id, reason, matched_rules, capabilities }`.

- *Parts.* Every entry of the classification (each simple command, wrapper and command a wrapper runs, including those
  in substitutions and function bodies) is decided by `evaluate_command`, and `matched_rules` lists each part's verdict
  and rule ID in source order. A dynamic part with no entry of its own (a line the parser could not read, a construct
  kept whole such as `[[ … ]]`, `coproc`) is decided by `exec.default` (FR-POL-20), even inside a dynamic command:
  `python3 -c x "$([[ $(rm -rf /) ]])"` is not decided by `python3`'s allow rule alone.
- *Verdict.* Deny if any part is denied, else ask if any part asks, else allow. `rule_id` is the first part with that
  verdict. A line with no parts (a comment) runs nothing and is allowed. `source` is `rule`, except under the
  `unattended` profile (below).
- *Capabilities.* What the line may receive if it runs: the hosts open to it (`network.hosts`), the approval hosts it
  may reach once its classes or an approval allow (`network.approval_hosts`; the proxy decides each connection,
  FR-NET-03), the approval hosts its classes alone open (`class_hosts`, above), the loopback ports, the classes it presents, and the `secrets.env` variables whose `inject_for` patterns
  certainly match one of its commands (an upper bound: asking and injecting are FR-SEC-01 – FR-SEC-02's). Under
  `network.mode = "none"` there are no hosts. A denied line receives nothing.
- *Line classes.* The proxy identifies a line, not a command within it, so a line presents classes only when every
  command that can connect through the proxy has them: the union of its normalised commands' classes, or none if any
  other program runs (a binary not normalised, a project executable, a name built from an expansion). Builtins,
  function calls, names not found and wrappers are skipped, since their commands are entries of their own. So
  `cd repo && git fetch` presents `network:fetch`, and `git fetch && curl …` presents nothing.
- *Fail closed.* Any failure inside the evaluation (a classification that breaks its own invariants, a panic) is a deny
  with source `rule`, no rule ID, the reason "policy evaluation failed" and no capabilities.

## Dynamic code

| ID | Requirement |
| --- | --- |
| FR-POL-20 | Dynamic code (`eval`, `sh -c`, `python3 -c`, names from variables) must be allowed or asked as the profile says, but must never inherit classes from what it might run. |
| FR-POL-21 | Dynamic code's network must be limited to `network.hosts`; it must receive no secrets and can never reach `approval_hosts`. So `python3 -c "subprocess.run(['git','push'])"` cannot reach github.com. |

**Clamp (KNSH-041).** If any part of a line is dynamic, the whole line is clamped, even when it is allowed or later
approved: its hosts are `network.hosts` only, with no approval hosts, no secrets and no classes. The loopback ports
stay, being open to every command alike. One dynamic part clamps every part, because the proxy and the injected
environment are per line.

## Fixed denies

| ID | Requirement |
| --- | --- |
| FR-POL-30 | Engine files, sockets and the control service must be denied to every envelope and command, and no profile can change that. |

**Fixed-deny set (KNSH-041).** The set is compiled into `knsh-core` and is the only source of the engine's location
names: the engine data directory `~/Library/Application Support/knsh/` (records, grants, pushed policy, checkpoints and
the sockets in `run/`), the configuration directory `~/.config/knsh/`, and the Mach service `knsh.control`.
`knsh-platform` builds its engine paths from the same constants. The sandbox compiler denies the set in every profile
(FR-SBX-05, FR-SBX-10). The loader refuses a profile in which a key that grants access (`fs.read` as a list,
`fs.write`, `exec.trusted_folders`, `exec.bash`, `checkpoints.roots`) names an engine path or a path below one, after
canonicalisation (so a symlink into an engine directory is caught) and ignoring ASCII case (the home volume is
case-insensitive by default). A path above an engine path (`fs.write = ["~"]`) is accepted, because the fixed denies
are carved out of it; `fs.deny` may name engine paths. No profile key names a socket or a Mach service. Checkpoint stores on other volumes
(`.knsh-checkpoints/` at a volume's root, KNSH-078) cannot be listed per home, so the name itself is reserved: every
path with a `.knsh-checkpoints` component (ignoring ASCII case) is a fixed deny, refused by the loader like an engine
path and denied in every profile by the regex `/\.knsh-checkpoints(/|$)` (reading, listing, writing, renaming and
executing it observed denied on macOS 26.6.2).

## The `unattended` profile

**Proposed (KNSH-041), for FR-AGT-21.** A non-interactive `knsh` or `knsh -c` outside any envelope runs under the
built-in profile `unattended`. It is compiled into the engine (its integrity is the binary's code signature, not
FR-POL-40's file signature) and read by the same loader, with no `extends` and no preset; a file of the same name in
the policies directory is never read in its place. Selecting it for such a session is part b's (the supervisor's).

Any `ask` verdict under a profile named `unattended` becomes `deny` with source `standalone` and a reason naming the
profile and the rule that asked, because no one can answer. So does an allowed line holding dynamic code (the reason
names the rule of its first dynamic part): an allowed tool given a code variable (`GIT_EXTERNAL_DIFF=./x git diff`,
`PAGER=./x git log`) runs any program, which is never a plain read-only command. A deny rule still denies with source
`rule`. Grants (KNSH-042) are applied first: an ask a live grant answers is allowed with source `grant`
(the grant is the prior answer), but a granted line holding dynamic code is still denied.

| Setting | Value |
| --- | --- |
| `fs.read` | `"all"` |
| `fs.write` | `${TMPDIR}` only |
| `fs.deny` | `~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.kube`, `~/.docker`, `~/.config/gh`, `~/.netrc`, `~/.git-credentials`, `~/.npmrc`, `~/.pypirc`, `~/Library/Keychains`, `~/Library/Cookies`, `~/Library/Mail`, `~/Library/Messages` |
| `exec.allow` | Builtins `cd`, `pwd`, `echo`, `printf`, `true`, `false`, `test`, `[`, `type`, `command`; read-only tools `ls`, `cat`, `head`, `tail`, `wc`, `file`, `stat`, `du`, `basename`, `dirname`, `realpath`, `readlink`, `grep`, `rg`, `find`, `diff`, `cmp`, `sort`, `uniq`, `cut`, `tr`, `date`, `uname`, `whoami`, `which`; `git status`, `git log`, `git diff`, `git show`, `git rev-parse`, `git ls-files`, `git blame` |
| `exec.deny` | Options that run programs or delete files: `find * -exec* *`, `find * -ok* *`, `find * -delete *`, `rg * --pre* *`; git configuration that runs programs: `git -c *`, `git --config-env* *`; and `sudo`, `su`, `security`, `launchctl`, `osascript`, `open` |
| `exec.project_executables`, `exec.default` | `ask` (so denied, with the `unattended` reason) |
| `network.mode` | `none` (no hosts, approval hosts or loopback ports) |
| `approvals.irreversible` | `deny` |
| `recording` | `commands = true`, `output = false` |

Interpreters and programmable tools (`sed`, `awk`, `xargs`, `env`, shells) are left out on purpose. Command rules
remain intent filters: the sandbox (writes only to `${TMPDIR}`, no network) is the hard limit.

## Integrity

| ID | Requirement |
| --- | --- |
| FR-POL-40 | Each policy file must carry a signature made by `knshd` with a key stored in a Keychain item that only `knshd`'s code signature can read. |
| FR-POL-41 | `knsh policy edit` opens the file; saving must require Touch ID or the user's password, checked by `knshd`, before it is signed. |
| FR-POL-42 | A file with a missing or bad signature must be ignored and reported with `policy.invalid`. |

**Signature format and key (KNSH-065, resolving the story's spec gap).**

- **Algorithm:** HMAC-SHA-256 through `CommonCrypto` (`CCHmac`), with a 32-byte random key. Symmetric, because only
  `knshd` both signs and verifies; KNSH-111 implements the same primitive for Linux so the format never diverges.
- **Where:** an **embedded trailer**, the file's last line, exactly `# knsh-signature: v1 hmac-sha256 <64 lowercase
  hex digits>` and a newline. Text and signature are one file, replaced atomically on save, so no reader sees new text
  with an old signature and no sidecar can be lost or left behind. The trailer is a TOML comment.
- **Coverage:** the MAC is over `knsh-policy-signature-v1`, NUL, the profile name, NUL, and the exact bytes before the
  trailer (the body). Any byte change, a trailer that is not exactly the format (uppercase hex, trailing bytes), or
  the file under another name invalidates it. A body without a final newline gets one before it is signed.
  Comparison is constant time.
- **Key:** a generic-password item (service `knsh.policy-signing`, account `hmac-sha256-v1`) in the file-based login
  keychain, created by `knshd` with `SecItemAdd` on the **first signature** (never on a verification), with Keychain
  user interaction disabled ([decision 11](../09-reference/decisions.md)). It is read once per `knshd` process and
  kept in memory. A read failure on an existing item (tampering, a locked keychain) is never repaired: every file is
  then ignored and nothing is signed (fail closed). An existing item is never overwritten.
- **Ignored files:** the loader never sees an ignored file's text. A parent in the `extends` chain counts too. On a
  session's line, `policy.invalid` names the profile on that session and the line is denied with the reason; starting
  a session or `policy.check` with such a profile fails (`-32603`), logged as `policy.invalid` in the system log. No
  session falls back to another profile.
- **Editing:** [`knsh policy edit`](../06-api/cli.md#policy-edit) through [`policy.read` and
  `policy.edit`](../06-api/user-socket.md#policy-files). The prompt names the profile, the text's size and the start
  of its SHA-256. A file is signed only if it loads.
- **Adoption:** files from before KNSH-065 are unsigned and ignored until saved once with `knsh policy edit`. Ad-hoc
  and Homebrew-from-source builds lose the key on each upgrade (claim C5), so every file must be saved again.
- **Not covered (pending):** recovering from a tampered key item (a new key needs Touch ID or the password, and a way
  to replace an item `knshd` cannot read); rolling back a file to an older signed version of the same profile (a
  same-user process outside envelopes can restore an old file; envelopes cannot write the policies directory);
  signing the hook configuration (`config.toml`, FR-HOOK-07 relies on the fixed deny only).

## Lifetime of pushed policy

| ID | Requirement |
| --- | --- |
| FR-POL-50 | A pushed snapshot must carry an `expires_at`. |
| FR-POL-51 | When it expires, agent sessions using it must be paused until the authority returns or the user selects a local profile with `knsh profile use`, confirmed with Touch ID. |
| FR-POL-52 | The engine must never silently fall back to a different policy. |
| FR-POL-53 | Loading a snapshot must emit `policy.updated`. |

## Grants

A grant is a time-limited rule added on top of a profile, usually after an approval: "allow `git push` in this session for one hour". See [../05-models/grant.md](../05-models/grant.md).

| ID | Requirement |
| --- | --- |
| FR-POL-60 | Grants must have a scope (`session` or `profile`), an `expires_at` and an ID, and must be kept in `knshd`'s state store. |
| FR-POL-61 | Grants must be listable with `policy.grants` and revocable with `policy.revoke`. |
| FR-POL-62 | Only the authority, or the user with Touch ID, may create grants. |

A grant only turns an `ask` into an `allow` (source `grant`), when it covers every part of the line that asks. It never
overrides a deny or a fixed deny, never relaxes the dynamic-code limits, and never matches once expired. The
evaluation rules are in [../05-models/grant.md#evaluation-knsh-042](../05-models/grant.md#evaluation-knsh-042).

## Dry runs

| ID | Requirement |
| --- | --- |
| FR-POL-70 | `policy.check` must report what policy would decide for a line without running it, on both `agent.sock` and `user.sock`. |
