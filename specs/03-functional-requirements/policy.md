# Policy

A policy profile says what an agent may read, write, run and reach, and what needs approval. Command rules are intent filters that make approvals specific and stop honest mistakes; the hard limits are the sandbox, its executable rules, the proxy and credential scoping ([enforcement model](../architecture/enforcement-model.md)). The file format is in [../models/policy-profile.md](../models/policy-profile.md).

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
| FR-POL-13 | A name rule (such as `git`) must match only a binary resolved from a trusted folder: `/usr/bin`, `/bin`, `/usr/sbin`, `/opt/homebrew/bin`, `/usr/local/bin`, plus folders the profile adds. |
| FR-POL-14 | A binary found in an agent-writable place (such as `node_modules/.bin`) must never match a name rule and must fall under `project_executables` (`allow`, `ask` or `deny`). |
| FR-POL-15 | Patterns are globs over normalised arguments. For tools with subcommands in the classifier's table (git, npm, cargo, docker, kubectl and others), options before the subcommand must be normalised, so `git -c x=y push` matches `git push`. |
| FR-POL-16 | A pattern without `*` must also match the same command with arguments. |
| FR-POL-17 | Precedence across all matching rules must be deny, then ask, then allow. No match uses `exec.default`. |
| FR-POL-18 | For a whole line, the verdict is deny if any part is denied, ask if any part asks. |

## Dynamic code

| ID | Requirement |
| --- | --- |
| FR-POL-20 | Dynamic code (`eval`, `sh -c`, `python3 -c`, names from variables) must be allowed or asked as the profile says, but must never inherit classes from what it might run. |
| FR-POL-21 | Dynamic code's network must be limited to `network.hosts`; it must receive no secrets and can never reach `approval_hosts`. So `python3 -c "subprocess.run(['git','push'])"` cannot reach github.com. |

## Fixed denies

| ID | Requirement |
| --- | --- |
| FR-POL-30 | Engine files, sockets and the control service must be denied to every envelope and command, and no profile can change that. |

## Integrity

| ID | Requirement |
| --- | --- |
| FR-POL-40 | Each policy file must carry a signature made by `knshd` with a key stored in a Keychain item that only `knshd`'s code signature can read. |
| FR-POL-41 | `knsh policy edit` opens the file; saving must require Touch ID or the user's password, checked by `knshd`, before it is signed. |
| FR-POL-42 | A file with a missing or bad signature must be ignored and reported with `policy.invalid`. |

## Lifetime of pushed policy

| ID | Requirement |
| --- | --- |
| FR-POL-50 | A pushed snapshot must carry an `expires_at`. |
| FR-POL-51 | When it expires, agent sessions using it must be paused until the authority returns or the user selects a local profile with `knsh profile use`, confirmed with Touch ID. |
| FR-POL-52 | The engine must never silently fall back to a different policy. |
| FR-POL-53 | Loading a snapshot must emit `policy.updated`. |

## Grants

A grant is a time-limited rule added on top of a profile, usually after an approval: "allow `git push` in this session for one hour". See [../models/grant.md](../models/grant.md).

| ID | Requirement |
| --- | --- |
| FR-POL-60 | Grants must have a scope (`session` or `profile`), an `expires_at` and an ID, and must be kept in `knshd`'s state store. |
| FR-POL-61 | Grants must be listable with `policy.grants` and revocable with `policy.revoke`. |
| FR-POL-62 | Only the authority, or the user with Touch ID, may create grants. |

## Dry runs

| ID | Requirement |
| --- | --- |
| FR-POL-70 | `policy.check` must report what policy would decide for a line without running it, on both `agent.sock` and `user.sock`. |
