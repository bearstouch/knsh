# Sandbox profiles

Two kinds of profile confine every agent: the envelope profile and a per-command profile for each supervised line. How they are applied is in [../02-architecture/enforcement-model.md](../02-architecture/enforcement-model.md).

## Profile contents (macOS)

| Area | Default | Notes |
| --- | --- | --- |
| File read | Everything except the deny list | Canonical paths; engine paths always denied |
| File write | The profile's write roots, plus `/dev/null`, `/dev/zero`, `/dev/stdout`, `/dev/stderr` and `/dev/fd/N` | Plus the fixed write denies below. The devices reach no file: they are the null devices and descriptors the process already holds (`2>/dev/null`) |
| Fixed write denies | Every `.git` entry itself; `hooks/`, `config`, `config.worktree` and `commondir` at any depth inside `.git` (submodule git directories included); the `.git/modules` and `.git/worktrees` entries and the git directories directly below them; the entry of every directory above a fixed, engine or `fs.deny` path; shell startup files (`~/.zshenv`, `~/.zprofile`, `~/.zshrc`, `~/.zlogin`, `~/.zlogout`, `~/.bash_profile`, `~/.bash_login`, `~/.bashrc`, `~/.bash_logout`, `~/.profile`), `~/Library/LaunchAgents`, `~/.ssh`, engine paths, and `~/Library/Keychains` (proposed by decision 11, pending acceptance) | Blocks planting code that later runs outside the sandbox; git configuration changes go through an approved command. Denying the `.git` entry stops renaming a planted directory into place as `.git`, or the real one away; `git commit`, `checkout` and `gc` still work (in submodules and linked worktrees too), while `git init`, `git clone`, `git submodule add` and `git worktree add` fail (KNSH-044). `commondir` names the directory git takes hooks and configuration from, so writing it alone would plant a hook. Protecting ancestors' entries stops renaming a protected path away inside its parent, editing it and renaming it back. Keychain files are written by the client process itself, so this deny stops an agent overwriting or planting `knshd`'s Keychain items while it can still read its own (KNSH-026) |
| Executables | Trusted binary folders (and everything below them), the system tool folders (`/usr/libexec`, `/Library/Developer/CommandLineTools`, `/Applications/Xcode.app/Contents/Developer`), `exec.bash`, the canonical binaries the supervisor resolved for the line (or the agent CLI and shims for an envelope), and the write roots if `project_executables = "allow"` | Enforced by the kernel at every exec, including by children. The kernel checks the path after every symlink: Homebrew's `/opt/homebrew/bin/node` runs `/opt/homebrew/Cellar/…/node`, which the trusted folder does not cover, and the `/usr/bin` stubs (`git`, `clang`, `python3`, `make`) run the developer directory's copy, hence the system tool folders (KNSH-045). The supervisor names each resolved binary exactly, so a Homebrew tool the line names runs, but one a child starts by name does not unless its target is listed. A script given to an interpreter (`sh x.sh`) is read, not executed, so exec rules do not stop it. With `ask` or `deny`, an approved project executable is allowed as a named binary only |
| System services | Every Mach service except the denied ones (the short list command-line tools need is not measured yet: a gap listed in every profile's header) | Denied: LaunchServices (`open`), Apple Events (scripting other apps), launchd job submission, the knsh control service, the DNS resolver. Denying the resolver does not stop a tool that sends DNS over UDP itself; the network row does. App bundles that need LaunchServices (such as Chrome.app) run only as trusted tools (KNSH-025, decision 10) |
| Unix sockets | `agent.sock` for envelopes; none for commands | Denied unless the profile allows: `user.sock`, the Docker socket, the SSH agent socket. No profile key allows the Docker or SSH agent socket yet: Docker's (`/private/var/run/docker.sock`, `~/.docker/run/docker.sock`) has its own tagged deny, the SSH agent's (a launchd path that changes per login) falls under the default deny. `user.sock` is a fixed deny after every other rule. Binding a socket under the profile's own write roots is allowed; only connecting is limited. Binding one in an engine directory is denied, so no endpoint can be squatted. `agent.sock` lies inside the denied engine directory: the Unix-socket allow reaches it, files cannot (KNSH-045) |
| Network | The proxy's port and the profile's loopback ports | Outbound TCP and UDP only to `localhost:<proxy port>` and `localhost:<port>` for each `network.loopback` port, which may also be bound and served. All other traffic is refused, including other loopback ports and DNS sent over UDP by the tool itself |
| Process information and signals | Own sandbox only (was "own process group"; proposed by decision 8, pending acceptance) | Other processes' arguments and environment stay hidden, and so does the system-wide process list. macOS withholds the environment of Apple platform binaries only, so the profile must hide it for every other process. setuid tools such as `ps` cannot run in any profile |
| System settings | Read-only | `user-preference-read` only: `defaults read` works, `defaults write` fails (KNSH-045) |

The Seatbelt operations and filters that implement each row on macOS, and what each one cannot do, were measured by
KNSH-025 and are recorded in [verification claims C8](../07-testing/verification-claims.md#c8-process-information-signals-sockets-and-services).
Seatbelt matches canonical paths only, so every path in a compiled profile is canonical. The file rules are compiled by
`knsh-sandbox` (KNSH-044): every deny comes after every allow, so the fixed and engine denies always win, and every
path is written as an SBPL string literal with `\` and `"` escaped.
The rest of the table is compiled by KNSH-045 with those forms. The one deny written before an allow is process
information's (`(deny process-info*)` then `(allow process-info* (target same-sandbox))`), because `(deny default)`
does not cover it. Every compiled profile starts with a comment naming the profile and listing what it cannot enforce:
limits apply to the sandbox instance, not a process group (decision 8); the process list is denied as a whole; signal
denials are never logged; Mach services other than the denied ones are allowed; DNS sent over UDP by the tool itself
bypasses the resolver deny and is stopped by the network rules; setuid binaries cannot run; and a script given to an
interpreter is not an exec.

`knshd` writes each compiled profile to `<sha256>.sb` in the profiles directory ([file locations](../09-reference/file-locations.md)),
atomically, mode `0600`, after checking that the directory is this user's and `0700`, and reads it back before use.
Any failure denies the line or envelope (fail closed). A file is removed when the last running line or envelope using
it ends, and files left by an earlier run are swept when `knshd` starts. The record's `sandbox_profile` is
`<profile name>@<first 16 hex digits of the SHA-256>` ([execution record](../05-models/execution-record.md)).

## Requirements

| ID | Requirement |
| --- | --- |
| FR-SBX-01 | Every envelope and every supervised line must run under a deny-by-default profile compiled by `knshd`. |
| FR-SBX-02 | Profiles must contain the areas and defaults in the table above. |
| FR-SBX-03 | A line's profile must be the session's per-command baseline plus whatever its classes, grants and approvals add. |
| FR-SBX-04 | Executable rules must be enforced by the kernel at every exec, including by children. |
| FR-SBX-05 | `user.sock` must be denied in every profile, regardless of profile settings (fixed deny). |
| FR-SBX-06 | Every deny rule must carry a knsh tag, so reported violations can be traced to a session and command. |
| FR-SBX-07 | The sandbox compiler must write each compiled profile to a private file in an engine path; `sandbox_profile` in the record must hold the profile name and a hash of the compiled profile. |
| FR-SBX-08 | Sandbox denials reported by the system must be emitted as `sandbox.violation` and attached to the record's `sandbox_violations`, best effort. |
| FR-SBX-09 | A profile may name **trusted tools**, which the supervisor runs without a per-command profile, only after an approval or grant. |
| FR-SBX-10 | All engine paths must be denied to every envelope and command. |
