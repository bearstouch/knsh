# Sandbox profiles

Two kinds of profile confine every agent: the envelope profile and a per-command profile for each supervised line. How they are applied is in [../architecture/enforcement-model.md](../architecture/enforcement-model.md).

## Profile contents (macOS)

| Area | Default | Notes |
| --- | --- | --- |
| File read | Everything except the deny list | Canonical paths; engine paths always denied |
| File write | The profile's write roots | Plus the fixed write denies below |
| Fixed write denies | `.git/hooks/`, `.git/config`, shell startup files (`~/.zshrc`, `~/.zprofile`, `~/.bashrc`, `~/.bash_profile`, `~/.profile`), `~/Library/LaunchAgents`, `~/.ssh`, engine paths | Blocks planting code that later runs outside the sandbox; git configuration changes go through an approved command |
| Executables | Trusted binary folders, paths the profile names, and project executables if allowed | Enforced by the kernel at every exec, including by children |
| System services | A short list command-line tools need | Denied: LaunchServices (`open`), Apple Events (scripting other apps), launchd job submission, the knsh control service, the DNS resolver |
| Unix sockets | `agent.sock` for envelopes; none for commands | Denied unless the profile allows: `user.sock`, the Docker socket, the SSH agent socket |
| Network | The proxy's port and the profile's loopback ports | All other traffic is refused |
| Process information and signals | Own process group only | Other processes' arguments and environment stay hidden |
| System settings | Read-only, short list | |

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
