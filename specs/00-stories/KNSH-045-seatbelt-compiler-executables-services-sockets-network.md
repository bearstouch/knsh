# KNSH-045 — Seatbelt compiler: executables, services, sockets, network, process info, profile files and hashes

[Phase 2](README.md#phase-2--contain-and-decide) · [Story index and plan](README.md)

| Phase | Epic | Size | Depends on | Crates | Requirements |
| --- | --- | --- | --- | --- | --- |
| 2 | Sandbox | XL (8) | [KNSH-011](KNSH-011-engine-directories-permissions-and-backup-exclusion.md), [KNSH-025](KNSH-025-spike-seatbelt-behaviour-c1-c2-c8.md), [KNSH-044](KNSH-044-seatbelt-compiler-file-rules-and-fixed-denies.md) | `knsh-sandbox`, `knshd` | FR-SBX-02, FR-SBX-04, FR-SBX-05, FR-LC-15, FR-NET-08, FR-SEC-05, FR-SBX-07, decision 1 |

**Description.** Merged from *Seatbelt compiler: executables, services, sockets, network, process info* and *Compiled profile files and hashes*: they are done and validated together because the compiled profile file and its hash are the compiler's output under test.

*Seatbelt compiler: executables, services, sockets, network, process info.* As the supervisor, I want the rest of the profile table compiled: executable rules, system service
denials, Unix socket rules, network limited to the proxy port and loopback ports, process information and signals
limited to the own sandbox (decision 8), read-only system settings. Rule forms come from KNSH-025's results.

*Compiled profile files and hashes.* As the supervisor, I want each compiled profile written to a private file in an engine path with a
content hash, so that `knsh-exec` can apply it with `-f` and records can name exactly what ran.

**Acceptance criteria**
*Seatbelt compiler: executables, services, sockets, network, process info*

- [x] `process-exec` allowed only for trusted folders, profile-named paths and (if allowed) project executables
  (FR-SBX-04, FR-LC-15).
- [x] LaunchServices, Apple Events, launchd job submission, the knsh control service and the DNS resolver are denied
  (FR-NET-08).
- [x] Envelope profiles allow connecting to `agent.sock` only; command profiles allow no Unix socket; `user.sock` is
  always denied (FR-SBX-05); Docker and SSH agent sockets only when the profile allows.
- [x] Outbound network allowed only to `127.0.0.1:<proxy port>` and `network.loopback` ports.
- [x] Process info and signals limited to the own sandbox (decision 8; rule forms in KNSH-025's C8 results); any gap
  is documented in the profile header comment and the spec.

*Compiled profile files and hashes*

- [x] Files are created with mode 0600 in a 0700 engine directory, written atomically, named by hash.
- [x] `sandbox_profile` value is `<profile name>@<sha256 prefix>` (format documented).
- [x] Old profile files are garbage-collected when no running line references them.
- [x] Write failures deny the line (fail closed).

**Unit tests**
*Seatbelt compiler: executables, services, sockets, network, process info*

- `exec_allowed_only_from_trusted_and_named_paths`.
- `project_executables_follow_setting`.
- `control_service_lookup_always_denied`.
- `user_sock_always_denied`.
- `command_profile_has_no_unix_socket_allow`.
- `network_limited_to_proxy_and_loopback_ports`.

*Compiled profile files and hashes*

- `profile_file_named_by_content_hash`.
- `profile_file_mode_is_0600`.
- `write_failure_denies`.
- `unused_profiles_are_collected`.

**Integration tests**
*Seatbelt compiler: executables, services, sockets, network, process info*

- Under a compiled command profile: `open -a Safari` fails, `osascript` sending an Apple Event to another application
  fails (`osascript -e 1` sends none and succeeds, observed on macOS 26.6.2, so the test sends one to Finder), `nc` to a
  non-loopback address fails, connecting to a fake `user.sock` fails, executing a binary copied into the project fails
  when `project_executables = "deny"`.

**Verified** (macOS 26.6.2, `knsh-sandbox` unit, golden and `sandbox-exec` integration tests; `knshd` `profiles`
tests): every criterion above. **Pending:** macOS 14 and 15; the measured short list of Mach services (all but the
denied ones are allowed, a gap listed in each profile header); Homebrew tools a child starts by name (their `Cellar`
targets lie outside the trusted folder); wiring the file store into the supervisor (KNSH-050), which calls it for each
envelope and line and denies on error.
