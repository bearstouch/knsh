# KNSH-046 — `knsh-exec` trampoline and sandbox capability probe

[Phase 2](README.md#phase-2--contain-and-decide) · [Story index and plan](README.md)

| Phase | Epic | Size | Depends on | Crates | Requirements |
| --- | --- | --- | --- | --- | --- |
| 2 | Sandbox | XL (8) | [KNSH-014](KNSH-014-hello-handshake-method-catalogue-and-capability-probe-v1.md), [KNSH-025](KNSH-025-spike-seatbelt-behaviour-c1-c2-c8.md), [KNSH-045](KNSH-045-seatbelt-compiler-executables-services-sockets-network.md) | `knsh-exec`, `knshd` | decision 1, NFR-SUP-01, FR-LC-13, FR-LC-14, FR-AGT-06, NFR-REL-08, NFR-SEC-10 |

**Description.** Merged from *`knsh-exec` trampoline* and *Capability probe: sandbox backend*: they are done and validated together because the probe reports `seatbelt` exactly when the trampoline can apply a profile.

*`knsh-exec` trampoline.* As the supervisor, I want a tiny single-threaded trampoline that receives a profile path, an
interpreter and a line, sets up descriptors and process group, then runs `sandbox-exec -f <profile>` with the
interpreter, so that sandboxes are never applied inside multithreaded `knshd`. Scope: argument and descriptor
protocol between `knshd` and `knsh-exec`; `setpgid`; closing inherited descriptors except stdio and those named;
exact `execve` of `/usr/bin/sandbox-exec` by absolute path.

*Capability probe: sandbox backend.* As a client, I want `hello` to report `sandbox: "seatbelt"` only when a test profile was actually
applied and enforced on this machine, and `none` otherwise, so that agent sessions refuse to start rather than run
unconfined.

**Acceptance criteria**
*`knsh-exec` trampoline*

- [x] Depends on `std` only; no workspace or third-party crates; `unsafe` limited to hand-written `extern` calls with
  `// SAFETY:` comments (NFR-SUP-01).
- [x] Never spawns threads; verified by a test that checks thread count before exec.
- [x] Rejects malformed input (missing profile, relative paths, extra args) with a distinct exit code and message on
  stderr; never runs the command unsandboxed.
- [x] Executes `/usr/bin/sandbox-exec -f <profile> <interpreter> -c <line>` (or `-c` variant per interpreter), with
  interpreter an absolute path.
- [x] Inherits only stdio and explicitly listed descriptors (`O_CLOEXEC` on everything else).
- [x] If `sandbox-exec` is missing or fails to apply the profile, exits non-zero; the supervisor treats that as deny
  and the probe reports `sandbox: none`.

*Capability probe: sandbox backend*

- [x] At start, the probe runs `knsh-exec` with a minimal deny profile and a command that attempts a denied write;
  `seatbelt` only if the attempt fails as expected.
- [x] Any probe error reports `none`.
- [ ] With `sandbox: none`, `session.start_agent` fails with `-32005` naming `sandbox` (wiring in part b).
- [x] Result cached; re-probed on `knshd` restart.

**Unit tests**
*`knsh-exec` trampoline*

- `rejects_relative_profile_path`.
- `rejects_missing_arguments`.
- `builds_exec_argv_with_absolute_paths`.
- `closes_unlisted_descriptors`.

*Capability probe: sandbox backend*

- `probe_reports_seatbelt_when_denial_observed`.
- `probe_reports_none_when_write_succeeds`.
- `probe_reports_none_on_error`.

**Integration tests**
*`knsh-exec` trampoline*

- A line run through `knsh-exec` with a profile denying writes cannot write; `echo $$` process group equals its PID;
  a failing `sandbox-exec` path never falls back to running the command.

**Notes.** Done on macOS 26.6 (Apple M1 Pro). The protocol and exit codes are in
[process model](../02-architecture/process-model.md#knsh-exec); the probe in
[capabilities](../05-models/capabilities.md#probe).

- *Threads:* `knsh-exec` refuses to exec unless `proc_pidinfo` reports exactly one thread, so every integration test
  whose line runs (`execs_single_threaded` in particular) observes the count before exec; `counts_this_processs_threads`
  shows the count is real.
- *Argv:* `sandbox-exec -f <profile> <interpreter> -c -- <line>`. The `--` keeps a line that starts with `-` from
  being read as an interpreter option (checked for `/bin/sh`, `/bin/bash`, `/bin/zsh`).
- *Missing or failing `sandbox-exec`:* a failed `execve` exits 69 (`failed_exec_returns_the_error`, with a path that
  does not exist; `/usr/bin/sandbox-exec` itself is fixed and present here); a profile `sandbox-exec` cannot compile
  exits 65 and the line never runs (`failing_sandbox_never_falls_back_to_running_the_line`). Either way the probe
  reports `none` (`probe_reports_none_on_error`).
- *Hardening beyond the story:* the profile file must be a regular `0600`-style file of the user (not a symlink,
  not group- or world-writable); closed stdio is refused; `SIGPIPE` is reset to its default (the Rust runtime ignores
  it, and that would survive the exec).
- *`session.start_agent` and `-32005`:* the catalogue entry now requires the sandbox backend, so once the method is
  served it is unlisted and answered `-32005` naming `sandbox` under `sandbox: none`. The handler itself is part b
  (KNSH-056); that box stays unchecked until it is observed.
- *Not exercised:* a real `knshd` under launchd reporting `seatbelt` in `hello` (the probe path is covered with fakes,
  and the exact probe profile and line run against the real Seatbelt in `capability_probe_line_observes_the_denial`).
  macOS 14 and 15 are pending.
