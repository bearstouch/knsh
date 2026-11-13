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

- [ ] Depends on `std` only; no workspace or third-party crates; `unsafe` limited to hand-written `extern` calls with
  `// SAFETY:` comments (NFR-SUP-01).
- [ ] Never spawns threads; verified by a test that checks thread count before exec.
- [ ] Rejects malformed input (missing profile, relative paths, extra args) with a distinct exit code and message on
  stderr; never runs the command unsandboxed.
- [ ] Executes `/usr/bin/sandbox-exec -f <profile> <interpreter> -c <line>` (or `-c` variant per interpreter), with
  interpreter an absolute path.
- [ ] Inherits only stdio and explicitly listed descriptors (`O_CLOEXEC` on everything else).
- [ ] If `sandbox-exec` is missing or fails to apply the profile, exits non-zero; the supervisor treats that as deny
  and the probe reports `sandbox: none`.

*Capability probe: sandbox backend*

- [ ] At start, the probe runs `knsh-exec` with a minimal deny profile and a command that attempts a denied write;
  `seatbelt` only if the attempt fails as expected.
- [ ] Any probe error reports `none`.
- [ ] With `sandbox: none`, `session.start_agent` fails with `-32005` naming `sandbox` (wiring in part b).
- [ ] Result cached; re-probed on `knshd` restart.

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
