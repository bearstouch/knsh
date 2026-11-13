# KNSH-049 — Agent client: `knsh -c` forwarding, descriptor passing and shims

[Phase 2](README.md#phase-2--contain-and-decide) · [Story index and plan](README.md)

| Phase | Epic | Size | Depends on | Crates | Requirements |
| --- | --- | --- | --- | --- | --- |
| 2 | Supervisor | XL (8) | [KNSH-048](KNSH-048-agent-sock-endpoint-session-tokens-and-audit-token-fallback.md) | `knsh`, `knsh-proto`, `knshd` | FR-AGT-10, FR-LC-01, FR-LC-31, FR-OUT-03, FR-OUT-04, NFR-COMPAT-09, FR-LC-14, FR-LC-16, [agent integration](../03-functional-requirements/agent-integration.md) |

**Description.** Merged from *Agent client: `knsh -c` forwarding with descriptor passing* and *`sh`, `bash` and `zsh` shims*: they are done and validated together because the shims are validated by routing through `knsh -c`.

*Agent client: `knsh -c` forwarding with descriptor passing.* As an agent CLI running inside an envelope, I want `$SHELL -c '…'` (which is `knsh -c`) to behave
like `bash -c`, so that the supervisor can decide on and run my command without me noticing any difference.

In scope:
- Inside an envelope, `knsh -c` connects to `agent.sock` and sends the line, working directory, environment, requested
  interpreter and its stdin/stdout/stderr descriptors (`SCM_RIGHTS`).
- It waits for the result and exits with the line's exit code. On denial it prints the reason on stderr and exits 126.

Out of scope: shims (covered in this story) and the `exec.run` output modes (KNSH-053).

*`sh`, `bash` and `zsh` shims.* As an agent CLI that calls `sh`, `bash` or `zsh` by name, I want those names to route to
`knsh -c`, so that my commands are supervised too.

In scope: a shim directory containing `sh`, `bash` and `zsh` entries that invoke `knsh` with the interpreter name
preserved. Only the envelope's `PATH` puts that directory first (KNSH-057).

**Acceptance criteria**
*Agent client: `knsh -c` forwarding with descriptor passing*

- [ ] The client is detected as "inside an envelope" only through the session token in the environment or a
      successful audit-token match. Labels never relax policy.
- [ ] The line, cwd, full environment and the requested interpreter are forwarded unchanged.
- [ ] Stdio descriptors are passed with `SCM_RIGHTS`. Command output goes straight to the caller's terminal or pipes
      and never crosses the API as JSON (FR-OUT-04).
- [ ] The client exits with the line's exit code. If the line was killed by a signal, it exits 128 + the signal number.
- [ ] On denial (`-32001`), the client prints the reason and rule ID on stderr and exits **126**.
- [ ] On `-32007` (paused or human control), the client stays held and does not exit with an error, according to
      the hold semantics fixed in KNSH-054.
- [ ] If `knshd` is unreachable, the client runs nothing, prints a clear error on stderr and exits non-zero
      (see Notes).
- [ ] The client itself never `exec`s the line locally, under any error path.

*`sh`, `bash` and `zsh` shims*

- [ ] `bash -c '…'`, `sh -c '…'` and `zsh -c '…'` inside an envelope are forwarded as `knsh -c` with the requested
      interpreter recorded, so `sh` later runs `/bin/sh`, `zsh` runs zsh and `bash` runs the profile's bash.
- [ ] Policy is identical whichever interpreter was asked for (FR-LC-14).
- [ ] Supervised lines run with a `PATH` that does not contain the shim directory (FR-LC-16).
- [ ] The shims are only reachable through `PATH`. `/bin/bash` by absolute path is not intercepted (FR-AGT-31).

**Unit tests**
*Agent client: `knsh -c` forwarding with descriptor passing*

- `forwards_line_cwd_env_and_interpreter` — FR-AGT-10.
- `exits_with_line_exit_code` — FR-AGT-10.
- `exits_126_and_prints_reason_on_denial` — FR-LC-31.
- `maps_signal_termination_to_128_plus_n` — NFR-COMPAT-09.
- `never_executes_locally_when_daemon_unreachable` — NFR-REL-01.
- `does_not_serialise_output_into_json` — FR-OUT-04.

*`sh`, `bash` and `zsh` shims*

- `shim_preserves_requested_interpreter` — FR-LC-14.
- `supervised_path_excludes_shim_directory` — FR-LC-16.
- `policy_verdict_independent_of_interpreter` — FR-LC-14.

**Integration tests**
*Agent client: `knsh -c` forwarding with descriptor passing*

- `knsh -c 'echo hi | tr a-z A-Z'` in a test envelope writes `HI` to the caller's own stdout pipe.
- `knsh -c 'exit 3'` exits 3. A denied line exits 126 with the reason on stderr.

**Notes**
*Agent client: `knsh -c` forwarding with descriptor passing*

- Spec gap: the exit code when `knshd` is unreachable is not specified. Propose 126 with a "supervisor unavailable"
  message, and record the choice in [reliability](../04-non-functional-requirements/reliability.md).
- Spec gap: whether the client forwards signals it receives (for example SIGINT from the agent CLI) to the running
  line's process group. Resolve in the spec before implementing; the proposal is to forward SIGINT, SIGTERM and SIGHUP.

*`sh`, `bash` and `zsh` shims*

- Spec gap: forms other than `-c` (`bash script.sh`, `bash -s`, `bash` reading stdin, `bash -l -c`) are not specified.
  Propose forwarding them as the equivalent line, with the script path classified as dynamic code when it is
  agent-writable (FR-LC-05). Resolve in [agent integration](../03-functional-requirements/agent-integration.md).
