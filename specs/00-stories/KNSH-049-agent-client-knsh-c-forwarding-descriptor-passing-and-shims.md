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

- [x] The client is detected as "inside an envelope" only through the session token in the environment or a
      successful audit-token match. Labels never relax policy. *The client sends `KNSH_SESSION_TOKEN` in `hello` and
      lets `knshd` bind the connection (by token, else audit token, KNSH-048); nothing else is consulted.*
- [x] The line, cwd, full environment and the requested interpreter are forwarded unchanged.
- [x] Stdio descriptors are passed with `SCM_RIGHTS`. Command output goes straight to the caller's terminal or pipes
      and never crosses the API as JSON (FR-OUT-04).
- [x] The client exits with the line's exit code. If the line was killed by a signal, it exits 128 + the signal number.
- [x] On denial (`-32001`), the client prints the reason and rule ID on stderr and exits **126**.
- [x] On `-32007` (paused or human control), the client stays held and does not exit with an error, according to
      the hold semantics fixed in KNSH-054. *Semantics settled in [sessions](../03-functional-requirements/sessions.md)
      (answered at once, client retries every second); observed against a stand-in supervisor. `knshd` holding lines
      is KNSH-054.*
- [x] If `knshd` is unreachable, the client runs nothing, prints a clear error on stderr and exits non-zero
      (see Notes).
- [x] The client itself never `exec`s the line locally, under any error path.

*`sh`, `bash` and `zsh` shims*

- [x] `bash -c '…'`, `sh -c '…'` and `zsh -c '…'` inside an envelope are forwarded as `knsh -c` with the requested
      interpreter recorded, so `sh` later runs `/bin/sh`, `zsh` runs zsh and `bash` runs the profile's bash.
      *Forwarding with the interpreter recorded observed end to end; choosing the binary from it is KNSH-051.*
- [x] Policy is identical whichever interpreter was asked for (FR-LC-14). *By construction: `knshd` hands the
      supervisor a proposal (line, cwd, `PATH`) with no interpreter in it; checked with the real policy evaluator.
      The orchestrator that decides on it is KNSH-050.*
- [x] Supervised lines run with a `PATH` that does not contain the shim directory (FR-LC-16). *`knshd` strips it
      (and the session token) on receipt, before names are resolved; spawning with that environment is KNSH-051.*
- [x] The shims are only reachable through `PATH`. `/bin/bash` by absolute path is not intercepted (FR-AGT-31).

*Not served yet:* `exec.run` stays `planned` in the method catalogue until the supervisor exists (KNSH-050), so a
real `knshd` answers `-32601` and `knsh -c` exits 126. The handler is complete and tested against a fake supervisor;
the client is tested against a stand-in supervisor that runs lines with `/bin/bash` on the passed descriptors.
Descriptor passing from inside a real Seatbelt envelope is verification claim C13 (pending, KNSH-057).

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

- Resolved: unreachable `knshd` exits 126 with "the supervisor is unavailable … the line did not run", recorded in
  [reliability](../04-non-functional-requirements/reliability.md) (NFR-REL-01) and
  [exit codes](../09-reference/exit-codes.md).
- Resolved (differently from the proposal): the client installs no signal handlers. A signal that ends it closes the
  connection, which the supervisor treats as the caller gone (cancel a pending decision, FR-LC-41; stop the running
  line's group, KNSH-051). Forwarding one particular signal is left to `exec.kill`. Recorded in
  [agent integration](../03-functional-requirements/agent-integration.md#forwarding-details-knsh-049).

*`sh`, `bash` and `zsh` shims*

- Resolved: forms other than `-c` are forwarded as the equivalent line (`sh 'script.sh' 'a'`) under the shim's
  interpreter; `-l` and `-i` are ignored. Recorded in
  [agent integration](../03-functional-requirements/agent-integration.md#forwarding-details-knsh-049). Classifying the
  script as dynamic code when agent-writable is the classifier's (FR-LC-05).
- The shim directory is `~/Library/Application Support/knsh-shims/` ([file locations](../09-reference/file-locations.md)):
  outside the fixed denies, since envelopes must run it. `knsh agent` installs it (KNSH-056).
