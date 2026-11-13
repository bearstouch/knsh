# KNSH-057 — Envelope profile and launch

[Phase 2](README.md#phase-2--contain-and-decide) · [Story index and plan](README.md)

| Phase | Epic | Size | Depends on | Crates | Requirements |
| --- | --- | --- | --- | --- | --- |
| 2 | Envelope | L (5) | [KNSH-045](KNSH-045-seatbelt-compiler-executables-services-sockets-network.md), [KNSH-046](KNSH-046-knsh-exec-trampoline-and-sandbox-capability-probe.md), [KNSH-049](KNSH-049-agent-client-knsh-c-forwarding-descriptor-passing-and-shims.md), [KNSH-056](KNSH-056-knsh-agent-and-session-start-agent.md) | `knshd`, `knsh-sandbox` | FR-AGT-03 – FR-AGT-05, FR-AGT-11, FR-AGT-12, FR-AGT-20, FR-AUTH-16, FR-SBX-01, FR-SBX-05 |

**Description.** As the engine, I want to compile the envelope profile and start the agent CLI through `knsh-exec`
with the right environment, so that everything the agent does directly stays confined.

**Acceptance criteria**
- [ ] The envelope profile is compiled from the session's policy profile plus its preset, and applied by `knsh-exec`.
- [ ] The CLI starts with `SHELL=knsh`, the shim directory first in `PATH`, the session token in the environment, and
      proxy settings carrying envelope-specific credentials.
- [ ] The envelope allows `agent.sock` and denies `user.sock`, the control service lookup and all engine paths.
- [ ] Network from the envelope goes only to the proxy and the profile's loopback ports.
- [ ] Every process in the envelope's tree is treated as the agent, including commands typed into its terminal.
- [ ] Nothing started directly inside the envelope can exceed the envelope profile. Only supervisor-spawned lines can
      receive more.
- [ ] The envelope gets its own process group, which `knshd` keeps for pause and resume.

**Unit tests**
- `envelope_env_sets_shell_path_token_and_proxy` — FR-AGT-03.
- `envelope_profile_allows_agent_socket_only` — FR-SBX-05.
- `envelope_profile_denies_control_service_lookup` — FR-AUTH-16.
- `envelope_profile_includes_preset_grants` — FR-AGT-04.

**Integration tests**
- From inside a test envelope: connecting to `user.sock` fails, an XPC lookup of `knsh.control` fails, a direct
  `curl` that ignores the proxy fails, and `knsh -c true` succeeds.
