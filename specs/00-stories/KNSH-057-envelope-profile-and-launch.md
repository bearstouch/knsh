# KNSH-057 — Envelope profile and launch

[Phase 2](README.md#phase-2--contain-and-decide) · [Story index and plan](README.md)

| Phase | Epic | Size | Depends on | Crates | Requirements |
| --- | --- | --- | --- | --- | --- |
| 2 | Envelope | L (5) | [KNSH-045](KNSH-045-seatbelt-compiler-executables-services-sockets-network.md), [KNSH-046](KNSH-046-knsh-exec-trampoline-and-sandbox-capability-probe.md), [KNSH-049](KNSH-049-agent-client-knsh-c-forwarding-descriptor-passing-and-shims.md), [KNSH-056](KNSH-056-knsh-agent-and-session-start-agent.md) | `knshd`, `knsh-sandbox` | FR-AGT-03 – FR-AGT-05, FR-AGT-11, FR-AGT-12, FR-AGT-20, FR-AUTH-16, FR-SBX-01, FR-SBX-05 |

**Description.** As the engine, I want to compile the envelope profile and start the agent CLI through `knsh-exec`
with the right environment, so that everything the agent does directly stays confined.

**Acceptance criteria**
- [x] The envelope profile is compiled from the session's policy profile plus its preset, and applied by `knsh-exec`.
- [ ] The CLI starts with `SHELL=knsh`, the shim directory first in `PATH`, the session token in the environment, and
      proxy settings carrying envelope-specific credentials. (`SHELL`, `PATH` and the token are observed in a real
      envelope. The proxy settings, decision 14's variables with credentials issued per session and revoked when it
      ends, are observed reaching a test proxy's port from a real envelope; `knshd` sets none until the proxy exists,
      KNSH-059.)
- [x] The envelope allows `agent.sock` and denies `user.sock`, the control service lookup and all engine paths.
- [x] Network from the envelope goes only to the proxy and the profile's loopback ports.
- [x] Every process in the envelope's tree is treated as the agent, including commands typed into its terminal.
- [x] Nothing started directly inside the envelope can exceed the envelope profile. Only supervisor-spawned lines can
      receive more.
- [x] The envelope gets its own process group, which `knshd` keeps for pause and resume.

**Unit tests**
- `envelope_env_sets_shell_path_token_and_proxy` — FR-AGT-03.
- `envelope_profile_allows_agent_socket_only` — FR-SBX-05.
- `envelope_profile_denies_control_service_lookup` — FR-AUTH-16.
- `envelope_profile_includes_preset_grants` — FR-AGT-04.

**Integration tests**
- From inside a test envelope: connecting to `user.sock` fails, an XPC lookup of `knsh.control` fails, a direct
  `curl` that ignores the proxy fails, and `knsh -c true` succeeds.

**Notes**
- Implemented in `knshd` (`start_agent`, new `proxy` module) and `knsh` (shell mode). The preset is already merged by
  the profile loader (KNSH-039), so the envelope profile is the resolved profile compiled for an envelope
  (`envelope_profile`); the CLI and `knsh` are the binaries it names.
- Proxy credentials: `EnvelopeProxy` issues them when the session opens and revokes them when its envelope ends; a
  proxy that cannot issue them starts nothing (`-32603`). Until KNSH-059, `knshd` wires `NoProxy`: no proxy
  settings, no proxy port, so the envelope reaches only its loopback ports (fail closed). Inherited proxy settings
  (`HTTPS_PROXY`, `ALL_PROXY`, `NO_PROXY`, the tool-specific ones) never reach an envelope.
- FR-AGT-20: `knsh` with the session token in its environment never hosts a human shell; an interactive `knsh` there
  is forwarded as an agent line. Without the token it is still confined by the envelope's sandbox.
- Integration test: `envelope_confines_sockets_services_and_network` (`knshd`) runs the probes in a real envelope, each
  first outside it as a positive control. `knsh -c true` talks to a stand-in supervisor on the test home's
  `agent.sock`; against a launchd-started `knshd` it is still pending (as for KNSH-056).
- Known limits: commands typed into an interactive `knsh` inside an envelope run as one forwarded stdin-reading
  `bash` line, so they are the agent's but not decided one by one. Once a proxy runs, no `NO_PROXY` is set, so the
  proxy must forward the profile's `network.loopback` ports (or decision 14 must change) — KNSH-059. Only the CLI's
  canonical path and `knsh` run by name besides the trusted and system folders: a script CLI whose interpreter lies
  elsewhere (Homebrew `node`) needs its folder trusted — KNSH-058 presets. More inherited proxy variables
  (`FTP_PROXY`, `YARN_HTTPS_PROXY`, `GLOBAL_AGENT_*`) could be stripped; the sandbox limits the network regardless.
