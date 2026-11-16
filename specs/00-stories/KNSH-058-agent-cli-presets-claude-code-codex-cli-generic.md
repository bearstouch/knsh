# KNSH-058 — Agent CLI presets (Claude Code, Codex CLI, generic)

[Phase 2](README.md#phase-2--contain-and-decide) · [Story index and plan](README.md)

| Phase | Epic | Size | Depends on | Crates | Requirements |
| --- | --- | --- | --- | --- | --- |
| 2 | Envelope | L (5) | [KNSH-057](KNSH-057-envelope-profile-and-launch.md), [KNSH-060](KNSH-060-proxy-connection-rules-host-rules-address-checks-and.md) | `knsh-core` (preset data), `knshd` | FR-AGT-04, FR-AGT-05, FR-AGT-30 – FR-AGT-32, FR-NET-12, [agent CLIs](../08-integrations/agent-clis.md) |

**Description.** As a user, I want tested presets for the agent CLIs I use, so that they work inside an envelope
without hand-tuning.

**Acceptance criteria**
- [x] The `claude-code` preset grants `api.anthropic.com`, read and write to `~/.claude`, and the project. It sets
      tool-specific proxy settings where the CLI needs them. *(Also `~/.claude.json` and `platform.claude.com`, the
      OAuth refresh host. Claude Code 2.1.325's native build reads `HTTPS_PROXY`/`HTTP_PROXY` itself, so it needs no
      setting of its own; confirmed from its binary, the network run is pending below.)*
- [x] The Codex CLI preset grants the CLI's model API host, its configuration folder and the project. *(Read from
      Codex CLI 0.165.0: `api.openai.com`, `chatgpt.com` and `auth.openai.com` for ChatGPT sign-in, `~/.codex`. The
      `codex` binary is the `codex-cli` actor.)*
- [x] The generic preset grants only the project and requires the profile to name the model host. *(The loader
      refuses a `generic` profile with no `network.hosts` under `allowlist` and no `network.loopback` port.)*
- [x] Each preset documents how to turn off the CLI's own sandbox, and `knsh agent` warns when it detects that the
      sandbox is still on. *(Also when a setting cannot be read or understood. The warning is advisory.)*
- [x] A per-release checklist verifies that each CLI's shell tool honours `SHELL` or calls `sh` or `bash` by name.
      *(Written in [agent CLIs](../08-integrations/agent-clis.md#per-release-checklist); running it is the pending
      manual check below.)*
- [x] Presets can let class-specific commands reach `approval_hosts` (for example `git fetch` to github.com).
      *(Proposed key `network.class_hosts`; the line decision carries `capabilities.class_hosts`. The proxy enforces
      it in KNSH-060, not started.)*

**Unit tests**
- `claude_code_preset_grants_api_host_and_config_folder` — FR-AGT-04.
- `generic_preset_grants_no_model_host` — FR-AGT-32.
- `preset_class_allows_git_fetch_to_github` — FR-NET-03.
- Also: `codex_cli_preset_grants_model_hosts_and_config_folder`, `class_hosts_must_be_approval_hosts`,
  `class_hosts_follow_line_classes`, `class_hosts_never_widen`, `derives_codex_cli_actor_from_codex`, and the
  `knsh agent` sandbox checks (`claude_code_sandbox_follows_settings_precedence`,
  `claude_code_unreadable_or_odd_settings_are_unknown`, `codex_cli_sandbox_is_on_unless_turned_off`,
  `warns_with_the_switch_that_turns_it_off`).

**Notes**
- KNSH-027 (C9, proposed decision 14): Claude Code and Codex CLI are Node programs; Node uses the proxy only with
  `NODE_USE_ENV_PROXY=1` (not in Node 22.20) and only with an HTTP proxy URL, never SOCKS5. Verify each CLI's own HTTP
  client honours it; if a CLI bundles its own proxy handling, set its setting too.
  *Finding (KNSH-058):* the releases installed here are not Node programs: Claude Code 2.1.325 is a native build on
  Bun 1.4.4 and Codex CLI 0.165.0 a native Rust binary. Both name `HTTPS_PROXY`/`HTTP_PROXY` in their binaries; neither
  needs `NODE_USE_ENV_PROXY` (still set by the envelope for Node tools the agent runs).

**Integration tests**
- **Pending (manual, per release):** run Claude Code and Codex CLI inside an envelope on a sample repo. Confirm that
  shell commands arrive at the supervisor and that model traffic passes the TLS server-name check.

**Notes**
- Codex CLI's API host, configuration folder and sandbox switch must be confirmed against the release in use. Don't
  hard-code from memory.
- Known limits: the hosts, folders and switches were read from the installed binaries (URLs, settings keys and
  environment variables they name), not observed in a networked run. If Claude Code saves `~/.claude.json` through an
  atomic replace with a temporary file beside it in `~`, the envelope refuses the temporary file; the binary has a
  fallback for a failed atomic write, still to be confirmed in the manual run. Codex CLI's shell choice was not read from its binary.
