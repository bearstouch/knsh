# KNSH-058 — Agent CLI presets (Claude Code, Codex CLI, generic)

[Phase 2](README.md#phase-2--contain-and-decide) · [Story index and plan](README.md)

| Phase | Epic | Size | Depends on | Crates | Requirements |
| --- | --- | --- | --- | --- | --- |
| 2 | Envelope | L (5) | [KNSH-057](KNSH-057-envelope-profile-and-launch.md), [KNSH-060](KNSH-060-proxy-connection-rules-host-rules-address-checks-and.md) | `knsh-core` (preset data), `knshd` | FR-AGT-04, FR-AGT-05, FR-AGT-30 – FR-AGT-32, FR-NET-12, [agent CLIs](../08-integrations/agent-clis.md) |

**Description.** As a user, I want tested presets for the agent CLIs I use, so that they work inside an envelope
without hand-tuning.

**Acceptance criteria**
- [ ] The `claude-code` preset grants `api.anthropic.com`, read and write to `~/.claude`, and the project. It sets
      tool-specific proxy settings where the CLI needs them.
- [ ] The Codex CLI preset grants the CLI's model API host, its configuration folder and the project.
- [ ] The generic preset grants only the project and requires the profile to name the model host.
- [ ] Each preset documents how to turn off the CLI's own sandbox, and `knsh agent` warns when it detects that the
      sandbox is still on.
- [ ] A per-release checklist verifies that each CLI's shell tool honours `SHELL` or calls `sh` or `bash` by name.
- [ ] Presets can let class-specific commands reach `approval_hosts` (for example `git fetch` to github.com).

**Unit tests**
- `claude_code_preset_grants_api_host_and_config_folder` — FR-AGT-04.
- `generic_preset_grants_no_model_host` — FR-AGT-32.
- `preset_class_allows_git_fetch_to_github` — FR-NET-03.

**Integration tests**
- **Pending (manual, per release):** run Claude Code and Codex CLI inside an envelope on a sample repo. Confirm that
  shell commands arrive at the supervisor and that model traffic passes the TLS server-name check.

**Notes**
- Codex CLI's API host, configuration folder and sandbox switch must be confirmed against the release in use. Don't
  hard-code from memory.
