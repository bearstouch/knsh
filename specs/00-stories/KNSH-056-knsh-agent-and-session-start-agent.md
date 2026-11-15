# KNSH-056 — `knsh agent` and `session.start_agent`

[Phase 2](README.md#phase-2--contain-and-decide) · [Story index and plan](README.md)

| Phase | Epic | Size | Depends on | Crates | Requirements |
| --- | --- | --- | --- | --- | --- |
| 2 | Envelope | M (3) | [KNSH-009](KNSH-009-in-house-command-line-argument-parser.md), [KNSH-013](KNSH-013-knshd-connection-server-dispatcher-and-idle-exit.md), [KNSH-015](KNSH-015-session-model-and-registry.md) | `knsh`, `knshd`, `knsh-proto` | FR-AGT-01, FR-AGT-02, FR-AGT-06, FR-SES-02, FR-SES-03, [CLI](../06-api/cli.md) |

**Description.** As a user, I want `knsh agent --profile web-app -- claude` to start an agent session, so that the
agent CLI runs under supervision with one command.

**Acceptance criteria**
- [ ] `knsh agent [--profile <p>] [--agent <name>] -- <cmd…>` calls `session.start_agent` over `user.sock`.
      (Request building and the handler are tested; the binary against a launchd-started `knshd` is pending.)
- [x] The actor is `--agent` if given, otherwise derived from the command (`claude` becomes `claude-code`).
- [x] An agent session refuses to start with `-32005` when the capability probe reports `sandbox: none`.
- [x] A session started from inside another one records `parent_session_id` and gets the parent's profile or a
      stricter one. A looser profile is refused.
- [x] `session.start_agent` is unavailable on `agent.sock`.
- [x] `knsh agent` exits with the agent CLI's exit code, and the session ends (`session.ended`) when the CLI exits.
- [x] `--json` prints the session ID and profile.

**Unit tests**
- `derives_claude_code_actor_from_claude` — FR-AGT-02.
- `uses_explicit_agent_name` — FR-AGT-02.
- `refuses_start_when_sandbox_none` — FR-AGT-06.
- `nested_session_cannot_loosen_profile` — FR-SES-03.
- `start_agent_absent_from_agent_socket` — FR-SES-02.

**Notes**
- Spec gap: the derivation table only names `claude → claude-code`. The Codex CLI binary name and actor are needed
  for KNSH-058.
- Spec gap: "stricter profile" needs a comparison rule. Propose: a child profile is stricter if every allow is
  allowed by the parent and every parent deny stays denied. Otherwise use the parent's profile.
- Resolved: the derivation table is `claude → claude-code`, any other command its own file name
  ([agent CLIs](../08-integrations/agent-clis.md#starting)); the Codex CLI row is still KNSH-058's.
- Resolved: strictness is the proposed rule, key by key ([session model](../05-models/session.md#profile-strictness)).
  Without `--profile` a nested session gets the parent's profile; a looser `--profile` is refused with `-32003`.
- Implemented with a minimal real launch (session profile compiled for an envelope, `SHELL`, shims on `PATH`, token)
  so the CLI actually runs; the preset, proxy and confinement checks of the envelope remain KNSH-057 and KNSH-058.
