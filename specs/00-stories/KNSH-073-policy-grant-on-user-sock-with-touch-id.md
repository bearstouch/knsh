# KNSH-073 — `policy.grant` on `user.sock` with Touch ID

[Phase 2](README.md#phase-2--contain-and-decide) · [Story index and plan](README.md)

| Phase | Epic | Size | Depends on | Crates | Requirements |
| --- | --- | --- | --- | --- | --- |
| 2 | Authority | S (2) | [KNSH-042](KNSH-042-grants.md), [KNSH-064](KNSH-064-localauthentication-service-touch-id-or-password.md) | `knshd` | FR-POL-62, NFR-SEC-04, [user socket](../06-api/user-socket.md) |

**Description.** As a user without an authority app, I want to create a grant from the CLI with Touch ID, so that I
can allow a repeated action for a limited time.

**Acceptance criteria**
- [x] `policy.grant` on `user.sock` creates a grant only after the `knshd` prompt shows the rule, scope and
      duration, and authentication passes. *(The prompt reads `grant the agent command rule: <rule> (session <id> |
      profile <name>, for <duration>)`, escaped as every prompt is. Everything the engine would refuse (a rule that is
      not a command pattern, a session that is not a live agent session) is refused before any prompt; after it the
      session is checked again and the grant lasts `duration_s` from then. Any outcome but success is `-32001` with
      `source: "user"` and no grant. **Pending (manual):** the real Touch ID prompt, as for KNSH-065.)*
- [x] Grants created this way are listed and revocable like authority grants. *(Same grant store and state file as
      the authority's. `policy.grants` and `policy.revoke` are now on `user.sock` too, without a prompt, so a user
      without an authority app can list and revoke them: `knsh policy grants`, `knsh policy revoke <grant_id>`.)*
- [x] `policy.grant` is not available on `agent.sock`. *(Nor `policy.grants` or `policy.revoke`: not listed in
      `hello`, `-32003` from the catalogue and again in the handler.)*

**Unit tests**
- `user_grant_requires_authentication` — FR-POL-62.
- `user_grant_absent_on_agent_socket` — FR-POL-62.

Also: `user_grant_checks_before_prompting`, `user_grant_rechecks_after_the_prompt`,
`user_grants_are_listed_and_revocable_like_authority_grants` and `writes_durations_exactly` (`knshd`,
`policy_admin`); `reads_grant_results_back` (`knsh-proto`, `control`); `checks_grant_command_lines_before_sending`,
`reads_durations_strictly`, `sends_the_grant_and_reports_it`, `lists_and_revokes` and
`failure_messages_name_the_refusal` (`knsh`, `cli::grants`).

**Notes**
- [CLI](../06-api/cli.md) listed no `knsh` command for grants. Added `knsh policy grant`, `knsh policy grants` and
  `knsh policy revoke` ([CLI](../06-api/cli.md#grants)).
