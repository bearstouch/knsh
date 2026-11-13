# KNSH-062 — Hook configuration and runner

[Phase 2](README.md#phase-2--contain-and-decide) · [Story index and plan](README.md)

| Phase | Epic | Size | Depends on | Crates | Requirements |
| --- | --- | --- | --- | --- | --- |
| 2 | Hooks | XL (8) | [KNSH-006](KNSH-006-toml-subset-parser.md), [KNSH-050](KNSH-050-supervisor-lifecycle-orchestrator.md) | `knsh-core`, `knshd` | FR-HOOK-07, [hook model](../05-models/hook.md), FR-HOOK-01 – FR-HOOK-06, NFR-SEC-09 |

**Description.** Merged from *Hook configuration* and *Hook runner*: they are done and validated together because configuration is validated by running the configured hooks.

*Hook configuration.* As a user, I want to register hooks in my configuration, so that my own checks run on agent
commands.

*Hook runner.* As the supervisor, I want to run matching hooks safely before policy, so that user checks can
allow, deny, ask, rewrite or annotate agent lines.

**Acceptance criteria**
*Hook configuration*

- [ ] `[[hooks]]` entries with `event`, optional `match` (`binary` list), `run` and `timeout_ms` are loaded in
      declared order.
- [ ] Only `event = "command.proposed"` is accepted. Other events and unknown keys are configuration errors.
- [ ] `run` is resolved (`~` expanded) to an absolute path that must exist and be executable. Otherwise the hook is
      invalid.
- [ ] An invalid hook configuration denies every agent line that the hook would match, rather than silently dropping
      the hook (fail closed).
- [ ] The configuration lives under `~/.config/knsh/`, which every profile denies to envelopes.

*Hook runner*

- [ ] Hooks run only for supervised agent lines, in the supervisor, before policy. Human sessions run none.
- [ ] The hook executable is spawned directly (never through a shell), with the `command.proposed` event as JSON on
      stdin.
- [ ] Stdout is parsed as a verdict (`allow`, `deny`, `ask`, `rewrite`, `annotate`) under a size limit.
- [ ] Empty stdout uses the exit code: 0 is allow, 2 is deny. Any other exit code is an error.
- [ ] Any error, unparsable output or timeout (`timeout_ms`) is a **deny**. The hook's process group is killed on
      timeout.
- [ ] Each hook's run time is stored per record.

**Unit tests**
*Hook configuration*

- `loads_hooks_in_declared_order` — FR-HOOK-10.
- `rejects_unknown_event` — hook model.
- `matches_by_binary_basename` — hook model.
- `invalid_hook_denies_matching_lines` — FR-HOOK-04.

*Hook runner*

- `passes_event_json_on_stdin` — FR-HOOK-02.
- `exit_zero_without_output_allows` — FR-HOOK-03.
- `exit_two_without_output_denies` — FR-HOOK-03.
- `other_exit_code_denies` — FR-HOOK-04.
- `timeout_denies_and_kills_hook` — FR-HOOK-04.
- `unparsable_output_denies` — FR-HOOK-04.
- `records_hook_duration` — FR-HOOK-05.
- `no_hooks_run_for_human_sessions` — FR-HOOK-01.

**Notes**
*Hook configuration*

- Spec gap: the configuration file name and whether it is signed like policy files are not specified. Propose
  `~/.config/knsh/config.toml`, integrity-protected the same way as policies (FR-POL-40).

*Hook runner*

- Spec gap: the exact stdout format (plain word or JSON object with `verdict`, `reason`, `command`, `labels`) is not
  defined. Propose JSON, and define it in [hook model](../05-models/hook.md) before implementing.
