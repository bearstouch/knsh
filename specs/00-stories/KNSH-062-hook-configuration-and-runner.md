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

- [x] `[[hooks]]` entries with `event`, optional `match` (`binary` list), `run` and `timeout_ms` are loaded in
      declared order.
- [x] Only `event = "command.proposed"` is accepted. Other events and unknown keys are configuration errors.
- [x] `run` is resolved (`~` expanded) to an absolute path that must exist and be executable. Otherwise the hook is
      invalid.
- [x] An invalid hook configuration denies every agent line that the hook would match, rather than silently dropping
      the hook (fail closed).
- [x] The configuration lives under `~/.config/knsh/`, which every profile denies to envelopes.

*Hook runner*

- [x] Hooks run only for supervised agent lines, in the supervisor, before policy. Human sessions run none.
- [x] The hook executable is spawned directly (never through a shell), with the `command.proposed` event as JSON on
      stdin.
- [x] Stdout is parsed as a verdict (`allow`, `deny`, `ask`, `rewrite`, `annotate`) under a size limit.
- [x] Empty stdout uses the exit code: 0 is allow, 2 is deny. Any other exit code is an error.
- [x] Any error, unparsable output or timeout (`timeout_ms`) is a **deny**. The hook's process group is killed on
      timeout.
- [x] Each hook's run time is stored per record.

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

- Spec gap, resolved: hooks live in `~/.config/knsh/config.toml` ([hook model](../05-models/hook.md)), read by
  `knshd` for every agent line. Integrity protection like policies (FR-POL-40) is **pending**: it arrives with policy
  signing ([KNSH-065](KNSH-065-policy-file-signing-and-knsh-policy-edit.md)). Until then the file is protected only by
  the fixed deny of the configuration directory in every envelope profile (FR-HOOK-07).

*Hook runner*

- Spec gap, resolved: stdout is one JSON object (`verdict`, `reason`, `command`, `labels`), defined with its limits
  in [hook model](../05-models/hook.md#output). Each hook's run time is stored in the record's `decision.hooks`
  ([execution record](../05-models/execution-record.md#decision)).
- A `rewrite` ends the chain of its pass; the rewritten line gets a pass of its own in which every hook runs again,
  so later hooks see the new line (FR-HOOK-10). The finer combination rules are
  [KNSH-063](KNSH-063-verdict-combination-and-rewrite-chain.md)'s.
