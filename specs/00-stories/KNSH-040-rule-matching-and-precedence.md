# KNSH-040 — Rule matching and precedence

[Phase 2](README.md#phase-2--contain-and-decide) · [Story index and plan](README.md)

| Phase | Epic | Size | Depends on | Crates | Requirements |
| --- | --- | --- | --- | --- | --- |
| 2 | Policy | L (5) | [KNSH-037](KNSH-037-subcommand-normalisation-and-network-intent-classes.md), [KNSH-039](KNSH-039-policy-profile-model-and-loader.md) | `knsh-core` | FR-POL-13 – FR-POL-17 |

**Description.** As the policy engine, I want each classified simple command matched against `exec.allow`, `ask`,
`deny` and `project_executables`, with deny-ask-allow precedence and stable rule IDs, so that verdicts are
predictable and explainable. Scope: globs over normalised arguments; names match only trusted binaries; a pattern
without `*` also matches with extra arguments; default when nothing matches.

**Acceptance criteria**
- [x] `evaluate_command(&ResolvedProfile, &ClassifiedCommand) -> CommandVerdict { verdict, rule_id }` is pure.
- [x] `git` in `exec.allow` matches `/usr/bin/git` but not `./node_modules/.bin/git` (FR-POL-13/14).
- [x] `git push` matches `git push origin main` and `git -c x=y push` (FR-POL-15/16).
- [x] `rm -rf *` glob semantics are documented and tested (glob over the argument string, not the filesystem).
- [x] Precedence across all matching rules: deny > ask > allow; no match → `exec.default` (FR-POL-17).
- [x] Rule IDs have the form `exec.allow[1]` and refer to the resolved profile's index, documented across `extends`.

**Unit tests**
- `name_rule_matches_only_trusted_binary`.
- `project_executable_uses_project_executables_setting`.
- `pattern_without_star_matches_with_extra_args`.
- `normalised_git_push_matches_ask_rule`.
- `deny_beats_ask_beats_allow`.
- `no_match_uses_default`.
- `rule_id_points_at_matching_rule`.
- `glob_matches_arguments_not_files`.
