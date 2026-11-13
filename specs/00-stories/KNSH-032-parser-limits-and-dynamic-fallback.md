# KNSH-032 — Parser limits and dynamic fallback

[Phase 2](README.md#phase-2--contain-and-decide) · [Story index and plan](README.md)

| Phase | Epic | Size | Depends on | Crates | Requirements |
| --- | --- | --- | --- | --- | --- |
| 2 | Parser | M (3) | [KNSH-029](KNSH-029-bash-parser-simple-commands-assignments-pipelines-lists.md), [KNSH-030](KNSH-030-bash-parser-compound-commands-and-function-definitions.md), [KNSH-031](KNSH-031-bash-parser-command-substitution-backticks-and-here.md) | `knsh-bash` | FR-LC-05, decision 6, NFR-SEC-05 |

**Description.** As the supervisor, I want hard limits and a single fail-closed fallback, so that anything the parser
cannot read with confidence becomes dynamic code instead of an error path that could allow it. Scope: input size
limit, nesting depth limit, token count limit, a `ParseOutcome` type with `Exact(Script)` or `Dynamic(reason, span)`
per part of the line.

**Acceptance criteria**
- [ ] Limits are constants documented with their rationale; exceeding any one yields `Dynamic`, before allocation
  proportional to the excess.
- [ ] Syntax errors, `Node::Unsupported`, `eval`, `source`/`.`, `coproc`, and names built from expansions all map to
  `Dynamic` with a machine-readable reason.
- [ ] There is no code path from a parser error to an `Exact` outcome (checked by tests and by type: the classifier
  only accepts `ParseOutcome`).
- [ ] No panics on any input (fuzzed for at least the CI smoke budget with the corpus as seeds).

**Unit tests**
- `deeply_nested_substitution_becomes_dynamic` — depth limit + 1.
- `oversized_line_becomes_dynamic_without_parsing`.
- `syntax_error_becomes_dynamic_not_error_allow`.
- `coproc_is_dynamic`, `eval_is_dynamic`, `source_is_dynamic` — decision 6.
- `command_name_from_variable_is_dynamic` — `$CMD args`.

**Notes.** — Limits values are not in the spec; propose them in [../09-reference/defaults-and-limits.md](../09-reference/defaults-and-limits.md)
with this story.
