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
- [x] Limits are constants documented with their rationale; exceeding any one yields `Dynamic`, before allocation
  proportional to the excess.
- [x] Syntax errors, `Node::Unsupported`, `eval`, `source`/`.`, `coproc`, and names built from expansions all map to
  `Dynamic` with a machine-readable reason.
- [x] There is no code path from a parser error to an `Exact` outcome (checked by tests and by type: the classifier
  only accepts `ParseOutcome`).
- [x] No panics on any input (fuzzed for at least the CI smoke budget with the corpus as seeds).

**Unit tests**
- `deeply_nested_substitution_becomes_dynamic` — depth limit + 1.
- `oversized_line_becomes_dynamic_without_parsing`.
- `syntax_error_becomes_dynamic_not_error_allow`.
- `coproc_is_dynamic`, `eval_is_dynamic`, `source_is_dynamic` — decision 6.
- `command_name_from_variable_is_dynamic` — `$CMD args`.

**Notes.** — Limits values are not in the spec; propose them in [../09-reference/defaults-and-limits.md](../09-reference/defaults-and-limits.md)
with this story.

**Notes (clarified during implementation).**
- Limits: input 1 MiB (`MAX_INPUT_LEN`), 65,536 tokens per line (`MAX_TOKENS`, one budget shared with every
  substitution body, since each body is lexed again when parsed), nesting 32 (`MAX_NESTING_DEPTH`, lexer and parser).
  Values and rationale are in `defaults-and-limits.md` and on the constants.
- The entry point is `knsh_bash::parse_line(&str) -> ParseOutcome`, which never fails. `ParseOutcome` is
  `Exact(Exact)` or `Dynamic(Dynamic)`; both payloads have private fields, so only `parse_line` can build one. A line
  `parse` rejects is `Dynamic` with no script and one part; a line that parses keeps its script and lists each dynamic
  part (`DynamicPart { reason, span }`), so the exact parts are still decided (FR-LC-09). "Per part of the line" is read
  this way.
- `DynamicReason` is a closed enum with stable `snake_case` codes: `input_too_large`, `too_many_tokens`,
  `nesting_too_deep`, `syntax_error`, `ambiguous_syntax`, `here_document_delimiter`, `unsupported`, `coproc`, `eval`,
  `source`, `expanded_command_name`, `interpreter_input`.
- "Names built from expansions" covers parameters, substitutions, arithmetic, a leading `~`, unquoted globs (`*`, `?`,
  `[` except the name `[`), brace expansion (`{`) and ANSI-C or locale quotes (not decoded). Quotes and escapes are
  removed before comparing with `eval`, `source` and `.` (`e'va'l` is `eval`).
- Wrappers that run another command (`command eval`, `builtin eval`, `env $CMD`) are left to KNSH-036.
- Spans of parts inside a backtick body that bash un-escapes point at that backtick substitution on the line.
