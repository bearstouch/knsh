# KNSH-029 — Bash parser: simple commands, assignments, pipelines, lists, redirections

[Phase 2](README.md#phase-2--contain-and-decide) · [Story index and plan](README.md)

| Phase | Epic | Size | Depends on | Crates | Requirements |
| --- | --- | --- | --- | --- | --- |
| 2 | Parser | L (5) | [KNSH-028](KNSH-028-bash-lexer-words-operators-and-every-quoting-form.md) | `knsh-bash` | FR-LC-02, FR-LC-09, decision 6 |

**Description.** As the supervisor, I want an AST for simple commands, assignments before a command, pipelines
(including `!` and `|&`), and lists joined by `&&`, `||`, `;`, `&` and newlines, with redirections attached, so that
policy can see every simple command in a line. Out of scope: compound commands (KNSH-030), substitutions (KNSH-031).

**Acceptance criteria**
- [x] Pure `parse(&str) -> Result<Script, ParseError>`; AST nodes keep spans.
- [x] `Script::simple_commands()` iterates every simple command in source order, including those inside pipelines
  and lists.
- [x] Assignments before a command (`A=1 B=2 cmd`) are separated from arguments; a line of only assignments is a
  simple command with no name.
- [x] Redirections are parsed in any position (`>out cmd arg`, `cmd >out arg`).
- [x] A syntax error returns `ParseError` with span; the caller treats it as dynamic (KNSH-032), never as allow.
- [x] Recursion is bounded by the depth limit from KNSH-032.
- [x] Fuzz target `bash_parse` added.

**Unit tests**
- `parses_assignments_before_command` — `FOO=1 npm test` → name `npm`, env `FOO=1`.
- `parses_pipeline_with_negation_and_pipe_amp` — `! a |& b`.
- `parses_and_or_list_left_associative` — `a && b || c`.
- `parses_background_and_sequential_lists` — `a & b; c`.
- `attaches_redirections_anywhere_in_command` — `>f echo hi 2>&1`.
- `yields_every_simple_command_in_order` — `a | b && c; d` → `[a, b, c, d]`.
- `reports_error_for_dangling_operator` — `a &&` is an error with span.
- `assignment_only_line_has_no_command_name` — `X=1`.

**Notes (clarified during implementation).**
- The reference is `/bin/bash` 3.2, which agent lines use by default. It recognises reserved words only as the first
  token of a command (`A=1 if x` runs a program named `if`), accepts one `!` per pipeline and only at its start
  (`! ! a`, `a | ! b` and `!` followed by a newline are syntax errors), and rejects `|&`. `|&` is still parsed as a
  bash 4 pipe of both outputs, as this story asks; under bash 3.2 such a line fails before anything runs.
- Valid bash that belongs to later stories is refused with `ParseError::Unsupported` rather than read partly:
  subshells, `{ }`, `if`, loops, `case`, `select`, `[[ ]]`, `function` and `name()` definitions (KNSH-030),
  here-documents (KNSH-031), `coproc` and `time`, `name=(…)` array values (also as arguments, as in
  `declare -a x=(1)`), `name[…]=…` element assignments, a `name[` where a command starts whose subscript the word
  does not close (bash reads it on across blanks and operators: `a[ 1 ]=x rm f` runs `rm`), and `{name}>file`
  descriptor-variable redirections (bash 4.1 and later run `cmd` in `{fd}>f cmd`; bash 3.2 runs `{fd}`). Each is
  dynamic for the caller (KNSH-032).
- Substitutions (`$( … )`, backticks, `<( … )`, `>( … )`) are accepted here as opaque word segments; the commands
  inside them are not yet in `simple_commands()` (KNSH-031). Until then a caller must treat a word containing one as
  dynamic (KNSH-032), and likewise a command name that is not plain literal text (`$x`, globs, brace expansion).
- An assignment needs an unquoted name and an unquoted `=` or `+=`, as in bash; line continuations inside the name are
  removed first. After the command name, assignment-shaped words are ordinary arguments (`env A=1`).
- The tree is flat (vectors, no chains of boxes), so a long `a && a && …` line never deepens recursion or the drop of
  the tree. The list parser takes its nesting depth and refuses lists deeper than `MAX_NESTING_DEPTH` (32, the
  lexer's constant); only KNSH-030 and KNSH-031 can nest lists, so the guard is exercised directly in a unit test.
