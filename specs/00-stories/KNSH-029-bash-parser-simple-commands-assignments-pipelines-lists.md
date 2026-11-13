# KNSH-029 — Bash parser: simple commands, assignments, pipelines, lists, redirections

[Phase 2](README.md#phase-2--contain-and-decide) · [Story index and plan](README.md)

| Phase | Epic | Size | Depends on | Crates | Requirements |
| --- | --- | --- | --- | --- | --- |
| 2 | Parser | L (5) | [KNSH-028](KNSH-028-bash-lexer-words-operators-and-every-quoting-form.md) | `knsh-bash` | FR-LC-02, FR-LC-09, decision 6 |

**Description.** As the supervisor, I want an AST for simple commands, assignments before a command, pipelines
(including `!` and `|&`), and lists joined by `&&`, `||`, `;`, `&` and newlines, with redirections attached, so that
policy can see every simple command in a line. Out of scope: compound commands (KNSH-030), substitutions (KNSH-031).

**Acceptance criteria**
- [ ] Pure `parse(&str) -> Result<Script, ParseError>`; AST nodes keep spans.
- [ ] `Script::simple_commands()` iterates every simple command in source order, including those inside pipelines
  and lists.
- [ ] Assignments before a command (`A=1 B=2 cmd`) are separated from arguments; a line of only assignments is a
  simple command with no name.
- [ ] Redirections are parsed in any position (`>out cmd arg`, `cmd >out arg`).
- [ ] A syntax error returns `ParseError` with span; the caller treats it as dynamic (KNSH-032), never as allow.
- [ ] Recursion is bounded by the depth limit from KNSH-032.
- [ ] Fuzz target `bash_parse` added.

**Unit tests**
- `parses_assignments_before_command` — `FOO=1 npm test` → name `npm`, env `FOO=1`.
- `parses_pipeline_with_negation_and_pipe_amp` — `! a |& b`.
- `parses_and_or_list_left_associative` — `a && b || c`.
- `parses_background_and_sequential_lists` — `a & b; c`.
- `attaches_redirections_anywhere_in_command` — `>f echo hi 2>&1`.
- `yields_every_simple_command_in_order` — `a | b && c; d` → `[a, b, c, d]`.
- `reports_error_for_dangling_operator` — `a &&` is an error with span.
- `assignment_only_line_has_no_command_name` — `X=1`.
