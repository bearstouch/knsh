# KNSH-030 — Bash parser: compound commands and function definitions

[Phase 2](README.md#phase-2--contain-and-decide) · [Story index and plan](README.md)

| Phase | Epic | Size | Depends on | Crates | Requirements |
| --- | --- | --- | --- | --- | --- |
| 2 | Parser | L (5) | [KNSH-029](KNSH-029-bash-parser-simple-commands-assignments-pipelines-lists.md) | `knsh-bash` | FR-LC-02, decision 6 |

**Description.** As the supervisor, I want subshells `( )`, groups `{ }`, `if`, `for` (both forms), `while`, `until`,
`case` and function definitions (`name() …`, `function name …`) parsed exactly, so that commands inside them are
decided. Function bodies are walked as code; calls to functions defined in the same line are recognised.
Out of scope: `select`, arithmetic `for ((…))` and `[[ ]]` semantics beyond parsing them as opaque constructs —
anything not listed as exact in decision 6 is classified dynamic.

**Acceptance criteria**
- [ ] Every compound command in decision 6's exact list parses with spans, including redirections on the compound.
- [ ] `simple_commands()` descends into all bodies, conditions, case arms and function bodies.
- [ ] A call to a function defined earlier in the same line is marked as a function call, and its body is what policy
  evaluates; a call to an undefined name is resolved as a binary (KNSH-035).
- [ ] Constructs outside decision 6's exact list (`select`, `((…))`, `[[ … ]]` with unsupported forms) are returned as
  `Node::Unsupported` with span, never silently dropped.

**Unit tests**
- `parses_if_elif_else_fi` — all branches' commands are visible.
- `parses_for_in_and_for_without_in`.
- `parses_while_and_until_loops`.
- `parses_case_with_multiple_patterns_and_fallthrough_terminators` — `;;`, `;&`, `;;&`.
- `parses_subshell_and_group_with_redirection` — `(a; b) >f`, `{ a; } 2>&1`.
- `parses_both_function_definition_forms`.
- `descends_into_function_bodies` — `f() { rm -rf x; }; f` exposes `rm`.
- `marks_select_as_unsupported` — never omitted.
