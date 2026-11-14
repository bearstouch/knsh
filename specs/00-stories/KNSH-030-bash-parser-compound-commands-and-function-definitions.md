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
- [x] Every compound command in decision 6's exact list parses with spans, including redirections on the compound.
- [x] `simple_commands()` descends into all bodies, conditions, case arms and function bodies.
- [x] A call to a function defined earlier in the same line is marked as a function call, and its body is what policy
  evaluates; a call to an undefined name is resolved as a binary (KNSH-035).
- [x] Constructs outside decision 6's exact list (`select`, `((…))`, `[[ … ]]` with unsupported forms) are returned as
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

**Notes (clarified during implementation).**
- `Node::Unsupported` is `Command::Unsupported { construct, span }`. It is produced for `select`, `[[ … ]]`, `(( … ))`,
  `for (( … ))`, and for a function whose body is one of them; the span covers the whole construct and the
  redirections after it, and nothing inside it is read (opaque). `Script::commands()` yields it, so KNSH-032 maps it
  to dynamic. `coproc` and `time` stay `ParseError::Unsupported`: they prefix a pipeline rather than form a command,
  and `coproc` is dynamic by decision 6 anyway.
- `(( … ))` follows bash 3.2: after `((`, the `)` that matches the second `(` must be followed directly by `)`;
  otherwise the line is nested subshells (`((a); (b))`). Bash treats `#` as text inside `(( … ))` where the lexer starts
  a comment, so a `((` whose scanned part holds a comment is refused. `[[ … ]]` ends at the first `]]` word and a
  newline inside it is a syntax error, as in bash 3.2.
- Bash 3.2 forms accepted: `for x; do`, `for x do`, `for x in; do`, a newline before `in`, `{ … }` as a `for` or
  `select` body, `case x in esac`, empty case-arm bodies, a last arm without `;;`, `(pattern)`, and closing words right
  after a compound command (`{ (a) }`, `if (a) then b; fi`). `;&` and `;;&` are bash 4 (bash 3.2 rejects them) and
  are parsed the bash 4 way, as `|&` was in KNSH-029. Rejected as in bash: an empty compound list (`( )`, `{ }`,
  `do done`), a word after a compound command (`{ a; } b`), `f() echo x`, `function f ( a )`, `function f` newline
  `()`, `A=1 f() …`; an unterminated compound command is `ParseError::Unclosed` with the opener's span.
- Function bodies are walked as code where they are defined, called or not, so policy always sees their commands.
  `SimpleCommand::function_call` is set only when the call **certainly** reaches a function defined earlier; it names
  the definitions it may run by span. Every doubt leaves it unset, so the name is resolved as a binary (KNSH-035) and
  the body is still decided: definitions in subshells, pipelines, background items, conditional branches and loops,
  in compound commands with redirections (a failed redirection skips them), in `while`/`until` conditions (`break`
  can leave them early), and in a top-level command (up to a newline) that may be abandoned partway by an error bash
  does not exit on (arithmetic or `${…}` expansion errors, `failglob`, assignments to read-only variables such as
  `UID`); arms after `;&` or `;;&` name the definitions of the arms before them;
  calls inside a function body to functions defined outside it; anything after `unset` or a call to a function that
  may change functions; names that are not plain identifiers or are POSIX special builtins (POSIX mode finds those
  first); and every call on a line holding `eval`, `source`, `.`, `command`, `builtin`, `trap`, `alias`, `readonly`,
  `declare`, `typeset` or a command name that is not plain text. Past `MAX_FUNCTION_DEFINITIONS` (64) definitions
  nothing is marked, which keeps the analysis linear.
- Functions inherited from the environment (`BASH_FUNC_*`, `export -f`) and aliases enabled earlier in the line
  (`shopt -s expand_aliases`) are not seen by the parser; the supervisor's environment handling (KNSH-035, KNSH-036)
  must account for them.
