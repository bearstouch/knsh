# KNSH-096 — Interpreter core and AST evaluator

[Phase 4](README.md#phase-4--native-interpreter) · [Story index and plan](README.md)

| Phase | Epic | Size | Depends on | Crates | Requirements |
| --- | --- | --- | --- | --- | --- |
| 4 | Interpreter | XL (8) | [KNSH-030](KNSH-030-bash-parser-compound-commands-and-function-definitions.md), [KNSH-031](KNSH-031-bash-parser-command-substitution-backticks-and-here.md) | `knsh-interp` (proposed), `knsh-bash` | NFR-COMPAT-01, NFR-COMPAT-02 |

**Description.** As a `knsh` developer, I want an evaluator that walks the `knsh-bash` AST and executes it, so that
later stories can add expansions, builtins and per-command decisions to one execution engine.

Scope: shell state (variables, positional parameters, exit status `$?`, options placeholder), evaluation of simple
commands (external commands only, via an injected process spawner), `;`, `&&`, `||`, `!`, `if`, `for` (word lists
without expansion beyond literals), `while`, `until`, `case` (literal patterns), `{ }` groups, and exit status rules.
External commands are spawned through a `knsh-platform` trait so tests run without real processes.

Out of scope: expansions (402–404), redirections (405), pipelines and subshells (406), builtins (407–408).

**Acceptance criteria**
- [x] The parser's AST is consumed unchanged; the evaluator adds no second parser.
- [x] `$?` and exit status follow bash for lists, `!`, `if`, loops and `case` (no-match is 0).
- [x] Command not found returns 127; found but not executable returns 126 (NFR-COMPAT-09).
- [x] A command killed by signal n yields 128+n.
- [x] Evaluation depth and loop iteration have no hidden limits beyond bash's own behaviour, but recursion is bounded
      by an explicit, documented limit that fails with an error rather than a stack overflow.
- [x] All process effects go through injected traits; the crate has `#![forbid(unsafe_code)]`.

**Unit tests**
- `and_or_lists_short_circuit_like_bash` — `false && x; true || x` never runs `x`.
- `negation_inverts_exit_status` — `! false` gives 0.
- `case_without_match_returns_zero` — matches bash.
- `missing_command_returns_127` — NFR-COMPAT-09.
- `non_executable_returns_126` — NFR-COMPAT-09.
- `signal_exit_is_128_plus_signal` — fake spawner reports SIGKILL → 137.
- `deep_recursion_fails_with_error_not_crash` — bounded depth.

**Integration tests**
- Run a 50-line script mixing lists, `if`, loops and `case` under `knsh` and `/bin/bash`; compare stdout and status.

**Notes.** Crate placement is a spec gap (see phase intro). The process-spawn trait must allow KNSH-108 to insert a
decision before each spawn.

**Implementation notes (KNSH-096).** The crate is `knsh-interp`; external commands run through
`knsh_platform::CommandSpawner` (the KNSH-108 seam) and are looked up through `knsh_platform::Fs`. A check of the whole
script refuses everything later stories implement before any command runs (expansions, tilde including after `NAME=`
in any word, brace and pathname expansion, `$'…'`, redirections, pipelines, `&`, subshells, `time`, functions,
builtins). Until KNSH-101 and KNSH-102, `echo`, `printf`, `true`, `false`, `test` and `[` run as their programs,
looked up in `/bin:/usr/bin` only, never the user's `PATH`. Forms where those programs differ from bash's builtins are
refused: `echo` with any backslash or with option words other than a single `-n`; `printf` with a format starting
with `-` or using `%q`, `%Q` or `%(…)T`; `test` and `[` with `-N`, `-v`, `-R`, `-a` or `-o`. KNSH-101 and KNSH-102
lift these refusals. The evaluation depth limit is in
[defaults and limits](../09-reference/defaults-and-limits.md).
