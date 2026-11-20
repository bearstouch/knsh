# KNSH-097 — Parameter, variable and arithmetic expansion

[Phase 4](README.md#phase-4--native-interpreter) · [Story index and plan](README.md)

| Phase | Epic | Size | Depends on | Crates | Requirements |
| --- | --- | --- | --- | --- | --- |
| 4 | Expansion | XL (8) | [KNSH-096](KNSH-096-interpreter-core-and-ast-evaluator.md) | `knsh-interp` | NFR-COMPAT-02 |

**Description.** Merged from *Parameter and variable expansion* and *Arithmetic expansion and evaluation*: they are done and validated together because arithmetic is reached through the same expansion engine and tests.

*Parameter and variable expansion.* As an agent running scripts, I want bash parameter expansion to behave exactly as in bash 5.2, so
that scripts produce the same results.

Scope: `$name`, `${name}`, special parameters (`$@ $* $# $? $$ $! $0 $-` and `$1…`), `${#x}`, `${x:-}`, `${x:=}`,
`${x:?}`, `${x:+}`, substring `${x:o:l}`, pattern removal `# ## % %%`, substitution `/ // /# /%`, case modification
`^ ^^ , ,,`, indirection `${!x}`, `${!prefix*}`, `${x@Q}` and other `@` operators in bash 5.2, tilde expansion,
command substitution results (reusing 401's evaluator), environment import/export and `set -u` interaction.

Out of scope: arrays (409), arithmetic (403), word splitting and globbing (404).

*Arithmetic expansion and evaluation.* As a script author, I want `$(( ))`, `(( ))`, `let` and arithmetic `for` to follow bash, so that
counters and conditions behave identically.

Scope: 64-bit signed integer arithmetic with bash's wrap-around, all bash operators (including `**`, ternary,
comma, assignment operators, pre/post increment), bases (`0x`, `0`, `n#digits`), variable references by name,
division-by-zero error, and `(( ))` exit status (0 when non-zero result).

**Acceptance criteria**
*Parameter and variable expansion*

- [ ] Every operator above matches bash 5.2 output for the corpus and the bash test-suite cases that cover it.
      *Pending:* only bash 3.2 is installed here, and the corpus and bash test-suite runs belong to KNSH-109. Forms
      bash 3.2 and 5.2 share are compared with `/bin/bash` (`expansion_script_matches_bash`); the others follow bash
      5.2's source and are unit-tested.
- [x] `"$@"` preserves argument boundaries; `"$*"` joins with the first character of `IFS`.
- [ ] With `set -u`, an unset parameter is an error with bash's exit status and message shape. *Implemented as bash
      5.2 does it (status 1, `name: line n: x: unbound variable`, the script ends) and unit-tested; pending a check
      against bash 5.2, since bash 3.2 exits with 127.*
- [x] Differences between bash 3.2 and 5.2 used in the corpus (e.g. `${x^^}` absent in 3.2) are listed in a
      compatibility note and covered by tests (NFR-COMPAT-05).

*Arithmetic expansion and evaluation*

- [x] Operator precedence and associativity match bash for every operator.
- [x] Overflow wraps like bash on 64-bit platforms.
- [x] Division by zero reports an error and a non-zero status, without aborting the interpreter.
- [x] Recursive variable evaluation (`a=b; b=3; $((a))`) matches bash and is bounded.

**Unit tests**
*Parameter and variable expansion*

- `quoted_at_preserves_argument_boundaries`
- `quoted_star_joins_with_first_ifs_char`
- `default_and_assign_operators_match_bash`
- `pattern_removal_shortest_and_longest`
- `substitution_anchored_prefix_and_suffix`
- `case_modification_operators`
- `indirection_reads_named_variable`
- `nounset_errors_on_unset_parameter`
- `tilde_expands_home_and_user`

*Arithmetic expansion and evaluation*

- `precedence_matches_bash_table`
- `exponent_is_right_associative`
- `integer_overflow_wraps`
- `base_notation_parses_n_hash_digits`
- `division_by_zero_is_error_not_panic`
- `double_paren_status_is_zero_for_nonzero_result`
- `recursive_variable_reference_is_bounded`

**Integration tests**
*Arithmetic expansion and evaluation*

- Fuzz target `arith_expr` added to `fuzz/` (no panics).

**Implementation notes (KNSH-097).** Expansion runs when a command runs (`knsh-interp`'s `expand` module): words
first, then assignments left to right, each seeing the ones before it. `${…}` bodies are read with bash 5.2's rules
(`param`), the words inside them and arithmetic bodies by a scanner that finds the extents the lexer found (`scan`),
and arithmetic is a port of bash 5.2's `expr.c` (`arith`). The parser now keeps the expression of `(( … ))` and the
header and body of `for (( … ))` on their opaque nodes (`ArithmeticParts`), still opaque to the classifier. `let`
is evaluated natively; `~name` uses the new `knsh_platform::UserHomes` trait (`getpwnam_r`).

Errors follow `bash -c`: a fatal one (`set -u`, `${x?}`) ends the script with status 1; any other (a bad
substitution, an arithmetic error in `$(( ))`, an invalid indirection, `${1:=x}`) abandons the rest of its line with
`$?` set to 1. An arithmetic error in `(( ))`, `let` or an arithmetic `for` sets status 1 and the script goes on.

Deferred, refused with their story named: command substitution (KNSH-100, which can capture output; the spawner has
no output capture yet), word splitting and pathname expansion of unquoted expansion results (KNSH-098; a value bash
would split or match is refused, otherwise the result is bash's), arrays (KNSH-103), `${x@P}` (KNSH-107), `~N`,
`~-` and `OLDPWD` (KNSH-101), and variables bash maintains itself (`RANDOM`, `LINENO`, `BASH_VERSION`, `$_` …,
KNSH-101; also `COMP_WORDBREAKS`, and `PATH` and the others bash gives a default when the environment has none, while
unset), whether read, listed by `${!prefix*}` or assigned. `let` with prefix assignments (`a=1 let …`, a temporary
scope) is refused. Where bash does not split (an assignment, a `case` word, the word of `${x:=…}`), an unquoted `$*`
or `$@` with several parameters is joined with a space; bash joins it with the first character of `IFS` in some of
those places and versions, so unless that character is a space it is refused as word splitting (KNSH-098). The `set` builtin is KNSH-104; until then `set -u` is `ShellOptions::nounset`. At start-up the state sets
`IFS`, `PWD` and `SHLVL` as bash does (`PWD` and `SHLVL` exported). `$-` is `hBc` (`huBc` under `set -u`), as for
`bash -c`. The nesting limits are in [defaults and limits](../09-reference/defaults-and-limits.md).
