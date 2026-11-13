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
- [ ] `"$@"` preserves argument boundaries; `"$*"` joins with the first character of `IFS`.
- [ ] With `set -u`, an unset parameter is an error with bash's exit status and message shape.
- [ ] Differences between bash 3.2 and 5.2 used in the corpus (e.g. `${x^^}` absent in 3.2) are listed in a
      compatibility note and covered by tests (NFR-COMPAT-05).

*Arithmetic expansion and evaluation*

- [ ] Operator precedence and associativity match bash for every operator.
- [ ] Overflow wraps like bash on 64-bit platforms.
- [ ] Division by zero reports an error and a non-zero status, without aborting the interpreter.
- [ ] Recursive variable evaluation (`a=b; b=3; $((a))`) matches bash and is bounded.

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
