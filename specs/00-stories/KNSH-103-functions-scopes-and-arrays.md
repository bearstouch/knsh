# KNSH-103 — Functions, scopes and arrays

[Phase 4](README.md#phase-4--native-interpreter) · [Story index and plan](README.md)

| Phase | Epic | Size | Depends on | Crates | Requirements |
| --- | --- | --- | --- | --- | --- |
| 4 | Language | L (5) | [KNSH-097](KNSH-097-parameter-variable-and-arithmetic-expansion.md) | `knsh-interp` | NFR-COMPAT-02 |

**Description.** As a script author, I want functions, dynamic scoping and indexed and associative arrays to match
bash, so that larger scripts and rc files work.

Scope: function definitions (both syntaxes), dynamic scoping with `local`, `FUNCNAME`, `BASH_SOURCE`, `BASH_LINENO`,
recursion limit (`FUNCNEST`), indexed arrays, associative arrays (`declare -A`), array expansions (`${a[@]}`,
`${!a[@]}`, `${#a[@]}`, slices), `declare -n` namerefs, `mapfile`/`readarray`.

**Acceptance criteria**
- [x] Dynamic scoping matches bash, including `local` shadowing and unset behaviour. *Each call pushes a scope (with
      the assignments written before the call, exported); lookups go innermost first; an assignment to a name no
      scope holds is global; `unset` of the running function's local leaves it local and unset, of a caller's local
      removes it so the global shows again; `declare` in a function is local unless `-g`; a local inherits only the
      export attribute and cannot shadow a read-only variable. `local_shadows_and_restores_global`,
      `unset_of_a_callers_local_reveals_the_global`, `declare_in_a_function_is_local_and_local_follows_bash`, and
      `functions_and_arrays_script_matches_bash` against `/bin/bash` 3.2.*
- [x] Sparse indexed arrays and negative indices match bash 5.2. *Elements kept by index; `${!a[@]}`, `+=` after the
      greatest index, slices by index (bash's `array_subrange`), per-element operators;
      `sparse_array_indices_listed_in_order` and the differential script (3.2). Negative subscripts read, assign and
      unset counting back from one past the greatest index; before the first element bash's `bad array subscript` is
      reported and reads as unset, and an assignment abandons the line: `negative_index_reads_from_end`, following
      5.2's `arrayfunc.c` (3.2 has no negative subscripts). Pending: a run against bash 5.2 itself (KNSH-109).*
- [x] Associative array iteration order matches bash's observable order where scripts rely on it, or the difference
      is documented. *Reproduced from bash 5.2's hash table (`assoc.c` over `hashlib.c`: 1,024 FNV-1 buckets, newest
      key first in a bucket, growth by four past two entries per bucket); `associative_order_follows_bash_buckets`,
      `keys_sharing_a_bucket_list_newest_first`, `a_full_table_grows_and_keeps_every_entry` (`vars`) and
      `associative_array_assignment_and_lookup`. Documented in
      [compatibility](../04-non-functional-requirements/compatibility.md); pending a run against bash 5.2 itself
      (KNSH-109).*
- [x] Namerefs resolve as in bash, including circular-reference errors. *Reading, assigning (a reference without a
      value takes the name), `+=`, unset (`unset -n` for the reference itself), `${!ref}` as the name, `local -n` to
      a caller's variable or array, `[ -R ]`: `nameref_reads_and_writes_target`. `declare -n x=x` is bash's
      `nameref variable self references not allowed`, an invalid target `invalid variable name for name reference`,
      a circular chain `warning: a: circular name reference` and unset: `circular_nameref_is_error`. Following 5.2's
      `variables.c`; the forms not reproduced (an element target, a circular chain inside a function, assigning
      through one) are refused and listed in compatibility.*
- [x] Bash 3.2 lacks associative arrays and namerefs: corpus lines that rely on them are tagged (NFR-COMPAT-05).
      *The seed corpus's `declare -A`, `local -n`, `mapfile`, `readarray` and `${arr[-1]}` lines are tagged
      `b32-missing` and `knsh-corpus check` is clean; the importer's detection now reads every option word of a
      declaration builtin (`declare -g -A`, `readonly -A`, `typeset +x -n`): `flags_bash4_constructs`.*

**Unit tests**
- `local_shadows_and_restores_global`
- `funcname_stack_matches_call_chain`
- `sparse_array_indices_listed_in_order`
- `negative_index_reads_from_end`
- `associative_array_assignment_and_lookup`
- `nameref_reads_and_writes_target`
- `circular_nameref_is_error`
- `mapfile_reads_lines_into_array`
- Also (`knsh-interp` evaluator): `unset_of_a_callers_local_reveals_the_global`,
  `declare_in_a_function_is_local_and_local_follows_bash`, `calls_take_arguments_and_return_statuses`,
  `break_inside_a_function_is_not_the_callers`, `bash_source_names_sourced_files`, `funcnest_limits_recursion`,
  `definitions_follow_bash`, `functions_run_in_pipelines`, `attributes_apply_to_elements`,
  `functions_outlive_the_text_that_defined_them`, `deep_function_recursion_fails_with_error_not_crash`, and the
  updated `variable_option_and_descriptor_tests`, `printf_builtin_assigns_quotes_and_reports`,
  `read_options_and_errors`; `array_elements_read_and_assign` (arithmetic); `elements_keys_and_lengths` (`${…}`
  reader); `arrays_print_like_bash_5_2` (`declare -p`); `associative_order_follows_bash_buckets`,
  `keys_sharing_a_bucket_list_newest_first`, `a_full_table_grows_and_keeps_every_entry`,
  `negative_indices_count_back_from_the_end` (`vars`); `funcnest_reads_as_bash_reads_numbers`;
  `arrays_option_reads_compound_and_element_assignments` (`knsh-bash`); `flags_bash4_constructs` (`knsh-corpus`).

**Integration tests**
- `crates/knsh-interp/tests/bash_differential.rs` `functions_and_arrays_script_matches_bash` (against `/bin/bash`
  3.2: functions, locals, recursion, `return`, temporary assignments, `FUNCNAME`, sparse arrays, slices, element
  operators, arithmetic on elements, `read -a`, functions in pipelines, `unset -f`).
- `crates/knsh-interp/tests/fuzz_regressions.rs`: the `word_expansion` and `builtin_conditional` targets now parse
  lines as the interpreter does (arrays on), with new seeds for arrays, functions, name references and `mapfile`.

**Implementation notes (KNSH-103).** The parser gained `ParseOptions::arrays` (`knsh-bash`), off by default so the
classifier still refuses array assignments (decision 6): with it, `name=(…)`, `name+=(…)`, `name[sub]=v`,
`name[sub]+=v` and a declaration builtin's `name=(…)` argument are read (`Assignment::subscript`,
`Assignment::array`, `CommandWord::array`, `ArrayValue`), and the substitutions of a list's elements are listed with
the assignment's or word's own. The interpreter parses with it on (`eval`, `source` and aliases too). Shell state
holds a value per variable (string, sparse indexed array, associative array in bash's hash order: `crate::vars`), a
scope per running function, the functions (each with the text it was parsed from, so one defined by `eval` or a
sourced file outlives it) and the call stack behind `FUNCNAME`, `BASH_SOURCE` and `BASH_LINENO`. Name references
are followed through at most 8 references (bash's `NAMEREF_MAX`). A call resets the loop count (bash 4.4), applies
the body's redirections, and puts back the scope, frame and positional parameters however it ends; `f() ( … )` runs
in a subshell; a function in a pipeline stage that is not the last runs on a thread of its own. `FUNCNEST` gives
bash's error and abandons the line; without it the evaluator's nesting limit applies. `mapfile`/`readarray` read a
byte at a time, bounded to 64 MiB; `read -a`, `read name[i]`, `printf -v name[i]`, `test -v name[i]` and `[ -R ]`
work. Refused rather than approximated (listed in
[compatibility](../04-non-functional-requirements/compatibility.md)): printing function definitions, `export -f`,
`BASH_SOURCE` elements of functions defined in the main script, a function named by an expansion in a non-final
pipeline stage, name references to elements or circular inside functions, `${a[@]@A}`/`@K`/`@k`, array assignments
before a command, and subscripts bash would expand a second time. Pending: a run against bash 5.2 itself for the
bash 4/5-only forms (KNSH-109); fuzzing under libFuzzer (nightly, not run here).
