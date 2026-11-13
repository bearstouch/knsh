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
- [ ] Dynamic scoping matches bash, including `local` shadowing and unset behaviour.
- [ ] Sparse indexed arrays and negative indices match bash 5.2.
- [ ] Associative array iteration order matches bash's observable order where scripts rely on it, or the difference
      is documented.
- [ ] Namerefs resolve as in bash, including circular-reference errors.
- [ ] Bash 3.2 lacks associative arrays and namerefs: corpus lines that rely on them are tagged (NFR-COMPAT-05).

**Unit tests**
- `local_shadows_and_restores_global`
- `funcname_stack_matches_call_chain`
- `sparse_array_indices_listed_in_order`
- `negative_index_reads_from_end`
- `associative_array_assignment_and_lookup`
- `nameref_reads_and_writes_target`
- `circular_nameref_is_error`
- `mapfile_reads_lines_into_array`
