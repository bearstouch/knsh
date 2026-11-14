# KNSH-038 — Line re-serialisation with resolved absolute paths

[Phase 2](README.md#phase-2--contain-and-decide) · [Story index and plan](README.md)

| Phase | Epic | Size | Depends on | Crates | Requirements |
| --- | --- | --- | --- | --- | --- |
| 2 | Classifier | L (5) | [KNSH-035](KNSH-035-binary-resolution-and-trusted-folders.md) | `knsh-bash` | FR-LC-13, FR-LC-15 |

**Description.** As the supervisor, I want to re-emit the parsed line with every resolved command name replaced by its
absolute canonical path, and nothing else changed, so that the binary that runs is the one that was classified.
Scope: replacement by span; quoting of paths with special characters; builtins, functions and dynamic parts left
untouched.

**Acceptance criteria**
- [x] Output differs from input only at command-name spans of `Trusted` and `ProjectExecutable` resolutions.
- [x] Re-parsing the output yields the same AST shape and the same simple commands (property test over the corpus).
- [x] Paths containing spaces or shell metacharacters are single-quoted correctly.
- [x] Commands inside substitutions, function bodies and compound commands are rewritten too.
- [ ] If any replacement cannot be done safely, the function returns an error and the supervisor denies (fail closed).
  The error is done and tested (`ReserialiseError`); the supervisor's denial is pending its wiring in KNSH-050.

**Unit tests**
- `replaces_bare_name_with_absolute_path`.
- `leaves_builtins_and_functions_unchanged`.
- `rewrites_inside_command_substitution`.
- `quotes_path_with_space`.
- `round_trip_preserves_ast_over_corpus` — property test.
- `does_not_touch_dynamic_parts`.
