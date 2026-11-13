# KNSH-006 — TOML subset parser

[Phase 0](README.md#phase-0--foundations) · [Story index and plan](README.md)

| Phase | Epic | Size | Depends on | Crates | Requirements |
| --- | --- | --- | --- | --- | --- |
| 0 | Configuration | L (5) | [KNSH-001](KNSH-001-workspace-toolchain-lint-baseline-and-ci.md) | `knsh-toml` | NFR-SUP-06, [policy profile](../05-models/policy-profile.md), [hook](../05-models/hook.md) |

**Description.** As the engine, I want a small parser for exactly the TOML the policy and configuration files use,
so that no TOML crate is needed and anything outside the subset is rejected, not guessed. The subset: comments,
bare and quoted keys, dotted keys, `[table]`, `[a.b]`, `[[array-of-tables]]`, basic and literal strings, integers,
booleans, arrays (possibly multi-line, trailing comma allowed as in TOML), inline tables. Out of scope: dates,
floats, multi-line strings (unless a spec example needs them), and policy semantics (KNSH-039).

**Acceptance criteria**
- [ ] Parses the full example in [policy-profile.md](../05-models/policy-profile.md) and the hook example in
      [hook.md](../05-models/hook.md) into a value tree with source positions.
- [ ] Rejects duplicate keys and redefinition of a table, as TOML does.
- [ ] Rejects any construct outside the subset with an error naming line and column.
- [ ] Bounds nesting depth and input size; never panics (fuzz target `toml_parser` added to KNSH-005's harness).
- [ ] Errors are a typed enum; no stringly-typed errors.

**Unit tests**
- `parses_policy_profile_example` — spec example.
- `parses_hooks_array_of_tables` — `[[hooks]]` with inline table `match`.
- `rejects_duplicate_key` — strictness.
- `rejects_table_redefinition` — strictness.
- `rejects_datetime_outside_subset_with_position` — subset boundary.
- `rejects_excessive_nesting` — limits.

**Notes.** — The subset must be documented in the crate header; any spec example that needs more TOML extends the
subset deliberately, in the spec first.
