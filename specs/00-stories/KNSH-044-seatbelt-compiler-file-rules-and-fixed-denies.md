# KNSH-044 — Seatbelt compiler: file rules and fixed denies

[Phase 2](README.md#phase-2--contain-and-decide) · [Story index and plan](README.md)

| Phase | Epic | Size | Depends on | Crates | Requirements |
| --- | --- | --- | --- | --- | --- |
| 2 | Sandbox | L (5) | [KNSH-025](KNSH-025-spike-seatbelt-behaviour-c1-c2-c8.md), [KNSH-039](KNSH-039-policy-profile-model-and-loader.md) | `knsh-sandbox` | FR-SBX-01, FR-SBX-02, FR-SBX-06, FR-SBX-10, NFR-SEC-03 |

**Description.** As the supervisor, I want a pure compiler from a resolved profile plus line capabilities to Seatbelt
profile text covering file reads and writes, so that the kernel enforces file limits. Scope: deny-by-default base;
read everything except `fs.deny`; writes to write roots; fixed write denies (`.git/hooks/`, `.git/config`, shell
startup files, `~/Library/LaunchAgents`, `~/.ssh`, engine paths); engine paths denied for read and write; every deny
carries a knsh tag.

**Acceptance criteria**
- [ ] `compile(&ProfileInput) -> SbplText` is pure and deterministic: same input, same bytes (property test).
- [ ] Paths are emitted as canonical literals/subpaths, correctly escaped; no string interpolation of untrusted text
  without escaping.
- [ ] Fixed write denies and engine-path denies are emitted after allows so they win, and cannot be disabled by input.
- [ ] `.git/hooks/` and `.git/config` denies apply to every git directory under write roots (regex or subpath rules
  as determined by KNSH-025).
- [ ] Every deny rule carries a tag of the form `knsh:<session>:<command>:<rule>` (FR-SBX-06).
- [ ] Golden-file tests for the example profile.

**Unit tests**
- `compiles_deterministically`.
- `write_roots_become_write_allows`.
- `fs_deny_paths_denied_for_read_and_write`.
- `fixed_write_denies_always_present`.
- `engine_paths_denied_even_if_input_allows`.
- `escapes_paths_with_quotes_and_backslashes`.
- `every_deny_rule_is_tagged`.

**Integration tests**
- Under the compiled profile (via `sandbox-exec -f`), writing `${PROJECT}/.git/hooks/pre-commit` and `~/.zshrc`
  fails; writing `${PROJECT}/src/x` succeeds (test home in a temp dir).
