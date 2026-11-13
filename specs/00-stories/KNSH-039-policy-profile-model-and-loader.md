# KNSH-039 — Policy profile model and loader

[Phase 2](README.md#phase-2--contain-and-decide) · [Story index and plan](README.md)

| Phase | Epic | Size | Depends on | Crates | Requirements |
| --- | --- | --- | --- | --- | --- |
| 2 | Policy | L (5) | [KNSH-002](KNSH-002-core-value-types-ulids-canonical-paths-redacted-text.md), [KNSH-006](KNSH-006-toml-subset-parser.md) | `knsh-core` | FR-POL-01, FR-POL-02, FR-POL-10, FR-POL-11, FR-POL-12, FR-POL-03 |

**Description.** As the supervisor, I want profiles loaded from the TOML subset into typed, validated models with
`extends` and `preset` resolved and variables expanded to canonical paths, so that evaluation works on one resolved
profile. Scope: every key in [../05-models/policy-profile.md](../05-models/policy-profile.md); `${PROJECT}`,
`${HOME}`, `${TMPDIR}`; `~`; canonicalisation through the `Fs` trait. Signature checks are KNSH-065.

**Acceptance criteria**
- [ ] Unknown keys, wrong types and invalid enum values are errors naming the key; an invalid profile is never
  partially applied.
- [ ] `extends` chains resolve with child overriding parent per key; cycles are an error.
- [ ] `fs.read` defaults to `"all"` (FR-POL-12); `exec.default` defaults are documented.
- [ ] `${PROJECT}` resolves to the git root, or the session start directory when there is none (FR-POL-10).
- [ ] All paths are canonical (`/private/var/…`), symlinks followed (FR-POL-11).
- [ ] The resolved profile is a value type (`Eq`, `Clone`), so it can be hashed and compared.
- [ ] The engine never writes or generates profile content (FR-POL-03); only presets shipped as data.

**Unit tests**
- `loads_web_app_example_profile` — the example in the models page parses.
- `rejects_unknown_key_with_name`.
- `child_overrides_parent_exec_allow`.
- `detects_extends_cycle`.
- `project_variable_uses_git_root`, `project_variable_falls_back_to_start_dir`.
- `canonicalises_tmpdir_to_private_var`.
- `invalid_profile_is_not_partially_applied`.

**Notes.** — The spec lists profile settings without TOML keys (trusted folders, trusted tools, irreversible list,
agent bash path, default output mode). Propose key names in the models page with this story.
