# KNSH-035 — Binary resolution and trusted folders

[Phase 2](README.md#phase-2--contain-and-decide) · [Story index and plan](README.md)

| Phase | Epic | Size | Depends on | Crates | Requirements |
| --- | --- | --- | --- | --- | --- |
| 2 | Classifier | M (3) | [KNSH-007](KNSH-007-platform-interface-and-test-fakes.md), [KNSH-029](KNSH-029-bash-parser-simple-commands-assignments-pipelines-lists.md) | `knsh-bash` (pure), `knsh-core` | FR-LC-03, FR-POL-11, FR-POL-13, FR-POL-14 |

**Description.** As the supervisor, I want every simple command's name resolved to an absolute canonical path and
tagged as trusted, project executable or builtin, so that name rules only match binaries from trusted folders.
Scope: resolution against the caller's `PATH` and cwd through the injected `Fs` trait (pure core + effect at edge);
trusted folders `/usr/bin`, `/bin`, `/usr/sbin`, `/opt/homebrew/bin`, `/usr/local/bin` plus profile additions;
symlinks followed; bash builtins and keywords recognised.

**Acceptance criteria**
- [x] `resolve(name, env_path, cwd, trusted, fs) -> Resolution` returns `Trusted(CanonicalPath)`,
  `ProjectExecutable(CanonicalPath)`, `Builtin`, `Function`, or `NotFound`.
- [x] A binary whose canonical path is outside trusted folders (e.g. `node_modules/.bin/x`, `./scripts/x`) is
  `ProjectExecutable` even if invoked by bare name (FR-POL-14).
- [x] A symlink in a trusted folder pointing outside is classified by its canonical target.
- [x] Names containing `/` are resolved relative to cwd and canonicalised.
- [x] `NotFound` is carried through so the line fails as bash would (127), not allowed as unknown.
- [x] Fake `Fs` from KNSH-007 used in tests; no real filesystem in unit tests.

**Unit tests**
- `resolves_git_from_usr_bin_as_trusted` — FR-POL-13.
- `classifies_node_modules_bin_as_project_executable` — FR-POL-14.
- `follows_symlink_to_canonical_target_outside_trusted` — FR-POL-11.
- `relative_path_command_resolved_against_cwd`.
- `builtins_are_not_resolved_on_path` — `cd`, `export`.
- `profile_added_trusted_folder_is_honoured`.
- `missing_binary_is_not_found`.
