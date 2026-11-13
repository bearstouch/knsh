# KNSH-037 — Subcommand normalisation and network-intent classes

[Phase 2](README.md#phase-2--contain-and-decide) · [Story index and plan](README.md)

| Phase | Epic | Size | Depends on | Crates | Requirements |
| --- | --- | --- | --- | --- | --- |
| 2 | Classifier | L (5) | [KNSH-035](KNSH-035-binary-resolution-and-trusted-folders.md) | `knsh-bash`, `knsh-core` | FR-POL-15, FR-POL-16, FR-LC-06, FR-NET-03 |

**Description.** As the policy engine, I want a classifier table for tools with subcommands so that `git -c x=y push`
normalises to `git push`, and each command gets network-intent classes (e.g. `git fetch` may reach a preset's git
host). Scope: table entries for git, npm, cargo, docker, kubectl and others listed in the spec; global options before
the subcommand (with and without values) skipped; class assignment (`network:none`, `network:fetch`,
`network:publish`, …).

**Acceptance criteria**
- [ ] The table is static data in `knsh-bash` with documented entries; adding a tool needs no code change.
- [ ] Normalised argv is `[tool, subcommand, …remaining args]` with skipped global options recorded.
- [ ] Unknown global options before the subcommand make normalisation fail to the raw argv (rules still match on raw;
  never guess the subcommand).
- [ ] Each normalised command gets zero or more network-intent classes used later by host rules (KNSH-060).
- [ ] Irreversibility hooks: the normalised form is what KNSH-093 matches; this story only exposes it.

**Unit tests**
- `git_dash_c_before_push_normalises_to_git_push` — FR-POL-15.
- `git_dash_capital_c_path_option_is_skipped`.
- `npm_global_flags_before_run`.
- `docker_context_option_before_push`.
- `kubectl_namespace_option_before_apply`.
- `unknown_global_option_falls_back_to_raw_argv`.
- `git_fetch_gets_fetch_network_class`.
