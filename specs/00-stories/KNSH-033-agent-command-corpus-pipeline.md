# KNSH-033 — Agent-command corpus pipeline

[Phase 2](README.md#phase-2--contain-and-decide) · [Story index and plan](README.md)

| Phase | Epic | Size | Depends on | Crates | Requirements |
| --- | --- | --- | --- | --- | --- |
| 2 | Parser | L (5) | [KNSH-001](KNSH-001-workspace-toolchain-lint-baseline-and-ci.md) | `tools/corpus` (dev-only), `tests/corpus/` | decision 7, NFR-PRIV-08, NFR-COMPAT-05 |

**Description.** As the engine team, I want a reproducible, normalised corpus of agent-generated command lines, so
that the parser, classifier and later the interpreter are measured against what agents actually run. Scope: import
from published agent trajectories of public coding benchmarks where licences allow, and from traces of supported agent
CLIs run on open-source repositories in CI; normalise paths, user names, hosts and secret-like values into
placeholders; record source and licence per line. Out of scope: `knsh corpus export` (KNSH-124); any user telemetry.

**Acceptance criteria**
- [ ] Corpus stored as versioned text files under `tests/corpus/`, one line per entry with source ID; licences listed.
- [ ] Normaliser replaces home paths, user names, host names, IPs and secret-like tokens (high-entropy strings, known
  token prefixes) with stable placeholders; a check fails CI if a raw `/Users/<name>` or token pattern remains.
- [ ] The import tool is a dev-only binary with no runtime dependency added to shipped crates.
- [ ] Corpus contains bash 3.2 vs 5.2 sensitive constructs tagged for NFR-COMPAT-05.
- [ ] Contains no user telemetry; provenance documented in [../07-testing/agent-command-corpus.md](../07-testing/agent-command-corpus.md).

**Unit tests**
- `normalises_home_paths_to_placeholder`.
- `normalises_secret_like_tokens` — e.g. `ghp_…`, `sk-…`, long base64.
- `normalisation_is_idempotent`.
- `rejects_entry_without_source_and_licence`.
