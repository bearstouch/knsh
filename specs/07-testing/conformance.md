# Conformance

## Bash conformance

Measured in CI on every release against:

- The bash test suite
- The bash-compatible subset of the Oils project's cross-shell tests
- The agent-command corpus ([agent-command-corpus.md](agent-command-corpus.md))

Native mode (phase 4) target: bash 5.2, including bash's POSIX mode when started as `sh` or with `--posix`; at least 99% of corpus commands behaving as in bash. Differences between bash 3.2 (macOS `/bin/bash`) and 5.2 that agents rely on are covered by corpus tests.

## Phase 2 parser

The phase 2 parser classifies lines; it does not execute them. Its scope (decision 6):

| Parsed exactly | Classified as dynamic |
| --- | --- |
| Simple commands, assignments before a command, pipelines, `&&`, `\|\|`, `;`, `&`, redirections, every quoting form, command substitution and backticks (parsed recursively), subshells, `{ }` groups, `if`, `for`, `while`, `until`, `case`, function definitions | `eval`, `source` and `.`, command names built from expansions, `coproc`, here-documents fed to shells or interpreters, anything the parser cannot read |

### Exit criterion

- At least **95%** of corpus lines parsed exactly.
- **Every** line's accept or reject verdict matches bash in differential tests.

### Measurement (KNSH-034)

The differential harness `knsh-difftest` (`tools/difftest`, dev-only, never shipped) measures both criteria over every
corpus line ([agent-command-corpus.md](agent-command-corpus.md)):

- **Bash's verdict:** `bash -n -c -- <line>` (read, never executed), environment cleared, standard streams closed,
  10 s deadline per line. Exit 0 accepts, 2 rejects; any other status, a signal or a timeout fails the run. Shells:
  `/bin/bash` (3.2) always, plus `/opt/homebrew/bin/bash` and `/usr/local/bin/bash` when present (5.x), or the ones
  named with `--bash`.
- **Our verdict** (`parse_line`): *accept* when the line was read whole (`Exact`, or dynamic in parts); *reject* for
  a whole-line `syntax_error`; *no verdict* for a line not read for another reason (a limit, a construct refused
  before it could be delimited, `ambiguous_syntax`); such a line is dynamic, so never `Exact`.
- **Verdict gate:** any disagreement with a gating bash fails the run and is listed with file, line and command:
  `exact_but_shell_rejects` (the line is `Exact`, bash rejects it), `parsed_but_shell_rejects`, or
  `rejected_but_shell_accepts`. An empty corpus or no gating bash also fails it. One exception: bash 3.2 rejecting
  a line tagged `b32-missing` is an expected version difference (NFR-COMPAT-05); the line is still compared with
  every bash 5.x found.
- **Exact gate:** `Exact` lines × 100 ≥ total × 95, in whole numbers; an empty corpus fails. The gate is always
  measured and reported, and fails **release runs** (CI on a `v*` tag, or `KNSH_RELEASE=1 scripts/check.sh
  difftest`), which the phase 2 release waits for. Other runs report a shortfall without failing.
- **Reference shells** (`--reference`, for example brush) are compared and listed, never gating.
- **Report:** Markdown with every shell's path and version, the exact, dynamic-in-parts, syntax-error and not-read
  shares, lines per dynamic reason, per-shell counts and every mismatch. CI writes it to
  `target/difftest/report.md`, adds it to the job summary and uploads it as the `parser-differential-report`
  artefact. `cargo test` runs the verdict gate over the corpus too (`tools/difftest/tests/`).

Existing Rust shells such as brush serve as references and test oracles, not dependencies.
