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

Existing Rust shells such as brush serve as references and test oracles, not dependencies.
