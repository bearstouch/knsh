# Conformance

## Bash conformance

Measured in CI on every release against:

- The bash test suite
- The bash-compatible subset of the Oils project's cross-shell tests
- The agent-command corpus ([agent-command-corpus.md](agent-command-corpus.md))

Native mode (phase 4) target: bash 5.2, including bash's POSIX mode when started as `sh` or with `--posix`; at least 99% of corpus commands behaving as in bash. Differences between bash 3.2 (macOS `/bin/bash`) and 5.2 that agents rely on are covered by corpus tests.

## Phase 4 native mode

The phase 4 gate (KNSH-109, NFR-COMPAT-02, NFR-COMPAT-05, NFR-COMPAT-07, NFR-COMPAT-11) is measured by
`knsh-conformance` (`tools/conformance`, dev-only, never shipped), run by `scripts/conformance.sh` and by the CI
`conformance` job on every `v*` tag, every push to `master` and on demand.

### Shells

- **Reference:** bash 5.2.37, built from the GNU source by `scripts/conformance.sh` (pinned URL and SHA-256), so
  the reference is exactly 5.2 (Homebrew ships newer). The tool refuses a reference that does not report 5.2.
- **Candidate:** `knsh`'s native interpreter, started as `bash` is (`-c`, a script file or standard input, the
  start-up options as `set` arguments), built exactly as `knsh --native-line` builds it (same state, platform
  services and parse options) except that commands are started directly, not through the supervisor: the gate
  measures the interpreter, not policy. That entry point exists only in the dev-only tool.
- **Bash 3.2:** `/bin/bash`, run over the corpus for the 3.2 vs 5.2 difference list (not gating).

### Comparison

"Behaves as in bash 5.2" is decided per corpus line by these rules (`tools/conformance/src/observe.rs`):

| Aspect | Same when |
| --- | --- |
| Exit status | Same exit status, or killed by the same signal, or both past the deadline |
| Standard output | Same bytes |
| Standard error shape | Same number of lines and, on each, the same speaker (the text before the first `": "`, for example `shell` in `shell: line 1: x: command not found`); the wording is not compared |
| File effects | Same files, directories and links under the run's directory afterwards, each with the same permission bits and the same contents (length and hash) or link target; timestamps, owners and inode numbers are not compared |

- **Environment:** each run gets a fresh directory holding `work/` (a copy of `tests/conformance/fixture/`, the
  working directory), `home/` (`HOME`) and `tmp/` (`TMPDIR`). Nothing is inherited: `PATH=/usr/bin:/bin:/usr/sbin:/sbin`,
  `LC_ALL=C`, `LANG=C`, `TZ=UTC`, `TERM=dumb`, `USER` and `LOGNAME` `conformance`. Standard input is `/dev/null`; the
  line runs as `shell -c LINE shell`, so `$0` and the shells' own messages name `shell`. Every fixture entry's
  modification time is 2024-01-01T00:00:00Z.
- **Normalisation:** the run's directory is replaced by `$RUN` in both streams, in file contents and in link targets,
  before comparing.
- **Time and randomness:** the reference runs every line twice. An aspect that differs between those two runs
  (`date`, `ps`, `$RANDOM`, `$$`, a file holding a time stamp) is not compared for that line: output or stderr shape
  entirely, a file's contents (its presence and kind still are), a file present after one run only, or the status.
- **Deadline:** 10 s per run (`KNSH_CONFORMANCE_TIMEOUT`); a run past it is killed with its process group. Two runs
  past the deadline agree on status, and their streams and files are not compared.
- **Confinement:** every run of every shell is confined by the same Seatbelt profile: no network, writes only under
  its own directory (and `/dev/null`, `/dev/tty`, `/dev/fd`), no preference writes (`defaults write` goes through
  `cfprefsd`, outside the sandbox), no signals to processes outside the sandbox, no `sudo`, `su`, `login`,
  `launchctl`, `osascript`, `open`, `shutdown`, `reboot`, `halt`, `security`, `diskutil` or `tmutil`. A refused operation fails the same
  way under both shells. Lines that need the network or another machine are therefore compared on how they fail.

### Suites

| Suite | What runs | Compared | Category of a failure |
| --- | --- | --- | --- |
| Agent-command corpus | Every corpus line | All four aspects, as above | First differing aspect |
| Oils subset | Every case of every Oils spec file (pinned commit) whose `## compare_shells:` names `bash`, except those marked `N-I bash`; code on standard input as `test/sh_spec.py` feeds it, `SH`, `TMP`, `REPO_ROOT` and `PATH` as it sets them | Status and standard output | Spec file |
| Bash test suite | Every `tests/run-*` driver of bash 5.2.37 (not `run-all`, `run-minimal`, `run-gprof`), as `run-all` runs it, with `THIS_SH` naming each shell | The driver's output (its differences from the `.right` files) and status, against bash 5.2's own | Driver |

A suite's pass rate is passed ÷ run, rounded down to hundredths of a percent.

### Gate

- At least **99%** of corpus lines behave as in bash 5.2 (`passed × 100 ≥ total × 99`, in whole numbers), and every
  line that does not is listed in `tests/conformance/known-differences.tsv` with the heading of the
  [compatibility page](../04-non-functional-requirements/compatibility.md#native-mode-known-differences) that
  documents it (the tool checks the heading exists).
- All three suites ran, each with at least one case. Oils and bash-suite failures are published, with known ones
  marked, but do not gate.
- Enforced on release runs (CI on a `v*` tag, or `KNSH_RELEASE=1 scripts/conformance.sh`); other runs report the
  same numbers and fail only when the corpus did not run. Any run that cannot complete (a download whose checksum
  differs, a shell that cannot start) fails.
- **Report:** `target/conformance/report.md`: the shells and versions, each suite's pass rate, failures by category,
  every failure with whether it is documented, the bash 3.2 vs 5.2 difference list (lines not tagged `b32-missing`
  or `b32-differs` flagged) and known differences that now pass. CI adds it to the job summary and uploads it as the
  `native-conformance-report` artefact; a release's copy is stored under `specs/07-testing/qualification/`.

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
